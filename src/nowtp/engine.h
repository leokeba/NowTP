// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdlib>
#include <memory>
#include <utility>
#include <vector>

#include "link.h"
#include "types.h"
#include "wire.h"

namespace nowtp {

// Heap buffers from malloc, which returns null on a short heap. `new
// (std::nothrow)` doesn't: with exceptions off (ESP-IDF), libstdc++'s nothrow
// operator new calls the throwing one, whose throw aborts.
struct FreeBytes {
    void operator()(uint8_t* p) const { std::free(p); }
};
typedef std::unique_ptr<uint8_t[], FreeBytes> Bytes;

/// Bytes after the payload that NowTP may need in an outgoing message's
/// buffer: the authentication trailer and the CRC of a multi-frame message.
constexpr size_t kSendOverhead = wire::kAuthTrailerSize + wire::kCrcSize;

/// A received frame as seen before any filtering, for diagnostics.
struct FrameInfo {
    Mac src;
    int8_t rssi;
    bool nowtp;          ///< Header decodes as some NowTP version.
    uint8_t version;     ///< Protocol version bits (valid when len >= 1).
    bool sameNetwork;    ///< Decodes and carries our network id and version.
    wire::Header header; ///< Valid when `nowtp`.
    const uint8_t* payload;
    size_t payloadLen;
};

using FrameObserver = std::function<void(const FrameInfo&)>;

/// Message authentication, plugged into the engine by Security.
///
/// Authenticated messages carry wire::kAuthTrailerSize bytes after the
/// application payload and the kFlagAuth header flag; acks for them carry a
/// wire::kAckTagSize tag. Called with the engine's lock held.
class Authenticator {
public:
    virtual ~Authenticator() {}

    enum class Verdict : uint8_t {
        Authentic,        ///< Verified: deliver with Message::authenticated set.
        Unauthenticated,  ///< Deliver as a plain message.
        Reject,           ///< Drop; a reliable sender is told Rejected.
        Retry,            ///< Not verifiable yet (unknown sender epoch): drop silently, a reliable sender retries.
    };

    /// True to authenticate an outgoing message on `port` (and the acks of
    /// incoming authenticated messages on it).
    virtual bool sealing(uint8_t port) const = 0;
    /// Writes the trailer of a message about to be queued. `flags` are the
    /// message's reliable and latest-only flags.
    virtual void seal(const Mac& dst, uint8_t port, uint8_t flags, const uint8_t* data, size_t len,
                      uint8_t* trailer) = 0;
    /// Checks a received message; `trailer` is null for an unauthenticated one.
    virtual Verdict open(const Mac& src, uint8_t port, uint8_t flags, const uint8_t* data, size_t len,
                         const uint8_t* trailer, uint32_t nowMs) = 0;
    /// Tags an ack frame (header included) sent to `dst`. `bind`, when the
    /// acknowledged message is known, is its trailer's first kAckBindSize
    /// bytes (epoch and sequence), so the ack can't stand for another message.
    virtual void sealAck(const Mac& dst, const uint8_t* frame, size_t len, const uint8_t* bind, uint8_t* tag) = 0;
    /// Verifies an ack frame from `src` for our message whose trailer starts
    /// with `bind`, or with `bindBefore` (its seal before the last reseal()).
    virtual bool openAck(const Mac& src, const uint8_t* frame, size_t len, const uint8_t* tag, const uint8_t* bind,
                         const uint8_t* bindBefore) = 0;

    enum class Screen : uint8_t {
        Normal,
        Limited,  ///< Sender without a verified epoch: one reassembly slot shared by all of them.
        Reject,   ///< Will be rejected once complete anyway (e.g. unauthenticated where required).
    };
    /// Screens a multi-frame message before reassembly takes memory for it;
    /// its tag can only be checked once it is complete. `flags` as on the wire.
    virtual Screen screen(const Mac& src, uint8_t port, uint8_t flags) const {
        (void)src;
        (void)port;
        (void)flags;
        return Screen::Normal;
    }
};

/// Platform-independent protocol engine: fragmentation, reassembly, pacing,
/// acknowledgements and retransmission.
///
/// The engine is single-threaded and does no I/O or timekeeping of its own:
/// the platform layer feeds it radio events and the current time, and calls
/// tick() periodically (every 5-10 ms is plenty). Callbacks run synchronously
/// from whichever entry point triggered them and may call back into the engine
/// (e.g. send() from a receive handler).
class Engine {
public:
    /// `firstMessageId` should be random per boot so a restarted sender is not
    /// mistaken for duplicates of its previous run.
    explicit Engine(Link& link, const Config& config = Config(), uint16_t firstMessageId = 0);
    ~Engine();

    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    /// Queues a message. The payload is copied. `done` (optional) is called once
    /// with the final outcome; it may run before send() returns.
    Status send(const Mac& dst, uint8_t port, const uint8_t* data, size_t len, const SendOptions& options,
                CompletionHandler done, uint32_t nowMs);
    /// Like send(), but takes `buffer`: a malloc()ed block of `capacity` bytes
    /// whose first `len` are the payload. With capacity >= len + kSendOverhead
    /// it is used without a copy; otherwise it is realloc()ed. It is freed in
    /// every case, including when an error is returned.
    Status sendBuffer(const Mac& dst, uint8_t port, uint8_t* buffer, size_t len, size_t capacity,
                      const SendOptions& options, CompletionHandler done, uint32_t nowMs);

    /// Sets the handler for messages arriving on `port`; an empty handler removes it.
    /// Messages for ports without a handler are dropped (reliable ones are rejected).
    void listen(uint8_t port, ReceiveHandler handler);

    /// Feeds one frame received from the radio. `rssi` is in dBm, 0 if unknown;
    /// `timestampUs` is the local clock when the radio delivered it, 0 if unknown.
    void onFrameReceived(const Mac& src, const uint8_t* data, size_t len, uint32_t nowMs, int8_t rssi = 0,
                         uint64_t timestampUs = 0);

    /// Reports the outcome of the last frame accepted by Link::sendFrame().
    /// `delivered` is the radio's view: MAC-level ack for unicast, always true for broadcast.
    void onFrameSent(bool delivered, uint32_t nowMs);

    /// Drives timeouts and retransmissions.
    void tick(uint32_t nowMs);

    /// Sees every received frame before filtering (other network ids, other
    /// protocol versions, non-NowTP ESP-NOW traffic). For diagnostics; one at a time.
    void setFrameObserver(FrameObserver observer) { observer_ = std::move(observer); }

    /// Authenticates outgoing messages and checks incoming ones (null: none).
    void setAuthenticator(Authenticator* auth) { auth_ = auth; }
    /// True when outgoing messages on `port` are authenticated (a key is installed).
    bool authenticates(uint8_t port) const { return auth_ && auth_->sealing(port); }
    /// Seals the authenticated messages queued for `dst` again, with fresh
    /// sequence numbers. Called by Security after answering dst's challenge:
    /// dst then accepts only numbers above the one we reported.
    void reseal(const Mac& dst);

    /// Fails every outgoing message with `reason` and drops partial incoming ones.
    void cancelAll(Status reason = Status::Cancelled);

    const Config& config() const { return config_; }
    const Stats& stats() const { return stats_; }

    /// Outgoing messages queued or awaiting acknowledgement.
    size_t pendingMessages() const { return tx_.size(); }

    /// Largest message on `port` that fits in a single frame to `dst`.
    size_t singleFramePayload(const Mac& dst, uint8_t port = 0) const;

private:
    struct TxMessage;
    struct RxMessage;

    // Objects from malloc, like Bytes: `new (std::nothrow)` aborts on a short
    // heap with exceptions off.
    template <class T>
    struct FreeObject {
        void operator()(T* p) const {
            if (!p) return;
            p->~T();
            std::free(p);
        }
    };
    template <class T>
    using Owned = std::unique_ptr<T, FreeObject<T>>;
    template <class T>
    static Owned<T> create();

    static constexpr size_t kMaxControlFrames = 8;

    struct Control {
        Mac dst;
        uint16_t messageId;
        Bytes frame;  // malloc'd, `len` bytes
        size_t len;
    };

    struct Recent {
        Mac src;
        uint8_t port;
        uint8_t flags;
        uint16_t messageId;
        uint32_t at;
        bool used;
        bool bound;  // `bind` holds the message's epoch and sequence
        uint8_t bind[wire::kAckBindSize];
    };

    // A destination whose frames failed: served again only after `retryAt`
    // while others have frames to send.
    struct Backoff {
        Mac dst;
        uint8_t failures;
        uint32_t retryAt;
    };

    struct InFlight {
        bool active = false;
        bool control = false;
        bool firstPass = false;
        bool ackRequest = false;
        TxMessage* msg = nullptr;  // null once the message finished while its frame was in flight
        uint16_t index = 0;
        uint32_t deadline = 0;
    };

    void pump(uint32_t now);
    TxMessage* nextMessage(uint32_t now);
    Backoff* backoff(const Mac& dst);
    size_t buildFrame(const TxMessage& tx, uint16_t index, bool ackRequest);
    void frameSent(bool delivered, uint32_t now);
    Status queue(const Mac& dst, uint8_t port, const uint8_t* data, Bytes owned, size_t len, size_t capacity,
                 const SendOptions& options, CompletionHandler done, uint32_t now);
    void finish(TxMessage* tx, Status status);
    void flushCompletions();

    void handleSingle(const Mac& src, const wire::Header& h, const uint8_t* payload, size_t len, uint32_t now);
    void handleFragment(const Mac& src, const wire::Header& h, const uint8_t* payload, size_t len, uint32_t now);
    void handleAck(const Mac& src, const wire::Header& h, const uint8_t* payload, size_t len, uint32_t now);

    enum class Place : uint8_t { Ok, Invalid, TooLarge, NoMemory };
    Place placeFragment(RxMessage& rx, uint16_t index, const uint8_t* payload, size_t len);
    Place allocateRxBuffer(RxMessage& rx, uint16_t fragSize);
    enum class Admission : uint8_t { Yes, Busy, Never };
    Admission admitRx(const Mac& src, uint16_t index, uint16_t count, size_t len, bool limited, uint32_t now);
    bool reserveRx(size_t bytes);
    RxMessage* findRx(const Mac& src, uint16_t id);
    void dropRx(RxMessage* rx, bool countAsDropped = true);
    void completeRx(RxMessage* rx, uint32_t now);
    void deliver(const Mac& src, uint8_t port, uint8_t flags, const uint8_t* data, size_t len, int8_t rssi,
                 uint64_t timestampUs, bool authenticated, uint8_t* buffer = nullptr);
    enum class Auth : uint8_t { Accept, Reject, Retry };
    Auth authorize(const Mac& src, uint8_t port, uint8_t flags, const uint8_t* data, size_t& len, bool& authenticated,
                   uint32_t now);
    bool hasListener(uint8_t port) const;
    /// Largest reassembled stream accepted: message, trailer and CRC.
    size_t maxStream() const { return config_.maxMessageSize + wire::kAuthTrailerSize + wire::kCrcSize; }

    void remember(const Mac& src, uint8_t port, uint8_t flags, uint16_t id, const uint8_t* bind, uint32_t now);
    const Recent* findRecent(const Mac& src, uint16_t id, uint32_t now) const;
    bool isStaleLatest(const Mac& src, uint8_t port, uint16_t id, uint32_t now) const;
    void dropOlderLatest(const Mac& src, uint8_t port, uint16_t id);

    void queueAck(const Mac& dst, uint8_t port, uint16_t id, uint8_t flags, wire::AckStatus status,
                  const RxMessage* missing, const uint8_t* bind = nullptr);
    Control& control(size_t i) { return control_[(controlHead_ + i) % kMaxControlFrames]; }
    void popControl();

    Link& link_;
    Config config_;
    Stats stats_;
    uint16_t nextId_;

    // Fixed capacities, reserved up front: nothing on the send or receive
    // path grows a container (an allocation failure would abort).
    std::vector<Owned<TxMessage>> tx_;
    std::vector<Owned<RxMessage>> rx_;
    Control control_[kMaxControlFrames];  // ring of acks to send
    size_t controlHead_ = 0;
    size_t controlCount_ = 0;
    std::vector<Recent> recent_;
    size_t recentNext_ = 0;
    std::vector<std::pair<uint8_t, ReceiveHandler>> listeners_;
    TxMessage* doneHead_ = nullptr;  // finished messages whose handler is still to run
    TxMessage* doneTail_ = nullptr;
    std::vector<uint8_t> frame_;

    std::vector<Backoff> backoffs_;
    Mac lastDst_{};  // destination of the last data frame, for round-robin
    InFlight inflight_;
    size_t txBytes_ = 0;
    size_t rxBytes_ = 0;
    bool linkBusy_ = false;
    uint32_t linkBusyUntil_ = 0;
    bool pumping_ = false;
    bool flushing_ = false;
    int8_t rxRssi_ = 0;  // RSSI of the frame being processed
    uint64_t rxTimeUs_ = 0;
    FrameObserver observer_;
    Authenticator* auth_ = nullptr;
};

}  // namespace nowtp
