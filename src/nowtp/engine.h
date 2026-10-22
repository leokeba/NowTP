// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdlib>
#include <memory>
#include <utility>
#include <vector>

#include "callback.h"
#include "deadline.h"
#include "heap.h"
#include "link.h"
#include "table.h"
#include "types.h"
#include "wire.h"

namespace nowtp {

// Heap buffers from malloc, which returns null on a short heap. `new
// (std::nothrow)` doesn't: with exceptions off (ESP-IDF), libstdc++'s nothrow
// operator new calls the throwing one, whose throw aborts.
struct FreeBytes {
    void operator()(uint8_t* p) const { heap::release(p); }
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
/// `src` was heard: see Engine::setHeardObserver().
using HeardObserver = std::function<void(const Mac& src, bool authenticated, uint32_t nowMs)>;
/// A single-frame message went out: see Engine::setSentObserver().
using SentObserver = std::function<void(const Mac& dst, uint8_t port, uint32_t messageId, uint64_t sentUs)>;

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

    /// A reliable message open() found Authentic was refused by its receive
    /// handler, and its sender will send it again. `bind` is the start of its
    /// trailer (epoch and sequence): that sequence number may be accepted once more.
    virtual void refused(const Mac& src, const uint8_t* bind) {
        (void)src;
        (void)bind;
    }

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
    /// `messageId`, if given, receives the message's id (see setSentObserver()).
    Status send(const Mac& dst, uint8_t port, const uint8_t* data, size_t len, const SendOptions& options,
                CompletionHandler done, uint32_t nowMs, uint32_t* messageId = nullptr);
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
    /// `sentUs` is the local clock when the radio reported it, 0 if unknown.
    void onFrameSent(bool delivered, uint32_t nowMs, uint64_t sentUs = 0);

    /// Drives timeouts and retransmissions.
    void tick(uint32_t nowMs);
    /// Adds when tick() has work next to `d`: a frame the radio never
    /// reported, an ack timeout, a message deadline, a send to retry. Frames
    /// received and sent bring their own work; nothing is added for them.
    void nextTick(Deadline& d) const;
    /// The time passed to the latest call into the engine: during a callback,
    /// the time of the event that triggered it. Services timestamp what their
    /// handlers do with it, however long ago their own tick() ran.
    uint32_t now() const { return now_; }

    /// Sees every received frame before filtering (other network ids, other
    /// protocol versions, non-NowTP ESP-NOW traffic). For diagnostics; one at a time.
    void setFrameObserver(FrameObserver observer) { observer_.set(std::move(observer)); }
    /// Called for each message accepted from `src` (past authentication when a
    /// key is installed; `authenticated` when verified with it), and for each
    /// ack to one of our reliable messages (`authenticated` when its tag
    /// verified). Discovery sets it, so that a peer whose announcements go
    /// missing while it exchanges messages with us isn't reported lost. One at a time.
    void setHeardObserver(HeardObserver observer) { heard_.set(std::move(observer)); }
    /// Called when the radio reports a single-frame message of ours delivered,
    /// with the time it reported it (see onFrameSent()): time sync stamps its
    /// exchanges with it. One at a time.
    void setSentObserver(SentObserver observer) { sent_.set(std::move(observer)); }

    /// Opened around application callbacks: receive handlers on ports below
    /// kFirstReservedPort, and completions of messages sent on them (null:
    /// none). NowTP's own services, on the reserved ports, run inside.
    void setCallbackGate(CallbackGate* gate) { gate_ = gate; }
    CallbackGate* callbackGate() const { return gate_; }

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

    /// Heap held for messages right now: what the queue and reassembly limits
    /// count. Fixed buffers (the frame being built, tables) are not included.
    struct MemoryUse {
        size_t txMessages = 0;  ///< Queued or awaiting their ack.
        size_t txBytes = 0;     ///< Their payloads, with CRC and trailer.
        size_t rxMessages = 0;  ///< Being reassembled.
        size_t rxBytes = 0;     ///< Reserved for them (whole buffers once the fragment size is known).
    };
    MemoryUse memory() const {
        MemoryUse m;
        m.txMessages = tx_.size();
        m.txBytes = txBytes_;
        m.rxMessages = rx_.size();
        m.rxBytes = rxBytes_;
        return m;
    }

    /// Largest message on `port` that fits in a single frame to `dst`.
    size_t singleFramePayload(const Mac& dst, uint8_t port = 0) const;

    /// The largest message `peer` accepts (its Config::maxMessageSize, as it
    /// announces it), so that send() refuses a larger one with TooLarge at
    /// once, instead of the receiver rejecting it. 0 forgets it. Discovery
    /// sets it; at most kMaxPeerLimits peers are known at once.
    void setPeerMessageLimit(const Mac& peer, size_t maxMessageSize);
    /// 0 if unknown (no limit is applied then).
    size_t peerMessageLimit(const Mac& peer) const;
    static constexpr size_t kMaxPeerLimits = 32;

private:
    struct TxMessage;
    struct RxMessage;

    // Objects from malloc, like Bytes: `new (std::nothrow)` aborts on a short
    // heap with exceptions off.
    template <class T>
    using Owned = heap::Owned<T>;

    static constexpr size_t kMaxControlFrames = 8;

    struct Control {
        Mac dst;
        uint16_t messageId;
        Bytes frame;  // malloc'd, `len` bytes
        size_t len;
    };

    struct Recent {  // 24 bytes, packed by hand
        uint32_t at;
        uint16_t messageId;
        uint8_t port;
        uint8_t flags;
        Mac src;
        bool used;
        bool bound;  // `bind` holds the message's epoch and sequence
        uint8_t bind[wire::kAckBindSize];
    };

    // Message ids delivered from one sender, so a duplicate is recognized
    // however many other senders' messages arrived since. Ids fall in
    // kSeenBlocks blocks of 32 (block id / 32 at slot (id / 32) % kSeenBlocks),
    // ending with the block of the newest id. A block's bits count for
    // recentTtlMs after its last delivery, as entries of `recent_` do.
    static constexpr uint16_t kSeenBlocks = 4;
    struct Seen {  // 44 bytes
        Mac src;
        uint16_t top;   // newest id delivered
        uint32_t last;  // last delivery
        uint32_t bits[kSeenBlocks];
        uint32_t at[kSeenBlocks];  // last delivery in each block
    };

    struct PeerLimit {
        Mac peer;
        size_t maxMessageSize;
    };

    // A destination whose frames failed: served again only after `retryAt`
    // while others have frames to send.
    struct Backoff {
        Mac dst;
        uint8_t failures;
        uint32_t retryAt;
    };

    // Room a receiver said it has for our next message, less what we started
    // since (Config::receiverCredit). Good for creditTtl().
    struct Credit {
        Mac dst;
        uint32_t room;  // bytes; UINT32_MAX: plenty
        uint32_t at;
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
    Credit* credit(const Mac& dst);
    const Credit* credit(const Mac& dst) const;
    uint32_t creditTtl() const { return 3 * config_.ackTimeoutMs + 1; }
    /// True while `tx` may not start: its receiver said it has no room for it.
    /// `until` receives when that word expires.
    bool waitsForCredit(const TxMessage& tx, uint32_t now, uint32_t* until = nullptr) const;
    void noteCredit(const Mac& dst, uint8_t units, uint32_t now);
    void spendCredit(const TxMessage& tx);
    /// What we tell `src` in an ack: room for its next message, in kCreditUnit.
    uint8_t creditFor(const Mac& src, uint32_t now) const;
    size_t buildFrame(const TxMessage& tx, uint16_t index, bool ackRequest);
    void frameSent(bool delivered, uint32_t now, uint64_t sentUs);
    Status queue(const Mac& dst, uint8_t port, const uint8_t* data, Bytes owned, size_t len, size_t capacity,
                 const SendOptions& options, CompletionHandler done, uint32_t now, uint32_t* messageId = nullptr);
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
    enum class Delivery : uint8_t { Taken, Refused, NoListener };
    Delivery deliver(const Mac& src, uint8_t port, uint8_t flags, const uint8_t* data, size_t len, int8_t rssi,
                     uint64_t timestampUs, bool authenticated, uint8_t* buffer = nullptr);
    /// Records a delivered message, or answers one the handler refused, and
    /// queues the ack a reliable sender needs.
    void delivered(Delivery d, const Mac& src, uint8_t port, uint8_t flags, uint16_t id, const uint8_t* bind,
                   uint32_t now);
    enum class Auth : uint8_t { Accept, Reject, Retry };
    Auth authorize(const Mac& src, uint8_t port, uint8_t flags, const uint8_t* data, size_t& len, bool& authenticated,
                   uint32_t now);
    bool hasListener(uint8_t port) const;
    /// Largest reassembled stream accepted: message, trailer and CRC.
    size_t maxStream() const { return config_.maxMessageSize + wire::kAuthTrailerSize + wire::kCrcSize; }

    void remember(const Mac& src, uint8_t port, uint8_t flags, uint16_t id, const uint8_t* bind, uint32_t now);
    const Recent* findRecent(const Mac& src, uint16_t id, uint32_t now) const;
    /// True if message `id` from `src` was delivered recently. `bind` is set
    /// to its epoch and sequence when remembered (authenticated messages).
    bool isDuplicate(const Mac& src, uint16_t id, uint32_t now, const uint8_t*& bind) const;
    void markSeen(const Mac& src, uint16_t id, uint32_t now);
    bool wasSeen(const Mac& src, uint16_t id, uint32_t now) const;
    bool isStaleLatest(const Mac& src, uint8_t port, uint16_t id, uint32_t now) const;
    void dropOlderLatest(const Mac& src, uint8_t port, uint16_t id);

    /// `full`: say there's no room, whatever reassembly has (a handler refused).
    void queueAck(const Mac& dst, uint8_t port, uint16_t id, uint8_t flags, wire::AckStatus status,
                  const RxMessage* missing, const uint8_t* bind = nullptr, bool full = false);
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
    Table<Seen> seen_;  // memory per sender heard, not reserved for recentSenders
    Table<PeerLimit> limits_;
    std::vector<std::pair<uint8_t, Callback<void(const Message&)>>> listeners_;
    TxMessage* doneHead_ = nullptr;  // finished messages whose handler is still to run
    TxMessage* doneTail_ = nullptr;
    Bytes frame_;  // the frame being built, malloc'd at the largest size used
    size_t frameCapacity_ = 0;

    std::vector<Backoff> backoffs_;
    std::vector<Credit> credits_;
    Mac lastDst_{};  // destination of the last data frame, for round-robin
    InFlight inflight_;
    size_t txBytes_ = 0;
    size_t rxBytes_ = 0;
    bool linkBusy_ = false;
    uint32_t linkBusyUntil_ = 0;
    bool pumping_ = false;
    bool flushing_ = false;
    uint32_t now_ = 0;   // see now()
    int8_t rxRssi_ = 0;  // RSSI of the frame being processed
    uint64_t rxTimeUs_ = 0;
    Callback<void(const FrameInfo&)> observer_;
    Callback<void(const Mac&, bool, uint32_t)> heard_;
    Callback<void(const Mac&, uint8_t, uint32_t, uint64_t)> sent_;
    Authenticator* auth_ = nullptr;
    CallbackGate* gate_ = nullptr;
};

}  // namespace nowtp
