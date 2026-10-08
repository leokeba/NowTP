// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <deque>
#include <memory>
#include <utility>
#include <vector>

#include "link.h"
#include "types.h"
#include "wire.h"

namespace nowtp {

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

    /// Sets the handler for messages arriving on `port`; an empty handler removes it.
    /// Messages for ports without a handler are dropped (reliable ones are rejected).
    void listen(uint8_t port, ReceiveHandler handler);

    /// Feeds one frame received from the radio. `rssi` is in dBm, 0 if unknown.
    void onFrameReceived(const Mac& src, const uint8_t* data, size_t len, uint32_t nowMs, int8_t rssi = 0);

    /// Reports the outcome of the last frame accepted by Link::sendFrame().
    /// `delivered` is the radio's view: MAC-level ack for unicast, always true for broadcast.
    void onFrameSent(bool delivered, uint32_t nowMs);

    /// Drives timeouts and retransmissions.
    void tick(uint32_t nowMs);

    /// Fails every outgoing message with `reason` and drops partial incoming ones.
    void cancelAll(Status reason = Status::Cancelled);

    const Config& config() const { return config_; }
    const Stats& stats() const { return stats_; }

    /// Outgoing messages queued or awaiting acknowledgement.
    size_t pendingMessages() const { return tx_.size(); }

    /// Largest message that fits in a single frame to `dst`.
    size_t singleFramePayload(const Mac& dst) const;

private:
    struct TxMessage;
    struct RxMessage;

    struct Control {
        Mac dst;
        uint16_t messageId;
        std::vector<uint8_t> frame;
    };

    struct Recent {
        Mac src;
        uint8_t port;
        uint8_t flags;
        uint16_t messageId;
        uint32_t at;
        bool used;
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
    size_t buildFrame(const TxMessage& tx, uint16_t index, bool ackRequest);
    void frameSent(bool delivered, uint32_t now);
    void finish(TxMessage* tx, Status status);
    void flushCompletions();

    void handleSingle(const Mac& src, const wire::Header& h, const uint8_t* payload, size_t len, uint32_t now);
    void handleFragment(const Mac& src, const wire::Header& h, const uint8_t* payload, size_t len, uint32_t now);
    void handleAck(const Mac& src, const wire::Header& h, const uint8_t* payload, size_t len, uint32_t now);

    enum class Place : uint8_t { Ok, Invalid, TooLarge, NoMemory };
    Place placeFragment(RxMessage& rx, uint16_t index, const uint8_t* payload, size_t len);
    Place allocateRxBuffer(RxMessage& rx, uint16_t fragSize);
    bool reserveRx(size_t bytes, const RxMessage* keep);
    RxMessage* findRx(const Mac& src, uint16_t id);
    void dropRx(RxMessage* rx, bool countAsDropped = true);
    void completeRx(RxMessage* rx, uint32_t now);
    void deliver(const Mac& src, uint8_t port, uint8_t flags, const uint8_t* data, size_t len, int8_t rssi);
    bool hasListener(uint8_t port) const;

    void remember(const Mac& src, uint8_t port, uint8_t flags, uint16_t id, uint32_t now);
    bool isRecent(const Mac& src, uint16_t id, uint32_t now) const;
    bool isStaleLatest(const Mac& src, uint8_t port, uint16_t id, uint32_t now) const;
    void dropOlderLatest(const Mac& src, uint8_t port, uint16_t id);

    void queueAck(const Mac& dst, uint8_t port, uint16_t id, wire::AckStatus status, const RxMessage* missing);

    Link& link_;
    Config config_;
    Stats stats_;
    uint16_t nextId_;

    std::vector<std::unique_ptr<TxMessage>> tx_;
    std::vector<std::unique_ptr<RxMessage>> rx_;
    std::deque<Control> control_;
    std::vector<Recent> recent_;
    size_t recentNext_ = 0;
    std::vector<std::pair<uint8_t, ReceiveHandler>> listeners_;
    std::vector<std::pair<CompletionHandler, Status>> completions_;
    std::vector<uint8_t> frame_;

    InFlight inflight_;
    size_t txBytes_ = 0;
    size_t rxBytes_ = 0;
    bool linkBusy_ = false;
    uint32_t linkBusyUntil_ = 0;
    bool pumping_ = false;
    bool flushing_ = false;
    int8_t rxRssi_ = 0;  // RSSI of the frame being processed
};

}  // namespace nowtp
