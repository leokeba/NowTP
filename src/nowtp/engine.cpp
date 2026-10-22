// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "engine.h"

#include <algorithm>
#include <cstdlib>
#include <new>

namespace nowtp {

using namespace wire;

namespace {

// Wrap-safe "now has reached deadline".
inline bool reached(uint32_t now, uint32_t deadline) {
    return static_cast<int32_t>(now - deadline) >= 0;
}

// True if message id `a` is older than `b` by less than `window`.
inline bool olderWithin(uint16_t a, uint16_t b, uint16_t window) {
    uint16_t d = static_cast<uint16_t>(b - a);
    return d != 0 && d < window;
}

// Late frames of a superseded message are at most a few ids behind; anything
// further back is more likely a rebooted sender and is accepted.
constexpr uint16_t kStaleWindow = 256;
constexpr size_t kAckHeaderSize = kCommonHeaderSize + 1;  // + status byte
// Backoff of a destination whose frames fail, doubling per failure. A failed
// unicast frame holds the radio ~100 ms (hardware retries), so an absent peer
// served in turn would still take most of the airtime.
constexpr uint32_t kBackoffMinMs = 50;
constexpr uint32_t kBackoffMaxMs = 800;

}  // namespace

// Message and control frame buffers (Bytes, engine.h): null on a short heap.
static Bytes allocBytes(size_t n) { return Bytes(static_cast<uint8_t*>(heap::allocate(n == 0 ? 1 : n))); }
static Bytes allocZeroed(size_t n) {
    Bytes b = allocBytes(n);
    if (b) memset(b.get(), 0, n == 0 ? 1 : n);
    return b;
}

constexpr size_t Engine::kMaxControlFrames;
constexpr uint16_t Engine::kSeenBlocks;
constexpr size_t Engine::kMaxPeerLimits;

const char* toString(Status s) {
    switch (s) {
        case Status::Ok: return "Ok";
        case Status::InvalidArgument: return "InvalidArgument";
        case Status::InvalidState: return "InvalidState";
        case Status::TooLarge: return "TooLarge";
        case Status::QueueFull: return "QueueFull";
        case Status::NoMemory: return "NoMemory";
        case Status::LinkError: return "LinkError";
        case Status::SendFailed: return "SendFailed";
        case Status::Timeout: return "Timeout";
        case Status::Rejected: return "Rejected";
        case Status::Superseded: return "Superseded";
        case Status::Cancelled: return "Cancelled";
        case Status::AuthFailed: return "AuthFailed";
    }
    return "Unknown";
}

struct Engine::TxMessage {
    Mac dst;
    uint8_t port = 0;
    uint8_t flags = 0;  // kFlagReliable | kFlagLatest
    uint16_t id = 0;
    uint16_t count = 1;     // 1 = single frame
    uint16_t fragSize = 0;  // stream bytes per fragment when count > 1
    size_t streamLen = 0;   // payload, plus CRC-32 when count > 1
    size_t trailerAt = 0;   // offset of the authentication trailer (with kFlagAuth)
    bool hasBindBefore = false;
    uint8_t bindBefore[kAckBindSize];  // the trailer's start before the last reseal()
    Bytes stream;
    uint16_t nextIndex = 0;  // next fragment of the first pass
    Bytes resend;            // bitmap of fragments to send again, allocated on first use
    uint16_t resendCount = 0;
    bool awaitingAck = false;
    uint32_t ackDeadline = 0;
    uint32_t deadline = 0;
    uint8_t frameFailures = 0;
    CompletionHandler done;
    Status result = Status::Ok;  // once finished
    TxMessage* nextDone = nullptr;

    bool reliable() const { return (flags & kFlagReliable) != 0; }
    bool latest() const { return (flags & kFlagLatest) != 0; }
    bool firstPassPending() const { return nextIndex < count; }
    bool hasPendingFrame() const { return firstPassPending() || resendCount > 0; }
    bool resending(uint16_t i) const { return resend && ((resend[i >> 3] >> (i & 7)) & 1); }
    uint16_t pendingFrame() const {
        if (firstPassPending()) return nextIndex;
        for (uint16_t i = 0; i < count; ++i) {
            if (resending(i)) return i;
        }
        return 0;
    }
    bool isLastPending() const {
        return firstPassPending() ? (nextIndex + 1 == count && resendCount == 0) : resendCount == 1;
    }
    // Without memory for the bitmap, the fragment is not queued: the probe
    // after the ack timeout asks the receiver again.
    void addResend(uint16_t index) {
        if (index >= count) return;
        if (firstPassPending() && index >= nextIndex) return;  // first pass will send it anyway
        if (!resend) resend = allocZeroed((static_cast<size_t>(count) + 7) / 8);
        if (!resend || resending(index)) return;
        resend[index >> 3] = static_cast<uint8_t>(resend[index >> 3] | (1u << (index & 7)));
        resendCount++;
    }
    void sentResend(uint16_t index) {
        if (!resending(index)) return;
        resend[index >> 3] = static_cast<uint8_t>(resend[index >> 3] & ~(1u << (index & 7)));
        resendCount--;
    }
    void clearResend() {
        resend.reset();
        resendCount = 0;
    }
};

struct Engine::RxMessage {
    Mac src;
    uint8_t port = 0;
    uint8_t flags = 0;
    uint16_t id = 0;
    uint16_t count = 0;
    uint16_t received = 0;
    uint16_t fragSize = 0;  // learned from the first non-last fragment
    bool limited = false;   // its sender has no verified epoch (Authenticator::screen)
    Bytes buf;
    Bytes bitmap;
    Bytes stashedLast;  // last fragment, held until fragSize is known (lastLen bytes)
    size_t lastLen = 0;
    size_t reserved = 0;  // bytes counted in rxBytes_
    uint32_t lastActivity = 0;
    int8_t rssi = 0;
    uint64_t timeUs = 0;

    bool has(uint16_t i) const { return (bitmap[i >> 3] >> (i & 7)) & 1; }
    void mark(uint16_t i) { bitmap[i >> 3] |= static_cast<uint8_t>(1u << (i & 7)); }
};

Engine::Engine(Link& link, const Config& config, uint16_t firstMessageId)
    : link_(link), config_(config), nextId_(firstMessageId), seen_(config.recentSenders), limits_(kMaxPeerLimits) {
    if (config_.recentEntries == 0) config_.recentEntries = 1;
    if (config_.sendTimeoutMs == 0) config_.sendTimeoutMs = 1;
    recent_.resize(config_.recentEntries);
    for (Recent& r : recent_) r.used = false;
    tx_.reserve(config_.maxTxMessages);
    rx_.reserve(config_.maxRxMessages);
    backoffs_.reserve(config_.maxTxMessages);
}

Engine::~Engine() {
    while (doneHead_) {
        Owned<TxMessage> done(doneHead_);
        doneHead_ = doneHead_->nextDone;
    }
}

size_t Engine::singleFramePayload(const Mac& dst, uint8_t port) const {
    size_t mtu = link_.maxFrameSize(dst);
    size_t overhead = kCommonHeaderSize + (auth_ && auth_->sealing(port) ? kAuthTrailerSize : 0);
    return mtu > overhead ? mtu - overhead : 0;
}

void Engine::setPeerMessageLimit(const Mac& peer, size_t maxMessageSize) {
    for (size_t i = 0; i < limits_.size(); ++i) {
        if (!(limits_[i].peer == peer)) continue;
        if (maxMessageSize) {
            limits_[i].maxMessageSize = maxMessageSize;
        } else {
            limits_.erase(i);
        }
        return;
    }
    if (!maxMessageSize || peer.isBroadcast()) return;
    PeerLimit l = {peer, maxMessageSize};
    limits_.add(l);  // full or no memory: unknown, as before
}

size_t Engine::peerMessageLimit(const Mac& peer) const {
    for (const PeerLimit& l : limits_) {
        if (l.peer == peer) return l.maxMessageSize;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Sending

Status Engine::send(const Mac& dst, uint8_t port, const uint8_t* data, size_t len, const SendOptions& options,
                    CompletionHandler done, uint32_t now, uint32_t* messageId) {
    if (data == nullptr && len > 0) return Status::InvalidArgument;
    return queue(dst, port, data, Bytes(), len, 0, options, std::move(done), now, messageId);
}

Status Engine::sendBuffer(const Mac& dst, uint8_t port, uint8_t* buffer, size_t len, size_t capacity,
                          const SendOptions& options, CompletionHandler done, uint32_t now) {
    Bytes owned(buffer);
    if (!owned || capacity < len) return Status::InvalidArgument;
    return queue(dst, port, nullptr, std::move(owned), len, capacity, options, std::move(done), now);
}

// The payload is `data`, copied, or the first `len` bytes of `owned`.
Status Engine::queue(const Mac& dst, uint8_t port, const uint8_t* data, Bytes owned, size_t len, size_t capacity,
                     const SendOptions& options, CompletionHandler done, uint32_t now, uint32_t* messageId) {
    now_ = now;
    if (options.reliable && dst.isBroadcast()) return Status::InvalidArgument;
    if (len > config_.maxMessageSize) return Status::TooLarge;
    size_t peerLimit = peerMessageLimit(dst);
    if (peerLimit && len > peerLimit) return Status::TooLarge;  // the receiver would reject it

    size_t mtu = link_.maxFrameSize(dst);
    if (mtu <= kFragmentHeaderSize) return Status::InvalidArgument;

    uint8_t flags = static_cast<uint8_t>((options.reliable ? kFlagReliable : 0) | (options.latestOnly ? kFlagLatest : 0));
    // Authenticated messages carry a trailer after the payload (see Security).
    size_t trailer = auth_ && auth_->sealing(port) ? kAuthTrailerSize : 0;
    size_t payloadLen = len + trailer;
    uint16_t count = 1;
    uint16_t fragSize = 0;
    size_t streamLen = payloadLen;
    if (payloadLen > mtu - kCommonHeaderSize) {
        fragSize = static_cast<uint16_t>(mtu - kFragmentHeaderSize);
        streamLen = payloadLen + kCrcSize;
        size_t n = (streamLen + fragSize - 1) / fragSize;
        if (n > 0xFFFF) return Status::TooLarge;
        count = static_cast<uint16_t>(n);
    }

    // A newer latest-only message replaces older ones before queue limits apply,
    // so a fast producer never fills the queue with stale data.
    if (options.latestOnly) {
        for (size_t i = 0; i < tx_.size();) {
            TxMessage* old = tx_[i].get();
            if (old->latest() && old->port == port && old->dst == dst) {
                finish(old, Status::Superseded);
                continue;
            }
            ++i;
        }
    }

    size_t peerMessages = 0, peerBytes = 0;
    for (const auto& t : tx_) {
        if (!(t->dst == dst)) continue;
        peerMessages++;
        peerBytes += t->streamLen;
    }
    if (tx_.size() >= config_.maxTxMessages || txBytes_ + streamLen > config_.maxTxBytes ||
        peerMessages >= config_.maxTxMessagesPerPeer || peerBytes + streamLen > config_.maxTxBytesPerPeer) {
        flushCompletions();
        return Status::QueueFull;
    }

    Bytes stream;
    if (owned) {
        if (capacity >= streamLen) {
            stream = std::move(owned);
        } else {
            uint8_t* grown = static_cast<uint8_t*>(heap::reallocate(owned.get(), streamLen));
            if (grown) {
                owned.release();  // moved into `grown`
                stream.reset(grown);
            }
        }
    } else {
        stream = allocBytes(streamLen);
        if (stream && len > 0) memcpy(stream.get(), data, len);
    }
    Owned<TxMessage> tx = heap::make<TxMessage>();
    if (!stream || !tx) {
        flushCompletions();
        return Status::NoMemory;
    }
    tx->dst = dst;
    tx->port = port;
    tx->flags = flags;
    tx->count = count;
    tx->fragSize = fragSize;
    tx->streamLen = streamLen;
    tx->stream = std::move(stream);
    if (trailer) {
        auth_->seal(dst, port, tx->flags, tx->stream.get(), len, tx->stream.get() + len);
        tx->flags = static_cast<uint8_t>(tx->flags | kFlagAuth);
        tx->trailerAt = len;
    }
    if (count > 1) putU32(tx->stream.get() + payloadLen, crc32(tx->stream.get(), payloadLen));

    tx->id = nextId_++;
    if (messageId) *messageId = tx->id;
    tx->deadline = now + (options.timeoutMs ? options.timeoutMs : config_.sendTimeoutMs);
    tx->done = std::move(done);
    txBytes_ += tx->streamLen;
    tx_.push_back(std::move(tx));  // within the reserved capacity

    pump(now);
    flushCompletions();
    return Status::Ok;
}

// 0 if there is no memory for the frame buffer.
size_t Engine::buildFrame(const TxMessage& tx, uint16_t index, bool ackRequest) {
    size_t mtu = link_.maxFrameSize(tx.dst);
    if (frameCapacity_ < mtu) {
        // As large as the largest frame sent so far (1470 bytes with v2 peers).
        Bytes bigger = allocBytes(mtu);
        if (!bigger) return 0;
        frame_ = std::move(bigger);
        frameCapacity_ = mtu;
    }

    Header h;
    h.type = tx.count > 1 ? Type::Fragment : Type::Single;
    h.flags = static_cast<uint8_t>(tx.flags | (ackRequest ? kFlagAckRequest : 0));
    h.networkId = config_.networkId;
    h.port = tx.port;
    h.messageId = tx.id;
    h.index = index;
    h.count = tx.count;
    size_t off = encodeHeader(h, frame_.get());

    size_t start = tx.count > 1 ? static_cast<size_t>(index) * tx.fragSize : 0;
    size_t n = tx.count > 1 ? std::min<size_t>(tx.fragSize, tx.streamLen - start) : tx.streamLen;
    if (n > 0) memcpy(frame_.get() + off, tx.stream.get() + start, n);
    return off + n;
}

void Engine::pump(uint32_t now) {
    if (pumping_) return;
    pumping_ = true;

    while (!inflight_.active) {
        if (linkBusy_) {
            if (!reached(now, linkBusyUntil_)) break;
            linkBusy_ = false;
        }

        // Control frames (acks) go first: they unblock the peer's sender.
        if (controlCount_ > 0) {
            Control& c = control(0);
            inflight_ = InFlight();
            inflight_.active = true;
            inflight_.control = true;
            inflight_.deadline = now + config_.frameSentTimeoutMs;
            Status st = link_.sendFrame(c.dst, c.frame.get(), c.len);
            if (st == Status::QueueFull) {
                inflight_.active = false;
                linkBusy_ = true;
                linkBusyUntil_ = now + config_.linkBusyBackoffMs;
                break;
            }
            popControl();
            if (st == Status::Ok) {
                stats_.framesSent++;
            } else {
                inflight_.active = false;
                stats_.framesFailed++;
            }
            continue;
        }

        TxMessage* tx = nextMessage(now);
        if (!tx) break;
        lastDst_ = tx->dst;

        uint16_t index = tx->pendingFrame();
        bool ackRequest = tx->reliable() && tx->isLastPending();
        size_t len = buildFrame(*tx, index, ackRequest);
        if (len == 0) {  // short heap: try again shortly
            linkBusy_ = true;
            linkBusyUntil_ = now + config_.linkBusyBackoffMs;
            break;
        }

        inflight_ = InFlight();
        inflight_.active = true;
        inflight_.msg = tx;
        inflight_.index = index;
        inflight_.firstPass = tx->firstPassPending();
        inflight_.ackRequest = ackRequest;
        inflight_.deadline = now + config_.frameSentTimeoutMs;

        Status st = link_.sendFrame(tx->dst, frame_.get(), len);
        if (st == Status::QueueFull) {
            inflight_.active = false;
            linkBusy_ = true;
            linkBusyUntil_ = now + config_.linkBusyBackoffMs;
            break;
        }
        if (st != Status::Ok) {
            inflight_.active = false;
            stats_.framesFailed++;
            finish(tx, st);
            continue;
        }
        stats_.framesSent++;
        if (!inflight_.firstPass) stats_.retransmissions++;
    }

    pumping_ = false;
}

// Destinations take turns, one frame each, in the order of their oldest
// pending message; within one, messages go in order. One whose frames are
// failing waits out its backoff while others have something to send.
Engine::TxMessage* Engine::nextMessage(uint32_t now) {
    size_t n = tx_.size();
    // Start after the last served destination's current message.
    size_t start = 0;
    for (size_t i = 0; i < n; ++i) {
        if (tx_[i]->hasPendingFrame() && tx_[i]->dst == lastDst_) {
            start = i + 1;
            break;
        }
    }
    TxMessage* waiting = nullptr;  // in backoff; sent only if nothing else is
    for (size_t k = 0; k < n; ++k) {
        TxMessage* t = tx_[(start + k) % n].get();
        if (!t->hasPendingFrame()) continue;
        bool head = true;  // oldest pending message for its destination
        for (size_t j = 0; j < n && tx_[j].get() != t; ++j) {
            if (tx_[j]->hasPendingFrame() && tx_[j]->dst == t->dst) {
                head = false;
                break;
            }
        }
        if (!head) continue;
        Backoff* b = backoff(t->dst);
        if (b && !reached(now, b->retryAt)) {
            if (!waiting) waiting = t;
            continue;
        }
        return t;
    }
    return waiting;
}

Engine::Backoff* Engine::backoff(const Mac& dst) {
    for (Backoff& b : backoffs_) {
        if (b.dst == dst) return &b;
    }
    return nullptr;
}

void Engine::onFrameSent(bool delivered, uint32_t now, uint64_t sentUs) {
    now_ = now;
    frameSent(delivered, now, sentUs);
    pump(now);
    flushCompletions();
}

void Engine::frameSent(bool delivered, uint32_t now, uint64_t sentUs) {
    if (!inflight_.active) return;
    InFlight f = inflight_;
    inflight_.active = false;

    if (f.control) {
        if (!delivered) stats_.framesFailed++;
        return;
    }
    TxMessage* tx = f.msg;
    if (!tx) return;  // finished (acked, superseded, timed out) while in flight

    Backoff* b = backoff(tx->dst);
    if (!delivered) {
        stats_.framesFailed++;
        if (!b && backoffs_.size() < backoffs_.capacity()) {  // never grows (see tx_)
            Backoff fresh = {tx->dst, 0, 0};
            backoffs_.push_back(fresh);
            b = &backoffs_.back();
        }
        if (b) {
            if (b->failures < 8) b->failures++;
            b->retryAt = now + std::min(kBackoffMaxMs, kBackoffMinMs << (b->failures - 1));
        }
        if (++tx->frameFailures > config_.frameRetries) finish(tx, Status::SendFailed);
        return;  // otherwise the same frame is still pending and goes out again
    }

    if (b) backoffs_.erase(backoffs_.begin() + (b - backoffs_.data()));
    tx->frameFailures = 0;
    // Reported once the frame's bookkeeping is done: tx may be gone by then.
    bool report = sentUs != 0 && tx->count == 1 && sent_;
    Mac dst = tx->dst;
    uint8_t port = tx->port;
    uint32_t id = tx->id;
    if (f.firstPass) {
        // Not backwards: a Busy ack may have ended the first pass meanwhile.
        tx->nextIndex = std::max(tx->nextIndex, static_cast<uint16_t>(f.index + 1));
    } else {
        tx->sentResend(f.index);
    }

    if (!tx->hasPendingFrame()) {
        if (tx->reliable()) {
            if (!tx->awaitingAck) {  // already set by a Busy ack: keep its backoff
                tx->awaitingAck = true;
                tx->ackDeadline = now + config_.ackTimeoutMs;
            }
        } else {
            finish(tx, Status::Ok);
        }
    }
    if (report) sent_(dst, port, id, sentUs);
}

void Engine::finish(TxMessage* tx, Status status) {
    for (size_t i = 0; i < tx_.size(); ++i) {
        if (tx_[i].get() != tx) continue;
        if (inflight_.msg == tx) inflight_.msg = nullptr;
        txBytes_ -= tx->streamLen;
        if (status == Status::Ok) {
            stats_.messagesSent++;
        } else {
            stats_.messagesFailed++;
        }
        Owned<TxMessage> owned(std::move(tx_[i]));
        tx_.erase(tx_.begin() + static_cast<std::ptrdiff_t>(i));
        if (owned->done) {
            // The handler runs from flushCompletions(); its memory goes back now.
            owned->result = status;
            owned->stream.reset();
            owned->clearResend();
            TxMessage* t = owned.release();
            if (doneTail_) {
                doneTail_->nextDone = t;
            } else {
                doneHead_ = t;
            }
            doneTail_ = t;
        }
        return;
    }
}

void Engine::flushCompletions() {
    if (flushing_) return;
    flushing_ = true;
    // Handlers may finish more messages; they join the end of the list.
    while (doneHead_) {
        Owned<TxMessage> t(doneHead_);
        doneHead_ = t->nextDone;
        if (!doneHead_) doneTail_ = nullptr;
        t->done(t->result);
    }
    flushing_ = false;
}

void Engine::reseal(const Mac& dst) {
    if (!auth_) return;
    for (auto& t : tx_) {
        if (!(t->dst == dst) || !(t->flags & kFlagAuth) || !auth_->sealing(t->port)) continue;
        uint8_t* trailer = t->stream.get() + t->trailerAt;
        memcpy(t->bindBefore, trailer, kAckBindSize);  // an ack may still come for the old seal
        t->hasBindBefore = true;
        auth_->seal(dst, t->port, static_cast<uint8_t>(t->flags & (kFlagReliable | kFlagLatest)), t->stream.get(),
                    t->trailerAt, trailer);
        size_t payloadLen = t->trailerAt + kAuthTrailerSize;
        if (t->count > 1) putU32(t->stream.get() + payloadLen, crc32(t->stream.get(), payloadLen));
    }
}

void Engine::tick(uint32_t now) {
    now_ = now;
    if (inflight_.active && reached(now, inflight_.deadline)) {
        frameSent(false, now, 0);  // the radio never reported back; treat as lost
    }

    for (size_t i = 0; i < tx_.size();) {
        TxMessage* tx = tx_[i].get();
        if (reached(now, tx->deadline)) {
            finish(tx, Status::Timeout);
            continue;
        }
        if (tx->awaitingAck && reached(now, tx->ackDeadline)) {
            // No feedback: probe by resending the last fragment with an ack request.
            tx->awaitingAck = false;
            tx->addResend(static_cast<uint16_t>(tx->count - 1));
        }
        ++i;
    }

    // Forget a backoff once it is over and nothing is queued for its destination.
    for (size_t i = 0; i < backoffs_.size();) {
        bool queued = false;
        for (const auto& t : tx_) queued = queued || t->dst == backoffs_[i].dst;
        if (!queued && reached(now, backoffs_[i].retryAt)) {
            backoffs_.erase(backoffs_.begin() + static_cast<std::ptrdiff_t>(i));
            continue;
        }
        ++i;
    }

    for (size_t i = 0; i < rx_.size();) {
        RxMessage* rx = rx_[i].get();
        if (reached(now, rx->lastActivity + config_.rxTimeoutMs)) {
            dropRx(rx);
            continue;
        }
        ++i;
    }

    pump(now);
    flushCompletions();
}

// What tick() checks, as times. Sending needs no tick while a frame is in
// flight (its report pumps the next one) or nothing is pending.
void Engine::nextTick(Deadline& d) const {
    if (inflight_.active) d.at(inflight_.deadline);
    bool pending = controlCount_ > 0;
    for (const auto& t : tx_) {
        d.at(t->deadline);
        if (t->awaitingAck) d.at(t->ackDeadline);
        pending = pending || t->hasPendingFrame();
    }
    if (pending && !inflight_.active) d.at(linkBusy_ ? linkBusyUntil_ : d.now());
    for (const Backoff& b : backoffs_) d.at(b.retryAt);  // forgotten then, if idle
    for (const auto& r : rx_) d.at(r->lastActivity + config_.rxTimeoutMs);
}

void Engine::cancelAll(Status reason) {
    while (!tx_.empty()) finish(tx_.front().get(), reason);
    while (!rx_.empty()) dropRx(rx_.front().get(), false);
    while (controlCount_ > 0) popControl();
    flushCompletions();
}

// ---------------------------------------------------------------------------
// Receiving

void Engine::listen(uint8_t port, ReceiveHandler handler) {
    for (size_t i = 0; i < listeners_.size(); ++i) {
        if (listeners_[i].first != port) continue;
        if (handler) {
            listeners_[i].second.set(std::move(handler));
        } else {
            listeners_.erase(listeners_.begin() + static_cast<std::ptrdiff_t>(i));
        }
        return;
    }
    if (handler) listeners_.push_back(std::make_pair(port, Callback<void(const Message&)>(std::move(handler))));
}

bool Engine::hasListener(uint8_t port) const {
    for (const auto& l : listeners_) {
        if (l.first == port) return true;
    }
    return false;
}

// `buffer`, if set, is the malloc()ed buffer behind `data`: it is freed here
// unless the handler takes it (Message::buffer).
Engine::Delivery Engine::deliver(const Mac& src, uint8_t port, uint8_t flags, const uint8_t* data, size_t len,
                                 int8_t rssi, uint64_t timestampUs, bool authenticated, uint8_t* buffer) {
    Bytes owned(buffer);
    Callback<void(const Message&)> handler;
    for (const auto& l : listeners_) {
        if (l.first == port) {
            handler = l.second;  // shared, not copied: the handler may replace itself via listen()
            break;
        }
    }
    if (!handler) {
        stats_.messagesDropped++;
        return Delivery::NoListener;
    }
    Message m;
    m.src = src;
    m.port = port;
    m.data = data;
    m.len = len;
    m.reliable = (flags & kFlagReliable) != 0;
    m.latestOnly = (flags & kFlagLatest) != 0;
    m.rssi = rssi;
    m.authenticated = authenticated;
    m.timestampUs = timestampUs;
    m.buffer = owned.release();
    handler(m);
    heap::release(m.buffer);
    if (m.refused) {
        stats_.messagesRefused++;
        stats_.messagesDropped++;
        return Delivery::Refused;
    }
    stats_.messagesReceived++;
    return Delivery::Taken;
}

// Acks go out only once the handler has taken the message, so a refusal can
// still turn into "busy". A refused message isn't remembered: the sender's
// retry is delivered as new.
void Engine::delivered(Delivery d, const Mac& src, uint8_t port, uint8_t flags, uint16_t id, const uint8_t* bind,
                       uint32_t now) {
    bool reliable = (flags & kFlagReliable) != 0;
    switch (d) {
        case Delivery::Taken:
            remember(src, port, flags, id, bind, now);
            if (reliable) queueAck(src, port, id, flags, AckStatus::Complete, nullptr, bind);
            break;
        case Delivery::Refused:
            if (!reliable) break;
            if (bind && auth_) auth_->refused(src, bind);  // its sequence number comes back with the retry
            queueAck(src, port, id, flags, AckStatus::Busy, nullptr, bind);
            break;
        case Delivery::NoListener:
            if (reliable) queueAck(src, port, id, flags, AckStatus::Rejected, nullptr);
            break;
    }
}

// Splits off and checks an authentication trailer. `len` shrinks to the
// application payload.
Engine::Auth Engine::authorize(const Mac& src, uint8_t port, uint8_t flags, const uint8_t* data, size_t& len,
                               bool& authenticated, uint32_t now) {
    authenticated = false;
    const uint8_t* trailer = nullptr;
    if (flags & kFlagAuth) {
        if (len < kAuthTrailerSize) return Auth::Reject;
        len -= kAuthTrailerSize;
        trailer = data + len;
    }
    if (!auth_) return Auth::Accept;  // no key: an authenticated message is delivered as a plain one
    switch (auth_->open(src, port, static_cast<uint8_t>(flags & (kFlagReliable | kFlagLatest)), data, len, trailer,
                        now)) {
        case Authenticator::Verdict::Authentic:
            authenticated = trailer != nullptr;
            return Auth::Accept;
        case Authenticator::Verdict::Unauthenticated: return Auth::Accept;
        case Authenticator::Verdict::Retry: return Auth::Retry;
        case Authenticator::Verdict::Reject: break;
    }
    stats_.authRejected++;
    stats_.messagesDropped++;
    return Auth::Reject;
}

void Engine::onFrameReceived(const Mac& src, const uint8_t* data, size_t len, uint32_t now, int8_t rssi,
                             uint64_t timestampUs) {
    now_ = now;
    stats_.framesReceived++;
    rxRssi_ = rssi;
    rxTimeUs_ = timestampUs;
    Header h;
    size_t off = 0;
    bool decoded = data != nullptr && decodeHeader(data, len, h, off);
    if (observer_ && data != nullptr && len > 0) {
        FrameInfo info;
        info.src = src;
        info.rssi = rssi;
        info.version = static_cast<uint8_t>(data[0] >> 6);
        // Another version's header may still parse with our layout; good enough to report it.
        Header any;
        size_t anyOff = 0;
        uint8_t patched[kFragmentHeaderSize];
        info.nowtp = decoded;
        if (!decoded && len >= kCommonHeaderSize) {
            size_t n = len < sizeof(patched) ? len : sizeof(patched);
            memcpy(patched, data, n);
            patched[0] = static_cast<uint8_t>((patched[0] & 0x3F) | (kVersion << 6));
            info.nowtp = info.version != kVersion && decodeHeader(patched, n, any, anyOff);
        }
        info.header = decoded ? h : any;
        info.sameNetwork = decoded && h.networkId == config_.networkId;
        size_t start = decoded ? off : (info.nowtp ? anyOff : 0);
        info.payload = data + start;
        info.payloadLen = len - start;
        observer_(info);
    }
    if (!decoded) {
        stats_.framesInvalid++;
        return;
    }
    if (h.networkId != config_.networkId) return;

    switch (h.type) {
        case Type::Single: handleSingle(src, h, data + off, len - off, now); break;
        case Type::Fragment: handleFragment(src, h, data + off, len - off, now); break;
        case Type::Ack: handleAck(src, h, data + off, len - off, now); break;
    }
    pump(now);
    flushCompletions();
}

void Engine::handleSingle(const Mac& src, const Header& h, const uint8_t* payload, size_t len, uint32_t now) {
    bool reliable = (h.flags & kFlagReliable) != 0;
    bool latest = (h.flags & kFlagLatest) != 0;
    bool ackRequest = reliable && (h.flags & kFlagAckRequest) != 0;

    // Also catches unreliable duplicates: the radio resends a frame whose MAC ack was lost.
    const uint8_t* seenBind = nullptr;
    if (isDuplicate(src, h.messageId, now, seenBind)) {
        if (ackRequest) queueAck(src, h.port, h.messageId, h.flags, AckStatus::Complete, nullptr, seenBind);
        return;
    }
    if (!hasListener(h.port)) {
        stats_.messagesDropped++;
        if (reliable) queueAck(src, h.port, h.messageId, h.flags, AckStatus::Rejected, nullptr);
        return;
    }
    bool authenticated = false;
    Auth auth = authorize(src, h.port, h.flags, payload, len, authenticated, now);
    if (auth != Auth::Accept) {
        // Untagged: the sender may hold another key, or none.
        if (auth == Auth::Reject && reliable) queueAck(src, h.port, h.messageId, 0, AckStatus::Rejected, nullptr);
        return;
    }
    if (heard_) heard_(src, authenticated, now);
    if (latest) {
        if (isStaleLatest(src, h.port, h.messageId, now)) {
            stats_.messagesDropped++;
            return;
        }
        dropOlderLatest(src, h.port, h.messageId);
    }
    const uint8_t* bind = authenticated ? payload + len : nullptr;  // the trailer follows the payload
    Delivery d = deliver(src, h.port, h.flags, payload, len, rxRssi_, rxTimeUs_, authenticated);
    delivered(d, src, h.port, h.flags, h.messageId, bind, now);
}

void Engine::handleFragment(const Mac& src, const Header& h, const uint8_t* payload, size_t len, uint32_t now) {
    bool reliable = (h.flags & kFlagReliable) != 0;
    bool latest = (h.flags & kFlagLatest) != 0;
    bool ackRequest = reliable && (h.flags & kFlagAckRequest) != 0;

    const uint8_t* seenBind = nullptr;
    if (isDuplicate(src, h.messageId, now, seenBind)) {
        if (ackRequest) queueAck(src, h.port, h.messageId, h.flags, AckStatus::Complete, nullptr, seenBind);
        return;
    }

    RxMessage* rx = findRx(src, h.messageId);
    if (rx && (rx->port != h.port || rx->count != h.count)) {
        // Same id but a different message: the sender restarted. Start over.
        stats_.framesInvalid++;
        dropRx(rx);
        rx = nullptr;
    }

    if (!rx) {
        // Every fragment carries at least one byte, so `count` bounds the size.
        if (!hasListener(h.port) || static_cast<size_t>(h.count) > maxStream()) {
            stats_.messagesDropped++;
            if (reliable) queueAck(src, h.port, h.messageId, h.flags, AckStatus::Rejected, nullptr);
            return;
        }
        if (latest) {
            if (isStaleLatest(src, h.port, h.messageId, now)) {
                stats_.messagesDropped++;
                return;
            }
            dropOlderLatest(src, h.port, h.messageId);
        }

        // Authentication is only checked once the message is complete: until
        // then, unverified senders share a single slot.
        bool limited = false;
        if (auth_) {
            Authenticator::Screen screen = auth_->screen(src, h.port, h.flags);
            if (screen == Authenticator::Screen::Reject) {
                if (h.index == 0 || ackRequest) {
                    stats_.authRejected++;
                    stats_.messagesDropped++;
                    // Untagged, as for any authentication failure.
                    if (reliable) queueAck(src, h.port, h.messageId, 0, AckStatus::Rejected, nullptr);
                }
                return;
            }
            limited = screen == Authenticator::Screen::Limited;
        }

        size_t bitmapBytes = (static_cast<size_t>(h.count) + 7) / 8;
        Admission admission = admitRx(src, h.index, h.count, len, limited, now);
        if (admission == Admission::Never) {
            stats_.messagesDropped++;
            if (reliable) queueAck(src, h.port, h.messageId, h.flags, AckStatus::Rejected, nullptr);
            return;
        }
        if (admission == Admission::Busy || !reserveRx(bitmapBytes)) {
            // Refuse the newcomer rather than evict a message in progress: with
            // senders interleaving, the evicted one is always the next to need
            // its slot. Answer the first fragment and probes; the sender backs off.
            if (h.index == 0 || ackRequest) {
                stats_.messagesDropped++;
                stats_.reassemblyRefused++;
                if (reliable) queueAck(src, h.port, h.messageId, h.flags, AckStatus::Busy, nullptr);
            }
            return;
        }
        Owned<RxMessage> created = heap::make<RxMessage>();
        Bytes bitmap = allocZeroed(bitmapBytes);
        if (!created || !bitmap) {
            rxBytes_ -= bitmapBytes;
            return;  // a reliable sender retries
        }
        created->src = src;
        created->port = h.port;
        created->flags = static_cast<uint8_t>(h.flags & (kFlagReliable | kFlagLatest | kFlagAuth));
        created->id = h.messageId;
        created->count = h.count;
        created->bitmap = std::move(bitmap);
        created->limited = limited;
        created->reserved = bitmapBytes;
        rx = created.get();
        rx_.push_back(std::move(created));
    }

    rx->lastActivity = now;
    rx->rssi = rxRssi_;
    rx->timeUs = rxTimeUs_;
    if (!rx->has(h.index)) {
        Place result = placeFragment(*rx, h.index, payload, len);
        if (result != Place::Ok) {
            if (result == Place::Invalid) stats_.framesInvalid++;
            if (result == Place::TooLarge && reliable) {
                queueAck(src, h.port, h.messageId, h.flags, AckStatus::Rejected, nullptr);
            }
            if (result == Place::NoMemory && ackRequest) {
                queueAck(src, h.port, h.messageId, h.flags, AckStatus::Busy, nullptr);
            }
            dropRx(rx);  // on NoMemory a reliable sender retries later
            return;
        }
        rx->mark(h.index);
        rx->received++;
    }

    if (rx->received == rx->count) {
        completeRx(rx, now);
    } else if (ackRequest) {
        queueAck(src, h.port, h.messageId, h.flags, AckStatus::Missing, rx);
    }
}

Engine::Place Engine::placeFragment(RxMessage& rx, uint16_t index, const uint8_t* payload, size_t len) {
    if (len == 0) return Place::Invalid;
    bool last = index + 1 == rx.count;

    if (!last) {
        if (rx.fragSize == 0) {
            if (len > 0xFFFF) return Place::Invalid;
            Place p = allocateRxBuffer(rx, static_cast<uint16_t>(len));
            if (p != Place::Ok) return p;
        } else if (len != rx.fragSize) {
            return Place::Invalid;
        }
        memcpy(rx.buf.get() + static_cast<size_t>(index) * rx.fragSize, payload, len);
        return Place::Ok;
    }

    rx.lastLen = len;
    if (rx.fragSize == 0) {
        if (!reserveRx(len)) return Place::NoMemory;
        rx.reserved += len;
        rx.stashedLast = allocBytes(len);
        if (!rx.stashedLast) return Place::NoMemory;
        memcpy(rx.stashedLast.get(), payload, len);
        return Place::Ok;
    }
    if (len > rx.fragSize) return Place::Invalid;
    memcpy(rx.buf.get() + static_cast<size_t>(index) * rx.fragSize, payload, len);
    return Place::Ok;
}

Engine::Place Engine::allocateRxBuffer(RxMessage& rx, uint16_t fragSize) {
    if (rx.stashedLast && rx.lastLen > fragSize) return Place::Invalid;
    // Smallest possible stream: full fragments plus a 1-byte last one.
    size_t minStream = static_cast<size_t>(rx.count - 1) * fragSize + 1;
    if (minStream > maxStream()) return Place::TooLarge;

    size_t capacity = static_cast<size_t>(rx.count) * fragSize;
    if (!reserveRx(capacity)) return Place::NoMemory;
    rx.reserved += capacity;
    rx.buf = allocBytes(capacity);
    if (!rx.buf) return Place::NoMemory;
    rx.fragSize = fragSize;

    if (rx.stashedLast) {
        memcpy(rx.buf.get() + static_cast<size_t>(rx.count - 1) * fragSize, rx.stashedLast.get(), rx.lastLen);
        rx.stashedLast.reset();
    }
    return Place::Ok;
}

// Makes room for a new message by evicting only idle ones: a live sender
// sends again within its ack timeout (a probe at worst), so a partial message
// idle for longer is abandoned, or waits on a sender busy elsewhere.
Engine::Admission Engine::admitRx(const Mac& src, uint16_t index, uint16_t count, size_t len, bool limited,
                                  uint32_t now) {
    if (config_.maxRxMessages == 0 || config_.maxRxMessagesPerSender == 0) return Admission::Never;
    // Room for its whole buffer, so admitted messages can finish. A last
    // fragment arriving first (a probe) doesn't tell the fragment size:
    // assume full frames from this peer, at most the whole budget.
    size_t frag = len;
    bool last = index + 1 == count;
    if (last) {
        size_t mtu = link_.maxFrameSize(src);
        if (mtu > kFragmentHeaderSize) frag = std::max(frag, mtu - kFragmentHeaderSize);
    }
    size_t need = std::min(static_cast<size_t>(count) * frag, maxStream() + frag) + (count + 7u) / 8;
    if (need > config_.maxRxBytes) {
        if (!last) return Admission::Never;
        need = config_.maxRxBytes;
    }

    uint32_t idleMs = 3 * config_.ackTimeoutMs;
    for (;;) {
        size_t fromSrc = 0, unverified = 0;
        for (const auto& r : rx_) {
            if (r->src == src) fromSrc++;
            if (r->limited) unverified++;
        }
        bool perSender = fromSrc >= config_.maxRxMessagesPerSender;
        bool shared = limited && unverified >= 1;
        if (!perSender && !shared && rx_.size() < config_.maxRxMessages && rxBytes_ + need <= config_.maxRxBytes) {
            return Admission::Yes;
        }
        // Evicting only helps if it lifts the limits that apply.
        RxMessage* victim = nullptr;
        for (auto& r : rx_) {
            if (perSender && !(r->src == src)) continue;
            if (shared && !r->limited) continue;
            if (!reached(now, r->lastActivity + idleMs)) continue;
            if (!victim || static_cast<int32_t>(r->lastActivity - victim->lastActivity) < 0) victim = r.get();
        }
        if (!victim) return Admission::Busy;
        dropRx(victim);
    }
}

bool Engine::reserveRx(size_t bytes) {
    if (rxBytes_ + bytes > config_.maxRxBytes) return false;
    rxBytes_ += bytes;
    return true;
}

Engine::RxMessage* Engine::findRx(const Mac& src, uint16_t id) {
    for (auto& r : rx_) {
        if (r->id == id && r->src == src) return r.get();
    }
    return nullptr;
}

void Engine::dropRx(RxMessage* rx, bool countAsDropped) {
    for (size_t i = 0; i < rx_.size(); ++i) {
        if (rx_[i].get() != rx) continue;
        rxBytes_ -= rx->reserved;
        if (countAsDropped) stats_.messagesDropped++;
        rx_.erase(rx_.begin() + static_cast<std::ptrdiff_t>(i));
        return;
    }
}

void Engine::completeRx(RxMessage* rx, uint32_t now) {
    // Detach first: the handler may re-enter the engine.
    Owned<RxMessage> owned;
    for (size_t i = 0; i < rx_.size(); ++i) {
        if (rx_[i].get() == rx) {
            owned = std::move(rx_[i]);
            rx_.erase(rx_.begin() + static_cast<std::ptrdiff_t>(i));
            break;
        }
    }
    if (!owned) return;
    rxBytes_ -= owned->reserved;

    size_t total = static_cast<size_t>(owned->count - 1) * owned->fragSize + owned->lastLen;
    if (total < kCrcSize) {
        stats_.framesInvalid++;
        stats_.messagesDropped++;
        return;
    }
    size_t len = total - kCrcSize;
    const uint8_t* data = owned->buf.get();
    if (len > config_.maxMessageSize + kAuthTrailerSize || crc32(data, len) != getU32(data + len)) {
        stats_.messagesDropped++;
        return;  // corrupt or mixed-up fragments; a reliable sender will retry
    }

    bool reliable = (owned->flags & kFlagReliable) != 0;
    bool authenticated = false;
    Auth auth = authorize(owned->src, owned->port, owned->flags, data, len, authenticated, now);
    if (auth != Auth::Accept) {
        // On Retry the sender's probe rebuilds the message once its epoch is verified.
        if (auth == Auth::Reject && reliable) {
            queueAck(owned->src, owned->port, owned->id, 0, AckStatus::Rejected, nullptr);
        }
        return;
    }
    if (heard_) heard_(owned->src, authenticated, now);
    if (len > config_.maxMessageSize) {
        stats_.messagesDropped++;
        return;
    }
    // The trailer follows the payload, in a buffer the handler may take or free.
    uint8_t bind[kAckBindSize];
    if (authenticated) memcpy(bind, data + len, sizeof(bind));
    Delivery d = deliver(owned->src, owned->port, owned->flags, data, len, owned->rssi, owned->timeUs, authenticated,
                         owned->buf.release());
    delivered(d, owned->src, owned->port, owned->flags, owned->id, authenticated ? bind : nullptr, now);
}

void Engine::handleAck(const Mac& src, const Header& h, const uint8_t* payload, size_t len, uint32_t now) {
    if (len < 1) {
        stats_.framesInvalid++;
        return;
    }
    TxMessage* tx = nullptr;
    for (auto& t : tx_) {
        if (t->id == h.messageId && t->reliable() && t->dst == src) {
            tx = t.get();
            break;
        }
    }
    if (!tx) return;  // already finished, or not ours

    if (tx->flags & kFlagAuth) {
        // Only a holder of the key may confirm an authenticated message. An
        // untagged refusal means the receiver could not verify it: another
        // key, or none. Forging one achieves no more than jamming would.
        if (!(h.flags & kFlagAuth)) {
            if (static_cast<AckStatus>(payload[0]) == AckStatus::Rejected) {
                finish(tx, Status::AuthFailed);
            } else {
                stats_.authRejected++;
            }
            return;
        }
        const uint8_t* frame = payload - kCommonHeaderSize;
        if (!auth_ || len < 1 + kAckTagSize ||
            !auth_->openAck(src, frame, kCommonHeaderSize + len - kAckTagSize, payload + len - kAckTagSize,
                            tx->stream.get() + tx->trailerAt, tx->hasBindBefore ? tx->bindBefore : nullptr)) {
            stats_.authRejected++;
            return;
        }
        len -= kAckTagSize;
    }
    if (heard_) heard_(src, (tx->flags & kFlagAuth) != 0, now);

    switch (static_cast<AckStatus>(payload[0])) {
        case AckStatus::Complete: finish(tx, Status::Ok); break;
        case AckStatus::Rejected: finish(tx, Status::Rejected); break;
        case AckStatus::Missing:
            for (size_t i = 1; i + 1 < len; i += 2) tx->addResend(getU16(payload + i));
            if (tx->hasPendingFrame()) tx->awaitingAck = false;
            break;
        case AckStatus::Busy:
            // No room at the receiver: stop sending, then probe with the last
            // fragment, which reopens reassembly once there is room. Spread
            // by message id so refused senders don't return in step.
            stats_.receiverBusy++;
            tx->clearResend();
            tx->nextIndex = tx->count;
            tx->awaitingAck = true;
            tx->ackDeadline = now + config_.ackTimeoutMs + config_.ackTimeoutMs * (tx->id % 4u) / 2;
            break;
        default: stats_.framesInvalid++; break;
    }
}

void Engine::queueAck(const Mac& dst, uint8_t port, uint16_t id, uint8_t flags, AckStatus status,
                      const RxMessage* missing, const uint8_t* bind) {
    bool tagged = (flags & kFlagAuth) && auth_ && auth_->sealing(port);
    size_t mtu = link_.maxFrameSize(dst);
    if (mtu < kAckHeaderSize + kAckTagSize) return;
    size_t room = tagged ? mtu - kAckTagSize : mtu;

    // The frame's exact size first: a full frame per acknowledgement would
    // take an MTU of heap each time.
    size_t len = kAckHeaderSize;
    if (missing) {
        for (uint16_t i = 0; i < missing->count && len + 2 <= room; ++i) {
            if (!missing->has(i)) len += 2;
        }
    }
    if (tagged) len += kAckTagSize;
    Control c;
    c.dst = dst;
    c.messageId = id;
    c.frame = allocBytes(len);
    if (!c.frame) return;  // no heap: the sender sends again
    c.len = len;
    Header h;
    h.type = Type::Ack;
    h.flags = tagged ? kFlagAuth : 0;
    h.networkId = config_.networkId;
    h.port = port;
    h.messageId = id;
    size_t off = encodeHeader(h, c.frame.get());
    c.frame[off++] = static_cast<uint8_t>(status);
    if (missing) {
        for (uint16_t i = 0; i < missing->count && off + 2 <= room; ++i) {
            if (missing->has(i)) continue;
            putU16(c.frame.get() + off, i);
            off += 2;
        }
    }
    if (tagged) {
        auth_->sealAck(dst, c.frame.get(), off, bind, c.frame.get() + off);
        off += kAckTagSize;
    }

    // Only the newest feedback for a message matters.
    for (size_t i = 0; i < controlCount_; ++i) {
        Control& q = control(i);
        if (q.messageId == id && q.dst == dst) {
            q.frame.swap(c.frame);
            q.len = c.len;
            return;
        }
    }
    if (controlCount_ >= kMaxControlFrames) popControl();
    control(controlCount_++) = std::move(c);
}

void Engine::popControl() {
    control(0).frame.reset();
    controlHead_ = (controlHead_ + 1) % kMaxControlFrames;
    controlCount_--;
}

// ---------------------------------------------------------------------------
// Recently completed messages: duplicate suppression and latest-only ordering

void Engine::remember(const Mac& src, uint8_t port, uint8_t flags, uint16_t id, const uint8_t* bind, uint32_t now) {
    markSeen(src, id, now);
    Recent& r = recent_[recentNext_];
    r.bound = bind != nullptr;
    if (bind) memcpy(r.bind, bind, sizeof(r.bind));
    recentNext_ = (recentNext_ + 1) % recent_.size();
    r.src = src;
    r.port = port;
    r.flags = flags;
    r.messageId = id;
    r.at = now;
    r.used = true;
}

const Engine::Recent* Engine::findRecent(const Mac& src, uint16_t id, uint32_t now) const {
    for (const Recent& r : recent_) {
        if (r.used && r.messageId == id && r.src == src && !reached(now, r.at + config_.recentTtlMs)) return &r;
    }
    return nullptr;
}

// An authenticated duplicate that only the sender's window still knows is
// acknowledged unbound, which a sender checking bound acks doesn't take: it
// times out rather than being told a reused id was delivered.
bool Engine::isDuplicate(const Mac& src, uint16_t id, uint32_t now, const uint8_t*& bind) const {
    bind = nullptr;
    if (const Recent* r = findRecent(src, id, now)) {
        if (r->bound) bind = r->bind;
        return true;
    }
    return wasSeen(src, id, now);
}

namespace {
// Block of 32 ids; 2048 of them cover the id space, so differences wrap at 11 bits.
inline uint16_t blocksBehind(uint16_t newer, uint16_t older) {
    return static_cast<uint16_t>(((newer >> 5) - (older >> 5)) & 0x7FF);
}
}  // namespace

void Engine::markSeen(const Mac& src, uint16_t id, uint32_t now) {
    Seen* s = nullptr;
    size_t oldest = 0;
    for (size_t i = 0; i < seen_.size(); ++i) {
        if (seen_[i].src == src) {
            s = &seen_[i];
            break;
        }
        if (static_cast<int32_t>(seen_[i].last - seen_[oldest].last) < 0) oldest = i;
    }
    bool fresh = s == nullptr || reached(now, s->last + config_.recentTtlMs);
    if (!s) {
        Seen blank;
        memset(&blank, 0, sizeof(blank));
        blank.src = src;
        s = seen_.add(blank);
        // Full, or no memory for another: the sender heard least recently gives way.
        if (!s && !seen_.empty()) s = &seen_[oldest];
        if (!s) return;  // `recent_` still holds the id
        s->src = src;
    }
    if (fresh) {
        memset(s->bits, 0, sizeof(s->bits));
        s->top = id;
    } else if (static_cast<int16_t>(id - s->top) > 0) {
        // Newer: clear the blocks the window moves onto.
        uint16_t steps = std::min(blocksBehind(id, s->top), kSeenBlocks);
        for (uint16_t k = 1; k <= steps; ++k) s->bits[((s->top >> 5) + k) % kSeenBlocks] = 0;
        s->top = id;
    } else if (blocksBehind(s->top, id) >= kSeenBlocks) {
        return;  // older than the window; `recent_` may still hold it
    }
    size_t slot = (id >> 5) % kSeenBlocks;
    s->bits[slot] |= 1u << (id & 31);
    s->at[slot] = now;
    s->last = now;
}

bool Engine::wasSeen(const Mac& src, uint16_t id, uint32_t now) const {
    for (const Seen& s : seen_) {
        if (!(s.src == src)) continue;
        if (reached(now, s.last + config_.recentTtlMs)) return false;
        if (static_cast<int16_t>(id - s.top) > 0 || blocksBehind(s.top, id) >= kSeenBlocks) return false;
        size_t slot = (id >> 5) % kSeenBlocks;
        return ((s.bits[slot] >> (id & 31)) & 1) && !reached(now, s.at[slot] + config_.recentTtlMs);
    }
    return false;
}

bool Engine::isStaleLatest(const Mac& src, uint8_t port, uint16_t id, uint32_t now) const {
    for (const Recent& r : recent_) {
        if (r.used && (r.flags & kFlagLatest) && r.port == port && r.src == src &&
            !reached(now, r.at + config_.recentTtlMs) && olderWithin(id, r.messageId, kStaleWindow)) {
            return true;
        }
    }
    for (const auto& rx : rx_) {
        if ((rx->flags & kFlagLatest) && rx->port == port && rx->src == src &&
            olderWithin(id, rx->id, kStaleWindow)) {
            return true;
        }
    }
    return false;
}

void Engine::dropOlderLatest(const Mac& src, uint8_t port, uint16_t id) {
    for (size_t i = 0; i < rx_.size();) {
        RxMessage* rx = rx_[i].get();
        if ((rx->flags & kFlagLatest) && rx->port == port && rx->src == src && olderWithin(rx->id, id, kStaleWindow)) {
            dropRx(rx);
            continue;
        }
        ++i;
    }
}

}  // namespace nowtp
