// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "engine.h"

#include <algorithm>
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
constexpr size_t kMaxControlFrames = 8;
constexpr size_t kAckHeaderSize = kCommonHeaderSize + 1;  // + status byte

template <typename T>
std::unique_ptr<T[]> allocBytes(size_t n) {
    return std::unique_ptr<T[]>(new (std::nothrow) T[n == 0 ? 1 : n]);
}

}  // namespace

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
    std::unique_ptr<uint8_t[]> stream;
    uint16_t nextIndex = 0;        // next fragment of the first pass
    std::vector<uint16_t> resend;  // fragments to send again
    bool awaitingAck = false;
    uint32_t ackDeadline = 0;
    uint32_t deadline = 0;
    uint8_t frameFailures = 0;
    CompletionHandler done;

    bool reliable() const { return (flags & kFlagReliable) != 0; }
    bool latest() const { return (flags & kFlagLatest) != 0; }
    bool firstPassPending() const { return nextIndex < count; }
    bool hasPendingFrame() const { return firstPassPending() || !resend.empty(); }
    uint16_t pendingFrame() const { return firstPassPending() ? nextIndex : resend.front(); }
    bool isLastPending() const {
        return firstPassPending() ? (nextIndex + 1 == count && resend.empty()) : resend.size() == 1;
    }
    void addResend(uint16_t index) {
        if (index >= count) return;
        if (firstPassPending() && index >= nextIndex) return;  // first pass will send it anyway
        if (std::find(resend.begin(), resend.end(), index) == resend.end()) resend.push_back(index);
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
    std::unique_ptr<uint8_t[]> buf;
    std::vector<uint8_t> bitmap;
    std::vector<uint8_t> stashedLast;  // last fragment, held until fragSize is known
    size_t lastLen = 0;
    size_t reserved = 0;  // bytes counted in rxBytes_
    uint32_t lastActivity = 0;
    int8_t rssi = 0;

    bool has(uint16_t i) const { return (bitmap[i >> 3] >> (i & 7)) & 1; }
    void mark(uint16_t i) { bitmap[i >> 3] |= static_cast<uint8_t>(1u << (i & 7)); }
};

Engine::Engine(Link& link, const Config& config, uint16_t firstMessageId)
    : link_(link), config_(config), nextId_(firstMessageId) {
    if (config_.recentEntries == 0) config_.recentEntries = 1;
    if (config_.sendTimeoutMs == 0) config_.sendTimeoutMs = 1;
    recent_.resize(config_.recentEntries);
    for (Recent& r : recent_) r.used = false;
}

Engine::~Engine() = default;

size_t Engine::singleFramePayload(const Mac& dst) const {
    size_t mtu = link_.maxFrameSize(dst);
    return mtu > kCommonHeaderSize ? mtu - kCommonHeaderSize : 0;
}

// ---------------------------------------------------------------------------
// Sending

Status Engine::send(const Mac& dst, uint8_t port, const uint8_t* data, size_t len, const SendOptions& options,
                    CompletionHandler done, uint32_t now) {
    if (data == nullptr && len > 0) return Status::InvalidArgument;
    if (options.reliable && dst.isBroadcast()) return Status::InvalidArgument;
    if (len > config_.maxMessageSize) return Status::TooLarge;

    size_t mtu = link_.maxFrameSize(dst);
    if (mtu <= kFragmentHeaderSize) return Status::InvalidArgument;

    std::unique_ptr<TxMessage> tx(new (std::nothrow) TxMessage());
    if (!tx) return Status::NoMemory;
    tx->dst = dst;
    tx->port = port;
    tx->flags = static_cast<uint8_t>((options.reliable ? kFlagReliable : 0) | (options.latestOnly ? kFlagLatest : 0));

    if (len <= mtu - kCommonHeaderSize) {
        tx->count = 1;
        tx->streamLen = len;
    } else {
        tx->fragSize = static_cast<uint16_t>(mtu - kFragmentHeaderSize);
        tx->streamLen = len + kCrcSize;
        size_t count = (tx->streamLen + tx->fragSize - 1) / tx->fragSize;
        if (count > 0xFFFF) return Status::TooLarge;
        tx->count = static_cast<uint16_t>(count);
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

    if (tx_.size() >= config_.maxTxMessages || txBytes_ + tx->streamLen > config_.maxTxBytes) {
        flushCompletions();
        return Status::QueueFull;
    }

    tx->stream = allocBytes<uint8_t>(tx->streamLen);
    if (!tx->stream) {
        flushCompletions();
        return Status::NoMemory;
    }
    if (len > 0) memcpy(tx->stream.get(), data, len);
    if (tx->count > 1) putU32(tx->stream.get() + len, crc32(data, len));

    tx->id = nextId_++;
    tx->deadline = now + (options.timeoutMs ? options.timeoutMs : config_.sendTimeoutMs);
    tx->done = std::move(done);
    txBytes_ += tx->streamLen;
    tx_.push_back(std::move(tx));

    pump(now);
    flushCompletions();
    return Status::Ok;
}

size_t Engine::buildFrame(const TxMessage& tx, uint16_t index, bool ackRequest) {
    size_t mtu = link_.maxFrameSize(tx.dst);
    if (frame_.size() < mtu) frame_.resize(mtu);

    Header h;
    h.type = tx.count > 1 ? Type::Fragment : Type::Single;
    h.flags = static_cast<uint8_t>(tx.flags | (ackRequest ? kFlagAckRequest : 0));
    h.networkId = config_.networkId;
    h.port = tx.port;
    h.messageId = tx.id;
    h.index = index;
    h.count = tx.count;
    size_t off = encodeHeader(h, frame_.data());

    size_t start = tx.count > 1 ? static_cast<size_t>(index) * tx.fragSize : 0;
    size_t n = tx.count > 1 ? std::min<size_t>(tx.fragSize, tx.streamLen - start) : tx.streamLen;
    if (n > 0) memcpy(frame_.data() + off, tx.stream.get() + start, n);
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
        if (!control_.empty()) {
            Control& c = control_.front();
            inflight_ = InFlight();
            inflight_.active = true;
            inflight_.control = true;
            inflight_.deadline = now + config_.frameSentTimeoutMs;
            Status st = link_.sendFrame(c.dst, c.frame.data(), c.frame.size());
            if (st == Status::QueueFull) {
                inflight_.active = false;
                linkBusy_ = true;
                linkBusyUntil_ = now + config_.linkBusyBackoffMs;
                break;
            }
            control_.pop_front();
            if (st == Status::Ok) {
                stats_.framesSent++;
            } else {
                inflight_.active = false;
                stats_.framesFailed++;
            }
            continue;
        }

        TxMessage* tx = nullptr;
        for (auto& t : tx_) {
            if (t->hasPendingFrame()) {
                tx = t.get();
                break;
            }
        }
        if (!tx) break;

        uint16_t index = tx->pendingFrame();
        bool ackRequest = tx->reliable() && tx->isLastPending();
        size_t len = buildFrame(*tx, index, ackRequest);

        inflight_ = InFlight();
        inflight_.active = true;
        inflight_.msg = tx;
        inflight_.index = index;
        inflight_.firstPass = tx->firstPassPending();
        inflight_.ackRequest = ackRequest;
        inflight_.deadline = now + config_.frameSentTimeoutMs;

        Status st = link_.sendFrame(tx->dst, frame_.data(), len);
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

void Engine::onFrameSent(bool delivered, uint32_t now) {
    frameSent(delivered, now);
    pump(now);
    flushCompletions();
}

void Engine::frameSent(bool delivered, uint32_t now) {
    if (!inflight_.active) return;
    InFlight f = inflight_;
    inflight_.active = false;

    if (f.control) {
        if (!delivered) stats_.framesFailed++;
        return;
    }
    TxMessage* tx = f.msg;
    if (!tx) return;  // finished (acked, superseded, timed out) while in flight

    if (!delivered) {
        stats_.framesFailed++;
        if (++tx->frameFailures > config_.frameRetries) finish(tx, Status::SendFailed);
        return;  // otherwise the same frame is still pending and goes out again
    }

    tx->frameFailures = 0;
    if (f.firstPass) {
        tx->nextIndex = static_cast<uint16_t>(f.index + 1);
    } else {
        auto it = std::find(tx->resend.begin(), tx->resend.end(), f.index);
        if (it != tx->resend.end()) tx->resend.erase(it);
    }

    if (tx->hasPendingFrame()) return;
    if (tx->reliable()) {
        tx->awaitingAck = true;
        tx->ackDeadline = now + config_.ackTimeoutMs;
    } else {
        finish(tx, Status::Ok);
    }
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
        if (tx->done) completions_.push_back(std::make_pair(std::move(tx->done), status));
        tx_.erase(tx_.begin() + static_cast<std::ptrdiff_t>(i));
        return;
    }
}

void Engine::flushCompletions() {
    if (flushing_) return;
    flushing_ = true;
    std::vector<std::pair<CompletionHandler, Status>> batch;
    while (!completions_.empty()) {
        batch.clear();
        batch.swap(completions_);
        for (auto& c : batch) c.first(c.second);
    }
    flushing_ = false;
}

void Engine::tick(uint32_t now) {
    if (inflight_.active && reached(now, inflight_.deadline)) {
        frameSent(false, now);  // the radio never reported back; treat as lost
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

void Engine::cancelAll(Status reason) {
    while (!tx_.empty()) finish(tx_.front().get(), reason);
    while (!rx_.empty()) dropRx(rx_.front().get(), false);
    control_.clear();
    flushCompletions();
}

// ---------------------------------------------------------------------------
// Receiving

void Engine::listen(uint8_t port, ReceiveHandler handler) {
    for (size_t i = 0; i < listeners_.size(); ++i) {
        if (listeners_[i].first != port) continue;
        if (handler) {
            listeners_[i].second = std::move(handler);
        } else {
            listeners_.erase(listeners_.begin() + static_cast<std::ptrdiff_t>(i));
        }
        return;
    }
    if (handler) listeners_.push_back(std::make_pair(port, std::move(handler)));
}

bool Engine::hasListener(uint8_t port) const {
    for (const auto& l : listeners_) {
        if (l.first == port) return true;
    }
    return false;
}

void Engine::deliver(const Mac& src, uint8_t port, uint8_t flags, const uint8_t* data, size_t len, int8_t rssi) {
    ReceiveHandler handler;
    for (const auto& l : listeners_) {
        if (l.first == port) {
            handler = l.second;  // copy: the handler may replace itself via listen()
            break;
        }
    }
    if (!handler) {
        stats_.messagesDropped++;
        return;
    }
    stats_.messagesReceived++;
    Message m;
    m.src = src;
    m.port = port;
    m.data = data;
    m.len = len;
    m.reliable = (flags & kFlagReliable) != 0;
    m.latestOnly = (flags & kFlagLatest) != 0;
    m.rssi = rssi;
    handler(m);
}

void Engine::onFrameReceived(const Mac& src, const uint8_t* data, size_t len, uint32_t now, int8_t rssi) {
    stats_.framesReceived++;
    rxRssi_ = rssi;
    Header h;
    size_t off = 0;
    if (data == nullptr || !decodeHeader(data, len, h, off)) {
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
    if (isRecent(src, h.messageId, now)) {
        if (ackRequest) queueAck(src, h.port, h.messageId, AckStatus::Complete, nullptr);
        return;
    }
    if (!hasListener(h.port)) {
        stats_.messagesDropped++;
        if (reliable) queueAck(src, h.port, h.messageId, AckStatus::Rejected, nullptr);
        return;
    }
    if (latest) {
        if (isStaleLatest(src, h.port, h.messageId, now)) {
            stats_.messagesDropped++;
            return;
        }
        dropOlderLatest(src, h.port, h.messageId);
    }
    remember(src, h.port, h.flags, h.messageId, now);
    if (ackRequest) queueAck(src, h.port, h.messageId, AckStatus::Complete, nullptr);
    deliver(src, h.port, h.flags, payload, len, rxRssi_);
}

void Engine::handleFragment(const Mac& src, const Header& h, const uint8_t* payload, size_t len, uint32_t now) {
    bool reliable = (h.flags & kFlagReliable) != 0;
    bool latest = (h.flags & kFlagLatest) != 0;
    bool ackRequest = reliable && (h.flags & kFlagAckRequest) != 0;

    if (isRecent(src, h.messageId, now)) {
        if (ackRequest) queueAck(src, h.port, h.messageId, AckStatus::Complete, nullptr);
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
        if (!hasListener(h.port) || static_cast<size_t>(h.count) > config_.maxMessageSize + kCrcSize) {
            stats_.messagesDropped++;
            if (reliable) queueAck(src, h.port, h.messageId, AckStatus::Rejected, nullptr);
            return;
        }
        if (latest) {
            if (isStaleLatest(src, h.port, h.messageId, now)) {
                stats_.messagesDropped++;
                return;
            }
            dropOlderLatest(src, h.port, h.messageId);
        }

        size_t bitmapBytes = (static_cast<size_t>(h.count) + 7) / 8;
        if (rx_.size() >= config_.maxRxMessages && !rx_.empty()) {
            // Make room by evicting the least recently active message.
            RxMessage* oldest = rx_.front().get();
            for (auto& r : rx_) {
                if (static_cast<int32_t>(r->lastActivity - oldest->lastActivity) < 0) oldest = r.get();
            }
            dropRx(oldest);
        }
        if (config_.maxRxMessages == 0 || !reserveRx(bitmapBytes, nullptr)) {
            stats_.messagesDropped++;
            return;
        }
        std::unique_ptr<RxMessage> created(new (std::nothrow) RxMessage());
        if (!created) {
            rxBytes_ -= bitmapBytes;
            return;
        }
        created->src = src;
        created->port = h.port;
        created->flags = static_cast<uint8_t>(h.flags & (kFlagReliable | kFlagLatest));
        created->id = h.messageId;
        created->count = h.count;
        created->bitmap.assign(bitmapBytes, 0);
        created->reserved = bitmapBytes;
        rx = created.get();
        rx_.push_back(std::move(created));
    }

    rx->lastActivity = now;
    rx->rssi = rxRssi_;
    if (!rx->has(h.index)) {
        Place result = placeFragment(*rx, h.index, payload, len);
        if (result != Place::Ok) {
            if (result == Place::Invalid) stats_.framesInvalid++;
            if (result == Place::TooLarge && reliable) {
                queueAck(src, h.port, h.messageId, AckStatus::Rejected, nullptr);
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
        queueAck(src, h.port, h.messageId, AckStatus::Missing, rx);
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
        if (!reserveRx(len, &rx)) return Place::NoMemory;
        rx.reserved += len;
        rx.stashedLast.assign(payload, payload + len);
        return Place::Ok;
    }
    if (len > rx.fragSize) return Place::Invalid;
    memcpy(rx.buf.get() + static_cast<size_t>(index) * rx.fragSize, payload, len);
    return Place::Ok;
}

Engine::Place Engine::allocateRxBuffer(RxMessage& rx, uint16_t fragSize) {
    if (!rx.stashedLast.empty() && rx.stashedLast.size() > fragSize) return Place::Invalid;
    // Smallest possible stream: full fragments plus a 1-byte last one.
    size_t minStream = static_cast<size_t>(rx.count - 1) * fragSize + 1;
    if (minStream > config_.maxMessageSize + kCrcSize) return Place::TooLarge;

    size_t capacity = static_cast<size_t>(rx.count) * fragSize;
    if (!reserveRx(capacity, &rx)) return Place::NoMemory;
    rx.reserved += capacity;
    rx.buf = allocBytes<uint8_t>(capacity);
    if (!rx.buf) return Place::NoMemory;
    rx.fragSize = fragSize;

    if (!rx.stashedLast.empty()) {
        memcpy(rx.buf.get() + static_cast<size_t>(rx.count - 1) * fragSize, rx.stashedLast.data(),
               rx.stashedLast.size());
        std::vector<uint8_t>().swap(rx.stashedLast);
    }
    return Place::Ok;
}

bool Engine::reserveRx(size_t bytes, const RxMessage* keep) {
    while (rxBytes_ + bytes > config_.maxRxBytes) {
        RxMessage* victim = nullptr;
        for (auto& r : rx_) {
            if (r.get() == keep) continue;
            if (!victim || static_cast<int32_t>(r->lastActivity - victim->lastActivity) < 0) victim = r.get();
        }
        if (!victim) return false;
        dropRx(victim);
    }
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
    std::unique_ptr<RxMessage> owned;
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
    if (len > config_.maxMessageSize || crc32(data, len) != getU32(data + len)) {
        stats_.messagesDropped++;
        return;  // corrupt or mixed-up fragments; a reliable sender will retry
    }

    bool reliable = (owned->flags & kFlagReliable) != 0;
    remember(owned->src, owned->port, owned->flags, owned->id, now);
    if (reliable) {
        queueAck(owned->src, owned->port, owned->id, AckStatus::Complete, nullptr);
    }
    deliver(owned->src, owned->port, owned->flags, data, len, owned->rssi);
}

void Engine::handleAck(const Mac& src, const Header& h, const uint8_t* payload, size_t len, uint32_t now) {
    (void)now;
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

    switch (static_cast<AckStatus>(payload[0])) {
        case AckStatus::Complete: finish(tx, Status::Ok); break;
        case AckStatus::Rejected: finish(tx, Status::Rejected); break;
        case AckStatus::Missing:
            for (size_t i = 1; i + 1 < len; i += 2) tx->addResend(getU16(payload + i));
            if (tx->hasPendingFrame()) tx->awaitingAck = false;
            break;
        default: stats_.framesInvalid++; break;
    }
}

void Engine::queueAck(const Mac& dst, uint8_t port, uint16_t id, AckStatus status, const RxMessage* missing) {
    size_t mtu = link_.maxFrameSize(dst);
    if (mtu < kAckHeaderSize) return;

    Control c;
    c.dst = dst;
    c.messageId = id;
    c.frame.resize(mtu);
    Header h;
    h.type = Type::Ack;
    h.networkId = config_.networkId;
    h.port = port;
    h.messageId = id;
    size_t off = encodeHeader(h, c.frame.data());
    c.frame[off++] = static_cast<uint8_t>(status);
    if (missing) {
        for (uint16_t i = 0; i < missing->count && off + 2 <= mtu; ++i) {
            if (missing->has(i)) continue;
            putU16(c.frame.data() + off, i);
            off += 2;
        }
    }
    c.frame.resize(off);

    // Only the newest feedback for a message matters.
    for (Control& q : control_) {
        if (q.messageId == id && q.dst == dst) {
            q.frame.swap(c.frame);
            return;
        }
    }
    if (control_.size() >= kMaxControlFrames) control_.pop_front();
    control_.push_back(std::move(c));
}

// ---------------------------------------------------------------------------
// Recently completed messages: duplicate suppression and latest-only ordering

void Engine::remember(const Mac& src, uint8_t port, uint8_t flags, uint16_t id, uint32_t now) {
    Recent& r = recent_[recentNext_];
    recentNext_ = (recentNext_ + 1) % recent_.size();
    r.src = src;
    r.port = port;
    r.flags = flags;
    r.messageId = id;
    r.at = now;
    r.used = true;
}

bool Engine::isRecent(const Mac& src, uint16_t id, uint32_t now) const {
    for (const Recent& r : recent_) {
        if (r.used && r.messageId == id && r.src == src && !reached(now, r.at + config_.recentTtlMs)) return true;
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
