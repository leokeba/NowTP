// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "engine_internal.h"

namespace nowtp {

constexpr size_t Engine::kMaxControlFrames;

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

Engine::Engine(Link& link, const Config& config, uint16_t firstMessageId)
    : link_(link), config_(config), nextId_(firstMessageId),
      seen_(config.recentSenders, config.recentTtlMs),
      credits_(config.maxTxMessages, 3 * config.ackTimeoutMs + 1) {
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
        if (tx->resealWanted && reached(now, tx->resealAt + kResealIntervalMs)) {
            if (auth_ && auth_->sealing(tx->port)) {
                resealOne(*tx, now);
            } else {
                tx->resealWanted = false;
            }
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

    credits_.expire(now);

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
// flight (its report pumps the next one) or nothing is pending, nor for a
// destination whose next message waits for credit, until that expires.
void Engine::nextTick(Deadline& d) const {
    if (inflight_.active) d.at(inflight_.deadline);
    bool pending = controlCount_ > 0;
    for (size_t i = 0; i < tx_.size(); ++i) {
        const TxMessage* t = tx_[i].get();
        d.at(t->deadline);
        if (t->awaitingAck) d.at(t->ackDeadline);
        if (t->resealWanted) d.at(t->resealAt + kResealIntervalMs);
        if (!t->hasPendingFrame()) continue;
        bool head = true;  // see nextMessage()
        for (size_t j = 0; j < i && head; ++j) head = !(tx_[j]->hasPendingFrame() && tx_[j]->dst == t->dst);
        uint32_t until = 0;
        if (!head) continue;
        if (waitsForCredit(*t, d.now(), &until)) {
            d.at(until);
            continue;
        }
        pending = true;
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

void Engine::queueAck(const Mac& dst, uint8_t port, uint16_t id, uint8_t flags, AckStatus status,
                      const RxMessage* missing, const uint8_t* bind, bool full) {
    bool tagged = (flags & kFlagAuth) && auth_ && auth_->sealing(port);
    // A single trailing byte, so that older senders, reading missing
    // fragments two bytes at a time, never see it.
    bool withCredit = config_.receiverCredit && status != AckStatus::Rejected;
    size_t mtu = link_.maxFrameSize(dst);
    if (mtu < kAckHeaderSize + 1 + kAckTagSize) return;
    size_t room = (tagged ? mtu - kAckTagSize : mtu) - (withCredit ? 1 : 0);

    // The frame's exact size first: a full frame per acknowledgement would
    // take an MTU of heap each time.
    size_t len = kAckHeaderSize;
    if (missing) {
        for (uint16_t i = 0; i < missing->count && len + 2 <= room; ++i) {
            if (!missing->has(i)) len += 2;
        }
    }
    if (withCredit) len += 1;
    if (tagged) len += kAckTagSize;
    Control c;
    c.dst = dst;
    c.messageId = id;
    c.frame = allocBytes(len);
    if (!c.frame) return;  // no heap: the sender sends again
    c.len = len;
    Header h;
    h.type = Type::Ack;
    h.flags = static_cast<uint8_t>((tagged ? kFlagAuth : 0) | (withCredit ? kFlagCredit : 0));
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
    if (withCredit) c.frame[off++] = full ? 0 : creditFor(dst, now_);
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

}  // namespace nowtp
