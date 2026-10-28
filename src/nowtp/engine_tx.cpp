// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
//
// Sending: queueing and cutting messages, pacing frames, acks of our
// messages, completions, reseals.
#include "engine_internal.h"

namespace nowtp {

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

    // Frame headers are written in the buffer, just before each frame's bytes.
    size_t room = kSendHeadroom + payloadLen + kCrcSize;
    Bytes stream;
    if (owned) {
        if (capacity < room) {
            uint8_t* grown = static_cast<uint8_t*>(heap::reallocate(owned.get(), room));
            if (grown) {
                owned.release();  // moved into `grown`
                owned.reset(grown);
            } else {
                owned.reset();
            }
        }
        if (owned && len > 0) memmove(owned.get() + kSendHeadroom, owned.get(), len);
        stream = std::move(owned);
    } else {
        stream = allocBytes(room);
        if (stream && len > 0) memcpy(stream.get() + kSendHeadroom, data, len);
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
        auth_->seal(dst, port, tx->flags, tx->data(), len, tx->data() + len);
        tx->flags = static_cast<uint8_t>(tx->flags | kFlagAuth);
        tx->trailerAt = len;
    }
    if (count > 1) putU32(tx->data() + payloadLen, crc32(tx->data(), payloadLen));

    tx->id = nextId_++;
    if (messageId) *messageId = tx->id;
    tx->deadline = now + (options.timeoutMs ? options.timeoutMs : config_.sendTimeoutMs);
    tx->done = std::move(done);
    tx->tag = options.tag;
    txBytes_ += tx->streamLen;
    tx_.push_back(std::move(tx));  // within the reserved capacity

    pump(now);
    flushCompletions();
    return Status::Ok;
}

// A message is cut for its destination's frame size when it is queued, and
// that may shrink meanwhile (the peer lost, or announced again smaller). The
// message is then cut again, under a new id if a frame of the old cut went
// out: the receiver may hold some. False if it was finished instead.
bool Engine::fitFrames(TxMessage& tx) {
    size_t mtu = link_.maxFrameSize(tx.dst);
    size_t largest = tx.count > 1 ? kFragmentHeaderSize + tx.fragSize : kCommonHeaderSize + tx.streamLen;
    if (largest <= mtu) return true;
    size_t payloadLen = tx.payloadLen();
    size_t streamLen = payloadLen + kCrcSize;
    if (mtu <= kFragmentHeaderSize) {
        finish(&tx, Status::LinkError);
        return false;
    }
    uint16_t fragSize = static_cast<uint16_t>(std::min<size_t>(mtu - kFragmentHeaderSize, 0xFFFF));
    size_t count = (streamLen + fragSize - 1) / fragSize;
    if (count > 0xFFFF) {
        finish(&tx, Status::TooLarge);
        return false;
    }
    if (tx.count == 1) putU32(tx.data() + payloadLen, crc32(tx.data(), payloadLen));
    txBytes_ = txBytes_ - tx.streamLen + streamLen;
    tx.streamLen = streamLen;
    tx.fragSize = fragSize;
    tx.count = static_cast<uint16_t>(count);
    if (tx.onAir) tx.id = nextId_++;
    tx.onAir = false;
    tx.nextIndex = 0;
    tx.clearResend();
    tx.awaitingAck = false;
    stats_.messagesRecut++;
    return true;
}

// Frame `index` of `tx`, its header written in place just before its bytes:
// over the headroom for the first, over the end of the previous fragment for
// the others. Those bytes go to `saved` (kFragmentHeaderSize), to be put back
// once the link has copied the frame. Returns the frame; `headerLen` and
// `len` receive its header's size and its own.
uint8_t* Engine::buildFrame(TxMessage& tx, uint16_t index, bool ackRequest, uint8_t* saved, size_t& headerLen,
                            size_t& len) {
    Header h;
    h.type = tx.count > 1 ? Type::Fragment : Type::Single;
    h.flags = static_cast<uint8_t>(tx.flags | (ackRequest ? kFlagAckRequest : 0));
    h.networkId = config_.networkId;
    h.port = tx.port;
    h.messageId = tx.id;
    h.index = index;
    h.count = tx.count;
    size_t start = tx.count > 1 ? static_cast<size_t>(index) * tx.fragSize : 0;
    size_t n = tx.count > 1 ? std::min<size_t>(tx.fragSize, tx.streamLen - start) : tx.streamLen;
    headerLen = headerSize(h.type);
    uint8_t* frame = tx.data() + start - headerLen;
    memcpy(saved, frame, headerLen);
    encodeHeader(h, frame);
    len = headerLen + n;
    return frame;
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

        if (!fitFrames(*tx)) continue;
        uint16_t index = tx->pendingFrame();
        bool ackRequest = tx->reliable() && tx->isLastPending();
        uint8_t saved[kFragmentHeaderSize];
        size_t headerLen = 0, len = 0;
        uint8_t* frame = buildFrame(*tx, index, ackRequest, saved, headerLen, len);

        inflight_ = InFlight();
        inflight_.active = true;
        inflight_.msg = tx;
        inflight_.index = index;
        inflight_.firstPass = tx->firstPassPending();
        inflight_.ackRequest = ackRequest;
        inflight_.deadline = now + config_.frameSentTimeoutMs;

        Status st = link_.sendFrame(tx->dst, frame, len);  // copies the frame
        memcpy(frame, saved, headerLen);
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
        tx->sentSinceSeal = true;
        tx->onAir = true;
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
        if (waitsForCredit(*t, now)) {
            if (!t->waitedForCredit) stats_.creditWaits++;
            t->waitedForCredit = true;
            continue;  // and the destination's later messages wait behind it
        }
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

// ---------------------------------------------------------------------------
// Receiver credit: a receiver's acks say how much room it has left for our
// next message. A new multi-frame message it has no room for waits, instead
// of costing a frame and a Busy ack; one refused already probes as before,
// and its acks bring fresh credit. Single-frame messages need no room.

bool Engine::waitsForCredit(const TxMessage& tx, uint32_t now, uint32_t* until) const {
    if (tx.count < 2 || tx.nextIndex > 0 || tx.resendCount > 0 || tx.awaitingAck) return false;  // started
    return credits_.waits(tx.dst, CreditBook::need(tx.count, tx.fragSize), now, until);
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
    // Only once delivered: a first frame lost at the MAC level goes again at once.
    // Messages started after the receiver's word take room it didn't count.
    if (f.firstPass && f.index == 0 && tx->count > 1) credits_.spend(tx->dst, CreditBook::need(tx->count, tx->fragSize));
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
        if (owned->done || observer(owned->port)) {
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
        if (t->done) {
            GateScope open(t->port < kFirstReservedPort ? gate_ : nullptr);
            t->done(t->result);
        } else if (const Callback<void(uint32_t, Status)>* o = observer(t->port)) {
            Callback<void(uint32_t, Status)> report = *o;  // shared: no allocation
            GateScope open(t->port < kFirstReservedPort ? gate_ : nullptr);
            report(t->tag, t->result);
        }
    }
    flushing_ = false;
}

// Anyone can ask for this, under any MAC (Security answers every challenge):
// each message is sealed again at most once a second, later requests within
// that second when it is over. Until then, a receiver that really forgot us
// drops its copies as replays, and reliable delivery tries again.
void Engine::reseal(const Mac& dst, uint32_t now) {
    if (!auth_) return;
    for (auto& t : tx_) {
        if (!(t->dst == dst) || !(t->flags & kFlagAuth) || !auth_->sealing(t->port)) continue;
        if (t->resealed && !reached(now, t->resealAt + kResealIntervalMs)) {
            t->resealWanted = true;
            continue;
        }
        resealOne(*t, now);
    }
}

void Engine::resealOne(TxMessage& t, uint32_t now) {
    uint8_t* trailer = t.data() + t.trailerAt;
    if (t.sentSinceSeal) {
        memmove(t.bindsBefore + kAckBindSize, t.bindsBefore, (TxMessage::kOldBinds - 1) * kAckBindSize);
        memcpy(t.bindsBefore, trailer, kAckBindSize);
        if (t.oldBinds < TxMessage::kOldBinds) t.oldBinds++;
        t.sentSinceSeal = false;
    }
    auth_->seal(t.dst, t.port, static_cast<uint8_t>(t.flags & (kFlagReliable | kFlagLatest)), t.data(),
                t.trailerAt, trailer);
    size_t payloadLen = t.trailerAt + kAuthTrailerSize;
    if (t.count > 1) putU32(t.data() + payloadLen, crc32(t.data(), payloadLen));
    t.resealed = true;
    t.resealWanted = false;
    t.resealAt = now;
}

void Engine::observeCompletions(uint8_t port, CompletionObserver observer) {
    for (size_t i = 0; i < observers_.size(); ++i) {
        if (observers_[i].first != port) continue;
        if (observer) {
            observers_[i].second.set(std::move(observer));
        } else {
            observers_.erase(observers_.begin() + static_cast<std::ptrdiff_t>(i));
        }
        return;
    }
    if (observer) observers_.push_back(std::make_pair(port, Callback<void(uint32_t, Status)>(std::move(observer))));
}

const Callback<void(uint32_t, Status)>* Engine::observer(uint8_t port) const {
    for (const auto& o : observers_) {
        if (o.first == port) return &o.second;
    }
    return nullptr;
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
                            tx->data() + tx->trailerAt, tx->bindsBefore, tx->oldBinds)) {
            stats_.authRejected++;
            return;
        }
        len -= kAckTagSize;
    }
    if ((h.flags & kFlagCredit) && len >= 2) {
        len--;  // the credit byte, after any missing fragments
        if (config_.receiverCredit) credits_.note(src, payload[len], now);
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

}  // namespace nowtp
