// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
//
// Receiving: reassembly and its admission, delivery to handlers, duplicates
// and latest-only order.
#include "engine_internal.h"

namespace nowtp {

// As admitRx() sees it: partial messages idle long enough to be evicted are room.
uint8_t Engine::creditFor(const Mac& src, uint32_t now) const {
    uint32_t idleMs = 3 * config_.ackTimeoutMs;
    size_t live = 0, fromSrc = 0, held = 0;
    for (const auto& r : rx_) {
        if (reached(now, r->lastActivity + idleMs)) continue;
        live++;
        held += r->reserved;
        if (r->src == src) fromSrc++;
    }
    if (live >= config_.maxRxMessages || fromSrc >= config_.maxRxMessagesPerSender || held >= config_.maxRxBytes) {
        return 0;
    }
    size_t units = (config_.maxRxBytes - held) / kCreditUnit;
    return units >= kCreditMax ? kCreditMax : static_cast<uint8_t>(units);
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
    {
        GateScope open(port < kFirstReservedPort ? gate_ : nullptr);
        handler(m);
    }
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
            queueAck(src, port, id, flags, AckStatus::Busy, nullptr, bind, true);
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

// ---------------------------------------------------------------------------
// Recently completed messages: duplicate suppression and latest-only ordering

void Engine::remember(const Mac& src, uint8_t port, uint8_t flags, uint16_t id, const uint8_t* bind, uint32_t now) {
    seen_.mark(src, id, now);
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
    return seen_.seen(src, id, now);
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
