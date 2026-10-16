// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "discovery.h"

#include <algorithm>

namespace nowtp {

namespace {

// Announcement layout (payload of a message on kDiscoveryPort):
//   type (1) = kHello | flags (1) | max frame size (2, LE)
//   | name length (1) | name | metadata length (1) | metadata
//   | extension flags (1) | channel (1) | [move-to channel (1), moving notices only]
//   | [largest message accepted (4, LE), with extension flag kExtMaxMessage]
// The extension is optional: earlier versions neither send nor read it, and
// 0.5 reads no further than the move-to channel.
constexpr uint8_t kHello = 1;
constexpr size_t kFixedSize = 6;  // type, flags, frame size, two length bytes
constexpr size_t kExtSize = 7;

inline bool reached(uint32_t now, uint32_t deadline) {
    return static_cast<int32_t>(now - deadline) >= 0;
}

}  // namespace

constexpr size_t Discovery::kMaxName;
constexpr size_t Discovery::kMaxMetadata;

Discovery::Discovery(Engine& engine, const DiscoveryConfig& config, uint16_t localMaxFrameSize,
                     std::function<uint32_t()> random)
    : engine_(engine),
      config_(config),
      localMaxFrameSize_(localMaxFrameSize),
      random_(std::move(random)),
      peers_(config.maxPeers) {
    if (config_.name.size() > kMaxName) config_.name.resize(kMaxName);
    if (config_.metadata.size() > kMaxMetadata) config_.metadata.resize(kMaxMetadata);
    if (!random_) random_ = [] { return 0u; };
}

Discovery::~Discovery() {
    if (!running_) return;
    engine_.listen(kDiscoveryPort, ReceiveHandler());
    engine_.setHeardObserver(HeardObserver());
}

void Discovery::start(uint32_t now) {
    now_ = now;
    running_ = true;
    engine_.listen(kDiscoveryPort, [this](const Message& m) { handle(m); });
    engine_.setHeardObserver([this](const Mac& src, bool authenticated, uint32_t t) { heard(src, authenticated, t); });
    queryDue_ = true;  // sent from tick() so start() itself never fails
    tick(now);
}

void Discovery::stop(uint32_t now) {
    if (!running_) return;
    now_ = now;
    announce(kGoodbye);
    engine_.listen(kDiscoveryPort, ReceiveHandler());
    engine_.setHeardObserver(HeardObserver());
    running_ = false;
    replyDue_ = queryDue_ = false;
    for (const PeerInfo& p : peers_) engine_.setPeerMessageLimit(p.mac, 0);
    peers_.clear();
}

void Discovery::discover(uint32_t now) {
    if (!running_) return;
    queryDue_ = true;
    tick(now);
}

bool Discovery::announceMove(uint8_t channel, uint32_t now) {
    if (!running_) return false;
    now_ = now;
    // Not latest-only, so the copies do not replace each other in the queue.
    bool sent = false;
    for (int i = 0; i < 3; ++i) sent = announce(kGoodbye | kMoving, channel) || sent;
    return sent;
}

void Discovery::setChannelInfo(uint8_t channel, bool anchor, uint32_t now) {
    uint8_t flags = static_cast<uint8_t>(anchor ? (extFlags_ | kExtAnchor) : (extFlags_ & ~kExtAnchor));
    if (channel == channel_ && flags == extFlags_) return;
    channel_ = channel;
    extFlags_ = flags;
    if (!running_) return;
    announceDue_ = true;
    tick(now);
}

void Discovery::setTimeReference(bool reference, uint32_t now) {
    uint8_t flags =
        static_cast<uint8_t>(reference ? (extFlags_ | kExtTimeReference) : (extFlags_ & ~kExtTimeReference));
    if (flags == extFlags_) return;
    extFlags_ = flags;
    if (!running_) return;
    announceDue_ = true;
    tick(now);
}

void Discovery::setMetadata(const uint8_t* data, size_t len, uint32_t now) {
    config_.metadata.assign(data, data + std::min(len, kMaxMetadata));
    if (!running_) return;
    announceDue_ = true;  // tell everyone right away
    tick(now);
}

std::vector<PeerInfo> Discovery::peers() const {
    std::vector<PeerInfo> out;
    out.reserve(peers_.size());
    for (const PeerInfo& p : peers_) out.push_back(p);
    return out;
}

const PeerInfo* Discovery::find(const Mac& mac) const {
    for (const PeerInfo& p : peers_) {
        if (p.mac == mac) return &p;
    }
    return nullptr;
}

bool Discovery::announce(uint8_t flags, uint8_t moveTo) {
    uint8_t buf[kFixedSize + kMaxName + kMaxMetadata + kExtSize];
    size_t n = 0;
    buf[n++] = kHello;
    buf[n++] = flags;
    wire::putU16(buf + n, localMaxFrameSize_);
    n += 2;
    buf[n++] = static_cast<uint8_t>(config_.name.size());
    memcpy(buf + n, config_.name.data(), config_.name.size());
    n += config_.name.size();
    buf[n++] = static_cast<uint8_t>(config_.metadata.size());
    if (!config_.metadata.empty()) memcpy(buf + n, config_.metadata.data(), config_.metadata.size());
    n += config_.metadata.size();
    buf[n++] = static_cast<uint8_t>(extFlags_ | kExtMaxMessage);
    buf[n++] = channel_;
    if (flags & kMoving) buf[n++] = moveTo;
    size_t limit = engine_.config().maxMessageSize;
    wire::putU32(buf + n, static_cast<uint32_t>(std::min<size_t>(limit, 0xFFFFFFFFu)));
    n += 4;

    SendOptions opts;
    opts.latestOnly = (flags & kMoving) == 0;  // a queued announcement is replaced by a fresher one
    return engine_.send(Mac::broadcast(), kDiscoveryPort, buf, n, opts, CompletionHandler(), now_) == Status::Ok;
}

void Discovery::tick(uint32_t now) {
    now_ = now;
    if (!running_) return;

    // Peers that went quiet.
    for (size_t i = 0; i < peers_.size();) {
        if (reached(now, peers_[i].lastSeenMs + config_.peerTimeoutMs)) {
            PeerInfo lost = std::move(peers_[i]);
            peers_.erase(i);
            emit(PeerEvent::Lost, lost);
            continue;
        }
        ++i;
    }

    bool replyNow = replyDue_ && reached(now, replyAt_);
    bool periodic = config_.announceIntervalMs > 0 && reached(now, nextAnnounce_);
    if (!queryDue_ && !announceDue_ && !replyNow && !periodic) return;
    if (retryPending_ && !reached(now, retryAt_)) return;

    uint8_t flags = static_cast<uint8_t>((queryDue_ ? kQuery : 0) | (replyNow ? kReply : 0));
    if (!announce(flags)) {
        retryPending_ = true;  // send queue full; try again shortly
        retryAt_ = now + 20;
        return;
    }
    retryPending_ = queryDue_ = announceDue_ = false;
    replyDue_ = false;  // any announcement answers pending queries
    if (config_.announceIntervalMs) {
        // +-10% jitter keeps nodes that booted together from announcing in lockstep.
        uint32_t jitter = config_.announceIntervalMs / 5;
        nextAnnounce_ = now + config_.announceIntervalMs - jitter / 2 + (jitter ? random_() % jitter : 0);
    }
}

bool Discovery::parse(const uint8_t* p, size_t len, Announcement& out) {
    if (!view(p, len, out)) return false;
    out.name.assign(out.nameData, out.nameLen);
    return true;
}

bool Discovery::view(const uint8_t* p, size_t len, Announcement& out) {
    if (len < kFixedSize || p[0] != kHello) return false;
    size_t nameLen = p[4];
    if (nameLen > kMaxName || kFixedSize + nameLen > len) return false;
    size_t metaLen = p[5 + nameLen];
    if (metaLen > kMaxMetadata || kFixedSize + nameLen + metaLen > len) return false;
    out = Announcement();
    out.flags = p[1];
    out.maxFrameSize = wire::getU16(p + 2);
    out.nameData = reinterpret_cast<const char*>(p + 5);
    out.nameLen = nameLen;
    out.metadata = p + kFixedSize + nameLen;
    out.metadataLen = metaLen;
    size_t ext = kFixedSize + nameLen + metaLen;
    if (len >= ext + 2) {
        out.extFlags = p[ext];
        out.channel = p[ext + 1];
        size_t at = ext + 2;
        if (out.flags & kMoving) {
            if (len >= ext + 3) out.moveTo = p[ext + 2];
            at++;
        }
        if ((out.extFlags & kExtMaxMessage) && len >= at + 4) out.maxMessageSize = wire::getU32(p + at);
    }
    return true;
}

bool Discovery::parseAnnouncement(const uint8_t* p, size_t len, std::string& name, uint16_t& maxFrameSize) {
    Announcement a;
    if (!parse(p, len, a)) return false;
    name = a.name;
    maxFrameSize = a.maxFrameSize;
    return true;
}

// The name and metadata of a new or changed peer take heap through the
// public std::string and std::vector, from operator new, which can't fail
// softly: on a short heap the announcement is ignored (it comes again).
void Discovery::handle(const Message& m) {
    Announcement a;
    if (!view(m.data, m.len, a)) return;
    // Held twice: in the table, and in the copy an event carries.
    size_t need = 2 * (a.nameLen + 1 + a.metadataLen);

    if (a.flags & kGoodbye) {
        for (size_t i = 0; i < peers_.size(); ++i) {
            if (peers_[i].mac != m.src) continue;
            PeerInfo lost = std::move(peers_[i]);
            peers_.erase(i);
            emit(PeerEvent::Lost, lost);
            if ((a.flags & kMoving) && a.moveTo != 0 && moveHandler_) moveHandler_(lost, a.moveTo);
            break;
        }
        return;
    }

    if ((a.flags & kQuery) && !replyDue_) {
        replyDue_ = true;
        replyAt_ = now_ + (config_.replyJitterMs ? random_() % (config_.replyJitterMs + 1) : 0);
    }

    PeerInfo* peer = nullptr;
    for (PeerInfo& q : peers_) {
        if (q.mac == m.src) peer = &q;
    }
    bool anchor = (a.extFlags & kExtAnchor) != 0;
    bool timeReference = (a.extFlags & kExtTimeReference) != 0;
    if (!peer) {
        if (!heap::fits(need)) return;
        if (peers_.full()) {
            // Full: a peer not heard for a while gives way, the one heard
            // least recently first, so a burst of (possibly spoofed)
            // announcements can't hide peers for good. Peers that keep
            // announcing keep their place (no churn), and an authenticated peer
            // gives way only to another one.
            uint32_t silentMs = config_.announceIntervalMs ? config_.announceIntervalMs * 3 / 2
                                                           : config_.peerTimeoutMs / 2;
            size_t victim = peers_.size();
            for (size_t i = 0; i < peers_.size(); ++i) {
                if (peers_[i].authenticated && !m.authenticated) continue;
                if (static_cast<int32_t>(now_ - peers_[i].lastSeenMs) < static_cast<int32_t>(silentMs)) continue;
                if (victim == peers_.size() ||
                    static_cast<int32_t>(peers_[i].lastSeenMs - peers_[victim].lastSeenMs) < 0) {
                    victim = i;
                }
            }
            if (victim == peers_.size()) return;
            PeerInfo lost = std::move(peers_[victim]);
            peers_.erase(victim);
            emit(PeerEvent::Lost, lost);
            // The handler may have re-entered; look again.
            for (PeerInfo& q : peers_) {
                if (q.mac == m.src) return;
            }
            if (peers_.full()) return;
        }
        PeerInfo fresh;
        fresh.mac = m.src;
        fresh.name.assign(a.nameData, a.nameLen);
        fresh.metadata.assign(a.metadata, a.metadata + a.metadataLen);
        fresh.maxFrameSize = a.maxFrameSize;
        fresh.maxMessageSize = a.maxMessageSize;
        fresh.rssi = m.rssi;
        fresh.firstSeenMs = fresh.lastSeenMs = now_;
        fresh.channel = a.channel;
        fresh.anchor = anchor;
        fresh.timeReference = timeReference;
        fresh.authenticated = m.authenticated;
        if (!peers_.add(fresh)) return;  // no memory: heard again at its next announcement
        emit(PeerEvent::Found, fresh);
        return;
    }

    peer->lastSeenMs = now_;
    peer->rssi = m.rssi;
    bool changed = peer->name.size() != a.nameLen || peer->name.compare(0, a.nameLen, a.nameData, a.nameLen) != 0 ||
                   peer->maxFrameSize != a.maxFrameSize || peer->maxMessageSize != a.maxMessageSize ||
                   peer->metadata.size() != a.metadataLen ||
                   !std::equal(peer->metadata.begin(), peer->metadata.end(), a.metadata) ||
                   peer->channel != a.channel || peer->anchor != anchor || peer->timeReference != timeReference ||
                   peer->authenticated != m.authenticated;
    if (changed && heap::fits(need)) {
        peer->name.assign(a.nameData, a.nameLen);
        peer->metadata.assign(a.metadata, a.metadata + a.metadataLen);
        peer->maxFrameSize = a.maxFrameSize;
        peer->maxMessageSize = a.maxMessageSize;
        peer->channel = a.channel;
        peer->anchor = anchor;
        peer->timeReference = timeReference;
        peer->authenticated = m.authenticated;
        PeerInfo copy = *peer;
        emit(PeerEvent::Updated, copy);
    }
}

// Announcements are unacknowledged broadcasts: on a busy channel, or with a
// weak link, a peer can miss several in a row while its messages and acks
// still get through. Those keep it, but only announcements add or change one.
void Discovery::heard(const Mac& src, bool authenticated, uint32_t now) {
    for (PeerInfo& p : peers_) {
        if (p.mac != src) continue;
        // An authenticated peer is vouched for by authenticated traffic only.
        if (p.authenticated && !authenticated) return;
        if (static_cast<int32_t>(now - p.lastSeenMs) > 0) p.lastSeenMs = now;
        return;
    }
}

void Discovery::emit(PeerEvent event, const PeerInfo& peer) {
    // What the peer takes, so send() refuses more at once (0: unknown, none).
    engine_.setPeerMessageLimit(peer.mac, event == PeerEvent::Lost ? 0 : peer.maxMessageSize);
    if (handler_) handler_(event, peer);  // the handler may replace itself
}

}  // namespace nowtp
