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
// The extension is optional: earlier versions neither send nor read it.
constexpr uint8_t kHello = 1;
constexpr size_t kFixedSize = 6;  // type, flags, frame size, two length bytes
constexpr size_t kExtSize = 3;

inline bool reached(uint32_t now, uint32_t deadline) {
    return static_cast<int32_t>(now - deadline) >= 0;
}

}  // namespace

constexpr size_t Discovery::kMaxName;
constexpr size_t Discovery::kMaxMetadata;

Discovery::Discovery(Engine& engine, const DiscoveryConfig& config, uint16_t localMaxFrameSize,
                     std::function<uint32_t()> random)
    : engine_(engine), config_(config), localMaxFrameSize_(localMaxFrameSize), random_(std::move(random)) {
    if (config_.name.size() > kMaxName) config_.name.resize(kMaxName);
    if (config_.metadata.size() > kMaxMetadata) config_.metadata.resize(kMaxMetadata);
    if (!random_) random_ = [] { return 0u; };
}

Discovery::~Discovery() {
    if (running_) engine_.listen(kDiscoveryPort, ReceiveHandler());
}

void Discovery::start(uint32_t now) {
    now_ = now;
    running_ = true;
    engine_.listen(kDiscoveryPort, [this](const Message& m) { handle(m); });
    queryDue_ = true;  // sent from tick() so start() itself never fails
    tick(now);
}

void Discovery::stop(uint32_t now) {
    if (!running_) return;
    now_ = now;
    announce(kGoodbye);
    engine_.listen(kDiscoveryPort, ReceiveHandler());
    running_ = false;
    replyDue_ = queryDue_ = false;
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
    buf[n++] = extFlags_;
    buf[n++] = channel_;
    if (flags & kMoving) buf[n++] = moveTo;

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
            PeerInfo lost = peers_[i];
            peers_.erase(peers_.begin() + static_cast<std::ptrdiff_t>(i));
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
    if (len < kFixedSize || p[0] != kHello) return false;
    size_t nameLen = p[4];
    if (nameLen > kMaxName || kFixedSize + nameLen > len) return false;
    size_t metaLen = p[5 + nameLen];
    if (metaLen > kMaxMetadata || kFixedSize + nameLen + metaLen > len) return false;
    out = Announcement();
    out.flags = p[1];
    out.maxFrameSize = wire::getU16(p + 2);
    out.name.assign(reinterpret_cast<const char*>(p + 5), nameLen);
    out.metadata = p + kFixedSize + nameLen;
    out.metadataLen = metaLen;
    size_t ext = kFixedSize + nameLen + metaLen;
    if (len >= ext + 2) {
        out.extFlags = p[ext];
        out.channel = p[ext + 1];
        if ((out.flags & kMoving) && len >= ext + 3) out.moveTo = p[ext + 2];
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

void Discovery::handle(const Message& m) {
    Announcement a;
    if (!parse(m.data, m.len, a)) return;

    if (a.flags & kGoodbye) {
        for (size_t i = 0; i < peers_.size(); ++i) {
            if (peers_[i].mac != m.src) continue;
            PeerInfo lost = peers_[i];
            peers_.erase(peers_.begin() + static_cast<std::ptrdiff_t>(i));
            emit(PeerEvent::Lost, lost);
            if ((a.flags & kMoving) && a.moveTo != 0 && moveHandler_) {
                MoveHandler h = moveHandler_;
                h(lost, a.moveTo);
            }
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
        if (peers_.size() >= config_.maxPeers) return;
        PeerInfo fresh;
        fresh.mac = m.src;
        fresh.name = a.name;
        fresh.metadata.assign(a.metadata, a.metadata + a.metadataLen);
        fresh.maxFrameSize = a.maxFrameSize;
        fresh.rssi = m.rssi;
        fresh.firstSeenMs = fresh.lastSeenMs = now_;
        fresh.channel = a.channel;
        fresh.anchor = anchor;
        fresh.timeReference = timeReference;
        fresh.authenticated = m.authenticated;
        peers_.push_back(fresh);
        emit(PeerEvent::Found, fresh);
        return;
    }

    peer->lastSeenMs = now_;
    peer->rssi = m.rssi;
    bool changed = peer->name != a.name || peer->maxFrameSize != a.maxFrameSize ||
                   peer->metadata.size() != a.metadataLen ||
                   !std::equal(peer->metadata.begin(), peer->metadata.end(), a.metadata) ||
                   peer->channel != a.channel || peer->anchor != anchor || peer->timeReference != timeReference ||
                   peer->authenticated != m.authenticated;
    if (changed) {
        peer->name = a.name;
        peer->metadata.assign(a.metadata, a.metadata + a.metadataLen);
        peer->maxFrameSize = a.maxFrameSize;
        peer->channel = a.channel;
        peer->anchor = anchor;
        peer->timeReference = timeReference;
        peer->authenticated = m.authenticated;
        PeerInfo copy = *peer;
        emit(PeerEvent::Updated, copy);
    }
}

void Discovery::emit(PeerEvent event, const PeerInfo& peer) {
    if (handler_) {
        PeerHandler h = handler_;  // the handler may replace itself
        h(event, peer);
    }
}

}  // namespace nowtp
