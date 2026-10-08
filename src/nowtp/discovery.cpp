// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "discovery.h"

#include <algorithm>

namespace nowtp {

namespace {

// Announcement layout (payload of a message on kDiscoveryPort):
//   type (1) = kHello | flags (1) | max frame size (2, LE)
//   | name length (1) | name | metadata length (1) | metadata
constexpr uint8_t kHello = 1;
constexpr size_t kFixedSize = 6;  // type, flags, frame size, two length bytes

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

bool Discovery::announce(uint8_t flags) {
    uint8_t buf[kFixedSize + kMaxName + kMaxMetadata];
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

    SendOptions opts;
    opts.latestOnly = true;  // a queued announcement is replaced by a fresher one
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

void Discovery::handle(const Message& m) {
    const uint8_t* p = m.data;
    size_t len = m.len;
    if (len < kFixedSize || p[0] != kHello) return;
    uint8_t flags = p[1];
    uint16_t maxFrame = wire::getU16(p + 2);
    size_t nameLen = p[4];
    if (nameLen > kMaxName || 5 + nameLen + 1 > len) return;
    size_t metaLen = p[5 + nameLen];
    if (metaLen > kMaxMetadata || 6 + nameLen + metaLen > len) return;

    if (flags & kGoodbye) {
        for (size_t i = 0; i < peers_.size(); ++i) {
            if (peers_[i].mac != m.src) continue;
            PeerInfo lost = peers_[i];
            peers_.erase(peers_.begin() + static_cast<std::ptrdiff_t>(i));
            emit(PeerEvent::Lost, lost);
            break;
        }
        return;
    }

    if ((flags & kQuery) && !replyDue_) {
        replyDue_ = true;
        replyAt_ = now_ + (config_.replyJitterMs ? random_() % (config_.replyJitterMs + 1) : 0);
    }

    std::string name(reinterpret_cast<const char*>(p + 5), nameLen);
    const uint8_t* meta = p + 6 + nameLen;

    PeerInfo* peer = nullptr;
    for (PeerInfo& q : peers_) {
        if (q.mac == m.src) peer = &q;
    }
    if (!peer) {
        if (peers_.size() >= config_.maxPeers) return;
        PeerInfo fresh;
        fresh.mac = m.src;
        fresh.name = name;
        fresh.metadata.assign(meta, meta + metaLen);
        fresh.maxFrameSize = maxFrame;
        fresh.rssi = m.rssi;
        fresh.firstSeenMs = fresh.lastSeenMs = now_;
        peers_.push_back(fresh);
        emit(PeerEvent::Found, fresh);
        return;
    }

    peer->lastSeenMs = now_;
    peer->rssi = m.rssi;
    bool changed = peer->name != name || peer->maxFrameSize != maxFrame || peer->metadata.size() != metaLen ||
                   !std::equal(peer->metadata.begin(), peer->metadata.end(), meta);
    if (changed) {
        peer->name = name;
        peer->metadata.assign(meta, meta + metaLen);
        peer->maxFrameSize = maxFrame;
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
