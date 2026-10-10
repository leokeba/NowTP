// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "channel.h"

namespace nowtp {

namespace {

inline bool reached(uint32_t now, uint32_t deadline) {
    return static_cast<int32_t>(now - deadline) >= 0;
}

}  // namespace

ChannelFollower::ChannelFollower(Discovery& discovery, RadioControl& radio, const ChannelConfig& config)
    : discovery_(discovery), radio_(radio), config_(config) {
    if (config_.dwellMs == 0) config_.dwellMs = 1;
}

void ChannelFollower::start(uint32_t now) {
    running_ = true;
    okSince_ = now;
    nextSearchAt_ = now;
}

void ChannelFollower::stop() {
    running_ = false;
    searching_ = false;
    peers_.clear();
    hadAnchor_ = false;
}

bool ChannelFollower::free() const {
    return config_.follow && !config_.anchor && !radio_.channelFixed();
}

bool ChannelFollower::anchorPresent() const {
    for (const Tracked& t : peers_) {
        if (t.anchor) return true;
    }
    return false;
}

void ChannelFollower::setSuspended(bool suspended, uint32_t now) {
    if (suspended == suspended_) return;
    suspended_ = suspended;
    if (suspended && searching_) endSearch(false, now);
    okSince_ = now;  // whatever happened meanwhile, start counting afresh
}

void ChannelFollower::track(const PeerInfo& peer) {
    for (Tracked& t : peers_) {
        if (t.mac != peer.mac) continue;
        t.anchor = peer.anchor;
        return;
    }
    Tracked t = {peer.mac, peer.anchor};
    peers_.push_back(t);
}

void ChannelFollower::onPeerEvent(PeerEvent event, const PeerInfo& peer, uint32_t now) {
    if (!running_) return;
    if (event == PeerEvent::Lost) {
        // Always processed, so a peer lost while suspended is not kept forever.
        for (size_t i = 0; i < peers_.size(); ++i) {
            if (peers_[i].mac == peer.mac) {
                peers_.erase(peers_.begin() + static_cast<std::ptrdiff_t>(i));
                break;
            }
        }
        return;
    }
    // Peers heard while deep discovery visits other channels do not live on ours.
    if (suspended_) return;
    track(peer);
    if (!peer.anchor) {
        if (searching_ && searchAny_) endSearch(true, now);
        return;
    }
    hadAnchor_ = true;
    okSince_ = now;
    // Strong signals leak into adjacent channels: trust the channel the anchor states.
    if (free() && peer.channel != 0 && peer.channel != radio_.channel()) {
        if (searching_) searching_ = false;
        moveTo(peer.channel, now);
        return;
    }
    if (searching_) endSearch(true, now);
}

void ChannelFollower::onPeerMoved(const PeerInfo& peer, uint8_t channel, uint32_t now) {
    if (!running_ || suspended_ || !free()) return;
    // Once we know anchors, only they lead; until then any peer does.
    if (hadAnchor_ && !peer.anchor) return;
    if (channel == radio_.channel()) return;
    searching_ = false;
    moveTo(channel, now);
}

void ChannelFollower::onChannelChanged(uint8_t channel, uint32_t now) {
    (void)channel;
    if (!running_) return;
    searching_ = false;
    okSince_ = now;
    discovery_.discover(now);  // let peers on the new channel know us at once
}

void ChannelFollower::moveTo(uint8_t channel, uint32_t now) {
    if (radio_.setChannel(channel) != Status::Ok) return;
    okSince_ = now;
    discovery_.discover(now);
    if (handler_) {
        ChannelHandler h = handler_;
        h(channel);
    }
}

Status ChannelFollower::search(uint32_t now) {
    if (!running_) return Status::InvalidState;
    if (radio_.channelFixed()) return Status::InvalidState;
    if (!searching_) beginSearch(true, now);
    return Status::Ok;
}

void ChannelFollower::beginSearch(bool anyPeer, uint32_t now) {
    searching_ = true;
    searchAny_ = anyPeer;
    origin_ = radio_.channel();
    plan_.clear();
    std::vector<uint8_t> all = config_.channels;
    if (all.empty()) {
        for (uint8_t c = 1; c <= 13; ++c) all.push_back(c);
    }
    for (uint8_t c : all) {
        if (c != origin_) plan_.push_back(c);
    }
    plan_.push_back(origin_);  // end where we started: the peers may come back there
    step_ = 0;
    step(now);
}

void ChannelFollower::step(uint32_t now) {
    while (step_ < plan_.size()) {
        uint8_t ch = plan_[step_];
        Status st = ch == radio_.channel() ? Status::Ok : radio_.setChannel(ch);
        if (st == Status::InvalidState) {
            searching_ = false;  // an access point took over the channel
            return;
        }
        if (st != Status::Ok) {
            step_++;  // not allowed in this country, for example
            continue;
        }
        discovery_.discover(now);
        stepEnd_ = now + config_.dwellMs;
        return;
    }
    endSearch(false, now);
}

void ChannelFollower::endSearch(bool found, uint32_t now) {
    searching_ = false;
    okSince_ = now;
    if (found) {
        if (radio_.channel() != origin_ && handler_) {
            ChannelHandler h = handler_;
            h(radio_.channel());
        }
        return;
    }
    if (radio_.channel() != origin_) radio_.setChannel(origin_);
    nextSearchAt_ = now + config_.retryMs;
}

void ChannelFollower::tick(uint32_t now) {
    if (!running_ || suspended_) return;
    if (searching_) {
        if (reached(now, stepEnd_)) {
            step_++;
            step(now);
        }
        return;
    }
    bool wanted = hadAnchor_ || config_.findAnchor;
    if (!free() || !wanted || anchorPresent()) {
        okSince_ = now;
        return;
    }
    if (reached(now, okSince_ + config_.searchAfterMs) && reached(now, nextSearchAt_)) beginSearch(false, now);
}

}  // namespace nowtp
