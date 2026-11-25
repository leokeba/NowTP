// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "channel.h"

#include <string.h>

#include "heap.h"

namespace nowtp {

namespace {

inline bool reached(uint32_t now, uint32_t deadline) {
    return static_cast<int32_t>(now - deadline) >= 0;
}

}  // namespace

constexpr size_t ChannelFollower::kMaxAnchors;
constexpr size_t ChannelSweep::kMaxNodes;

size_t ChannelSweep::count(uint8_t ch, bool anchorsOnly) const {
    size_t n = 0;
    for (const SweptNode& s : nodes) {
        if (s.channel == ch && (s.anchor || !anchorsOnly)) n++;
    }
    return n;
}

ChannelFollower::ChannelFollower(Discovery& discovery, RadioControl& radio, const ChannelConfig& config)
    : discovery_(discovery), radio_(radio), config_(config) {
    if (config_.dwellMs == 0) config_.dwellMs = 1;
    // Searching and tracking follow radio and peer events: nothing to allocate then.
    plan_.reserve((config_.channels.empty() ? 13 : config_.channels.size()) + 2);
    peers_.reserve(kMaxAnchors);
    if (config_.pick == ChannelPick::Busiest) reserveSweep();
}

// The report's room, taken once: sweeps record within it.
bool ChannelFollower::reserveSweep() {
    if (sweep_.nodes.capacity() >= ChannelSweep::kMaxNodes) return true;
    if (!heap::fits(ChannelSweep::kMaxNodes * sizeof(SweptNode))) return false;
    sweep_.nodes.reserve(ChannelSweep::kMaxNodes);
    return true;
}

void ChannelFollower::start(uint32_t now) {
    running_ = true;
    okSince_ = now;
    nextSearchAt_ = now;
    if (!free()) return;
    if (config_.preferred != 0 && config_.preferred != radio_.channel() &&
        radio_.setChannel(config_.preferred) == Status::Ok) {  // not allowed here: stay
        discovery_.discover(now);
    }
    // Only a sweep tells which channel is busiest; a preferred channel is
    // kept if it hears nodes (see settled()).
    sweepDue_ = config_.pick == ChannelPick::Busiest && config_.findAnchor && config_.preferred == 0;
}

void ChannelFollower::stop() {
    running_ = false;
    if (searching_ && full_) abortSweep();
    searching_ = false;
    peers_.clear();
    hadAnchor_ = false;
    pinned_ = 0;
    sweepDue_ = false;
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

bool ChannelFollower::nodeHere() const {
    bool any = false;
    discovery_.forEachPeer([&any](const PeerInfo& p) {
        if (!p.otherChannel) any = true;
    });
    return any;
}

// Where we are is fine: an anchor answers, or, after settling on the busiest
// channel without one, any node does.
bool ChannelFollower::settled() const {
    if (anchorPresent()) return true;
    return config_.pick == ChannelPick::Busiest && !hadAnchor_ && nodeHere();
}

void ChannelFollower::setSuspended(bool suspended, uint32_t now) {
    if (suspended == suspended_) return;
    suspended_ = suspended;
    if (suspended && searching_) {
        if (full_) abortSweep();
        endSearch(false, now);
    }
    okSince_ = now;  // whatever happened meanwhile, start counting afresh
}

// Only anchors matter, and a few at most: the list is reserved, never grown.
void ChannelFollower::track(const PeerInfo& peer) {
    for (size_t i = 0; i < peers_.size(); ++i) {
        if (peers_[i].mac != peer.mac) continue;
        if (!peer.anchor) peers_.erase(peers_.begin() + static_cast<std::ptrdiff_t>(i));
        return;
    }
    if (!peer.anchor || peers_.size() >= kMaxAnchors) return;
    Tracked t = {peer.mac, true};
    peers_.push_back(t);
}

void ChannelFollower::onPeerEvent(PeerEvent event, const PeerInfo& peer, uint32_t now) {
    if (!running_) return;
    if (event == PeerEvent::Lost) {
        // Always processed, so a peer lost while suspended is not kept forever.
        // Discovery has already dropped the peer: it counts as here if it was.
        bool wasSettled = anchorPresent() || (config_.pick == ChannelPick::Busiest && !hadAnchor_ &&
                                              (!peer.otherChannel || nodeHere()));
        for (size_t i = 0; i < peers_.size(); ++i) {
            if (peers_[i].mac == peer.mac) {
                peers_.erase(peers_.begin() + static_cast<std::ptrdiff_t>(i));
                break;
            }
        }
        // Present until now, however long ago tick() last saw it.
        if (wasSettled && !settled()) okSince_ = now;
        return;
    }
    // Peers heard while deep discovery visits other channels do not live on
    // ours; a sweep sorts out what it heard when it ends.
    if (suspended_ || (searching_ && full_)) return;
    track(peer);
    if (!peer.anchor) {
        if (searching_ && searchAny_) endSearch(true, now);
        return;
    }
    hadAnchor_ = true;
    okSince_ = now;
    if (pinned_ != 0) return;
    // Strong signals leak into adjacent channels: trust the channel the anchor states.
    if (free() && peer.channel != 0 && peer.channel != radio_.channel()) {
        if (searching_) searching_ = false;
        moveTo(peer.channel, now);
        return;
    }
    if (searching_) endSearch(true, now);
}

void ChannelFollower::onPeerMoved(const PeerInfo& peer, uint8_t channel, uint32_t now) {
    if (!running_ || suspended_ || !free() || pinned_ != 0 || (searching_ && full_)) return;
    // Once we know anchors, only they lead; until then any peer does.
    if (hadAnchor_ && !peer.anchor) return;
    if (channel == radio_.channel()) return;
    searching_ = false;
    moveTo(channel, now);
}

void ChannelFollower::onChannelChanged(uint8_t channel, uint32_t now) {
    if (!running_) return;
    if (searching_ && full_) abortSweep();
    searching_ = false;
    sweepDue_ = false;
    okSince_ = now;
    if (pinned_ != 0 && channel != 0) pinned_ = channel;  // the application moved us
    discovery_.discover(now);  // let peers on the new channel know us at once
}

void ChannelFollower::moveTo(uint8_t channel, uint32_t now) {
    if (radio_.setChannel(channel) != Status::Ok) return;
    okSince_ = now;
    discovery_.discover(now);
    if (handler_) handler_(channel);
}

Status ChannelFollower::search(uint32_t now) {
    if (!running_) return Status::InvalidState;
    if (radio_.channelFixed()) return Status::InvalidState;
    if (config_.pick == ChannelPick::Busiest) return sweep(now);
    if (pinned_ != 0) return Status::InvalidState;
    if (!searching_) beginSearch(true, false, now);
    return Status::Ok;
}

Status ChannelFollower::sweep(uint32_t now) {
    if (!running_) return Status::InvalidState;
    if (radio_.channelFixed()) return Status::InvalidState;
    if (searching_ && full_) return Status::Ok;
    if (!reserveSweep()) return Status::NoMemory;
    if (searching_) {
        searching_ = false;  // a first-found search: start over from where it began
        if (radio_.channel() != origin_) radio_.setChannel(origin_);
    }
    sweepDue_ = false;
    beginSearch(true, true, now);
    return Status::Ok;
}

Status ChannelFollower::pin(uint8_t channel, uint32_t now) {
    if (!running_) return Status::InvalidState;
    if (channel == 0) {
        unpin(now);
        return Status::Ok;
    }
    if (radio_.channelFixed()) return Status::InvalidState;
    if (searching_) {
        if (full_) abortSweep();
        searching_ = false;
    }
    sweepDue_ = false;
    if (channel != radio_.channel()) {
        Status st = radio_.setChannel(channel);
        if (st != Status::Ok) return st;
        peers_.clear();  // the anchors we knew are elsewhere
        discovery_.discover(now);
    }
    pinned_ = channel;
    okSince_ = now;
    return Status::Ok;
}

void ChannelFollower::unpin(uint32_t now) {
    pinned_ = 0;
    okSince_ = now;  // search as configured, from now
    nextSearchAt_ = now;
}

void ChannelFollower::beginSearch(bool anyPeer, bool full, uint32_t now) {
    searching_ = true;
    searchAny_ = anyPeer;
    full_ = full;
    origin_ = radio_.channel();
    plan_.clear();
    uint8_t first = config_.preferred != origin_ ? config_.preferred : 0;
    if (first != 0) plan_.push_back(first);
    size_t count = config_.channels.empty() ? 13 : config_.channels.size();
    for (size_t i = 0; i < count; ++i) {
        uint8_t c = config_.channels.empty() ? static_cast<uint8_t>(i + 1) : config_.channels[i];
        if (c != origin_ && c != first) plan_.push_back(c);  // within the reserved capacity
    }
    plan_.push_back(origin_);  // end where we started: the peers may come back there
    if (full) {
        sweep_.sequence++;
        sweep_.startedMs = now;
        sweep_.finishedMs = 0;
        sweep_.running = true;
        sweep_.complete = false;
        sweep_.channel = 0;
        sweep_.nodes.clear();
    }
    step_ = 0;
    step(now);
}

void ChannelFollower::step(uint32_t now) {
    while (step_ < plan_.size()) {
        uint8_t ch = plan_[step_];
        Status st = ch == radio_.channel() ? Status::Ok : radio_.setChannel(ch);
        if (st == Status::InvalidState) {
            if (full_) abortSweep();
            searching_ = false;  // an access point took over the channel
            return;
        }
        if (st != Status::Ok) {
            step_++;  // not allowed in this country, for example
            continue;
        }
        discovery_.discover(now);
        stepStart_ = now;
        stepEnd_ = now + config_.dwellMs;
        return;
    }
    if (full_) {
        endSweep(now);
    } else {
        endSearch(false, now);
    }
}

// The nodes heard since `since`, on `channel` or leaking in from another.
// Discovery's table is read, not its events: a node already known (from our
// own channel, or an earlier sweep) is not Found again.
void ChannelFollower::record(uint8_t channel, uint32_t since) {
    std::vector<SweptNode>& nodes = sweep_.nodes;
    discovery_.forEachPeer([&](const PeerInfo& p) {
        if (!reached(p.lastSeenMs, since)) return;
        uint8_t stated = p.channel != 0 ? p.channel : channel;
        SweptNode* s = nullptr;
        for (SweptNode& n : nodes) {
            if (n.mac == p.mac) s = &n;
        }
        bool fresh = s == nullptr;
        if (fresh) {
            if (nodes.size() >= nodes.capacity()) return;  // never grown
            SweptNode blank;
            memset(&blank, 0, sizeof(blank));
            nodes.push_back(blank);
            s = &nodes.back();
            s->mac = p.mac;
        }
        // Leaking in from an adjacent channel is weaker: prefer its own channel.
        if (fresh || stated == channel) s->rssi = p.rssi;
        s->channel = stated;
        s->anchor = p.anchor;
        size_t len = p.name.size() < Discovery::kMaxName ? p.name.size() : Discovery::kMaxName;
        memcpy(s->name, p.name.data(), len);
        s->name[len] = 0;
    });
}

// Most nodes, then most anchors, then where we are, then the preferred
// channel, then the lowest; 0 when no channel answered.
uint8_t ChannelFollower::busiest() const {
    uint8_t best = 0;
    size_t bestNodes = 0, bestAnchors = 0;
    for (uint8_t c : plan_) {
        size_t n = sweep_.count(c), a = sweep_.count(c, true);
        if (n == 0) continue;
        bool better = best == 0 || n > bestNodes || (n == bestNodes && a > bestAnchors);
        if (!better && n == bestNodes && a == bestAnchors) {
            if (best == origin_) {
                better = false;
            } else if (c == origin_) {
                better = true;
            } else if (best == config_.preferred) {
                better = false;
            } else if (c == config_.preferred) {
                better = true;
            } else {
                better = c < best;
            }
        }
        if (better) {
            best = c;
            bestNodes = n;
            bestAnchors = a;
        }
    }
    return best;
}

void ChannelFollower::abortSweep() {
    sweep_.running = false;
    sweep_.complete = false;
    sweep_.finishedMs = 0;
    sweep_.channel = 0;
    full_ = false;
}

void ChannelFollower::endSweep(uint32_t now) {
    searching_ = false;
    full_ = false;
    okSince_ = now;
    uint8_t target = pinned_ != 0 ? pinned_ : busiest();
    if (target == 0) {
        target = origin_;  // nothing answered
        nextSearchAt_ = now + config_.retryMs;
    }
    if (target != radio_.channel() && radio_.setChannel(target) != Status::Ok) target = radio_.channel();
    sweep_.running = false;
    sweep_.complete = true;
    sweep_.finishedMs = now;
    sweep_.channel = radio_.channel();
    if (pinned_ == 0) {
        // Discovery already knows the nodes here, so no Found event will name
        // the anchors: take them from the sweep.
        peers_.clear();
        for (const SweptNode& s : sweep_.nodes) {
            if (s.channel != target || !s.anchor || peers_.size() >= kMaxAnchors) continue;
            Tracked t = {s.mac, true};
            peers_.push_back(t);
        }
        hadAnchor_ = !peers_.empty();
    }
    discovery_.discover(now);  // we were away: tell the nodes here at once
    if (radio_.channel() != origin_ && handler_) handler_(radio_.channel());
}

void ChannelFollower::endSearch(bool found, uint32_t now) {
    searching_ = false;
    okSince_ = now;
    if (found) {
        if (radio_.channel() != origin_ && handler_) handler_(radio_.channel());
        return;
    }
    if (radio_.channel() != origin_) radio_.setChannel(origin_);
    nextSearchAt_ = now + config_.retryMs;
}

void ChannelFollower::tick(uint32_t now) {
    if (!running_ || suspended_) return;
    if (searching_) {
        if (reached(now, stepEnd_)) {
            if (full_) record(plan_[step_], stepStart_);
            step_++;
            step(now);
        }
        return;
    }
    if (pinned_ != 0) {
        okSince_ = now;
        return;
    }
    if (sweepDue_) {
        sweepDue_ = false;
        if (free() && reserveSweep()) beginSearch(false, true, now);
        return;
    }
    bool wanted = hadAnchor_ || config_.findAnchor;
    if (!free() || !wanted || settled()) {
        okSince_ = now;
        return;
    }
    if (reached(now, okSince_ + config_.searchAfterMs) && reached(now, nextSearchAt_)) {
        bool full = config_.pick == ChannelPick::Busiest && reserveSweep();
        beginSearch(false, full, now);
    }
}

void ChannelFollower::nextTick(Deadline& d) const {
    if (!running_ || suspended_) return;
    if (searching_) {
        d.at(stepEnd_);
        return;
    }
    if (pinned_ != 0) return;
    if (sweepDue_) {
        d.at(okSince_);
        return;
    }
    bool wanted = hadAnchor_ || config_.findAnchor;
    if (!free() || !wanted || settled()) return;
    uint32_t at = okSince_ + config_.searchAfterMs;
    d.at(static_cast<int32_t>(nextSearchAt_ - at) > 0 ? nextSearchAt_ : at);
}

}  // namespace nowtp
