// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <vector>

#include "discovery.h"
#include "radio.h"

namespace nowtp {

struct ChannelConfig {
    /// Follow peers that announce a move to another channel, and search the
    /// other channels when every anchor peer has gone silent. An anchor is a
    /// node whose channel is fixed: by the access point its station is
    /// connected to, by its own soft-AP, or by `anchor` below.
    bool follow = true;
    /// Also search when no anchor has been seen at all yet: for nodes that
    /// must find a master whose access point may be on any channel, e.g.
    /// right after boot.
    bool findAnchor = false;
    /// Announce this node as an anchor although no access point fixes its
    /// channel. Anchors never search; the others follow them.
    bool anchor = false;
    /// Time without any anchor before searching. Peers are only reported lost
    /// after DiscoveryConfig::peerTimeoutMs, so this adds to that.
    uint32_t searchAfterMs = 2000;
    /// Listening time per channel during a search. Peers answer a discovery
    /// query within about 100 ms.
    uint32_t dwellMs = 250;
    /// Pause after a search that found nothing.
    uint32_t retryMs = 15000;
    /// Channels to search; empty searches 1-13.
    std::vector<uint8_t> channels;
};

/// Keeps a node on the same channel as its peers.
///
/// A node that is free to choose its channel (no access point fixes it)
/// follows the others: it switches when a peer announces a move
/// (Discovery::announceMove()), and when every anchor it knew has gone silent,
/// for example because the master's station roamed to an access point on
/// another channel, it searches the other channels with discovery queries
/// until an anchor answers. A search makes the node deaf on its own channel
/// for up to dwellMs per channel.
///
/// Platform-independent and single-threaded: the owner feeds it discovery
/// events and calls tick().
class ChannelFollower {
public:
    using ChannelHandler = std::function<void(uint8_t channel)>;

    ChannelFollower(Discovery& discovery, RadioControl& radio, const ChannelConfig& config);

    ChannelFollower(const ChannelFollower&) = delete;
    ChannelFollower& operator=(const ChannelFollower&) = delete;

    void start(uint32_t nowMs);
    void stop();
    void tick(uint32_t nowMs);

    /// Pauses following while something else moves the radio (deep discovery).
    void setSuspended(bool suspended, uint32_t nowMs);
    bool suspended() const { return suspended_; }

    // Discovery events, forwarded by the owner.
    void onPeerEvent(PeerEvent event, const PeerInfo& peer, uint32_t nowMs);
    void onPeerMoved(const PeerInfo& peer, uint8_t channel, uint32_t nowMs);
    /// Our channel changed outside the follower (a roaming station, the application).
    void onChannelChanged(uint8_t channel, uint32_t nowMs);

    /// Searches the channels now for any peer. Fails with InvalidState when an
    /// access point fixes our channel.
    Status search(uint32_t nowMs);
    bool searching() const { return searching_; }

    /// Called after the follower moved the radio to another channel.
    void onChannelChange(ChannelHandler handler) { handler_ = std::move(handler); }

private:
    struct Tracked {
        Mac mac;
        bool anchor;
    };

    bool free() const;
    bool anchorPresent() const;
    void track(const PeerInfo& peer);
    void beginSearch(bool anyPeer, uint32_t now);
    void step(uint32_t now);
    void endSearch(bool found, uint32_t now);
    void moveTo(uint8_t channel, uint32_t now);

    Discovery& discovery_;
    RadioControl& radio_;
    ChannelConfig config_;
    ChannelHandler handler_;
    std::vector<Tracked> peers_;
    bool running_ = false;
    bool suspended_ = false;
    bool hadAnchor_ = false;
    uint32_t okSince_ = 0;  // last time an anchor was present (or none was needed)
    uint32_t nextSearchAt_ = 0;

    bool searching_ = false;
    bool searchAny_ = false;
    std::vector<uint8_t> plan_;
    size_t step_ = 0;
    uint32_t stepEnd_ = 0;
    uint8_t origin_ = 0;
};

}  // namespace nowtp
