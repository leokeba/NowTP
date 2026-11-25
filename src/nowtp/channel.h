// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <vector>

#include "discovery.h"
#include "radio.h"

namespace nowtp {

/// How a search picks the channel to settle on.
enum class ChannelPick : uint8_t {
    /// Stop on the first channel where an anchor answers (any node, for
    /// ChannelFollower::search()).
    First,
    /// Listen on every channel, then settle on the one where the most nodes
    /// answered. Ties go to the channel with more anchors, then the current
    /// channel, then `ChannelConfig::preferred`, then the lowest. A node that
    /// settled where no anchor answered stays while it hears any node there.
    Busiest,
};

struct ChannelConfig {
    /// Follow peers that announce a move to another channel, and search the
    /// other channels when every anchor peer has gone silent. An anchor is a
    /// node whose channel is fixed: by the access point its station is
    /// connected to, by its own soft-AP, or by `anchor` below.
    ///
    /// Who is followed: the leader, if the application set one
    /// (ChannelFollower::setLeader()), and no one else. Otherwise, with
    /// ChannelPick::First, an anchor that announces a move from our channel,
    /// or states another channel (heard from an adjacent one); until an anchor
    /// is known, any peer's move. With ChannelPick::Busiest, only the last
    /// node on our channel, when it announces a move: nodes heard from other
    /// channels never move it, sweeps decide.
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
    /// How a search picks its channel. Busiest also sweeps every channel at
    /// start() when findAnchor is set and `preferred` is 0.
    ChannelPick pick = ChannelPick::First;
    /// Channel to start on and to search first (0: none), e.g. the last one
    /// used, saved by the application. With findAnchor, a node that hears what
    /// it looks for there (an anchor, or with Busiest any node) stays without
    /// searching.
    uint8_t preferred = 0;
};

/// A node heard during a sweep (see ChannelSweep).
struct SweptNode {
    Mac mac;
    /// The channel it states; the one it was heard on if it does not say.
    uint8_t channel;
    bool anchor;
    int8_t rssi;  ///< dBm, preferably as heard on its own channel.
    char name[Discovery::kMaxName + 1];  ///< Null-terminated.
};

/// What the last sweep heard on each channel. A sweep listens on every
/// channel: search() with ChannelPick::Busiest, sweep(), and the boot sweep.
/// It sees at most DiscoveryConfig::maxPeers nodes at once (lost ones make
/// room after 1.5 announcement intervals) and keeps kMaxNodes.
struct ChannelSweep {
    static constexpr size_t kMaxNodes = 32;
    uint32_t sequence = 0;    ///< Sweeps begun so far; 0: none yet.
    uint32_t startedMs = 0;
    uint32_t finishedMs = 0;  ///< When it ended (0 while running).
    bool running = false;     ///< `nodes` fills as it goes.
    bool complete = false;    ///< Every channel was visited (false: interrupted).
    /// The channel it settled on or returned to; 0 while running or if interrupted.
    uint8_t channel = 0;
    std::vector<SweptNode> nodes;

    /// Nodes heard on `channel` (only anchors, with `anchorsOnly`).
    size_t count(uint8_t channel, bool anchorsOnly = false) const;
};

/// Keeps a node on the same channel as its peers.
///
/// A node that is free to choose its channel (no access point fixes it)
/// follows the others: it switches when a peer announces a move
/// (Discovery::announceMove(); ChannelConfig::follow says whose), and when
/// every anchor it knew has gone silent, for example because the master's
/// station roamed to an access point on
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
    /// Adds when tick() has work next (a search step, a search to begin).
    void nextTick(Deadline& d) const;

    /// Pauses following while something else moves the radio (deep discovery).
    void setSuspended(bool suspended, uint32_t nowMs);
    bool suspended() const { return suspended_; }

    // Discovery events, forwarded by the owner.
    void onPeerEvent(PeerEvent event, const PeerInfo& peer, uint32_t nowMs);
    void onPeerMoved(const PeerInfo& peer, uint8_t channel, uint32_t nowMs);
    /// Our channel changed outside the follower (a roaming station, the application).
    void onChannelChanged(uint8_t channel, uint32_t nowMs);

    /// Searches the channels now for any peer (see ChannelConfig::pick). Fails
    /// with InvalidState when an access point fixes our channel.
    Status search(uint32_t nowMs);
    /// Listens on every channel, recording what answers (see lastSweep()), then
    /// settles on the busiest channel (ChannelPick::Busiest), or returns to
    /// the pinned one. Fails with InvalidState when an access point fixes our
    /// channel, with NoMemory if the report can't be allocated.
    Status sweep(uint32_t nowMs);
    bool searching() const { return searching_; }
    /// A search that visits every channel is running.
    bool sweeping() const { return searching_ && full_; }
    const ChannelSweep& lastSweep() const { return sweep_; }

    /// Moves to `channel` (quietly: peers are not told) and stays there:
    /// no following, no searching, until unpin(). sweep() still works and
    /// comes back. 0 unpins. Fails with InvalidState when an access point
    /// fixes our channel.
    Status pin(uint8_t channel, uint32_t nowMs);
    void unpin(uint32_t nowMs);
    /// The pinned channel; 0 when following.
    uint8_t pinned() const { return pinned_; }

    /// Follows `peer` (its MAC or device id), e.g. the node the user is
    /// interacting with, and no one else: its announced moves, and the channel
    /// it states, from now on (at the next tick() if it states another one
    /// already). It keeps us where it is (no search while it answers), and a
    /// sweep that hears it settles on its channel. Pinning still wins.
    void setLeader(const Mac& peer, uint32_t nowMs);
    /// Follows as ChannelConfig::follow says again.
    void clearLeader();
    /// The leader, if `hasLeader()`.
    const Mac& leader() const { return leader_; }
    bool hasLeader() const { return hasLeader_; }

    /// Called after the follower moved the radio to another channel.
    void onChannelChange(ChannelHandler handler) { handler_.set(std::move(handler)); }

private:
    bool free() const;
    bool here(const PeerInfo& peer) const;
    bool leads(const PeerInfo& peer) const;
    const PeerInfo* findLeader() const;
    bool anchorPresent() const;
    bool nodeHere() const;
    bool settled() const;
    bool reserveSweep();
    void joinLeader(uint32_t now);
    void beginSearch(bool anyPeer, bool full, uint32_t now);
    void step(uint32_t now);
    void record(uint8_t channel, uint32_t since);
    uint8_t busiest() const;
    void endSearch(bool found, uint32_t now);
    void endSweep(uint32_t now);
    void abortSweep();
    bool moveTo(uint8_t channel, uint32_t now);

    Discovery& discovery_;
    RadioControl& radio_;
    ChannelConfig config_;
    Callback<void(uint8_t)> handler_;
    bool running_ = false;
    bool suspended_ = false;
    bool hadAnchor_ = false;
    uint32_t okSince_ = 0;  // last time an anchor was present (or none was needed)
    uint32_t nextSearchAt_ = 0;

    uint8_t pinned_ = 0;
    bool hasLeader_ = false;
    Mac leader_ = Mac();
    bool joinDue_ = false;  // go where the leader is, at the next tick()
    uint32_t joinAt_ = 0;
    bool sweepDue_ = false;  // the boot sweep

    bool searching_ = false;
    bool searchAny_ = false;
    bool full_ = false;  // a sweep: every channel, recorded
    uint32_t stepStart_ = 0;
    ChannelSweep sweep_;
    std::vector<uint8_t> plan_;
    size_t step_ = 0;
    uint32_t stepEnd_ = 0;
    uint8_t origin_ = 0;
};

}  // namespace nowtp
