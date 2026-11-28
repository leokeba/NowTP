// Host-side tests for the NowTP protocol engine: channel following.

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "heap_limit.h"

#include "nowtp/channel.h"
#include "nowtp/crypto.h"
#include "nowtp/diagnostics.h"
#include "nowtp/credit_book.h"
#include "nowtp/discovery.h"
#include "nowtp/duplicate_filter.h"
#include "nowtp/engine.h"
#include "nowtp/frame_sizes.h"
#include "nowtp/link_monitor.h"
#include "nowtp/peer_table.h"
#include "nowtp/security.h"
#include "nowtp/send_tracker.h"
#include "nowtp/stream.h"
#include "nowtp/table.h"
#include "nowtp/timesync.h"
#include "nowtp/wire.h"
#include "sim.h"

using namespace nowtp;

#include "harness.h"
#include "helpers.h"

// ---------------------------------------------------------------------------
// Channel following
TEST(channel_peers_follow_announced_move) {
    FollowRig rig;
    size_t a = rig.add(1, false), b = rig.add(1, false), c = rig.add(1, false);
    rig.start();
    rig.net.run(1000);
    CHECK_EQ(rig.disc[b]->peers().size(), 2u);

    CHECK(rig.disc[a]->announceMove(6, rig.net.now()));
    rig.net.run(20);  // the notices go out on the old channel
    CHECK(rig.net.node(a).radio.setChannel(6) == Status::Ok);
    rig.fol[a]->onChannelChanged(6, rig.net.now());
    rig.net.run(500);
    CHECK_EQ(rig.chan(b), 6);
    CHECK_EQ(rig.chan(c), 6);
    CHECK_EQ(rig.disc[a]->peers().size(), 2u);
    CHECK(rig.disc[b]->find(rig.net.mac(a)) != nullptr);
    CHECK_EQ(rig.disc[b]->find(rig.net.mac(a))->channel, 6);
}

TEST(channel_followers_find_roaming_anchor) {
    FollowRig rig;
    size_t master = rig.add(1, true), b = rig.add(1, false), c = rig.add(1, false);
    rig.start();
    rig.net.run(1000);
    const PeerInfo* anchor = rig.disc[b]->find(rig.net.mac(master));
    CHECK(anchor && anchor->anchor);

    // The master's station roams to an access point on channel 9, without notice.
    rig.net.node(master).radio.chan = 9;
    rig.fol[master]->onChannelChanged(9, rig.net.now());
    bool followed = rig.net.runUntil([&] { return rig.chan(b) == 9 && rig.chan(c) == 9; }, 20000);
    CHECK(followed);
    rig.net.run(1000);
    CHECK(rig.disc[b]->find(rig.net.mac(master)) != nullptr);
    CHECK(rig.disc[master]->find(rig.net.mac(c)) != nullptr);
    CHECK(rig.moves[b] >= 1);
}

TEST(channel_find_anchor_at_boot) {
    FollowRig rig;
    ChannelConfig find;
    find.findAnchor = true;
    size_t master = rig.add(11, true), node = rig.add(1, false, find);
    rig.start();
    CHECK(rig.net.runUntil([&] { return rig.chan(node) == 11; }, 15000));
    rig.net.run(500);
    CHECK(rig.disc[node]->find(rig.net.mac(master)) != nullptr);
}

TEST(channel_moves_to_the_channel_an_anchor_states) {
    FollowRig rig;
    size_t master = rig.add(6, true), node = rig.add(5, false);
    rig.start();
    // Adjacent-channel leakage: the simulation only connects equal channels,
    // so deliver one of the master's announcements by hand.
    rig.net.run(600);
    std::vector<uint8_t> hello;
    for (size_t i = rig.net.log.size(); i-- > 0;) {
        if (rig.net.log[i].from == master) {
            hello = rig.net.log[i].data;
            break;
        }
    }
    CHECK(!hello.empty());
    rig.net.inject(node, rig.net.mac(master), hello);
    rig.net.run(10);
    CHECK_EQ(rig.chan(node), 6);
}

TEST(channel_no_search_without_anchors) {
    FollowRig rig;
    size_t a = rig.add(3, false), b = rig.add(3, false);
    rig.start();
    rig.net.run(1000);
    rig.net.node(b).online = false;
    rig.net.run(30000);
    CHECK_EQ(rig.chan(a), 3);
    CHECK_EQ(rig.moves[a], 0);
    CHECK(!rig.fol[a]->searching());
}

TEST(channel_search_returns_home_when_nothing_found) {
    FollowRig rig;
    ChannelConfig cc;
    cc.retryMs = 60000;
    size_t master = rig.add(4, true), node = rig.add(4, false, cc);
    rig.start();
    rig.net.run(1000);
    rig.net.node(master).online = false;
    CHECK(rig.net.runUntil([&] { return rig.fol[node]->searching(); }, 10000));
    CHECK(rig.net.runUntil([&] { return !rig.fol[node]->searching(); }, 10000));
    CHECK_EQ(rig.chan(node), 4);
    rig.net.node(master).online = true;  // back where it was
    rig.net.run(1500);
    CHECK(rig.disc[node]->find(rig.net.mac(master)) != nullptr);
}

TEST(channel_anchors_ignore_moves_and_followers_ignore_non_anchors) {
    FollowRig rig;
    size_t master = rig.add(1, true), b = rig.add(1, false), c = rig.add(1, false);
    rig.start();
    rig.net.run(1000);
    rig.disc[c]->announceMove(8, rig.net.now());  // c is no anchor
    rig.net.run(50);
    CHECK_EQ(rig.chan(master), 1);
    CHECK_EQ(rig.chan(b), 1);  // b follows the master, not c
}

TEST(channel_follower_pauses_while_suspended) {
    FollowRig rig;
    size_t master = rig.add(1, true), b = rig.add(1, false);
    rig.start();
    rig.net.run(1000);
    rig.fol[b]->setSuspended(true, rig.net.now());
    rig.net.node(master).online = false;
    rig.net.run(8000);
    CHECK(!rig.fol[b]->searching());
    CHECK_EQ(rig.chan(b), 1);
    (void)master;
}

TEST(channel_busiest_sweeps_at_boot_and_settles_where_most_nodes_are) {
    FollowRig rig;
    ChannelConfig cc;
    cc.findAnchor = true;
    cc.pick = ChannelPick::Busiest;
    // A stray anchor on channel 1, where the node starts, and three nodes
    // without anchors on channel 6.
    size_t stray = rig.add(1, true);
    size_t a = rig.add(6, false), b = rig.add(6, false), c = rig.add(6, false);
    size_t node = rig.add(1, false, cc);
    rig.start();
    CHECK(rig.net.runUntil([&] { return rig.fol[node]->sweeping(); }, 100));
    CHECK(rig.net.runUntil([&] { return !rig.fol[node]->searching(); }, 10000));
    CHECK_EQ(rig.chan(node), 6);
    CHECK_EQ(rig.moves[node], 1);
    const ChannelSweep& s = rig.fol[node]->lastSweep();
    CHECK_EQ(s.sequence, 1u);
    CHECK(s.complete && !s.running);
    CHECK_EQ(s.channel, 6);
    CHECK_EQ(s.count(6), 3u);
    CHECK_EQ(s.count(6, true), 0u);
    CHECK_EQ(s.count(1), 1u);
    CHECK_EQ(s.count(1, true), 1u);
    CHECK_EQ(s.nodes.size(), 4u);
    bool named = false;
    for (const SweptNode& n : s.nodes) {
        if (n.mac == rig.net.mac(stray)) named = std::string(n.name) == "n" + std::to_string(stray) && n.anchor;
    }
    CHECK(named);
    // No anchor here, but nodes: it stays, and doesn't sweep again.
    rig.net.run(40000);
    CHECK_EQ(rig.chan(node), 6);
    CHECK_EQ(rig.fol[node]->lastSweep().sequence, 1u);
    CHECK(rig.disc[a]->find(rig.net.mac(node)) != nullptr);
    // Once they all go, it looks again.
    rig.net.node(a).online = rig.net.node(b).online = rig.net.node(c).online = false;
    CHECK(rig.net.runUntil([&] { return rig.fol[node]->lastSweep().sequence == 2; }, 20000));
    CHECK(rig.net.runUntil([&] { return !rig.fol[node]->searching(); }, 10000));
    CHECK_EQ(rig.chan(node), 1);  // where the stray is
}

TEST(channel_busiest_prefers_anchors_then_the_current_channel) {
    FollowRig rig;
    ChannelConfig cc;
    cc.pick = ChannelPick::Busiest;
    rig.add(3, true);
    size_t free8 = rig.add(8, false);
    rig.add(8, true);
    rig.add(10, false);
    rig.add(10, false);
    size_t node = rig.add(10, false, cc);
    rig.start();
    rig.net.run(1000);
    // 10 and 8 tie on nodes (2 each, not counting us); 8 has an anchor.
    CHECK(rig.fol[node]->search(rig.net.now()) == Status::Ok);
    CHECK(rig.fol[node]->sweeping());
    CHECK(rig.net.runUntil([&] { return !rig.fol[node]->searching(); }, 10000));
    CHECK_EQ(rig.chan(node), 8);
    CHECK_EQ(rig.fol[node]->lastSweep().count(8), 2u);
    // Now 8 and 10 tie on nodes, and 8 and 3 on anchors: stay.
    rig.net.node(free8).online = false;
    rig.net.run(3000);
    size_t late = rig.add(3, false);
    rig.disc[late]->start(rig.net.now());
    rig.fol[late]->start(rig.net.now());
    rig.net.run(1000);
    CHECK(rig.fol[node]->sweep(rig.net.now()) == Status::Ok);
    CHECK(rig.net.runUntil([&] { return !rig.fol[node]->searching(); }, 10000));
    CHECK_EQ(rig.fol[node]->lastSweep().count(3), 2u);
    CHECK_EQ(rig.fol[node]->lastSweep().count(8), 1u);
    CHECK_EQ(rig.chan(node), 3);
}

TEST(channel_preferred_channel_is_kept_when_nodes_answer) {
    FollowRig rig;
    ChannelConfig cc;
    cc.findAnchor = true;
    cc.pick = ChannelPick::Busiest;
    cc.preferred = 6;
    rig.add(1, true);
    rig.add(6, false);
    size_t node = rig.add(1, false, cc);
    rig.start();
    CHECK_EQ(rig.chan(node), 6);
    rig.net.run(30000);
    CHECK_EQ(rig.chan(node), 6);
    CHECK_EQ(rig.fol[node]->lastSweep().sequence, 0u);
}

TEST(channel_preferred_channel_searched_first) {
    FollowRig rig;
    ChannelConfig cc;
    cc.preferred = 9;
    size_t low = rig.add(2, true), master = rig.add(9, true);
    size_t node = rig.add(9, false, cc);
    rig.start();
    rig.net.run(1000);
    // The master moves to 4, the node follows, then the master goes back
    // silently: the search tries channel 9 first, before the anchor on 2.
    CHECK(rig.disc[master]->announceMove(4, rig.net.now()));
    rig.net.run(20);
    rig.net.node(master).radio.chan = 4;
    rig.fol[master]->onChannelChanged(4, rig.net.now());
    CHECK(rig.net.runUntil([&] { return rig.chan(node) == 4; }, 1000));
    rig.net.run(1000);
    rig.net.node(master).radio.chan = 9;
    rig.fol[master]->onChannelChanged(9, rig.net.now());
    CHECK(rig.net.runUntil([&] { return rig.fol[node]->searching(); }, 10000));
    CHECK(rig.net.runUntil([&] { return !rig.fol[node]->searching(); }, 10000));
    CHECK_EQ(rig.chan(node), 9);
    (void)low;
}

TEST(channel_pinned_node_neither_follows_nor_searches) {
    FollowRig rig;
    size_t master = rig.add(1, true), node = rig.add(1, false);
    rig.add(9, false);
    rig.start();
    rig.net.run(1000);
    CHECK(rig.fol[node]->pin(4, rig.net.now()) == Status::Ok);
    CHECK_EQ(rig.chan(node), 4);
    CHECK_EQ(rig.fol[node]->pinned(), 4);
    rig.net.run(20000);  // no anchor here: it would search
    CHECK(!rig.fol[node]->searching());
    CHECK_EQ(rig.chan(node), 4);
    // A sweep comes back to the pinned channel.
    CHECK(rig.fol[node]->sweep(rig.net.now()) == Status::Ok);
    CHECK(rig.net.runUntil([&] { return !rig.fol[node]->searching(); }, 10000));
    CHECK_EQ(rig.chan(node), 4);
    const ChannelSweep& s = rig.fol[node]->lastSweep();
    CHECK(s.complete);
    CHECK_EQ(s.channel, 4);
    CHECK_EQ(s.count(1, true), 1u);
    CHECK_EQ(s.count(9), 1u);
    CHECK_EQ(rig.moves[node], 0);
    // Pinned on the master's channel, it ignores its moves.
    CHECK(rig.fol[node]->pin(1, rig.net.now()) == Status::Ok);
    rig.net.run(1000);
    CHECK(rig.disc[master]->announceMove(6, rig.net.now()));
    rig.net.run(20);
    rig.net.node(master).radio.chan = 6;
    rig.fol[master]->onChannelChanged(6, rig.net.now());
    rig.net.run(1000);
    CHECK_EQ(rig.chan(node), 1);
    // Following again, it searches and finds the master.
    rig.fol[node]->unpin(rig.net.now());
    CHECK_EQ(rig.fol[node]->pinned(), 0);
    CHECK(rig.net.runUntil([&] { return rig.chan(node) == 6 && !rig.fol[node]->searching(); }, 20000));
}

TEST(channel_sweep_fails_where_an_access_point_fixes_the_channel) {
    FollowRig rig;
    size_t node = rig.add(1, true);
    rig.start();
    CHECK(rig.fol[node]->sweep(rig.net.now()) == Status::InvalidState);
    CHECK(rig.fol[node]->pin(3, rig.net.now()) == Status::InvalidState);
    CHECK_EQ(rig.fol[node]->lastSweep().sequence, 0u);
}

// Anchors of other installations on neighbouring channels, heard faintly,
// must not toss a node around (seen on a remote in a house with anchors on
// 8, 9, 10 and 11): only a sweep decides where a Busiest node goes.
TEST(channel_busiest_ignores_nodes_heard_from_other_channels) {
    FollowRig rig;
    ChannelConfig cc;
    cc.findAnchor = true;
    cc.pick = ChannelPick::Busiest;
    cc.preferred = 8;
    size_t home = rig.add(8, true);
    size_t nine = rig.add(9, true), ten = rig.add(10, true), drifter = rig.add(9, false);
    size_t node = rig.add(8, false, cc);
    rig.start();
    rig.net.run(1000);
    CHECK(rig.disc[node]->find(rig.net.mac(home)) != nullptr);
    for (int round = 0; round < 10; ++round) {
        rig.leak(nine, node);
        rig.leak(ten, node);
        rig.leak(drifter, node);
        rig.net.run(1000);
    }
    const PeerInfo* faint = rig.disc[node]->find(rig.net.mac(ten));
    CHECK(faint != nullptr && faint->channel == 10 && faint->anchor);
    // Their moves aren't ours to follow either: they weren't on our channel.
    rig.leak(nine, node);
    rig.leak(drifter, node);
    CHECK(rig.disc[nine]->announceMove(8, rig.net.now()));
    CHECK(rig.disc[drifter]->announceMove(3, rig.net.now()));
    rig.net.run(20);
    rig.leak(nine, node);
    rig.leak(drifter, node);
    rig.net.run(5000);
    CHECK_EQ(rig.chan(node), 8);
    CHECK_EQ(rig.moves[node], 0);
    CHECK_EQ(rig.fol[node]->lastSweep().sequence, 0u);  // settled with the anchor here
}

// A First node that knows no anchor follows any peer's move, but only from
// its own channel: Discovery tells the move handler where the mover was.
TEST(channel_moves_heard_from_other_channels_are_ignored) {
    FollowRig rig;
    size_t stray = rig.add(6, false), neighbour = rig.add(5, false), node = rig.add(5, false);
    std::vector<uint8_t> movedFrom;
    rig.disc[node]->onPeerMoved([&](const PeerInfo& p, uint8_t ch) {
        movedFrom.push_back(p.channel);
        rig.fol[node]->onPeerMoved(p, ch, rig.net.now());
    });
    rig.start();
    rig.net.run(1000);
    rig.leak(stray, node);
    CHECK(rig.disc[stray]->announceMove(9, rig.net.now()));
    rig.net.run(20);
    rig.leak(stray, node);
    rig.net.run(100);
    CHECK_EQ(movedFrom.size(), 1u);
    CHECK_EQ(movedFrom[0], 6);
    CHECK_EQ(rig.chan(node), 5);
    // One from our channel is followed.
    CHECK(rig.disc[neighbour]->announceMove(9, rig.net.now()));
    rig.net.run(20);
    CHECK_EQ(movedFrom.size(), 2u);
    CHECK_EQ(movedFrom[1], 5);
    CHECK_EQ(rig.chan(node), 9);
}

// Without a leader, a Busiest node follows a move only when the mover was
// the last node on its channel.
TEST(channel_busiest_follows_the_last_node_here) {
    FollowRig rig;
    ChannelConfig cc;
    cc.findAnchor = true;
    cc.pick = ChannelPick::Busiest;
    cc.preferred = 6;
    size_t a = rig.add(6, true), b = rig.add(6, true), node = rig.add(6, false, cc);
    rig.start();
    rig.net.run(1000);
    rig.relocate(a, 3);
    rig.net.run(1000);
    CHECK_EQ(rig.chan(node), 6);  // b is still here
    CHECK_EQ(rig.moves[node], 0);
    rig.relocate(b, 11);
    rig.net.run(1000);
    CHECK_EQ(rig.chan(node), 11);
    CHECK_EQ(rig.moves[node], 1);
    CHECK(rig.disc[node]->find(rig.net.mac(b)) != nullptr);
    CHECK_EQ(rig.fol[node]->lastSweep().sequence, 0u);
}

// The leader set by the application, and only it, is followed: its moves
// from anywhere, the channel it states, and sweeps go where it is.
TEST(channel_leader_alone_is_followed) {
    FollowRig rig;
    ChannelConfig cc;
    cc.findAnchor = true;
    cc.pick = ChannelPick::Busiest;
    cc.preferred = 6;
    size_t lead = rig.add(6, true), other = rig.add(6, true), node = rig.add(6, false, cc);
    size_t crowd1 = rig.add(2, false), crowd2 = rig.add(2, false), crowd3 = rig.add(2, false);
    (void)crowd1, (void)crowd2, (void)crowd3;
    rig.start();
    rig.net.run(1000);
    rig.fol[node]->setLeader(rig.net.mac(lead), rig.net.now());
    CHECK(rig.fol[node]->hasLeader());
    rig.net.run(100);
    CHECK_EQ(rig.chan(node), 6);  // it's here: nothing to do

    // The leader moves while another node stays: followed.
    rig.relocate(lead, 9);
    rig.net.run(1000);
    CHECK_EQ(rig.chan(node), 9);
    CHECK_EQ(rig.moves[node], 1);

    // The leader goes silent; the last other node here leaves: not followed.
    rig.relocate(other, 9);
    rig.net.run(1000);
    rig.net.node(lead).online = false;
    rig.relocate(other, 4);
    rig.net.run(1000);
    CHECK_EQ(rig.chan(node), 9);
    rig.net.node(lead).online = true;
    rig.net.run(1000);

    // The leader turns up on another channel without notice, heard faintly:
    // the channel it states is followed.
    rig.net.node(lead).radio.chan = 10;
    rig.fol[lead]->onChannelChanged(10, rig.net.now());
    rig.net.run(600);
    rig.leak(lead, node);
    rig.net.run(10);
    CHECK_EQ(rig.chan(node), 10);

    // A sweep settles where the leader is, not on the busiest channel (2).
    CHECK(rig.fol[node]->sweep(rig.net.now()) == Status::Ok);
    CHECK(rig.net.runUntil([&] { return !rig.fol[node]->searching(); }, 10000));
    CHECK_EQ(rig.fol[node]->lastSweep().count(2), 3u);
    CHECK_EQ(rig.chan(node), 10);

    // Without a leader, the sweep goes to the crowd.
    rig.fol[node]->clearLeader();
    CHECK(!rig.fol[node]->hasLeader());
    CHECK(rig.fol[node]->sweep(rig.net.now()) == Status::Ok);
    CHECK(rig.net.runUntil([&] { return !rig.fol[node]->searching(); }, 10000));
    CHECK_EQ(rig.chan(node), 2);

    // Setting a leader known on another channel goes there at the next tick.
    rig.net.run(1000);
    rig.leak(lead, node);
    rig.net.run(10);
    CHECK_EQ(rig.chan(node), 2);
    rig.fol[node]->setLeader(rig.net.mac(lead), rig.net.now());
    CHECK_EQ(rig.chan(node), 2);  // not from the caller
    rig.net.run(10);
    CHECK_EQ(rig.chan(node), 10);
}

// A leader that isn't an anchor keeps the node where it is: no search while
// it answers, although the anchor it settled with has left.
TEST(channel_leader_keeps_the_node_here) {
    FollowRig rig;
    ChannelConfig cc;
    cc.findAnchor = true;
    cc.pick = ChannelPick::Busiest;
    cc.preferred = 5;
    ChannelConfig still;
    still.follow = false;  // doesn't go looking for the anchor either
    size_t anchor = rig.add(5, true), lead = rig.add(5, false, still), node = rig.add(5, false, cc);
    rig.add(7, false);
    rig.add(7, false);
    rig.start();
    rig.net.run(1000);
    rig.fol[node]->setLeader(rig.net.mac(lead), rig.net.now());
    rig.net.node(anchor).online = false;
    rig.net.run(20000);
    CHECK_EQ(rig.chan(node), 5);
    CHECK(!rig.fol[node]->searching());
    CHECK_EQ(rig.fol[node]->lastSweep().sequence, 0u);
    // Without it, the node looks for its anchor again.
    rig.fol[node]->clearLeader();
    CHECK(rig.net.runUntil([&] { return rig.fol[node]->lastSweep().sequence == 1; }, 10000));
}

// ---------------------------------------------------------------------------
// Stopping, suspending and pinning in the middle of a sweep
TEST(channel_stop_while_following) {
    FollowRig rig;
    size_t master = rig.add(1, true), node = rig.add(1, false);
    rig.start();
    rig.net.run(1000);
    CHECK(rig.disc[node]->find(rig.net.mac(master)) != nullptr);
    rig.fol[node]->stop();
    // The master moves on; the stopped follower stays.
    rig.relocate(master, 6);
    rig.net.run(2000);
    CHECK_EQ(rig.chan(node), 1);
    CHECK(!rig.fol[node]->searching());
    CHECK_EQ(rig.moves[node], 0);
    // The calls that would move the radio are refused.
    CHECK(rig.fol[node]->search(rig.net.now()) == Status::InvalidState);
    CHECK(rig.fol[node]->sweep(rig.net.now()) == Status::InvalidState);
    CHECK(rig.fol[node]->pin(4, rig.net.now()) == Status::InvalidState);
}

// Stopped in the middle of a sweep, the follower gives up where the radio
// happens to be: the report is interrupted and nothing moves the radio back.
TEST(channel_stop_mid_sweep) {
    FollowRig rig;
    ChannelConfig cc;
    cc.pick = ChannelPick::Busiest;
    size_t node = rig.add(5, false, cc);
    rig.start();
    rig.net.run(1000);
    CHECK(rig.fol[node]->sweep(rig.net.now()) == Status::Ok);
    CHECK(rig.fol[node]->sweeping());
    rig.net.run(600);  // the plan is 1, 2, 3, ...: the radio is on 3 now
    CHECK_EQ(rig.chan(node), 3);
    rig.fol[node]->stop();
    CHECK(!rig.fol[node]->searching());
    const ChannelSweep& s = rig.fol[node]->lastSweep();
    CHECK_EQ(s.sequence, 1u);
    CHECK(!s.running && !s.complete);
    CHECK_EQ(s.channel, 0);
    // The radio stays where the sweep left it; nothing else moves it.
    rig.net.run(5000);
    CHECK_EQ(rig.chan(node), 3);
    CHECK_EQ(rig.fol[node]->lastSweep().sequence, 1u);
    CHECK(rig.fol[node]->search(rig.net.now()) == Status::InvalidState);
    CHECK(rig.fol[node]->sweep(rig.net.now()) == Status::InvalidState);
    CHECK(rig.fol[node]->pin(4, rig.net.now()) == Status::InvalidState);
}

// Suspended in the middle of a sweep, the follower puts the radio back on
// the channel it started from and marks the report interrupted; unsuspended,
// sweeps run to the end again.
TEST(channel_suspend_aborts_the_sweep_and_returns_home) {
    FollowRig rig;
    ChannelConfig cc;
    cc.pick = ChannelPick::Busiest;
    size_t node = rig.add(5, false, cc);
    rig.start();
    rig.net.run(1000);
    CHECK(rig.fol[node]->sweep(rig.net.now()) == Status::Ok);
    rig.net.run(600);  // the radio is on 3 now
    CHECK_EQ(rig.chan(node), 3);
    rig.fol[node]->setSuspended(true, rig.net.now());
    CHECK(rig.fol[node]->suspended());
    CHECK(!rig.fol[node]->searching());
    CHECK_EQ(rig.chan(node), 5);  // back where the sweep started
    const ChannelSweep& s = rig.fol[node]->lastSweep();
    CHECK_EQ(s.sequence, 1u);
    CHECK(!s.running && !s.complete);
    CHECK_EQ(s.channel, 0);
    // Unsuspended: a new sweep runs to the end.
    rig.fol[node]->setSuspended(false, rig.net.now());
    CHECK(rig.fol[node]->sweep(rig.net.now()) == Status::Ok);
    CHECK(rig.net.runUntil([&] { return !rig.fol[node]->searching(); }, 10000));
    CHECK_EQ(rig.chan(node), 5);
    CHECK_EQ(rig.fol[node]->lastSweep().sequence, 2u);
    CHECK(rig.fol[node]->lastSweep().complete);
}

// Pinned in the middle of a sweep, the follower aborts it and goes to the
// pinned channel; the report is interrupted, and pin(0) unpins again.
TEST(channel_pin_aborts_the_sweep_and_goes_to_the_pinned_channel) {
    FollowRig rig;
    ChannelConfig cc;
    cc.pick = ChannelPick::Busiest;
    size_t node = rig.add(5, false, cc);
    rig.start();
    rig.net.run(1000);
    CHECK(rig.fol[node]->sweep(rig.net.now()) == Status::Ok);
    rig.net.run(600);  // the radio is on 3 now
    CHECK_EQ(rig.chan(node), 3);
    CHECK(rig.fol[node]->pin(9, rig.net.now()) == Status::Ok);
    CHECK(!rig.fol[node]->searching());
    CHECK_EQ(rig.chan(node), 9);
    CHECK_EQ(rig.fol[node]->pinned(), 9);
    const ChannelSweep& s = rig.fol[node]->lastSweep();
    CHECK_EQ(s.sequence, 1u);
    CHECK(!s.running && !s.complete);
    // Pinned: it stays, and a sweep comes back to the pinned channel.
    rig.net.run(3000);
    CHECK_EQ(rig.chan(node), 9);
    CHECK(rig.fol[node]->sweep(rig.net.now()) == Status::Ok);
    CHECK(rig.net.runUntil([&] { return !rig.fol[node]->searching(); }, 10000));
    CHECK_EQ(rig.chan(node), 9);
    const ChannelSweep& s2 = rig.fol[node]->lastSweep();
    CHECK(s2.complete && !s2.running);
    CHECK_EQ(s2.channel, 9);
    // pin(0) unpins; nothing moves the radio again.
    CHECK(rig.fol[node]->pin(0, rig.net.now()) == Status::Ok);
    CHECK_EQ(rig.fol[node]->pinned(), 0);
    rig.net.run(1000);
    CHECK_EQ(rig.chan(node), 9);
}

// search() is refused while pinned (the node stays put); a sweep still runs
// and comes back to the pinned channel; after unpin, search() works again.
TEST(channel_search_refused_while_pinned) {
    FollowRig rig;
    size_t master = rig.add(1, true), node = rig.add(1, false);
    rig.start();
    rig.net.run(1000);
    CHECK(rig.fol[node]->pin(4, rig.net.now()) == Status::Ok);
    CHECK_EQ(rig.chan(node), 4);
    // Pinned: a search is refused, and the node stays.
    CHECK(rig.fol[node]->search(rig.net.now()) == Status::InvalidState);
    CHECK(!rig.fol[node]->searching());
    CHECK_EQ(rig.chan(node), 4);
    // A sweep is not refused: it comes back to the pinned channel.
    CHECK(rig.fol[node]->sweep(rig.net.now()) == Status::Ok);
    CHECK(rig.net.runUntil([&] { return !rig.fol[node]->searching(); }, 10000));
    CHECK_EQ(rig.chan(node), 4);
    const ChannelSweep& s = rig.fol[node]->lastSweep();
    CHECK(s.complete);
    CHECK_EQ(s.channel, 4);
    CHECK_EQ(s.count(1, true), 1u);  // the anchor on 1, heard during the sweep
    // Unpinned: search() works and finds the master.
    rig.fol[node]->unpin(rig.net.now());
    CHECK(rig.fol[node]->search(rig.net.now()) == Status::Ok);
    CHECK(rig.net.runUntil([&] { return !rig.fol[node]->searching(); }, 10000));
    CHECK_EQ(rig.chan(node), 1);
    CHECK(rig.disc[node]->find(rig.net.mac(master)) != nullptr);
}

// A sweep that ties the origin channel with another settles on the origin,
// not on the lower channel.
TEST(channel_busiest_tie_prefers_the_origin_channel) {
    FollowRig rig;
    ChannelConfig cc;
    cc.pick = ChannelPick::Busiest;
    rig.add(5, false);
    rig.add(7, false);
    size_t node = rig.add(7, false, cc);
    rig.start();
    rig.net.run(1000);
    CHECK(rig.fol[node]->sweep(rig.net.now()) == Status::Ok);
    CHECK(rig.net.runUntil([&] { return !rig.fol[node]->searching(); }, 10000));
    // 5 and 7 tie on one node each, and neither has an anchor: the origin (7)
    // wins over the lower channel.
    CHECK_EQ(rig.chan(node), 7);
    CHECK_EQ(rig.moves[node], 0);
    const ChannelSweep& s = rig.fol[node]->lastSweep();
    CHECK(s.complete && !s.running);
    CHECK_EQ(s.channel, 7);
    CHECK_EQ(s.count(5), 1u);
    CHECK_EQ(s.count(7), 1u);
    // It settles there: no anchor anywhere, but it does not sweep again.
    rig.net.run(40000);
    CHECK_EQ(rig.chan(node), 7);
    CHECK_EQ(rig.fol[node]->lastSweep().sequence, 1u);
}

// A sweep that hears nothing on any channel comes back to where it started,
// and looks again after the retry.
TEST(channel_sweep_comes_home_when_nothing_answers) {
    FollowRig rig;
    ChannelConfig cc;
    cc.findAnchor = true;
    cc.pick = ChannelPick::Busiest;
    size_t node = rig.add(2, false, cc);
    rig.start();
    // The boot sweep hears no one on any channel.
    CHECK(rig.net.runUntil([&] { return rig.fol[node]->sweeping(); }, 100));
    CHECK(rig.net.runUntil([&] { return !rig.fol[node]->searching(); }, 10000));
    const ChannelSweep& s = rig.fol[node]->lastSweep();
    CHECK_EQ(s.sequence, 1u);
    CHECK(s.complete && !s.running);
    CHECK_EQ(s.channel, 2);
    CHECK_EQ(s.nodes.size(), 0u);
    CHECK_EQ(rig.chan(node), 2);
    // And it looks again after the retry.
    CHECK(rig.net.runUntil([&] { return rig.fol[node]->lastSweep().sequence == 2; }, 30000));
    CHECK(rig.net.runUntil([&] { return !rig.fol[node]->searching(); }, 10000));
    CHECK_EQ(rig.chan(node), 2);
    CHECK_EQ(rig.moves[node], 0);
}
