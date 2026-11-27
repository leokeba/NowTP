// Host-side tests for the NowTP protocol engine: peer table and discovery.

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
// Peer table
// ESP-NOW holds 20 peers. Acks alone (to spoofed or real senders) used to
// fill it for good; then every new destination failed with LinkError.
TEST(peer_table_full_of_senders_still_reaches_new_peers) {
    sim::Network net;
    size_t gw = net.addNode();
    net.node(gw).link.driver.capacity = 20;
    Inbox inbox;
    net.engine(gw).listen(1, inbox.handler());
    std::vector<size_t> senders;
    std::vector<Outcome> outs(25);
    for (size_t i = 0; i < 25; ++i) senders.push_back(net.addNode());
    auto msg = pattern(50);
    for (size_t i = 0; i < 25; ++i) {
        net.engine(senders[i]).send(net.mac(gw), 1, msg.data(), msg.size(), reliable(), outs[i].handler(),
                                    net.now());
    }
    CHECK(net.runUntil([&] {
        for (auto& o : outs) {
            if (!o.done) return false;
        }
        return true;
    }));
    for (auto& o : outs) CHECK(o.status == Status::Ok);  // every ack went out
    CHECK(net.node(gw).link.driver.table.size() == 20u);
    CHECK(net.node(gw).link.driver.removed >= 5u);

    size_t fresh = net.addNode();
    Inbox in2;
    for (size_t i : {fresh, senders[0], senders[24]}) net.engine(i).listen(1, in2.handler());
    for (size_t i : {fresh, senders[0], senders[24]}) {
        Outcome out;
        net.engine(gw).send(net.mac(i), 1, msg.data(), msg.size(), reliable(), out.handler(), net.now());
        CHECK(net.runUntil([&] { return out.done; }));
        CHECK(out.status == Status::Ok);
    }
}

TEST(peer_table_keeps_pinned_and_in_flight_peers) {
    sim::SimPeerDriver d;
    d.capacity = 3;
    PeerTable t(d);
    Mac m[5];
    for (uint8_t i = 0; i < 5; ++i) m[i] = Mac{{0x02, 0, 0, 0, 1, i}};
    CHECK(d.add(m[0]) == PeerTable::Driver::Result::Ok);
    t.pin(m[0]);  // the application's (e.g. encrypted) peer
    bool added = false;
    CHECK(t.use(m[1], 1, added) == Status::Ok && added);
    CHECK(t.use(m[2], 2, added) == Status::Ok && added);
    CHECK(t.use(m[1], 3, added) == Status::Ok && !added);
    t.setInFlight(m[2]);
    // Full: m[2] is the least recently used, but a frame to it is in flight.
    CHECK(t.use(m[3], 4, added) == Status::Ok && added);
    CHECK(d.exists(m[0]) && d.exists(m[2]) && d.exists(m[3]) && !d.exists(m[1]));
    // A peer that left is removed once its frame is reported.
    t.release(m[2]);
    CHECK(d.exists(m[2]));
    t.clearInFlight();
    CHECK(!d.exists(m[2]));
    t.release(m[0]);  // pinned: stays
    CHECK(d.exists(m[0]));
    t.setInFlight(m[3]);
    CHECK(t.use(m[4], 5, added) == Status::Ok && added);  // a free slot
    CHECK(t.use(m[1], 6, added) == Status::Ok && added);  // evicts m[4], not m[3] (in flight)
    CHECK(d.exists(m[1]) && d.exists(m[3]) && !d.exists(m[4]));
    // Nothing evictable: the new destination fails.
    t.pin(m[1]);
    CHECK(t.use(m[4], 7, added) == Status::LinkError);
    CHECK_EQ(t.automatic(), 1u);
}

TEST(table_holds_up_to_its_limit) {
    Table<std::string> t(3);
    CHECK(t.empty());
    CHECK(t.add("a") && t.add("b") && t.add("c"));
    CHECK(t.full());
    CHECK(t.add("d") == nullptr);  // refused, never grown
    t.erase(1);
    CHECK(t.add("e") != nullptr);
    std::string all;
    for (const std::string& x : t) all += x;
    CHECK(all == "ace");
    t.clear();
    CHECK_EQ(t.size(), 0u);
}

TEST(discovery_nodes_find_each_other) {
    DiscoveryRig rig;
    DiscoveryConfig withMeta;
    withMeta.metadata = {1, 2, 3};
    size_t a = rig.add("alpha", withMeta, 1470), b = rig.add("beta");
    rig.nodes[a]->start(rig.net.now());
    rig.nodes[b]->start(rig.net.now());
    rig.run(100);
    CHECK_EQ(rig.nodes[a]->peers().size(), 1u);
    CHECK_EQ(rig.nodes[b]->peers().size(), 1u);
    const PeerInfo* seenByB = rig.nodes[b]->find(rig.net.mac(a));
    CHECK(seenByB != nullptr);
    CHECK(seenByB->name == "alpha");
    CHECK((seenByB->metadata == std::vector<uint8_t>{1, 2, 3}));
    CHECK_EQ(seenByB->maxFrameSize, 1470);
    CHECK(rig.nodes[a]->find(rig.net.mac(b))->name == "beta");
    CHECK_EQ(rig.count(a, PeerEvent::Found), 1u);
}

TEST(discovery_late_joiner_found_quickly) {
    DiscoveryRig rig;
    DiscoveryConfig slow;
    slow.announceIntervalMs = 10000;
    size_t a = rig.add("a", slow), b = rig.add("b", slow), c = rig.add("c", slow);
    rig.nodes[a]->start(rig.net.now());
    rig.nodes[b]->start(rig.net.now());
    rig.run(1000);
    rig.nodes[c]->start(rig.net.now());
    rig.run(150);  // far less than the announce interval: the query triggers replies
    CHECK_EQ(rig.nodes[c]->peers().size(), 2u);
    CHECK_EQ(rig.nodes[a]->peers().size(), 2u);
    CHECK_EQ(rig.nodes[b]->peers().size(), 2u);
}

TEST(discovery_reports_lost_peers) {
    DiscoveryRig rig;
    DiscoveryConfig cfg;
    cfg.announceIntervalMs = 500;
    cfg.peerTimeoutMs = 1600;
    size_t a = rig.add("a", cfg), b = rig.add("b", cfg), c = rig.add("c", cfg);
    for (auto& d : rig.nodes) d->start(rig.net.now());
    rig.run(1000);
    CHECK_EQ(rig.nodes[a]->peers().size(), 2u);

    rig.net.node(b).online = false;  // vanishes silently
    rig.run(2500);
    CHECK_EQ(rig.count(a, PeerEvent::Lost), 1u);
    CHECK(rig.events[a].back().second.mac == rig.net.mac(b));
    CHECK_EQ(rig.nodes[a]->peers().size(), 1u);

    rig.nodes[c]->stop(rig.net.now());  // says goodbye
    rig.run(5);
    CHECK_EQ(rig.count(a, PeerEvent::Lost), 2u);
    CHECK(rig.nodes[a]->peers().empty());
}

TEST(discovery_keeps_peers_heard_sending_data) {
    DiscoveryRig rig;
    DiscoveryConfig cfg;
    cfg.announceIntervalMs = 500;
    cfg.peerTimeoutMs = 1600;
    size_t a = rig.add("a", cfg), b = rig.add("b", cfg), c = rig.add("c", cfg);
    for (auto& d : rig.nodes) d->start(rig.net.now());
    rig.run(1000);
    CHECK_EQ(rig.nodes[a]->peers().size(), 2u);

    // b's and c's announcements are lost, but b sends messages to a, and c
    // acknowledges a's messages: neither is lost while that goes on.
    rig.net.dropIf = dropAnnouncementsFrom({b, c});
    Inbox atA, atC;
    rig.net.engine(a).listen(1, atA.handler());
    rig.net.engine(c).listen(1, atC.handler());
    auto big = pattern(600), small = pattern(20);  // reassembled, and single-frame
    for (int i = 0; i < 25; ++i) {
        const std::vector<uint8_t>& m = i % 2 ? big : small;
        CHECK(rig.net.engine(b).send(rig.net.mac(a), 1, m.data(), m.size(), SendOptions(), nullptr, rig.net.now()) ==
              Status::Ok);
        CHECK(rig.net.engine(a).send(rig.net.mac(c), 1, small.data(), small.size(), reliable(), nullptr,
                                     rig.net.now()) == Status::Ok);
        rig.run(200);
    }
    CHECK_EQ(atA.messages.size(), 25u);
    CHECK_EQ(atC.messages.size(), 25u);
    CHECK_EQ(rig.count(a, PeerEvent::Lost), 0u);
    CHECK_EQ(rig.nodes[a]->peers().size(), 2u);

    // Once the traffic stops as well, both are lost.
    rig.run(2500);
    CHECK_EQ(rig.count(a, PeerEvent::Lost), 2u);
    CHECK(rig.nodes[a]->peers().empty());
    rig.net.dropIf = nullptr;
}

TEST(discovery_metadata_updates) {
    DiscoveryRig rig;
    DiscoveryConfig cfg;
    cfg.announceIntervalMs = 0;  // only explicit announcements
    size_t a = rig.add("a", cfg), b = rig.add("b", cfg);
    rig.nodes[a]->start(rig.net.now());
    rig.nodes[b]->start(rig.net.now());
    rig.run(100);
    uint8_t meta[] = {42};
    rig.nodes[a]->setMetadata(meta, sizeof(meta), rig.net.now());
    rig.run(10);
    CHECK_EQ(rig.count(b, PeerEvent::Updated), 1u);
    CHECK_EQ(rig.nodes[b]->find(rig.net.mac(a))->metadata.size(), 1u);
    CHECK_EQ(rig.nodes[b]->find(rig.net.mac(a))->metadata[0], 42);
    size_t framesBefore = rig.net.log.size();
    rig.run(5000);
    CHECK_EQ(rig.net.log.size(), framesBefore);  // no periodic traffic
}

TEST(discovery_respects_max_peers) {
    DiscoveryRig rig;
    DiscoveryConfig small;
    small.maxPeers = 2;
    size_t a = rig.add("a", small);
    for (int i = 0; i < 4; ++i) rig.add("n" + std::to_string(i));
    for (auto& d : rig.nodes) d->start(rig.net.now());
    rig.run(300);
    CHECK_EQ(rig.nodes[a]->peers().size(), 2u);
    CHECK_EQ(rig.nodes[1]->peers().size(), 4u);
    // Peers that keep announcing keep their place...
    size_t lostBefore = rig.count(a, PeerEvent::Lost);
    rig.run(4000);
    CHECK_EQ(rig.count(a, PeerEvent::Lost), lostBefore);
    // ...but once they fall silent, a newcomer replaces one (reported lost),
    // before the peer timeout.
    for (size_t i = 0; i < rig.nodes.size(); ++i) rig.net.node(i).online = i == a;
    rig.run(3500);
    CHECK_EQ(rig.count(a, PeerEvent::Lost), lostBefore);
    size_t late = rig.add("late");
    rig.nodes[late]->start(rig.net.now());
    rig.run(300);
    bool found = false;
    for (const PeerInfo& p : rig.nodes[a]->peers()) found = found || p.name == "late";
    CHECK(found);
    CHECK_EQ(rig.nodes[a]->peers().size(), 2u);
    CHECK(rig.count(a, PeerEvent::Lost) > lostBefore);
}

TEST(discovery_ignores_malformed_announcements) {
    DiscoveryRig rig;
    size_t a = rig.add("a");
    rig.nodes[a]->start(rig.net.now());
    Mac src = {{0x02, 5, 5, 5, 5, 5}};
    std::mt19937 rng(3);
    for (int i = 0; i < 5000; ++i) {
        std::vector<uint8_t> payload(rng() % 40);
        for (auto& x : payload) x = static_cast<uint8_t>(rng());
        if (!payload.empty()) payload[0] = 1;
        if (payload.size() > 4) payload[4] = static_cast<uint8_t>(payload[4] % 40);
        wire::Header h;
        h.type = wire::Type::Single;
        h.port = kDiscoveryPort;
        h.messageId = static_cast<uint16_t>(i);
        std::vector<uint8_t> f(wire::kCommonHeaderSize);
        wire::encodeHeader(h, f.data());
        f.insert(f.end(), payload.begin(), payload.end());
        rig.net.inject(a, src, f);
    }
    // Some random payloads are valid announcements; nothing may crash or overflow.
    CHECK(rig.nodes[a]->peers().size() <= 1u);
}

TEST(discovery_reports_peers_on_other_channels) {
    FollowRig rig;
    size_t master = rig.add(6, true), fixed = rig.add(5, true), b = rig.add(5, false);
    std::vector<PeerInfo> lost;
    rig.disc[fixed]->onPeerEvent([&](PeerEvent e, const PeerInfo& p) {
        if (e == PeerEvent::Lost) lost.push_back(p);
    });
    rig.start();
    rig.net.run(600);
    // The master leaks in from channel 6 (see above); `fixed` can't follow it.
    std::vector<uint8_t> hello;
    for (size_t i = rig.net.log.size(); i-- > 0;) {
        if (rig.net.log[i].from == master) {
            hello = rig.net.log[i].data;
            break;
        }
    }
    CHECK(!hello.empty());
    rig.net.inject(fixed, rig.net.mac(master), hello);
    rig.net.run(10);
    const PeerInfo* m = rig.disc[fixed]->find(rig.net.mac(master));
    CHECK(m != nullptr);
    CHECK_EQ(m->channel, 6);
    CHECK(m->otherChannel);
    const PeerInfo* nb = rig.disc[fixed]->find(rig.net.mac(b));
    CHECK(nb != nullptr && !nb->otherChannel);

    // Moving to our channel makes it a neighbour; the flag follows our channel.
    rig.disc[fixed]->setChannelInfo(6, true, rig.net.now());
    CHECK(!rig.disc[fixed]->find(rig.net.mac(master))->otherChannel);
    CHECK(rig.disc[fixed]->find(rig.net.mac(b))->otherChannel);
    rig.disc[fixed]->setChannelInfo(5, true, rig.net.now());

    // b moves away: its Lost event says where to.
    CHECK(rig.disc[b]->announceMove(9, rig.net.now()));
    rig.net.run(20);
    CHECK_EQ(lost.size(), 1u);
    CHECK(lost[0].mac == rig.net.mac(b));
    CHECK_EQ(lost[0].channel, 9);
    CHECK(lost[0].otherChannel);
}

TEST(discovery_reads_announcements_without_extension) {
    // A NowTP 0.4 announcement: no channel extension.
    std::vector<uint8_t> p = {1, 0, 0xFA, 0, 3, 'a', 'b', 'c', 1, 9};
    Discovery::Announcement a;
    CHECK(Discovery::parse(p.data(), p.size(), a));
    CHECK(a.name == "abc");
    CHECK_EQ(a.channel, 0);
    CHECK_EQ(a.metadataLen, 1u);
    p.push_back(1);  // anchor
    p.push_back(11);
    CHECK(Discovery::parse(p.data(), p.size(), a));
    CHECK_EQ(a.channel, 11);
    CHECK_EQ(a.extFlags, 1);
    CHECK_EQ(a.maxMessageSize, 0u);  // 0.5: no message limit
    // The limit follows the move-to channel, which 0.5 reads no further than.
    std::vector<uint8_t> moving = {1, 0x0C, 0xFA, 0, 0, 0, 0x04, 11, 6, 0x00, 0x10, 0, 0};
    CHECK(Discovery::parse(moving.data(), moving.size(), a));
    CHECK_EQ(a.moveTo, 6);
    CHECK_EQ(a.maxMessageSize, 4096u);
    moving[6] = 0;  // without the flag the bytes mean nothing
    CHECK(Discovery::parse(moving.data(), moving.size(), a));
    CHECK_EQ(a.maxMessageSize, 0u);
}

// A node announces the largest message it accepts; send() to it refuses a
// larger one at once instead of waiting for the receiver to reject it.
TEST(discovery_shares_message_limits) {
    sim::Network net;
    Config smallCfg;
    smallCfg.maxMessageSize = 4096;
    size_t small = net.addNode(smallCfg), big = net.addNode();
    std::mt19937 rng(3);
    auto random = [&rng] { return static_cast<uint32_t>(rng()); };
    DiscoveryConfig dc;
    dc.name = "small";
    Discovery ds(net.engine(small), dc, 250, random);
    dc.name = "big";
    Discovery db(net.engine(big), dc, 250, random);
    net.tickers.push_back(sim::Ticker(
        [&](uint32_t now) {
            ds.tick(now);
            db.tick(now);
        },
        [&](Deadline& d) {
            ds.nextTick(d);
            db.nextTick(d);
        }));
    ds.start(net.now());
    db.start(net.now());
    net.run(100);
    const PeerInfo* p = db.find(net.mac(small));
    CHECK(p != nullptr);
    CHECK_EQ(p->maxMessageSize, 4096u);
    CHECK_EQ(ds.find(net.mac(big))->maxMessageSize, 16384u);
    CHECK_EQ(net.engine(big).peerMessageLimit(net.mac(small)), 4096u);

    Inbox inbox;
    net.engine(small).listen(1, inbox.handler());
    auto tooBig = pattern(5000), fits = pattern(4096);
    CHECK(net.engine(big).send(net.mac(small), 1, tooBig.data(), tooBig.size(), reliable(), nullptr, net.now()) ==
          Status::TooLarge);
    uint8_t* buffer = static_cast<uint8_t*>(std::malloc(tooBig.size()));
    CHECK(net.engine(big).sendBuffer(net.mac(small), 1, buffer, tooBig.size(), tooBig.size(), reliable(), nullptr,
                                     net.now()) == Status::TooLarge);  // and freed
    Outcome out;
    net.engine(big).send(net.mac(small), 1, fits.data(), fits.size(), reliable(), out.handler(), net.now());
    CHECK(net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Ok);
    CHECK_EQ(inbox.messages.size(), 1u);
    // Broadcast isn't limited by any one peer.
    CHECK(net.engine(big).send(Mac::broadcast(), 1, tooBig.data(), tooBig.size(), SendOptions(), nullptr,
                               net.now()) == Status::Ok);

    // Gone: no limit is known any more.
    ds.stop(net.now());
    net.run(20);
    CHECK(db.find(net.mac(small)) == nullptr);
    CHECK_EQ(net.engine(big).peerMessageLimit(net.mac(small)), 0u);
    CHECK_EQ(net.engine(small).peerMessageLimit(net.mac(big)), 0u);  // its own stop() forgot them
    net.tickers.clear();
}

TEST(discovery_announces_a_device_id) {
    // A node sending from another address (its soft-AP's) names its device.
    DiscoveryRig rig;
    size_t a = rig.add("alpha"), b = rig.add("beta");
    rig.nodes[a]->setDeviceId(deviceMac(0x42));
    rig.nodes[a]->start(rig.net.now());
    rig.nodes[b]->start(rig.net.now());
    rig.run(100);
    const PeerInfo* p = rig.nodes[b]->find(rig.net.mac(a));
    CHECK(p && p->deviceId == deviceMac(0x42));
    CHECK(rig.nodes[b]->findDevice(deviceMac(0x42)) == p);
    CHECK(p && p->maxMessageSize != 0);  // read before it
    const PeerInfo* q = rig.nodes[a]->find(rig.net.mac(b));
    CHECK(q && q->deviceId == rig.net.mac(b));  // none said: its address
    CHECK(rig.nodes[a]->findDevice(rig.net.mac(b)) == q);
    // Back on its own address: an update, named by it again.
    rig.nodes[a]->setDeviceId(Mac());
    rig.run(3000);
    p = rig.nodes[b]->find(rig.net.mac(a));
    CHECK(p && p->deviceId == rig.net.mac(a));
    CHECK(rig.nodes[b]->findDevice(deviceMac(0x42)) == nullptr);
    CHECK(rig.count(b, PeerEvent::Updated) >= 1u);
}
