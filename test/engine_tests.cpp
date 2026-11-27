// Host-side tests for the NowTP protocol engine: engine, ports and API behavior.

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

namespace {

// The ESP-NOW transport's link monitoring, on node `a` of a simulated
// network: frames heard and send reports as the transport feeds them, power
// from a's simulated radio, events recorded. `b` announces itself every
// 300 ms, so that `a` hears it.
struct MonitorRig : LinkMonitor::Host {
    sim::Network net{7};
    size_t a = net.addNode(), b = net.addNode();
    std::unique_ptr<LinkMonitor> monitor;
    std::vector<std::pair<LinkMonitor::Event, float>> events;  // with toDbm
    bool aTalks = false;  // a sends b a message every 100 ms
    uint32_t nextBeacon = 0, nextTalk = 0;

    MonitorRig() {
        monitor.reset(new LinkMonitor(net.engine(a), *this));
        monitor->reset(true);
        net.node(a).onHeard = [this](const Mac& src) { monitor->heard(src, net.now()); };
        net.node(a).onSent = [this](const Mac& dst, bool ok) { monitor->sent(dst, ok, net.now()); };
        net.tickers.push_back(sim::Ticker([this](uint32_t now) { monitor->tick(now); },
                                          [this](Deadline& d) { monitor->nextTick(d); }, a));
        net.tickers.push_back(sim::Ticker([this](uint32_t now) { traffic(now); },
                                          [this](Deadline& d) {
                                              d.at(nextBeacon);
                                              if (aTalks) d.at(nextTalk);
                                          }));
        nextBeacon = nextTalk = net.now();
    }
    void traffic(uint32_t now) {
        static const uint8_t hello[4] = {1, 2, 3, 4};
        if (static_cast<int32_t>(now - nextBeacon) >= 0) {
            net.engine(b).send(Mac::broadcast(), 1, hello, sizeof(hello), SendOptions(), nullptr, now);
            nextBeacon = now + 300;
        }
        if (aTalks && static_cast<int32_t>(now - nextTalk) >= 0) {
            net.engine(a).send(net.mac(b), 1, hello, sizeof(hello), SendOptions(), nullptr, now);
            nextTalk = now + 100;
        }
    }
    // a's frames get through only at 13 dBm or less: a sagging supply.
    void weakSupply() {
        size_t weak = a;
        net.linkModel = [weak](size_t from, size_t, PhyRate, float dbm) { return from == weak && dbm > 13.5f ? 1.0 : 0.0; };
    }
    size_t count(LinkMonitor::Event e) const {
        size_t n = 0;
        for (const auto& ev : events) n += ev.first == e;
        return n;
    }

    float txPower() const override { return const_cast<sim::Network&>(net).node(a).radio.power; }
    void setTxPower(float dbm) override { net.node(a).radio.setTxPower(dbm); }
    void linkEvent(LinkMonitor::Event e, const Mac& peer, float, float to) override {
        testing::HeapExempt app;
        CHECK(peer == net.mac(b));
        events.push_back(std::make_pair(e, to));
    }
};

}  // namespace

TEST(broadcast_reaches_all_nodes) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode(), c = net.addNode();
    Inbox ib, ic;
    net.engine(b).listen(9, ib.handler());
    net.engine(c).listen(9, ic.handler());
    auto msg = pattern(3000);
    CHECK(net.engine(a).send(Mac::broadcast(), 9, msg.data(), msg.size(), SendOptions(), nullptr, net.now()) ==
          Status::Ok);
    CHECK(net.runUntil([&] { return ib.messages.size() == 1 && ic.messages.size() == 1; }));
    CHECK(ib.messages[0] == msg);
    CHECK(ic.messages[0] == msg);
}

TEST(many_messages_survive_id_wraparound) {
    // The old library used 8-bit ids that collided within the reassembly timeout.
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    const int total = 600;
    int sent = 0;
    std::vector<std::vector<uint8_t>> expected;
    while (sent < total) {
        auto msg = pattern(300 + static_cast<size_t>(sent % 7) * 50, static_cast<uint32_t>(sent));
        Status s = net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), SendOptions(), nullptr, net.now());
        if (s == Status::QueueFull) {
            net.step();
            continue;
        }
        CHECK(s == Status::Ok);
        expected.push_back(msg);
        sent++;
    }
    CHECK(net.runUntil([&] { return inbox.messages.size() == expected.size(); }, 100000));
    CHECK(inbox.messages == expected);
}

TEST(unicast_link_failure_reports_send_failed) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    net.node(b).online = false;
    Outcome out;
    auto msg = pattern(1000);
    CHECK(net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), SendOptions(), out.handler(), net.now()) ==
          Status::Ok);
    CHECK(net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::SendFailed);
    CHECK_EQ(net.log.size(), 1u + net.engine(a).config().frameRetries);
}

// An absent peer's frames take ~100 ms each to fail. Messages to it must not
// hold up other destinations, or fill the queue for them.
TEST(absent_peer_does_not_block_others) {
    sim::Network net;  // failed frames are reported after 100 ms, as on hardware
    size_t a = net.addNode(), b = net.addNode(), c = net.addNode();
    net.node(c).online = false;
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    auto small = pattern(100);
    std::vector<Outcome> dead(5);
    for (size_t i = 0; i < 4; ++i) {
        CHECK(net.engine(a).send(net.mac(c), 1, small.data(), small.size(), SendOptions(), dead[i].handler(),
                                 net.now()) == Status::Ok);
    }
    // The queue limit applies per destination.
    CHECK(net.engine(a).send(net.mac(c), 1, small.data(), small.size(), SendOptions(), dead[4].handler(),
                             net.now()) == Status::QueueFull);
    uint32_t t0 = net.now();
    CHECK(net.engine(a).send(net.mac(b), 1, small.data(), small.size(), SendOptions(), nullptr, net.now()) ==
          Status::Ok);
    CHECK(net.runUntil([&] { return !inbox.messages.empty(); }));
    CHECK(net.now() - t0 <= 110u);  // one failing frame at most, not 4 messages x 3 attempts

    // A large message streams mostly during the absent peer's backoff.
    auto big = pattern(16000);
    Outcome out;
    t0 = net.now();
    CHECK(net.engine(a).send(net.mac(b), 1, big.data(), big.size(), reliable(), out.handler(), net.now()) ==
          Status::Ok);
    CHECK(net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Ok);
    uint32_t bigMs = net.now() - t0;
    std::printf("    16 KB to a live peer beside an absent one: %u ms\n", bigMs);
    CHECK(bigMs < 700u);
    CHECK(net.runUntil([&] { return dead[3].done; }, 10000));
    for (size_t i = 0; i < 4; ++i) CHECK(dead[i].status == Status::SendFailed);
}

TEST(destinations_take_turns) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode(), c = net.addNode();
    Inbox ib, ic;
    net.engine(b).listen(1, ib.handler());
    net.engine(c).listen(1, ic.handler());
    auto big = pattern(8000);
    auto small = pattern(100);
    net.engine(a).send(net.mac(b), 1, big.data(), big.size(), SendOptions(), nullptr, net.now());
    net.engine(a).send(net.mac(c), 1, small.data(), small.size(), SendOptions(), nullptr, net.now());
    // The short message to c doesn't wait for the whole 8 KB to b.
    CHECK(net.runUntil([&] { return !ic.messages.empty(); }));
    CHECK(ib.messages.empty());
    CHECK(net.runUntil([&] { return !ib.messages.empty(); }));
    // Frames alternate while both have some.
    net.engine(a).send(net.mac(b), 1, big.data(), big.size(), SendOptions(), nullptr, net.now());
    net.engine(a).send(net.mac(c), 1, big.data(), big.size(), SendOptions(), nullptr, net.now());
    size_t from = net.log.size();
    CHECK(net.runUntil([&] { return ib.messages.size() == 2 && ic.messages.size() == 2; }));
    for (size_t i = from + 1; i < from + 20; ++i) CHECK(!(net.log[i].dst == net.log[i - 1].dst));
}

TEST(per_peer_byte_limit) {
    sim::Network net;
    Config cfg;
    cfg.maxTxBytesPerPeer = 10000;
    size_t a = net.addNode(cfg), b = net.addNode(), c = net.addNode();
    auto msg = pattern(6000);
    CHECK(net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), SendOptions(), nullptr, net.now()) ==
          Status::Ok);
    CHECK(net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), SendOptions(), nullptr, net.now()) ==
          Status::QueueFull);
    CHECK(net.engine(a).send(net.mac(c), 1, msg.data(), msg.size(), SendOptions(), nullptr, net.now()) ==
          Status::Ok);
}

// What a stalled peer makes us hold, as the application can sample it.
TEST(engine_reports_memory_held) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    CHECK_EQ(net.engine(a).memory().txBytes, 0u);
    // b receives every fragment but the last: a waits for the ack, b holds the partial message.
    net.dropIf = [&](const sim::Frame& f) {
        wire::Header h;
        size_t off;
        return f.from == a && wire::decodeHeader(f.data.data(), f.data.size(), h, off) &&
               h.type == wire::Type::Fragment && h.index + 1 == h.count;
    };
    auto msg = pattern(3900);
    Outcome out;
    net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), reliable(), out.handler(), net.now());
    Engine::MemoryUse tx = net.engine(a).memory();
    CHECK_EQ(tx.txMessages, 1u);
    CHECK_EQ(tx.txBytes, msg.size() + 4);  // with its CRC
    net.run(50);
    Engine::MemoryUse rx = net.engine(b).memory();
    CHECK_EQ(rx.rxMessages, 1u);
    CHECK(rx.rxBytes >= msg.size());
    net.dropIf = nullptr;
    CHECK(net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Ok);
    net.run(10);
    CHECK_EQ(net.engine(a).memory().txMessages, 0u);
    CHECK_EQ(net.engine(a).memory().txBytes, 0u);
    CHECK_EQ(net.engine(b).memory().rxMessages, 0u);
    CHECK_EQ(net.engine(b).memory().rxBytes, 0u);
}

TEST(no_listener_drops_message) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    auto msg = pattern(100);
    net.engine(a).send(net.mac(b), 77, msg.data(), msg.size(), SendOptions(), nullptr, net.now());
    net.run(10);
    CHECK_EQ(net.engine(b).stats().messagesDropped, 1u);
    CHECK_EQ(net.engine(b).stats().messagesReceived, 0u);
}

TEST(ports_are_independent) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    Inbox p1, p2;
    net.engine(b).listen(1, p1.handler());
    net.engine(b).listen(2, p2.handler());
    auto m1 = pattern(10, 1), m2 = pattern(600, 2);
    net.engine(a).send(net.mac(b), 2, m2.data(), m2.size(), SendOptions(), nullptr, net.now());
    net.engine(a).send(net.mac(b), 1, m1.data(), m1.size(), SendOptions(), nullptr, net.now());
    CHECK(net.runUntil([&] { return p1.messages.size() == 1 && p2.messages.size() == 1; }));
    CHECK(p1.messages[0] == m1);
    CHECK(p2.messages[0] == m2);
}

TEST(network_id_isolates_traffic) {
    sim::Network net;
    Config other;
    other.networkId = 42;
    size_t a = net.addNode(), b = net.addNode(other);
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    auto msg = pattern(10);
    net.engine(a).send(Mac::broadcast(), 1, msg.data(), msg.size(), SendOptions(), nullptr, net.now());
    net.run(10);
    CHECK(inbox.messages.empty());
}

TEST(link_busy_backs_off_and_recovers) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    net.node(a).link.busyReplies = 5;
    auto msg = pattern(1200);
    net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), SendOptions(), nullptr, net.now());
    CHECK(net.runUntil([&] { return inbox.messages.size() == 1; }));
    CHECK(inbox.messages[0] == msg);
}

// A board whose supply sags at full power: b's frames arrive, a's fail. The
// link is reported one-way, and the fallback steps the power down until b
// acknowledges, checks the full power still fails, and keeps the lower one.
TEST(link_monitor_lowers_power_for_a_one_way_link) {
    MonitorRig rig;
    rig.weakSupply();
    rig.aTalks = true;
    CHECK(rig.net.runUntil([&] { return rig.count(LinkMonitor::Event::PowerLowered) > 0; }, 20000));
    CHECK_EQ(rig.count(LinkMonitor::Event::OneWay), 1u);
    CHECK_EQ(rig.count(LinkMonitor::Event::FallbackStarted), 1u);
    CHECK_EQ(rig.events.back().second, 13.0f);
    CHECK_EQ(rig.net.node(rig.a).radio.power, 13.0f);
    CHECK(!rig.monitor->fallbackActive());
    // a's messages now get through.
    Outcome out;
    static const uint8_t data[2] = {9, 9};
    rig.net.engine(rig.a).send(rig.net.mac(rig.b), 1, data, sizeof(data), SendOptions(), out.handler(), rig.net.now());
    CHECK(rig.net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Ok);
    // Once tried for a peer, no second search however its frames fare.
    rig.net.run(5000);
    CHECK_EQ(rig.count(LinkMonitor::Event::FallbackStarted), 1u);
}

// A peer briefly away (rebooting, scanning) fails our frames too. The search
// may find that a lower power "works" once it is back, but the original
// power works as well then: it stays.
TEST(link_monitor_keeps_power_for_a_peer_briefly_away) {
    MonitorRig rig;
    rig.aTalks = true;
    rig.net.run(1000);
    rig.net.node(rig.b).online = false;
    CHECK(rig.net.runUntil([&] { return rig.count(LinkMonitor::Event::FallbackStarted) > 0; }, 5000));
    rig.net.node(rig.b).online = true;
    CHECK(rig.net.runUntil([&] { return !rig.monitor->fallbackActive(); }, 10000));
    CHECK_EQ(rig.count(LinkMonitor::Event::PowerKept), 1u);
    CHECK_EQ(rig.count(LinkMonitor::Event::PowerLowered), 0u);
    CHECK_EQ(rig.net.node(rig.a).radio.power, 20.0f);

    // A peer never heard is merely absent: no one-way link, no search.
    MonitorRig quiet;
    quiet.net.node(quiet.b).online = false;
    quiet.aTalks = true;
    quiet.net.run(5000);
    CHECK(quiet.events.empty());
}

// A peer discovery finds is pinged until it acknowledges, up to three times:
// with nothing else to send, that is what reveals a one-way link.
TEST(link_monitor_checks_new_peers) {
    MonitorRig healthy;
    healthy.net.run(500);
    healthy.monitor->found(healthy.net.mac(healthy.b), healthy.net.now());
    size_t sent = healthy.net.engine(healthy.a).stats().framesSent;
    healthy.net.run(2000);
    CHECK_EQ(healthy.net.engine(healthy.a).stats().framesSent - sent, 1u);  // one ping, acknowledged
    CHECK(healthy.events.empty());
    Deadline d(healthy.net.now());
    healthy.monitor->nextTick(d);
    CHECK(!d.set());  // done: nothing left to wake for

    MonitorRig weak;
    weak.weakSupply();
    weak.net.run(500);
    weak.monitor->found(weak.net.mac(weak.b), weak.net.now());
    CHECK(weak.net.runUntil([&] { return weak.count(LinkMonitor::Event::PowerLowered) > 0; }, 20000));
    CHECK_EQ(weak.count(LinkMonitor::Event::OneWay), 1u);

    // Without the fallback, neither checks nor searches.
    MonitorRig off;
    off.monitor->reset(false);
    off.weakSupply();
    off.aTalks = true;
    off.monitor->found(off.net.mac(off.b), off.net.now());
    off.net.run(5000);
    CHECK_EQ(off.count(LinkMonitor::Event::OneWay), 1u);  // still reported
    CHECK_EQ(off.count(LinkMonitor::Event::FallbackStarted), 0u);
    CHECK_EQ(off.net.node(off.a).radio.power, 20.0f);
}

TEST(random_frames_do_not_crash) {
    sim::Network net;
    Config cfg;
    cfg.maxMessageSize = 4096;
    size_t b = net.addNode(cfg);
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    net.engine(b).listen(2, inbox.handler());
    std::mt19937 rng(1234);
    for (int i = 0; i < 200000; ++i) {
        size_t len = rng() % 260;
        std::vector<uint8_t> f(len);
        for (auto& x : f) x = static_cast<uint8_t>(rng());
        if (len > 0) f[0] = static_cast<uint8_t>(0x40 | (f[0] & 0x3F));  // mostly valid version
        if (len > 1) f[1] = 0;
        if (len > 2) f[2] = static_cast<uint8_t>(1 + (rng() & 1));
        if (len > 8) {
            f[4] = 0;
            f[8] = 0;
            f[6] = 0;
            f[7] = static_cast<uint8_t>(f[7] % 24);
        }
        Mac src = {{0x02, 1, 1, 1, 1, static_cast<uint8_t>(rng() % 4)}};
        net.inject(b, src, f);
        if (i % 10 == 0) net.step();  // completes any acks the engine sent
    }
    net.run(2000);
    CHECK_EQ(net.engine(b).pendingMessages(), 0u);
}

TEST(larger_mtu_uses_fewer_frames) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    net.node(a).link.mtu = 1470;
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    auto msg = pattern(10000);
    net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), reliable(), nullptr, net.now());
    CHECK(net.runUntil([&] { return inbox.messages.size() == 1; }));
    CHECK(inbox.messages[0] == msg);
    size_t dataFrames = 0;
    for (auto& f : net.log) dataFrames += f.from == a;
    CHECK_EQ(dataFrames, (msg.size() + 4 + 1461 - 1) / 1461);
}

// Other tasks call in while a callback runs: the engine carries on with
// whatever they changed.
TEST(engine_carries_on_after_calls_made_while_callbacks_run) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    TestGate ga, gb;
    net.engine(a).setCallbackGate(&ga);
    net.engine(b).setCallbackGate(&gb);
    Inbox later;
    int first = 0;
    net.engine(b).listen(1, [&](const Message&) {
        first++;
        // Meanwhile: the handler is replaced, and a reply goes out.
        gb.meanwhile = [&] {
            net.engine(b).listen(1, later.handler());
            uint8_t reply[300] = {};
            net.engine(b).send(net.mac(a), 2, reply, sizeof(reply), reliable(), nullptr, net.now());
        };
    });
    Inbox replies;
    net.engine(a).listen(2, replies.handler());
    std::vector<Outcome> outs(3);
    auto msg = pattern(700);
    for (auto& o : outs) {
        net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), reliable(), o.handler(), net.now());
    }
    // A completion meanwhile: everything else is cancelled (another task ending).
    ga.meanwhile = [&] { net.engine(a).cancelAll(Status::Cancelled); };
    CHECK(net.runUntil([&] { return outs[2].done; }));
    CHECK(outs[0].status == Status::Ok);
    CHECK(outs[1].status == Status::Cancelled);
    CHECK(outs[2].status == Status::Cancelled);
    CHECK_EQ(first, 1);
    net.run(500);
    CHECK_EQ(replies.messages.size(), 1u);
    auto again = pattern(800, 2);
    Outcome out;
    net.engine(a).send(net.mac(b), 1, again.data(), again.size(), reliable(), out.handler(), net.now());
    CHECK(net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Ok);
    CHECK_EQ(later.messages.size(), 1u);
}

TEST(engine_reports_receive_timestamps) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    net.node(b).clockOffsetUs = 42000000;
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    net.run(10);
    net.engine(a).send(net.mac(b), 1, nullptr, 0, SendOptions(), nullptr, net.now());
    net.run(5);
    CHECK_EQ(inbox.meta.size(), 1u);
    CHECK(inbox.meta[0].timestampUs >= 42000000u + 10000u);
    CHECK(!inbox.meta[0].authenticated);
}

TEST(engine_reports_its_next_work) {
    sim::Network net;
    net.sparse = true;
    size_t a = net.addNode(), b = net.addNode();
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    auto due = [&] {
        Deadline d(net.now());
        net.engine(a).nextTick(d);
        return d;
    };
    CHECK(!due().set());

    // Queued and sent at once: nothing for tick() while the frame is in flight but its timeout.
    SendOptions reliable;
    reliable.reliable = true;
    uint8_t payload[600] = {};
    Status result = Status::InvalidState;
    CHECK(net.engine(a).send(net.mac(b), 1, payload, sizeof(payload), reliable, [&](Status s) { result = s; },
                             net.now()) == Status::Ok);
    CHECK_EQ(due().delay(), net.engine(a).config().frameSentTimeoutMs);
    CHECK(net.runUntil([&] { return result != Status::InvalidState; }, 2000));
    CHECK(result == Status::Ok);
    CHECK_EQ(inbox.messages.size(), 1u);
    CHECK(!due().set());

    // An absent peer: retries back off, then the message fails; idle again afterwards.
    net.node(b).online = false;
    result = Status::InvalidState;
    net.engine(a).send(net.mac(b), 1, payload, sizeof(payload), reliable, [&](Status s) { result = s; }, net.now());
    size_t before = net.ticksRun;
    CHECK(net.runUntil([&] { return result != Status::InvalidState; }, 10000));
    CHECK(result == Status::SendFailed || result == Status::Timeout);
    net.run(2000);
    CHECK(!due().set());
    CHECK(net.ticksRun - before < net.now() / 4);  // both engines, every ms: 2 per ms
}
