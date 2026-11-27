// Host-side tests for the NowTP protocol engine: time synchronization.

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

// The simulator timestamps frames to the millisecond, so an estimate is off by
// up to about a millisecond per hop (well under that on hardware). A step or an
// error beyond these would be a reference change that lost the network time
// (which would be seconds: another node's uptime).
constexpr int64_t kHopUs = 1500;
constexpr int64_t kTwoHopsUs = 2500;

// The largest change of node i's network-time error against `truth` (the
// network time as it should be) between two samples 10 ms apart, and the
// largest error.
struct StepWatch {
    TimeRig& rig;
    size_t node;
    std::function<uint64_t()> truth;
    int64_t last = 0;
    int64_t maxStep = 0;
    int64_t maxError = 0;
    bool first = true;
    void run(uint32_t ms) {
        for (uint32_t t = 0; t < ms; t += 10) {
            rig.net.run(10);
            int64_t e = static_cast<int64_t>(rig.ts[node]->networkTime() - truth());
            if (!first) maxStep = std::max(maxStep, absValue(e - last));
            maxError = std::max(maxError, absValue(e));
            first = false;
            last = e;
        }
    }
};

}  // namespace

namespace {

void putTime(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
}

uint64_t getTime(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

}  // namespace

namespace {

// Time requests arrive 2 ms after their "sent" report, responses at once: a
// delay that depends on the direction, which send-time stamps can't see. A
// follower's own rounds then put half of it into its estimate.
void delayTimeRequests(sim::Network& net) {
    net.deliveryDelayMs = [](const sim::Frame& f) -> uint32_t {
        return f.data.size() > 5 && f.data[2] == kTimeSyncPort && f.data[5] == 1 ? 2 : 0;
    };
}

}  // namespace

namespace {

struct CountingGuard : CarrierGuard {
    bool open = true;
    int depth = 0;
    int entered = 0;
    bool enter() override {
        if (!open) return false;
        depth++;
        entered++;
        return true;
    }
    void leave() override { depth--; }
};

}  // namespace

// ---------------------------------------------------------------------------
// Time synchronization
TEST(timesync_estimates_offset_and_drift) {
    TimeRig rig;
    size_t ref = rig.add(true, 5000000000ull, 0), b = rig.add(false, 1234567890ull, 40e-6);
    rig.start();
    CHECK(!rig.ts[b]->synced());
    CHECK(rig.net.runUntil([&] { return rig.ts[b]->synced(); }, 5000));
    CHECK(absValue(rig.error(b, ref)) < 1000);
    CHECK(rig.ts[b]->status().reference == rig.net.mac(ref));
    rig.net.run(60000);
    TimeSyncStatus s = rig.ts[b]->status();
    CHECK(s.synced);
    CHECK(s.rounds >= 10u);
    CHECK(absValue(rig.error(b, ref)) < 1000);
    CHECK(s.driftPpm < -35 && s.driftPpm > -45);  // our clock runs 40 ppm fast
    CHECK(rig.ts[ref]->status().isReference);
    CHECK_EQ(rig.error(ref, ref), 0);
}

TEST(timesync_drift_estimate_bridges_gaps) {
    TimeRig rig;
    size_t ref = rig.add(true, 7000000000ull, 0), b = rig.add(false, 1000000ull, -100e-6);
    rig.start();
    rig.net.run(45000);
    CHECK(absValue(rig.error(b, ref)) < 1000);
    // The reference goes quiet for 30 s: 100 ppm would drift 3 ms uncorrected.
    rig.net.node(ref).online = false;
    rig.net.run(30000);
    CHECK(absValue(rig.error(b, ref)) < 1000);
    CHECK(rig.ts[b]->synced());
    CHECK(rig.ts[b]->status().ageMs >= 29000u);
}

TEST(timesync_converts_both_ways) {
    TimeRig rig;
    rig.add(true, 3000000000ull, 0);
    size_t b = rig.add(false, 1000ull, 25e-6);
    rig.start();
    rig.net.run(20000);
    uint64_t local = rig.net.node(b).clockUs(rig.net.now()) + 500000;
    uint64_t net = rig.ts[b]->toNetwork(local);
    int64_t back = static_cast<int64_t>(rig.ts[b]->toLocal(net) - local);
    CHECK(absValue(back) <= 2);
}

TEST(timesync_explicit_reference_chains) {
    TimeRig rig;
    size_t ref = rig.add(true, 9000000000ull, 0), b = rig.add(false, 4000000000ull, 30e-6),
           c = rig.add(false, 1000ull, -20e-6);
    rig.start();
    rig.ts[c]->setReference(rig.net.mac(b), rig.net.now());  // c only talks to b
    rig.net.run(30000);
    CHECK(rig.ts[c]->synced());
    CHECK(absValue(rig.error(c, ref)) < 2000);
}

TEST(timesync_rejects_outliers_and_follows_a_jump) {
    TimeRig rig;
    size_t ref = rig.add(true, 2000000000ull, 0), b = rig.add(false, 1000ull, 0);
    rig.start();
    rig.net.run(30000);
    CHECK(absValue(rig.error(b, ref)) < 1000);
    // The reference rebooted: its clock restarted from a much smaller value.
    rig.net.node(ref).clockOffsetUs -= 1500000000ull;
    rig.net.run(40000);
    CHECK(absValue(rig.error(b, ref)) < 1000);
}

TEST(timesync_stamps_exchanges_on_air) {
    // The reference's frames wait 4 ms in its driver before going on air: one
    // direction only, so queue-time stamps would be 2 ms off. Stamped when
    // the radio reports them sent, the wait drops out.
    TimeRig rig;
    size_t ref = rig.add(true, 8000000000ull, 0), b = rig.add(false, 1234ull, 35e-6);
    rig.net.node(ref).txQueueMs = 4;
    rig.start();
    rig.net.run(60000);
    CHECK(rig.ts[b]->synced());
    CHECK(absValue(rig.error(b, ref)) < 20);
}

TEST(timesync_works_with_older_responders) {
    // A responder from before on-air stamps: 27-byte responses, queue-time t3.
    TimeRig rig;
    size_t old = rig.add(true, 3000000000ull, 0), b = rig.add(false, 1000ull, -15e-6);
    sim::Node* node = &rig.net.node(old);
    node->txQueueMs = 4;  // with queue-time stamps only, 2 ms of it shows
    rig.net.engine(old).listen(kTimeSyncPort, [&rig, node, old](const Message& m) {
        if (m.len < 11 || m.data[0] != 1) return;
        uint8_t out[27];
        memcpy(out, m.data, 11);
        out[0] = 2;
        uint64_t t2 = m.timestampUs, t3 = node->clockUs(rig.net.now());
        for (int i = 0; i < 8; ++i) {
            out[11 + i] = static_cast<uint8_t>(t2 >> (8 * i));
            out[19 + i] = static_cast<uint8_t>(t3 >> (8 * i));
        }
        rig.net.engine(old).send(m.src, kTimeSyncPort, out, sizeof(out), SendOptions(), CompletionHandler(),
                                 rig.net.now());
    });
    rig.ts[b]->start(rig.net.now());
    rig.disc[b]->start(rig.net.now());
    rig.disc[old]->start(rig.net.now());
    CHECK(rig.net.runUntil([&] { return rig.ts[b]->synced(); }, 10000));
    rig.net.run(30000);
    int64_t e = rig.error(b, old);
    CHECK(e > -2000 - kHopUs && e < -2000 + kHopUs);
    CHECK_EQ(rig.ts[b]->status().calibrations, 0u);  // it never measures us
}

// Found by fuzz_frames: a response's times are the responder's to choose,
// and the round trip (t4 - t1) - (t3 - t2) overflowed int64_t with t3 - t2
// at 2^63, as did the offset ((t2 - t1) + (t3 - t4)) / 2 with t2 and t3
// 2^62 µs ahead. The first two exchanges of every round get such times here
// (the second one looking the fastest); the others are honest, and the round
// goes on without them.
TEST(timesync_drops_exchanges_with_impossible_times) {
    TimeRig rig;
    size_t ref = rig.add(true, 3000000000ull, 0), b = rig.add(false, 1000ull, 10e-6);
    sim::Node* node = &rig.net.node(ref);
    size_t hostile = 0;
    rig.net.engine(ref).listen(kTimeSyncPort, [&rig, &hostile, node, ref](const Message& m) {
        if (m.len < 11 || m.data[0] != 1) return;
        uint8_t out[27];
        memcpy(out, m.data, 11);
        out[0] = 2;
        uint64_t t2 = m.timestampUs, t3 = node->clockUs(rig.net.now());
        if (m.data[2] == 0) {
            t2 = 0;
            t3 = 1ull << 63;
            hostile++;
        } else if (m.data[2] == 1) {
            t2 = getTime(m.data + 3) + (3ull << 61);
            t3 = t2 + 1500;  // held 1.5 ms: the shortest round trip
            hostile++;
        }
        putTime(out + 11, t2);
        putTime(out + 19, t3);
        rig.net.engine(ref).send(m.src, kTimeSyncPort, out, sizeof(out), SendOptions(), CompletionHandler(),
                                 rig.net.now());
    });
    rig.ts[b]->start(rig.net.now());
    rig.disc[b]->start(rig.net.now());
    rig.disc[ref]->start(rig.net.now());
    CHECK(rig.net.runUntil([&] { return rig.ts[b]->synced(); }, 10000));
    rig.net.run(20000);
    CHECK(hostile > 5);
    CHECK(absValue(rig.error(b, ref)) < kHopUs);
}

// The same with send times: the responder reports the send time of the
// exchange itself, 2^63 - 1 µs past the request, and t2 2^62 µs past it, so
// that the offset's two halves overflow int64_t when added. A responder
// whose every stamped exchange is impossible is never followed.
TEST(timesync_drops_stamped_exchanges_with_impossible_times) {
    TimeRig rig;
    size_t ref = rig.add(true, 3000000000ull, 0), b = rig.add(false, 1000ull, 0);
    size_t hostile = 0;
    rig.net.engine(ref).listen(kTimeSyncPort, [&rig, &hostile, ref](const Message& m) {
        if (m.len < 11 || m.data[0] != 1) return;
        uint8_t out[37];
        memcpy(out, m.data, 11);
        out[0] = 2;
        uint64_t t1 = getTime(m.data + 3);
        putTime(out + 11, t1 + (1ull << 62));
        putTime(out + 19, t1 + (1ull << 62));
        out[27] = m.data[1];  // this round,
        out[28] = m.data[2];  // this exchange
        putTime(out + 29, t1 + 0x7FFFFFFFFFFFFFFFull);
        hostile++;
        rig.net.engine(ref).send(m.src, kTimeSyncPort, out, sizeof(out), SendOptions(), CompletionHandler(),
                                 rig.net.now());
    });
    rig.ts[b]->start(rig.net.now());
    rig.disc[b]->start(rig.net.now());
    rig.disc[ref]->start(rig.net.now());
    rig.net.run(10000);
    CHECK(hostile > 20);
    CHECK(!rig.ts[b]->synced());
}

TEST(timesync_calibration_cancels_a_direction_delay) {
    for (bool calibrate : {false, true}) {
        TimeRig rig;
        rig.configure = [calibrate](size_t, TimeSyncConfig& c) { c.calibrationIntervalMs = calibrate ? 10000 : 0; };
        size_t ref = rig.add(true, 8000000000ull, 0), b = rig.add(false, 1234ull, 35e-6);
        delayTimeRequests(rig.net);
        rig.start();
        rig.net.run(90000);
        TimeSyncStatus s = rig.ts[b]->status();
        CHECK(s.synced);
        if (!calibrate) {
            CHECK(rig.error(b, ref) > 900 && rig.error(b, ref) < 1100);  // half the delay
            CHECK_EQ(s.calibrations, 0u);
        } else {
            CHECK(absValue(rig.error(b, ref)) < 50);
            CHECK(s.calibrationUs > 900 && s.calibrationUs < 1100);
            CHECK(s.calibrations >= 5u);
        }
    }
}

TEST(timesync_calibration_ignores_whatever_memory_held) {
    // Its tables start empty, whatever the memory held: built over garbage, a
    // reference measures only the follower that asked.
    TimeRig rig;
    size_t ref = rig.add(true, 8000000000ull, 0), b = rig.add(false, 1234ull, 35e-6);
    alignas(TimeSync) static unsigned char storage[sizeof(TimeSync)];
    memset(storage, 0xFF, sizeof(storage));  // slots that look heard just now, and due
    TimeSyncConfig tc;
    tc.role = TimeRole::Reference;
    sim::Node* node = &rig.net.node(ref);
    sim::Network* nw = &rig.net;
    TimeSync* dirty = new (storage) TimeSync(rig.net.engine(ref), [node, nw] { return node->clockUs(nw->now()); }, tc,
                                             rig.net.mac(ref));
    struct Destroy {
        TimeSync* t;
        ~Destroy() { t->~TimeSync(); }
    } destroy{dirty};
    rig.ts[ref].reset();
    rig.disc[ref]->onPeerEvent([dirty, &rig](PeerEvent e, const PeerInfo& p) { dirty->onPeerEvent(e, p, rig.net.now()); });
    dirty->setDiscovery(rig.disc[ref].get());
    rig.net.tickers[ref] = sim::Ticker(
        [&rig, ref, dirty](uint32_t now) {
            rig.disc[ref]->tick(now);
            dirty->tick(now);
        },
        [&rig, ref, dirty](Deadline& d) {
            rig.disc[ref]->nextTick(d);
            dirty->nextTick(d);
        },
        ref);
    rig.disc[ref]->start(rig.net.now());
    dirty->start(rig.net.now());
    rig.start(b);
    rig.net.run(60000);
    for (const sim::Frame& f : rig.net.log) {
        if (f.from == ref && f.data.size() > 2 && f.data[2] == kTimeSyncPort) CHECK(f.dst == rig.net.mac(b));
    }
    CHECK(rig.ts[b]->status().calibrations >= 3u);
    rig.disc[ref]->stop(rig.net.now());
}

TEST(timesync_calibration_serves_several_followers) {
    TimeRig rig;
    size_t ref = rig.add(true, 8000000000ull, 0);
    const double skews[] = {20e-6, -30e-6, 45e-6};
    for (double skew : skews) rig.add(false, 1000ull, skew);
    delayTimeRequests(rig.net);
    rig.start();
    rig.net.run(120000);
    for (size_t i = 1; i < 4; ++i) {
        CHECK(absValue(rig.error(i, ref)) < 50);
        CHECK(rig.ts[i]->status().calibrations >= 5u);
    }
}

TEST(timesync_calibration_carries_into_a_takeover) {
    // b corrects its estimate, then takes over: the network time it serves
    // keeps the correction, rather than stepping back by the delay.
    TimeRig rig;
    size_t a = rig.add(TimeRole::Candidate, 5000000000ull, 0), b = rig.add(TimeRole::Candidate, 1000ull, 25e-6),
           c = rig.add(TimeRole::Candidate, 2000ull, -25e-6);
    delayTimeRequests(rig.net);
    rig.start();
    rig.net.run(90000);
    CHECK(rig.ts[a]->isReference());
    CHECK(absValue(rig.error(b, a)) < 50);
    rig.net.node(a).online = false;
    sim::Node* na = &rig.net.node(a);
    StepWatch wb{rig, b, [&] { return na->clockUs(rig.net.now()); }};
    wb.run(60000);
    CHECK(rig.ts[b]->isReference());
    CHECK_EQ(rig.ts[b]->status().calibrationUs, 0);  // folded into the network time it serves
    CHECK(wb.maxError < 100);
    // c now calibrates against b.
    CHECK(absValue(static_cast<int64_t>(rig.ts[c]->networkTime() - na->clockUs(rig.net.now()))) < 100);
}

TEST(timesync_candidates_agree_on_one_reference) {
    TimeRig rig;
    const double skews[] = {10e-6, -20e-6, 30e-6, -5e-6};
    for (size_t k = 0; k < 4; ++k) rig.add(TimeRole::Candidate, 1000000000ull * (k + 1) + 12345 * k, skews[k]);
    rig.start();
    rig.net.run(4000);
    CHECK_EQ(rig.acting(), 0u);  // listening for an incumbent first
    CHECK(rig.net.runUntil([&] { return rig.acting() == 1 && rig.allSynced(); }, 20000));
    CHECK(rig.ts[0]->isReference());  // the lowest MAC
    rig.net.run(30000);
    CHECK_EQ(rig.acting(), 1u);
    for (size_t k = 0; k < 4; ++k) {
        CHECK(absValue(rig.error(k, 0)) < kHopUs);
        TimeSyncStatus s = rig.ts[k]->status();
        CHECK(s.reference == rig.net.mac(0));
        CHECK(s.role == TimeRole::Candidate);
    }
    const PeerInfo* p = rig.disc[1]->find(rig.net.mac(0));
    CHECK(p && p->timeReference && p->timeCandidate && p->timeSynced);
    p = rig.disc[0]->find(rig.net.mac(1));
    CHECK(p && !p->timeReference && p->timeCandidate && p->timeSynced);
}

TEST(timesync_takeover_keeps_network_time) {
    TimeRig rig;
    size_t a = rig.add(TimeRole::Candidate, 5000000000ull, 0), b = rig.add(TimeRole::Candidate, 1000ull, 40e-6),
           c = rig.add(TimeRole::Candidate, 3000000ull, -30e-6);
    rig.start();
    rig.net.run(40000);
    CHECK(rig.ts[a]->isReference());
    // The reference goes away for good; the network time is its clock, still.
    rig.net.node(a).online = false;
    sim::Node* na = &rig.net.node(a);
    StepWatch wb{rig, b, [&] { return na->clockUs(rig.net.now()); }};
    StepWatch wc{rig, c, [&] { return na->clockUs(rig.net.now()); }};
    for (int i = 0; i < 600; ++i) {
        wb.run(50);
        wc.run(50);
        CHECK(!rig.ts[c]->isReference());
    }
    CHECK(rig.ts[b]->isReference());  // synchronized, then the lower MAC
    CHECK(rig.ts[c]->status().reference == rig.net.mac(b));
    CHECK(rig.ts[c]->synced());
    CHECK(wb.maxError < kHopUs);
    CHECK(wc.maxError < kTwoHopsUs);
    CHECK(wb.maxStep < kHopUs);
    CHECK(wc.maxStep < kHopUs);
}

TEST(timesync_late_candidate_follows_the_incumbent) {
    TimeRig rig;
    size_t low = rig.add(TimeRole::Candidate, 9000000000ull, 0), b = rig.add(TimeRole::Candidate, 1000ull, 20e-6),
           c = rig.add(TimeRole::Candidate, 2000ull, -20e-6);
    rig.start(b);
    rig.start(c);
    rig.net.run(20000);
    CHECK(rig.ts[b]->isReference());
    // A lower MAC boots later: it follows instead of resetting everyone's time.
    rig.start(low);
    StepWatch w{rig, c, [&] { return rig.net.node(b).clockUs(rig.net.now()); }};
    w.run(20000);
    CHECK(rig.ts[b]->isReference());
    CHECK_EQ(rig.acting(), 1u);
    CHECK(rig.ts[low]->synced());
    CHECK(absValue(rig.error(low, b)) < kHopUs);
    CHECK(w.maxError < kHopUs);
}

TEST(timesync_split_references_merge_on_the_lowest_mac) {
    TimeRig rig;
    size_t a = rig.add(TimeRole::Candidate, 4000000000ull, 0), b = rig.add(TimeRole::Candidate, 1000ull, 15e-6),
           c = rig.add(TimeRole::Candidate, 2000ull, -15e-6);
    bool split = true;
    rig.net.linkModel = [&](size_t from, size_t to, PhyRate, float) {
        return split && ((from == a) != (to == a)) ? 1.0 : 0.0;
    };
    rig.start();
    rig.net.run(20000);
    CHECK(rig.ts[a]->isReference());
    CHECK(rig.ts[b]->isReference());
    CHECK(rig.ts[c]->status().reference == rig.net.mac(b));
    split = false;
    rig.net.run(20000);
    CHECK_EQ(rig.acting(), 1u);
    CHECK(rig.ts[a]->isReference());
    CHECK(absValue(rig.error(b, a)) < kHopUs);
    CHECK(absValue(rig.error(c, a)) < kHopUs);
}

TEST(timesync_rebooted_reference_hands_over_to_a_synced_candidate) {
    TimeRig rig;
    size_t a = rig.add(TimeRole::Candidate, 6000000000ull, 0), b = rig.add(TimeRole::Candidate, 1000ull, 25e-6),
           c = rig.add(TimeRole::Candidate, 2000ull, -25e-6);
    rig.start();
    rig.net.run(30000);
    CHECK(rig.ts[a]->isReference());
    // The network time is a's clock before the reboot, which restarts it at 2 s.
    uint64_t base = rig.net.node(a).clockUs(rig.net.now());
    uint32_t at = rig.net.now();
    auto truth = [&] { return base + static_cast<uint64_t>(rig.net.now() - at) * 1000; };
    rig.reboot(a, 2000000);
    StepWatch w{rig, c, truth};
    w.run(30000);
    // a has the lowest MAC, but lost the time: b, synchronized, took over.
    CHECK(rig.ts[b]->isReference());
    CHECK_EQ(rig.acting(), 1u);
    CHECK(rig.ts[a]->synced());
    CHECK(rig.ts[a]->status().reference == rig.net.mac(b));
    CHECK(absValue(static_cast<int64_t>(rig.ts[a]->networkTime() - truth())) < kTwoHopsUs);
    CHECK(w.maxError < kTwoHopsUs);
    CHECK(w.maxStep < kHopUs);
}

TEST(timesync_configured_reference_wins_over_candidates) {
    TimeRig rig;
    size_t a = rig.add(TimeRole::Candidate, 3000000000ull, 0), b = rig.add(TimeRole::Candidate, 1000ull, 10e-6),
           r = rig.add(TimeRole::Follow, 2000ull, -10e-6);
    rig.start();
    rig.net.run(20000);
    CHECK(rig.ts[a]->isReference());
    CHECK(rig.ts[r]->status().reference == rig.net.mac(a));
    // Made the reference at runtime: it keeps the network time it had.
    StepWatch w{rig, b, [&] { return rig.net.node(a).clockUs(rig.net.now()); }};
    w.run(1000);
    rig.ts[r]->setRole(TimeRole::Reference, rig.net.now());
    CHECK(rig.ts[r]->isReference());
    CHECK(absValue(rig.error(r, a)) < kHopUs);
    w.run(20000);
    CHECK_EQ(rig.acting(), 1u);  // the candidate gave way
    CHECK(rig.ts[a]->status().reference == rig.net.mac(r));
    CHECK(rig.ts[b]->status().reference == rig.net.mac(r));
    CHECK(w.maxStep < kTwoHopsUs);
    CHECK(w.maxError < kTwoHopsUs);
    CHECK(absValue(rig.apart(a, r)) < kHopUs);  // r serves its estimate of a's clock
    CHECK(absValue(rig.apart(b, r)) < kHopUs);
}

TEST(timesync_roles_and_reference_change_at_runtime) {
    TimeRig rig;
    size_t a = rig.add(TimeRole::Reference, 3000000000ull, 0), b = rig.add(TimeRole::Follow, 1000ull, 10e-6),
           c = rig.add(TimeRole::Candidate, 2000ull, 0);
    rig.start();
    rig.net.run(10000);
    CHECK(rig.allSynced());
    // Explicit reference: c follows b, and stops offering itself.
    rig.ts[c]->setReference(rig.net.mac(b), rig.net.now());
    rig.net.run(5000);
    TimeSyncStatus s = rig.ts[c]->status();
    CHECK(s.explicitReference && s.reference == rig.net.mac(b) && s.synced);
    const PeerInfo* p = rig.disc[a]->find(rig.net.mac(c));
    CHECK(p && !p->timeCandidate && p->timeSynced);
    rig.ts[c]->clearReference(rig.net.now());
    rig.net.run(5000);
    s = rig.ts[c]->status();
    CHECK(!s.explicitReference && s.reference == rig.net.mac(a));
    p = rig.disc[a]->find(rig.net.mac(c));
    CHECK(p && p->timeCandidate);
    // Off: the local clock, nothing announced.
    rig.ts[b]->setRole(TimeRole::Off, rig.net.now());
    CHECK(!rig.ts[b]->synced());
    CHECK_EQ(rig.ts[b]->networkTime(), rig.net.node(b).clockUs(rig.net.now()));
    rig.net.run(3000);
    p = rig.disc[a]->find(rig.net.mac(b));
    CHECK(p && !p->timeSynced && !p->timeCandidate && !p->timeReference);
    rig.ts[b]->setRole(TimeRole::Follow, rig.net.now());
    CHECK(rig.net.runUntil([&] { return rig.ts[b]->synced(); }, 5000));
    CHECK(absValue(rig.error(b, a)) < kHopUs);
    // The configured reference steps down to a candidate; c, synchronized,
    // and with a higher MAC, is next in line, and keeps a's time.
    rig.ts[a]->setRole(TimeRole::Follow, rig.net.now());
    rig.ts[a]->setInterval(1000);
    sim::Node* na = &rig.net.node(a);
    StepWatch w{rig, b, [&] { return na->clockUs(rig.net.now()); }};
    w.run(15000);
    CHECK(rig.ts[c]->isReference());
    CHECK_EQ(rig.acting(), 1u);
    CHECK(w.maxStep < kHopUs);
    CHECK(w.maxError < kTwoHopsUs);
}

// ---------------------------------------------------------------------------
// Time synchronization over several carriers
TEST(timesync_elects_and_synchronizes_over_beacons) {
    // No discovery on the carrier: offers go out as beacons. Four candidates
    // agree on one reference, the lowest MAC, and keep its time when it goes.
    CarrierRig rig;
    FakeWire& udp = rig.wire("udp");
    const double skews[] = {10e-6, -20e-6, 30e-6, -5e-6};
    for (size_t k = 0; k < 4; ++k) {
        size_t i = rig.add(TimeRole::Candidate, 1000000000ull * (k + 1) + 12345 * k, skews[k]);
        udp.join(i, *rig.ts[i]);
    }
    rig.start();
    rig.net.run(4000);
    CHECK_EQ(rig.acting(), 0u);  // listening for an incumbent first
    CHECK(rig.net.runUntil([&] { return rig.acting() == 1 && rig.allSynced(); }, 30000));
    CHECK(rig.ts[0]->isReference());
    rig.net.run(30000);
    CHECK_EQ(rig.acting(), 1u);
    for (size_t k = 1; k < 4; ++k) {
        CHECK(absValue(rig.error(k, 0)) < kHopUs);
        TimeSyncStatus s = rig.ts[k]->status();
        CHECK(s.reference == rig.ids[0]);
        CHECK(std::string(s.carrier) == "udp");
    }
    CHECK(std::string(rig.ts[0]->status().carrier).empty());
    // Beacons every 2 s from the four (all candidates), and the exchanges:
    // nothing like a flood.
    size_t before = udp.sentCount;
    rig.net.run(10000);
    CHECK(udp.sentCount - before < 250);

    // The reference goes for good: the next one keeps its network time.
    udp.unplugged[0] = true;
    sim::Node* n0 = &rig.net.node(0);
    int64_t worst = 0;
    for (int i = 0; i < 3000; ++i) {
        rig.net.run(10);
        worst = std::max(worst, absValue(static_cast<int64_t>(rig.ts[2]->networkTime() - n0->clockUs(rig.net.now()))));
    }
    CHECK(rig.ts[1]->isReference());
    CHECK_EQ(rig.acting(), 2u);  // node 0 still acts, alone
    CHECK(rig.ts[2]->status().reference == rig.ids[1]);
    CHECK(rig.ts[3]->synced());
    CHECK(worst < kTwoHopsUs);
}

TEST(timesync_fails_over_between_carriers) {
    CarrierRig rig;
    FakeWire& udp = rig.wire("udp", 1);
    FakeWire& radio = rig.wire("radio", 3);
    size_t ref = rig.add(TimeRole::Reference, 8000000000ull, 0), f = rig.add(TimeRole::Follow, 1234ull, 30e-6);
    for (size_t i : {ref, f}) {
        udp.join(i, *rig.ts[i]);  // first: preferred
        radio.join(i, *rig.ts[i]);
    }
    rig.start();
    CHECK(rig.net.runUntil([&] { return rig.ts[f]->synced(); }, 5000));
    rig.net.run(20000);
    CHECK(rig.carrier(f) == "udp");
    CHECK(absValue(rig.error(f, ref)) < kHopUs);

    // Unplugged: the next round goes by radio, from the same estimate.
    udp.unplugged[f] = true;
    CHECK(rig.watch(f, ref, 30000) < kHopUs);
    CHECK(rig.carrier(f) == "radio");
    CHECK(rig.ts[f]->status().reference == rig.ids[ref]);
    // Back on the preferred carrier at the next round.
    udp.unplugged[f] = false;
    CHECK(rig.watch(f, ref, 12000) < kHopUs);
    CHECK(rig.carrier(f) == "udp");

    // Silent, though it still reaches it: a round without an answer moves it,
    // and the carrier gets another chance later.
    udp.silent[f] = true;
    CHECK(rig.watch(f, ref, 15000) < kHopUs);
    CHECK(rig.carrier(f) == "radio");
    udp.silent[f] = false;
    CHECK(rig.watch(f, ref, 40000) < kHopUs);
    CHECK(rig.carrier(f) == "udp");

    // Left out of the order: radio only, at once.
    const char* order[] = {"radio"};
    CHECK_EQ(rig.ts[f]->setCarrierOrder(order, 1, rig.net.now()), 1u);
    CHECK(rig.watch(f, ref, 12000) < kHopUs);
    CHECK(rig.carrier(f) == "radio");
    const char* both[] = {"radio", "udp"};
    CHECK_EQ(rig.ts[f]->setCarrierOrder(both, 2, rig.net.now()), 2u);
    rig.net.run(12000);
    CHECK(rig.carrier(f) == "radio");  // preferred now
    // Removed: what came through it goes too.
    rig.ts[f]->removeCarrier(*radio.at[f], rig.net.now());
    CHECK(rig.watch(f, ref, 12000) < kHopUs);
    CHECK(rig.carrier(f) == "udp");
}

TEST(timesync_answers_on_the_carrier_asked) {
    // One reference serves a follower on each carrier.
    CarrierRig rig;
    FakeWire& udp = rig.wire("udp", 1);
    FakeWire& radio = rig.wire("radio", 2);
    size_t ref = rig.add(TimeRole::Reference, 8000000000ull, 0), a = rig.add(TimeRole::Follow, 1234ull, 30e-6),
           b = rig.add(TimeRole::Follow, 99999ull, -25e-6);
    udp.join(ref, *rig.ts[ref]);
    radio.join(ref, *rig.ts[ref]);
    udp.join(a, *rig.ts[a]);
    radio.join(b, *rig.ts[b]);
    rig.start();
    CHECK(rig.net.runUntil([&] { return rig.allSynced(); }, 10000));
    rig.net.run(30000);
    CHECK(rig.carrier(a) == "udp");
    CHECK(rig.carrier(b) == "radio");
    CHECK(absValue(rig.error(a, ref)) < kHopUs);
    CHECK(absValue(rig.error(b, ref)) < kHopUs);
    CHECK(absValue(rig.apart(a, b)) < kTwoHopsUs);
}

TEST(timesync_calibration_is_kept_per_carrier) {
    // Requests wait 2 ms after their stamps on udp, none on radio: each
    // carrier has its own correction, and a failover doesn't carry one over.
    CarrierRig rig;
    rig.configure = [](size_t, TimeSyncConfig& c) { c.calibrationIntervalMs = 10000; };
    FakeWire& udp = rig.wire("udp", 1);
    FakeWire& radio = rig.wire("radio", 1);
    udp.requestDelayMs = 2;
    size_t ref = rig.add(TimeRole::Reference, 8000000000ull, 0), f = rig.add(TimeRole::Follow, 1234ull, 35e-6);
    for (size_t i : {ref, f}) {
        udp.join(i, *rig.ts[i]);
        radio.join(i, *rig.ts[i]);
    }
    rig.start();
    rig.net.run(90000);
    TimeSyncStatus s = rig.ts[f]->status();
    CHECK(std::string(s.carrier) == "udp");
    CHECK(absValue(rig.error(f, ref)) < 50);
    CHECK(s.calibrationUs > 900 && s.calibrationUs < 1100);

    udp.unplugged[f] = true;
    CHECK(rig.watch(f, ref, 60000) < 300);
    s = rig.ts[f]->status();
    CHECK(std::string(s.carrier) == "radio");
    CHECK(absValue(s.calibrationUs) < 50);
    CHECK(s.calibrations >= 3u);

    udp.unplugged[f] = false;  // its correction is still there
    CHECK(rig.watch(f, ref, 30000) < 300);
    s = rig.ts[f]->status();
    CHECK(std::string(s.carrier) == "udp");
    CHECK(s.calibrationUs > 900 && s.calibrationUs < 1100);
}

TEST(timesync_one_clock_over_nowtp_and_udp) {
    // The reference on both, with ESP-NOW sending from another address than
    // its device id (its soft-AP's): one follower on each, both on its time.
    CarrierRig rig;
    FakeWire& udp = rig.wire("udp", 1);
    size_t ref = rig.add(TimeRole::Reference, 8000000000ull, 0, deviceMac(0x10)),
           a = rig.add(TimeRole::Follow, 1234ull, 30e-6), b = rig.add(TimeRole::Follow, 99999ull, -25e-6);
    rig.addRadio(ref);
    udp.join(ref, *rig.ts[ref]);
    rig.addRadio(a);
    udp.join(b, *rig.ts[b]);
    rig.start();
    CHECK(rig.net.runUntil([&] { return rig.allSynced(); }, 10000));
    rig.net.run(30000);
    CHECK(rig.carrier(a) == "nowtp");
    CHECK(rig.carrier(b) == "udp");
    CHECK(rig.ts[a]->status().reference == deviceMac(0x10));
    CHECK(rig.ts[b]->status().reference == deviceMac(0x10));
    CHECK(absValue(rig.error(a, ref)) < kHopUs);
    CHECK(absValue(rig.error(b, ref)) < kHopUs);
    const PeerInfo* p = rig.disc[a]->find(rig.net.mac(ref));
    CHECK(p && p->deviceId == deviceMac(0x10) && p->timeReference);

    // A follower on both, with the reference named the same on each: one
    // reference, followed over the first carrier, then the other.
    size_t c = rig.add(TimeRole::Candidate, 5555ull, 10e-6);
    udp.join(c, *rig.ts[c]);
    rig.addRadio(c);
    rig.disc[c]->start(rig.net.now());
    rig.ts[c]->start(rig.net.now());
    CHECK(rig.net.runUntil([&] { return rig.ts[c]->synced(); }, 10000));
    rig.net.run(20000);
    CHECK(rig.carrier(c) == "udp");
    CHECK(rig.ts[c]->status().reference == deviceMac(0x10));
    CHECK(!rig.ts[c]->isReference());
    udp.unplugged[c] = true;
    CHECK(rig.watch(c, ref, 20000) < kHopUs);
    CHECK(rig.carrier(c) == "nowtp");
}

TEST(timesync_engine_carrier_queues_for_another_task) {
    // The TimeSync of node f takes what ESP-NOW brings in its own tick().
    CarrierRig rig;
    size_t ref = rig.add(TimeRole::Reference, 8000000000ull, 0), f = rig.add(TimeRole::Follow, 1234ull, 30e-6);
    rig.addRadio(ref);
    EngineTimeCarrier& c = rig.addRadio(f);
    CountingGuard guard;
    int wakes = 0;
    CHECK(c.setQueued([&wakes] { wakes++; }));
    c.setGuard(&guard);
    rig.start();
    CHECK(rig.net.runUntil([&] { return rig.ts[f]->synced(); }, 10000));
    rig.net.run(20000);
    CHECK(absValue(rig.error(f, ref)) < kHopUs);
    CHECK(rig.carrier(f) == "nowtp");
    CHECK(wakes > 20);
    CHECK(guard.entered > 20);
    CHECK_EQ(guard.depth, 0);
    CHECK_EQ(c.dropped(), 0u);

    // Queued, then not delivered until the TimeSync ticks.
    c.peerEvent(PeerEvent::Lost, *rig.disc[f]->find(rig.net.mac(ref)));
    CHECK(c.pending());
    Deadline d(rig.net.now());
    rig.ts[f]->nextTick(d);
    CHECK(d.set() && d.delay() == 0);

    // Detached (the transport ended): its offers go, and nothing more is sent.
    c.attach(nullptr, nullptr);
    guard.open = false;
    rig.ts[f]->tick(rig.net.now());
    CHECK(!c.pending());
    CHECK(std::string(rig.carrier(f)).empty());
    CHECK(!c.reaches(rig.ids[ref]));
    uint32_t token = 0;
    const uint8_t ping[1] = {0};
    CHECK(c.send(rig.ids[ref], ping, 1, &token) == Status::InvalidState);
    CHECK(rig.ts[f]->synced());  // the estimate stays until it goes stale
}

TEST(timesync_network_time_reads_from_another_task) {
    // Rounds update the estimate while another thread converts: every read
    // sees one whole estimate (a torn one, mixing two rounds, would be off by
    // the drift over the seconds between them). A smoke test: on the host,
    // even an unguarded copy is rarely caught mid-write.
    CarrierRig rig;
    FakeWire& udp = rig.wire("udp");
    size_t ref = rig.add(TimeRole::Reference, 8000000000ull, 0), f = rig.add(TimeRole::Follow, 1234ull, 40e-6);
    udp.join(ref, *rig.ts[ref]);
    udp.join(f, *rig.ts[f]);
    rig.start();
    CHECK(rig.net.runUntil([&] { return rig.ts[f]->synced(); }, 5000));
    uint64_t local = rig.net.node(f).clockUs(rig.net.now()) + 5000000;
    std::atomic<bool> done{false};
    std::atomic<uint32_t> reads{0}, torn{0};
    TimeSync* t = rig.ts[f].get();
    std::thread reader([&] {
        while (!done.load()) {
            // Two calls: compared only when no round changed the estimate between them.
            uint64_t n = t->toNetwork(local);
            int64_t back = static_cast<int64_t>(t->toLocal(n) - local);
            if (t->toNetwork(local) == n && (back > 2 || back < -2)) torn++;
            if (!t->isReference() && t->role() != TimeRole::Follow) torn++;
            reads++;
        }
    });
    rig.net.run(60000);
    done = true;
    reader.join();
    CHECK_EQ(torn.load(), 0u);
    CHECK(reads.load() > 1000u);
    CHECK(absValue(rig.error(f, ref)) < kHopUs);
}
