// Host-side tests for the NowTP protocol engine: diagnostics.

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

// A spoofed Apply (rate 1 Mbps, 5 dBm) from `src`, without authentication.
void injectApply(sim::Network& net, size_t to, const Mac& src) {
    std::vector<uint8_t> payload = {6, 1, 0, 0, static_cast<uint8_t>(PhyRate::B1M), 20};
    wire::Header h;
    h.port = kDiagnosticsPort;
    std::vector<uint8_t> f(wire::kCommonHeaderSize);
    wire::encodeHeader(h, f.data());
    f.insert(f.end(), payload.begin(), payload.end());
    net.inject(to, src, f);
    net.run(500);
}

}  // namespace

// ---------------------------------------------------------------------------
// Diagnostics
TEST(diag_ping_healthy_link) {
    DiagRig rig;
    size_t a = rig.add(), b = rig.add();
    float req = 0, rep = 0;
    CHECK(rig.diag[a]->ping(rig.net.mac(b), &req, &rep) == Status::Ok);
    CHECK(req == 20.0f);
    CHECK(rep == 20.0f);
}

TEST(diag_ping_falls_back_to_lower_power) {
    DiagRig rig;
    size_t a = rig.add(), b = rig.add();
    rig.net.linkModel = weakSupply(b);  // b's answers are lost at 20 dBm
    float req = 0, rep = 0;
    CHECK(rig.diag[a]->ping(rig.net.mac(b), &req, &rep) == Status::Ok);
    CHECK(rep <= 17.0f);
    CHECK(rig.net.node(b).radio.power == 20.0f);  // restored after the answer
}

TEST(diag_unresponsive_peer) {
    DiagRig rig;
    DiagnosticsConfig silent;
    silent.respond = false;
    size_t a = rig.add(), b = rig.add("", Config(), 1470, silent);
    LinkDiagnosis d;
    CHECK(rig.diag[a]->diagnose(rig.net.mac(b), d) == Status::Timeout);
    CHECK(!d.responds);
    CHECK(DiagRig::has(d.issues, IssueKind::PeerUnresponsive));
}

TEST(diag_measure_is_directional) {
    DiagRig rig;
    size_t a = rig.add(), b = rig.add();
    // a's transmitter is distorted at 36 Mbps and above; b is fine.
    rig.net.linkModel = [a](size_t from, size_t, PhyRate rate, float) {
        return from == a && isOfdm(rate) && nominalKbps(rate) >= 36000 ? 1.0 : 0.0;
    };
    std::vector<ProbeStep> steps = {ProbeStep(PhyRate::B1M, 0), ProbeStep(PhyRate::G24M, 0),
                                    ProbeStep(PhyRate::G54M, 0)};
    std::vector<ProbeResult> fwd, rev;
    CHECK(rig.diag[a]->measure(rig.net.mac(b), steps, 10, &fwd, &rev) == Status::Ok);
    CHECK_EQ(fwd.size(), 3u);
    CHECK_EQ(rev.size(), 3u);
    CHECK_EQ(fwd[0].received, 10);
    CHECK_EQ(fwd[1].received, 10);
    CHECK_EQ(fwd[2].received, 0);
    CHECK_EQ(rev[2].received, 10);
    // Radio settings are back to normal on both nodes.
    CHECK(rig.net.node(a).radio.bcast == PhyRate::Default);
    CHECK(rig.net.node(b).radio.bcast == PhyRate::Default);
    CHECK(rig.net.node(b).radio.power == 20.0f);
}

TEST(diag_finds_weak_supply_on_both_sides) {
    DiagRig rig;
    size_t a = rig.add(), b = rig.add();
    rig.net.linkModel = weakSupply(a);
    LinkDiagnosis fromA, fromB;
    CHECK(rig.diag[a]->diagnose(rig.net.mac(b), fromA) == Status::Ok);
    CHECK(fromA.ours.dsssDbm == 17.0f);
    CHECK(fromA.ours.ofdmDbm == 13.0f);
    CHECK(fromA.theirs.dsssDbm == 20.0f);
    CHECK(fromA.theirs.ofdmDbm == 20.0f);
    CHECK(DiagRig::has(fromA.issues, IssueKind::TxPowerLimited, true));
    CHECK(DiagRig::has(fromA.issues, IssueKind::OfdmPowerLimited, true));
    CHECK(!DiagRig::has(fromA.issues, IssueKind::TxPowerLimited, false));

    CHECK(rig.diag[b]->diagnose(rig.net.mac(a), fromB) == Status::Ok);
    CHECK(fromB.theirs.dsssDbm == 17.0f);
    CHECK(fromB.theirs.ofdmDbm == 13.0f);
    CHECK(DiagRig::has(fromB.issues, IssueKind::TxPowerLimited, false));
    CHECK(rig.net.node(a).radio.power == 20.0f);  // diagnosis alone changes nothing
}

TEST(diag_measures_power_response) {
    DiagRig rig;
    size_t a = rig.add(), b = rig.add();
    // b's power setting hardly changes what it radiates.
    rig.net.rssiModel = [b](size_t from, size_t, float power) {
        return from == b ? static_cast<int>(-45 + power / 10) : static_cast<int>(-60 + power);
    };
    LinkDiagnosis d;
    CHECK(rig.diag[a]->diagnose(rig.net.mac(b), d) == Status::Ok);
    CHECK(d.ours.powerResponse > 0.9f && d.ours.powerResponse < 1.1f);
    CHECK(d.theirs.powerResponse < 0.3f);
    CHECK(DiagRig::has(d.issues, IssueKind::PowerControlIneffective, false));
    CHECK(!DiagRig::has(d.issues, IssueKind::PowerControlIneffective, true));
}

TEST(diag_long_range_on_one_side_only) {
    DiagRig rig;
    size_t a = rig.add(), b = rig.add();
    rig.net.node(a).radio.lr = true;  // b has no Long Range
    LinkDiagnosis d;
    CHECK(rig.diag[a]->diagnose(rig.net.mac(b), d) == Status::Ok);
    CHECK(DiagRig::has(d.issues, IssueKind::LongRangeUnavailable));
    bool lrRateIssue = false;
    for (const Issue& i : d.issues) {
        lrRateIssue = lrRateIssue || ((i.kind == IssueKind::RateFailsForward || i.kind == IssueKind::RateFailsReverse) &&
                                      isLongRange(i.rate));
    }
    CHECK(!lrRateIssue);
    // b cannot send LR frames: it must not fake them at another rate.
    for (const ProbeResult& r : d.reverse) {
        if (isLongRange(r.step.rate)) CHECK_EQ(r.received, 0);
    }
}

TEST(diag_finds_rate_failures) {
    DiagRig rig;
    size_t a = rig.add(), b = rig.add();
    rig.net.linkModel = [b](size_t from, size_t, PhyRate rate, float) {
        return from == b && (rate == PhyRate::G54M || rate == PhyRate::MCS7) ? 1.0 : 0.0;
    };
    LinkDiagnosis d;
    CHECK(rig.diag[a]->diagnose(rig.net.mac(b), d) == Status::Ok);
    bool sawG54 = false, sawMcs7 = false;
    for (const Issue& i : d.issues) {
        if (i.kind != IssueKind::RateFailsReverse) continue;
        sawG54 = sawG54 || i.rate == PhyRate::G54M;
        sawMcs7 = sawMcs7 || i.rate == PhyRate::MCS7;
    }
    CHECK(sawG54 && sawMcs7);
    CHECK(!DiagRig::has(d.issues, IssueKind::RateFailsForward));
}

TEST(diag_optimize_picks_fastest_reliable_rates) {
    DiagRig rig;
    DiagnosticsConfig tunable;
    tunable.acceptRemoteTuning = true;
    size_t a = rig.add(), b = rig.add("", Config(), 1470, tunable);
    // Rates above 24 Mbps fail from a to b; b to a everything works.
    rig.net.linkModel = [a](size_t from, size_t, PhyRate rate, float) {
        return from == a && nominalKbps(rate) > 26000 ? 1.0 : 0.0;
    };
    OptimizeOptions opt;
    LinkProfile p;
    CHECK(rig.diag[a]->optimize(rig.net.mac(b), opt, p) == Status::Ok);
    CHECK(p.rateToPeer == PhyRate::MCS3);  // 26 Mbps
    CHECK(p.rateFromPeer == PhyRate::MCS7);
    CHECK(p.applied);
    CHECK(p.verified);
    CHECK(rig.net.node(a).radio.peerRate(rig.net.mac(b)) == PhyRate::MCS3);
    CHECK(rig.net.node(b).radio.peerRate(rig.net.mac(a)) == PhyRate::MCS7);

    // Data still flows with the new settings.
    Inbox inbox;
    rig.net.engine(b).listen(1, inbox.handler());
    auto msg = pattern(10000);
    Outcome out;
    SendOptions rel;
    rel.reliable = true;
    rig.net.engine(a).send(rig.net.mac(b), 1, msg.data(), msg.size(), rel, out.handler(), rig.net.now());
    CHECK(rig.net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Ok);
}

TEST(diag_optimize_lowers_power_of_weak_board) {
    DiagRig rig;
    DiagnosticsConfig tunable;
    tunable.acceptRemoteTuning = true;
    size_t a = rig.add(), b = rig.add("", Config(), 1470, tunable);
    rig.net.linkModel = weakSupply(b);
    LinkProfile p;
    CHECK(rig.diag[a]->optimize(rig.net.mac(b), OptimizeOptions(), p) == Status::Ok);
    CHECK(p.verified);
    CHECK(rig.net.node(b).radio.power <= 17.0f);  // b was told its working power
    CHECK(isOfdm(p.rateFromPeer) ? rig.net.node(b).radio.power <= 13.0f : true);
    CHECK(rig.net.node(a).radio.power == 20.0f);
}

TEST(diag_optimize_without_ofdm) {
    DiagRig rig;
    size_t a = rig.add(), b = rig.add();
    OptimizeOptions opt;
    opt.allowOfdm = false;
    opt.apply = false;
    LinkProfile p;
    CHECK(rig.diag[a]->optimize(rig.net.mac(b), opt, p) == Status::Ok);
    CHECK(p.rateToPeer == PhyRate::B11M);
    CHECK(!p.applied);
    CHECK(rig.net.node(a).radio.peerRate(rig.net.mac(b)) != PhyRate::B11M);
}

TEST(deep_discovery_reports_incompatibilities) {
    DiagRig rig;
    size_t a = rig.add("scanner");
    size_t sameChan = rig.add("good");
    size_t otherChan = rig.add("elsewhere");
    Config net7;
    net7.networkId = 7;
    size_t otherNet = rig.add("othernet", net7);
    size_t lrOnly = rig.add("faraway");
    size_t v1 = rig.add("old", Config(), 250);
    size_t deaf = rig.add("deaf");
    rig.net.node(otherChan).radio.chan = 6;
    rig.net.node(lrOnly).radio.lr = true;
    rig.net.node(lrOnly).radio.bcast = PhyRate::LR500K;
    rig.net.node(lrOnly).radio.unicastDefault = PhyRate::LR500K;
    // Frames from a never reach "deaf" above 11 dBm.
    rig.net.linkModel = [a, deaf](size_t from, size_t to, PhyRate, float power) {
        return from == a && to == deaf && power > 11.01f ? 1.0 : 0.0;
    };
    rig.startDiscovery();
    // Some non-NowTP ESP-NOW traffic during the scan.
    Mac foreign = {{0x02, 0xEE, 0, 0, 0, 1}};
    rig.net.tickers.push_back([&rig, a, foreign](uint32_t now) {
        if (now % 500 == 0) rig.net.inject(a, foreign, std::vector<uint8_t>{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC});
    });

    DeepDiscoveryOptions opt;
    opt.channels = {1, 6, 11};
    DeepDiscoveryReport report;
    CHECK(rig.diag[a]->deepDiscover(opt, report) == Status::Ok);
    CHECK_EQ(report.homeChannel, 1);

    auto node = [&](size_t i) -> const DiscoveredNode* {
        for (const DiscoveredNode& n : report.nodes) {
            if (n.mac == rig.net.mac(i)) return &n;
        }
        return nullptr;
    };
    CHECK(node(sameChan) && node(sameChan)->compatible && node(sameChan)->hearsUs);
    CHECK(node(sameChan)->name == "good");
    CHECK(node(otherChan) && node(otherChan)->channel == 6 && !node(otherChan)->compatible);
    CHECK(node(otherNet) && node(otherNet)->networkId == 7 && !node(otherNet)->compatible);
    CHECK(node(lrOnly) && node(lrOnly)->longRangeOnly);
    CHECK(node(v1) && node(v1)->maxFrameSize == 250);
    CHECK(node(deaf) && node(deaf)->hearsUs && node(deaf)->hearsUsAtDbm <= 11.0f);
    CHECK(DiagRig::has(report.issues, IssueKind::OtherChannel));
    CHECK(DiagRig::has(report.issues, IssueKind::OtherNetworkId));
    CHECK(DiagRig::has(report.issues, IssueKind::LongRangeOnly));
    CHECK(DiagRig::has(report.issues, IssueKind::SmallFramesOnly));
    CHECK(DiagRig::has(report.issues, IssueKind::HearsUsOnlyAtLowerPower));
    CHECK(DiagRig::has(report.issues, IssueKind::ForeignTraffic));
    // Everything is restored.
    CHECK_EQ(rig.net.node(a).radio.chan, 1);
    CHECK(!rig.net.node(a).radio.lr);
    CHECK(rig.net.node(a).radio.power == 20.0f);
}

TEST(deep_discovery_channel_locked) {
    DiagRig rig;
    size_t a = rig.add(), b = rig.add();
    rig.net.node(b).radio.chan = 6;
    rig.net.node(a).radio.channelLocked = true;
    rig.startDiscovery();
    DeepDiscoveryOptions opt;
    opt.channels = {1, 6};
    opt.checkLongRange = false;
    DeepDiscoveryReport report;
    CHECK(rig.diag[a]->deepDiscover(opt, report) == Status::Ok);
    CHECK(DiagRig::has(report.issues, IssueKind::ChannelScanUnavailable));
    CHECK(report.nodes.empty());
}

TEST(diag_rejects_oversized_burst_requests) {
    DiagRig rig;
    size_t a = rig.add();
    Mac src = {{0x02, 9, 9, 9, 9, 9}};
    // 64 steps x 100 frames: far above maxBurstFrames.
    std::vector<uint8_t> payload = {4, 1, 0, 0, 100, 64};
    for (int i = 0; i < 64; ++i) {
        payload.push_back(static_cast<uint8_t>(PhyRate::B1M));
        payload.push_back(80);
    }
    wire::Header h;
    h.port = kDiagnosticsPort;
    std::vector<uint8_t> f(wire::kCommonHeaderSize);
    wire::encodeHeader(h, f.data());
    f.insert(f.end(), payload.begin(), payload.end());
    size_t before = rig.net.log.size();
    rig.net.inject(a, src, f);
    rig.net.run(500);
    CHECK_EQ(rig.net.log.size(), before);  // no reply, no burst
}

TEST(diag_random_payloads_do_not_crash) {
    DiagRig rig;
    DiagnosticsConfig tunable;
    tunable.acceptRemoteTuning = true;
    size_t a = rig.add("", Config(), 1470, tunable);
    std::mt19937 rng(77);
    for (int i = 0; i < 20000; ++i) {
        std::vector<uint8_t> payload(rng() % 140);
        for (auto& x : payload) x = static_cast<uint8_t>(rng());
        if (!payload.empty()) payload[0] = static_cast<uint8_t>(1 + rng() % 10);
        wire::Header h;
        h.port = kDiagnosticsPort;
        h.messageId = static_cast<uint16_t>(i);
        std::vector<uint8_t> f(wire::kCommonHeaderSize);
        wire::encodeHeader(h, f.data());
        f.insert(f.end(), payload.begin(), payload.end());
        Mac src = {{0x02, 1, 1, 1, 1, static_cast<uint8_t>(rng() % 3)}};
        rig.net.inject(a, src, f);
        if (i % 20 == 0) rig.net.step();
    }
    rig.net.run(35000);  // any started burst finishes or times out
    // Random "apply" requests may legitimately tune power; it must stay valid.
    CHECK(rig.net.node(a).radio.power >= 2.0f && rig.net.node(a).radio.power <= 20.0f);
    CHECK(rig.net.node(a).radio.bcast == PhyRate::Default);
}

TEST(diag_remote_tuning_is_refused_by_default) {
    DiagRig rig;
    size_t a = rig.add(), b = rig.add();
    rig.net.linkModel = weakSupply(b);  // optimize() would lower b's power
    LinkProfile p;
    CHECK(rig.diag[a]->optimize(rig.net.mac(b), OptimizeOptions(), p) == Status::Ok);
    CHECK(!p.applied);
    CHECK(rig.net.node(b).radio.peerRate(rig.net.mac(a)) == PhyRate::Default);
    CHECK(rig.net.node(b).radio.power == 20.0f);
}

TEST(diag_remote_tuning_requires_authentication_with_a_key) {
    DiagRig rig;
    DiagnosticsConfig tunable;
    tunable.acceptRemoteTuning = true;
    size_t a = rig.add("", Config(), 1470, tunable);
    Mac src = {{0x02, 9, 9, 9, 9, 9}};

    // Without a key, an opted-in node accepts the request.
    injectApply(rig.net, a, src);
    CHECK(rig.net.node(a).radio.power == 5.0f);
    CHECK(rig.net.node(a).radio.peerRate(src) == PhyRate::B1M);

    // With a key, even in optional mode (plain messages delivered), it must be authenticated.
    rig.net.node(a).radio.power = 20.0f;
    SecurityConfig sc;
    sc.key = std::vector<uint8_t>(32, 0x42);
    sc.requireAuthentication = false;
    Security sec(rig.net.engine(a), rig.host, rig.net.mac(a), sc);
    sec.start();
    Mac other = {{0x02, 9, 9, 9, 9, 8}};
    size_t before = rig.net.log.size();
    injectApply(rig.net, a, other);
    CHECK(rig.net.node(a).radio.power == 20.0f);
    CHECK(rig.net.node(a).radio.peerRate(other) == PhyRate::Default);

    // Nor does an unauthenticated burst request start a burst.
    std::vector<uint8_t> payload = {4, 2, 0, 0, 5, 1, static_cast<uint8_t>(PhyRate::B1M), 80};
    wire::Header h;
    h.port = kDiagnosticsPort;
    std::vector<uint8_t> f(wire::kCommonHeaderSize);
    wire::encodeHeader(h, f.data());
    f.insert(f.end(), payload.begin(), payload.end());
    rig.net.inject(a, other, f);
    rig.net.run(500);
    CHECK_EQ(rig.net.log.size(), before);  // no reply, no burst
    sec.stop();
}
