// Host-side tests for the NowTP protocol engine.
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "nowtp/diagnostics.h"
#include "nowtp/discovery.h"
#include "nowtp/engine.h"
#include "nowtp/wire.h"
#include "sim.h"

using namespace nowtp;

// ---------------------------------------------------------------------------
// Minimal test harness

namespace {

struct TestCase {
    const char* name;
    void (*fn)();
};

std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}

struct Registrar {
    Registrar(const char* name, void (*fn)()) { registry().push_back(TestCase{name, fn}); }
};

int g_failures = 0;
bool g_currentFailed = false;

}  // namespace

#define TEST(name)                                   \
    static void name();                              \
    static Registrar registrar_##name(#name, name); \
    static void name()

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::printf("    %s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond); \
            g_currentFailed = true;                                              \
            return;                                                              \
        }                                                                        \
    } while (0)

#define CHECK_EQ(a, b)                                                                       \
    do {                                                                                     \
        auto va = (a);                                                                       \
        auto vb = (b);                                                                       \
        if (!(va == vb)) {                                                                   \
            std::printf("    %s:%d: CHECK_EQ(%s, %s) failed: %lld vs %lld\n", __FILE__, __LINE__, #a, #b, \
                        (long long)va, (long long)vb);                                       \
            g_currentFailed = true;                                                          \
            return;                                                                          \
        }                                                                                    \
    } while (0)

// ---------------------------------------------------------------------------
// Helpers

namespace {

std::vector<uint8_t> pattern(size_t n, uint32_t seed = 7) {
    std::vector<uint8_t> v(n);
    std::mt19937 rng(seed);
    for (auto& b : v) b = static_cast<uint8_t>(rng());
    return v;
}

struct Inbox {
    std::vector<std::vector<uint8_t>> messages;
    std::vector<Message> meta;

    ReceiveHandler handler() {
        return [this](const Message& m) {
            messages.emplace_back(m.data, m.data + m.len);
            meta.push_back(m);
            meta.back().data = nullptr;
        };
    }
};

struct Outcome {
    bool done = false;
    Status status = Status::Ok;

    CompletionHandler handler() {
        return [this](Status s) {
            done = true;
            status = s;
        };
    }
};

SendOptions reliable() {
    SendOptions o;
    o.reliable = true;
    return o;
}

SendOptions latest() {
    SendOptions o;
    o.latestOnly = true;
    return o;
}

std::vector<uint8_t> fragmentFrame(uint8_t flags, uint8_t port, uint16_t id, uint16_t index, uint16_t count,
                                   const std::vector<uint8_t>& payload) {
    wire::Header h;
    h.type = wire::Type::Fragment;
    h.flags = flags;
    h.port = port;
    h.messageId = id;
    h.index = index;
    h.count = count;
    std::vector<uint8_t> f(wire::kFragmentHeaderSize);
    wire::encodeHeader(h, f.data());
    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}

// Splits `msg` into the frames a sender with the given mtu would produce.
std::vector<std::vector<uint8_t>> fragmentsOf(const std::vector<uint8_t>& msg, uint8_t flags, uint8_t port,
                                              uint16_t id, size_t mtu = 250) {
    std::vector<uint8_t> stream = msg;
    stream.resize(msg.size() + 4);
    wire::putU32(stream.data() + msg.size(), wire::crc32(msg.data(), msg.size()));
    size_t frag = mtu - wire::kFragmentHeaderSize;
    uint16_t count = static_cast<uint16_t>((stream.size() + frag - 1) / frag);
    std::vector<std::vector<uint8_t>> out;
    for (uint16_t i = 0; i < count; ++i) {
        size_t start = i * frag;
        size_t n = std::min(frag, stream.size() - start);
        std::vector<uint8_t> p(stream.begin() + start, stream.begin() + start + n);
        out.push_back(fragmentFrame(flags, port, id, i, count, p));
    }
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// Wire format

TEST(crc32_matches_reference) {
    const char* s = "123456789";
    CHECK_EQ(wire::crc32(reinterpret_cast<const uint8_t*>(s), 9), 0xCBF43926u);
    uint32_t part = wire::crc32(reinterpret_cast<const uint8_t*>(s), 4);
    CHECK_EQ(wire::crc32(reinterpret_cast<const uint8_t*>(s) + 4, 5, part), 0xCBF43926u);
}

TEST(header_roundtrip) {
    wire::Header h;
    h.type = wire::Type::Fragment;
    h.flags = wire::kFlagReliable | wire::kFlagAckRequest;
    h.networkId = 0x5A;
    h.port = 200;
    h.messageId = 0xBEEF;
    h.index = 513;
    h.count = 1024;
    uint8_t buf[16];
    CHECK_EQ(wire::encodeHeader(h, buf), wire::kFragmentHeaderSize);
    wire::Header d;
    size_t off = 0;
    CHECK(wire::decodeHeader(buf, sizeof(buf), d, off));
    CHECK_EQ(off, wire::kFragmentHeaderSize);
    CHECK(d.type == wire::Type::Fragment);
    CHECK_EQ(d.flags, h.flags);
    CHECK_EQ(d.networkId, 0x5A);
    CHECK_EQ(d.port, 200);
    CHECK_EQ(d.messageId, 0xBEEF);
    CHECK_EQ(d.index, 513);
    CHECK_EQ(d.count, 1024);
}

TEST(header_rejects_malformed) {
    wire::Header d;
    size_t off;
    uint8_t shortFrame[4] = {0x40, 0, 0, 0};
    CHECK(!wire::decodeHeader(shortFrame, sizeof(shortFrame), d, off));
    uint8_t badVersion[5] = {0x80, 0, 0, 0, 0};
    CHECK(!wire::decodeHeader(badVersion, sizeof(badVersion), d, off));
    uint8_t badType[5] = {0x70, 0, 0, 0, 0};
    CHECK(!wire::decodeHeader(badType, sizeof(badType), d, off));
    uint8_t truncatedFragment[6] = {0x50, 0, 0, 0, 0, 0};
    CHECK(!wire::decodeHeader(truncatedFragment, sizeof(truncatedFragment), d, off));
    uint8_t indexPastCount[9] = {0x50, 0, 0, 0, 0, 5, 0, 5, 0};
    CHECK(!wire::decodeHeader(indexPastCount, sizeof(indexPastCount), d, off));
    uint8_t countOne[9] = {0x50, 0, 0, 0, 0, 0, 0, 1, 0};
    CHECK(!wire::decodeHeader(countOne, sizeof(countOne), d, off));
}

// ---------------------------------------------------------------------------
// Unreliable delivery

TEST(small_unicast_uses_single_frame) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    Outcome out;
    auto msg = pattern(40);
    CHECK(net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), SendOptions(), out.handler(), net.now()) ==
          Status::Ok);
    CHECK(net.runUntil([&] { return out.done && inbox.messages.size() == 1; }));
    CHECK(out.status == Status::Ok);
    CHECK(inbox.messages[0] == msg);
    CHECK(inbox.meta[0].src == net.mac(a));
    CHECK_EQ(inbox.meta[0].port, 1);
    CHECK_EQ(net.log.size(), 1u);
    CHECK_EQ(net.log[0].data.size(), msg.size() + wire::kCommonHeaderSize);
}

TEST(empty_message) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    Inbox inbox;
    net.engine(b).listen(3, inbox.handler());
    CHECK(net.engine(a).send(net.mac(b), 3, nullptr, 0, SendOptions(), nullptr, net.now()) == Status::Ok);
    CHECK(net.runUntil([&] { return inbox.messages.size() == 1; }));
    CHECK(inbox.messages[0].empty());
}

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

TEST(large_message_is_fragmented_and_reassembled) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    auto msg = pattern(10000);
    Outcome out;
    CHECK(net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), SendOptions(), out.handler(), net.now()) ==
          Status::Ok);
    CHECK(net.runUntil([&] { return out.done && inbox.messages.size() == 1; }));
    CHECK(out.status == Status::Ok);
    CHECK(inbox.messages[0] == msg);
    size_t frag = 250 - wire::kFragmentHeaderSize;
    CHECK_EQ(net.log.size(), (msg.size() + 4 + frag - 1) / frag);
}

TEST(boundary_sizes_roundtrip) {
    // Sizes around the single-frame limit and where the CRC spills into a new fragment.
    const size_t single = 250 - wire::kCommonHeaderSize;
    const size_t frag = 250 - wire::kFragmentHeaderSize;
    const size_t sizes[] = {single - 1, single, single + 1, 2 * frag - 4, 2 * frag - 3, 2 * frag, 2 * frag + 1};
    for (size_t n : sizes) {
        sim::Network net;
        size_t a = net.addNode(), b = net.addNode();
        Inbox inbox;
        net.engine(b).listen(1, inbox.handler());
        auto msg = pattern(n, static_cast<uint32_t>(n));
        CHECK(net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), SendOptions(), nullptr, net.now()) ==
              Status::Ok);
        CHECK(net.runUntil([&] { return inbox.messages.size() == 1; }));
        CHECK(inbox.messages[0] == msg);
    }
}

TEST(lost_fragment_drops_message_without_garbage) {
    sim::Network net;
    Config cfg;
    cfg.rxTimeoutMs = 50;
    size_t a = net.addNode(cfg), b = net.addNode(cfg);
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    int seen = 0;
    net.dropIf = [&](const sim::Frame&) { return ++seen == 3; };  // lose a middle fragment
    auto msg = pattern(2000);
    CHECK(net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), SendOptions(), nullptr, net.now()) ==
          Status::Ok);
    net.run(200);
    CHECK(inbox.messages.empty());
    CHECK_EQ(net.engine(b).stats().messagesDropped, 1u);

    // The slot was released: the next message gets through.
    net.dropIf = nullptr;
    CHECK(net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), SendOptions(), nullptr, net.now()) ==
          Status::Ok);
    CHECK(net.runUntil([&] { return inbox.messages.size() == 1; }));
    CHECK(inbox.messages[0] == msg);
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

TEST(lost_mac_ack_does_not_duplicate_messages) {
    sim::Network net(5);
    net.macAckLoss = 0.4;
    Config cfg;
    cfg.frameRetries = 6;
    size_t a = net.addNode(cfg), b = net.addNode(cfg);
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    std::vector<std::vector<uint8_t>> expected;
    for (uint32_t i = 0; i < 100; ++i) {
        auto msg = pattern(i % 2 ? 30 : 600, i);  // single-frame and fragmented
        Outcome out;
        net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), SendOptions(), out.handler(), net.now());
        CHECK(net.runUntil([&] { return out.done; }));
        if (out.status == Status::Ok) expected.push_back(msg);
    }
    net.run(50);
    CHECK(net.engine(a).stats().framesFailed > 10u);
    // Every delivered message arrives once; a message reported failed may still have arrived.
    CHECK(inbox.messages.size() >= expected.size());
    CHECK(inbox.messages.size() <= 100u);
    for (size_t i = 1; i < inbox.messages.size(); ++i) CHECK(inbox.messages[i] != inbox.messages[i - 1]);
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

// ---------------------------------------------------------------------------
// Reliable delivery

TEST(reliable_rejects_broadcast) {
    sim::Network net;
    size_t a = net.addNode();
    uint8_t x = 1;
    CHECK(net.engine(a).send(Mac::broadcast(), 1, &x, 1, reliable(), nullptr, net.now()) ==
          Status::InvalidArgument);
}

TEST(reliable_single_frame_acknowledged) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    Outcome out;
    auto msg = pattern(20);
    net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), reliable(), out.handler(), net.now());
    CHECK(net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Ok);
    CHECK_EQ(inbox.messages.size(), 1u);
    CHECK(inbox.meta[0].reliable);
}

TEST(reliable_recovers_from_receiver_side_loss) {
    for (uint32_t seed = 1; seed <= 20; ++seed) {
        sim::Network net(seed);
        net.appLoss = 0.25;
        size_t a = net.addNode(), b = net.addNode();
        Inbox inbox;
        net.engine(b).listen(1, inbox.handler());
        Outcome out;
        auto msg = pattern(8000, seed);
        net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), reliable(), out.handler(), net.now());
        CHECK(net.runUntil([&] { return out.done; }));
        CHECK(out.status == Status::Ok);
        net.run(300);  // let any straggling retransmissions settle
        CHECK_EQ(inbox.messages.size(), 1u);
        CHECK(inbox.messages[0] == msg);
    }
}

TEST(reliable_recovers_from_air_loss) {
    sim::Network net(3);
    net.airLoss = 0.2;
    net.appLoss = 0.1;
    Config cfg;
    cfg.frameRetries = 4;
    size_t a = net.addNode(cfg), b = net.addNode(cfg);
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    int ok = 0;
    for (int i = 0; i < 20; ++i) {
        Outcome out;
        auto msg = pattern(1500, static_cast<uint32_t>(i));
        net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), reliable(), out.handler(), net.now());
        CHECK(net.runUntil([&] { return out.done; }));
        if (out.status == Status::Ok) ok++;
    }
    net.run(300);
    CHECK_EQ(ok, 20);
    CHECK_EQ(inbox.messages.size(), 20u);
}

TEST(reliable_duplicate_suppressed_when_ack_lost) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    // Drop the first ack the receiver sends.
    bool dropped = false;
    net.dropIf = [&](const sim::Frame& f) {
        wire::Header h;
        size_t off;
        if (!dropped && f.from == b && wire::decodeHeader(f.data.data(), f.data.size(), h, off) &&
            h.type == wire::Type::Ack) {
            dropped = true;
            return true;
        }
        return false;
    };
    Outcome out;
    auto msg = pattern(700);
    net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), reliable(), out.handler(), net.now());
    CHECK(net.runUntil([&] { return out.done; }));
    CHECK(dropped);
    CHECK(out.status == Status::Ok);
    CHECK_EQ(inbox.messages.size(), 1u);
    CHECK(net.engine(a).stats().retransmissions >= 1);
}

TEST(reliable_no_listener_is_rejected) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    Outcome out;
    auto msg = pattern(3000);
    net.engine(a).send(net.mac(b), 5, msg.data(), msg.size(), reliable(), out.handler(), net.now());
    CHECK(net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Rejected);
}

TEST(reliable_too_large_for_receiver_is_rejected) {
    sim::Network net;
    Config small;
    small.maxMessageSize = 1000;
    size_t a = net.addNode(), b = net.addNode(small);
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    Outcome out;
    auto msg = pattern(4000);
    net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), reliable(), out.handler(), net.now());
    CHECK(net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Rejected);
    CHECK(inbox.messages.empty());
}

TEST(reliable_silent_receiver_times_out) {
    sim::Network net;
    net.appLoss = 1.0;  // MAC acks succeed, nothing reaches the receiver's engine
    size_t a = net.addNode(), b = net.addNode();
    Outcome out;
    SendOptions o = reliable();
    o.timeoutMs = 500;
    auto msg = pattern(100);
    net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), o, out.handler(), net.now());
    CHECK(net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Timeout);
    CHECK(net.now() >= 500u);
}

TEST(reliable_does_not_block_other_messages) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode(), c = net.addNode();
    net.node(b).online = true;
    Inbox ic;
    net.engine(c).listen(1, ic.handler());
    // b has no listener on port 1 and never answers because frames to it are dropped by the app.
    net.dropIf = [&](const sim::Frame& f) { return f.dst == net.mac(b); };
    Outcome slow, fast;
    auto msg = pattern(100);
    SendOptions o = reliable();
    o.timeoutMs = 1000;
    net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), o, slow.handler(), net.now());
    net.engine(a).send(net.mac(c), 1, msg.data(), msg.size(), SendOptions(), fast.handler(), net.now());
    CHECK(net.runUntil([&] { return fast.done; }, 50));
    CHECK(!slow.done);
    CHECK_EQ(ic.messages.size(), 1u);
}

// ---------------------------------------------------------------------------
// Latest-only

TEST(latest_only_supersedes_queued_messages) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    std::vector<Outcome> outs(5);
    for (size_t i = 0; i < outs.size(); ++i) {
        auto msg = pattern(1000, static_cast<uint32_t>(i));
        CHECK(net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), latest(), outs[i].handler(), net.now()) ==
              Status::Ok);
    }
    for (size_t i = 0; i + 1 < outs.size(); ++i) {
        CHECK(outs[i].done);
        CHECK(outs[i].status == Status::Superseded);
    }
    CHECK(net.runUntil([&] { return outs.back().done; }));
    CHECK(outs.back().status == Status::Ok);
    net.run(20);
    CHECK_EQ(inbox.messages.size(), 1u);
    CHECK(inbox.messages[0] == pattern(1000, 4));
}

TEST(latest_only_never_fills_queue) {
    sim::Network net;
    Config cfg;
    cfg.maxTxMessages = 2;
    size_t a = net.addNode(cfg), b = net.addNode(cfg);
    auto msg = pattern(500);
    for (int i = 0; i < 50; ++i) {
        CHECK(net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), latest(), nullptr, net.now()) ==
              Status::Ok);
    }
}

TEST(receiver_drops_older_partial_latest_message) {
    sim::Network net;
    size_t b = net.addNode();
    Mac src = {{0x02, 9, 9, 9, 9, 9}};
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    auto oldMsg = pattern(1000, 1), newMsg = pattern(1000, 2);
    auto oldFrames = fragmentsOf(oldMsg, wire::kFlagLatest, 1, 10);
    auto newFrames = fragmentsOf(newMsg, wire::kFlagLatest, 1, 11);
    net.inject(b, src, oldFrames[0]);
    net.inject(b, src, oldFrames[1]);
    for (auto& f : newFrames) net.inject(b, src, f);
    // Late fragments of the superseded message must not resurrect it.
    for (size_t i = 2; i < oldFrames.size(); ++i) net.inject(b, src, oldFrames[i]);
    net.inject(b, src, oldFrames[0]);
    net.inject(b, src, oldFrames[1]);
    CHECK_EQ(inbox.messages.size(), 1u);
    CHECK(inbox.messages[0] == newMsg);
}

// ---------------------------------------------------------------------------
// Robustness

TEST(out_of_order_fragments_reassemble) {
    sim::Network net;
    size_t b = net.addNode();
    Mac src = {{0x02, 9, 9, 9, 9, 9}};
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    auto msg = pattern(1500);
    auto frames = fragmentsOf(msg, 0, 1, 77);
    // Last fragment first exercises the stash path (fragment size not known yet).
    for (size_t i = frames.size(); i-- > 0;) net.inject(b, src, frames[i]);
    CHECK_EQ(inbox.messages.size(), 1u);
    CHECK(inbox.messages[0] == msg);
}

TEST(corrupted_message_fails_crc) {
    sim::Network net;
    size_t b = net.addNode();
    Mac src = {{0x02, 9, 9, 9, 9, 9}};
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    auto frames = fragmentsOf(pattern(800), 0, 1, 5);
    frames[1][20] ^= 0x01;
    for (auto& f : frames) net.inject(b, src, f);
    CHECK(inbox.messages.empty());
    CHECK_EQ(net.engine(b).stats().messagesDropped, 1u);
}

TEST(inconsistent_fragment_sizes_are_rejected) {
    sim::Network net;
    size_t b = net.addNode();
    Mac src = {{0x02, 9, 9, 9, 9, 9}};
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    net.inject(b, src, fragmentFrame(0, 1, 1, 0, 3, pattern(100)));
    net.inject(b, src, fragmentFrame(0, 1, 1, 1, 3, pattern(120)));  // wrong size
    net.inject(b, src, fragmentFrame(0, 1, 1, 2, 3, pattern(10)));
    CHECK(inbox.messages.empty());
    // Last fragment longer than the others.
    net.inject(b, src, fragmentFrame(0, 1, 2, 0, 2, pattern(100)));
    net.inject(b, src, fragmentFrame(0, 1, 2, 1, 2, pattern(101)));
    CHECK(inbox.messages.empty());
    CHECK(net.engine(b).stats().framesInvalid >= 2u);
}

TEST(oversized_fragment_count_is_refused) {
    sim::Network net;
    Config cfg;
    cfg.maxMessageSize = 2000;
    size_t b = net.addNode(cfg);
    Mac src = {{0x02, 9, 9, 9, 9, 9}};
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    net.inject(b, src, fragmentFrame(0, 1, 1, 0, 60000, pattern(241)));
    net.inject(b, src, fragmentFrame(0, 1, 2, 0, 20, pattern(241)));  // 20 * 241 > 2000
    CHECK(inbox.messages.empty());
    CHECK_EQ(net.engine(b).stats().messagesDropped, 2u);
}

TEST(reassembly_memory_is_bounded) {
    sim::Network net;
    Config cfg;
    cfg.maxRxMessages = 2;
    cfg.maxRxBytes = 4000;
    size_t b = net.addNode(cfg);
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    // Many senders each start a message and never finish it.
    for (uint8_t s = 0; s < 20; ++s) {
        Mac src = {{0x02, 8, 8, 8, 8, s}};
        auto frames = fragmentsOf(pattern(3000, s), 0, 1, 1);
        net.inject(b, src, frames[0]);
    }
    // A complete message still gets through.
    Mac src = {{0x02, 7, 7, 7, 7, 7}};
    auto msg = pattern(1500, 99);
    for (auto& f : fragmentsOf(msg, 0, 1, 1)) net.inject(b, src, f);
    CHECK_EQ(inbox.messages.size(), 1u);
    CHECK(inbox.messages[0] == msg);
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

// ---------------------------------------------------------------------------
// API behavior

TEST(send_validates_arguments) {
    sim::Network net;
    Config cfg;
    cfg.maxMessageSize = 1000;
    cfg.maxTxMessages = 2;
    size_t a = net.addNode(cfg), b = net.addNode(cfg);
    auto big = pattern(1001);
    CHECK(net.engine(a).send(net.mac(b), 1, big.data(), big.size(), SendOptions(), nullptr, net.now()) ==
          Status::TooLarge);
    CHECK(net.engine(a).send(net.mac(b), 1, nullptr, 10, SendOptions(), nullptr, net.now()) ==
          Status::InvalidArgument);
    auto msg = pattern(10);
    CHECK(net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), SendOptions(), nullptr, net.now()) == Status::Ok);
    CHECK(net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), SendOptions(), nullptr, net.now()) == Status::Ok);
    CHECK(net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), SendOptions(), nullptr, net.now()) ==
          Status::QueueFull);
}

TEST(handlers_can_reenter_engine) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    Inbox replies;
    net.engine(a).listen(2, replies.handler());
    // b echoes everything back from inside its receive handler.
    net.engine(b).listen(1, [&](const Message& m) {
        net.engine(b).send(m.src, 2, m.data, m.len, reliable(), nullptr, net.now());
    });
    int chained = 0;
    std::function<void(Status)> next = [&](Status s) {
        if (s != Status::Ok || ++chained >= 5) return;
        auto msg = pattern(600, static_cast<uint32_t>(chained));
        net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), reliable(), next, net.now());
    };
    auto first = pattern(600, 0);
    net.engine(a).send(net.mac(b), 1, first.data(), first.size(), reliable(), next, net.now());
    CHECK(net.runUntil([&] { return replies.messages.size() == 5; }));
    for (int i = 0; i < 5; ++i) CHECK(replies.messages[i] == pattern(600, static_cast<uint32_t>(i)));
}

TEST(cancel_all_completes_everything) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    net.node(b).online = true;
    Outcome o1, o2;
    auto msg = pattern(3000);
    net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), reliable(), o1.handler(), net.now());
    net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), SendOptions(), o2.handler(), net.now());
    net.engine(a).cancelAll();
    CHECK(o1.done && o1.status == Status::Cancelled);
    CHECK(o2.done && o2.status == Status::Cancelled);
    CHECK_EQ(net.engine(a).pendingMessages(), 0u);
    net.run(10);  // the frame that was in flight completes harmlessly
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

// ---------------------------------------------------------------------------
// Discovery

namespace {

struct DiscoveryRig {
    sim::Network net;
    std::vector<std::unique_ptr<Discovery>> nodes;
    std::vector<std::vector<std::pair<PeerEvent, PeerInfo>>> events;
    std::mt19937 rng{99};

    size_t add(const std::string& name, DiscoveryConfig cfg = DiscoveryConfig(), uint16_t maxFrame = 250) {
        size_t i = net.addNode();
        cfg.name = name;
        nodes.emplace_back(new Discovery(net.engine(i), cfg, maxFrame, [this] { return static_cast<uint32_t>(rng()); }));
        events.emplace_back();
        nodes.back()->onPeerEvent([this, i](PeerEvent e, const PeerInfo& p) { events[i].push_back(std::make_pair(e, p)); });
        return i;
    }
    void run(uint32_t ms) {
        for (uint32_t t = 0; t < ms; ++t) {
            net.step();
            for (auto& d : nodes) d->tick(net.now());
        }
    }
    size_t count(size_t node, PeerEvent e) const {
        size_t n = 0;
        for (const auto& ev : events[node]) n += ev.first == e;
        return n;
    }
};

}  // namespace

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

// ---------------------------------------------------------------------------
// Diagnostics

namespace {

struct DiagRig {
    sim::Network net{11};
    sim::SimHost host{net};
    std::vector<std::unique_ptr<Diagnostics>> diag;
    std::vector<std::unique_ptr<Discovery>> disc;

    size_t add(const std::string& name = "", Config cfg = Config(), uint16_t maxFrame = 1470,
               DiagnosticsConfig dc = DiagnosticsConfig()) {
        size_t i = net.addNode(cfg);
        diag.emplace_back(new Diagnostics(net.engine(i), net.node(i).radio, host, dc));
        diag.back()->start();
        DiscoveryConfig dcfg;
        dcfg.name = name.empty() ? "n" + std::to_string(i) : name;
        disc.emplace_back(new Discovery(net.engine(i), dcfg, maxFrame, [this] { return static_cast<uint32_t>(net.rng()()); }));
        diag.back()->setDiscovery(disc.back().get());
        Diagnostics* d = diag.back().get();
        Discovery* ds = disc.back().get();
        net.tickers.push_back([d, ds](uint32_t now) {
            d->tick(now);
            ds->tick(now);
        });
        return i;
    }
    void startDiscovery() {
        for (auto& d : disc) d->start(net.now());
        net.run(200);
    }
    static bool has(const std::vector<Issue>& issues, IssueKind kind, bool local) {
        for (const Issue& i : issues) {
            if (i.kind == kind && i.local == local) return true;
        }
        return false;
    }
    static bool has(const std::vector<Issue>& issues, IssueKind kind) {
        return has(issues, kind, true) || has(issues, kind, false);
    }
};

// A board whose supply sags: nothing above 17 dBm, no OFDM above 13 dBm.
sim::LinkModel weakSupply(size_t board) {
    return [board](size_t from, size_t, PhyRate rate, float power) {
        if (from != board) return 0.0;
        if (power > 17.01f) return 1.0;
        if (isOfdm(rate) && power > 13.01f) return 1.0;
        return 0.0;
    };
}

}  // namespace

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
    size_t a = rig.add(), b = rig.add();
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
    size_t a = rig.add(), b = rig.add();
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
    size_t a = rig.add();
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

TEST(diag_remote_tuning_can_be_refused) {
    DiagRig rig;
    DiagnosticsConfig strict;
    strict.acceptRemoteTuning = false;
    size_t a = rig.add(), b = rig.add("", Config(), 1470, strict);
    LinkProfile p;
    CHECK(rig.diag[a]->optimize(rig.net.mac(b), OptimizeOptions(), p) == Status::Ok);
    CHECK(!p.applied);
    CHECK(rig.net.node(b).radio.peerRate(rig.net.mac(a)) == PhyRate::Default);
}

// ---------------------------------------------------------------------------

int main(int argc, char** argv) {
    const char* filter = argc > 1 ? argv[1] : nullptr;
    int run = 0;
    for (const TestCase& t : registry()) {
        if (filter && std::strstr(t.name, filter) == nullptr) continue;
        g_currentFailed = false;
        t.fn();
        run++;
        std::printf("[%s] %s\n", g_currentFailed ? "FAIL" : " OK ", t.name);
        if (g_currentFailed) g_failures++;
    }
    std::printf("\n%d tests, %d failed\n", run, g_failures);
    return g_failures == 0 ? 0 : 1;
}
