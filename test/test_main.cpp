// Host-side tests for the NowTP protocol engine.
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

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
