// Host-side tests for the NowTP protocol engine.
#include <dlfcn.h>
#include <execinfo.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

// Before sim.h, which includes the declarations.
#define NOWTP_HEAP_LIMIT_IMPLEMENTATION
#include "heap_limit.h"

#include "nowtp/channel.h"
#include "nowtp/crypto.h"
#include "nowtp/diagnostics.h"
#include "nowtp/discovery.h"
#include "nowtp/engine.h"
#include "nowtp/peer_table.h"
#include "nowtp/security.h"
#include "nowtp/send_tracker.h"
#include "nowtp/stream.h"
#include "nowtp/table.h"
#include "nowtp/timesync.h"
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
            testing::HeapExempt app;  // the application's memory
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

TEST(handler_can_take_reassembled_buffer) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    std::vector<std::pair<uint8_t*, size_t>> kept;
    const uint8_t* singleBuffer = reinterpret_cast<const uint8_t*>(1);
    net.engine(b).listen(1, [&](const Message& m) {
        if (!m.buffer) {
            singleBuffer = m.buffer;
            return;
        }
        CHECK(m.data == m.buffer);
        kept.push_back(std::make_pair(m.buffer, m.len));
        m.buffer = nullptr;
    });
    auto big = pattern(5000), small = pattern(40);
    CHECK(net.engine(a).send(net.mac(b), 1, big.data(), big.size(), SendOptions(), nullptr, net.now()) == Status::Ok);
    CHECK(net.engine(a).send(net.mac(b), 1, small.data(), small.size(), SendOptions(), nullptr, net.now()) ==
          Status::Ok);
    CHECK(net.runUntil([&] { return kept.size() == 1 && singleBuffer == nullptr; }));
    // The taken buffer outlives the handler and the engine's later work.
    CHECK(std::vector<uint8_t>(kept[0].first, kept[0].first + kept[0].second) == big);
    std::free(kept[0].first);
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

TEST(send_buffer_takes_ownership) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    for (size_t len : {100u, 3000u}) {
        for (size_t slack : {kSendOverhead, size_t(0)}) {  // in place, then via realloc
            auto msg = pattern(len, static_cast<uint8_t>(len + slack));
            uint8_t* buf = static_cast<uint8_t*>(std::malloc(len + slack));
            std::memcpy(buf, msg.data(), len);
            Outcome out;
            CHECK(net.engine(a).sendBuffer(net.mac(b), 1, buf, len, len + slack, reliable(), out.handler(),
                                           net.now()) == Status::Ok);
            CHECK(net.runUntil([&] { return out.done; }));
            CHECK(out.status == Status::Ok);
            CHECK(inbox.messages.back() == msg);
        }
    }
    // Freed on errors too (ASan reports a leak or double free otherwise).
    uint8_t* big = static_cast<uint8_t*>(std::malloc(net.engine(a).config().maxMessageSize + 1));
    CHECK(net.engine(a).sendBuffer(net.mac(b), 1, big, net.engine(a).config().maxMessageSize + 1,
                                   net.engine(a).config().maxMessageSize + 1, SendOptions(), nullptr,
                                   net.now()) == Status::TooLarge);
    CHECK(net.engine(a).sendBuffer(net.mac(b), 1, nullptr, 0, 0, SendOptions(), nullptr, net.now()) ==
          Status::InvalidArgument);
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

// Many senders at a high rate, with acks lost: a probe for a message whose
// ack was lost arrives after hundreds of other messages, which a ring shared
// by all senders had already forgotten (the message was delivered twice).
TEST(duplicates_suppressed_per_sender_at_high_rate) {
    sim::Network net(3);
    size_t r = net.addNode();
    const size_t kSenders = 8;
    const uint32_t kMessages = 100;
    std::vector<size_t> tx;
    for (size_t i = 0; i < kSenders; ++i) tx.push_back(net.addNode());
    std::vector<int> delivered(kSenders * kMessages, 0);
    net.engine(r).listen(1, [&](const Message& m) {
        uint32_t key;
        std::memcpy(&key, m.data, sizeof(key));
        delivered[key]++;
    });
    std::mt19937 rng(9);
    uint32_t acksDropped = 0;
    net.dropIf = [&](const sim::Frame& f) {
        wire::Header h;
        size_t off;
        if (f.from == r && wire::decodeHeader(f.data.data(), f.data.size(), h, off) && h.type == wire::Type::Ack &&
            rng() % 4 == 0) {
            acksDropped++;
            return true;
        }
        return false;
    };
    std::vector<uint32_t> queued(kSenders, 0), finished(kSenders, 0);
    std::vector<Status> outcome(kSenders * kMessages, Status::Ok);
    auto refill = [&] {
        for (size_t i = 0; i < kSenders; ++i) {
            while (queued[i] < kMessages && queued[i] - finished[i] < 3) {
                uint32_t key = static_cast<uint32_t>(i * kMessages + queued[i]);
                auto msg = pattern(40, key);
                std::memcpy(msg.data(), &key, sizeof(key));
                Status st = net.engine(tx[i]).send(net.mac(r), 1, msg.data(), msg.size(), reliable(),
                                                   [&, i, key](Status s) {
                                                       finished[i]++;
                                                       outcome[key] = s;
                                                   },
                                                   net.now());
                if (st != Status::Ok) break;
                queued[i]++;
            }
        }
    };
    uint32_t t0 = net.now();
    CHECK(net.runUntil(
        [&] {
            refill();
            for (size_t i = 0; i < kSenders; ++i) {
                if (finished[i] < kMessages) return false;
            }
            return true;
        },
        60000));
    net.run(100);
    std::printf("    %u messages in %u ms, %u acks dropped\n", static_cast<unsigned>(kSenders * kMessages),
                net.now() - t0, acksDropped);
    CHECK(acksDropped > 50u);
    for (size_t k = 0; k < delivered.size(); ++k) {
        CHECK(delivered[k] <= 1);
        if (outcome[k] == Status::Ok) CHECK_EQ(delivered[k], 1);
    }
}

TEST(duplicate_window_edges) {
    auto single = [](uint16_t id) {
        wire::Header h;
        h.type = wire::Type::Single;
        h.port = 1;
        h.messageId = id;
        std::vector<uint8_t> f(wire::kCommonHeaderSize);
        wire::encodeHeader(h, f.data());
        f.push_back(static_cast<uint8_t>(id));
        return f;
    };
    sim::Network net;
    Config cfg;
    cfg.recentSenders = 2;
    size_t b = net.addNode(cfg);
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    auto from = [](uint8_t n) { return Mac{{0x06, 0, 0, 0, 0, n}}; };
    auto count = [&] { return inbox.messages.size(); };
    Mac x = from(1);
    for (uint16_t id : {65534, 65535, 0, 1}) net.inject(b, x, single(id));  // across the wrap
    CHECK_EQ(count(), 4u);
    // Push x's ids out of the shared ring: the window still knows them.
    Mac y = from(2);
    for (uint16_t id = 0; id < 40; ++id) net.inject(b, y, single(id));
    CHECK_EQ(count(), 44u);
    for (uint16_t id : {65534, 65535, 0, 1}) net.inject(b, x, single(id));
    CHECK_EQ(count(), 44u);
    // Newer ids move the window; one older than it is taken as new.
    net.inject(b, x, single(200));
    net.inject(b, x, single(65535));
    CHECK_EQ(count(), 46u);
    net.inject(b, x, single(110));  // within the window, not seen
    net.inject(b, x, single(110));
    CHECK_EQ(count(), 47u);
    // A third sender evicts the one heard least recently (y).
    net.run(10);
    net.inject(b, x, single(201));
    net.run(10);
    net.inject(b, from(3), single(5));
    CHECK_EQ(count(), 49u);
    net.inject(b, x, single(201));  // x's window
    net.inject(b, y, single(39));   // the shared ring
    CHECK_EQ(count(), 49u);
    net.inject(b, y, single(0));  // forgotten by both
    CHECK_EQ(count(), 50u);
    // A block's bits expire with recentTtlMs, even while the sender is active.
    sim::Network net2;
    size_t c = net2.addNode();
    Inbox inbox2;
    net2.engine(c).listen(1, inbox2.handler());
    net2.inject(c, x, single(5));
    for (uint16_t id : {40, 70, 100}) {
        net2.run(2000);
        net2.inject(c, x, single(id));
    }
    net2.inject(c, x, single(5));
    CHECK_EQ(inbox2.messages.size(), 5u);
    net2.inject(c, x, single(70));
    CHECK_EQ(inbox2.messages.size(), 5u);
}

// A handler that can't take a message refuses it: the sender is told busy,
// never Ok, and sends it again.
TEST(handler_refusal_makes_the_sender_retry) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    Inbox inbox;
    ReceiveHandler take = inbox.handler();
    int refusals = 0, calls = 0;
    net.engine(b).listen(1, [&](const Message& m) {
        calls++;
        if (refusals > 0) {
            refusals--;
            m.refused = true;
            return;
        }
        take(m);
    });
    for (size_t size : {100, 3000}) {
        inbox.messages.clear();
        calls = 0;
        refusals = 2;
        auto msg = pattern(size, static_cast<uint32_t>(size));
        Outcome out;
        net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), reliable(), out.handler(), net.now());
        CHECK(net.runUntil([&] { return out.done; }));
        CHECK(out.status == Status::Ok);
        CHECK_EQ(calls, 3);
        CHECK_EQ(inbox.messages.size(), 1u);
        CHECK(inbox.messages[0] == msg);
    }
    CHECK_EQ(net.engine(b).stats().messagesRefused, 4u);
    CHECK_EQ(net.engine(b).stats().messagesReceived, 2u);
    CHECK(net.engine(a).stats().receiverBusy >= 4u);

    // Refused until its deadline: the sender times out.
    inbox.messages.clear();
    refusals = 1000;
    auto msg = pattern(100);
    Outcome out;
    net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), reliable(), out.handler(), net.now());
    CHECK(net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Timeout);
    CHECK(inbox.messages.empty());

    // Unreliable: dropped.
    refusals = 1;
    uint32_t refused = net.engine(b).stats().messagesRefused;
    net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), SendOptions(), nullptr, net.now());
    net.run(50);
    CHECK(inbox.messages.empty());
    CHECK_EQ(net.engine(b).stats().messagesRefused, refused + 1);
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
    // Messages in progress are not evicted for a newcomer...
    Mac src = {{0x02, 7, 7, 7, 7, 7}};
    auto msg = pattern(1500, 99);
    for (auto& f : fragmentsOf(msg, 0, 1, 1)) net.inject(b, src, f);
    CHECK(inbox.messages.empty());
    CHECK(net.engine(b).stats().reassemblyRefused >= 1u);
    // ...but abandoned ones are, once idle for a few ack timeouts.
    net.run(3 * cfg.ackTimeoutMs);
    for (auto& f : fragmentsOf(msg, 0, 1, 1)) net.inject(b, src, f);
    CHECK_EQ(inbox.messages.size(), 1u);
    CHECK(inbox.messages[0] == msg);
}

TEST(reassembly_slots_are_shared_between_senders) {
    sim::Network net;
    size_t b = net.addNode();
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    // One sender starts four messages; it gets maxRxMessagesPerSender slots.
    Mac greedy = {{0x02, 8, 8, 8, 8, 8}};
    for (uint16_t id = 1; id <= 4; ++id) net.inject(b, greedy, fragmentsOf(pattern(1000), 0, 1, id)[0]);
    CHECK_EQ(net.engine(b).stats().reassemblyRefused, 2u);
    // Two others still fit.
    for (uint8_t s = 0; s < 2; ++s) {
        Mac src = {{0x02, 7, 7, 7, 7, s}};
        for (auto& f : fragmentsOf(pattern(1000, s), 0, 1, 1)) net.inject(b, src, f);
    }
    CHECK_EQ(inbox.messages.size(), 2u);
}

TEST(reassembly_rejects_what_can_never_fit) {
    sim::Network net;
    Config small;
    small.maxRxBytes = 4000;
    size_t a = net.addNode(), b = net.addNode(small);
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    auto msg = pattern(6000);
    Outcome out;
    net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), reliable(), out.handler(), net.now());
    CHECK(net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Rejected);  // not Busy until the deadline
    CHECK(net.now() < 100u);
}

// More senders than reassembly slots or bytes: evicting the least recently
// active message used to starve all of them (every message timed out).
TEST(reassembly_survives_more_senders_than_slots) {
    struct Case {
        size_t senders;
        size_t bytes;
    };
    for (Case c : {Case{5, 4000}, Case{8, 4000}, Case{3, 12000}, Case{6, 12000}}) {
        sim::Network net;
        size_t r = net.addNode();
        std::vector<size_t> tx;
        for (size_t i = 0; i < c.senders; ++i) tx.push_back(net.addNode());
        Inbox in;
        net.engine(r).listen(1, in.handler());
        std::vector<Outcome> outs(c.senders);
        for (size_t i = 0; i < c.senders; ++i) {
            auto msg = pattern(c.bytes, static_cast<uint8_t>(i));
            net.engine(tx[i]).send(net.mac(r), 1, msg.data(), msg.size(), reliable(), outs[i].handler(), net.now());
        }
        uint32_t t0 = net.now();
        CHECK(net.runUntil([&] {
            for (auto& o : outs) {
                if (!o.done) return false;
            }
            return true;
        }));
        uint32_t retx = 0, busy = 0;
        for (size_t i = 0; i < c.senders; ++i) {
            CHECK(outs[i].status == Status::Ok);
            retx += net.engine(tx[i]).stats().retransmissions;
            busy += net.engine(tx[i]).stats().receiverBusy;
        }
        CHECK_EQ(in.messages.size(), c.senders);
        // Refused senders resend their message once, plus a probe per backoff.
        size_t frames = (c.bytes + 4) / 241 + 1;
        CHECK(retx <= c.senders * frames + 4 * busy);
        CHECK(busy > 0u);
        std::printf("    %zu x %zu B: %u ms, %u retransmissions, %u busy\n", c.senders, c.bytes, net.now() - t0,
                    retx, busy);
    }
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

// The radio's "sent" callback doesn't say which frame it reports.
TEST(send_tracker_matches_callbacks_to_frames) {
    Mac a = {{0x02, 0, 0, 0, 0, 1}}, b = {{0x02, 0, 0, 0, 0, 2}};
    {
        SendTracker t;
        t.sent(a, 0, 0);
        CHECK(!t.reports(0, a));  // nothing new
        CHECK(t.reports(1, a));
        CHECK(!t.reports(1, a));  // once
        t.sent(b, 1, 10);
        CHECK(!t.reports(2, a));  // another destination's
    }
    {
        // The engine gave up on a frame; its late callback isn't the next frame's.
        SendTracker t;
        t.sent(a, 0, 0);
        t.sent(a, 0, 600);
        CHECK(!t.reports(1, a));
        CHECK(t.reports(2, a));
    }
    {
        // A callback that never came stops counting after a while...
        SendTracker t;
        t.sent(a, 0, 0);
        t.sent(b, 0, 3000);
        CHECK(t.reports(1, b));
        // ...and if it comes after all, it isn't taken for the next frame's.
        SendTracker u;
        u.sent(a, 0, 0);
        u.sent(b, 0, 3000);
        CHECK(!u.reports(1, a));
        CHECK(u.reports(2, b));
    }
    {
        SendTracker t;  // a driver that doesn't name the destination
        t.sent(a, 0, 0);
        CHECK(t.reports(1, Mac()));
    }
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

namespace {

// Drops `from`'s frames on kDiscoveryPort: its announcements are lost.
std::function<bool(const sim::Frame&)> dropAnnouncementsFrom(const std::vector<size_t>& nodes) {
    return [nodes](const sim::Frame& f) {
        wire::Header h;
        size_t off;
        return std::find(nodes.begin(), nodes.end(), f.from) != nodes.end() &&
               wire::decodeHeader(f.data.data(), f.data.size(), h, off) && h.port == kDiscoveryPort;
    };
}

}  // namespace

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

// ---------------------------------------------------------------------------
// Crypto

namespace {

std::vector<uint8_t> unhex(const char* s) {
    std::vector<uint8_t> out;
    for (size_t i = 0; s[i] && s[i + 1]; i += 2) {
        unsigned v = 0;
        std::sscanf(s + i, "%2x", &v);
        out.push_back(static_cast<uint8_t>(v));
    }
    return out;
}

bool sameBytes(const uint8_t* a, const std::vector<uint8_t>& b) {
    return std::memcmp(a, b.data(), b.size()) == 0;
}

}  // namespace

TEST(crypto_sha256_vectors) {
    uint8_t out[32];
    crypto::sha256(reinterpret_cast<const uint8_t*>("abc"), 3, out);
    CHECK(sameBytes(out, unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")));
    crypto::Sha256 h;
    std::vector<uint8_t> a(1001, 'a');
    for (int i = 0; i < 1000; ++i) h.update(a.data(), i % 2 ? 999 : 1001);  // odd chunk sizes
    h.finish(out);
    CHECK(sameBytes(out, unhex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")));
}

TEST(crypto_hmac_and_hkdf_vectors) {
    uint8_t out[42];
    const char* msg = "what do ya want for nothing?";
    crypto::hmacSha256(reinterpret_cast<const uint8_t*>("Jefe"), 4, reinterpret_cast<const uint8_t*>(msg),
                       std::strlen(msg), out);
    CHECK(sameBytes(out, unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")));
    std::vector<uint8_t> longKey(131, 0xaa);
    const char* m2 = "Test Using Larger Than Block-Size Key - Hash Key First";
    crypto::hmacSha256(longKey.data(), longKey.size(), reinterpret_cast<const uint8_t*>(m2), std::strlen(m2), out);
    CHECK(sameBytes(out, unhex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")));

    std::vector<uint8_t> ikm(22, 0x0b), salt, info;
    for (uint8_t i = 0; i < 13; ++i) salt.push_back(i);
    for (uint8_t i = 0xf0; i < 0xfa; ++i) info.push_back(i);
    crypto::hkdf(salt.data(), salt.size(), ikm.data(), ikm.size(), info.data(), info.size(), out, 42);
    CHECK(sameBytes(out, unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")));
}

TEST(crypto_x25519_vectors) {
    auto a = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    auto b = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    uint8_t pa[32], pb[32], s1[32], s2[32];
    crypto::x25519Base(pa, a.data());
    crypto::x25519Base(pb, b.data());
    CHECK(sameBytes(pa, unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")));
    CHECK(sameBytes(pb, unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")));
    crypto::x25519(s1, a.data(), pb);
    crypto::x25519(s2, b.data(), pa);
    auto shared = unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    CHECK(sameBytes(s1, shared));
    CHECK(sameBytes(s2, shared));
    CHECK(crypto::equal(s1, s2, 32));
    s2[31] ^= 1;
    CHECK(!crypto::equal(s1, s2, 32));
}

// ---------------------------------------------------------------------------
// Security

namespace {

std::vector<uint8_t> testKey(uint8_t seed = 0x42) {
    std::vector<uint8_t> k(32);
    for (size_t i = 0; i < k.size(); ++i) k[i] = static_cast<uint8_t>(seed + i * 7);
    return k;
}

struct SecureRig {
    sim::Network net{21};
    sim::Scheduler sched{net};
    sim::Scheduler::Host host{sched};
    std::vector<std::unique_ptr<Security>> sec;

    size_t add(const std::vector<uint8_t>& key, bool require = true, const std::string& code = "") {
        size_t i = net.addNode();
        sec.emplace_back();
        reboot(i, key, require, code);
        net.tickers.push_back([this, i](uint32_t now) { sec[i]->tick(now); });
        return i;
    }
    // A fresh Security object, as after a reboot: new epoch, no replay state.
    void reboot(size_t i, const std::vector<uint8_t>& key, bool require = true, const std::string& code = "") {
        if (sec[i]) sec[i]->stop();
        SecurityConfig c;
        c.key = key;
        c.requireAuthentication = require;
        c.pairingCode = code;
        sec[i].reset(new Security(net.engine(i), host, net.mac(i), c));
        sec[i]->start();
    }
    Status sendWait(size_t from, size_t to, uint8_t port, const std::vector<uint8_t>& data, SendOptions o) {
        Outcome out;
        net.engine(from).send(net.mac(to), port, data.data(), data.size(), o, out.handler(), net.now());
        net.runUntil([&] { return out.done; }, 10000);
        return out.done ? out.status : Status::Cancelled;
    }
    // Last frame `from` sent on `port`.
    std::vector<uint8_t> lastFrame(size_t from, uint8_t port) const {
        for (size_t i = net.log.size(); i-- > 0;) {
            const sim::Frame& f = net.log[i];
            wire::Header h;
            size_t off;
            if (f.from == from && wire::decodeHeader(f.data.data(), f.data.size(), h, off) && h.port == port &&
                h.type != wire::Type::Ack) {
                return f.data;
            }
        }
        return std::vector<uint8_t>();
    }
};

}  // namespace

TEST(secure_messages_are_authenticated) {
    SecureRig rig;
    size_t a = rig.add(testKey()), b = rig.add(testKey());
    Inbox inbox;
    rig.net.engine(b).listen(1, inbox.handler());

    // The first message from a new epoch waits for a challenge; reliable delivery retries through it.
    auto msg = pattern(100);
    CHECK(rig.sendWait(a, b, 1, msg, reliable()) == Status::Ok);
    CHECK_EQ(inbox.messages.size(), 1u);
    CHECK(inbox.messages[0] == msg);
    CHECK(inbox.meta[0].authenticated);
    CHECK_EQ(rig.sec[b]->counters().epochsVerified, 1u);

    auto big = pattern(5000, 3);
    CHECK(rig.sendWait(a, b, 1, big, SendOptions()) == Status::Ok);
    rig.net.run(20);
    CHECK_EQ(inbox.messages.size(), 2u);
    CHECK(inbox.messages[1] == big);
    CHECK(inbox.meta[1].authenticated);

    // A buffer handed over keeps room for the trailer and CRC.
    auto owned = pattern(3000, 5);
    uint8_t* buf = static_cast<uint8_t*>(std::malloc(owned.size() + kSendOverhead));
    std::memcpy(buf, owned.data(), owned.size());
    Outcome sent;
    rig.net.engine(a).sendBuffer(rig.net.mac(b), 1, buf, owned.size(), owned.size() + kSendOverhead, reliable(),
                                 sent.handler(), rig.net.now());
    rig.net.runUntil([&] { return sent.done; });
    CHECK(sent.status == Status::Ok);
    CHECK(inbox.messages.back() == owned);
    CHECK(inbox.meta.back().authenticated);
    inbox.messages.pop_back();
    inbox.meta.pop_back();

    // Broadcast is authenticated too.
    CHECK(rig.net.engine(a).send(Mac::broadcast(), 1, msg.data(), msg.size(), SendOptions(), nullptr,
                                 rig.net.now()) == Status::Ok);
    rig.net.run(20);
    CHECK_EQ(inbox.messages.size(), 3u);
    CHECK(inbox.meta[2].authenticated);
    CHECK_EQ(rig.net.engine(b).stats().authRejected, 0u);
}

TEST(secure_discovery_peer_is_kept_by_authenticated_traffic_only) {
    SecureRig rig;
    size_t a = rig.add(testKey(), false), b = rig.add(testKey(), false);  // optional: plain messages delivered
    DiscoveryConfig cfg;
    cfg.announceIntervalMs = 500;
    cfg.peerTimeoutMs = 1600;
    Discovery da(rig.net.engine(a), cfg, 250, [] { return 0u; });
    Discovery db(rig.net.engine(b), cfg, 250, [] { return 0u; });
    size_t lost = 0;
    da.onPeerEvent([&](PeerEvent e, const PeerInfo&) { lost += e == PeerEvent::Lost; });
    rig.net.tickers.push_back([&](uint32_t now) {
        da.tick(now);
        db.tick(now);
    });
    da.start(rig.net.now());
    db.start(rig.net.now());
    rig.net.run(3000);
    const PeerInfo* peer = da.find(rig.net.mac(b));
    CHECK(peer != nullptr && peer->authenticated);

    // b's announcements are lost; its authenticated messages keep it.
    rig.net.dropIf = dropAnnouncementsFrom({b});
    Inbox inbox;
    rig.net.engine(a).listen(1, inbox.handler());
    auto msg = pattern(20);
    for (int i = 0; i < 20; ++i) {
        rig.net.engine(b).send(rig.net.mac(a), 1, msg.data(), msg.size(), SendOptions(), nullptr, rig.net.now());
        rig.net.run(200);
    }
    CHECK_EQ(inbox.messages.size(), 20u);
    CHECK(inbox.meta.back().authenticated);
    CHECK_EQ(lost, 0u);

    // Plain messages in b's name don't: anyone could send them.
    for (int i = 0; i < 13; ++i) {
        wire::Header h;
        h.port = 1;
        h.messageId = static_cast<uint16_t>(30000 + i);
        std::vector<uint8_t> f(wire::kCommonHeaderSize);
        wire::encodeHeader(h, f.data());
        f.push_back(7);
        rig.net.inject(a, rig.net.mac(b), f);
        rig.net.run(200);
    }
    CHECK(!inbox.meta.back().authenticated);  // delivered, as plain messages
    CHECK_EQ(lost, 1u);
    CHECK(da.find(rig.net.mac(b)) == nullptr);
    rig.net.dropIf = nullptr;
    da.stop(rig.net.now());
    db.stop(rig.net.now());
}

TEST(secure_first_unreliable_message_waits_for_epoch) {
    SecureRig rig;
    size_t a = rig.add(testKey()), b = rig.add(testKey());
    Inbox inbox;
    rig.net.engine(b).listen(1, inbox.handler());
    auto msg = pattern(10);
    rig.net.engine(a).send(rig.net.mac(b), 1, msg.data(), msg.size(), SendOptions(), nullptr, rig.net.now());
    rig.net.run(50);
    CHECK_EQ(inbox.messages.size(), 0u);  // held back: the epoch was unknown
    CHECK_EQ(rig.sec[b]->counters().epochsVerified, 1u);
    rig.net.engine(a).send(rig.net.mac(b), 1, msg.data(), msg.size(), SendOptions(), nullptr, rig.net.now());
    rig.net.run(50);
    CHECK_EQ(inbox.messages.size(), 1u);
}

TEST(secure_refuses_unkeyed_and_wrong_key) {
    SecureRig rig;
    size_t a = rig.add(testKey()), b = rig.add(testKey()), plain = rig.add({}), other = rig.add(testKey(7));
    (void)a;
    Inbox inbox;
    rig.net.engine(b).listen(1, inbox.handler());
    auto msg = pattern(300);
    CHECK(rig.sendWait(plain, b, 1, msg, reliable()) == Status::Rejected);
    CHECK(rig.sendWait(other, b, 1, msg, reliable()) == Status::AuthFailed);  // b could not verify it
    CHECK_EQ(inbox.messages.size(), 0u);
    CHECK(rig.net.engine(b).stats().authRejected >= 2u);
}

// Reassembly checks the tag only once a message is complete, so it must not
// hand its memory to whoever claims a large message.
TEST(secure_reassembly_bounds_unverified_senders) {
    SecureRig rig;
    size_t a = rig.add(testKey()), b = rig.add(testKey()), plain = rig.add({});
    Inbox inbox;
    rig.net.engine(b).listen(1, inbox.handler());

    // Unauthenticated where authentication is required: refused at the first fragment.
    auto msg = pattern(4000);
    size_t before = rig.net.log.size();
    CHECK(rig.sendWait(plain, b, 1, msg, reliable()) == Status::Rejected);
    size_t sent = 0;
    for (size_t i = before; i < rig.net.log.size(); ++i) sent += rig.net.log[i].from == plain;
    CHECK(sent < 5u);  // not all 17 fragments

    // Claimed authenticated, from senders b hasn't verified: one slot for all of them.
    uint32_t refused = rig.net.engine(b).stats().reassemblyRefused;
    for (uint8_t i = 0; i < 3; ++i) {
        Mac spoof = {{0x02, 6, 6, 6, 6, i}};
        rig.net.inject(b, spoof, fragmentsOf(msg, wire::kFlagAuth, 1, 1)[0]);
    }
    CHECK_EQ(rig.net.engine(b).stats().reassemblyRefused, refused + 2);

    // A key holder b hasn't verified yet still gets through, once the slot's idle.
    CHECK(rig.sendWait(a, b, 1, msg, reliable()) == Status::Ok);
    CHECK_EQ(inbox.messages.size(), 1u);
    CHECK(inbox.meta[0].authenticated);
}

TEST(secure_optional_mode_marks_plain_messages) {
    SecureRig rig;
    size_t b = rig.add(testKey(), false), plain = rig.add({});
    Inbox inbox;
    rig.net.engine(b).listen(1, inbox.handler());
    CHECK(rig.sendWait(plain, b, 1, pattern(20), reliable()) == Status::Ok);
    CHECK_EQ(inbox.messages.size(), 1u);
    CHECK(!inbox.meta[0].authenticated);
}

TEST(secure_rejects_tampering_and_replays) {
    SecureRig rig;
    size_t a = rig.add(testKey()), b = rig.add(testKey());
    Inbox inbox;
    rig.net.engine(b).listen(1, inbox.handler());
    CHECK(rig.sendWait(a, b, 1, pattern(40), reliable()) == Status::Ok);
    CHECK(rig.sendWait(a, b, 1, pattern(40, 9), SendOptions()) == Status::Ok);
    rig.net.run(10);
    CHECK_EQ(inbox.messages.size(), 2u);
    std::vector<uint8_t> frame = rig.lastFrame(a, 1);
    CHECK(!frame.empty());

    std::vector<uint8_t> tampered = frame;
    tampered[wire::kCommonHeaderSize + 3] ^= 0x01;  // payload byte
    tampered[3] ^= 0x55;                           // new message id: not a duplicate
    rig.net.inject(b, rig.net.mac(a), tampered);
    CHECK_EQ(inbox.messages.size(), 2u);

    std::vector<uint8_t> replay = frame;
    replay[3] ^= 0x55;  // a fresh message id slips past duplicate suppression, not past the sequence check
    rig.net.inject(b, rig.net.mac(a), replay);
    CHECK_EQ(inbox.messages.size(), 2u);
    rig.net.run(6000);  // also after duplicate suppression forgot it
    rig.net.inject(b, rig.net.mac(a), frame);
    CHECK_EQ(inbox.messages.size(), 2u);
    CHECK(rig.sec[b]->counters().replaysRejected >= 2u);
    CHECK(rig.sec[b]->counters().forgeriesRejected >= 1u);

    // Spoofing another node's address does not help without the key either.
    size_t c = rig.add({});
    std::vector<uint8_t> forged = frame;
    forged[3] ^= 0x33;
    rig.net.inject(b, rig.net.mac(c), forged);
    CHECK_EQ(inbox.messages.size(), 2u);
}

TEST(secure_old_epoch_is_not_replayable_after_reboot) {
    SecureRig rig;
    size_t a = rig.add(testKey()), b = rig.add(testKey());
    Inbox inbox;
    rig.net.engine(b).listen(1, inbox.handler());
    CHECK(rig.sendWait(a, b, 1, pattern(40), reliable()) == Status::Ok);
    std::vector<uint8_t> old = rig.lastFrame(a, 1);

    rig.net.run(3000);
    rig.reboot(a, testKey());
    CHECK(rig.sendWait(a, b, 1, pattern(41), reliable()) == Status::Ok);  // the new epoch gets verified
    CHECK_EQ(inbox.messages.size(), 2u);

    old[3] ^= 0x77;
    rig.net.inject(b, rig.net.mac(a), old);
    rig.net.run(3000);  // challenges come back with the new epoch only
    rig.net.inject(b, rig.net.mac(a), old);
    rig.net.run(500);
    CHECK_EQ(inbox.messages.size(), 2u);

    // A receiver that rebooted (no state) still refuses the old epoch.
    rig.reboot(b, testKey());
    rig.net.engine(b).listen(1, inbox.handler());
    rig.net.inject(b, rig.net.mac(a), old);
    rig.net.run(1000);
    rig.net.inject(b, rig.net.mac(a), old);
    rig.net.run(500);
    CHECK_EQ(inbox.messages.size(), 2u);
}

// A recorded message must not be accepted again: not after the receiver
// reboots, and not after an old epoch's message forces a new challenge.
TEST(secure_replay_after_receiver_reboot_is_refused) {
    SecureRig rig;
    size_t a = rig.add(testKey()), b = rig.add(testKey());
    Inbox inbox;
    rig.net.engine(b).listen(1, inbox.handler());
    CHECK(rig.sendWait(a, b, 1, pattern(40), reliable()) == Status::Ok);
    std::vector<uint8_t> m = rig.lastFrame(a, 1);
    CHECK_EQ(inbox.messages.size(), 1u);
    rig.reboot(b, testKey());
    rig.net.engine(b).listen(1, inbox.handler());
    m[3] ^= 0x5A;  // another message id: not a duplicate for the engine
    rig.net.inject(b, rig.net.mac(a), m);  // held back; b challenges a
    rig.net.run(200);
    CHECK_EQ(rig.sec[b]->counters().epochsVerified, 1u);
    m[3] ^= 0x01;
    rig.net.inject(b, rig.net.mac(a), m);
    rig.net.run(10);
    CHECK_EQ(inbox.messages.size(), 1u);
    CHECK(rig.sec[b]->counters().replaysRejected >= 1u);
    // a's new messages still get through.
    CHECK(rig.sendWait(a, b, 1, pattern(41), reliable()) == Status::Ok);
    CHECK_EQ(inbox.messages.size(), 2u);
}

TEST(secure_forced_reverification_does_not_reopen_the_window) {
    SecureRig rig;
    size_t a = rig.add(testKey()), b = rig.add(testKey());
    Inbox inbox;
    rig.net.engine(b).listen(1, inbox.handler());
    CHECK(rig.sendWait(a, b, 1, pattern(40), reliable()) == Status::Ok);
    std::vector<uint8_t> oldEpoch = rig.lastFrame(a, 1);
    rig.net.run(3000);
    rig.reboot(a, testKey());
    CHECK(rig.sendWait(a, b, 1, pattern(41, 7), reliable()) == Status::Ok);
    std::vector<uint8_t> cur = rig.lastFrame(a, 1);
    rig.net.run(2000);
    for (int round = 0; round < 3; ++round) {
        oldEpoch[3] ^= 0x11;
        rig.net.inject(b, rig.net.mac(a), oldEpoch);  // old epoch: b challenges a again
        rig.net.run(200);
        cur[3] = static_cast<uint8_t>(cur[3] + 0x21);
        size_t before = inbox.messages.size();
        rig.net.inject(b, rig.net.mac(a), cur);
        rig.net.run(1500);
        CHECK_EQ(inbox.messages.size(), before);
    }
    CHECK(rig.sec[b]->counters().epochsVerified >= 3u);  // the challenges did happen
    CHECK(rig.sendWait(a, b, 1, pattern(42), reliable()) == Status::Ok);
}

// An ack names the message it acknowledges (epoch and sequence), so a recorded
// "complete" can't confirm a later message that reuses the id.
TEST(secure_acks_are_bound_to_the_message) {
    SecureRig rig;
    size_t a = rig.add(testKey()), b = rig.add(testKey());
    rig.net.engine(a).listen(1, [](const Message&) {});
    rig.net.engine(b).listen(1, [](const Message&) {});
    // Each verifies the other, learning its capabilities.
    CHECK(rig.sendWait(a, b, 1, pattern(10), reliable()) == Status::Ok);
    CHECK(rig.sendWait(b, a, 1, pattern(10), reliable()) == Status::Ok);

    uint8_t frame[6];
    wire::Header h;
    h.type = wire::Type::Ack;
    h.flags = wire::kFlagAuth;
    h.port = 1;
    h.messageId = 777;
    wire::encodeHeader(h, frame);
    const uint8_t first[8] = {1, 2, 3, 4, 5, 0, 0, 0};
    const uint8_t later[8] = {1, 2, 3, 4, 9, 0, 0, 0};
    uint8_t tag[wire::kAckTagSize];
    Mac ma = rig.net.mac(a), mb = rig.net.mac(b);
    for (uint8_t status : {uint8_t(wire::AckStatus::Complete), uint8_t(wire::AckStatus::Missing)}) {
        frame[5] = status;
        rig.sec[b]->sealAck(ma, frame, sizeof(frame), first, tag);
        CHECK(rig.sec[a]->openAck(mb, frame, sizeof(frame), tag, first, nullptr));
        CHECK(rig.sec[a]->openAck(mb, frame, sizeof(frame), tag, later, first));  // sealed again since
        CHECK(!rig.sec[a]->openAck(mb, frame, sizeof(frame), tag, later, nullptr));
        // Unbound: accepted only for other statuses, from a receiver that binds.
        rig.sec[b]->sealAck(ma, frame, sizeof(frame), nullptr, tag);
        bool complete = status == uint8_t(wire::AckStatus::Complete);
        CHECK(rig.sec[a]->openAck(mb, frame, sizeof(frame), tag, later, nullptr) == !complete);
    }
}

// A response without the capabilities extension, as from NowTP 0.5: the
// sender won't seal its queued message again, so the receiver keeps the old
// window rule and the held-back message still gets through.
// The sequence number of a refused message is released for its retry.
TEST(secure_refused_message_is_delivered_on_retry) {
    SecureRig rig;
    size_t a = rig.add(testKey()), b = rig.add(testKey());
    Inbox inbox;
    ReceiveHandler take = inbox.handler();
    int refusals = 0;
    rig.net.engine(b).listen(1, [&](const Message& m) {
        if (refusals > 0) {
            refusals--;
            m.refused = true;
            return;
        }
        take(m);
    });
    CHECK(rig.sendWait(a, b, 1, pattern(10), reliable()) == Status::Ok);  // verifies the epoch
    for (size_t size : {100, 3000}) {
        inbox.messages.clear();
        inbox.meta.clear();
        refusals = 1;
        auto msg = pattern(size, static_cast<uint32_t>(size));
        CHECK(rig.sendWait(a, b, 1, msg, reliable()) == Status::Ok);
        CHECK_EQ(inbox.messages.size(), 1u);
        CHECK(inbox.messages[0] == msg);
        CHECK(inbox.meta[0].authenticated);
    }
    CHECK_EQ(rig.net.engine(b).stats().messagesRefused, 2u);
    CHECK_EQ(rig.sec[b]->counters().replaysRejected, 0u);
}

TEST(secure_older_senders_still_verify) {
    SecureRig rig;
    size_t a = rig.add(testKey()), b = rig.add(testKey());
    Inbox inbox;
    rig.net.engine(b).listen(1, inbox.handler());
    // b's challenges never reach a; we answer them the old way instead.
    rig.net.dropIf = [&](const sim::Frame& f) {
        wire::Header fh;
        size_t off;
        return f.from == b && wire::decodeHeader(f.data.data(), f.data.size(), fh, off) &&
               fh.port == kSecurityPort;
    };
    Outcome out;
    auto msg = pattern(20);
    rig.net.engine(a).send(rig.net.mac(b), 1, msg.data(), msg.size(), reliable(), out.handler(), rig.net.now());
    rig.net.run(30);
    CHECK(inbox.messages.empty());
    std::vector<uint8_t> challenge = rig.lastFrame(b, kSecurityPort);
    std::vector<uint8_t> m = rig.lastFrame(a, 1);
    CHECK(challenge.size() >= wire::kCommonHeaderSize + 9 && m.size() > wire::kAuthTrailerSize);
    const uint8_t* trailer = m.data() + m.size() - wire::kAuthTrailerSize;

    std::vector<uint8_t> resp(1 + 8 + 4 + 4);
    resp[0] = 2;
    std::memcpy(&resp[1], &challenge[wire::kCommonHeaderSize + 1], 8);
    std::memcpy(&resp[9], trailer, 8);  // a's epoch, and its current sequence: the held-back message's
    uint8_t kc[32], full[32];
    auto key = testKey();
    crypto::hmacSha256(key.data(), key.size(), reinterpret_cast<const uint8_t*>("NowTP challenge"), 15, kc);
    crypto::HmacSha256 t(kc, sizeof(kc));
    t.update(rig.net.mac(a).bytes, 6);
    t.update(rig.net.mac(b).bytes, 6);
    t.update(&resp[1], 16);
    t.finish(full);
    resp.insert(resp.end(), full, full + 16);
    wire::Header rh;
    rh.port = kSecurityPort;
    rh.messageId = 4321;
    std::vector<uint8_t> f(wire::kCommonHeaderSize);
    wire::encodeHeader(rh, f.data());
    f.insert(f.end(), resp.begin(), resp.end());
    rig.net.inject(b, rig.net.mac(a), f);
    CHECK(rig.net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Ok);
    CHECK_EQ(inbox.messages.size(), 1u);
}

TEST(secure_forged_acks_are_ignored) {
    SecureRig rig;
    size_t a = rig.add(testKey()), b = rig.add(testKey());
    Inbox inbox;
    rig.net.engine(b).listen(1, inbox.handler());
    CHECK(rig.sendWait(a, b, 1, pattern(10), reliable()) == Status::Ok);  // epoch verified

    rig.net.appLoss = 1.0;  // frames reach b's radio but never its application
    Outcome out;
    auto msg = pattern(10, 5);
    rig.net.engine(a).send(rig.net.mac(b), 1, msg.data(), msg.size(), reliable(), out.handler(), rig.net.now());
    rig.net.run(5);
    std::vector<uint8_t> frame = rig.lastFrame(a, 1);
    wire::Header h;
    size_t off;
    CHECK(wire::decodeHeader(frame.data(), frame.size(), h, off));
    for (int tagged = 0; tagged < 2; ++tagged) {
        wire::Header ack;
        ack.type = wire::Type::Ack;
        ack.flags = tagged ? wire::kFlagAuth : 0;
        ack.port = 1;
        ack.messageId = h.messageId;
        std::vector<uint8_t> f(wire::kCommonHeaderSize);
        wire::encodeHeader(ack, f.data());
        f.push_back(static_cast<uint8_t>(wire::AckStatus::Complete));
        if (tagged) f.insert(f.end(), wire::kAckTagSize, 0x5A);
        rig.net.inject(a, rig.net.mac(b), f);
    }
    rig.net.runUntil([&] { return out.done; }, 5000);
    CHECK(out.done);
    CHECK(out.status != Status::Ok);
    CHECK(rig.net.engine(a).stats().authRejected >= 2u);
}

TEST(pairing_hands_over_the_key) {
    SecureRig rig;
    size_t a = rig.add({}), b = rig.add({}), bystander = rig.add({});
    std::vector<uint8_t> savedA, savedB;
    rig.sec[a]->onKeyChanged([&](const std::vector<uint8_t>& k) { savedA = k; });
    rig.sec[b]->onKeyChanged([&](const std::vector<uint8_t>& k) { savedB = k; });
    Status ra = Status::Cancelled, rb = Status::Cancelled;
    Mac joined = Mac::broadcast(), member = Mac::broadcast();
    rig.sched.run({[&] { ra = rig.sec[a]->acceptPairing(8000, &joined); },
                   [&] {
                       rig.host.sleep(300);  // the window opens first
                       rb = rig.sec[b]->pair(8000, &member);
                   }});
    CHECK(ra == Status::Ok);
    CHECK(rb == Status::Ok);
    CHECK(joined == rig.net.mac(b));
    CHECK(member == rig.net.mac(a));
    CHECK_EQ(rig.sec[a]->key().size(), 32u);
    CHECK(rig.sec[a]->key() == rig.sec[b]->key());
    CHECK(savedA == rig.sec[a]->key());  // created by the first member
    CHECK(savedB == rig.sec[a]->key());
    CHECK(rig.sec[bystander]->key().empty());

    Inbox inbox;
    rig.net.engine(a).listen(1, inbox.handler());
    CHECK(rig.sendWait(b, a, 1, pattern(500), reliable()) == Status::Ok);
    CHECK(inbox.meta.back().authenticated);
    CHECK(rig.sendWait(bystander, a, 1, pattern(5), reliable()) == Status::Rejected);
}

TEST(pairing_with_existing_key_and_code) {
    SecureRig rig;
    size_t a = rig.add(testKey(), true, "correct horse"), b = rig.add({}, true, "correct horse");
    Status ra = Status::Cancelled, rb = Status::Cancelled;
    rig.sched.run({[&] { ra = rig.sec[a]->acceptPairing(8000); }, [&] { rb = rig.sec[b]->pair(8000); }});
    CHECK(ra == Status::Ok);
    CHECK(rb == Status::Ok);
    CHECK(rig.sec[b]->key() == testKey());  // the installation's key, unchanged on the member
}

TEST(pairing_refuses_another_code) {
    SecureRig rig;
    size_t a = rig.add(testKey(), true, "1234"), b = rig.add({}, true, "9999");
    Status ra = Status::Cancelled, rb = Status::Cancelled;
    rig.sched.run({[&] { ra = rig.sec[a]->acceptPairing(4000); }, [&] { rb = rig.sec[b]->pair(3000); }});
    CHECK(ra == Status::AuthFailed);
    CHECK(rb == Status::AuthFailed);
    CHECK(rig.sec[b]->key().empty());
}

TEST(pairing_times_out_without_member) {
    SecureRig rig;
    size_t b = rig.add({});
    rig.add({});  // has no window open
    Status rb = Status::Cancelled;
    rig.sched.run({[&] { rb = rig.sec[b]->pair(2000); }});
    CHECK(rb == Status::Timeout);
}

// ---------------------------------------------------------------------------
// Channel following

namespace {

struct FollowRig {
    sim::Network net{5};
    std::mt19937 rng{3};
    std::vector<std::unique_ptr<Discovery>> disc;
    std::vector<std::unique_ptr<ChannelFollower>> fol;
    std::vector<int> moves;

    size_t add(uint8_t channel, bool locked, ChannelConfig cc = ChannelConfig()) {
        size_t i = net.addNode();
        net.node(i).radio.chan = channel;
        net.node(i).radio.channelLocked = locked;
        DiscoveryConfig dc;
        dc.name = "n" + std::to_string(i);
        dc.announceIntervalMs = 500;
        dc.peerTimeoutMs = 1600;
        disc.emplace_back(new Discovery(net.engine(i), dc, 250, [this] { return static_cast<uint32_t>(rng()); }));
        fol.emplace_back(new ChannelFollower(*disc.back(), net.node(i).radio, cc));
        moves.push_back(0);
        disc[i]->onPeerEvent([this, i](PeerEvent e, const PeerInfo& p) { fol[i]->onPeerEvent(e, p, net.now()); });
        disc[i]->onPeerMoved([this, i](const PeerInfo& p, uint8_t ch) { fol[i]->onPeerMoved(p, ch, net.now()); });
        fol[i]->onChannelChange([this, i](uint8_t) { moves[i]++; });
        bool anchor = cc.anchor;
        net.tickers.push_back([this, i, anchor](uint32_t now) {
            // What the transport does: announce the current channel and anchor state.
            const sim::SimRadio& r = net.node(i).radio;
            disc[i]->setChannelInfo(r.chan, anchor || r.channelLocked, now);
            disc[i]->tick(now);
            fol[i]->tick(now);
        });
        return i;
    }
    void start() {
        for (size_t i = 0; i < disc.size(); ++i) {
            disc[i]->start(net.now());
            fol[i]->start(net.now());
        }
    }
    uint8_t chan(size_t i) { return net.node(i).radio.chan; }
};

}  // namespace

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
    net.tickers.push_back([&](uint32_t now) {
        ds.tick(now);
        db.tick(now);
    });
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

// ---------------------------------------------------------------------------
// Time synchronization

namespace {

struct TimeRig {
    sim::Network net{8};
    std::mt19937 rng{4};
    std::vector<std::unique_ptr<Discovery>> disc;
    std::vector<std::unique_ptr<TimeSync>> ts;
    std::vector<TimeRole> roles;
    std::function<void(size_t, TimeSyncConfig&)> configure;  // applied when a node is built

    size_t add(TimeRole role, uint64_t clockOffsetUs, double skew) {
        size_t i = net.addNode();
        net.node(i).clockOffsetUs = clockOffsetUs;
        net.node(i).clockSkew = skew;
        disc.emplace_back();
        ts.emplace_back();
        roles.push_back(role);
        build(i);
        net.tickers.push_back([this, i](uint32_t now) {
            disc[i]->tick(now);
            ts[i]->tick(now);
        });
        return i;
    }
    size_t add(bool reference, uint64_t clockOffsetUs, double skew) {
        return add(reference ? TimeRole::Reference : TimeRole::Follow, clockOffsetUs, skew);
    }
    // Node i's Discovery and TimeSync, as they are after a boot (not started).
    void build(size_t i) {
        ts[i].reset();
        DiscoveryConfig dc;
        dc.name = "t" + std::to_string(i);
        disc[i].reset(new Discovery(net.engine(i), dc, 250, [this] { return static_cast<uint32_t>(rng()); }));
        TimeSyncConfig tc;
        tc.role = roles[i];
        if (configure) configure(i, tc);
        sim::Node* node = &net.node(i);
        sim::Network* nw = &net;
        ts[i].reset(new TimeSync(net.engine(i), [node, nw] { return node->clockUs(nw->now()); }, tc, net.mac(i)));
        ts[i]->setDiscovery(disc[i].get());
        disc[i]->onPeerEvent([this, i](PeerEvent e, const PeerInfo& p) { ts[i]->onPeerEvent(e, p, net.now()); });
    }
    void start(size_t i) {
        disc[i]->start(net.now());
        ts[i]->start(net.now());
    }
    void start() {
        for (size_t i = 0; i < ts.size(); ++i) start(i);
    }
    // A reboot without goodbye: the node's clock restarts near `uptimeUs`.
    void reboot(size_t i, uint64_t uptimeUs) {
        net.node(i).online = false;  // what the old objects send on the way out is lost
        build(i);
        net.node(i).clockOffsetUs = uptimeUs - static_cast<uint64_t>(net.now()) * 1000;
        net.node(i).clockSkew = 0;
        net.node(i).online = true;
        start(i);
    }
    size_t acting() const {
        size_t n = 0;
        for (const auto& t : ts) n += t->isReference() ? 1 : 0;
        return n;
    }
    bool allSynced() const {
        for (const auto& t : ts) {
            if (!t->synced()) return false;
        }
        return true;
    }
    // Error of node i's network time against the reference's clock, µs.
    int64_t error(size_t i, size_t ref) {
        return static_cast<int64_t>(ts[i]->networkTime() - net.node(ref).clockUs(net.now()));
    }
    // Difference between two nodes' network times, µs.
    int64_t apart(size_t i, size_t j) { return static_cast<int64_t>(ts[i]->networkTime() - ts[j]->networkTime()); }
};

int64_t absValue(int64_t v) {
    return v < 0 ? -v : v;
}

}  // namespace

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
    rig.net.tickers[ref] = [&rig, ref, dirty](uint32_t now) {
        rig.disc[ref]->tick(now);
        dirty->tick(now);
    };
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
// Streams

namespace {

struct Received {
    std::vector<uint8_t> data;
    bool done = false;
    Status status = Status::Ok;
    StreamInfo info;
};

struct StreamRig {
    sim::Network net{13};
    std::mt19937 rng{2};
    // Before `st`: a stream still open when a test returns reports to its
    // receiver and sender as the Streams go.
    std::deque<Received> receivers;
    std::deque<Outcome> outcomes;
    std::vector<std::unique_ptr<Streams>> st;

    Received& receiver() {
        receivers.emplace_back();
        return receivers.back();
    }
    Outcome& outcome() {
        outcomes.emplace_back();
        return outcomes.back();
    }

    size_t add(Config cfg = Config()) {
        size_t i = net.addNode(cfg);
        st.emplace_back(new Streams(net.engine(i), [this] { return static_cast<uint32_t>(rng()); }));
        st[i]->start();
        net.tickers.push_back([this, i](uint32_t now) { st[i]->tick(now); });
        return i;
    }
};

StreamAcceptor collectInto(Received& r, bool accept = true, size_t failAt = SIZE_MAX) {
    // The application's memory, not NowTP's.
    return [&r, accept, failAt](const StreamInfo& info, StreamSink& sink) {
        testing::HeapExempt app;
        r.info = info;
        if (!accept) return false;
        sink.write = [&r, failAt](uint32_t offset, const uint8_t* d, size_t n) {
            testing::HeapExempt app;
            if (offset != r.data.size() || r.data.size() + n > failAt) return false;
            r.data.insert(r.data.end(), d, d + n);
            return true;
        };
        sink.done = [&r](Status s) {
            r.done = true;
            r.status = s;
        };
        return true;
    };
}

}  // namespace

TEST(stream_transfers_large_data_under_loss) {
    StreamRig rig;
    size_t a = rig.add(), b = rig.add();
    rig.net.airLoss = 0.05;
    rig.net.appLoss = 0.02;
    Received& r = rig.receiver();
    rig.st[b]->onIncoming(collectInto(r));
    std::vector<uint8_t> data = pattern(300 * 1024, 11);
    uint32_t lastRead = 0;
    bool inOrder = true;
    uint32_t progressCalls = 0;
    StreamOptions o;
    o.topic = 7;
    o.header = {1, 2, 3};
    o.progress = [&](uint32_t, uint32_t) { progressCalls++; };
    Outcome& out = rig.outcome();
    CHECK(rig.st[a]->send(rig.net.mac(b), static_cast<uint32_t>(data.size()),
                          [&](uint32_t offset, uint8_t* buf, size_t n) {
                              inOrder = inOrder && offset == lastRead;
                              lastRead = offset + static_cast<uint32_t>(n);
                              memcpy(buf, data.data() + offset, n);
                              return true;
                          },
                          out.handler(), o, rig.net.now()) == Status::Ok);
    CHECK(rig.net.runUntil([&] { return out.done; }, 120000));
    if (out.status != Status::Ok) std::printf("    stream: %s after %u of %u bytes, receiver %s\n", toString(out.status), (unsigned)r.data.size(), (unsigned)data.size(), r.done ? toString(r.status) : "busy");
    CHECK(out.status == Status::Ok);
    CHECK(r.done);
    CHECK(r.status == Status::Ok);
    CHECK(r.data == data);
    CHECK(inOrder);
    CHECK_EQ(r.info.topic, 7);
    CHECK((r.info.header == std::vector<uint8_t>{1, 2, 3}));
    CHECK_EQ(r.info.size, data.size());
    CHECK_EQ(progressCalls, (data.size() + o.chunkSize - 1) / o.chunkSize);
    CHECK_EQ(rig.st[a]->outgoing(), 0u);
    CHECK_EQ(rig.st[b]->incoming(), 0u);
}

TEST(stream_refused_or_aborted_by_receiver) {
    StreamRig rig;
    size_t a = rig.add(), b = rig.add();
    std::vector<uint8_t> data = pattern(20000);
    auto reader = [&](uint32_t offset, uint8_t* buf, size_t n) {
        memcpy(buf, data.data() + offset, n);
        return true;
    };
    Received& refused = rig.receiver();
    rig.st[b]->onIncoming(collectInto(refused, false));
    Outcome& out = rig.outcome();
    rig.st[a]->send(rig.net.mac(b), 20000, reader, out.handler(), StreamOptions(), rig.net.now());
    CHECK(rig.net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Rejected);

    Received& failing = rig.receiver();
    rig.st[b]->onIncoming(collectInto(failing, true, 9000));  // e.g. a flash write error
    Outcome& out2 = rig.outcome();
    rig.st[a]->send(rig.net.mac(b), 20000, reader, out2.handler(), StreamOptions(), rig.net.now());
    CHECK(rig.net.runUntil([&] { return out2.done; }));
    CHECK(out2.status == Status::Rejected);
    CHECK(failing.done);
    CHECK(failing.status == Status::Rejected);

    // Nobody listening for streams at all.
    rig.st[b]->stop();
    Outcome& out3 = rig.outcome();
    rig.st[a]->send(rig.net.mac(b), 100, reader, out3.handler(), StreamOptions(), rig.net.now());
    CHECK(rig.net.runUntil([&] { return out3.done; }));
    CHECK(out3.status == Status::Rejected);
}

TEST(stream_cancel_and_vanishing_peers) {
    StreamRig rig;
    size_t a = rig.add(), b = rig.add();
    std::vector<uint8_t> data(100000, 3);
    auto reader = [&](uint32_t offset, uint8_t* buf, size_t n) {
        memcpy(buf, data.data() + offset, n);
        return true;
    };
    Received& r = rig.receiver();
    rig.st[b]->onIncoming(collectInto(r));
    Outcome& out = rig.outcome();
    uint32_t id = 0;
    rig.st[a]->send(rig.net.mac(b), 100000, reader, out.handler(), StreamOptions(), rig.net.now(), &id);
    rig.net.run(100);
    CHECK(rig.st[a]->cancel(id, rig.net.now()) == Status::Ok);
    CHECK(out.done);
    CHECK(out.status == Status::Cancelled);
    CHECK(rig.net.runUntil([&] { return r.done; }));
    CHECK(r.status == Status::Cancelled);

    // The receiver disappears halfway.
    Received& r2 = rig.receiver();
    rig.st[b]->onIncoming(collectInto(r2));
    Outcome& out2 = rig.outcome();
    rig.st[a]->send(rig.net.mac(b), 100000, reader, out2.handler(), StreamOptions(), rig.net.now());
    rig.net.runUntil([&] { return r2.data.size() > 30000; });
    rig.net.node(b).online = false;
    CHECK(rig.net.runUntil([&] { return out2.done; }, 30000));
    CHECK(out2.status != Status::Ok);
    CHECK(rig.net.runUntil([&] { return r2.done; }, 40000));  // idle timeout on the receiver
    CHECK(r2.status == Status::Timeout);
}

TEST(stream_validates_options) {
    StreamRig rig;
    size_t a = rig.add(), b = rig.add();
    auto reader = [](uint32_t, uint8_t*, size_t) { return true; };
    StreamOptions big;
    big.chunkSize = 64 * 1024;
    CHECK(rig.st[a]->send(rig.net.mac(b), 10, reader, nullptr, big, 0) == Status::TooLarge);
    CHECK(rig.st[a]->send(Mac::broadcast(), 10, reader, nullptr, StreamOptions(), 0) == Status::InvalidArgument);
    StreamOptions header;
    header.header.resize(Streams::kMaxHeader + 1);
    CHECK(rig.st[a]->send(rig.net.mac(b), 10, reader, nullptr, header, 0) == Status::InvalidArgument);
}

TEST(stream_over_secured_link) {
    SecureRig rig;
    size_t a = rig.add(testKey()), b = rig.add(testKey());
    // Before the Streams, which report to them as they go.
    Received r;
    std::vector<uint8_t> data = pattern(50000, 5);
    Outcome out;
    Streams sa(rig.net.engine(a), [] { return 77u; }), sb(rig.net.engine(b), [] { return 78u; });
    sa.start();
    sb.start();
    rig.net.tickers.push_back([&](uint32_t now) {
        sa.tick(now);
        sb.tick(now);
    });
    sb.onIncoming(collectInto(r));
    sa.send(rig.net.mac(b), 50000,
            [&](uint32_t offset, uint8_t* buf, size_t n) {
                memcpy(buf, data.data() + offset, n);
                return true;
            },
            out.handler(), StreamOptions(), rig.net.now());
    CHECK(rig.net.runUntil([&] { return out.done; }, 60000));
    CHECK(out.status == Status::Ok);
    CHECK(r.data == data);
    rig.net.tickers.pop_back();
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

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Short heaps. Each test runs a scenario at every heap size from 0 to 24 KB
// above what is held, in 512-byte steps. Only what NowTP takes counts; the
// simulator and the test's own memory are exempt. An operator new past the
// limit aborts the test program, as it would abort the device; NowTP's
// malloc() fails softly there and must be handled. Afterwards the limit is
// lifted, traffic must flow again, and everything NowTP took must be back.

namespace {

constexpr size_t kHeapSweepMax = 24 * 1024;
constexpr size_t kHeapSweepStep = 512;

// NowTP's work on behalf of the test (send(), service ticks) is counted.
template <class F>
void counted(F f) {
    testing::HeapCounted nowtp;
    f();
}

}  // namespace

TEST(heap_engine_survives_any_heap_size) {
    size_t refusals = testing::heapRefusals();
    for (size_t above = 0; above <= kHeapSweepMax; above += kHeapSweepStep) {
        size_t before = testing::heapUsed();
        {
            testing::HeapExempt test;
            sim::Network net(static_cast<uint32_t>(above));
            net.airLoss = 0.05;
            Config cfg;
            cfg.maxMessageSize = 4096;
            size_t a = net.addNode(cfg), b = net.addNode(cfg), c = net.addNode(cfg);
            Inbox inbox;
            net.engine(b).listen(1, inbox.handler());
            // Captures past std::function's own buffer: copying it would take heap.
            uint64_t state[6] = {};
            net.engine(b).listen(2, [state](const Message& m) { m.refused = m.len % 2 == state[0]; });
            auto big = pattern(3000), small = pattern(100), medium = pattern(600), odd = pattern(601);
            {
                testing::HeapLimit limit(above);
                for (int round = 0; round < 6; ++round) {
                    const std::vector<uint8_t>& refusedOrNot = round % 2 ? odd : medium;
                    counted([&] {
                        for (size_t from : {a, c}) {
                            Engine& e = net.engine(from);
                            e.send(net.mac(b), 1, big.data(), big.size(), reliable(), nullptr, net.now());
                            e.send(net.mac(b), 1, small.data(), small.size(), reliable(), nullptr, net.now());
                            e.send(net.mac(b), 1, medium.data(), medium.size(), latest(), nullptr, net.now());
                            e.send(net.mac(b), 2, refusedOrNot.data(), refusedOrNot.size(), reliable(), nullptr,
                                   net.now());
                            e.send(Mac::broadcast(), 1, medium.data(), medium.size(), SendOptions(), nullptr,
                                   net.now());
                        }
                    });
                    net.run(250);
                }
                net.run(2500);  // everything queued finishes or times out
            }
            Outcome out;
            net.engine(a).send(net.mac(b), 1, big.data(), big.size(), reliable(), out.handler(), net.now());
            CHECK(net.runUntil([&] { return out.done; }));
            CHECK(out.status == Status::Ok);
        }
        CHECK_EQ(testing::heapUsed(), before);
    }
    CHECK(testing::heapRefusals() > refusals);
}

TEST(heap_security_survives_any_heap_size) {
    for (size_t above = 0; above <= kHeapSweepMax; above += kHeapSweepStep) {
        size_t before = testing::heapUsed();
        {
            testing::HeapExempt test;
            SecureRig rig;
            size_t a = rig.add(testKey()), b = rig.add(testKey()), stranger = rig.add(pattern(32, 3));
            Inbox inbox;
            rig.net.engine(b).listen(1, inbox.handler());
            auto big = pattern(3000), small = pattern(100);
            {
                testing::HeapLimit limit(above);
                for (int round = 0; round < 4; ++round) {
                    counted([&] {
                        for (size_t from : {a, stranger}) {
                            Engine& e = rig.net.engine(from);
                            e.send(rig.net.mac(b), 1, big.data(), big.size(), reliable(), nullptr, rig.net.now());
                            e.send(rig.net.mac(b), 1, small.data(), small.size(), reliable(), nullptr,
                                   rig.net.now());
                            e.send(Mac::broadcast(), 1, small.data(), small.size(), SendOptions(), nullptr,
                                   rig.net.now());
                        }
                    });
                    rig.net.run(300);
                }
                rig.net.run(2500);
            }
            CHECK(rig.sendWait(a, b, 1, big, reliable()) == Status::Ok);
            CHECK(inbox.meta.back().authenticated);
        }
        CHECK_EQ(testing::heapUsed(), before);
    }
}

TEST(heap_discovery_survives_any_heap_size) {
    for (size_t above = 0; above <= kHeapSweepMax; above += kHeapSweepStep) {
        size_t before = testing::heapUsed();
        {
            testing::HeapExempt test;
            DiscoveryRig rig;
            DiscoveryConfig cfg;
            cfg.announceIntervalMs = 300;
            cfg.peerTimeoutMs = 1000;
            for (int i = 0; i < 4; ++i) {
                cfg.metadata = pattern(40 + 30 * static_cast<size_t>(i), static_cast<uint32_t>(i));
                rig.add("a node with a long name " + std::to_string(i), cfg);  // past std::string's own buffer
            }
            auto drive = [&](uint32_t ms) {
                for (uint32_t t = 0; t < ms; ++t) {
                    rig.net.step();
                    counted([&] {
                        for (auto& d : rig.nodes) d->tick(rig.net.now());
                    });
                }
            };
            {
                testing::HeapLimit limit(above);
                // start() and stop() are the application's set-up, not counted;
                // what the others do on hearing them is.
                for (auto& d : rig.nodes) d->start(rig.net.now());
                drive(1500);
                uint8_t meta[100] = {9};
                rig.nodes[1]->setMetadata(meta, sizeof(meta), rig.net.now());
                rig.nodes[2]->stop(rig.net.now());
                drive(500);
                rig.nodes[2]->start(rig.net.now());
                drive(1500);
            }
            drive(1500);
            for (auto& d : rig.nodes) CHECK_EQ(d->peers().size(), 3u);
        }
        CHECK_EQ(testing::heapUsed(), before);
    }
}

// The responder answers whatever a peer asks; the procedures are the
// application's (not counted), but what they do on received frames is.
TEST(heap_diagnostics_survives_any_heap_size) {
    for (size_t above = 0; above <= kHeapSweepMax; above += kHeapSweepStep) {
        size_t before = testing::heapUsed();
        {
            testing::HeapExempt test;
            DiagRig rig;
            size_t a = rig.add(), b = rig.add();
            rig.startDiscovery();
            std::vector<ProbeStep> steps = {ProbeStep(PhyRate::B1M, 0), ProbeStep(PhyRate::G24M, 15)};
            {
                testing::HeapLimit limit(above);
                std::vector<ProbeResult> fwd, rev;
                rig.diag[a]->ping(rig.net.mac(b));
                rig.diag[a]->measure(rig.net.mac(b), steps, 5, &fwd, &rev);
                rig.net.run(500);
            }
            CHECK(rig.diag[a]->ping(rig.net.mac(b)) == Status::Ok);
            std::vector<ProbeResult> fwd, rev;
            CHECK(rig.diag[a]->measure(rig.net.mac(b), steps, 5, &fwd, &rev) == Status::Ok);
            CHECK_EQ(rev.size(), 2u);
            CHECK_EQ(rev[0].received, 5);
            // The responder's radio is back to normal.
            CHECK(rig.net.node(b).radio.bcast == PhyRate::Default);
            CHECK(rig.net.node(b).radio.power == 20.0f);
        }
        CHECK_EQ(testing::heapUsed(), before);
    }
}

TEST(heap_streams_survive_any_heap_size) {
    std::vector<uint8_t> data = pattern(30000, 4);
    auto reader = [&](uint32_t offset, uint8_t* buf, size_t n) {
        memcpy(buf, data.data() + offset, n);
        return true;
    };
    StreamOptions o;
    o.chunkSize = 2000;
    o.window = 3;  // chunks arrive early and are held
    o.header = pattern(50);
    o.progress = [](uint32_t, uint32_t) {};
    for (size_t above = 0; above <= kHeapSweepMax; above += kHeapSweepStep) {
        size_t before = testing::heapUsed();
        {
            testing::HeapExempt test;
            StreamRig rig;
            rig.net.airLoss = 0.03;
            rig.net.appLoss = 0.05;  // a chunk left incomplete while the next one completes
            size_t a = rig.add(), b = rig.add();
            {
                testing::HeapLimit limit(above);
                Received& r = rig.receiver();
                rig.st[b]->onIncoming(collectInto(r));
                Outcome& out = rig.outcome();
                rig.st[a]->send(rig.net.mac(b), static_cast<uint32_t>(data.size()), reader, out.handler(), o,
                                rig.net.now());
                rig.net.runUntil([&] { return out.done; }, 20000);
            }
            Received& r = rig.receiver();
            rig.st[b]->onIncoming(collectInto(r));
            Outcome& out = rig.outcome();
            CHECK(rig.st[a]->send(rig.net.mac(b), static_cast<uint32_t>(data.size()), reader, out.handler(), o,
                                  rig.net.now()) == Status::Ok);
            CHECK(rig.net.runUntil([&] { return out.done; }, 60000));
            CHECK(out.status == Status::Ok);
            CHECK(r.data == data);
        }
        CHECK_EQ(testing::heapUsed(), before);
    }
}

// NOWTP_HEAP_SWEEP=1: runs each test at several heap limits, counting only
// what NowTP takes while the simulator drives it (received frames, sent
// frames, ticks), and prints every distinct place where operator new went
// past the limit: on ESP-IDF, each would abort. Checks failing for lack of
// memory are expected there and not reported.
namespace sweep {

constexpr int kDepth = 24;
constexpr size_t kMaxSites = 64;
size_t g_sites[kMaxSites];
size_t g_siteCount = 0;
size_t g_overruns = 0;

bool startsWith(const char* s, const char* prefix) { return std::strncmp(s, prefix, std::strlen(prefix)) == 0; }

// The innermost caller outside the standard library is NowTP's own code, not
// the test's or the simulator's (an application's handler allocating is its
// own business). Unknown without symbols: reported.
bool nowtpSite(void* const* frames, int n) {
    for (int i = 2; i < n; ++i) {
        Dl_info info;
        if (!dladdr(frames[i], &info) || !info.dli_sname) return true;
        const char* s = info.dli_sname;
        if (*s == '_' && startsWith(s + 1, "_Z")) ++s;  // Mach-O's extra underscore
        if (startsWith(s, "_ZNSt") || startsWith(s, "_ZNKSt") || startsWith(s, "_ZSt") || startsWith(s, "_Znw") ||
            startsWith(s, "_Zna") || startsWith(s, "_ZN5nowtp7testing")) {
            continue;
        }
        return startsWith(s, "_ZN5nowtp") || startsWith(s, "_ZNK5nowtp") || startsWith(s, "_ZZN5nowtp") ||
               startsWith(s, "_ZZNK5nowtp");
    }
    return true;
}

void exceeded(size_t bytes, size_t used, size_t limit) {
    void* frames[kDepth];
    int n = backtrace(frames, kDepth);
    if (!nowtpSite(frames, n)) return;
    g_overruns++;
    size_t h = 1469598103934665603ull;
    for (int i = 2; i < n; ++i) h = (h ^ reinterpret_cast<size_t>(frames[i])) * 1099511628211ull;
    for (size_t i = 0; i < g_siteCount; ++i) {
        if (g_sites[i] == h) return;
    }
    if (g_siteCount < kMaxSites) g_sites[g_siteCount++] = h;
    std::fprintf(stderr, "  operator new(%zu) past the limit (%zu held of %zu):\n", bytes, used, limit);
    backtrace_symbols_fd(frames + 2, n - 2, 2);
}

int run(const char* filter) {
    void* warm[1];
    backtrace(warm, 1);  // loads what backtrace() needs before any limit
    testing::onExceeded(exceeded);
    for (const TestCase& t : registry()) {
        if (filter && std::strstr(t.name, filter) == nullptr) continue;
        size_t before = g_overruns;
        for (size_t above : {0, 128, 512, 2048, 8192, 32768}) {
            testing::HeapExempt test;  // only the simulator counts, while it drives NowTP
            testing::HeapLimit limit(above);
            t.fn();
        }
        std::printf("[%s] %s: %zu operator new past the limit\n", g_overruns == before ? " OK " : "NEW ", t.name,
                    g_overruns - before);
    }
    std::printf("\n%zu distinct sites\n", g_siteCount);
    return g_siteCount == 0 ? 0 : 1;
}

}  // namespace sweep

int main(int argc, char** argv) {
    const char* filter = argc > 1 ? argv[1] : nullptr;
    if (std::getenv("NOWTP_HEAP_SWEEP")) return sweep::run(filter);
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
