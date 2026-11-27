// Host-side tests for the NowTP protocol engine: reliable and latest-only delivery.

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

// Messages without a handler of their own report to their port's observer,
// with their tag: one stored callback instead of a std::function per send.
TEST(completion_observer_reports_tagged_messages) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    std::vector<std::pair<uint32_t, Status>> reported;
    net.engine(a).observeCompletions(1, [&](uint32_t tag, Status st) {
        testing::HeapExempt app;
        reported.push_back(std::make_pair(tag, st));
    });
    Mac absent = {{0x02, 0x77, 0, 0, 0, 1}};
    auto msg = pattern(600);
    SendOptions o = reliable();
    o.timeoutMs = 400;
    o.tag = 7;
    CHECK(net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), o, nullptr, net.now()) == Status::Ok);
    o.tag = 8;
    CHECK(net.engine(a).send(absent, 1, msg.data(), msg.size(), o, nullptr, net.now()) == Status::Ok);
    Outcome own;  // its own handler: not reported to the observer
    o.tag = 9;
    CHECK(net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), o, own.handler(), net.now()) == Status::Ok);
    o.tag = 10;  // another port, no observer: unreported
    CHECK(net.engine(a).send(net.mac(b), 2, msg.data(), msg.size(), o, nullptr, net.now()) == Status::Ok);
    CHECK(net.runUntil([&] { return reported.size() == 2 && own.done; }));
    net.run(500);
    CHECK_EQ(reported.size(), 2u);
    std::sort(reported.begin(), reported.end());
    CHECK(reported[0] == std::make_pair(7u, Status::Ok));
    CHECK(reported[1].first == 8u && reported[1].second != Status::Ok);  // nobody there
    CHECK(own.status == Status::Ok);

    net.engine(a).observeCompletions(1, CompletionObserver());
    o.tag = 11;
    CHECK(net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), o, nullptr, net.now()) == Status::Ok);
    net.run(200);
    CHECK_EQ(reported.size(), 2u);
    CHECK_EQ(inbox.messages.size(), 3u);
}

// A sender's last ~128 ids, whatever other senders deliver meanwhile.
TEST(duplicate_filter_windows_per_sender) {
    Mac a = {{2, 0, 0, 0, 0, 1}}, b = {{2, 0, 0, 0, 0, 2}};
    uint32_t t = sim::clockStart();
    DuplicateFilter f(2, 5000);
    for (uint16_t id = 0; id < 128; ++id) f.mark(a, id, t);
    for (uint16_t id = 0; id < 1000; ++id) f.mark(b, id, t);  // b's traffic doesn't push a's out
    bool all = true;
    for (uint16_t id = 0; id < 128; ++id) all = all && f.seen(a, id, t);
    CHECK(all);
    CHECK(!f.seen(a, 200, t));
    CHECK(f.seen(b, 999, t) && !f.seen(b, 800, t));  // b's window moved on
    f.mark(a, 128, t);  // a new block: the oldest (ids 0-31) goes
    CHECK(!f.seen(a, 0, t) && !f.seen(a, 31, t) && f.seen(a, 32, t) && f.seen(a, 128, t));
    f.mark(a, 5, t);  // older than the window: not recorded
    CHECK(!f.seen(a, 5, t));

    // Ids wrap.
    DuplicateFilter w(1, 5000);
    w.mark(a, 0xFFFE, t);
    w.mark(a, 0x0001, t);
    CHECK(w.seen(a, 0xFFFE, t) && w.seen(a, 0x0001, t) && !w.seen(a, 0xFFFF, t));

    // Remembered for ttlMs, a block from its last delivery.
    CHECK(f.seen(a, 128, t + 4999));
    CHECK(!f.seen(a, 128, t + 5000));

    // Full: the sender that delivered least recently gives way.
    Mac c = {{2, 0, 0, 0, 0, 3}};
    f.mark(b, 1000, t + 10);
    f.mark(a, 129, t + 20);
    f.mark(c, 7, t + 30);
    CHECK_EQ(f.senders(), 2u);
    CHECK(f.seen(c, 7, t + 30) && f.seen(a, 129, t + 30) && !f.seen(b, 1000, t + 30));
}

// Receiver credit on the sending side: a word holds until it expires, a
// message started spends room, and the book never grows past its capacity.
TEST(credit_book_holds_messages_a_receiver_has_no_room_for) {
    Mac a = {{2, 0, 0, 0, 0, 1}}, b = {{2, 0, 0, 0, 0, 2}}, c = {{2, 0, 0, 0, 0, 3}};
    uint32_t t = sim::clockStart();
    CreditBook book(2, 301);
    size_t need = CreditBook::need(3, 1461);  // a 3-fragment message
    CHECK_EQ(need, 3u * 1461u + 1u);
    CHECK(!book.waits(a, need, t));  // no word: go
    book.note(a, 20, t);             // 5120 bytes of room
    CHECK(!book.waits(a, need, t));
    book.spend(a, need);  // 5120 - 4384 = 736 left
    uint32_t until = 0;
    CHECK(book.waits(a, need, t + 10, &until));
    CHECK_EQ(until, t + 301);
    CHECK(!book.waits(a, need, t + 301));  // the word expired: probe
    book.note(a, wire::kCreditMax, t);     // plenty, whatever is spent
    book.spend(a, 100000);
    CHECK(!book.waits(a, need, t));
    book.note(b, 0, t + 1);
    CHECK(book.waits(b, 1, t + 1));
    book.note(c, 0, t + 2);  // full: a's word, the oldest, goes
    CHECK_EQ(book.size(), 2u);
    CHECK(book.waits(c, 1, t + 2) && book.waits(b, 1, t + 2));
    book.expire(t + 302);
    CHECK_EQ(book.size(), 1u);  // b's expired, c's holds a moment longer
    book.expire(t + 303);
    CHECK_EQ(book.size(), 0u);
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

// A receiver that has no room says so in its acks: the sender's next messages
// wait instead of each sending a fragment only to be refused.
TEST(receiver_credit_holds_messages_a_full_receiver_refuses) {
    struct Run {
        uint32_t framesSent, creditWaits, receiverBusy, ms;
    };
    auto run = [](bool senderCredit, bool receiverCredit, Run& r) {
        sim::Network net;
        Config tx, rx;
        tx.receiverCredit = senderCredit;
        rx.receiverCredit = receiverCredit;
        rx.maxRxMessages = 1;  // room for one message at a time
        size_t recv = net.addNode(rx);
        std::vector<size_t> senders = {net.addNode(tx), net.addNode(tx), net.addNode(tx)};
        Inbox inbox;
        net.engine(recv).listen(1, inbox.handler());
        std::vector<Outcome> outs(4 * senders.size());
        for (size_t i = 0; i < outs.size(); ++i) {
            auto msg = pattern(2000, static_cast<uint32_t>(i));
            CHECK(net.engine(senders[i % senders.size()])
                      .send(net.mac(recv), 1, msg.data(), msg.size(), reliable(), outs[i].handler(), net.now()) ==
                  Status::Ok);
        }
        CHECK(net.runUntil([&] {
            for (auto& o : outs) {
                if (!o.done) return false;
            }
            return true;
        }));
        for (auto& o : outs) CHECK(o.status == Status::Ok);
        CHECK_EQ(inbox.messages.size(), outs.size());
        r = Run{0, 0, 0, net.now()};
        for (size_t s : senders) {
            const Stats& st = net.engine(s).stats();
            r.framesSent += st.framesSent;
            r.creditWaits += st.creditWaits;
            r.receiverBusy += st.receiverBusy;
        }
    };
    Run with = {}, without = {}, oldReceiver = {}, oldSender = {};
    run(true, true, with);
    run(false, false, without);
    run(true, false, oldReceiver);  // acks without credit: nothing waits
    run(false, true, oldSender);    // ignores the credit
    std::printf("    with credit: %u frames, %u busy, %u waits, %u ms; without: %u frames, %u busy, %u ms\n",
                with.framesSent, with.receiverBusy, with.creditWaits, with.ms, without.framesSent,
                without.receiverBusy, without.ms);
    CHECK(with.creditWaits > 0u);
    CHECK(with.receiverBusy * 2 < without.receiverBusy);
    CHECK(with.framesSent < without.framesSent);
    CHECK_EQ(without.creditWaits, 0u);
    CHECK_EQ(oldReceiver.creditWaits, 0u);
    CHECK_EQ(oldReceiver.framesSent, without.framesSent);
    CHECK_EQ(oldSender.framesSent, without.framesSent);
}

// The credit byte ends the ack, after missing fragments listed two bytes each:
// a sender reading only those pairs, as older ones do, never sees it.
TEST(receiver_credit_is_invisible_to_older_senders) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    Inbox inbox;
    net.engine(b).listen(1, inbox.handler());
    uint32_t t0 = net.now();
    net.dropIf = [&](const sim::Frame& f) {
        wire::Header h;
        size_t off;
        return f.from == a && wire::decodeHeader(f.data.data(), f.data.size(), h, off) &&
               h.type == wire::Type::Fragment && (h.index == 2 || h.index == 5) && net.now() - t0 < 50;
    };
    Outcome out;
    auto msg = pattern(2000);
    net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), reliable(), out.handler(), net.now());
    CHECK(net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Ok);
    bool sawMissing = false;
    for (const sim::Frame& frame : net.log) {
        wire::Header h;
        size_t off;
        if (frame.from != b || !wire::decodeHeader(frame.data.data(), frame.data.size(), h, off) ||
            h.type != wire::Type::Ack) {
            continue;
        }
        const std::vector<uint8_t>& f = frame.data;
        CHECK(h.flags & wire::kFlagCredit);
        const uint8_t* p = f.data() + wire::kCommonHeaderSize;
        size_t len = f.size() - wire::kCommonHeaderSize;
        if (p[0] != static_cast<uint8_t>(wire::AckStatus::Missing)) continue;
        sawMissing = true;
        std::vector<uint16_t> old;  // the loop older senders run
        for (size_t i = 1; i + 1 < len; i += 2) old.push_back(wire::getU16(p + i));
        CHECK(old == (std::vector<uint16_t>{2, 5}));
        CHECK(p[len - 1] > 0);  // room for more
    }
    CHECK(sawMissing);
}

// Credit is spent when a message's first frame is delivered: one lost at the
// MAC level goes again at once, instead of waiting for the credit to expire.
TEST(receiver_credit_is_spent_by_delivered_frames) {
    SizedLink link;
    Mac b = {{0x02, 0, 0, 0, 0, 3}};
    uint32_t t = sim::clockStart();
    Engine e(link, Config(), 0);
    auto small = pattern(10), big = pattern(1000);
    CHECK(e.send(b, 1, small.data(), small.size(), reliable(), nullptr, t) == Status::Ok);
    e.onFrameSent(true, t + 1);
    uint8_t ack[8];
    wire::Header h;
    h.type = wire::Type::Ack;
    h.flags = wire::kFlagCredit;
    h.port = 1;
    h.messageId = 0;
    size_t n = wire::encodeHeader(h, ack);
    ack[n++] = static_cast<uint8_t>(wire::AckStatus::Complete);
    ack[n++] = 5;  // room for 1280 bytes
    e.onFrameReceived(b, ack, n, t + 2);
    CHECK(e.send(b, 1, big.data(), big.size(), reliable(), nullptr, t + 3) == Status::Ok);  // 5 frames: it fits
    CHECK_EQ(link.sent.size(), 2u);
    e.onFrameSent(false, t + 4);  // its first frame fails
    for (uint32_t dt = 5; dt < 20 && link.sent.size() < 3; ++dt) e.tick(t + dt);
    CHECK_EQ(link.sent.size(), 3u);
    wire::Header first;
    size_t off;
    CHECK(wire::decodeHeader(link.sent[2].data(), link.sent[2].size(), first, off) && first.index == 0);
    CHECK_EQ(e.stats().creditWaits, 0u);
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

TEST(handlers_stamp_with_the_events_time) {
    // Services timestamp what a message does with the engine's time, not
    // their last tick(), which a poller may have run long before.
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    DiscoveryConfig cfg;
    Discovery da(net.engine(a), cfg, 250, [] { return 0u; });
    Discovery db(net.engine(b), cfg, 250, [] { return 0u; });
    da.start(net.now());  // never ticked again
    db.start(net.now());
    net.tickers.push_back([&](uint32_t now) { db.tick(now); });
    net.run(5000);
    const PeerInfo* p = da.find(net.mac(b));
    CHECK(p != nullptr);
    CHECK(p && static_cast<int32_t>(net.now() - p->lastSeenMs) < static_cast<int32_t>(cfg.announceIntervalMs * 2));
}
