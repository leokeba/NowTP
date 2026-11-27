// Host-side tests for the NowTP protocol engine: wire format.

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
    uint32_t t0 = net.now();
    net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), reliable(), out.handler(), net.now());
    CHECK(net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Rejected);  // not Busy until the deadline
    CHECK(net.now() - t0 < 100u);
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

// Found by fuzz_frames: an ack is sized for its destination when queued too,
// and waits behind the frame in flight. A long "missing" list built for
// 1470-byte frames then went out to a peer back to 250 (lost, or announced
// again smaller), which can't receive it. Such an ack is dropped now; the
// sender's next probe gets one of the current size.
TEST(frame_size_shrinking_under_a_queued_ack) {
    struct CheckedLink : SizedLink {
        size_t tooLarge = 0;
        std::vector<Mac> to;
        Status sendFrame(const Mac& dst, const uint8_t* data, size_t len) override {
            if (len > maxFrameSize(dst)) tooLarge++;
            to.push_back(dst);
            return SizedLink::sendFrame(dst, data, len);
        }
    };
    CheckedLink link;
    Engine e(link);
    Inbox inbox;
    e.listen(1, inbox.handler());
    uint32_t now = sim::clockStart();
    Mac other = {{0x02, 0, 0, 0, 0, 1}};
    auto small = pattern(10);
    CHECK(e.send(other, 1, small.data(), small.size(), SendOptions(), nullptr, now) == Status::Ok);  // in flight

    // The last of 200 fragments, asking for an ack: 199 are missing.
    auto lastFragment = [&] {
        wire::Header h;
        h.type = wire::Type::Fragment;
        h.flags = wire::kFlagReliable | wire::kFlagAckRequest;
        h.port = 1;
        h.messageId = 77;
        h.index = 199;
        h.count = 200;
        std::vector<uint8_t> f(wire::kFragmentHeaderSize + 10, 0xAB);
        wire::encodeHeader(h, f.data());
        return f;
    };
    auto f = lastFragment();
    e.onFrameReceived(link.wide, f.data(), f.size(), now + 1);
    CHECK_EQ(link.sent.size(), 1u);  // the ack waits behind the frame in flight

    link.wideSize = 250;
    e.onFrameSent(true, now + 2);
    e.tick(now + 3);
    CHECK_EQ(link.tooLarge, 0u);

    // The sender's probe: an ack within 250 bytes, as many missing as fit.
    e.onFrameReceived(link.wide, f.data(), f.size(), now + 200);
    e.tick(now + 201);
    CHECK_EQ(link.tooLarge, 0u);
    CHECK(link.to.back() == link.wide);
    const std::vector<uint8_t>& ack = link.sent.back();
    wire::Header h;
    size_t off = 0;
    CHECK(wire::decodeHeader(ack.data(), ack.size(), h, off) && h.type == wire::Type::Ack && h.messageId == 77);
    CHECK_EQ(ack[off], static_cast<uint8_t>(wire::AckStatus::Missing));
    CHECK(ack.size() <= 250u && ack.size() >= 240u);
}

// A message is cut for its destination's frame size when queued, which may
// shrink before it has all gone out (a peer lost, or announced again
// smaller). A 1205-byte frame once went into a 250-byte buffer; then such
// messages went out too big and timed out. Now they are cut again, under a
// new id if a frame of the old cut went out.
TEST(frame_size_shrinking_under_a_queued_message) {
    for (size_t size : {1200, 3000}) {
        for (bool started : {false, true}) {
            if (started && size < 1465) continue;  // one frame: nothing left to cut
            SizedLink link, rxLink;
            Mac narrow = {{0x02, 0, 0, 0, 0, 1}}, src = {{0x02, 0, 0, 0, 0, 9}};
            Engine e(link), receiver(rxLink);
            Inbox inbox;
            receiver.listen(1, inbox.handler());
            uint32_t now = sim::clockStart();
            auto small = pattern(10), big = pattern(size);
            CHECK(e.send(narrow, 1, small.data(), small.size(), SendOptions(), nullptr, now) == Status::Ok);
            Outcome out;
            CHECK(e.send(link.wide, 1, big.data(), big.size(), SendOptions(), out.handler(), now) == Status::Ok);
            if (started) {
                e.onFrameSent(true, now + 1);
                CHECK_EQ(link.sent.back().size(), 1470u);  // the first of the old cut
            }
            link.wideSize = 250;
            for (uint32_t t = 2; t < 40 && !out.done; ++t) e.onFrameSent(true, now + t);
            CHECK(out.done && out.status == Status::Ok);
            CHECK_EQ(e.stats().messagesRecut, 1u);
            for (size_t i = 1; i < link.sent.size(); ++i) {
                if (!(started && i == 1)) CHECK(link.sent[i].size() <= 250u);
                receiver.onFrameReceived(src, link.sent[i].data(), link.sent[i].size(), now + 40);
            }
            CHECK_EQ(inbox.messages.size(), 1u);
            CHECK(!inbox.messages.empty() && inbox.messages.back() == big);
        }
    }
}

// ---------------------------------------------------------------------------
// Discovery
// Frame sizes follow discovery's peer events: negotiated with a peer found
// (the smaller of both maxima, above the default), back to the default when
// it is lost, and a size given to addPeer() wins over both.
TEST(frame_sizes_follow_peer_events) {
    DiscoveryRig rig;
    DiscoveryConfig dc;
    dc.peerTimeoutMs = 3000;
    size_t a = rig.add("a", dc, 1470), wide = rig.add("wide", dc, 1470), mid = rig.add("mid", dc, 800),
           narrow = rig.add("narrow", dc, 250);
    FrameSizes sizes(250, 1470, true);
    sizes.setDiscovery(rig.nodes[a].get());
    rig.net.node(a).link.sizeFor = [&](const Mac& dst) { return sizes.sizeFor(dst); };
    Mac w = rig.net.mac(wide), m = rig.net.mac(mid), n = rig.net.mac(narrow);
    CHECK_EQ(sizes.sizeFor(w), 250u);  // not discovered yet
    for (auto& d : rig.nodes) d->start(rig.net.now());
    rig.run(200);
    CHECK_EQ(sizes.sizeFor(w), 1470u);
    CHECK_EQ(sizes.sizeFor(m), 800u);
    CHECK_EQ(sizes.sizeFor(n), 250u);
    CHECK_EQ(sizes.sizeFor(Mac::broadcast()), 250u);

    // A message to `wide` goes in 1470-byte frames.
    auto big = pattern(3000);
    size_t logged = rig.net.log.size();
    CHECK(rig.net.engine(a).send(w, 1, big.data(), big.size(), SendOptions(), nullptr, rig.net.now()) == Status::Ok);
    rig.run(50);
    size_t largest = 0;
    for (size_t i = logged; i < rig.net.log.size(); ++i) {
        if (rig.net.log[i].from == a && rig.net.log[i].dst == w) largest = std::max(largest, rig.net.log[i].data.size());
    }
    CHECK_EQ(largest, 1470u);

    sizes.set(n, 600);  // addPeer(narrow, 600)
    sizes.set(w, 400);
    CHECK_EQ(sizes.sizeFor(n), 600u);
    CHECK_EQ(sizes.sizeFor(w), 400u);
    sizes.set(w, 0);  // addPeer(wide) without a size: back to what discovery says
    CHECK_EQ(sizes.sizeFor(w), 1470u);

    rig.nodes[wide]->stop(rig.net.now());  // says goodbye: Lost
    rig.run(50);
    CHECK_EQ(rig.count(a, PeerEvent::Lost), 1u);
    CHECK_EQ(sizes.sizeFor(w), 250u);
    CHECK_EQ(sizes.sizeFor(n), 600u);

    FrameSizes fixed(250, 1470, false);  // negotiateFrameSize = false
    fixed.setDiscovery(rig.nodes[a].get());
    CHECK_EQ(fixed.sizeFor(m), 250u);
}
