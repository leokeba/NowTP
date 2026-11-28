// Host-side tests for the NowTP protocol engine: streams, gates, deadlines and heap sweeps.

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
        net.tickers.push_back(
            sim::Ticker([this, i](uint32_t now) { st[i]->tick(now); }, [this, i](Deadline& d) { st[i]->nextTick(d); }, i));
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

// ---------------------------------------------------------------------------
// Streams
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

// An offer whose chunk is near 2^32 is refused as too large on every
// architecture: `chunk + kDataHeader` in a 32-bit size_t (the ESP32) wrapped to
// a small sum and accepted it.
TEST(stream_offer_chunk_near_2pow32) {
    StreamRig rig;
    size_t a = rig.add(), b = rig.add();
    Received& r = rig.receiver();
    rig.st[a]->onIncoming(collectInto(r));

    const uint32_t id = 0x42;
    std::vector<uint8_t> offer(15);
    offer[0] = 1;  // kOffer
    wire::putU32(offer.data() + 1, id);
    wire::putU32(offer.data() + 5, 100);
    wire::putU32(offer.data() + 9, 0xFFFFFFF7u);  // chunk: wraps with kDataHeader on 32-bit
    offer[14] = 1;  // window

    auto frameOf = [](uint16_t messageId, const std::vector<uint8_t>& payload) {
        wire::Header h;
        h.port = kStreamPort;
        h.messageId = messageId;
        std::vector<uint8_t> f(wire::kCommonHeaderSize + payload.size());
        size_t off = wire::encodeHeader(h, f.data());
        memcpy(f.data() + off, payload.data(), payload.size());
        return f;
    };
    auto dataAt = [&](uint32_t offset, uint32_t n) {
        std::vector<uint8_t> d(9 + n);
        d[0] = 4;  // kData
        wire::putU32(d.data() + 1, id);
        wire::putU32(d.data() + 5, offset);
        for (uint32_t i = 0; i < n; ++i) d[9 + i] = static_cast<uint8_t>(offset + i);
        return d;
    };
    auto countFromA = [&](uint8_t type) {
        int n = 0;
        for (const sim::Frame& f : rig.net.log) {
            if (f.from != a) continue;
            wire::Header h;
            size_t off;
            if (!wire::decodeHeader(f.data.data(), f.data.size(), h, off)) continue;
            if (h.port == kStreamPort && f.data[off] == type) n++;
        }
        return n;
    };

    rig.net.inject(a, rig.net.mac(b), frameOf(9, offer));
    rig.net.run(2);

    CHECK_EQ(rig.st[a]->incoming(), 0u);
    CHECK_EQ(countFromA(3), 1);  // kReject
    rig.net.inject(a, rig.net.mac(b), frameOf(10, dataAt(0, 10)));
    rig.net.run(2);
    CHECK_EQ(countFromA(7), 1);  // kAbort
    CHECK(r.data.empty());
}

// The end message is a step like the chunks: it can fail (the receiver went
// away, or stopped listening) and be retried until the sender gives up.
TEST(stream_sender_gives_up_on_the_end) {
    for (int variant = 0; variant < 2; ++variant) {
        StreamRig rig;
        size_t a = rig.add(), b = rig.add();
        std::vector<uint8_t> data = pattern(4096, 7);
        Received& r = rig.receiver();
        rig.st[b]->onIncoming(collectInto(r));
        Outcome& out = rig.outcome();
        StreamOptions o;
        o.chunkSize = 1024;
        o.timeoutMs = 200;  // each failed end message reports quickly
        o.progress = [&](uint32_t done, uint32_t) {
            if (done != data.size()) return;  // everything acknowledged: the end goes out now
            if (variant == 0) rig.net.node(b).online = false;  // it vanishes
            else rig.st[b]->stop();  // or stops listening for streams
        };
        CHECK(rig.st[a]->send(rig.net.mac(b), static_cast<uint32_t>(data.size()),
                              [&](uint32_t offset, uint8_t* buf, size_t n) {
                                  memcpy(buf, data.data() + offset, n);
                                  return true;
                              },
                              out.handler(), o, rig.net.now()) == Status::Ok);
        CHECK(rig.net.runUntil([&] { return out.done; }, 30000));
        auto countEnds = [&] {
            int n = 0;
            for (const sim::Frame& f : rig.net.log) {
                if (f.from != a) continue;
                wire::Header h;
                size_t off;
                if (!wire::decodeHeader(f.data.data(), f.data.size(), h, off)) continue;
                if (h.port == kStreamPort && f.data[off] == 5) n++;  // kEnd
            }
            return n;
        };
        CHECK(r.data == data);
        CHECK_EQ(rig.st[a]->outgoing(), 0u);
        if (variant == 0) {
            CHECK(out.status == Status::Timeout);
            CHECK(countEnds() >= 5);  // one end message per attempt, each retried on air
            CHECK(!r.done);
            CHECK(rig.net.runUntil([&] { return r.done; }, 40000));  // the receiver's idle timeout
            CHECK(r.status == Status::Timeout);
        } else {
            CHECK(out.status == Status::Rejected);
            CHECK_EQ(countEnds(), 1);
            CHECK(r.done);
            CHECK(r.status == Status::Cancelled);
        }
        CHECK_EQ(rig.st[b]->incoming(), 0u);
    }
}

// A repeat offer for a stream we already accepted gets another accept, not an
// error: our first one may simply have been lost.
TEST(stream_offer_again_for_an_accepted_stream) {
    StreamRig rig;
    size_t a = rig.add(), b = rig.add();
    std::vector<uint8_t> data = pattern(16384, 9);
    Received& r = rig.receiver();
    rig.st[b]->onIncoming(collectInto(r));
    Outcome& out = rig.outcome();
    StreamOptions o;
    uint32_t id = 0;
    CHECK(rig.st[a]->send(rig.net.mac(b), static_cast<uint32_t>(data.size()),
                          [&](uint32_t offset, uint8_t* buf, size_t n) {
                              memcpy(buf, data.data() + offset, n);
                              return true;
                          },
                          out.handler(), o, rig.net.now(), &id) == Status::Ok);
    CHECK(rig.net.runUntil([&] { return r.data.size() > 0; }));

    // The same offer again, from the same peer, as if our accept had been lost.
    std::vector<uint8_t> offer(15);
    offer[0] = 1;  // kOffer
    wire::putU32(offer.data() + 1, id);
    wire::putU32(offer.data() + 5, data.size());
    wire::putU32(offer.data() + 9, o.chunkSize);
    offer[14] = o.window;
    wire::Header h;
    h.port = kStreamPort;
    h.messageId = 77;  // a's engine ids are far from this one here
    std::vector<uint8_t> frame(wire::kCommonHeaderSize + offer.size());
    size_t off = wire::encodeHeader(h, frame.data());
    memcpy(frame.data() + off, offer.data(), offer.size());
    rig.net.inject(b, rig.net.mac(a), frame);

    CHECK(rig.net.runUntil([&] { return out.done && r.done; }, 30000));
    CHECK(out.status == Status::Ok);
    CHECK(r.status == Status::Ok);
    CHECK(r.data == data);
    int accepts = 0;
    for (const sim::Frame& f : rig.net.log) {
        if (f.from != b) continue;
        wire::Header hh;
        size_t off2;
        if (!wire::decodeHeader(f.data.data(), f.data.size(), hh, off2)) continue;
        if (hh.port == kStreamPort && f.data[off2] == 2) accepts++;  // kAccept
    }
    CHECK_EQ(accepts, 2);  // the original and the answer to the repeat
    CHECK_EQ(rig.st[a]->outgoing(), 0u);
    CHECK_EQ(rig.st[b]->incoming(), 0u);
}

// A started receiver with no acceptor refuses the offer itself, as "refused",
// not with the engine's "no listener" rejection.
TEST(stream_offer_without_an_acceptor) {
    StreamRig rig;
    size_t a = rig.add(), b = rig.add();  // b is started, but never onIncoming()
    std::vector<uint8_t> data = pattern(1000);
    Received& r = rig.receiver();
    Outcome& out = rig.outcome();
    rig.st[a]->send(rig.net.mac(b), static_cast<uint32_t>(data.size()),
                    [&](uint32_t offset, uint8_t* buf, size_t n) {
                        memcpy(buf, data.data() + offset, n);
                        return true;
                    },
                    out.handler(), StreamOptions(), rig.net.now());
    CHECK(rig.net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Rejected);
    CHECK(!r.done);
    CHECK(r.data.empty());
    int refused = 0;
    for (const sim::Frame& f : rig.net.log) {
        if (f.from != b) continue;
        wire::Header h;
        size_t off;
        if (!wire::decodeHeader(f.data.data(), f.data.size(), h, off)) continue;
        if (h.port == kStreamPort && f.data[off] == 3 && f.data[off + 5] == 0) refused++;  // kReject, kRefused
    }
    CHECK_EQ(refused, 1);
    CHECK_EQ(rig.st[a]->outgoing(), 0u);
    CHECK_EQ(rig.st[b]->incoming(), 0u);
}

// A chunk that reaches the receiver while another task is still in its sink's
// write is refused (Busy), so the sender can send it again; the stream goes on.
TEST(stream_chunk_refused_while_the_sink_is_writing) {
    StreamRig rig;
    size_t a = rig.add(), b = rig.add();
    // Wide enough links that a chunk is one whole frame, so a copy of it
    // reaches the stream handler as a message rather than a lone fragment.
    rig.net.node(a).link.mtu = 2048;
    rig.net.node(b).link.mtu = 2048;
    std::vector<uint8_t> data = pattern(16384, 11);
    TestGate gate;
    rig.net.engine(b).setCallbackGate(&gate);
    Received& r = rig.receiver();
    StreamAcceptor accept = collectInto(r);
    uint32_t id = 0;
    bool foundFrame = false;
    rig.st[b]->onIncoming([&](const StreamInfo& info, StreamSink& sink) {
        bool ok = accept(info, sink);
        std::function<bool(uint32_t, const uint8_t*, size_t)> write = sink.write;
        sink.write = [&, write](uint32_t offset, const uint8_t* d, size_t n) {
            testing::HeapExempt app;
            if (offset == 0 && !gate.meanwhile) {
                gate.meanwhile = [&, offset] {
                    // The chunk being written is in flight: its frame is the
                    // newest data one from a. Deliver an exact copy of it now,
                    // under a fresh message id (a same-id copy would be a
                    // duplicate), while this write still runs.
                    for (auto it = rig.net.log.rbegin(); it != rig.net.log.rend(); ++it) {
                        if (it->from != a) continue;
                        wire::Header h;
                        size_t off;
                        if (!wire::decodeHeader(it->data.data(), it->data.size(), h, off)) continue;
                        if (h.port != kStreamPort || it->data[off] != 4) continue;  // kData
                        if (wire::getU32(it->data.data() + off + 1) != id) continue;
                        if (wire::getU32(it->data.data() + off + 5) != offset) continue;
                        h.messageId = 77;  // unused by a
                        std::vector<uint8_t> f(it->data.size());
                        size_t noff = wire::encodeHeader(h, f.data());
                        memcpy(f.data() + noff, it->data.data() + off, it->data.size() - off);
                        rig.net.inject(b, rig.net.mac(a), f);
                        foundFrame = true;
                        break;
                    }
                };
            }
            return write(offset, d, n);
        };
        return ok;
    });
    Outcome& out = rig.outcome();
    StreamOptions o;
    o.chunkSize = 1024;  // with the wide links above, one chunk is one frame
    CHECK(rig.st[a]->send(rig.net.mac(b), static_cast<uint32_t>(data.size()),
                          [&](uint32_t offset, uint8_t* buf, size_t n) {
                              memcpy(buf, data.data() + offset, n);
                              return true;
                          },
                          out.handler(), o, rig.net.now(), &id) == Status::Ok);
    CHECK(rig.net.runUntil([&] { return out.done && r.done; }, 30000));
    CHECK(foundFrame);
    CHECK(out.status == Status::Ok);
    CHECK(r.status == Status::Ok);
    CHECK(r.data == data);
    CHECK(rig.net.engine(b).stats().messagesRefused >= 1);
    CHECK_EQ(rig.st[a]->outgoing(), 0u);
    CHECK_EQ(rig.st[b]->incoming(), 0u);
}

// An end with bytes still missing is a failure, not an Ok: the receiver says
// "incomplete" and the sender reports Rejected. Here the last chunk was lost
// after its MAC ack, so the sender believed it delivered; confirming that one
// by hand lets the transfer reach its end.
TEST(stream_ends_with_bytes_missing) {
    StreamRig rig;
    size_t a = rig.add(), b = rig.add();
    std::vector<uint8_t> data = pattern(4096, 13);
    Received& r = rig.receiver();
    rig.st[b]->onIncoming(collectInto(r));
    StreamOptions o;
    o.chunkSize = 1024;  // four chunks
    uint16_t lostId = 0;  // the wire id of the last chunk, dropped after its MAC ack
    rig.net.dropIf = [&](const sim::Frame& f) {
        if (f.from != a) return false;
        wire::Header h;
        size_t off;
        if (!wire::decodeHeader(f.data.data(), f.data.size(), h, off)) return false;
        if (h.port != kStreamPort || f.data[off] != 4) return false;  // kData
        if (wire::getU32(f.data.data() + off + 5) != data.size() - o.chunkSize) return false;
        lostId = h.messageId;
        return true;
    };
    Outcome& out = rig.outcome();
    CHECK(rig.st[a]->send(rig.net.mac(b), static_cast<uint32_t>(data.size()),
                          [&](uint32_t offset, uint8_t* buf, size_t n) {
                              memcpy(buf, data.data() + offset, n);
                              return true;
                          },
                          out.handler(), o, rig.net.now()) == Status::Ok);
    CHECK(rig.net.runUntil([&] { return r.data.size() == data.size() - o.chunkSize && lostId != 0; }, 5000));

    wire::Header h;
    h.type = wire::Type::Ack;
    h.port = kStreamPort;
    h.messageId = lostId;
    std::vector<uint8_t> ack(wire::kCommonHeaderSize + 1);
    size_t off = wire::encodeHeader(h, ack.data());
    ack[off] = 0;  // Complete
    rig.net.inject(a, rig.net.mac(b), ack);

    CHECK(rig.net.runUntil([&] { return out.done && r.done; }, 30000));
    CHECK(out.status == Status::Rejected);
    CHECK(r.status == Status::Rejected);
    CHECK_EQ(r.data.size(), data.size() - o.chunkSize);
    int incomplete = 0, ends = 0;
    for (const sim::Frame& f : rig.net.log) {
        wire::Header hh;
        size_t off2;
        if (!wire::decodeHeader(f.data.data(), f.data.size(), hh, off2)) continue;
        if (hh.port != kStreamPort) continue;
        if (f.from == b && f.data[off2] == 6 && f.data[off2 + 5] == 2) incomplete++;  // kResult, kResultIncomplete
        if (f.from == a && f.data[off2] == 5) ends++;  // kEnd
    }
    CHECK_EQ(incomplete, 1);
    CHECK(ends >= 1);
    CHECK_EQ(rig.st[a]->outgoing(), 0u);
    CHECK_EQ(rig.st[b]->incoming(), 0u);
}

// A receiver whose heap can't hold a big window's reorder blocks refuses the
// offer as busy, before it has told the sender anything else.
TEST(stream_offer_refused_when_the_heap_cant_hold_its_blocks) {
    size_t before = testing::heapUsed();
    {
        testing::HeapExempt test;
        std::vector<uint8_t> data = pattern(20000, 13);
        StreamRig rig;
        size_t a = rig.add(), b = rig.add();
        Received& r = rig.receiver();
        rig.st[b]->onIncoming(collectInto(r));
        Outcome& out = rig.outcome();
        StreamOptions o;
        o.chunkSize = 100;
        o.window = 255;  // (window - 1) reorder blocks, more than the limit holds
        {
            testing::HeapLimit limit(1024);  // room for the offer's state, not its blocks
            CHECK(rig.st[a]->send(rig.net.mac(b), static_cast<uint32_t>(data.size()),
                                  [&](uint32_t offset, uint8_t* buf, size_t n) {
                                      memcpy(buf, data.data() + offset, n);
                                      return true;
                                  },
                                  out.handler(), o, rig.net.now()) == Status::Ok);
            CHECK(rig.net.runUntil([&] { return out.done; }, 30000));
        }
        CHECK(out.status == Status::Rejected);
        CHECK(!r.done);
        CHECK(r.data.empty());
        int busy = 0;
        for (const sim::Frame& f : rig.net.log) {
            if (f.from != b) continue;
            wire::Header h;
            size_t off;
            if (!wire::decodeHeader(f.data.data(), f.data.size(), h, off)) continue;
            if (h.port == kStreamPort && f.data[off] == 3 && f.data[off + 5] == 2) busy++;  // kReject, kBusy
        }
        CHECK_EQ(busy, 1);
        rig.net.run(100);  // let the rest settle
        CHECK_EQ(rig.st[a]->outgoing(), 0u);
        CHECK_EQ(rig.st[b]->incoming(), 0u);
    }
    CHECK_EQ(testing::heapUsed(), before);
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
    rig.net.tickers.push_back(sim::Ticker(
        [&](uint32_t now) {
            sa.tick(now);
            sb.tick(now);
        },
        [&](Deadline& d) {
            sa.nextTick(d);
            sb.nextTick(d);
        }));
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

// ---------------------------------------------------------------------------
// Application callbacks without the lock (CallbackGate)
TEST(gate_brackets_application_callbacks_only) {
    sim::Network net;
    size_t a = net.addNode(), b = net.addNode();
    TestGate ga, gb;
    net.engine(a).setCallbackGate(&ga);
    net.engine(b).setCallbackGate(&gb);
    int appRx = -1, serviceRx = -1, appDone = -1, serviceDone = -1;
    net.engine(b).listen(1, [&](const Message&) { appRx = gb.depth; });
    net.engine(b).listen(kStreamPort, [&](const Message&) { serviceRx = gb.depth; });
    auto msg = pattern(600);
    net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), reliable(), [&](Status) { appDone = ga.depth; },
                       net.now());
    net.engine(a).send(net.mac(b), kStreamPort, msg.data(), msg.size(), reliable(),
                       [&](Status) { serviceDone = ga.depth; }, net.now());
    CHECK(net.runUntil([&] { return appDone >= 0 && serviceDone >= 0; }));
    CHECK_EQ(appRx, 1);
    CHECK_EQ(appDone, 1);
    CHECK_EQ(serviceRx, 0);  // NowTP's own services keep the lock
    CHECK_EQ(serviceDone, 0);
}

TEST(stream_survives_being_finished_while_callbacks_run) {
    std::vector<uint8_t> data = pattern(40000, 5);
    // Sender: another task cancels the stream while the reader runs, or pumps it.
    for (int variant = 0; variant < 2; ++variant) {
        StreamRig rig;
        size_t a = rig.add(), b = rig.add();
        TestGate gate;
        rig.net.engine(a).setCallbackGate(&gate);
        Received& r = rig.receiver();
        rig.st[b]->onIncoming(collectInto(r));
        Outcome& out = rig.outcome();
        uint32_t id = 0, reads = 0, next = 0;
        bool inOrder = true;
        auto reader = [&](uint32_t offset, uint8_t* buf, size_t n) {
            inOrder = inOrder && offset == next;
            next = offset + static_cast<uint32_t>(n);
            memcpy(buf, data.data() + offset, n);
            if (++reads == 3) {
                gate.meanwhile = [&, variant] {
                    if (variant == 0) {
                        rig.st[a]->cancel(id, rig.net.now());
                    } else {
                        rig.st[a]->tick(rig.net.now());  // must not read again meanwhile
                    }
                };
            }
            return true;
        };
        CHECK(rig.st[a]->send(rig.net.mac(b), static_cast<uint32_t>(data.size()), reader, out.handler(),
                              StreamOptions(), rig.net.now(), &id) == Status::Ok);
        CHECK(rig.net.runUntil([&] { return out.done; }, 30000));
        CHECK(inOrder);
        if (variant == 0) {
            CHECK(out.status == Status::Cancelled);
        } else {
            CHECK(out.status == Status::Ok);
            CHECK(r.data == data);
        }
        CHECK_EQ(rig.st[a]->outgoing(), 0u);
    }

    // Receiver: another task stops streams (ends the transport) while the sink
    // writes, and while the acceptor decides.
    for (int variant = 0; variant < 2; ++variant) {
        StreamRig rig;
        size_t a = rig.add(), b = rig.add();
        TestGate gate;
        rig.net.engine(b).setCallbackGate(&gate);
        Received& r = rig.receiver();
        StreamAcceptor accept = collectInto(r);
        rig.st[b]->onIncoming([&, variant](const StreamInfo& info, StreamSink& sink) {
            bool ok = accept(info, sink);
            std::function<bool(uint32_t, const uint8_t*, size_t)> write = sink.write;
            if (variant == 0) {
                gate.meanwhile = [&] { rig.st[b]->stop(); };
            } else {
                sink.write = [&, write](uint32_t offset, const uint8_t* d, size_t n) {
                    testing::HeapExempt app;
                    if (offset > 0 && !gate.meanwhile) gate.meanwhile = [&] { rig.st[b]->stop(); };
                    return write(offset, d, n);
                };
            }
            return ok;
        });
        Outcome& out = rig.outcome();
        rig.st[a]->send(rig.net.mac(b), static_cast<uint32_t>(data.size()),
                        [&](uint32_t offset, uint8_t* buf, size_t n) {
                            memcpy(buf, data.data() + offset, n);
                            return true;
                        },
                        out.handler(), StreamOptions(), rig.net.now());
        CHECK(rig.net.runUntil([&] { return out.done && r.done; }, 30000));
        CHECK(out.status != Status::Ok);
        CHECK(r.status == Status::Cancelled);
        CHECK_EQ(rig.st[b]->incoming(), 0u);
    }
}

// ---------------------------------------------------------------------------
// Deadlines: when tick() has work next, so that a poller can sleep until then
// (EspNowTransport::pollDelayMs()). NOWTP_SPARSE_TICKS=1 runs every test
// ticking only then; these check that idle nodes do sleep.
TEST(deadline_takes_the_earliest_time) {
    Deadline d(1000);
    CHECK(!d.set());
    CHECK_EQ(d.delay(), UINT32_MAX);
    CHECK_EQ(d.delay(250), 250u);
    d.at(1500);
    CHECK_EQ(d.delay(), 500u);
    d.in(20);
    d.at(1600);
    CHECK_EQ(d.delay(), 20u);
    d.at(900);  // already past: due now
    CHECK_EQ(d.delay(), 0u);
    Deadline w(0xFFFFFFF0u);
    w.at(0x10);  // across the wrap
    CHECK_EQ(w.delay(), 0x20u);
}

TEST(idle_services_sleep_between_their_timers) {
    TimeRig rig;
    rig.net.sparse = true;
    size_t ref = rig.add(true, 5000000000ull, 0), b = rig.add(false, 1234567890ull, 20e-6);
    rig.add(false, 777000000ull, -15e-6);
    rig.start();
    rig.net.run(30000);  // synchronized, past the fast first rounds
    CHECK(rig.allSynced());
    size_t run = rig.net.ticksRun, skipped = rig.net.ticksSkipped;
    rig.net.run(60000);
    CHECK(rig.allSynced());
    CHECK(absValue(rig.error(b, ref)) < 2000);
    run = rig.net.ticksRun - run;
    skipped = rig.net.ticksSkipped - skipped;
    std::printf("    3 nodes, 60 s idle: %zu of %zu ticks run\n", run, run + skipped);
    CHECK(run * 20 < run + skipped);
}

// ---------------------------------------------------------------------------
// Short heaps. Each test runs a scenario at every heap size from 0 to 24 KB
// above what is held, in 512-byte steps. Only what NowTP takes counts; the
// simulator and the test's own memory are exempt. An operator new past the
// limit aborts the test program, as it would abort the device; NowTP's
// malloc() fails softly there and must be handled. Afterwards the limit is
// lifted, traffic must flow again, and everything NowTP took must be back.
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
