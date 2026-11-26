// libFuzzer harness for NowTP's receive path (test/fuzz/README.md).
//
// One node, the target, runs the engine with every service: discovery,
// security, time sync, streams, diagnostics, and an application port. The
// fuzzer input is a short configuration, then a sequence of operations by
// four fake peers: raw frames, messages they build (fragmented, sealed with
// the installation key or not, with chosen epochs and sequence numbers),
// answers to the target's challenges, acks for its messages, time sync
// responses, announcements, replays, and the target's own actions (sending,
// streaming, a pairing window) in between.
//
// Beyond ASan and UBSan, the simulator aborts on a frame larger than its
// destination takes, or on a second frame in flight; and with a heap limit,
// on any operator new of NowTP's past it (NowTP must use its own malloc,
// which fails softly).
#define NOWTP_HEAP_LIMIT_IMPLEMENTATION
#include "heap_limit.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <memory>
#include <vector>

#include "nowtp/crypto.h"
#include "nowtp/diagnostics.h"
#include "nowtp/discovery.h"
#include "nowtp/engine.h"
#include "nowtp/frame_sizes.h"
#include "nowtp/security.h"
#include "nowtp/stream.h"
#include "nowtp/timesync.h"
#include "nowtp/wire.h"
#include "sim.h"

using namespace nowtp;

namespace {

const uint8_t kKey[16] = {0x4e, 0x6f, 0x77, 0x54, 0x50, 0x20, 0x66, 0x75,
                          0x7a, 0x7a, 0x20, 0x6b, 0x65, 0x79, 0x21, 0x21};
constexpr uint8_t kAppPort = 1;
constexpr size_t kPeers = 4;          // three nodes that hear the target, one that doesn't
constexpr uint32_t kMaxSimMs = 30000;  // per input
constexpr size_t kMaxOps = 256;

// Security's message, ack and challenge keys, derived as it does.
struct Keys {
    uint8_t msg[32], ack[32], challenge[32];
    Keys() {
        derive("NowTP message", msg);
        derive("NowTP ack", ack);
        derive("NowTP challenge", challenge);
    }
    static void derive(const char* label, uint8_t out[32]) {
        crypto::HmacSha256 h(kKey, sizeof(kKey));
        h.update(reinterpret_cast<const uint8_t*>(label), strlen(label));
        h.finish(out);
    }
};

const Keys& keys() {
    static const Keys k;
    return k;
}

// Security's pairing derivations (security.cpp), for peers that pair with
// the target honestly: session keys from the X25519 secret, the (empty)
// pairing code and the transcript; tags; the key's keystream.
struct PairKeys {
    uint8_t transcript[32], confirm[32], encrypt[32];
};

void derivePairKeys(const uint8_t* dh, const Mac& joiner, const Mac& member, const uint8_t* joinerPub,
                    const uint8_t* joinerNonce, const uint8_t* memberPub, const uint8_t* memberNonce, PairKeys& k) {
    crypto::Sha256 t;
    const char* tag = "NowTP pairing v1";
    t.update(reinterpret_cast<const uint8_t*>(tag), strlen(tag));
    t.update(joiner.bytes, 6);
    t.update(member.bytes, 6);
    t.update(joinerPub, 32);
    t.update(joinerNonce, 16);
    t.update(memberPub, 32);
    t.update(memberNonce, 16);
    t.finish(k.transcript);
    uint8_t salt[32];
    crypto::Sha256 c;
    const char* saltTag = "NowTP pairing code";
    c.update(reinterpret_cast<const uint8_t*>(saltTag), strlen(saltTag));
    c.finish(salt);
    uint8_t okm[64];
    crypto::hkdf(salt, sizeof(salt), dh, 32, k.transcript, sizeof(k.transcript), okm, sizeof(okm));
    memcpy(k.confirm, okm, 32);
    memcpy(k.encrypt, okm + 32, 32);
}

void pairTag(const PairKeys& k, const char* what, const uint8_t* extra, size_t extraLen, uint8_t out[16]) {
    crypto::HmacSha256 h(k.confirm, sizeof(k.confirm));
    h.update(reinterpret_cast<const uint8_t*>(what), strlen(what));
    h.update(k.transcript, sizeof(k.transcript));
    if (extraLen) h.update(extra, extraLen);
    uint8_t full[32];
    h.finish(full);
    memcpy(out, full, 16);
}

void keystream(const PairKeys& k, uint8_t out[33]) {
    uint8_t block[32];
    uint8_t counter = 1;
    crypto::hmacSha256(k.encrypt, sizeof(k.encrypt), &counter, 1, block);
    memcpy(out, block, 32);
    counter = 2;
    crypto::hmacSha256(k.encrypt, sizeof(k.encrypt), &counter, 1, block);
    out[32] = block[0];
}

class Input {
public:
    Input(const uint8_t* p, size_t n) : p_(p), n_(n) {}
    bool empty() const { return n_ == 0; }
    uint8_t u8() {
        if (!n_) return 0;
        n_--;
        return *p_++;
    }
    uint16_t u16() { return static_cast<uint16_t>(u8() | (u8() << 8)); }
    uint32_t u32() { return u16() | (static_cast<uint32_t>(u16()) << 16); }
    uint64_t u64() { return u32() | (static_cast<uint64_t>(u32()) << 32); }
    std::vector<uint8_t> bytes(size_t n) {
        if (n > n_) n = n_;
        std::vector<uint8_t> v(p_, p_ + n);
        p_ += n;
        n_ -= n;
        return v;
    }

private:
    const uint8_t* p_;
    size_t n_;
};

struct Peer {
    size_t node;
    uint32_t epoch;
    uint32_t seq = 0;
    uint16_t nextId;
    // Its X25519 key pair and nonce, for pairing.
    uint8_t priv[32], pub[32], nonce[16];
};

// The target's frames, as logged by the simulator.
struct Sent {
    wire::Header h;
    const uint8_t* payload;
    size_t len;
};

class Harness : public ServiceHost {
public:
    explicit Harness(Input& in) : in_(in), net_(7) {
        uint8_t mode = in_.u8();
        uint8_t limits = in_.u8();
        withKey_ = mode & 0x01;
        bool require = (mode & 0x02) == 0;
        static const TimeRole roles[4] = {TimeRole::Follow, TimeRole::Candidate, TimeRole::Reference, TimeRole::Off};
        TimeRole role = roles[(mode >> 2) & 3];
        bool heapLimit = (mode & 0x10) != 0;
        uint16_t localMax = (mode & 0x20) ? 1470 : 250;

        Config cfg;
        cfg.maxMessageSize = (limits & 1) ? 2048 : 16 * 1024;
        cfg.maxRxMessages = static_cast<uint8_t>(1 + ((limits >> 1) & 3));
        cfg.maxRxMessagesPerSender = static_cast<uint8_t>(1 + ((limits >> 3) & 1));
        cfg.maxRxBytes = (limits & 0x10) ? 4096 : 32 * 1024;
        cfg.receiverCredit = (limits & 0x20) == 0;
        cfg.recentEntries = (limits & 0x40) ? 4 : 32;
        cfg.recentSenders = (limits & 0x80) ? 2 : 20;
        target_ = net_.addNode(cfg);
        for (size_t i = 0; i < kPeers; ++i) {
            Peer p;
            p.node = net_.addNode();
            p.epoch = 0x1000u + static_cast<uint32_t>(i);
            p.nextId = static_cast<uint16_t>(0x100 * (i + 1));
            for (size_t b = 0; b < 32; ++b) p.priv[b] = static_cast<uint8_t>(0x40 + 7 * i + b);
            for (size_t b = 0; b < 16; ++b) p.nonce[b] = static_cast<uint8_t>(0x90 + 5 * i + b);
            crypto::x25519Base(p.pub, p.priv);
            peers_.push_back(p);
        }
        net_.node(peers_[kPeers - 1].node).online = false;  // the target's frames never reach it
        // The peers' engines never see the target's frames: the fuzzer speaks for them.
        net_.dropIf = [this](const sim::Frame& f) { return f.from == target_; };
        net_.sparse = true;

        sim::Node& node = net_.node(target_);
        sizes_.reset(new FrameSizes(250, localMax, true));
        node.link.sizeFor = [this](const Mac& dst) { return sizes_->sizeFor(dst); };

        sim::Counted counted;
        DiscoveryConfig dc;
        dc.name = "target";
        dc.maxPeers = 3;
        disc_.reset(new Discovery(engine(), dc, localMax, [this] { return random(); }));
        sizes_->setDiscovery(disc_.get());
        SecurityConfig sc;
        if (withKey_) sc.key.assign(kKey, kKey + sizeof(kKey));
        sc.requireAuthentication = require;
        sc.maxPeers = 3;
        sec_.reset(new Security(engine(), *this, net_.mac(target_), sc));
        TimeSyncConfig tc;
        tc.role = role;
        tc.takeoverAfterMs = 2000;
        sim::Network* nw = &net_;
        sim::Node* n = &node;
        ts_.reset(new TimeSync(engine(), [n, nw] { return n->clockUs(nw->now()); }, tc, net_.mac(target_)));
        ts_->setDiscovery(disc_.get());
        disc_->onPeerEvent([this](PeerEvent e, const PeerInfo& p) { ts_->onPeerEvent(e, p, net_.now()); });
        streams_.reset(new Streams(engine(), [this] { return random(); }));
        streams_->onIncoming([this](const StreamInfo& info, StreamSink& sink) { return accept(info, sink); });
        DiagnosticsConfig gc;
        gc.acceptRemoteTuning = (mode & 0x80) != 0;
        gc.maxBurstFrames = 40;
        diag_.reset(new Diagnostics(engine(), node.radio, *this, gc));
        engine().listen(kAppPort, [this](const Message& m) { app(m); });

        sec_->start();
        disc_->start(net_.now());
        ts_->start(net_.now());
        streams_->start();
        diag_->start();

        net_.tickers.push_back(sim::Ticker(
            [this](uint32_t now) {
                disc_->tick(now);
                sec_->tick(now);
                ts_->tick(now);
                streams_->tick(now);
                diag_->tick(now);
            },
            [this](Deadline& d) {
                disc_->nextTick(d);
                ts_->nextTick(d);
                streams_->nextTick(d);
                diag_->nextTick(d);
            },
            target_));

        if (heapLimit) testing::setHeapLimit(testing::heapUsed() + 4096 + 1024 * (limits & 0x1F));
    }

    ~Harness() {
        testing::setHeapLimit(0);
        if (verbose()) report();
        sim::Counted counted;
        diag_.reset();
        streams_.reset();
        ts_.reset();
        sec_.reset();
        disc_.reset();
    }

    void run() {
        for (size_t ops = 0; ops < kMaxOps && !in_.empty() && elapsed() < kMaxSimMs; ++ops) op(false);
        step(500);  // what the last frames set off
    }

    // --- ServiceHost: the target's blocking procedures (pairing) -------------
    uint32_t now() override { return net_.now(); }
    // While a pairing procedure waits, the fake peers carry on.
    void sleep(uint32_t ms) override {
        testing::HeapExempt own;  // the network's step counts NowTP's work
        if (!in_.empty() && elapsed() < kMaxSimMs) op(true);
        step(ms ? ms : 1);
    }
    void lock() override {}
    void unlock() override {}
    uint32_t random() override {
        rng_ = rng_ * 1664525u + 1013904223u;
        return rng_;
    }

private:
    static bool verbose() {
        static const bool on = getenv("NOWTP_FUZZ_VERBOSE") != nullptr;
        return on;
    }

    // NOWTP_FUZZ_VERBOSE=1: what an input reached, to check seeds and coverage.
    void report() {
        const Stats& st = engine().stats();
        const Security::Counters& c = sec_->counters();
        TimeSyncStatus t = ts_->status();
        fprintf(stderr,
                "fuzz_frames: %u ms, frames in %u invalid %u, messages in %u dropped %u refused %u auth-rejected %u, "
                "reassembly refused %u | security: challenges %u answered %u verified %u replays %u forgeries %u | "
                "peers %zu | time: synced %d reference %d rounds %u | streams in %zu out %zu | key %d, pairing %s\n",
                elapsed(), static_cast<unsigned>(st.framesReceived), static_cast<unsigned>(st.framesInvalid),
                static_cast<unsigned>(st.messagesReceived), static_cast<unsigned>(st.messagesDropped),
                static_cast<unsigned>(st.messagesRefused), static_cast<unsigned>(st.authRejected),
                static_cast<unsigned>(st.reassemblyRefused), c.challengesSent, c.challengesAnswered, c.epochsVerified,
                c.replaysRejected, c.forgeriesRejected, disc_->peers().size(), t.synced, t.isReference, t.rounds,
                streams_->incoming(), streams_->outgoing(), sec_->enabled(), toString(pairing_));
    }

    Engine& engine() { return net_.engine(target_); }
    uint32_t elapsed() const { return net_.now() - start_; }
    Mac targetMac() const { return net_.mac(target_); }
    Peer& peer(uint8_t b) { return peers_[b % kPeers]; }
    Mac macOf(const Peer& p) const { return net_.mac(p.node); }

    void step(uint32_t ms) {
        for (uint32_t i = 0; i < ms; ++i) net_.step();
    }

    void put(const Peer& p, const std::vector<uint8_t>& frame) {
        if (frame.size() > wire::kMaxFrameSize) return;  // ESP-NOW doesn't carry it
        net_.deliver(target_, p.node, frame);
        history_.push_back(std::make_pair(p.node, frame));
        if (history_.size() > 16) history_.erase(history_.begin());
    }

    static void header(std::vector<uint8_t>& f, const wire::Header& h) {
        uint8_t b[wire::kFragmentHeaderSize];
        size_t n = wire::encodeHeader(h, b);
        f.insert(f.begin(), b, b + n);
    }

    // The trailer Security::seal() writes, for a peer holding the key.
    void seal(const Mac& src, const Mac& dst, uint8_t port, uint8_t flags, const uint8_t* data, size_t len,
              uint32_t epoch, uint32_t seq, uint8_t kind, uint8_t* trailer) const {
        wire::putU32(trailer, epoch);
        wire::putU32(trailer + 4, seq);
        trailer[8] = kind;
        crypto::HmacSha256 h(keys().msg, 32);
        uint8_t meta[3] = {0, port, static_cast<uint8_t>(flags & (wire::kFlagReliable | wire::kFlagLatest))};
        h.update(meta, 1);
        h.update(src.bytes, 6);
        h.update(dst.bytes, 6);
        h.update(meta + 1, 2);
        h.update(trailer, 9);
        h.update(data, len);
        uint8_t full[32];
        h.finish(full);
        memcpy(trailer + 9, full, 8);
    }

    // A message from `p`, framed as NowTP does: single, or fragments of
    // `payload | trailer | CRC`. The input chooses the flags, the id, the
    // authentication, the fragment size, and which fragments go out in which order.
    void message(Peer& p, uint8_t port, std::vector<uint8_t> payload) {
        uint8_t flags = in_.u8();
        uint8_t how = in_.u8();
        bool broadcast = flags & 0x80;
        Mac dst = broadcast ? Mac::broadcast() : targetMac();
        uint8_t hflags = flags & (wire::kFlagReliable | wire::kFlagLatest | wire::kFlagAckRequest);
        uint16_t id = (how & 0x01) ? in_.u16() : p.nextId++;
        int auth = (how >> 1) & 3;  // 0: none, 1: sealed, 2: sealed with a chosen sequence, 3: bad tag
        if (auth) {
            hflags |= wire::kFlagAuth;
            uint32_t seq = ++p.seq;
            uint32_t epoch = p.epoch;
            if (auth == 2) {
                uint8_t s = in_.u8();
                seq = (s & 0x80) ? in_.u32() : p.seq - (s & 0x7F);  // back into the window, or anywhere
                if (s & 0x40) epoch = in_.u32();
            }
            uint8_t trailer[wire::kAuthTrailerSize];
            seal(macOf(p), dst, port, hflags, payload.data(), payload.size(), epoch, seq, broadcast ? 1 : 0,
                 trailer);
            if (auth == 3) trailer[9 + in_.u8() % 8] ^= static_cast<uint8_t>(1 + in_.u8() % 255);
            payload.insert(payload.end(), trailer, trailer + sizeof(trailer));
        }
        wire::Header h;
        h.flags = hflags;
        h.port = port;
        h.messageId = id;
        size_t mtu = (how & 0x08) ? 1470 : 250;
        bool fragmented = (how & 0x10) || payload.size() + wire::kCommonHeaderSize > mtu;
        if (!fragmented) {
            h.type = wire::Type::Single;
            header(payload, h);
            put(p, payload);
            return;
        }
        uint8_t crc[4];
        wire::putU32(crc, wire::crc32(payload.data(), payload.size()));
        if (how & 0x20) crc[0] ^= 1;
        payload.insert(payload.end(), crc, crc + 4);
        size_t frag = 1 + in_.u16() % (mtu - wire::kFragmentHeaderSize);
        size_t count = (payload.size() + frag - 1) / frag;
        if (count < 2) {
            frag = (payload.size() + 1) / 2;
            count = (payload.size() + frag - 1) / frag;
        }
        if (count > 64) count = 64;  // the rest are never sent
        h.type = wire::Type::Fragment;
        h.count = static_cast<uint16_t>((payload.size() + frag - 1) / frag);
        uint64_t skip = (how & 0x40) ? in_.u64() : 0;  // fragments left out
        bool reverse = how & 0x80;
        for (size_t k = 0; k < count; ++k) {
            size_t i = reverse ? count - 1 - k : k;
            if (skip & (static_cast<uint64_t>(1) << i)) continue;
            h.index = static_cast<uint16_t>(i);
            size_t at = i * frag;
            size_t n = std::min(frag, payload.size() - at);
            std::vector<uint8_t> f(payload.begin() + static_cast<std::ptrdiff_t>(at),
                                   payload.begin() + static_cast<std::ptrdiff_t>(at + n));
            header(f, h);
            put(p, f);
        }
    }

    // The target's last frame to `dst` on `port` of `type` (any port: 0xFFFF), newest first.
    bool lastSent(const Mac& dst, int port, wire::Type type, Sent& out, size_t skip = 0) const {
        for (size_t i = net_.log.size(); i-- > 0;) {
            const sim::Frame& f = net_.log[i];
            if (f.from != target_ || !(f.dst == dst)) continue;
            wire::Header h;
            size_t off;
            if (!wire::decodeHeader(f.data.data(), f.data.size(), h, off)) continue;
            if (h.type != type || (port >= 0 && h.port != port)) continue;
            if (skip--) continue;
            out.h = h;
            out.payload = f.data.data() + off;
            out.len = f.data.size() - off;
            return true;
        }
        return false;
    }

    // The target's latest reliable data frame (single or fragment) to `dst`.
    bool lastReliable(const Mac& dst, Sent& out, size_t skip) const {
        for (size_t i = net_.log.size(); i-- > 0;) {
            const sim::Frame& f = net_.log[i];
            wire::Header h;
            size_t off;
            if (f.from != target_ || !(f.dst == dst) || !wire::decodeHeader(f.data.data(), f.data.size(), h, off) ||
                h.type == wire::Type::Ack || !(h.flags & wire::kFlagReliable)) {
                continue;
            }
            if (skip--) continue;
            out.h = h;
            out.payload = f.data.data() + off;
            out.len = f.data.size() - off;
            return true;
        }
        return false;
    }

    // The epoch and sequence the target sealed its message `id` to `dst` with, if logged.
    bool bindOf(const Mac& dst, uint16_t id, uint8_t* bind) const {
        std::vector<uint8_t> tail;  // the message's stream, from its last fragment back
        int expect = -1;
        for (size_t i = net_.log.size(); i-- > 0;) {
            const sim::Frame& f = net_.log[i];
            wire::Header h;
            size_t off;
            if (f.from != target_ || !(f.dst == dst) || !wire::decodeHeader(f.data.data(), f.data.size(), h, off) ||
                h.messageId != id || h.type == wire::Type::Ack || !(h.flags & wire::kFlagAuth)) {
                continue;
            }
            const uint8_t* d = f.data.data() + off;
            size_t n = f.data.size() - off;
            if (h.type == wire::Type::Single) {
                if (n < wire::kAuthTrailerSize) return false;
                memcpy(bind, d + n - wire::kAuthTrailerSize, wire::kAckBindSize);
                return true;
            }
            if (expect < 0 && h.index + 1 == h.count) {
                tail.assign(d, d + n);
                expect = h.index - 1;
            } else if (expect >= 0 && h.index == expect) {
                tail.insert(tail.begin(), d, d + n);
                expect--;
            } else {
                continue;
            }
            if (tail.size() >= wire::kAuthTrailerSize + wire::kCrcSize) {
                memcpy(bind, tail.data() + tail.size() - wire::kCrcSize - wire::kAuthTrailerSize,
                       wire::kAckBindSize);
                return true;
            }
        }
        return false;
    }

    void op(bool inProcedure) {
        uint8_t code = in_.u8();
        Peer& p = peer(in_.u8());
        switch (code % 18) {
            case 0: {  // a raw frame
                put(p, in_.bytes(in_.u16() % (wire::kMaxFrameSize + 1)));
                break;
            }
            case 1: {  // a message on a port the input picks
                static const uint8_t ports[8] = {kAppPort, kStreamPort, kTimeSyncPort, kSecurityPort,
                                                 kDiagnosticsPort, kDiscoveryPort, 2, 245};
                uint8_t port = ports[in_.u8() % 8];
                message(p, port, in_.bytes(in_.u16() % 3000));
                break;
            }
            case 2:
            case 3: {  // time passes
                uint8_t t = in_.u8();
                if (!inProcedure) step((t & 0x80) ? 10u * (t & 0x7F) : t + 1u);
                break;
            }
            case 4: answerChallenge(p); break;
            case 5: ack(p); break;
            case 6: timeResponse(p); break;
            case 7: announce(p); break;
            case 8: {  // a recent frame again, perhaps changed, perhaps from another peer
                if (history_.empty()) break;
                std::vector<uint8_t> f = history_[in_.u8() % history_.size()].second;
                uint8_t edit = in_.u8();
                if ((edit & 1) && !f.empty()) f[in_.u16() % f.size()] ^= static_cast<uint8_t>(1 + in_.u8() % 255);
                put(p, f);
                break;
            }
            case 9: reflect(p); break;
            case 10: {  // the target sends to a peer
                uint16_t n = in_.u16() % 4000;
                uint8_t f = in_.u8();
                SendOptions o;
                o.reliable = f & 1;
                o.latestOnly = f & 2;
                o.timeoutMs = (f & 4) ? 300 : 0;
                std::vector<uint8_t> data(n, static_cast<uint8_t>(f));
                Mac dst = (f & 8) ? Mac::broadcast() : macOf(p);
                sim::Counted counted;
                engine().send(dst, (f & 0x10) ? kAppPort : static_cast<uint8_t>(2), data.data(), data.size(), o,
                              CompletionHandler(), net_.now());
                break;
            }
            case 11: {  // the target streams to a peer
                uint32_t size = in_.u16();
                StreamOptions so;
                so.chunkSize = 1 + in_.u16() % 4096;
                so.window = static_cast<uint8_t>(in_.u8() % 5);
                so.header = in_.bytes(in_.u8() % 220);
                // Streams::send() is the application's call and takes its memory
                // (operator new) in the application's task; what follows on the
                // network is counted.
                streams_->send(macOf(p), size,
                               [](uint32_t offset, uint8_t* buf, size_t len) {
                                   memset(buf, static_cast<int>(offset), len);
                                   return true;
                               },
                               StreamDone(), so, net_.now());
                break;
            }
            case 12: {  // a pairing window, or a pairing attempt (the peers carry on meanwhile)
                uint8_t b = in_.u8();
                if (inProcedure) break;
                uint32_t timeout = 100u + 8u * (b & 0x7F);  // an honest pairing takes ~150 ms
                // An application procedure, as the tests' Scheduler runs it: uncounted.
                pairing_ = (b & 0x80) ? sec_->acceptPairing(timeout) : sec_->pair(timeout);
                break;
            }
            case 13: {  // a peer reboots: new epoch, new message ids
                p.epoch = in_.u32();
                p.seq = 0;
                p.nextId = in_.u16();
                break;
            }
            case 14: {  // the target's radio refuses frames for a while
                net_.node(target_).link.busyReplies = in_.u8() % 8;
                break;
            }
            case 16: pairAsJoiner(p); break;
            case 17: pairAsMember(p); break;
            case 15: {  // the target asks who is there, or moves
                uint8_t b = in_.u8();
                sim::Counted counted;
                if (b & 1) {
                    disc_->discover(net_.now());
                } else {
                    disc_->announceMove(static_cast<uint8_t>(1 + b % 13), net_.now());
                }
                break;
            }
        }
    }

    // Answers the target's latest challenge to `p` as a key holder would,
    // with an epoch, a sequence and capabilities the input picks.
    void answerChallenge(Peer& p) {
        uint8_t how = in_.u8();
        Sent s;
        uint8_t nonce[8] = {0};
        if (lastSent(macOf(p), kSecurityPort, wire::Type::Single, s) && s.len >= 9 && s.payload[0] == 1) {
            memcpy(nonce, s.payload + 1, 8);
        }
        if (how & 0x01) p.epoch = in_.u32();
        uint32_t seq = (how & 0x02) ? in_.u32() : p.seq;
        uint8_t msg[33 + 17];
        msg[0] = 2;
        memcpy(msg + 1, nonce, 8);
        wire::putU32(msg + 9, p.epoch);
        wire::putU32(msg + 13, seq);
        Mac self = macOf(p), target = targetMac();
        uint8_t full[32];
        crypto::HmacSha256 h(keys().challenge, 32);
        h.update(self.bytes, 6);
        h.update(target.bytes, 6);
        h.update(msg + 1, 16);
        h.finish(full);
        memcpy(msg + 17, full, 16);
        if (how & 0x04) msg[17] ^= 1;
        msg[33] = in_.u8() & 3;
        crypto::HmacSha256 c(keys().challenge, 32);
        const char* label = "NowTP caps";
        c.update(reinterpret_cast<const uint8_t*>(label), strlen(label));
        c.update(self.bytes, 6);
        c.update(target.bytes, 6);
        c.update(msg + 1, 33);
        c.finish(full);
        memcpy(msg + 34, full, 16);
        size_t len = (how & 0x08) ? 33 : sizeof(msg);
        wire::Header hd;
        hd.port = kSecurityPort;
        hd.messageId = p.nextId++;
        std::vector<uint8_t> f(msg, msg + len);
        header(f, hd);
        put(p, f);
    }

    // Acks the target's latest reliable frame to `p`, tagged as a key holder would.
    void ack(Peer& p) {
        uint8_t how = in_.u8();
        Sent s;
        uint16_t id = in_.u16();
        uint8_t port = kAppPort;
        bool auth = false;
        if (!(how & 0x01) && lastReliable(macOf(p), s, in_.u8() % 3)) {
            id = s.h.messageId;
            port = s.h.port;
            auth = (s.h.flags & wire::kFlagAuth) != 0;
        }
        wire::Header h;
        h.type = wire::Type::Ack;
        h.port = port;
        h.messageId = id;
        bool credit = how & 0x02;
        bool tagged = (how & 0x04) ? !auth : auth;
        h.flags = static_cast<uint8_t>((credit ? wire::kFlagCredit : 0) | (tagged ? wire::kFlagAuth : 0));
        std::vector<uint8_t> f;
        f.push_back(static_cast<uint8_t>((how >> 3) % 5));  // status, one unknown
        uint8_t missing = in_.u8() % 12;
        for (uint8_t i = 0; i < missing; ++i) {
            uint16_t idx = in_.u16();
            f.push_back(static_cast<uint8_t>(idx));
            f.push_back(static_cast<uint8_t>(idx >> 8));
        }
        if (credit) f.push_back(in_.u8());
        header(f, h);
        if (tagged) {
            uint8_t bind[wire::kAckBindSize];
            bool bound = (how & 0x40) && bindOf(macOf(p), id, bind);
            Mac self = macOf(p), target = targetMac();
            crypto::HmacSha256 t(keys().ack, 32);
            t.update(self.bytes, 6);
            t.update(target.bytes, 6);
            t.update(f.data(), f.size());
            if (bound) t.update(bind, sizeof(bind));
            uint8_t full[32];
            t.finish(full);
            if (how & 0x80) full[0] ^= 1;
            f.insert(f.end(), full, full + wire::kAckTagSize);
        }
        put(p, f);
    }

    // Answers the target's latest time request to `p`, with times the input
    // picks around the request's, or sends a calibration report.
    void timeResponse(Peer& p) {
        uint8_t how = in_.u8();
        Sent s;
        uint8_t round = 0, index = 0;
        uint64_t t1 = 0;
        if (lastSent(macOf(p), kTimeSyncPort, wire::Type::Single, s, how & 1) && s.len >= 11) {
            size_t n = s.len - ((s.h.flags & wire::kFlagAuth) ? wire::kAuthTrailerSize : 0);
            if (n >= 11 && s.payload[0] == 1) {
                round = s.payload[1];
                index = s.payload[2];
                for (int i = 7; i >= 0; --i) t1 = (t1 << 8) | s.payload[3 + i];
            }
        }
        std::vector<uint8_t> d;
        auto put64 = [&d](uint64_t v) {
            for (int i = 0; i < 8; ++i) d.push_back(static_cast<uint8_t>(v >> (8 * i)));
        };
        auto near = [this](uint64_t base) {
            uint8_t k = in_.u8();
            if (k & 0x80) return in_.u64();  // anywhere
            int32_t delta = static_cast<int32_t>(in_.u32());
            return base + static_cast<uint64_t>(static_cast<int64_t>(delta) >> (k & 0x1F));
        };
        if (how & 0x02) {
            d.push_back(3);  // calibration: round, exchanges, difference
            d.push_back(in_.u8());
            d.push_back(in_.u8());
            uint32_t diff = in_.u32();
            for (int i = 0; i < 4; ++i) d.push_back(static_cast<uint8_t>(diff >> (8 * i)));
            d.push_back(0);
        } else {
            uint64_t remote = net_.node(p.node).clockUs(net_.now());
            d.push_back(2);
            d.push_back((how & 0x04) ? in_.u8() : round);
            d.push_back((how & 0x08) ? in_.u8() : index);
            put64(t1);
            uint64_t t2 = near(remote);
            put64(t2);
            put64(near(t2));
            d.push_back(in_.u8());
            d.push_back(in_.u8());
            put64(near(remote));
            if (how & 0x10) d.resize(27 + in_.u8() % 11);
        }
        wire::Header h;
        h.port = kTimeSyncPort;
        h.messageId = p.nextId++;
        if (how & 0x20) {
            h.flags = wire::kFlagAuth;
            uint8_t trailer[wire::kAuthTrailerSize];
            seal(macOf(p), targetMac(), kTimeSyncPort, 0, d.data(), d.size(), p.epoch, ++p.seq, 0, trailer);
            d.insert(d.end(), trailer, trailer + sizeof(trailer));
        }
        header(d, h);
        put(p, d);
    }

    // A discovery announcement from `p`, with fields the input picks.
    void announce(Peer& p) {
        std::vector<uint8_t> a;
        uint8_t flags = in_.u8();
        a.push_back(1);  // hello
        a.push_back(flags);
        uint16_t size = in_.u16();
        a.push_back(static_cast<uint8_t>(size));
        a.push_back(static_cast<uint8_t>(size >> 8));
        std::vector<uint8_t> name = in_.bytes(in_.u8() % 40);
        a.push_back(static_cast<uint8_t>(name.size()));
        a.insert(a.end(), name.begin(), name.end());
        std::vector<uint8_t> meta = in_.bytes(in_.u8());
        a.push_back(static_cast<uint8_t>(meta.size()));
        a.insert(a.end(), meta.begin(), meta.end());
        uint8_t ext = in_.u8();
        a.push_back(ext);
        a.push_back(in_.u8() % 15);  // channel
        if (flags & 0x08) a.push_back(in_.u8());
        if (ext & 0x04) {
            uint32_t m = in_.u32();
            for (int i = 0; i < 4; ++i) a.push_back(static_cast<uint8_t>(m >> (8 * i)));
        }
        if (ext & 0x20) {
            std::vector<uint8_t> id = in_.bytes(6);
            a.insert(a.end(), id.begin(), id.end());
        }
        if (in_.u8() & 1) a.resize(in_.u8() % (a.size() + 1));
        message(p, kDiscoveryPort, a);
    }

    // The target's latest frame to `p` (or broadcast) on a port, with a few
    // bytes changed, sent back as `p`'s message: requests become answers.
    void reflect(Peer& p) {
        uint8_t how = in_.u8();
        static const uint8_t ports[6] = {kStreamPort, kTimeSyncPort, kSecurityPort, kDiagnosticsPort,
                                         kDiscoveryPort, kAppPort};
        uint8_t port = ports[how % 6];
        Sent s;
        Mac dst = (how & 0x80) ? Mac::broadcast() : macOf(p);
        if (!lastSent(dst, port, wire::Type::Single, s, (how >> 3) & 3)) return;
        size_t n = s.len - ((s.h.flags & wire::kFlagAuth) && s.len >= wire::kAuthTrailerSize
                                ? wire::kAuthTrailerSize
                                : 0);
        std::vector<uint8_t> d(s.payload, s.payload + n);
        uint8_t edits = in_.u8() % 6;
        for (uint8_t i = 0; i < edits && !d.empty(); ++i) d[in_.u8() % d.size()] = in_.u8();
        if (how & 0x40) d.resize(in_.u8() % (d.size() + 2));
        message(p, port, d);
    }

    void sendPairing(Peer& p, const uint8_t* msg, size_t len) {
        wire::Header h;
        h.port = kSecurityPort;
        h.messageId = p.nextId++;
        std::vector<uint8_t> f(msg, msg + len);
        header(f, h);
        put(p, f);
    }

    // A peer joining through the target's pairing window (acceptPairing()),
    // as Security::pair() does: request, then the proof and the done
    // message for the target's latest offer. The input may spoil a tag.
    void pairAsJoiner(Peer& p) {
        uint8_t how = in_.u8();
        if ((how & 3) == 0) {
            uint8_t request[49];
            request[0] = 3;
            memcpy(request + 1, p.pub, 32);
            memcpy(request + 33, p.nonce, 16);
            sendPairing(p, request, sizeof(request));
            return;
        }
        if ((how & 3) == 3) {
            uint8_t refused = 8;
            sendPairing(p, &refused, 1);
            return;
        }
        Sent s;
        bool found = false;  // the target's latest offer, behind its key message perhaps
        for (size_t skip = 0; !found && skip < 8 && lastSent(macOf(p), kSecurityPort, wire::Type::Single, s, skip);
             ++skip) {
            found = s.len >= 81 && s.payload[0] == 4;
        }
        if (!found) return;
        uint8_t dh[32];
        crypto::x25519(dh, p.priv, s.payload + 17);
        PairKeys k;
        derivePairKeys(dh, macOf(p), targetMac(), p.pub, s.payload + 1, s.payload + 17, s.payload + 49, k);
        uint8_t msg[17];
        msg[0] = (how & 3) == 1 ? 5 : 7;  // proof, or done
        pairTag(k, msg[0] == 5 ? "proof" : "done", nullptr, 0, msg + 1);
        if (how & 0x80) msg[1 + in_.u8() % 16] ^= 1;
        sendPairing(p, msg, sizeof(msg));
    }

    // A member answering the target's pairing request (pair()), as
    // Security::acceptPairing() does: an offer, then the installation key
    // (the one the peers seal with, or another the input picks).
    void pairAsMember(Peer& p) {
        uint8_t how = in_.u8();
        Sent s;
        if (!lastSent(Mac::broadcast(), kSecurityPort, wire::Type::Single, s) || s.len < 49 || s.payload[0] != 3) {
            return;
        }
        const uint8_t* joinerPub = s.payload + 1;
        const uint8_t* joinerNonce = s.payload + 33;
        uint8_t dh[32];
        crypto::x25519(dh, p.priv, joinerPub);
        PairKeys k;
        derivePairKeys(dh, targetMac(), macOf(p), joinerPub, joinerNonce, p.pub, p.nonce, k);
        if (!(how & 1)) {
            uint8_t offer[81];
            offer[0] = 4;
            memcpy(offer + 1, joinerNonce, 16);
            memcpy(offer + 17, p.pub, 32);
            memcpy(offer + 49, p.nonce, 16);
            pairTag(k, "offer", nullptr, 0, offer + 65);
            if (how & 0x80) offer[65 + in_.u8() % 16] ^= 1;
            sendPairing(p, offer, sizeof(offer));
            return;
        }
        uint8_t plain[33] = {0};
        plain[0] = sizeof(kKey);
        memcpy(plain + 1, kKey, sizeof(kKey));
        if (how & 0x02) plain[0] = in_.u8();  // a length out of range, perhaps
        uint8_t stream[33];
        keystream(k, stream);
        uint8_t msg[50];
        msg[0] = 6;
        for (size_t i = 0; i < 33; ++i) msg[1 + i] = static_cast<uint8_t>(plain[i] ^ stream[i]);
        pairTag(k, "key", msg + 1, 33, msg + 34);
        if (how & 0x80) msg[34 + in_.u8() % 16] ^= 1;
        sendPairing(p, msg, sizeof(msg));
    }

    // The application on the target: takes a buffer now and then, refuses some.
    void app(const Message& m) {
        testing::HeapExempt own;
        if (m.len && m.data[0] == 0xEE) m.refused = true;
        if (m.buffer && m.len > 1 && m.data[1] == 0xBB) {
            uint8_t* b = m.buffer;
            m.buffer = nullptr;
            heap::release(b);
        }
    }

    bool accept(const StreamInfo& info, StreamSink& sink) {
        testing::HeapExempt own;
        if (info.topic & 1) return false;
        sink.write = [](uint32_t offset, const uint8_t*, size_t) { return (offset & 0x10000) == 0; };
        sink.done = [](Status) {};
        return true;
    }

    Input& in_;
    sim::Network net_;
    size_t target_ = 0;
    uint32_t start_ = net_.now();
    uint32_t rng_ = 12345;
    bool withKey_ = false;
    Status pairing_ = Status::InvalidState;  // the last pairing procedure's outcome
    std::vector<Peer> peers_;
    std::vector<std::pair<size_t, std::vector<uint8_t>>> history_;
    std::unique_ptr<FrameSizes> sizes_;
    std::unique_ptr<Discovery> disc_;
    std::unique_ptr<Security> sec_;
    std::unique_ptr<TimeSync> ts_;
    std::unique_ptr<Streams> streams_;
    std::unique_ptr<Diagnostics> diag_;
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    testing::HeapExempt own;  // the harness's and the simulator's; NowTP's calls are counted
    Input in(data, size);
    {
        Harness h(in);
        h.run();
    }
    return 0;
}
