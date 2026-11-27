// Host-side tests for the NowTP protocol engine: crypto and security.

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

namespace {

std::vector<uint8_t> challengeFrame(uint16_t id, uint8_t fill) {
    wire::Header h;
    h.port = kSecurityPort;
    h.messageId = id;
    std::vector<uint8_t> f(wire::kCommonHeaderSize + 9, fill);
    size_t n = wire::encodeHeader(h, f.data());
    f[n] = 1;  // challenge, then the nonce
    return f;
}

size_t responsesTo(const sim::Network& net, size_t from, const Mac& to) {
    size_t n = 0;
    for (const sim::Frame& f : net.log) {
        wire::Header h;
        size_t off;
        if (f.from == from && f.dst == to && wire::decodeHeader(f.data.data(), f.data.size(), h, off) &&
            h.port == kSecurityPort && f.data.size() > off && f.data[off] == 2) {
            n++;
        }
    }
    return n;
}

}  // namespace

// ---------------------------------------------------------------------------
// Crypto
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
    rig.net.tickers.push_back(sim::Ticker(
        [&](uint32_t now) {
            da.tick(now);
            db.tick(now);
        },
        [&](Deadline& d) {
            da.nextTick(d);
            db.nextTick(d);
        }));
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
        CHECK(rig.sec[a]->openAck(mb, frame, sizeof(frame), tag, first, nullptr, 0));
        CHECK(rig.sec[a]->openAck(mb, frame, sizeof(frame), tag, later, first, 1));  // sealed again since
        uint8_t before[3 * 8] = {};  // newest first: sealed three times since
        std::memcpy(before + 16, first, 8);
        CHECK(rig.sec[a]->openAck(mb, frame, sizeof(frame), tag, later, before, 3));
        CHECK(!rig.sec[a]->openAck(mb, frame, sizeof(frame), tag, later, before, 2));
        CHECK(!rig.sec[a]->openAck(mb, frame, sizeof(frame), tag, later, nullptr, 0));
        // Unbound: accepted only for other statuses, from a receiver that binds.
        rig.sec[b]->sealAck(ma, frame, sizeof(frame), nullptr, tag);
        bool complete = status == uint8_t(wire::AckStatus::Complete);
        CHECK(rig.sec[a]->openAck(mb, frame, sizeof(frame), tag, later, nullptr, 0) == !complete);
    }
}

// Anyone can send challenges under any MAC. Each challenger gets four answers
// a second, whatever others do, and from any uptime: a window that started at
// 0 once stopped all answers on a node started after 2^31 ms.
TEST(secure_challenges_are_answered_per_challenger) {
    for (uint32_t start : {sim::clockStart(), sim::clockStart() + 25u * 86400 * 1000}) {
        SecureRig rig(start);
        size_t a = rig.add(testKey()), b = rig.add(testKey()), c = rig.add(testKey());
        for (uint16_t i = 0; i < 20; ++i) {
            rig.net.inject(a, rig.net.mac(b), challengeFrame(i, static_cast<uint8_t>(i)));
            if (i % 5 == 0) rig.net.inject(a, rig.net.mac(c), challengeFrame(static_cast<uint16_t>(100 + i), 0xC0));
            rig.net.run(100);
        }
        CHECK_EQ(responsesTo(rig.net, a, rig.net.mac(b)), 8u);  // 4 a second
        CHECK_EQ(responsesTo(rig.net, a, rig.net.mac(c)), 4u);  // all
        CHECK_EQ(rig.sec[a]->counters().challengesAnswered, 12u);
    }
}

// Challenges reseal what is queued for the challenger, once a second at most,
// and an ack bound to any seal that went on air still confirms the message.
// A delivered message whose acks were lost through two reseals used to end
// Timeout, and the application might send it again.
TEST(secure_delivered_message_survives_reseals) {
    SecureRig rig;
    size_t a = rig.add(testKey()), b = rig.add(testKey());
    Inbox inbox;
    rig.net.engine(b).listen(1, inbox.handler());
    CHECK(rig.sendWait(a, b, 1, pattern(10), reliable()) == Status::Ok);  // b verifies a's epoch
    bool dropAcks = true;
    rig.net.dropIf = [&](const sim::Frame& f) {
        wire::Header h;
        size_t off;
        return dropAcks && f.from == b && wire::decodeHeader(f.data.data(), f.data.size(), h, off) &&
               h.type == wire::Type::Ack;
    };
    Outcome out;
    SendOptions o = reliable();
    o.timeoutMs = 4000;
    auto msg = pattern(100, 3);
    rig.net.engine(a).send(rig.net.mac(b), 1, msg.data(), msg.size(), o, out.handler(), rig.net.now());
    std::vector<uint32_t> seqs;  // a's sequence numbers for it
    for (uint16_t i = 0; i < 9; ++i) {
        rig.net.run(300);
        rig.net.inject(a, rig.net.mac(b), challengeFrame(i, static_cast<uint8_t>(i)));
        std::vector<uint8_t> f = rig.lastFrame(a, 1);
        uint32_t seq = wire::getU32(&f[f.size() - wire::kAuthTrailerSize + 4]);
        if (seqs.empty() || seqs.back() != seq) seqs.push_back(seq);
    }
    CHECK_EQ(inbox.messages.size(), 2u);
    CHECK(!out.done);
    CHECK(seqs.size() >= 3u && seqs.size() <= 4u);  // resealed about once a second
    dropAcks = false;
    CHECK(rig.net.runUntil([&] { return out.done; }));
    CHECK(out.status == Status::Ok);
    CHECK_EQ(inbox.messages.size(), 2u);
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
