// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "security.h"

#include <string.h>

#include <memory>

#include "crypto.h"

namespace nowtp {

using wire::getU32;
using wire::putU32;

namespace {

constexpr size_t kTagSize = 8;            // in a message trailer
constexpr size_t kResponseTagSize = 16;   // challenge responses and pairing
constexpr uint32_t kChallengeRetryMs = 300;
constexpr uint8_t kChallengeTries = 5;
constexpr uint32_t kChallengeBackoffMs = 2000;
// An epoch other than the one verified this recently is a replay, not a reboot.
constexpr uint32_t kFreshVerificationMs = 1000;
constexpr uint8_t kMaxResponsesPerSecond = 20;
constexpr uint32_t kPairRequestIntervalMs = 500;
constexpr uint32_t kPairStepMs = 2500;

inline bool reached(uint32_t now, uint32_t deadline) {
    return static_cast<int32_t>(now - deadline) >= 0;
}

void label(crypto::HmacSha256& h, const char* text) {
    h.update(reinterpret_cast<const uint8_t*>(text), strlen(text));
}

void deriveLabel(const std::vector<uint8_t>& key, const char* text, uint8_t out[32]) {
    crypto::HmacSha256 h(key.data(), key.size());
    label(h, text);
    h.finish(out);
}

// Pairing session keys from the X25519 secret, the pairing code and the transcript.
struct PairKeys {
    uint8_t transcript[32];
    uint8_t confirm[32];
    uint8_t encrypt[32];
    ~PairKeys() { crypto::wipe(this, sizeof(*this)); }
};

void derivePairKeys(const std::string& code, const uint8_t* dh, const Mac& joiner, const Mac& member,
                    const uint8_t* joinerPub, const uint8_t* joinerNonce, const uint8_t* memberPub,
                    const uint8_t* memberNonce, PairKeys& k) {
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
    crypto::Sha256 s;
    const char* saltTag = "NowTP pairing code";
    s.update(reinterpret_cast<const uint8_t*>(saltTag), strlen(saltTag));
    s.update(reinterpret_cast<const uint8_t*>(code.data()), code.size());
    s.finish(salt);

    uint8_t okm[64];
    crypto::hkdf(salt, sizeof(salt), dh, 32, k.transcript, sizeof(k.transcript), okm, sizeof(okm));
    memcpy(k.confirm, okm, 32);
    memcpy(k.encrypt, okm + 32, 32);
    crypto::wipe(okm, sizeof(okm));
}

// HMAC(confirm key, label | transcript | extra), truncated to 16 bytes.
void pairTag(const PairKeys& k, const char* what, const uint8_t* extra, size_t extraLen, uint8_t out[16]) {
    crypto::HmacSha256 h(k.confirm, sizeof(k.confirm));
    label(h, what);
    h.update(k.transcript, sizeof(k.transcript));
    if (extraLen) h.update(extra, extraLen);
    uint8_t full[32];
    h.finish(full);
    memcpy(out, full, 16);
}

// The installation key travels as length (1) | key padded to 32, XORed with
// a keystream from the encryption key.
void keystream(const PairKeys& k, uint8_t out[33]) {
    uint8_t block[32];
    uint8_t counter = 1;
    crypto::hmacSha256(k.encrypt, sizeof(k.encrypt), &counter, 1, block);
    memcpy(out, block, 32);
    counter = 2;
    crypto::hmacSha256(k.encrypt, sizeof(k.encrypt), &counter, 1, block);
    out[32] = block[0];
    crypto::wipe(block, sizeof(block));
}

bool allZero(const uint8_t* p, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; ++i) acc = static_cast<uint8_t>(acc | p[i]);
    return acc == 0;
}

}  // namespace

constexpr size_t Security::kMinKey;
constexpr size_t Security::kMaxKey;

Security::Security(Engine& engine, ServiceHost& host, const Mac& localMac, const SecurityConfig& config)
    : engine_(engine), host_(host), local_(localMac), config_(config) {
    if (config_.maxPeers == 0) config_.maxPeers = 1;
    while (epoch_ == 0) epoch_ = host_.random();
    if (config_.key.size() >= kMinKey && config_.key.size() <= kMaxKey) key_ = config_.key;
    crypto::wipe(config_.key.data(), config_.key.size());
    config_.key.clear();
    deriveKeys();
}

Security::~Security() {
    stop();
    crypto::wipe(msgKey_, sizeof(msgKey_));
    crypto::wipe(ackKey_, sizeof(ackKey_));
    crypto::wipe(challengeKey_, sizeof(challengeKey_));
    if (!key_.empty()) crypto::wipe(key_.data(), key_.size());
}

void Security::start() {
    running_ = true;
    engine_.listen(kSecurityPort, [this](const Message& m) { handle(m); });
    engine_.setAuthenticator(this);
}

void Security::stop() {
    if (!running_) return;
    engine_.setAuthenticator(nullptr);
    engine_.listen(kSecurityPort, ReceiveHandler());
    running_ = false;
}

void Security::deriveKeys() {
    if (key_.empty()) {
        memset(msgKey_, 0, sizeof(msgKey_));
        memset(ackKey_, 0, sizeof(ackKey_));
        memset(challengeKey_, 0, sizeof(challengeKey_));
        return;
    }
    deriveLabel(key_, "NowTP message", msgKey_);
    deriveLabel(key_, "NowTP ack", ackKey_);
    deriveLabel(key_, "NowTP challenge", challengeKey_);
}

Status Security::setKey(const uint8_t* key, size_t len) {
    if (len != 0 && (len < kMinKey || len > kMaxKey || !key)) return Status::InvalidArgument;
    host_.lock();
    installKey(key, len);
    host_.unlock();
    return Status::Ok;
}

void Security::installKey(const uint8_t* key, size_t len) {
    if (!key_.empty()) crypto::wipe(key_.data(), key_.size());
    key_.assign(key, key + len);
    deriveKeys();
    peers_.clear();  // verified epochs were verified with the old key
}

std::vector<uint8_t> Security::key() {
    host_.lock();
    std::vector<uint8_t> copy = key_;
    host_.unlock();
    return copy;
}

// ---------------------------------------------------------------------------
// Message authentication (engine context, lock held)

bool Security::sealing(uint8_t port) const {
    return !key_.empty() && port != kSecurityPort;
}

// HMAC(message key, network id | src | dst | port | flags | epoch, sequence,
// destination kind | payload), truncated.
void Security::messageTag(const Mac& src, const Mac& dst, uint8_t port, uint8_t flags, const uint8_t* head,
                          const uint8_t* data, size_t len, uint8_t* out) {
    crypto::HmacSha256 h(msgKey_, sizeof(msgKey_));
    uint8_t meta[3] = {engine_.config().networkId, port, flags};
    h.update(meta, 1);
    h.update(src.bytes, 6);
    h.update(dst.bytes, 6);
    h.update(meta + 1, 2);
    h.update(head, 9);
    h.update(data, len);
    uint8_t full[32];
    h.finish(full);
    memcpy(out, full, kTagSize);
}

void Security::seal(const Mac& dst, uint8_t port, uint8_t flags, const uint8_t* data, size_t len, uint8_t* trailer) {
    if (++seq_ == 0) {
        // 2^32 messages in one boot: start a new epoch rather than reuse numbers.
        uint32_t old = epoch_;
        while (epoch_ == 0 || epoch_ == old) epoch_ = host_.random();
        seq_ = 1;
    }
    putU32(trailer, epoch_);
    putU32(trailer + 4, seq_);
    trailer[8] = dst.isBroadcast() ? 1 : 0;
    messageTag(local_, dst, port, flags, trailer, data, len, trailer + 9);
}

Authenticator::Verdict Security::open(const Mac& src, uint8_t port, uint8_t flags, const uint8_t* data, size_t len,
                                      const uint8_t* trailer, uint32_t now) {
    now_ = now;
    if (key_.empty()) return Verdict::Unauthenticated;
    if (!trailer) {
        if (config_.requireAuthentication && port != kSecurityPort) {
            counters_.forgeriesRejected++;
            return Verdict::Reject;
        }
        return Verdict::Unauthenticated;
    }
    if (trailer[8] > 1) {
        counters_.forgeriesRejected++;
        return Verdict::Reject;
    }
    Mac dst = trailer[8] ? Mac::broadcast() : local_;
    uint8_t tag[kTagSize];
    messageTag(src, dst, port, flags, trailer, data, len, tag);
    if (!crypto::equal(tag, trailer + 9, kTagSize)) {
        counters_.forgeriesRejected++;
        return Verdict::Reject;
    }

    uint32_t epoch = getU32(trailer);
    uint32_t seq = getU32(trailer + 4);
    Peer* p = peer(src, true, now);
    if (p->verified && p->epoch == epoch) {
        if (acceptSequence(*p, seq)) return Verdict::Authentic;
        counters_.replaysRejected++;
        return Verdict::Reject;
    }
    if (p->verified && static_cast<int32_t>(now - p->verifiedAt) < static_cast<int32_t>(kFreshVerificationMs)) {
        // The sender just proved another epoch is its current one.
        counters_.replaysRejected++;
        return Verdict::Reject;
    }
    challenge(*p, now);
    return Verdict::Retry;
}

bool Security::acceptSequence(Peer& p, uint32_t seq) {
    if (seq > p.highest) {
        uint32_t shift = seq - p.highest;
        p.window = shift >= 64 ? 0 : p.window << shift;
        p.window |= 1;
        p.highest = seq;
        return true;
    }
    uint32_t back = p.highest - seq;
    if (back >= 64) return false;
    uint64_t bit = static_cast<uint64_t>(1) << back;
    if (p.window & bit) return false;
    p.window |= bit;
    return true;
}

void Security::sealAck(const Mac& dst, const uint8_t* frame, size_t len, uint8_t* tag) {
    crypto::HmacSha256 h(ackKey_, sizeof(ackKey_));
    h.update(local_.bytes, 6);
    h.update(dst.bytes, 6);
    h.update(frame, len);
    uint8_t full[32];
    h.finish(full);
    memcpy(tag, full, wire::kAckTagSize);
}

bool Security::openAck(const Mac& src, const uint8_t* frame, size_t len, const uint8_t* tag) {
    if (key_.empty()) return false;
    crypto::HmacSha256 h(ackKey_, sizeof(ackKey_));
    h.update(src.bytes, 6);
    h.update(local_.bytes, 6);
    h.update(frame, len);
    uint8_t full[32];
    h.finish(full);
    if (crypto::equal(full, tag, wire::kAckTagSize)) return true;
    counters_.forgeriesRejected++;
    return false;
}

Security::Peer* Security::peer(const Mac& mac, bool create, uint32_t now) {
    for (Peer& p : peers_) {
        if (p.mac == mac) {
            p.lastUse = now;
            return &p;
        }
    }
    if (!create) return nullptr;
    if (peers_.size() >= config_.maxPeers) {
        size_t oldest = 0;
        for (size_t i = 1; i < peers_.size(); ++i) {
            if (static_cast<int32_t>(peers_[i].lastUse - peers_[oldest].lastUse) < 0) oldest = i;
        }
        peers_.erase(peers_.begin() + static_cast<std::ptrdiff_t>(oldest));
    }
    peers_.push_back(Peer());
    Peer& p = peers_.back();
    p.mac = mac;
    p.lastUse = now;
    return &p;
}

// ---------------------------------------------------------------------------
// Epoch challenges: "prove that epoch is live by tagging my fresh nonce"

void Security::challenge(Peer& p, uint32_t now) {
    if (p.challenging) {
        if (!reached(now, p.challengeAt + kChallengeRetryMs)) return;
        if (p.tries >= kChallengeTries) {
            if (!reached(now, p.challengeAt + kChallengeBackoffMs)) return;
            p.tries = 0;
        }
    } else {
        p.tries = 0;
    }
    p.challenging = true;
    p.challengeAt = now;
    p.tries++;
    for (size_t i = 0; i < sizeof(p.nonce); i += 4) putU32(p.nonce + i, host_.random());
    uint8_t msg[1 + sizeof(p.nonce)];
    msg[0] = kChallenge;
    memcpy(msg + 1, p.nonce, sizeof(p.nonce));
    counters_.challengesSent++;
    engine_.send(p.mac, kSecurityPort, msg, sizeof(msg), SendOptions(), CompletionHandler(), now);
}

void Security::respond(const Mac& to, const uint8_t* nonce, uint32_t now) {
    if (key_.empty()) return;
    if (static_cast<int32_t>(now - responseWindowStart_) >= 1000) {
        responseWindowStart_ = now;
        responsesInWindow_ = 0;
    }
    if (responsesInWindow_ >= kMaxResponsesPerSecond) return;
    responsesInWindow_++;

    // type | nonce (8) | epoch (4) | sequence (4) | tag (16)
    uint8_t msg[1 + 8 + 4 + 4 + kResponseTagSize];
    msg[0] = kResponse;
    memcpy(msg + 1, nonce, 8);
    putU32(msg + 9, epoch_);
    putU32(msg + 13, seq_);
    crypto::HmacSha256 h(challengeKey_, sizeof(challengeKey_));
    h.update(local_.bytes, 6);
    h.update(to.bytes, 6);
    h.update(msg + 1, 16);
    uint8_t full[32];
    h.finish(full);
    memcpy(msg + 17, full, kResponseTagSize);
    counters_.challengesAnswered++;
    engine_.send(to, kSecurityPort, msg, sizeof(msg), SendOptions(), CompletionHandler(), now);
}

void Security::verifyResponse(const Mac& from, const uint8_t* d, size_t len, uint32_t now) {
    if (len < 17 + kResponseTagSize || key_.empty()) return;
    Peer* p = peer(from, false, now);
    if (!p || !p->challenging || !crypto::equal(p->nonce, d + 1, sizeof(p->nonce))) return;
    crypto::HmacSha256 h(challengeKey_, sizeof(challengeKey_));
    h.update(from.bytes, 6);
    h.update(local_.bytes, 6);
    h.update(d + 1, 16);
    uint8_t full[32];
    h.finish(full);
    if (!crypto::equal(full, d + 17, kResponseTagSize)) {
        counters_.forgeriesRejected++;
        return;
    }
    p->challenging = false;
    p->verified = true;
    p->epoch = getU32(d + 9);
    p->highest = getU32(d + 13);
    p->window = 0;  // the last 64 sequence numbers may still arrive once each
    p->verifiedAt = now;
    counters_.epochsVerified++;
    if (verifiedHandler_) {
        std::function<void(const Mac&)> handler = verifiedHandler_;
        handler(from);
    }
}

void Security::tick(uint32_t now) {
    now_ = now;
}

void Security::handle(const Message& m) {
    if (m.len < 1) return;
    const uint8_t* d = m.data;
    switch (d[0]) {
        case kChallenge:
            if (m.len >= 9) respond(m.src, d + 1, now_);
            break;
        case kResponse: verifyResponse(m.src, d, m.len, now_); break;
        case kPairRequest:
            // type | public key (32) | nonce (16)
            if (pairing_.role != Pairing::Member || pairing_.busy || pairing_.request || m.len < 49) return;
            pairing_.request = true;
            pairing_.joiner = m.src;
            memcpy(pairing_.joinerPub, d + 1, 32);
            memcpy(pairing_.joinerNonce, d + 33, 16);
            break;
        case kPairOffer:
            // type | joiner nonce (16) | public key (32) | nonce (16) | tag (16)
            if (pairing_.role != Pairing::Joiner || pairing_.offer || m.len < 81) return;
            if (!crypto::equal(d + 1, pairing_.nonce, 16)) return;
            pairing_.offer = true;
            pairing_.member = m.src;
            memcpy(pairing_.memberPub, d + 17, 32);
            memcpy(pairing_.memberNonce, d + 49, 16);
            memcpy(pairing_.offerTag, d + 65, 16);
            break;
        case kPairProof:
            if (pairing_.role != Pairing::Member || !pairing_.busy || m.src != pairing_.joiner || m.len < 17) return;
            pairing_.proof = true;
            memcpy(pairing_.proofTag, d + 1, 16);
            break;
        case kPairKey:
            // type | sealed key (33) | tag (16)
            if (pairing_.role != Pairing::Joiner || !pairing_.offer || m.src != pairing_.member || m.len < 50) return;
            pairing_.keyMsg = true;
            memcpy(pairing_.sealedKey, d + 1, 33);
            memcpy(pairing_.keyTag, d + 34, 16);
            break;
        case kPairDone:
            if (pairing_.role != Pairing::Member || !pairing_.busy || m.src != pairing_.joiner || m.len < 17) return;
            pairing_.done = true;
            memcpy(pairing_.doneTag, d + 1, 16);
            break;
        case kPairRefused:
            // Carries no secret; at worst a forged one changes what acceptPairing() reports.
            if (pairing_.role != Pairing::Member || !pairing_.busy || m.src != pairing_.joiner) return;
            pairing_.refused = true;
            break;
        default: break;
    }
}

// ---------------------------------------------------------------------------
// Pairing (application task)

void Security::randomBytes(uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        uint32_t r = host_.random();
        for (size_t j = 0; j < 4 && i + j < len; ++j) out[i + j] = static_cast<uint8_t>(r >> (8 * j));
    }
}

Status Security::sendLocked(const Mac& dst, const uint8_t* data, size_t len, bool reliable) {
    SendOptions o;
    o.reliable = reliable;
    host_.lock();
    Status st = engine_.send(dst, kSecurityPort, data, len, o, CompletionHandler(), host_.now());
    host_.unlock();
    return st;
}

bool Security::waitFor(const std::function<bool()>& done, uint32_t timeoutMs) {
    uint32_t start = host_.now();
    for (;;) {
        host_.lock();
        bool ok = done();
        host_.unlock();
        if (ok) return true;
        if (host_.now() - start >= timeoutMs) return false;
        host_.sleep(5);
    }
}

Status Security::acceptPairing(uint32_t timeoutMs, Mac* joined) {
    if (!running_) return Status::InvalidState;
    host_.lock();
    if (pairing_.role != Pairing::None) {
        host_.unlock();
        return Status::InvalidState;
    }
    bool created = false;
    if (key_.empty()) {
        // The first node of an installation creates its key.
        uint8_t fresh[32];
        host_.unlock();
        randomBytes(fresh, sizeof(fresh));
        host_.lock();
        installKey(fresh, sizeof(fresh));
        crypto::wipe(fresh, sizeof(fresh));
        created = true;
    }
    pairing_ = Pairing();
    pairing_.role = Pairing::Member;
    host_.unlock();
    if (created && keyHandler_) keyHandler_(key());

    Status result = Status::Timeout;
    bool failed = false;
    uint32_t deadline = host_.now() + timeoutMs;
    while (!reached(host_.now(), deadline)) {
        result = Status::Timeout;
        if (!waitFor([this] { return pairing_.request; }, 50)) continue;

        host_.lock();
        pairing_.busy = true;
        Mac joiner = pairing_.joiner;
        uint8_t joinerPub[32], joinerNonce[16];
        memcpy(joinerPub, pairing_.joinerPub, 32);
        memcpy(joinerNonce, pairing_.joinerNonce, 16);
        host_.unlock();

        uint8_t priv[32], pub[32], nonce[16], dh[32];
        randomBytes(priv, sizeof(priv));
        randomBytes(nonce, sizeof(nonce));
        crypto::x25519Base(pub, priv);
        crypto::x25519(dh, priv, joinerPub);
        crypto::wipe(priv, sizeof(priv));
        bool ok = !allZero(dh, sizeof(dh));
        std::unique_ptr<PairKeys> k(new PairKeys());
        derivePairKeys(config_.pairingCode, dh, joiner, local_, joinerPub, joinerNonce, pub, nonce, *k);
        crypto::wipe(dh, sizeof(dh));

        // Offer, until the joiner proves it derived the same keys (same code).
        uint8_t offer[81];
        offer[0] = kPairOffer;
        memcpy(offer + 1, joinerNonce, 16);
        memcpy(offer + 17, pub, 32);
        memcpy(offer + 49, nonce, 16);
        pairTag(*k, "offer", nullptr, 0, offer + 65);
        bool proved = false, refused = false;
        for (uint32_t t0 = host_.now(); ok && !proved && !refused && host_.now() - t0 < kPairStepMs;) {
            sendLocked(joiner, offer, sizeof(offer), false);
            waitFor([this] { return pairing_.proof || pairing_.refused; }, kPairRequestIntervalMs);
            host_.lock();
            proved = pairing_.proof;
            refused = pairing_.refused;
            host_.unlock();
        }
        if (refused) result = Status::AuthFailed;
        if (proved) {
            uint8_t expect[16];
            pairTag(*k, "proof", nullptr, 0, expect);
            host_.lock();
            proved = crypto::equal(expect, pairing_.proofTag, 16);
            host_.unlock();
            if (!proved) result = Status::AuthFailed;  // another pairing code
        }
        if (result == Status::AuthFailed) failed = true;

        bool done = false;
        if (proved) {
            uint8_t msg[50];
            msg[0] = kPairKey;
            uint8_t stream[33];
            keystream(*k, stream);
            host_.lock();
            uint8_t plain[33] = {static_cast<uint8_t>(key_.size())};
            memcpy(plain + 1, key_.data(), key_.size());
            host_.unlock();
            for (size_t i = 0; i < 33; ++i) msg[1 + i] = static_cast<uint8_t>(plain[i] ^ stream[i]);
            crypto::wipe(plain, sizeof(plain));
            crypto::wipe(stream, sizeof(stream));
            pairTag(*k, "key", msg + 1, 33, msg + 34);
            for (uint32_t t0 = host_.now(); !done && host_.now() - t0 < kPairStepMs;) {
                sendLocked(joiner, msg, sizeof(msg), false);
                done = waitFor([this] { return pairing_.done; }, kPairRequestIntervalMs);
            }
            if (done) {
                uint8_t expect[16];
                pairTag(*k, "done", nullptr, 0, expect);
                host_.lock();
                done = crypto::equal(expect, pairing_.doneTag, 16);
                host_.unlock();
            }
        }

        host_.lock();
        Pairing fresh = Pairing();
        fresh.role = Pairing::Member;
        pairing_ = fresh;  // ready for the next joiner
        host_.unlock();
        if (done) {
            if (joined) *joined = joiner;
            result = Status::Ok;
            break;
        }
        // Keep the window open for the rest of its time: another node may get it right.
    }
    if (result != Status::Ok) result = failed ? Status::AuthFailed : Status::Timeout;
    host_.lock();
    pairing_ = Pairing();
    host_.unlock();
    return result;
}

Status Security::pair(uint32_t timeoutMs, Mac* member) {
    if (!running_) return Status::InvalidState;
    host_.lock();
    if (pairing_.role != Pairing::None) {
        host_.unlock();
        return Status::InvalidState;
    }
    pairing_ = Pairing();
    pairing_.role = Pairing::Joiner;
    host_.unlock();

    uint8_t priv[32], pub[32], nonce[16];
    randomBytes(priv, sizeof(priv));
    randomBytes(nonce, sizeof(nonce));
    crypto::x25519Base(pub, priv);
    host_.lock();
    memcpy(pairing_.nonce, nonce, 16);
    host_.unlock();

    uint8_t request[49];
    request[0] = kPairRequest;
    memcpy(request + 1, pub, 32);
    memcpy(request + 33, nonce, 16);

    Status result = Status::Timeout;
    uint32_t deadline = host_.now() + timeoutMs;
    while (!reached(host_.now(), deadline)) {
        sendLocked(Mac::broadcast(), request, sizeof(request), false);
        if (!waitFor([this] { return pairing_.offer; }, kPairRequestIntervalMs)) continue;

        host_.lock();
        Mac from = pairing_.member;
        uint8_t memberPub[32], memberNonce[16], offerTag[16];
        memcpy(memberPub, pairing_.memberPub, 32);
        memcpy(memberNonce, pairing_.memberNonce, 16);
        memcpy(offerTag, pairing_.offerTag, 16);
        host_.unlock();

        uint8_t dh[32];
        crypto::x25519(dh, priv, memberPub);
        std::unique_ptr<PairKeys> k(new PairKeys());
        derivePairKeys(config_.pairingCode, dh, local_, from, pub, nonce, memberPub, memberNonce, *k);
        bool ok = !allZero(dh, sizeof(dh));
        crypto::wipe(dh, sizeof(dh));
        uint8_t expect[16];
        pairTag(*k, "offer", nullptr, 0, expect);
        if (!ok || !crypto::equal(expect, offerTag, 16)) {
            // A member with another pairing code (or an impostor): say so, and keep looking.
            uint8_t refusal[1] = {kPairRefused};
            sendLocked(from, refusal, sizeof(refusal), false);
            result = Status::AuthFailed;
            host_.lock();
            pairing_.offer = false;
            host_.unlock();
            host_.sleep(kPairRequestIntervalMs);
            continue;
        }

        uint8_t proof[17];
        proof[0] = kPairProof;
        pairTag(*k, "proof", nullptr, 0, proof + 1);
        bool gotKey = false;
        for (uint32_t t0 = host_.now(); !gotKey && host_.now() - t0 < kPairStepMs;) {
            sendLocked(from, proof, sizeof(proof), false);
            gotKey = waitFor([this] { return pairing_.keyMsg; }, kPairRequestIntervalMs);
        }
        uint8_t plain[33];
        bool valid = false;
        if (gotKey) {
            host_.lock();
            uint8_t sealed[33], tag[16];
            memcpy(sealed, pairing_.sealedKey, 33);
            memcpy(tag, pairing_.keyTag, 16);
            host_.unlock();
            pairTag(*k, "key", sealed, 33, expect);
            if (crypto::equal(expect, tag, 16)) {
                uint8_t stream[33];
                keystream(*k, stream);
                for (size_t i = 0; i < 33; ++i) plain[i] = static_cast<uint8_t>(sealed[i] ^ stream[i]);
                crypto::wipe(stream, sizeof(stream));
                valid = plain[0] >= kMinKey && plain[0] <= kMaxKey;
            }
        }
        if (!valid) {
            host_.lock();
            pairing_.offer = pairing_.keyMsg = false;
            host_.unlock();
            continue;
        }

        host_.lock();
        installKey(plain + 1, plain[0]);
        host_.unlock();
        crypto::wipe(plain, sizeof(plain));

        uint8_t done[17];
        done[0] = kPairDone;
        pairTag(*k, "done", nullptr, 0, done + 1);
        // The member resends the key until it hears this; a few copies cover losses.
        for (int i = 0; i < 3; ++i) {
            sendLocked(from, done, sizeof(done), false);
            host_.sleep(30);
        }
        if (member) *member = from;
        result = Status::Ok;
        break;
    }
    crypto::wipe(priv, sizeof(priv));
    host_.lock();
    pairing_ = Pairing();
    host_.unlock();
    if (result == Status::Ok && keyHandler_) keyHandler_(key());
    return result;
}

}  // namespace nowtp
