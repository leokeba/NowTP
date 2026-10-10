// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <string>
#include <vector>

#include "engine.h"
#include "host.h"

namespace nowtp {

struct SecurityConfig {
    /// Installation key shared by every trusted node, 16 to 32 bytes. Empty
    /// leaves security off until pairing or Security::setKey() provides one.
    std::vector<uint8_t> key;
    /// With a key, drop every message not authenticated with it, except the
    /// pairing and challenge traffic on kSecurityPort. When false,
    /// unauthenticated messages are still delivered, with
    /// Message::authenticated false, and the application decides.
    bool requireAuthentication = true;
    /// Optional secret that both sides of a pairing must know. It keeps a node
    /// from joining the wrong installation when several have a pairing window
    /// open. Only a long random code also defeats an active attacker present
    /// during the pairing window (see docs/PROTOCOL.md).
    std::string pairingCode;
    /// Senders whose replay state is remembered; the least recently heard is
    /// forgotten first (it then has to answer a challenge again).
    uint8_t maxPeers = 32;
};

/// Message authentication with a shared installation key, and pairing to
/// hand that key to new nodes.
///
/// With a key, every message (application ports, discovery, diagnostics, time
/// sync, streams) carries an HMAC-SHA256 tag over its content, sender,
/// destination and port, plus the sender's boot epoch and a sequence number
/// against replays. Acks of authenticated messages are tagged too, so only a
/// key holder can confirm or refuse delivery. The first message from a sender
/// in a new boot epoch is held back until the sender answers a challenge
/// proving the epoch is live; reliable senders retry transparently, and
/// discovery announcements usually complete that exchange before the
/// application sends anything.
///
/// Pairing: a member opens a window with acceptPairing(); a new node calls
/// pair(). The two run an X25519 key exchange, prove to each other that they
/// know the pairing code, and the member sends the installation key encrypted.
/// Anyone in range during an open window without a pairing code can join, so
/// keep windows short (e.g. on a button press).
///
/// Every key holder can impersonate every other one: the key authenticates
/// membership of the installation, not individual nodes. Message content is
/// not encrypted.
class Security : public Authenticator {
public:
    static constexpr size_t kMinKey = 16;
    static constexpr size_t kMaxKey = 32;

    using KeyHandler = std::function<void(const std::vector<uint8_t>& key)>;

    Security(Engine& engine, ServiceHost& host, const Mac& localMac, const SecurityConfig& config = SecurityConfig());
    ~Security();

    Security(const Security&) = delete;
    Security& operator=(const Security&) = delete;

    /// Listens on kSecurityPort and starts authenticating through the engine.
    void start();
    void stop();
    void tick(uint32_t nowMs);

    /// Installs (16-32 bytes) or removes (`len` 0) the installation key.
    /// Takes the host lock.
    Status setKey(const uint8_t* key, size_t len);
    bool enabled() const { return !key_.empty(); }
    /// A copy of the installation key (empty without one). Takes the host lock.
    std::vector<uint8_t> key();
    /// Called after pair() or acceptPairing() installed a new key, in the
    /// caller's task, without the lock: a place to persist it.
    void onKeyChanged(KeyHandler handler) { keyHandler_ = std::move(handler); }
    /// Called (engine context) when a peer proved a new boot epoch. Messages it
    /// sent before were held back: e.g. ask for announcements again.
    void onPeerVerified(std::function<void(const Mac&)> handler) { verifiedHandler_ = std::move(handler); }

    // --- Blocking procedures (application task, never a NowTP callback) -------

    /// Opens a pairing window and waits for one node to join. Creates a random
    /// installation key first if this node has none. Returns AuthFailed if only
    /// nodes with another pairing code tried, Timeout if nobody did.
    Status acceptPairing(uint32_t timeoutMs, Mac* joined = nullptr);
    /// Looks for a member with an open pairing window and obtains the
    /// installation key from it. Returns AuthFailed if only members with
    /// another pairing code answered, Timeout if none did.
    Status pair(uint32_t timeoutMs, Mac* member = nullptr);

    struct Counters {
        uint32_t challengesSent = 0;
        uint32_t challengesAnswered = 0;  ///< Challenges we answered for others.
        uint32_t epochsVerified = 0;
        uint32_t replaysRejected = 0;
        uint32_t forgeriesRejected = 0;  ///< Bad tags, and unauthenticated messages refused.
    };
    const Counters& counters() const { return counters_; }

    // --- Authenticator ---------------------------------------------------------
    bool sealing(uint8_t port) const override;
    void seal(const Mac& dst, uint8_t port, uint8_t flags, const uint8_t* data, size_t len, uint8_t* trailer) override;
    Verdict open(const Mac& src, uint8_t port, uint8_t flags, const uint8_t* data, size_t len, const uint8_t* trailer,
                 uint32_t nowMs) override;
    void sealAck(const Mac& dst, const uint8_t* frame, size_t len, uint8_t* tag) override;
    bool openAck(const Mac& src, const uint8_t* frame, size_t len, const uint8_t* tag) override;

private:
    enum MsgType : uint8_t {
        kChallenge = 1,
        kResponse = 2,
        kPairRequest = 3,
        kPairOffer = 4,
        kPairProof = 5,
        kPairKey = 6,
        kPairDone = 7,
        kPairRefused = 8,
    };

    struct Peer {
        Mac mac;
        bool verified = false;
        uint32_t epoch = 0;
        uint32_t highest = 0;
        uint64_t window = 0;  // bit i: sequence `highest - i` seen
        uint32_t verifiedAt = 0;
        uint32_t lastUse = 0;
        bool challenging = false;
        uint8_t nonce[8];
        uint32_t challengeAt = 0;
        uint8_t tries = 0;
    };

    struct Pairing {
        enum Role : uint8_t { None, Member, Joiner } role = None;
        // Member
        bool busy = false;
        bool request = false;
        Mac joiner;
        uint8_t joinerPub[32];
        uint8_t joinerNonce[16];
        bool proof = false;
        uint8_t proofTag[16];
        bool done = false;
        uint8_t doneTag[16];
        bool refused = false;  // the joiner could not verify our offer: another code
        // Joiner
        uint8_t nonce[16];
        bool offer = false;
        Mac member;
        uint8_t memberPub[32];
        uint8_t memberNonce[16];
        uint8_t offerTag[16];
        bool keyMsg = false;
        uint8_t sealedKey[33];
        uint8_t keyTag[16];
    };

    void handle(const Message& m);
    void deriveKeys();
    void messageTag(const Mac& src, const Mac& dst, uint8_t port, uint8_t flags, const uint8_t* head,
                    const uint8_t* data, size_t len, uint8_t* out);
    Peer* peer(const Mac& mac, bool create, uint32_t now);
    void challenge(Peer& p, uint32_t now);
    void respond(const Mac& to, const uint8_t* nonce, uint32_t now);
    void verifyResponse(const Mac& from, const uint8_t* d, size_t len, uint32_t now);
    bool acceptSequence(Peer& p, uint32_t seq);

    // Pairing helpers (host lock not held unless noted).
    void randomBytes(uint8_t* out, size_t len);
    Status sendLocked(const Mac& dst, const uint8_t* data, size_t len, bool reliable);
    bool waitFor(const std::function<bool()>& done, uint32_t timeoutMs);
    void installKey(const uint8_t* key, size_t len);

    Engine& engine_;
    ServiceHost& host_;
    Mac local_;
    SecurityConfig config_;
    KeyHandler keyHandler_;
    std::function<void(const Mac&)> verifiedHandler_;
    bool running_ = false;
    uint32_t now_ = 0;

    std::vector<uint8_t> key_;
    uint8_t msgKey_[32];
    uint8_t ackKey_[32];
    uint8_t challengeKey_[32];
    uint32_t epoch_ = 0;
    uint32_t seq_ = 0;
    std::vector<Peer> peers_;
    uint32_t responseWindowStart_ = 0;
    uint8_t responsesInWindow_ = 0;
    Pairing pairing_;
    Counters counters_;
};

}  // namespace nowtp
