// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <string>
#include <vector>

#include "engine.h"

namespace nowtp {

/// A peer seen by discovery.
struct PeerInfo {
    Mac mac;
    std::string name;
    std::vector<uint8_t> metadata;
    uint16_t maxFrameSize = 250;  ///< Largest frame the peer's driver can receive.
    int8_t rssi = 0;              ///< Signal strength of its last announcement, dBm.
    uint32_t firstSeenMs = 0;
    uint32_t lastSeenMs = 0;
    /// Wi-Fi channel the peer says it is on; 0 if it does not say (NowTP < 0.5).
    uint8_t channel = 0;
    /// Its channel is fixed (by an access point, or by configuration): other
    /// nodes follow it when it moves (see ChannelFollower).
    bool anchor = false;
    /// It offers its clock as the network time (see TimeSync).
    bool timeReference = false;
    /// Its announcements are authenticated with the installation key (see Security).
    bool authenticated = false;
};

enum class PeerEvent : uint8_t {
    Found,    ///< First announcement from this peer.
    Updated,  ///< Its name, metadata or frame size changed.
    Lost,     ///< Said goodbye, or silent for DiscoveryConfig::peerTimeoutMs.
};

using PeerHandler = std::function<void(PeerEvent, const PeerInfo&)>;
/// A peer announced that it is moving to another channel.
using MoveHandler = std::function<void(const PeerInfo&, uint8_t channel)>;

struct DiscoveryConfig {
    /// Human-readable name announced to others (at most 32 bytes).
    std::string name;
    /// Application data announced to others (at most 160 bytes), e.g. a role or
    /// service list. Peers can filter on it.
    std::vector<uint8_t> metadata;
    /// Periodic announcement interval; 0 announces only on start, on discover()
    /// and in reply to other nodes' queries.
    uint32_t announceIntervalMs = 2000;
    /// A peer is reported lost after this long without an announcement.
    uint32_t peerTimeoutMs = 7000;
    /// Replies to a query are delayed randomly by up to this much to avoid collisions.
    uint32_t replyJitterMs = 50;
    /// Peers tracked at most; further ones are ignored until a slot frees up.
    uint8_t maxPeers = 20;
};

/// Peer discovery over broadcast announcements on kDiscoveryPort.
///
/// Platform-independent: runs on an Engine, driven by tick(). Every node
/// announces itself periodically; a query (discover(), sent automatically by
/// start()) makes every listening node announce itself promptly.
class Discovery {
public:
    static constexpr size_t kMaxName = 32;
    static constexpr size_t kMaxMetadata = 160;

    /// `random` supplies jitter; `localMaxFrameSize` is announced to peers.
    Discovery(Engine& engine, const DiscoveryConfig& config, uint16_t localMaxFrameSize,
              std::function<uint32_t()> random);
    ~Discovery();

    Discovery(const Discovery&) = delete;
    Discovery& operator=(const Discovery&) = delete;

    /// Starts listening and sends a query.
    void start(uint32_t nowMs);
    /// Sends a goodbye and forgets all peers (no Lost events).
    void stop(uint32_t nowMs);
    /// Tells peers we are about to switch to `channel`; they report us lost
    /// and may follow (see ChannelFollower). Sent a few times since broadcast
    /// is not acknowledged.
    bool announceMove(uint8_t channel, uint32_t nowMs);
    /// Asks every node in range to announce itself.
    void discover(uint32_t nowMs);
    void tick(uint32_t nowMs);

    void setMetadata(const uint8_t* data, size_t len, uint32_t nowMs);
    /// What this node announces about its radio; announced right away when it changes.
    void setChannelInfo(uint8_t channel, bool anchor, uint32_t nowMs);
    void setTimeReference(bool reference, uint32_t nowMs);
    void onPeerEvent(PeerHandler handler) { handler_ = std::move(handler); }
    void onPeerMoved(MoveHandler handler) { moveHandler_ = std::move(handler); }

    const std::vector<PeerInfo>& peers() const { return peers_; }
    const PeerInfo* find(const Mac& mac) const;

    /// A parsed announcement payload (as carried on kDiscoveryPort).
    struct Announcement {
        uint8_t flags = 0;
        uint16_t maxFrameSize = 0;
        std::string name;
        const uint8_t* metadata = nullptr;
        size_t metadataLen = 0;
        uint8_t channel = 0;  ///< 0 when the sender does not say.
        uint8_t extFlags = 0;
        uint8_t moveTo = 0;   ///< Channel of a moving notice, else 0.
    };
    static bool parse(const uint8_t* data, size_t len, Announcement& out);
    static bool parseAnnouncement(const uint8_t* data, size_t len, std::string& name, uint16_t& maxFrameSize);

private:
    enum Flags : uint8_t { kQuery = 0x01, kReply = 0x02, kGoodbye = 0x04, kMoving = 0x08 };
    enum ExtFlags : uint8_t { kExtAnchor = 0x01, kExtTimeReference = 0x02 };

    void handle(const Message& m);
    bool announce(uint8_t flags, uint8_t moveTo = 0);
    void emit(PeerEvent event, const PeerInfo& peer);

    Engine& engine_;
    DiscoveryConfig config_;
    uint16_t localMaxFrameSize_;
    std::function<uint32_t()> random_;
    PeerHandler handler_;
    MoveHandler moveHandler_;
    std::vector<PeerInfo> peers_;
    uint8_t channel_ = 0;
    uint8_t extFlags_ = 0;
    uint32_t now_ = 0;
    uint32_t nextAnnounce_ = 0;
    uint32_t replyAt_ = 0;
    uint32_t retryAt_ = 0;
    bool replyDue_ = false;
    bool queryDue_ = false;
    bool announceDue_ = false;
    bool retryPending_ = false;
    bool running_ = false;
};

}  // namespace nowtp
