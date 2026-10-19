// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <vector>

#include "discovery.h"
#include "engine.h"

namespace nowtp {

/// What a node does about network time. EspNowTransport::setTimeRole()
/// changes it at runtime.
enum class TimeRole : uint8_t {
    /// No synchronization: network time is the local clock. Requests are still
    /// answered (TimeSyncConfig::respond).
    Off,
    /// Synchronizes with the reference announced through discovery, and never
    /// becomes one.
    Follow,
    /// Follows the reference announced through discovery, and offers to take
    /// over: when none is heard for TimeSyncConfig::takeoverAfterMs, one
    /// candidate becomes the reference (synchronized ones first, then the
    /// lowest MAC), keeping the network time it had. A fleet of identical
    /// nodes, all candidates, thus agrees on one reference without
    /// configuration, and keeps its time when the reference goes away.
    Candidate,
    /// Always the reference. Followers prefer it to an acting candidate.
    Reference,
};

const char* toString(TimeRole role);

struct TimeSyncConfig {
    TimeRole role = TimeRole::Follow;
    /// Same as role = TimeRole::Reference (kept for older code).
    bool reference = false;
    /// Pause between synchronization rounds once synchronized. The first rounds
    /// run every second.
    uint32_t intervalMs = 5000;
    /// Request/response exchanges per round; the one with the shortest round
    /// trip is used, since queueing delays only ever add to it.
    uint8_t samples = 8;
    uint32_t sampleSpacingMs = 15;
    /// Synchronization counts as lost after this long without a successful round.
    uint32_t staleAfterMs = 60000;
    /// Candidate role: how long no reference must be heard before the first
    /// candidate takes over. The next one in line waits twice as long, and so on.
    uint32_t takeoverAfterMs = 5000;
    /// Answer other nodes' time requests.
    bool respond = true;
};

struct TimeSyncStatus {
    TimeRole role = TimeRole::Follow;
    bool synced = false;       ///< A recent estimate exists (or this node is the reference).
    bool isReference = false;  ///< This node's clock is the network time (it acts as the reference).
    /// The reference was chosen with setReference(), not through discovery.
    bool explicitReference = false;
    Mac reference = Mac();     ///< Node whose clock is the network time (this node, while it acts).
    int64_t offsetUs = 0;      ///< Network time minus local time, now.
    uint32_t roundTripUs = 0;  ///< Shortest round trip of the last round (0 while acting).
    float driftPpm = 0;        ///< How fast the offset grows, in µs per second.
    uint32_t ageMs = 0;        ///< Since the last successful round (0 while acting).
    uint32_t rounds = 0;       ///< Successful rounds with the current reference.
};

/// Network time: every node estimates the offset between its clock and the
/// reference node's clock, so that an instant can be named in network time
/// ("start at T") and every node acts at that instant on its own clock.
///
/// The estimate comes from NTP-style exchanges on kTimeSyncPort, with receive
/// times taken when the radio delivers each frame. Between two boards about a
/// meter apart, the error is typically well under a millisecond; a drift
/// estimate keeps it there between rounds.
///
/// Which node is the reference follows from the roles (see TimeRole), which
/// discovery announces. A node that becomes the reference while synchronized
/// keeps serving the network time it had (its estimate, extrapolated with the
/// drift), so the shared clock doesn't jump when the reference changes.
///
/// Platform-independent: the owner provides a microsecond clock and calls
/// tick(), and feeds discovery events for automatic reference selection.
class TimeSync {
public:
    using Clock = std::function<uint64_t()>;

    /// `localMac` is the address peers see this node send from: candidates
    /// compare it with theirs.
    TimeSync(Engine& engine, Clock localClockUs, const TimeSyncConfig& config = TimeSyncConfig(),
             const Mac& localMac = Mac());
    ~TimeSync();

    TimeSync(const TimeSync&) = delete;
    TimeSync& operator=(const TimeSync&) = delete;

    /// Where this node's role is announced (or none). Called before start().
    void setDiscovery(Discovery* discovery);
    void start(uint32_t nowMs);
    void stop();
    void tick(uint32_t nowMs);

    /// Discovery events: picks the announced reference unless one was set.
    void onPeerEvent(PeerEvent event, const PeerInfo& peer, uint32_t nowMs);
    void setRole(TimeRole role, uint32_t nowMs);
    TimeRole role() const { return role_; }
    /// Synchronizes with `mac` instead of the reference announced through
    /// discovery, in the Follow and Candidate roles (a candidate then doesn't
    /// take over). A node that is itself synchronized answers in network time,
    /// so any synchronized node can serve as a time source.
    void setReference(const Mac& mac, uint32_t nowMs);
    /// Back to the reference announced through discovery.
    void clearReference(uint32_t nowMs);
    /// Pause between rounds once synchronized (at least 1 s).
    void setInterval(uint32_t ms);

    /// This node acts as the reference: its network time is the network time.
    bool isReference() const { return acting_; }
    bool synced() const;
    /// Current network time in µs (the local clock while unsynchronized).
    uint64_t networkTime() const { return toNetwork(clock_()); }
    uint64_t toNetwork(uint64_t localUs) const;
    uint64_t toLocal(uint64_t networkUs) const;
    TimeSyncStatus status() const;

private:
    enum MsgType : uint8_t { kRequest = 1, kResponse = 2 };

    struct Sample {
        uint64_t localUs;
        int64_t offsetUs;
    };
    /// A peer that acts as the reference or offers to.
    struct Offer {
        Mac mac;
        bool acting;
        bool candidate;
        bool synced;
    };

    void handle(const Message& m);
    void evaluate(uint32_t now);
    const Offer* bestActing() const;
    bool aheadOfUs(const Offer& o) const;
    void act(bool acting, uint32_t now);
    void publish();
    void switchTo(const Mac& mac, uint32_t now);
    void forget();
    void sendRequest(uint32_t now);
    void endRound(uint32_t now);
    bool addSample(uint64_t localUs, int64_t offsetUs, uint32_t rttUs);
    void fit();
    int64_t offsetAt(uint64_t localUs) const;

    Engine& engine_;
    Clock clock_;
    TimeSyncConfig config_;
    Mac self_;
    Discovery* discovery_ = nullptr;
    TimeRole role_;
    bool running_ = false;
    uint32_t now_ = 0;

    bool acting_ = false;
    bool explicitRef_ = false;
    bool haveRef_ = false;
    Mac ref_ = Mac();
    Mac explicit_ = Mac();
    std::vector<Offer> offers_;
    bool vacant_ = true;  // no acting reference heard, since vacantSince_
    uint32_t vacantSince_ = 0;
    int published_ = -1;  // flags last given to discovery

    // Current round
    bool roundActive_ = false;
    uint8_t round_ = 0;
    uint8_t sent_ = 0;
    uint32_t nextSampleAt_ = 0;
    uint32_t lastSentAt_ = 0;
    uint32_t nextRoundAt_ = 0;
    bool haveBest_ = false;
    uint64_t bestLocal_ = 0;
    int64_t bestOffset_ = 0;
    uint32_t bestRtt_ = 0;

    // Estimate: offset(t) = base_ + drift_ * (t - baseLocal_). Frozen while acting.
    std::vector<Sample> samples_;
    bool haveEstimate_ = false;
    bool carried_ = false;  // the estimate comes from the previous reference (or from acting)
    uint64_t baseLocal_ = 0;
    int64_t base_ = 0;
    double drift_ = 0;  // µs per µs
    uint64_t lastSyncLocal_ = 0;
    uint32_t lastRtt_ = 0;
    uint32_t minRtt_ = 0;  // shortest round trip accepted lately
    uint32_t rounds_ = 0;
    uint8_t rejected_ = 0;
};

}  // namespace nowtp
