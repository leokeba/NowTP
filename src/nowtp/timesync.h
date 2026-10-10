// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <vector>

#include "discovery.h"
#include "engine.h"

namespace nowtp {

struct TimeSyncConfig {
    /// Offer this node's clock as the network time. Other nodes find it through
    /// discovery (the lowest MAC wins if several offer) unless the application
    /// picks one with TimeSync::setReference(). Configure one reference per
    /// installation.
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
    /// Answer other nodes' time requests.
    bool respond = true;
};

struct TimeSyncStatus {
    bool synced = false;       ///< A recent estimate exists (or this node is the reference).
    bool isReference = false;  ///< This node's clock is the network time.
    Mac reference;             ///< Node whose clock is the network time.
    int64_t offsetUs = 0;      ///< Network time minus local time, now.
    uint32_t roundTripUs = 0;  ///< Shortest round trip of the last round.
    float driftPpm = 0;        ///< How fast the offset grows, in µs per second.
    uint32_t ageMs = 0;        ///< Since the last successful round.
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
/// Platform-independent: the owner provides a microsecond clock and calls
/// tick(), and feeds discovery events for automatic reference selection.
class TimeSync {
public:
    using Clock = std::function<uint64_t()>;

    TimeSync(Engine& engine, Clock localClockUs, const TimeSyncConfig& config = TimeSyncConfig());
    ~TimeSync();

    TimeSync(const TimeSync&) = delete;
    TimeSync& operator=(const TimeSync&) = delete;

    void start(uint32_t nowMs);
    void stop();
    void tick(uint32_t nowMs);

    /// Discovery events: picks the announced reference unless one was set.
    void onPeerEvent(PeerEvent event, const PeerInfo& peer, uint32_t nowMs);
    /// Synchronizes with `mac` instead of the reference announced through
    /// discovery. A node that is itself synchronized answers in network time,
    /// so any synchronized node can serve as a time source.
    void setReference(const Mac& mac, uint32_t nowMs);
    /// Back to the reference announced through discovery.
    void clearReference(uint32_t nowMs);

    bool isReference() const { return config_.reference; }
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

    void handle(const Message& m);
    void chooseReference(uint32_t now);
    void switchTo(const Mac& mac, bool known, uint32_t now);
    void sendRequest(uint32_t now);
    void endRound(uint32_t now);
    void addSample(uint64_t localUs, int64_t offsetUs, uint32_t rttUs);
    void fit();
    int64_t offsetAt(uint64_t localUs) const;

    Engine& engine_;
    Clock clock_;
    TimeSyncConfig config_;
    bool running_ = false;
    uint32_t now_ = 0;

    bool explicitRef_ = false;
    bool haveRef_ = false;
    Mac ref_;
    std::vector<Mac> announced_;  // peers announcing themselves as references

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

    // Estimate: offset(t) = base_ + drift_ * (t - baseLocal_)
    std::vector<Sample> samples_;
    bool haveEstimate_ = false;
    uint64_t baseLocal_ = 0;
    int64_t base_ = 0;
    double drift_ = 0;  // µs per µs
    uint64_t lastSyncLocal_ = 0;
    uint32_t lastRtt_ = 0;
    uint32_t rounds_ = 0;
    uint8_t rejected_ = 0;
};

}  // namespace nowtp
