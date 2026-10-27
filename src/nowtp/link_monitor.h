// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include "deadline.h"
#include "engine.h"

namespace nowtp {

/// Watches links from what the radio reports, for the transport: which peers
/// we hear, and which of our frames they acknowledge. It finds one-way links
/// (our frames fail while the peer's own arrive), pings newly discovered
/// peers to see that they hear us, and, with the power fallback on, looks
/// for a lower transmit power that a weak supply sustains. A lower power that
/// works is re-checked at the original one: a peer briefly away (rebooting,
/// on another channel) is not a power problem. Platform-independent; runs
/// under the transport's lock. Its pings complete into it: it must outlive
/// the engine's queue (Engine::cancelAll(), or the engine itself).
class LinkMonitor {
public:
    enum class Event : uint8_t {
        OneWay,          ///< Frames to `peer` fail while its own arrive (reported once per peer).
        FallbackStarted, ///< Trying lower powers for `peer`, first `toDbm`.
        PowerKept,       ///< `peer` got through at `fromDbm` again: it was away, power is unchanged.
        PowerLowered,    ///< Lowered from `fromDbm` to `toDbm`, which `peer` acknowledges.
        FallbackFailed,  ///< No lower power reached `peer`; back at `fromDbm`.
    };

    /// The radio's power, and where events go (logs, statistics).
    class Host {
    public:
        virtual ~Host() {}
        virtual float txPower() const = 0;
        virtual void setTxPower(float dbm) = 0;
        virtual void linkEvent(Event event, const Mac& peer, float fromDbm, float toDbm) = 0;
    };

    static constexpr size_t kMaxPeers = 20;  ///< Peers heard, for one-way detection.
    static constexpr size_t kMaxChecks = 8;  ///< New peers being checked at once.
    static constexpr uint16_t kOneWayFailures = 8;  ///< Consecutive failed frames...
    static constexpr uint32_t kOneWayHeardMs = 3000;  ///< ...to a peer heard this recently.

    LinkMonitor(Engine& engine, Host& host);
    LinkMonitor(const LinkMonitor&) = delete;
    LinkMonitor& operator=(const LinkMonitor&) = delete;

    /// Forgets every peer; `powerFallback` turns the fallback and the checks
    /// of new peers on or off.
    void reset(bool powerFallback);
    /// A frame arrived from `peer`.
    void heard(const Mac& peer, uint32_t now);
    /// The radio reported a frame to `peer` acknowledged or not.
    void sent(const Mac& peer, bool delivered, uint32_t now);
    /// Discovery found `peer`: check that it hears us.
    void found(const Mac& peer, uint32_t now);
    void tick(uint32_t now);
    void nextTick(Deadline& d) const;

    bool fallbackActive() const { return fallback_.active; }

private:
    struct Health {
        Mac mac;
        uint32_t lastHeardMs;
        uint16_t failures;
        bool warned;
    };
    struct Check {
        uint32_t id;  // the completion captures it (with `this`: nothing to allocate)
        Mac peer;
        uint8_t remaining;
        bool inFlight;
        uint32_t nextAt;
    };
    struct Fallback {
        bool active = false;
        Mac peer;
        float original = 0;
        float ladder[6];
        size_t steps = 0;
        size_t index = 0;
        uint8_t failures = 0;
        bool pingInFlight = false;
        bool confirming = false;  // re-testing the original power after a success
        uint32_t nextPingAt = 0;
        Mac tried[8];  // the most recent peers tried
        size_t triedCount = 0;
    };

    Health* health(const Mac& mac);
    Health* addHealth(const Mac& mac, uint32_t now);
    void startFallback(const Mac& peer, uint32_t now);
    void sendFallbackPing(uint32_t now);
    void onFallbackPing(Status status);
    void onCheck(uint32_t id, Status status);

    Engine& engine_;
    Host& host_;
    bool powerFallback_ = true;
    Health health_[kMaxPeers];
    size_t healthCount_ = 0;
    Check checks_[kMaxChecks];
    size_t checkCount_ = 0;
    uint32_t nextCheckId_ = 0;
    Fallback fallback_;
};

const char* toString(LinkMonitor::Event event);

}  // namespace nowtp
