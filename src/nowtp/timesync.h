// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <atomic>
#include <vector>

#include "discovery.h"
#include "engine.h"
#include "heap.h"

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
    uint8_t samples = 8;  ///< At most 16.
    uint32_t sampleSpacingMs = 15;
    /// Synchronization counts as lost after this long without a successful round.
    uint32_t staleAfterMs = 60000;
    /// Candidate role: how long no reference must be heard before the first
    /// candidate takes over. The next one in line waits twice as long, and so on.
    uint32_t takeoverAfterMs = 5000;
    /// Answer other nodes' time requests.
    bool respond = true;
    /// Ask the reference to measure, every this often, how far our network
    /// time is from its own (a round in the other direction), and correct the
    /// difference: what remains of the radio driver's delays after send-time
    /// stamps differs between requests and responses (~20 µs on ESP32). 0: never.
    uint32_t calibrationIntervalMs = 10000;
    /// Carriers without discovery of their own (see TimeCarrier::hasDiscovery()):
    /// how often the reference and the candidates broadcast an offer beacon,
    /// and how long an offer heard that way lasts. As NowTP's discovery.
    uint32_t beaconIntervalMs = 2000;
    uint32_t beaconTimeoutMs = 7000;
};

struct TimeSyncStatus {
    TimeRole role = TimeRole::Follow;
    bool synced = false;       ///< A recent estimate exists (or this node is the reference).
    bool isReference = false;  ///< This node's clock is the network time (it acts as the reference).
    /// The reference was chosen with setReference(), not through discovery.
    bool explicitReference = false;
    Mac reference = Mac();     ///< Node whose clock is the network time (this node, while it acts).
    /// The carrier (TimeCarrier::name()) the reference is followed over; ""
    /// while acting or without a reference.
    const char* carrier = "";
    int64_t offsetUs = 0;      ///< Network time minus local time, now.
    uint32_t roundTripUs = 0;  ///< Shortest round trip of the last round (0 while acting).
    float driftPpm = 0;        ///< How fast the offset grows, in µs per second.
    uint32_t ageMs = 0;        ///< Since the last successful round (0 while acting).
    uint32_t rounds = 0;       ///< Successful rounds with the current reference (and carrier).
    /// Correction from the reference's measurements, subtracted from the
    /// estimate (see TimeSyncConfig::calibrationIntervalMs), µs.
    int32_t calibrationUs = 0;
    uint8_t calibrations = 0;  ///< Reference measurements held (up to 9), on the carrier in use.
};

class TimeSync;
class EngineTimeCarrier;

/// How much a carrier's exchanges vary: the bounds of TimeSync's tests for
/// rounds held up in queues and for outliers.
struct TimeCarrierLimits {
    /// A round whose shortest round trip exceeds twice the shortest seen
    /// lately, plus this, waited in a queue: it is skipped.
    uint32_t slowRoundUs = 1500;
    /// A round whose offset is further than this, plus 4 round trips, from
    /// the estimate is an outlier (three in a row are believed).
    uint32_t outlierUs = 2000;
};

/// What carries TimeSync's datagrams to other devices: ESP-NOW
/// (EngineTimeCarrier), UDP, anything that can send a short datagram to a
/// device and say when it left. Devices are named by a 6-byte id (a station
/// MAC), the same on every carrier.
///
/// The carrier reports back to the TimeSync it was added to: received() with
/// what arrives, stamped with the local clock (the TimeSync's) as early as
/// possible, and sent() with when a datagram left. It may queue them and
/// deliver them in poll(), which tick() calls, so that the TimeSync runs in
/// one task.
class TimeCarrier {
public:
    virtual ~TimeCarrier() {}
    /// Short name for status: "nowtp", "udp/ethernet". Must outlive the carrier's use.
    virtual const char* name() const = 0;
    /// Sends a datagram (at most TimeSync::kMaxDatagram bytes) to `device`, or
    /// to every device the carrier reaches when it is Mac::broadcast() (offer
    /// beacons only). Ok: taken; `*token` then names it in sent() reports.
    /// QueueFull: try again shortly. Anything else: not sent.
    virtual Status send(const Mac& device, const uint8_t* data, size_t len, uint32_t* token) = 0;
    /// Whether `device` can be reached on this carrier now.
    virtual bool reaches(const Mac& device) const = 0;
    /// The carrier announces our role itself (NowTP's discovery), through
    /// announce(), and reports others' with TimeSync::offer(). Otherwise
    /// TimeSync broadcasts offer beacons on it.
    virtual bool hasDiscovery() const { return false; }
    virtual void announce(bool /*acting*/, bool /*candidate*/, bool /*synced*/) {}
    /// Called by TimeSync::tick(): a carrier that queues what it receives delivers it here.
    virtual void poll(TimeSync& /*core*/) {}
    /// poll() has something to deliver (TimeSync::nextTick() then asks for a tick now).
    virtual bool pending() const { return false; }
    virtual TimeCarrierLimits limits() const { return TimeCarrierLimits(); }
};

/// Network time: every node estimates the offset between its clock and the
/// reference node's clock, so that an instant can be named in network time
/// ("start at T") and every node acts at that instant on its own clock.
///
/// The estimate comes from NTP-style exchanges, with receive times taken when
/// the carrier delivers each datagram and send times when it reports one gone.
/// Between two ESP32 boards about a meter apart on ESP-NOW, the error is
/// typically well under a millisecond; a drift estimate keeps it there
/// between rounds.
///
/// Which node is the reference follows from the roles (see TimeRole),
/// announced through NowTP's discovery or offer beacons. A node that becomes
/// the reference while synchronized keeps serving the network time it had
/// (its estimate, extrapolated with the drift), so the shared clock doesn't
/// jump when the reference changes.
///
/// Carriers (see TimeCarrier): one election runs across all of them, offers
/// merged by device. A follower reaches the reference over the first carrier
/// in order that reaches() it, and moves to the next when that one stops
/// reaching it or a round gets no answer, keeping its estimate; a node answers
/// each request on the carrier it came by. Calibration is kept per carrier.
///
/// Platform-independent. The owner provides a µs clock, calls tick(), and runs
/// every call in one task (or under one lock), except networkTime(),
/// toNetwork(), toLocal(), synced(), isReference() and role(), which any task
/// may call at any time.
class TimeSync {
public:
    using Clock = std::function<uint64_t()>;
    using MsClock = std::function<uint32_t()>;
    static constexpr size_t kMaxCarriers = 4;
    /// The longest datagram TimeSync sends (a carrier may take longer ones,
    /// from later versions).
    static constexpr size_t kMaxDatagram = 37;

    /// On NowTP's engine alone (port 252), peers named by their ESP-NOW
    /// address. `localMac` is the address peers see this node send from:
    /// candidates compare it with theirs.
    TimeSync(Engine& engine, Clock localClockUs, const TimeSyncConfig& config = TimeSyncConfig(),
             const Mac& localMac = Mac());
    /// On the carriers added with addCarrier(); `self` is this device's id.
    /// `nowMs` is the clock of every `nowMs` argument (tick()'s included);
    /// none: the local µs clock / 1000.
    TimeSync(Clock localClockUs, const TimeSyncConfig& config, const Mac& self, MsClock nowMs = MsClock());
    ~TimeSync();

    TimeSync(const TimeSync&) = delete;
    TimeSync& operator=(const TimeSync&) = delete;

    /// Adds a carrier, preferred less than those added before (see
    /// setCarrierOrder()). InvalidState with kMaxCarriers already.
    Status addCarrier(TimeCarrier& carrier);
    /// Forgets a carrier, its offers, calibration and requesters.
    void removeCarrier(TimeCarrier& carrier, uint32_t nowMs);
    /// The order in which to prefer carriers, by name(); a carrier not named
    /// isn't used (it neither sends, answers nor beacons). Returns how many
    /// carriers were named.
    size_t setCarrierOrder(const char* const* names, size_t count, uint32_t nowMs);
    /// From a carrier: a datagram from `device`, received at `rxUs` on the
    /// local clock (0: unknown, now is used).
    void received(TimeCarrier& carrier, const Mac& device, const uint8_t* data, size_t len, uint64_t rxUs);
    /// From a carrier: the datagram `token` left at `txUs` (0: unknown).
    void sent(TimeCarrier& carrier, uint32_t token, uint64_t txUs);
    /// From a carrier with discovery: `device` acts as the reference, offers
    /// to (candidate), or neither (then as withdraw()).
    void offer(TimeCarrier& carrier, const Mac& device, bool acting, bool candidate, bool synced, uint32_t nowMs);
    void withdraw(TimeCarrier& carrier, const Mac& device, uint32_t nowMs);
    /// Every offer heard on `carrier` (it lost its discovery).
    void withdrawAll(TimeCarrier& carrier, uint32_t nowMs);

    /// The engine's discovery (first constructor): where this node's role is
    /// announced (or none). Called before start().
    void setDiscovery(Discovery* discovery);
    /// The address peers see this node send from changed.
    void setLocalMac(const Mac& mac) { self_ = mac; }
    void start(uint32_t nowMs);
    void stop();
    void tick(uint32_t nowMs);
    /// Adds when tick() has work next (rounds and their requests, a takeover,
    /// beacons, offers expiring, the estimate going stale).
    void nextTick(Deadline& d) const;

    /// Discovery events (first constructor): picks the announced reference unless one was set.
    void onPeerEvent(PeerEvent event, const PeerInfo& peer, uint32_t nowMs);
    void setRole(TimeRole role, uint32_t nowMs);
    TimeRole role() const { return shared().role; }
    /// Synchronizes with `device` instead of the reference announced through
    /// discovery, in the Follow and Candidate roles (a candidate then doesn't
    /// take over). A node that is itself synchronized answers in network time,
    /// so any synchronized node can serve as a time source.
    void setReference(const Mac& device, uint32_t nowMs);
    /// Back to the reference announced through discovery.
    void clearReference(uint32_t nowMs);
    /// Pause between rounds once synchronized (at least 1 s).
    void setInterval(uint32_t ms);

    /// This node acts as the reference: its network time is the network time.
    bool isReference() const { return shared().acting; }
    bool synced() const;
    /// Current network time in µs (the local clock while unsynchronized).
    uint64_t networkTime() const { return toNetwork(clock_()); }
    uint64_t toNetwork(uint64_t localUs) const;
    uint64_t toLocal(uint64_t networkUs) const;
    TimeSyncStatus status() const;
    /// The ms clock of `nowMs` arguments (see the constructors).
    uint32_t nowMs() const;

private:
    enum MsgType : uint8_t { kRequest = 1, kResponse = 2, kCalibration = 3, kOffer = 4 };

    struct Sample {
        uint64_t localUs;
        int64_t offsetUs;
    };
    /// One request/response of the current round, by request index.
    struct Exchange {
        uint32_t requestId;  ///< The carrier's token for the request.
        bool answered;
        uint64_t t1, t2, t3, t4;  ///< Request queued, request received, response queued, response received.
        uint64_t sentUs;          ///< When the request went out (0: not reported).
        uint64_t answerSentUs;    ///< When the response went out, as the responder reported later (0: not yet).
    };
    static constexpr size_t kMaxExchanges = 16;
    /// A requester: our last response to it, whose send time goes in the
    /// next one, and the calibration rounds it asked for.
    struct Answer {
        Mac to;
        bool used;
        uint8_t link;  ///< The carrier it asked by.
        uint8_t round, index;
        uint32_t messageId;
        uint64_t sentUs;  ///< 0 until the carrier reports it.
        uint32_t lastMs;  ///< Its last request.
        uint32_t calibrateEveryMs;  ///< 0: it didn't ask.
        uint32_t nextCalibrationMs;
    };
    static constexpr size_t kMaxAnswers = 8;
    static constexpr size_t kMaxCalibrations = 9;
    static constexpr uint8_t kUnused = 0xFF;
    /// A carrier, and what we know through it.
    struct Link {
        TimeCarrier* carrier;  ///< Null: a free slot.
        uint8_t rank;          ///< Preference, lowest first; kUnused: left out by setCarrierOrder().
        bool failed;           ///< A round got no answer: passed over until retryAtMs.
        uint32_t retryAtMs;
        uint32_t minRtt;       ///< Shortest round trip accepted lately.
        // Calibration (followers): the reference's measurements, as the bias
        // each implies, and the correction they make: kept across a change of
        // reference (until the new one's measurements replace it), dropped
        // when we act.
        int16_t implied[kMaxCalibrations];
        uint8_t impliedCount, impliedNext;
        bool biasSet;  ///< From the current reference's measurements.
        int32_t bias;
        int published;  ///< Flags last announced or beaconed (-1: none yet).
        uint32_t nextBeaconMs;
    };
    /// A device that acts as the reference or offers to.
    struct Offer {
        Mac mac;
        bool acting;
        bool candidate;
        bool synced;
        uint8_t via;        ///< Links it was heard on (bits).
        uint8_t beaconVia;  ///< Of those, the ones heard through beacons, which expire.
        uint32_t heardMs;   ///< Its last beacon.
    };
    /// What other tasks read: the estimate, published whole.
    struct Shared {
        bool acting;
        bool have;
        TimeRole role;
        int32_t bias;
        uint64_t baseLocal;
        int64_t base;
        double drift;
        uint64_t lastSyncLocal;
    };

    int linkOf(const TimeCarrier& c) const;
    bool usable(size_t l) const { return links_[l].carrier && links_[l].rank != kUnused; }
    void resetLink(Link& l);
    void resetCalibration();
    void setOffer(size_t link, const Mac& mac, bool acting, bool candidate, bool synced, bool beacon, uint32_t now);
    void dropVia(uint8_t bits, uint32_t now);
    void expireBeacons(uint32_t now);
    void beacon(uint32_t now);
    int offerFlags() const;
    int pickLink(const Mac& device, uint32_t now) const;
    void useLink(int link);
    void leaveLink();
    void handle(size_t link, const Mac& from, const uint8_t* d, size_t len, uint64_t rxUs);
    void evaluate(uint32_t now);
    const Offer* bestActing() const;
    bool aheadOfUs(const Offer& o) const;
    void act(bool acting, uint32_t now);
    void publish();
    void switchTo(const Mac& mac, uint32_t now);
    void forget();
    void sendRequest(uint32_t now);
    void endRound(uint32_t now);
    void endCalibration(int64_t offsetUs, size_t stamped, uint32_t now);
    void calibrate(Link& link, int32_t reportedUs);
    /// Where this round's requests go: the reference, or (while acting) the
    /// follower a calibration round measures.
    const Mac& target() const { return acting_ ? peer_ : ref_; }
    bool addSample(size_t link, uint64_t localUs, int64_t offsetUs, uint32_t rttUs);
    void fit();
    int64_t offsetAt(uint64_t localUs) const;
    bool isSynced() const;  ///< synced(), from our own state
    Shared live() const;
    void share();
    Shared shared() const;
    static int64_t servedAt(const Shared& s, uint64_t localUs);
    int64_t servedAt(uint64_t localUs) const { return servedAt(live(), localUs); }
    uint64_t netOf(uint64_t localUs) const { return localUs + static_cast<uint64_t>(servedAt(localUs)); }

    Engine* engine_ = nullptr;  // first constructor
    Clock clock_;
    MsClock msClock_;
    TimeSyncConfig config_;
    Mac self_;
    heap::Owned<EngineTimeCarrier> own_;  // first constructor: the engine's carrier
    TimeRole role_;
    bool running_ = false;
    uint32_t now_ = 0;

    Link links_[kMaxCarriers];
    uint8_t nextRank_ = 0;
    int followLink_ = -1;    // the carrier we follow the reference over
    int roundLink_ = -1;     // the carrier of the current round
    int estimateLink_ = -1;  // the carrier the estimate's samples came by

    bool acting_ = false;
    bool explicitRef_ = false;
    bool haveRef_ = false;
    Mac ref_ = Mac();
    Mac explicit_ = Mac();
    std::vector<Offer> offers_;
    bool vacant_ = true;  // no acting reference heard, since vacantSince_
    uint32_t vacantSince_ = 0;

    // Current round
    bool roundActive_ = false;
    uint8_t round_ = 0;
    uint8_t sent_ = 0;
    uint32_t nextSampleAt_ = 0;
    uint32_t lastSentAt_ = 0;
    uint32_t nextRoundAt_ = 0;
    Exchange* exchanges_ = nullptr;  // config_.samples of them, malloc'd for the first round
    bool refStamps_ = false;  // the reference reports its send times
    Answer answers_[kMaxAnswers];
    Mac peer_ = Mac();  // the follower measured by the current calibration round

    int32_t bias_ = 0;  // the correction served: the bias of estimateLink_, once it has one

    // Estimate: offset(t) = base_ + drift_ * (t - baseLocal_). Frozen while acting.
    std::vector<Sample> samples_;
    bool haveEstimate_ = false;
    bool carried_ = false;  // the estimate comes from the previous reference (or carrier, or from acting)
    uint64_t baseLocal_ = 0;
    int64_t base_ = 0;
    double drift_ = 0;  // µs per µs
    uint64_t lastSyncLocal_ = 0;
    uint32_t lastRtt_ = 0;
    uint32_t rounds_ = 0;
    uint8_t rejected_ = 0;

    // Published for other tasks: two copies, each with a sequence count (odd
    // while written); gen_ names the current one. The writer writes the other.
    Shared shared_[2];
    std::atomic<uint32_t> sharedSeq_[2];
    std::atomic<uint32_t> gen_;
};

/// Brackets the calls a TimeSync in another task makes into an
/// EngineTimeCarrier (send(), reaches(), announce()): enter() takes the
/// engine's lock, or returns false when the engine is gone.
class CarrierGuard {
public:
    virtual ~CarrierGuard() {}
    virtual bool enter() = 0;
    virtual void leave() = 0;
};

/// NowTP's engine as a TimeCarrier (port 252), with discovery announcing roles.
///
/// It delivers to its TimeSync at once, in the engine's task, or, queued
/// (setQueued()), in the TimeSync's tick() (poll()), for a TimeSync in
/// another task; a CarrierGuard then brackets the TimeSync's calls into it.
class EngineTimeCarrier : public TimeCarrier {
public:
    EngineTimeCarrier();
    ~EngineTimeCarrier();

    EngineTimeCarrier(const EngineTimeCarrier&) = delete;
    EngineTimeCarrier& operator=(const EngineTimeCarrier&) = delete;

    /// Listens on `engine` for `core` (either null: stops). With the engine's
    /// lock held. Detaching from a queued core also withdraws, in its next
    /// poll(), the offers this carrier reported.
    void attach(Engine* engine, TimeSync* core);
    /// Where roles are announced and offers come from (null: none).
    void setDiscovery(Discovery* discovery);
    /// Queues what arrives (up to 16 datagrams, reports and offers) for the
    /// core's poll(), and calls `wake` (in the engine's task, with its lock
    /// held; it must not wait for the core) when it queued something. False
    /// on a short heap.
    bool setQueued(std::function<void()> wake);
    void setGuard(CarrierGuard* guard) { guard_ = guard; }
    /// The engine's clock (ms) for sends from another task; none: Engine::now().
    void setClock(std::function<uint32_t()> nowMs) { nowMs_ = std::move(nowMs); }
    /// Names peers by the device id discovery reports (PeerInfo::deviceId:
    /// their station MAC) instead of their ESP-NOW address.
    void setDeviceIds(bool on) { deviceIds_ = on; }
    /// A discovery event, in the engine's task: an offer for the core.
    void peerEvent(PeerEvent event, const PeerInfo& peer);
    /// Datagrams and reports dropped because the queue was full.
    uint32_t dropped() const { return dropped_; }

    const char* name() const override { return "nowtp"; }
    Status send(const Mac& device, const uint8_t* data, size_t len, uint32_t* token) override;
    bool reaches(const Mac& device) const override;
    bool hasDiscovery() const override { return true; }
    void announce(bool acting, bool candidate, bool synced) override;
    void poll(TimeSync& core) override;
    bool pending() const override;

private:
    enum Kind : uint8_t { kReceived, kSent, kOffered, kReset };
    static constexpr size_t kInbox = 16;
    static constexpr size_t kMaxInboxData = 48;
    struct Entry {
        uint8_t kind;
        uint8_t len;    ///< kReceived: bytes in data.
        uint8_t flags;  ///< kOffered: 1 acting, 2 candidate, 4 synced (0: withdrawn).
        Mac device;
        uint32_t token;
        uint64_t us;
        uint8_t data[kMaxInboxData];
    };

    Mac idOf(const Mac& address) const;
    Mac addressOf(const Mac& device) const;
    void arrive(const Mac& src, const uint8_t* data, size_t len, uint64_t rxUs);
    void left(uint32_t token, uint64_t txUs);
    /// Queues an entry; false if full (dropped).
    bool push(const Entry& e);

    Engine* engine_ = nullptr;
    Discovery* discovery_ = nullptr;
    TimeSync* core_ = nullptr;
    CarrierGuard* guard_ = nullptr;
    std::function<uint32_t()> nowMs_;
    std::function<void()> wake_;
    bool deviceIds_ = false;
    int announced_ = -1;  // last flags announced, applied again to a new discovery
    Entry* inbox_ = nullptr;
    std::atomic<uint8_t> head_;  // next entry to deliver (the core's task)
    std::atomic<uint8_t> tail_;  // next free slot (the engine's task)
    bool resetDue_ = false;      // a reset that found the queue full goes ahead of the next entry
    uint32_t dropped_ = 0;
};

}  // namespace nowtp
