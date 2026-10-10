// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <string>
#include <vector>

#include "discovery.h"
#include "engine.h"
#include "host.h"
#include "radio.h"

namespace nowtp {

/// Port used by NowTP's diagnostics service (reserved range).
constexpr uint8_t kDiagnosticsPort = 254;

/// Host for the blocking diagnostic procedures (see ServiceHost).
using DiagnosticsHost = ServiceHost;

/// One probing configuration: frames sent at `rate` with the sender's maximum
/// power set to `txPowerDbm` (0 keeps the sender's current power).
struct ProbeStep {
    PhyRate rate = PhyRate::B1M;
    float txPowerDbm = 0;
    ProbeStep() {}
    ProbeStep(PhyRate r, float dbm) : rate(r), txPowerDbm(dbm) {}
};

/// Frames delivered for one ProbeStep in one direction.
struct ProbeResult {
    ProbeStep step;
    uint8_t sent = 0;
    uint8_t received = 0;
    int8_t rssi = 0;  ///< Average at the receiver, dBm; 0 if nothing arrived or unknown.
    float ratio() const { return sent ? static_cast<float>(received) / sent : 0.0f; }
};

/// Highest transmit power at which a node's frames are still received.
struct TxCeiling {
    float limitDbm = 0;  ///< Highest power the node's driver accepts.
    float dsssDbm = -1;  ///< 802.11b rates; -1 if no tested power worked.
    float ofdmDbm = -1;  ///< 802.11g/n rates; -1 if no tested power worked.
    /// RSSI change at the receiver per dB of power setting, from the 1 Mbps
    /// probes (about 1.0 when power control works; 0 if not measured).
    float powerResponse = 0;
    bool limited() const { return dsssDbm < limitDbm - 0.01f || ofdmDbm < limitDbm - 0.01f; }
};

enum class IssueKind : uint8_t {
    PeerUnresponsive,        ///< No answer from the peer's diagnostics at any power.
    DoesNotHearUs,           ///< The peer's frames arrive, ours never reach it.
    HearsUsOnlyAtLowerPower, ///< Our frames reach the peer only after lowering our power.
    TxPowerLimited,          ///< A node's frames are lost above some power (weak supply).
    OfdmPowerLimited,        ///< OFDM (802.11g/n) frames fail at a lower power than 802.11b.
    PowerControlIneffective, ///< Received signal barely changes with the power setting.
    RateFailsForward,        ///< Frames at a rate from us to the peer are lost.
    RateFailsReverse,        ///< Frames at a rate from the peer to us are lost.
    WeakSignal,              ///< Low RSSI even at 1 Mbps: range or antenna problem.
    OtherChannel,            ///< A NowTP node is on another channel.
    OtherNetworkId,          ///< A NowTP node uses another network id.
    OtherProtocolVersion,    ///< A node speaks another NowTP protocol version.
    LongRangeOnly,           ///< A node is only heard with Long Range enabled.
    LongRangeUnavailable,    ///< Long Range frames do not get through: not enabled on both sides.
    SmallFramesOnly,         ///< A node only takes 250-byte frames (ESP-NOW v1).
    ChannelScanUnavailable,  ///< The channel is fixed by an access point.
    ForeignTraffic,          ///< Non-NowTP ESP-NOW traffic on the channel.
};

const char* toString(IssueKind kind);

struct Issue {
    IssueKind kind;
    bool local;  ///< About this node rather than the peer.
    Mac peer;
    float value;  ///< Power in dBm, channel, network id... depending on the kind.
    PhyRate rate;
    std::string detail;  ///< Human-readable explanation and suggested fix.
};

/// Result of Diagnostics::diagnose().
struct LinkDiagnosis {
    Mac peer;
    bool responds = false;
    float requestPowerDbm = 0;  ///< Our power at which the peer answered.
    float replyPowerDbm = 0;    ///< The peer's power at which its answer arrived.
    TxCeiling ours;
    TxCeiling theirs;
    std::vector<ProbeResult> forward;  ///< Rate table, us to peer, at our ceilings.
    std::vector<ProbeResult> reverse;  ///< Rate table, peer to us, at the peer's ceilings.
    int8_t forwardRssi = 0;            ///< At 1 Mbps.
    int8_t reverseRssi = 0;
    std::vector<Issue> issues;
};

struct OptimizeOptions {
    /// Share of probe frames that must arrive for a rate to be chosen.
    float minDeliveryRatio = 0.95f;
    /// Upper bound for the power chosen for this node; 0 for the hardware ceiling.
    float maxTxPowerDbm = 0;
    bool allowOfdm = true;
    /// Long Range rates are only considered when Long Range is enabled.
    bool allowLongRange = true;
    /// Apply the chosen settings on both nodes (otherwise only report them).
    bool apply = true;
    uint8_t framesPerStep = 20;
};

/// Settings chosen for one link by Diagnostics::optimize().
struct LinkProfile {
    Mac peer;
    PhyRate rateToPeer = PhyRate::Default;
    PhyRate rateFromPeer = PhyRate::Default;
    float txPowerDbm = 0;      ///< Ours.
    float peerTxPowerDbm = 0;  ///< The peer's.
    float deliveryToPeer = 0;
    float deliveryFromPeer = 0;
    bool applied = false;
    bool verified = false;  ///< A reliable message went through with the new settings.
};

struct DeepDiscoveryOptions {
    /// Channels to scan; empty scans 1-13 (the current channel first).
    std::vector<uint8_t> channels;
    /// Listening time per channel. Compatible nodes answer a query within
    /// ~100 ms; nodes that do not understand us (other network id or version)
    /// are only heard when they announce, so cover one announce interval.
    uint32_t dwellMs = 2500;
    bool checkLongRange = true;
    bool checkTxPower = true;
};

/// A node found by Diagnostics::deepDiscover().
struct DiscoveredNode {
    Mac mac;
    std::string name;
    uint8_t channel = 0;
    bool nowtp = false;        ///< Speaks NowTP (any version).
    uint8_t networkId = 0;
    uint8_t protocolVersion = 0;
    bool compatible = false;   ///< Same channel, network id and version: can talk to us now.
    bool longRangeOnly = false;
    uint16_t maxFrameSize = 0;  ///< From its announcement; 0 if unknown.
    int8_t rssi = 0;
    bool heardOnHome = false;   ///< Heard on our channel at some point of the scan.
    bool hearsUs = false;       ///< Our unicast frames are acknowledged.
    float hearsUsAtDbm = 0;     ///< Highest of our tested powers that worked.
};

struct DeepDiscoveryReport {
    uint8_t homeChannel = 0;
    std::vector<DiscoveredNode> nodes;
    std::vector<Issue> issues;
};

struct DiagnosticsConfig {
    /// Answer other nodes' diagnostic requests (like ping on a network).
    bool respond = true;
    /// Let a peer that ran optimize() set our rate toward it and our transmit
    /// power. Power is global to the node, so only enable this among trusted
    /// nodes (ESP-NOW frames are not authenticated unless encrypted).
    bool acceptRemoteTuning = true;
    /// Upper bound on frames sent for one remote burst request.
    uint16_t maxBurstFrames = 400;
    /// Size of probe frames' payload.
    uint8_t probeBytes = 200;
};

/// Link diagnostics, tuning and deep discovery over the reserved port 254.
///
/// Every node answers probe requests; the procedures below are run by one
/// initiator against one or more peers. They block for up to a few seconds
/// each and must be called from an application task, never from a NowTP
/// callback. Probing temporarily changes this node's power and rates (and,
/// on request, the peer's), and restores them afterwards.
class Diagnostics {
public:
    Diagnostics(Engine& engine, RadioControl& radio, DiagnosticsHost& host,
                const DiagnosticsConfig& config = DiagnosticsConfig());
    ~Diagnostics();

    Diagnostics(const Diagnostics&) = delete;
    Diagnostics& operator=(const Diagnostics&) = delete;

    void start();
    void stop();
    /// Drives bursts requested by peers. Call with the engine's tick.
    void tick(uint32_t nowMs);
    /// Used by deepDiscover() to query nodes.
    void setDiscovery(Discovery* discovery) { discovery_ = discovery; }
    /// A blocking procedure is running (it may move the radio to other channels).
    bool busy() const { return activeProcedures_ > 0; }

    // --- Blocking procedures ---------------------------------------------------

    /// Round trip to the peer's diagnostics, lowering power on both sides if
    /// needed. Reports the powers that worked.
    Status ping(const Mac& peer, float* requestPowerDbm = nullptr, float* replyPowerDbm = nullptr);
    /// Delivery per step: `forward` measures us to peer, `reverse` peer to us.
    Status measure(const Mac& peer, const std::vector<ProbeStep>& steps, uint8_t framesPerStep,
                   std::vector<ProbeResult>* forward, std::vector<ProbeResult>* reverse);
    /// Power ceilings on both sides, rate tables in both directions, issues.
    /// Returns QueueFull if the peer stayed busy with its own measurements
    /// (retry later), Timeout if it never answered.
    Status diagnose(const Mac& peer, LinkDiagnosis& out, uint8_t framesPerStep = 20);
    /// Chooses and (by default) applies the fastest reliable settings for the link.
    /// Pass a fresh diagnose() result as `known` to skip measuring again.
    Status optimize(const Mac& peer, const OptimizeOptions& options, LinkProfile& out,
                    const LinkDiagnosis* known = nullptr);
    /// Scans channels and radio modes for nodes and incompatibilities.
    Status deepDiscover(const DeepDiscoveryOptions& options, DeepDiscoveryReport& out);

private:
    enum MsgType : uint8_t {
        kBurst = 1,
        kCollect = 2,
        kReport = 3,
        kBurstRequest = 4,
        kBurstAck = 5,
        kApply = 6,
        kApplyAck = 7,
        kPing = 8,
        kPong = 9,
        kBurstDone = 10,
    };

    struct Counter {
        Mac src;
        uint16_t session = 0;
        uint32_t lastUse = 0;
        std::vector<uint8_t> received;
        std::vector<int32_t> rssiSum;
        std::vector<uint8_t> rssiCount;
    };

    struct Reply {
        uint8_t type = 0;
        uint16_t session = 0;
        Mac src;
        bool got = false;
        std::vector<uint8_t> data;
    };

    struct OutgoingBurst {
        bool active = false;
        Mac requester;
        uint16_t session = 0;
        std::vector<ProbeStep> steps;
        uint8_t perStep = 0;
        size_t step = 0;
        std::vector<bool> skip;  // steps this radio cannot send (e.g. LR without Long Range)
        uint8_t sent = 0;
        uint8_t completed = 0;
        bool stepReady = false;
        float savedPower = 0;
        PhyRate savedRate = PhyRate::Default;
        uint32_t startedAt = 0;
    };

    void handle(const Message& m);
    void countBurst(const Message& m);
    void reply(const Mac& to, uint8_t attempt, const uint8_t* data, size_t len);
    Counter* counter(const Mac& src, uint16_t session, size_t steps, bool create);
    void finishBurst();

    // Blocking helpers (lock internally).
    Status request(const Mac& peer, uint8_t replyType, uint16_t session, std::vector<uint8_t> payload,
                   size_t attemptOffset, Reply& out, float* requestPower, uint8_t attempts = 5);
    Status sendBurstFrames(const Mac& dst, uint16_t session, const std::vector<ProbeStep>& steps, uint8_t perStep);
    bool waitFor(const std::function<bool()>& done, uint32_t timeoutMs);
    uint16_t newSession();
    float powerForAttempt(uint8_t attempt, float current) const;
    // Requests that would disturb a measurement we are running get "busy".
    struct Busy {
        Diagnostics& d;
        explicit Busy(Diagnostics& diag) : d(diag) {
            d.host_.lock();
            d.localProcedures_++;
            d.activeProcedures_++;
            d.host_.unlock();
        }
        ~Busy() {
            d.host_.lock();
            d.localProcedures_--;
            d.activeProcedures_--;
            d.host_.unlock();
        }
    };
    void yieldToPeer();
    Status measureCeilings(const Mac& peer, uint8_t frames, LinkDiagnosis& d);

    Engine& engine_;
    RadioControl& radio_;
    DiagnosticsHost& host_;
    DiagnosticsConfig config_;
    Discovery* discovery_ = nullptr;
    bool running_ = false;
    uint32_t now_ = 0;

    std::vector<Counter> counters_;
    std::vector<Reply> replies_;  // expected replies of the running procedure
    OutgoingBurst burst_;
    int replyPowerOverrides_ = 0;
    int localProcedures_ = 0;   // dropped to 0 while yielding to a peer
    int activeProcedures_ = 0;  // never dropped
    float replySavedPower_ = 0;
};

}  // namespace nowtp
