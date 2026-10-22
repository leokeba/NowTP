// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#if defined(ESP_PLATFORM)

#include <atomic>
#include <memory>
#include <utility>
#include <vector>

#include "channel.h"
#include "diagnostics.h"
#include "discovery.h"
#include "engine.h"
#include "peer_table.h"
#include "send_tracker.h"
#include "radio.h"
#include "security.h"
#include "stream.h"
#include "timesync.h"
#include "esp_event.h"
#include "esp_wifi_types.h"
#include "freertos/FreeRTOS.h"
#include "freertos/ringbuf.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

namespace nowtp {

/// Wi-Fi modem sleep (esp_wifi_set_ps()) while NowTP runs.
///
/// Modem sleep only acts while the station is connected to an access point:
/// the radio then sleeps between the AP's DTIM beacons (typically 100-300 ms)
/// and wakes for traffic the AP buffered. Nothing buffers ESP-NOW frames, so
/// those arriving while it sleeps are lost. A unicast frame fails once the
/// sender's hardware retries run out (~100 ms): unreliable messages are lost,
/// reliable ones get through by resending, with latency up to a DTIM period
/// and a fraction of the throughput. Broadcasts, discovery announcements
/// among them, go missing, so peers may be reported lost. Sending is unaffected.
enum class PowerSave : uint8_t {
    Leave,     ///< Keep whatever the application set.
    None,      ///< WIFI_PS_NONE: ESP-NOW hears every frame (the default).
    MinModem,  ///< WIFI_PS_MIN_MODEM: wakes at every DTIM beacon.
    MaxModem,  ///< WIFI_PS_MAX_MODEM: wakes every listen interval; misses even more.
};

/// Radio settings applied by begin(). The defaults are what every ESP-NOW
/// device understands: 1 Mbps, no Long Range, driver power and country.
struct RadioConfig {
    /// If the application has not set up Wi-Fi, initialize and start it in
    /// station mode and stop it again in end(). When false, begin() fails
    /// unless Wi-Fi is already initialized.
    bool initWifi = true;
    /// Channel to use when NowTP is free to choose: no station connection and
    /// no soft-AP. Otherwise the access point dictates the channel. 0 keeps the
    /// current channel. All nodes must share a channel.
    uint8_t channel = 1;
    /// Wi-Fi modem sleep while NowTP runs (see PowerSave for what sleep costs).
    /// end() restores the application's setting. Change it at run time with
    /// EspNowTransport::setPowerSave().
    PowerSave powerSave = PowerSave::None;
    /// Deprecated: false is powerSave = PowerSave::Leave.
    bool disablePowerSave = true;
    /// Maximum transmit power in dBm (2 to 20, 0.25 dB steps); 0 keeps the
    /// driver's setting (usually 20 dBm). Boards with a weak supply often fail to
    /// transmit at full power; 15-17 dBm is a common fix.
    float txPowerDbm = 0;
    /// Rate for broadcast frames, including discovery. Keep the default unless
    /// every node is known to be close: slower frames reach further.
    PhyRate broadcastRate = PhyRate::Default;
    /// Rate for unicast frames to peers without their own PeerOptions::rate.
    PhyRate unicastRate = PhyRate::Default;
    /// Add Espressif Long Range mode to the Wi-Fi protocols (802.11b/g/n stay
    /// enabled, so ordinary nodes are still heard). Required to send or receive
    /// at LR250K / LR500K.
    bool longRange = false;
    /// Two-letter country code ("US", "FR", "JP", ... or "01" for world-safe)
    /// selecting allowed channels and power limits; empty keeps the driver's.
    char countryCode[3] = {0, 0, 0};
    /// When a peer we hear does not acknowledge our frames, step our transmit
    /// power down until it does (many boards cannot sustain full power). The
    /// working power is kept for the rest of the boot, also across end()/begin().
    bool autoPowerFallback = true;
};

struct PeerOptions {
    /// Wi-Fi channel of the peer; 0 means the current channel.
    uint8_t channel = 0;
    /// Use ESP-NOW encryption with this local master key (unicast only; see setPrimaryKey()).
    bool encrypt = false;
    uint8_t lmk[16] = {};
    /// Largest frame to send to this peer; 0 uses EspNowConfig::defaultMaxFrameSize.
    /// Up to 1470 when both sides run ESP-NOW v2 (ESP-IDF 5.4+, Arduino-ESP32 3.2+).
    uint16_t maxFrameSize = 0;
    /// Rate for frames to this peer; Default uses RadioConfig::unicastRate.
    /// Per-peer rates need ESP-IDF 5.1+ (Arduino-ESP32 3.x).
    PhyRate rate = PhyRate::Default;
};

struct EspNowConfig {
    Config protocol;

    RadioConfig radio;

    // --- Discovery ---------------------------------------------------------
    /// Announce this node and track peers (see Discovery).
    bool enableDiscovery = false;
    DiscoveryConfig discovery;
    /// For discovered peers, send unicast frames of the largest size both sides
    /// support (1470 between ESP-NOW v2 nodes), unless addPeer() set a size.
    bool negotiateFrameSize = true;

    // --- Diagnostics -------------------------------------------------------
    /// Answer diagnostic requests and allow the diagnose()/optimize() calls.
    bool enableDiagnostics = true;
    DiagnosticsConfig diagnostics;

    // --- Channel following (needs enableDiscovery) ---------------------------
    /// Follow peers that move to another channel, and search for anchor peers
    /// (nodes whose channel an access point fixes) once they go silent.
    ChannelConfig channel;

    // --- Security ------------------------------------------------------------
    /// Installation key and pairing code. Security is off until a key is set
    /// here, loaded from NVS, installed with setSecurityKey() or obtained by pair().
    SecurityConfig security;
    /// Keep the installation key in NVS (namespace "nowtp"): begin() loads it
    /// when security.key is empty, and pairing and setSecurityKey() store it.
    bool persistSecurityKey = true;

    // --- Network time and streams ----------------------------------------------
    /// Answer time requests and synchronize with the reference node.
    bool enableTimeSync = true;
    TimeSyncConfig timeSync;
    /// Accept and send streams (sendStream(), onStream()).
    bool enableStreams = true;

    // --- Transport -----------------------------------------------------------
    /// Frame size for broadcast and for peers without their own setting.
    /// 250 is understood by every ESP-NOW version.
    uint16_t defaultMaxFrameSize = 250;
    /// Register unknown unicast destinations as unencrypted peers on first use,
    /// including senders that need an acknowledgement. When false, call addPeer()
    /// for every peer you exchange unicast or reliable messages with, on both sides.
    /// ESP-NOW allows at most 20 peers: when full, the automatic peer used least
    /// recently makes room (never one registered with addPeer()), and a peer
    /// discovery reports lost is removed.
    bool autoAddPeers = true;
    /// Process radio events and run callbacks in a dedicated task. When false,
    /// call EspNowTransport::poll() regularly (e.g. from Arduino's loop()), or
    /// from a task that `wake` wakes, at the latest after pollDelayMs().
    bool runTask = true;
    uint32_t taskStackSize = 4096;
    UBaseType_t taskPriority = 5;
    BaseType_t taskCore = tskNO_AFFINITY;
    /// With runTask false: called whenever poll() has new work, so that the
    /// application can wake the task that polls (e.g. with xTaskNotifyGive()).
    /// That is when a frame arrived or the radio reported one sent (called in
    /// the Wi-Fi driver's task), and when a call into NowTP from any task may
    /// have given it work (called in that task, once NowTP's lock is released).
    /// Always task context, never an ISR. Keep it short, don't block in it and
    /// don't call NowTP from it.
    void (*wake)(void* context) = nullptr;
    void* wakeContext = nullptr;
    /// On chips with PSRAM, take NowTP's large buffers from it: message copies,
    /// reassembly and stream buffers (blocks of 256 bytes and more) and the
    /// event buffer, leaving internal RAM to Wi-Fi, lwIP and DMA. Internal RAM
    /// is used when there is no PSRAM, or no room in it.
    bool usePsram = true;
    /// Bytes buffered between the Wi-Fi driver's receive callback and the NowTP
    /// task: about 5 frames of 1470 bytes (ESP-NOW v2), 28 of 250. Frames that
    /// don't fit are dropped and counted (stats().droppedEvents); reliable
    /// messages recover them. Send results don't go through it.
    size_t eventBufferSize = 8 * 1024;
    /// How often timeouts and retransmissions are checked.
    uint32_t tickIntervalMs = 5;
};

/// How begin() found and configured the radio.
struct RadioInfo {
    uint8_t channel = 0;
    float txPowerDbm = 0;  ///< Maximum transmit power currently set in the driver.
    bool longRange = false;  ///< Long Range mode enabled on the interface.
    float txPowerLimitDbm = 0;     ///< Highest power the driver accepts on this chip.
    float learnedTxCeilingDbm = 0; ///< Power found to work by fallback or optimize() (0: none).
    wifi_interface_t interface = WIFI_IF_STA;  ///< Interface ESP-NOW peers are bound to.
    bool stationConnected = false;             ///< Connected to an AP (channel follows it).
    bool softApActive = false;                 ///< Running a soft-AP (channel follows it).
    bool wifiStartedByNowTP = false;           ///< NowTP initialized/started Wi-Fi and will stop it.
};

/// NowTP over the ESP-NOW driver, for both ESP-IDF and Arduino-ESP32.
///
/// begin() works with whatever Wi-Fi state the application left: nothing set
/// up, station (connected or not), soft-AP or both. Only one instance can be
/// active, since ESP-NOW has a single pair of driver callbacks. Receive and
/// completion callbacks run in the NowTP task (or inside poll()), never in the
/// Wi-Fi driver task; keep them short.
class EspNowTransport : public RadioControl {
public:
    /// Engine counters plus radio-level ones.
    struct TransportStats : Stats {
        uint32_t droppedEvents = 0;  ///< Radio events lost because the event buffer was full.
        uint32_t oneWayLinks = 0;    ///< Peers we hear but whose MAC never acknowledges our frames.
        uint32_t powerFallbacks = 0; ///< Times the transmit power was lowered automatically.
    };

    EspNowTransport();
    ~EspNowTransport();

    EspNowTransport(const EspNowTransport&) = delete;
    EspNowTransport& operator=(const EspNowTransport&) = delete;

    Status begin(const EspNowConfig& config = EspNowConfig());
    /// Stops the transport; pending messages complete with Status::Cancelled.
    void end();
    bool started() const { return started_; }

    /// Registers (or updates) a unicast peer: encryption, channel, frame size.
    /// Required before unicast unless EspNowConfig::autoAddPeers is set.
    Status addPeer(const Mac& mac, const PeerOptions& options = PeerOptions());
    Status removePeer(const Mac& mac);
    /// Sets the ESP-NOW primary master key used to encrypt local master keys.
    Status setPrimaryKey(const uint8_t pmk[16]);

    /// Queues a message; returns immediately. `done` runs once with the outcome.
    Status send(const Mac& dst, uint8_t port, const void* data, size_t len,
                const SendOptions& options = SendOptions(), CompletionHandler done = nullptr);
    /// Like send(), without copying: takes `buffer`, malloc()ed with `capacity`
    /// bytes, the first `len` of them the payload. Allocate len + kSendOverhead
    /// so NowTP needn't realloc() it. Freed in every case, errors included.
    Status sendBuffer(const Mac& dst, uint8_t port, uint8_t* buffer, size_t len, size_t capacity,
                      const SendOptions& options = SendOptions(), CompletionHandler done = nullptr);
    /// Sends and blocks until the outcome is known. Requires runTask and must not
    /// be called from a NowTP callback.
    Status sendAndWait(const Mac& dst, uint8_t port, const void* data, size_t len,
                       const SendOptions& options = SendOptions());

    /// Sets the handler for a port (may be called before begin()). Ports from
    /// kFirstReservedPort up are reserved and rejected.
    Status listen(uint8_t port, ReceiveHandler handler);

    /// Discovery (EspNowConfig::enableDiscovery). The handler may be set before
    /// begin() and runs in the NowTP task.
    void onPeerEvent(PeerHandler handler);
    /// Asks every node in range to announce itself now.
    Status discover();
    /// Peers currently known to discovery.
    std::vector<PeerInfo> peers() const;
    /// The largest message this node accepts (EspNowConfig::protocol.maxMessageSize),
    /// which discovery announces.
    size_t maxMessageSize() const { return config_.protocol.maxMessageSize; }
    /// The largest message `peer` accepts, as its announcements say; 0 if
    /// unknown (no discovery, or NowTP 0.5 and earlier). send() refuses a
    /// larger message to it with TooLarge.
    size_t peerMaxMessageSize(const Mac& peer) const;
    /// Changes the metadata this node announces and announces it right away.
    Status setDiscoveryMetadata(const void* data, size_t len);

    // --- Channels --------------------------------------------------------------
    /// Tells peers we are moving to `channel`, then switches to it; peers that
    /// follow (EspNowConfig::channel) come along. Fails with InvalidState when
    /// an access point fixes our channel. Blocks for up to ~300 ms.
    Status moveToChannel(uint8_t channel);
    /// Tells peers we are about to move to `channel` without switching: call it
    /// before connecting the station to an access point on another channel.
    Status announceChannelChange(uint8_t channel);
    /// Searches the other channels for peers now (normally automatic).
    Status searchChannels();
    /// Called in the NowTP task whenever our channel changed: we followed a
    /// peer, or the access point we depend on moved.
    void onChannelChange(std::function<void(uint8_t channel)> handler);

    // --- Security (see Security) ---------------------------------------------
    /// Installs the installation key (16-32 bytes) and stores it if
    /// persistSecurityKey is set. Every message is authenticated from then on.
    Status setSecurityKey(const void* key, size_t len);
    /// Removes the key, here and in NVS: security is off again.
    Status forgetSecurityKey();
    /// An installation key is installed.
    bool secured() const;
    /// Opens a pairing window for up to `timeoutMs` and hands the installation
    /// key (created now if there is none) to one node calling pair(). Blocking.
    Status acceptPairing(uint32_t timeoutMs, Mac* joined = nullptr);
    /// Obtains the installation key from a node with an open pairing window. Blocking.
    Status pair(uint32_t timeoutMs, Mac* member = nullptr);

    // --- Network time (see TimeSync) -----------------------------------------
    /// The reference node's clock now, in µs. Equals esp_timer_get_time() on
    /// the reference and while unsynchronized.
    uint64_t networkTimeUs() const;
    /// The esp_timer_get_time() value at which network time `networkUs` occurs:
    /// schedule an action there (e.g. with esp_timer_start_once()).
    int64_t localTimeUs(uint64_t networkUs) const;
    TimeSyncStatus timeSyncStatus() const;
    /// Changes this node's role (see TimeRole) at once, without a restart; it
    /// also applies to the next begin(). A node that becomes the reference
    /// while synchronized keeps the network time it had.
    Status setTimeRole(TimeRole role);
    /// Synchronizes with `peer` instead of the reference announced by
    /// discovery (roles Follow and Candidate), until clearTimeReference() or end().
    Status setTimeReference(const Mac& peer);
    Status clearTimeReference();
    /// Pause between synchronization rounds once synchronized (at least 1 s);
    /// also applies to the next begin().
    Status setTimeSyncInterval(uint32_t ms);

    // --- Streams (see Streams) -----------------------------------------------
    /// Sends `size` bytes pulled from `read` to `dst`. `done` runs once in the
    /// NowTP task with the outcome. Returns at once.
    Status sendStream(const Mac& dst, uint32_t size, StreamReader read, StreamDone done = nullptr,
                      const StreamOptions& options = StreamOptions(), uint32_t* id = nullptr);
    Status cancelStream(uint32_t id);
    /// Decides about incoming streams (may be called before begin()).
    void onStream(StreamAcceptor acceptor);

    /// The radio state found and set by begin(), with current power and LR state.
    RadioInfo radioInfo() const;

    // --- Radio controls (RadioControl) ---------------------------------------
    /// Changes the maximum transmit power (dBm, 2-20) while running.
    Status setTxPower(float dbm) override;
    float txPower() const override;
    float txPowerLimit() const override;
    /// Changes the rate of broadcast frames while running.
    Status setBroadcastRate(PhyRate rate) override;
    PhyRate broadcastRate() const override;
    /// Changes the rate for peers without their own PeerOptions::rate.
    Status setUnicastRate(PhyRate rate);
    /// Changes Wi-Fi modem sleep while running (RadioConfig::powerSave); Leave
    /// hands the setting back as the application had it before NowTP changed it.
    Status setPowerSave(PowerSave mode);
    PowerSave powerSave() const;
    /// Rate used toward one peer; Default reverts it to the unicast rate.
    Status setPeerRate(const Mac& peer, PhyRate rate) override;
    PhyRate peerRate(const Mac& mac) const override;
    bool rateUsable(PhyRate rate) const override;
    uint8_t channel() const override;
    /// Fails with InvalidState when a station connection or soft-AP fixes the channel.
    Status setChannel(uint8_t channel) override;
    bool longRange() const override;
    Status setLongRange(bool enabled) override;
    bool channelFixed() const override;

    // --- Diagnostics (blocking; call from an application task) ---------------
    /// Round trip to a peer's diagnostics, falling back to lower power if needed.
    Status ping(const Mac& peer, float* requestPowerDbm = nullptr, float* replyPowerDbm = nullptr);
    /// Delivery ratio and RSSI per step, us to peer and/or peer to us.
    Status measureLink(const Mac& peer, const std::vector<ProbeStep>& steps, uint8_t framesPerStep,
                       std::vector<ProbeResult>* forward, std::vector<ProbeResult>* reverse);
    /// Power ceilings on both sides, rate tables in both directions, issues found.
    Status diagnose(const Mac& peer, LinkDiagnosis& out);
    /// Picks and applies the fastest reliable rates and working powers for a link.
    /// Pass a recent diagnose() result as `known` to skip measuring the link again.
    Status optimizeLink(const Mac& peer, LinkProfile& out, const OptimizeOptions& options = OptimizeOptions(),
                        const LinkDiagnosis* known = nullptr);
    /// optimizeLink() for every discovered peer; our power ends at the lowest chosen.
    Status optimizeAll(std::vector<LinkProfile>& out, const OptimizeOptions& options = OptimizeOptions());
    /// Scans channels and radio modes for nodes and incompatibilities. Takes about
    /// options.dwellMs per channel; normal traffic pauses while off-channel.
    Status deepDiscover(DeepDiscoveryReport& out, const DeepDiscoveryOptions& options = DeepDiscoveryOptions());

    /// Processes pending radio events and timers when runTask is false.
    /// Returns pollDelayMs(). end() must not run while another task is in poll().
    uint32_t poll();
    /// Milliseconds until poll() must run again (0: at once) for timers:
    /// retransmissions, timeouts, announcements, time rounds. At most 250.
    /// New frames don't wait for it: EspNowConfig::wake reports them. Without
    /// that hook, poll every few milliseconds instead.
    uint32_t pollDelayMs() const;

    Mac localMac() const;
    TransportStats stats() const;
    /// Heap NowTP holds for messages now (see Engine::MemoryUse); zeros
    /// before begin(). Takes the lock: cheap enough to sample every few ms.
    Engine::MemoryUse memory() const;
    /// Radio events lost because the event buffer was full.
    uint32_t droppedEvents() const;

    /// Largest frame the local ESP-NOW driver can send (250 or 1470).
    static uint16_t maxSupportedFrameSize();
    /// Transmit power found to work by the automatic fallback or optimizeLink()
    /// during this boot (0 if none). Useful to configure Wi-Fi before begin().
    static float learnedTxPowerCeiling();

private:
    class RadioLink;
    class PeerDriver;

    static void taskEntry(void* arg);
    Status prepareRadio();
    Status applyRadioSettings();
    Status applyTxPower(float dbm);
    Status applyPowerSave(PowerSave mode);
    Status applyPeerRate(const Mac& mac);
    void releaseRadio();
    static void wifiEventHandler(void* arg, esp_event_base_t base, int32_t id, void* data);
    bool stationConnected() const;
    void handlePeerEvent(PeerEvent event, const PeerInfo& peer);
    class Host;
    Status diagnosticsReady() const;
    void startPowerFallback(const Mac& peer);
    void sendFallbackPing();
    void onFallbackPing(Status status);
    void tickLinkChecks(uint32_t now);
    void pollChannel(uint32_t now);
    Status sendMoveNotice(uint8_t channel);
    Status appTaskReady() const;
    void storeKey(const std::vector<uint8_t>& key);
    struct LinkHealth {
        Mac mac;
        uint32_t lastHeardMs = 0;
        uint16_t failures = 0;
        bool warned = false;
    };
    LinkHealth* linkHealth(const Mac& mac, bool create);
    void notePeerHeard(const Mac& mac);
    void notePeerSendResult(const Mac& mac, bool delivered);
    bool hasExplicitFrameSize(const Mac& mac) const;
    bool processEvents(TickType_t wait);  // true if events are left
    void checkSent();
    void lock() const;
    /// `changed`: the caller may have given NowTP work, which a poller asleep
    /// until pollDelayMs() must look at (see EspNowConfig::wake).
    void unlock(bool changed = true) const;
    void cleanup();

    EspNowConfig config_;
    SendTracker sendTracker_;
    uint32_t sentSeen_ = 0;
    std::unique_ptr<PeerDriver> peerDriver_;
    std::unique_ptr<PeerTable> peerTable_;  // ESP-NOW's 20 slots: LRU eviction of automatic peers
    std::unique_ptr<RadioLink> link_;
    std::unique_ptr<Engine> engine_;
    std::unique_ptr<Discovery> discovery_;
    std::vector<std::pair<uint8_t, ReceiveHandler>> listeners_;
    Callback<void(PeerEvent, const PeerInfo&)> peerHandler_;
    std::vector<Mac> explicitFrameSizes_;
    std::vector<std::pair<Mac, PhyRate>> peerRates_;
    std::vector<LinkHealth> linkHealth_;
    std::unique_ptr<Host> host_;
    std::unique_ptr<Diagnostics> diagnostics_;
    std::unique_ptr<Security> security_;
    std::unique_ptr<ChannelFollower> follower_;
    std::unique_ptr<TimeSync> timeSync_;
    std::unique_ptr<Streams> streams_;
    StreamAcceptor streamAcceptor_;
    Callback<void(uint8_t)> channelHandler_;
    uint32_t lastChannelPoll_ = 0;
    uint8_t pendingChannel_ = 0;
    uint32_t pendingChannelSince_ = 0;
    int8_t limitQuarterDbm_ = 80;
    struct PowerFallback {
        bool active = false;
        Mac peer;
        float original = 0;
        std::vector<float> ladder;
        size_t index = 0;
        uint8_t failures = 0;
        bool pingInFlight = false;
        bool confirming = false;  // re-testing the original power after a success
        uint32_t nextPingAt = 0;
        std::vector<Mac> tried;
    } fallback_;
    struct LinkCheck {
        Mac peer;
        uint8_t remaining;
        bool inFlight;
        uint32_t nextAt;
    };
    std::vector<LinkCheck> linkChecks_;
    TransportStats stats_;  // radio-level counters only
    struct SavedRadio {
        bool powerSave = false;
        int powerSaveMode = 0;
        bool txPower = false;
        int8_t txPowerQuarterDbm = 0;
        bool protocol = false;
        uint8_t protocolBitmap = 0;
        bool country = false;
        char countryCode[4] = {0, 0, 0, 0};  // the driver returns two letters plus an environment byte
    } saved_;
    RadioInfo radio_;
    RingbufHandle_t events_ = nullptr;
    void* ringStorage_ = nullptr;  // the event buffer's storage when in PSRAM
    void* ringControl_ = nullptr;  // and its StaticRingbuffer_t, in internal RAM
    uint32_t taken_ = 0;           // frames taken from the event buffer
    bool psram_ = false;           // large buffers come from PSRAM
    mutable int lockDepth_ = 0;
    SemaphoreHandle_t mutex_ = nullptr;
    SemaphoreHandle_t taskExited_ = nullptr;
    TaskHandle_t task_ = nullptr;
    wifi_interface_t interface_ = WIFI_IF_STA;
    volatile bool stopping_ = false;
    bool ending_ = false;  // in end(): no more wake-ups for the poller
    bool started_ = false;
    bool espNowInitialized_ = false;
    bool ownsWifiInit_ = false;
    bool ownsWifiStart_ = false;
    bool ownsEventLoop_ = false;
    // Station association, followed from Wi-Fi events: querying the driver logs a
    // warning on every call while the station is not associated.
    esp_event_handler_instance_t wifiEvents_ = nullptr;
    std::atomic<bool> staConnected_{false};
    bool ratesChanged_ = false;
};

}  // namespace nowtp

#endif  // ESP_PLATFORM
