// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#if defined(ESP_PLATFORM)

#include <memory>
#include <utility>
#include <vector>

#include "discovery.h"
#include "engine.h"
#include "esp_wifi_types.h"
#include "freertos/FreeRTOS.h"
#include "freertos/ringbuf.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

namespace nowtp {

/// Over-the-air PHY rate for ESP-NOW frames. Faster rates shorten airtime but
/// need a stronger signal; every receiver decodes any 802.11b/g/n rate, while
/// the Long Range rates need RadioConfig::longRange on both sides.
enum class PhyRate : uint8_t {
    Default = 0,  ///< Not set: 1 Mbps 802.11b (driver default), or the transport's unicastRate for a peer.
    B1M,          ///< 802.11b 1 Mbps: longest standard range, understood by everyone.
    B2M,
    B5_5M,
    B11M,
    G6M,  ///< 802.11g OFDM
    G9M,
    G12M,
    G18M,
    G24M,
    G36M,
    G48M,
    G54M,
    MCS0,  ///< 802.11n HT20, long guard interval: 6.5 Mbps
    MCS1,
    MCS2,
    MCS3,
    MCS4,
    MCS5,
    MCS6,
    MCS7,    ///< 65 Mbps
    LR250K,  ///< Espressif Long Range 250 kbps: longest range, Espressif chips only.
    LR500K,
};

const char* toString(PhyRate rate);

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
    /// Disable Wi-Fi modem sleep. A sleeping station misses most ESP-NOW frames.
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

    // --- Transport -----------------------------------------------------------
    /// Frame size for broadcast and for peers without their own setting.
    /// 250 is understood by every ESP-NOW version.
    uint16_t defaultMaxFrameSize = 250;
    /// Register unknown unicast destinations as unencrypted peers on first use,
    /// including senders that need an acknowledgement. When false, call addPeer()
    /// for every peer you exchange unicast or reliable messages with, on both sides.
    /// ESP-NOW allows at most 20 peers.
    bool autoAddPeers = true;
    /// Process radio events and run callbacks in a dedicated task. When false,
    /// call EspNowTransport::poll() regularly (e.g. from Arduino's loop()).
    bool runTask = true;
    uint32_t taskStackSize = 4096;
    UBaseType_t taskPriority = 5;
    BaseType_t taskCore = tskNO_AFFINITY;
    /// Bytes buffered between the Wi-Fi driver callbacks and the NowTP task.
    size_t eventBufferSize = 8 * 1024;
    /// How often timeouts and retransmissions are checked.
    uint32_t tickIntervalMs = 5;
};

/// How begin() found and configured the radio.
struct RadioInfo {
    uint8_t channel = 0;
    float txPowerDbm = 0;  ///< Maximum transmit power currently set in the driver.
    bool longRange = false;  ///< Long Range mode enabled on the interface.
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
class EspNowTransport {
public:
    /// Engine counters plus radio-level ones.
    struct TransportStats : Stats {
        uint32_t droppedEvents = 0;  ///< Radio events lost because the event buffer was full.
        uint32_t oneWayLinks = 0;    ///< Peers we hear but whose MAC never acknowledges our frames.
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
    /// Changes the metadata this node announces and announces it right away.
    Status setDiscoveryMetadata(const void* data, size_t len);

    /// The radio state found and set by begin(), with current power and LR state.
    RadioInfo radioInfo() const;

    /// Changes the maximum transmit power (dBm, 2-20) while running.
    Status setTxPower(float dbm);
    /// Changes the rate of broadcast frames while running.
    Status setBroadcastRate(PhyRate rate);
    /// Changes the rate for peers without their own PeerOptions::rate.
    Status setUnicastRate(PhyRate rate);

    /// Processes pending radio events and timers when runTask is false.
    void poll();

    Mac localMac() const;
    TransportStats stats() const;
    /// Radio events lost because the event buffer was full.
    uint32_t droppedEvents() const;

    /// Largest frame the local ESP-NOW driver can send (250 or 1470).
    static uint16_t maxSupportedFrameSize();

private:
    class RadioLink;

    static void taskEntry(void* arg);
    Status prepareRadio();
    Status applyRadioSettings();
    Status applyTxPower(float dbm);
    Status applyPeerRate(const Mac& mac);
    PhyRate peerRate(const Mac& mac) const;
    void releaseRadio();
    void handlePeerEvent(PeerEvent event, const PeerInfo& peer);
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
    void processEvents(TickType_t wait);
    void lock() const;
    void unlock() const;
    void cleanup();

    EspNowConfig config_;
    std::unique_ptr<RadioLink> link_;
    std::unique_ptr<Engine> engine_;
    std::unique_ptr<Discovery> discovery_;
    std::vector<std::pair<uint8_t, ReceiveHandler>> listeners_;
    PeerHandler peerHandler_;
    std::vector<Mac> explicitFrameSizes_;
    std::vector<std::pair<Mac, PhyRate>> peerRates_;
    std::vector<LinkHealth> linkHealth_;
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
    SemaphoreHandle_t mutex_ = nullptr;
    SemaphoreHandle_t taskExited_ = nullptr;
    TaskHandle_t task_ = nullptr;
    wifi_interface_t interface_ = WIFI_IF_STA;
    volatile bool stopping_ = false;
    bool started_ = false;
    bool espNowInitialized_ = false;
    bool ownsWifiInit_ = false;
    bool ownsWifiStart_ = false;
    bool ownsEventLoop_ = false;
    bool ratesChanged_ = false;
};

}  // namespace nowtp

#endif  // ESP_PLATFORM
