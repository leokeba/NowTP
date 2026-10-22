// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#if defined(ESP_PLATFORM)

#include "espnow_transport.h"

#include <string.h>

#include <algorithm>

#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_now.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "nvs.h"
#include "nvs_flash.h"
#if ESP_IDF_VERSION_MAJOR >= 5
#include "esp_random.h"
#else
#include "esp_system.h"
#endif

// On Arduino, Wi-Fi is brought up through the WiFi library (part of the ESP32
// core) so that its own state stays consistent if the sketch uses WiFi later.
#if defined(ARDUINO)
#include <WiFi.h>
#define NOWTP_ARDUINO_WIFI 1
#endif

// Per-peer ESP-NOW rates arrived in ESP-IDF 5.1; before that one global rate.
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 1, 0)
#define NOWTP_PER_PEER_RATE 1
#endif

namespace nowtp {

namespace {

const char* const kTag = "nowtp";

struct RateInfo {
    wifi_phy_rate_t rate;
    uint8_t mode;  // 0 = 11b, 1 = 11g, 2 = HT20, 3 = LR
    const char* name;
};

// Indexed by PhyRate.
const RateInfo kRates[] = {
    {WIFI_PHY_RATE_1M_L, 0, "default (1 Mbps)"},
    {WIFI_PHY_RATE_1M_L, 0, "1 Mbps"},
    {WIFI_PHY_RATE_2M_L, 0, "2 Mbps"},
    {WIFI_PHY_RATE_5M_L, 0, "5.5 Mbps"},
    {WIFI_PHY_RATE_11M_L, 0, "11 Mbps"},
    {WIFI_PHY_RATE_6M, 1, "6 Mbps"},
    {WIFI_PHY_RATE_9M, 1, "9 Mbps"},
    {WIFI_PHY_RATE_12M, 1, "12 Mbps"},
    {WIFI_PHY_RATE_18M, 1, "18 Mbps"},
    {WIFI_PHY_RATE_24M, 1, "24 Mbps"},
    {WIFI_PHY_RATE_36M, 1, "36 Mbps"},
    {WIFI_PHY_RATE_48M, 1, "48 Mbps"},
    {WIFI_PHY_RATE_54M, 1, "54 Mbps"},
    {WIFI_PHY_RATE_MCS0_LGI, 2, "MCS0 (6.5 Mbps)"},
    {WIFI_PHY_RATE_MCS1_LGI, 2, "MCS1 (13 Mbps)"},
    {WIFI_PHY_RATE_MCS2_LGI, 2, "MCS2 (19.5 Mbps)"},
    {WIFI_PHY_RATE_MCS3_LGI, 2, "MCS3 (26 Mbps)"},
    {WIFI_PHY_RATE_MCS4_LGI, 2, "MCS4 (39 Mbps)"},
    {WIFI_PHY_RATE_MCS5_LGI, 2, "MCS5 (52 Mbps)"},
    {WIFI_PHY_RATE_MCS6_LGI, 2, "MCS6 (58.5 Mbps)"},
    {WIFI_PHY_RATE_MCS7_LGI, 2, "MCS7 (65 Mbps)"},
    {WIFI_PHY_RATE_LORA_250K, 3, "LR 250 kbps"},
    {WIFI_PHY_RATE_LORA_500K, 3, "LR 500 kbps"},
};

inline const RateInfo& rateInfo(PhyRate r) {
    size_t i = static_cast<size_t>(r);
    return kRates[i < sizeof(kRates) / sizeof(kRates[0]) ? i : 0];
}

inline bool validRate(PhyRate r) {
    return isValid(r);
}

// dBm to the driver's 0.25 dBm units; 0 if out of range.
inline int8_t quarterDbm(float dbm) {
    if (!(dbm >= 2.0f && dbm <= 21.0f)) return 0;
    return static_cast<int8_t>(dbm * 4.0f + 0.5f);
}

// A received frame in the event buffer: this header, then the frame.
struct EventHeader {
    uint32_t timeLo;  // esp_timer time of the driver callback, µs (split: ring buffer
    uint32_t timeHi;  // items are only 4-byte aligned)
    int8_t rssi;      // 0 if unknown
    uint8_t mac[6];   // source
};

// A ring buffer item's own header, and its rounding.
constexpr size_t kRingItemOverhead = 8;
inline size_t ringItemSize(size_t frame) {
    return kRingItemOverhead + ((sizeof(EventHeader) + frame + 3) & ~static_cast<size_t>(3));
}

// ESP-NOW callbacks carry no user pointer, so they reach the active
// instance through these.
std::atomic<RingbufHandle_t> s_events{nullptr};  // received frames
std::atomic<uint32_t> s_received{0};             // frames put in it
std::atomic<TaskHandle_t> s_task{nullptr};       // woken by both callbacks
std::atomic<void (*)(void*)> s_wake{nullptr};    // or the poller's hook (EspNowConfig::wake)
void* s_wakeContext = nullptr;
std::atomic<int> s_inCallback{0};                // end() waits for these to return
// The last "sent" callback. Kept out of the event buffer: a burst of
// received frames could fill it, and a lost "sent" event stalls sending.
// The callback writes the fields, then bumps `count`.
struct SentSlot {
    std::atomic<uint32_t> count{0};
    std::atomic<bool> delivered{false};
    uint8_t mac[6];
    uint64_t timeUs;  // when the driver reported it (time sync stamps exchanges with it)
};
SentSlot s_sent;
// Power found to work by the automatic fallback or optimize(); kept for the boot.
float s_learnedCeilingDbm = 0;
volatile uint32_t s_droppedEvents = 0;
bool s_active = false;

struct CallbackGuard {
    CallbackGuard() { s_inCallback.fetch_add(1); }
    ~CallbackGuard() { s_inCallback.fetch_sub(1); }
};

void wakeTask() {
    TaskHandle_t t = s_task.load();
    if (t) xTaskNotifyGive(t);
    void (*wake)(void*) = s_wake.load();
    if (wake) wake(s_wakeContext);
}

// After the callbacks are unregistered: one may still be running.
void waitForCallbacks() {
    s_events = nullptr;
    s_task = nullptr;
    s_wake = nullptr;
    while (s_inCallback.load() != 0) vTaskDelay(1);
}

inline uint32_t nowMs() {
    return static_cast<uint32_t>(esp_timer_get_time() / 1000);
}

constexpr uint32_t kChannelPollMs = 250;

// Large blocks in PSRAM (EspNowConfig::usePsram). Small ones stay internal:
// message bookkeeping, acks, short messages, all short-lived and often used.
constexpr size_t kPsramMinBytes = 256;
const uint32_t kPsramCaps = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT;

void* psramAllocate(size_t n) {
    if (n >= kPsramMinBytes) {
        void* p = heap_caps_malloc(n, kPsramCaps);
        if (p) return p;
    }
    return malloc(n);
}

void* psramReallocate(void* p, size_t n) {
    if (n >= kPsramMinBytes) {
        void* q = heap_caps_realloc(p, n, kPsramCaps);  // leaves `p` alone on failure
        if (q) return q;
    }
    return realloc(p, n);
}

void psramRelease(void* p) {
    free(p);
}

const heap::Hooks kPsramHooks = {psramAllocate, psramReallocate, psramRelease};

// Images built with CONFIG_SPIRAM_IGNORE_NOTFOUND also run on boards without it.
bool psramPresent() {
    return heap_caps_get_total_size(MALLOC_CAP_SPIRAM) > 0;
}

const char* const kNvsNamespace = "nowtp";
const char* const kNvsKey = "key";

bool loadStoredKey(std::vector<uint8_t>& out) {
    nvs_handle_t h;
    if (nvs_open(kNvsNamespace, NVS_READONLY, &h) != ESP_OK) return false;
    uint8_t buf[Security::kMaxKey];
    size_t len = sizeof(buf);
    esp_err_t err = nvs_get_blob(h, kNvsKey, buf, &len);
    nvs_close(h);
    if (err != ESP_OK || len < Security::kMinKey || len > Security::kMaxKey) return false;
    out.assign(buf, buf + len);
    memset(buf, 0, sizeof(buf));
    return true;
}

// Unencrypted peer on the current channel.
esp_err_t addPlainPeer(const Mac& mac, wifi_interface_t interface) {
    esp_now_peer_info_t peer;
    memset(&peer, 0, sizeof(peer));
    memcpy(peer.peer_addr, mac.bytes, sizeof(peer.peer_addr));
    peer.ifidx = interface;
    return esp_now_add_peer(&peer);
}

// Runs in the Wi-Fi driver task: copy the frame out and return quickly.
void pushReceived(const uint8_t* mac, int8_t rssi, const uint8_t* data, size_t len) {
    // First, like the "sent" callback: time sync compares the two, and taking
    // the ring buffer's lock can wait.
    uint64_t t = static_cast<uint64_t>(esp_timer_get_time());
    CallbackGuard guard;
    RingbufHandle_t rb = s_events;
    if (!rb) return;
    void* slot = nullptr;
    if (xRingbufferSendAcquire(rb, &slot, sizeof(EventHeader) + len, 0) != pdTRUE || !slot) {
        s_droppedEvents = s_droppedEvents + 1;
        return;
    }
    EventHeader* h = static_cast<EventHeader*>(slot);
    h->timeLo = static_cast<uint32_t>(t);
    h->timeHi = static_cast<uint32_t>(t >> 32);
    h->rssi = rssi;
    memcpy(h->mac, mac, sizeof(h->mac));
    memcpy(static_cast<uint8_t*>(slot) + sizeof(EventHeader), data, len);
    xRingbufferSendComplete(rb, slot);
    s_received.fetch_add(1, std::memory_order_release);
    wakeTask();
}

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 1, 0)
void onRecv(const esp_now_recv_info_t* info, const uint8_t* data, int len) {
    if (!info || len <= 0) return;
    int8_t rssi = info->rx_ctrl ? static_cast<int8_t>(info->rx_ctrl->rssi) : 0;
    pushReceived(info->src_addr, rssi, data, static_cast<size_t>(len));
}
#else
void onRecv(const uint8_t* mac, const uint8_t* data, int len) {
    if (!mac || len <= 0) return;
    pushReceived(mac, 0, data, static_cast<size_t>(len));
}
#endif

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 5, 0)
void onSent(const esp_now_send_info_t* info, esp_now_send_status_t status) {
    const uint8_t* mac = info ? info->des_addr : nullptr;
#else
void onSent(const uint8_t* mac, esp_now_send_status_t status) {
#endif
    uint64_t t = static_cast<uint64_t>(esp_timer_get_time());
    CallbackGuard guard;
    if (!s_events.load()) return;
    s_sent.timeUs = t;
    if (mac) {
        memcpy(s_sent.mac, mac, sizeof(s_sent.mac));
    } else {
        memset(s_sent.mac, 0, sizeof(s_sent.mac));
    }
    s_sent.delivered.store(status == ESP_NOW_SEND_SUCCESS, std::memory_order_relaxed);
    s_sent.count.fetch_add(1, std::memory_order_release);
    wakeTask();
}

}  // namespace

// ESP-NOW's peer table, for PeerTable.
class EspNowTransport::PeerDriver : public PeerTable::Driver {
public:
    explicit PeerDriver(wifi_interface_t interface) : interface_(interface) {}
    void setInterface(wifi_interface_t interface) { interface_ = interface; }
    Result add(const Mac& mac) override {
        esp_err_t err = addPlainPeer(mac, interface_);
        if (err == ESP_OK || err == ESP_ERR_ESPNOW_EXIST) return Result::Ok;
        if (err == ESP_ERR_ESPNOW_FULL) return Result::Full;
        ESP_LOGW(kTag, "adding peer: %s", esp_err_to_name(err));
        return Result::Error;
    }
    void remove(const Mac& mac) override { esp_now_del_peer(mac.bytes); }
    bool exists(const Mac& mac) const override { return esp_now_is_peer_exist(mac.bytes); }

private:
    wifi_interface_t interface_;
};

// Link implementation over esp_now_send(), with per-peer frame sizes.
class EspNowTransport::RadioLink : public Link {
public:
    RadioLink(uint16_t defaultSize, bool autoAddPeers, PeerTable& peers, SendTracker& tracker,
              std::function<void(const Mac&)> added)
        : defaultSize_(defaultSize),
          autoAddPeers_(autoAddPeers),
          peers_(peers),
          tracker_(tracker),
          added_(std::move(added)) {}

    Status sendFrame(const Mac& dst, const uint8_t* data, size_t len) override {
        if (autoAddPeers_ && !dst.isBroadcast()) {
            bool added = false;
            if (peers_.use(dst, nowMs(), added) != Status::Ok) {
                ESP_LOGW(kTag, "no room in the ESP-NOW peer table");
                return Status::LinkError;
            }
            if (added && added_) added_(dst);  // apply the unicast rate to the new peer
        }
        uint32_t reported = s_sent.count.load(std::memory_order_acquire);
        esp_err_t err = esp_now_send(dst.bytes, data, len);
        if (err == ESP_OK) {
            tracker_.sent(dst, reported, nowMs());
            peers_.setInFlight(dst);
            return Status::Ok;
        }
        if (err == ESP_ERR_ESPNOW_NO_MEM) return Status::QueueFull;
        ESP_LOGW(kTag, "esp_now_send: %s", esp_err_to_name(err));
        return Status::LinkError;
    }

    size_t maxFrameSize(const Mac& dst) const override {
        for (const auto& p : sizes_) {
            if (p.first == dst) return p.second;
        }
        return defaultSize_;
    }

    /// A size of 0 reverts the peer to the default.
    void setFrameSize(const Mac& mac, uint16_t size) {
        for (size_t i = 0; i < sizes_.size(); ++i) {
            if (sizes_[i].first != mac) continue;
            if (size) {
                sizes_[i].second = size;
            } else {
                sizes_.erase(sizes_.begin() + static_cast<std::ptrdiff_t>(i));
            }
            return;
        }
        if (size) sizes_.push_back(std::make_pair(mac, size));
    }

private:
    uint16_t defaultSize_;
    bool autoAddPeers_;
    PeerTable& peers_;
    SendTracker& tracker_;
    std::function<void(const Mac&)> added_;
    std::vector<std::pair<Mac, uint16_t>> sizes_;
};

// Lets the blocking diagnostic procedures run in the caller's task while the
// NowTP task (or poll()) keeps the engine going.
class EspNowTransport::Host : public DiagnosticsHost {
public:
    explicit Host(EspNowTransport& t) : t_(t) {}
    uint32_t now() override { return nowMs(); }
    void sleep(uint32_t ms) override {
        if (t_.config_.runTask) {
            TickType_t ticks = pdMS_TO_TICKS(ms);
            vTaskDelay(ticks ? ticks : 1);
            return;
        }
        uint32_t end = nowMs() + ms;
        do {
            t_.processEvents(1);
        } while (static_cast<int32_t>(nowMs() - end) < 0);
    }
    void lock() override { t_.lock(); }
    void unlock() override { t_.unlock(); }
    uint32_t random() override { return esp_random(); }

private:
    EspNowTransport& t_;
};

// Lets go of the lock, however deep the calling task holds it, while an
// application callback runs (see CallbackGate), and takes it back after.
class EspNowTransport::Gate : public CallbackGate {
public:
    explicit Gate(EspNowTransport& t) : t_(t) {}
    uint32_t enter() override {
        t_.callbacks_++;
        if (xSemaphoreGetMutexHolder(t_.mutex_) != xTaskGetCurrentTaskHandle()) return 0;
        int depth = t_.lockDepth_;
        t_.lockDepth_ = 0;
        for (int i = 0; i < depth; ++i) xSemaphoreGiveRecursive(t_.mutex_);
        return static_cast<uint32_t>(depth);
    }
    void leave(uint32_t depth) override {
        for (uint32_t i = 0; i < depth; ++i) xSemaphoreTakeRecursive(t_.mutex_, portMAX_DELAY);
        if (depth) t_.lockDepth_ = static_cast<int>(depth);
        t_.callbacks_--;
    }

private:
    EspNowTransport& t_;
};

EspNowTransport::EspNowTransport() {}

EspNowTransport::~EspNowTransport() {
    end();
}

uint16_t EspNowTransport::maxSupportedFrameSize() {
#ifdef ESP_NOW_MAX_DATA_LEN_V2
    return ESP_NOW_MAX_DATA_LEN_V2;
#else
    return ESP_NOW_MAX_DATA_LEN;
#endif
}

float EspNowTransport::learnedTxPowerCeiling() {
    return s_learnedCeilingDbm;
}

uint32_t EspNowTransport::droppedEvents() const {
    return s_droppedEvents;
}

Status EspNowTransport::begin(const EspNowConfig& config) {
    if (started_ || s_active) return Status::InvalidState;

    config_ = config;
    // Where NowTP can only allocate with operator new, it first checks this.
    heap::probe() = [] { return heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT); };
    Status radio = prepareRadio();
    if (radio != Status::Ok) return radio;
    psram_ = config_.usePsram && psramPresent();
    if (psram_) heap::hooks() = &kPsramHooks;

    uint16_t maxSize = maxSupportedFrameSize();
    if (config_.defaultMaxFrameSize > maxSize) config_.defaultMaxFrameSize = maxSize;
    if (config_.defaultMaxFrameSize < 32) config_.defaultMaxFrameSize = 32;
    if (config_.tickIntervalMs == 0) config_.tickIntervalMs = 1;

    // At least one frame of the largest size must fit.
    size_t ring = std::max(config_.eventBufferSize, ringItemSize(maxSupportedFrameSize()));
    ring = (ring + 3) & ~static_cast<size_t>(3);
    events_ = nullptr;
#if configSUPPORT_STATIC_ALLOCATION
    // Only the Wi-Fi task and NowTP's poller touch it, never with the flash
    // cache off; its control block stays internal.
    if (psram_) {
        ringStorage_ = heap_caps_malloc(ring, kPsramCaps);
        ringControl_ = heap_caps_malloc(sizeof(StaticRingbuffer_t), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        if (ringStorage_ && ringControl_) {
            events_ = xRingbufferCreateStatic(ring, RINGBUF_TYPE_NOSPLIT, static_cast<uint8_t*>(ringStorage_),
                                              static_cast<StaticRingbuffer_t*>(ringControl_));
        }
        if (!events_) {
            free(ringStorage_);
            free(ringControl_);
            ringStorage_ = ringControl_ = nullptr;
        }
    }
#endif
    if (!events_) events_ = xRingbufferCreate(ring, RINGBUF_TYPE_NOSPLIT);
    sendTracker_ = SendTracker();
    mutex_ = xSemaphoreCreateRecursiveMutex();
    taskExited_ = xSemaphoreCreateBinary();
    peerDriver_.reset(new PeerDriver(interface_));
    peerTable_.reset(new PeerTable(*peerDriver_));
    link_.reset(new RadioLink(config_.defaultMaxFrameSize, config_.autoAddPeers, *peerTable_, sendTracker_,
                              [this](const Mac& mac) { applyPeerRate(mac); }));
    engine_.reset(new Engine(*link_, config_.protocol, static_cast<uint16_t>(esp_random())));
    gate_.reset(new Gate(*this));
    engine_->setCallbackGate(gate_.get());
    if (!events_ || !mutex_ || !taskExited_) {
        cleanup();
        return Status::NoMemory;
    }
    for (auto& l : listeners_) engine_->listen(l.first, l.second);
    host_.reset(new Host(*this));

    SecurityConfig sc = config_.security;
    if (sc.key.empty() && config_.persistSecurityKey && loadStoredKey(sc.key)) {
        ESP_LOGI(kTag, "using the installation key stored in NVS");
    }
    security_.reset(new Security(*engine_, *host_, localMac(), sc));
    if (!sc.key.empty()) memset(sc.key.data(), 0, sc.key.size());
    if (config_.persistSecurityKey) security_->onKeyChanged([this](const std::vector<uint8_t>& k) { storeKey(k); });

    if (config_.enableDiscovery) {
        discovery_.reset(new Discovery(*engine_, config_.discovery, maxSupportedFrameSize(),
                                       [] { return static_cast<uint32_t>(esp_random()); }));
        discovery_->onPeerEvent([this](PeerEvent e, const PeerInfo& p) { handlePeerEvent(e, p); });
        discovery_->setChannelInfo(radio_.channel, config_.channel.anchor || channelFixed(), nowMs());
        follower_.reset(new ChannelFollower(*discovery_, *this, config_.channel));
        follower_->onChannelChange([this](uint8_t ch) {
            ESP_LOGI(kTag, "followed peers to channel %u", ch);
            channelChanged(ch);
        });
        discovery_->onPeerMoved([this](const PeerInfo& p, uint8_t ch) { follower_->onPeerMoved(p, ch, nowMs()); });
        // A new peer's first announcement waits for its epoch to be verified: ask again at once.
        security_->onPeerVerified([this](const Mac& mac) {
            if (!discovery_->find(mac)) discovery_->discover(nowMs());
        });
    }
    if (config_.enableDiagnostics) {
        diagnostics_.reset(new Diagnostics(*engine_, *this, *host_, config_.diagnostics));
        diagnostics_->setDiscovery(discovery_.get());
    }
    if (config_.enableTimeSync) {
        timeSync_.reset(new TimeSync(*engine_, [] { return static_cast<uint64_t>(esp_timer_get_time()); },
                                     config_.timeSync, localMac()));
        timeSync_->setDiscovery(discovery_.get());
    }
    if (config_.enableStreams) {
        streams_.reset(new Streams(*engine_, [] { return static_cast<uint32_t>(esp_random()); }));
        streams_->onIncoming(streamAcceptor_);
    }
    fallback_ = PowerFallback();
    linkChecks_.clear();

    esp_err_t err = esp_now_init();
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "esp_now_init: %s", esp_err_to_name(err));
        cleanup();
        return Status::LinkError;
    }
    espNowInitialized_ = true;

    s_droppedEvents = 0;
    stats_ = TransportStats();
    linkHealth_.clear();
    // Per-peer settings belong to a session: ESP-NOW forgets its peers on deinit.
    peerRates_.clear();
    explicitFrameSizes_.clear();
    s_sent.count = 0;  // no callbacks registered yet
    sentSeen_ = 0;
    s_received = 0;
    taken_ = 0;
    lockDepth_ = 0;
    s_wakeContext = config_.wakeContext;
    if (!config_.runTask) s_wake = config_.wake;
    s_events = events_;
    s_active = true;
    esp_now_register_recv_cb(onRecv);
    esp_now_register_send_cb(onSent);

    Mac bcast = Mac::broadcast();
    if (!esp_now_is_peer_exist(bcast.bytes)) {
        err = addPlainPeer(bcast, interface_);
        if (err != ESP_OK) {
            ESP_LOGE(kTag, "adding broadcast peer: %s", esp_err_to_name(err));
            cleanup();
            return Status::LinkError;
        }
    }
    if (applyPeerRate(bcast) != Status::Ok) {
        cleanup();
        return Status::LinkError;
    }

    stopping_ = false;
    ending_ = false;
    started_ = true;
    lastChannelPoll_ = nowMs();
    pendingChannel_ = 0;
    security_->start();  // first, so that every announcement is authenticated
    if (diagnostics_) diagnostics_->start();
    if (timeSync_) timeSync_->start(nowMs());
    if (streams_) streams_->start();
    if (discovery_) discovery_->start(nowMs());
    if (follower_) follower_->start(nowMs());
    if (config_.runTask) {
        BaseType_t ok = xTaskCreatePinnedToCore(taskEntry, "nowtp", config_.taskStackSize, this,
                                                config_.taskPriority, &task_, config_.taskCore);
        if (ok != pdPASS) {
            task_ = nullptr;
            cleanup();
            return Status::NoMemory;
        }
        s_task = task_;
    }
    return Status::Ok;
}

void EspNowTransport::end() {
    if (!started_) return;
    // A poller woken now would run while end() takes things down.
    ending_ = true;
    s_wake = nullptr;
    lock();
    if (diagnostics_) diagnostics_->stop();
    if (streams_) streams_->stop();  // pending streams complete with Cancelled
    if (follower_) follower_->stop();
    if (timeSync_) timeSync_->stop();
    unlock();
    if (discovery_) {
        // Say goodbye so peers drop us at once, and give the frame time to go out.
        lock();
        discovery_->stop(nowMs());
        unlock();
        for (int i = 0; i < 50 && engine_->pendingMessages() > 0; ++i) {
            if (task_) {
                vTaskDelay(pdMS_TO_TICKS(2));
            } else {
                processEvents(pdMS_TO_TICKS(2));
            }
        }
    }
    esp_now_unregister_recv_cb();
    esp_now_unregister_send_cb();
    waitForCallbacks();

    if (task_) {
        stopping_ = true;
        xTaskNotifyGive(task_);
        xSemaphoreTake(taskExited_, portMAX_DELAY);
        task_ = nullptr;
    }
    lock();
    engine_->cancelAll(Status::Cancelled);
    unlock();
    // Callbacks run without the lock: one may still be running in another task.
    while (callbacks_.load() != 0) vTaskDelay(1);
    cleanup();
}

void EspNowTransport::cleanup() {
    if (espNowInitialized_) {
        esp_now_unregister_recv_cb();
        esp_now_unregister_send_cb();
        esp_now_deinit();
        espNowInitialized_ = false;
    }
    waitForCallbacks();  // before the event buffer goes
    s_active = false;
    // Services before what they run on.
    streams_.reset();
    timeSync_.reset();
    follower_.reset();
    diagnostics_.reset();
    discovery_.reset();
    security_.reset();
    host_.reset();
    engine_.reset();
    gate_.reset();
    link_.reset();
    peerTable_.reset();
    peerDriver_.reset();
    if (events_) {
        vRingbufferDelete(events_);
        events_ = nullptr;
    }
    free(ringStorage_);  // a static ring buffer's memory is ours to free
    free(ringControl_);
    ringStorage_ = ringControl_ = nullptr;
    // NowTP's blocks are all freed; any a handler took are freed with free().
    if (heap::hooks() == &kPsramHooks) heap::hooks() = nullptr;
    psram_ = false;
    if (mutex_) {
        vSemaphoreDelete(mutex_);
        mutex_ = nullptr;
    }
    if (taskExited_) {
        vSemaphoreDelete(taskExited_);
        taskExited_ = nullptr;
    }
    started_ = false;
    releaseRadio();
}

void EspNowTransport::lock() const {
    xSemaphoreTakeRecursive(mutex_, portMAX_DELAY);
    lockDepth_++;
}

// A call that may have changed what pollDelayMs() says wakes the poller
// once it lets go. poll() itself doesn't: its callbacks' calls are nested.
void EspNowTransport::unlock(bool changed) const {
    bool wake = --lockDepth_ == 0 && changed && !config_.runTask && config_.wake && !ending_;
    xSemaphoreGiveRecursive(mutex_);
    if (wake) config_.wake(config_.wakeContext);
}

void EspNowTransport::taskEntry(void* arg) {
    EspNowTransport* self = static_cast<EspNowTransport*>(arg);
    TickType_t wait = pdMS_TO_TICKS(self->config_.tickIntervalMs);
    if (wait == 0) wait = 1;
    bool more = false;
    while (!self->stopping_) more = self->processEvents(more ? 0 : wait);
    xSemaphoreGive(self->taskExited_);
    vTaskDelete(nullptr);
}

uint32_t EspNowTransport::poll() {
    if (started_ && !config_.runTask) processEvents(0);
    return pollDelayMs();
}

uint32_t EspNowTransport::pollDelayMs() const {
    if (!started_) return kChannelPollMs;
    lock();
    // Frames or a "sent" report waiting (more than one poll() takes, or new).
    if (s_received.load(std::memory_order_acquire) != taken_ ||
        s_sent.count.load(std::memory_order_acquire) != sentSeen_ || modeChanged_.load() || stationChanged_.load()) {
        unlock(false);
        return 0;
    }
    Deadline d(nowMs());
    engine_->nextTick(d);
    if (discovery_) discovery_->nextTick(d);
    if (diagnostics_) diagnostics_->nextTick(d);
    if (follower_) follower_->nextTick(d);
    if (timeSync_) timeSync_->nextTick(d);
    if (streams_) streams_->nextTick(d);
    d.at(lastChannelPoll_ + kChannelPollMs);
    if (fallback_.active && !fallback_.pingInFlight) d.at(fallback_.nextPingAt);
    for (const LinkCheck& c : linkChecks_) {
        if (!c.inFlight) d.at(c.nextAt);
    }
    unlock(false);
    return d.delay(kChannelPollMs);
}

// The latest "sent" callback, if it reports the frame the engine waits for.
void EspNowTransport::checkSent() {
    uint32_t count = s_sent.count.load(std::memory_order_acquire);
    if (count == sentSeen_) return;
    Mac mac = Mac::from(s_sent.mac);
    bool delivered = s_sent.delivered.load(std::memory_order_relaxed);
    uint64_t sentUs = s_sent.timeUs;
    if (s_sent.count.load(std::memory_order_acquire) != count) return;  // being written; it wakes us again
    sentSeen_ = count;
    notePeerSendResult(mac, delivered);
    if (!sendTracker_.reports(count, mac)) return;  // a late report for a frame the engine gave up on
    peerTable_->clearInFlight();
    engine_->onFrameSent(delivered, nowMs(), sentUs);
}

bool EspNowTransport::processEvents(TickType_t wait) {
    size_t size = 0;
    void* item = nullptr;
    if (wait) {
        if (task_ && xTaskGetCurrentTaskHandle() == task_) {
            ulTaskNotifyTake(pdTRUE, wait);  // either callback wakes us, or the tick
        } else {
            // An application task (poll mode): its notifications aren't ours.
            item = xRingbufferReceive(events_, &size, wait);
        }
    }
    lock();
    if (modeChanged_.exchange(false)) followInterface();
    if (stationChanged_.exchange(false)) stationChanged(nowMs());
    checkSent();
    // Bounded batch so timers still run under a flood of frames.
    int n = 0;
    while (n < 32 && (item || (item = xRingbufferReceive(events_, &size, 0)) != nullptr)) {
        ++n;
        ++taken_;
        if (size >= sizeof(EventHeader)) {
            const EventHeader* h = static_cast<const EventHeader*>(item);
            const uint8_t* data = static_cast<const uint8_t*>(item) + sizeof(EventHeader);
            Mac src = Mac::from(h->mac);
            notePeerHeard(src);
            uint64_t at = h->timeLo | (static_cast<uint64_t>(h->timeHi) << 32);
            engine_->onFrameReceived(src, data, size - sizeof(EventHeader), nowMs(), h->rssi, at);
        }
        vRingbufferReturnItem(events_, item);
        item = nullptr;
        checkSent();  // the next frame can go as soon as the last one is reported
    }
    uint32_t now = nowMs();
    engine_->tick(now);
    if (security_) security_->tick(now);
    if (discovery_) discovery_->tick(now);
    if (diagnostics_) diagnostics_->tick(now);
    pollChannel(now);
    if (follower_) {
        follower_->setSuspended(diagnostics_ && diagnostics_->busy(), now);
        follower_->tick(now);
    }
    if (timeSync_) timeSync_->tick(now);
    if (streams_) streams_->tick(now);
    tickLinkChecks(now);
    unlock(false);
    return n >= 32;
}

Status EspNowTransport::addPeer(const Mac& mac, const PeerOptions& options) {
    if (!started_) return Status::InvalidState;
    uint16_t size = options.maxFrameSize;
    if (size > maxSupportedFrameSize() || !validRate(options.rate)) return Status::InvalidArgument;
    if (options.rate != PhyRate::Default) {
        if (mac.isBroadcast()) return Status::InvalidArgument;  // use setBroadcastRate()
        if (!rateUsable(options.rate)) return Status::InvalidArgument;
#if !defined(NOWTP_PER_PEER_RATE)
        if (options.rate != config_.radio.unicastRate) {
            ESP_LOGE(kTag, "per-peer rates need ESP-IDF 5.1 or later");
            return Status::InvalidArgument;
        }
#endif
    }

    if (!mac.isBroadcast()) {
        esp_now_peer_info_t peer;
        memset(&peer, 0, sizeof(peer));
        memcpy(peer.peer_addr, mac.bytes, sizeof(peer.peer_addr));
        peer.channel = options.channel;
        peer.ifidx = interface_;
        peer.encrypt = options.encrypt;
        if (options.encrypt) memcpy(peer.lmk, options.lmk, sizeof(peer.lmk));
        lock();
        esp_err_t err = esp_now_is_peer_exist(mac.bytes) ? esp_now_mod_peer(&peer) : esp_now_add_peer(&peer);
        // Room taken by peers added automatically is the application's to claim.
        if (err == ESP_ERR_ESPNOW_FULL && peerTable_->evictOne()) err = esp_now_add_peer(&peer);
        if (err == ESP_OK) peerTable_->pin(mac);
        unlock();
        if (err == ESP_ERR_ESPNOW_FULL) return Status::NoMemory;
        if (err != ESP_OK) {
            ESP_LOGE(kTag, "adding peer: %s", esp_err_to_name(err));
            return Status::LinkError;
        }
    }
    lock();
    link_->setFrameSize(mac, size);
    explicitFrameSizes_.erase(std::remove(explicitFrameSizes_.begin(), explicitFrameSizes_.end(), mac),
                              explicitFrameSizes_.end());
    if (size) explicitFrameSizes_.push_back(mac);
    for (size_t i = 0; i < peerRates_.size(); ++i) {
        if (peerRates_[i].first == mac) peerRates_.erase(peerRates_.begin() + static_cast<std::ptrdiff_t>(i));
    }
    if (options.rate != PhyRate::Default) peerRates_.push_back(std::make_pair(mac, options.rate));
    Status st = mac.isBroadcast() ? Status::Ok : applyPeerRate(mac);
    unlock();
    return st;
}

Status EspNowTransport::removePeer(const Mac& mac) {
    if (!started_) return Status::InvalidState;
    if (mac.isBroadcast()) return Status::InvalidArgument;
    lock();
    esp_err_t err = esp_now_del_peer(mac.bytes);
    peerTable_->forget(mac);
    link_->setFrameSize(mac, 0);
    for (size_t i = 0; i < peerRates_.size(); ++i) {
        if (peerRates_[i].first == mac) peerRates_.erase(peerRates_.begin() + static_cast<std::ptrdiff_t>(i));
    }
    unlock();
    return err == ESP_OK || err == ESP_ERR_ESPNOW_NOT_FOUND ? Status::Ok : Status::LinkError;
}

Status EspNowTransport::setPrimaryKey(const uint8_t pmk[16]) {
    if (!started_) return Status::InvalidState;
    return esp_now_set_pmk(pmk) == ESP_OK ? Status::Ok : Status::LinkError;
}

Status EspNowTransport::send(const Mac& dst, uint8_t port, const void* data, size_t len,
                             const SendOptions& options, CompletionHandler done) {
    if (!started_) return Status::InvalidState;
    if (port >= kFirstReservedPort) return Status::InvalidArgument;
    if (!config_.autoAddPeers && !dst.isBroadcast() && !esp_now_is_peer_exist(dst.bytes)) {
        return Status::LinkError;
    }
    lock();
    Status st = engine_->send(dst, port, static_cast<const uint8_t*>(data), len, options, std::move(done), nowMs());
    unlock();
    return st;
}

Status EspNowTransport::sendBuffer(const Mac& dst, uint8_t port, uint8_t* buffer, size_t len, size_t capacity,
                                   const SendOptions& options, CompletionHandler done) {
    Bytes owned(buffer);
    if (!started_) return Status::InvalidState;
    if (port >= kFirstReservedPort) return Status::InvalidArgument;
    if (!config_.autoAddPeers && !dst.isBroadcast() && !esp_now_is_peer_exist(dst.bytes)) {
        return Status::LinkError;
    }
    lock();
    Status st = engine_->sendBuffer(dst, port, owned.release(), len, capacity, options, std::move(done), nowMs());
    unlock();
    return st;
}

Status EspNowTransport::sendAndWait(const Mac& dst, uint8_t port, const void* data, size_t len,
                                    const SendOptions& options) {
    if (!started_ || !config_.runTask || xTaskGetCurrentTaskHandle() == task_) return Status::InvalidState;

    struct Wait {
        SemaphoreHandle_t done;
        Status status;
    } wait;
    wait.done = xSemaphoreCreateBinary();
    wait.status = Status::Cancelled;
    if (!wait.done) return Status::NoMemory;

    Wait* w = &wait;
    Status st = send(dst, port, data, len, options, [w](Status s) {
        w->status = s;
        xSemaphoreGive(w->done);
    });
    if (st == Status::Ok) {
        // The engine always completes a message (at the latest on its deadline or end()).
        xSemaphoreTake(wait.done, portMAX_DELAY);
        st = wait.status;
    }
    vSemaphoreDelete(wait.done);
    return st;
}

Status EspNowTransport::listen(uint8_t port, ReceiveHandler handler) {
    if (port >= kFirstReservedPort) return Status::InvalidArgument;
    bool replaced = false;
    for (size_t i = 0; i < listeners_.size(); ++i) {
        if (listeners_[i].first != port) continue;
        if (handler) {
            listeners_[i].second = handler;
        } else {
            listeners_.erase(listeners_.begin() + static_cast<std::ptrdiff_t>(i));
        }
        replaced = true;
        break;
    }
    if (!replaced && handler) listeners_.push_back(std::make_pair(port, handler));

    if (started_) {
        lock();
        engine_->listen(port, std::move(handler));
        unlock();
    }
    return Status::Ok;
}

Mac EspNowTransport::localMac() const {
    Mac m;
    memset(m.bytes, 0, sizeof(m.bytes));
    esp_wifi_get_mac(interface_, m.bytes);
    return m;
}

EspNowTransport::TransportStats EspNowTransport::stats() const {
    if (!started_) return TransportStats();
    lock();
    TransportStats s;
    static_cast<Stats&>(s) = engine_->stats();
    s.droppedEvents = s_droppedEvents;
    s.oneWayLinks = stats_.oneWayLinks;
    unlock(false);
    return s;
}

// ---------------------------------------------------------------------------
// Radio setup

Status EspNowTransport::prepareRadio() {
    ownsWifiInit_ = ownsWifiStart_ = ownsEventLoop_ = false;
    radio_ = RadioInfo();
    saved_ = SavedRadio();
    ratesChanged_ = false;

    if (!config_.radio.disablePowerSave) config_.radio.powerSave = PowerSave::Leave;
    const RadioConfig& rc = config_.radio;
    if ((rc.txPowerDbm != 0 && quarterDbm(rc.txPowerDbm) == 0) || !validRate(rc.broadcastRate) ||
        !validRate(rc.unicastRate) || static_cast<uint8_t>(rc.powerSave) > static_cast<uint8_t>(PowerSave::MaxModem)) {
        ESP_LOGE(kTag, "invalid radio settings (power 2-21 dBm)");
        return Status::InvalidArgument;
    }
    if (!rc.longRange && (isLongRange(rc.broadcastRate) || isLongRange(rc.unicastRate))) {
        ESP_LOGE(kTag, "Long Range rates need RadioConfig::longRange");
        return Status::InvalidArgument;
    }
#if !defined(NOWTP_PER_PEER_RATE)
    if (rc.broadcastRate != PhyRate::Default && rc.unicastRate != PhyRate::Default &&
        rc.broadcastRate != rc.unicastRate) {
        ESP_LOGE(kTag, "different broadcast and unicast rates need ESP-IDF 5.1 or later");
        return Status::InvalidArgument;
    }
#endif

    wifi_mode_t mode = WIFI_MODE_NULL;
    esp_err_t err = esp_wifi_get_mode(&mode);
    bool initialized = err == ESP_OK;
    if (err != ESP_OK && err != ESP_ERR_WIFI_NOT_INIT) {
        ESP_LOGE(kTag, "esp_wifi_get_mode: %s", esp_err_to_name(err));
        return Status::LinkError;
    }

    if (!initialized || mode == WIFI_MODE_NULL) {
        if (!config_.radio.initWifi) {
            ESP_LOGE(kTag, "Wi-Fi is not set up and EspNowConfig::initWifi is false");
            return Status::InvalidState;
        }
#if defined(NOWTP_ARDUINO_WIFI)
        if (!WiFi.mode(WIFI_STA)) {
            ESP_LOGE(kTag, "WiFi.mode(WIFI_STA) failed");
            return Status::LinkError;
        }
        ownsWifiInit_ = true;  // undone with WiFi.mode(WIFI_OFF)
#else
        if (!initialized) {
            // The Wi-Fi driver posts events to the default loop and keeps PHY
            // calibration in NVS. Provide both if the application has not; NVS is
            // only initialized, never erased.
            esp_err_t loop = esp_event_loop_create_default();
            ownsEventLoop_ = loop == ESP_OK;
            if (loop != ESP_OK && loop != ESP_ERR_INVALID_STATE) {
                ESP_LOGW(kTag, "esp_event_loop_create_default: %s", esp_err_to_name(loop));
            }
            esp_err_t nvs = nvs_flash_init();
            if (nvs != ESP_OK) ESP_LOGD(kTag, "nvs_flash_init: %s (PHY calibration not cached)", esp_err_to_name(nvs));

            wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
            cfg.nvs_enable = 0;  // nothing to persist; the app may not have set up NVS
            err = esp_wifi_init(&cfg);
            if (err != ESP_OK) {
                ESP_LOGE(kTag, "esp_wifi_init: %s", esp_err_to_name(err));
                return Status::LinkError;
            }
            ownsWifiInit_ = true;
            esp_wifi_set_storage(WIFI_STORAGE_RAM);
        }
        err = esp_wifi_set_mode(WIFI_MODE_STA);
        if (err != ESP_OK) {
            ESP_LOGE(kTag, "esp_wifi_set_mode: %s", esp_err_to_name(err));
            releaseRadio();
            return Status::LinkError;
        }
#endif
        mode = WIFI_MODE_STA;
    }

    // Initialized but not started (this query has no side effects).
    uint16_t apCount = 0;
    if (esp_wifi_scan_get_ap_num(&apCount) == ESP_ERR_WIFI_NOT_STARTED) {
        err = esp_wifi_start();
        if (err != ESP_OK) {
            ESP_LOGE(kTag, "esp_wifi_start: %s", esp_err_to_name(err));
            releaseRadio();
            return Status::LinkError;
        }
        ownsWifiStart_ = true;
    }

    // Follow the station's association from events, then read where it stands now.
    err = esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &EspNowTransport::wifiEventHandler,
                                              this, &wifiEvents_);
    if (err != ESP_OK) {
        ESP_LOGW(kTag, "no Wi-Fi event handler (%s): polling the station", esp_err_to_name(err));
        wifiEvents_ = nullptr;
    }
    wifi_ap_record_t ap;
    staConnected_ = (mode == WIFI_MODE_STA || mode == WIFI_MODE_APSTA) && esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
    radio_.wifiStartedByNowTP = ownsWifiInit_ || ownsWifiStart_;
    radio_.softApActive = mode == WIFI_MODE_AP || mode == WIFI_MODE_APSTA;
    radio_.stationConnected = staConnected_;
    interface_ = mode == WIFI_MODE_AP ? WIFI_IF_AP : WIFI_IF_STA;
    radio_.interface = interface_;

    // Country first: it decides which channels and powers are allowed.
    if (config_.radio.countryCode[0]) {
        if (!ownsWifiInit_ && esp_wifi_get_country_code(saved_.countryCode) == ESP_OK) {
            saved_.countryCode[3] = 0;
            saved_.country = true;
        }
        char cc[3] = {config_.radio.countryCode[0], config_.radio.countryCode[1], 0};
        err = esp_wifi_set_country_code(cc, false);
        if (err != ESP_OK) {
            ESP_LOGE(kTag, "esp_wifi_set_country_code(%s): %s", cc, esp_err_to_name(err));
            releaseRadio();
            return Status::InvalidArgument;
        }
    }

    uint8_t channel = 0;
    wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
    esp_wifi_get_channel(&channel, &second);
    const uint8_t wanted = config_.radio.channel;
    if (wanted && channel != wanted) {
        if (radio_.stationConnected || radio_.softApActive) {
            ESP_LOGI(kTag, "staying on channel %u, set by the %s", channel,
                     radio_.stationConnected ? "access point" : "soft-AP");
        } else {
            err = esp_wifi_set_channel(wanted, WIFI_SECOND_CHAN_NONE);
            if (err != ESP_OK) ESP_LOGW(kTag, "esp_wifi_set_channel: %s", esp_err_to_name(err));
            esp_wifi_get_channel(&channel, &second);
        }
    }
    radio_.channel = channel;

    // The chip's power ceiling: ask for the maximum, read back, restore.
    int8_t before = 0, limit = 80;
    if (esp_wifi_get_max_tx_power(&before) == ESP_OK) {
        esp_wifi_set_max_tx_power(84);
        esp_wifi_get_max_tx_power(&limit);
        esp_wifi_set_max_tx_power(before);
    }
    limitQuarterDbm_ = limit;

    Status settings = applyRadioSettings();
    if (settings != Status::Ok) {
        releaseRadio();
        return settings;
    }
    if (config_.radio.autoPowerFallback && s_learnedCeilingDbm > 0 && txPower() > s_learnedCeilingDbm + 0.01f) {
        ESP_LOGI(kTag, "using the %.1f dBm transmit power found to work earlier", s_learnedCeilingDbm);
        applyTxPower(s_learnedCeilingDbm);
    }

    ESP_LOGI(kTag, "radio ready: channel %u on %s%s%s%s", radio_.channel, interface_ == WIFI_IF_AP ? "AP" : "STA",
             radio_.stationConnected ? ", station connected" : "", radio_.softApActive ? ", soft-AP active" : "",
             radio_.wifiStartedByNowTP ? ", Wi-Fi started by NowTP" : "");
    return Status::Ok;
}

void EspNowTransport::wifiEventHandler(void* arg, esp_event_base_t base, int32_t id, void* data) {
    (void)base;
    (void)data;
    EspNowTransport* self = static_cast<EspNowTransport*>(arg);
    // The channel the station settled on: the access point's. Scans never
    // raise these, unlike a channel merely read from the driver.
    uint8_t home = 0;
    if (id == WIFI_EVENT_STA_CONNECTED) {
        self->staConnected_ = true;
        if (data) home = static_cast<const wifi_event_sta_connected_t*>(data)->channel;
    } else if (id == WIFI_EVENT_STA_DISCONNECTED || id == WIFI_EVENT_STA_STOP) {
        self->staConnected_ = false;
    }
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 3, 0)
    if (id == WIFI_EVENT_HOME_CHANNEL_CHANGE && data) {
        home = static_cast<const wifi_event_home_channel_change_t*>(data)->new_chan;
    }
#endif
    if (id == WIFI_EVENT_STA_CONNECTED || id == WIFI_EVENT_STA_DISCONNECTED || home != 0) {
        if (home != 0) self->homeChannel_ = home;
        self->stationChanged_ = true;  // the NowTP task tells peers at once
        wakeTask();
    }
    if (id == WIFI_EVENT_STA_START || id == WIFI_EVENT_STA_STOP || id == WIFI_EVENT_AP_START ||
        id == WIFI_EVENT_AP_STOP) {
        self->modeChanged_ = true;  // the NowTP task looks at the mode
        wakeTask();
    }
}

// ESP-NOW sends through one interface: the station's while it runs, else the
// soft-AP's. Peers stay bound to the one they were added on, and frames to them
// fail once it stops, so they all move when the application changes the mode
// (drops a fallback soft-AP, starts the station, or the reverse). Our address
// is that interface's MAC, so it changes too. NowTP task, lock held.
void EspNowTransport::followInterface() {
    wifi_mode_t mode = WIFI_MODE_NULL;
    if (esp_wifi_get_mode(&mode) != ESP_OK || mode == WIFI_MODE_NULL) return;
    radio_.softApActive = mode == WIFI_MODE_AP || mode == WIFI_MODE_APSTA;
    wifi_interface_t want = mode == WIFI_MODE_AP ? WIFI_IF_AP : WIFI_IF_STA;
    if (want == interface_) return;
    wifi_interface_t old = interface_;
    uint8_t bitmap = 0;
    bool lr = esp_wifi_get_protocol(old, &bitmap) == ESP_OK && (bitmap & WIFI_PROTOCOL_LR) != 0;
    interface_ = radio_.interface = want;
    peerDriver_->setInterface(want);

    // Collected first: modifying peers while fetching them is not documented as safe.
    Mac macs[ESP_NOW_MAX_TOTAL_PEER_NUM + 1];
    size_t n = 0;
    macs[n++] = Mac::broadcast();  // which esp_now_fetch_peer() skips
    esp_now_peer_info_t peer;
    for (bool first = true; n < ESP_NOW_MAX_TOTAL_PEER_NUM + 1 && esp_now_fetch_peer(first, &peer) == ESP_OK;
         first = false) {
        macs[n++] = Mac::from(peer.peer_addr);
    }
    for (size_t i = 0; i < n; ++i) {
        if (esp_now_get_peer(macs[i].bytes, &peer) != ESP_OK) continue;
        peer.ifidx = want;
        esp_err_t err = esp_now_mod_peer(&peer);
        if (err != ESP_OK) ESP_LOGW(kTag, "moving a peer to the new interface: %s", esp_err_to_name(err));
        applyPeerRate(macs[i]);
    }
    // Long Range and (before ESP-IDF 5.1) the rate are set per interface. The
    // new interface's protocols aren't restored by end(): only the first one's.
    if (lr && esp_wifi_get_protocol(want, &bitmap) == ESP_OK && !(bitmap & WIFI_PROTOCOL_LR)) {
        esp_wifi_set_protocol(want, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N | WIFI_PROTOCOL_LR);
    }
#if !defined(NOWTP_PER_PEER_RATE)
    PhyRate global = config_.radio.unicastRate != PhyRate::Default ? config_.radio.unicastRate
                                                                   : config_.radio.broadcastRate;
    if (global != PhyRate::Default) esp_wifi_config_espnow_rate(want, rateInfo(global).rate);
#endif
    Mac self = localMac();
    if (security_) security_->setLocalMac(self);
    if (timeSync_) timeSync_->setLocalMac(self);
    ESP_LOGI(kTag, "Wi-Fi mode changed: ESP-NOW now uses the %s interface, as %02x:%02x:%02x:%02x:%02x:%02x",
             want == WIFI_IF_AP ? "AP" : "STA", self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3],
             self.bytes[4], self.bytes[5]);
}

bool EspNowTransport::stationConnected() const {
    if (wifiEvents_) return staConnected_;
    wifi_ap_record_t ap;
    return esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
}

void EspNowTransport::releaseRadio() {
    if (wifiEvents_) {
        esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, wifiEvents_);
        wifiEvents_ = nullptr;
    }
    // Hand the application's Wi-Fi back as it was.
    if (!ownsWifiInit_) {
        if (saved_.txPower) esp_wifi_set_max_tx_power(saved_.txPowerQuarterDbm);
        if (saved_.protocol) esp_wifi_set_protocol(saved_.protocolInterface, saved_.protocolBitmap);
        if (saved_.powerSave) esp_wifi_set_ps(static_cast<wifi_ps_type_t>(saved_.powerSaveMode));
        if (saved_.country) esp_wifi_set_country_code(saved_.countryCode, false);
    }
    saved_ = SavedRadio();
    if (ownsWifiInit_) {
#if defined(NOWTP_ARDUINO_WIFI)
        WiFi.mode(WIFI_OFF);
#else
        esp_wifi_stop();
        esp_wifi_deinit();
#endif
    } else if (ownsWifiStart_) {
        esp_wifi_stop();
    }
#if !defined(NOWTP_ARDUINO_WIFI)
    if (ownsEventLoop_) esp_event_loop_delete_default();
#endif
    ownsWifiInit_ = ownsWifiStart_ = ownsEventLoop_ = false;
}

// Power save, transmit power, Long Range and (before ESP-IDF 5.1) the global
// rate. What it changes on an application's Wi-Fi is restored by releaseRadio().
Status EspNowTransport::applyRadioSettings() {
    const RadioConfig& rc = config_.radio;
    esp_err_t err;

    applyPowerSave(rc.powerSave);

    if (rc.longRange) {
        uint8_t bitmap = 0;
        esp_wifi_get_protocol(interface_, &bitmap);
        if (!(bitmap & WIFI_PROTOCOL_LR)) {
            if (!ownsWifiInit_) {
                saved_.protocol = true;
                saved_.protocolBitmap = bitmap;
                saved_.protocolInterface = interface_;
            }
            // Keep 802.11b/g/n so ordinary nodes are still heard.
            err = esp_wifi_set_protocol(interface_,
                                        WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N | WIFI_PROTOCOL_LR);
            if (err != ESP_OK) {
                ESP_LOGE(kTag, "enabling Long Range: %s", esp_err_to_name(err));
                return Status::LinkError;
            }
        }
    }

    if (rc.txPowerDbm != 0) {
        Status st = applyTxPower(rc.txPowerDbm);
        if (st != Status::Ok) return st;
    }

#if !defined(NOWTP_PER_PEER_RATE)
    PhyRate global = rc.unicastRate != PhyRate::Default ? rc.unicastRate : rc.broadcastRate;
    if (global != PhyRate::Default) {
        err = esp_wifi_config_espnow_rate(interface_, rateInfo(global).rate);
        if (err != ESP_OK) {
            ESP_LOGE(kTag, "esp_wifi_config_espnow_rate: %s", esp_err_to_name(err));
            return Status::LinkError;
        }
    }
#endif
    return Status::Ok;
}

// The application's own setting is saved the first time NowTP changes it;
// Leave and releaseRadio() put it back.
Status EspNowTransport::applyPowerSave(PowerSave mode) {
    wifi_ps_type_t current = WIFI_PS_NONE;
    if (esp_wifi_get_ps(&current) != ESP_OK) return Status::LinkError;
    wifi_ps_type_t want = current;
    switch (mode) {
        case PowerSave::Leave:
            if (saved_.powerSave) want = static_cast<wifi_ps_type_t>(saved_.powerSaveMode);
            saved_.powerSave = false;
            break;
        case PowerSave::None: want = WIFI_PS_NONE; break;
        case PowerSave::MinModem: want = WIFI_PS_MIN_MODEM; break;
        case PowerSave::MaxModem: want = WIFI_PS_MAX_MODEM; break;
        default: return Status::InvalidArgument;
    }
    if (want == current) return Status::Ok;
    if (mode != PowerSave::Leave && !ownsWifiInit_ && !saved_.powerSave) {
        saved_.powerSave = true;
        saved_.powerSaveMode = current;
    }
    esp_err_t err = esp_wifi_set_ps(want);
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "esp_wifi_set_ps: %s", esp_err_to_name(err));
        return Status::LinkError;
    }
    return Status::Ok;
}

Status EspNowTransport::setPowerSave(PowerSave mode) {
    if (!started_) return Status::InvalidState;
    if (static_cast<uint8_t>(mode) > static_cast<uint8_t>(PowerSave::MaxModem)) return Status::InvalidArgument;
    lock();
    Status st = applyPowerSave(mode);
    if (st == Status::Ok) config_.radio.powerSave = mode;
    unlock(false);
    return st;
}

PowerSave EspNowTransport::powerSave() const {
    return config_.radio.powerSave;
}

PhyRate EspNowTransport::peerRate(const Mac& mac) const {
    if (mac.isBroadcast()) return config_.radio.broadcastRate;
    for (const auto& p : peerRates_) {
        if (p.first == mac) return p.second;
    }
    return config_.radio.unicastRate;
}

Status EspNowTransport::applyPeerRate(const Mac& mac) {
#if defined(NOWTP_PER_PEER_RATE)
    PhyRate rate = peerRate(mac);
    // Leave untouched peers on the driver default; once anything was changed,
    // always set the rate so a switch back to Default takes effect.
    if (rate == PhyRate::Default && !ratesChanged_) return Status::Ok;
    ratesChanged_ = true;
    const RateInfo& info = rateInfo(rate);
    static const wifi_phy_mode_t kModes[] = {WIFI_PHY_MODE_11B, WIFI_PHY_MODE_11G, WIFI_PHY_MODE_HT20,
                                             WIFI_PHY_MODE_LR};
    esp_now_rate_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.phymode = kModes[info.mode];
    cfg.rate = info.rate;
    esp_err_t err = esp_now_set_peer_rate_config(mac.bytes, &cfg);
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "setting rate %s: %s", info.name, esp_err_to_name(err));
        return Status::LinkError;
    }
#else
    (void)mac;
#endif
    return Status::Ok;
}

RadioInfo EspNowTransport::radioInfo() const {
    RadioInfo info = radio_;
    if (!started_) return info;
    int8_t power = 0;
    if (esp_wifi_get_max_tx_power(&power) == ESP_OK) info.txPowerDbm = power / 4.0f;
    uint8_t bitmap = 0;
    if (esp_wifi_get_protocol(interface_, &bitmap) == ESP_OK) info.longRange = (bitmap & WIFI_PROTOCOL_LR) != 0;
    info.txPowerLimitDbm = limitQuarterDbm_ / 4.0f;
    info.learnedTxCeilingDbm = s_learnedCeilingDbm;
    uint8_t ch = 0;
    wifi_second_chan_t second;
    if (esp_wifi_get_channel(&ch, &second) == ESP_OK) info.channel = ch;
    return info;
}

Status EspNowTransport::setTxPower(float dbm) {
    if (!started_) return Status::InvalidState;
    return applyTxPower(dbm);
}

Status EspNowTransport::applyTxPower(float dbm) {
    int8_t q = quarterDbm(dbm);
    if (q == 0) return Status::InvalidArgument;
    if (!ownsWifiInit_ && !saved_.txPower) {
        int8_t previous = 0;
        if (esp_wifi_get_max_tx_power(&previous) == ESP_OK) {
            saved_.txPower = true;
            saved_.txPowerQuarterDbm = previous;
        }
    }
    esp_err_t err = esp_wifi_set_max_tx_power(q);
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "esp_wifi_set_max_tx_power: %s", esp_err_to_name(err));
        return Status::LinkError;
    }
    return Status::Ok;
}

Status EspNowTransport::setBroadcastRate(PhyRate rate) {
    if (!started_) return Status::InvalidState;
    if (!rateUsable(rate)) return Status::InvalidArgument;
#if defined(NOWTP_PER_PEER_RATE)
    lock();
    config_.radio.broadcastRate = rate;
    Status st = applyPeerRate(Mac::broadcast());
    unlock();
    return st;
#else
    // One ESP-NOW rate for everything before ESP-IDF 5.1.
    lock();
    config_.radio.broadcastRate = config_.radio.unicastRate = rate;
    esp_err_t err = esp_wifi_config_espnow_rate(interface_, rateInfo(rate).rate);
    unlock();
    return err == ESP_OK ? Status::Ok : Status::LinkError;
#endif
}

Status EspNowTransport::setUnicastRate(PhyRate rate) {
    if (!started_) return Status::InvalidState;
    if (!rateUsable(rate)) return Status::InvalidArgument;
#if defined(NOWTP_PER_PEER_RATE)
    lock();
    config_.radio.unicastRate = rate;
    // Re-apply to every registered peer that has no rate of its own.
    Status st = Status::Ok;
    esp_now_peer_info_t peer;
    for (bool first = true; esp_now_fetch_peer(first, &peer) == ESP_OK; first = false) {
        Mac mac = Mac::from(peer.peer_addr);
        if (!mac.isBroadcast() && applyPeerRate(mac) != Status::Ok) st = Status::LinkError;
    }
    unlock();
    return st;
#else
    return setBroadcastRate(rate);  // one rate for everything before ESP-IDF 5.1
#endif
}

// ---------------------------------------------------------------------------
// One-way link detection
//
// Unicast frames that keep failing at the MAC level to a peer whose own frames
// arrive fine point at this node's transmitter: commonly a board whose supply
// cannot sustain the driver's default power, or a rate the peer cannot decode.

namespace {
constexpr uint16_t kOneWayFailures = 8;    // consecutive failed frames
constexpr uint32_t kOneWayHeardMs = 3000;  // peer heard this recently
constexpr size_t kMaxLinkEntries = 20;
}  // namespace

EspNowTransport::LinkHealth* EspNowTransport::linkHealth(const Mac& mac, bool create) {
    for (auto& l : linkHealth_) {
        if (l.mac == mac) return &l;
    }
    if (!create) return nullptr;
    if (linkHealth_.size() >= kMaxLinkEntries) {
        size_t oldest = 0;
        for (size_t i = 1; i < linkHealth_.size(); ++i) {
            if (static_cast<int32_t>(linkHealth_[i].lastHeardMs - linkHealth_[oldest].lastHeardMs) < 0) oldest = i;
        }
        linkHealth_.erase(linkHealth_.begin() + static_cast<std::ptrdiff_t>(oldest));
    }
    LinkHealth fresh;
    fresh.mac = mac;
    linkHealth_.push_back(fresh);
    return &linkHealth_.back();
}

void EspNowTransport::notePeerHeard(const Mac& mac) {
    linkHealth(mac, true)->lastHeardMs = nowMs();
}

void EspNowTransport::notePeerSendResult(const Mac& mac, bool delivered) {
    if (mac.isBroadcast()) return;
    LinkHealth* l = linkHealth(mac, false);
    if (!l) return;  // never heard from it: an absent peer, not a one-way link
    if (delivered) {
        l->failures = 0;
        return;
    }
    if (++l->failures < kOneWayFailures) return;
    if (static_cast<int32_t>(nowMs() - l->lastHeardMs) > static_cast<int32_t>(kOneWayHeardMs)) return;
    if (!l->warned) {
        l->warned = true;
        stats_.oneWayLinks++;
        int8_t power = 0;
        esp_wifi_get_max_tx_power(&power);
        ESP_LOGW(kTag,
                 "frames to %02x:%02x:%02x:%02x:%02x:%02x keep failing although its frames arrive: the link is one-way. "
                 "This board may not sustain %.1f dBm (try radio.txPowerDbm = 15) or the peer may not decode rate %s.",
                 mac.bytes[0], mac.bytes[1], mac.bytes[2], mac.bytes[3], mac.bytes[4], mac.bytes[5], power / 4.0,
                 toString(peerRate(mac)));
    }
    if (config_.radio.autoPowerFallback) startPowerFallback(mac);
}

// ---------------------------------------------------------------------------
// Discovery

void EspNowTransport::handlePeerEvent(PeerEvent event, const PeerInfo& peer) {
    // Runs in the NowTP task with the lock held.
    if (follower_) follower_->onPeerEvent(event, peer, nowMs());
    if (timeSync_) timeSync_->onPeerEvent(event, peer, nowMs());
    // Check new peers hear us; failures feed the one-way detection and fallback.
    if (event == PeerEvent::Found && config_.radio.autoPowerFallback && linkChecks_.size() < 8) {
        LinkCheck c = {peer.mac, 3, false, nowMs()};
        linkChecks_.push_back(c);
    }
    // Its slot in ESP-NOW's peer table, if we added it, goes back to the pool.
    if (event == PeerEvent::Lost) peerTable_->release(peer.mac);
    if (config_.negotiateFrameSize && !hasExplicitFrameSize(peer.mac)) {
        uint16_t size = 0;  // default
        if (event != PeerEvent::Lost) {
            uint16_t common = std::min(peer.maxFrameSize, maxSupportedFrameSize());
            if (common > config_.defaultMaxFrameSize) size = common;
        }
        link_->setFrameSize(peer.mac, size);
    }
    if (peerHandler_) {
        // A copy: another task may replace the handler while it runs unlocked.
        Callback<void(PeerEvent, const PeerInfo&)> handler = peerHandler_;
        GateScope open(gate_.get());
        handler(event, peer);
    }
}

void EspNowTransport::channelChanged(uint8_t ch) {
    if (!channelHandler_) return;
    Callback<void(uint8_t)> handler = channelHandler_;
    GateScope open(gate_.get());
    handler(ch);
}

bool EspNowTransport::hasExplicitFrameSize(const Mac& mac) const {
    return std::find(explicitFrameSizes_.begin(), explicitFrameSizes_.end(), mac) != explicitFrameSizes_.end();
}

void EspNowTransport::onPeerEvent(PeerHandler handler) {
    if (started_) lock();
    peerHandler_.set(std::move(handler));
    if (started_) unlock();
}

Status EspNowTransport::discover() {
    if (!started_ || !discovery_) return Status::InvalidState;
    lock();
    discovery_->discover(nowMs());
    unlock();
    return Status::Ok;
}

std::vector<PeerInfo> EspNowTransport::peers() const {
    if (!started_ || !discovery_) return std::vector<PeerInfo>();
    lock();
    std::vector<PeerInfo> copy = discovery_->peers();
    unlock(false);
    return copy;
}

Engine::MemoryUse EspNowTransport::memory() const {
    if (!started_) return Engine::MemoryUse();
    lock();
    Engine::MemoryUse m = engine_->memory();
    unlock(false);
    return m;
}

size_t EspNowTransport::peerMaxMessageSize(const Mac& peer) const {
    if (!started_) return 0;
    lock();
    size_t limit = engine_->peerMessageLimit(peer);
    unlock(false);
    return limit;
}

Status EspNowTransport::setDiscoveryMetadata(const void* data, size_t len) {
    if (len > Discovery::kMaxMetadata || (data == nullptr && len > 0)) return Status::InvalidArgument;
    if (!started_ || !discovery_) return Status::InvalidState;  // before begin(), use EspNowConfig::discovery
    lock();
    discovery_->setMetadata(static_cast<const uint8_t*>(data), len, nowMs());
    unlock();
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Radio controls

float EspNowTransport::txPower() const {
    int8_t q = 0;
    return esp_wifi_get_max_tx_power(&q) == ESP_OK ? q / 4.0f : 0.0f;
}

float EspNowTransport::txPowerLimit() const {
    return limitQuarterDbm_ / 4.0f;
}

PhyRate EspNowTransport::broadcastRate() const {
    return config_.radio.broadcastRate;
}

Status EspNowTransport::setPeerRate(const Mac& mac, PhyRate rate) {
    if (!started_) return Status::InvalidState;
    if (mac.isBroadcast()) return setBroadcastRate(rate);
    if (!rateUsable(rate)) return Status::InvalidArgument;
#if defined(NOWTP_PER_PEER_RATE)
    lock();
    for (size_t i = 0; i < peerRates_.size(); ++i) {
        if (peerRates_[i].first == mac) peerRates_.erase(peerRates_.begin() + static_cast<std::ptrdiff_t>(i));
    }
    if (rate != PhyRate::Default) peerRates_.push_back(std::make_pair(mac, rate));
    Status st = Status::Ok;
    if (!esp_now_is_peer_exist(mac.bytes)) {
        bool added = false;
        st = config_.autoAddPeers ? peerTable_->use(mac, nowMs(), added) : Status::LinkError;
    }
    if (st == Status::Ok) st = applyPeerRate(mac);
    unlock();
    return st;
#else
    return rate == PhyRate::Default ? Status::Ok : Status::InvalidArgument;
#endif
}

bool EspNowTransport::rateUsable(PhyRate rate) const {
    if (!validRate(rate)) return false;
    if (isLongRange(rate) && !longRange()) return false;
    return true;
}

uint8_t EspNowTransport::channel() const {
    uint8_t ch = 0;
    wifi_second_chan_t second;
    esp_wifi_get_channel(&ch, &second);
    return ch;
}

bool EspNowTransport::channelFixed() const {
    wifi_mode_t mode = WIFI_MODE_NULL;
    if (esp_wifi_get_mode(&mode) != ESP_OK) return false;
    if (mode == WIFI_MODE_AP || mode == WIFI_MODE_APSTA) return true;
    return mode == WIFI_MODE_STA && stationConnected();
}

Status EspNowTransport::setChannel(uint8_t ch) {
    if (!started_) return Status::InvalidState;
    if (channelFixed()) return Status::InvalidState;
    esp_err_t err = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) return err == ESP_ERR_INVALID_ARG ? Status::InvalidArgument : Status::LinkError;
    lock();
    radio_.channel = ch;
    pendingChannel_ = 0;
    unlock();
    return Status::Ok;
}

bool EspNowTransport::longRange() const {
    uint8_t bitmap = 0;
    return esp_wifi_get_protocol(interface_, &bitmap) == ESP_OK && (bitmap & WIFI_PROTOCOL_LR) != 0;
}

Status EspNowTransport::setLongRange(bool enabled) {
    if (!started_) return Status::InvalidState;
    uint8_t bitmap = 0;
    esp_wifi_get_protocol(interface_, &bitmap);
    if (!ownsWifiInit_ && !saved_.protocol) {
        saved_.protocol = true;
        saved_.protocolBitmap = bitmap;
        saved_.protocolInterface = interface_;
    }
    uint8_t want = WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N | (enabled ? WIFI_PROTOCOL_LR : 0);
    if (bitmap == want) return Status::Ok;
    return esp_wifi_set_protocol(interface_, want) == ESP_OK ? Status::Ok : Status::LinkError;
}

// ---------------------------------------------------------------------------
// Automatic transmit power fallback (runs in the NowTP task, lock held)

namespace {
const float kFallbackLadder[] = {17, 15, 13, 11, 8, 5};
const uint8_t kPing[1] = {0};  // type 0: ignored by the receiver's diagnostics
}  // namespace

void EspNowTransport::startPowerFallback(const Mac& peer) {
    if (fallback_.active) return;
    if (std::find(fallback_.tried.begin(), fallback_.tried.end(), peer) != fallback_.tried.end()) return;
    float current = txPower();
    std::vector<float> ladder;
    for (float p : kFallbackLadder) {
        if (p < current - 0.1f) ladder.push_back(p);
    }
    fallback_.tried.push_back(peer);
    if (ladder.empty()) return;
    fallback_.active = true;
    fallback_.peer = peer;
    fallback_.original = current;
    fallback_.ladder = ladder;
    fallback_.index = 0;
    fallback_.failures = 0;
    fallback_.pingInFlight = false;
    fallback_.confirming = false;
    fallback_.nextPingAt = nowMs();
    ESP_LOGI(kTag, "frames to %02x:%02x:%02x:%02x:%02x:%02x are not acknowledged: trying lower transmit power",
             peer.bytes[0], peer.bytes[1], peer.bytes[2], peer.bytes[3], peer.bytes[4], peer.bytes[5]);
    applyTxPower(ladder[0]);
}

void EspNowTransport::sendFallbackPing() {
    fallback_.pingInFlight = true;
    Status st = engine_->send(fallback_.peer, kDiagnosticsPort, kPing, sizeof(kPing), SendOptions(),
                              [this](Status s) { onFallbackPing(s); }, nowMs());
    if (st != Status::Ok) {
        fallback_.pingInFlight = false;
        fallback_.nextPingAt = nowMs() + 50;
    }
}

void EspNowTransport::onFallbackPing(Status status) {
    if (!fallback_.active) return;
    fallback_.pingInFlight = false;
    const Mac& p = fallback_.peer;
    if (fallback_.confirming) {
        // A lower power worked; does the original power work again too? Then the
        // peer was briefly away (rebooting, other channel), not our transmitter.
        fallback_.confirming = false;
        if (status == Status::Ok) {
            fallback_.active = false;
            if (LinkHealth* l = linkHealth(p, false)) l->failures = 0;
            ESP_LOGI(kTag, "frames to %02x:%02x:%02x:%02x:%02x:%02x get through at %.1f dBm again: keeping it",
                     p.bytes[0], p.bytes[1], p.bytes[2], p.bytes[3], p.bytes[4], p.bytes[5], fallback_.original);
            return;
        }
        applyTxPower(fallback_.ladder[fallback_.index]);
        float now = txPower();
        s_learnedCeilingDbm = now;
        stats_.powerFallbacks++;
        fallback_.active = false;
        if (LinkHealth* l = linkHealth(p, false)) l->failures = 0;
        ESP_LOGW(kTag,
                 "transmit power lowered from %.1f to %.1f dBm: %02x:%02x:%02x:%02x:%02x:%02x did not acknowledge "
                 "frames at higher power (this board's supply likely sags). Set radio.txPowerDbm to skip the search.",
                 fallback_.original, now, p.bytes[0], p.bytes[1], p.bytes[2], p.bytes[3], p.bytes[4], p.bytes[5]);
        return;
    }
    if (status == Status::Ok) {
        fallback_.confirming = true;
        applyTxPower(fallback_.original);
        fallback_.nextPingAt = nowMs();
        return;
    }
    if (++fallback_.failures < 2) {
        fallback_.nextPingAt = nowMs() + 50;
        return;
    }
    fallback_.failures = 0;
    if (++fallback_.index < fallback_.ladder.size()) {
        applyTxPower(fallback_.ladder[fallback_.index]);
        fallback_.nextPingAt = nowMs();
        return;
    }
    applyTxPower(fallback_.original);
    fallback_.active = false;
    ESP_LOGW(kTag, "lowering transmit power did not help with %02x:%02x:%02x:%02x:%02x:%02x: out of range, or its "
                   "receiver is the problem",
             p.bytes[0], p.bytes[1], p.bytes[2], p.bytes[3], p.bytes[4], p.bytes[5]);
}

void EspNowTransport::tickLinkChecks(uint32_t now) {
    if (fallback_.active && !fallback_.pingInFlight && static_cast<int32_t>(now - fallback_.nextPingAt) >= 0) {
        sendFallbackPing();
    }
    for (size_t i = 0; i < linkChecks_.size(); ++i) {
        LinkCheck& c = linkChecks_[i];
        if (c.inFlight || static_cast<int32_t>(now - c.nextAt) < 0) continue;
        if (c.remaining == 0) {
            linkChecks_.erase(linkChecks_.begin() + static_cast<std::ptrdiff_t>(i));
            --i;
            continue;
        }
        c.inFlight = true;
        c.remaining--;
        Mac mac = c.peer;
        Status st = engine_->send(mac, kDiagnosticsPort, kPing, sizeof(kPing), SendOptions(),
                                  [this, mac](Status s) {
                                      for (size_t j = 0; j < linkChecks_.size(); ++j) {
                                          if (linkChecks_[j].peer != mac) continue;
                                          linkChecks_[j].inFlight = false;
                                          linkChecks_[j].nextAt = nowMs() + 200;
                                          if (s == Status::Ok) linkChecks_[j].remaining = 0;  // healthy
                                      }
                                  },
                                  now);
        if (st != Status::Ok) c.inFlight = false;
    }
}

// ---------------------------------------------------------------------------
// Channels (NowTP task, lock held, unless noted)

namespace {
// A station's own scan visits other channels briefly; only a channel that
// stays is a move.
constexpr uint32_t kChannelSettleMs = 600;
}  // namespace

void EspNowTransport::pollChannel(uint32_t now) {
    if (static_cast<int32_t>(now - lastChannelPoll_) < static_cast<int32_t>(kChannelPollMs)) return;
    lastChannelPoll_ = now;
    followInterface();  // also without Wi-Fi events
    bool fixed = channelFixed();
    if (discovery_) discovery_->setChannelInfo(radio_.channel, config_.channel.anchor || fixed, now);
    if (diagnostics_ && diagnostics_->busy()) {
        pendingChannel_ = 0;  // deep discovery is visiting other channels
        return;
    }
    uint8_t ch = channel();
    if (ch == 0 || ch == radio_.channel) {
        pendingChannel_ = 0;
        return;
    }
    if (ch != pendingChannel_) {
        pendingChannel_ = ch;
        pendingChannelSince_ = now;
        return;
    }
    if (static_cast<int32_t>(now - pendingChannelSince_) < static_cast<int32_t>(kChannelSettleMs)) return;
    adoptChannel(ch, fixed, now);
}

void EspNowTransport::adoptChannel(uint8_t ch, bool fixed, uint32_t now) {
    pendingChannel_ = 0;
    ESP_LOGI(kTag, "channel changed from %u to %u%s", radio_.channel, ch,
             fixed ? " (set by the access point)" : "");
    radio_.channel = ch;
    wifi_mode_t mode = WIFI_MODE_NULL;
    esp_wifi_get_mode(&mode);
    radio_.softApActive = mode == WIFI_MODE_AP || mode == WIFI_MODE_APSTA;
    radio_.stationConnected = (mode == WIFI_MODE_STA || mode == WIFI_MODE_APSTA) && stationConnected();
    if (discovery_) discovery_->setChannelInfo(ch, config_.channel.anchor || fixed, now);
    if (follower_) follower_->onChannelChanged(ch, now);
    channelChanged(ch);
}

// The station connected, disconnected or followed its access point to another
// channel. A roam can't be announced where it would help, on the channel left
// behind: by the time it is known, the station is gone (announceChannelChange()
// is for moves the application plans). So peers learn what they can at once,
// instead of at the next channel check, by when a roaming station may have
// left. On a disconnect, still on the old channel, we are no longer an anchor:
// followers start searching after ChannelConfig::searchAfterMs, rather than
// once they lose us. On the new channel, we announce ourselves without
// waiting for the channel to settle, so that searching followers find us.
void EspNowTransport::stationChanged(uint32_t now) {
    uint8_t home = homeChannel_.exchange(0);
    bool fixed = channelFixed();
    radio_.stationConnected = stationConnected();
    if (diagnostics_ && diagnostics_->busy()) return;  // deep discovery is visiting other channels
    if (home != 0 && home != radio_.channel && channel() == home) {
        adoptChannel(home, fixed, now);
        return;
    }
    if (discovery_) discovery_->setChannelInfo(radio_.channel, config_.channel.anchor || fixed, now);
}

Status EspNowTransport::appTaskReady() const {
    if (!started_) return Status::InvalidState;
    if (task_ && xTaskGetCurrentTaskHandle() == task_) return Status::InvalidState;  // would deadlock
    return Status::Ok;
}

// Application task: queue the notice, then give it time to leave on this channel.
Status EspNowTransport::sendMoveNotice(uint8_t ch) {
    Status st = appTaskReady();
    if (st != Status::Ok) return st;
    if (ch < 1 || ch > 14) return Status::InvalidArgument;
    if (!discovery_) return Status::InvalidState;
    lock();
    bool queued = discovery_->announceMove(ch, nowMs());
    unlock();
    if (!queued) return Status::QueueFull;
    for (int i = 0; i < 150 && engine_->pendingMessages() > 0; ++i) {
        if (task_) {
            vTaskDelay(pdMS_TO_TICKS(2));
        } else {
            processEvents(pdMS_TO_TICKS(2));
        }
    }
    return Status::Ok;
}

Status EspNowTransport::moveToChannel(uint8_t ch) {
    Status st = appTaskReady();
    if (st != Status::Ok) return st;
    if (channelFixed()) return Status::InvalidState;
    if (ch == channel()) return Status::Ok;
    if (discovery_) {
        st = sendMoveNotice(ch);
        if (st != Status::Ok) return st;
    }
    st = setChannel(ch);
    if (st != Status::Ok) return st;
    lock();
    if (discovery_) discovery_->setChannelInfo(ch, config_.channel.anchor, nowMs());
    if (follower_) follower_->onChannelChanged(ch, nowMs());  // and ask who is there
    unlock();
    return Status::Ok;
}

Status EspNowTransport::announceChannelChange(uint8_t ch) {
    return sendMoveNotice(ch);
}

Status EspNowTransport::searchChannels() {
    if (!started_ || !follower_) return Status::InvalidState;
    lock();
    Status st = follower_->search(nowMs());
    unlock();
    return st;
}

void EspNowTransport::onChannelChange(std::function<void(uint8_t channel)> handler) {
    if (started_) lock();
    channelHandler_.set(std::move(handler));
    if (started_) unlock();
}

// ---------------------------------------------------------------------------
// Security

void EspNowTransport::storeKey(const std::vector<uint8_t>& key) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(kNvsNamespace, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGW(kTag, "cannot store the installation key: nvs_open: %s", esp_err_to_name(err));
        return;
    }
    err = key.empty() ? nvs_erase_key(h, kNvsKey) : nvs_set_blob(h, kNvsKey, key.data(), key.size());
    if (err == ESP_OK || err == ESP_ERR_NVS_NOT_FOUND) err = nvs_commit(h);
    nvs_close(h);
    if (err != ESP_OK) ESP_LOGW(kTag, "storing the installation key: %s", esp_err_to_name(err));
}

Status EspNowTransport::setSecurityKey(const void* key, size_t len) {
    if (!started_) return Status::InvalidState;
    if (len < Security::kMinKey || len > Security::kMaxKey || !key) return Status::InvalidArgument;
    Status st = security_->setKey(static_cast<const uint8_t*>(key), len);
    if (st == Status::Ok && config_.persistSecurityKey) {
        const uint8_t* k = static_cast<const uint8_t*>(key);
        storeKey(std::vector<uint8_t>(k, k + len));
    }
    return st;
}

Status EspNowTransport::forgetSecurityKey() {
    if (!started_) return Status::InvalidState;
    security_->setKey(nullptr, 0);
    if (config_.persistSecurityKey) storeKey(std::vector<uint8_t>());
    return Status::Ok;
}

bool EspNowTransport::secured() const {
    if (!started_) return false;
    lock();
    bool on = security_->enabled();
    unlock(false);
    return on;
}

Status EspNowTransport::acceptPairing(uint32_t timeoutMs, Mac* joined) {
    Status st = appTaskReady();
    return st == Status::Ok ? security_->acceptPairing(timeoutMs, joined) : st;
}

Status EspNowTransport::pair(uint32_t timeoutMs, Mac* member) {
    Status st = appTaskReady();
    return st == Status::Ok ? security_->pair(timeoutMs, member) : st;
}

// ---------------------------------------------------------------------------
// Network time

uint64_t EspNowTransport::networkTimeUs() const {
    uint64_t local = static_cast<uint64_t>(esp_timer_get_time());
    if (!started_ || !timeSync_) return local;
    lock();
    uint64_t t = timeSync_->toNetwork(local);
    unlock(false);
    return t;
}

int64_t EspNowTransport::localTimeUs(uint64_t networkUs) const {
    if (!started_ || !timeSync_) return static_cast<int64_t>(networkUs);
    lock();
    uint64_t t = timeSync_->toLocal(networkUs);
    unlock(false);
    return static_cast<int64_t>(t);
}

TimeSyncStatus EspNowTransport::timeSyncStatus() const {
    if (!started_ || !timeSync_) {
        TimeSyncStatus s;
        s.role = !config_.enableTimeSync     ? TimeRole::Off
                 : config_.timeSync.reference ? TimeRole::Reference
                                              : config_.timeSync.role;
        return s;
    }
    lock();
    TimeSyncStatus s = timeSync_->status();
    unlock(false);
    return s;
}

Status EspNowTransport::setTimeRole(TimeRole role) {
    if (!config_.enableTimeSync) return Status::InvalidState;
    if (!started_) {
        config_.timeSync.role = role;
        config_.timeSync.reference = false;
        return Status::Ok;
    }
    lock();
    config_.timeSync.role = role;
    config_.timeSync.reference = false;
    timeSync_->setRole(role, nowMs());
    unlock();
    return Status::Ok;
}

Status EspNowTransport::setTimeReference(const Mac& peer) {
    if (!started_ || !timeSync_) return Status::InvalidState;
    lock();
    timeSync_->setReference(peer, nowMs());
    unlock();
    return Status::Ok;
}

Status EspNowTransport::clearTimeReference() {
    if (!started_ || !timeSync_) return Status::InvalidState;
    lock();
    timeSync_->clearReference(nowMs());
    unlock();
    return Status::Ok;
}

Status EspNowTransport::setTimeSyncInterval(uint32_t ms) {
    if (!config_.enableTimeSync) return Status::InvalidState;
    if (!started_) {
        config_.timeSync.intervalMs = ms;
        return Status::Ok;
    }
    lock();
    config_.timeSync.intervalMs = ms;
    timeSync_->setInterval(ms);
    unlock();
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Streams

Status EspNowTransport::sendStream(const Mac& dst, uint32_t size, StreamReader read, StreamDone done,
                                   const StreamOptions& options, uint32_t* id) {
    if (!started_ || !streams_) return Status::InvalidState;
    if (!config_.autoAddPeers && !esp_now_is_peer_exist(dst.bytes)) return Status::LinkError;
    lock();
    Status st = streams_->send(dst, size, std::move(read), std::move(done), options, nowMs(), id);
    unlock();
    return st;
}

Status EspNowTransport::cancelStream(uint32_t id) {
    if (!started_ || !streams_) return Status::InvalidState;
    lock();
    Status st = streams_->cancel(id, nowMs());
    unlock();
    return st;
}

void EspNowTransport::onStream(StreamAcceptor acceptor) {
    if (started_) lock();
    streamAcceptor_ = acceptor;
    if (streams_) streams_->onIncoming(std::move(acceptor));
    if (started_) unlock();
}

// ---------------------------------------------------------------------------
// Diagnostics API

Status EspNowTransport::diagnosticsReady() const {
    if (!started_ || !diagnostics_) return Status::InvalidState;
    if (task_ && xTaskGetCurrentTaskHandle() == task_) return Status::InvalidState;  // would deadlock
    return Status::Ok;
}

Status EspNowTransport::ping(const Mac& peer, float* requestPowerDbm, float* replyPowerDbm) {
    Status st = diagnosticsReady();
    return st == Status::Ok ? diagnostics_->ping(peer, requestPowerDbm, replyPowerDbm) : st;
}

Status EspNowTransport::measureLink(const Mac& peer, const std::vector<ProbeStep>& steps, uint8_t framesPerStep,
                                   std::vector<ProbeResult>* forward, std::vector<ProbeResult>* reverse) {
    Status st = diagnosticsReady();
    return st == Status::Ok ? diagnostics_->measure(peer, steps, framesPerStep, forward, reverse) : st;
}

Status EspNowTransport::diagnose(const Mac& peer, LinkDiagnosis& out) {
    Status st = diagnosticsReady();
    return st == Status::Ok ? diagnostics_->diagnose(peer, out) : st;
}

Status EspNowTransport::optimizeLink(const Mac& peer, LinkProfile& out, const OptimizeOptions& options,
                                     const LinkDiagnosis* known) {
    Status st = diagnosticsReady();
    if (st != Status::Ok) return st;
    st = diagnostics_->optimize(peer, options, out, known);
    if (st == Status::Ok && out.applied && out.txPowerDbm < txPowerLimit() - 0.01f &&
        (s_learnedCeilingDbm == 0 || out.txPowerDbm < s_learnedCeilingDbm)) {
        s_learnedCeilingDbm = out.txPowerDbm;
    }
    return st;
}

Status EspNowTransport::optimizeAll(std::vector<LinkProfile>& out, const OptimizeOptions& options) {
    out.clear();
    Status st = diagnosticsReady();
    if (st != Status::Ok) return st;
    std::vector<PeerInfo> list = peers();
    if (list.empty()) return Status::InvalidState;  // needs discovery and at least one peer
    float power = 0;
    for (const PeerInfo& p : list) {
        LinkProfile profile;
        if (optimizeLink(p.mac, profile, options) == Status::Ok) {
            if (profile.applied) power = power == 0 ? profile.txPowerDbm : std::min(power, profile.txPowerDbm);
            out.push_back(profile);
        }
    }
    // Power is shared by all links: settle on what works for every peer.
    if (options.apply && power > 0) setTxPower(power);
    return out.empty() ? Status::Timeout : Status::Ok;
}

Status EspNowTransport::deepDiscover(DeepDiscoveryReport& out, const DeepDiscoveryOptions& options) {
    Status st = diagnosticsReady();
    return st == Status::Ok ? diagnostics_->deepDiscover(options, out) : st;
}

}  // namespace nowtp

#endif  // ESP_PLATFORM
