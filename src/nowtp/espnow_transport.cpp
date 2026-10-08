// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#if defined(ESP_PLATFORM)

#include "espnow_transport.h"

#include <string.h>

#include <algorithm>

#include "esp_event.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_now.h"
#include "esp_timer.h"
#include "esp_wifi.h"
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

namespace nowtp {

namespace {

const char* const kTag = "nowtp";

enum EventKind : uint8_t { kEventReceived = 1, kEventSent = 2 };

struct EventHeader {
    uint8_t kind;
    uint8_t delivered;  // kEventSent only
    int8_t rssi;        // kEventReceived only; 0 if unknown
    uint8_t mac[6];     // kEventReceived only
};

// ESP-NOW callbacks carry no user pointer, so they reach the active
// instance's event buffer through these.
RingbufHandle_t volatile s_events = nullptr;
volatile uint32_t s_droppedEvents = 0;
bool s_active = false;

inline uint32_t nowMs() {
    return static_cast<uint32_t>(esp_timer_get_time() / 1000);
}

// Unencrypted peer on the current channel.
esp_err_t addPlainPeer(const Mac& mac, wifi_interface_t interface) {
    esp_now_peer_info_t peer;
    memset(&peer, 0, sizeof(peer));
    memcpy(peer.peer_addr, mac.bytes, sizeof(peer.peer_addr));
    peer.ifidx = interface;
    return esp_now_add_peer(&peer);
}

// Runs in the Wi-Fi driver task: copy the event out and return quickly.
void pushEvent(uint8_t kind, const uint8_t* mac, bool delivered, int8_t rssi, const uint8_t* data, size_t len) {
    RingbufHandle_t rb = s_events;
    if (!rb) return;
    void* slot = nullptr;
    if (xRingbufferSendAcquire(rb, &slot, sizeof(EventHeader) + len, 0) != pdTRUE || !slot) {
        s_droppedEvents = s_droppedEvents + 1;
        return;
    }
    EventHeader* h = static_cast<EventHeader*>(slot);
    h->kind = kind;
    h->delivered = delivered ? 1 : 0;
    h->rssi = rssi;
    if (mac) {
        memcpy(h->mac, mac, sizeof(h->mac));
    } else {
        memset(h->mac, 0, sizeof(h->mac));
    }
    if (len) memcpy(static_cast<uint8_t*>(slot) + sizeof(EventHeader), data, len);
    xRingbufferSendComplete(rb, slot);
}

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 1, 0)
void onRecv(const esp_now_recv_info_t* info, const uint8_t* data, int len) {
    if (!info || len <= 0) return;
    int8_t rssi = info->rx_ctrl ? static_cast<int8_t>(info->rx_ctrl->rssi) : 0;
    pushEvent(kEventReceived, info->src_addr, false, rssi, data, static_cast<size_t>(len));
}
#else
void onRecv(const uint8_t* mac, const uint8_t* data, int len) {
    if (!mac || len <= 0) return;
    pushEvent(kEventReceived, mac, false, 0, data, static_cast<size_t>(len));
}
#endif

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 5, 0)
void onSent(const esp_now_send_info_t*, esp_now_send_status_t status) {
#else
void onSent(const uint8_t*, esp_now_send_status_t status) {
#endif
    pushEvent(kEventSent, nullptr, status == ESP_NOW_SEND_SUCCESS, 0, nullptr, 0);
}

}  // namespace

// Link implementation over esp_now_send(), with per-peer frame sizes.
class EspNowTransport::RadioLink : public Link {
public:
    RadioLink(uint16_t defaultSize, bool autoAddPeers, wifi_interface_t interface)
        : defaultSize_(defaultSize), autoAddPeers_(autoAddPeers), interface_(interface) {}

    Status sendFrame(const Mac& dst, const uint8_t* data, size_t len) override {
        esp_err_t err = esp_now_send(dst.bytes, data, len);
        if (err == ESP_ERR_ESPNOW_NOT_FOUND && autoAddPeers_ && addPlainPeer(dst, interface_) == ESP_OK) {
            err = esp_now_send(dst.bytes, data, len);
        }
        if (err == ESP_OK) return Status::Ok;
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
    wifi_interface_t interface_;
    std::vector<std::pair<Mac, uint16_t>> sizes_;
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

uint32_t EspNowTransport::droppedEvents() const {
    return s_droppedEvents;
}

Status EspNowTransport::begin(const EspNowConfig& config) {
    if (started_ || s_active) return Status::InvalidState;

    config_ = config;
    Status radio = prepareRadio();
    if (radio != Status::Ok) return radio;

    uint16_t maxSize = maxSupportedFrameSize();
    if (config_.defaultMaxFrameSize > maxSize) config_.defaultMaxFrameSize = maxSize;
    if (config_.defaultMaxFrameSize < 32) config_.defaultMaxFrameSize = 32;
    if (config_.tickIntervalMs == 0) config_.tickIntervalMs = 1;

    events_ = xRingbufferCreate(config_.eventBufferSize, RINGBUF_TYPE_NOSPLIT);
    mutex_ = xSemaphoreCreateRecursiveMutex();
    taskExited_ = xSemaphoreCreateBinary();
    link_.reset(new RadioLink(config_.defaultMaxFrameSize, config_.autoAddPeers, interface_));
    engine_.reset(new Engine(*link_, config_.protocol, static_cast<uint16_t>(esp_random())));
    if (!events_ || !mutex_ || !taskExited_) {
        cleanup();
        return Status::NoMemory;
    }
    for (auto& l : listeners_) engine_->listen(l.first, l.second);
    if (config_.enableDiscovery) {
        discovery_.reset(new Discovery(*engine_, config_.discovery, maxSupportedFrameSize(),
                                       [] { return static_cast<uint32_t>(esp_random()); }));
        discovery_->onPeerEvent([this](PeerEvent e, const PeerInfo& p) { handlePeerEvent(e, p); });
    }

    esp_err_t err = esp_now_init();
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "esp_now_init: %s", esp_err_to_name(err));
        cleanup();
        return Status::LinkError;
    }
    espNowInitialized_ = true;

    s_droppedEvents = 0;
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

    stopping_ = false;
    started_ = true;
    if (discovery_) discovery_->start(nowMs());
    if (config_.runTask) {
        BaseType_t ok = xTaskCreatePinnedToCore(taskEntry, "nowtp", config_.taskStackSize, this,
                                                config_.taskPriority, &task_, config_.taskCore);
        if (ok != pdPASS) {
            task_ = nullptr;
            cleanup();
            return Status::NoMemory;
        }
    }
    return Status::Ok;
}

void EspNowTransport::end() {
    if (!started_) return;
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
    s_events = nullptr;

    if (task_) {
        stopping_ = true;
        xSemaphoreTake(taskExited_, portMAX_DELAY);
        task_ = nullptr;
    }
    lock();
    engine_->cancelAll(Status::Cancelled);
    unlock();
    cleanup();
}

void EspNowTransport::cleanup() {
    if (espNowInitialized_) {
        esp_now_unregister_recv_cb();
        esp_now_unregister_send_cb();
        esp_now_deinit();
        espNowInitialized_ = false;
    }
    s_events = nullptr;
    s_active = false;
    discovery_.reset();
    engine_.reset();
    link_.reset();
    if (events_) {
        vRingbufferDelete(events_);
        events_ = nullptr;
    }
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
}

void EspNowTransport::unlock() const {
    xSemaphoreGiveRecursive(mutex_);
}

void EspNowTransport::taskEntry(void* arg) {
    EspNowTransport* self = static_cast<EspNowTransport*>(arg);
    TickType_t wait = pdMS_TO_TICKS(self->config_.tickIntervalMs);
    if (wait == 0) wait = 1;
    while (!self->stopping_) self->processEvents(wait);
    xSemaphoreGive(self->taskExited_);
    vTaskDelete(nullptr);
}

void EspNowTransport::poll() {
    if (!started_ || config_.runTask) return;
    processEvents(0);
}

void EspNowTransport::processEvents(TickType_t wait) {
    size_t size = 0;
    void* item = xRingbufferReceive(events_, &size, wait);
    lock();
    // Bounded batch so timers still run under a flood of frames.
    for (int n = 0; item;) {
        if (size >= sizeof(EventHeader)) {
            const EventHeader* h = static_cast<const EventHeader*>(item);
            if (h->kind == kEventReceived) {
                const uint8_t* data = static_cast<const uint8_t*>(item) + sizeof(EventHeader);
                engine_->onFrameReceived(Mac::from(h->mac), data, size - sizeof(EventHeader), nowMs(), h->rssi);
            } else if (h->kind == kEventSent) {
                engine_->onFrameSent(h->delivered != 0, nowMs());
            }
        }
        vRingbufferReturnItem(events_, item);
        if (++n >= 32) break;
        item = xRingbufferReceive(events_, &size, 0);
    }
    uint32_t now = nowMs();
    engine_->tick(now);
    if (discovery_) discovery_->tick(now);
    unlock();
}

Status EspNowTransport::addPeer(const Mac& mac, const PeerOptions& options) {
    if (!started_) return Status::InvalidState;
    uint16_t size = options.maxFrameSize;
    if (size > maxSupportedFrameSize()) return Status::InvalidArgument;

    if (!mac.isBroadcast()) {
        esp_now_peer_info_t peer;
        memset(&peer, 0, sizeof(peer));
        memcpy(peer.peer_addr, mac.bytes, sizeof(peer.peer_addr));
        peer.channel = options.channel;
        peer.ifidx = interface_;
        peer.encrypt = options.encrypt;
        if (options.encrypt) memcpy(peer.lmk, options.lmk, sizeof(peer.lmk));
        esp_err_t err = esp_now_is_peer_exist(mac.bytes) ? esp_now_mod_peer(&peer) : esp_now_add_peer(&peer);
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
    unlock();
    return Status::Ok;
}

Status EspNowTransport::removePeer(const Mac& mac) {
    if (!started_) return Status::InvalidState;
    if (mac.isBroadcast()) return Status::InvalidArgument;
    esp_err_t err = esp_now_del_peer(mac.bytes);
    lock();
    link_->setFrameSize(mac, 0);
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

Stats EspNowTransport::stats() const {
    if (!started_) return Stats();
    lock();
    Stats s = engine_->stats();
    unlock();
    return s;
}

// ---------------------------------------------------------------------------
// Radio setup

Status EspNowTransport::prepareRadio() {
    ownsWifiInit_ = ownsWifiStart_ = ownsEventLoop_ = false;
    radio_ = RadioInfo();

    wifi_mode_t mode = WIFI_MODE_NULL;
    esp_err_t err = esp_wifi_get_mode(&mode);
    bool initialized = err == ESP_OK;
    if (err != ESP_OK && err != ESP_ERR_WIFI_NOT_INIT) {
        ESP_LOGE(kTag, "esp_wifi_get_mode: %s", esp_err_to_name(err));
        return Status::LinkError;
    }

    if (!initialized || mode == WIFI_MODE_NULL) {
        if (!config_.initWifi) {
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

    wifi_ap_record_t ap;
    radio_.wifiStartedByNowTP = ownsWifiInit_ || ownsWifiStart_;
    radio_.softApActive = mode == WIFI_MODE_AP || mode == WIFI_MODE_APSTA;
    radio_.stationConnected =
        (mode == WIFI_MODE_STA || mode == WIFI_MODE_APSTA) && esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
    interface_ = mode == WIFI_MODE_AP ? WIFI_IF_AP : WIFI_IF_STA;
    radio_.interface = interface_;

    uint8_t channel = 0;
    wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
    esp_wifi_get_channel(&channel, &second);
    if (config_.channel && channel != config_.channel) {
        if (radio_.stationConnected || radio_.softApActive) {
            ESP_LOGI(kTag, "staying on channel %u, set by the %s", channel,
                     radio_.stationConnected ? "access point" : "soft-AP");
        } else {
            err = esp_wifi_set_channel(config_.channel, WIFI_SECOND_CHAN_NONE);
            if (err != ESP_OK) ESP_LOGW(kTag, "esp_wifi_set_channel: %s", esp_err_to_name(err));
            esp_wifi_get_channel(&channel, &second);
        }
    }
    radio_.channel = channel;

    if (config_.disablePowerSave) esp_wifi_set_ps(WIFI_PS_NONE);
    if (config_.maxTxPower) {
        err = esp_wifi_set_max_tx_power(config_.maxTxPower);
        if (err != ESP_OK) ESP_LOGW(kTag, "esp_wifi_set_max_tx_power: %s", esp_err_to_name(err));
    }

    ESP_LOGI(kTag, "radio ready: channel %u on %s%s%s%s", radio_.channel, interface_ == WIFI_IF_AP ? "AP" : "STA",
             radio_.stationConnected ? ", station connected" : "", radio_.softApActive ? ", soft-AP active" : "",
             radio_.wifiStartedByNowTP ? ", Wi-Fi started by NowTP" : "");
    return Status::Ok;
}

void EspNowTransport::releaseRadio() {
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

// ---------------------------------------------------------------------------
// Discovery

void EspNowTransport::handlePeerEvent(PeerEvent event, const PeerInfo& peer) {
    // Runs in the NowTP task with the lock held.
    if (config_.negotiateFrameSize && !hasExplicitFrameSize(peer.mac)) {
        uint16_t size = 0;  // default
        if (event != PeerEvent::Lost) {
            uint16_t common = std::min(peer.maxFrameSize, maxSupportedFrameSize());
            if (common > config_.defaultMaxFrameSize) size = common;
        }
        link_->setFrameSize(peer.mac, size);
    }
    if (peerHandler_) {
        PeerHandler h = peerHandler_;
        h(event, peer);
    }
}

bool EspNowTransport::hasExplicitFrameSize(const Mac& mac) const {
    return std::find(explicitFrameSizes_.begin(), explicitFrameSizes_.end(), mac) != explicitFrameSizes_.end();
}

void EspNowTransport::onPeerEvent(PeerHandler handler) {
    if (started_) lock();
    peerHandler_ = std::move(handler);
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
    unlock();
    return copy;
}

Status EspNowTransport::setDiscoveryMetadata(const void* data, size_t len) {
    if (len > Discovery::kMaxMetadata || (data == nullptr && len > 0)) return Status::InvalidArgument;
    if (!started_ || !discovery_) return Status::InvalidState;  // before begin(), use EspNowConfig::discovery
    lock();
    discovery_->setMetadata(static_cast<const uint8_t*>(data), len, nowMs());
    unlock();
    return Status::Ok;
}

}  // namespace nowtp

#endif  // ESP_PLATFORM
