// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#if defined(ESP_PLATFORM)

#include "espnow_transport.h"

#include <string.h>

#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_now.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#if ESP_IDF_VERSION_MAJOR >= 5
#include "esp_random.h"
#else
#include "esp_system.h"
#endif

namespace nowtp {

namespace {

const char* const kTag = "nowtp";

enum EventKind : uint8_t { kEventReceived = 1, kEventSent = 2 };

struct EventHeader {
    uint8_t kind;
    uint8_t delivered;  // kEventSent only
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
void pushEvent(uint8_t kind, const uint8_t* mac, bool delivered, const uint8_t* data, size_t len) {
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
    pushEvent(kEventReceived, info->src_addr, false, data, static_cast<size_t>(len));
}
#else
void onRecv(const uint8_t* mac, const uint8_t* data, int len) {
    if (!mac || len <= 0) return;
    pushEvent(kEventReceived, mac, false, data, static_cast<size_t>(len));
}
#endif

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 5, 0)
void onSent(const esp_now_send_info_t*, esp_now_send_status_t status) {
#else
void onSent(const uint8_t*, esp_now_send_status_t status) {
#endif
    pushEvent(kEventSent, nullptr, status == ESP_NOW_SEND_SUCCESS, nullptr, 0);
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

    wifi_mode_t mode = WIFI_MODE_NULL;
    if (esp_wifi_get_mode(&mode) != ESP_OK || mode == WIFI_MODE_NULL) {
        ESP_LOGE(kTag, "start Wi-Fi before NowTP (e.g. WiFi.mode(WIFI_STA))");
        return Status::InvalidState;
    }
    interface_ = mode == WIFI_MODE_AP ? WIFI_IF_AP : WIFI_IF_STA;

    config_ = config;
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
                engine_->onFrameReceived(Mac::from(h->mac), data, size - sizeof(EventHeader), nowMs());
            } else if (h->kind == kEventSent) {
                engine_->onFrameSent(h->delivered != 0, nowMs());
            }
        }
        vRingbufferReturnItem(events_, item);
        if (++n >= 32) break;
        item = xRingbufferReceive(events_, &size, 0);
    }
    engine_->tick(nowMs());
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

void EspNowTransport::listen(uint8_t port, ReceiveHandler handler) {
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

}  // namespace nowtp

#endif  // ESP_PLATFORM
