// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#if defined(ESP_PLATFORM)

#include <memory>
#include <utility>
#include <vector>

#include "engine.h"
#include "esp_wifi_types.h"
#include "freertos/FreeRTOS.h"
#include "freertos/ringbuf.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

namespace nowtp {

struct PeerOptions {
    /// Wi-Fi channel of the peer; 0 means the current channel.
    uint8_t channel = 0;
    /// Use ESP-NOW encryption with this local master key (unicast only; see setPrimaryKey()).
    bool encrypt = false;
    uint8_t lmk[16] = {};
    /// Largest frame to send to this peer; 0 uses EspNowConfig::defaultMaxFrameSize.
    /// Up to 1470 when both sides run ESP-NOW v2 (ESP-IDF 5.4+, Arduino-ESP32 3.2+).
    uint16_t maxFrameSize = 0;
};

struct EspNowConfig {
    Config protocol;
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

/// NowTP over the ESP-NOW driver, for both ESP-IDF and Arduino-ESP32.
///
/// Wi-Fi must be started by the application first (e.g. `WiFi.mode(WIFI_STA)` on
/// Arduino). Only one instance can be active, since ESP-NOW has a single pair of
/// driver callbacks. Receive and completion callbacks run in the NowTP task (or
/// inside poll()), never in the Wi-Fi driver task; keep them short.
class EspNowTransport {
public:
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

    /// Sets the handler for a port (may be called before begin()).
    void listen(uint8_t port, ReceiveHandler handler);

    /// Processes pending radio events and timers when runTask is false.
    void poll();

    Mac localMac() const;
    Stats stats() const;
    /// Radio events lost because the event buffer was full.
    uint32_t droppedEvents() const;

    /// Largest frame the local ESP-NOW driver can send (250 or 1470).
    static uint16_t maxSupportedFrameSize();

private:
    class RadioLink;

    static void taskEntry(void* arg);
    void processEvents(TickType_t wait);
    void lock() const;
    void unlock() const;
    void cleanup();

    EspNowConfig config_;
    std::unique_ptr<RadioLink> link_;
    std::unique_ptr<Engine> engine_;
    std::vector<std::pair<uint8_t, ReceiveHandler>> listeners_;
    RingbufHandle_t events_ = nullptr;
    SemaphoreHandle_t mutex_ = nullptr;
    SemaphoreHandle_t taskExited_ = nullptr;
    TaskHandle_t task_ = nullptr;
    wifi_interface_t interface_ = WIFI_IF_STA;
    volatile bool stopping_ = false;
    bool started_ = false;
    bool espNowInitialized_ = false;
};

}  // namespace nowtp

#endif  // ESP_PLATFORM
