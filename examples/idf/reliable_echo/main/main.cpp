// NowTP example for ESP-IDF: flash it on two or more boards.
//
// Boards find each other with discovery. Each board sends every peer it knows
// a 4 KB message on port 2 with reliable delivery, logging the outcome and
// round-trip time, and logs what it receives.
//
// NowTP starts Wi-Fi itself here. An application that manages Wi-Fi (station
// connected to an AP, soft-AP, ...) can set it up first; begin() then uses it as is.
#include <vector>

#include "NowTP.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

static const char* TAG = "example";
static constexpr uint8_t kPortData = 2;

static nowtp::EspNowTransport transport;
static QueueHandle_t peerEvents;

struct PeerChange {
    nowtp::Mac mac;
    bool found;
};

extern "C" void app_main() {
    peerEvents = xQueueCreate(8, sizeof(PeerChange));

    // Callbacks run in the NowTP task: keep them short and hand work off.
    transport.onPeerEvent([](nowtp::PeerEvent e, const nowtp::PeerInfo& p) {
        if (e == nowtp::PeerEvent::Updated) return;
        PeerChange c = {p.mac, e == nowtp::PeerEvent::Found};
        xQueueSend(peerEvents, &c, 0);
        ESP_LOGI(TAG, "%s \"%s\" (%d dBm, frames up to %u bytes)", c.found ? "found" : "lost", p.name.c_str(),
                 p.rssi, p.maxFrameSize);
    });
    transport.listen(kPortData, [](const nowtp::Message& m) {
        uint32_t sum = 0;
        for (size_t i = 0; i < m.len; ++i) sum += m.data[i];
        ESP_LOGI(TAG, "received %u bytes from %02x:%02x:%02x:%02x:%02x:%02x (sum %lu)", (unsigned)m.len,
                 m.src.bytes[0], m.src.bytes[1], m.src.bytes[2], m.src.bytes[3], m.src.bytes[4], m.src.bytes[5],
                 (unsigned long)sum);
    });

    nowtp::EspNowConfig config;
    config.enableDiscovery = true;
    config.discovery.name = "reliable_echo";
    ESP_ERROR_CHECK(transport.begin(config) == nowtp::Status::Ok ? ESP_OK : ESP_FAIL);
    nowtp::RadioInfo radio = transport.radioInfo();
    ESP_LOGI(TAG, "NowTP started on channel %u", radio.channel);

    std::vector<nowtp::Mac> peers;
    std::vector<uint8_t> payload(4000);
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<uint8_t>(i);
    nowtp::SendOptions reliable;
    reliable.reliable = true;

    for (;;) {
        PeerChange c;
        while (xQueueReceive(peerEvents, &c, 0) == pdTRUE) {
            for (size_t i = 0; i < peers.size(); ++i) {
                if (peers[i] == c.mac) peers.erase(peers.begin() + i);
            }
            if (c.found) peers.push_back(c.mac);
        }

        for (const auto& p : peers) {
            int64_t start = esp_timer_get_time();
            nowtp::Status st = transport.sendAndWait(p, kPortData, payload.data(), payload.size(), reliable);
            ESP_LOGI(TAG, "reliable send: %s in %lld ms", nowtp::toString(st),
                     (long long)((esp_timer_get_time() - start) / 1000));
        }
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}
