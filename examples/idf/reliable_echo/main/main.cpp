// NowTP example for ESP-IDF: flash it on two or more boards.
//
// Every board broadcasts a short "hello" on port 1. When a board hears a new
// peer it registers it and, from then on, sends it a 4 KB message on port 2
// with reliable delivery, logging the outcome and round-trip time.
#include <stdio.h>
#include <string.h>

#include <vector>

#include "NowTP.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs_flash.h"

static const char* TAG = "example";

static constexpr uint8_t kPortHello = 1;
static constexpr uint8_t kPortData = 2;
static constexpr uint8_t kChannel = 1;

static nowtp::EspNowTransport transport;
static QueueHandle_t newPeers;

// The application owns Wi-Fi; NowTP only needs it started.
static void startWifi() {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_channel(kChannel, WIFI_SECOND_CHAN_NONE));
}

extern "C" void app_main() {
    startWifi();
    newPeers = xQueueCreate(8, sizeof(nowtp::Mac));

    // Callbacks run in the NowTP task: keep them short and hand work off.
    transport.listen(kPortHello, [](const nowtp::Message& m) {
        xQueueSend(newPeers, &m.src, 0);
    });
    transport.listen(kPortData, [](const nowtp::Message& m) {
        uint32_t sum = 0;
        for (size_t i = 0; i < m.len; ++i) sum += m.data[i];
        ESP_LOGI(TAG, "received %u bytes from %02x:%02x:%02x:%02x:%02x:%02x (sum %lu)", (unsigned)m.len,
                 m.src.bytes[0], m.src.bytes[1], m.src.bytes[2], m.src.bytes[3], m.src.bytes[4], m.src.bytes[5],
                 (unsigned long)sum);
    });

    ESP_ERROR_CHECK(transport.begin() == nowtp::Status::Ok ? ESP_OK : ESP_FAIL);
    nowtp::Mac self = transport.localMac();
    ESP_LOGI(TAG, "NowTP started on %02x:%02x:%02x:%02x:%02x:%02x", self.bytes[0], self.bytes[1], self.bytes[2],
             self.bytes[3], self.bytes[4], self.bytes[5]);

    std::vector<nowtp::Mac> peers;
    std::vector<uint8_t> payload(4000);
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<uint8_t>(i);

    nowtp::SendOptions reliable;
    reliable.reliable = true;

    for (;;) {
        const char hello[] = "hello";
        transport.send(nowtp::Mac::broadcast(), kPortHello, hello, sizeof(hello));

        nowtp::Mac m;
        while (xQueueReceive(newPeers, &m, 0) == pdTRUE) {
            bool known = false;
            for (const auto& p : peers) known = known || p == m;
            if (!known && transport.addPeer(m) == nowtp::Status::Ok) {
                peers.push_back(m);
                ESP_LOGI(TAG, "new peer, %u total", (unsigned)peers.size());
            }
        }

        for (const auto& p : peers) {
            int64_t start = esp_timer_get_time();
            nowtp::Status st = transport.sendAndWait(p, kPortData, payload.data(), payload.size(), reliable);
            ESP_LOGI(TAG, "reliable send: %s in %lld ms", nowtp::toString(st),
                     (long long)((esp_timer_get_time() - start) / 1000));
        }

        nowtp::Stats s = transport.stats();
        ESP_LOGI(TAG, "frames sent %lu failed %lu received %lu, retransmissions %lu", (unsigned long)s.framesSent,
                 (unsigned long)s.framesFailed, (unsigned long)s.framesReceived, (unsigned long)s.retransmissions);
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}
