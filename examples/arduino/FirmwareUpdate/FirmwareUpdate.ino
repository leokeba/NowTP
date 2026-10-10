// NowTP: over-the-air updates to nodes that only speak ESP-NOW, with a stream.
// Flash this sketch on every node (with an OTA partition scheme, the default).
// After changing it, flash one node and press its BOOT button: it streams its
// own firmware to every peer, which installs it and restarts. A node accepts
// an image only if it differs from what it runs.
#include <NowTP.h>
#include <Update.h>

#include "esp_ota_ops.h"
#include "esp_partition.h"

#ifndef BUTTON_PIN
#define BUTTON_PIN 0  // BOOT on most ESP32 and ESP32-S3 boards (GPIO 9 on ESP32-C3)
#endif

nowtp::EspNowTransport transport;
const uint8_t kTopicFirmware = 1;
String runningMd5;

// Receiving: called in the NowTP task when a peer offers a stream.
bool acceptFirmware(const nowtp::StreamInfo& info, nowtp::StreamSink& sink) {
    String md5((const char*)info.header.data(), info.header.size());
    if (info.topic != kTopicFirmware || md5 == runningMd5) return false;  // nothing new
    if (!Update.begin(info.size)) return false;
    Update.setMD5(md5.c_str());
    Serial.printf("receiving %u bytes of firmware\n", (unsigned)info.size);
    sink.write = [](uint32_t, const uint8_t* data, size_t len) {
        return Update.write(const_cast<uint8_t*>(data), len) == len;
    };
    sink.done = [](nowtp::Status s) {
        if (s == nowtp::Status::Ok && Update.end()) {
            Serial.println("update installed, restarting");
            delay(200);
            ESP.restart();
        }
        Serial.printf("update failed: %s\n", nowtp::toString(s));
        Update.abort();
    };
    return true;
}

// Sending: our own application image, read straight from flash.
void shareFirmware(const nowtp::Mac& peer) {
    const esp_partition_t* running = esp_ota_get_running_partition();
    nowtp::StreamOptions o;
    o.topic = kTopicFirmware;
    o.header.assign(runningMd5.c_str(), runningMd5.c_str() + runningMd5.length());
    o.progress = [](uint32_t done, uint32_t total) {
        if (done % (64 * 1024) < 4096) Serial.printf("  %u / %u\n", (unsigned)done, (unsigned)total);
    };
    nowtp::Status st = transport.sendStream(
        peer, ESP.getSketchSize(),
        [running](uint32_t offset, uint8_t* buf, size_t len) {
            return esp_partition_read(running, offset, buf, len) == ESP_OK;
        },
        [](nowtp::Status s) { Serial.printf("firmware stream: %s\n", nowtp::toString(s)); }, o);
    if (st != nowtp::Status::Ok) Serial.printf("cannot start stream: %s\n", nowtp::toString(st));
}

void setup() {
    Serial.begin(115200);
    pinMode(BUTTON_PIN, INPUT_PULLUP);
    runningMd5 = ESP.getSketchMD5();
    Serial.printf("running firmware %s\n", runningMd5.c_str());

    nowtp::EspNowConfig config;
    config.enableDiscovery = true;
    transport.onStream(acceptFirmware);
    if (transport.begin(config) != nowtp::Status::Ok) Serial.println("NowTP failed to start");
}

void loop() {
    if (digitalRead(BUTTON_PIN) == LOW) {
        for (const nowtp::PeerInfo& p : transport.peers()) {
            Serial.printf("offering firmware to %s\n", p.name.c_str());
            shareFirmware(p.mac);
        }
        delay(1000);
    }
    delay(20);
}
