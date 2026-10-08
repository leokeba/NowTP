// NowTP: radio power, rate and Long Range settings.
// Flash on two boards. They find each other and exchange 16 KB messages at a
// faster unicast rate, printing throughput. Broadcast (discovery) stays at the
// default 1 Mbps so nodes keep finding each other at full range.
#include <NowTP.h>

nowtp::EspNowTransport transport;
const uint8_t kPort = 1;
QueueHandle_t foundPeers;
uint8_t payload[16000];

void setup() {
    Serial.begin(115200);
    foundPeers = xQueueCreate(4, sizeof(nowtp::Mac));

    nowtp::EspNowConfig config;
    config.enableDiscovery = true;
    // 11 Mbps (802.11b) is about 5x faster than the default and robust even on
    // cheap boards. OFDM rates (G6M..G54M, MCS0..MCS7) go faster still but need a
    // clean signal on both sides.
    config.radio.unicastRate = nowtp::PhyRate::B11M;
    // Boards whose supply cannot sustain the default 20 dBm lose their frames;
    // 15 dBm is a safe cap for most (0 keeps the driver's setting).
    config.radio.txPowerDbm = 15;
    // Long Range (both sides): config.radio.longRange = true; then
    // config.radio.unicastRate = nowtp::PhyRate::LR250K for ~25 KB/s at long range.

    transport.onPeerEvent([](nowtp::PeerEvent e, const nowtp::PeerInfo& p) {
        if (e == nowtp::PeerEvent::Found) xQueueSend(foundPeers, &p.mac, 0);
    });
    transport.listen(kPort, [](const nowtp::Message& m) {
        Serial.printf("received %u bytes at %d dBm\n", (unsigned)m.len, m.rssi);
    });
    if (transport.begin(config) != nowtp::Status::Ok) Serial.println("NowTP failed to start");

    nowtp::RadioInfo radio = transport.radioInfo();
    Serial.printf("channel %u, max TX power %.2f dBm, unicast at %s\n", radio.channel, radio.txPowerDbm,
                  nowtp::toString(config.radio.unicastRate));
}

void loop() {
    static nowtp::Mac peer;
    static bool havePeer = false;
    nowtp::Mac m;
    if (xQueueReceive(foundPeers, &m, 0) == pdTRUE) {
        peer = m;
        havePeer = true;
    }
    if (!havePeer) {
        delay(100);
        return;
    }
    nowtp::SendOptions options;
    options.reliable = true;
    unsigned long start = millis();
    nowtp::Status st = transport.sendAndWait(peer, kPort, payload, sizeof(payload), options);
    unsigned long ms = millis() - start;
    Serial.printf("16 KB reliable: %s in %lu ms (%.0f KB/s)\n", nowtp::toString(st), ms,
                  ms ? sizeof(payload) / 1024.0 / (ms / 1000.0) : 0.0);
    delay(2000);
}
