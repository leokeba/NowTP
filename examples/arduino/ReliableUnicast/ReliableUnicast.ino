// NowTP: reliable unicast between two boards that find each other.
// Flash the same sketch on both. Discovery finds the other board; each then
// sends it a 5 KB message every 2 s that is retransmitted until the receiver
// confirms the whole thing arrived intact.
#include <NowTP.h>

nowtp::EspNowTransport transport;
const uint8_t kPortData = 2;

QueueHandle_t foundPeers;
uint8_t payload[5000];

void setup() {
    Serial.begin(115200);
    foundPeers = xQueueCreate(4, sizeof(nowtp::Mac));
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (uint8_t)i;

    // Callbacks run in the NowTP task: hand work to loop() instead of doing it here.
    transport.onPeerEvent([](nowtp::PeerEvent e, const nowtp::PeerInfo& p) {
        if (e == nowtp::PeerEvent::Found) xQueueSend(foundPeers, &p.mac, 0);
    });
    transport.listen(kPortData, [](const nowtp::Message& m) {
        bool intact = m.len == sizeof(payload) && memcmp(m.data, payload, m.len) == 0;
        Serial.printf("received %u bytes, %s\n", (unsigned)m.len, intact ? "intact" : "MISMATCH");
    });

    nowtp::EspNowConfig config;
    config.enableDiscovery = true;
    if (transport.begin(config) != nowtp::Status::Ok) Serial.println("NowTP failed to start");
}

void loop() {
    static nowtp::Mac peer;
    static bool havePeer = false;
    nowtp::Mac m;
    if (xQueueReceive(foundPeers, &m, 0) == pdTRUE) {
        peer = m;
        havePeer = true;
        Serial.println("peer found");
    }
    if (!havePeer) {
        delay(100);
        return;
    }

    nowtp::SendOptions options;
    options.reliable = true;
    unsigned long start = millis();
    // Non-blocking alternative: transport.send(peer, kPortData, payload, sizeof(payload), options,
    //                                          [](nowtp::Status s) { ... });
    nowtp::Status st = transport.sendAndWait(peer, kPortData, payload, sizeof(payload), options);
    Serial.printf("reliable send: %s in %lu ms\n", nowtp::toString(st), millis() - start);
    delay(2000);
}
