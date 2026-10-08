// NowTP: reliable unicast between two boards.
// Flash the same sketch on both. Each board announces itself by broadcast,
// registers whoever it hears, then sends it a 5 KB message that is
// retransmitted until the receiver confirms the whole thing arrived intact.
#include <NowTP.h>
#include <WiFi.h>

nowtp::EspNowTransport transport;
const uint8_t kPortHello = 1;
const uint8_t kPortData = 2;

QueueHandle_t heardPeers;
nowtp::Mac peer;
bool havePeer = false;
uint8_t payload[5000];

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);
    heardPeers = xQueueCreate(4, sizeof(nowtp::Mac));
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (uint8_t)i;

    // Callbacks run in the NowTP task: hand work to loop() instead of doing it here.
    transport.listen(kPortHello, [](const nowtp::Message& m) { xQueueSend(heardPeers, &m.src, 0); });
    transport.listen(kPortData, [](const nowtp::Message& m) {
        bool intact = m.len == sizeof(payload) && memcmp(m.data, payload, m.len) == 0;
        Serial.printf("received %u bytes, %s\n", (unsigned)m.len, intact ? "intact" : "MISMATCH");
    });

    if (transport.begin() != nowtp::Status::Ok) Serial.println("NowTP failed to start");
}

void loop() {
    nowtp::Mac m;
    if (!havePeer && xQueueReceive(heardPeers, &m, 0) == pdTRUE && transport.addPeer(m) == nowtp::Status::Ok) {
        peer = m;
        havePeer = true;
        Serial.println("peer registered");
    }

    if (!havePeer) {
        transport.send(nowtp::Mac::broadcast(), kPortHello, "hi", 2);
        delay(500);
        return;
    }

    nowtp::SendOptions options;
    options.reliable = true;
    unsigned long start = millis();
    // Non-blocking alternative: transport.send(peer, kPortData, payload, sizeof(payload), options,
    //                                          [](nowtp::Status s) { ... });
    nowtp::Status st = transport.sendAndWait(peer, kPortData, payload, sizeof(payload), options);
    Serial.printf("reliable send: %s in %lu ms\n", nowtp::toString(st), millis() - start);

    // Keep announcing so a rebooted peer finds us again.
    transport.send(nowtp::Mac::broadcast(), kPortHello, "hi", 2);
    delay(2000);
}
