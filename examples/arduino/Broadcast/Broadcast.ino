// NowTP: broadcast a message of any size to every board on the channel.
// Flash on two or more boards and open the serial monitor.
#include <NowTP.h>
#include <WiFi.h>

nowtp::EspNowTransport transport;
const uint8_t kPort = 1;

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);  // NowTP needs Wi-Fi started; all boards must share a channel

    transport.listen(kPort, [](const nowtp::Message& m) {
        // Runs in the NowTP task. `m.data` is only valid during this call.
        Serial.printf("%u bytes from %02X:%02X:%02X:%02X:%02X:%02X: %.*s\n", (unsigned)m.len, m.src.bytes[0],
                      m.src.bytes[1], m.src.bytes[2], m.src.bytes[3], m.src.bytes[4], m.src.bytes[5],
                      (int)min(m.len, (size_t)40), (const char*)m.data);
    });

    if (transport.begin() != nowtp::Status::Ok) {
        Serial.println("NowTP failed to start");
        return;
    }
    Serial.printf("NowTP up on %s\n", WiFi.macAddress().c_str());
}

void loop() {
    // 1 KB does not fit in one ESP-NOW frame; NowTP fragments it.
    static char text[1024];
    int n = snprintf(text, sizeof(text), "uptime %lu ms, padding:", millis());
    memset(text + n, '.', sizeof(text) - n);

    // send() returns at once; the optional callback reports when the last frame went out.
    nowtp::Status st = transport.send(nowtp::Mac::broadcast(), kPort, text, sizeof(text), nowtp::SendOptions(),
                                      [](nowtp::Status s) { Serial.printf("broadcast: %s\n", nowtp::toString(s)); });
    if (st != nowtp::Status::Ok) Serial.printf("send: %s\n", nowtp::toString(st));
    delay(1000);
}
