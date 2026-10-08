// NowTP: stream state where only the newest value matters, with poll() mode.
// A newer "latest only" message cancels older queued or half-received ones,
// so a slow link drops stale updates instead of falling behind.
#include <NowTP.h>
#include <WiFi.h>

nowtp::EspNowTransport transport;
const uint8_t kPortState = 3;

struct State {
    uint32_t sequence;
    float readings[100];  // 404 bytes: two ESP-NOW frames
};

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);

    transport.listen(kPortState, [](const nowtp::Message& m) {
        if (m.len != sizeof(State)) return;
        State s;
        memcpy(&s, m.data, sizeof(s));
        Serial.printf("state #%lu\n", (unsigned long)s.sequence);
    });

    nowtp::EspNowConfig config;
    config.runTask = false;  // callbacks run inside poll(), from loop()
    if (transport.begin(config) != nowtp::Status::Ok) Serial.println("NowTP failed to start");
}

void loop() {
    transport.poll();

    static uint32_t sequence = 0;
    static unsigned long last = 0;
    if (millis() - last >= 20) {
        last = millis();
        State s;
        s.sequence = sequence++;
        for (int i = 0; i < 100; ++i) s.readings[i] = analogRead(0) * 0.001f;

        nowtp::SendOptions options;
        options.latestOnly = true;
        transport.send(nowtp::Mac::broadcast(), kPortState, &s, sizeof(s), options);
    }
}
