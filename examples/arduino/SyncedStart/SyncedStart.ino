// NowTP: network time, so that every node acts at the same instant.
// Flash on two or more boards; set IS_REFERENCE to 1 on exactly one of them.
// Every 3 s the reference picks an instant 300 ms ahead in network time and
// broadcasts it; every node, the reference included, toggles its LED at that
// instant on its own clock. Probe two LEDs with a scope to see the skew.
#include <NowTP.h>

#include "esp_timer.h"

#define IS_REFERENCE 0
#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

nowtp::EspNowTransport transport;
const uint8_t kPortStart = 3;
esp_timer_handle_t timer;

void onTimer(void*) {
    static bool on = false;
    on = !on;
    digitalWrite(LED_BUILTIN, on);
}

// Runs the action when network time reaches `at`.
void scheduleAt(uint64_t at) {
    int64_t delayUs = transport.localTimeUs(at) - esp_timer_get_time();
    esp_timer_stop(timer);
    esp_timer_start_once(timer, delayUs > 0 ? delayUs : 0);
}

void setup() {
    Serial.begin(115200);
    pinMode(LED_BUILTIN, OUTPUT);
    esp_timer_create_args_t args = {};
    args.callback = onTimer;
    args.name = "start";
    esp_timer_create(&args, &timer);

    nowtp::EspNowConfig config;
    config.enableDiscovery = true;           // the reference is announced through discovery
    config.timeSync.reference = IS_REFERENCE;
    transport.listen(kPortStart, [](const nowtp::Message& m) {
        uint64_t at;
        if (m.len != sizeof(at)) return;
        memcpy(&at, m.data, sizeof(at));
        scheduleAt(at);
    });
    if (transport.begin(config) != nowtp::Status::Ok) Serial.println("NowTP failed to start");
}

void loop() {
    delay(3000);
    nowtp::TimeSyncStatus s = transport.timeSyncStatus();
    Serial.printf("%s, offset %lld us, round trip %u us, drift %.1f ppm\n",
                  s.isReference ? "reference" : s.synced ? "synchronized" : "not synchronized", (long long)s.offsetUs,
                  (unsigned)s.roundTripUs, s.driftPpm);
    if (!IS_REFERENCE) return;
    uint64_t at = transport.networkTimeUs() + 300000;
    transport.send(nowtp::Mac::broadcast(), kPortStart, &at, sizeof(at));
    scheduleAt(at);
}
