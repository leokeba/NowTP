// NowTP: authenticated messages, and pairing to hand the installation key to new nodes.
// Flash on two or more boards. A board without a key looks for a pairing
// window at boot. Press BOOT on a board to open its window for 30 s; the first
// board to do so creates the installation's key. Keys are kept in NVS, so
// paired boards stay paired across reboots. Hold BOOT at power-up to forget the key.
#include <NowTP.h>

#ifndef BUTTON_PIN
#define BUTTON_PIN 0  // BOOT on most ESP32 and ESP32-S3 boards (GPIO 9 on ESP32-C3)
#endif

nowtp::EspNowTransport transport;
const uint8_t kPortHello = 1;

void setup() {
    Serial.begin(115200);
    pinMode(BUTTON_PIN, INPUT_PULLUP);

    nowtp::EspNowConfig config;
    config.enableDiscovery = true;
    // Optional: only nodes knowing this code can pair (use a long random one
    // to also resist an attacker present during the pairing window).
    config.security.pairingCode = "spin-seq-studio";
    transport.listen(kPortHello, [](const nowtp::Message& m) {
        // With a key, only authenticated messages arrive here.
        Serial.printf("%.*s (%s)\n", (int)m.len, (const char*)m.data, m.authenticated ? "authenticated" : "plain");
    });
    if (transport.begin(config) != nowtp::Status::Ok) Serial.println("NowTP failed to start");

    if (digitalRead(BUTTON_PIN) == LOW) {
        transport.forgetSecurityKey();
        Serial.println("key forgotten");
    }
    if (!transport.secured()) {
        Serial.println("no key yet: looking for a pairing window (press BOOT on a paired board)");
        nowtp::Mac member;
        nowtp::Status st = transport.pair(30000, &member);
        Serial.printf("pairing: %s\n", nowtp::toString(st));
    }
}

void loop() {
    if (digitalRead(BUTTON_PIN) == LOW) {
        Serial.println("pairing window open for 30 s");
        nowtp::Mac joined;
        nowtp::Status st = transport.acceptPairing(30000, &joined);
        Serial.printf("pairing: %s\n", nowtp::toString(st));
    }
    static unsigned long last = 0;
    if (millis() - last > 3000) {
        last = millis();
        char text[48];
        int n = snprintf(text, sizeof(text), "hello from %s node", transport.secured() ? "a paired" : "an unpaired");
        transport.send(nowtp::Mac::broadcast(), kPortHello, text, n);
    }
    delay(20);
}
