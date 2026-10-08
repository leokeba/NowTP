// NowTP: find other boards automatically.
// Flash on several boards. Each announces a name and a role, reports peers as
// they appear and disappear, and prints the current peer list every 5 s.
#include <NowTP.h>

nowtp::EspNowTransport transport;

const char* eventName(nowtp::PeerEvent e) {
    switch (e) {
        case nowtp::PeerEvent::Found: return "found";
        case nowtp::PeerEvent::Updated: return "updated";
        case nowtp::PeerEvent::Lost: return "lost";
    }
    return "?";
}

void setup() {
    Serial.begin(115200);

    char name[24];
    snprintf(name, sizeof(name), "node-%04X", (unsigned)(ESP.getEfuseMac() >> 32));
    const char role[] = "sensor";  // application data peers can filter on

    nowtp::EspNowConfig config;
    config.enableDiscovery = true;
    config.discovery.name = name;
    config.discovery.metadata.assign(role, role + strlen(role));

    transport.onPeerEvent([](nowtp::PeerEvent e, const nowtp::PeerInfo& p) {
        Serial.printf("%s %02X:%02X:%02X:%02X:%02X:%02X \"%s\" role=%.*s rssi=%d max frame=%u\n", eventName(e),
                      p.mac.bytes[0], p.mac.bytes[1], p.mac.bytes[2], p.mac.bytes[3], p.mac.bytes[4], p.mac.bytes[5],
                      p.name.c_str(), (int)p.metadata.size(), (const char*)p.metadata.data(), p.rssi, p.maxFrameSize);
    });

    if (transport.begin(config) != nowtp::Status::Ok) Serial.println("NowTP failed to start");
    Serial.printf("I am %s\n", name);
}

void loop() {
    delay(5000);
    std::vector<nowtp::PeerInfo> peers = transport.peers();
    Serial.printf("%u peer(s):\n", (unsigned)peers.size());
    for (const auto& p : peers) {
        Serial.printf("  %s  rssi %d  seen %lu ms ago\n", p.name.c_str(), p.rssi,
                      (unsigned long)(millis() - p.lastSeenMs));
    }
}
