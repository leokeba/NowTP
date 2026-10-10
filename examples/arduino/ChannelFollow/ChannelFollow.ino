// NowTP: keep ESP-NOW nodes on the channel of a master's Wi-Fi network.
// Flash one board with your network's credentials (the master), the others
// with WIFI_SSID left empty. The master's station follows its access point's
// channel, wherever that is; the other nodes search the channels until they
// find the master, and follow it whenever its network changes.
#include <NowTP.h>
#include <WiFi.h>

#define WIFI_SSID ""  // set on the master only
#define WIFI_PASSWORD ""

nowtp::EspNowTransport transport;
bool master = false;

void setup() {
    Serial.begin(115200);
    master = strlen(WIFI_SSID) > 0;
    if (master) {
        WiFi.mode(WIFI_STA);
        WiFi.begin(WIFI_SSID, WIFI_PASSWORD);  // NowTP keeps the application's Wi-Fi as it is
    }

    nowtp::EspNowConfig config;
    config.enableDiscovery = true;
    config.discovery.name = master ? "master" : "node";
    // A node whose station is connected is an anchor: the others follow it.
    // findAnchor makes a node search for the master right after boot too.
    config.channel.findAnchor = !master;
    transport.onChannelChange([](uint8_t ch) { Serial.printf("now on channel %u\n", ch); });
    transport.onPeerEvent([](nowtp::PeerEvent e, const nowtp::PeerInfo& p) {
        const char* what = e == nowtp::PeerEvent::Found ? "found" : e == nowtp::PeerEvent::Lost ? "lost" : "updated";
        Serial.printf("%s %s on channel %u%s\n", what, p.name.c_str(), p.channel, p.anchor ? " (anchor)" : "");
    });
    if (transport.begin(config) != nowtp::Status::Ok) Serial.println("NowTP failed to start");
}

void loop() {
    // Before switching the master to another network, warn the nodes so they
    // move at once instead of searching:
    //   transport.announceChannelChange(newChannel);
    //   WiFi.begin(otherSsid, otherPassword);
    delay(5000);
    Serial.printf("channel %u, %u peer(s)%s\n", transport.radioInfo().channel, (unsigned)transport.peers().size(),
                  master && WiFi.status() == WL_CONNECTED ? ", connected" : "");
}
