// NowTP: diagnose and tune links, and look for incompatible nodes.
// Flash on two or more boards (any NowTP sketch answers diagnostics). This one
// finds a peer, measures the link in both directions, prints what limits it,
// applies the fastest reliable settings, then scans channels and radio modes.
#include <NowTP.h>

nowtp::EspNowTransport transport;
QueueHandle_t foundPeers;

void printDiagnosis(const nowtp::LinkDiagnosis& d) {
    Serial.printf("power ceilings: us 11b %.1f / OFDM %.1f dBm (limit %.1f), peer 11b %.1f / OFDM %.1f dBm (limit %.1f)\n",
                  d.ours.dsssDbm, d.ours.ofdmDbm, d.ours.limitDbm, d.theirs.dsssDbm, d.theirs.ofdmDbm,
                  d.theirs.limitDbm);
    for (size_t i = 0; i < d.forward.size() && i < d.reverse.size(); ++i) {
        Serial.printf("  %-17s to peer %2u/%u  from peer %2u/%u\n", nowtp::toString(d.forward[i].step.rate),
                      d.forward[i].received, d.forward[i].sent, d.reverse[i].received, d.reverse[i].sent);
    }
    for (const nowtp::Issue& i : d.issues) {
        Serial.printf("  issue %s%s: %s\n", nowtp::toString(i.kind), i.local ? " (this board)" : "", i.detail.c_str());
    }
}

void setup() {
    Serial.begin(115200);
    foundPeers = xQueueCreate(8, sizeof(nowtp::Mac));

    nowtp::EspNowConfig config;
    config.enableDiscovery = true;  // diagnostics are on by default
    transport.onPeerEvent([](nowtp::PeerEvent e, const nowtp::PeerInfo& p) {
        if (e == nowtp::PeerEvent::Found) xQueueSend(foundPeers, &p.mac, 0);
    });
    if (transport.begin(config) != nowtp::Status::Ok) Serial.println("NowTP failed to start");
    nowtp::RadioInfo r = transport.radioInfo();
    Serial.printf("channel %u, power %.2f dBm (limit %.2f), Long Range %s\n", r.channel, r.txPowerDbm,
                  r.txPowerLimitDbm, r.longRange ? "on" : "off");
}

void loop() {
    nowtp::Mac peer;
    if (xQueueReceive(foundPeers, &peer, pdMS_TO_TICKS(1000)) != pdTRUE) return;

    // Diagnose and tune: blocking calls, run from loop(), never from a callback.
    nowtp::LinkDiagnosis d;
    nowtp::Status st = transport.diagnose(peer, d);
    if (st == nowtp::Status::QueueFull) {
        // The peer is busy with its own measurements (e.g. it runs this sketch too).
        Serial.println("peer busy, retrying shortly");
        delay(random(1000, 4000));
        xQueueSend(foundPeers, &peer, 0);
        return;
    }
    if (st != nowtp::Status::Ok) {
        // Timeout: the peer did not answer (out of range, or away scanning channels).
        Serial.printf("diagnosis failed: %s, retrying later\n", nowtp::toString(st));
        delay(random(3000, 8000));
        xQueueSend(foundPeers, &peer, 0);
        return;
    }
    printDiagnosis(d);
    nowtp::LinkProfile p;
    if (transport.optimizeLink(peer, p, nowtp::OptimizeOptions(), &d) == nowtp::Status::Ok) {
        Serial.printf("tuned: %s to peer at %.1f dBm, %s back (verified: %s)\n", nowtp::toString(p.rateToPeer),
                      p.txPowerDbm, nowtp::toString(p.rateFromPeer), p.verified ? "yes" : "no");
    }

    // Who else is around, and what would stop us from talking to them?
    nowtp::DeepDiscoveryOptions o;
    o.dwellMs = 1500;  // per channel; covers most announcement intervals
    nowtp::DeepDiscoveryReport r;
    if (transport.deepDiscover(r, o) == nowtp::Status::Ok) {
        Serial.printf("deep discovery on channel %u: %u node(s)\n", r.homeChannel, (unsigned)r.nodes.size());
        for (const nowtp::Issue& i : r.issues) Serial.printf("  %s: %s\n", nowtp::toString(i.kind), i.detail.c_str());
    }
}
