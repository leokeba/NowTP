// Two-board integration test for NowTP. Flash the same firmware on two boards.
//
// The board with the lower MAC drives the tests ("driver"); the other serves
// echo and counter endpoints ("responder"). Boards synchronize through their
// discovery metadata, which carries the current phase name.
//
// Phases cover the radio states begin() must handle:
//   1. nothing initialized: NowTP brings Wi-Fi up and down itself
//   2. application-started station, not connected, on channel 3
//   3. driver runs a soft-AP on channel 6, responder is a station connected to it
//
// Both boards print "PASS"/"FAIL" lines and finally "DONE pass=<n> fail=<n>".
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include "NowTP.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs_flash.h"

using nowtp::Mac;
using nowtp::Status;

namespace {

// Ports
constexpr uint8_t kEcho = 10;        // responder echoes to kEchoReply with the same reliability
constexpr uint8_t kEchoReply = 11;
constexpr uint8_t kBulk = 13;        // responder counts messages and bytes
constexpr uint8_t kLatest = 14;      // responder checks sequence numbers
constexpr uint8_t kStats = 15;       // query/reply responder counters (and reset them)
constexpr uint8_t kNoListener = 20;  // nobody listens

constexpr const char* kApSsid = "NOWTP-PAIR";
constexpr uint8_t kApChannel = 6;

int g_pass = 0, g_fail = 0;
bool g_driver = false;
nowtp::EspNowTransport transport;

void report(const char* name, bool ok, const std::string& detail = std::string()) {
    (ok ? g_pass : g_fail)++;
    printf("%s %s %s\n", ok ? "PASS" : "FAIL", name, detail.c_str());
}

std::string fmt(const char* f, ...) __attribute__((format(printf, 1, 2)));
std::string fmt(const char* f, ...) {
    char buf[160];
    va_list ap;
    va_start(ap, f);
    vsnprintf(buf, sizeof(buf), f, ap);
    va_end(ap);
    return buf;
}

int64_t millis() {
    return esp_timer_get_time() / 1000;
}

std::string macStr(const Mac& m) {
    return fmt("%02x:%02x:%02x:%02x:%02x:%02x", m.bytes[0], m.bytes[1], m.bytes[2], m.bytes[3], m.bytes[4],
               m.bytes[5]);
}

// This S3 board loses its frames above ~17 dBm (its supply sags); cap it.
constexpr float kS3MaxDbm = 17;
void boardTxPowerFix() {
#if CONFIG_IDF_TARGET_ESP32S3
    esp_wifi_set_max_tx_power(static_cast<int8_t>(kS3MaxDbm * 4));
#endif
}

// ---------------------------------------------------------------------------
// Peer tracking (fed from the NowTP task)

std::mutex g_peerMutex;
bool g_peerPresent = false;
nowtp::PeerInfo g_peer;
std::atomic<int> g_peerLostCount{0};

void onPeer(nowtp::PeerEvent e, const nowtp::PeerInfo& p) {
    // Other NowTP nodes may be on the air; only follow the other test board.
    if (p.name != "driver" && p.name != "board") return;
    std::lock_guard<std::mutex> lock(g_peerMutex);
    if (e == nowtp::PeerEvent::Lost) {
        g_peerPresent = false;
        g_peerLostCount++;
    } else {
        g_peerPresent = true;
        g_peer = p;
    }
}

std::string peerMeta() {
    std::lock_guard<std::mutex> lock(g_peerMutex);
    return g_peerPresent ? std::string(g_peer.metadata.begin(), g_peer.metadata.end()) : std::string();
}

nowtp::PeerInfo peerInfo() {
    std::lock_guard<std::mutex> lock(g_peerMutex);
    return g_peer;
}

bool waitFor(const std::function<bool()>& cond, int timeoutMs) {
    int64_t end = millis() + timeoutMs;
    while (!cond()) {
        if (millis() > end) return false;
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    return true;
}

// ---------------------------------------------------------------------------
// Responder side

struct Counters {
    uint32_t bulkMessages;
    uint32_t bulkBytes;
    uint32_t latestReceived;
    uint32_t latestOutOfOrder;
    int32_t latestLastSeq;
    int32_t rssiSum;
    uint32_t rssiCount;
};
std::mutex g_countersMutex;
const Counters kZeroCounters = {0, 0, 0, 0, -1, 0, 0};
Counters g_counters = kZeroCounters;

void listenResponder() {
    transport.listen(kEcho, [](const nowtp::Message& m) {
        nowtp::SendOptions o;
        o.reliable = m.reliable;
        transport.send(m.src, kEchoReply, m.data, m.len, o);
    });
    transport.listen(kBulk, [](const nowtp::Message& m) {
        std::lock_guard<std::mutex> lock(g_countersMutex);
        g_counters.bulkMessages++;
        g_counters.bulkBytes += m.len;
        if (m.rssi) {
            g_counters.rssiSum += m.rssi;
            g_counters.rssiCount++;
        }
    });
    transport.listen(kLatest, [](const nowtp::Message& m) {
        if (m.len < 4) return;
        int32_t seq;
        memcpy(&seq, m.data, 4);
        std::lock_guard<std::mutex> lock(g_countersMutex);
        g_counters.latestReceived++;
        if (seq <= g_counters.latestLastSeq) g_counters.latestOutOfOrder++;
        g_counters.latestLastSeq = seq;
    });
    transport.listen(kStats, [](const nowtp::Message& m) {
        Counters c;
        {
            std::lock_guard<std::mutex> lock(g_countersMutex);
            c = g_counters;
            g_counters = kZeroCounters;
        }
        nowtp::SendOptions o;
        o.reliable = true;
        transport.send(m.src, kStats, &c, sizeof(c), o);
    });
}

// ---------------------------------------------------------------------------
// Driver side

SemaphoreHandle_t g_echoSem;
std::mutex g_echoMutex;
std::vector<uint8_t> g_echoData;
SemaphoreHandle_t g_statsSem;
Counters g_statsReply;

void listenDriver() {
    transport.listen(kEchoReply, [](const nowtp::Message& m) {
        {
            std::lock_guard<std::mutex> lock(g_echoMutex);
            g_echoData.assign(m.data, m.data + m.len);
        }
        xSemaphoreGive(g_echoSem);
    });
    transport.listen(kStats, [](const nowtp::Message& m) {
        if (m.len == sizeof(Counters)) memcpy(&g_statsReply, m.data, sizeof(Counters));
        xSemaphoreGive(g_statsSem);
    });
}

std::vector<uint8_t> pattern(size_t n, uint32_t seed) {
    std::vector<uint8_t> v(n);
    uint32_t x = seed * 2654435761u + 1;
    for (auto& b : v) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        b = static_cast<uint8_t>(x);
    }
    return v;
}

bool queryStats(const Mac& peer, Counters& out) {
    xSemaphoreTake(g_statsSem, 0);
    nowtp::SendOptions o;
    o.reliable = true;
    if (transport.send(peer, kStats, "Q", 1, o) != Status::Ok) return false;
    if (xSemaphoreTake(g_statsSem, pdMS_TO_TICKS(2000)) != pdTRUE) return false;
    out = g_statsReply;
    return true;
}

void echoTest(const Mac& peer, const char* name, size_t len, bool reliable) {
    auto data = pattern(len, static_cast<uint32_t>(len));
    xSemaphoreTake(g_echoSem, 0);
    nowtp::SendOptions o;
    o.reliable = reliable;
    int64_t start = esp_timer_get_time();
    Status st = transport.send(peer, kEcho, data.data(), data.size(), o);
    bool got = st == Status::Ok && xSemaphoreTake(g_echoSem, pdMS_TO_TICKS(3000)) == pdTRUE;
    int64_t rtt = esp_timer_get_time() - start;
    bool same;
    {
        std::lock_guard<std::mutex> lock(g_echoMutex);
        same = got && g_echoData == data;
    }
    report(name, same, fmt("(%u bytes, %s, round trip %lld ms)", (unsigned)len, nowtp::toString(st),
                           (long long)(rtt / 1000)));
}

// Sends `count` messages back to back; returns ms until all completed, or -1.
int64_t pipelined(const Mac& peer, uint8_t port, size_t len, int count, bool reliable, int* okCount) {
    std::vector<uint8_t> data(len, 0x77);
    std::atomic<int> done{0}, ok{0};
    nowtp::SendOptions o;
    o.reliable = reliable;
    int64_t start = millis();
    for (int i = 0; i < count; ++i) {
        Status st;
        while ((st = transport.send(peer, port, data.data(), data.size(), o, [&](Status s) {
                    if (s == Status::Ok) ok++;
                    done++;
                })) == Status::QueueFull) {
            vTaskDelay(1);
        }
        if (st != Status::Ok) done++;
    }
    bool finished = waitFor([&] { return done.load() == count; }, 30000);
    *okCount = ok.load();
    return finished ? millis() - start : -1;
}

void driverDataTests(const Mac& peer, bool full) {
    echoTest(peer, "echo_small_unreliable", 10, false);
    echoTest(peer, "echo_16k_reliable", 16000, true);
    if (!full) return;
    echoTest(peer, "echo_4k_unreliable", 4000, false);
    echoTest(peer, "echo_1_frame_reliable", 200, true);

    // Frame size negotiated through discovery: 4000 bytes in 1470-byte frames is 3 frames, not 17.
    Counters c;
    queryStats(peer, c);  // reset
    nowtp::Stats before = transport.stats();
    std::vector<uint8_t> four(4000, 1);
    transport.sendAndWait(peer, kBulk, four.data(), four.size());
    uint32_t frames = transport.stats().framesSent - before.framesSent;
    bool v2 = peerInfo().maxFrameSize > 250 && nowtp::EspNowTransport::maxSupportedFrameSize() > 250;
    report("frame_size_negotiated", v2 ? frames <= 4 : frames >= 17,
           fmt("(peer max %u, 4000 bytes took %lu frames)", peerInfo().maxFrameSize, (unsigned long)frames));

    int ok = 0;
    int64_t ms = pipelined(peer, kBulk, 16000, 20, true, &ok);
    bool counted = queryStats(peer, c);
    report("reliable_throughput", ms > 0 && ok == 20 && counted && c.bulkMessages == 21,
           fmt("(20 x 16000 B in %lld ms = %.1f KB/s, peer counted %lu)", (long long)ms,
               ms > 0 ? 20 * 16000.0 / 1024 / (ms / 1000.0) : 0.0, (unsigned long)c.bulkMessages));

    ms = pipelined(peer, kBulk, 16000, 20, false, &ok);
    counted = queryStats(peer, c);
    report("unreliable_unicast_throughput", ms > 0 && counted && c.bulkMessages >= 19,
           fmt("(20 x 16000 B in %lld ms = %.1f KB/s, peer got %lu/20)", (long long)ms,
               ms > 0 ? 20 * 16000.0 / 1024 / (ms / 1000.0) : 0.0, (unsigned long)c.bulkMessages));

    // Latest-only stream: older messages are superseded, never delivered out of order.
    std::atomic<int> superseded{0}, delivered{0}, finished{0};
    nowtp::SendOptions lo;
    lo.latestOnly = true;
    std::vector<uint8_t> state(2000, 5);
    for (int32_t seq = 0; seq < 200; ++seq) {
        memcpy(state.data(), &seq, 4);
        transport.send(peer, kLatest, state.data(), state.size(), lo, [&](Status s) {
            if (s == Status::Superseded) superseded++;
            if (s == Status::Ok) delivered++;
            finished++;
        });
        vTaskDelay(seq % 10 == 0 ? 1 : 0);
    }
    waitFor([&] { return finished.load() == 200; }, 5000);
    vTaskDelay(pdMS_TO_TICKS(200));
    counted = queryStats(peer, c);
    report("latest_only_stream",
           counted && c.latestLastSeq == 199 && c.latestOutOfOrder == 0 && superseded.load() > 0,
           fmt("(sent %d, superseded %d, peer received %lu, last seq %ld, out of order %lu)", delivered.load(),
               superseded.load(), (unsigned long)c.latestReceived, (long)c.latestLastSeq,
               (unsigned long)c.latestOutOfOrder));

    nowtp::SendOptions rel;
    rel.reliable = true;
    Status st = transport.sendAndWait(peer, kNoListener, "x", 1, rel);
    report("reliable_without_listener_rejected", st == Status::Rejected, nowtp::toString(st));
}

// ---------------------------------------------------------------------------
// Phases

nowtp::EspNowConfig baseConfig(const std::string& phase) {
    nowtp::EspNowConfig cfg;
    cfg.enableDiscovery = true;
    cfg.discovery.name = g_driver ? "driver" : "board";
    cfg.discovery.metadata.assign(phase.begin(), phase.end());
    cfg.discovery.announceIntervalMs = 300;
    cfg.discovery.peerTimeoutMs = 2000;
#if CONFIG_IDF_TARGET_ESP32S3
    cfg.radio.txPowerDbm = kS3MaxDbm;
#endif
    return cfg;
}

// Starts NowTP for a phase and waits for the peer to reach the same phase.
bool startPhase(const std::string& phase, nowtp::EspNowConfig cfg) {
    transport.onPeerEvent(onPeer);
    Status st = transport.begin(cfg);
    report((phase + "_begin").c_str(), st == Status::Ok, nowtp::toString(st));
    if (st != Status::Ok) return false;
    bool synced = waitFor([&] { return peerMeta() == phase; }, 30000);
    nowtp::PeerInfo p = peerInfo();
    report((phase + "_peer_discovered").c_str(), synced,
           fmt("(%s \"%s\", rssi %d, max frame %u)", macStr(p.mac).c_str(), p.name.c_str(), p.rssi,
               p.maxFrameSize));
    if (!synced) transport.end();
    return synced;
}

// Driver announces "<phase>-done" and waits for the responder to say goodbye.
void finishPhase(const std::string& phase) {
    if (g_driver) {
        std::string done = phase + "-done";
        transport.setDiscoveryMetadata(done.data(), done.size());
        int lostBefore = g_peerLostCount.load();
        bool goodbye = waitFor([&] { return g_peerLostCount.load() > lostBefore; }, 5000);
        report((phase + "_goodbye_seen").c_str(), goodbye);
    } else {
        waitFor([&] { return peerMeta() == phase + "-done"; }, 120000);
    }
    transport.end();
    {
        std::lock_guard<std::mutex> lock(g_peerMutex);
        g_peerPresent = false;
    }
    vTaskDelay(pdMS_TO_TICKS(300));
}

void listenAll() {
    if (g_driver) {
        listenDriver();
    } else {
        listenResponder();
    }
}

// Phase 1: nothing initialized. Roles are decided here.
void phaseAutoInit() {
    wifi_mode_t mode;
    report("p1_wifi_untouched_before", esp_wifi_get_mode(&mode) == ESP_ERR_WIFI_NOT_INIT);

    // Role is unknown until the peer is seen, so register every endpoint first.
    listenDriver();
    listenResponder();
    nowtp::EspNowConfig cfg = baseConfig("p1");
    if (!startPhase("p1", cfg)) return;

    Mac self = transport.localMac();
    Mac peer = peerInfo().mac;
    g_driver = memcmp(self.bytes, peer.bytes, 6) < 0;
    printf("ROLE %s (self %s, peer %s)\n", g_driver ? "driver" : "responder", macStr(self).c_str(),
           macStr(peer).c_str());
    // Endpoints the other role owns are dropped so stats replies route correctly.
    if (g_driver) {
        transport.listen(kEcho, nowtp::ReceiveHandler());
        transport.listen(kBulk, nowtp::ReceiveHandler());
        transport.listen(kLatest, nowtp::ReceiveHandler());
        listenDriver();
    } else {
        transport.listen(kEchoReply, nowtp::ReceiveHandler());
        listenResponder();
    }

    nowtp::RadioInfo r = transport.radioInfo();
    report("p1_radio_auto_started", r.wifiStartedByNowTP && r.channel == 1 && r.interface == WIFI_IF_STA &&
                                        !r.stationConnected && !r.softApActive,
           fmt("(channel %u)", r.channel));

    if (g_driver) driverDataTests(peer, true);
    finishPhase("p1");
    report("p1_wifi_released_after_end", esp_wifi_get_mode(&mode) == ESP_ERR_WIFI_NOT_INIT);
}

EventGroupHandle_t g_wifiEvents;
constexpr EventBits_t kConnected = 1;

void wifiEventHandler(void*, esp_event_base_t base, int32_t id, void*) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_CONNECTED) xEventGroupSetBits(g_wifiEvents, kConnected);
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        xEventGroupClearBits(g_wifiEvents, kConnected);
        esp_wifi_connect();  // keep trying while the AP comes up
    }
}

void appWifiInit() {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();
    esp_netif_create_default_wifi_ap();
    g_wifiEvents = xEventGroupCreate();
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifiEventHandler, nullptr);
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
}

// Phase 2: the application started a station on channel 3; NowTP must keep it.
void phaseAppStation() {
    appWifiInit();
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    boardTxPowerFix();
    ESP_ERROR_CHECK(esp_wifi_set_channel(3, WIFI_SECOND_CHAN_NONE));

    nowtp::EspNowConfig cfg = baseConfig("p2");
    cfg.radio.channel = 0;  // keep the application's channel
    listenAll();
    if (startPhase("p2", cfg)) {
        nowtp::RadioInfo r = transport.radioInfo();
        report("p2_radio_kept_app_setup", !r.wifiStartedByNowTP && r.channel == 3 && r.interface == WIFI_IF_STA,
               fmt("(channel %u)", r.channel));
        if (g_driver) driverDataTests(peerInfo().mac, false);
        finishPhase("p2");
    }
    wifi_mode_t mode;
    report("p2_app_wifi_still_running", esp_wifi_get_mode(&mode) == ESP_OK && mode == WIFI_MODE_STA);
    esp_wifi_stop();
}

// Phase 3: driver is a soft-AP on channel 6, responder a station connected to it.
void phaseSoftApAndConnectedStation() {
    if (g_driver) {
        wifi_config_t ap = {};
        strcpy(reinterpret_cast<char*>(ap.ap.ssid), kApSsid);
        ap.ap.ssid_len = strlen(kApSsid);
        ap.ap.channel = kApChannel;
        ap.ap.max_connection = 2;
        ap.ap.authmode = WIFI_AUTH_OPEN;
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap));
        ESP_ERROR_CHECK(esp_wifi_start());
        boardTxPowerFix();
    } else {
        wifi_config_t sta = {};
        strcpy(reinterpret_cast<char*>(sta.sta.ssid), kApSsid);
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta));
        ESP_ERROR_CHECK(esp_wifi_start());
        boardTxPowerFix();
        esp_wifi_connect();
        bool connected = xEventGroupWaitBits(g_wifiEvents, kConnected, pdFALSE, pdTRUE, pdMS_TO_TICKS(30000)) &
                         kConnected;
        report("p3_station_connected_to_soft_ap", connected);
    }

    nowtp::EspNowConfig cfg = baseConfig("p3");  // channel 1 requested, but the AP decides
    listenAll();
    if (startPhase("p3", cfg)) {
        nowtp::RadioInfo r = transport.radioInfo();
        bool ok = r.channel == kApChannel && !r.wifiStartedByNowTP &&
                  (g_driver ? (r.softApActive && r.interface == WIFI_IF_AP)
                            : (r.stationConnected && r.interface == WIFI_IF_STA));
        report("p3_radio_follows_access_point", ok,
               fmt("(channel %u, interface %s, connected %d, soft-AP %d)", r.channel,
                   r.interface == WIFI_IF_AP ? "AP" : "STA", r.stationConnected, r.softApActive));
        if (g_driver) driverDataTests(peerInfo().mac, false);
        finishPhase("p3");
    }
    esp_wifi_stop();
    esp_wifi_deinit();  // phases 4 and 5 let NowTP own Wi-Fi again
}

Mac bulkTarget;
int bulkOk;

// Sends `count` unreliable messages of `len` bytes to the responder's counter and
// returns how many it counted, with the average RSSI it saw.
int64_t measuredBulk(const Mac& peer, const Mac& dst, size_t len, int count, Counters& c) {
    queryStats(peer, c);  // reset
    int64_t ms = pipelined(dst, kBulk, len, count, false, &bulkOk);
    vTaskDelay(pdMS_TO_TICKS(50));
    if (!queryStats(peer, c)) c = kZeroCounters;
    return ms;
}

// Phase 4: both boards in Long Range mode. Rates, broadcast rate and power.
void phaseRadioSettings() {
    nowtp::EspNowConfig cfg = baseConfig("p4");
    cfg.radio.longRange = true;
    listenAll();
    if (!startPhase("p4", cfg)) return;
    nowtp::RadioInfo r = transport.radioInfo();
    report("p4_long_range_enabled", r.longRange && r.wifiStartedByNowTP);

    if (g_driver) {
        Mac peer = peerInfo().mac;
        // 10 dBm: the test S3 cannot sustain OFDM rates above ~15 dBm.
        transport.setTxPower(10);
        using nowtp::PhyRate;
        const PhyRate rates[] = {PhyRate::B1M,  PhyRate::B2M,  PhyRate::B5_5M, PhyRate::B11M, PhyRate::G6M,
                                 PhyRate::G12M, PhyRate::G24M, PhyRate::G54M,  PhyRate::MCS0, PhyRate::MCS3,
                                 PhyRate::MCS7, PhyRate::LR500K, PhyRate::LR250K};
        for (PhyRate rate : rates) {
            bool lr = rate == PhyRate::LR250K || rate == PhyRate::LR500K;
            int count = lr ? 2 : 5;
            Counters c;
            queryStats(peer, c);
            Status st = transport.setUnicastRate(rate);
            int64_t ms = measuredBulk(peer, peer, 16000, count, c);
            std::string name = std::string("unicast_rate ") + nowtp::toString(rate);
            report(name.c_str(), st == Status::Ok && ms > 0 && (int)c.bulkMessages == count,
                   fmt("(%d x 16000 B in %lld ms = %.1f KB/s, peer got %lu, rssi %ld)", count, (long long)ms,
                       ms > 0 ? count * 16000.0 / 1024 / (ms / 1000.0) : 0.0, (unsigned long)c.bulkMessages,
                       (long)(c.rssiCount ? c.rssiSum / (int32_t)c.rssiCount : 0)));
        }
        transport.setUnicastRate(PhyRate::Default);

        Counters c;
        // Broadcast has no MAC-level retries: single frames, and only require that
        // frames at the configured rate get through, not a perfect link.
        Status st = transport.setBroadcastRate(PhyRate::B11M);
        int64_t ms = measuredBulk(peer, Mac::broadcast(), 200, 20, c);
        report("broadcast_rate 11 Mbps", st == Status::Ok && c.bulkMessages >= 10,
               fmt("(20 x 200 B in %lld ms, peer got %lu)", (long long)ms, (unsigned long)c.bulkMessages));
        transport.setBroadcastRate(PhyRate::Default);

        const float powers[] = {2, 5, 8, 11, 14, 17};
        long rssiFirst = 0, rssiLast = 0;
        for (size_t i = 0; i < sizeof(powers) / sizeof(powers[0]); ++i) {
            Status ps = transport.setTxPower(powers[i]);
            float actual = transport.radioInfo().txPowerDbm;  // the driver quantizes on some chips
            measuredBulk(peer, peer, 200, 20, c);
            long rssi = c.rssiCount ? c.rssiSum / (int32_t)c.rssiCount : 0;
            if (i == 0) rssiFirst = rssi;
            rssiLast = rssi;
            std::string name = fmt("tx_power %.0f dBm", powers[i]);
            report(name.c_str(), ps == Status::Ok && actual > powers[i] - 1.1f && actual < powers[i] + 0.3f &&
                                     c.bulkMessages >= 18,
                   fmt("(driver reports %.2f dBm, peer got %lu/20 at %ld dBm)", actual,
                       (unsigned long)c.bulkMessages, rssi));
        }
        report("tx_power_moves_rssi", rssiLast - rssiFirst >= 6,
               fmt("(rssi %ld dBm at 2 dBm, %ld dBm at 17 dBm)", rssiFirst, rssiLast));
        report("tx_power_out_of_range_rejected", transport.setTxPower(30) == Status::InvalidArgument);
        transport.setTxPower(17);
    }
    finishPhase("p4");
}

// Phase 5: the driver runs Long Range, the responder does not.
void phaseLongRangeInterop() {
    nowtp::EspNowConfig cfg = baseConfig("p5");
    cfg.radio.longRange = g_driver;
    listenAll();
    if (!startPhase("p5", cfg)) return;
    report("p5_long_range_only_on_driver", transport.radioInfo().longRange == g_driver);
    if (g_driver) {
        Mac peer = peerInfo().mac;
        echoTest(peer, "lr_node_and_plain_node_interoperate", 3000, true);
        transport.setUnicastRate(nowtp::PhyRate::LR250K);
        Status st = transport.sendAndWait(peer, kBulk, "x", 1);
        report("lr_frames_not_heard_by_plain_node", st == Status::SendFailed, nowtp::toString(st));
        transport.setUnicastRate(nowtp::PhyRate::Default);
    }
    finishPhase("p5");
}

}  // namespace

extern "C" void app_main() {
    g_echoSem = xSemaphoreCreateBinary();
    g_statsSem = xSemaphoreCreateBinary();
    vTaskDelay(pdMS_TO_TICKS(1500));
    printf("\nNOWTP PAIR TEST\n");

    phaseAutoInit();
    if (g_pass > 0 && g_fail == 0) {
        phaseAppStation();
        phaseSoftApAndConnectedStation();
        phaseRadioSettings();
        phaseLongRangeInterop();
    }
    printf("DONE pass=%d fail=%d\n", g_pass, g_fail);
    for (;;) vTaskDelay(portMAX_DELAY);
}
