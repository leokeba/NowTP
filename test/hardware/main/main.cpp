// On-target smoke test for NowTP. Needs a single board; no peer required.
//
// 1. Runs the protocol engine on the chip over the simulated lossy network
//    used by the host tests (real compiler, heap and CPU).
// 2. Exercises EspNowTransport against the real ESP-NOW driver: start/stop,
//    broadcast pacing and throughput, unicast failure reporting, queue limits,
//    cancellation, poll mode and API misuse.
//
// Results are printed as "PASS <name>" / "FAIL <name>: ..." lines followed by
// "DONE pass=<n> fail=<n>".
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>

#include "NowTP.h"
#include "nowtp/crypto.h"
#include "esp_event.h"
#include "esp_idf_version.h"
#include "esp_now.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "sim.h"

using nowtp::Mac;
using nowtp::Status;

namespace {

int g_pass = 0;
int g_fail = 0;

void report(const char* name, bool ok, const char* detail = "");
void report(const char* name, bool ok, const std::string& detail) {
    report(name, ok, detail.c_str());
}

void report(const char* name, bool ok, const char* detail) {
    if (ok) {
        g_pass++;
        printf("PASS %s %s\n", name, detail);
    } else {
        g_fail++;
        printf("FAIL %s: %s\n", name, detail);
    }
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

// Completion tracker shared with the NowTP task.
struct Outcome {
    volatile bool done = false;
    volatile Status status = Status::Ok;
    nowtp::CompletionHandler handler() {
        return [this](Status s) {
            status = s;
            done = true;
        };
    }
    bool wait(int timeoutMs) {
        int64_t end = millis() + timeoutMs;
        while (!done && millis() < end) vTaskDelay(1);
        return done;
    }
};

void startWifi() {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE));
}

// ---------------------------------------------------------------------------
// Engine on target, simulated radio

// Crypto on the chip: test vectors (real compiler and CPU), and timings.
void cryptoOnTarget() {
    using namespace nowtp::crypto;
    uint8_t out[32];
    sha256(reinterpret_cast<const uint8_t*>("abc"), 3, out);
    const uint8_t abc[4] = {0xba, 0x78, 0x16, 0xbf};
    report("sha256_vector", memcmp(out, abc, 4) == 0);

    uint8_t a[32] = {0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                     0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a};
    uint8_t pub[32];
    int64_t t0 = esp_timer_get_time();
    x25519Base(pub, a);
    int64_t x25519Us = esp_timer_get_time() - t0;
    const uint8_t apub[4] = {0x85, 0x20, 0xf0, 0x09};
    report("x25519_vector", memcmp(pub, apub, 4) == 0, fmt("(%lld ms)", (long long)(x25519Us / 1000)));

    std::vector<uint8_t> msg(16000, 0x5a);
    uint8_t key[32] = {1};
    t0 = esp_timer_get_time();
    for (int i = 0; i < 10; ++i) hmacSha256(key, sizeof(key), msg.data(), msg.size(), out);
    int64_t us = (esp_timer_get_time() - t0) / 10;
    report("hmac_16k_speed", us > 0, fmt("(%lld us per 16 KB = %.0f KB/s)", (long long)us, 16000.0 / 1024 / (us / 1e6)));
}

void engineOnTarget() {
    sim::Network net(42);
    net.appLoss = 0.2;
    net.airLoss = 0.05;
    size_t a = net.addNode(), b = net.addNode();
    std::vector<uint8_t> received;
    net.engine(b).listen(1, [&](const nowtp::Message& m) { received.assign(m.data, m.data + m.len); });

    std::vector<uint8_t> msg(16 * 1024);
    for (size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<uint8_t>(i * 7 + 3);
    nowtp::SendOptions opts;
    opts.reliable = true;
    Status result = Status::Cancelled;
    bool done = false;
    int64_t start = esp_timer_get_time();
    net.engine(a).send(net.mac(b), 1, msg.data(), msg.size(), opts,
                       [&](Status s) {
                           result = s;
                           done = true;
                       },
                       net.now());
    net.runUntil([&] { return done; }, 20000);
    int64_t us = esp_timer_get_time() - start;

    char detail[96];
    snprintf(detail, sizeof(detail), "(16 KB, 20%% loss: %s, %lu retransmissions, %lld us CPU)",
             nowtp::toString(result), (unsigned long)net.engine(a).stats().retransmissions, (long long)us);
    report("engine_reliable_16k_lossy", done && result == Status::Ok && received == msg, detail);
}

// ---------------------------------------------------------------------------
// Real ESP-NOW driver

nowtp::EspNowTransport transport;
const Mac kAbsent = {{0x02, 0x00, 0x00, 0x12, 0x34, 0x56}};  // locally administered, nobody answers

void beginEnd() {
    Status st = transport.begin();
    report("begin", st == Status::Ok, nowtp::toString(st));
    report("begin_twice_rejected", transport.begin() == Status::InvalidState);

    uint8_t mac[6];
    esp_wifi_get_mac(WIFI_IF_STA, mac);
    report("local_mac", transport.localMac() == Mac::from(mac));
}

void broadcastSingleAndFragmented() {
    const size_t sizes[] = {1, 245, 246, 3000, 16 * 1024};
    for (size_t n : sizes) {
        std::vector<uint8_t> msg(n, 0xA5);
        nowtp::Stats before = transport.stats();
        Outcome out;
        Status st = transport.send(Mac::broadcast(), 1, msg.data(), msg.size(), nowtp::SendOptions(), out.handler());
        bool ok = st == Status::Ok && out.wait(2000) && out.status == Status::Ok;
        nowtp::Stats after = transport.stats();
        uint32_t frames = after.framesSent - before.framesSent;
        size_t expected = n <= 245 ? 1 : (n + 4 + 240) / 241;
        char name[48], detail[64];
        snprintf(name, sizeof(name), "broadcast_%u_bytes", (unsigned)n);
        snprintf(detail, sizeof(detail), "(%lu frames, expected %u)", (unsigned long)frames, (unsigned)expected);
        report(name, ok && frames == expected && after.framesFailed == before.framesFailed, detail);
    }
}

void broadcastThroughput(uint16_t frameSize) {
    if (frameSize > 250) {
        nowtp::PeerOptions po;
        po.maxFrameSize = frameSize;
        if (transport.addPeer(Mac::broadcast(), po) != Status::Ok) {
            report("throughput_v2", false, "addPeer(broadcast, 1470) failed");
            return;
        }
    }
    std::vector<uint8_t> msg(8000, 0x5A);
    const int count = 40;
    int okCount = 0, queued = 0;
    std::vector<Outcome> outs(count);
    int64_t start = millis();
    for (int i = 0; i < count; ++i) {
        Status st;
        while ((st = transport.send(Mac::broadcast(), 1, msg.data(), msg.size(), nowtp::SendOptions(),
                                    outs[i].handler())) == Status::QueueFull) {
            vTaskDelay(1);
        }
        if (st == Status::Ok) queued++;
    }
    for (int i = 0; i < count; ++i) {
        if (outs[i].wait(10000) && outs[i].status == Status::Ok) okCount++;
    }
    int64_t ms = millis() - start;
    char name[40], detail[96];
    snprintf(name, sizeof(name), "broadcast_throughput_%u", frameSize);
    snprintf(detail, sizeof(detail), "(%d x 8000 B in %lld ms = %.1f KB/s, dropped events %lu)", count, (long long)ms,
             count * 8000.0 / 1024.0 / (ms / 1000.0), (unsigned long)transport.droppedEvents());
    report(name, queued == count && okCount == count, detail);

    if (frameSize > 250) {
        nowtp::PeerOptions po;  // back to the default size
        transport.addPeer(Mac::broadcast(), po);
    }
}

void unicastToAbsentPeer() {
    std::vector<uint8_t> msg(1000, 1);
    nowtp::Stats before = transport.stats();
    Outcome out;
    int64_t start = millis();
    Status st = transport.send(kAbsent, 1, msg.data(), msg.size(), nowtp::SendOptions(), out.handler());
    bool done = out.wait(3000);
    char detail[96];
    snprintf(detail, sizeof(detail), "(%s after %lld ms, %lu frames failed)", nowtp::toString(out.status),
             (long long)(millis() - start), (unsigned long)(transport.stats().framesFailed - before.framesFailed));
    report("unicast_absent_send_failed", st == Status::Ok && done && out.status == Status::SendFailed, detail);

    Outcome rel;
    nowtp::SendOptions opts;
    opts.reliable = true;
    start = millis();
    st = transport.send(kAbsent, 1, msg.data(), msg.size(), opts, rel.handler());
    done = rel.wait(3000);
    snprintf(detail, sizeof(detail), "(%s after %lld ms)", nowtp::toString(rel.status), (long long)(millis() - start));
    report("reliable_absent_send_failed", st == Status::Ok && done && rel.status == Status::SendFailed, detail);

    report("reliable_broadcast_rejected",
           transport.send(Mac::broadcast(), 1, msg.data(), msg.size(), opts) == Status::InvalidArgument);
}

void sendAndWaitBehaviour() {
    uint8_t x[600] = {};
    Status st = transport.sendAndWait(Mac::broadcast(), 1, x, sizeof(x));
    report("send_and_wait_broadcast", st == Status::Ok, nowtp::toString(st));

    // From inside a NowTP callback it must refuse instead of deadlocking.
    Outcome inner;
    volatile Status nested = Status::Ok;
    transport.send(Mac::broadcast(), 1, x, 10, nowtp::SendOptions(), [&](Status) {
        nested = transport.sendAndWait(Mac::broadcast(), 1, x, 10);
        inner.done = true;
    });
    inner.wait(1000);
    report("send_and_wait_in_callback_refused", inner.done && nested == Status::InvalidState,
           nowtp::toString(nested));
}

void queueLimitsAndLatest() {
    std::vector<uint8_t> msg(3000, 2);
    std::vector<Outcome> outs(9);
    int accepted = 0;
    Status last = Status::Ok;
    for (auto& o : outs) {
        last = transport.send(Mac::broadcast(), 1, msg.data(), msg.size(), nowtp::SendOptions(), o.handler());
        if (last == Status::Ok) accepted++;
    }
    report("queue_full_after_8", accepted == 8 && last == Status::QueueFull);
    for (int i = 0; i < accepted; ++i) outs[i].wait(3000);

    nowtp::SendOptions latest;
    latest.latestOnly = true;
    std::vector<Outcome> lo(20);
    int superseded = 0, okCount = 0;
    for (auto& o : lo) transport.send(Mac::broadcast(), 2, msg.data(), msg.size(), latest, o.handler());
    for (auto& o : lo) {
        o.wait(3000);
        superseded += o.status == Status::Superseded;
        okCount += o.status == Status::Ok;
    }
    char detail[64];
    snprintf(detail, sizeof(detail), "(%d superseded, %d sent)", superseded, okCount);
    report("latest_only_supersedes", superseded > 0 && lo.back().status == Status::Ok && superseded + okCount == 20,
           detail);
}

void endCancelsAndRestart() {
    std::vector<uint8_t> msg(8000, 3);
    std::vector<Outcome> outs(4);
    for (auto& o : outs) transport.send(Mac::broadcast(), 1, msg.data(), msg.size(), nowtp::SendOptions(), o.handler());
    transport.end();
    int cancelled = 0, completed = 0;
    for (auto& o : outs) {
        completed += o.done;
        cancelled += o.done && o.status == Status::Cancelled;
    }
    char detail[64];
    snprintf(detail, sizeof(detail), "(%d/4 completed, %d cancelled)", completed, cancelled);
    report("end_completes_pending", completed == 4 && cancelled >= 3, detail);
    report("send_after_end_rejected", transport.send(Mac::broadcast(), 1, msg.data(), 10) == Status::InvalidState);

    Status st = transport.begin();
    Outcome out;
    transport.send(Mac::broadcast(), 1, msg.data(), msg.size(), nowtp::SendOptions(), out.handler());
    report("restart_works", st == Status::Ok && out.wait(2000) && out.status == Status::Ok);
    transport.end();
}

void pollModeAndManualPeers() {
    nowtp::EspNowConfig cfg;
    cfg.runTask = false;
    cfg.autoAddPeers = false;
    Status st = transport.begin(cfg);
    report("begin_poll_mode", st == Status::Ok, nowtp::toString(st));

    std::vector<uint8_t> msg(5000, 4);
    Outcome out;
    transport.send(Mac::broadcast(), 1, msg.data(), msg.size(), nowtp::SendOptions(), out.handler());
    vTaskDelay(pdMS_TO_TICKS(100));
    bool doneWithoutPoll = out.done;  // nothing runs until poll()
    int64_t end = millis() + 2000;
    while (!out.done && millis() < end) {
        transport.poll();
        vTaskDelay(1);
    }
    report("poll_mode_progresses_only_in_poll", !doneWithoutPoll && out.done && out.status == Status::Ok);
    report("poll_mode_send_and_wait_refused", transport.sendAndWait(Mac::broadcast(), 1, msg.data(), 10) ==
                                                  Status::InvalidState);

    report("unknown_peer_rejected_without_auto_add",
           transport.send(kAbsent, 1, msg.data(), 10) == Status::LinkError);
    nowtp::PeerOptions po;
    report("add_peer", transport.addPeer(kAbsent, po) == Status::Ok);
    report("remove_peer", transport.removePeer(kAbsent) == Status::Ok);
    transport.end();
}

// Raw driver behaviour, without NowTP: how long the send callback takes to
// report a unicast frame nobody acknowledges.
volatile int64_t g_rawCbAt = 0;
volatile int g_rawCbStatus = -1;
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 5, 0)
void rawSent(const esp_now_send_info_t*, esp_now_send_status_t status) {
#else
void rawSent(const uint8_t*, esp_now_send_status_t status) {
#endif
    g_rawCbStatus = status;
    g_rawCbAt = esp_timer_get_time();
}

void rawDriverLatency() {
    ESP_ERROR_CHECK(esp_now_init());
    esp_now_register_send_cb(rawSent);
    esp_now_peer_info_t peer;
    memset(&peer, 0, sizeof(peer));
    memcpy(peer.peer_addr, kAbsent.bytes, 6);
    peer.ifidx = WIFI_IF_STA;
    esp_now_add_peer(&peer);
    uint8_t data[250] = {};
    for (int i = 0; i < 3; ++i) {
        g_rawCbAt = 0;
        int64_t start = esp_timer_get_time();
        esp_err_t err = esp_now_send(kAbsent.bytes, data, sizeof(data));
        while (g_rawCbAt == 0 && esp_timer_get_time() - start < 2000000) vTaskDelay(1);
        printf("INFO raw unicast to absent peer: send=%s callback status=%d after %lld us\n", esp_err_to_name(err),
               g_rawCbStatus, (long long)(g_rawCbAt ? g_rawCbAt - start : -1));
    }
    esp_now_deinit();
}

void noLeakAcrossRestarts() {
    std::vector<uint8_t> msg(3000, 9);
    size_t heapAfterWarmup = 0;
    for (int i = 0; i < 20; ++i) {
        transport.begin();
        transport.listen(1, [](const nowtp::Message&) {});
        transport.sendAndWait(Mac::broadcast(), 1, msg.data(), msg.size());
        transport.send(kAbsent, 1, msg.data(), msg.size());  // auto-added peer, left in flight
        transport.end();
        if (i == 1) heapAfterWarmup = esp_get_free_heap_size();
    }
    size_t heapNow = esp_get_free_heap_size();
    char detail[80];
    snprintf(detail, sizeof(detail), "(free heap %u after 2 cycles, %u after 20)", (unsigned)heapAfterWarmup,
             (unsigned)heapNow);
    report("no_leak_across_restarts", heapNow + 512 >= heapAfterWarmup, detail);
}

// begin() with each starting state of the radio that one board can produce.
void radioSetupModes() {
    wifi_mode_t mode;
    nowtp::EspNowConfig noInit;
    noInit.radio.initWifi = false;
    report("radio_init_disabled_rejected", transport.begin(noInit) == Status::InvalidState);

    // Nothing set up: NowTP initializes Wi-Fi and tears it down again.
    Status st = transport.begin();
    nowtp::RadioInfo r = transport.radioInfo();
    report("radio_auto_init", st == Status::Ok && r.wifiStartedByNowTP && r.channel == 1 && r.interface == WIFI_IF_STA,
           nowtp::toString(st));
    transport.end();
    report("radio_auto_init_released", esp_wifi_get_mode(&mode) == ESP_ERR_WIFI_NOT_INIT);

    // Initialized by the application but not started: NowTP starts it, then stops it again.
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    nowtp::EspNowConfig ch5;
    ch5.radio.channel = 5;
    st = transport.begin(ch5);
    r = transport.radioInfo();
    report("radio_started_for_app", st == Status::Ok && r.wifiStartedByNowTP && r.channel == 5, nowtp::toString(st));
    transport.end();
    uint16_t n;
    report("radio_start_undone", esp_wifi_get_mode(&mode) == ESP_OK &&
                                     esp_wifi_scan_get_ap_num(&n) == ESP_ERR_WIFI_NOT_STARTED);
    ESP_ERROR_CHECK(esp_wifi_deinit());
}

// Settings NowTP changes on an application's Wi-Fi come back on end().
void radioSettingsRestored() {
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
    esp_wifi_set_max_tx_power(60);  // 15 dBm; some chips round it down
    int8_t appPower = 0;
    esp_wifi_get_max_tx_power(&appPower);
    char appCountry[4] = {0, 0, 0, 0};
    esp_wifi_get_country_code(appCountry);
    uint8_t appProtocol = 0;
    esp_wifi_get_protocol(WIFI_IF_STA, &appProtocol);

    nowtp::EspNowConfig bad;
    bad.radio.txPowerDbm = 30;
    report("radio_bad_power_rejected", transport.begin(bad) == Status::InvalidArgument);
    bad = nowtp::EspNowConfig();
    bad.radio.unicastRate = nowtp::PhyRate::LR250K;  // without longRange
    report("radio_lr_rate_needs_long_range", transport.begin(bad) == Status::InvalidArgument);
    report("set_power_before_begin_rejected", transport.setTxPower(10) == Status::InvalidState);

    nowtp::EspNowConfig cfg;
    cfg.radio.txPowerDbm = 10;
    cfg.radio.longRange = true;
    cfg.radio.unicastRate = nowtp::PhyRate::B11M;
    cfg.radio.broadcastRate = nowtp::PhyRate::B2M;
    memcpy(cfg.radio.countryCode, "JP", 2);
    Status st = transport.begin(cfg);
    nowtp::RadioInfo r = transport.radioInfo();
    char country[4] = {0, 0, 0, 0};
    esp_wifi_get_country_code(country);
    wifi_ps_type_t ps = WIFI_PS_MAX_MODEM;
    esp_wifi_get_ps(&ps);
    report("radio_settings_applied",
           st == Status::Ok && r.txPowerDbm > 8.9f && r.txPowerDbm <= 10 && r.longRange && strncmp(country, "JP", 2) == 0 && ps == WIFI_PS_NONE,
           fmt("(%s, power %.2f dBm, LR %d, country %s, ps %d)", nowtp::toString(st), r.txPowerDbm, r.longRange,
               country, ps));

    nowtp::PeerOptions po;
    po.rate = nowtp::PhyRate::G54M;
    report("broadcast_peer_rate_rejected", transport.addPeer(Mac::broadcast(), po) == Status::InvalidArgument);
    report("peer_rate_set", transport.addPeer(kAbsent, po) == Status::Ok);
    report("runtime_rate_changes", transport.setUnicastRate(nowtp::PhyRate::MCS7) == Status::Ok &&
                                       transport.setBroadcastRate(nowtp::PhyRate::Default) == Status::Ok);
    uint8_t x[300] = {};
    report("send_with_custom_rates", transport.sendAndWait(Mac::broadcast(), 1, x, sizeof(x)) == Status::Ok);
    transport.end();

    int8_t power = 0;
    esp_wifi_get_max_tx_power(&power);
    uint8_t protocol = 0;
    esp_wifi_get_protocol(WIFI_IF_STA, &protocol);
    esp_wifi_get_country_code(country);
    esp_wifi_get_ps(&ps);
    report("radio_settings_restored",
           power == appPower && protocol == appProtocol && strncmp(country, appCountry, 2) == 0 && ps == WIFI_PS_MIN_MODEM,
           fmt("(power %.2f dBm, protocol 0x%x, country %s, ps %d)", power / 4.0, protocol, country, ps));
    esp_wifi_stop();
    ESP_ERROR_CHECK(esp_wifi_deinit());
}

// Diagnostics features that need no peer.
void diagnosticsAlone() {
    Status st = transport.begin();
    if (st != Status::Ok) {
        report("diag_begin", false, nowtp::toString(st));
        return;
    }
    nowtp::RadioInfo r = transport.radioInfo();
    report("radio_power_limit_known", r.txPowerLimitDbm >= 2 && r.txPowerLimitDbm <= 21,
           fmt("(limit %.2f dBm)", r.txPowerLimitDbm));
    report("set_channel", transport.setChannel(6) == Status::Ok && transport.channel() == 6);
    transport.setChannel(1);
    report("long_range_toggle", transport.setLongRange(true) == Status::Ok && transport.longRange() &&
                                    transport.setLongRange(false) == Status::Ok && !transport.longRange());
    report("lr_rate_needs_lr", !transport.rateUsable(nowtp::PhyRate::LR250K));

    int64_t t0 = millis();
    st = transport.ping(kAbsent);
    report("ping_absent_times_out", st == Status::Timeout, fmt("(%s after %lld ms)", nowtp::toString(st), (long long)(millis() - t0)));

    nowtp::DeepDiscoveryOptions o;
    o.channels = {1, 6};
    o.dwellMs = 500;
    nowtp::DeepDiscoveryReport report_;
    t0 = millis();
    st = transport.deepDiscover(report_, o);
    r = transport.radioInfo();
    report("deep_discovery_alone_restores_radio",
           st == Status::Ok && report_.homeChannel == 1 && r.channel == 1 && !r.longRange,
           fmt("(%u nodes, %u issues, %lld ms)", (unsigned)report_.nodes.size(), (unsigned)report_.issues.size(),
               (long long)(millis() - t0)));

    // From inside a NowTP callback the blocking calls must refuse.
    volatile Status nested = Status::Ok;
    volatile bool ran = false;
    transport.send(Mac::broadcast(), 1, "x", 1, nowtp::SendOptions(), [&](Status) {
        nowtp::LinkDiagnosis d;
        nested = transport.diagnose(kAbsent, d);
        ran = true;
    });
    int64_t end = millis() + 1000;
    while (!ran && millis() < end) vTaskDelay(1);
    report("diagnose_in_callback_refused", ran && nested == Status::InvalidState);
    transport.end();
}

}  // namespace

extern "C" void app_main() {
    vTaskDelay(pdMS_TO_TICKS(1500));  // let the serial monitor attach
    printf("\nNOWTP HARDWARE TEST, ESP-NOW max frame %u, free heap %lu\n", nowtp::EspNowTransport::maxSupportedFrameSize(),
           (unsigned long)esp_get_free_heap_size());

    cryptoOnTarget();
    engineOnTarget();

    radioSetupModes();
    radioSettingsRestored();
    startWifi();
    printf("INFO free heap after Wi-Fi start %lu\n", (unsigned long)esp_get_free_heap_size());
    rawDriverLatency();
    beginEnd();
    broadcastSingleAndFragmented();
    broadcastThroughput(250);
    broadcastThroughput(1470);
    unicastToAbsentPeer();
    sendAndWaitBehaviour();
    queueLimitsAndLatest();
    endCancelsAndRestart();
    pollModeAndManualPeers();
    noLeakAcrossRestarts();
    diagnosticsAlone();

    printf("free heap after tests %lu\n", (unsigned long)esp_get_free_heap_size());
    printf("DONE pass=%d fail=%d\n", g_pass, g_fail);
    for (;;) vTaskDelay(portMAX_DELAY);
}
