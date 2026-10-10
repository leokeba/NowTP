// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "timesync.h"

#include <string.h>

namespace nowtp {

namespace {

constexpr size_t kMaxSamples = 8;
constexpr uint32_t kRoundGraceMs = 300;   // wait for late responses after the last request
constexpr uint32_t kFastRounds = 3;       // first rounds run every second
constexpr uint32_t kFastIntervalMs = 1000;
constexpr double kMaxDrift = 500e-6;      // crystals are within ±50 ppm; anything more is noise
constexpr uint64_t kMinFitSpanUs = 2000000;
constexpr uint8_t kRejectLimit = 3;       // consecutive outliers that mean the reference's clock jumped

inline bool reached(uint32_t now, uint32_t deadline) {
    return static_cast<int32_t>(now - deadline) >= 0;
}

void putU64(uint8_t* p, uint64_t v) {
    wire::putU32(p, static_cast<uint32_t>(v));
    wire::putU32(p + 4, static_cast<uint32_t>(v >> 32));
}

uint64_t getU64(const uint8_t* p) {
    return wire::getU32(p) | (static_cast<uint64_t>(wire::getU32(p + 4)) << 32);
}

bool lessMac(const Mac& a, const Mac& b) {
    return memcmp(a.bytes, b.bytes, sizeof(a.bytes)) < 0;
}

}  // namespace

TimeSync::TimeSync(Engine& engine, Clock localClockUs, const TimeSyncConfig& config)
    : engine_(engine), clock_(std::move(localClockUs)), config_(config) {
    if (config_.samples == 0) config_.samples = 1;
    if (config_.intervalMs < kFastIntervalMs) config_.intervalMs = kFastIntervalMs;
}

TimeSync::~TimeSync() {
    stop();
}

void TimeSync::start(uint32_t now) {
    running_ = true;
    nextRoundAt_ = now;
    engine_.listen(kTimeSyncPort, [this](const Message& m) { handle(m); });
}

void TimeSync::stop() {
    if (!running_) return;
    engine_.listen(kTimeSyncPort, ReceiveHandler());
    running_ = false;
    roundActive_ = false;
}

// ---------------------------------------------------------------------------
// Reference selection

void TimeSync::onPeerEvent(PeerEvent event, const PeerInfo& peer, uint32_t now) {
    bool listed = false;
    for (size_t i = 0; i < announced_.size(); ++i) {
        if (announced_[i] != peer.mac) continue;
        listed = true;
        if (event == PeerEvent::Lost || !peer.timeReference) {
            announced_.erase(announced_.begin() + static_cast<std::ptrdiff_t>(i));
        }
        break;
    }
    if (!listed && event != PeerEvent::Lost && peer.timeReference) announced_.push_back(peer.mac);
    chooseReference(now);
}

void TimeSync::chooseReference(uint32_t now) {
    if (explicitRef_ || config_.reference) return;
    if (announced_.empty()) {
        // Keep the estimate: it stays usable (with drift) until it goes stale.
        return;
    }
    Mac best = announced_.front();
    for (const Mac& m : announced_) {
        if (lessMac(m, best)) best = m;
    }
    if (!haveRef_ || best != ref_) switchTo(best, true, now);
}

void TimeSync::setReference(const Mac& mac, uint32_t now) {
    explicitRef_ = true;
    if (!haveRef_ || mac != ref_) switchTo(mac, true, now);
}

void TimeSync::clearReference(uint32_t now) {
    explicitRef_ = false;
    chooseReference(now);
}

void TimeSync::switchTo(const Mac& mac, bool known, uint32_t now) {
    haveRef_ = known;
    ref_ = mac;
    samples_.clear();
    haveEstimate_ = false;
    drift_ = 0;
    rounds_ = 0;
    rejected_ = 0;
    roundActive_ = false;
    nextRoundAt_ = now;
}

// ---------------------------------------------------------------------------
// Rounds

void TimeSync::tick(uint32_t now) {
    now_ = now;
    if (!running_ || config_.reference || !haveRef_) return;
    if (!roundActive_) {
        if (!reached(now, nextRoundAt_)) return;
        roundActive_ = true;
        round_++;
        sent_ = 0;
        haveBest_ = false;
        nextSampleAt_ = now;
    }
    if (sent_ < config_.samples) {
        if (reached(now, nextSampleAt_)) sendRequest(now);
        return;
    }
    if (reached(now, lastSentAt_ + kRoundGraceMs)) endRound(now);
}

void TimeSync::sendRequest(uint32_t now) {
    // type | round | index | t1 (8)
    uint8_t msg[11];
    msg[0] = kRequest;
    msg[1] = round_;
    msg[2] = sent_;
    putU64(msg + 3, clock_());
    Status st = engine_.send(ref_, kTimeSyncPort, msg, sizeof(msg), SendOptions(), CompletionHandler(), now);
    if (st == Status::QueueFull) {
        nextSampleAt_ = now + 2;
        return;
    }
    sent_++;
    lastSentAt_ = now;
    nextSampleAt_ = now + config_.sampleSpacingMs;
}

void TimeSync::handle(const Message& m) {
    if (m.len < 1) return;
    const uint8_t* d = m.data;
    if (d[0] == kRequest) {
        if (!config_.respond || m.len < 11) return;
        uint64_t t2 = m.timestampUs ? m.timestampUs : clock_();
        // Answered in our network time: the reference's clock, if we follow one.
        // A node set to synchronize with us thereby joins the same network time.
        bool chained = synced();
        uint8_t out[27];
        out[0] = kResponse;
        out[1] = d[1];
        out[2] = d[2];
        memcpy(out + 3, d + 3, 8);
        putU64(out + 11, chained ? toNetwork(t2) : t2);
        uint64_t t3 = clock_();
        putU64(out + 19, chained ? toNetwork(t3) : t3);
        engine_.send(m.src, kTimeSyncPort, out, sizeof(out), SendOptions(), CompletionHandler(), now_);
        return;
    }
    if (d[0] != kResponse || m.len < 27) return;
    uint64_t t4 = m.timestampUs ? m.timestampUs : clock_();
    if (!roundActive_ || !haveRef_ || m.src != ref_ || d[1] != round_) return;
    uint64_t t1 = getU64(d + 3);
    uint64_t t2 = getU64(d + 11);
    uint64_t t3 = getU64(d + 19);
    int64_t rtt = static_cast<int64_t>(t4 - t1) - static_cast<int64_t>(t3 - t2);
    if (t4 < t1 || rtt < 0 || rtt > 1000000) return;
    // Offset = reference clock - local clock, assuming symmetric delays.
    int64_t offset = (static_cast<int64_t>(t2 - t1) + static_cast<int64_t>(t3 - t4)) / 2;
    if (!haveBest_ || static_cast<uint32_t>(rtt) < bestRtt_) {
        haveBest_ = true;
        bestRtt_ = static_cast<uint32_t>(rtt);
        bestOffset_ = offset;
        bestLocal_ = t1 + static_cast<uint64_t>(rtt / 2);
    }
}

void TimeSync::endRound(uint32_t now) {
    roundActive_ = false;
    if (!haveBest_) {
        nextRoundAt_ = now + kFastIntervalMs;
        return;
    }
    addSample(bestLocal_, bestOffset_, bestRtt_);
    nextRoundAt_ = now + (rounds_ < kFastRounds ? kFastIntervalMs : config_.intervalMs);
}

void TimeSync::addSample(uint64_t localUs, int64_t offsetUs, uint32_t rttUs) {
    if (haveEstimate_ && samples_.size() >= 3) {
        // A sample far from the prediction is a delayed exchange, or the
        // reference rebooted; after a few in a row, believe them.
        int64_t error = offsetUs - offsetAt(localUs);
        int64_t tolerance = 2000 + 4 * static_cast<int64_t>(rttUs);
        if (error > tolerance || error < -tolerance) {
            if (++rejected_ < kRejectLimit) return;
            samples_.clear();
            drift_ = 0;
        }
    }
    rejected_ = 0;
    if (samples_.size() >= kMaxSamples) samples_.erase(samples_.begin());
    Sample s = {localUs, offsetUs};
    samples_.push_back(s);
    lastSyncLocal_ = localUs;
    lastRtt_ = rttUs;
    rounds_++;
    fit();
}

void TimeSync::fit() {
    const Sample& last = samples_.back();
    uint64_t span = last.localUs - samples_.front().localUs;
    if (samples_.size() < 3 || span < kMinFitSpanUs) {
        // Too short a baseline to tell drift from noise: keep the previous drift.
        baseLocal_ = last.localUs;
        base_ = last.offsetUs;
        haveEstimate_ = true;
        return;
    }
    // Least squares around the latest sample, in double (relative values stay small).
    double n = static_cast<double>(samples_.size());
    double sx = 0, sy = 0, sxx = 0, sxy = 0;
    for (const Sample& s : samples_) {
        double x = -static_cast<double>(last.localUs - s.localUs);
        double y = static_cast<double>(s.offsetUs - last.offsetUs);
        sx += x;
        sy += y;
        sxx += x * x;
        sxy += x * y;
    }
    double denom = n * sxx - sx * sx;
    double slope = denom > 0 ? (n * sxy - sx * sy) / denom : 0;
    if (slope > kMaxDrift) slope = kMaxDrift;
    if (slope < -kMaxDrift) slope = -kMaxDrift;
    double intercept = (sy - slope * sx) / n;
    drift_ = slope;
    baseLocal_ = last.localUs;
    base_ = last.offsetUs + static_cast<int64_t>(intercept);
    haveEstimate_ = true;
}

int64_t TimeSync::offsetAt(uint64_t localUs) const {
    if (!haveEstimate_) return 0;
    double dt = localUs >= baseLocal_ ? static_cast<double>(localUs - baseLocal_)
                                      : -static_cast<double>(baseLocal_ - localUs);
    return base_ + static_cast<int64_t>(drift_ * dt);
}

// ---------------------------------------------------------------------------
// Queries

bool TimeSync::synced() const {
    if (config_.reference) return true;
    if (!haveEstimate_) return false;
    return clock_() - lastSyncLocal_ < static_cast<uint64_t>(config_.staleAfterMs) * 1000;
}

uint64_t TimeSync::toNetwork(uint64_t localUs) const {
    if (config_.reference) return localUs;
    return localUs + static_cast<uint64_t>(offsetAt(localUs));
}

uint64_t TimeSync::toLocal(uint64_t networkUs) const {
    if (config_.reference || !haveEstimate_) return networkUs;
    // The offset barely changes over the gap, so evaluating it near the answer is exact enough.
    uint64_t guess = networkUs - static_cast<uint64_t>(base_);
    return networkUs - static_cast<uint64_t>(offsetAt(guess));
}

TimeSyncStatus TimeSync::status() const {
    TimeSyncStatus s;
    s.isReference = config_.reference;
    s.synced = synced();
    s.reference = ref_;
    uint64_t now = clock_();
    s.offsetUs = config_.reference ? 0 : offsetAt(now);
    s.roundTripUs = lastRtt_;
    s.driftPpm = static_cast<float>(drift_ * 1e6);
    s.ageMs = haveEstimate_ ? static_cast<uint32_t>((now - lastSyncLocal_) / 1000) : 0;
    s.rounds = rounds_;
    return s;
}

}  // namespace nowtp
