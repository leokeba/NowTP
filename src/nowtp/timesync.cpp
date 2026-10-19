// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "timesync.h"

#include <string.h>

namespace nowtp {

namespace {

constexpr size_t kMaxSamples = 8;
constexpr size_t kMaxOffers = 16;     // peers acting as the reference or offering to, tracked
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

const char* toString(TimeRole role) {
    switch (role) {
        case TimeRole::Off:
            return "off";
        case TimeRole::Follow:
            return "follow";
        case TimeRole::Candidate:
            return "candidate";
        case TimeRole::Reference:
            return "reference";
    }
    return "?";
}

TimeSync::TimeSync(Engine& engine, Clock localClockUs, const TimeSyncConfig& config, const Mac& localMac)
    : engine_(engine),
      clock_(std::move(localClockUs)),
      config_(config),
      self_(localMac),
      role_(config.reference ? TimeRole::Reference : config.role) {
    if (config_.samples == 0) config_.samples = 1;
    // Both grow on what the network does: reserved here, never grown.
    samples_.reserve(kMaxSamples);
    offers_.reserve(kMaxOffers);
    if (config_.intervalMs < kFastIntervalMs) config_.intervalMs = kFastIntervalMs;
    acting_ = role_ == TimeRole::Reference;
}

TimeSync::~TimeSync() {
    stop();
}

void TimeSync::setDiscovery(Discovery* discovery) {
    discovery_ = discovery;
    published_ = -1;
    publish();
}

void TimeSync::start(uint32_t now) {
    running_ = true;
    now_ = now;
    nextRoundAt_ = now;
    vacant_ = true;  // a candidate listens for a reference before taking over
    vacantSince_ = now;
    engine_.listen(kTimeSyncPort, [this](const Message& m) { handle(m); });
    evaluate(now);
}

void TimeSync::stop() {
    if (!running_) return;
    engine_.listen(kTimeSyncPort, ReceiveHandler());
    running_ = false;
    roundActive_ = false;
}

// ---------------------------------------------------------------------------
// Roles and reference selection

void TimeSync::onPeerEvent(PeerEvent event, const PeerInfo& peer, uint32_t now) {
    bool offers = event != PeerEvent::Lost && (peer.timeReference || peer.timeCandidate);
    size_t i = 0;
    while (i < offers_.size() && offers_[i].mac != peer.mac) ++i;
    if (!offers) {
        if (i < offers_.size()) offers_.erase(offers_.begin() + static_cast<std::ptrdiff_t>(i));
    } else {
        Offer o = {peer.mac, peer.timeReference, peer.timeCandidate, peer.timeSynced};
        if (i < offers_.size()) {
            offers_[i] = o;
        } else if (offers_.size() < kMaxOffers) {
            offers_.push_back(o);
        } else {
            // Full: keep the acting ones, and the candidates first in line (lowest MACs).
            size_t victim = offers_.size();
            for (size_t j = 0; j < offers_.size(); ++j) {
                if (offers_[j].acting) continue;
                if (victim == offers_.size() || lessMac(offers_[victim].mac, offers_[j].mac)) victim = j;
            }
            if (victim < offers_.size() && (o.acting || lessMac(o.mac, offers_[victim].mac))) offers_[victim] = o;
        }
    }
    evaluate(now);
}

void TimeSync::setRole(TimeRole role, uint32_t now) {
    role_ = role;
    evaluate(now);
}

void TimeSync::setReference(const Mac& mac, uint32_t now) {
    explicitRef_ = true;
    explicit_ = mac;
    evaluate(now);
}

void TimeSync::clearReference(uint32_t now) {
    explicitRef_ = false;
    evaluate(now);
}

void TimeSync::setInterval(uint32_t ms) {
    config_.intervalMs = ms < kFastIntervalMs ? kFastIntervalMs : ms;
    uint32_t next = now_ + config_.intervalMs;
    if (!roundActive_ && static_cast<int32_t>(nextRoundAt_ - next) > 0) nextRoundAt_ = next;
}

// The acting reference a follower takes: one configured as the reference
// before an acting candidate, then the lowest MAC.
const TimeSync::Offer* TimeSync::bestActing() const {
    const Offer* best = nullptr;
    for (const Offer& o : offers_) {
        if (!o.acting) continue;
        if (!best || (best->candidate && !o.candidate) ||
            (best->candidate == o.candidate && lessMac(o.mac, best->mac))) {
            best = &o;
        }
    }
    return best;
}

// Candidates take over in turn: synchronized ones first, which keep the
// network time, then the lowest MAC.
bool TimeSync::aheadOfUs(const Offer& o) const {
    bool us = synced();
    if (o.synced != us) return o.synced;
    return lessMac(o.mac, self_);
}

void TimeSync::evaluate(uint32_t now) {
    now_ = now;
    if (role_ == TimeRole::Off) {
        if (acting_) act(false, now);
        forget();
    } else if (role_ == TimeRole::Reference) {
        act(true, now);
    } else if (explicitRef_) {
        act(false, now);
        if (!haveRef_ || ref_ != explicit_) switchTo(explicit_, now);
    } else {
        const Offer* best = bestActing();
        // Two references: an acting candidate gives way to a configured
        // reference, or to a candidate with a lower MAC.
        if (acting_ && !(role_ == TimeRole::Candidate && (!best || (best->candidate && lessMac(self_, best->mac))))) {
            act(false, now);
        }
        if (!acting_ && best) {
            vacant_ = false;
            if (!haveRef_ || ref_ != best->mac) switchTo(best->mac, now);
        } else if (!acting_) {
            // The estimate stays usable (with drift) until it goes stale.
            // Rounds stop: requests to an absent node hold the radio ~100 ms
            // each and would delay the first rounds with the next reference.
            haveRef_ = false;
            if (!vacant_) {
                vacant_ = true;
                vacantSince_ = now;
            }
            if (role_ == TimeRole::Candidate && running_) {
                uint32_t ahead = 0;
                for (const Offer& o : offers_) {
                    if (o.candidate && aheadOfUs(o)) ahead++;
                }
                if (reached(now, vacantSince_ + config_.takeoverAfterMs * (ahead + 1))) act(true, now);
            }
        }
    }
    publish();
}

void TimeSync::act(bool acting, uint32_t now) {
    if (acting == acting_) return;
    acting_ = acting;
    roundActive_ = false;
    if (acting) {
        // Keeps serving the network time it had: the estimate, extrapolated
        // with the drift and no longer updated (none: the local clock).
        haveRef_ = false;
        return;
    }
    // What it served as the network time is where its estimate starts.
    uint64_t local = clock_();
    if (haveEstimate_) {
        base_ = offsetAt(local);
    } else {
        base_ = 0;
        drift_ = 0;
        haveEstimate_ = true;
    }
    baseLocal_ = local;
    lastSyncLocal_ = local;
    carried_ = true;
    samples_.clear();
    rounds_ = 0;
    rejected_ = 0;
    vacant_ = true;
    vacantSince_ = now;
    nextRoundAt_ = now;
}

void TimeSync::publish() {
    if (!discovery_) return;
    bool candidate = role_ == TimeRole::Candidate && !explicitRef_;
    bool isSynced = synced();
    int flags = (acting_ ? 1 : 0) | (candidate ? 2 : 0) | (isSynced ? 4 : 0);
    if (flags == published_) return;
    published_ = flags;
    discovery_->setTimeState(acting_, candidate, isSynced);
}

// A new reference serves the same network time when it was synchronized (or
// is the one we follow through a chain): the estimate is kept, and the first
// round corrects it. A reference with another time base replaces it then.
void TimeSync::switchTo(const Mac& mac, uint32_t now) {
    haveRef_ = true;
    ref_ = mac;
    carried_ = haveEstimate_;
    samples_.clear();
    rounds_ = 0;
    rejected_ = 0;
    roundActive_ = false;
    nextRoundAt_ = now;
}

void TimeSync::forget() {
    haveRef_ = false;
    ref_ = Mac();
    samples_.clear();
    haveEstimate_ = false;
    carried_ = false;
    minRtt_ = 0;
    drift_ = 0;
    rounds_ = 0;
    rejected_ = 0;
    lastRtt_ = 0;
    roundActive_ = false;
}

// ---------------------------------------------------------------------------
// Rounds

void TimeSync::tick(uint32_t now) {
    now_ = now;
    if (!running_) return;
    evaluate(now);  // a candidate's takeover is due by time
    if (acting_ || role_ == TimeRole::Off || !haveRef_) return;
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
    // type | round | index | t1 (8), padded to the response's length: both
    // directions then take the same air time, which the offset assumes.
    uint8_t msg[27];
    memset(msg, 0, sizeof(msg));
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
        // Answered in our network time: the reference's clock, if we follow one
        // (or the one we serve). A node set to synchronize with us thereby
        // joins the same network time.
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
    bool taken = addSample(bestLocal_, bestOffset_, bestRtt_);
    nextRoundAt_ = now + (!taken || rounds_ < kFastRounds ? kFastIntervalMs : config_.intervalMs);
}

bool TimeSync::addSample(uint64_t localUs, int64_t offsetUs, uint32_t rttUs) {
    // A slow round was queued behind other traffic (or failed frames, which
    // hold the radio ~100 ms): the delay is on one side, and half of it goes
    // into the offset. Such rounds are skipped; the threshold relaxes with
    // each one, so a lasting change (e.g. a slower rate) is taken in the end.
    if (minRtt_ != 0 && rttUs > 2 * minRtt_ + 1500) {
        minRtt_ += minRtt_ / 8 + 1;
        return false;
    }
    if (haveEstimate_ && (samples_.size() >= 3 || carried_)) {
        // A sample far from the prediction is a delayed exchange, or the
        // reference rebooted; after a few in a row, believe them.
        int64_t error = offsetUs - offsetAt(localUs);
        int64_t tolerance = 2000 + 4 * static_cast<int64_t>(rttUs);
        if (error > tolerance || error < -tolerance) {
            if (++rejected_ < kRejectLimit) return false;
            samples_.clear();
            drift_ = 0;
            carried_ = false;
        }
    }
    rejected_ = 0;
    if (minRtt_ == 0 || rttUs < minRtt_) minRtt_ = rttUs;
    if (samples_.size() >= kMaxSamples) samples_.erase(samples_.begin());
    Sample s = {localUs, offsetUs};
    samples_.push_back(s);
    lastSyncLocal_ = localUs;
    lastRtt_ = rttUs;
    rounds_++;
    fit();
    return true;
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
    if (acting_) return true;
    if (!haveEstimate_) return false;
    return clock_() - lastSyncLocal_ < static_cast<uint64_t>(config_.staleAfterMs) * 1000;
}

uint64_t TimeSync::toNetwork(uint64_t localUs) const {
    return localUs + static_cast<uint64_t>(offsetAt(localUs));
}

uint64_t TimeSync::toLocal(uint64_t networkUs) const {
    if (!haveEstimate_) return networkUs;
    // The offset barely changes over the gap, so evaluating it near the answer is exact enough.
    uint64_t guess = networkUs - static_cast<uint64_t>(base_);
    return networkUs - static_cast<uint64_t>(offsetAt(guess));
}

TimeSyncStatus TimeSync::status() const {
    TimeSyncStatus s;
    s.role = role_;
    s.isReference = acting_;
    s.explicitReference = explicitRef_ && !acting_ && role_ != TimeRole::Off;
    s.synced = synced();
    s.reference = acting_ ? self_ : ref_;
    uint64_t now = clock_();
    s.offsetUs = offsetAt(now);
    s.driftPpm = static_cast<float>(drift_ * 1e6);
    s.rounds = rounds_;
    if (!acting_) {
        s.roundTripUs = lastRtt_;
        s.ageMs = haveEstimate_ ? static_cast<uint32_t>((now - lastSyncLocal_) / 1000) : 0;
    }
    return s;
}

}  // namespace nowtp
