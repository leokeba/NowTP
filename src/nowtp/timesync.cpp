// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "timesync.h"

#include <stdint.h>
#include <string.h>

#include <algorithm>

namespace nowtp {

namespace {

constexpr size_t kMaxSamples = 16;     // rounds in the fit: ~80 s at the 5 s interval
constexpr size_t kMaxOffers = 16;     // peers acting as the reference or offering to, tracked
constexpr uint32_t kRoundGraceMs = 300;   // wait for late responses after the last request
constexpr uint32_t kFastRounds = 8;       // first rounds run every second: a drift fit over a 7 s baseline
constexpr uint32_t kFastIntervalMs = 1000;
constexpr double kMaxDrift = 500e-6;      // crystals are within ±50 ppm; anything more is noise
constexpr uint64_t kMinFitSpanUs = 2000000;
constexpr uint8_t kRejectLimit = 3;       // consecutive outliers that mean the reference's clock jumped
constexpr size_t kRequestSize = 37;       // padded to the response's length
constexpr size_t kResponseSize = 37;      // with the previous response's send time
constexpr size_t kBasicResponseSize = 27; // from responders without send times
constexpr uint8_t kNoIndex = 0xFF;
constexpr uint8_t kMinStamped = 3;        // stamped exchanges a round needs to use them
constexpr size_t kCalibrationSize = 8;    // type | round | stamped | offset (int32) | pad
constexpr uint32_t kMinCalibrationMs = 5000;     // per follower, whatever it asks
constexpr uint32_t kCalibrationGapMs = 1000;     // between calibration rounds, at the reference
constexpr uint32_t kRequesterTimeoutMs = 30000;  // a follower not heard for this long isn't measured
constexpr int32_t kMaxBiasUs = 2000;             // implied biases beyond are discarded
constexpr uint8_t kMinCalibrations = 3;          // measurements before the first correction
constexpr int32_t kMaxBiasStepUs = 10;           // later corrections move by at most this much

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

constexpr size_t TimeSync::kMaxExchanges;
constexpr size_t TimeSync::kMaxAnswers;
constexpr size_t TimeSync::kMaxCalibrations;

TimeSync::TimeSync(Engine& engine, Clock localClockUs, const TimeSyncConfig& config, const Mac& localMac)
    : engine_(engine),
      clock_(std::move(localClockUs)),
      config_(config),
      self_(localMac),
      role_(config.reference ? TimeRole::Reference : config.role) {
    if (config_.samples == 0) config_.samples = 1;
    if (config_.samples > kMaxExchanges) config_.samples = static_cast<uint8_t>(kMaxExchanges);
    // Both grow on what the network does: reserved here, never grown.
    samples_.reserve(kMaxSamples);
    offers_.reserve(kMaxOffers);
    if (config_.intervalMs < kFastIntervalMs) config_.intervalMs = kFastIntervalMs;
    acting_ = role_ == TimeRole::Reference;
    for (Answer& a : answers_) a = Answer();  // a member array isn't zeroed by itself
}

TimeSync::~TimeSync() {
    stop();
    heap::release(exchanges_);
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
    engine_.setSentObserver([this](const Mac& dst, uint8_t port, uint32_t id, uint64_t sentUs) {
        if (port == kTimeSyncPort) onSent(dst, id, sentUs);
    });
    evaluate(now);
}

void TimeSync::stop() {
    if (!running_) return;
    engine_.listen(kTimeSyncPort, ReceiveHandler());
    engine_.setSentObserver(SentObserver());
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
        // with the drift and no longer updated (none: the local clock), its
        // calibration included.
        haveRef_ = false;
        base_ -= bias_;
        bias_ = 0;
        biasSet_ = false;
        impliedCount_ = 0;
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
    refStamps_ = false;
    carried_ = haveEstimate_;
    // The correction stays until the new reference's measurements replace it.
    biasSet_ = false;
    impliedCount_ = 0;
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
    bias_ = 0;
    biasSet_ = false;
    impliedCount_ = 0;
}

// ---------------------------------------------------------------------------
// Rounds

void TimeSync::tick(uint32_t now) {
    now_ = now;
    if (!running_) return;
    evaluate(now);  // a candidate's takeover is due by time
    if (role_ == TimeRole::Off || (!acting_ && !haveRef_)) return;
    if (!roundActive_) {
        if (!reached(now, nextRoundAt_)) return;
        if (acting_) {
            // The reference measures its followers that asked, in turn: a
            // round in the other direction (see calibrate()).
            Answer* due = nullptr;
            for (Answer& a : answers_) {
                if (!a.used || !a.calibrateEveryMs || !reached(now, a.nextCalibrationMs)) continue;
                if (reached(now, a.lastMs + kRequesterTimeoutMs)) continue;
                if (!due || static_cast<int32_t>(a.nextCalibrationMs - due->nextCalibrationMs) < 0) due = &a;
            }
            if (!due) {
                nextRoundAt_ = now + 100;
                return;
            }
            due->nextCalibrationMs = now + due->calibrateEveryMs;
            peer_ = due->to;
        }
        if (!exchanges_) {
            exchanges_ = static_cast<Exchange*>(heap::allocate(config_.samples * sizeof(Exchange)));
            if (!exchanges_) {  // short heap: try again shortly
                nextRoundAt_ = now + kFastIntervalMs;
                return;
            }
        }
        roundActive_ = true;
        round_++;
        sent_ = 0;
        nextSampleAt_ = now;
    }
    if (sent_ < config_.samples) {
        if (reached(now, nextSampleAt_)) sendRequest(now);
        return;
    }
    if (reached(now, lastSentAt_ + kRoundGraceMs)) endRound(now);
}

void TimeSync::nextTick(Deadline& d) const {
    if (!running_) return;
    // The earliest a candidate takes over (later with others ahead of it).
    if (role_ == TimeRole::Candidate && !explicitRef_ && !acting_ && !haveRef_ && vacant_) {
        d.at(vacantSince_ + config_.takeoverAfterMs);
    }
    // What we announce changes when the estimate goes stale.
    if (!acting_ && haveEstimate_) {
        uint64_t age = clock_() - lastSyncLocal_;
        uint64_t stale = static_cast<uint64_t>(config_.staleAfterMs) * 1000;
        if (age < stale) d.in(static_cast<uint32_t>((stale - age + 999) / 1000));
    }
    if (role_ == TimeRole::Off || (!acting_ && !haveRef_)) return;
    if (roundActive_) {
        d.at(sent_ < config_.samples ? nextSampleAt_ : lastSentAt_ + kRoundGraceMs);
        return;
    }
    if (!acting_) {
        d.at(nextRoundAt_);
        return;
    }
    // The reference runs rounds for the followers that asked to be measured.
    for (const Answer& a : answers_) {
        if (!a.used || !a.calibrateEveryMs) continue;
        uint32_t at = static_cast<int32_t>(a.nextCalibrationMs - nextRoundAt_) > 0 ? a.nextCalibrationMs : nextRoundAt_;
        if (static_cast<int32_t>(at - (a.lastMs + kRequesterTimeoutMs)) < 0) d.at(at);
    }
}

void TimeSync::sendRequest(uint32_t now) {
    // type | round | index | t1 (8) | calibration interval (s; 0: none), padded
    // to the response's length: both directions then take the same air time.
    uint8_t msg[kRequestSize];
    memset(msg, 0, sizeof(msg));
    msg[0] = kRequest;
    msg[1] = round_;
    msg[2] = sent_;
    uint64_t t1 = clock_();
    putU64(msg + 3, t1);
    if (!acting_ && config_.calibrationIntervalMs) {
        uint32_t s = (config_.calibrationIntervalMs + 999) / 1000;
        msg[11] = static_cast<uint8_t>(s > 255 ? 255 : s);
    }
    uint32_t id = 0;
    Status st = engine_.send(target(), kTimeSyncPort, msg, sizeof(msg), SendOptions(), CompletionHandler(), now, &id);
    if (st == Status::QueueFull) {
        nextSampleAt_ = now + 2;
        return;
    }
    Exchange& e = exchanges_[sent_];
    e = Exchange();
    e.requestId = id;
    e.t1 = t1;
    sent_++;
    lastSentAt_ = now;
    nextSampleAt_ = now + config_.sampleSpacingMs;
}

// The radio reported one of our messages on air. Stamped there, an exchange
// leaves out the time spent in queues and waiting for the channel, which
// differ between the two directions; what remains is the same on both sides
// (the driver's reporting and receive latencies) and cancels out.
void TimeSync::onSent(const Mac& dst, uint32_t messageId, uint64_t sentUs) {
    if (roundActive_ && (acting_ || haveRef_) && dst == target()) {
        for (uint8_t i = 0; i < sent_; ++i) {
            if (exchanges_[i].requestId != messageId) continue;
            exchanges_[i].sentUs = sentUs;
            return;
        }
    }
    for (Answer& a : answers_) {
        if (a.messageId == messageId && a.to == dst) {
            a.sentUs = sentUs;
            return;
        }
    }
}

void TimeSync::handle(const Message& m) {
    now_ = engine_.now();  // our last tick() may be long past
    if (m.len < 1) return;
    const uint8_t* d = m.data;
    if (d[0] == kRequest) {
        if (!config_.respond || m.len < 11) return;
        uint64_t t2 = m.timestampUs ? m.timestampUs : clock_();
        // Answered in our network time: the reference's clock, if we follow one
        // (or the one we serve). A node set to synchronize with us thereby
        // joins the same network time.
        bool chained = synced();
        // The previous response to this requester, whose send time we now
        // know. A new one takes the slot heard from least recently.
        Answer* slot = nullptr;
        for (Answer& a : answers_) {
            if (a.used && a.to == m.src) slot = &a;
        }
        if (!slot) {
            for (Answer& a : answers_) {
                if (!slot || !a.used || (slot->used && static_cast<int32_t>(a.lastMs - slot->lastMs) < 0)) slot = &a;
                if (!slot->used) break;
            }
            *slot = Answer();
            slot->used = true;
            slot->to = m.src;
            slot->index = kNoIndex;
            slot->nextCalibrationMs = now_ + 2000;
        }
        slot->lastMs = now_;
        // Calibration rounds asked for, served while we act as the reference.
        uint32_t every = m.len >= 12 ? static_cast<uint32_t>(d[11]) * 1000 : 0;
        slot->calibrateEveryMs = every ? std::max(every, kMinCalibrationMs) : 0;
        // type | round | index | t1 (echoed) | t2 | t3 | previous round | index | its send time
        uint8_t out[kResponseSize];
        out[0] = kResponse;
        out[1] = d[1];
        out[2] = d[2];
        memcpy(out + 3, d + 3, 8);
        putU64(out + 11, chained ? toNetwork(t2) : t2);
        out[27] = slot->round;
        out[28] = slot->sentUs ? slot->index : kNoIndex;
        putU64(out + 29, !slot->sentUs ? 0 : chained ? toNetwork(slot->sentUs) : slot->sentUs);
        uint64_t t3 = clock_();
        putU64(out + 19, chained ? toNetwork(t3) : t3);
        uint32_t id = 0;
        Status st = engine_.send(m.src, kTimeSyncPort, out, sizeof(out), SendOptions(), CompletionHandler(), now_, &id);
        slot->round = d[1];
        slot->index = d[2];
        slot->messageId = id;
        slot->sentUs = 0;
        if (st != Status::Ok) slot->index = kNoIndex;
        return;
    }
    if (d[0] == kCalibration) {
        // The reference measured our network time against its own.
        if (m.len < kCalibrationSize || acting_ || !haveRef_ || m.src != ref_ || !synced()) return;
        calibrate(static_cast<int32_t>(wire::getU32(d + 3)));
        return;
    }
    if (d[0] != kResponse || m.len < kBasicResponseSize) return;
    uint64_t t4 = m.timestampUs ? m.timestampUs : clock_();
    if (!roundActive_ || (!acting_ && !haveRef_) || m.src != target() || d[1] != round_) return;
    if (m.len >= kResponseSize && d[27] == round_ && d[28] < sent_) {
        exchanges_[d[28]].answerSentUs = getU64(d + 29);
        refStamps_ = true;
    }
    if (d[2] >= sent_) return;
    Exchange& e = exchanges_[d[2]];
    if (getU64(d + 3) != e.t1) return;  // not the request we sent under this index
    e.answered = true;
    e.t2 = getU64(d + 11);
    e.t3 = getU64(d + 19);
    e.t4 = t4;
}

namespace {

int64_t median(int64_t* v, size_t n) {
    std::sort(v, v + n);
    return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2;
}

}  // namespace

void TimeSync::endRound(uint32_t now) {
    roundActive_ = false;
    // Queue-time round trips: queueing only ever adds to them, so the fastest
    // exchanges carry the least asymmetry.
    uint32_t fastest = 0;
    uint8_t answered = 0;
    for (uint8_t i = 0; i < sent_; ++i) {
        const Exchange& e = exchanges_[i];
        if (!e.answered) continue;
        int64_t rtt = static_cast<int64_t>(e.t4 - e.t1) - static_cast<int64_t>(e.t3 - e.t2);
        if (e.t4 < e.t1 || rtt < 0 || rtt > 1000000) continue;
        if (answered == 0 || static_cast<uint32_t>(rtt) < fastest) fastest = static_cast<uint32_t>(rtt);
        answered++;
    }
    if (answered == 0) {
        nextRoundAt_ = now + kFastIntervalMs;
        return;
    }
    int64_t offsets[kMaxExchanges];
    uint64_t base = 0;
    int64_t sumLocal = 0;
    size_t n = 0;
    // Exchanges stamped on air at both ends (when the responder reports its
    // send times): the median of their offsets.
    for (uint8_t i = 0; i < sent_; ++i) {
        const Exchange& e = exchanges_[i];
        if (!e.answered || !e.sentUs || !e.answerSentUs) continue;
        if (n == 0) base = e.sentUs;
        offsets[n++] = (static_cast<int64_t>(e.t2 - e.sentUs) + static_cast<int64_t>(e.answerSentUs - e.t4)) / 2;
        sumLocal += static_cast<int64_t>((e.sentUs + e.t4) / 2 - base);
    }
    if (acting_) {
        endCalibration(n ? median(offsets, n) : 0, n, now);
        return;
    }
    if (n < kMinStamped && refStamps_) {
        // Mixing in queue-time rounds, biased differently, would make the
        // estimate jump between the two: try again shortly instead.
        nextRoundAt_ = now + kFastIntervalMs;
        return;
    }
    if (n < kMinStamped) {
        // Queue-time stamps (a responder without send times): the fastest
        // exchange. Averaging those close to it measured worse on hardware:
        // a slightly slower exchange mostly waited on one side, so they pull
        // the offset one way.
        n = 0;
        for (uint8_t i = 0; i < sent_; ++i) {
            const Exchange& e = exchanges_[i];
            if (!e.answered) continue;
            int64_t rtt = static_cast<int64_t>(e.t4 - e.t1) - static_cast<int64_t>(e.t3 - e.t2);
            if (e.t4 < e.t1 || rtt != static_cast<int64_t>(fastest)) continue;
            base = e.t1 + static_cast<uint64_t>(rtt / 2);
            offsets[0] = (static_cast<int64_t>(e.t2 - e.t1) + static_cast<int64_t>(e.t3 - e.t4)) / 2;
            sumLocal = 0;
            n = 1;
            break;
        }
    }
    if (n == 0) {
        nextRoundAt_ = now + kFastIntervalMs;
        return;
    }
    uint64_t local = base + static_cast<uint64_t>(sumLocal / static_cast<int64_t>(n));
    bool taken = addSample(local, median(offsets, n), fastest);
    nextRoundAt_ = now + (!taken || rounds_ < kFastRounds ? kFastIntervalMs : config_.intervalMs);
}

// A calibration round, run while acting: the follower answered in its
// network time, so the offset is its network time minus our local clock.
void TimeSync::endCalibration(int64_t offsetUs, size_t stamped, uint32_t now) {
    nextRoundAt_ = now + kCalibrationGapMs;
    if (stamped < kMinStamped) return;
    // Ours is the network time: local plus the estimate we serve (if any).
    int64_t diff = offsetUs - servedAt(clock_());
    if (diff > INT32_MAX || diff < INT32_MIN) return;
    uint8_t msg[kCalibrationSize];
    memset(msg, 0, sizeof(msg));
    msg[0] = kCalibration;
    msg[1] = round_;
    msg[2] = static_cast<uint8_t>(stamped);
    wire::putU32(msg + 3, static_cast<uint32_t>(static_cast<int32_t>(diff)));
    engine_.send(peer_, kTimeSyncPort, msg, sizeof(msg), SendOptions(), CompletionHandler(), now);
}

// The reference measured our network time minus its own: `reportedUs`. What
// is left of the drivers' delays after send-time stamps depends on which side
// asks, by some b: our rounds put b into our estimate, and the reference's
// round, in the other direction, measures that error plus b again. With our
// correction c applied, it reports 2b - c, so b = (report + c) / 2. The
// median over recent reports becomes the correction.
void TimeSync::calibrate(int32_t reportedUs) {
    int32_t implied = static_cast<int32_t>((static_cast<int64_t>(reportedUs) + bias_) / 2);
    if (implied > kMaxBiasUs || implied < -kMaxBiasUs) return;
    implied_[impliedNext_] = implied;
    impliedNext_ = static_cast<uint8_t>((impliedNext_ + 1) % kMaxCalibrations);
    if (impliedCount_ < kMaxCalibrations) impliedCount_++;
    if (impliedCount_ < kMinCalibrations) return;
    int64_t v[kMaxCalibrations];
    for (uint8_t i = 0; i < impliedCount_; ++i) v[i] = implied_[i];
    int32_t target = static_cast<int32_t>(median(v, impliedCount_));
    if (!biasSet_) {
        bias_ = target;  // the first correction applies at once
        biasSet_ = true;
        return;
    }
    // Then gently: single rounds spread over ~50 µs, and a step in network
    // time disturbs whatever was scheduled on it.
    int32_t step = (target - bias_) / 4;
    if (step > kMaxBiasStepUs) step = kMaxBiasStepUs;
    if (step < -kMaxBiasStepUs) step = -kMaxBiasStepUs;
    bias_ += step;
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
        int64_t error = offsetUs - offsetAt(localUs);
        int64_t magnitude = error < 0 ? -error : error;
        // Far from the prediction: a delayed exchange, or the reference
        // rebooted; after a few in a row, believe them.
        if (magnitude > 2000 + 4 * static_cast<int64_t>(rttUs)) {
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
    return localUs + static_cast<uint64_t>(servedAt(localUs));
}

uint64_t TimeSync::toLocal(uint64_t networkUs) const {
    if (!haveEstimate_) return networkUs;
    // The offset barely changes over the gap, so evaluating it near the answer is exact enough.
    uint64_t guess = networkUs - static_cast<uint64_t>(base_);
    return networkUs - static_cast<uint64_t>(servedAt(guess));
}

TimeSyncStatus TimeSync::status() const {
    TimeSyncStatus s;
    s.role = role_;
    s.isReference = acting_;
    s.explicitReference = explicitRef_ && !acting_ && role_ != TimeRole::Off;
    s.synced = synced();
    s.reference = acting_ ? self_ : ref_;
    uint64_t now = clock_();
    s.offsetUs = servedAt(now);
    s.driftPpm = static_cast<float>(drift_ * 1e6);
    s.rounds = rounds_;
    s.calibrationUs = bias_;
    s.calibrations = impliedCount_;
    if (!acting_) {
        s.roundTripUs = lastRtt_;
        s.ageMs = haveEstimate_ ? static_cast<uint32_t>((now - lastSyncLocal_) / 1000) : 0;
    }
    return s;
}

}  // namespace nowtp
