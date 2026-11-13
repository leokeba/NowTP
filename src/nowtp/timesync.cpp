// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "timesync.h"

#include <stdint.h>
#include <string.h>

#include <algorithm>
#include <new>

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
constexpr uint32_t kLinkRetryMs = 30000;         // a carrier whose round got no answer is passed over this long
constexpr uint32_t kBeaconRetryMs = 100;         // a beacon the carrier couldn't take
constexpr size_t kOfferSize = 4;                 // type | version | flags | reserved
constexpr uint8_t kOfferVersion = 1;
enum OfferBits : uint8_t { kActingBit = 0x1, kCandidateBit = 0x2, kSyncedBit = 0x4 };

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

uint8_t bitOf(size_t link) {
    return static_cast<uint8_t>(1u << link);
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

constexpr size_t TimeSync::kMaxCarriers;
constexpr size_t TimeSync::kMaxDatagram;
constexpr size_t TimeSync::kMaxExchanges;
constexpr size_t TimeSync::kMaxAnswers;
constexpr size_t TimeSync::kMaxCalibrations;
constexpr uint8_t TimeSync::kUnused;

TimeSync::TimeSync(Clock localClockUs, const TimeSyncConfig& config, const Mac& self, MsClock nowMs)
    : clock_(std::move(localClockUs)),
      msClock_(std::move(nowMs)),
      config_(config),
      self_(self),
      role_(config.reference ? TimeRole::Reference : config.role) {
    if (config_.samples == 0) config_.samples = 1;
    if (config_.samples > kMaxExchanges) config_.samples = static_cast<uint8_t>(kMaxExchanges);
    if (config_.beaconIntervalMs == 0) config_.beaconIntervalMs = 2000;
    // Both grow on what the network does: reserved here, never grown.
    samples_.reserve(kMaxSamples);
    offers_.reserve(kMaxOffers);
    if (config_.intervalMs < kFastIntervalMs) config_.intervalMs = kFastIntervalMs;
    acting_ = role_ == TimeRole::Reference;
    for (Answer& a : answers_) a = Answer();  // a member array isn't zeroed by itself
    for (Link& l : links_) resetLink(l);
    shared_[0] = shared_[1] = live();
    sharedSeq_[0].store(0, std::memory_order_relaxed);
    sharedSeq_[1].store(0, std::memory_order_relaxed);
    gen_.store(0, std::memory_order_release);
}

TimeSync::TimeSync(Engine& engine, Clock localClockUs, const TimeSyncConfig& config, const Mac& localMac)
    : TimeSync(std::move(localClockUs), config, localMac) {
    engine_ = &engine;
    void* p = heap::allocate(sizeof(EngineTimeCarrier));
    if (!p) return;  // a short heap at boot: no carrier, never synchronized
    own_.reset(new (p) EngineTimeCarrier());
    // Sends at the time of our entry point, as the engine expects.
    own_->setClock([this] { return now_; });
    addCarrier(*own_);
}

TimeSync::~TimeSync() {
    stop();
    heap::release(exchanges_);
}

uint32_t TimeSync::nowMs() const {
    if (engine_) return engine_->now();
    if (msClock_) return msClock_();
    return static_cast<uint32_t>(clock_() / 1000);
}

// ---------------------------------------------------------------------------
// Carriers

int TimeSync::linkOf(const TimeCarrier& c) const {
    for (size_t l = 0; l < kMaxCarriers; ++l) {
        if (links_[l].carrier == &c) return static_cast<int>(l);
    }
    return -1;
}

void TimeSync::resetLink(Link& l) {
    l = Link();
    l.carrier = nullptr;
    l.rank = kUnused;
    l.published = -1;
}

void TimeSync::resetCalibration() {
    for (Link& l : links_) {
        l.biasSet = false;
        l.impliedCount = 0;
        l.impliedNext = 0;
    }
}

Status TimeSync::addCarrier(TimeCarrier& carrier) {
    if (linkOf(carrier) >= 0) return Status::Ok;
    for (Link& l : links_) {
        if (l.carrier) continue;
        if (nextRank_ >= kUnused - 1) {
            // Ranks ran out after many changes: number the carriers in use again.
            uint8_t n = 0;
            for (uint8_t r = 0; r < kUnused; ++r) {
                for (Link& o : links_) {
                    if (o.carrier && o.rank == r) o.rank = n++;
                }
            }
            nextRank_ = n;
        }
        resetLink(l);
        l.carrier = &carrier;
        l.rank = nextRank_++;
        return Status::Ok;
    }
    return Status::InvalidState;
}

void TimeSync::removeCarrier(TimeCarrier& carrier, uint32_t now) {
    int l = linkOf(carrier);
    if (l < 0) return;
    links_[l].rank = kUnused;  // as left out, first: what goes through it stops
    for (Answer& a : answers_) {
        if (a.used && a.link == l) a.used = false;
    }
    if (roundLink_ == l) {
        roundActive_ = false;
        roundLink_ = -1;
    }
    if (followLink_ == l) leaveLink();
    if (estimateLink_ == l) estimateLink_ = -1;
    resetLink(links_[l]);
    dropVia(bitOf(static_cast<size_t>(l)), now);
}

size_t TimeSync::setCarrierOrder(const char* const* names, size_t count, uint32_t now) {
    size_t named = 0;
    uint8_t dropped = 0;
    for (size_t l = 0; l < kMaxCarriers; ++l) {
        Link& link = links_[l];
        if (!link.carrier) continue;
        bool was = link.rank != kUnused;
        link.rank = kUnused;
        for (size_t k = 0; k < count && k < kUnused - 1; ++k) {
            if (names[k] && strcmp(names[k], link.carrier->name()) == 0) {
                link.rank = static_cast<uint8_t>(k);
                named++;
                break;
            }
        }
        if (link.rank != kUnused || !was) continue;
        // Left out now: nothing goes through it any more.
        dropped = static_cast<uint8_t>(dropped | bitOf(l));
        for (Answer& a : answers_) {
            if (a.used && a.link == l) a.used = false;
        }
        if (roundLink_ == static_cast<int>(l)) {
            roundActive_ = false;
            roundLink_ = -1;
        }
        if (followLink_ == static_cast<int>(l)) leaveLink();
        link.published = -1;
    }
    nextRank_ = static_cast<uint8_t>(std::min<size_t>(count, kUnused - 1));
    if (dropped) {
        dropVia(dropped, now);
    } else {
        evaluate(now);
    }
    return named;
}

// The carrier to reach `device` by: the first in order that reaches it, one
// whose last round got no answer only if no other does.
int TimeSync::pickLink(const Mac& device, uint32_t now) const {
    int best = -1;
    int bestRank = 4;
    for (size_t l = 0; l < kMaxCarriers; ++l) {
        if (!usable(l)) continue;
        const Link& link = links_[l];
        bool failed = link.failed && !reached(now, link.retryAtMs);
        bool reaches = link.carrier->reaches(device);
        int rank = (reaches ? 0 : 2) + (failed ? 1 : 0);
        if (best < 0 || rank < bestRank || (rank == bestRank && link.rank < links_[best].rank)) {
            best = static_cast<int>(l);
            bestRank = rank;
        }
    }
    return best;
}

// Following the reference over another carrier: the estimate is kept, and
// carried until the new carrier's rounds replace it (their delays differ).
void TimeSync::leaveLink() {
    followLink_ = -1;
    samples_.clear();
    carried_ = haveEstimate_;
    rounds_ = 0;
    rejected_ = 0;
    refStamps_ = false;
}

void TimeSync::useLink(int link) {
    if (followLink_ == link) return;
    if (followLink_ >= 0) leaveLink();
    followLink_ = link;
}

// ---------------------------------------------------------------------------
// From carriers

void TimeSync::received(TimeCarrier& carrier, const Mac& device, const uint8_t* data, size_t len, uint64_t rxUs) {
    int l = linkOf(carrier);
    if (l < 0 || !usable(static_cast<size_t>(l)) || !running_) return;
    now_ = nowMs();  // our last tick() may be long past
    handle(static_cast<size_t>(l), device, data, len, rxUs);
    share();
}

// The carrier reported one of our datagrams on its way. Stamped there, an
// exchange leaves out the time spent in queues and waiting for the medium,
// which differ between the two directions; what remains is the same on both
// sides (the driver's reporting and receive latencies) and cancels out.
void TimeSync::sent(TimeCarrier& carrier, uint32_t token, uint64_t txUs) {
    int l = linkOf(carrier);
    if (l < 0 || !running_) return;
    if (roundActive_ && l == roundLink_ && exchanges_) {
        for (uint8_t i = 0; i < sent_; ++i) {
            if (exchanges_[i].requestId != token) continue;
            exchanges_[i].sentUs = txUs;
            return;
        }
    }
    for (Answer& a : answers_) {
        if (a.used && a.link == l && a.messageId == token) {
            a.sentUs = txUs;
            return;
        }
    }
}

void TimeSync::offer(TimeCarrier& carrier, const Mac& device, bool acting, bool candidate, bool synced,
                     uint32_t now) {
    int l = linkOf(carrier);
    if (l < 0) return;
    setOffer(static_cast<size_t>(l), device, acting, candidate, synced, false, now);
}

void TimeSync::withdraw(TimeCarrier& carrier, const Mac& device, uint32_t now) {
    offer(carrier, device, false, false, false, now);
}

void TimeSync::withdrawAll(TimeCarrier& carrier, uint32_t now) {
    int l = linkOf(carrier);
    if (l >= 0) dropVia(bitOf(static_cast<size_t>(l)), now);
}

// ---------------------------------------------------------------------------
// Roles and reference selection

void TimeSync::setDiscovery(Discovery* discovery) {
    if (!own_) return;
    own_->setDiscovery(discovery);
    int l = linkOf(*own_);
    if (l >= 0) links_[l].published = -1;
    publish();
}

void TimeSync::start(uint32_t now) {
    running_ = true;
    now_ = now;
    nextRoundAt_ = now;
    vacant_ = true;  // a candidate listens for a reference before taking over
    vacantSince_ = now;
    if (own_) own_->attach(engine_, this);
    evaluate(now);
}

void TimeSync::stop() {
    if (!running_) return;
    if (own_) own_->attach(engine_, nullptr);
    running_ = false;
    roundActive_ = false;
}

void TimeSync::onPeerEvent(PeerEvent event, const PeerInfo& peer, uint32_t now) {
    if (!own_) return;
    bool lost = event == PeerEvent::Lost;
    offer(*own_, peer.mac, !lost && peer.timeReference, !lost && peer.timeCandidate, peer.timeSynced, now);
}

void TimeSync::setOffer(size_t link, const Mac& mac, bool acting, bool candidate, bool synced, bool beacon,
                        uint32_t now) {
    uint8_t bit = bitOf(link);
    size_t i = 0;
    while (i < offers_.size() && offers_[i].mac != mac) ++i;
    if (!acting && !candidate) {
        if (i < offers_.size()) {
            Offer& o = offers_[i];
            o.via = static_cast<uint8_t>(o.via & ~bit);
            o.beaconVia = static_cast<uint8_t>(o.beaconVia & ~bit);
            if (!o.via) offers_.erase(offers_.begin() + static_cast<std::ptrdiff_t>(i));
        }
    } else if (i < offers_.size()) {
        Offer& o = offers_[i];
        o.acting = acting;
        o.candidate = candidate;
        o.synced = synced;
        o.via = static_cast<uint8_t>(o.via | bit);
        if (beacon) {
            o.beaconVia = static_cast<uint8_t>(o.beaconVia | bit);
            o.heardMs = now;
        } else {
            o.beaconVia = static_cast<uint8_t>(o.beaconVia & ~bit);
        }
    } else {
        Offer o = {mac, acting, candidate, synced, bit, static_cast<uint8_t>(beacon ? bit : 0), now};
        if (offers_.size() < kMaxOffers) {
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

void TimeSync::dropVia(uint8_t bits, uint32_t now) {
    for (size_t i = 0; i < offers_.size();) {
        Offer& o = offers_[i];
        o.via = static_cast<uint8_t>(o.via & ~bits);
        o.beaconVia = static_cast<uint8_t>(o.beaconVia & ~bits);
        if (!o.via) {
            offers_.erase(offers_.begin() + static_cast<std::ptrdiff_t>(i));
        } else {
            ++i;
        }
    }
    evaluate(now);
}

// Offers heard through beacons last until they stop.
void TimeSync::expireBeacons(uint32_t now) {
    for (size_t i = 0; i < offers_.size();) {
        Offer& o = offers_[i];
        if (o.beaconVia && reached(now, o.heardMs + config_.beaconTimeoutMs)) {
            o.via = static_cast<uint8_t>(o.via & ~o.beaconVia);
            o.beaconVia = 0;
            if (!o.via) {
                offers_.erase(offers_.begin() + static_cast<std::ptrdiff_t>(i));
                continue;
            }
        }
        ++i;
    }
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
    bool us = isSynced();
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
    share();
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
        resetCalibration();
        for (Link& l : links_) l.bias = 0;
        followLink_ = -1;
        estimateLink_ = -1;
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

int TimeSync::offerFlags() const {
    bool candidate = role_ == TimeRole::Candidate && !explicitRef_;
    if (!acting_ && !candidate) return 0;
    return (acting_ ? kActingBit : 0) | (candidate ? kCandidateBit : 0) | (isSynced() ? kSyncedBit : 0);
}

// Our role, to carriers that announce it (NowTP's discovery). Beacons go out
// from tick().
void TimeSync::publish() {
    bool candidate = role_ == TimeRole::Candidate && !explicitRef_;
    bool synced = isSynced();
    int flags = (acting_ ? kActingBit : 0) | (candidate ? kCandidateBit : 0) | (synced ? kSyncedBit : 0);
    for (size_t l = 0; l < kMaxCarriers; ++l) {
        Link& link = links_[l];
        if (!usable(l) || !link.carrier->hasDiscovery() || link.published == flags) continue;
        link.published = flags;
        link.carrier->announce(acting_, candidate, synced);
    }
}

// Offer beacons, on carriers without discovery: from the reference and the
// candidates, every beaconIntervalMs and when what they say changes; a node
// that stops offering says so once.
void TimeSync::beacon(uint32_t now) {
    int flags = offerFlags();
    for (size_t l = 0; l < kMaxCarriers; ++l) {
        Link& link = links_[l];
        if (!usable(l) || link.carrier->hasDiscovery()) continue;
        if (flags == link.published && !(flags && reached(now, link.nextBeaconMs))) continue;
        if (!flags && link.published <= 0) {
            link.published = 0;  // never offered: nothing to withdraw
            continue;
        }
        // type | version | flags (1 acting, 2 candidate, 4 synced) | reserved
        uint8_t msg[kOfferSize] = {kOffer, kOfferVersion, static_cast<uint8_t>(flags), 0};
        uint32_t token = 0;
        Status st = link.carrier->send(Mac::broadcast(), msg, sizeof(msg), &token);
        link.published = flags;
        link.nextBeaconMs = now + (st == Status::QueueFull ? kBeaconRetryMs : config_.beaconIntervalMs);
    }
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
    resetCalibration();
    followLink_ = -1;
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
    drift_ = 0;
    rounds_ = 0;
    rejected_ = 0;
    lastRtt_ = 0;
    roundActive_ = false;
    bias_ = 0;
    resetCalibration();
    for (Link& l : links_) {
        l.minRtt = 0;
        l.bias = 0;
    }
    followLink_ = -1;
    estimateLink_ = -1;
}

// ---------------------------------------------------------------------------
// Rounds

void TimeSync::tick(uint32_t now) {
    now_ = now;
    // What carriers queued (offers too, while stopped).
    for (Link& l : links_) {
        if (l.carrier) l.carrier->poll(*this);
    }
    now_ = now;
    if (!running_) return;
    expireBeacons(now);
    evaluate(now);  // a candidate's takeover is due by time
    beacon(now);
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
            roundLink_ = due->link;
        } else {
            int l = pickLink(ref_, now);
            if (l < 0) {  // no carrier
                nextRoundAt_ = now + kFastIntervalMs;
                return;
            }
            useLink(l);
            roundLink_ = l;
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
    for (const Link& l : links_) {
        if (l.carrier && l.carrier->pending()) d.in(0);
    }
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
    // Beacons, and offers heard through them expiring.
    int flags = offerFlags();
    for (size_t l = 0; l < kMaxCarriers; ++l) {
        const Link& link = links_[l];
        if (!usable(l) || link.carrier->hasDiscovery()) continue;
        if (flags != link.published && (flags || link.published > 0)) {
            d.in(0);
        } else if (flags) {
            d.at(link.nextBeaconMs);
        }
    }
    for (const Offer& o : offers_) {
        if (o.beaconVia) d.at(o.heardMs + config_.beaconTimeoutMs);
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
    Status st = links_[roundLink_].carrier->send(target(), msg, sizeof(msg), &id);
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

void TimeSync::handle(size_t link, const Mac& from, const uint8_t* d, size_t len, uint64_t rxUs) {
    if (len < 1) return;
    if (d[0] == kRequest) {
        if (!config_.respond || len < 11) return;
        uint64_t t2 = rxUs ? rxUs : clock_();
        // Answered in our network time: the reference's clock, if we follow one
        // (or the one we serve). A node set to synchronize with us thereby
        // joins the same network time.
        bool chained = isSynced();
        // The previous response to this requester (on this carrier), whose
        // send time we now know. A new one takes the slot heard from least
        // recently.
        Answer* slot = nullptr;
        for (Answer& a : answers_) {
            if (a.used && a.to == from && a.link == link) slot = &a;
        }
        if (!slot) {
            for (Answer& a : answers_) {
                if (!slot || !a.used || (slot->used && static_cast<int32_t>(a.lastMs - slot->lastMs) < 0)) slot = &a;
                if (!slot->used) break;
            }
            *slot = Answer();
            slot->used = true;
            slot->to = from;
            slot->link = static_cast<uint8_t>(link);
            slot->index = kNoIndex;
            slot->nextCalibrationMs = now_ + 2000;
        }
        slot->lastMs = now_;
        // Calibration rounds asked for, served while we act as the reference.
        uint32_t every = len >= 12 ? static_cast<uint32_t>(d[11]) * 1000 : 0;
        slot->calibrateEveryMs = every ? std::max(every, kMinCalibrationMs) : 0;
        // type | round | index | t1 (echoed) | t2 | t3 | previous round | index | its send time
        uint8_t out[kResponseSize];
        out[0] = kResponse;
        out[1] = d[1];
        out[2] = d[2];
        memcpy(out + 3, d + 3, 8);
        putU64(out + 11, chained ? netOf(t2) : t2);
        out[27] = slot->round;
        out[28] = slot->sentUs ? slot->index : kNoIndex;
        putU64(out + 29, !slot->sentUs ? 0 : chained ? netOf(slot->sentUs) : slot->sentUs);
        uint64_t t3 = clock_();
        putU64(out + 19, chained ? netOf(t3) : t3);
        uint32_t id = 0;
        Status st = links_[link].carrier->send(from, out, sizeof(out), &id);
        slot->round = d[1];
        slot->index = d[2];
        slot->messageId = id;
        slot->sentUs = 0;
        if (st != Status::Ok) slot->index = kNoIndex;
        return;
    }
    if (d[0] == kCalibration) {
        // The reference measured our network time against its own, over the
        // carrier we follow it by.
        if (len < kCalibrationSize || acting_ || !haveRef_ || from != ref_ || !isSynced()) return;
        if (static_cast<int>(link) != followLink_ || estimateLink_ != followLink_) return;
        calibrate(links_[link], static_cast<int32_t>(wire::getU32(d + 3)));
        return;
    }
    if (d[0] == kOffer) {
        // A beacon (version 1 and later: what follows the flags is ignored).
        if (len < 3 || d[1] < 1 || from == self_) return;
        setOffer(link, from, (d[2] & kActingBit) != 0, (d[2] & kCandidateBit) != 0, (d[2] & kSyncedBit) != 0,
                 true, now_);
        return;
    }
    if (d[0] != kResponse || len < kBasicResponseSize) return;
    uint64_t t4 = rxUs ? rxUs : clock_();
    if (!roundActive_ || (!acting_ && !haveRef_) || static_cast<int>(link) != roundLink_ || from != target() ||
        d[1] != round_) {
        return;
    }
    if (len >= kResponseSize && d[27] == round_ && d[28] < sent_) {
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
    Link& link = links_[roundLink_];
    if (answered == 0) {
        // Another carrier that reaches the reference gets the next round.
        if (!acting_) {
            link.failed = true;
            link.retryAtMs = now + kLinkRetryMs;
        }
        nextRoundAt_ = now + kFastIntervalMs;
        return;
    }
    link.failed = false;
    int64_t offsets[kMaxExchanges];
    uint64_t base = 0;
    int64_t sumLocal = 0;
    size_t n = 0;
    // Exchanges stamped on their way at both ends (when the responder reports
    // its send times): the median of their offsets.
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
    bool taken = addSample(static_cast<size_t>(roundLink_), local, median(offsets, n), fastest);
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
    uint32_t token = 0;
    links_[roundLink_].carrier->send(peer_, msg, sizeof(msg), &token);
}

// The reference measured our network time minus its own: `reportedUs`. What
// is left of the drivers' delays after send-time stamps depends on which side
// asks, by some b: our rounds put b into our estimate, and the reference's
// round, in the other direction, measures that error plus b again. With our
// correction c applied, it reports 2b - c, so b = (report + c) / 2. The
// median over recent reports becomes the carrier's correction (b differs
// between carriers), served while the estimate comes from that carrier.
void TimeSync::calibrate(Link& link, int32_t reportedUs) {
    int32_t implied = static_cast<int32_t>((static_cast<int64_t>(reportedUs) + bias_) / 2);
    if (implied > kMaxBiasUs || implied < -kMaxBiasUs) return;
    link.implied[link.impliedNext] = static_cast<int16_t>(implied);
    link.impliedNext = static_cast<uint8_t>((link.impliedNext + 1) % kMaxCalibrations);
    if (link.impliedCount < kMaxCalibrations) link.impliedCount++;
    if (link.impliedCount < kMinCalibrations) return;
    int64_t v[kMaxCalibrations];
    for (uint8_t i = 0; i < link.impliedCount; ++i) v[i] = link.implied[i];
    int32_t target = static_cast<int32_t>(median(v, link.impliedCount));
    if (!link.biasSet) {
        link.bias = target;  // the first correction applies at once
        link.biasSet = true;
    } else {
        // Then gently: single rounds spread over ~50 µs, and a step in network
        // time disturbs whatever was scheduled on it.
        int32_t step = (target - bias_) / 4;
        if (step > kMaxBiasStepUs) step = kMaxBiasStepUs;
        if (step < -kMaxBiasStepUs) step = -kMaxBiasStepUs;
        link.bias = bias_ + step;
    }
    bias_ = link.bias;
    share();
}

bool TimeSync::addSample(size_t l, uint64_t localUs, int64_t offsetUs, uint32_t rttUs) {
    Link& link = links_[l];
    TimeCarrierLimits limits = link.carrier->limits();
    // A slow round was queued behind other traffic (or failed frames, which
    // hold the radio ~100 ms): the delay is on one side, and half of it goes
    // into the offset. Such rounds are skipped; the threshold relaxes with
    // each one, so a lasting change (e.g. a slower rate) is taken in the end.
    if (link.minRtt != 0 && rttUs > 2 * link.minRtt + limits.slowRoundUs) {
        link.minRtt += link.minRtt / 8 + 1;
        return false;
    }
    if (haveEstimate_ && (samples_.size() >= 3 || carried_)) {
        int64_t error = offsetUs - offsetAt(localUs);
        int64_t magnitude = error < 0 ? -error : error;
        // Far from the prediction: a delayed exchange, or the reference
        // rebooted; after a few in a row, believe them.
        if (magnitude > static_cast<int64_t>(limits.outlierUs) + 4 * static_cast<int64_t>(rttUs)) {
            if (++rejected_ < kRejectLimit) return false;
            samples_.clear();
            drift_ = 0;
            carried_ = false;
        }
    }
    rejected_ = 0;
    if (link.minRtt == 0 || rttUs < link.minRtt) link.minRtt = rttUs;
    if (static_cast<int>(l) != estimateLink_) {
        // The estimate comes from this carrier now: its correction applies,
        // the last one it had (none if never calibrated). Another carrier's
        // would be wrong here: their stamping delays differ.
        estimateLink_ = static_cast<int>(l);
        bias_ = link.bias;
    }
    if (samples_.size() >= kMaxSamples) samples_.erase(samples_.begin());
    Sample s = {localUs, offsetUs};
    samples_.push_back(s);
    lastSyncLocal_ = localUs;
    lastRtt_ = rttUs;
    rounds_++;
    fit();
    share();
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

TimeSync::Shared TimeSync::live() const {
    Shared s;
    s.acting = acting_;
    s.have = haveEstimate_;
    s.role = role_;
    s.bias = bias_;
    s.baseLocal = baseLocal_;
    s.base = base_;
    s.drift = drift_;
    s.lastSyncLocal = lastSyncLocal_;
    return s;
}

// Writes the copy readers don't use, then makes it current. A reader that
// interrupts the writer reads the other copy, so it never waits for it; one
// that overlaps a write of its own copy (two updates during its read) reads again.
void TimeSync::share() {
    uint32_t g = gen_.load(std::memory_order_relaxed) + 1;
    size_t i = g & 1;
    uint32_t seq = sharedSeq_[i].load(std::memory_order_relaxed);
    sharedSeq_[i].store(seq + 1, std::memory_order_relaxed);
    std::atomic_thread_fence(std::memory_order_release);
    shared_[i] = live();
    sharedSeq_[i].store(seq + 2, std::memory_order_release);
    gen_.store(g, std::memory_order_release);
}

TimeSync::Shared TimeSync::shared() const {
    for (;;) {
        uint32_t g = gen_.load(std::memory_order_acquire);
        size_t i = g & 1;
        uint32_t seq = sharedSeq_[i].load(std::memory_order_acquire);
        if (seq & 1) continue;
        Shared s = shared_[i];
        std::atomic_thread_fence(std::memory_order_acquire);
        if (sharedSeq_[i].load(std::memory_order_relaxed) == seq) return s;
    }
}

int64_t TimeSync::servedAt(const Shared& s, uint64_t localUs) {
    if (!s.have) return 0;
    double dt = localUs >= s.baseLocal ? static_cast<double>(localUs - s.baseLocal)
                                       : -static_cast<double>(s.baseLocal - localUs);
    return s.base + static_cast<int64_t>(s.drift * dt) - s.bias;
}

bool TimeSync::isSynced() const {
    if (acting_) return true;
    if (!haveEstimate_) return false;
    return clock_() - lastSyncLocal_ < static_cast<uint64_t>(config_.staleAfterMs) * 1000;
}

bool TimeSync::synced() const {
    Shared s = shared();
    if (s.acting) return true;
    if (!s.have) return false;
    return clock_() - s.lastSyncLocal < static_cast<uint64_t>(config_.staleAfterMs) * 1000;
}

uint64_t TimeSync::toNetwork(uint64_t localUs) const {
    return localUs + static_cast<uint64_t>(servedAt(shared(), localUs));
}

uint64_t TimeSync::toLocal(uint64_t networkUs) const {
    Shared s = shared();
    if (!s.have) return networkUs;
    // The offset barely changes over the gap, so evaluating it near the answer is exact enough.
    uint64_t guess = networkUs - static_cast<uint64_t>(s.base);
    return networkUs - static_cast<uint64_t>(servedAt(s, guess));
}

TimeSyncStatus TimeSync::status() const {
    TimeSyncStatus s;
    s.role = role_;
    s.isReference = acting_;
    s.explicitReference = explicitRef_ && !acting_ && role_ != TimeRole::Off;
    s.synced = isSynced();
    s.reference = acting_ ? self_ : ref_;
    uint64_t now = clock_();
    s.offsetUs = servedAt(now);
    s.driftPpm = static_cast<float>(drift_ * 1e6);
    s.rounds = rounds_;
    s.calibrationUs = bias_;
    if (!acting_) {
        if (haveRef_ && followLink_ >= 0) {
            s.carrier = links_[followLink_].carrier->name();
            s.calibrations = links_[followLink_].impliedCount;
        }
        s.roundTripUs = lastRtt_;
        s.ageMs = haveEstimate_ ? static_cast<uint32_t>((now - lastSyncLocal_) / 1000) : 0;
    }
    return s;
}

// ---------------------------------------------------------------------------
// EngineTimeCarrier

constexpr size_t EngineTimeCarrier::kInbox;
constexpr size_t EngineTimeCarrier::kMaxInboxData;

EngineTimeCarrier::EngineTimeCarrier() {
    head_.store(0, std::memory_order_relaxed);
    tail_.store(0, std::memory_order_relaxed);
}

EngineTimeCarrier::~EngineTimeCarrier() {
    attach(nullptr, nullptr);
    heap::release(inbox_);
}

void EngineTimeCarrier::attach(Engine* engine, TimeSync* core) {
    if (!engine || !core) {
        engine = nullptr;
        core = nullptr;
    }
    if (engine_ && engine_ != engine) {
        engine_->listen(kTimeSyncPort, ReceiveHandler());
        engine_->setSentObserver(SentObserver());
    }
    bool detached = core_ && !core;
    engine_ = engine;
    core_ = core;
    if (engine_) {
        engine_->listen(kTimeSyncPort,
                        [this](const Message& m) { arrive(m.src, m.data, m.len, m.timestampUs); });
        engine_->setSentObserver([this](const Mac&, uint8_t port, uint32_t id, uint64_t sentUs) {
            if (port == kTimeSyncPort) left(id, sentUs);
        });
    }
    // The core forgets the offers we reported, in order with what we queued.
    if (detached && inbox_) {
        Entry e = Entry();
        e.kind = kReset;
        if (!push(e)) resetDue_ = true;
    }
}

void EngineTimeCarrier::setDiscovery(Discovery* discovery) {
    discovery_ = discovery;
    if (discovery_ && announced_ >= 0) {
        discovery_->setTimeState((announced_ & kActingBit) != 0, (announced_ & kCandidateBit) != 0,
                                 (announced_ & kSyncedBit) != 0);
    }
}

bool EngineTimeCarrier::setQueued(std::function<void()> wake) {
    if (!inbox_) inbox_ = static_cast<Entry*>(heap::allocate(kInbox * sizeof(Entry)));
    if (!inbox_) return false;
    wake_ = std::move(wake);
    return true;
}

Mac EngineTimeCarrier::idOf(const Mac& address) const {
    if (!deviceIds_ || !discovery_) return address;
    const PeerInfo* p = discovery_->find(address);
    return p ? p->deviceId : address;
}

Mac EngineTimeCarrier::addressOf(const Mac& device) const {
    if (!deviceIds_ || !discovery_ || device.isBroadcast() || discovery_->find(device)) return device;
    const PeerInfo* p = discovery_->findDevice(device);
    return p ? p->mac : device;
}

bool EngineTimeCarrier::push(const Entry& e) {
    uint8_t tail = tail_.load(std::memory_order_relaxed);
    uint8_t head = head_.load(std::memory_order_acquire);
    if (resetDue_) {
        uint8_t next = static_cast<uint8_t>((tail + 1) % kInbox);
        if (next == head) {
            dropped_++;
            return false;
        }
        Entry r = Entry();
        r.kind = kReset;
        inbox_[tail] = r;
        tail = next;
        tail_.store(tail, std::memory_order_release);
        resetDue_ = false;
    }
    uint8_t next = static_cast<uint8_t>((tail + 1) % kInbox);
    if (next == head) {
        dropped_++;
        return false;
    }
    inbox_[tail] = e;
    tail_.store(next, std::memory_order_release);
    return true;
}

void EngineTimeCarrier::arrive(const Mac& src, const uint8_t* data, size_t len, uint64_t rxUs) {
    Mac device = idOf(src);
    if (!inbox_) {
        if (core_) core_->received(*this, device, data, len, rxUs);
        return;
    }
    if (len > kMaxInboxData) return;  // from a later version, which we couldn't read whole anyway
    Entry e = Entry();
    e.kind = kReceived;
    e.len = static_cast<uint8_t>(len);
    e.device = device;
    e.us = rxUs;
    memcpy(e.data, data, len);
    if (push(e) && wake_) wake_();
}

void EngineTimeCarrier::left(uint32_t token, uint64_t txUs) {
    if (!inbox_) {
        if (core_) core_->sent(*this, token, txUs);
        return;
    }
    Entry e = Entry();
    e.kind = kSent;
    e.token = token;
    e.us = txUs;
    if (push(e) && wake_) wake_();
}

void EngineTimeCarrier::peerEvent(PeerEvent event, const PeerInfo& peer) {
    bool lost = event == PeerEvent::Lost;
    uint8_t flags = static_cast<uint8_t>(lost ? 0
                                              : (peer.timeReference ? kActingBit : 0) |
                                                    (peer.timeCandidate ? kCandidateBit : 0) |
                                                    (peer.timeSynced ? kSyncedBit : 0));
    Mac device = deviceIds_ ? peer.deviceId : peer.mac;
    if (!inbox_) {
        if (core_) {
            core_->offer(*this, device, (flags & kActingBit) != 0, (flags & kCandidateBit) != 0,
                         (flags & kSyncedBit) != 0, core_->nowMs());
        }
        return;
    }
    Entry e = Entry();
    e.kind = kOffered;
    e.flags = flags;
    e.device = device;
    if (push(e) && wake_) wake_();
}

void EngineTimeCarrier::poll(TimeSync& core) {
    if (!inbox_) return;
    for (;;) {
        uint8_t head = head_.load(std::memory_order_relaxed);
        if (head == tail_.load(std::memory_order_acquire)) return;
        Entry e = inbox_[head];
        head_.store(static_cast<uint8_t>((head + 1) % kInbox), std::memory_order_release);
        switch (e.kind) {
            case kReceived:
                core.received(*this, e.device, e.data, e.len, e.us);
                break;
            case kSent:
                core.sent(*this, e.token, e.us);
                break;
            case kOffered:
                core.offer(*this, e.device, (e.flags & kActingBit) != 0, (e.flags & kCandidateBit) != 0,
                           (e.flags & kSyncedBit) != 0, core.nowMs());
                break;
            case kReset:
                core.withdrawAll(*this, core.nowMs());
                break;
            default:
                break;
        }
    }
}

bool EngineTimeCarrier::pending() const {
    return inbox_ && head_.load(std::memory_order_relaxed) != tail_.load(std::memory_order_acquire);
}

Status EngineTimeCarrier::send(const Mac& device, const uint8_t* data, size_t len, uint32_t* token) {
    if (guard_ && !guard_->enter()) return Status::InvalidState;
    Status st = Status::InvalidState;
    if (engine_) {
        uint32_t now = nowMs_ ? nowMs_() : engine_->now();
        st = engine_->send(addressOf(device), kTimeSyncPort, data, len, SendOptions(), CompletionHandler(), now,
                           token);
    }
    if (guard_) guard_->leave();
    return st;
}

bool EngineTimeCarrier::reaches(const Mac& device) const {
    if (guard_ && !guard_->enter()) return false;
    bool r = engine_ && (!discovery_ || discovery_->find(addressOf(device)));
    if (guard_) guard_->leave();
    return r;
}

void EngineTimeCarrier::announce(bool acting, bool candidate, bool synced) {
    announced_ = (acting ? kActingBit : 0) | (candidate ? kCandidateBit : 0) | (synced ? kSyncedBit : 0);
    if (guard_ && !guard_->enter()) return;
    if (discovery_) discovery_->setTimeState(acting, candidate, synced);
    if (guard_) guard_->leave();
}

}  // namespace nowtp
