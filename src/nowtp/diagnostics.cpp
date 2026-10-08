// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "diagnostics.h"

#include <stdarg.h>
#include <stdio.h>

#include <algorithm>
#include <memory>

namespace nowtp {

using wire::getU16;
using wire::putU16;

namespace {

// Requests that go unanswered are retried with less power on both ends: a
// board whose supply sags at full power can still be reached and can answer.
const float kFallbackPowers[] = {15, 11, 8, 5};
constexpr uint8_t kAttempts = 5;
constexpr uint32_t kAttemptWaitMs = 400;
constexpr size_t kMaxSteps = 64;
constexpr size_t kMaxCounters = 4;
constexpr float kCeilingRatio = 0.8f;

inline int8_t toQuarter(float dbm) {
    return static_cast<int8_t>(dbm * 4.0f + (dbm >= 0 ? 0.5f : -0.5f));
}

inline float fromQuarter(int8_t q) {
    return q / 4.0f;
}

// Powers to try, highest first, up to `limit`.
std::vector<float> powerLadder(float limit) {
    const float candidates[] = {17, 15, 13, 11, 8, 5, 2};
    std::vector<float> out;
    out.push_back(limit);
    for (float p : candidates) {
        if (p < limit - 0.3f) out.push_back(p);
    }
    return out;
}

std::string format(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
std::string format(const char* fmt, ...) {
    char buf[200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return buf;
}

Issue makeIssue(IssueKind kind, bool local, const Mac& peer, float value, PhyRate rate, const std::string& detail) {
    Issue i;
    i.kind = kind;
    i.local = local;
    i.peer = peer;
    i.value = value;
    i.rate = rate;
    i.detail = detail;
    return i;
}

// Rough time on air plus pacing per probe frame, for timeouts.
uint32_t frameMs(PhyRate rate, size_t bytes) {
    uint32_t kbps = nominalKbps(rate);
    if (kbps == 0) kbps = 1000;
    return static_cast<uint32_t>((bytes + 60) * 8 / kbps) + 3;
}

}  // namespace

const char* toString(IssueKind kind) {
    switch (kind) {
        case IssueKind::PeerUnresponsive: return "PeerUnresponsive";
        case IssueKind::DoesNotHearUs: return "DoesNotHearUs";
        case IssueKind::HearsUsOnlyAtLowerPower: return "HearsUsOnlyAtLowerPower";
        case IssueKind::TxPowerLimited: return "TxPowerLimited";
        case IssueKind::OfdmPowerLimited: return "OfdmPowerLimited";
        case IssueKind::PowerControlIneffective: return "PowerControlIneffective";
        case IssueKind::RateFailsForward: return "RateFailsForward";
        case IssueKind::RateFailsReverse: return "RateFailsReverse";
        case IssueKind::WeakSignal: return "WeakSignal";
        case IssueKind::OtherChannel: return "OtherChannel";
        case IssueKind::OtherNetworkId: return "OtherNetworkId";
        case IssueKind::OtherProtocolVersion: return "OtherProtocolVersion";
        case IssueKind::LongRangeOnly: return "LongRangeOnly";
        case IssueKind::LongRangeUnavailable: return "LongRangeUnavailable";
        case IssueKind::SmallFramesOnly: return "SmallFramesOnly";
        case IssueKind::ChannelScanUnavailable: return "ChannelScanUnavailable";
        case IssueKind::ForeignTraffic: return "ForeignTraffic";
    }
    return "Unknown";
}

Diagnostics::Diagnostics(Engine& engine, RadioControl& radio, DiagnosticsHost& host, const DiagnosticsConfig& config)
    : engine_(engine), radio_(radio), host_(host), config_(config) {
    if (config_.probeBytes < 8) config_.probeBytes = 8;
}

Diagnostics::~Diagnostics() {
    stop();
}

void Diagnostics::start() {
    running_ = true;
    engine_.listen(kDiagnosticsPort, [this](const Message& m) { handle(m); });
}

void Diagnostics::stop() {
    if (!running_) return;
    if (burst_.active) finishBurst();
    engine_.listen(kDiagnosticsPort, ReceiveHandler());
    running_ = false;
}

// ---------------------------------------------------------------------------
// Responder (runs in the engine's context)

float Diagnostics::powerForAttempt(uint8_t attempt, float current) const {
    if (attempt == 0) return current;
    size_t i = std::min<size_t>(attempt - 1, sizeof(kFallbackPowers) / sizeof(kFallbackPowers[0]) - 1);
    return std::min(current, kFallbackPowers[i]);
}

Diagnostics::Counter* Diagnostics::counter(const Mac& src, uint16_t session, size_t steps, bool create) {
    Counter* found = nullptr;
    for (Counter& c : counters_) {
        if (c.session == session && c.src == src) found = &c;
    }
    if (!found && create) {
        if (counters_.size() >= kMaxCounters) {
            size_t oldest = 0;
            for (size_t i = 1; i < counters_.size(); ++i) {
                if (static_cast<int32_t>(counters_[i].lastUse - counters_[oldest].lastUse) < 0) oldest = i;
            }
            counters_.erase(counters_.begin() + static_cast<std::ptrdiff_t>(oldest));
        }
        counters_.push_back(Counter());
        found = &counters_.back();
        found->src = src;
        found->session = session;
    }
    if (found && found->received.size() < steps) {
        found->received.resize(steps, 0);
        found->rssiSum.resize(steps, 0);
        found->rssiCount.resize(steps, 0);
    }
    if (found) found->lastUse = now_;
    return found;
}

void Diagnostics::countBurst(const Message& m) {
    if (m.len < 5) return;
    uint16_t session = getU16(m.data + 1);
    uint8_t step = m.data[3];
    if (step >= kMaxSteps) return;
    Counter* c = counter(m.src, session, static_cast<size_t>(step) + 1, true);
    if (!c) return;
    if (c->received[step] < 255) c->received[step]++;
    if (m.rssi != 0 && c->rssiCount[step] < 255) {
        c->rssiSum[step] += m.rssi;
        c->rssiCount[step]++;
    }
}

void Diagnostics::reply(const Mac& to, uint8_t attempt, const uint8_t* data, size_t len) {
    // Answers go out at 1 Mbps and, on retries, with less power.
    float current = radio_.txPower();
    float power = powerForAttempt(attempt, current);
    bool lowered = power < current - 0.01f;
    if (lowered) {
        if (replyPowerOverrides_++ == 0) replySavedPower_ = current;
        radio_.setTxPower(power);
    }
    PhyRate savedRate = radio_.peerRate(to);
    bool rateChanged = savedRate != PhyRate::Default && savedRate != PhyRate::B1M &&
                       radio_.setPeerRate(to, PhyRate::B1M) == Status::Ok;

    std::vector<uint8_t> buf(data, data + len);
    if (buf.size() >= 4) buf[3] = static_cast<uint8_t>(toQuarter(radio_.txPower()));  // power actually used
    Status st = engine_.send(to, kDiagnosticsPort, buf.data(), buf.size(), SendOptions(),
                             [this, lowered, rateChanged, to, savedRate](Status) {
                                 if (lowered && --replyPowerOverrides_ == 0) radio_.setTxPower(replySavedPower_);
                                 if (rateChanged) radio_.setPeerRate(to, savedRate);
                             },
                             now_);
    if (st != Status::Ok) {
        if (lowered && --replyPowerOverrides_ == 0) radio_.setTxPower(replySavedPower_);
        if (rateChanged) radio_.setPeerRate(to, savedRate);
    }
}

void Diagnostics::handle(const Message& m) {
    if (m.len < 3) return;
    const uint8_t* d = m.data;
    uint8_t type = d[0];
    uint16_t session = getU16(d + 1);

    // Answers to our own requests.
    if (type == kReport || type == kBurstAck || type == kApplyAck || type == kPong || type == kBurstDone) {
        for (Reply& r : replies_) {
            if (!r.got && r.type == type && r.session == session && r.src == m.src) {
                r.got = true;
                r.data.assign(d, d + m.len);
            }
        }
        return;
    }
    if (type == kBurst) {
        countBurst(m);
        return;
    }
    if (!config_.respond || m.len < 4) return;
    uint8_t attempt = d[3];

    switch (type) {
        case kPing: {
            uint8_t out[5] = {kPong, d[1], d[2], 0, static_cast<uint8_t>(toQuarter(radio_.txPowerLimit()))};
            reply(m.src, attempt, out, sizeof(out));
            break;
        }
        case kCollect: {
            Counter* c = counter(m.src, session, 0, false);
            size_t n = c ? c->received.size() : 0;
            std::vector<uint8_t> out;
            out.push_back(kReport);
            out.push_back(d[1]);
            out.push_back(d[2]);
            out.push_back(0);  // power, filled by reply()
            out.push_back(static_cast<uint8_t>(n));
            for (size_t i = 0; i < n; ++i) {
                out.push_back(c->received[i]);
                int8_t rssi = c->rssiCount[i] ? static_cast<int8_t>(c->rssiSum[i] / c->rssiCount[i]) : 0;
                out.push_back(static_cast<uint8_t>(rssi));
            }
            reply(m.src, attempt, out.data(), out.size());
            break;
        }
        case kBurstRequest: {
            if (m.len < 6) return;
            uint8_t perStep = d[4];
            size_t n = d[5];
            if (n == 0 || n > kMaxSteps || m.len < 6 + 2 * n || perStep == 0) return;
            if (static_cast<size_t>(perStep) * n > config_.maxBurstFrames) return;
            if (localProcedures_ > 0) {
                // Our own measurement is running: our radio settings are not ours to change.
                uint8_t busy[6] = {kBurstAck, d[1], d[2], 0, static_cast<uint8_t>(toQuarter(radio_.txPowerLimit())), 1};
                reply(m.src, attempt, busy, sizeof(busy));
                break;
            }
            bool same = burst_.active && burst_.session == session && burst_.requester == m.src;
            if (!same) {
                if (burst_.active) finishBurst();
                burst_ = OutgoingBurst();
                burst_.active = true;
                burst_.requester = m.src;
                burst_.session = session;
                burst_.perStep = perStep;
                for (size_t i = 0; i < n; ++i) {
                    ProbeStep s;
                    s.rate = static_cast<PhyRate>(d[6 + 2 * i]);
                    s.txPowerDbm = fromQuarter(static_cast<int8_t>(d[7 + 2 * i]));
                    // Never substitute another rate: the requester would misread the result.
                    burst_.skip.push_back(!isValid(s.rate) || !radio_.rateUsable(s.rate));
                    burst_.steps.push_back(s);
                }
                burst_.savedPower = radio_.txPower();
                burst_.savedRate = radio_.broadcastRate();
                burst_.startedAt = now_;
            }
            uint8_t out[6] = {kBurstAck, d[1], d[2], 0, static_cast<uint8_t>(toQuarter(radio_.txPowerLimit())), 0};
            reply(m.src, attempt, out, sizeof(out));
            break;
        }
        case kApply: {
            if (m.len < 6) return;
            if (localProcedures_ > 0) {
                uint8_t busy[5] = {kApplyAck, d[1], d[2], 0, 1};
                reply(m.src, attempt, busy, sizeof(busy));
                break;
            }
            PhyRate rate = static_cast<PhyRate>(d[4]);
            float power = fromQuarter(static_cast<int8_t>(d[5]));
            if (!config_.acceptRemoteTuning) return;
            if (isValid(rate) && radio_.rateUsable(rate)) radio_.setPeerRate(m.src, rate);
            if (power >= 2) radio_.setTxPower(std::min(power, radio_.txPowerLimit()));
            uint8_t out[5] = {kApplyAck, d[1], d[2], 0, 0};
            reply(m.src, attempt, out, sizeof(out));
            break;
        }
        default: break;
    }
}

void Diagnostics::finishBurst() {
    radio_.setTxPower(burst_.savedPower);
    radio_.setBroadcastRate(burst_.savedRate);
    burst_.active = false;
}

void Diagnostics::tick(uint32_t now) {
    now_ = now;
    if (!burst_.active) return;
    if (static_cast<int32_t>(now - burst_.startedAt) > 30000) {
        finishBurst();  // safety net against a stuck request
        return;
    }
    if (replyPowerOverrides_ > 0) return;  // let the acknowledgement go out first

    if (!burst_.stepReady) {
        if (burst_.step >= burst_.steps.size()) {
            Mac requester = burst_.requester;
            uint8_t out[4] = {kBurstDone, static_cast<uint8_t>(burst_.session),
                              static_cast<uint8_t>(burst_.session >> 8), 0};
            finishBurst();
            reply(requester, 0, out, sizeof(out));
            return;
        }
        if (burst_.skip[burst_.step]) {
            burst_.step++;
            return;
        }
        const ProbeStep& s = burst_.steps[burst_.step];
        if (s.txPowerDbm >= 2) radio_.setTxPower(std::min(s.txPowerDbm, radio_.txPowerLimit()));
        radio_.setBroadcastRate(s.rate);
        burst_.stepReady = true;
        burst_.sent = burst_.completed = 0;
    }

    std::vector<uint8_t> frame(config_.probeBytes, 0);
    frame[0] = kBurst;
    putU16(frame.data() + 1, burst_.session);
    frame[3] = static_cast<uint8_t>(burst_.step);
    uint16_t session = burst_.session;
    while (burst_.sent < burst_.perStep && burst_.sent - burst_.completed < 2) {
        frame[4] = burst_.sent;
        Status st = engine_.send(Mac::broadcast(), kDiagnosticsPort, frame.data(), frame.size(), SendOptions(),
                                 [this, session](Status) {
                                     if (burst_.active && burst_.session == session) burst_.completed++;
                                 },
                                 now);
        if (st != Status::Ok) break;
        burst_.sent++;
    }
    if (burst_.completed >= burst_.perStep) {
        burst_.step++;
        burst_.stepReady = false;
    }
}

// ---------------------------------------------------------------------------
// Blocking procedures (application task)

bool Diagnostics::waitFor(const std::function<bool()>& done, uint32_t timeoutMs) {
    uint32_t start = host_.now();
    for (;;) {
        host_.lock();
        bool ok = done();
        host_.unlock();
        if (ok) return true;
        if (host_.now() - start >= timeoutMs) return false;
        host_.sleep(5);
    }
}

uint16_t Diagnostics::newSession() {
    uint16_t s = 0;
    while (s == 0) s = static_cast<uint16_t>(host_.random());
    return s;
}

Status Diagnostics::request(const Mac& peer, uint8_t replyType, uint16_t session, std::vector<uint8_t> payload,
                            size_t attemptOffset, Reply& out, float* requestPower, uint8_t attempts) {
    for (uint8_t attempt = 0; attempt < attempts && attempt < kAttempts; ++attempt) {
        payload[attemptOffset] = attempt;
        std::shared_ptr<bool> sent(new bool(false));

        host_.lock();
        Reply expected;
        expected.type = replyType;
        expected.session = session;
        expected.src = peer;
        replies_.push_back(expected);
        float current = radio_.txPower();
        float power = powerForAttempt(attempt, current);
        bool lowered = power < current - 0.01f;
        if (lowered) radio_.setTxPower(power);
        float used = radio_.txPower();
        Status st = engine_.send(peer, kDiagnosticsPort, payload.data(), payload.size(), SendOptions(),
                                 [sent](Status) { *sent = true; }, host_.now());
        host_.unlock();

        if (st == Status::Ok) {
            waitFor(
                [this, replyType, session, peer]() {
                    for (const Reply& r : replies_) {
                        if (r.got && r.type == replyType && r.session == session && r.src == peer) return true;
                    }
                    return false;
                },
                kAttemptWaitMs);
        }
        if (lowered) waitFor([sent]() { return *sent; }, 1000);  // our frame must leave before restoring power

        host_.lock();
        if (lowered) radio_.setTxPower(current);
        bool got = false;
        for (size_t i = 0; i < replies_.size(); ++i) {
            Reply& r = replies_[i];
            if (r.type == replyType && r.session == session && r.src == peer) {
                if (r.got && !got) {
                    out = r;
                    got = true;
                }
                replies_.erase(replies_.begin() + static_cast<std::ptrdiff_t>(i));
                --i;
            }
        }
        host_.unlock();
        if (got) {
            if (requestPower) *requestPower = used;
            return Status::Ok;
        }
    }
    return Status::Timeout;
}

Status Diagnostics::sendBurstFrames(const Mac& dst, uint16_t session, const std::vector<ProbeStep>& steps,
                                    uint8_t perStep) {
    host_.lock();
    float savedPower = radio_.txPower();
    PhyRate savedRate = radio_.broadcastRate();
    host_.unlock();

    std::vector<uint8_t> frame(config_.probeBytes, 0);
    frame[0] = kBurst;
    putU16(frame.data() + 1, session);
    for (size_t i = 0; i < steps.size(); ++i) {
        host_.lock();
        if (steps[i].txPowerDbm >= 2) radio_.setTxPower(std::min(steps[i].txPowerDbm, radio_.txPowerLimit()));
        radio_.setBroadcastRate(steps[i].rate);
        host_.unlock();

        std::shared_ptr<int> completed(new int(0));
        int sent = 0;
        frame[3] = static_cast<uint8_t>(i);
        for (uint8_t seq = 0; seq < perStep; ++seq) {
            frame[4] = seq;
            for (int tries = 0; tries < 500; ++tries) {
                host_.lock();
                Status st = engine_.send(dst, kDiagnosticsPort, frame.data(), frame.size(), SendOptions(),
                                         [completed](Status) { ++*completed; }, host_.now());
                host_.unlock();
                if (st == Status::Ok) {
                    sent++;
                    break;
                }
                if (st != Status::QueueFull) break;
                host_.sleep(1);
            }
        }
        waitFor([completed, sent]() { return *completed >= sent; }, 3000 + perStep * frameMs(steps[i].rate, frame.size()));
    }

    host_.lock();
    radio_.setTxPower(savedPower);
    radio_.setBroadcastRate(savedRate);
    host_.unlock();
    return Status::Ok;
}

void Diagnostics::yieldToPeer() {
    // Both sides measuring at once: step aside for a random while (serving the
    // other side meanwhile) so one of them can finish.
    host_.lock();
    int held = localProcedures_;
    localProcedures_ = 0;
    host_.unlock();
    host_.sleep(300 + host_.random() % 1200);
    host_.lock();
    localProcedures_ += held;
    host_.unlock();
}

Status Diagnostics::ping(const Mac& peer, float* requestPowerDbm, float* replyPowerDbm) {
    uint16_t session = newSession();
    std::vector<uint8_t> payload = {kPing, static_cast<uint8_t>(session), static_cast<uint8_t>(session >> 8), 0};
    Reply r;
    Status st = request(peer, kPong, session, payload, 3, r, requestPowerDbm);
    if (st == Status::Ok && replyPowerDbm && r.data.size() >= 4) *replyPowerDbm = fromQuarter(static_cast<int8_t>(r.data[3]));
    return st;
}

Status Diagnostics::measure(const Mac& peer, const std::vector<ProbeStep>& steps, uint8_t framesPerStep,
                            std::vector<ProbeResult>* forward, std::vector<ProbeResult>* reverse) {
    Busy guard(*this);
    if (steps.empty() || steps.size() > kMaxSteps || framesPerStep == 0 || framesPerStep > 100) {
        return Status::InvalidArgument;
    }
    if (static_cast<size_t>(framesPerStep) * steps.size() > config_.maxBurstFrames) return Status::InvalidArgument;

    // Control traffic to the peer at 1 Mbps for the duration.
    host_.lock();
    PhyRate savedPeerRate = radio_.peerRate(peer);
    radio_.setPeerRate(peer, PhyRate::B1M);
    host_.unlock();

    Status result = Status::Ok;
    if (forward) {
        forward->clear();
        uint16_t session = newSession();
        sendBurstFrames(Mac::broadcast(), session, steps, framesPerStep);
        host_.sleep(30);
        std::vector<uint8_t> payload = {kCollect, static_cast<uint8_t>(session), static_cast<uint8_t>(session >> 8), 0};
        Reply r;
        result = request(peer, kReport, session, payload, 3, r, nullptr);
        if (result == Status::Ok) {
            size_t n = r.data.size() >= 5 ? r.data[4] : 0;
            for (size_t i = 0; i < steps.size(); ++i) {
                ProbeResult pr;
                pr.step = steps[i];
                pr.sent = framesPerStep;
                if (i < n && r.data.size() >= 5 + 2 * (i + 1)) {
                    pr.received = std::min(r.data[5 + 2 * i], framesPerStep);
                    pr.rssi = static_cast<int8_t>(r.data[6 + 2 * i]);
                }
                forward->push_back(pr);
            }
        }
    }

    if (reverse && result == Status::Ok) {
        reverse->clear();
        uint16_t session = newSession();
        std::vector<uint8_t> payload = {kBurstRequest, static_cast<uint8_t>(session), static_cast<uint8_t>(session >> 8),
                                        0, framesPerStep, static_cast<uint8_t>(steps.size())};
        uint32_t expectMs = 0;
        for (const ProbeStep& s : steps) {
            payload.push_back(static_cast<uint8_t>(s.rate));
            payload.push_back(static_cast<uint8_t>(toQuarter(s.txPowerDbm)));
            expectMs += framesPerStep * frameMs(s.rate, config_.probeBytes);
        }
        host_.lock();
        Reply done;
        done.type = kBurstDone;
        done.session = session;
        done.src = peer;
        replies_.push_back(done);
        host_.unlock();

        Reply ack;
        for (int tries = 0;; ++tries) {
            result = request(peer, kBurstAck, session, payload, 3, ack, nullptr);
            bool busy = result == Status::Ok && ack.data.size() >= 6 && (ack.data[5] & 1);
            if (!busy) break;
            if (tries >= 20) {
                result = Status::QueueFull;  // the peer stayed busy with its own measurements
                break;
            }
            yieldToPeer();
        }
        if (result == Status::Ok) {
            waitFor(
                [this, session, peer]() {
                    for (const Reply& r : replies_) {
                        if (r.got && r.type == kBurstDone && r.session == session && r.src == peer) return true;
                    }
                    return false;
                },
                2 * expectMs + 1500);
            host_.sleep(30);
            host_.lock();
            Counter* c = counter(peer, session, 0, false);
            for (size_t i = 0; i < steps.size(); ++i) {
                ProbeResult pr;
                pr.step = steps[i];
                pr.sent = framesPerStep;
                if (c && i < c->received.size()) {
                    pr.received = std::min(c->received[i], framesPerStep);
                    pr.rssi = c->rssiCount[i] ? static_cast<int8_t>(c->rssiSum[i] / c->rssiCount[i]) : 0;
                }
                reverse->push_back(pr);
            }
            host_.unlock();
        }
        host_.lock();
        for (size_t i = 0; i < replies_.size(); ++i) {
            if (replies_[i].type == kBurstDone && replies_[i].session == session) {
                replies_.erase(replies_.begin() + static_cast<std::ptrdiff_t>(i));
                --i;
            }
        }
        host_.unlock();
    }

    host_.lock();
    radio_.setPeerRate(peer, savedPeerRate);
    host_.unlock();
    return result;
}

namespace {

// RSSI change per dB of power over the 1 Mbps probes that arrived.
float powerResponse(const std::vector<ProbeResult>& results) {
    const ProbeResult* hi = nullptr;
    const ProbeResult* lo = nullptr;
    for (const ProbeResult& r : results) {
        if (r.step.rate != PhyRate::B1M || r.ratio() < kCeilingRatio || r.rssi == 0) continue;
        if (!hi || r.step.txPowerDbm > hi->step.txPowerDbm) hi = &r;
        if (!lo || r.step.txPowerDbm < lo->step.txPowerDbm) lo = &r;
    }
    if (!hi || !lo || hi->step.txPowerDbm - lo->step.txPowerDbm < 6) return 0;
    return (hi->rssi - lo->rssi) / (hi->step.txPowerDbm - lo->step.txPowerDbm);
}

}  // namespace

Status Diagnostics::measureCeilings(const Mac& peer, uint8_t frames, LinkDiagnosis& d) {
    // Our transmitter: broadcast probes counted by the peer, highest power first.
    std::vector<float> ours = powerLadder(d.ours.limitDbm);
    std::vector<ProbeStep> steps;
    for (float p : ours) steps.push_back(ProbeStep{PhyRate::B1M, p});
    for (float p : ours) steps.push_back(ProbeStep{PhyRate::G24M, p});
    std::vector<ProbeResult> fwd;
    Status st = measure(peer, steps, frames, &fwd, nullptr);
    if (st != Status::Ok) return st;
    {
        for (const ProbeResult& r : fwd) {
            if (r.ratio() < kCeilingRatio) continue;
            float& slot = isOfdm(r.step.rate) ? d.ours.ofdmDbm : d.ours.dsssDbm;
            slot = std::max(slot, r.step.txPowerDbm);
        }
        d.ours.powerResponse = powerResponse(fwd);
    }

    // The peer's transmitter, on request.
    std::vector<float> theirs = powerLadder(d.theirs.limitDbm);
    steps.clear();
    for (float p : theirs) steps.push_back(ProbeStep{PhyRate::B1M, p});
    for (float p : theirs) steps.push_back(ProbeStep{PhyRate::G24M, p});
    std::vector<ProbeResult> rev;
    st = measure(peer, steps, frames, nullptr, &rev);
    if (st != Status::Ok) return st;
    {
        for (const ProbeResult& r : rev) {
            if (r.ratio() < kCeilingRatio) continue;
            float& slot = isOfdm(r.step.rate) ? d.theirs.ofdmDbm : d.theirs.dsssDbm;
            slot = std::max(slot, r.step.txPowerDbm);
        }
        d.theirs.powerResponse = powerResponse(rev);
    }
    return Status::Ok;
}

Status Diagnostics::diagnose(const Mac& peer, LinkDiagnosis& d, uint8_t frames) {
    Busy guard(*this);
    d = LinkDiagnosis();
    d.peer = peer;

    // Can we talk at all? Also learns the peer's power limit.
    uint16_t session = newSession();
    std::vector<uint8_t> payload = {kPing, static_cast<uint8_t>(session), static_cast<uint8_t>(session >> 8), 0};
    Reply pong;
    host_.lock();
    float current = radio_.txPower();
    d.ours.limitDbm = radio_.txPowerLimit();
    host_.unlock();
    if (request(peer, kPong, session, payload, 3, pong, &d.requestPowerDbm) != Status::Ok) {
        d.issues.push_back(makeIssue(IssueKind::PeerUnresponsive, false, peer, 0, PhyRate::Default,
                                     "no answer at any power: the peer is out of range, not running NowTP "
                                     "diagnostics, or neither side's transmitter gets through"));
        return Status::Timeout;
    }
    d.responds = true;
    if (pong.data.size() >= 5) {
        d.replyPowerDbm = fromQuarter(static_cast<int8_t>(pong.data[3]));
        d.theirs.limitDbm = fromQuarter(static_cast<int8_t>(pong.data[4]));
    }
    if (d.requestPowerDbm < current - 0.01f) {
        // Only an answer at reduced power: was it the power, or was the peer
        // briefly away (scanning channels, rebooting)? Ask once more at full power.
        Reply again;
        uint16_t s2 = newSession();
        std::vector<uint8_t> retry = {kPing, static_cast<uint8_t>(s2), static_cast<uint8_t>(s2 >> 8), 0};
        float full = 0;
        if (request(peer, kPong, s2, retry, 3, again, &full, 1) == Status::Ok) d.requestPowerDbm = full;
    }
    if (d.requestPowerDbm < current - 0.01f) {
        d.issues.push_back(makeIssue(IssueKind::HearsUsOnlyAtLowerPower, true, peer, d.requestPowerDbm,
                                     PhyRate::Default,
                                     format("the peer only heard us after lowering our power to %.1f dBm", d.requestPowerDbm)));
    }

    // A failure here is "busy" or "gone", not a property of the hardware.
    Status st = measureCeilings(peer, frames, d);
    if (st != Status::Ok) return st;

    // Rate tables at each side's working power.
    const PhyRate rates[] = {PhyRate::B1M,  PhyRate::B2M,  PhyRate::B5_5M, PhyRate::B11M, PhyRate::G6M,
                             PhyRate::G12M, PhyRate::G24M, PhyRate::G36M,  PhyRate::G48M, PhyRate::G54M,
                             PhyRate::MCS0, PhyRate::MCS3, PhyRate::MCS5,  PhyRate::MCS7, PhyRate::LR500K,
                             PhyRate::LR250K};
    std::vector<ProbeStep> fwdSteps, revSteps;
    host_.lock();
    for (PhyRate r : rates) {
        if (!radio_.rateUsable(r) || (isLongRange(r) && !radio_.longRange())) continue;
        float ours = isOfdm(r) ? d.ours.ofdmDbm : d.ours.dsssDbm;
        float theirs = isOfdm(r) ? d.theirs.ofdmDbm : d.theirs.dsssDbm;
        // Where nothing worked, probe at the lowest power: still tells which rates fail.
        fwdSteps.push_back(ProbeStep{r, ours > 0 ? ours : 2});
        revSteps.push_back(ProbeStep{r, theirs > 0 ? theirs : 2});
    }
    host_.unlock();
    st = measure(peer, fwdSteps, frames, &d.forward, nullptr);
    if (st == Status::Ok) st = measure(peer, revSteps, frames, nullptr, &d.reverse);
    if (st != Status::Ok) return st;
    if (!d.forward.empty()) d.forwardRssi = d.forward[0].rssi;
    if (!d.reverse.empty()) d.reverseRssi = d.reverse[0].rssi;

    // Findings.
    struct Side {
        const TxCeiling* c;
        bool local;
        const char* who;
    } sides[] = {{&d.ours, true, "this node"}, {&d.theirs, false, "the peer"}};
    for (const Side& s : sides) {
        if (s.c->dsssDbm < 0) {
            d.issues.push_back(makeIssue(s.local ? IssueKind::DoesNotHearUs : IssueKind::RateFailsReverse, s.local, peer,
                                         0, PhyRate::B1M,
                                         format("frames from %s were not received at any tested power", s.who)));
        } else if (s.c->dsssDbm < s.c->limitDbm - 0.01f) {
            d.issues.push_back(makeIssue(
                IssueKind::TxPowerLimited, s.local, peer, s.c->dsssDbm, PhyRate::B1M,
                format("frames from %s are lost above %.1f dBm (limit %.1f): its supply probably sags at full power; "
                       "set radio.txPowerDbm to %.1f",
                       s.who, s.c->dsssDbm, s.c->limitDbm, s.c->dsssDbm)));
        }
        // RSSI should follow the power setting roughly dB for dB.
        if (s.c->powerResponse > 0 && s.c->powerResponse < 0.5f) {
            d.issues.push_back(makeIssue(
                IssueKind::PowerControlIneffective, s.local, peer, s.c->powerResponse, PhyRate::B1M,
                format("the received signal changes only %.1f dB per dB of power set on %s: its power control "
                       "barely works, so lowering power saves little and raising it gains little range",
                       s.c->powerResponse, s.who)));
        }
        if (s.c->dsssDbm > 0 && s.c->ofdmDbm < s.c->dsssDbm - 0.01f) {
            d.issues.push_back(makeIssue(
                IssueKind::OfdmPowerLimited, s.local, peer, s.c->ofdmDbm, PhyRate::G24M,
                s.c->ofdmDbm < 0 ? format("OFDM frames (802.11g/n) from %s fail at every tested power", s.who)
                                 : format("OFDM frames (802.11g/n) from %s are lost above %.1f dBm", s.who, s.c->ofdmDbm)));
        }
    }
    bool lrFails = false;
    for (size_t i = 0; i < d.forward.size(); ++i) {
        bool lr = isLongRange(d.forward[i].step.rate);
        bool fails = d.forward[i].ratio() < 0.5f || (i < d.reverse.size() && d.reverse[i].ratio() < 0.5f);
        lrFails = lrFails || (lr && fails);
    }
    if (lrFails) {
        d.issues.push_back(makeIssue(IssueKind::LongRangeUnavailable, false, peer, 0, PhyRate::LR250K,
                                     "Long Range frames do not get through in both directions: enable radio.longRange "
                                     "on both nodes to use the LR rates"));
    }
    for (size_t i = 0; i < d.forward.size(); ++i) {
        const ProbeResult& f = d.forward[i];
        if (f.ratio() >= 0.5f || isLongRange(f.step.rate)) continue;
        bool reverseOk = i < d.reverse.size() && d.reverse[i].ratio() >= kCeilingRatio;
        d.issues.push_back(makeIssue(IssueKind::RateFailsForward, true, peer, f.ratio(), f.step.rate,
                                     format("%s frames from this node arrive %u/%u%s", toString(f.step.rate), f.received,
                                            f.sent, reverseOk ? " (the other direction works: our transmitter or the peer's receiver)" : "")));
    }
    for (size_t i = 0; i < d.reverse.size(); ++i) {
        const ProbeResult& r = d.reverse[i];
        if (r.ratio() >= 0.5f || isLongRange(r.step.rate)) continue;
        bool forwardOk = i < d.forward.size() && d.forward[i].ratio() >= kCeilingRatio;
        d.issues.push_back(makeIssue(IssueKind::RateFailsReverse, false, peer, r.ratio(), r.step.rate,
                                     format("%s frames from the peer arrive %u/%u%s", toString(r.step.rate), r.received,
                                            r.sent, forwardOk ? " (the other direction works: its transmitter or our receiver)" : "")));
    }
    int8_t weakest = std::min(d.forwardRssi ? d.forwardRssi : int8_t(0), d.reverseRssi ? d.reverseRssi : int8_t(0));
    if (weakest != 0 && weakest < -80) {
        d.issues.push_back(makeIssue(IssueKind::WeakSignal, false, peer, weakest, PhyRate::B1M,
                                     format("weak signal (%d dBm at 1 Mbps): check antennas and distance; Long Range helps",
                                            weakest)));
    }
    return Status::Ok;
}

Status Diagnostics::optimize(const Mac& peer, const OptimizeOptions& opt, LinkProfile& out,
                             const LinkDiagnosis* known) {
    Busy guard(*this);
    out = LinkProfile();
    out.peer = peer;
    LinkDiagnosis fresh;
    if (!known || !known->responds || known->peer != peer) {
        Status st = diagnose(peer, fresh, opt.framesPerStep);
        if (st != Status::Ok) return st;
        known = &fresh;
    }
    const LinkDiagnosis& d = *known;

    auto pick = [&](const std::vector<ProbeResult>& table, float& ratio) {
        PhyRate best = PhyRate::B1M;
        float bestScore = -1;
        ratio = 0;
        for (const ProbeResult& r : table) {
            if (r.ratio() < opt.minDeliveryRatio) continue;
            if (isOfdm(r.step.rate) && !opt.allowOfdm) continue;
            if (isLongRange(r.step.rate) && !opt.allowLongRange) continue;
            float score = nominalKbps(r.step.rate) * r.ratio();
            if (score > bestScore) {
                bestScore = score;
                best = r.step.rate;
                ratio = r.ratio();
            }
        }
        return best;
    };
    out.rateToPeer = pick(d.forward, out.deliveryToPeer);
    out.rateFromPeer = pick(d.reverse, out.deliveryFromPeer);

    float ours = isOfdm(out.rateToPeer) ? d.ours.ofdmDbm : d.ours.dsssDbm;
    float theirs = isOfdm(out.rateFromPeer) ? d.theirs.ofdmDbm : d.theirs.dsssDbm;
    if (ours <= 0) ours = d.requestPowerDbm;
    if (theirs <= 0) theirs = d.replyPowerDbm;
    if (opt.maxTxPowerDbm > 0) ours = std::min(ours, opt.maxTxPowerDbm);
    out.txPowerDbm = ours;
    out.peerTxPowerDbm = theirs;
    if (!opt.apply) return Status::Ok;

    host_.lock();
    radio_.setTxPower(ours);
    radio_.setPeerRate(peer, out.rateToPeer);
    host_.unlock();

    uint16_t session = newSession();
    std::vector<uint8_t> payload = {kApply, static_cast<uint8_t>(session), static_cast<uint8_t>(session >> 8), 0,
                                    static_cast<uint8_t>(out.rateFromPeer), static_cast<uint8_t>(toQuarter(theirs))};
    Reply ack;
    for (int tries = 0;; ++tries) {
        out.applied = request(peer, kApplyAck, session, payload, 3, ack, nullptr) == Status::Ok &&
                      !(ack.data.size() >= 5 && (ack.data[4] & 1));
        if (out.applied || tries >= 20 || ack.data.size() < 5) break;
        yieldToPeer();
    }

    // Verify with a reliable message both ways (data out, acknowledgement back).
    std::vector<uint8_t> probe(1500, 0);  // type 0: ignored by the peer's diagnostics
    std::shared_ptr<int> result(new int(-1));
    host_.lock();
    SendOptions rel;
    rel.reliable = true;
    Status sst = engine_.send(peer, kDiagnosticsPort, probe.data(), probe.size(), rel,
                              [result](Status s) { *result = static_cast<int>(s); }, host_.now());
    host_.unlock();
    if (sst == Status::Ok) waitFor([result]() { return *result >= 0; }, 5000);
    out.verified = *result == static_cast<int>(Status::Ok);

    if (!out.verified) {
        // Fall back to what always works.
        host_.lock();
        radio_.setPeerRate(peer, PhyRate::B1M);
        host_.unlock();
        payload[4] = static_cast<uint8_t>(PhyRate::B1M);
        payload[5] = 0;
        request(peer, kApplyAck, session, payload, 3, ack, nullptr);
        out.rateToPeer = out.rateFromPeer = PhyRate::B1M;
    }
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Deep discovery

Status Diagnostics::deepDiscover(const DeepDiscoveryOptions& opt, DeepDiscoveryReport& out) {
    Busy guard(*this);
    out = DeepDiscoveryReport();
    struct Scan {
        uint8_t channel = 0;
        uint8_t home = 0;
        bool longRangePass = false;
        std::vector<DiscoveredNode> nodes;
        std::vector<Mac> foreign;
        std::vector<bool> heardWithoutLr;
    };
    std::shared_ptr<Scan> scan(new Scan());
    const uint8_t ourNetwork = engine_.config().networkId;

    host_.lock();
    const uint8_t home = radio_.channel();
    const bool savedLr = radio_.longRange();
    const PhyRate savedRate = radio_.broadcastRate();
    out.homeChannel = home;
    scan->channel = home;
    scan->home = home;
    engine_.setFrameObserver([scan](const FrameInfo& f) {
        if (!f.nowtp) {
            if (std::find(scan->foreign.begin(), scan->foreign.end(), f.src) == scan->foreign.end()) {
                scan->foreign.push_back(f.src);
            }
            return;
        }
        DiscoveredNode* n = nullptr;
        for (DiscoveredNode& x : scan->nodes) {
            if (x.mac == f.src) n = &x;
        }
        bool onHome = scan->channel == scan->home;
        if (!n) {
            scan->nodes.push_back(DiscoveredNode());
            n = &scan->nodes.back();
            n->mac = f.src;
            n->channel = scan->channel;
            n->rssi = f.rssi;
            n->longRangeOnly = scan->longRangePass;
        } else if (!n->heardOnHome && f.rssi != 0 && f.rssi > n->rssi && !scan->longRangePass) {
            // Strong signals leak into adjacent channels: keep the strongest.
            n->channel = scan->channel;
            n->rssi = f.rssi;
        }
        // Heard on our channel at all: it lives there (it may have been
        // scanning other channels itself when we heard it elsewhere).
        if (onHome && !n->heardOnHome) {
            n->heardOnHome = true;
            n->channel = scan->home;
            n->rssi = f.rssi;
        }
        if (!scan->longRangePass) n->longRangeOnly = false;
        n->nowtp = true;
        n->protocolVersion = f.version;
        n->networkId = f.header.networkId;
        if (f.header.type == wire::Type::Single && f.header.port == kDiscoveryPort) {
            std::string name;
            uint16_t maxFrame = 0;
            if (Discovery::parseAnnouncement(f.payload, f.payloadLen, name, maxFrame)) {
                n->name = name;
                n->maxFrameSize = maxFrame;
            }
        }
    });
    host_.unlock();

    std::vector<uint8_t> channels = opt.channels;
    if (channels.empty()) {
        channels.push_back(home);
        for (uint8_t c = 1; c <= 13; ++c) {
            if (c != home) channels.push_back(c);
        }
    }

    bool channelLocked = false;
    for (uint8_t ch : channels) {
        host_.lock();
        Status st = ch == home ? Status::Ok : radio_.setChannel(ch);
        if (st == Status::Ok) {
            scan->channel = ch;
            if (discovery_) discovery_->discover(host_.now());
        }
        host_.unlock();
        if (st != Status::Ok) {
            channelLocked = true;
            break;
        }
        host_.sleep(opt.dwellMs);
    }
    host_.lock();
    if (radio_.channel() != home) radio_.setChannel(home);
    scan->channel = home;
    host_.unlock();
    if (channelLocked) {
        out.issues.push_back(makeIssue(IssueKind::ChannelScanUnavailable, true, Mac(), home, PhyRate::Default,
                                       format("only channel %u was scanned: an access point fixes the channel", home)));
    }

    // Long Range: nodes that only send at LR rates are invisible without it.
    if (opt.checkLongRange && !savedLr) {
        host_.lock();
        bool lrOn = radio_.setLongRange(true) == Status::Ok;
        if (lrOn) {
            scan->longRangePass = true;
            radio_.setBroadcastRate(PhyRate::LR500K);
            if (discovery_) discovery_->discover(host_.now());
        }
        host_.unlock();
        if (lrOn) {
            host_.sleep(opt.dwellMs);
            host_.lock();
            scan->longRangePass = false;
            radio_.setBroadcastRate(savedRate);
            radio_.setLongRange(false);
            host_.unlock();
        }
    }

    host_.lock();
    engine_.setFrameObserver(FrameObserver());
    std::vector<DiscoveredNode> nodes = scan->nodes;
    std::vector<Mac> foreign = scan->foreign;
    host_.unlock();

    for (DiscoveredNode& n : nodes) {
        n.compatible = n.nowtp && n.protocolVersion == wire::kVersion && n.networkId == ourNetwork &&
                       n.channel == home && !n.longRangeOnly;
    }

    // Do compatible nodes hear us? A unicast frame is acknowledged by the
    // receiver's radio itself, so this works even without diagnostics there.
    for (int pass = 0; opt.checkTxPower && pass < 2; ++pass) {
        if (pass == 1) {
            bool again = false;
            for (const DiscoveredNode& n : nodes) again = again || (n.compatible && !n.hearsUs);
            if (!again) break;
            host_.sleep(opt.dwellMs);  // it may be away scanning, or rebooting
        }
        for (DiscoveredNode& n : nodes) {
            if (!n.compatible || n.hearsUs) continue;
            host_.lock();
            float current = radio_.txPower();
            host_.unlock();
            std::vector<float> powers;
            powers.push_back(current);
            for (float p : kFallbackPowers) {
                if (p < current - 0.01f) powers.push_back(p);
            }
            for (float p : powers) {
                std::shared_ptr<int> result(new int(-1));
                uint8_t ping[4] = {0, 0, 0, 0};  // type 0: ignored by the receiver
                host_.lock();
                radio_.setTxPower(p);
                Status st = engine_.send(n.mac, kDiagnosticsPort, ping, sizeof(ping), SendOptions(),
                                         [result](Status s) { *result = static_cast<int>(s); }, host_.now());
                host_.unlock();
                if (st == Status::Ok) waitFor([result]() { return *result >= 0; }, 2000);
                host_.lock();
                radio_.setTxPower(current);
                host_.unlock();
                if (*result == static_cast<int>(Status::Ok)) {
                    n.hearsUs = true;
                    n.hearsUsAtDbm = p;
                    break;
                }
            }
        }
    }

    for (const DiscoveredNode& n : nodes) {
        if (!n.nowtp) continue;
        std::string who = n.name.empty() ? std::string("a node") : "\"" + n.name + "\"";
        if (n.protocolVersion != wire::kVersion) {
            out.issues.push_back(makeIssue(IssueKind::OtherProtocolVersion, false, n.mac, n.protocolVersion,
                                           PhyRate::Default,
                                           format("%s speaks NowTP protocol version %u (we speak %u)", who.c_str(),
                                                  n.protocolVersion, wire::kVersion)));
            continue;
        }
        if (n.networkId != ourNetwork) {
            out.issues.push_back(makeIssue(IssueKind::OtherNetworkId, false, n.mac, n.networkId, PhyRate::Default,
                                           format("%s uses network id %u (ours is %u)", who.c_str(), n.networkId,
                                                  ourNetwork)));
        }
        if (n.channel != home) {
            out.issues.push_back(makeIssue(IssueKind::OtherChannel, false, n.mac, n.channel, PhyRate::Default,
                                           format("%s is on channel %u (we are on %u)", who.c_str(), n.channel, home)));
        }
        if (n.longRangeOnly) {
            out.issues.push_back(makeIssue(IssueKind::LongRangeOnly, false, n.mac, 0, PhyRate::LR500K,
                                           format("%s is only heard with Long Range: enable radio.longRange", who.c_str())));
        }
        if (n.maxFrameSize != 0 && n.maxFrameSize <= 250) {
            out.issues.push_back(makeIssue(IssueKind::SmallFramesOnly, false, n.mac, n.maxFrameSize, PhyRate::Default,
                                           format("%s takes 250-byte frames only (ESP-NOW v1)", who.c_str())));
        }
        if (n.compatible && opt.checkTxPower) {
            if (!n.hearsUs) {
                out.issues.push_back(makeIssue(IssueKind::DoesNotHearUs, true, n.mac, 0, PhyRate::Default,
                                               format("we hear %s but it never acknowledges our frames", who.c_str())));
            }
        }
    }
    for (const DiscoveredNode& n : nodes) {
        if (n.compatible && n.hearsUs && !nodes.empty()) {
            host_.lock();
            float current = radio_.txPower();
            host_.unlock();
            if (n.hearsUsAtDbm < current - 0.01f) {
                std::string who = n.name.empty() ? std::string("a node") : "\"" + n.name + "\"";
                out.issues.push_back(makeIssue(IssueKind::HearsUsOnlyAtLowerPower, true, n.mac, n.hearsUsAtDbm,
                                               PhyRate::Default,
                                               format("%s only acknowledges us at %.1f dBm or less: set radio.txPowerDbm",
                                                      who.c_str(), n.hearsUsAtDbm)));
            }
        }
    }
    if (!foreign.empty()) {
        out.issues.push_back(makeIssue(IssueKind::ForeignTraffic, false, foreign.front(), static_cast<float>(foreign.size()),
                                       PhyRate::Default,
                                       format("%u node(s) send non-NowTP ESP-NOW traffic", static_cast<unsigned>(foreign.size()))));
    }
    out.nodes = nodes;
    return Status::Ok;
}

}  // namespace nowtp
