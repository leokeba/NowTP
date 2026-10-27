// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "link_monitor.h"

#include <algorithm>

#include "diagnostics.h"  // kDiagnosticsPort

namespace nowtp {

namespace {

inline bool reached(uint32_t now, uint32_t deadline) {
    return static_cast<int32_t>(now - deadline) >= 0;
}

const float kLadder[] = {17, 15, 13, 11, 8, 5};
const uint8_t kPing[1] = {0};  // type 0: ignored by the receiver's diagnostics
constexpr uint8_t kCheckPings = 3;
constexpr uint32_t kCheckSpacingMs = 200;
constexpr uint32_t kRetryMs = 50;

}  // namespace

constexpr size_t LinkMonitor::kMaxPeers;
constexpr size_t LinkMonitor::kMaxChecks;
constexpr uint16_t LinkMonitor::kOneWayFailures;
constexpr uint32_t LinkMonitor::kOneWayHeardMs;

const char* toString(LinkMonitor::Event event) {
    switch (event) {
        case LinkMonitor::Event::OneWay: return "OneWay";
        case LinkMonitor::Event::FallbackStarted: return "FallbackStarted";
        case LinkMonitor::Event::PowerKept: return "PowerKept";
        case LinkMonitor::Event::PowerLowered: return "PowerLowered";
        case LinkMonitor::Event::FallbackFailed: return "FallbackFailed";
    }
    return "?";
}

LinkMonitor::LinkMonitor(Engine& engine, Host& host) : engine_(engine), host_(host) {}

void LinkMonitor::reset(bool powerFallback) {
    powerFallback_ = powerFallback;
    healthCount_ = 0;
    checkCount_ = 0;
    fallback_ = Fallback();
}

LinkMonitor::Health* LinkMonitor::health(const Mac& mac) {
    for (size_t i = 0; i < healthCount_; ++i) {
        if (health_[i].mac == mac) return &health_[i];
    }
    return nullptr;
}

// Full: the peer heard least recently gives way.
LinkMonitor::Health* LinkMonitor::addHealth(const Mac& mac, uint32_t now) {
    size_t i = healthCount_;
    if (i == kMaxPeers) {
        i = 0;
        for (size_t j = 1; j < healthCount_; ++j) {
            if (static_cast<int32_t>(health_[j].lastHeardMs - health_[i].lastHeardMs) < 0) i = j;
        }
    } else {
        healthCount_++;
    }
    Health fresh = {mac, now, 0, false};
    health_[i] = fresh;
    return &health_[i];
}

void LinkMonitor::heard(const Mac& peer, uint32_t now) {
    Health* h = health(peer);
    if (!h) h = addHealth(peer, now);
    h->lastHeardMs = now;
}

void LinkMonitor::sent(const Mac& peer, bool delivered, uint32_t now) {
    if (peer.isBroadcast()) return;
    Health* h = health(peer);
    if (!h) return;  // never heard from it: an absent peer, not a one-way link
    if (delivered) {
        h->failures = 0;
        return;
    }
    if (++h->failures < kOneWayFailures) return;
    if (static_cast<int32_t>(now - h->lastHeardMs) > static_cast<int32_t>(kOneWayHeardMs)) return;
    if (!h->warned) {
        h->warned = true;
        float p = host_.txPower();
        host_.linkEvent(Event::OneWay, peer, p, p);
    }
    if (powerFallback_) startFallback(peer, now);
}

void LinkMonitor::found(const Mac& peer, uint32_t now) {
    if (!powerFallback_ || checkCount_ == kMaxChecks) return;
    Check c = {nextCheckId_++, peer, kCheckPings, false, now};
    checks_[checkCount_++] = c;
}

void LinkMonitor::startFallback(const Mac& peer, uint32_t now) {
    Fallback& f = fallback_;
    if (f.active) return;
    const size_t kTried = sizeof(f.tried) / sizeof(f.tried[0]);
    size_t tried = std::min(f.triedCount, kTried);
    if (std::find(f.tried, f.tried + tried, peer) != f.tried + tried) return;
    f.tried[f.triedCount++ % kTried] = peer;
    float current = host_.txPower();
    size_t steps = 0;
    for (float p : kLadder) {
        if (p < current - 0.1f) f.ladder[steps++] = p;
    }
    if (steps == 0) return;
    f.active = true;
    f.peer = peer;
    f.original = current;
    f.steps = steps;
    f.index = 0;
    f.failures = 0;
    f.pingInFlight = false;
    f.confirming = false;
    f.nextPingAt = now;
    host_.linkEvent(Event::FallbackStarted, peer, current, f.ladder[0]);
    host_.setTxPower(f.ladder[0]);
}

void LinkMonitor::sendFallbackPing(uint32_t now) {
    fallback_.pingInFlight = true;
    Status st = engine_.send(fallback_.peer, kDiagnosticsPort, kPing, sizeof(kPing), SendOptions(),
                             [this](Status s) { onFallbackPing(s); }, now);
    if (st != Status::Ok && fallback_.pingInFlight) {  // not already completed
        fallback_.pingInFlight = false;
        fallback_.nextPingAt = now + kRetryMs;
    }
}

void LinkMonitor::onFallbackPing(Status status) {
    Fallback& f = fallback_;
    if (!f.active) return;
    f.pingInFlight = false;
    uint32_t now = engine_.now();
    if (f.confirming) {
        // A lower power worked; does the original power work again too? Then the
        // peer was briefly away (rebooting, other channel), not our transmitter.
        f.confirming = false;
        f.active = false;
        if (Health* h = health(f.peer)) h->failures = 0;
        if (status == Status::Ok) {
            host_.linkEvent(Event::PowerKept, f.peer, f.original, f.original);
            return;
        }
        host_.setTxPower(f.ladder[f.index]);
        host_.linkEvent(Event::PowerLowered, f.peer, f.original, host_.txPower());
        return;
    }
    if (status == Status::Ok) {
        f.confirming = true;
        host_.setTxPower(f.original);
        f.nextPingAt = now;
        return;
    }
    if (++f.failures < 2) {
        f.nextPingAt = now + kRetryMs;
        return;
    }
    f.failures = 0;
    if (++f.index < f.steps) {
        host_.setTxPower(f.ladder[f.index]);
        f.nextPingAt = now;
        return;
    }
    host_.setTxPower(f.original);
    f.active = false;
    host_.linkEvent(Event::FallbackFailed, f.peer, f.original, f.original);
}

void LinkMonitor::onCheck(uint32_t id, Status status) {
    for (size_t i = 0; i < checkCount_; ++i) {
        Check& c = checks_[i];
        if (c.id != id) continue;
        c.inFlight = false;
        c.nextAt = engine_.now() + kCheckSpacingMs;
        if (status == Status::Ok) c.remaining = 0;  // healthy
        return;
    }
}

void LinkMonitor::tick(uint32_t now) {
    if (fallback_.active && !fallback_.pingInFlight && reached(now, fallback_.nextPingAt)) sendFallbackPing(now);
    for (size_t i = 0; i < checkCount_;) {
        Check& c = checks_[i];
        if (c.inFlight || !reached(now, c.nextAt)) {
            ++i;
            continue;
        }
        if (c.remaining == 0) {
            checks_[i] = checks_[--checkCount_];
            continue;
        }
        // Each failed frame reaches sent() through the radio's report: the
        // ping is only there to make one.
        c.inFlight = true;
        c.remaining--;
        uint32_t id = c.id;
        Status st = engine_.send(c.peer, kDiagnosticsPort, kPing, sizeof(kPing), SendOptions(),
                                 [this, id](Status s) { onCheck(id, s); }, now);
        if (st != Status::Ok) {
            for (size_t j = 0; j < checkCount_; ++j) {
                if (checks_[j].id == id) checks_[j].inFlight = false;
            }
        }
        ++i;
    }
}

void LinkMonitor::nextTick(Deadline& d) const {
    if (fallback_.active && !fallback_.pingInFlight) d.at(fallback_.nextPingAt);
    for (size_t i = 0; i < checkCount_; ++i) {
        if (!checks_[i].inFlight) d.at(checks_[i].nextAt);
    }
}

}  // namespace nowtp
