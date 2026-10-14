// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "peer_table.h"

namespace nowtp {

PeerTable::Entry* PeerTable::find(const Mac& mac) {
    for (Entry& e : entries_) {
        if (e.mac == mac) return &e;
    }
    return nullptr;
}

Status PeerTable::use(const Mac& mac, uint32_t nowMs, bool& added) {
    added = false;
    if (hasInFlight_ && inFlight_ == mac) releaseInFlight_ = false;  // wanted again
    Entry* e = find(mac);
    if (e) {
        e->lastUsed = nowMs;
        if (e->pinned || driver_.exists(mac)) return Status::Ok;
    } else if (driver_.exists(mac)) {
        return Status::Ok;  // registered outside NowTP's knowledge: leave it alone
    }
    for (;;) {
        Driver::Result r = driver_.add(mac);
        if (r == Driver::Result::Ok) break;
        if (r == Driver::Result::Error || !evictOne()) return Status::LinkError;
    }
    added = true;
    e = find(mac);  // evictOne() may have moved entries
    if (e) {
        e->lastUsed = nowMs;
    } else {
        Entry fresh = {mac, nowMs, false};
        entries_.push_back(fresh);
    }
    return Status::Ok;
}

bool PeerTable::evictOne() {
    size_t victim = entries_.size();
    for (size_t i = 0; i < entries_.size(); ++i) {
        const Entry& e = entries_[i];
        if (e.pinned || (hasInFlight_ && e.mac == inFlight_)) continue;
        if (victim == entries_.size() || static_cast<int32_t>(e.lastUsed - entries_[victim].lastUsed) < 0) victim = i;
    }
    if (victim == entries_.size()) return false;
    driver_.remove(entries_[victim].mac);
    entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(victim));
    return true;
}

void PeerTable::pin(const Mac& mac) {
    Entry* e = find(mac);
    if (e) {
        e->pinned = true;
    } else {
        Entry fresh = {mac, 0, true};
        entries_.push_back(fresh);
    }
    if (hasInFlight_ && inFlight_ == mac) releaseInFlight_ = false;
}

void PeerTable::forget(const Mac& mac) {
    for (size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].mac == mac) {
            entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(i));
            break;
        }
    }
    if (hasInFlight_ && inFlight_ == mac) releaseInFlight_ = false;
}

void PeerTable::release(const Mac& mac) {
    Entry* e = find(mac);
    if (!e || e->pinned) return;
    if (hasInFlight_ && inFlight_ == mac) {
        releaseInFlight_ = true;
        return;
    }
    driver_.remove(mac);
    forget(mac);
}

void PeerTable::setInFlight(const Mac& mac) {
    // The previous frame was never reported (the engine gave up on it).
    if (hasInFlight_ && !(inFlight_ == mac)) clearInFlight();
    inFlight_ = mac;
    hasInFlight_ = true;
    releaseInFlight_ = false;
}

void PeerTable::clearInFlight() {
    if (!hasInFlight_) return;
    hasInFlight_ = false;
    if (releaseInFlight_) {
        releaseInFlight_ = false;
        release(inFlight_);
    }
}

void PeerTable::clear() {
    entries_.clear();
    hasInFlight_ = false;
    releaseInFlight_ = false;
}

size_t PeerTable::automatic() const {
    size_t n = 0;
    for (const Entry& e : entries_) {
        if (!e.pinned) n++;
    }
    return n;
}

}  // namespace nowtp
