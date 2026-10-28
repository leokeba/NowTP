// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "credit_book.h"

#include "wire.h"

namespace nowtp {

namespace {
inline bool reached(uint32_t now, uint32_t deadline) {
    return static_cast<int32_t>(now - deadline) >= 0;
}
}  // namespace

CreditBook::Credit* CreditBook::find(const Mac& dst) {
    for (Credit& c : credits_) {
        if (c.dst == dst) return &c;
    }
    return nullptr;
}

const CreditBook::Credit* CreditBook::find(const Mac& dst) const {
    for (const Credit& c : credits_) {
        if (c.dst == dst) return &c;
    }
    return nullptr;
}

void CreditBook::note(const Mac& dst, uint8_t units, uint32_t now) {
    Credit* c = find(dst);
    if (!c && credits_.size() < credits_.capacity()) {  // never grows
        Credit fresh = {dst, 0, 0};
        credits_.push_back(fresh);
        c = &credits_.back();
    }
    if (!c) {  // full: the oldest word goes, likely expired (they are forgotten only in expire())
        if (credits_.empty()) return;
        c = &credits_[0];
        for (Credit& x : credits_) {
            if (static_cast<int32_t>(x.at - c->at) < 0) c = &x;
        }
        c->dst = dst;
    }
    c->room = units >= wire::kCreditMax ? UINT32_MAX : static_cast<uint32_t>(units * wire::kCreditUnit);
    c->at = now;
}

void CreditBook::spend(const Mac& dst, size_t bytes) {
    Credit* c = find(dst);
    if (!c || c->room == UINT32_MAX) return;
    c->room = c->room > bytes ? static_cast<uint32_t>(c->room - bytes) : 0;
}

bool CreditBook::waits(const Mac& dst, size_t bytes, uint32_t now, uint32_t* until) const {
    const Credit* c = find(dst);
    if (!c || reached(now, c->at + ttlMs_) || c->room >= bytes) return false;
    if (until) *until = c->at + ttlMs_;
    return true;
}

void CreditBook::expire(uint32_t now) {
    for (size_t i = 0; i < credits_.size();) {
        if (reached(now, credits_[i].at + ttlMs_)) {
            credits_.erase(credits_.begin() + static_cast<std::ptrdiff_t>(i));
            continue;
        }
        ++i;
    }
}

}  // namespace nowtp
