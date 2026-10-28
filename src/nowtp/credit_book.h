// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <stdint.h>

#include <vector>

#include "types.h"

namespace nowtp {

/// Receiver credit, on the sending side: the room each receiver last said
/// it has for our next message (in its acks, Config::receiverCredit), less
/// what we started since. A word holds for `ttlMs`. A new multi-frame message
/// it has no room for waits, instead of costing a frame and a Busy ack.
/// At most `capacity` receivers, reserved up front: noting one never
/// allocates (it runs on the receive path); when full, the oldest word goes.
class CreditBook {
public:
    CreditBook(size_t capacity, uint32_t ttlMs) : ttlMs_(ttlMs) { credits_.reserve(capacity); }

    /// What reassembling `count` fragments of `fragSize` takes at a receiver
    /// (Engine::admitRx()): the buffer and its bitmap.
    static size_t need(uint16_t count, uint16_t fragSize) {
        return static_cast<size_t>(count) * fragSize + (count + 7u) / 8;
    }

    /// `dst` said it has `units` of wire::kCreditUnit (wire::kCreditMax: plenty).
    void note(const Mac& dst, uint8_t units, uint32_t now);
    /// A message needing `bytes` at `dst` started: room the word didn't count.
    void spend(const Mac& dst, size_t bytes);
    /// True while a new message needing `bytes` may not start at `dst`;
    /// `until` receives when the word saying so expires.
    bool waits(const Mac& dst, size_t bytes, uint32_t now, uint32_t* until = nullptr) const;
    /// Forgets expired words.
    void expire(uint32_t now);
    size_t size() const { return credits_.size(); }

private:
    struct Credit {
        Mac dst;
        uint32_t room;  // bytes; UINT32_MAX: plenty
        uint32_t at;
    };
    Credit* find(const Mac& dst);
    const Credit* find(const Mac& dst) const;

    std::vector<Credit> credits_;
    uint32_t ttlMs_;
};

}  // namespace nowtp
