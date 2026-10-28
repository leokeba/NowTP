// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <stdint.h>

#include "table.h"
#include "types.h"

namespace nowtp {

/// Message ids delivered from each sender, so that a duplicate is recognized
/// however many other senders' messages arrived since. A sender's ids fall
/// in kBlocks blocks of 32 (block id / 32 at slot (id / 32) % kBlocks),
/// ending with the block of its newest id: about the last 100 to 128 ids of
/// all its traffic. A block's bits count for `ttlMs` after its last delivery.
/// One entry per sender heard (44 bytes, malloc'd), up to `senders`; when
/// full, or short of memory, the sender that delivered least recently gives
/// way.
class DuplicateFilter {
public:
    static constexpr uint16_t kBlocks = 4;

    DuplicateFilter(size_t senders, uint32_t ttlMs) : seen_(senders), ttlMs_(ttlMs) {}

    /// Records `id` from `src` as delivered.
    void mark(const Mac& src, uint16_t id, uint32_t now);
    /// True if `id` from `src` was delivered within the window.
    bool seen(const Mac& src, uint16_t id, uint32_t now) const;
    size_t senders() const { return seen_.size(); }

private:
    struct Seen {  // 44 bytes
        Mac src;
        uint16_t top;   // newest id delivered
        uint32_t last;  // last delivery
        uint32_t bits[kBlocks];
        uint32_t at[kBlocks];  // last delivery in each block
    };
    Table<Seen> seen_;
    uint32_t ttlMs_;
};

}  // namespace nowtp
