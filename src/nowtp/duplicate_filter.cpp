// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "duplicate_filter.h"

#include <string.h>

#include <algorithm>

namespace nowtp {

constexpr uint16_t DuplicateFilter::kBlocks;

namespace {

inline bool reached(uint32_t now, uint32_t deadline) {
    return static_cast<int32_t>(now - deadline) >= 0;
}

// Block of 32 ids; 2048 of them cover the id space, so differences wrap at 11 bits.
inline uint16_t blocksBehind(uint16_t newer, uint16_t older) {
    return static_cast<uint16_t>(((newer >> 5) - (older >> 5)) & 0x7FF);
}

}  // namespace

void DuplicateFilter::mark(const Mac& src, uint16_t id, uint32_t now) {
    Seen* s = nullptr;
    size_t oldest = 0;
    for (size_t i = 0; i < seen_.size(); ++i) {
        if (seen_[i].src == src) {
            s = &seen_[i];
            break;
        }
        if (static_cast<int32_t>(seen_[i].last - seen_[oldest].last) < 0) oldest = i;
    }
    bool fresh = s == nullptr || reached(now, s->last + ttlMs_);
    if (!s) {
        Seen blank;
        memset(&blank, 0, sizeof(blank));
        blank.src = src;
        s = seen_.add(blank);
        // Full, or no memory for another: the sender heard least recently gives way.
        if (!s && !seen_.empty()) s = &seen_[oldest];
        if (!s) return;  // the engine's ring of recent messages still holds the id
        s->src = src;
    }
    if (fresh) {
        memset(s->bits, 0, sizeof(s->bits));
        s->top = id;
    } else if (static_cast<int16_t>(id - s->top) > 0) {
        // Newer: clear the blocks the window moves onto.
        uint16_t steps = std::min(blocksBehind(id, s->top), kBlocks);
        for (uint16_t k = 1; k <= steps; ++k) s->bits[((s->top >> 5) + k) % kBlocks] = 0;
        s->top = id;
    } else if (blocksBehind(s->top, id) >= kBlocks) {
        return;  // older than the window; the engine's ring may still hold it
    }
    size_t slot = (id >> 5) % kBlocks;
    s->bits[slot] |= 1u << (id & 31);
    s->at[slot] = now;
    s->last = now;
}

bool DuplicateFilter::seen(const Mac& src, uint16_t id, uint32_t now) const {
    for (const Seen& s : seen_) {
        if (!(s.src == src)) continue;
        if (reached(now, s.last + ttlMs_)) return false;
        if (static_cast<int16_t>(id - s.top) > 0 || blocksBehind(s.top, id) >= kBlocks) return false;
        size_t slot = (id >> 5) % kBlocks;
        return ((s.bits[slot] >> (id & 31)) & 1) && !reached(now, s.at[slot] + ttlMs_);
    }
    return false;
}

}  // namespace nowtp
