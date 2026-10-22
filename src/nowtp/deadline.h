// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <stdint.h>

namespace nowtp {

/// When tick() must run next: the earliest of the times the parts of NowTP
/// name (retransmissions, timeouts, announcements, time rounds...). Times are
/// in ms on the caller's wrapping clock. A part may name a time too early,
/// never too late: ticking early does no harm, late delays its work.
class Deadline {
public:
    explicit Deadline(uint32_t nowMs) : now_(nowMs) {}

    /// Something is due at `t`; a time already past is due now.
    void at(uint32_t t) {
        int32_t d = static_cast<int32_t>(t - now_);
        uint32_t ms = d > 0 ? static_cast<uint32_t>(d) : 0;
        if (!set_ || ms < delay_) delay_ = ms;
        set_ = true;
    }
    /// Something is due `ms` from now.
    void in(uint32_t ms) { at(now_ + ms); }

    uint32_t now() const { return now_; }
    /// False while nothing is due at all (events alone have work for tick()).
    bool set() const { return set_; }
    /// Milliseconds until the earliest time, 0 if due; `none` if nothing is.
    uint32_t delay(uint32_t none = UINT32_MAX) const { return set_ ? delay_ : none; }

private:
    uint32_t now_;
    uint32_t delay_ = 0;
    bool set_ = false;
};

}  // namespace nowtp
