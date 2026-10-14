// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include "types.h"

namespace nowtp {

/// Matches a radio's "sent" callbacks to frames, for a platform layer whose
/// callback doesn't say which frame it reports. It counts frames handed to
/// the driver against callbacks, and checks the destination.
///
/// The engine keeps one frame outstanding, but gives up on one after
/// Config::frameSentTimeoutMs. That frame's callback may still come, and must
/// not be credited to the next frame (to the same peer, the MAC alone can't
/// tell them apart).
class SendTracker {
public:
    /// A callback missing this long after its frame was sent is never coming.
    static constexpr uint32_t kLostMs = 2000;

    /// A frame to `dst` was handed to the driver; `reported` is the driver's
    /// callback count so far.
    void sent(const Mac& dst, uint32_t reported, uint32_t nowMs) {
        if (outstanding(reported) > 0 && static_cast<int32_t>(nowMs - lastSentMs_) >= static_cast<int32_t>(kLostMs)) {
            skipped_ = issued_ - reported;
        }
        issued_++;
        dst_ = dst;
        lastSentMs_ = nowMs;
    }

    /// The driver has made `reported` callbacks, the last one for `mac` (all
    /// zero if it didn't say). True if that one reports the frame sent last,
    /// once: then nothing is outstanding.
    bool reports(uint32_t reported, const Mac& mac) {
        if (reported == seen_) return false;
        seen_ = reported;
        int32_t ahead = static_cast<int32_t>(reported + skipped_ - issued_);
        if (ahead > 0) {
            skipped_ = issued_ - reported;  // a callback we had given up on
            return false;
        }
        if (ahead < 0) return false;  // for a frame the engine gave up on; the last one's is still to come
        if (mac == dst_ || mac == Mac()) return true;
        if (skipped_ > 0) skipped_--;  // the late callback of one given up on: the last one's is still to come
        return false;
    }

private:
    int32_t outstanding(uint32_t reported) const { return static_cast<int32_t>(issued_ - skipped_ - reported); }

    uint32_t issued_ = 0;
    uint32_t skipped_ = 0;  // callbacks given up on
    uint32_t seen_ = 0;
    uint32_t lastSentMs_ = 0;
    Mac dst_{};
};

}  // namespace nowtp
