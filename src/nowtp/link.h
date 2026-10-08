// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include "types.h"

namespace nowtp {

/// Frame-level radio interface the protocol engine runs on.
///
/// The engine keeps at most one frame outstanding: after a successful
/// sendFrame() it waits for Engine::onFrameSent() before sending the next one.
/// That keeps frames in order and paces the sender to what the radio and the
/// receiver can absorb.
class Link {
public:
    virtual ~Link() {}

    /// Hands one frame to the radio. The data may be reused once this returns.
    /// Return Ok if accepted, QueueFull if the radio is temporarily busy (the
    /// engine retries shortly), or another status to fail the message.
    virtual Status sendFrame(const Mac& dst, const uint8_t* data, size_t len) = 0;

    /// Largest frame that may be sent to `dst`.
    virtual size_t maxFrameSize(const Mac& dst) const = 0;
};

}  // namespace nowtp
