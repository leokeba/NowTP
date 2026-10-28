// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
//
// The engine's own types and helpers, shared by engine.cpp (setup, timers,
// frame dispatch, control frames), engine_tx.cpp (sending) and
// engine_rx.cpp (receiving). Not part of the API.
#pragma once

#include "engine.h"

#include <algorithm>
#include <cstdlib>
#include <new>

namespace nowtp {

using namespace wire;

namespace engine_detail {

// Wrap-safe "now has reached deadline".
inline bool reached(uint32_t now, uint32_t deadline) {
    return static_cast<int32_t>(now - deadline) >= 0;
}

// True if message id `a` is older than `b` by less than `window`.
inline bool olderWithin(uint16_t a, uint16_t b, uint16_t window) {
    uint16_t d = static_cast<uint16_t>(b - a);
    return d != 0 && d < window;
}

// Late frames of a superseded message are at most a few ids behind; anything
// further back is more likely a rebooted sender and is accepted.
constexpr uint16_t kStaleWindow = 256;
constexpr size_t kAckHeaderSize = kCommonHeaderSize + 1;  // + status byte
// Backoff of a destination whose frames fail, doubling per failure. A failed
// unicast frame holds the radio ~100 ms (hardware retries), so an absent peer
// served in turn would still take most of the airtime.
constexpr uint32_t kBackoffMinMs = 50;
constexpr uint32_t kBackoffMaxMs = 800;
constexpr uint32_t kResealIntervalMs = 1000;  // per message (see reseal())

// Message and control frame buffers (Bytes, engine.h): null on a short heap.
inline Bytes allocBytes(size_t n) { return Bytes(static_cast<uint8_t*>(heap::allocate(n == 0 ? 1 : n))); }
inline Bytes allocZeroed(size_t n) {
    Bytes b = allocBytes(n);
    if (b) memset(b.get(), 0, n == 0 ? 1 : n);
    return b;
}

}  // namespace engine_detail

using namespace engine_detail;

struct Engine::TxMessage {
    Mac dst;
    uint8_t port = 0;
    uint8_t flags = 0;  // kFlagReliable | kFlagLatest
    uint16_t id = 0;
    uint16_t count = 1;     // 1 = single frame
    uint16_t fragSize = 0;  // stream bytes per fragment when count > 1
    size_t streamLen = 0;   // payload, plus CRC-32 when count > 1
    size_t trailerAt = 0;   // offset of the authentication trailer (with kFlagAuth)
    bool onAir = false;     // a frame of this cut was sent (see fitFrames())
    // Earlier seals' binds, newest first: an ack may still come for a copy
    // sent before reseal(). Seals that never went on air aren't kept.
    static constexpr size_t kOldBinds = 3;
    uint8_t oldBinds = 0;
    bool sentSinceSeal = false;
    bool resealed = false;      // by reseal(), at `resealAt`
    bool resealWanted = false;  // asked again within a second: done at resealAt + 1 s
    uint32_t resealAt = 0;
    uint8_t bindsBefore[kOldBinds * kAckBindSize];
    // kSendHeadroom bytes, then the stream, then room for a CRC-32 even when
    // count is 1 (fitFrames() may cut it into fragments later).
    Bytes stream;
    uint16_t nextIndex = 0;  // next fragment of the first pass
    Bytes resend;            // bitmap of fragments to send again, allocated on first use
    uint16_t resendCount = 0;
    bool awaitingAck = false;
    uint32_t ackDeadline = 0;
    uint32_t deadline = 0;
    uint8_t frameFailures = 0;
    bool waitedForCredit = false;
    CompletionHandler done;
    uint32_t tag = 0;            // for the port's observer, without `done`
    Status result = Status::Ok;  // once finished
    TxMessage* nextDone = nullptr;

    uint8_t* data() const { return stream.get() + kSendHeadroom; }
    size_t payloadLen() const { return count > 1 ? streamLen - kCrcSize : streamLen; }
    bool reliable() const { return (flags & kFlagReliable) != 0; }
    bool latest() const { return (flags & kFlagLatest) != 0; }
    bool firstPassPending() const { return nextIndex < count; }
    bool hasPendingFrame() const { return firstPassPending() || resendCount > 0; }
    bool resending(uint16_t i) const { return resend && ((resend[i >> 3] >> (i & 7)) & 1); }
    uint16_t pendingFrame() const {
        if (firstPassPending()) return nextIndex;
        for (uint16_t i = 0; i < count; ++i) {
            if (resending(i)) return i;
        }
        return 0;
    }
    bool isLastPending() const {
        return firstPassPending() ? (nextIndex + 1 == count && resendCount == 0) : resendCount == 1;
    }
    // Without memory for the bitmap, the fragment is not queued: the probe
    // after the ack timeout asks the receiver again.
    void addResend(uint16_t index) {
        if (index >= count) return;
        if (firstPassPending() && index >= nextIndex) return;  // first pass will send it anyway
        if (!resend) resend = allocZeroed((static_cast<size_t>(count) + 7) / 8);
        if (!resend || resending(index)) return;
        resend[index >> 3] = static_cast<uint8_t>(resend[index >> 3] | (1u << (index & 7)));
        resendCount++;
    }
    void sentResend(uint16_t index) {
        if (!resending(index)) return;
        resend[index >> 3] = static_cast<uint8_t>(resend[index >> 3] & ~(1u << (index & 7)));
        resendCount--;
    }
    void clearResend() {
        resend.reset();
        resendCount = 0;
    }
};

struct Engine::RxMessage {
    Mac src;
    uint8_t port = 0;
    uint8_t flags = 0;
    uint16_t id = 0;
    uint16_t count = 0;
    uint16_t received = 0;
    uint16_t fragSize = 0;  // learned from the first non-last fragment
    bool limited = false;   // its sender has no verified epoch (Authenticator::screen)
    Bytes buf;
    Bytes bitmap;
    Bytes stashedLast;  // last fragment, held until fragSize is known (lastLen bytes)
    size_t lastLen = 0;
    size_t reserved = 0;  // bytes counted in rxBytes_
    uint32_t lastActivity = 0;
    int8_t rssi = 0;
    uint64_t timeUs = 0;

    bool has(uint16_t i) const { return (bitmap[i >> 3] >> (i & 7)) & 1; }
    void mark(uint16_t i) { bitmap[i >> 3] |= static_cast<uint8_t>(1u << (i & 7)); }
};

}  // namespace nowtp
