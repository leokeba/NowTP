// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <functional>

namespace nowtp {

/// 6-byte MAC address.
struct Mac {
    uint8_t bytes[6];

    static Mac broadcast() {
        Mac m;
        memset(m.bytes, 0xFF, sizeof(m.bytes));
        return m;
    }

    static Mac from(const uint8_t* b) {
        Mac m;
        memcpy(m.bytes, b, sizeof(m.bytes));
        return m;
    }

    bool isBroadcast() const {
        for (uint8_t b : bytes) {
            if (b != 0xFF) return false;
        }
        return true;
    }

    bool operator==(const Mac& o) const { return memcmp(bytes, o.bytes, sizeof(bytes)) == 0; }
    bool operator!=(const Mac& o) const { return !(*this == o); }
};

/// Result of an operation, or final outcome of a sent message.
enum class Status : uint8_t {
    Ok = 0,
    InvalidArgument,  ///< Bad parameters (e.g. reliable delivery to broadcast).
    InvalidState,     ///< Not started, or called from a context where it would deadlock.
    TooLarge,         ///< Message exceeds Config::maxMessageSize or the protocol limit.
    QueueFull,        ///< Too many messages or bytes queued for sending.
    NoMemory,         ///< Allocation failed.
    LinkError,        ///< The radio rejected the frame (e.g. unknown peer).
    SendFailed,       ///< The radio could not deliver a frame after retries.
    Timeout,          ///< Reliable message not acknowledged before its deadline.
    Rejected,         ///< Receiver refused the message (no listener on port, too large).
    Superseded,       ///< Replaced by a newer "latest only" message to the same peer and port.
    Cancelled,        ///< Transport stopped before the message completed.
    AuthFailed,       ///< Authentication failed: the receiver holds another installation key, or none.
};

const char* toString(Status s);

/// Per-message send options.
struct SendOptions {
    /// Retransmit until the receiver acknowledges the whole message. Unicast only.
    bool reliable = false;
    /// Only the newest message per (peer, port) matters: a newer one cancels older
    /// queued/partial ones on both the sender and the receiver.
    bool latestOnly = false;
    /// Deadline for the whole message in ms; 0 uses Config::sendTimeoutMs.
    uint32_t timeoutMs = 0;
};

/// A received message. `data` is only valid during the receive callback,
/// unless the handler takes `buffer`.
struct Message {
    Mac src;
    uint8_t port;
    const uint8_t* data;
    size_t len;
    bool reliable;
    bool latestOnly;
    /// Signal strength of the last frame in dBm; 0 if the radio did not report it.
    int8_t rssi;
    /// Verified with the installation key (see Security). Always false without one.
    bool authenticated;
    /// Local clock (microseconds) when the radio delivered the last frame; 0 if unknown.
    uint64_t timestampUs;
    /// For a message reassembled from several frames: the malloc()ed buffer
    /// that `data` points to the start of. A handler keeps the message without
    /// copying by setting this to nullptr; it then owns the buffer, `data`
    /// stays valid, and it must free() the buffer itself. Otherwise NowTP frees
    /// it after the handler. Null for a single-frame message (`data` points
    /// into the frame), which must be copied to be kept.
    mutable uint8_t* buffer = nullptr;
    /// Set by the handler to refuse a message it can't take now, e.g. on a
    /// short heap. The message counts as not received: a reliable sender is
    /// told the receiver is busy and sends it again shortly, which the
    /// handler then sees as a new delivery. An unreliable message is dropped.
    mutable bool refused = false;
};

/// Ports used by NowTP's own services. Ports 240-255 are reserved.
constexpr uint8_t kDiscoveryPort = 255;
constexpr uint8_t kSecurityPort = 253;
constexpr uint8_t kTimeSyncPort = 252;
constexpr uint8_t kStreamPort = 251;
constexpr uint8_t kFirstReservedPort = 240;

using ReceiveHandler = std::function<void(const Message&)>;
using CompletionHandler = std::function<void(Status)>;

/// Protocol engine limits and timings. Defaults suit 250-byte ESP-NOW v1 frames.
struct Config {
    /// Separates independent NowTP networks sharing a channel. Frames with a
    /// different id are ignored. This is not a security feature.
    uint8_t networkId = 0;
    /// Largest message accepted for sending or reassembly.
    size_t maxMessageSize = 16 * 1024;
    /// Outgoing messages queued or in flight.
    uint8_t maxTxMessages = 8;
    /// Total payload bytes held by queued outgoing messages.
    size_t maxTxBytes = 32 * 1024;
    /// Of those, to a single destination, so an absent peer cannot fill the
    /// queue for everyone (send() returns QueueFull for that destination only).
    uint8_t maxTxMessagesPerPeer = 4;
    size_t maxTxBytesPerPeer = 24 * 1024;
    /// Messages being reassembled at once. When full (or over maxRxBytes), a
    /// new message replaces one idle for 3 x ackTimeoutMs, or else is refused
    /// (a reliable sender is told to back off and retry). A message in
    /// progress is never evicted.
    uint8_t maxRxMessages = 4;
    /// Of those, from a single sender (so one sender cannot take every slot).
    uint8_t maxRxMessagesPerSender = 2;
    /// Total bytes held by reassembly buffers.
    size_t maxRxBytes = 32 * 1024;
    /// Tell senders, in acks, how much reassembly room is left for their next
    /// message, and hold a new multi-frame message to a receiver that said it
    /// has no room for it, until it says so again or 3 x ackTimeoutMs pass,
    /// instead of sending a frame only to be refused. Older nodes neither send
    /// nor read it.
    bool receiverCredit = true;
    /// A partial message is dropped after this long without a new fragment.
    uint32_t rxTimeoutMs = 1000;
    /// Default deadline for a whole outgoing message.
    uint32_t sendTimeoutMs = 2000;
    /// Reliable mode: wait this long for an acknowledgement before probing again.
    uint32_t ackTimeoutMs = 100;
    /// Retries for a single frame the radio reports as failed.
    uint8_t frameRetries = 2;
    /// Fallback if the radio never reports a sent frame. Must exceed the driver's
    /// own retry time: an unacknowledged unicast frame takes ~100 ms to be reported.
    uint32_t frameSentTimeoutMs = 500;
    /// Delay before retrying when the radio's own queue is full.
    uint32_t linkBusyBackoffMs = 2;
    /// Completed messages remembered, across all senders, for latest-only
    /// ordering, for acks of authenticated duplicates, and as a second check
    /// for duplicates.
    uint8_t recentEntries = 32;
    /// Senders whose last ~100-128 message ids are tracked for duplicate
    /// suppression (44 bytes each, taken as senders are heard). When full, the
    /// sender that delivered least recently gives way.
    uint8_t recentSenders = 20;
    /// How long a completed message is remembered.
    uint32_t recentTtlMs = 5000;
};

/// Counters for diagnostics.
struct Stats {
    uint32_t framesSent = 0;
    uint32_t framesFailed = 0;
    uint32_t framesReceived = 0;
    uint32_t framesInvalid = 0;
    uint32_t messagesSent = 0;
    uint32_t messagesFailed = 0;
    uint32_t messagesReceived = 0;
    uint32_t messagesDropped = 0;
    uint32_t retransmissions = 0;
    /// Messages dropped because authentication failed or was missing.
    uint32_t authRejected = 0;
    /// New multi-frame messages refused for lack of reassembly room (the
    /// sender retries). Also counted in messagesDropped.
    uint32_t reassemblyRefused = 0;
    /// Our messages the receiver had no room for yet; each backs off and retries.
    uint32_t receiverBusy = 0;
    /// Our messages that waited to start until the receiver had room for them
    /// (Config::receiverCredit).
    uint32_t creditWaits = 0;
    /// Messages a receive handler refused (Message::refused). Also counted in
    /// messagesDropped, not in messagesReceived.
    uint32_t messagesRefused = 0;
    /// Queued messages cut again into smaller frames because their
    /// destination's frame size shrank (e.g. it came back with ESP-NOW v1).
    uint32_t messagesRecut = 0;
};

}  // namespace nowtp
