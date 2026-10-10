// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
//
// On-air frame format. See docs/PROTOCOL.md for the full description.
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace nowtp {
namespace wire {

constexpr uint8_t kVersion = 1;

enum class Type : uint8_t {
    Single = 0,    ///< Whole message in one frame.
    Fragment = 1,  ///< One fragment of a multi-frame message.
    Ack = 2,       ///< Receiver feedback for a reliable message.
};

enum Flags : uint8_t {
    kFlagReliable = 0x01,
    kFlagLatest = 0x02,
    kFlagAckRequest = 0x04,
    kFlagAuth = 0x08,  ///< Payload ends with an authentication trailer (Security).
};

enum class AckStatus : uint8_t {
    Complete = 0,  ///< Whole message received; payload is empty.
    Missing = 1,   ///< Payload lists missing fragment indices (uint16 LE each).
    Rejected = 2,  ///< Receiver will not accept this message.
};

constexpr size_t kCommonHeaderSize = 5;    // control, network id, port, message id
constexpr size_t kFragmentHeaderSize = 9;  // + fragment index, fragment count
constexpr size_t kCrcSize = 4;             // CRC-32 trailing a multi-frame message
/// Trailer of an authenticated message: epoch (4), sequence (4), destination
/// kind (1), tag (8). See docs/PROTOCOL.md.
constexpr size_t kAuthTrailerSize = 17;
/// Tag appended to an ack for an authenticated message.
constexpr size_t kAckTagSize = 8;

struct Header {
    Type type = Type::Single;
    uint8_t flags = 0;
    uint8_t networkId = 0;
    uint8_t port = 0;
    uint16_t messageId = 0;
    uint16_t index = 0;  // Fragment only
    uint16_t count = 1;  // Fragment only
};

inline size_t headerSize(Type t) {
    return t == Type::Fragment ? kFragmentHeaderSize : kCommonHeaderSize;
}

/// Writes the header for `h.type` and returns its size.
size_t encodeHeader(const Header& h, uint8_t* out);

/// Parses and validates a frame header. On success returns true and sets
/// `payloadOffset` to the first byte after the header.
bool decodeHeader(const uint8_t* in, size_t len, Header& out, size_t& payloadOffset);

inline void putU16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
}

inline uint16_t getU16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

inline void putU32(uint8_t* p, uint32_t v) {
    putU16(p, static_cast<uint16_t>(v));
    putU16(p + 2, static_cast<uint16_t>(v >> 16));
}

inline uint32_t getU32(const uint8_t* p) {
    return getU16(p) | (static_cast<uint32_t>(getU16(p + 2)) << 16);
}

/// CRC-32 (IEEE 802.3). Pass the previous result as `crc` to continue a running checksum.
uint32_t crc32(const uint8_t* data, size_t len, uint32_t crc = 0);

}  // namespace wire
}  // namespace nowtp
