// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "wire.h"

namespace nowtp {
namespace wire {

size_t encodeHeader(const Header& h, uint8_t* out) {
    out[0] = static_cast<uint8_t>((kVersion << 6) | (static_cast<uint8_t>(h.type) << 4) | (h.flags & 0x0F));
    out[1] = h.networkId;
    out[2] = h.port;
    putU16(out + 3, h.messageId);
    if (h.type != Type::Fragment) return kCommonHeaderSize;
    putU16(out + 5, h.index);
    putU16(out + 7, h.count);
    return kFragmentHeaderSize;
}

bool decodeHeader(const uint8_t* in, size_t len, Header& out, size_t& payloadOffset) {
    if (len < kCommonHeaderSize) return false;
    if ((in[0] >> 6) != kVersion) return false;
    uint8_t type = (in[0] >> 4) & 0x03;
    if (type > static_cast<uint8_t>(Type::Ack)) return false;

    out.type = static_cast<Type>(type);
    out.flags = in[0] & 0x0F;
    out.networkId = in[1];
    out.port = in[2];
    out.messageId = getU16(in + 3);
    out.index = 0;
    out.count = 1;

    if (out.type == Type::Fragment) {
        if (len < kFragmentHeaderSize) return false;
        out.index = getU16(in + 5);
        out.count = getU16(in + 7);
        if (out.count < 2 || out.index >= out.count) return false;
    }
    payloadOffset = headerSize(out.type);
    return true;
}

uint32_t crc32(const uint8_t* data, size_t len, uint32_t crc) {
    // Nibble-wise table: small enough for any MCU, fast enough for radio payloads.
    static const uint32_t kTable[16] = {
        0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC, 0x76DC4190, 0x6B6B51F4, 0x4DB26158, 0x5005713C,
        0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C, 0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C,
    };
    crc = ~crc;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        crc = (crc >> 4) ^ kTable[crc & 0x0F];
        crc = (crc >> 4) ^ kTable[crc & 0x0F];
    }
    return ~crc;
}

}  // namespace wire
}  // namespace nowtp
