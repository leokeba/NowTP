// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
//
// Small, portable cryptographic primitives for Security: SHA-256, HMAC-SHA256,
// HKDF and X25519. Written for clarity and testability rather than speed; the
// hot path (one HMAC per message) costs a few microseconds per frame on an ESP32.
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace nowtp {
namespace crypto {

constexpr size_t kSha256Size = 32;

class Sha256 {
public:
    Sha256() { reset(); }
    void reset();
    void update(const uint8_t* data, size_t len);
    void finish(uint8_t out[kSha256Size]);

private:
    void block(const uint8_t* p);
    uint32_t h_[8];
    uint8_t buf_[64];
    uint64_t total_;
    size_t fill_;
};

void sha256(const uint8_t* data, size_t len, uint8_t out[kSha256Size]);

class HmacSha256 {
public:
    HmacSha256(const uint8_t* key, size_t keyLen);
    void update(const uint8_t* data, size_t len);
    void finish(uint8_t out[kSha256Size]);

private:
    Sha256 inner_;
    uint8_t outerKey_[64];
};

void hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t len, uint8_t out[kSha256Size]);

/// HKDF-SHA256 (RFC 5869). `outLen` is at most 255 * 32.
void hkdf(const uint8_t* salt, size_t saltLen, const uint8_t* ikm, size_t ikmLen, const uint8_t* info, size_t infoLen,
          uint8_t* out, size_t outLen);

constexpr size_t kX25519Size = 32;

/// X25519 (RFC 7748): out = scalar * point.
void x25519(uint8_t out[kX25519Size], const uint8_t scalar[kX25519Size], const uint8_t point[kX25519Size]);
/// Public key for a private scalar: scalar * base point.
void x25519Base(uint8_t out[kX25519Size], const uint8_t scalar[kX25519Size]);

/// Compares in time independent of the contents.
bool equal(const uint8_t* a, const uint8_t* b, size_t len);

/// Overwrites memory in a way the compiler does not optimize out.
void wipe(void* p, size_t len);

}  // namespace crypto
}  // namespace nowtp
