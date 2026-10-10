// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "crypto.h"

#include <string.h>

namespace nowtp {
namespace crypto {

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)

namespace {

const uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

inline uint32_t rotr(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t loadBe32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

inline void storeBe32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

}  // namespace

void Sha256::reset() {
    static const uint32_t kInit[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(h_, kInit, sizeof(h_));
    total_ = 0;
    fill_ = 0;
}

void Sha256::block(const uint8_t* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) w[i] = loadBe32(p + 4 * i);
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + kK[i] + w[i];
        uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h_[0] += a;
    h_[1] += b;
    h_[2] += c;
    h_[3] += d;
    h_[4] += e;
    h_[5] += f;
    h_[6] += g;
    h_[7] += h;
}

void Sha256::update(const uint8_t* data, size_t len) {
    total_ += len;
    while (len > 0) {
        if (fill_ == 0 && len >= 64) {
            block(data);
            data += 64;
            len -= 64;
            continue;
        }
        size_t n = 64 - fill_ < len ? 64 - fill_ : len;
        memcpy(buf_ + fill_, data, n);
        fill_ += n;
        data += n;
        len -= n;
        if (fill_ == 64) {
            block(buf_);
            fill_ = 0;
        }
    }
}

void Sha256::finish(uint8_t out[kSha256Size]) {
    uint64_t bits = total_ * 8;
    uint8_t pad = 0x80;
    update(&pad, 1);
    uint8_t zero = 0;
    while (fill_ != 56) update(&zero, 1);
    uint8_t len[8];
    for (int i = 0; i < 8; ++i) len[i] = static_cast<uint8_t>(bits >> (56 - 8 * i));
    update(len, 8);
    for (int i = 0; i < 8; ++i) storeBe32(out + 4 * i, h_[i]);
    reset();
}

void sha256(const uint8_t* data, size_t len, uint8_t out[kSha256Size]) {
    Sha256 s;
    s.update(data, len);
    s.finish(out);
}

// ---------------------------------------------------------------------------
// HMAC (RFC 2104) and HKDF (RFC 5869)

HmacSha256::HmacSha256(const uint8_t* key, size_t keyLen) {
    uint8_t k[64];
    memset(k, 0, sizeof(k));
    if (keyLen > 64) {
        sha256(key, keyLen, k);
    } else if (keyLen > 0) {
        memcpy(k, key, keyLen);
    }
    uint8_t ipad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = static_cast<uint8_t>(k[i] ^ 0x36);
        outerKey_[i] = static_cast<uint8_t>(k[i] ^ 0x5c);
    }
    inner_.update(ipad, sizeof(ipad));
    wipe(k, sizeof(k));
    wipe(ipad, sizeof(ipad));
}

void HmacSha256::update(const uint8_t* data, size_t len) {
    inner_.update(data, len);
}

void HmacSha256::finish(uint8_t out[kSha256Size]) {
    uint8_t innerHash[kSha256Size];
    inner_.finish(innerHash);
    Sha256 outer;
    outer.update(outerKey_, sizeof(outerKey_));
    outer.update(innerHash, sizeof(innerHash));
    outer.finish(out);
    wipe(outerKey_, sizeof(outerKey_));
}

void hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t len, uint8_t out[kSha256Size]) {
    HmacSha256 h(key, keyLen);
    h.update(data, len);
    h.finish(out);
}

void hkdf(const uint8_t* salt, size_t saltLen, const uint8_t* ikm, size_t ikmLen, const uint8_t* info, size_t infoLen,
          uint8_t* out, size_t outLen) {
    uint8_t zeros[kSha256Size];
    memset(zeros, 0, sizeof(zeros));
    uint8_t prk[kSha256Size];
    if (saltLen == 0) {
        salt = zeros;
        saltLen = sizeof(zeros);
    }
    hmacSha256(salt, saltLen, ikm, ikmLen, prk);

    uint8_t t[kSha256Size];
    size_t tLen = 0;
    for (uint8_t counter = 1; outLen > 0; ++counter) {
        HmacSha256 h(prk, sizeof(prk));
        h.update(t, tLen);
        h.update(info, infoLen);
        h.update(&counter, 1);
        h.finish(t);
        tLen = sizeof(t);
        size_t n = outLen < tLen ? outLen : tLen;
        memcpy(out, t, n);
        out += n;
        outLen -= n;
    }
    wipe(prk, sizeof(prk));
    wipe(t, sizeof(t));
}

// ---------------------------------------------------------------------------
// X25519, after TweetNaCl (public domain): 16 limbs of 16 bits in int64.

namespace {

typedef int64_t Fe[16];

const Fe k121665 = {0xDB41, 1};

void carry(Fe o) {
    for (int i = 0; i < 16; ++i) {
        o[i] += static_cast<int64_t>(1) << 16;
        int64_t c = o[i] >> 16;  // arithmetic shift; c may be negative
        if (i < 15) {
            o[i + 1] += c - 1;
        } else {
            o[0] += 38 * (c - 1);
        }
        o[i] -= c * 65536;  // not c << 16: shifting a negative value is undefined
    }
}

// Swaps p and q when b is 1, in constant time.
void select(Fe p, Fe q, int64_t b) {
    int64_t mask = ~(b - 1);
    for (int i = 0; i < 16; ++i) {
        int64_t t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

void pack(uint8_t* o, const Fe n) {
    Fe m, t;
    for (int i = 0; i < 16; ++i) t[i] = n[i];
    carry(t);
    carry(t);
    carry(t);
    for (int j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int64_t b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        select(t, m, 1 - b);
    }
    for (int i = 0; i < 16; ++i) {
        o[2 * i] = static_cast<uint8_t>(t[i] & 0xff);
        o[2 * i + 1] = static_cast<uint8_t>((t[i] >> 8) & 0xff);
    }
}

void unpack(Fe o, const uint8_t* n) {
    for (int i = 0; i < 16; ++i) o[i] = n[2 * i] + (static_cast<int64_t>(n[2 * i + 1]) << 8);
    o[15] &= 0x7fff;
}

void add(Fe o, const Fe a, const Fe b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}

void sub(Fe o, const Fe a, const Fe b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}

void mul(Fe o, const Fe a, const Fe b) {
    int64_t t[31];
    for (int i = 0; i < 31; ++i) t[i] = 0;
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 16; ++j) t[i + j] += a[i] * b[j];
    }
    for (int i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; ++i) o[i] = t[i];
    carry(o);
    carry(o);
}

void square(Fe o, const Fe a) {
    mul(o, a, a);
}

void invert(Fe o, const Fe in) {
    Fe c;
    for (int i = 0; i < 16; ++i) c[i] = in[i];
    for (int a = 253; a >= 0; --a) {
        square(c, c);
        if (a != 2 && a != 4) mul(c, c, in);
    }
    for (int i = 0; i < 16; ++i) o[i] = c[i];
}

}  // namespace

void x25519(uint8_t out[kX25519Size], const uint8_t scalar[kX25519Size], const uint8_t point[kX25519Size]) {
    uint8_t z[32];
    memcpy(z, scalar, 32);
    z[31] = static_cast<uint8_t>((z[31] & 127) | 64);
    z[0] &= 248;

    Fe x, a, b, c, d, e, f;
    unpack(x, point);
    for (int i = 0; i < 16; ++i) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (int i = 254; i >= 0; --i) {
        int64_t r = (z[i >> 3] >> (i & 7)) & 1;
        select(a, b, r);
        select(c, d, r);
        add(e, a, c);
        sub(a, a, c);
        add(c, b, d);
        sub(b, b, d);
        square(d, e);
        square(f, a);
        mul(a, c, a);
        mul(c, b, e);
        add(e, a, c);
        sub(a, a, c);
        square(b, a);
        sub(c, d, f);
        mul(a, c, k121665);
        add(a, a, d);
        mul(c, c, a);
        mul(a, d, f);
        mul(d, b, x);
        square(b, e);
        select(a, b, r);
        select(c, d, r);
    }
    invert(c, c);
    mul(a, a, c);
    pack(out, a);
    wipe(z, sizeof(z));
}

void x25519Base(uint8_t out[kX25519Size], const uint8_t scalar[kX25519Size]) {
    uint8_t base[32] = {9};
    x25519(out, scalar, base);
}

bool equal(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
    return diff == 0;
}

void wipe(void* p, size_t len) {
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    while (len--) *v++ = 0;
}

}  // namespace crypto
}  // namespace nowtp
