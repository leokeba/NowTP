// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <stddef.h>
#include <stdint.h>

#include <cstdlib>
#include <memory>
#include <new>

namespace nowtp {

/// NowTP's heap allocations. They all come from malloc(), which returns null
/// on a short heap (a handler may free() a buffer it took). Host tests build
/// with NOWTP_HEAP_HOOKS to count them and to make them fail, as on a short
/// heap; otherwise these are malloc, realloc and free.
namespace heap {

/// Largest block the heap could give now. Code that can only allocate with
/// operator new (a std::string or std::vector in the public API), which
/// aborts on failure with exceptions off, checks fits() first and otherwise
/// does without. The platform sets the probe (EspNowTransport on ESP-IDF; the
/// host tests); without one, fits() is always true.
typedef size_t (*Probe)();
inline Probe& probe() {
    static Probe p = nullptr;
    return p;
}
/// Left to the rest of the system: a std::vector is not worth its last bytes.
constexpr size_t kReserve = 4096;
/// True if `n` bytes from operator new would still leave kReserve.
inline bool fits(size_t n) {
    Probe p = probe();
    return !p || (n < SIZE_MAX - kReserve && p() >= n + kReserve);
}

#if defined(NOWTP_HEAP_HOOKS)
struct Hooks {
    void* (*allocate)(size_t n);
    void* (*reallocate)(void* p, size_t n);
    void (*release)(void* p);
};
/// The hooks in use; null for malloc, realloc and free.
inline const Hooks*& hooks() {
    static const Hooks* h = nullptr;
    return h;
}
inline void* allocate(size_t n) { return hooks() ? hooks()->allocate(n) : std::malloc(n); }
inline void* reallocate(void* p, size_t n) { return hooks() ? hooks()->reallocate(p, n) : std::realloc(p, n); }
inline void release(void* p) {
    if (hooks()) {
        hooks()->release(p);
    } else {
        std::free(p);
    }
}
#else
inline void* allocate(size_t n) { return std::malloc(n); }
inline void* reallocate(void* p, size_t n) { return std::realloc(p, n); }
inline void release(void* p) { std::free(p); }
#endif

/// An object in malloc()ed memory, for state a peer makes us create: `new`
/// (even `new (std::nothrow)`, in libstdc++) aborts on a short heap with
/// exceptions off. make() returns null instead.
template <class T>
struct Deleter {
    void operator()(T* p) const {
        if (!p) return;
        p->~T();
        release(p);
    }
};
template <class T>
using Owned = std::unique_ptr<T, Deleter<T>>;
template <class T>
Owned<T> make() {
    void* p = allocate(sizeof(T));
    return Owned<T>(p ? new (p) T() : nullptr);
}

}  // namespace heap
}  // namespace nowtp
