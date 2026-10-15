// A heap with a size, for host tests, as on ESP-IDF: past the limit,
// operator new aborts (exceptions are off there, so a failed new ends the
// device), and NowTP's malloc() returns null, which NowTP must handle.
//
// The same controls as TesserAPI's tesser/testing/heap_limit.h, so the
// repositories' tests read the same. Two additions: NowTP's own malloc()
// calls (nowtp/heap.h, built with NOWTP_HEAP_HOOKS) count against the same
// limit, and HeapCounted counts again inside a HeapExempt scope.
//
// In exactly one translation unit of the test program:
//
//   #define NOWTP_HEAP_LIMIT_IMPLEMENTATION
//   #include "heap_limit.h"
//
// which replaces the global operator new and delete and installs NowTP's
// heap hooks. Everywhere else, the header declares the controls:
//
//   nowtp::testing::HeapLimit limit(4096);    // 4 KB more than is held now
//   ...                                       // operator new past it aborts
//   { nowtp::testing::HeapExempt sim; ... }   // the test's own: not counted
//
// A test that wants to know rather than abort sets onExceeded(): the
// allocation then goes ahead, and the hook gets its size. A test that takes
// Message::buffer frees it with nowtp::heap::release(), so it is uncounted.
#pragma once

#include <stddef.h>

namespace nowtp {
namespace testing {

// Bytes held now by operator new and NowTP's malloc(), and the most held
// since resetHeapPeak().
size_t heapUsed();
size_t heapPeak();
void resetHeapPeak();
// The most both may hold; 0, the default, for no limit.
void setHeapLimit(size_t bytes);
size_t heapLimit();
// What is left below the limit (SIZE_MAX without one).
size_t heapLeft();
// NowTP malloc() calls refused for the limit since the program started.
size_t heapRefusals();
// Called, instead of aborting, for an operator new of `bytes` past the
// limit, which then goes ahead; nullptr (the default) aborts. Runs inside
// operator new: it must not allocate through it (write to stderr with
// fprintf, keep counts).
using Exceeded = void (*)(size_t bytes, size_t used, size_t limit);
void onExceeded(Exceeded hook);

// While set on a thread, its allocations are neither counted nor limited:
// for what the test and the simulated network hold.
void setHeapExempt(bool exempt);
bool heapExempt();

class HeapExempt {
public:
    explicit HeapExempt(bool exempt = true) : previous_(heapExempt()) { setHeapExempt(exempt); }
    ~HeapExempt() { setHeapExempt(previous_); }
    HeapExempt(const HeapExempt&) = delete;
    HeapExempt& operator=(const HeapExempt&) = delete;

private:
    bool previous_;
};

// Counted again, inside a HeapExempt scope: the simulator calling into NowTP.
class HeapCounted : public HeapExempt {
public:
    HeapCounted() : HeapExempt(false) {}
};

// A limit `above` what is held now, for its scope; the previous one after.
class HeapLimit {
public:
    explicit HeapLimit(size_t above) : previous_(heapLimit()) {
        size_t limit = heapUsed() + above;
        setHeapLimit(limit ? limit : 1);
    }
    ~HeapLimit() { setHeapLimit(previous_); }
    HeapLimit(const HeapLimit&) = delete;
    HeapLimit& operator=(const HeapLimit&) = delete;

private:
    size_t previous_;
};

}  // namespace testing
}  // namespace nowtp

#if defined(NOWTP_HEAP_LIMIT_IMPLEMENTATION)

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <atomic>
#include <mutex>
#include <new>
#include <unordered_map>

#include "nowtp/heap.h"

#if !defined(NOWTP_HEAP_HOOKS)
#error "build NowTP with NOWTP_HEAP_HOOKS for its malloc() to be counted"
#endif

namespace nowtp {
namespace testing {
namespace heap_limit_detail {

// Each operator new block carries its size in front, so an unsized delete
// knows it, and whether it was counted.
constexpr size_t kHeader = alignof(max_align_t) > 2 * sizeof(size_t) ? alignof(max_align_t) : 2 * sizeof(size_t);

std::atomic<size_t> g_used{0};
std::atomic<size_t> g_peak{0};
std::atomic<size_t> g_limit{0};
std::atomic<size_t> g_refusals{0};
std::atomic<Exceeded> g_hook{nullptr};
thread_local bool g_exempt = false;

void notePeak(size_t used) {
    size_t peak = g_peak.load();
    while (used > peak && !g_peak.compare_exchange_weak(peak, used)) {
    }
}

void* newBlock(size_t n, bool nothrow) {
    bool counted = !g_exempt;
    if (counted) {
        size_t limit = g_limit.load();
        size_t used = g_used.fetch_add(n) + n;
        if (limit && used > limit) {
            Exceeded hook = g_hook.load();
            if (!hook) {
                fprintf(stderr, "heap_limit: operator new(%zu) past the limit: %zu held of %zu\n", n, used - n,
                        limit);
                abort();  // as ESP-IDF does: no exceptions, no way back
            }
            hook(n, used - n, limit);
        }
        notePeak(used);
    }
    void* p = malloc(kHeader + (n ? n : 1));
    if (!p) {
        if (counted) g_used.fetch_sub(n);
        if (nothrow) return nullptr;
        abort();
    }
    static_cast<size_t*>(p)[0] = n;
    static_cast<size_t*>(p)[1] = counted ? 1 : 0;
    return static_cast<char*>(p) + kHeader;
}

void deleteBlock(void* p) {
    if (!p) return;
    char* block = static_cast<char*>(p) - kHeader;
    size_t* header = reinterpret_cast<size_t*>(block);
    if (header[1]) g_used.fetch_sub(header[0]);
    free(block);
}

// NowTP's malloc() blocks: their sizes, kept aside since a handler may free()
// a buffer it took, which a header would break. Unknown blocks (malloc()ed by
// the test, e.g. for sendBuffer()) are not counted.
std::mutex g_blocksLock;
std::unordered_map<void*, size_t>* g_blocks = nullptr;  // never destroyed: static order

void track(void* p, size_t n) {
    HeapExempt own;
    std::lock_guard<std::mutex> l(g_blocksLock);
    if (!g_blocks) g_blocks = new std::unordered_map<void*, size_t>();
    (*g_blocks)[p] = n;
}

size_t untrack(void* p) {
    if (!p) return 0;
    HeapExempt own;
    std::lock_guard<std::mutex> l(g_blocksLock);
    if (!g_blocks) return 0;
    auto it = g_blocks->find(p);
    if (it == g_blocks->end()) return 0;
    size_t n = it->second;
    g_blocks->erase(it);
    return n;
}

// Takes `n` more bytes under the limit; false (nothing taken) past it.
bool reserve(size_t n) {
    size_t limit = g_limit.load();
    size_t used = g_used.fetch_add(n) + n;
    if (limit && used > limit) {
        g_used.fetch_sub(n);
        g_refusals++;
        return false;
    }
    notePeak(used);
    return true;
}

void* hookAllocate(size_t n) {
    if (g_exempt) return malloc(n);
    if (!reserve(n)) return nullptr;
    void* p = malloc(n);
    if (!p) {
        g_used.fetch_sub(n);
        return nullptr;
    }
    track(p, n);
    return p;
}

void* hookReallocate(void* p, size_t n) {
    size_t old = untrack(p);
    if (g_exempt || n <= old) {
        void* q = realloc(p, n);
        if (!q) {
            if (old) track(p, old);
            return nullptr;
        }
        g_used.fetch_sub(g_exempt ? old : old - n);
        if (!g_exempt) track(q, n);
        return q;
    }
    if (!reserve(n - old)) {
        if (old) track(p, old);
        return nullptr;
    }
    void* q = realloc(p, n);
    if (!q) {
        g_used.fetch_sub(n - old);
        if (old) track(p, old);
        return nullptr;
    }
    track(q, n);
    return q;
}

void hookRelease(void* p) {
    g_used.fetch_sub(untrack(p));
    free(p);
}

const heap::Hooks g_hooks = {hookAllocate, hookReallocate, hookRelease};

// NowTP's free-heap probe sees the same heap.
size_t probe() { return heapLeft(); }

struct Install {
    Install() {
        heap::hooks() = &g_hooks;
        heap::probe() = probe;
    }
} g_install;

}  // namespace heap_limit_detail

size_t heapUsed() { return heap_limit_detail::g_used.load(); }
size_t heapPeak() { return heap_limit_detail::g_peak.load(); }
void resetHeapPeak() { heap_limit_detail::g_peak = heap_limit_detail::g_used.load(); }
void setHeapLimit(size_t bytes) { heap_limit_detail::g_limit = bytes; }
size_t heapLimit() { return heap_limit_detail::g_limit.load(); }
size_t heapLeft() {
    size_t limit = heapLimit(), used = heapUsed();
    if (!limit) return SIZE_MAX;
    return used < limit ? limit - used : 0;
}
size_t heapRefusals() { return heap_limit_detail::g_refusals.load(); }
void onExceeded(Exceeded hook) { heap_limit_detail::g_hook = hook; }
void setHeapExempt(bool exempt) { heap_limit_detail::g_exempt = exempt; }
bool heapExempt() { return heap_limit_detail::g_exempt; }

}  // namespace testing
}  // namespace nowtp

void* operator new(size_t n) { return nowtp::testing::heap_limit_detail::newBlock(n, false); }
void* operator new[](size_t n) { return nowtp::testing::heap_limit_detail::newBlock(n, false); }
void* operator new(size_t n, const std::nothrow_t&) noexcept {
    return nowtp::testing::heap_limit_detail::newBlock(n, true);
}
void* operator new[](size_t n, const std::nothrow_t&) noexcept {
    return nowtp::testing::heap_limit_detail::newBlock(n, true);
}
void operator delete(void* p) noexcept { nowtp::testing::heap_limit_detail::deleteBlock(p); }
void operator delete[](void* p) noexcept { nowtp::testing::heap_limit_detail::deleteBlock(p); }
void operator delete(void* p, size_t) noexcept { nowtp::testing::heap_limit_detail::deleteBlock(p); }
void operator delete[](void* p, size_t) noexcept { nowtp::testing::heap_limit_detail::deleteBlock(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { nowtp::testing::heap_limit_detail::deleteBlock(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept {
    nowtp::testing::heap_limit_detail::deleteBlock(p);
}

#endif  // NOWTP_HEAP_LIMIT_IMPLEMENTATION
