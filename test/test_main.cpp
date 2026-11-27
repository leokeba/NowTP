// Host-side tests for the NowTP protocol engine: runner and heap sweep.

#include <dlfcn.h>
#include <execinfo.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

// Before sim.h, which includes the declarations.
#define NOWTP_HEAP_LIMIT_IMPLEMENTATION
#include "heap_limit.h"

#include "nowtp/channel.h"
#include "nowtp/crypto.h"
#include "nowtp/diagnostics.h"
#include "nowtp/credit_book.h"
#include "nowtp/discovery.h"
#include "nowtp/duplicate_filter.h"
#include "nowtp/engine.h"
#include "nowtp/frame_sizes.h"
#include "nowtp/link_monitor.h"
#include "nowtp/peer_table.h"
#include "nowtp/security.h"
#include "nowtp/send_tracker.h"
#include "nowtp/stream.h"
#include "nowtp/table.h"
#include "nowtp/timesync.h"
#include "nowtp/wire.h"
#include "sim.h"

using namespace nowtp;

#include "harness.h"

int g_failures = 0;
bool g_currentFailed = false;

// NOWTP_HEAP_SWEEP=1: runs each test at several heap limits, counting only
// what NowTP takes while the simulator drives it (received frames, sent
// frames, ticks), and prints every distinct place where operator new went
// past the limit: on ESP-IDF, each would abort. Checks failing for lack of
// memory are expected there and not reported.
namespace sweep {

constexpr int kDepth = 24;
constexpr size_t kMaxSites = 64;
size_t g_sites[kMaxSites];
size_t g_siteCount = 0;
size_t g_overruns = 0;

bool startsWith(const char* s, const char* prefix) { return std::strncmp(s, prefix, std::strlen(prefix)) == 0; }

// The innermost caller outside the standard library is NowTP's own code, not
// the test's or the simulator's (an application's handler allocating is its
// own business). Unknown without symbols: reported.
bool nowtpSite(void* const* frames, int n) {
    for (int i = 2; i < n; ++i) {
        Dl_info info;
        if (!dladdr(frames[i], &info) || !info.dli_sname) return true;
        const char* s = info.dli_sname;
        if (*s == '_' && startsWith(s + 1, "_Z")) ++s;  // Mach-O's extra underscore
        if (startsWith(s, "_ZNSt") || startsWith(s, "_ZNKSt") || startsWith(s, "_ZSt") || startsWith(s, "_Znw") ||
            startsWith(s, "_Zna") || startsWith(s, "_ZN5nowtp7testing")) {
            continue;
        }
        return startsWith(s, "_ZN5nowtp") || startsWith(s, "_ZNK5nowtp") || startsWith(s, "_ZZN5nowtp") ||
               startsWith(s, "_ZZNK5nowtp");
    }
    return true;
}

void exceeded(size_t bytes, size_t used, size_t limit) {
    void* frames[kDepth];
    int n = backtrace(frames, kDepth);
    if (!nowtpSite(frames, n)) return;
    g_overruns++;
    size_t h = 1469598103934665603ull;
    for (int i = 2; i < n; ++i) h = (h ^ reinterpret_cast<size_t>(frames[i])) * 1099511628211ull;
    for (size_t i = 0; i < g_siteCount; ++i) {
        if (g_sites[i] == h) return;
    }
    if (g_siteCount < kMaxSites) g_sites[g_siteCount++] = h;
    std::fprintf(stderr, "  operator new(%zu) past the limit (%zu held of %zu):\n", bytes, used, limit);
    backtrace_symbols_fd(frames + 2, n - 2, 2);
}

int run(const char* filter) {
    void* warm[1];
    backtrace(warm, 1);  // loads what backtrace() needs before any limit
    testing::onExceeded(exceeded);
    for (const TestCase& t : registry()) {
        if (filter && std::strstr(t.name, filter) == nullptr) continue;
        size_t before = g_overruns;
        for (size_t above : {0, 128, 512, 2048, 8192, 32768}) {
            testing::HeapExempt test;  // only the simulator counts, while it drives NowTP
            testing::HeapLimit limit(above);
            t.fn();
        }
        std::printf("[%s] %s: %zu operator new past the limit\n", g_overruns == before ? " OK " : "NEW ", t.name,
                    g_overruns - before);
    }
    std::printf("\n%zu distinct sites\n", g_siteCount);
    return g_siteCount == 0 ? 0 : 1;
}

}  // namespace sweep

int main(int argc, char** argv) {
    const char* filter = argc > 1 ? argv[1] : nullptr;
    if (std::getenv("NOWTP_HEAP_SWEEP")) return sweep::run(filter);
    int run = 0;
    for (const TestCase& t : registry()) {
        if (filter && std::strstr(t.name, filter) == nullptr) continue;
        g_currentFailed = false;
        t.fn();
        run++;
        std::printf("[%s] %s\n", g_currentFailed ? "FAIL" : " OK ", t.name);
        if (g_currentFailed) g_failures++;
    }
    std::printf("\n%d tests, %d failed\n", run, g_failures);
    return g_failures == 0 ? 0 : 1;
}
