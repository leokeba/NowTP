#pragma once

#include <cstdio>
#include <vector>

// ---------------------------------------------------------------------------
// Minimal test harness


struct TestCase {
    const char* name;
    void (*fn)();
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}

struct Registrar {
    Registrar(const char* name, void (*fn)()) { registry().push_back(TestCase{name, fn}); }
};

extern int g_failures;
extern bool g_currentFailed;

#define TEST(name)                                   \
    static void name();                              \
    static Registrar registrar_##name(#name, name); \
    static void name()

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::printf("    %s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond); \
            g_currentFailed = true;                                              \
            return;                                                              \
        }                                                                        \
    } while (0)

#define CHECK_EQ(a, b)                                                                       \
    do {                                                                                     \
        auto va = (a);                                                                       \
        auto vb = (b);                                                                       \
        if (!(va == vb)) {                                                                   \
            std::printf("    %s:%d: CHECK_EQ(%s, %s) failed: %lld vs %lld\n", __FILE__, __LINE__, #a, #b, \
                        (long long)va, (long long)vb);                                       \
            g_currentFailed = true;                                                          \
            return;                                                                          \
        }                                                                                    \
    } while (0)
