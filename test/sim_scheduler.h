// The simulation's hosts and scheduler for host-side tests: a diagnostics host
// whose sleep steps the network, and a deterministic runner for several blocking
// procedures at once.
#pragma once

#include <condition_variable>
#include <functional>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

#include "nowtp/diagnostics.h"

#include "sim_network.h"

namespace sim {

/// Diagnostics host for the simulation: sleeping steps the whole network.
class SimHost : public nowtp::DiagnosticsHost {
public:
    explicit SimHost(Network& net) : net_(net) {}
    uint32_t now() override { return net_.now(); }
    void sleep(uint32_t ms) override { net_.run(ms ? ms : 1); }
    void lock() override {}
    void unlock() override {}
    uint32_t random() override { return static_cast<uint32_t>(net_.rng()()); }

private:
    Network& net_;
};

/// Runs several blocking procedures (e.g. both sides of a pairing) in their
/// own threads against one simulated network, deterministically: only one
/// thread runs at a time, and the network advances only while every thread
/// sleeps, up to the earliest wake-up time.
class Scheduler {
public:
    explicit Scheduler(Network& net) : net_(net) {}

    /// Host for one procedure thread.
    class Host : public nowtp::ServiceHost {
    public:
        explicit Host(Scheduler& s) : s_(s) {}
        uint32_t now() override { return s_.net_.now(); }
        void sleep(uint32_t ms) override { s_.sleep(ms ? ms : 1); }
        void lock() override {}  // only one thread runs at a time
        void unlock() override {}
        uint32_t random() override { return static_cast<uint32_t>(s_.net_.rng()()); }

    private:
        Scheduler& s_;
    };

    /// Runs every function in its own thread until all have returned.
    void run(const std::vector<std::function<void()>>& procedures);

private:
    void sleep(uint32_t ms);

    Network& net_;
    std::mutex m_;
    std::condition_variable cv_;
    std::multiset<uint32_t> wakeups_;
    size_t starting_ = 0;     // threads that have not run yet
    bool turnTaken_ = false;  // a thread is running
};

inline void Scheduler::sleep(uint32_t ms) {
    std::unique_lock<std::mutex> l(m_);
    uint32_t wake = net_.now() + ms;
    std::multiset<uint32_t>::iterator mine = wakeups_.insert(wake);
    turnTaken_ = false;
    cv_.notify_all();
    for (;;) {
        bool idle = !turnTaken_ && starting_ == 0;
        if (idle && static_cast<int32_t>(net_.now() - wake) >= 0) {
            wakeups_.erase(mine);
            turnTaken_ = true;
            return;
        }
        if (idle && static_cast<int32_t>(net_.now() - *wakeups_.begin()) < 0) {
            net_.step();  // everyone sleeps: advance to the earliest wake-up
            cv_.notify_all();
            continue;
        }
        cv_.wait(l);
    }
}

inline void Scheduler::run(const std::vector<std::function<void()>>& procedures) {
    {
        std::lock_guard<std::mutex> l(m_);
        starting_ = procedures.size();
    }
    std::vector<std::thread> threads;
    for (const auto& fn : procedures) {
        threads.emplace_back([this, fn] {
            Exempt app;  // the application's procedure; the network it drives is counted
            {
                std::unique_lock<std::mutex> l(m_);
                cv_.wait(l, [this] { return !turnTaken_; });
                turnTaken_ = true;
                starting_--;
            }
            fn();
            std::lock_guard<std::mutex> l(m_);
            turnTaken_ = false;
            cv_.notify_all();
        });
    }
    for (auto& t : threads) t.join();
}

}  // namespace sim
