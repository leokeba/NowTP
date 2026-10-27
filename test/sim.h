// Simulated radio network for host-side tests.
#pragma once

#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <thread>
#include <type_traits>
#include <vector>

#include "nowtp/diagnostics.h"
#include "nowtp/engine.h"
#include "nowtp/peer_table.h"
#include "nowtp/radio.h"

#if defined(NOWTP_HEAP_HOOKS)
#include "heap_limit.h"
#endif

namespace sim {

// The heap limit's scopes on the host (test/heap_limit.h); nothing on a chip
// (test/hardware runs this simulator too).
#if defined(NOWTP_HEAP_HOOKS)
typedef nowtp::testing::HeapExempt Exempt;
typedef nowtp::testing::HeapCounted Counted;
#else
struct Exempt {
    Exempt() {}
};
struct Counted {
    Counted() {}
};
#endif

using nowtp::Mac;
using nowtp::Status;

struct Frame {
    size_t from;
    Mac dst;
    std::vector<uint8_t> data;
};

class Network;

/// Simulated radio state; the delivery model in Network uses it.
class SimRadio : public nowtp::RadioControl {
public:
    float power = 20;
    float limit = 20;
    uint8_t chan = 1;
    bool lr = false;
    bool channelLocked = false;  // like a station connected to an AP
    nowtp::PhyRate bcast = nowtp::PhyRate::Default;
    nowtp::PhyRate unicastDefault = nowtp::PhyRate::Default;
    std::vector<std::pair<Mac, nowtp::PhyRate>> peers;

    float txPower() const override { return power; }
    float txPowerLimit() const override { return limit; }
    Status setTxPower(float dbm) override {
        if (dbm < 2) return Status::InvalidArgument;
        power = dbm > limit ? limit : dbm;
        return Status::Ok;
    }
    nowtp::PhyRate broadcastRate() const override { return bcast; }
    Status setBroadcastRate(nowtp::PhyRate r) override {
        if (!rateUsable(r)) return Status::InvalidArgument;
        bcast = r;
        return Status::Ok;
    }
    nowtp::PhyRate peerRate(const Mac& m) const override {
        for (const auto& p : peers) {
            if (p.first == m) return p.second;
        }
        return unicastDefault;
    }
    Status setPeerRate(const Mac& m, nowtp::PhyRate r) override {
        if (!rateUsable(r)) return Status::InvalidArgument;
        for (auto& p : peers) {
            if (p.first == m) {
                p.second = r;
                return Status::Ok;
            }
        }
        peers.push_back(std::make_pair(m, r));
        return Status::Ok;
    }
    bool rateUsable(nowtp::PhyRate r) const override { return nowtp::isValid(r) && (!nowtp::isLongRange(r) || lr); }
    uint8_t channel() const override { return chan; }
    Status setChannel(uint8_t c) override {
        if (channelLocked) return Status::InvalidState;
        if (c < 1 || c > 14) return Status::InvalidArgument;
        chan = c;
        return Status::Ok;
    }
    bool channelFixed() const override { return channelLocked; }
    bool longRange() const override { return lr; }
    Status setLongRange(bool on) override {
        lr = on;
        return Status::Ok;
    }
    nowtp::PhyRate rateFor(const Mac& dst) const {
        nowtp::PhyRate r = dst.isBroadcast() ? bcast : peerRate(dst);
        return r == nowtp::PhyRate::Default ? nowtp::PhyRate::B1M : r;
    }
};

/// The radio's peer table, as ESP-NOW's: a fixed number of slots.
class SimPeerDriver : public nowtp::PeerTable::Driver {
public:
    size_t capacity = 0;  // 0: unlimited, and the table is not modelled
    std::vector<Mac> table;
    size_t removed = 0;

    Result add(const Mac& m) override {
        if (exists(m)) return Result::Ok;
        if (table.size() >= capacity) return Result::Full;
        table.push_back(m);
        return Result::Ok;
    }
    void remove(const Mac& m) override {
        for (size_t i = 0; i < table.size(); ++i) {
            if (table[i] == m) {
                table.erase(table.begin() + static_cast<std::ptrdiff_t>(i));
                removed++;
                return;
            }
        }
    }
    bool exists(const Mac& m) const override {
        for (const Mac& t : table) {
            if (t == m) return true;
        }
        return false;
    }
};

class SimLink : public nowtp::Link {
public:
    SimLink(Network& net, size_t index) : peers(driver), net_(net), index_(index) {}
    Status sendFrame(const Mac& dst, const uint8_t* data, size_t len) override;
    size_t maxFrameSize(const Mac& dst) const override { return sizeFor ? sizeFor(dst) : mtu; }

    size_t mtu = 250;
    /// Per destination instead of `mtu`, as the transport's FrameSizes answers.
    std::function<size_t(const Mac&)> sizeFor;
    bool inFlight = false;
    int busyReplies = 0;  // next N sendFrame() calls return QueueFull
    /// Set driver.capacity to model the peer table, managed like the ESP-NOW
    /// transport does: unicast destinations are added on use, LRU evicted.
    SimPeerDriver driver;
    nowtp::PeerTable peers;

private:
    Network& net_;
    size_t index_;
};

/// NOWTP_CLOCK_START=<ms>: the network's clock starts there instead of 0, to
/// run the suite across 2^31 ms (24.8 days of uptime) or the wrap at 2^32.
inline uint32_t clockStart() {
    static const uint32_t start = [] {
        const char* v = std::getenv("NOWTP_CLOCK_START");
        return v && *v ? static_cast<uint32_t>(std::strtoul(v, nullptr, 0)) : 0u;
    }();
    return start;
}

struct Node {
    Node(Network& net, size_t index, const Mac& m, const nowtp::Config& cfg)
        : mac(m), link(net, index), engine(link, cfg, static_cast<uint16_t>(index * 1000)) {}
    Mac mac;
    SimLink link;
    nowtp::Engine engine;
    SimRadio radio;
    bool online = true;
    /// Time its frames wait in the driver before going on air: delivery and
    /// the "sent" report come this much later (one direction only, unlike air time).
    uint32_t txQueueMs = 0;
    /// What the ESP-NOW transport feeds its LinkMonitor: frames heard (before
    /// the engine), and the radio's report for each unicast frame sent.
    std::function<void(const Mac& src)> onHeard;
    std::function<void(const Mac& dst, bool delivered)> onSent;
    /// Local clock: offset and rate error against the simulation's time.
    uint64_t clockOffsetUs = 1000000000;
    double clockSkew = 0;  // e.g. 40e-6 for a crystal 40 ppm fast
    /// Like a device's 64-bit esp_timer, it carries on past the ms clock's wrap.
    uint64_t clockUs(uint32_t nowMs) const {
        uint64_t ms = static_cast<uint64_t>(clockStart()) + static_cast<uint32_t>(nowMs - clockStart());
        return clockOffsetUs + static_cast<uint64_t>(static_cast<double>(ms) * 1000.0 * (1.0 + clockSkew));
    }
};

/// Work run every simulated millisecond after the engines tick: services
/// (discovery, diagnostics...) or the test's own. With `due`, it says when its
/// work is next due, as the ESP-NOW transport asks before it lets a poller
/// sleep; sparse ticking (sparseTicks()) then runs it only then, or when
/// `node` (every node: SIZE_MAX) handled an event, as the transport does.
struct Ticker {
    template <class F, class = typename std::enable_if<
                           !std::is_same<typename std::decay<F>::type, Ticker>::value>::type>
    Ticker(F f) : tick(std::move(f)) {}
    Ticker(std::function<void(uint32_t)> t, std::function<void(nowtp::Deadline&)> d, size_t n = SIZE_MAX)
        : tick(std::move(t)), due(std::move(d)), node(n) {}
    std::function<void(uint32_t)> tick;
    std::function<void(nowtp::Deadline&)> due;  // empty: every millisecond
    size_t node = SIZE_MAX;
};

/// NOWTP_SPARSE_TICKS=1: engines and tickers with a `due` run only when due
/// or after an event of their node, as with EspNowTransport::pollDelayMs().
/// Every test must pass that way too: a deadline reported late shows.
inline bool sparseTicks() {
    static const bool on = [] {
        const char* v = std::getenv("NOWTP_SPARSE_TICKS");
        return v && *v && *v != '0';
    }();
    return on;
}

/// Probability that a frame from node `from` reaches node `to`, given the
/// sender's rate and power. Lets tests model weak boards and weak links.
using LinkModel = std::function<double(size_t from, size_t to, nowtp::PhyRate rate, float powerDbm)>;

class Network {
public:
    explicit Network(uint32_t seed = 1, uint32_t start = clockStart()) : rng_(seed), now_(start) {}

    size_t addNode(const nowtp::Config& cfg = nowtp::Config()) {
        Mac m = {{0x02, 0, 0, 0, 0, static_cast<uint8_t>(nodes_.size() + 1)}};
        nodes_.emplace_back(new Node(*this, nodes_.size(), m, cfg));
        return nodes_.size() - 1;
    }

    Node& node(size_t i) { return *nodes_[i]; }
    nowtp::Engine& engine(size_t i) { return nodes_[i]->engine; }
    Mac mac(size_t i) const { return nodes_[i]->mac; }
    uint32_t now() const { return now_; }

    /// Probability that a frame is lost on air. Unicast: the sender sees a
    /// failed MAC ack. Broadcast: silently lost.
    double airLoss = 0.0;
    /// Probability that a frame reaches the receiver's MAC (unicast ack OK)
    /// but is dropped before the application sees it (full receive queue).
    double appLoss = 0.0;
    /// Probability that a unicast frame arrives but its MAC ack is lost, so the
    /// sender sees a failure and may send it again.
    double macAckLoss = 0.0;
    /// How long the radio takes to report a failed unicast frame: the real
    /// driver retries in hardware for ~100 ms first.
    uint32_t failLatencyMs = 100;
    /// Return true to drop a specific frame (applied before random loss).
    std::function<bool(const Frame&)> dropIf;
    /// Extra milliseconds before a specific frame is delivered, after its
    /// "sent" report: an asymmetry that send-time stamps can't see.
    std::function<uint32_t(const Frame&)> deliveryDelayMs;
    /// Rate/power-dependent delivery (default: always).
    LinkModel linkModel;
    /// RSSI seen by `to` for a frame from `from` (default: -60 dBm + power).
    std::function<int(size_t from, size_t to, float powerDbm)> rssiModel;
    /// Run every simulated millisecond after the engines tick (see Ticker).
    std::vector<Ticker> tickers;
    /// Tick only what is due (see sparseTicks(), the default).
    bool sparse = sparseTicks();
    /// Engine and ticker ticks run and skipped (skipped only when sparse).
    size_t ticksRun = 0, ticksSkipped = 0;
    /// Every frame handed to the radio, in order.
    std::vector<Frame> log;

    Status transmit(size_t from, const Mac& dst, const uint8_t* data, size_t len) {
        Exempt air;  // the radio's buffers, not NowTP's
        SimLink& link = nodes_[from]->link;
        if (link.inFlight) {
            std::fprintf(stderr, "engine violated one-frame-in-flight\n");
            std::abort();
        }
        if (len > link.maxFrameSize(dst)) {
            std::fprintf(stderr, "frame larger than its destination takes\n");
            std::abort();
        }
        if (link.busyReplies > 0) {
            link.busyReplies--;
            return Status::QueueFull;
        }
        link.inFlight = true;
        Frame f;
        f.from = from;
        f.dst = dst;
        f.data.assign(data, data + len);
        log.push_back(f);
        bool forced = dropIf && dropIf(f);

        bool ok = true;
        uint32_t onAir = now_ + nodes_[from]->txQueueMs;  // when the frame leaves
        uint32_t arrives = onAir + 1 + (deliveryDelayMs ? deliveryDelayMs(f) : 0);
        const SimRadio& tx = nodes_[from]->radio;
        nowtp::PhyRate rate = tx.rateFor(dst);
        if (!nodes_[from]->online) {
            ok = dst.isBroadcast();  // a node that is off reaches nobody
        } else if (dst.isBroadcast()) {
            for (size_t i = 0; i < nodes_.size(); ++i) {
                if (i == from || !hears(from, i, rate)) continue;
                if (forced || chance(airLoss) || chance(appLoss)) continue;
                schedule(Event{arrives, Event::Deliver, i, from, f.data, true, rssi(from, i)});
            }
        } else {
            size_t to = find(dst);
            bool reachable = to != SIZE_MAX && hears(from, to, rate);
            if (!reachable || chance(airLoss)) {
                ok = false;
            } else {
                if (!forced && !chance(appLoss)) schedule(Event{arrives, Event::Deliver, to, from, f.data, true, rssi(from, to)});
                // The receiver's MAC acknowledgement must make it back.
                if (chance(macAckLoss) || !hears(to, from, nowtp::PhyRate::B1M)) ok = false;
            }
        }
        uint32_t latency = ok ? 1 : std::max<uint32_t>(1, failLatencyMs);
        schedule(Event{onAir + latency, Event::SendDone, from, from, std::vector<uint8_t>(), ok, 0, dst});
        return Status::Ok;
    }

    /// Delivers a hand-crafted frame straight to a node.
    void inject(size_t to, const Mac& src, const std::vector<uint8_t>& frame) {
        nodes_[to]->engine.onFrameReceived(src, frame.data(), frame.size(), now_);
    }

    // The simulation's own memory isn't counted against a heap limit; what
    // NowTP takes while handling an event is.
    void step() {
        Exempt own;
        now_++;
        // What is due now, asked before this millisecond's events, as the
        // transport asks before it sleeps; the events then wake their node.
        due_.assign(nodes_.size(), !sparse);
        tickerDue_.assign(tickers.size(), !sparse);
        if (sparse) {
            Counted counted;
            for (size_t i = 0; i < nodes_.size(); ++i) {
                nowtp::Deadline d(now_);
                nodes_[i]->engine.nextTick(d);
                due_[i] = d.set() && d.delay() == 0;
            }
            for (size_t i = 0; i < tickers.size(); ++i) {
                nowtp::Deadline d(now_);
                if (tickers[i].due) tickers[i].due(d);
                tickerDue_[i] = !tickers[i].due || (d.set() && d.delay() == 0);
            }
        }
        // The transport ticks everything of a node at once.
        for (size_t i = 0; i < tickers.size(); ++i) {
            if (tickerDue_[i] && tickers[i].node < due_.size()) due_[tickers[i].node] = true;
        }
        while (!events_.empty() && events_.front().time <= now_) {
            Event e = events_.front();
            events_.pop_front();
            due_[e.node] = true;
            Node& n = *nodes_[e.node];
            if (e.kind == Event::SendDone) {
                n.link.inFlight = false;
                Counted counted;
                n.link.peers.clearInFlight();
                if (n.onSent) n.onSent(e.dst, e.ok);
                n.engine.onFrameSent(e.ok, now_, n.clockUs(now_));
            } else if (n.online) {
                Counted counted;
                if (n.onHeard) n.onHeard(nodes_[e.from]->mac);
                n.engine.onFrameReceived(nodes_[e.from]->mac, e.data.data(), e.data.size(), now_, e.rssi,
                                         n.clockUs(now_));
            }
        }
        Counted counted;
        for (size_t i = 0; i < nodes_.size(); ++i) {
            if (!due_[i]) {
                ticksSkipped++;
                continue;
            }
            ticksRun++;
            nodes_[i]->engine.tick(now_);
        }
        bool anyDue = false;
        for (size_t i = 0; i < due_.size(); ++i) anyDue = anyDue || due_[i];
        // Indexed: a ticker may add tickers (they run from the next millisecond).
        for (size_t i = 0; i < tickerDue_.size(); ++i) {
            size_t node = tickers[i].node;
            bool woken = node == SIZE_MAX ? anyDue : node < due_.size() && due_[node];
            if (!tickerDue_[i] && !woken) {
                ticksSkipped++;
                continue;
            }
            ticksRun++;
            tickers[i].tick(now_);
        }
    }

    void run(uint32_t ms) {
        for (uint32_t i = 0; i < ms; ++i) step();
    }

    bool runUntil(const std::function<bool()>& done, uint32_t maxMs = 10000) {
        for (uint32_t i = 0; i < maxMs; ++i) {
            if (done()) return true;
            step();
        }
        return done();
    }

private:
    struct Event {
        uint32_t time;
        enum Kind { Deliver, SendDone } kind;
        size_t node;
        size_t from;
        std::vector<uint8_t> data;
        bool ok;
        int8_t rssi;
        Mac dst = Mac();  // SendDone: the frame's destination
    };

    int8_t rssi(size_t from, size_t to) const {
        float p = nodes_[from]->radio.power;
        int v = rssiModel ? rssiModel(from, to, p) : static_cast<int>(-60 + p);
        return static_cast<int8_t>(v);
    }

    // In time order, FIFO among equal times.
    void schedule(const Event& e) {
        auto it = events_.end();
        while (it != events_.begin() && (it - 1)->time > e.time) --it;
        events_.insert(it, e);
    }
    // One frame from `from` decoded by `to` (random draw with the link model).
    bool hears(size_t from, size_t to, nowtp::PhyRate rate) {
        const Node& a = *nodes_[from];
        const Node& b = *nodes_[to];
        if (!a.online || !b.online || a.radio.chan != b.radio.chan) return false;
        if (nowtp::isLongRange(rate) && !b.radio.lr) return false;
        if (!linkModel) return true;
        return chance(1.0 - linkModel(from, to, rate, a.radio.power));
    }
    bool chance(double p) { return p > 0 && std::uniform_real_distribution<double>(0, 1)(rng_) < p; }
    size_t find(const Mac& m) const {
        for (size_t i = 0; i < nodes_.size(); ++i) {
            if (nodes_[i]->mac == m) return i;
        }
        return SIZE_MAX;
    }

public:
    std::mt19937& rng() { return rng_; }

private:
    std::vector<std::unique_ptr<Node>> nodes_;
    std::vector<bool> due_, tickerDue_;
    std::deque<Event> events_;
    std::mt19937 rng_;
    uint32_t now_ = clockStart();
};

inline Status SimLink::sendFrame(const Mac& dst, const uint8_t* data, size_t len) {
    if (driver.capacity > 0 && !dst.isBroadcast()) {
        bool added = false;
        if (peers.use(dst, net_.now(), added) != Status::Ok) return Status::LinkError;
    }
    Status st = net_.transmit(index_, dst, data, len);
    if (st == Status::Ok) peers.setInFlight(dst);
    return st;
}

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
