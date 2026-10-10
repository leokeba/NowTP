// Simulated radio network for host-side tests.
#pragma once

#include <condition_variable>
#include <cstdio>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <thread>
#include <vector>

#include "nowtp/diagnostics.h"
#include "nowtp/engine.h"
#include "nowtp/radio.h"

namespace sim {

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

class SimLink : public nowtp::Link {
public:
    SimLink(Network& net, size_t index) : net_(net), index_(index) {}
    Status sendFrame(const Mac& dst, const uint8_t* data, size_t len) override;
    size_t maxFrameSize(const Mac&) const override { return mtu; }

    size_t mtu = 250;
    bool inFlight = false;
    int busyReplies = 0;  // next N sendFrame() calls return QueueFull

private:
    Network& net_;
    size_t index_;
};

struct Node {
    Node(Network& net, size_t index, const Mac& m, const nowtp::Config& cfg)
        : mac(m), link(net, index), engine(link, cfg, static_cast<uint16_t>(index * 1000)) {}
    Mac mac;
    SimLink link;
    nowtp::Engine engine;
    SimRadio radio;
    bool online = true;
    /// Local clock: offset and rate error against the simulation's time.
    uint64_t clockOffsetUs = 1000000000;
    double clockSkew = 0;  // e.g. 40e-6 for a crystal 40 ppm fast
    uint64_t clockUs(uint32_t nowMs) const {
        return clockOffsetUs + static_cast<uint64_t>(static_cast<double>(nowMs) * 1000.0 * (1.0 + clockSkew));
    }
};

/// Probability that a frame from node `from` reaches node `to`, given the
/// sender's rate and power. Lets tests model weak boards and weak links.
using LinkModel = std::function<double(size_t from, size_t to, nowtp::PhyRate rate, float powerDbm)>;

class Network {
public:
    explicit Network(uint32_t seed = 1) : rng_(seed) {}

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
    /// Return true to drop a specific frame (applied before random loss).
    std::function<bool(const Frame&)> dropIf;
    /// Rate/power-dependent delivery (default: always).
    LinkModel linkModel;
    /// RSSI seen by `to` for a frame from `from` (default: -60 dBm + power).
    std::function<int(size_t from, size_t to, float powerDbm)> rssiModel;
    /// Called every simulated millisecond after the engines tick (discovery, diagnostics...).
    std::vector<std::function<void(uint32_t)>> tickers;
    /// Every frame handed to the radio, in order.
    std::vector<Frame> log;

    Status transmit(size_t from, const Mac& dst, const uint8_t* data, size_t len) {
        SimLink& link = nodes_[from]->link;
        if (link.inFlight) {
            std::fprintf(stderr, "engine violated one-frame-in-flight\n");
            std::abort();
        }
        if (len > link.mtu) {
            std::fprintf(stderr, "frame larger than mtu\n");
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
        const SimRadio& tx = nodes_[from]->radio;
        nowtp::PhyRate rate = tx.rateFor(dst);
        if (!nodes_[from]->online) {
            ok = dst.isBroadcast();  // a node that is off reaches nobody
        } else if (dst.isBroadcast()) {
            for (size_t i = 0; i < nodes_.size(); ++i) {
                if (i == from || !hears(from, i, rate)) continue;
                if (forced || chance(airLoss) || chance(appLoss)) continue;
                schedule(Event{now_ + 1, Event::Deliver, i, from, f.data, true, rssi(from, i)});
            }
        } else {
            size_t to = find(dst);
            bool reachable = to != SIZE_MAX && hears(from, to, rate);
            if (!reachable || chance(airLoss)) {
                ok = false;
            } else {
                if (!forced && !chance(appLoss)) schedule(Event{now_ + 1, Event::Deliver, to, from, f.data, true, rssi(from, to)});
                // The receiver's MAC acknowledgement must make it back.
                if (chance(macAckLoss) || !hears(to, from, nowtp::PhyRate::B1M)) ok = false;
            }
        }
        schedule(Event{now_ + 1, Event::SendDone, from, from, std::vector<uint8_t>(), ok, 0});
        return Status::Ok;
    }

    /// Delivers a hand-crafted frame straight to a node.
    void inject(size_t to, const Mac& src, const std::vector<uint8_t>& frame) {
        nodes_[to]->engine.onFrameReceived(src, frame.data(), frame.size(), now_);
    }

    void step() {
        now_++;
        while (!events_.empty() && events_.front().time <= now_) {
            Event e = events_.front();
            events_.pop_front();
            Node& n = *nodes_[e.node];
            if (e.kind == Event::SendDone) {
                n.link.inFlight = false;
                n.engine.onFrameSent(e.ok, now_);
            } else if (n.online) {
                n.engine.onFrameReceived(nodes_[e.from]->mac, e.data.data(), e.data.size(), now_, e.rssi,
                                         n.clockUs(now_));
            }
        }
        for (auto& n : nodes_) n->engine.tick(now_);
        for (auto& t : tickers) t(now_);
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
    };

    int8_t rssi(size_t from, size_t to) const {
        float p = nodes_[from]->radio.power;
        int v = rssiModel ? rssiModel(from, to, p) : static_cast<int>(-60 + p);
        return static_cast<int8_t>(v);
    }

    void schedule(const Event& e) { events_.push_back(e); }
    // One frame from `from` decoded by `to` (random draw with the link model).
    bool hears(size_t from, size_t to, nowtp::PhyRate rate) {
        const Node& a = *nodes_[from];
        const Node& b = *nodes_[to];
        if (!a.online || !b.online || a.radio.chan != b.radio.chan) return false;
        if (nowtp::isLongRange(rate) && !b.radio.lr) return false;
        if (!linkModel) return true;
        return chance(1.0 - linkModel(from, to, rate, a.radio.power));
    }  // all events use now+1, so FIFO == time order
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
    std::deque<Event> events_;
    std::mt19937 rng_;
    uint32_t now_ = 0;
};

inline Status SimLink::sendFrame(const Mac& dst, const uint8_t* data, size_t len) {
    return net_.transmit(index_, dst, data, len);
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
