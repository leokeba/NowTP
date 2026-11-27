// Simulated network for host-side tests: nodes with their engines, the delivery
// model over air, and ticking. The radio state a node holds is in sim_radio.h.
#pragma once

#include <cstdio>
#include <cstdlib>
#include <deque>
#include <functional>
#include <memory>
#include <random>
#include <type_traits>
#include <vector>

#include "nowtp/engine.h"

#include "sim_radio.h"

namespace sim {

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
                schedule(Event{arrives, Event::Deliver, i, from, f.data, true, rssi(from, i), Mac()});
            }
        } else {
            size_t to = find(dst);
            bool reachable = to != SIZE_MAX && hears(from, to, rate);
            if (!reachable || chance(airLoss)) {
                ok = false;
            } else {
                if (!forced && !chance(appLoss)) schedule(Event{arrives, Event::Deliver, to, from, f.data, true, rssi(from, to), Mac()});
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

    /// Puts a hand-crafted frame on air from node `from` to node `to`: it
    /// arrives at the next step like any frame (RSSI, local timestamp, the
    /// node woken for sparse ticking), whatever the loss settings. `from` may
    /// be offline (a sender whose own frames we don't model).
    void deliver(size_t to, size_t from, const std::vector<uint8_t>& frame) {
        Exempt air;
        schedule(Event{now_ + 1, Event::Deliver, to, from, frame, true, rssi(from, to), Mac()});
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
        Mac dst;  // SendDone: the frame's destination (no initializer: C++11 aggregate)
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

}  // namespace sim
