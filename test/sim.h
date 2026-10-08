// Simulated radio network for host-side tests.
#pragma once

#include <cstdio>
#include <deque>
#include <functional>
#include <memory>
#include <random>
#include <vector>

#include "nowtp/engine.h"

namespace sim {

using nowtp::Mac;
using nowtp::Status;

struct Frame {
    size_t from;
    Mac dst;
    std::vector<uint8_t> data;
};

class Network;

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
    bool online = true;
};

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
        if (!nodes_[from]->online) {
            ok = dst.isBroadcast();  // a node that is off reaches nobody
        } else if (dst.isBroadcast()) {
            for (size_t i = 0; i < nodes_.size(); ++i) {
                if (i == from || !nodes_[i]->online) continue;
                if (forced || chance(airLoss) || chance(appLoss)) continue;
                schedule(Event{now_ + 1, Event::Deliver, i, from, f.data, true});
            }
        } else {
            size_t to = find(dst);
            bool reachable = to != SIZE_MAX && nodes_[to]->online;
            if (!reachable || chance(airLoss)) {
                ok = false;
            } else {
                if (!forced && !chance(appLoss)) schedule(Event{now_ + 1, Event::Deliver, to, from, f.data, true});
                if (chance(macAckLoss)) ok = false;
            }
        }
        schedule(Event{now_ + 1, Event::SendDone, from, from, std::vector<uint8_t>(), ok});
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
                n.engine.onFrameReceived(nodes_[e.from]->mac, e.data.data(), e.data.size(), now_);
            }
        }
        for (auto& n : nodes_) n->engine.tick(now_);
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
    };

    void schedule(const Event& e) { events_.push_back(e); }  // all events use now+1, so FIFO == time order
    bool chance(double p) { return p > 0 && std::uniform_real_distribution<double>(0, 1)(rng_) < p; }
    size_t find(const Mac& m) const {
        for (size_t i = 0; i < nodes_.size(); ++i) {
            if (nodes_[i]->mac == m) return i;
        }
        return SIZE_MAX;
    }

    std::vector<std::unique_ptr<Node>> nodes_;
    std::deque<Event> events_;
    std::mt19937 rng_;
    uint32_t now_ = 0;
};

inline Status SimLink::sendFrame(const Mac& dst, const uint8_t* data, size_t len) {
    return net_.transmit(index_, dst, data, len);
}

}  // namespace sim
