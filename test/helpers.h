#pragma once

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <utility>
#include <vector>

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

// ---------------------------------------------------------------------------
// Helpers

namespace {

[[maybe_unused]] std::vector<uint8_t> pattern(size_t n, uint32_t seed = 7) {
    std::vector<uint8_t> v(n);
    std::mt19937 rng(seed);
    for (auto& b : v) b = static_cast<uint8_t>(rng());
    return v;
}

struct Inbox {
    std::vector<std::vector<uint8_t>> messages;
    std::vector<Message> meta;

    ReceiveHandler handler() {
        return [this](const Message& m) {
            testing::HeapExempt app;  // the application's memory
            messages.emplace_back(m.data, m.data + m.len);
            meta.push_back(m);
            meta.back().data = nullptr;
        };
    }
};

struct Outcome {
    bool done = false;
    Status status = Status::Ok;

    CompletionHandler handler() {
        return [this](Status s) {
            done = true;
            status = s;
        };
    }
};

[[maybe_unused]] SendOptions reliable() {
    SendOptions o;
    o.reliable = true;
    return o;
}

[[maybe_unused]] SendOptions latest() {
    SendOptions o;
    o.latestOnly = true;
    return o;
}

std::vector<uint8_t> fragmentFrame(uint8_t flags, uint8_t port, uint16_t id, uint16_t index, uint16_t count,
                                   const std::vector<uint8_t>& payload) {
    wire::Header h;
    h.type = wire::Type::Fragment;
    h.flags = flags;
    h.port = port;
    h.messageId = id;
    h.index = index;
    h.count = count;
    std::vector<uint8_t> f(wire::kFragmentHeaderSize);
    wire::encodeHeader(h, f.data());
    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}

// Splits `msg` into the frames a sender with the given mtu would produce.
[[maybe_unused]] std::vector<std::vector<uint8_t>> fragmentsOf(const std::vector<uint8_t>& msg, uint8_t flags, uint8_t port,
                                              uint16_t id, size_t mtu = 250) {
    std::vector<uint8_t> stream = msg;
    stream.resize(msg.size() + 4);
    wire::putU32(stream.data() + msg.size(), wire::crc32(msg.data(), msg.size()));
    size_t frag = mtu - wire::kFragmentHeaderSize;
    uint16_t count = static_cast<uint16_t>((stream.size() + frag - 1) / frag);
    std::vector<std::vector<uint8_t>> out;
    for (uint16_t i = 0; i < count; ++i) {
        size_t start = i * frag;
        size_t n = std::min(frag, stream.size() - start);
        std::vector<uint8_t> p(stream.begin() + start, stream.begin() + start + n);
        out.push_back(fragmentFrame(flags, port, id, i, count, p));
    }
    return out;
}

}  // namespace

namespace {

// Frame sizes per destination, as the transport negotiates them.
struct SizedLink : Link {
    Mac wide = {{0x02, 0, 0, 0, 0, 2}};
    size_t wideSize = 1470;
    std::vector<std::vector<uint8_t>> sent;
    Status sendFrame(const Mac&, const uint8_t* data, size_t len) override {
        testing::HeapExempt radio;
        sent.emplace_back(data, data + len);
        return Status::Ok;
    }
    size_t maxFrameSize(const Mac& dst) const override { return dst == wide ? wideSize : 250; }
};

}  // namespace

namespace {

struct DiscoveryRig {
    sim::Network net;
    std::vector<std::unique_ptr<Discovery>> nodes;
    std::vector<std::vector<std::pair<PeerEvent, PeerInfo>>> events;
    std::mt19937 rng{99};

    size_t add(const std::string& name, DiscoveryConfig cfg = DiscoveryConfig(), uint16_t maxFrame = 250) {
        size_t i = net.addNode();
        cfg.name = name;
        nodes.emplace_back(new Discovery(net.engine(i), cfg, maxFrame, [this] { return static_cast<uint32_t>(rng()); }));
        events.emplace_back();
        nodes.back()->onPeerEvent([this, i](PeerEvent e, const PeerInfo& p) { events[i].push_back(std::make_pair(e, p)); });
        return i;
    }
    void run(uint32_t ms) {
        for (uint32_t t = 0; t < ms; ++t) {
            net.step();
            for (auto& d : nodes) d->tick(net.now());
        }
    }
    size_t count(size_t node, PeerEvent e) const {
        size_t n = 0;
        for (const auto& ev : events[node]) n += ev.first == e;
        return n;
    }
};

}  // namespace

namespace {

// Drops `from`'s frames on kDiscoveryPort: its announcements are lost.
[[maybe_unused]] std::function<bool(const sim::Frame&)> dropAnnouncementsFrom(const std::vector<size_t>& nodes) {
    return [nodes](const sim::Frame& f) {
        wire::Header h;
        size_t off;
        return std::find(nodes.begin(), nodes.end(), f.from) != nodes.end() &&
               wire::decodeHeader(f.data.data(), f.data.size(), h, off) && h.port == kDiscoveryPort;
    };
}

}  // namespace

namespace {

struct DiagRig {
    sim::Network net{11};
    sim::SimHost host{net};
    std::vector<std::unique_ptr<Diagnostics>> diag;
    std::vector<std::unique_ptr<Discovery>> disc;

    size_t add(const std::string& name = "", Config cfg = Config(), uint16_t maxFrame = 1470,
               DiagnosticsConfig dc = DiagnosticsConfig()) {
        size_t i = net.addNode(cfg);
        diag.emplace_back(new Diagnostics(net.engine(i), net.node(i).radio, host, dc));
        diag.back()->start();
        DiscoveryConfig dcfg;
        dcfg.name = name.empty() ? "n" + std::to_string(i) : name;
        disc.emplace_back(new Discovery(net.engine(i), dcfg, maxFrame, [this] { return static_cast<uint32_t>(net.rng()()); }));
        diag.back()->setDiscovery(disc.back().get());
        Diagnostics* d = diag.back().get();
        Discovery* ds = disc.back().get();
        net.tickers.push_back(sim::Ticker(
            [d, ds](uint32_t now) {
                d->tick(now);
                ds->tick(now);
            },
            [d, ds](Deadline& dl) {
                d->nextTick(dl);
                ds->nextTick(dl);
            },
            i));
        return i;
    }
    void startDiscovery() {
        for (auto& d : disc) d->start(net.now());
        net.run(200);
    }
    static bool has(const std::vector<Issue>& issues, IssueKind kind, bool local) {
        for (const Issue& i : issues) {
            if (i.kind == kind && i.local == local) return true;
        }
        return false;
    }
    static bool has(const std::vector<Issue>& issues, IssueKind kind) {
        return has(issues, kind, true) || has(issues, kind, false);
    }
};

// A board whose supply sags: nothing above 17 dBm, no OFDM above 13 dBm.
[[maybe_unused]] sim::LinkModel weakSupply(size_t board) {
    return [board](size_t from, size_t, PhyRate rate, float power) {
        if (from != board) return 0.0;
        if (power > 17.01f) return 1.0;
        if (isOfdm(rate) && power > 13.01f) return 1.0;
        return 0.0;
    };
}

}  // namespace

namespace {

[[maybe_unused]] std::vector<uint8_t> testKey(uint8_t seed = 0x42) {
    std::vector<uint8_t> k(32);
    for (size_t i = 0; i < k.size(); ++i) k[i] = static_cast<uint8_t>(seed + i * 7);
    return k;
}

struct SecureRig {
    SecureRig() {}
    explicit SecureRig(uint32_t clockStart) : net(21, clockStart) {}
    sim::Network net{21};
    sim::Scheduler sched{net};
    sim::Scheduler::Host host{sched};
    std::vector<std::unique_ptr<Security>> sec;

    size_t add(const std::vector<uint8_t>& key, bool require = true, const std::string& code = "") {
        size_t i = net.addNode();
        sec.emplace_back();
        reboot(i, key, require, code);
        // No timers: what it does follows messages.
        net.tickers.push_back(sim::Ticker([this, i](uint32_t now) { sec[i]->tick(now); }, [](Deadline&) {}, i));
        return i;
    }
    // A fresh Security object, as after a reboot: new epoch, no replay state.
    void reboot(size_t i, const std::vector<uint8_t>& key, bool require = true, const std::string& code = "") {
        if (sec[i]) sec[i]->stop();
        SecurityConfig c;
        c.key = key;
        c.requireAuthentication = require;
        c.pairingCode = code;
        sec[i].reset(new Security(net.engine(i), host, net.mac(i), c));
        sec[i]->start();
    }
    Status sendWait(size_t from, size_t to, uint8_t port, const std::vector<uint8_t>& data, SendOptions o) {
        Outcome out;
        net.engine(from).send(net.mac(to), port, data.data(), data.size(), o, out.handler(), net.now());
        net.runUntil([&] { return out.done; }, 10000);
        return out.done ? out.status : Status::Cancelled;
    }
    // Last frame `from` sent on `port`.
    std::vector<uint8_t> lastFrame(size_t from, uint8_t port) const {
        for (size_t i = net.log.size(); i-- > 0;) {
            const sim::Frame& f = net.log[i];
            wire::Header h;
            size_t off;
            if (f.from == from && wire::decodeHeader(f.data.data(), f.data.size(), h, off) && h.port == port &&
                h.type != wire::Type::Ack) {
                return f.data;
            }
        }
        return std::vector<uint8_t>();
    }
};

}  // namespace

namespace {

struct FollowRig {
    sim::Network net{5};
    std::mt19937 rng{3};
    std::vector<std::unique_ptr<Discovery>> disc;
    std::vector<std::unique_ptr<ChannelFollower>> fol;
    std::vector<int> moves;

    size_t add(uint8_t channel, bool locked, ChannelConfig cc = ChannelConfig()) {
        size_t i = net.addNode();
        net.node(i).radio.chan = channel;
        net.node(i).radio.channelLocked = locked;
        DiscoveryConfig dc;
        dc.name = "n" + std::to_string(i);
        dc.announceIntervalMs = 500;
        dc.peerTimeoutMs = 1600;
        disc.emplace_back(new Discovery(net.engine(i), dc, 250, [this] { return static_cast<uint32_t>(rng()); }));
        fol.emplace_back(new ChannelFollower(*disc.back(), net.node(i).radio, cc));
        moves.push_back(0);
        disc[i]->onPeerEvent([this, i](PeerEvent e, const PeerInfo& p) { fol[i]->onPeerEvent(e, p, net.now()); });
        disc[i]->onPeerMoved([this, i](const PeerInfo& p, uint8_t ch) { fol[i]->onPeerMoved(p, ch, net.now()); });
        fol[i]->onChannelChange([this, i](uint8_t) { moves[i]++; });
        bool anchor = cc.anchor;
        net.tickers.push_back([this, i, anchor](uint32_t now) {
            // What the transport does: announce the current channel and anchor state.
            const sim::SimRadio& r = net.node(i).radio;
            disc[i]->setChannelInfo(r.chan, anchor || r.channelLocked, now);
            disc[i]->tick(now);
            fol[i]->tick(now);
        });
        return i;
    }
    void start() {
        for (size_t i = 0; i < disc.size(); ++i) {
            disc[i]->start(net.now());
            fol[i]->start(net.now());
        }
    }
    uint8_t chan(size_t i) { return net.node(i).radio.chan; }
    // Delivers `from`'s last frame (an announcement, or a goodbye after
    // announceMove()) to `to` by hand: adjacent-channel leakage, which the
    // simulation doesn't model (it only connects equal channels).
    void leak(size_t from, size_t to) {
        for (size_t i = net.log.size(); i-- > 0;) {
            if (net.log[i].from != from) continue;
            net.inject(to, net.mac(from), net.log[i].data);
            return;
        }
        CHECK(false);
    }
    // A node with a locked channel that announces a move, then makes it.
    void relocate(size_t i, uint8_t channel) {
        CHECK(disc[i]->announceMove(channel, net.now()));
        net.run(20);  // the notices go out on the old channel
        net.node(i).radio.chan = channel;
        disc[i]->setChannelInfo(channel, true, net.now());  // as the transport does, before telling the follower
        fol[i]->onChannelChanged(channel, net.now());
    }
};

}  // namespace

namespace {

struct TimeRig {
    sim::Network net{8};
    std::mt19937 rng{4};
    std::vector<std::unique_ptr<Discovery>> disc;
    std::vector<std::unique_ptr<TimeSync>> ts;
    std::vector<TimeRole> roles;
    std::function<void(size_t, TimeSyncConfig&)> configure;  // applied when a node is built

    size_t add(TimeRole role, uint64_t clockOffsetUs, double skew) {
        size_t i = net.addNode();
        net.node(i).clockOffsetUs = clockOffsetUs;
        net.node(i).clockSkew = skew;
        disc.emplace_back();
        ts.emplace_back();
        roles.push_back(role);
        build(i);
        net.tickers.push_back(sim::Ticker(
            [this, i](uint32_t now) {
                disc[i]->tick(now);
                ts[i]->tick(now);
            },
            [this, i](Deadline& d) {
                disc[i]->nextTick(d);
                if (ts[i]) ts[i]->nextTick(d);
            },
            i));
        return i;
    }
    size_t add(bool reference, uint64_t clockOffsetUs, double skew) {
        return add(reference ? TimeRole::Reference : TimeRole::Follow, clockOffsetUs, skew);
    }
    // Node i's Discovery and TimeSync, as they are after a boot (not started).
    void build(size_t i) {
        ts[i].reset();
        DiscoveryConfig dc;
        dc.name = "t" + std::to_string(i);
        disc[i].reset(new Discovery(net.engine(i), dc, 250, [this] { return static_cast<uint32_t>(rng()); }));
        TimeSyncConfig tc;
        tc.role = roles[i];
        if (configure) configure(i, tc);
        sim::Node* node = &net.node(i);
        sim::Network* nw = &net;
        ts[i].reset(new TimeSync(net.engine(i), [node, nw] { return node->clockUs(nw->now()); }, tc, net.mac(i)));
        ts[i]->setDiscovery(disc[i].get());
        disc[i]->onPeerEvent([this, i](PeerEvent e, const PeerInfo& p) { ts[i]->onPeerEvent(e, p, net.now()); });
    }
    void start(size_t i) {
        disc[i]->start(net.now());
        ts[i]->start(net.now());
    }
    void start() {
        for (size_t i = 0; i < ts.size(); ++i) start(i);
    }
    // A reboot without goodbye: the node's clock restarts near `uptimeUs`.
    void reboot(size_t i, uint64_t uptimeUs) {
        net.node(i).online = false;  // what the old objects send on the way out is lost
        build(i);
        net.node(i).clockOffsetUs = uptimeUs - static_cast<uint64_t>(net.now()) * 1000;
        net.node(i).clockSkew = 0;
        net.node(i).online = true;
        start(i);
    }
    size_t acting() const {
        size_t n = 0;
        for (const auto& t : ts) n += t->isReference() ? 1 : 0;
        return n;
    }
    bool allSynced() const {
        for (const auto& t : ts) {
            if (!t->synced()) return false;
        }
        return true;
    }
    // Error of node i's network time against the reference's clock, µs.
    int64_t error(size_t i, size_t ref) {
        return static_cast<int64_t>(ts[i]->networkTime() - net.node(ref).clockUs(net.now()));
    }
    // Difference between two nodes' network times, µs.
    int64_t apart(size_t i, size_t j) { return static_cast<int64_t>(ts[i]->networkTime() - ts[j]->networkTime()); }
};

int64_t absValue(int64_t v) {
    return v < 0 ? -v : v;
}

}  // namespace

namespace {

struct FakeWire;

// A carrier between TimeSyncs, as UDP on a LAN: a datagram arrives after a
// fixed delay, stamped with the nodes' clocks as it leaves and arrives.
struct FakeCarrier : TimeCarrier {
    FakeWire* wire = nullptr;
    size_t node = 0;
    TimeSync* core = nullptr;
    uint32_t nextToken = 1;
    TimeCarrierLimits lim;
    const char* name() const override;
    Status send(const Mac& device, const uint8_t* data, size_t len, uint32_t* token) override;
    bool reaches(const Mac& device) const override;
    TimeCarrierLimits limits() const override { return lim; }
};

struct FakeWire {
    struct Packet {
        size_t from, to;
        std::vector<uint8_t> data;
        uint32_t at;
    };
    struct Report {
        size_t node;
        uint32_t token;
        uint64_t us;
    };
    sim::Network& net;
    const std::vector<Mac>& ids;  // devices, by node
    std::string name;
    uint32_t delayMs;
    uint32_t requestDelayMs = 0;  // more for requests: a delay in one direction, after the stamps
    std::vector<std::unique_ptr<FakeCarrier>> at;  // by node; null: not on this wire
    std::vector<bool> unplugged;  // nothing goes in or out, and reaches() says so
    std::vector<bool> silent;     // nothing goes in or out, but reaches() doesn't say so
    std::vector<Packet> packets;
    std::vector<Report> reports;
    size_t sentCount = 0;

    FakeWire(sim::Network& n, const std::vector<Mac>& i, std::string nm, uint32_t delay)
        : net(n), ids(i), name(std::move(nm)), delayMs(delay) {
        net.tickers.push_back(sim::Ticker([this](uint32_t now) { step(now); }, [this](Deadline& d) { due(d); }));
    }
    FakeCarrier& join(size_t node, TimeSync& core) {
        if (at.size() <= node) {
            at.resize(node + 1);
            unplugged.resize(node + 1);
            silent.resize(node + 1);
        }
        at[node].reset(new FakeCarrier());
        FakeCarrier& c = *at[node];
        c.wire = this;
        c.node = node;
        c.core = &core;
        if (core.addCarrier(c) != Status::Ok) std::abort();
        return c;
    }
    bool open(size_t i) const { return i < at.size() && at[i] && !unplugged[i] && !silent[i]; }
    int find(const Mac& m) const {
        for (size_t i = 0; i < at.size(); ++i) {
            if (at[i] && ids[i] == m) return static_cast<int>(i);
        }
        return -1;
    }
    void step(uint32_t now) {
        testing::HeapCounted nowtp;
        std::vector<Report> r;
        r.swap(reports);
        for (const Report& x : r) {
            if (at[x.node]) at[x.node]->core->sent(*at[x.node], x.token, x.us);
        }
        for (size_t i = 0; i < packets.size();) {
            if (static_cast<int32_t>(now - packets[i].at) < 0) {
                ++i;
                continue;
            }
            Packet p = std::move(packets[i]);
            packets.erase(packets.begin() + static_cast<std::ptrdiff_t>(i));
            if (!open(p.from) || !open(p.to)) continue;
            at[p.to]->core->received(*at[p.to], ids[p.from], p.data.data(), p.data.size(),
                                     net.node(p.to).clockUs(now));
        }
    }
    void due(Deadline& d) const {
        if (!reports.empty()) d.in(0);
        for (const Packet& p : packets) d.at(p.at);
    }
};

const char* FakeCarrier::name() const {
    return wire->name.c_str();
}

Status FakeCarrier::send(const Mac& device, const uint8_t* data, size_t len, uint32_t* token) {
    testing::HeapExempt wireMemory;
    if (len > TimeSync::kMaxDatagram) std::abort();
    if (wire->unplugged[node]) return Status::LinkError;
    std::vector<size_t> to;
    if (device.isBroadcast()) {
        for (size_t j = 0; j < wire->at.size(); ++j) {
            if (j != node && wire->at[j]) to.push_back(j);
        }
    } else {
        int j = wire->find(device);
        if (j < 0) return Status::LinkError;
        to.push_back(static_cast<size_t>(j));
    }
    uint32_t now = wire->net.now();
    uint32_t extra = len > 0 && data[0] == 1 ? wire->requestDelayMs : 0;
    for (size_t j : to) {
        wire->packets.push_back(FakeWire::Packet{node, j, std::vector<uint8_t>(data, data + len), now + wire->delayMs + extra});
    }
    *token = nextToken++;
    wire->reports.push_back(FakeWire::Report{node, *token, wire->net.node(node).clockUs(now)});
    wire->sentCount++;
    return Status::Ok;
}

bool FakeCarrier::reaches(const Mac& device) const {
    int j = wire->find(device);
    return j >= 0 && !wire->unplugged[node] && !wire->unplugged[static_cast<size_t>(j)];
}

// TimeSyncs on fake wires and, for some, NowTP's engine (EngineTimeCarrier).
struct CarrierRig {
    sim::Network net{8};
    std::mt19937 rng{11};
    std::vector<Mac> ids;  // device ids, by node: the node's MAC unless set otherwise
    std::vector<std::unique_ptr<TimeSync>> ts;
    std::vector<std::unique_ptr<Discovery>> disc;
    std::vector<std::unique_ptr<EngineTimeCarrier>> radio;
    std::vector<std::unique_ptr<FakeWire>> wires;
    std::function<void(size_t, TimeSyncConfig&)> configure;

    FakeWire& wire(const char* name, uint32_t delayMs = 1) {
        wires.emplace_back(new FakeWire(net, ids, name, delayMs));
        return *wires.back();
    }
    size_t add(TimeRole role, uint64_t clockOffsetUs, double skew, Mac id = Mac()) {
        size_t i = net.addNode();
        net.node(i).clockOffsetUs = clockOffsetUs;
        net.node(i).clockSkew = skew;
        ids.push_back(id == Mac() ? net.mac(i) : id);
        TimeSyncConfig tc;
        tc.role = role;
        if (configure) configure(i, tc);
        sim::Node* node = &net.node(i);
        sim::Network* nw = &net;
        ts.emplace_back(new TimeSync([node, nw] { return node->clockUs(nw->now()); }, tc, ids[i],
                                     [nw] { return nw->now(); }));
        disc.emplace_back();
        radio.emplace_back();
        net.tickers.push_back(sim::Ticker([this, i](uint32_t now) {
            if (disc[i]) disc[i]->tick(now);
            ts[i]->tick(now);
        },
                                          [this, i](Deadline& d) {
                                              if (disc[i]) disc[i]->nextTick(d);
                                              ts[i]->nextTick(d);
                                          },
                                          i));
        return i;
    }
    // Node i on ESP-NOW too: its engine as a carrier, peers named by device id.
    EngineTimeCarrier& addRadio(size_t i) {
        DiscoveryConfig dc;
        dc.name = "c" + std::to_string(i);
        disc[i].reset(new Discovery(net.engine(i), dc, 250, [this] { return static_cast<uint32_t>(rng()); }));
        if (ids[i] != net.mac(i)) disc[i]->setDeviceId(ids[i]);
        radio[i].reset(new EngineTimeCarrier());
        EngineTimeCarrier& c = *radio[i];
        sim::Network* nw = &net;
        c.setClock([nw] { return nw->now(); });
        c.setDiscovery(disc[i].get());
        c.setDeviceIds(true);
        if (ts[i]->addCarrier(c) != Status::Ok) std::abort();
        c.attach(&net.engine(i), ts[i].get());
        disc[i]->onPeerEvent([this, i](PeerEvent e, const PeerInfo& p) { radio[i]->peerEvent(e, p); });
        return c;
    }
    void start() {
        for (size_t i = 0; i < ts.size(); ++i) {
            if (disc[i]) disc[i]->start(net.now());
            ts[i]->start(net.now());
        }
    }
    size_t acting() const {
        size_t n = 0;
        for (const auto& t : ts) n += t->isReference() ? 1 : 0;
        return n;
    }
    bool allSynced() const {
        for (const auto& t : ts) {
            if (!t->synced()) return false;
        }
        return true;
    }
    int64_t error(size_t i, size_t ref) {
        return static_cast<int64_t>(ts[i]->networkTime() - net.node(ref).clockUs(net.now()));
    }
    int64_t apart(size_t i, size_t j) { return static_cast<int64_t>(ts[i]->networkTime() - ts[j]->networkTime()); }
    std::string carrier(size_t i) const { return ts[i]->status().carrier; }
    // Runs `ms`, checking node i stays synchronized; returns its largest error against `ref`.
    int64_t watch(size_t i, size_t ref, uint32_t ms) {
        int64_t worst = 0;
        for (uint32_t t = 0; t < ms; t += 10) {
            net.run(10);
            if (!ts[i]->synced()) worst = INT64_MAX;  // fails the caller's bound
            if (worst != INT64_MAX) worst = std::max(worst, absValue(error(i, ref)));
        }
        return worst;
    }
};

[[maybe_unused]] Mac deviceMac(uint8_t last) {
    Mac m;
    const uint8_t b[6] = {0x02, 0xde, 0xad, 0xbe, 0xef, last};
    memcpy(m.bytes, b, sizeof(b));
    return m;
}

}  // namespace

namespace {

// Stands in for EspNowTransport's gate, which lets go of its lock. What
// another task does meanwhile runs in leave(): after the callback, before
// NowTP's code goes on, the worst moment.
struct TestGate : CallbackGate {
    int depth = 0;
    int opened = 0;
    std::function<void()> meanwhile;  // runs once, at the next leave()

    uint32_t enter() override {
        depth++;
        opened++;
        return 0;
    }
    void leave(uint32_t) override {
        depth--;
        if (!meanwhile) return;
        std::function<void()> f;
        f.swap(meanwhile);
        f();
    }
};

}  // namespace
