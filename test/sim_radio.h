// Simulated radio for host-side tests: the per-node radio state, the ESP-NOW-style
// peer table driver, the link the engine runs on, and the network's clock start.
#pragma once

#include <cstdlib>
#include <functional>
#include <utility>
#include <vector>

#include "nowtp/link.h"
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

}  // namespace sim
