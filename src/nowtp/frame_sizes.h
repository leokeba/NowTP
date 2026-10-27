// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <stdint.h>

#include <algorithm>
#include <utility>
#include <vector>

#include "discovery.h"

namespace nowtp {

/// The frame size for each destination, as the transport chooses it: the one
/// given to addPeer() if any, else the one negotiated with the discovered
/// peer (the smaller of its announced size and ours, if above the default),
/// else the default. Asked per frame, so a peer lost or announced again
/// smaller is seen at once; the engine then cuts queued messages again.
class FrameSizes {
public:
    FrameSizes(uint16_t defaultSize, uint16_t localMax, bool negotiate)
        : default_(defaultSize), localMax_(localMax), negotiate_(negotiate) {}

    void setDiscovery(const Discovery* discovery) { discovery_ = discovery; }
    /// A size of 0 forgets the peer's own size.
    void set(const Mac& mac, uint16_t size) {
        forget(mac);
        if (size) explicit_.push_back(std::make_pair(mac, size));
    }
    void clear() { explicit_.clear(); }

    /// The size negotiated with a discovered peer; 0 (the default) otherwise.
    uint16_t negotiated(const Mac& mac) const {
        const PeerInfo* p = negotiate_ && discovery_ ? discovery_->find(mac) : nullptr;
        if (!p) return 0;
        uint16_t common = std::min(p->maxFrameSize, localMax_);
        return common > default_ ? common : 0;
    }
    uint16_t sizeFor(const Mac& mac) const {
        for (const auto& e : explicit_) {
            if (e.first == mac) return e.second;
        }
        uint16_t n = negotiated(mac);
        return n ? n : default_;
    }

private:
    void forget(const Mac& mac) {
        for (size_t i = 0; i < explicit_.size(); ++i) {
            if (explicit_[i].first != mac) continue;
            explicit_.erase(explicit_.begin() + static_cast<std::ptrdiff_t>(i));
            return;
        }
    }

    uint16_t default_;
    uint16_t localMax_;
    bool negotiate_;
    const Discovery* discovery_ = nullptr;
    std::vector<std::pair<Mac, uint16_t>> explicit_;  // set by addPeer()
};

}  // namespace nowtp
