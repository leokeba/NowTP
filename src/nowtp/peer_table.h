// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <vector>

#include "types.h"

namespace nowtp {

/// Bookkeeping for the radio's peer table, which holds few entries (ESP-NOW:
/// 20, fewer with encryption). Unicast destinations are registered on first
/// use; when the table is full, the least recently used peer that was added
/// that way gives way. Pinned peers (registered by the application, and the
/// broadcast address) and the destination of the frame in flight never do.
/// Without eviction, a long-lived node (or anyone spoofing 20 sender MACs, to
/// which we send acks) would fill the table for good.
class PeerTable {
public:
    /// The radio's own table.
    class Driver {
    public:
        enum class Result : uint8_t { Ok, Full, Error };
        virtual ~Driver() {}
        /// Registers an unencrypted peer on the current channel.
        virtual Result add(const Mac& mac) = 0;
        virtual void remove(const Mac& mac) = 0;
        virtual bool exists(const Mac& mac) const = 0;
    };

    explicit PeerTable(Driver& driver) : driver_(driver) {}

    /// Makes sure `mac` is registered before a frame goes to it, evicting if
    /// needed. `added` tells the caller to apply its per-peer settings.
    Status use(const Mac& mac, uint32_t nowMs, bool& added);
    /// Frees one slot by evicting the least recently used automatic peer.
    bool evictOne();
    /// The application registered `mac` itself: never evicted.
    void pin(const Mac& mac);
    /// The application removed `mac` from the driver.
    void forget(const Mac& mac);
    /// `mac` left (e.g. discovery lost it): remove it from the driver if it was
    /// added automatically, once no frame to it is in flight.
    void release(const Mac& mac);

    /// The frame just handed to the driver goes to `mac`.
    void setInFlight(const Mac& mac);
    /// The driver reported the frame in flight; runs a deferred release().
    void clearInFlight();

    /// The driver forgot everything (radio restarted).
    void clear();
    /// Peers added automatically and still registered.
    size_t automatic() const;

private:
    struct Entry {
        Mac mac;
        uint32_t lastUsed;
        bool pinned;
    };
    Entry* find(const Mac& mac);

    Driver& driver_;
    std::vector<Entry> entries_;
    Mac inFlight_{};
    bool hasInFlight_ = false;
    bool releaseInFlight_ = false;
};

}  // namespace nowtp
