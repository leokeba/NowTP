// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
//
// Platform-independent description of the radio: PHY rates and the controls
// diagnostics need to measure and tune a link.
#pragma once

#include "types.h"

namespace nowtp {

/// Over-the-air PHY rate for ESP-NOW frames. Faster rates shorten airtime but
/// need a stronger signal; every receiver decodes any 802.11b/g/n rate, while
/// the Long Range rates need Long Range enabled on both sides.
enum class PhyRate : uint8_t {
    Default = 0,  ///< Not set: 1 Mbps 802.11b (driver default), or the transport's unicastRate for a peer.
    B1M,          ///< 802.11b 1 Mbps: longest standard range, understood by everyone.
    B2M,
    B5_5M,
    B11M,
    G6M,  ///< 802.11g OFDM
    G9M,
    G12M,
    G18M,
    G24M,
    G36M,
    G48M,
    G54M,
    MCS0,  ///< 802.11n HT20, long guard interval: 6.5 Mbps
    MCS1,
    MCS2,
    MCS3,
    MCS4,
    MCS5,
    MCS6,
    MCS7,    ///< 65 Mbps
    LR250K,  ///< Espressif Long Range 250 kbps: longest range, Espressif chips only.
    LR500K,
};

constexpr uint8_t kPhyRateCount = static_cast<uint8_t>(PhyRate::LR500K) + 1;

const char* toString(PhyRate rate);
/// Nominal over-the-air rate in kbit/s (Default counts as 1 Mbps).
uint32_t nominalKbps(PhyRate rate);
inline bool isValid(PhyRate r) {
    return static_cast<uint8_t>(r) < kPhyRateCount;
}
inline bool isLongRange(PhyRate r) {
    return r == PhyRate::LR250K || r == PhyRate::LR500K;
}
/// 802.11g/n rates: OFDM modulation, sensitive to transmitter distortion.
inline bool isOfdm(PhyRate r) {
    return r >= PhyRate::G6M && r <= PhyRate::MCS7;
}

/// Radio controls used by diagnostics. Implemented by the platform transport
/// (and by the host-side simulator in tests). Changes are immediate and
/// global to the node except per-peer rates.
class RadioControl {
public:
    virtual ~RadioControl() {}

    /// Current maximum transmit power in dBm, after any rounding by the driver.
    virtual float txPower() const = 0;
    /// Highest power the driver accepts on this chip, in dBm.
    virtual float txPowerLimit() const = 0;
    virtual Status setTxPower(float dbm) = 0;

    virtual PhyRate broadcastRate() const = 0;
    virtual Status setBroadcastRate(PhyRate rate) = 0;
    /// Rate used for unicast frames to `peer` (Default: the node's unicast default).
    virtual PhyRate peerRate(const Mac& peer) const = 0;
    virtual Status setPeerRate(const Mac& peer, PhyRate rate) = 0;
    /// False for rates the platform cannot use right now (e.g. LR without Long Range).
    virtual bool rateUsable(PhyRate rate) const = 0;

    virtual uint8_t channel() const = 0;
    /// Fails with InvalidState when an access point dictates the channel.
    virtual Status setChannel(uint8_t channel) = 0;

    virtual bool longRange() const = 0;
    virtual Status setLongRange(bool enabled) = 0;
};

}  // namespace nowtp
