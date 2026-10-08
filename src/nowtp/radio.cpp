// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "radio.h"

namespace nowtp {

namespace {

struct RateName {
    const char* name;
    uint32_t kbps;
};

// Indexed by PhyRate.
const RateName kRateNames[kPhyRateCount] = {
    {"default (1 Mbps)", 1000}, {"1 Mbps", 1000},      {"2 Mbps", 2000},          {"5.5 Mbps", 5500},
    {"11 Mbps", 11000},         {"6 Mbps", 6000},      {"9 Mbps", 9000},          {"12 Mbps", 12000},
    {"18 Mbps", 18000},         {"24 Mbps", 24000},    {"36 Mbps", 36000},        {"48 Mbps", 48000},
    {"54 Mbps", 54000},         {"MCS0 (6.5 Mbps)", 6500}, {"MCS1 (13 Mbps)", 13000}, {"MCS2 (19.5 Mbps)", 19500},
    {"MCS3 (26 Mbps)", 26000},  {"MCS4 (39 Mbps)", 39000}, {"MCS5 (52 Mbps)", 52000}, {"MCS6 (58.5 Mbps)", 58500},
    {"MCS7 (65 Mbps)", 65000},  {"LR 250 kbps", 250},  {"LR 500 kbps", 500},
};

}  // namespace

const char* toString(PhyRate rate) {
    return isValid(rate) ? kRateNames[static_cast<uint8_t>(rate)].name : "invalid";
}

uint32_t nominalKbps(PhyRate rate) {
    return isValid(rate) ? kRateNames[static_cast<uint8_t>(rate)].kbps : 0;
}

}  // namespace nowtp
