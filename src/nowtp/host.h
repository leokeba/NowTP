// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <stdint.h>

namespace nowtp {

/// What NowTP's blocking procedures (diagnostics, pairing) need from the platform.
///
/// The procedures run in an application task: sleep() must let the engine keep
/// processing radio events (the NowTP task on ESP32; stepping the simulated
/// network in host tests), and lock()/unlock() guard the engine and radio.
class ServiceHost {
public:
    virtual ~ServiceHost() {}
    virtual uint32_t now() = 0;
    virtual void sleep(uint32_t ms) = 0;
    virtual void lock() = 0;
    virtual void unlock() = 0;
    virtual uint32_t random() = 0;
};

}  // namespace nowtp
