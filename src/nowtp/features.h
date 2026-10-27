// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
//
// Services EspNowTransport can leave out of the build, to save flash: define
// NOWTP_STREAMS, NOWTP_TIMESYNC, NOWTP_SECURITY or NOWTP_DIAGNOSTICS as 0
// (e.g. -DNOWTP_STREAMS=0 in build flags), or on ESP-IDF turn them off in
// menuconfig (Component config > NowTP). A service left out is never created,
// whatever EspNowConfig says, and its calls return InvalidState. The code
// goes only when the compiler optimizes (any -O but -O0).
#pragma once

#if defined(ESP_PLATFORM)
#include "sdkconfig.h"
#endif

#ifndef NOWTP_STREAMS
#if defined(CONFIG_NOWTP_NO_STREAMS)
#define NOWTP_STREAMS 0
#else
#define NOWTP_STREAMS 1
#endif
#endif

#ifndef NOWTP_TIMESYNC
#if defined(CONFIG_NOWTP_NO_TIMESYNC)
#define NOWTP_TIMESYNC 0
#else
#define NOWTP_TIMESYNC 1
#endif
#endif

#ifndef NOWTP_SECURITY
#if defined(CONFIG_NOWTP_NO_SECURITY)
#define NOWTP_SECURITY 0
#else
#define NOWTP_SECURITY 1
#endif
#endif

/// The diagnostics responder (port 254) and procedures (ping, measure,
/// diagnose, optimize, deep discovery).
#ifndef NOWTP_DIAGNOSTICS
#if defined(CONFIG_NOWTP_NO_DIAGNOSTICS)
#define NOWTP_DIAGNOSTICS 0
#else
#define NOWTP_DIAGNOSTICS 1
#endif
#endif
