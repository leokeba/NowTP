// Simulated radio network for host-side tests, split by concern; this stays
// the one include. What each holds:
//   sim_radio.h     Exempt, Counted, Frame, SimRadio, SimPeerDriver, SimLink, clockStart
//   sim_network.h   Node, Ticker, sparseTicks, Network, SimLink::sendFrame
//   sim_scheduler.h SimHost, Scheduler
#pragma once

#include "sim_radio.h"
#include "sim_network.h"
#include "sim_scheduler.h"
