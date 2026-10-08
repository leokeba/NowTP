# NowTP

**Reliable, arbitrary-length messaging over ESP-NOW for Arduino and ESP-IDF.**

ESP-NOW sends single frames of up to 250 bytes (1470 with ESP-NOW v2), with no ordering, no reassembly, and only frame-level acknowledgement. NowTP is a small transport layer on top of it, playing the role TCP and UDP play on top of IP:

- **Messages of any size** up to a configurable limit. They are split into fragments and reassembled, and every multi-frame message carries a CRC-32.
- **Ports.** Independent parts of an application share the radio, even though ESP-NOW allows only one receive callback per device.
- **Three delivery modes, chosen per message:**
  - *unreliable*: works for broadcast and unicast.
  - *reliable*: unicast only. Only the missing fragments are retransmitted, and the receiver suppresses duplicates.
  - *latest-only*: a newer message replaces older ones that are still queued or half received. Use it for state where stale data is worse than no data.
- **Non-blocking sends.** Each message gets a completion callback. `sendAndWait()` is available when blocking is easier.
- **Paced by the radio.** The next frame goes out when the driver reports the previous one sent, instead of after a fixed delay.
- **Peer discovery.** Nodes announce a name and app metadata, and report peers as they are found, change or are lost. Discovered peers get the largest frame size both sides support.
- **Works with any Wi-Fi state.** `begin()` brings Wi-Fi up if nothing has, and otherwise adapts to the application's setup: a station (connected or not), a soft-AP, or both.
- **Bounded memory.** Queue sizes, message size and reassembly memory are all configurable.
- **Callbacks never run in the Wi-Fi driver task.** They run in a NowTP task, or inside `poll()` from your loop.
- **Testable on your computer.** The protocol core has no platform dependencies and is tested on a desktop machine against a simulated lossy radio.

> **Status:** early (0.2). The wire format and API may still change before 1.0.

## Quick start (Arduino)

```cpp
#include <NowTP.h>

nowtp::EspNowTransport transport;

void setup() {
    Serial.begin(115200);
    transport.listen(1, [](const nowtp::Message& m) {
        Serial.printf("got %u bytes on port %u\n", (unsigned)m.len, m.port);
    });
    transport.begin();  // starts Wi-Fi if the sketch has not
}

void loop() {
    static uint8_t big[3000];
    transport.send(nowtp::Mac::broadcast(), 1, big, sizeof(big));
    delay(1000);
}
```

Reliable unicast, with a completion callback:

```cpp
nowtp::SendOptions opts;
opts.reliable = true;
transport.send(peerMac, 2, data, len, opts, [](nowtp::Status s) {
    Serial.printf("delivery: %s\n", nowtp::toString(s));
});

// or, blocking (not from inside a NowTP callback):
nowtp::Status s = transport.sendAndWait(peerMac, 2, data, len, opts);
```

Finding peers:

```cpp
nowtp::EspNowConfig config;
config.enableDiscovery = true;
config.discovery.name = "kitchen-sensor";
transport.onPeerEvent([](nowtp::PeerEvent e, const nowtp::PeerInfo& p) {
    if (e == nowtp::PeerEvent::Found) Serial.printf("found %s\n", p.name.c_str());
});
transport.begin(config);
```

More sketches are in [examples/arduino](examples/arduino):

- [Broadcast](examples/arduino/Broadcast/Broadcast.ino)
- [Discovery](examples/arduino/Discovery/Discovery.ino)
- [ReliableUnicast](examples/arduino/ReliableUnicast/ReliableUnicast.ino): two boards that find each other and exchange reliable messages
- [LatestOnly](examples/arduino/LatestOnly/LatestOnly.ino), which also shows `poll()` mode

## ESP-IDF

NowTP is an ESP-IDF component. You can add it in any of these ways:

- Clone or add it as a submodule under your project's `components/` directory.
- Point `EXTRA_COMPONENT_DIRS` at a checkout.
- Use the component manager, in your `main/idf_component.yml`:

  ```yaml
  dependencies:
    nowtp:
      git: https://github.com/leokeba/NowTP.git
      version: main
  ```

See [examples/idf/reliable_echo](examples/idf/reliable_echo).

## Concepts

### Radio setup

`begin()` adapts to whatever the application has done with Wi-Fi:

| Wi-Fi state before `begin()` | What NowTP does | Undone by `end()` |
|---|---|---|
| Nothing set up | Initializes and starts a station on `EspNowConfig::channel` (default 1). On ESP-IDF it also creates the default event loop and initializes NVS if the app hasn't. On Arduino it calls `WiFi.mode(WIFI_STA)`. | Yes |
| Initialized, not started | Starts it (station mode if no mode is set) on `channel` | Stops it |
| Station, not connected | Sets `channel` (set it to 0 to keep the current channel) | – |
| Station connected to an AP | Keeps the AP's channel | – |
| Soft-AP, or AP + station | Keeps the AP's channel. In AP-only mode, ESP-NOW uses the AP interface | – |

- `disablePowerSave` (default on) turns off Wi-Fi modem sleep. A sleeping station misses most ESP-NOW frames.
- `maxTxPower` caps transmit power. See *Troubleshooting* below.
- Set `initWifi = false` to make `begin()` fail instead of starting Wi-Fi.
- `radioInfo()` reports the channel, interface and connection state that `begin()` found.

Things to keep in mind:
- **Shared channel.** All nodes must be on the same channel. A node connected to an AP is on the AP's channel.
- **Addresses depend on the interface.** A node is addressed by the MAC of the interface ESP-NOW uses. A soft-AP node sends from its AP MAC, which is usually its station MAC + 1.

### Discovery

With `enableDiscovery`, a node announces itself by broadcast on reserved port 255.
- **Announcements.** Each one carries `discovery.name` (up to 32 bytes), `discovery.metadata` (up to 160 bytes of app data, for example a role to filter on) and the largest frame the node can receive. Nodes announce every `announceIntervalMs` (2 s by default).
- **Queries.** `begin()` and `discover()` ask every node in range to answer promptly, after a random delay of up to `replyJitterMs`. A node that joins late is found within about 100 ms instead of a full interval.
- **Peer events.** `onPeerEvent()` reports peers as they are found, change their name, metadata or frame size, or are lost. A peer is lost when it says goodbye in `end()`, or after `peerTimeoutMs` (7 s by default) of silence.
- **Reading and updating.** `peers()` returns the current list, and `setDiscoveryMetadata()` changes what this node announces.
- **Frame size.** With `negotiateFrameSize` (on by default), unicast to a discovered peer uses the largest frame both sides support. That's 1470 bytes between two ESP-NOW v2 nodes, and 250 as soon as either side is v1.

### Ports

Every message is sent to a port (0–239; ports 240–255 are reserved, and `send()`/`listen()` reject them). `listen(port, handler)` sets that port's handler. Messages for a port with no handler are dropped, and reliable ones are answered with `Rejected`.

### Delivery modes

| | Broadcast | Unicast | Guarantee |
|---|---|---|---|
| default | ✓ | ✓ | Delivered whole and intact, or not at all; never twice |
| `reliable` | – | ✓ | Retransmitted until the receiver confirms, or `Timeout` / `Rejected` / `SendFailed` |
| `latestOnly` | ✓ | ✓ | Older queued or partial messages to the same peer and port are dropped (`Superseded`) |

`reliable` and `latestOnly` can be combined.

For unicast, ESP-NOW already acknowledges and retries each frame in hardware. Default mode is therefore quite dependable between two boards in range. `reliable` covers what remains: frames dropped in the receiver's queues, reassembly evicted for memory, and acks lost on the way back.

### Threading

ESP-NOW calls its callbacks from the Wi-Fi driver task. NowTP only copies each event into a ring buffer there. Everything else runs elsewhere:

- With `runTask = true` (the default), protocol work and your receive and completion callbacks run in a dedicated NowTP task.
- With `runTask = false`, they run inside `transport.poll()`, which you call from your loop.

Callbacks may call `send()` and `listen()`. Keep them short, and hand heavy work to your own task. `Message::data` is only valid during the receive callback.

### Peers and frame size

- **Peers.** Unknown unicast destinations are registered automatically as unencrypted peers on the current channel. The same happens for senders that need an ack. Set `EspNowConfig::autoAddPeers = false` to manage peers yourself with `addPeer()`. ESP-NOW allows at most 20 peers.
- **Encryption.** Use `addPeer(mac, opts)` with `opts.encrypt` and `opts.lmk`, plus `setPrimaryKey()`. Both sides must register each other with the same keys.
- **Frame size.** Frames are 250 bytes by default, which every ESP-NOW version understands. If both sides run ESP-NOW v2 (ESP-IDF ≥ 5.4, or Arduino-ESP32 ≥ 3.2), larger frames of up to 1470 bytes cut the number of frames by about 6×. Discovery sets this up automatically. Without discovery, set `PeerOptions::maxFrameSize` in `addPeer()`. A v1 receiver silently drops frames larger than 250 bytes, and broadcast always uses `defaultMaxFrameSize` (250).

### Throughput and latency

ESP-NOW sends at 1 Mbps by default, and that rate, not NowTP, sets the ceiling. Measured on an ESP32-S3 sending 8 KB broadcast messages:
- about 68 KB/s with 250-byte frames
- about 104 KB/s with 1470-byte frames

Two boards (ESP32-S3 ↔ ESP32) measured about 102 KB/s for reliable unicast with negotiated 1470-byte frames, and a 16 KB reliable echo round trip took about 310 ms. To go faster, raise the PHY rate with `esp_now_set_peer_rate_config()` (ESP-IDF ≥ 5.4) or `esp_wifi_config_espnow_rate()`, at the cost of range.

A unicast frame to a peer that is off or out of range takes the driver about 100 ms to report as failed. With the default 2 retries, a send to an unreachable peer fails with `SendFailed` after about 300 ms.

### Configuration

`nowtp::EspNowConfig` holds the platform settings and a `protocol` member (`nowtp::Config`) with the protocol limits:

| Field | Default | Meaning |
|---|---|---|
| `protocol.maxMessageSize` | 16 KB | Largest message accepted, sending or receiving |
| `protocol.maxTxMessages` / `maxTxBytes` | 8 / 32 KB | Send queue limits (`QueueFull` beyond) |
| `protocol.maxRxMessages` / `maxRxBytes` | 4 / 32 KB | Messages being reassembled at once, and their memory |
| `protocol.sendTimeoutMs` | 2000 | Default deadline for a whole message (`SendOptions::timeoutMs` overrides it) |
| `protocol.ackTimeoutMs` | 100 | Reliable mode: wait before probing the receiver again |
| `protocol.rxTimeoutMs` | 1000 | A partial incoming message is dropped after this long without progress |
| `protocol.networkId` | 0 | Separates NowTP deployments on one channel (not a security feature) |
| `initWifi`, `channel`, `disablePowerSave`, `maxTxPower` | true, 1, true, 0 | Radio setup (see above) |
| `enableDiscovery`, `discovery`, `negotiateFrameSize` | false, –, true | Discovery (see above) |
| `autoAddPeers`, `defaultMaxFrameSize` | true, 250 | Peer registration and default frame size |
| `runTask`, `taskStackSize`, `taskPriority`, `taskCore` | true, 4096, 5, any | NowTP task settings |
| `eventBufferSize` | 8 KB | Buffer between the Wi-Fi driver and NowTP |

### Status codes

`send()` returns a `Status` right away. The completion callback receives the final one:

| Status | Meaning |
|---|---|
| `Ok` | Accepted / delivered |
| `QueueFull` | The send queue is full. Retry later |
| `TooLarge` | Larger than `maxMessageSize` |
| `InvalidArgument` | For example, `reliable` to broadcast |
| `InvalidState` | Not started, or `sendAndWait()` called where it would deadlock |
| `SendFailed` | The radio could not deliver a frame (peer unreachable) |
| `Timeout` | No confirmation before the deadline |
| `Rejected` | The receiver has no handler on that port, or the message is too large for it |
| `Superseded` | Replaced by a newer `latestOnly` message |
| `Cancelled` | `end()` was called |
| `LinkError`, `NoMemory` | Driver or allocation failures |

### Troubleshooting

- **One board hears the other, but not the reverse.** Some boards can't sustain full-power transmission from their supply. Their frames then never arrive, while they still receive normally. Try `config.maxTxPower = 34` (8.5 dBm) on the board that can't be heard.
- **Nothing arrives at all.** Check that both nodes are on the same channel with `radioInfo().channel`. A node connected to an AP follows the AP's channel.
- **Large unicast frames are lost.** One side probably runs ESP-NOW v1 (ESP-IDF < 5.4 or Arduino-ESP32 2.x). Use discovery, which negotiates the frame size, or leave the frame size at 250.

## Compatibility

- **Arduino-ESP32:** 2.x (ESP-IDF 4.4) and 3.x (ESP-IDF 5.x).
- **ESP-IDF:** 4.4 and later.
- **Chips:** any ESP32-family chip with Wi-Fi.

CI compiles the examples and test firmware for ESP32 and ESP32-C3 against ESP-IDF 4.4, 5.1, 5.4, 5.5 and the latest release, and against Arduino-ESP32 2.0.17 and 3.3.7. The core library is C++11.

Tested on hardware with an ESP32-S3 and an ESP32:
- ESP-IDF 6.1 on both boards
- Arduino-ESP32 3.3 on the S3 talking to Arduino-ESP32 2.0.17 on the ESP32 (ESP-NOW v2 ↔ v1)

## How it works

The wire format and the reliability scheme are described in [docs/PROTOCOL.md](docs/PROTOCOL.md). The code is in two layers:

- `nowtp::Engine` ([src/nowtp/engine.h](src/nowtp/engine.h)) is the protocol engine. It has no platform dependencies and does no I/O or timekeeping of its own. It runs on any `nowtp::Link`, an interface with two methods: send a frame, and report the largest frame size.
- `nowtp::Discovery` ([src/nowtp/discovery.h](src/nowtp/discovery.h)) is the discovery service. It is also platform-independent and runs on top of an `Engine`.
- `nowtp::EspNowTransport` ([src/nowtp/espnow_transport.h](src/nowtp/espnow_transport.h)) runs both on the ESP-NOW driver. It handles radio setup, the callbacks, locking, the NowTP task and peers.

## Development

The protocol tests run on your computer, with AddressSanitizer and UndefinedBehaviorSanitizer:

```sh
cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure
```

The tests use a simulated network with configurable loss in three places: on air, in the receiver's queue, and in lost MAC acks. They cover fragmentation edge cases, loss recovery, duplicate suppression, latest-only ordering, malformed and random frames, and memory limits.

[test/hardware](test/hardware) is an ESP-IDF test firmware that needs only one board. It runs the engine on the chip and checks the ESP-NOW adapter: start and stop, frame counts, throughput, failure reporting, queue limits, cancellation, poll mode, and leaks across restarts. It prints `PASS`/`FAIL` lines on the serial console:

```sh
cd test/hardware && idf.py set-target esp32s3 && idf.py -p PORT flash monitor
```

[test/pair](test/pair) is the two-board integration test. Flash the same firmware on two boards. They find each other through discovery, and the board with the lower MAC drives the tests. Each board goes through three radio setups:
- nothing initialized
- a station started by the application
- one board as a soft-AP, with the other connected to it as a station

In each setup the boards check echo in both directions, reliable and unreliable throughput, latest-only ordering, rejection and goodbyes.

## Roadmap

- Streaming API for very large transfers (e.g. OTA-sized payloads)
- Following channel changes after `begin()` (e.g. a station that roams), and discovery across channels
- Optional add-ons: authenticated pairing, persistent peers

## License

MIT. See [LICENSE](LICENSE).
