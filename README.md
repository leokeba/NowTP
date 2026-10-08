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
- **Bounded memory.** Queue sizes, message size and reassembly memory are all configurable.
- **Callbacks never run in the Wi-Fi driver task.** They run in a NowTP task, or inside `poll()` from your loop.
- **Testable on your computer.** The protocol core has no platform dependencies and is tested on a desktop machine against a simulated lossy radio.

> **Status:** early (0.1). The wire format and API may still change before 1.0.

## Quick start (Arduino)

```cpp
#include <NowTP.h>
#include <WiFi.h>

nowtp::EspNowTransport transport;

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);  // NowTP uses your Wi-Fi setup; it only needs Wi-Fi started

    transport.listen(1, [](const nowtp::Message& m) {
        Serial.printf("got %u bytes on port %u\n", (unsigned)m.len, m.port);
    });
    transport.begin();
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

More sketches are in [examples/arduino](examples/arduino):

- [Broadcast](examples/arduino/Broadcast/Broadcast.ino)
- [ReliableUnicast](examples/arduino/ReliableUnicast/ReliableUnicast.ino)
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

Start Wi-Fi yourself, as in Espressif's ESP-NOW examples, then call `begin()`. See [examples/idf/reliable_echo](examples/idf/reliable_echo).

## Concepts

### Ports

Every message is sent to a port (0–239; ports 240–255 are reserved). `listen(port, handler)` sets that port's handler. Messages for a port with no handler are dropped, and reliable ones are answered with `Rejected`.

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
- **Frame size.** Frames are 250 bytes by default, which every ESP-NOW version understands. If both sides run ESP-NOW v2 (ESP-IDF ≥ 5.4, or Arduino-ESP32 ≥ 3.2), set `PeerOptions::maxFrameSize` up to 1470 for that peer. This cuts the number of frames by about 6×. A v1 receiver silently drops frames larger than 250 bytes.

All boards must be on the same Wi-Fi channel. If a board is connected to an access point, its channel follows the AP's.

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

## Compatibility

- **Arduino-ESP32:** 2.x (ESP-IDF 4.4) and 3.x (ESP-IDF 5.x).
- **ESP-IDF:** 4.4 and later.
- **Chips:** any ESP32-family chip with Wi-Fi.

CI compiles the examples for ESP32 and ESP32-C3 against ESP-IDF 4.4, 5.1, 5.4, 5.5 and the latest release, and against Arduino-ESP32 2.0.17 and 3.3.7. The core library is C++11.

## How it works

The wire format and the reliability scheme are described in [docs/PROTOCOL.md](docs/PROTOCOL.md). The code is in two layers:

- `nowtp::Engine` ([src/nowtp/engine.h](src/nowtp/engine.h)) is the protocol engine. It has no platform dependencies and does no I/O or timekeeping of its own. It runs on any `nowtp::Link`, an interface with two methods: send a frame, and report the largest frame size.
- `nowtp::EspNowTransport` ([src/nowtp/espnow_transport.h](src/nowtp/espnow_transport.h)) runs the engine on the ESP-NOW driver. It handles the callbacks, locking, the NowTP task and peers.

## Development

The protocol tests run on your computer, with AddressSanitizer and UndefinedBehaviorSanitizer:

```sh
cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure
```

The tests use a simulated network with configurable loss in three places: on air, in the receiver's queue, and in lost MAC acks. They cover fragmentation edge cases, loss recovery, duplicate suppression, latest-only ordering, malformed and random frames, and memory limits.

## Roadmap

- Automatic frame-size negotiation between v1 and v2 peers
- Streaming API for very large transfers (e.g. OTA-sized payloads)
- Optional add-ons: discovery/pairing, persistent peers

## License

MIT. See [LICENSE](LICENSE).
