# Fuzz harnesses

libFuzzer harnesses, under ASan and UBSan, for what a radio neighbour controls.

| Harness | Input | Checks |
|---|---|---|
| `fuzz_frames` | two configuration bytes (installation key, authentication required, time role, heap limit, 250/1470-byte frames, remote tuning; reassembly and duplicate limits), then up to 256 operations by four fake peers (three that hear the target, one that doesn't) | sanitizers; the simulator's checks (no frame larger than its destination takes, one frame in flight); with the heap limit on, no operator new of NowTP's past it |

The target is one simulated node (`test/sim.h`) running the engine with discovery, security, time sync, streams, diagnostics and an application port that sometimes refuses a message or takes its buffer. The operations (`Harness::op()` in `fuzz_frames.cpp`):

- raw frames, of any length up to 1470 bytes;
- messages a peer builds on a port the input picks: single or fragmented (any fragment size, some fragments left out, reversed, a bad CRC), reliable, latest-only, ack-requesting, broadcast, and unsealed, sealed with the installation key, sealed with a chosen epoch and sequence number (the replay window), or with a bad tag;
- answers to the target's latest challenge, with a chosen epoch, sequence and capabilities (or a bad tag, or no capabilities);
- acks of the target's latest reliable message, any status, missing-fragment lists, credit byte, bound or unbound tags;
- time sync responses to the target's latest request, with times near the request's or anywhere, and calibration reports;
- discovery announcements with every field chosen (frame size, name, metadata, channel, move, time roles, message limit, device id);
- replays of recent frames, unchanged or with a byte flipped, from the same or another peer;
- "reflections": the target's own latest frame on a port, with a few bytes changed, sent back by a peer (requests become answers: stream offers, pairing, diagnostics);
- the target's own actions: messages (reliable, latest-only, broadcast, with a deadline), streams, a pairing window or a pairing attempt (the peers' operations go on while it waits), discovery queries and channel moves, a radio that refuses frames for a while, a peer rebooting;
- time passing.

The peers seal and tag as `Security` does, with the key the harness holds, so authenticated traffic gets past the tag checks into the replay window, the ack binding and the services behind it. What isn't covered: a pairing that succeeds (it needs a joiner or member holding an X25519 key pair; the fuzzer only sends what it can forge), the blocking diagnostics procedures, and the ESP-NOW transport itself (platform code).

`NOWTP_FUZZ_VERBOSE=1` prints, after each input, what it reached: frames and messages in, challenges and verified epochs, replays rejected, peers, time sync rounds, streams.

## Running

clang with libFuzzer is needed (any clang ≥ 14; the official LLVM release tarball works without installing).

```sh
cmake -S . -B ../build-fuzz -DNOWTP_FUZZ=ON -DNOWTP_BUILD_TESTS=OFF \
      -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_CXX_FLAGS=-O1
cmake --build ../build-fuzz -j
python3 test/fuzz/seeds.py ../build-fuzz/seeds      # hand-written scenarios
mkdir -p ../build-fuzz/corpus
../build-fuzz/test/fuzz/fuzz_frames -max_len=4096 -max_total_time=1200 \
      ../build-fuzz/corpus ../build-fuzz/seeds/frames
```

`-fork=N -ignore_crashes=1` runs N workers and keeps going after a crash. A crash leaves `crash-<sha1>` in the current directory (or `-artifact_prefix`); `fuzz_frames crash-<sha1>` replays it. Each crash found becomes a host test in `test/test_main.cpp` with its fix.
