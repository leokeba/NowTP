# NowTP wire protocol (version 1)

NowTP runs on top of ESP-NOW frames. Every frame NowTP sends starts with a NowTP header. All multi-byte fields are little-endian.

## Frame types

### Common header (5 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | Control: `version:2 \| type:2 \| flags:4` (most significant bits first) |
| 1 | 1 | Network ID |
| 2 | 1 | Port |
| 3 | 2 | Message ID |

- **version**: `1`. Receivers drop frames with any other version.
- **type**: `0` = single, `1` = fragment, `2` = ack, `3` = reserved.
- **flags**:
  - `0x1` reliable: the sender expects an ack.
  - `0x2` latest-only: only the newest message per (sender, port) matters.
  - `0x4` ack-request: the receiver must answer with an ack now.
  - `0x8` reserved, must be 0.
- **network ID**: frames whose ID differs from the receiver's configured ID are ignored. This keeps separate deployments on the same channel apart. It is not a security feature.
- **port**: selects the receive handler, like a UDP port. Ports 240–255 are reserved for future protocol use.
- **message ID**: per sender. Each new message increments it, and the first value is random at boot.

### Single (type 0)

`common header | payload`

The whole message fits in one frame. There is no CRC, because the radio frame already has its own checksum.

### Fragment (type 1)

`common header | index (2) | count (2) | chunk`

- `count` is at least 2, and `index` is less than `count`. Receivers drop other values.
- The sender builds a stream: `payload | CRC-32(payload)`, where CRC-32 is the IEEE 802.3 checksum (as in zlib) stored little-endian. It splits the stream into `count` chunks.
- Every chunk except the last has the same length `S`. That length is the fragment size, and the receiver learns it from the first non-last fragment it receives. The last chunk holds 1 to `S` bytes.
- Fragment `i` starts at byte offset `i × S` of the stream. Fragments can therefore arrive in any order, and a receiver can place the last fragment before knowing `S` by holding it until `S` is known.
- The receiver drops the message if:
  - a non-last chunk's length differs from `S`,
  - the last chunk is longer than `S`, or
  - the CRC does not match.

### Ack (type 2)

`common header | status (1) | [missing indices…]`

Port and message ID repeat the values of the message being acknowledged. Status values:

- `0` complete: the whole message was received, verified and delivered (or was already delivered earlier).
- `1` missing: the payload lists missing fragment indices, 2 bytes each, in increasing order. The list may be cut short to fit one frame.
- `2` rejected: the receiver will never accept this message, because it has no handler on the port or the message is too large.

## Sending

- **Fragmentation.** Let `F` be the largest frame for the destination: 250 bytes by default, up to 1470 bytes with ESP-NOW v2.
  - A message of up to `F − 5` bytes is sent as one single frame.
  - Anything larger is sent as fragments with chunk size `S = F − 9`.
- **Pacing.** A sender has at most one frame outstanding with the radio. It sends the next frame only after the radio's send-complete callback, or after a short timeout if the callback never arrives. Ack frames go before data frames.
- **Order.** Messages go out in the order they were queued. A reliable message that is waiting for its ack does not hold up the messages behind it.
- **Link failures.** For unicast, the radio reports whether the peer's MAC acknowledged the frame. A failed frame is retried a few times, and the message fails after that.

## Reliable delivery (unicast only)

1. The sender sends every fragment, and sets ack-request on the last frame it sends.
2. On a frame with ack-request, the receiver answers:
   - complete, if it has the whole message,
   - missing, listing the gaps, or
   - rejected.
3. When a message completes, the receiver also sends complete without being asked.
4. On missing, the sender resends the listed fragments and sets ack-request on the last of them.
5. If no ack arrives within the ack timeout, the sender resends the last fragment with ack-request as a probe. This also works if the receiver has dropped its partial state: it rebuilds the state from the probe and reports the rest as missing.
6. The message fails with `Timeout` when its overall deadline passes.

ESP-NOW already acknowledges and retries each unicast frame in hardware. Reliable mode covers the remaining losses: frames dropped in the receiver's queues, reassembly evicted for memory, and acks lost on the way back.

## Duplicates and latest-only

- **Duplicates.** Receivers remember recently completed messages (sender and message ID) for a few seconds and ignore repeats. If a repeat carries ack-request, the receiver answers complete.
- **Latest-only on the sender.** A new latest-only message cancels queued or partly sent latest-only messages to the same destination and port.
- **Latest-only on the receiver.** A latest-only message from a sender drops any partial older latest-only message on the same port. It also causes late fragments of older messages to be ignored. "Older" means up to 256 message IDs behind; anything further back is treated as a sender that restarted.

## Discovery (port 255)

Discovery messages are ordinary single-frame broadcast messages, unreliable and latest-only, on port 255. The payload layout:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | Type: `1` = hello |
| 1 | 1 | Flags: `0x1` query (please announce yourself), `0x2` reply, `0x4` goodbye |
| 2 | 2 | Largest frame the sender can receive (250 for ESP-NOW v1, 1470 for v2) |
| 4 | 1 | Name length `N` (≤ 32) |
| 5 | N | Name (UTF-8) |
| 5+N | 1 | Metadata length `M` (≤ 160) |
| 6+N | M | Application metadata |

- **Announcing.** Nodes announce periodically, with ±10% jitter so nodes that booted together don't stay in step.
- **Answering queries.** A node that receives a query answers with its own announcement after a random delay. Any announcement it sends in the meantime counts as the answer.
- **Goodbye.** A goodbye removes the sender from the receiver's peer list right away.
- **Frame size.** A sender uses `min(local maximum, peer's advertised maximum)` as the frame size for unicast to that peer.

## Limits

- **Message size.** Each side sets its own maximum message size. Receivers check the claimed size before allocating memory.
- **Reassembly.** The number of messages being reassembled at once is bounded, and so is their total memory. When either limit is reached, the least recently active message is evicted.
