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
  - `0x8` authenticated: the payload ends with an authentication trailer (see [Security](#security-port-253)). On an ack, the ack ends with a tag.
- **network ID**: frames whose ID differs from the receiver's configured ID are ignored. This keeps separate deployments on the same channel apart. It is not a security feature.
- **port**: selects the receive handler, like a UDP port. Ports 240–255 are reserved for NowTP's own services: 251 streams, 252 time synchronization, 253 security, 254 diagnostics, 255 discovery.
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
| 6+N+M | 1 | Extension flags: `0x1` anchor (the sender's channel is fixed), `0x2` time reference |
| 7+N+M | 1 | The sender's Wi-Fi channel |
| 8+N+M | 1 | Moving notices only: the channel the sender moves to |

The last three fields arrived with NowTP 0.5. Older nodes neither send nor read them. A receiver treats a missing extension as channel 0 (unknown) with no flags.

- **Announcing.** Nodes announce periodically, with ±10% jitter so nodes that booted together don't stay in step.
- **Answering queries.** A node that receives a query answers with its own announcement after a random delay. Any announcement it sends in the meantime counts as the answer.
- **Goodbye.** A goodbye removes the sender from the receiver's peer list right away.
- **Moving.** Flag `0x8` (always with goodbye, `0x4`) announces that the sender is about to switch to the channel in the extension. It's sent three times, and not latest-only, since broadcast has no retries. Older nodes see a plain goodbye. Nodes that follow (see below) switch to that channel.
- **Anchors and channel following.** An anchor is a node whose channel an access point fixes (its station is connected, or it runs a soft-AP), or one configured as an anchor. A node free to change its channel follows moving notices. Once anchors are known, it only follows anchors. When every anchor it knew has gone silent, it searches: on each channel in turn it sends a query and listens for a dwell time (250 ms by default), and it stops on the first channel where an anchor answers. If none does, it returns to its original channel and tries again later. A node that hears an anchor state a channel other than its own (adjacent-channel leakage) moves to the stated channel.
- **Frame size.** A sender uses `min(local maximum, peer's advertised maximum)` as the frame size for unicast to that peer.

## Diagnostics (port 254)

Diagnostics messages are single-frame unicast messages on port 254, except probe bursts, which are broadcast. The first payload byte is the type, and bytes 1–2 are a session id chosen by the initiator. In requests, byte 3 is the attempt number. In replies, byte 3 is the replying node's transmit power, in units of 0.25 dBm (signed).

| Type | Name | Payload after type and session | Notes |
|---|---|---|---|
| 1 | Burst | step, sequence, padding | Probe frame (default 200-byte payload), broadcast at the step's rate and power |
| 2 | Collect | attempt | "Report what you counted for this session" |
| 3 | Report | power, n, n × (received, average RSSI) | |
| 4 | BurstRequest | attempt, frames per step, n, n × (rate, power) | Power 0 means "keep yours". Steps the responder can't send (e.g. LR without Long Range) are skipped, never substituted. |
| 5 | BurstAck | power, power limit, flags | Flag `0x1`: busy with its own measurement. The initiator backs off and retries. |
| 6 | Apply | attempt, rate, power | Asks the peer to use `rate` toward us, and `power`. Refused if remote tuning is off. |
| 7 | ApplyAck | power, flags | Flag `0x1`: busy |
| 8 | Ping | attempt | |
| 9 | Pong | power, power limit | |
| 10 | BurstDone | power | End of the requested bursts |

- **Power fallback on retries.** Attempt *k* > 0 of a request is sent with the sender's power capped at {15, 11, 8, 5} dBm, the *k*-th value. The reply to it is capped the same way. A node whose supply sags at full power can therefore still be reached, and can still answer.
- **Rate for control traffic.** Control frames always go at 1 Mbps.
- **Other payloads.** Payloads with type 0 are ignored. They serve as pings acknowledged only at the MAC level (for the power fallback and deep discovery's transmit check), and as the reliable verification message.

## Security (port 253)

Security is optional. All nodes of an installation share one installation key `K` (16–32 bytes). Every key below is derived as `HMAC-SHA256(K, label)`:
- the message key `Km`, with label `"NowTP message"`,
- the ack key `Ka`, with `"NowTP ack"`,
- the challenge key `Kc`, with `"NowTP challenge"`.

### Authenticated messages

A node with a key authenticates every message it sends, except those on port 253. It sets flag `0x8` and appends a 17-byte trailer to the payload, before fragmentation and the CRC:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | Epoch: random, chosen at boot (when the security service starts) |
| 4 | 4 | Sequence number, incremented for each authenticated message the node sends |
| 8 | 1 | Destination kind: `0` unicast, `1` broadcast |
| 9 | 8 | Tag: the first 8 bytes of `HMAC-SHA256(Km, network id ‖ src MAC ‖ dst MAC ‖ port ‖ flags ‖ trailer[0..9] ‖ payload)` |

- **What the tag covers.** `flags` are the message's reliable and latest-only bits. `dst MAC` is the receiver's own MAC for unicast, and `FF:FF:FF:FF:FF:FF` for broadcast, so a unicast message cannot be redirected to another node.
- **Receiver checks.** The receiver checks the tag, then the sequence number against a 64-entry sliding window per sender and epoch. Repeats and numbers older than the window are rejected.
- **Unknown epochs.** A message from an epoch the receiver hasn't verified is held back. The receiver drops it without an ack, and challenges the sender:
  - **Challenge** (type 1): `type ‖ nonce (8)`.
  - **Response** (type 2): `type ‖ nonce (8) ‖ epoch (4) ‖ current sequence (4) ‖ tag (16)`. The tag is the first 16 bytes of `HMAC(Kc, responder MAC ‖ challenger MAC ‖ nonce ‖ epoch ‖ sequence)`.

  A valid response makes that epoch the sender's verified epoch. The window then accepts, once each, numbers up to 64 below the reported sequence. A reliable sender's next probe gets through. A message whose epoch differs from one verified less than a second ago is a replay and is rejected outright. Responses are rate-limited to 20 per second.
- **Unauthenticated messages.** By default, a node with a key drops every message that is not authenticated, except on port 253. A reliable sender is told rejected.
- **Acks.** An ack for an authenticated message carries flag `0x8` and ends with an 8-byte tag: `HMAC(Ka, acker MAC ‖ ackee MAC ‖ ack frame)`. The sender ignores untagged or wrongly tagged complete and missing acks. An untagged rejected ack means the receiver could not verify the message (another key, or none), and the send fails with `AuthFailed`.

Content is not encrypted. Any key holder can impersonate any other: the key proves membership of the installation, not the identity of a node.

### Pairing

A member (a node with the key) opens a pairing window, and a joiner looks for one. All values are binary. `‖` is concatenation.

| Type | Name | Direction | Payload after the type byte |
|---|---|---|---|
| 3 | PairRequest | joiner → broadcast | joiner X25519 public key (32) ‖ joiner nonce (16) |
| 4 | PairOffer | member → joiner | joiner nonce (16) ‖ member public key (32) ‖ member nonce (16) ‖ tag("offer") (16) |
| 5 | PairProof | joiner → member | tag("proof") (16) |
| 6 | PairKey | member → joiner | sealed key (33) ‖ tag("key" ‖ sealed key) (16) |
| 7 | PairDone | joiner → member | tag("done") (16) |
| 8 | PairRefused | joiner → member | (none): the offer's tag did not verify |

The keys are derived as follows:
1. `T = SHA-256("NowTP pairing v1" ‖ joiner MAC ‖ member MAC ‖ joiner public key ‖ joiner nonce ‖ member public key ‖ member nonce)`.
2. `salt = SHA-256("NowTP pairing code" ‖ pairing code)`. The pairing code may be empty.
3. `HKDF-SHA256(salt, X25519 shared secret, info = T)` yields 64 bytes: the confirmation key `Kf`, then the encryption key `Ke`.
4. `tag(x)` is the first 16 bytes of `HMAC(Kf, x ‖ T)`, with the extra bytes after `T` for the key message.

The sealed key is `key length (1) ‖ key padded to 32` XORed with `HMAC(Ke, 0x01) ‖ HMAC(Ke, 0x02)[0]`.

The joiner proves it derived the same keys before the member sends anything secret. Messages are resent every 500 ms until the next step arrives.

- **Strength.** Without a code, anyone in range while a window is open can join, as with "just works" pairing. An eavesdropper learns nothing, because of the key exchange.
- **Short codes.** A short code keeps nodes from joining the wrong installation. It does not stop an active attacker who answers in the window: the offer tag lets the attacker test codes offline. Only a long random code resists that.

## Time synchronization (port 252)

Unicast, unreliable, single-frame messages. Times are microseconds on the sender's clock, 64-bit little-endian.

| Type | Name | Payload after the type byte |
|---|---|---|
| 1 | Request | round (1) ‖ index (1) ‖ t1 |
| 2 | Response | round ‖ index ‖ t1 (echoed) ‖ t2 ‖ t3 |

- **Timestamps.** `t2` is the time the request's frame arrived (taken in the radio driver's receive callback), and `t3` is the time the response was queued. A responder that is itself synchronized answers in network time, so nodes can synchronize through it.
- **Rounds.** A round is 8 exchanges, 15 ms apart. With `t4` the arrival time of the response, the client computes `rtt = (t4 − t1) − (t3 − t2)` and `offset = ((t2 − t1) + (t3 − t4)) / 2`, and keeps the exchange with the smallest `rtt`.
- **Estimate.** A least-squares fit over the last 8 rounds gives the offset and the drift. Rounds run every second at first, then every 5 s. A round far from the prediction is discarded, unless three in a row are: then the reference's clock has jumped.
- **Reference.** The reference is the node announcing the time-reference flag in discovery (the lowest MAC if several do), unless the application chose one.

## Streams (port 251)

All messages are reliable unicast.

| Type | Name | Payload after the type byte |
|---|---|---|
| 1 | Offer | stream id (4) ‖ size (4) ‖ chunk size (4) ‖ topic (1) ‖ window (1) ‖ header (≤ 200) |
| 2 | Accept | stream id |
| 3 | Reject | stream id ‖ reason (1): 0 refused, 1 too large, 2 busy |
| 4 | Data | stream id ‖ offset (4) ‖ chunk |
| 5 | End | stream id ‖ CRC-32 of the whole stream (4) |
| 6 | Result | stream id ‖ status (1): 0 ok, 1 checksum mismatch, 2 incomplete |
| 7 | Abort | stream id |

- **Flow.** The sender offers a stream, waits for accept, then sends chunks.
- **Window.** It never sends a chunk more than `window` chunks past the oldest unacknowledged one. The receiver therefore never holds more than `window − 1` chunks that arrived early. It writes chunks strictly in order and ignores duplicates.
- **Retries.** A chunk, offer or end whose reliable message fails is retried, up to 5 attempts.
- **Ending.** After the last chunk is acknowledged, the sender sends End, and the receiver answers with the result.
- **Silence.** A receiver gives up after 30 s without data. A Data message for an unknown stream is answered with Abort.

## Limits

- **Message size.** Each side sets its own maximum message size. Receivers check the claimed size before allocating memory.
- **Reassembly.** The number of messages being reassembled at once is bounded, and so is their total memory. When either limit is reached, the least recently active message is evicted.
