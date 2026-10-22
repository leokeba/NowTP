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
  - On an ack, `0x1` means credit instead: the ack carries a credit byte (see below).
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

`common header | status (1) | [missing indices…] | [credit (1)] | [tag (8)]`

Port and message ID repeat the values of the message being acknowledged. Status values:

- `0` complete: the whole message was received, verified and delivered (or was already delivered earlier).
- `1` missing: the payload lists missing fragment indices, 2 bytes each, in increasing order. The list may be cut short to fit one frame.
- `2` rejected: the receiver will never accept this message, because it has no handler on the port or the message is too large.
- `3` busy: the receiver has no room to reassemble this message right now. The sender stops sending it, waits one to two and a half ack timeouts (spread by message ID), then probes (step 5 below). Receivers send it for the first fragment and for ack-requests of a message they refuse, and for a complete message (single-frame or reassembled) that the receiving application refused. Senders that predate this status ignore it and simply probe after their ack timeout.

**Credit.** A complete, missing or busy ack with flag `0x1` ends with a credit byte, after any missing indices and before any tag: the reassembly room the receiver has left for the next message from the ack's recipient, in units of 256 bytes, with 255 meaning that much or more.
- **Receiver.** It counts the room it would grant now. A slot must be free, both overall and among those this sender may hold, and the bytes are what its reassembly budget has left. Partial messages idle long enough to be evicted count as free. An ack for a message the application refused carries 0.
- **Sender.** It notes the room, less the needs of the multi-frame messages it starts afterwards (`count × S` plus the bitmap, `⌈count / 8⌉` bytes). A new multi-frame message that needs more than the room waits, and so do the destination's messages behind it, until an ack brings fresh credit, or for three ack timeouts after the last word. A message already started, or refused (busy), continues and probes as before, and its acks bring fresh credit. Single-frame messages need no reassembly, and never wait on their own.
- **Compatibility.** Senders that predate credit ignore the flag on acks. They read missing indices two bytes at a time while two bytes remain, so the single trailing byte never reads as an index. The tag covers the byte like the rest of the frame. Receivers that predate credit send no credit, and their senders never wait.

## Sending

- **Fragmentation.** Let `F` be the largest frame for the destination: 250 bytes by default, up to 1470 bytes with ESP-NOW v2.
  - A message of up to `F − 5` bytes is sent as one single frame.
  - Anything larger is sent as fragments with chunk size `S = F − 9`.
- **Pacing.** A sender has at most one frame outstanding with the radio. It sends the next frame only after the radio's send-complete callback, or after a short timeout if the callback never arrives. Ack frames go before data frames.
- **Order.** Destinations take turns, one frame each. To any one destination, messages go out in the order they were queued. A reliable message that is waiting for its ack does not hold up the messages behind it.
- **Link failures.** For unicast, the radio reports whether the peer's MAC acknowledged the frame. A failed frame is retried a few times, and the message fails after that. Since the radio takes about 100 ms to report a failure, a destination whose frames fail waits a backoff (50 ms, doubling up to 800 ms, reset by a delivered frame) while other destinations have frames to send.

## Reliable delivery (unicast only)

1. The sender sends every fragment, and sets ack-request on the last frame it sends.
2. On a frame with ack-request, the receiver answers:
   - complete, if it has the whole message,
   - missing, listing the gaps, or
   - rejected.
3. When a message completes, the receiver also sends complete without being asked. It does so only once the application has taken the message. An application that can't take it (on a short heap, for instance) refuses it, and the receiver answers busy instead and forgets the message, so the sender's retry arrives as a new delivery.
4. On missing, the sender resends the listed fragments and sets ack-request on the last of them.
5. If no ack arrives within the ack timeout, the sender resends the last fragment with ack-request as a probe. This also works if the receiver has dropped its partial state: it rebuilds the state from the probe and reports the rest as missing.
   - On busy, the sender probes the same way after its backoff.
6. The message fails with `Timeout` when its overall deadline passes.

ESP-NOW already acknowledges and retries each unicast frame in hardware. Reliable mode covers the remaining losses: frames dropped in the receiver's queues, reassembly refused for memory, and acks lost on the way back.

**Reassembly admission.** A receiver reassembles a bounded number of messages, and bytes, at once, and only a few from any one sender. When a new message doesn't fit, the receiver evicts a partial message that has had no fragment for three ack timeouts (the most idle first), since a live sender would have probed by then. If none is that idle, the newcomer is refused (busy), and messages in progress are never evicted. Evicting the least recently active message instead starves everyone once more senders interleave than there are slots.

## Duplicates and latest-only

- **Duplicates.** Receivers remember recently completed messages (sender and message ID) for a few seconds and ignore repeats. If a repeat carries ack-request, the receiver answers complete.
  - **Per sender.** Each sender gets a window over its latest message IDs: four blocks of 32 IDs, ending with the block of the newest ID delivered (97 to 128 IDs). A repeat is recognized however many other senders' messages arrived in between. An ID newer than the window moves it forward. An ID older than the window is treated as new, unless the receiver's short list of the last completed messages (shared by all senders) still holds it.
  - **Expiry.** A block forgets its IDs a few seconds after its last delivery, and a sender's whole window after its last delivery. So a sender that restarts with IDs inside its old window loses messages only for those few seconds, as before.
  - **Sender IDs.** A sender numbers all its messages in one sequence, broadcast and every destination alike. A receiver therefore sees gaps, and a window covers 128 IDs of the sender's traffic in total, not only those sent to it. That is two seconds (the default deadline) at 64 messages per second.
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
| 6+N+M | 1 | Extension flags: `0x1` anchor (the sender's channel is fixed), `0x2` time reference (the sender's network time is the network time), `0x4` message limit follows, `0x8` time candidate (offers to become the reference), `0x10` synchronized to the network time |
| 7+N+M | 1 | The sender's Wi-Fi channel |
| 8+N+M | 1 | Moving notices only: the channel the sender moves to |
| next | 4 | With flag `0x4`: the largest message the sender accepts (its maximum message size), little-endian |

The extension flags, the channel and the move-to channel arrived with NowTP 0.5. Older nodes neither send nor read them. A receiver treats a missing extension as channel 0 (unknown) with no flags. The message limit came after 0.5, which reads no further than the move-to channel and so ignores it. Without flag `0x4`, a peer's limit is unknown. Flags `0x8` and `0x10` came later still; older nodes ignore them, and take any node with `0x2` as a reference.

- **Announcing.** Nodes announce periodically, with ±10% jitter so nodes that booted together don't stay in step.
- **Answering queries.** A node that receives a query answers with its own announcement after a random delay. Any announcement it sends in the meantime counts as the answer.
- **Goodbye.** A goodbye removes the sender from the receiver's peer list right away.
- **Losing peers.** A peer is dropped after a timeout (7 s by default) in which it wasn't heard. Its announcements count, and so does any message or ack accepted from it, since announcements are unacknowledged broadcasts that a busy channel or a weak link loses more easily than unicast. For a peer whose announcements are authenticated, only authenticated messages and acks count. Only announcements add a peer or change what is known about it.
- **Moving.** Flag `0x8` (always with goodbye, `0x4`) announces that the sender is about to switch to the channel in the extension. It's sent three times, and not latest-only, since broadcast has no retries. Older nodes see a plain goodbye. Nodes that follow (see below) switch to that channel.
- **Anchors and channel following.** An anchor is a node whose channel an access point fixes (its station is connected, or it runs a soft-AP), or one configured as an anchor. A node free to change its channel follows moving notices. Once anchors are known, it only follows anchors. When every anchor it knew has gone silent, it searches: on each channel in turn it sends a query and listens for a dwell time (250 ms by default), and it stops on the first channel where an anchor answers. If none does, it returns to its original channel and tries again later. A node that hears an anchor state a channel other than its own (adjacent-channel leakage) moves to the stated channel.
- **Frame size.** A sender uses `min(local maximum, peer's advertised maximum)` as the frame size for unicast to that peer.
- **Message limit.** A sender refuses, at once, to send a peer a message larger than the limit it announced, since the peer would reject it. The limit is forgotten when the peer is lost. Like the rest of discovery, it is only as trustworthy as the announcements: without a key, a forged announcement could lower it.

## Diagnostics (port 254)

Diagnostics messages are single-frame unicast messages on port 254, except probe bursts, which are broadcast. The first payload byte is the type, and bytes 1–2 are a session id chosen by the initiator. In requests, byte 3 is the attempt number. In replies, byte 3 is the replying node's transmit power, in units of 0.25 dBm (signed).

| Type | Name | Payload after type and session | Notes |
|---|---|---|---|
| 1 | Burst | step, sequence, padding | Probe frame (default 200-byte payload), broadcast at the step's rate and power |
| 2 | Collect | attempt | "Report what you counted for this session" |
| 3 | Report | power, n, n × (received, average RSSI) | |
| 4 | BurstRequest | attempt, frames per step, n, n × (rate, power) | Power 0 means "keep yours". Steps the responder can't send (e.g. LR without Long Range) are skipped, never substituted. Ignored if unauthenticated while the responder has a key. |
| 5 | BurstAck | power, power limit, flags | Flag `0x1`: busy with its own measurement. The initiator backs off and retries. |
| 6 | Apply | attempt, rate, power | Asks the peer to use `rate` toward us, and `power`. Ignored (no reply) if remote tuning is off, which is the default, or if unauthenticated while the responder has a key. |
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

- **What the tag covers.** `flags` are the message's reliable and latest-only bits. `dst MAC` is the receiver's own MAC for unicast, and `FF:FF:FF:FF:FF:FF` for broadcast, so a unicast message cannot be redirected to another node. The message ID is not covered: a recording sent again under another ID still carries its epoch and sequence number, and the checks below drop it.
- **Receiver checks.** The receiver checks the tag, then the sequence number against a 64-entry sliding window per sender and epoch. Repeats and numbers older than the window are dropped silently. A refusal could reach the real sender, which may have a message with that ID in flight.
  - **Refused by the application.** When the application refuses a verified reliable message (answered busy, see above), its sequence number is released, so the sender's retry verifies. The window doesn't move, and the numbers of delivered messages stay taken. Until the window passes that number, a recording of the refused message could still be delivered once, even after its sender gave up. That is no worse than a late retransmission. An unreliable message keeps its number, since no retry follows.
- **Unknown epochs.** A message from an epoch the receiver hasn't verified is held back. The receiver drops it without an ack, and challenges the sender:
  - **Challenge** (type 1): `type ‖ nonce (8)`.
  - **Response** (type 2): `type ‖ nonce (8) ‖ epoch (4) ‖ current sequence (4) ‖ tag (16) ‖ capabilities (1) ‖ capabilities tag (16)`.
    - The tag is the first 16 bytes of `HMAC(Kc, responder MAC ‖ challenger MAC ‖ nonce ‖ epoch ‖ sequence)`.
    - The capabilities tag is the first 16 bytes of `HMAC(Kc, "NowTP caps" ‖ responder MAC ‖ challenger MAC ‖ the 33 bytes from the nonce to the capabilities)`.
    - Capability bits: `0x1` reseals (below), `0x2` checks bound acks (below).
    - The two capability fields are optional. NowTP 0.5 and earlier neither send nor read them, so a response with them still verifies there.

  A valid response makes that epoch the sender's verified epoch:
  - **A new epoch** (or the first one heard from this sender):
    - From a sender that reseals, the window then accepts only numbers above the reported sequence. Anything at or below it may be a recording, for example of messages the receiver accepted before it rebooted.
    - From a sender without that capability, the window accepts, once each, numbers up to 64 below the reported sequence. This is the 0.5 behavior, kept for compatibility.
  - **The epoch already verified** (a challenge forced by a message from another epoch): the window carries on unchanged. It is never reopened.

  **Resealing.** After answering a challenge, a sender with capability `0x1` seals every authenticated message it has queued for the challenger again, with new sequence numbers above the one it reported, and recomputes their CRC. Its reliable retransmissions then get through. A message whose epoch differs from one verified less than a second ago is a replay and is dropped. Responses are rate-limited to 20 per second.
- **Unauthenticated messages.** By default, a node with a key drops every message that is not authenticated, except on port 253. A reliable sender is told rejected.
- **Acks.** An ack for an authenticated message carries flag `0x8` and ends with an 8-byte tag.
  - **Unbound tag:** `HMAC(Ka, acker MAC ‖ ackee MAC ‖ ack frame)`.
  - **Bound tag:** `HMAC(Ka, acker MAC ‖ ackee MAC ‖ ack frame ‖ epoch and sequence of the acknowledged message (8))`, the first 8 bytes of the message's trailer. It can't be replayed to confirm a later message that reuses the message ID.
  - **Who binds.** A receiver binds its acks when it knows the message (complete, also for duplicates) and the sender announced capability `0x2`. Otherwise it uses the unbound tag. A duplicate known only from its sender's window (its epoch and sequence no longer remembered) gets an unbound complete, which such a sender ignores: it times out rather than take a reused ID as delivered.
  - **What senders accept.** A sender accepts a bound tag for the message's current trailer, or for its trailer before the last reseal. It accepts an unbound tag too, except for a complete ack from a receiver that announced `0x2` itself.
  - **Ignored and refused acks.** The sender ignores untagged or wrongly tagged complete, missing and busy acks. An untagged rejected ack means the receiver could not verify the message (another key, or none), and the send fails with `AuthFailed`.
- **Compatibility.** Nodes running 0.5 and later versions interoperate with a shared key. Each side uses the stricter rules only with peers whose authenticated response announced them.
- **Before reassembly.** A multi-frame message can only be verified once complete. A node with a key therefore refuses, at the first fragment, a multi-frame message without flag `0x8` when authentication is required. Senders whose epoch it hasn't verified share a single reassembly slot.

### What security does not cover

- **No encryption.** A key provides integrity and freshness only. Payloads travel in clear, keyed or not, so anyone in range can read every message, including secrets an application sends (passwords, tokens). Encrypt those in the application, or use ESP-NOW's own per-peer encryption (unicast only). Any key holder can impersonate any other: the key proves membership of the installation, not the identity of a node.
- **Discovery frames.** Announcements, goodbyes and moving notices are ordinary messages on port 255, and are only as trustworthy as the rules applied to them:
  - **Without a key**, anyone in range can send them from any MAC address, or replay recorded ones:
    - A goodbye makes receivers report that peer lost at once, and forget its message limit. Applications that react to the loss (failing pending calls, dropping subscriptions) do so too.
    - An announcement can:
      - add a fake peer, which takes one of the peer table's slots. When the table is full, a peer gives way only after 1.5 announcement intervals without being heard, so peers that keep announcing keep their place.
      - change what is known about a real peer: name, metadata, frame size, message limit, channel and flags.
      - keep a peer that has gone silent from being reported lost.
    - A moving notice, or an announcement from an anchor stating another channel, moves every node free to follow to that channel.
    - An announcement with the time reference flag draws time sync to the sender, which can then set its followers' network time.
  - **With a key and authentication required** (the default), nodes drop unauthenticated discovery frames before discovery sees them, and the sequence window drops recordings. Only a key holder can do any of the above.
  - **With a key and authentication not required**, unauthenticated frames reach discovery, which acts on them as it would without a key, even for peers whose announcements are authenticated. An unauthenticated goodbye removes such a peer. An unauthenticated announcement from its address replaces what is known about it, and marks it unauthenticated. Discovery makes one exception: in a full table, an authenticated peer gives way only to another authenticated one.
- **Capability downgrade.** The capabilities tag uses `Kc`, so without the key nobody can set capability bits, but an attacker can remove the extension. To do so, it must keep the genuine response from reaching the challenger (selective jamming) and inject a copy cut back to 33 bytes, whose first tag still verifies. For that epoch, the challenger then treats the responder like a 0.5 node:
  - **Replays.** It accepts, once each, sequence numbers up to 64 below the one reported. Recordings of the responder's last 64 messages of that epoch are then delivered again, if the challenger no longer remembered them (it rebooted, or it had forgotten the sender: see `maxPeers`).
  - **Acks.** It accepts unbound complete acks from the responder. A recorded unbound complete can then confirm a later message that reuses the same 16-bit message ID, although that message was not delivered. Receivers send unbound completes, for example, for duplicates they know only from the sender's window.

  The downgrade cannot forge, alter or reveal messages. It affects only the challenger whose response was stripped, in that epoch. It cannot lower the capabilities of an epoch already verified, since proving the same epoch again only adds capabilities. It is possible only when a challenger verifies a new epoch: after either side reboots, or after the challenger has forgotten the sender.

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
| 1 | Request | round (1) ‖ index (1) ‖ t1 ‖ calibration interval (1, seconds; 0: none) ‖ zeros (25) |
| 2 | Response | round ‖ index ‖ t1 (echoed) ‖ t2 ‖ t3 ‖ previous round (1) ‖ previous index (1) ‖ previous send time |
| 3 | Calibration | round ‖ exchanges used (1) ‖ difference (4, signed µs) ‖ zero (1) |

- **Timestamps.** `t1` is the time the request was queued, `t2` the time its frame arrived (taken in the radio driver's receive callback), `t3` the time the response was queued, and `t4` the time it arrived. A responder that is itself synchronized answers in network time, so nodes can synchronize through it.
- **Send times.** Queue times include waiting in the driver and for the channel, which differs between the two directions. So each side also notes when the radio reports its frame sent (the driver's send callback, after the receiver's MAC ack): the requester for its own requests, the responder for its responses. A response carries the send time of the responder's previous response to the same requester, identified by round and index (index `0xFF`: none known), so the requester completes that exchange one response later. With `s1` and `s3` the send times of the request and the response, `offset = ((t2 − s1) + (s3 − t4)) / 2`. Air time and queueing drop out; what remains is the driver's reporting latency on each side, which cancels out when both sides run the same chip and code.
- **Compatibility.** Requests are padded to the response's length (37 bytes). Responders accept any request of 11 bytes or more, and requesters any response of 27 bytes or more: without send times, a round uses queue times.
- **Rounds.** A round is 8 exchanges, 15 ms apart. With send times from the responder, the round's offset is the median over exchanges stamped at both ends; with fewer than three such exchanges the round is skipped and retried a second later, since queue-time rounds carry a different bias. Without send times, the requester computes `rtt = (t4 − t1) − (t3 − t2)` and `offset = ((t2 − t1) + (t3 − t4)) / 2`, and keeps the exchange with the smallest `rtt`.
- **Calibration.** What remains of the drivers' delays after send-time stamps differs between requests and responses (about 20 µs on ESP32), so a follower's own rounds put a bias `b` into its estimate. A follower that sets a calibration interval asks the reference to measure it: while acting, the reference runs rounds towards each follower that asked, at that interval (at least 5 s, one round a second at most, only for followers heard in the last 30 s). The follower answers in its network time, and the reference sends a Calibration message with the follower's network time minus its own: `2b − c`, where `c` is the follower's current correction, since the measurement runs in the other direction. The follower takes `b = (difference + c) / 2` from each report and, once it holds three, sets `c` to their median (of the last nine). Later changes move `c` by a quarter of the difference, at most 10 µs per report. Its network time is its estimate minus `c`. A node that starts acting folds `c` into the estimate it serves. Older references ignore the interval byte and never report, and older followers send 0.
- **Estimate.** A least-squares fit over the last 16 rounds gives the offset and the drift. The first 8 rounds run every second, so the first drift fit spans 7 s, then rounds run every 5 s. A round whose queue-time round trip exceeds twice the shortest recent one plus 1.5 ms was queued behind other traffic, and is discarded; that threshold grows by an eighth with each one discarded, so a lasting change is accepted in the end. Discarded rounds are retried after a second. A round far from the prediction is discarded too, unless three in a row are: then the reference's clock has jumped.
- **Reference.** The application may choose the reference. Otherwise a node follows a peer announcing flag `0x2`: one without `0x8` (configured as the reference) before an acting candidate, then the lowest MAC. Rounds stop while no reference is announced; the estimate is kept.
- **Candidates.** A node with flag `0x8` takes over when no reference has been announced for the takeover delay (5 s by default; measured from its start, or from the moment the last reference disappeared). Candidates take turns: a candidate waits one takeover delay for each candidate ahead of it, synchronized ones (`0x10`) first, then lower MACs. An acting candidate that hears a reference without `0x8`, or an acting candidate with a lower MAC, gives way and follows it.
- **Continuity.** A node that starts acting keeps its estimate, extrapolated with its drift and no longer updated, as its network time. A node that switches references, or stops acting, keeps its estimate too; the first round with the new reference corrects it, after the checks above, so a reference with the same network time causes no step and one with another time base replaces it after three rounds.

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
- **Reassembly.** The number of messages being reassembled at once is bounded, and so is their total memory. When either limit is reached, a new message is refused (busy), unless a partial message idle for three ack timeouts can make room (see [Reassembly admission](#reliable-delivery-unicast-only)).
