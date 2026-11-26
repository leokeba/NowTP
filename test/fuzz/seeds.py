#!/usr/bin/env python3
"""Writes seed inputs for fuzz_frames (test/fuzz/README.md) into DIR/frames.

Each seed is a short scenario in the harness's input language: two
configuration bytes, then operations (see Harness::op() in fuzz_frames.cpp).
They reach the deeper states quickly: a verified epoch, a reassembled
message, a time reference followed, a stream offered, a pairing window.

usage: seeds.py DIR
"""
import os
import struct
import sys

# Operation codes (Harness::op()).
RAW, MESSAGE, WAIT, CHALLENGE, ACK, TIME, ANNOUNCE, REPLAY, REFLECT, SEND, STREAM, PAIR, REBOOT, BUSY, DISCOVER, \
    JOINER, MEMBER = (0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17)
# Port selectors of MESSAGE.
APP, STREAMS, TIMESYNC, SECURITY, DIAG, DISCOVERY = range(6)
# Mode bits.
KEY, OPTIONAL_AUTH, CANDIDATE, REFERENCE, HEAP_LIMIT, WIDE = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


def u16(v):
    return struct.pack("<H", v)


def u32(v):
    return struct.pack("<I", v)


def wait(ms):
    return bytes([WAIT, 0, ms - 1]) if ms <= 256 else bytes([WAIT, 0, 0x80 | min(ms // 10, 127)])


def message(peer, port, payload, flags=0x01, how=0, extra=b""):
    """how: bit0 explicit id, bits1-2 auth (1 sealed, 2 chosen sequence, 3 bad tag),
    bit3 1470-byte frames, bit4 fragment, bit5 bad CRC, bit6 skip mask, bit7 reverse."""
    out = bytes([MESSAGE, peer, port]) + u16(len(payload)) + payload + bytes([flags, how]) + extra
    if how & 0x10 or len(payload) > 200:
        out += u16(100)  # fragment size
    return out


def seeds():
    s = {}
    body = bytes(range(40))
    # Plain messages, single and fragmented, reliable, then acked duplicates.
    s["plain"] = bytes([0, 0]) + wait(50) + message(0, APP, body) + wait(20) + message(1, APP, bytes(600), how=0x10) + \
        wait(50) + bytes([REPLAY, 0, 0, 0]) + wait(20)
    # A sealed message: challenge, answer, then the retry is delivered.
    s["sealed"] = bytes([KEY, 0]) + wait(50) + message(0, APP, body, how=0x02) + wait(5) + \
        bytes([CHALLENGE, 0, 0, 3]) + wait(5) + message(0, APP, body, how=0x02) + wait(5) + \
        message(0, APP, body, how=0x04, extra=bytes([1])) + wait(5) + message(0, APP, bytes(900), how=0x12) + wait(50)
    # The replay window: numbers behind, ahead, and far ahead.
    s["window"] = bytes([KEY, 0]) + message(1, APP, body, how=0x02) + wait(3) + bytes([CHALLENGE, 1, 0x02]) + u32(100) + \
        bytes([3]) + wait(3) + message(1, APP, body, how=0x04, extra=bytes([0x80]) + u32(101)) + \
        message(1, APP, body, how=0x04, extra=bytes([0x80]) + u32(101)) + \
        message(1, APP, body, how=0x04, extra=bytes([0x80]) + u32(40)) + \
        message(1, APP, body, how=0x04, extra=bytes([0x80]) + u32(0xFFFFFFF0)) + wait(10)
    # Discovery: a peer announces a large frame size and is the time reference.
    ann = bytes([ANNOUNCE, 2, 0]) + u16(1470) + bytes([4]) + b"ref1" + bytes([0, 0x04 | 0x02, 1]) + u32(16384) + \
        bytes([0]) + bytes([0x80, 0])
    # Then answers a round of requests (one every 15 ms) with sensible times, twice.
    def response(prev):
        return bytes([TIME, 2, 0, 0]) + u32(300) + bytes([0]) + u32(50) + bytes([0, prev, 0]) + u32(0)
    round_ = b"".join(response(0xFF if i == 0 else i - 1) + wait(15) for i in range(8))
    s["timeref"] = bytes([WIDE, 0]) + ann + wait(30) + round_ + wait(900) + round_ + wait(20) + \
        bytes([TIME, 2, 0x02, 1, 3]) + u32(20) + wait(1000)
    # The target sends to a peer that announced 1470-byte frames, then the peer goes back to 250.
    small = bytes([ANNOUNCE, 0, 0]) + u16(250) + bytes([2]) + b"p0" + bytes([0, 0x04, 1]) + u32(16384) + bytes([0]) + \
        bytes([0x80, 0])
    big = bytes([ANNOUNCE, 0, 0]) + u16(1470) + bytes([2]) + b"p0" + bytes([0, 0x04, 1]) + u32(16384) + bytes([0]) + \
        bytes([0x80, 0])
    s["frame_size"] = bytes([WIDE, 0]) + big + wait(10) + bytes([SEND, 0]) + u16(3000) + bytes([0x11]) + wait(2) + \
        small + wait(5) + bytes([ACK, 0, 0x08 | 0x02]) + u16(0) + bytes([0, 2]) + u16(1) + u16(2) + bytes([40]) + wait(300)
    # A stream offered to the target, and one from it.
    offer = bytes([1]) + u32(7) + u32(1000) + u32(400) + bytes([0, 2, 3]) + b"hdr"
    s["stream"] = bytes([0, 0]) + message(0, STREAMS, offer) + wait(20) + \
        message(0, STREAMS, bytes([4]) + u32(7) + u32(0) + bytes(400), how=0x10) + wait(20) + \
        bytes([STREAM, 1]) + u16(5000) + u16(1000) + bytes([2, 0]) + wait(20) + bytes([REFLECT, 1, 0, 1, 0, 2, 0x01, 0]) + wait(100)
    # A pairing window with a request in it, and an attempt to join.
    req = bytes([3]) + bytes(range(32)) + bytes(range(16))
    s["pairing"] = bytes([KEY, 0]) + bytes([PAIR, 0, 0x80 | 20]) + message(1, SECURITY, req) + wait(20) + \
        bytes([REFLECT, 1, 2, 1, 0, 4, 0x01, 0]) + wait(50) + bytes([PAIR, 0, 20]) + bytes([REFLECT, 1, 0x80 | 2, 0, 0x01, 0]) + wait(50)
    # Honest pairings, each way. Inside a procedure each operation runs at one
    # of its waits (a few ms); WAIT operations only let it run on.
    idle = bytes([WAIT, 0, 0]) * 12
    s["pair_member"] = bytes([KEY, 0]) + bytes([PAIR, 0, 0x80 | 60]) + bytes([JOINER, 1, 0]) + idle + \
        bytes([JOINER, 1, 1]) + idle + bytes([JOINER, 1, 2]) + idle + wait(10)
    s["pair_joiner"] = bytes([0, 0]) + bytes([PAIR, 0, 60]) + idle + bytes([MEMBER, 2, 0]) + idle + \
        bytes([MEMBER, 2, 1]) + idle + wait(50) + message(2, APP, bytes(20), how=0x02) + wait(5) + \
        bytes([CHALLENGE, 2, 0, 3]) + wait(5) + message(2, APP, bytes(20), how=0x02) + wait(20)
    # Diagnostics: a ping and a burst request.
    s["diag"] = bytes([0, 0]) + message(0, DIAG, bytes([8, 1, 0, 0])) + wait(20) + \
        message(0, DIAG, bytes([4, 2, 0, 0, 5, 2, 1, 40, 2, 40])) + wait(300)
    return s


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out = os.path.join(sys.argv[1], "frames")
    os.makedirs(out, exist_ok=True)
    for name, data in seeds().items():
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
    print(f"frames: {len(seeds())} seeds in {out}")


if __name__ == "__main__":
    main()
