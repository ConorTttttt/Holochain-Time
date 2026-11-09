#!/usr/bin/env python3
"""Create deterministic RFC framing and exchange fuzz seeds outside the repo.

Seed files are not signatures or trusted network responses. They exercise
parser shape and boundary handling; genuine signatures are tested separately.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[2]
MAGIC = b"ROUGHTIM"


def frame(message: bytes) -> bytes:
    return MAGIC + struct.pack("<I", len(message)) + message


def encode_message(pairs: list[tuple[int, bytes]]) -> bytes:
    pairs = sorted(pairs)
    count = len(pairs)
    offsets = []
    offset = 0
    for _, value in pairs[:-1]:
        offset += len(value)
        offsets.append(offset)
    return (
        struct.pack("<I", count)
        + b"".join(struct.pack("<I", x) for x in offsets)
        + b"".join(struct.pack("<I", tag) for tag, _ in pairs)
        + b"".join(value for _, value in pairs)
    )


def request() -> bytes:
    # Mirrors a 1024-byte RFC request: NONC, TYPE, VER, ZZZZ.
    pairs = [
        (0x00524556, struct.pack("<I", 1)),  # VER
        (0x434e4f4e, bytes([0x73]) * 32),    # NONC
        (0x45505954, b"\0" * 4),            # TYPE
        (0x5a5a5a5a, b""),                 # ZZZZ
    ]
    length_without_pad = 12 + 8 * 4 + sum(len(data) for _, data in pairs)
    pairs[-1] = (0x5a5a5a5a, b"\0" * (1024 - length_without_pad))
    packed = frame(encode_message(pairs))
    assert len(packed) == 1024
    return packed


def seeds() -> dict[str, dict[str, bytes]]:
    good_request = request()
    bad_length = MAGIC + b"\xff" * 4 + b"\0" * 4
    max_tags = frame(b"\xff" * 4)
    empty = frame(b"\0" * 4)
    too_large_response = frame(b"\x00" * (16 * 1024 - 11))
    packets = {
        "empty_message": empty,
        "bad_length": bad_length,
        "max_tag_count": max_tags,
        "valid_request": good_request,
        "over_16k_frame": too_large_response,
        "truncated_frame": MAGIC,
    }
    exchange = {
        "empty_exchange": b"\0\0",
        "real_request_empty_response": struct.pack("<H", len(good_request)) + good_request,
        "real_request_bad_response": (
            struct.pack("<H", len(good_request)) + good_request + bad_length
        ),
        "oversized_request": struct.pack("<H", 4097) + b"r" * 4097 + empty,
        "oversized_response": b"\0\0" + too_large_response,
    }
    return {"roughtime_parser": packets, "roughtime_exchange": exchange}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="new corpus root OUTSIDE repo")
    args = parser.parse_args()
    out = args.out.resolve()
    if out == ROOT or ROOT in out.parents:
        parser.error("fuzz corpus must be outside source tree")
    if out.exists():
        parser.error("refusing to overwrite an existing corpus")
    all_seeds = seeds()
    for target, samples in all_seeds.items():
        target_directory = out / target
        target_directory.mkdir(parents=True, exist_ok=False)
        for name, value in sorted(samples.items()):
            (target_directory / name).write_bytes(value)
            print(f"{target}/{name} sha256={hashlib.sha256(value).hexdigest()} bytes={len(value)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
