#!/usr/bin/env python3
"""Independently regenerate Sprint 18 canonical fixtures.

Required only to regenerate/check vectors: Python 3, msgpack, cryptography.
All signers are publicly known deterministic TEST KEYS. Never deploy them.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import struct
from collections import OrderedDict
from pathlib import Path

import msgpack
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "integration" / "interop" / "fixtures"
MAGIC = b"ROUGHTIM"
RFC = 1
CTX_SREP = b"Roughtime v1 response signature\0"
CTX_DELE = b"Roughtime v1 delegation signature\0"
TAGS = {
    "SIG": 0x00474953, "VER": 0x00524556, "NONC": 0x434E4F4E,
    "DELE": 0x454C4544, "TYPE": 0x45505954, "PATH": 0x48544150,
    "RADI": 0x49444152, "PUBK": 0x4B425550, "MIDP": 0x5044494D,
    "SREP": 0x50455253, "VERS": 0x53524556, "MINT": 0x544E494D,
    "ROOT": 0x544F4F52, "CERT": 0x54524543, "MAXT": 0x5458414D,
    "INDX": 0x58444E49, "ZZZZ": 0x5A5A5A5A,
}


def u32(n: int) -> bytes:
    return struct.pack("<I", n)


def u64(n: int) -> bytes:
    return struct.pack("<Q", n)


def truncated_sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()[:32]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def message(pairs: list[tuple[str, bytes]]) -> bytes:
    values = sorted(((TAGS[k], v) for k, v in pairs), key=lambda x: x[0])
    offsets: list[bytes] = []
    offset = 0
    for _, value in values[:-1]:
        offset += len(value)
        assert offset % 4 == 0, "RFC offset not four-byte aligned"
        offsets.append(u32(offset))
    return (
        u32(len(values))
        + b"".join(offsets)
        + b"".join(u32(tag) for tag, _ in values)
        + b"".join(value for _, value in values)
    )


def frame(encoded: bytes) -> bytes:
    return MAGIC + u32(len(encoded)) + encoded


def request_packet(nonce: bytes) -> bytes:
    items = [("VER", u32(RFC)), ("NONC", nonce), ("TYPE", u32(0))]
    padding = 1024 - (12 + 8 * 4 + sum(len(v) for _, v in items))
    result = frame(message(items + [("ZZZZ", bytes(padding))]))
    assert len(result) == 1024
    return result


def holo_hash(prefix: bytes, core: bytes) -> str:
    digest = hashlib.blake2b(core, digest_size=16).digest()
    location = bytes(
        digest[i] ^ digest[i + 4] ^ digest[i + 8] ^ digest[i + 12]
        for i in range(4)
    )
    return "u" + base64.urlsafe_b64encode(prefix + core + location).decode().rstrip("=")


def produce() -> dict[str, dict]:
    nonce = bytes([0x73] * 32)
    request = request_packet(nonce)
    long_term = Ed25519PrivateKey.from_private_bytes(bytes([51] * 32))
    delegated = Ed25519PrivateKey.from_private_bytes(bytes([60] * 32))
    public_key = long_term.public_key().public_bytes_raw()
    delegate_key = delegated.public_key().public_bytes_raw()

    delegation = message([
        ("PUBK", delegate_key), ("MINT", u64(1_600_000_000)),
        ("MAXT", u64(2_000_000_000)),
    ])
    certificate = message([
        ("SIG", long_term.sign(CTX_DELE + delegation)), ("DELE", delegation)
    ])

    def signed_response(version: int) -> bytes:
        signed_part = message([
            ("VER", u32(version)), ("VERS", u32(RFC)), ("RADI", u32(2)),
            ("MIDP", u64(1_792_000_000)),
            ("ROOT", truncated_sha512(b"\x00" + request)),
        ])
        return frame(message([
            ("SIG", delegated.sign(CTX_SREP + signed_part)), ("NONC", nonce),
            ("PATH", b""), ("INDX", u32(0)), ("SREP", signed_part),
            ("CERT", certificate), ("TYPE", u32(1)),
        ]))

    response = signed_response(RFC)
    assert len(response) == 416
    oracle_private = Ed25519PrivateKey.from_private_bytes(bytes([7] * 32))
    oracle_public = oracle_private.public_key().public_bytes_raw()
    dna = holo_hash(bytes((0x84, 0x2D, 0x24)), bytes([1] * 32))
    oracle_text = holo_hash(bytes((0x84, 0x20, 0x24)), oracle_public)
    statement = OrderedDict([
        ("dna", dna), ("domain", "hc-vtime/oracle-statement/v2"),
        ("earliest", "1792000000000000"), ("floor", ""),
        ("latest", "1792000000000001"), ("nonce", nonce.hex()),
        ("oracle", oracle_text), ("prev", ""), ("seq", "0"),
    ])
    statement_bytes = msgpack.packb(statement, use_bin_type=True)
    signature = oracle_private.sign(statement_bytes)
    wire = OrderedDict([
        ("format", "hc-vtime/evidence-envelope"), ("version", 1),
        ("items", [OrderedDict([
            ("kind", "oracle"), ("oracle", OrderedDict([
                ("statement", statement), ("signature", signature),
            ])),
        ])]),
    ])
    wire_bytes = msgpack.packb(wire, use_bin_type=True)
    encoded = lambda value: base64.b64encode(value).decode()
    oracle_vector = {
        "schema": "hc-vtime-sprint18-canonical-v1",
        "id": "oracle_signed_canonical_v1",
        "expected": "accepted",
        "wire_base64": encoded(wire_bytes),
        "wire_sha256": sha256(wire_bytes),
        "statement_signing_bytes_sha256": sha256(statement_bytes),
        "public_key_hex": oracle_public.hex(),
        "nonce_hex": nonce.hex(),
        "dna": dna,
    }
    rt_vector = {
        "schema": "hc-vtime-sprint18-roughtime-v1",
        "server_public_key_hex": public_key.hex(),
        "request_b64": encoded(request),
        "response_b64": encoded(response),
        "request_sha256": sha256(request),
        "response_sha256": sha256(response),
        "nonce_hex": nonce.hex(),
        "expected_midpoint_s": 1_792_000_000,
        "expected_radius_s": 2,
        "invalid_cases": [
            {"id": "mutated_signature", "operation": "flip_response_byte",
             "offset": 70, "expected": "bad_signature"},
            {"id": "wrong_nonce", "operation": "flip_response_nonce",
             "expected": "nonce_mismatch"},
            {"id": "bad_framed_length", "operation": "overwrite_frame_length_max",
             "expected": "malformed"},
            {"id": "truncated_response", "operation": "truncate_response_by_one",
             "expected": "malformed"},
            {"id": "request_nonce_replay", "operation": "flip_request_nonce",
             "expected": "invalid"},
            {"id": "oversized_response", "operation": "pad_response_to_16385",
             "expected": "malformed"},
            {"id": "unsupported_srep_version", "operation": "replace_response",
             "response_b64": encoded(signed_response(2)),
             "expected": "unsupported_version"},
        ],
    }
    return {
        "v1_oracle.json": oracle_vector,
        "roughtime_rfc_v1.json": rt_vector,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true",
                      help="verify committed fixtures match independently generated bytes")
    mode.add_argument("--out", type=Path,
                      help="write new fixture set to an existing or new external directory")
    args = parser.parse_args()
    produced = produce()
    if args.check:
        failed = False
        for filename, expected in sorted(produced.items()):
            path = FIXTURES / filename
            actual = json.loads(path.read_text(encoding="utf-8"))
            if actual != expected:
                print(f"FAIL: fixture mismatch: {filename}")
                failed = True
            else:
                print(f"PASS: {filename}")
        return 1 if failed else 0
    out = args.out.resolve()
    if out == ROOT or ROOT in out.parents:
        parser.error("external output required; do not mutate checked-in fixtures")
    out.mkdir(parents=True, exist_ok=True)
    for filename, data in produced.items():
        target = out / filename
        if target.exists():
            parser.error(f"refusing to overwrite {target}")
        target.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")
        print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
