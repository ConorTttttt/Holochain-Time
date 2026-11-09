#!/usr/bin/env python3
"""Independent Python verification of Sprint 18 signed interoperability fixtures.

Only a fixture-level reference check, not a replacement for vtime_core's
complete Roughtime protocol validation. Requires msgpack and cryptography.
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
from collections import OrderedDict
from pathlib import Path

import msgpack
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "integration" / "interop" / "fixtures"
MAGIC = b"ROUGHTIM"
TAG_NAMES = {
    0x00474953: "SIG", 0x00524556: "VER", 0x434E4F4E: "NONC",
    0x454C4544: "DELE", 0x45505954: "TYPE", 0x48544150: "PATH",
    0x49444152: "RADI", 0x4B425550: "PUBK", 0x5044494D: "MIDP",
    0x50455253: "SREP", 0x53524556: "VERS", 0x544E494D: "MINT",
    0x544F4F52: "ROOT", 0x54524543: "CERT", 0x5458414D: "MAXT",
    0x58444E49: "INDX", 0x5A5A5A5A: "ZZZZ",
}


class Rejected(Exception):
    """A fixture did not satisfy the reference acceptance check."""


def require(condition: bool, reason: str = "malformed") -> None:
    if not condition:
        raise Rejected(reason)


def get32(data: bytes, offset: int) -> int:
    require(offset + 4 <= len(data))
    return struct.unpack_from("<I", data, offset)[0]


def get64(data: bytes) -> int:
    require(len(data) == 8)
    return struct.unpack("<Q", data)[0]


def u32(data: bytes) -> int:
    require(len(data) == 4)
    return struct.unpack("<I", data)[0]


def parse_message(data: bytes) -> dict[str, bytes]:
    require(4 <= len(data) <= 16_384)
    count = get32(data, 0)
    require(0 < count <= 64 and 8 * count <= len(data))
    offsets = [0] + [
        get32(data, 4 + 4 * i) for i in range(count - 1)
    ] + [len(data) - 8 * count]
    require(all(
        left <= right and left % 4 == 0
        for left, right in zip(offsets, offsets[1:])
    ))
    tags = [get32(data, 4 * count + 4 * i) for i in range(count)]
    require(all(a < b for a, b in zip(tags, tags[1:])))
    return {
        TAG_NAMES.get(tag, str(tag)): data[8 * count + offsets[i]:8 * count + offsets[i + 1]]
        for i, tag in enumerate(tags)
    }


def parse_frame(packet: bytes, maximum: int) -> dict[str, bytes]:
    require(12 <= len(packet) <= maximum and packet[:8] == MAGIC)
    require(get32(packet, 8) == len(packet) - 12)
    return parse_message(packet[12:])


def truncated_sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()[:32]


def verify_roughtime(request: bytes, response: bytes, key: bytes) -> dict:
    req = parse_frame(request, 4096)
    resp = parse_frame(response, 16384)
    require(req["NONC"] == resp["NONC"], "nonce_mismatch")
    require(len(req["NONC"]) == 32)
    signed = parse_message(resp["SREP"])
    version = u32(signed["VER"])
    require(version == 1, "unsupported_version")
    require(u32(req["VER"]) == version and u32(signed["VERS"]) == version)
    require(u32(resp["TYPE"]) == 1 and u32(signed["RADI"]) > 0)
    cert = parse_message(resp["CERT"])
    delegation = parse_message(cert["DELE"])
    require(len(key) == 32 and len(delegation["PUBK"]) == 32)
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(
            cert["SIG"], b"Roughtime v1 delegation signature\0" + cert["DELE"]
        )
        Ed25519PublicKey.from_public_bytes(delegation["PUBK"]).verify(
            resp["SIG"], b"Roughtime v1 response signature\0" + resp["SREP"]
        )
    except InvalidSignature as error:
        raise Rejected("bad_signature") from error
    midpoint = get64(signed["MIDP"])
    require(get64(delegation["MINT"]) <= midpoint <= get64(delegation["MAXT"]))
    require(u32(resp["INDX"]) == 0 and not resp["PATH"])
    require(signed["ROOT"] == truncated_sha512(b"\0" + request))
    return {
        "midpoint_s": midpoint, "radius_s": u32(signed["RADI"]),
        "nonce_hex": req["NONC"].hex(),
    }


def ordered_unique(pairs: list[tuple]) -> OrderedDict:
    output = OrderedDict()
    for key, value in pairs:
        require(key not in output)
        output[key] = value
    return output


def check_oracle(vector: dict) -> int:
    data = base64.b64decode(vector["wire_base64"], validate=True)
    require(hashlib.sha256(data).hexdigest() == vector["wire_sha256"])
    envelope = msgpack.unpackb(data, raw=False, object_pairs_hook=ordered_unique)
    require(list(envelope) == ["format", "version", "items"])
    require(envelope["version"] == 1 and envelope["format"] == "hc-vtime/evidence-envelope")
    require(len(envelope["items"]) == 1)
    item = envelope["items"][0]
    require(list(item) == ["kind", "oracle"] and item["kind"] == "oracle")
    oracle = item["oracle"]
    require(list(oracle) == ["statement", "signature"])
    statement = oracle["statement"]
    require(list(statement) == [
        "dna", "domain", "earliest", "floor", "latest",
        "nonce", "oracle", "prev", "seq",
    ])
    require(statement["dna"] == vector["dna"] and statement["nonce"] == vector["nonce_hex"])
    signed_bytes = msgpack.packb(statement, use_bin_type=True)
    require(hashlib.sha256(signed_bytes).hexdigest()
            == vector["statement_signing_bytes_sha256"])
    require(msgpack.packb(envelope, use_bin_type=True) == data)
    try:
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(vector["public_key_hex"])
        ).verify(oracle["signature"], signed_bytes)
    except InvalidSignature as error:
        raise Rejected("bad_signature") from error
    return len(data)


def check_roughtime(vector: dict) -> int:
    request = base64.b64decode(vector["request_b64"], validate=True)
    response = base64.b64decode(vector["response_b64"], validate=True)
    key = bytes.fromhex(vector["server_public_key_hex"])
    require(hashlib.sha256(request).hexdigest() == vector["request_sha256"])
    require(hashlib.sha256(response).hexdigest() == vector["response_sha256"])
    result = verify_roughtime(request, response, key)
    require(
        result["nonce_hex"] == vector["nonce_hex"]
        and result["midpoint_s"] == vector["expected_midpoint_s"]
        and result["radius_s"] == vector["expected_radius_s"]
    )
    nonce = bytes.fromhex(vector["nonce_hex"])
    for case in vector["invalid_cases"]:
        changed_request = bytearray(request)
        changed_response = bytearray(response)
        op = case["operation"]
        if op == "flip_response_byte":
            changed_response[case["offset"]] ^= 1
        elif op == "flip_response_nonce":
            changed_response[changed_response.index(nonce)] ^= 1
        elif op == "overwrite_frame_length_max":
            changed_response[8:12] = b"\xff" * 4
        elif op == "truncate_response_by_one":
            changed_response.pop()
        elif op == "flip_request_nonce":
            changed_request[changed_request.index(nonce)] ^= 1
        elif op == "pad_response_to_16385":
            changed_response.extend(bytes(16385 - len(changed_response)))
        elif op == "replace_response":
            changed_response = bytearray(base64.b64decode(case["response_b64"]))
        else:
            raise ValueError(f"unknown mutation operation {op}")
        try:
            verify_roughtime(bytes(changed_request), bytes(changed_response), key)
        except Rejected as error:
            if case["expected"] != "invalid":
                require(str(error) == case["expected"],
                        f"unexpected rejection for {case['id']}: {error}")
        else:
            raise AssertionError(f"invalid case {case['id']} was accepted")
    return len(vector["invalid_cases"])


def main() -> int:
    oracle = json.loads((FIXTURES / "v1_oracle.json").read_text(encoding="utf-8"))
    rt = json.loads((FIXTURES / "roughtime_rfc_v1.json").read_text(encoding="utf-8"))
    print(f"PASS: Python oracle signature / canonical MessagePack ({check_oracle(oracle)} bytes)")
    print(f"PASS: Python RFC signed time / invalid mutations ({check_roughtime(rt)} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
