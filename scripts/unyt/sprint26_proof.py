#!/usr/bin/env python3
"""Independent native-style v2 oracle signature/proven-time preflight.

Checks strictly canonical signed fields and Ed25519 signatures. This does NOT
prove that a Unyt agreement consumed a valid proof, a particular agreement
target was signed, a proof is fresh, or any network balance changed. Current
v2 unyt_time_proof() uses a random nonce: it is NOT target-action bound.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from collections import OrderedDict
from pathlib import Path

FIELD_ORDER = (
    "dna", "domain", "earliest", "floor", "latest",
    "nonce", "oracle", "prev", "seq",
)
DOMAIN = "hc-vtime/oracle-statement/v2"
MAX_US = 2**53
DECIMAL = re.compile(r"(?:0|-?[1-9][0-9]*)\Z")
NONNEG = re.compile(r"(?:0|[1-9][0-9]*)\Z")
HEX32 = re.compile(r"[0-9a-f]{64}\Z")
HEX64 = re.compile(r"[0-9a-f]{128}\Z")


class ProofRejected(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ProofRejected(reason)


def public_raw(value: str, prefix: bytes, label: str) -> bytes:
    require(isinstance(value, str) and value.startswith("u")
            and re.fullmatch("[A-Za-z0-9_-]+", value[1:]) is not None,
            f"{label}: malformed base64url Holochain identifier")
    try:
        raw = base64.urlsafe_b64decode(value[1:] + "=" * ((-len(value[1:])) % 4))
    except (ValueError, Exception) as err:
        raise ProofRejected(f"{label}: invalid base64url encoding") from err
    require(len(raw) == 39 and raw[:3] == prefix,
            f"{label}: incorrect typed Holochain hash length/prefix")
    payload = raw[3:35]
    digest = hashlib.blake2b(payload, digest_size=16).digest()
    check = bytes(digest[k] ^ digest[k+4] ^ digest[k+8] ^ digest[k+12] for k in range(4))
    require(raw[35:39] == check, f"{label}: invalid Holochain location checksum")
    require("u" + base64.urlsafe_b64encode(raw).decode().rstrip("=") == value,
            f"{label}: noncanonical Holochain encoding")
    return payload


def time_number(value: str, label: str, allow_negative: bool = False) -> int:
    pattern = DECIMAL if allow_negative else NONNEG
    require(isinstance(value, str) and pattern.fullmatch(value) is not None,
            f"{label}: noncanonical signed decimal")
    number = int(value)
    require(abs(number) < MAX_US, f"{label}: exceeds signed range")
    return number


def crypto_modules():
    try:
        import msgpack
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as error:
        raise ProofRejected("explicit Python test dependencies msgpack and cryptography required") from error
    return msgpack, InvalidSignature, Ed25519PublicKey


def verify_statement(entry: dict, dna: str, trusted_oracles: set[str]) -> dict:
    require(isinstance(entry, dict) and set(entry) == {"statement", "signature"},
            "one signed statement and 64-byte signature required")
    statement = entry["statement"]
    require(isinstance(statement, dict) and set(statement) == set(FIELD_ORDER),
            "oracle statement missing or unknown fields")
    require(statement["domain"] == DOMAIN, "unsupported signature domain")
    require(statement["dna"] == dna, "foreign DNA")
    public_raw(dna, b"\x84\x2d\x24", "DNA")
    oracle = statement["oracle"]
    require(oracle in trusted_oracles, "untrusted oracle")
    pubkey = public_raw(oracle, b"\x84\x20\x24", "oracle")
    seq = time_number(statement["seq"], "oracle seq")
    lo = time_number(statement["earliest"], "earliest", allow_negative=True)
    hi = time_number(statement["latest"], "latest", allow_negative=True)
    require(lo <= hi, "inverted signed interval")
    nonce = statement["nonce"]
    require(isinstance(nonce, str) and HEX32.fullmatch(nonce) is not None,
            "nonce must be exactly 32 bytes of lowercase hex")
    previous = statement["prev"]
    floor = statement["floor"]
    require(isinstance(previous, str) and isinstance(floor, str),
            "chain link must be signed strings")
    if seq == 0:
        require(previous == "" and floor == "", "genesis must have empty prev/floor")
    else:
        require(HEX64.fullmatch(previous) is not None,
                "previous signature must have 64 lowercase-hex bytes")
        previous_floor = time_number(floor, "prior high-water", allow_negative=True)
        require(hi >= previous_floor, "signed interval contradicts prior floor")
    signature = entry["signature"]
    require(isinstance(signature, list) and len(signature) == 64
            and all(type(b) is int and 0 <= b <= 255 for b in signature),
            "signature must be exactly 64 integer bytes")
    msgpack, InvalidSignature, Ed25519PublicKey = crypto_modules()
    signed_map = OrderedDict((key, statement[key]) for key in FIELD_ORDER)
    signed_bytes = msgpack.packb(signed_map, use_bin_type=True)
    require(len(signed_bytes) <= 2048, "unexpected v2 signing size")
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(bytes(signature), signed_bytes)
    except (InvalidSignature, ValueError) as error:
        raise ProofRejected("invalid signed oracle statement") from error
    return {"oracle": oracle, "nonce": nonce, "earliest": lo, "latest": hi}


def verify_time_proof(proof: dict, dna: str, trusted_oracles: list[str],
                      *, min_sources: int = 2, max_faulty: int = 1) -> dict:
    require(isinstance(proof, dict) and set(proof) == {"statements"},
            "UnytTimeProof must contain only statements array")
    statements = proof["statements"]
    require(isinstance(statements, list) and 1 <= len(statements) <= 32,
            "UnytTimeProof list must contain 1..32 bounded entries")
    require(isinstance(trusted_oracles, list) and len(set(trusted_oracles)) == len(trusted_oracles)
            and len(trusted_oracles) <= 32 and min_sources >= max_faulty + 1
            and max_faulty >= 0, "incoherent trusted quorum")
    count = []
    seen = set()
    nonces = set()
    for item in statements:
        signed = verify_statement(item, dna, set(trusted_oracles))
        require(signed["oracle"] not in seen, "duplicate signed oracle in one proof")
        seen.add(signed["oracle"])
        nonces.add(signed["nonce"])
        count.append(signed["earliest"])
    require(len(nonces) == 1, "quorum statements must refer to same request nonce")
    require(len(count) >= min_sources, "insufficient independent signed oracle statements")
    count.sort(reverse=True)
    floor = count[max_faulty]
    return {
        "status": "SIGNATURE_PREFLIGHT_ONLY_NO_UNYT_ACCEPTANCE",
        "valid_oracle_count": len(count),
        "lower_bound_us": str(floor),
        "request_nonce": next(iter(nonces)),
        "agreement_target_authenticated": False,
        "network_replay_exclusion_authenticated": False,
    }


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--proof", required=True, type=Path)
    ap.add_argument("--dna", required=True)
    ap.add_argument("--oracle", action="append", required=True)
    args = ap.parse_args()
    try:
        proof = json.loads(args.proof.read_text(encoding="utf-8"))
        result = verify_time_proof(proof, args.dna, args.oracle)
        print(json.dumps(result, indent=2, sort_keys=True))
    except (ProofRejected, OSError, ValueError, UnicodeError) as error:
        print(f"PROOF REJECTED: {error}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
