#!/usr/bin/env python3
"""Fail-closed accounting and chain-evidence receipt verifier for Sprint 14B.

The tool DOES NOT validate network consensus by itself. It requires an explicit,
independently obtained transaction verification attestation with a pinned chain
genesis hash and the raw receipt's SHA-256; an unverified explorer export alone
is not acceptable as finality evidence. A trusted Unyt client must supply and
authenticate the attestation during the funded phase.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

HEX64 = re.compile(r"[0-9a-fA-F]{64}\Z")
DEC = re.compile(r"(0|[1-9][0-9]*)\Z")
OUTCOMES = {
    "release": {"tranche_payout", "partial_release", "final_release"},
    "bond": {"slashed", "refunded"},
    "rejected": {"invalid_proof", "unauthorized", "too_early", "duplicate"},
}

def require(ok, reason):
    if not ok:
        raise ValueError(reason)

def amount(value):
    require(isinstance(value, str) and DEC.fullmatch(value) is not None,
            "amounts must be canonical nonnegative decimal strings")
    return int(value)

def hash64(value, name):
    require(isinstance(value, str) and HEX64.fullmatch(value) is not None,
            f"invalid {name}")

def checked(file, attestation, expectations):
    receipt_bytes = file.read_bytes()
    receipt = json.loads(receipt_bytes)
    require(isinstance(receipt, dict) and set(receipt) == {
        "schema", "network_genesis", "agreement_id", "tx_hash",
        "execution_id", "outcome", "status", "input_total",
        "allocations", "locked_remaining", "spent_sources",
    }, "unexpected receipt schema")
    require(receipt["schema"] == "hc-vtime/unyt-receipt/v1", "unexpected receipt version")
    hash64(receipt["network_genesis"], "network genesis")
    hash64(receipt["tx_hash"], "transaction hash")
    require(isinstance(receipt["agreement_id"], str) and receipt["agreement_id"],
            "missing agreement ID")
    require(isinstance(receipt["execution_id"], str) and receipt["execution_id"],
            "missing execution ID")
    require(receipt["status"] in {"committed", "rejected"}, "unknown status")
    require(receipt["outcome"] in set().union(*OUTCOMES.values()), "unknown outcome")
    require(isinstance(receipt["allocations"], list), "allocations must be list")
    require(isinstance(receipt["spent_sources"], list)
            and len(receipt["spent_sources"]) == len(set(receipt["spent_sources"])),
            "spent source list must be unique")
    allocated = 0
    for item in receipt["allocations"]:
        require(isinstance(item, dict) and set(item) == {"receiver", "amount", "source"},
                "invalid allocation record")
        require(isinstance(item["receiver"], str) and item["receiver"],
                "missing receiver")
        require(isinstance(item["source"], str) and item["source"] in receipt["spent_sources"],
                "allocation source is not accounted for")
        n = amount(item["amount"])
        require(n > 0, "zero-amount allocations are forbidden in committed receipts")
        allocated += n
    input_total = amount(receipt["input_total"])
    locked = amount(receipt["locked_remaining"])
    require(isinstance(expectations, dict) and set(expectations) == {
        "schema", "network_genesis", "agreement_id", "outcome",
        "status", "input_total", "locked_remaining",
        "allocations", "spent_sources",
    }, "unexpected expectation schema")
    require(expectations["schema"] == "hc-vtime/unyt-expectation/v1",
            "wrong expectation schema")
    for key in ("network_genesis", "agreement_id", "outcome",
                "status", "input_total", "locked_remaining",
                "allocations", "spent_sources"):
        require(receipt[key] == expectations[key],
                f"receipt mismatch with independently authored expectation: {key}")
    if receipt["status"] == "rejected":
        require(receipt["outcome"] in OUTCOMES["rejected"], "rejection has payout outcome")
        require(not receipt["allocations"] and not receipt["spent_sources"]
                and locked == input_total, "rejected transaction moved or consumed funds")
    else:
        require(receipt["outcome"] not in OUTCOMES["rejected"], "committed rejection")
        require(allocated + locked == input_total,
                "value conservation failed: allocations + locked != input")
        require(bool(receipt["spent_sources"]), "committed transaction has no consumed sources")
        if receipt["outcome"] in ("slashed", "refunded", "final_release"):
            require(locked == 0, "terminal financial transition left funds locked")
        if receipt["outcome"] == "partial_release":
            require(locked > 0 and allocated > 0, "partial release not partial")

    require(isinstance(attestation, dict) and set(attestation) == {
        "schema", "genesis_hash", "tx_hash", "receipt_sha256",
        "verification_method", "finality_verified", "independent_record",
    }, "unexpected attestation schema")
    require(attestation["schema"] == "hc-vtime/unyt-chain-attestation/v1",
            "wrong attestation schema")
    require(attestation["genesis_hash"] == receipt["network_genesis"]
            and attestation["tx_hash"] == receipt["tx_hash"],
            "attestation references a different chain or transaction")
    require(attestation["receipt_sha256"] == hashlib.sha256(receipt_bytes).hexdigest(),
            "attestation does not bind the exact receipt bytes")
    require(attestation["verification_method"] == "independent-unyt-node",
            "attestation must come from independent Unyt node validation")
    require(attestation["finality_verified"] is True,
            "no independent finalized transaction evidence")
    require(isinstance(attestation["independent_record"], str)
            and attestation["independent_record"].startswith("sha256:")
            and HEX64.fullmatch(attestation["independent_record"][7:]),
            "missing independently archived raw chain evidence digest")
    # This structure is only a *claim* unless the operator checks the
    # independent record against authenticated node response and real finality.
    # It does not give user-supplied JSON intrinsic proof of consensus.
    return receipt

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("receipt", type=Path)
    p.add_argument("expectation", type=Path)
    p.add_argument("attestation", type=Path)
    args = p.parse_args()
    result = checked(
        args.receipt,
        json.loads(args.attestation.read_text()),
        json.loads(args.expectation.read_text()),
    )
    print("ACCOUNTING AND ATTESTATION FIELDS MATCH:", result["tx_hash"])
    print("NOT A CONSENSUS PROOF: authenticate the independent node record manually.")

if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"REJECTED: {exc}")
