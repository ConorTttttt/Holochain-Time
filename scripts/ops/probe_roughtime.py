#!/usr/bin/env python3
"""Probe real Roughtime endpoints using the existing native Rust verifier.

Requires a prebuilt, SHA-256-pinned vtime_core roughtime_fetch executable.
Latency includes process start, UDP and cryptographic verification, not pure
network RTT. No signed response, public key, nonce or remote exception text
is ever copied to the event journal.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from events import (UnsafeEvent, append_event, json_unique, make_event,
                    pubkey_ref, require, fingerprint_bytes)

HEX64 = re.compile(r"[a-f0-9]{64}\Z")
MAX_REGISTRY_BYTES = 256_000
MAX_CLIENT_BYTES = 100 * 1024 * 1024


def check_file(path, max_bytes, expected_digest):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and
            path.stat().st_size <= max_bytes and
            type(expected_digest) is str and HEX64.fullmatch(expected_digest),
            "pinned executable/registry missing, linked, too large or unpinned")
    raw = path.read_bytes()
    require(fingerprint_bytes(raw) == expected_digest,
            "externally pinned executable/registry fingerprint mismatch")
    return raw


def candidates(registry, excluded):
    require(type(registry) is dict and registry.get("schema") ==
            "hc-vtime/independent-roughtime/v1",
            "expected Sprint 11 pinned Roughtime registry")
    rows = registry.get("sources")
    require(type(rows) is list and 4 <= len(rows) <= 32,
            "at least 4 and at most 32 trust roots required")
    require(type(excluded) is list and all(type(x) is str for x in excluded)
            and len(excluded) == len(set(excluded)),
            "excluded source names must be unique")
    results, seen_keys, seen_names, seen_ops = [], set(), set(), set()
    for row in rows:
        require(type(row) is dict and
                all(type(row.get(k)) is str for k in
                    ("name", "address", "operator", "public_key", "key_source")),
                "missing candidate operator/key/UDP metadata")
        require(row["key_source"].startswith("https://"),
                "source root lacks published HTTPS provenance")
        ref = pubkey_ref(row["public_key"])
        operator = row["operator"].strip().casefold()
        name = row["name"].strip().casefold()
        require(operator and name and ref not in seen_keys and
                name not in seen_names and operator not in seen_ops,
                "duplicate signing key, operator or name")
        seen_keys.add(ref); seen_names.add(name); seen_ops.add(operator)
        if row["name"] not in excluded:
            results.append(row)
    require(set(excluded) <= {x["name"] for x in rows},
            "excluded source name is not in pinned registry")
    require(len(results) >= 4, "fewer than 4 candidate signing roots")
    return results


def classify_failure(stderr):
    """Never include raw exception text in event records or stdout."""
    text = stderr.lower()
    if "unsupported" in text or ("version" in text and "invalid" in text):
        return "unsupported_protocol"
    if any(token in text for token in
           ("signature", "certificate", "merkle", "nonce mismatch",
            "invalid public key", "bad delegation")):
        return "invalid_signature"
    if "timed out" in text or "timeout" in text:
        return "timeout"
    return "unreachable"


def probe_one(client, source, timeout_seconds, invoke=subprocess.run):
    start = time.monotonic()
    nonce = os.urandom(32).hex()
    try:
        reply = invoke([str(client), source["address"], source["public_key"], nonce],
                       capture_output=True, text=True, timeout=timeout_seconds,
                       check=False)
        status = "ok" if reply.returncode == 0 else classify_failure(reply.stderr)
    except subprocess.TimeoutExpired:
        status = "timeout"
    elapsed = min((time.monotonic() - start) * 1000.0, 600_000.0)
    return make_event("roughtime", "time_source_probe", status,
                      source_ref=pubkey_ref(source["public_key"]),
                      latency_ms=round(elapsed, 2))


def probe_all(rows, client, timeout_seconds, append=None):
    events = []
    accepted = 0
    for source in rows:
        result = probe_one(client, source, timeout_seconds)
        events.append(result)
        if result["status"] == "ok":
            accepted += 1
    events.append(make_event(
        "roughtime", "quorum_check",
        "ok" if accepted >= 3 else "unavailable",
        available_sources=accepted, required_sources=3,
    ))
    events.append(make_event("roughtime", "heartbeat", "ok"))
    if append is not None:
        for item in events:
            append(item)
    return {
        "status": "SIGNED_QUORUM_OBSERVED" if accepted >= 3 else "INSUFFICIENT_SIGNED_SOURCES",
        "probed_roots": len(rows), "valid_signed_roots": accepted,
        "required_sources": 3,
        "one_source_outage_margin_met": len(rows) >= 4,
        "operator_independence_proven": False,
        "record_count": len(events),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--registry", required=True, type=Path)
    ap.add_argument("--expected-registry-sha256", required=True)
    ap.add_argument("--client", required=True, type=Path)
    ap.add_argument("--expected-client-sha256", required=True)
    ap.add_argument("--events", required=True, type=Path)
    ap.add_argument("--exclude-name", action="append", default=[])
    ap.add_argument("--timeout-seconds", type=int, default=8)
    args = ap.parse_args(argv)
    try:
        require(4 <= args.timeout_seconds <= 60, "timeout must be 4..60s")
        reg = check_file(args.registry, MAX_REGISTRY_BYTES,
                         args.expected_registry_sha256)
        require(not args.client.is_symlink(),
                "native Rust verifier symlinks are prohibited")
        client = args.client.resolve()
        check_file(client, MAX_CLIENT_BYTES, args.expected_client_sha256)
        require(os.access(client, os.X_OK), "native Rust verifier executable unavailable")
        rows = candidates(json.loads(reg.decode("utf-8"),
                                         object_pairs_hook=json_unique), args.exclude_name)
        result = probe_all(rows, client, args.timeout_seconds,
                           append=lambda item: append_event(args.events, item))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["valid_signed_roots"] >= 3 else 2
    except (UnsafeEvent, OSError, ValueError, TypeError) as error:
        print(json.dumps({"status": "BLOCKED", "reason": str(error),
                          "operator_independence_proven": False}))
        return 3


if __name__ == "__main__":
    sys.exit(main())
