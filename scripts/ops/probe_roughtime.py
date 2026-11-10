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
MIN_SOURCES = 3
OUTAGE_MARGIN = 1
LIVE_PROTOCOLS = {"rfc10049-live-verified", "draft15-live-verified"}
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


def reviewed_eligible(registry: dict, dossier: dict, excluded: list[str]) -> list[dict]:
    """Return only signer roots with exactly matched reviewed live credentials.

    Dossier review data is NOT cryptographic proof of independent control.
    Approval requires two human review records plus per-source key, protocol,
    infrastructure and live signed-evidence references, pinned outside Git.
    The native verifier then separately authenticates each fresh response.
    """
    selected = candidates(registry, excluded)
    require(type(dossier) is dict and
            dossier.get("schema") == "hc-vtime/roughtime-operator-dossier/v1" and
            dossier.get("status") == "REVIEWED_APPROVED" and
            dossier.get("min_sources") == MIN_SOURCES and
            dossier.get("max_faulty") == 1 and
            dossier.get("max_unavailable") == OUTAGE_MARGIN,
            "an approved Sprint 23 operator dossier with unchanged quorum is required")
    reviewers = dossier.get("reviewers")
    require(type(reviewers) is list and len(reviewers) >= 2 and
            all(type(x) is str and len(x.strip()) >= 4 for x in reviewers) and
            len({x.strip().casefold() for x in reviewers}) >= 2,
            "two distinct human root/infrastructure reviewers required")
    reviews = dossier.get("sources")
    require(type(reviews) is list and
            len(reviews) == len(registry["sources"]),
            "exactly one operator review per registry signer root required")
    from base64 import b64decode
    def key_bytes(value):
        require(type(value) is str, "dossier signing key must be canonical base64")
        try:
            raw = b64decode(value, validate=True)
        except (ValueError, __import__("binascii").Error) as exc:
            raise UnsafeEvent("invalid operator review public-key encoding") from exc
        require(len(raw) == 32, "operator review signing root not 32 bytes")
        return raw
    by_key = {}
    ids = set()
    for row in reviews:
        require(type(row) is dict, "operator review entry must be a JSON object")
        root = key_bytes(row.get("public_key"))
        require(root not in by_key, "duplicate operator review signing root")
        by_key[root] = row
        operator_id = row.get("operator_id")
        require(type(operator_id) is str and operator_id.strip() and
                operator_id.casefold().strip() not in ids,
                "duplicate or empty operator review identity")
        ids.add(operator_id.casefold().strip())
    trusted_roots = {key_bytes(row["public_key"]) for row in registry["sources"]}
    require(set(by_key) == trusted_roots,
            "review roots differ from pinned authenticated registry")
    eligible = []
    for row in selected:
        review = by_key[key_bytes(row["public_key"])]
        require(all(review.get(k) == row[k] for k in
                    ("name", "operator", "address", "key_source", "public_key")),
                "operator review not bound to exact registered source/endpoint")
        # A candidate-only protocol flag or a reported label NEVER makes this
        # an eligible source. Human review fields still require offline audit.
        require(review.get("supported_client_protocol") is True and
                review.get("protocol_assessment") in LIVE_PROTOCOLS and
                all(review.get(k) is True for k in
                    ("admin_independence_reviewed", "root_key_control_reviewed",
                     "shared_upstream_reviewed")) and
                type(review.get("live_signature_evidence_sha256")) is str and
                HEX64.fullmatch(review["live_signature_evidence_sha256"]) and
                type(review.get("infrastructure_evidence_refs")) is list and
                bool(review["infrastructure_evidence_refs"]),
                "candidate, unverified, or incomplete source is NOT eligible")
        eligible.append(row)
    require(len(eligible) >= MIN_SOURCES + OUTAGE_MARGIN,
            "fewer than quorum plus one externally reviewed eligible source roots")
    return eligible


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
        "status": (
            "QUORUM_WITH_VERIFIED_OUTAGE_MARGIN"
            if accepted >= MIN_SOURCES + OUTAGE_MARGIN else
            "QUORUM_DEGRADED_NO_OUTAGE_MARGIN"
            if accepted >= MIN_SOURCES else
            "INSUFFICIENT_SIGNED_SOURCES"
        ),
        "probed_roots": len(rows), "valid_signed_roots": accepted,
        "required_sources": 3,
        # Margin is based ONLY on cryptographically verified fresh response
        # successes from the externally reviewed eligible source set, not
        # configured roots, reported operator labels or failed probes.
        "one_source_outage_margin_met": accepted >= MIN_SOURCES + OUTAGE_MARGIN,
        "required_outage_margin_sources": OUTAGE_MARGIN,
        "eligible_roots_probed": len(rows),
        "eligible_signed_successes": accepted,
        "failed_or_unverified_roots": len(rows) - accepted,
        "operator_independence_proven": False,
        "record_count": len(events),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--registry", required=True, type=Path)
    ap.add_argument("--expected-registry-sha256", required=True)
    ap.add_argument("--dossier", required=True, type=Path,
                    help="Sprint 23 externally reviewed approved source dossier")
    ap.add_argument("--expected-dossier-sha256", required=True,
                    help="out-of-band human-reviewed dossier fingerprint")
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
        dossier_raw = check_file(args.dossier, MAX_REGISTRY_BYTES,
                                 args.expected_dossier_sha256)
        registry = json.loads(reg.decode("utf-8"), object_pairs_hook=json_unique)
        dossier = json.loads(dossier_raw.decode("utf-8"),
                             object_pairs_hook=json_unique)
        rows = reviewed_eligible(registry, dossier, args.exclude_name)
        result = probe_all(rows, client, args.timeout_seconds,
                           append=lambda item: append_event(args.events, item))
        print(json.dumps(result, indent=2, sort_keys=True))
        # Three verified sources can form a seal quorum but leave ZERO spare
        # healthy signers. Do not return success for the stronger acceptance
        # objective (three now AND three after one further source outage).
        return 0 if result["one_source_outage_margin_met"] else 2
    except (UnsafeEvent, OSError, ValueError, TypeError) as error:
        print(json.dumps({"status": "BLOCKED", "reason": str(error),
                          "operator_independence_proven": False}))
        return 3


if __name__ == "__main__":
    sys.exit(main())
