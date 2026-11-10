#!/usr/bin/env python3
"""Sprint 23: pin, capture, independently verify and locally consume live Roughtime.

No crypto is reimplemented here. The pinned Rust vtime_core verifier authenticates
Ed25519 long-term delegation, SREP signatures, nonce/Merkle inclusion, version,
bounds and the three-source quorum. This CLI NEVER proves operator independence
from a set of names/keys, and never changes DNA consensus or quorum policy.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
HASH39 = re.compile(r"[0-9a-f]{78}\Z")
OP_ID = re.compile(r"[a-z][a-z0-9-]{2,63}\Z")
WORK_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{7,127}\Z")
MIN_QUORUM = 3
MAX_UNAVAILABLE = 1


class Blocked(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Blocked(reason)


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def digest_file(path):
    return sha_bytes(Path(path).read_bytes())


def object_pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON field: " + key)
        result[key] = value
    return result


def read_json(path):
    p = Path(path)
    require(p.is_file() and not p.is_symlink() and p.stat().st_size <= 256_000,
            f"missing, symlinked or oversized JSON document: {path}")
    try:
        return json.loads(p.read_bytes().decode("utf-8"), object_pairs_hook=object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Blocked("invalid JSON: " + str(exc)) from exc


def decode_key(value):
    require(isinstance(value, str), "Roughtime key must be base64 text")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise Blocked("bad public key base64") from exc
    require(len(raw) == 32 and base64.b64encode(raw).decode() == value,
            "Ed25519 root must be 32 canonical bytes")
    return raw


def validate_dossier(registry, dossier, registry_sha):
    """Structural source/binding review, never independent-operator proof."""
    require(isinstance(registry, dict) and
            registry.get("schema") == "hc-vtime/independent-roughtime/v1",
            "unsupported Sprint 11 authenticated source registry")
    require(isinstance(dossier, dict) and
            dossier.get("schema") == "hc-vtime/roughtime-operator-dossier/v1",
            "unsupported source ownership dossier")
    require(dossier.get("min_sources") == MIN_QUORUM and
            dossier.get("max_faulty") == 1 and
            dossier.get("max_unavailable") == MAX_UNAVAILABLE,
            "three-source f=1 quorum and one-outage policy must not be downgraded")
    registry_rows, review_rows = registry.get("sources"), dossier.get("sources")
    require(isinstance(registry_rows, list) and len(registry_rows) >= 4 and
            len(registry_rows) <= 32, "registry needs at least four trusted operators")
    require(isinstance(review_rows, list) and len(review_rows) == len(registry_rows),
            "each trusted root requires exactly one review dossier entry")
    keys, names, operators, endpoints = set(), set(), set(), set()
    supported = []
    unsupported = []
    by_key = {}
    for index, row in enumerate(registry_rows):
        require(isinstance(row, dict), f"invalid registry row {index}")
        require(all(isinstance(row.get(field), str) for field in
                    ("name", "operator", "address", "public_key", "key_source")),
                "registry source missing name/operator/endpoint/provenance/key")
        raw = decode_key(row["public_key"])
        label = row["operator"].strip().casefold()
        name = row["name"].strip().casefold()
        endpoint = row["address"].strip().casefold()
        require(raw not in keys and label and label not in operators and
                name and name not in names and endpoint and endpoint not in endpoints,
                "duplicate signing key, operator, name or UDP endpoint")
        keys.add(raw); operators.add(label); names.add(name); endpoints.add(endpoint)
        require(row["key_source"].startswith("https://"),
                "candidate root must have documented HTTPS source of record")
        by_key[raw] = row
    ids = set()
    for row in review_rows:
        require(isinstance(row, dict), "dossier source must be an object")
        raw = decode_key(row.get("public_key"))
        original = by_key.get(raw)
        require(original is not None, "dossier contains untrusted root not in registry")
        require(all(row.get(field) == original[field] for field in
                    ("name", "operator", "address")) and
                row.get("key_source") == original["key_source"],
                "dossier identity/endpoint provenance changed without pinning registry")
        operator_id = row.get("operator_id")
        require(isinstance(operator_id, str) and OP_ID.fullmatch(operator_id),
                "dossier operator identifier must be a stable slug")
        require(operator_id not in ids, "two keys labelled as same real-world operator")
        ids.add(operator_id)
        require(isinstance(row.get("ownership_and_infrastructure_claim"), str) and
                len(row["ownership_and_infrastructure_claim"]) >= 25,
                "record ownership, hosting and common upstream risk")
        protocol = row.get("protocol_assessment")
        require(protocol in ("draft11-unsupported", "unknown-probe-required",
                             "rfc10049-candidate", "draft15-candidate",
                             "rfc10049-live-verified", "draft15-live-verified"),
                "unknown or unsupported protocol assessment")
        compat = row.get("supported_client_protocol")
        require(type(compat) is bool and
                (not compat if protocol == "draft11-unsupported" else compat),
                "known incompatible draft11 must never be eligible")
        if compat:
            supported.append(operator_id)
        else:
            unsupported.append(operator_id)
        for field in ("admin_independence_reviewed", "root_key_control_reviewed",
                      "shared_upstream_reviewed"):
            require(type(row.get(field)) is bool, f"{operator_id}: incomplete review field {field}")
        evidence = row.get("live_signature_evidence_sha256")
        require(evidence is None or (type(evidence) is str and
                                    DIGEST.fullmatch(evidence)),
                f"{operator_id}: malformed evidence SHA-256")
        require(isinstance(row.get("infrastructure_evidence_refs"), list),
                f"{operator_id}: infrastructure evidence references missing")
    require(len(supported) >= MIN_QUORUM + MAX_UNAVAILABLE,
            "fewer than four protocol-compatible candidate operators; outage tolerance impossible")
    require(dossier.get("status") in ("PENDING_EXTERNAL_REVIEW", "REVIEWED_APPROVED"),
            "invalid human review state")
    reviewers = dossier.get("reviewers")
    require(type(reviewers) is list, "reviewer records must be a list")
    approval = (dossier["status"] == "REVIEWED_APPROVED" and
                len(set(str(x).strip().casefold() for x in reviewers)) >= 2 and
                all(type(x) is str and len(x.strip()) >= 4 for x in reviewers) and
                all(row["admin_independence_reviewed"] and
                    row["root_key_control_reviewed"] and
                    row["shared_upstream_reviewed"] and
                    row["live_signature_evidence_sha256"] is not None and
                    bool(row["infrastructure_evidence_refs"])
                    for row in review_rows if row["supported_client_protocol"]))
    return {
        "schema": "hc-vtime/operator-review-audit/v1",
        "registry_sha256": registry_sha,
        "candidate_count": len(registry_rows),
        "eligible_candidate_count": len(supported),
        "eligible_candidate_operators": supported,
        "excluded_incompatible_operators": unsupported,
        "configured_distinct_operator_labels": len(operators),
        "human_review_records_complete": bool(approval),
        "operator_independence_proven": False,
        "status": "REVIEW_ASSERTIONS_COMPLETE" if approval else "PENDING_HUMAN_REVIEW",
        "note": "Even completed review fields are assertions: independent key control and shared infrastructure must be audited externally.",
    }


def prepare(args):
    registry_raw = Path(args.registry).read_bytes()
    require(DIGEST.fullmatch(args.expected_registry_sha256) and
            sha_bytes(registry_raw) == args.expected_registry_sha256,
            "trusted source registry changed; external SHA-256 pin missing/mismatched")
    registry = read_json(args.registry)
    dossier = read_json(args.dossier)
    review = validate_dossier(registry, dossier, sha_bytes(registry_raw))
    review["dossier_sha256"] = digest_file(args.dossier)
    return registry, dossier, review


def check_sha(exact_sha, *, strict=True):
    require(type(exact_sha) is str and SHA.fullmatch(exact_sha),
            "expected Git commit must be exact lowercase 40-character SHA")
    head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--verify", "HEAD"],
                          capture_output=True, text=True)
    require(head.returncode == 0 and head.stdout.strip() == exact_sha,
            "source checkout differs from pinned tested SHA")
    if strict:
        dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain",
                                "--untracked-files=all"], capture_output=True, text=True)
        require(dirty.returncode == 0 and not dirty.stdout.strip(),
                "source checkout is dirty; cannot certify exact-commit evidence")


def check_target(dna, target):
    require(type(dna) is str and HASH39.fullmatch(dna),
            "DNA must be raw 39-byte hash, exactly 78 lowercase hexadecimal digits")
    require(type(target) is str and HASH39.fullmatch(target),
            "target must be raw 39-byte ActionHash, exactly 78 lowercase hex digits")


def native_mode(mode, config, dna, target, receipt=None, timeout=180):
    argv = ["cargo", "run", "--locked", "-q", "-p", "vtime_core",
            "--example", "roughtime_independent", "--", mode, str(config)]
    if mode == "--verify":
        require(receipt is not None, "offline verify requires receipt")
        argv.append(str(receipt))
    argv += [dna, target]
    return subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                          timeout=timeout, check=False)


def native_summary(stdout_stderr, dna, target):
    records = []
    for line in stdout_stderr.splitlines():
        if "HC_RT_VERIFIED " in line:
            value = line.split("HC_RT_VERIFIED ", 1)[1]
            try:
                records.append(json.loads(value))
            except json.JSONDecodeError as exc:
                raise Blocked("malformed native verification record") from exc
    require(len(records) == 1, "expected exactly one native cryptographic verifier record")
    record = records[0]
    require(record.get("schema") == "hc-vtime/native-roughtime-verification/v1" and
            record.get("dna_hex") == dna and record.get("target_hex") == target,
            "native verification bound to wrong source DNA or target")
    require(record.get("verified_count", 0) >= MIN_QUORUM,
            "native verifier did not authenticate three signed Roughtime sources")
    intervals = record.get("intervals")
    require(isinstance(intervals, list) and len(intervals) == record["verified_count"],
            "native signed interval evidence incomplete")
    keys = []
    for row in intervals:
        require(isinstance(row, dict) and
                type(row.get("earliest_us")) is int and
                type(row.get("latest_us")) is int and
                row["earliest_us"] <= row["latest_us"] and
                isinstance(row.get("key_hex"), str) and
                len(row["key_hex"]) == 64,
                "invalid native-signed source interval")
        keys.append(row["key_hex"])
    require(len(set(keys)) == len(keys), "same signer appears twice in native result")
    require(record.get("operator_independence_proven") is False and
            record.get("same_target_replay_prevented") is False,
            "native verifier falsely claims independent operators or same-target freshness")
    return record


def store_report(directory, report, files=None):
    directory = Path(directory).resolve()
    require(not directory.exists(), "report directory already exists; evidence must be immutable")
    require(ROOT != directory and ROOT not in directory.parents,
            "evidence must be stored outside source control")
    directory.mkdir(parents=True)
    for name, data in (files or {}).items():
        require("/" not in name and name not in (".", ".."), "unsafe report filename")
        (directory / name).write_bytes(
            data if isinstance(data, bytes) else data.encode("utf-8"))
    (directory / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rows = []
    for p in sorted(directory.iterdir()):
        if p.is_file():
            rows.append(f"{digest_file(p)}  {p.name}")
    (directory / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")


def receipt_check(receipt, dna, target):
    require(type(receipt) is dict and receipt.get("schema") ==
            "hc-vtime/roughtime-receipt/v1", "wrong receipt schema")
    require(receipt.get("dna_hex") == dna and receipt.get("target_hex") == target,
            "receipt signed for wrong DNA or target")
    require(isinstance(receipt.get("nonce_hex"), str) and
            re.fullmatch(r"[0-9a-f]{64}", receipt["nonce_hex"]),
            "invalid receipt nonce")
    rows = receipt.get("evidence")
    require(type(rows) is list and len(rows) <= 32,
            "malformed or oversized signed packet evidence array")
    return len(rows)


def run_verify(registry_path, receipt_path, dna, target, *, timeout=180):
    result = native_mode("--verify", registry_path, dna, target,
                         receipt=receipt_path, timeout=timeout)
    require(result.returncode == 0,
            "native signed packet verification rejected receipt: " +
            result.stderr[-500:])
    return native_summary(result.stderr, dna, target), result


def make_outage_registry(registry, dossier, operator_id):
    require(any(row.get("operator_id") == operator_id and
                row.get("supported_client_protocol") is True
                for row in dossier["sources"]),
            "outage operator must be a compatible reviewed candidate")
    effective = json.loads(json.dumps(registry))
    for index, row in enumerate(dossier["sources"]):
        if row["operator_id"] == operator_id:
            effective["sources"][index]["address"] = "127.0.0.1:9"
    return effective


def freshness(intervals, now_us, age_seconds=600, future_seconds=90):
    """Local wall-clock gating only, NOT cryptographic same-target freshness."""
    require(type(now_us) is int and age_seconds > 0 and future_seconds >= 0,
            "invalid local-clock freshness policy")
    valid = [
        row for row in intervals
        if row["latest_us"] >= now_us - age_seconds * 1_000_000 and
        row["earliest_us"] <= now_us + future_seconds * 1_000_000
    ]
    return len(valid) >= MIN_QUORUM


def claim_local_ledger(path, dna, target, operation_id, packet_sha):
    """Atomically claim a verified receipt+workflow on ONE local SQLite host.

    Fail closed on repeated byte-identical evidence, or repeat submissions of
    the same logical operation. Cross-host and conductor-wide replay are NOT
    prevented by this ledger. It is not a substitute for an on-DHT state gate.
    """
    require(type(operation_id) is str and WORK_ID.fullmatch(operation_id),
            "idempotency operation ID must be 8..128 stable ASCII characters")
    require(HASH39.fullmatch(dna) and HASH39.fullmatch(target) and
            DIGEST.fullmatch(packet_sha), "ledger input must be exactly pinned")
    ledger = Path(path).resolve()
    require(ROOT not in ledger.parents and ledger != ROOT and
            not ledger.is_symlink(), "local replay ledger must be outside source checkout")
    ledger.parent.mkdir(parents=True, exist_ok=True)
    old_mask = os.umask(0o077)
    try:
        with sqlite3.connect(str(ledger), timeout=10, isolation_level=None) as db:
            db.execute("PRAGMA busy_timeout = 10000")
            db.execute("PRAGMA synchronous = FULL")
            db.execute("BEGIN IMMEDIATE")
            db.execute("""CREATE TABLE IF NOT EXISTS claims (
                dna TEXT NOT NULL,
                target TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                packet_sha256 TEXT NOT NULL,
                claimed_utc TEXT NOT NULL,
                UNIQUE(dna, target, operation_id),
                UNIQUE(dna, target, packet_sha256)
            )""")
            db.execute(
                "INSERT INTO claims VALUES (?,?,?,?,?)",
                (dna, target, operation_id, packet_sha,
                 dt.datetime.now(dt.timezone.utc).isoformat())
            )
            db.execute("COMMIT")
    except (sqlite3.IntegrityError, sqlite3.OperationalError, OSError) as exc:
        raise Blocked("duplicate/ambiguous local submission or ledger unavailable: " + str(exc)) from exc
    finally:
        os.umask(old_mask)
    return {"locally_claimed": True, "network_wide_replay_prevented": False,
            "same_target_crypto_reuse_still_valid": True,
            "ledger_path": str(ledger)}


def execute(args):
    registry, dossier, review = prepare(args)
    if args.command == "audit":
        return {"status": "CANDIDATE_ONLY", "review": review,
                "release_ready": False}, {}, False
    check_sha(args.expected_sha)
    check_target(args.dna_hex, args.target_hex)
    result = {
        "schema": "hc-vtime/roughtime-sprint23-acceptance/v1",
        "exact_commit_sha": args.expected_sha,
        "dna_hex": args.dna_hex, "target_hex": args.target_hex,
        "registry_sha256": review["registry_sha256"],
        "dossier_sha256": review["dossier_sha256"],
        "review": review, "min_sources": MIN_QUORUM,
        "max_faulty": 1, "max_unavailable": MAX_UNAVAILABLE,
        "cryptographic_quorum": "NOT RUN",
        "operator_independence_proven": False,
        "same_target_cryptographic_freshness_proven": False,
        "network_wide_idempotency_proven": False,
        "release_ready": False,
    }
    files = {}
    try:
        if args.command == "capture":
            effective = registry
            if args.outage_operator:
                effective = make_outage_registry(registry, dossier, args.outage_operator)
                files["outage-registry.json"] = json.dumps(effective, indent=2) + "\n"
            with tempfile.TemporaryDirectory(prefix="hc-vtime-roughtime-") as temp:
                config_path = Path(temp) / "registry.json"
                config_path.write_text(json.dumps(effective), encoding="utf-8")
                live = native_mode("--live", config_path, args.dna_hex,
                                   args.target_hex, timeout=args.timeout_seconds)
            files["native-capture.stderr.log"] = live.stderr
            files["native-capture.stdout.json"] = live.stdout
            result["native_capture_exit"] = live.returncode
            result["outage_operator"] = args.outage_operator
            result["capture_registry_sha256"] = sha_bytes(
                json.dumps(effective, sort_keys=True).encode("utf-8"))
            require(live.stdout.strip(), "Rust client produced no captured signed receipt")
            try:
                receipt = json.loads(live.stdout)
            except json.JSONDecodeError as exc:
                raise Blocked("Rust live capture has no parseable signed receipt") from exc
            receipt_check(receipt, args.dna_hex, args.target_hex)
            files["receipt.json"] = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
            require(live.returncode == 0, "fewer than 3 valid signed live services or invalid quorum")
            # Re-verify the actual stored receipt with the original authenticated
            # trust roots (never the mutated outage endpoint list).
            with tempfile.TemporaryDirectory(prefix="hc-vtime-offline-") as temp:
                receipt_path = Path(temp) / "receipt.json"
                receipt_path.write_text(files["receipt.json"], encoding="utf-8")
                verified, offline = run_verify(
                    args.registry, receipt_path, args.dna_hex, args.target_hex,
                    timeout=args.timeout_seconds)
        else:
            receipt_path = Path(args.receipt)
            receipt = read_json(receipt_path)
            receipt_check(receipt, args.dna_hex, args.target_hex)
            files["receipt.json"] = receipt_path.read_bytes()
            verified, offline = run_verify(args.registry, receipt_path,
                                           args.dna_hex, args.target_hex,
                                           timeout=args.timeout_seconds)
        files["native-verify.stderr.log"] = offline.stderr
        result["native_verification"] = verified
        result["cryptographic_quorum"] = "PASS"
        result["verified_source_count"] = verified["verified_count"]
        result["receipt_sha256"] = sha_bytes(
            files["receipt.json"] if isinstance(files["receipt.json"], bytes)
            else files["receipt.json"].encode("utf-8"))
        if args.command == "consume":
            require(freshness(verified["intervals"], time.time_ns() // 1000,
                              age_seconds=args.max_clock_age_seconds),
                    "verified response interval is stale/future relative to local clock; no security freshness proof")
            result["local_clock_screen"] = "PASS_ASSUMING_TRUSTED_LOCAL_CLOCK"
            result["local_replay_control"] = claim_local_ledger(
                args.ledger, args.dna_hex, args.target_hex,
                args.operation_id, result["receipt_sha256"])
        result["status"] = "CRYPTO_PASS_REVIEW_PENDING" if not review[
            "human_review_records_complete"] else "CRYPTO_PASS_REVIEW_ASSERTIONS_PRESENT"
        return result, files, True
    except (Blocked, subprocess.TimeoutExpired, OSError, ValueError) as exc:
        result["cryptographic_quorum"] = "FAIL"
        result["status"] = "BLOCKED"
        result["reason"] = str(exc)
        return result, files, False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("audit", "capture", "verify", "consume"):
        p = sub.add_parser(command)
        p.add_argument("--registry", type=Path, required=True)
        p.add_argument("--dossier", type=Path, required=True)
        p.add_argument("--expected-registry-sha256", required=True)
        p.add_argument("--report-dir", type=Path, required=command != "audit")
        if command != "audit":
            p.add_argument("--expected-sha", required=True)
            p.add_argument("--dna-hex", required=True)
            p.add_argument("--target-hex", required=True)
            p.add_argument("--timeout-seconds", type=int, default=180)
        if command in ("verify", "consume"):
            p.add_argument("--receipt", type=Path, required=True)
        if command == "capture":
            p.add_argument("--outage-operator",
                           help="simulate this eligible source as unavailable; never lower 3-source quorum")
        if command == "consume":
            p.add_argument("--ledger", type=Path, required=True)
            p.add_argument("--operation-id", required=True)
            p.add_argument("--max-clock-age-seconds", type=int, default=600)
    args = parser.parse_args(argv)
    try:
        if args.command != "audit":
            require(args.timeout_seconds >= 10 and args.timeout_seconds <= 600,
                    "bounded native invocation timeout must be 10..600s")
        report, files, passed = execute(args)
        if args.command != "audit":
            store_report(args.report_dir, report, files)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if (passed or args.command == "audit") else 3
    except (Blocked, OSError, ValueError) as error:
        print(json.dumps({
            "status": "BLOCKED", "reason": str(error),
            "operator_independence_proven": False, "release_ready": False
        }, sort_keys=True))
        return 3


if __name__ == "__main__":
    sys.exit(main())
