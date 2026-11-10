#!/usr/bin/env python3
"""Sprint 28: candidate-source readiness and real UDP one-outage evidence.

Builds on Sprint 23's Rust wire verifier. A successful survey proves that
authenticated responses were observed from configured public keys, NOT that
their operators are independent, that a network stays available, or that a
historical signed response is freshly produced.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import tempfile
import time

sys.dont_write_bytecode = True
import accept as s23

SCHEMA = "hc-vtime/sprint28-source-readiness/v1"
SUPPORTED = {"rfc10049-candidate", "draft15-candidate",
             "rfc10049-live-verified", "draft15-live-verified"}
MAX_EVIDENCE = 256_000


def require(condition, reason):
    s23.require(condition, reason)


def load_sources(args):
    registry, dossier, audit = s23.prepare(args)
    require(type(args.expected_dossier_sha256) is str and
            s23.DIGEST.fullmatch(args.expected_dossier_sha256) and
            s23.digest_file(args.dossier) == args.expected_dossier_sha256,
            "out-of-band dossier SHA-256 pin missing or mismatched")
    require(len(registry["sources"]) == len(dossier["sources"]),
            "missing source review")
    by_root = {s23.decode_key(row["public_key"]).hex(): row
               for row in dossier["sources"]}
    eligible = {}
    for row in registry["sources"]:
        key = s23.decode_key(row["public_key"]).hex()
        review = by_root[key]
        if review["supported_client_protocol"]:
            require(review["protocol_assessment"] in SUPPORTED,
                    "supported flag contradicts protocol compatibility")
            eligible[key] = review["operator_id"]
    require(len(eligible) >= 4, "fewer than four compatible candidate roots")
    return registry, dossier, audit, eligible


def assess_verified(native, eligible, outage_operator=None):
    """Only Rust-verified intervals may count; strings in receipts never count."""
    require(native.get("schema") == "hc-vtime/native-roughtime-verification/v1",
            "no native cryptographic proof")
    intervals = native.get("intervals")
    require(type(intervals) is list and type(native.get("verified_count")) is int
            and native["verified_count"] == len(intervals),
            "native signed source counts do not agree")
    keys = []
    for row in intervals:
        require(type(row) is dict and
                type(row.get("key_hex")) is str and
                bool(re.fullmatch("[0-9a-f]{64}", row["key_hex"])) and
                type(row.get("earliest_us")) is int and
                type(row.get("latest_us")) is int and
                row["earliest_us"] <= row["latest_us"],
                "invalid Rust-verifier interval record")
        keys.append(row["key_hex"])
    require(len(set(keys)) == len(keys), "duplicate cryptographic signer")
    require(native.get("operator_independence_proven") is False and
            native.get("same_target_replay_prevented") is False,
            "native report falsely asserted independence or replay protection")
    unexpected = sorted(set(keys) - eligible.keys())
    require(not unexpected, "signed source not eligible under pinned registry/dossier")
    operators = {eligible[key] for key in keys}
    require(len(operators) == len(keys), "duplicate operator counted twice")
    require(outage_operator is None or outage_operator not in operators,
            "simulated-offline operator unexpectedly signed the outage run")
    return {
        "verified_compatible_roots": len(keys),
        "verified_operator_ids": sorted(operators),
        "three_source_quorum_met": len(keys) >= 3,
        "four_source_outage_margin_met": len(keys) >= 4,
        "operator_independence_proven": False,
    }


def locally_fresh_signed_count(intervals, now_us, age_seconds=600,
                               future_seconds=90):
    """Conservative host-clock availability screen, never crypto freshness."""
    return sum(
        row["latest_us"] >= now_us - age_seconds * 1_000_000 and
        row["earliest_us"] <= now_us + future_seconds * 1_000_000
        for row in intervals
    )


def overall(baseline, outage, expected_outage):
    """Fail closed: four verified before loss AND three verified after loss."""
    base_ops = set(baseline["verified_operator_ids"])
    outage_ops = set(outage["verified_operator_ids"])
    eligible_loss = expected_outage in base_ops
    passed = (baseline["four_source_outage_margin_met"] and
              outage["three_source_quorum_met"] and eligible_loss and
              expected_outage not in outage_ops and
              outage_ops <= base_ops and len(outage_ops) >= 3)
    return {
        "signed_quorum": "PASS" if len(base_ops) >= 3 else "FAIL",
        "one_source_outage_scenario": "PASS" if passed else "FAIL",
        "eligible_baseline_signed_roots": len(base_ops),
        "eligible_outage_signed_roots": len(outage_ops),
        "outage_operator": expected_outage,
        "simulated_outage_only": True,
        "operator_independence_proven": False,
        "release_ready": False,
    }


def one_capture(name, registry, dossier, eligible, dna, target,
                timeout, outage_operator, files):
    effective = (s23.make_outage_registry(registry, dossier, outage_operator)
                 if outage_operator else registry)
    # The precise on-wire acquisition configuration and every failed attempt
    # are preserved, but no credentials or private data are required.
    source_bytes = (json.dumps(effective, sort_keys=True) + "\n").encode()
    files[name + ".capture-registry.json"] = source_bytes
    with tempfile.TemporaryDirectory(prefix="hc-rt28-") as temporary:
        registry_path = Path(temporary) / "capture.json"
        registry_path.write_bytes(source_bytes)
        started = time.monotonic()
        completed = s23.native_mode("--live", registry_path, dna, target,
                                    timeout=timeout)
        elapsed_ms = round((time.monotonic() - started) * 1000, 1)
    files[name + ".stdout.json"] = completed.stdout
    files[name + ".stderr.log"] = completed.stderr
    require(len(completed.stdout.encode()) <= MAX_EVIDENCE,
            "Roughtime capture too large")
    receipt = json.loads(completed.stdout, object_pairs_hook=s23.object_pairs)
    s23.receipt_check(receipt, dna, target)
    files[name + ".receipt.json"] = (json.dumps(receipt, sort_keys=True,
                                               indent=2) + "\n")
    require(completed.returncode == 0,
            name + ": fewer than three cryptographically verified sources")
    # Independently replay EXACT captured bytes through the unchanged Rust
    # verifier using the ORIGINAL pinned signing roots, not outage overrides.
    with tempfile.TemporaryDirectory(prefix="hc-rt28-reverify-") as temporary:
        receipt_path = Path(temporary) / "receipt.json"
        trusted_path = Path(temporary) / "trusted.json"
        receipt_path.write_text(files[name + ".receipt.json"], encoding="utf-8")
        trusted_path.write_text(json.dumps(registry), encoding="utf-8")
        verified, replay = s23.run_verify(trusted_path, receipt_path, dna,
                                          target, timeout=timeout)
    files[name + ".reverify.stderr.log"] = replay.stderr
    require(replay.returncode == 0, "offline native re-verification failed")
    result = assess_verified(verified, eligible, outage_operator)
    result.update({
        "capture_exit_code": completed.returncode,
        "receipt_sha256": s23.sha_bytes(files[name + ".receipt.json"].encode()),
        "elapsed_ms_including_process_and_network": elapsed_ms,
        "native_reverification": "PASS",
        # Only a host-clock screen; cannot establish crypto freshness.
        "local_clock_fresh_signed_roots": locally_fresh_signed_count(
            verified["intervals"], time.time_ns() // 1000),
        "historical_same_target_replay_excluded": False,
    })
    result["local_clock_screen_only"] = (
        result["local_clock_fresh_signed_roots"] ==
        result["verified_compatible_roots"]
    )
    require(result["local_clock_screen_only"],
            name + ": one or more signed sources outside local-clock bounds")
    return result


def execute(args):
    registry, dossier, review, eligible = load_sources(args)
    base = {
        "schema": SCHEMA,
        "status": "CANDIDATE_AUDIT_ONLY" if args.command == "audit" else "BLOCKED",
        "registry_sha256": review["registry_sha256"],
        "dossier_sha256": review["dossier_sha256"],
        "operator_review": review,
        "compatible_candidate_count": len(eligible),
        "three_source_required": 3,
        "one_outage_requires": 4,
        "operator_independence_proven": False,
        "network_wide_replay_prevented": False,
        "release_ready": False,
    }
    if args.command == "audit":
        base.update({
            "protocol_compatibility": "CANDIDATE_ONLY_NOT_PROBED",
            "signed_network_responses": "NOT RUN",
            "one_source_outage_scenario": "NOT RUN",
        })
        return base, {}, True
    s23.check_sha(args.expected_sha)
    s23.check_target(args.dna_hex, args.target_hex)
    require(30 <= args.timeout_seconds <= 600,
            "capture timeout must be 30 to 600 seconds")
    require(args.outage_operator in set(eligible.values()),
            "outage operator must be compatible and in pinned dossier")
    base.update({
        "exact_commit_sha": args.expected_sha,
        "dna_hex": args.dna_hex,
        "target_hex": args.target_hex,
    })
    files = {}
    try:
        baseline = one_capture(
            "baseline", registry, dossier, eligible, args.dna_hex,
            args.target_hex, args.timeout_seconds, None, files)
        base["baseline"] = baseline
        # Deliberately perform a SECOND real UDP capture with one configured
        # endpoint disabled. No replayed baseline receipt can satisfy it.
        outage = one_capture(
            "outage", registry, dossier, eligible, args.dna_hex,
            args.target_hex, args.timeout_seconds, args.outage_operator, files)
        base["outage"] = outage
        base.update(overall(baseline, outage, args.outage_operator))
        require(base["one_source_outage_scenario"] == "PASS",
                "fewer than four baseline and three post-outage verified sources")
        base["status"] = ("CRYPTO_PASS_REVIEW_ASSERTIONS_ONLY" if
                          review["human_review_records_complete"] else
                          "CRYPTO_PASS_HUMAN_REVIEW_PENDING")
        return base, files, True
    except (s23.Blocked, ValueError, OSError, TimeoutError,
            __import__("subprocess").TimeoutExpired) as exc:
        base["status"] = "BLOCKED"
        base["reason"] = str(exc)[:500]
        base["one_source_outage_scenario"] = "FAIL"
        return base, files, False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("audit", "survey"):
        command = commands.add_parser(name)
        command.add_argument("--registry", type=Path, required=True)
        command.add_argument("--dossier", type=Path, required=True)
        command.add_argument("--expected-registry-sha256", required=True)
        command.add_argument("--expected-dossier-sha256", required=True)
        if name == "survey":
            command.add_argument("--expected-sha", required=True)
            command.add_argument("--dna-hex", required=True)
            command.add_argument("--target-hex", required=True)
            command.add_argument("--outage-operator", required=True)
            command.add_argument("--report-dir", type=Path, required=True)
            command.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args(argv)
    try:
        report, evidence, ok = execute(args)
        if args.command == "survey":
            s23.store_report(args.report_dir, report, evidence)
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0 if ok else 3
    except (s23.Blocked, OSError, ValueError, TypeError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)[:500],
                          "operator_independence_proven": False,
                          "release_ready": False}, sort_keys=True))
        return 3


if __name__ == "__main__":
    sys.exit(main())
