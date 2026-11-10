#!/usr/bin/env python3
"""Sprint 23 live acceptance: real external UDP into real 3-conductor TimeSeal.

Requires an independently operator-reviewed DNA with the exact root keys and
a locally signed-off source dossier. This only invokes the opt-in Holochain
Sweettest. No production DNA installation, secrets or Unyt payments.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
import accept as gate

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_NEGATIVES = (
    "wrong_target_rejected", "wrong_dna_nonce_rejected",
    "two_source_quorum_rejected", "forged_packet_rejected",
    "duplicate_key_rejected", "same_target_crypto_reuse_permitted",
)


def parse_marker(log, marker):
    objects = []
    for line in log.splitlines():
        if marker in line:
            payload = line.split(marker, 1)[1].strip()
            try:
                objects.append(json.loads(payload))
            except json.JSONDecodeError as exc:
                raise gate.Blocked(f"malformed {marker} payload in actual conductor log") from exc
    gate.require(len(objects) == 1,
                 f"expected exactly one {marker} record, got {len(objects)}")
    return objects[0]


def verify_live_records(log, registry, dossier, dna_sha):
    receipt = parse_marker(log, "HC_RT_RECEIPT ")
    conductor = parse_marker(log, "HC_RT_CONDUCTOR ")
    negative = parse_marker(log, "HC_RT_NEGATIVE ")
    dna = receipt.get("dna_hex")
    target = receipt.get("target_hex")
    gate.check_target(dna, target)
    gate.receipt_check(receipt, dna, target)
    gate.require(
        conductor.get("schema") == "hc-vtime/live-conductor-acceptance/v1" and
        conductor.get("dna_hex") == dna and
        conductor.get("target_hex") == target and
        conductor.get("verified_by_peer") is True and
        conductor.get("operator_independence_proven") is False and
        conductor.get("replay_same_target_prevented_on_chain") is False,
        "conductor attestation incomplete, incorrectly bound or overclaims security"
    )
    gate.require(type(conductor.get("signed_roots")) is int and
                 conductor["signed_roots"] >= 3,
                 "real conductor did not authenticate three independent configured signatures")
    gate.require(
        negative.get("schema") == "hc-vtime/live-roughtime-negative-tests/v1" and
        all(negative.get(field) is True for field in EXPECTED_NEGATIVES),
        "one or more mandatory live conductor negative tests was not executed"
    )
    roots = {gate.decode_key(row["public_key"]).hex()
             for row in registry["sources"]}
    eligible = {
        gate.decode_key(row["public_key"]).hex()
        for row in dossier["sources"] if row["supported_client_protocol"]
    }
    raw_keys = receipt.get("evidence", [])
    gate.require(type(raw_keys) is list and len(raw_keys) >= 3,
                 "receipt contained fewer than three signed responses")
    # Only trust signer keys through the native verifier, not from JSON alone.
    # The outer metadata must nevertheless match the reviewed registry.
    for entry in raw_keys:
        key = entry.get("server_public_key") if isinstance(entry, dict) else None
        gate.require(isinstance(key, list) and len(key) == 32 and
                     all(type(byte) is int and 0 <= byte <= 255 for byte in key),
                     "malformed signed long-term key bytes in receipt")
        encoded = bytes(key).hex()
        gate.require(encoded in roots and encoded in eligible,
                     "unreviewed or incompatible operator key appeared in conductor receipt")
    gate.require(
        len({bytes(x["server_public_key"]).hex() for x in raw_keys}) == len(raw_keys),
        "duplicated signer key in captured conductor packet set"
    )
    return receipt, conductor, negative


def execute(args):
    registry, dossier, review = gate.prepare(args)
    gate.check_sha(args.expected_sha)
    gate.require(args.timeout_seconds >= 60 and args.timeout_seconds <= 7200,
                 "live runtime timeout must be between 60 and 7200s")
    gate.require(review["human_review_records_complete"] or args.allow_candidates,
                 "operator independence dossier has no completed two-reviewer attestations; exploratory runs need explicit --allow-candidates")
    if args.outage_operator:
        gate.make_outage_registry(registry, dossier, args.outage_operator)
    dna = Path(args.dna).resolve(strict=True)
    gate.require(dna.name == "vtime.dna" and dna.is_file() and not dna.is_symlink(),
                 "actual reviewed operator DNA file is required")
    gate.require(ROOT not in dna.parents, "live DNA bundle must be outside Git checkout")
    out = Path(args.report_dir).resolve()
    gate.require(not out.exists() and ROOT not in out.parents and out != ROOT,
                 "evidence directory must be new and outside the source repository")
    report = {
        "schema": "hc-vtime/roughtime-live-conductor/v1",
        "status": "NOT RUN",
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_commit_sha": args.expected_sha,
        "dna_bundle_sha256": gate.digest_file(dna),
        "registry_sha256": review["registry_sha256"],
        "dossier_sha256": review["dossier_sha256"],
        "human_review_assertions_complete": review["human_review_records_complete"],
        "min_sources": 3,
        "max_faulty": 1,
        "max_unavailable": 1,
        "requested_outage_operator": args.outage_operator,
        "operator_independence_proven": False,
        "same_target_cryptographic_freshness_proven": False,
        "network_wide_idempotency_proven": False,
        "production_deployed": False,
        "release_ready": False,
    }
    files = {}
    try:
        env = os.environ.copy()
        env.pop("HC_VTIME_SIGNED_TEST_ONLY", None)
        env.update({
            "HC_VTIME_LIVE_ROUGHTIME": "1",
            "HC_VTIME_LIVE_DNA": str(dna),
            "HC_VTIME_LIVE_OPERATOR_REGISTRY": str(Path(args.registry).resolve()),
        })
        if args.outage_operator:
            # A full operator name or source name matching the Rust registry.
            matching = next(row for row in dossier["sources"]
                            if row["operator_id"] == args.outage_operator)
            env["HC_VTIME_LIVE_OUTAGE_OPERATOR"] = matching["name"]
        else:
            env.pop("HC_VTIME_LIVE_OUTAGE_OPERATOR", None)
        cmd = [
            "cargo", "test", "--locked", "--manifest-path",
            str(ROOT / "integration/conductor/Cargo.toml"),
            "--test", "live_roughtime", "--", "--ignored", "--exact",
            "real_external_three_operator_quorum_and_negative_conductor_checks",
            "--nocapture", "--test-threads=1",
        ]
        run = subprocess.run(cmd, cwd=ROOT, env=env, text=True,
                             capture_output=True, timeout=args.timeout_seconds)
        files["conductor.stdout.log"] = run.stdout
        files["conductor.stderr.log"] = run.stderr
        report["conductor_test_exit"] = run.returncode
        gate.require(run.returncode == 0,
                     "live conductor acceptance test failed; inspect raw Rust logs")
        receipt, conductor, negative = verify_live_records(
            run.stdout, registry, dossier, gate.digest_file(dna)
        )
        report["real_conductor"] = conductor
        report["required_negatives"] = negative
        files["conductor-receipt.json"] = (
            json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        )
        with tempfile.TemporaryDirectory(prefix="sprint23-verify-") as temp:
            receipt_file = Path(temp) / "receipt.json"
            receipt_file.write_text(files["conductor-receipt.json"], encoding="utf-8")
            native, native_result = gate.run_verify(
                args.registry, receipt_file, receipt["dna_hex"], receipt["target_hex"],
                timeout=min(args.timeout_seconds, 600)
            )
        files["native-verify.stderr.log"] = native_result.stderr
        report["native_crypto"] = native
        # Recheck exact authenticated roots and that conductor source count
        # matches the independent offline verifier.
        gate.require(native["nonce_hex"] == receipt["nonce_hex"] and
                     native["verified_count"] == conductor["signed_roots"] and
                     native["verified_count"] == len(receipt["evidence"]),
                     "offline signed interval/nonce is not identical to conductor receipt")
        report["receipt_sha256"] = gate.sha_bytes(
            files["conductor-receipt.json"].encode("utf-8")
        )
        report["status"] = (
            "LIVE_CRYPTO_PASS_REVIEW_ASSERTED" if review["human_review_records_complete"]
            else "LIVE_CRYPTO_PASS_HUMAN_REVIEW_PENDING"
        )
        return report, files, review["human_review_records_complete"]
    except (gate.Blocked, OSError, ValueError, subprocess.TimeoutExpired) as error:
        report["status"] = "BLOCKED"
        report["reason"] = str(error)
        return report, files, False


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--expected-sha", required=True)
    ap.add_argument("--dna", type=Path, required=True)
    ap.add_argument("--registry", type=Path, required=True)
    ap.add_argument("--dossier", type=Path, required=True)
    ap.add_argument("--expected-registry-sha256", required=True)
    ap.add_argument("--outage-operator",
                    help="dossier operator_id of one deliberately excluded source")
    ap.add_argument("--allow-candidates", action="store_true",
                    help="exploratory signed live proof ONLY; never count as independent acceptance")
    ap.add_argument("--report-dir", type=Path, required=True)
    ap.add_argument("--timeout-seconds", type=int, default=1800)
    args = ap.parse_args(argv)
    try:
        report, files, accepted = execute(args)
        gate.store_report(args.report_dir, report, files)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if accepted else 3
    except (gate.Blocked, OSError, ValueError) as error:
        print(json.dumps({"status": "BLOCKED", "reason": str(error),
                          "operator_independence_proven": False,
                          "release_ready": False}, sort_keys=True))
        return 3


if __name__ == "__main__":
    sys.exit(main())
