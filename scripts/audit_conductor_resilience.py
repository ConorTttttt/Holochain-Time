#!/usr/bin/env python3
"""Fail-closed audit of Sprint 12 test logs, not an independent CI attestation.

A passing result means the named tests produced explicit success markers and
Rust reported an actual passing test run. It does NOT prove network operator
independence, unrestricted fault injection, or financial safety.
"""
import argparse
import json
import re
import sys
from pathlib import Path

BASELINE = frozenset({
    "durable_before_restart", "offline_conductor", "survivors_continue",
    "missing_witness_rejected", "conflicting_ancestry_rejected",
    "restart_rejoin_and_durable_proofs", "no_bootstrap_missing_proof",
    "peer_discovery_rejoin",
})
LONG = frozenset({"ancestry_255_actions_pass", "ancestry_257_actions_rejected"})
FORK = frozenset({"same_author_fork_untrusted"})


def check_log(path, required):
    problems = []
    try:
        data = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [f"{path.name}: missing/unreadable log: {exc}"], []
    markers = re.findall(r"RESILIENCE_CASE=([a-z0-9_]+):PASS\b", data)
    for name in sorted(required):
        count = markers.count(name)
        if count != 1:
            problems.append(f"{path.name}: expected exactly one PASS for {name}, got {count}")
    if not re.search(r"test result: ok\.\s+[1-9]\d* passed", data):
        problems.append(f"{path.name}: no successful executed Rust test summary")
    if "test result: FAILED" in data or "panicked at" in data:
        problems.append(f"{path.name}: Rust failure/panic recorded")
    return problems, markers


def audit(report, full=False):
    issues = []
    provenance = report / "provenance.txt"
    try:
        meta = provenance.read_text(encoding="utf-8")
    except OSError as exc:
        return {"status": "BLOCKED", "problems": [f"provenance missing: {exc}"],
                "release_ready": False}
    sha = re.findall(r"^commit=([a-f0-9]{40})$", meta, flags=re.M)
    if len(sha) != 1:
        issues.append("provenance: exactly one full commit SHA required")
    if "release_approved=false" not in meta:
        issues.append("provenance missing explicit non-release label")
    for log, required in [("resilience-baseline.log", BASELINE)]:
        p, _ = check_log(report / log, required)
        issues.extend(p)
    if full:
        for log, required in [("resilience-ancestry.log", LONG),
                               ("resilience-fork.log", FORK)]:
            p, _ = check_log(report / log, required)
            issues.extend(p)
    return {
        "status": "BLOCKED" if issues else ("FULL_FIXTURE_PASS" if full else "BASELINE_PASS"),
        "commit": sha[0] if len(sha) == 1 else None,
        "full_fault_injection_requested": full,
        "release_ready": False,
        "physical_network_partition_proven": False,
        "independent_roughtime_operators_proven": False,
        "problems": issues,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", required=True, type=Path)
    ap.add_argument("--require-full", action="store_true")
    args = ap.parse_args()
    result = audit(args.report, args.require_full)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not result["problems"] else 3


if __name__ == "__main__":
    sys.exit(main())
