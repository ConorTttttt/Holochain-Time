#!/usr/bin/env python3
"""Audit exact-SHA Sprint 34 offline exercise artifacts without reclassifying
safely injected diagnostic incidents as genuine security proof or live alerts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

REQUIRED_STEPS = {"negative_tests", "sprint25_regressions", "shell_syntax", "incident_drill"}
REQUIRED_ALERTS = {
    "time_quorum_unavailable", "time_source_invalid_signature",
    "seal_queue_saturated", "seal_retry_exhausted", "oracle_replay_rejected",
    "conductor_not_recovered", "fork_or_warrant_warrant_observed",
    "unexpected_oracle_signing",
}
REPORT_SCHEMA = "hc-vtime/ops34-acceptance/v1"


def safe_load(path: Path, maximum: int = 128 * 1024):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("missing, symlinked or oversized evidence artifact")
    return json.loads(path.read_text(encoding="utf-8"))


def audit(root: Path) -> dict:
    errors = []
    sha = None
    try:
        meta = (root / "provenance.txt").read_text(encoding="utf-8")
        found = re.findall(r"^git_sha=([0-9a-f]{40})$", meta, re.M)
        if len(found) != 1:
            errors.append("exactly one 40-digit source SHA required")
        else:
            sha = found[0]
        for required in ("mode=injected_test_only", "release_ready=false",
                         "actual_runtime_events_wired=false"):
            if required not in meta:
                errors.append("missing nonproduction provenance marker")
    except (OSError, UnicodeError):
        errors.append("missing provenance")
    try:
        lines = (root / "results.tsv").read_text().splitlines()
        if not lines or lines[0] != "step\texit_code":
            errors.append("invalid results.tsv header")
        rows = {}
        for line in lines[1:]:
            pair = line.split("\t")
            if len(pair) != 2 or pair[0] in rows or not pair[1].isdigit():
                errors.append("duplicate/malformed results.tsv row")
            else:
                rows[pair[0]] = int(pair[1])
        if REQUIRED_STEPS - rows.keys():
            errors.append("required execution steps missing")
        if any(value != 0 for value in rows.values()):
            errors.append("one or more commands failed")
    except (OSError, UnicodeError):
        errors.append("results.tsv missing")
    try:
        drill = safe_load(root / "drill" / "exercise.json")
        required = {
            "schema": "hc-vtime/ops34-incident-exercise/v1",
            "status": "INJECTED_INCIDENT_ALERTS_PASS",
            "source": "SAFELY_INJECTED_TEST_ONLY",
            "real_runtime_incidents_observed": False,
            "real_fork_warrant_authenticated": False,
            "operator_independence_proven": False,
            "global_evidence_completeness_proven": False,
            "release_ready": False,
            "actual_external_pager_invoked": False,
            "forged_mac_rejections": 1,
            "private_alerts_queued": 1,
        }
        if any(drill.get(k) != v for k, v in required.items()):
            errors.append("drill has missing/revised nonproduction provenance")
        if not REQUIRED_ALERTS <= set(drill.get("injected_alert_codes", [])):
            errors.append("not all required injected incidents produced alerts")
        if drill.get("authenticated_test_frame_count", 0) < 10:
            errors.append("insufficient injected authenticated test frames")
        checks = safe_load(root / "drill" / "checksums.json")
        if not isinstance(checks, dict) or not checks:
            errors.append("missing immutable drill checksums")
        else:
            files = {p.relative_to(root / "drill").as_posix()
                     for p in (root / "drill").rglob("*")
                     if p.is_file() and p.name != "checksums.json"}
            if set(checks) != files:
                errors.append("drill checksum manifest missing or has extra files")
            for name, claimed in checks.items():
                if not isinstance(name, str) or "/" in name and ".." in name:
                    errors.append("unsafe drill checksum name")
                    continue
                artifact = root / "drill" / name
                if not artifact.is_file() or artifact.is_symlink() or (
                    hashlib.sha256(artifact.read_bytes()).hexdigest() != claimed
                ):
                    errors.append("drill checksum mismatch")
    except (ValueError, OSError, UnicodeError, TypeError):
        errors.append("drill evidence invalid, absent or not JSON")
    return {
        "schema": REPORT_SCHEMA,
        "status": "BLOCKED" if errors else "INJECTED_INCIDENTS_PASS",
        "exact_git_sha": sha,
        "new_authenticated_journal_implemented": True,
        "safely_injected_incidents_exercised": not errors,
        "real_runtime_alerting_acceptance_proven": False,
        "signed_warrant_proof_verified": False,
        "operator_independence_proven": False,
        "production_release_ready": False,
        "errors": errors,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    result = audit(args.report)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not result["errors"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
