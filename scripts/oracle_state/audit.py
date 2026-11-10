#!/usr/bin/env python3
"""Fail-closed Sprint 24 acceptance report. Not an independent security audit.

A run is accepted only when *executed* Rust test names and passing summaries
occur in the exact-commit logs and each mandatory stage had exit status 0.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

REQUIRED = {
    "restart_safety": {
        "normal_restart_preserves_verified_chain_seq_and_highwater",
        "crash_before_signing_fence_allows_exact_prepared_retry",
        "signer_invoked_then_failure_or_uncertain_commit_never_resigns",
        "committed_but_lost_response_resends_exact_signature_without_signing",
        "stateful_verifier_denies_duplicate_signed_seq_and_conflicting_histories",
        "corruption_partial_append_policy_change_and_missing_state_fail_closed",
        "truncated_tail_is_not_silently_ignored_or_replayed",
        "same_identity_cannot_be_opened_by_two_writers_at_once",
        "forged_signature_is_not_durable_or_returned",
    },
    "process_crash": {
        "actual_process_kill_before_signer_fence_allows_retry",
        "actual_process_kill_after_signer_call_blocks_second_signature",
        "actual_process_kill_after_durable_commit_returns_original_receipt",
    },
    "backup_migration": {
        "safe_backup_matches_exact_externally_recorded_checkpoint_and_resumes",
        "rolling_back_a_valid_backup_fails_against_newer_checkpoint",
        "backup_is_blocked_while_a_signed_commit_may_be_in_flight",
    },
}
STAGES = {
    "reporter_tests", "rust_fmt", "restart_safety", "process_crash",
    "backup_migration", "crate_clippy", "workspace_tests", "workspace_clippy",
}


def test_log(path: Path, names: set[str]) -> list[str]:
    problems: list[str] = []
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return [f"{path.name}: unreadable: {error}"]
    for name in sorted(names):
        # Rust output is "test <name> ... ok"; module qualifiers may precede.
        occurrences = re.findall(
            r"^test (?:[a-zA-Z0-9_]+::)*" + re.escape(name) + r" \.\.\. ok\s*$",
            raw, re.M,
        )
        if len(occurrences) != 1:
            problems.append(
                f"{path.name}: expected one executed PASS for {name}, found {len(occurrences)}"
            )
    if not re.search(r"test result: ok\.\s+[1-9]\d* passed", raw):
        problems.append(f"{path.name}: no successful executed Rust test summary")
    if re.search(r"test result: FAILED|panicked at|thread '.*' panicked", raw):
        problems.append(f"{path.name}: panic or failed tests recorded")
    return problems


def audit(report: Path) -> dict:
    errors: list[str] = []
    try:
        provenance = (report / "provenance.txt").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return {"status": "BLOCKED", "problems": [f"provenance unavailable: {error}"],
                "release_ready": False}
    sha = re.findall(r"^git_sha=([a-f0-9]{40})$", provenance, re.M)
    if len(sha) != 1:
        errors.append("exactly one full commit SHA is required")
    for field in ("release_ready=false", "external_rollback_protection_proven=false"):
        if field not in provenance:
            errors.append(f"provenance missing {field}")
    rows: dict[str, str] = {}
    try:
        raw = (report / "results.tsv").read_text(encoding="utf-8")
        for line in raw.splitlines()[1:]:
            columns = line.split("\t")
            if len(columns) != 2 or columns[0] in rows:
                errors.append("missing, duplicate or malformed result row")
                continue
            rows[columns[0]] = columns[1]
    except (OSError, UnicodeError) as error:
        errors.append(f"missing results.tsv: {error}")
    for stage in sorted(STAGES):
        if stage not in rows:
            errors.append(f"missing required stage {stage}")
        elif rows[stage] != "0":
            errors.append(f"{stage}: nonzero exit status {rows[stage]}")
    for stage, names in REQUIRED.items():
        errors.extend(test_log(report / (stage + ".log"), names))
    return {
        "schema": "hc-vtime-sprint24-audit-v1",
        "status": "BLOCKED" if errors else "LOCAL_PERSISTENCE_REGRESSION_PASS",
        "git_sha": sha[0] if len(sha) == 1 else None,
        "durable_state_tests_executed": not errors,
        "signing_runtime_integrated": False,
        "external_rollback_protection_proven": False,
        "real_conductor_signing_integration_proven": False,
        "release_ready": False,
        "problems": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    result = audit(args.report)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if not result["problems"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
