#!/usr/bin/env python3
"""Fail-closed Sprint 33 execution auditor. Markers alone never imply release."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

SCHEMA = "hc-vtime/sprint33-recovery-audit/v1"
CHAOS_CASES = frozenset({
    "discovery_isolation_unknown_witness_rejected",
    "delayed_gossip_signed_bounds_available",
    "false_ancestry_and_missing_seal_rejected",
    "restart_rejoin_never_trusts_conflicting_ancestry",
    "unknown_author_health_not_trusted",
})
FORK_BASELINE = frozenset({
    "signed_witness_before_restart",
    "restart_rejoin_preserves_signed_bounds",
    "missing_witness_still_rejected_after_restart",
})
FORK_FULL = frozenset({
    "isolated_same_agent_branches_created",
    "integrated_warrant_against_forked_agent",
    "warrant_blocks_clean_classification",
    "warrant_survives_observer_restart",
    "warranted_author_not_cleared_after_restart",
})
RESILIENCE_CASES = frozenset({
    "durable_before_restart",
    "offline_conductor",
    "survivors_continue",
    "missing_witness_rejected",
    "conflicting_ancestry_rejected",
    "restart_rejoin_and_durable_proofs",
    "no_bootstrap_missing_proof",
    "peer_discovery_rejoin",
})
STEPS = frozenset({
    "python_negative", "workspace_fmt", "conductor_fmt", "workspace_tests",
    "workspace_clippy", "conductor_clippy", "wasm_build",
    "conductor_chaos", "fork_baseline", "prior_resilience",
})


def case_log(path: Path, prefix: str, expected: frozenset[str]) -> tuple[list[str], str]:
    errors = []
    try:
        data = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return [f"{path.name}: unreadable test log: {error}"], ""
    observed = re.findall(rf"^{re.escape(prefix)}=([a-z0-9_]+):PASS$", data, re.M)
    for marker in sorted(expected):
        if observed.count(marker) != 1:
            errors.append(f"{path.name}: marker {marker} count={observed.count(marker)}, expected 1")
    if not re.search(r"test result: ok\.\s+[1-9][0-9]* passed", data):
        errors.append(f"{path.name}: missing executed Rust test PASS summary")
    if re.search(r"test result: FAILED|panicked at|thread '.*' panicked", data):
        errors.append(f"{path.name}: recorded Rust failure/panic")
    return errors, data


def audit(report: Path, require_fork: bool) -> dict:
    problems: list[str] = []
    try:
        provenance = (report / "provenance.txt").read_text()
    except (OSError, UnicodeError) as error:
        provenance = ""
        problems.append(f"missing exact-SHA provenance: {error}")
    sha = re.findall(r"^git_sha=([a-f0-9]{40})$", provenance, re.M)
    if len(sha) != 1:
        problems.append("exactly one full git_sha is required")
    if "release_approved=false" not in provenance:
        problems.append("missing release-approval prohibition")
    if "test_only_signers=true" not in provenance:
        problems.append("missing test-only signing key provenance")
    expected_mode = "full_same_key_fork" if require_fork else "baseline"
    if f"mode={expected_mode}" not in provenance:
        problems.append("runner mode and auditor requirements disagree")

    try:
        rows = (report / "results.tsv").read_text().splitlines()
        if not rows or rows[0] != "step\texit_code":
            problems.append("results.tsv header absent/invalid")
        named = {}
        for row in rows[1:]:
            fields = row.split("\t")
            if len(fields) != 2 or fields[0] in named or not fields[1].isdigit():
                problems.append(f"duplicate or malformed results row: {row}")
                continue
            named[fields[0]] = int(fields[1])
        required = STEPS | ({"fork_injected"} if require_fork else set())
        missing = required - named.keys()
        if missing:
            problems.append("missing mandatory executed steps: " + ", ".join(sorted(missing)))
        if any(code != 0 for code in named.values()):
            problems.append("one or more executed steps returned nonzero")
        if not require_fork and "fork_injected" in named:
            problems.append("fork test logged but report claims baseline mode")
    except (OSError, UnicodeError) as error:
        problems.append(f"results.tsv missing/unreadable: {error}")

    errors, log = case_log(report / "conductor_chaos.log", "CHAOS33_CASE", CHAOS_CASES)
    problems.extend(errors)
    records = []
    for line in log.splitlines():
        marker = "CHAOS33_CONDUCTOR_REPORT "
        if marker in line:
            try:
                records.append(json.loads(line.split(marker, 1)[1]))
            except json.JSONDecodeError:
                problems.append("malformed live conductor JSON metrics")
    if len(records) != 1:
        problems.append("exactly one actual conductor JSON report required")
    else:
        record = records[0]
        expected = {
            "schema": "hc-vtime/sprint33-conductor/v1",
            "real_conductor": True,
            "transport_partition_proven": False,
            "unclean_sigkill_proven": False,
            "database_corruption_recovery_proven": False,
            "delayed_discovery_rejoin": True,
            "signed_bounds_preserved": True,
            "invalid_ancestry_rejected": True,
            "missing_witness_rejected": True,
            "evidence_complete": False,
            "release_approved": False,
        }
        if not isinstance(record, dict) or any(record.get(k) != v for k, v in expected.items()):
            problems.append("conductor report missing required bounded/negative assertions")
    errors, _ = case_log(report / "fork_baseline.log", "FORK_RECOVERY_CASE", FORK_BASELINE)
    problems.extend(errors)
    errors, _ = case_log(report / "prior_resilience.log", "RESILIENCE_CASE", RESILIENCE_CASES)
    problems.extend(errors)
    warrant_count = 0
    if require_fork:
        errors, forklog = case_log(report / "fork_injected.log", "FORK_RECOVERY_CASE", FORK_FULL)
        problems.extend(errors)
        counts = re.findall(r"^FORK_RECOVERY_WARRANT_COUNT=(\d+)$", forklog, re.M)
        if len(counts) != 1 or int(counts[0]) < 1:
            problems.append("no unique positive actual integrated warrant count")
        else:
            warrant_count = int(counts[0])
    return {
        "schema": SCHEMA,
        "status": ("BLOCKED" if problems else
                   "FORK_WARRANT_RESTART_PASS" if require_fork else
                   "REAL_CONDUCTOR_BASELINE_PASS"),
        "git_sha": sha[0] if len(sha) == 1 else None,
        "real_conductor_delayed_discovery_executed": not problems,
        "same_key_integrated_warrant_count": warrant_count if not problems else 0,
        "physical_transport_partition_proven": False,
        "actual_sigkill_recovery_proven": False,
        "database_corruption_recovery_proven": False,
        "global_evidence_completeness_proven": False,
        "release_approved": False,
        "problems": problems,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--require-fork", action="store_true")
    args = parser.parse_args(argv)
    result = audit(args.report, args.require_fork)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not result["problems"] else 3


if __name__ == "__main__":
    sys.exit(main())
