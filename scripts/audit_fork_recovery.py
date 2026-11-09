#!/usr/bin/env python3
"""Sprint 22 fail-closed audit of real conductor logs and warrant evidence.

PASS means the named Holochain tests actually executed successfully.
In particular, no generic zome failure can substitute for a real DHT warrant.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
import sys

BASELINE_MARKERS = frozenset({
    "signed_witness_before_restart",
    "restart_rejoin_preserves_signed_bounds",
    "missing_witness_still_rejected_after_restart",
})
FORK_MARKERS = frozenset({
    "isolated_same_agent_branches_created",
    "integrated_warrant_against_forked_agent",
    "warrant_blocks_clean_classification",
    "warrant_survives_observer_restart",
    "warranted_author_not_cleared_after_restart",
})


def read_case_log(path: Path, markers: frozenset[str]) -> tuple[list[str], str]:
    errors: list[str] = []
    try:
        data = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return [f"{path.name}: no readable executed test log: {error}"], ""
    observed = re.findall(r"FORK_RECOVERY_CASE=([a-z0-9_]+):PASS\b", data)
    for marker in sorted(markers):
        if observed.count(marker) != 1:
            errors.append(
                f"{path.name}: {marker} requires exactly one PASS, got {observed.count(marker)}"
            )
    if not re.search(r"test result: ok\.\s+[1-9][0-9]* passed", data):
        errors.append(f"{path.name}: missing executed Rust test PASS summary")
    if re.search(r"test result: FAILED|panicked at|thread '.*' panicked", data):
        errors.append(f"{path.name}: Rust failure/panic was recorded")
    return errors, data


def audit(report: Path, require_fork: bool) -> dict:
    problems = []
    meta_path = report / "provenance.txt"
    try:
        meta = meta_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return {
            "status": "BLOCKED", "problems": [f"missing provenance: {error}"],
            "warrant_detection_proven": False, "release_approved": False,
        }
    shas = re.findall(r"^git_sha=([a-f0-9]{40})$", meta, re.M)
    if len(shas) != 1:
        problems.append("provenance must contain one full exact SHA")
    if "release_approved=false" not in meta:
        problems.append("provenance missing non-release attestation")
    if "fixture_keys_public=true" not in meta:
        problems.append("provenance missing fixture-only provenance")
    baseline_errors, _ = read_case_log(
        report / "fork-baseline.log", BASELINE_MARKERS
    )
    problems.extend(baseline_errors)
    warrants_proven = False
    if require_fork:
        fork_errors, fork_data = read_case_log(
            report / "fork-injected.log", FORK_MARKERS
        )
        problems.extend(fork_errors)
        counts = re.findall(r"^FORK_RECOVERY_WARRANT_COUNT=(\d+)$", fork_data, re.M)
        if len(counts) != 1 or int(counts[0]) <= 0:
            problems.append(
                "fork-injected.log: require one positive integrated warrant count"
            )
        else:
            warrants_proven = not fork_errors

    results = report / "results.tsv"
    try:
        content = results.read_text(encoding="utf-8")
        rows = [line.split("\t") for line in content.splitlines()[1:] if line]
        mandatory = {"fixture_unit", "fork_baseline", "prior_resilience", "workspace_tests", "clippy"}
        if require_fork:
            mandatory.add("fork_injected")
        seen = {row[0] for row in rows if len(row) == 2}
        missing = mandatory - seen
        if missing:
            problems.append("results.tsv: missing steps " + ", ".join(sorted(missing)))
        for row in rows:
            if len(row) != 2 or not row[1].isdigit() or row[1] != "0":
                problems.append(f"results.tsv: failed or malformed step {row}")
    except (OSError, UnicodeError) as error:
        problems.append(f"results.tsv is missing: {error}")
    return {
        "schema": "hc-vtime-sprint22-audit-v1",
        "status": ("BLOCKED" if problems else
                   "FORK_WARRANT_RESTART_PASS" if require_fork else
                   "BASELINE_ONLY_FORK_NOT_RUN"),
        "git_sha": shas[0] if len(shas) == 1 else None,
        "warrant_detection_proven": warrants_proven,
        "real_conductor_baseline_executed": not baseline_errors,
        "same_agent_fork_requested": require_fork,
        "unclean_crash_recovery_proven": False,
        "physical_network_partition_proven": False,
        "independent_roughtime_operators_proven": False,
        "release_approved": False,
        "problems": problems,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--require-fork", action="store_true")
    args = parser.parse_args()
    result = audit(args.report, args.require_fork)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not result["problems"] else 3


if __name__ == "__main__":
    sys.exit(main())
