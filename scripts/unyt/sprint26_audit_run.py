#!/usr/bin/env python3
"""Sprint 26 report gate. Passing offline tests never proves funded Unyt execution."""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

STAGES = {
    "python_dependencies", "offline_unittests", "rust_fmt", "rust_harness",
    "workspace_tests", "workspace_clippy", "harness_clippy",
}


REQUIRED_RUST_CASES = {
    "release_pays_only_tranches_the_honest_quorum_proves",
    "release_refuses_tampered_duplicate_and_untrusted_proofs",
    "review_release_counts_only_listed_networks_and_never_confessions",
    "sprint14a_three_release_executions_conserve_deposit_and_chain_locks",
    "sprint14a_bond_slash_and_separate_refund_are_exactly_conservative",
    "bond_refuses_forged_or_foreign_proofs",
    "review_bond_refund_waits_for_the_challenge_period",
    "bond_is_slashed_for_equivocation_but_not_for_honest_statements",
}

def audit(path: Path) -> dict:
    problems = []
    try:
        provenance = (path / "provenance.txt").read_text(encoding="utf-8")
        rows = (path / "results.tsv").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as err:
        return {
            "status": "BLOCKED", "problems": [f"missing input: {err}"],
            "funded_unyt_network_verified": False, "release_ready": False,
        }
    shas = re.findall(r"^git_sha=([0-9a-f]{40})$", provenance, re.M)
    if len(shas) != 1:
        problems.append("exact one Git SHA needed in provenance")
    for marker in ("release_ready=false", "testnet_transactions_performed=false",
                   "native_unyt_peer_verified=false"):
        if marker not in provenance:
            problems.append(f"missing explicit negative gate {marker}")
    results = {}
    for line in rows[1:]:
        pieces = line.split("\t")
        if len(pieces) != 2 or pieces[0] in results:
            problems.append("malformed or duplicate stage row")
            continue
        results[pieces[0]] = pieces[1]
    for stage in STAGES:
        if stage not in results:
            problems.append(f"missing stage {stage}")
        elif results[stage] != "0":
            problems.append(f"failed stage {stage}: {results[stage]}")
    for name in ("offline_unittests", "rust_harness", "workspace_tests"):
        try:
            raw = (path / (name + ".log")).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as err:
            problems.append(f"{name} log missing: {err}")
            continue
        if name == "offline_unittests":
            if not re.search(r"Ran\s+[1-9]\d*\s+tests", raw) or \
                    not re.search(r"^OK\b", raw, re.M) or "skipped=" in raw:
                problems.append("Python signature/adversarial tests not verifiably executed")
        elif not re.search(r"test result: ok\.\s+[1-9]\d* passed", raw):
            problems.append(f"{name} has no executed nonempty Rust passing test summary")
        if name == "rust_harness":
            for test_name in sorted(REQUIRED_RUST_CASES):
                matches = re.findall(
                    r"^test (?:[a-zA-Z0-9_]+::)*" + re.escape(test_name)
                    + r" \.\.\. ok\s*$", raw, re.M
                )
                if len(matches) != 1:
                    problems.append(
                        f"rust_harness missing exactly one executed PASS for {test_name}"
                    )
        if "FAILED" in raw or "panicked at" in raw:
            problems.append(f"{name} failure text present")
    return {
        "schema": "hc-vtime/unyt-sprint26-offline-audit/v1",
        "status": "BLOCKED" if problems else "OFFLINE_SUITE_PASS_NO_FUNDED_UNYT_EVIDENCE",
        "git_sha": shas[0] if len(shas) == 1 else None,
        "funded_unyt_network_verified": False,
        "native_signed_rave_verified": False,
        "recipient_accept_verified": False,
        "testnet_transactions_performed": False,
        "release_ready": False,
        "problems": sorted(problems),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", required=True, type=Path)
    args = ap.parse_args()
    result = audit(args.report)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if not result["problems"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
