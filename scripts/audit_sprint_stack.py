#!/usr/bin/env python3
"""Audit PR ancestry before integrating the Holochain-Time sprint stack.

This gate checks *history*, NOT Rust safety, CI, conductor, or Unyt readiness.
It never merges PRs, changes branches, or issues a release approval.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

STACK = (16, 19, 21, 24, 26, 28, 32)
EXIT_BLOCKED = 3


def audit(prs, comparisons):
    """Validate reviewed PR dependency refs and actual GitHub ancestry."""
    findings = []
    evidence = []
    for number in STACK:
        pr = prs.get(str(number))
        if not isinstance(pr, dict):
            findings.append(f"PR #{number}: missing metadata")
            continue
        head = pr.get("head") or {}
        base = pr.get("base") or {}
        if pr.get("state") != "open":
            findings.append(f"PR #{number}: state is not open")
        if not re.fullmatch(r"[a-f0-9]{40}", str(head.get("sha", ""))):
            findings.append(f"PR #{number}: invalid full head SHA")
        if not head.get("ref") or not base.get("ref"):
            findings.append(f"PR #{number}: missing branch reference")
        evidence.append({"pr": number, "head": head.get("ref"), "sha": head.get("sha"),
                         "base": base.get("ref")})
    for parent, child in zip(STACK, STACK[1:]):
        p, c = prs.get(str(parent)), prs.get(str(child))
        key = f"{parent}:{child}"
        if not isinstance(p, dict) or not isinstance(c, dict):
            continue
        parent_ref = (p.get("head") or {}).get("ref")
        child_base = (c.get("base") or {}).get("ref")
        if child_base != parent_ref:
            findings.append(f"PR #{child}: base {child_base!r} is not PR #{parent}'s branch {parent_ref!r}")
        comparison = comparisons.get(key)
        if not isinstance(comparison, dict):
            findings.append(f"PR #{parent} -> #{child}: missing compare result")
            continue
        status = comparison.get("status")
        behind = comparison.get("behind_by")
        if status not in {"ahead", "identical"} or behind != 0:
            findings.append(f"PR #{parent} -> #{child}: {status}, behind_by={behind}; reconciliation required")
    return {"state": "blocked" if findings else "stack_consistent",
            "release_ready": False, "findings": findings, "prs": evidence,
            "note": "Only stacked ancestry is checked; missing CI, conductor, Unyt and audit evidence is NOT evaluated."}


def fetch_live(repo):
    def gh(endpoint):
        return json.loads(subprocess.check_output(["gh", "api", f"repos/{repo}/{endpoint}"],
                                                  stderr=subprocess.PIPE, text=True))
    prs = {str(n): gh(f"pulls/{n}") for n in STACK}
    comparisons = {}
    for parent, child in zip(STACK, STACK[1:]):
        ancestor, descendant = prs[str(parent)]["head"]["sha"], prs[str(child)]["head"]["sha"]
        if not (re.fullmatch(r"[a-f0-9]{40}", str(ancestor)) and
                re.fullmatch(r"[a-f0-9]{40}", str(descendant))):
            raise ValueError(f"PR #{parent} or #{child}: invalid head SHA")
        comparisons[f"{parent}:{child}"] = gh(f"compare/{ancestor}...{descendant}")
    return prs, comparisons


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="ConorTttttt/Holochain-Time")
    parser.add_argument("--fixture", type=Path, help="Offline test input: prs and comparisons JSON")
    parser.add_argument("--output", type=Path, help="Optional report JSON path")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", args.repo):
        parser.error("--repo must be an owner/repo identifier")
    try:
        if args.fixture:
            source = json.loads(args.fixture.read_text(encoding="utf-8"))
            prs, comparisons = source["prs"], source["comparisons"]
            origin = "fixture"
        else:
            prs, comparisons = fetch_live(args.repo)
            origin = "github"
        if not isinstance(prs, dict) or not isinstance(comparisons, dict):
            raise ValueError("Expected maps of PRs and comparisons")
        report = audit(prs, comparisons)
        report["source"] = origin
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"Could not audit PR history: {exc}", file=sys.stderr)
        return 2
    serialised = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(serialised, end="")
    if args.output:
        args.output.write_text(serialised, encoding="utf-8")
    return 0 if report["state"] == "stack_consistent" else EXIT_BLOCKED


if __name__ == "__main__":
    sys.exit(main())
