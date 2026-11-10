#!/usr/bin/env python3
"""Construct Sprint 17 reviewed pins from LIVE GitHub PR heads; never merge.

Run only on a clean, fully integrated and committed Codex candidate. This
helper intentionally fails rather than trusting stale PR-head snapshots.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

REPO = "ConorTttttt/Holochain-Time"
BASE_SHA = "cd0fae92929c9c56fc5e6b099ef2ad09ac70c2ad"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
AUTHORITATIVE = (
    (56, "sprint/22-fork-recovery-2026-11-09"),
    (57, "sprint/21-seal-throughput-queue-2026-11-09"),
    (58, "sprint/23-independent-roughtime-acceptance-2026-11-10"),
    (59, "sprint/24-oracle-persistence-restart-2026-11-10"),
    (64, "sprint/25-operations-monitoring-2026-11-10"),
    (63, "sprint/26-unyt-financial-integration-2026-11-10"),
    (65, "sprint/27-combined-acceptance-2026-11-10"),
)
SUPERSEDED = (
    {"pr": 60, "disposition": "reviewed and reconciled into authoritative PR #64; not mandatory"},
    {"pr": 62, "disposition": "alternative reviewed by authoritative PR #63; not mandatory"},
    {"pr": 50, "disposition": "older financial alternative; not mandatory"},
)


def execute(argv: list[str], cwd: Path) -> str:
    p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                       check=False, timeout=90)
    if p.returncode:
        raise ValueError(f"{argv[0]} command failed ({p.returncode}): {p.stderr[:350]}")
    return p.stdout.strip()


def validate_authoritative_pins(manifest: dict, *, candidate: str) -> None:
    if manifest.get("schema") != "hc-vtime/integration-pins/v1":
        raise ValueError("invalid Sprint 17 manifest schema")
    if manifest.get("candidate_sha") != candidate or not SHA40.fullmatch(candidate):
        raise ValueError("candidate SHA mismatch")
    if manifest.get("base") != {"branch": "main", "sha": BASE_SHA}:
        raise ValueError("unexpected original main baseline")
    entries = manifest.get("branches")
    if not isinstance(entries, list) or len(entries) != len(AUTHORITATIVE):
        raise ValueError("exactly seven authoritative PR branch pins required")
    expected = {branch for _, branch in AUTHORITATIVE}
    actual = set()
    for item in entries:
        if not isinstance(item, dict) or set(item) != {"branch", "sha"}:
            raise ValueError("invalid authoritative branch pin entry")
        if item["branch"] in actual or item["branch"] not in expected:
            raise ValueError("missing, duplicated or unauthoritative branch")
        if not isinstance(item["sha"], str) or not SHA40.fullmatch(item["sha"]):
            raise ValueError("invalid full branch-tip SHA")
        actual.add(item["branch"])
    if actual != expected:
        raise ValueError("one or more authoritative sprint branches missing")


def construct_manifest(candidate: str, live_prs: dict, tracking: dict,
                       is_ancestor) -> dict:
    """Pure, fail-closed validation of independently fetched GitHub PR heads."""
    if not isinstance(candidate, str) or not SHA40.fullmatch(candidate):
        raise ValueError("candidate must be full 40-character commit SHA")
    if tracking.get("main") != BASE_SHA or not is_ancestor(BASE_SHA, candidate):
        raise ValueError("main baseline moved or not contained in candidate")
    entries = []
    for number, branch in AUTHORITATIVE:
        pr = live_prs.get(number)
        if not isinstance(pr, dict):
            raise ValueError(f"PR #{number}: GitHub API response missing")
        head = pr.get("head")
        if (pr.get("state") != "open" or not isinstance(head, dict)
                or head.get("ref") != branch
                or not isinstance(head.get("repo"), dict)
                or head["repo"].get("full_name") != REPO
                or not isinstance(head.get("sha"), str)
                or not SHA40.fullmatch(head["sha"])):
            raise ValueError(f"PR #{number}: unexpected live PR identity/head")
        sha = head["sha"]
        if tracking.get(branch) != sha:
            raise ValueError(f"PR #{number}: outdated PR HEAD or stale origin ref")
        if not is_ancestor(sha, candidate):
            raise ValueError(f"PR #{number}: required sprint branch absent from candidate ancestry")
        entries.append({"branch": branch, "sha": sha})
    manifest = {
        "schema": "hc-vtime/integration-pins/v1",
        "candidate_sha": candidate,
        "base": {"branch": "main", "sha": BASE_SHA},
        "branches": entries,
        "review_disposition": list(SUPERSEDED),
    }
    validate_authoritative_pins(manifest, candidate=candidate)
    return manifest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument("--expected-sha", required=True,
                    help="full final integrated HEAD, including all seven PR tips")
    ap.add_argument("--output", required=True, type=Path,
                    help="new reviewed manifest path OUTSIDE Git checkout")
    args = ap.parse_args(argv)
    repo = args.repo.resolve()
    output = args.output.expanduser()
    output = output.parent.resolve() / output.name
    if (not repo.is_dir() or repo in output.parents or output.exists()
            or output.is_symlink()):
        ap.error("repo must exist and output must be new, outside checkout")
    if not SHA40.fullmatch(args.expected_sha):
        ap.error("full lowercase 40-character --expected-sha required")
    if not shutil.which("gh"):
        ap.error("authenticated gh CLI required for LIVE GitHub PR metadata")
    try:
        if execute(["git", "rev-parse", "--verify", "HEAD"], repo) != args.expected_sha:
            raise ValueError("expected SHA differs from candidate HEAD")
        if execute(["git", "status", "--porcelain", "--untracked-files=all"], repo):
            raise ValueError("candidate checkout dirty")
        if execute(["git", "rev-parse", "--is-shallow-repository"], repo) != "false":
            raise ValueError("full Git ancestry required, not shallow checkout")
        # Read current remote refs; never assume PR metadata from a dated document.
        execute(["git", "fetch", "origin", "--prune"], repo)
        prs = {}
        tracking = {}
        for number, branch in AUTHORITATIVE:
            prs[number] = json.loads(execute(
                ["gh", "api", f"repos/{REPO}/pulls/{number}"], repo))
            tracking[branch] = execute(
                ["git", "rev-parse", "--verify", "refs/remotes/origin/" + branch], repo)
        tracking["main"] = execute(
            ["git", "rev-parse", "--verify", "refs/remotes/origin/main"], repo)
        def ancestor(base, candidate):
            p = subprocess.run(["git", "merge-base", "--is-ancestor", base, candidate],
                               cwd=repo, capture_output=True, check=False, timeout=25)
            return p.returncode == 0
        manifest = construct_manifest(args.expected_sha, prs, tracking, ancestor)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as dest:
            json.dump(manifest, dest, indent=2)
            dest.write("\n")
        output.chmod(0o600)
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as exc:
        print(f"PIN GENERATION BLOCKED: {exc}", file=sys.stderr)
        return 3
    print(f"Reviewed exact-PR-head manifest: {output}")
    print("PRs pinned: " + ", ".join("#" + str(n) for n, _ in AUTHORITATIVE))
    print("No merge, rebase, deployment or production authorization performed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
