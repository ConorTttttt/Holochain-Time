#!/usr/bin/env python3
"""Sprints 28–35 exact-live-PR pinning for local Codex candidates (no merges)."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

from integration_validate import check_source

REPO = "ConorTttttt/Holochain-Time"
BASE = "bae1e5b9380e92cbee511e07fea1681011d4d6d0"
SCHEMA = "hc-vtime/integration-pins-28-35/v1"
SCOPE_SCHEMA = "hc-vtime/integration-scope-28-35/v1"
SHA = re.compile(r"[a-f0-9]{40}\Z")
AUTHORITATIVE = (
    (67, "sprint/28-roughtime-source-readiness-2026-11-10"),
    (69, "sprint/29-oracle-runtime-persistence-2026-11-10"),
    (76, "sprint/30-seal-admission-safety-2026-11-10"),
    (68, "sprint31/dht-resource-bounds-agent-u"),
    (71, "sprint/32a-unyt-protocol-native-interface-2026-11-10"),
    (72, "sprint33/conductor-chaos-agent-w"),
    (77, "sprint34/authenticated-monitoring-agent-x"),
    (74, "sprint/35-independent-audit-release-infrastructure-2026-11-10"),
)
EXPECTED = dict(AUTHORITATIVE)


def run(repo: Path, argv: list[str], *, timeout: int = 120) -> str:
    p = subprocess.run(argv, cwd=repo, capture_output=True, text=True,
                       timeout=timeout, check=False)
    if p.returncode:
        raise ValueError(f"{argv[0]} exit {p.returncode}: {p.stderr[:350]}")
    return p.stdout.strip()


def ancestor(repo: Path, earlier: str, later: str) -> bool:
    p = subprocess.run(["git", "merge-base", "--is-ancestor", earlier, later],
                       cwd=repo, capture_output=True, timeout=30, check=False)
    if p.returncode not in (0, 1):
        raise ValueError(f"cannot verify ancestry {earlier} -> {later}")
    return p.returncode == 0


def validate_scope(scope: dict, *, partial_authorized: bool) -> None:
    if not isinstance(scope, dict) or set(scope) != {
            "schema", "mode", "included_prs", "excluded_prs",
            "reviewed_extras", "reviewer", "reviewed_at_utc"}:
        raise ValueError("scope must have exact reviewed fields")
    if scope["schema"] != SCOPE_SCHEMA:
        raise ValueError("wrong scope schema")
    included = scope["included_prs"]
    excluded = scope["excluded_prs"]
    if (not isinstance(included, list) or not included
            or any(type(x) is not int for x in included)
            or len(included) != len(set(included))):
        raise ValueError("scope has invalid/duplicate included PRs")
    if not isinstance(excluded, list):
        raise ValueError("scope excluded_prs must be a list")
    seen = set()
    for item in excluded:
        if (not isinstance(item, dict) or set(item) != {"pr", "reason"}
                or type(item["pr"]) is not int or item["pr"] in seen
                or not isinstance(item["reason"], str) or len(item["reason"].strip()) < 12):
            raise ValueError("excluded PR requires unique PR and substantive review reason")
        seen.add(item["pr"])
    if set(included) & seen or set(included) | seen != set(EXPECTED):
        raise ValueError("scope omits, duplicates or invents an authoritative PR")
    if scope["mode"] == "complete":
        if seen or set(included) != set(EXPECTED):
            raise ValueError("complete scope must include all eight PRs")
    elif scope["mode"] == "reviewed_partial":
        if not partial_authorized or not seen:
            raise ValueError("partial integration requires explicit --allow-partial and exclusions")
    else:
        raise ValueError("unknown scope mode")
    if (not isinstance(scope["reviewer"], str) or not scope["reviewer"].strip()
            or any(token in scope["reviewer"].upper() for token in (
                "REPLACE", "TBD", "UNKNOWN", "<", ">"))
            or not isinstance(scope["reviewed_at_utc"], str)
            or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",
                                scope["reviewed_at_utc"])):
        raise ValueError("scope needs recorded reviewer and UTC review timestamp")
    extras = scope["reviewed_extras"]
    if not isinstance(extras, list):
        raise ValueError("reviewed_extras must be an explicit list (possibly empty)")
    seen = set()
    for item in extras:
        if (not isinstance(item, dict) or set(item) != {"sha", "reason"}
                or not isinstance(item["sha"], str) or not SHA.fullmatch(item["sha"])
                or item["sha"] in seen or not isinstance(item["reason"], str)
                or len(item["reason"].strip()) < 12):
            raise ValueError("integration-only commit requires unique SHA and review reason")
        seen.add(item["sha"])


def construct_manifest(candidate: str, prs: dict, tracking: dict, is_ancestor,
                       scope: dict, extra_commits: list[str], scope_hash: str,
                       *, partial_authorized: bool = False) -> dict:
    """Pure validation: no absent tip, failed branch, or novel input disappears."""
    if not isinstance(candidate, str) or not SHA.fullmatch(candidate):
        raise ValueError("candidate must be exact lowercase 40-hex SHA")
    validate_scope(scope, partial_authorized=partial_authorized)
    if tracking.get("main") != BASE or not is_ancestor(BASE, candidate):
        raise ValueError("origin/main changed or baseline absent from candidate")
    included = set(scope["included_prs"])
    tips = []
    used_sha = set()
    for number, name in AUTHORITATIVE:
        pr = prs.get(number)
        if not isinstance(pr, dict):
            raise ValueError(f"PR #{number}: live GitHub response missing")
        head = pr.get("head")
        base = pr.get("base")
        if (pr.get("state") != "open" or not isinstance(head, dict)
                or not isinstance(base, dict) or base.get("ref") != "main"
                or head.get("ref") != name or not isinstance(head.get("repo"), dict)
                or head["repo"].get("full_name") != REPO
                or not isinstance(head.get("sha"), str) or not SHA.fullmatch(head["sha"])):
            raise ValueError(f"PR #{number}: unexpected PR identity, state, base or HEAD")
        tip = head["sha"]
        if tip in used_sha or tip == BASE:
            raise ValueError(f"PR #{number}: duplicate/invalid input commit")
        used_sha.add(tip)
        if tracking.get(name) != tip:
            raise ValueError(f"PR #{number}: stale/missing origin branch ref")
        if not is_ancestor(BASE, tip):
            raise ValueError(f"PR #{number}: not descended from exact original main")
        contained = is_ancestor(tip, candidate)
        if contained != (number in included):
            raise ValueError(f"PR #{number}: ancestry inconsistent with reviewed scope")
        tips.append({"pr": number, "branch": name, "sha": tip,
                     "included": number in included, "base_is_ancestor": True,
                     "tip_is_candidate_ancestor": contained})
    if (not isinstance(scope_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", scope_hash)
            or not isinstance(extra_commits, list)
            or any(not isinstance(x, str) or not SHA.fullmatch(x) for x in extra_commits)
            or len(set(extra_commits)) != len(extra_commits)):
        raise ValueError("invalid scope hash or integration commit inventory")
    reviewed = {row["sha"] for row in scope["reviewed_extras"]}
    if set(extra_commits) != reviewed or (reviewed & used_sha) or BASE in reviewed:
        raise ValueError("unreviewed, stale, duplicate or unexpected integration-only commits")
    manifest = {
        "schema": SCHEMA, "repository": REPO, "candidate_sha": candidate,
        "base": {"branch": "main", "sha": BASE},
        "scope": scope, "scope_sha256": scope_hash, "branches": tips,
        "integration_only_commits": extra_commits,
        "development_scope_complete": scope["mode"] == "complete",
        "release_ready": False, "review_declaration_independently_authenticated": False,
    }
    validate_manifest(manifest, candidate=candidate, allow_partial=partial_authorized)
    return manifest


def validate_manifest(manifest: dict, *, candidate: str,
                      allow_partial: bool = False) -> None:
    if (not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA
            or manifest.get("repository") != REPO or manifest.get("candidate_sha") != candidate
            or manifest.get("base") != {"branch": "main", "sha": BASE}
            or manifest.get("release_ready") is not False
            or manifest.get("review_declaration_independently_authenticated") is not False):
        raise ValueError("integration manifest identity, baseline or release claim invalid")
    scope = manifest.get("scope")
    validate_scope(scope, partial_authorized=allow_partial)
    rows = manifest.get("branches")
    if not isinstance(rows, list) or len(rows) != len(AUTHORITATIVE):
        raise ValueError("all eight authoritative PR records required even in partial scope")
    for row, (number, branch) in zip(rows, AUTHORITATIVE):
        if (not isinstance(row, dict) or set(row) != {
                "pr", "branch", "sha", "included", "base_is_ancestor",
                "tip_is_candidate_ancestor"} or row["pr"] != number
                or row["branch"] != branch or not isinstance(row["sha"], str)
                or not SHA.fullmatch(row["sha"])
                or type(row["included"]) is not bool or row["base_is_ancestor"] is not True
                or row["tip_is_candidate_ancestor"] is not row["included"]
                or row["included"] != (number in scope["included_prs"])):
            raise ValueError(f"PR #{number}: malformed or inconsistent manifest evidence")
    hashes = [row["sha"] for row in rows]
    extras = manifest.get("integration_only_commits")
    if (len(set(hashes)) != 8 or not isinstance(extras, list)
            or set(extras) != {r["sha"] for r in scope["reviewed_extras"]}
            or len(set(extras)) != len(extras)
            or manifest.get("development_scope_complete") is not (scope["mode"] == "complete")
            or not isinstance(manifest.get("scope_sha256"), str)
            or not re.fullmatch("[a-f0-9]{64}", manifest["scope_sha256"])):
        raise ValueError("duplicate source, unexpected extras, or invalid scope declaration")


def external_path(repo: Path, target: Path, *, must_exist: bool) -> Path:
    if target.is_symlink():
        raise ValueError("external review paths cannot be symlinks")
    resolved = target.expanduser().resolve()
    if repo == resolved or repo in resolved.parents:
        raise ValueError("review scope and outputs MUST be outside source checkout")
    if must_exist:
        if not resolved.is_file() or resolved.stat().st_size > 128_000:
            raise ValueError("reviewed scope is absent or too large")
    elif resolved.exists():
        raise ValueError("output already exists; never overwrite reviewed evidence")
    return resolved


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument("--expected-sha", required=True)
    ap.add_argument("--reviewed-scope", required=True, type=Path,
                    help="reviewer-authored scope JSON OUTSIDE source checkout")
    ap.add_argument("--output", required=True, type=Path,
                    help="new manifest path OUTSIDE source checkout")
    ap.add_argument("--allow-partial", action="store_true",
                    help="explicit consent to reviewed partial candidate; never development-ready")
    args = ap.parse_args(argv)
    try:
        repo = args.repo.resolve(strict=True)
        scope_path = external_path(repo, args.reviewed_scope, must_exist=True)
        output = external_path(repo, args.output, must_exist=False)
        scope_raw = scope_path.read_bytes()
        scope = json.loads(scope_raw)
        validate_scope(scope, partial_authorized=args.allow_partial)
        source = check_source(repo, args.expected_sha)
        if source["status"] != "PASS":
            raise ValueError("unsafe/dirty/shallow/wrong-SHA checkout: " + source["reason"])
        if not shutil.which("gh"):
            raise ValueError("authenticated gh CLI required to verify LIVE PR heads")
        remote = run(repo, ["git", "remote", "get-url", "origin"])
        if remote not in (
                "https://github.com/" + REPO + ".git",
                "https://github.com/" + REPO,
                "git@github.com:" + REPO + ".git",
                "ssh://git@github.com/" + REPO + ".git"):
            raise ValueError("origin does not identify the authoritative repository")
        run(repo, ["git", "fetch", "origin", "--prune"], timeout=600)
        tracking = {"main": run(repo, ["git", "rev-parse", "--verify",
                                        "refs/remotes/origin/main^{commit}"])}
        prs = {}
        for number, branch in AUTHORITATIVE:
            prs[number] = json.loads(run(repo, ["gh", "api", f"repos/{REPO}/pulls/{number}"]))
            tracking[branch] = run(repo, ["git", "rev-parse", "--verify",
                                          f"refs/remotes/origin/{branch}^{{commit}}"])
        # Every candidate-only commit (merge resolution or glue) requires review.
        exclusion_args = ["^" + BASE] + ["^" + tracking[b] for _, b in AUTHORITATIVE]
        extras_raw = run(repo, ["git", "rev-list", "--reverse", args.expected_sha,
                                *exclusion_args])
        extras = extras_raw.splitlines() if extras_raw else []
        manifest = construct_manifest(
            args.expected_sha, prs, tracking, lambda a, b: ancestor(repo, a, b),
            scope, extras, hashlib.sha256(scope_raw).hexdigest(),
            partial_authorized=args.allow_partial)
        # Recheck immediately before writing: remote PRs/refs may move during review.
        for number, branch in AUTHORITATIVE:
            newest = json.loads(run(repo, ["gh", "api", f"repos/{REPO}/pulls/{number}"]))
            if newest.get("head", {}).get("sha") != prs[number]["head"]["sha"]:
                raise ValueError(f"PR #{number}: HEAD moved during pin generation")
        if check_source(repo, args.expected_sha)["status"] != "PASS":
            raise ValueError("source changed while pinning")
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as out:
            json.dump(manifest, out, indent=2, sort_keys=True)
            out.write("\n")
        output.chmod(0o600)
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as exc:
        print(f"SPRINT 28–35 PINS BLOCKED: {exc}", file=sys.stderr)
        return 3
    print(f"Reviewed manifest: {output}; scope={scope['mode']}; PRs checked=8")
    print("No merges, deployments or production release authorization performed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
