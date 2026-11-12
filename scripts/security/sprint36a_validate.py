#!/usr/bin/env python3
"""Sprint 36A locked-graph/matrix consistency check; NOT a vulnerability scan.

Requires Python 3.11+. Uses the checked-out Cargo.lock package/edge records.
This tool cannot establish cargo feature resolution, exploitability, upstream
compatibility, license approval, or a green supply-chain gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

LOCKS = (
    "Cargo.lock",
    "integration/conductor/Cargo.lock",
    "integration/load/Cargo.lock",
)
ALLOWED_STATUSES = {
    "PATCHED", "NOT APPLICABLE — REVIEW REQUIRED",
    "RISK ACCEPTANCE REQUIRED", "UNRESOLVED", "NOT VERIFIED",
}
ORIGINAL_IDS = {
    "RUSTSEC-2026-0459", "RUSTSEC-2026-0185", "RUSTSEC-2026-0338",
    "RUSTSEC-2026-0339", "RUSTSEC-2026-0340", "RUSTSEC-2026-0342",
    "RUSTSEC-2026-0344", "RUSTSEC-2026-0367", "RUSTSEC-2026-0368",
    "RUSTSEC-2026-0369", "RUSTSEC-2026-0429",
}
SHA = re.compile(r"[0-9a-f]{40}\Z")


def git_blob_sha(content: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\x00" + content).hexdigest()


def parse_lock(raw: bytes) -> dict[tuple[str, str], list[str]]:
    parsed = tomllib.loads(raw.decode("utf-8"))
    result: dict[tuple[str, str], list[str]] = {}
    for entry in parsed.get("package", []):
        key = (entry["name"], entry["version"])
        if key in result:
            raise ValueError(f"duplicate Cargo.lock package: {key}")
        result[key] = entry.get("dependencies", [])
    return result


def split_node(text: str) -> tuple[str, str]:
    if "@" not in text:
        raise ValueError(f"path node missing @version: {text}")
    name, version = text.rsplit("@", 1)
    if not name or not version:
        raise ValueError(f"invalid path node: {text}")
    return name, version


def dependency_edge_present(
    packages: dict[tuple[str, str], list[str]],
    parent: tuple[str, str],
    child: tuple[str, str],
) -> bool:
    if child not in packages or parent not in packages:
        return False
    for dependency in packages[parent]:
        # Cargo.lock entries are "name" or "name version" when ambiguous.
        words = dependency.split()
        if words[0] == child[0] and (len(words) == 1 or words[1] == child[1]):
            return True
    return False


def check_path(
    packages: dict[tuple[str, str], list[str]], path: list[str],
    expected_name: str, expected_version: str,
) -> None:
    if len(path) < 2:
        raise ValueError("path must show application plus transitive dependency")
    nodes = [split_node(x) for x in path]
    if nodes[0] != ("hc-vtime-conductor-smoke", "0.0.0"):
        raise ValueError("path does not start at the conductor/load application")
    if nodes[-1] != (expected_name, expected_version):
        raise ValueError("path does not end at recorded vulnerable version")
    for a, b in zip(nodes, nodes[1:]):
        if not dependency_edge_present(packages, a, b):
            raise ValueError(f"no Cargo.lock dependency edge: {a} -> {b}")


def check_matrix(repo: Path, matrix: dict) -> dict:
    if matrix["schema"] != "hc-vtime/sprint36a-dependency-vulnerabilities/v1":
        raise ValueError("unknown matrix schema")
    rows = matrix["advisories"]
    ids = [row["advisory_id"] for row in rows]
    if set(ids) != ORIGINAL_IDS or len(ids) != 11:
        raise ValueError("matrix does not uniquely cover the 11 original IDs")
    if matrix["approved_risk_acceptances"]:
        raise ValueError("no signed risk acceptance is documented by this sprint")
    if matrix["release_verdict"] != "NO-GO":
        raise ValueError("security gate must remain NO-GO")
    locks = {}
    for path in LOCKS:
        raw = (repo / path).read_bytes()
        if git_blob_sha(raw) != matrix["lockfile_git_blob_shas"][path]:
            raise ValueError(f"lockfile bytes differ from documented Git blob: {path}")
        locks[path] = parse_lock(raw)
    if any((row["package"], row["original_version"]) in locks["Cargo.lock"] for row in rows):
        raise ValueError("root graph unexpectedly contains an inventoried vulnerable version")
    for row in rows:
        if row["status"] not in ALLOWED_STATUSES:
            raise ValueError(f"invalid status for {row['advisory_id']}")
        if row["status"] == "PATCHED":
            raise ValueError("PATCHED requires independent tested, updated remediation evidence")
        if row["updated_version"] is not None:
            raise ValueError("no tested dependency upgrade is documented")
        if row["functionality_exercised"] != "NOT VERIFIED":
            raise ValueError("runtime reachability must not be assumed from lockfiles")
        if row["dependency_type"] != "transitive":
            raise ValueError("all 11 original findings are transitive")
        for graph in ("conductor", "load"):
            check_path(locks[f"integration/{graph}/Cargo.lock"],
                       row["dependency_paths"][graph],
                       row["package"], row["original_version"])
    return {
        "status": "PASS",
        "classification": "LOCKFILE_AND_MATRIX_CONSISTENCY_ONLY",
        "root_package_count": len(locks["Cargo.lock"]),
        "conductor_package_count": len(locks["integration/conductor/Cargo.lock"]),
        "load_package_count": len(locks["integration/load/Cargo.lock"]),
        "original_advisory_count": len(rows),
        "cargo_audit_run": False,
        "dependency_patch_verified": False,
        "license_approved": False,
        "production_ready": False,
    }


def git_head(repo: Path) -> str | None:
    try:
        p = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--verify", "HEAD"],
            capture_output=True, text=True, check=True, timeout=30,
        )
        head = p.stdout.strip()
        return head if SHA.fullmatch(head) else None
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--matrix", type=Path,
                        default=Path("docs/security/sprint36a_remediation_matrix.json"))
    parser.add_argument("--expected-sha", help="full exact HEAD SHA for Codex evidence")
    parser.add_argument("--output", type=Path, help="write generated report outside git")
    args = parser.parse_args()
    repo = args.repo.resolve()
    actual_head = git_head(repo)
    try:
        if args.expected_sha and (
            not SHA.fullmatch(args.expected_sha) or actual_head != args.expected_sha
        ):
            raise ValueError("HEAD does not equal requested full exact commit SHA")
        matrix_path = args.matrix if args.matrix.is_absolute() else repo / args.matrix
        matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
        result = check_matrix(repo, matrix)
        result["source_commit_sha"] = actual_head
        result["expected_commit_sha"] = args.expected_sha
        result["advisory_database_freshness_verified"] = False
        result["codex_exact_sha_acceptance_completed"] = False
        code = 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as exc:
        result = {"status": "FAIL", "reason": str(exc), "source_commit_sha": actual_head,
                  "production_ready": False}
        code = 2
    out = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        output_path = args.output.resolve()
        if output_path == repo or repo in output_path.parents:
            print("report must be written outside checkout", file=sys.stderr)
            return 2
        output_path.write_text(out, encoding="utf-8")
    print(out, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
