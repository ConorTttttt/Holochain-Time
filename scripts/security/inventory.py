#!/usr/bin/env python3
"""Exact-commit Rust dependency and source-level unsafe inventory.

This is an inventory, NOT a vulnerability scan or a proof that no unsafe
code exists in dependencies, generated code, WASM host, Rhai or C libraries.
Python 3.11+ only (tomllib).
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

ROOT = Path(__file__).resolve().parents[2]
LOCKS = ("Cargo.lock", "integration/conductor/Cargo.lock")
UNSAFE_DECLARATION = re.compile(
    r"\bunsafe\s*(?:\{|fn\b|impl\b|trait\b|extern\b)"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def lock_inventory(path: Path) -> dict:
    with path.open("rb") as file:
        document = tomllib.load(file)
    packages = sorted(
        [
            {
                "name": package["name"],
                "version": package["version"],
                "source": package.get("source", "local"),
                "checksum": package.get("checksum"),
            }
            for package in document.get("package", [])
        ],
        key=lambda pkg: (pkg["name"], pkg["version"], pkg["source"]),
    )
    return {
        "path": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
        "sha256": sha256(path),
        "package_count": len(packages),
        "packages": packages,
    }


def unsafe_source_inventory(path: Path) -> list[dict]:
    findings: list[dict] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        # Single-line comments are excluded; block comments/strings are not
        # lexically parsed, so a finding needs a human review.
        candidate = line.split("//", 1)[0]
        if UNSAFE_DECLARATION.search(candidate):
            findings.append({
                "line": line_number, "code": candidate.strip()[:160]
            })
    return findings


def source_inventory(repo: Path) -> dict:
    command = ["git", "-C", str(repo), "ls-files", "--", "*.rs"]
    tracked = subprocess.check_output(command, text=True).splitlines()
    markers = []
    forbidden = []
    for relative in sorted(tracked):
        path = repo / relative
        if not path.is_file():
            continue
        body = path.read_text(encoding="utf-8")
        if "#![forbid(unsafe_code)]" in body:
            forbidden.append(relative)
        matches = unsafe_source_inventory(path)
        if matches:
            markers.append({"file": relative, "matches": matches})
    return {
        "tracked_rust_files_scanned": len(tracked),
        "files_with_forbid_unsafe_code": forbidden,
        "possible_unsafe_code_declarations": markers,
        "search_method": "line heuristic; may misread block comments, macros or strings",
        "transitive_dependency_unsafe_coverage": False,
    }


def build(repo: Path = ROOT) -> dict:
    sha = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
    ).strip()
    locks = [lock_inventory(repo / item) for item in LOCKS if (repo / item).is_file()]
    return {
        "schema": "hc-vtime-sprint16-inventory-v1",
        "git_commit": sha,
        "locks": locks,
        "sources": source_inventory(repo),
        "cargo_audit_executed": False,
        "vulnerabilities_assessed": False,
        "lockfile_scope": "workspace and standalone Holochain conductor; fuzz crate needs an independently generated lockfile",
        "limitations": [
            "No advisory DB lookup or cargo-audit was executed.",
            "No unsafe code audit of external crates or host libraries.",
            "No generated source, WASM, foreign functions or Rhai audit.",
            "Possible unsafe matches are heuristic, not verified findings.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="write JSON to path outside source tree; otherwise stdout")
    parser.add_argument("--expected-sha", help="abort if working tree HEAD differs")
    args = parser.parse_args()
    report = build()
    if args.expected_sha and report["git_commit"] != args.expected_sha:
        parser.error("unexpected git commit; evidence must match reviewed SHA")
    contents = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.out:
        target = args.out.resolve()
        if target == ROOT or ROOT in target.parents:
            parser.error("inventory must be written outside the repository")
        if target.exists():
            parser.error("refusing to overwrite an existing inventory")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
        print(f"inventory={target} sha256={sha256(target)}")
    else:
        sys.stdout.write(contents)
    return 0


if __name__ == "__main__":
    sys.exit(main())
