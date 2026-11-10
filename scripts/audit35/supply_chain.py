#!/usr/bin/env python3
"""Sprint 35 optional executable supply-chain stages with truthful evidence states.

Generates a separate exact-SHA report outside the repository. A command
exiting zero is only an executed command, NOT a fresh independent security
review; advisory database freshness and license findings require human review.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SCHEMA = "hc-vtime/sprint35-supply-chain-run/v1"
STAGES = (
    ("metadata_workspace", ("cargo", "metadata", "--locked", "--offline", "--format-version", "1"), "cargo"),
    ("metadata_conductor", ("cargo", "metadata", "--locked", "--offline", "--format-version", "1", "--manifest-path", "integration/conductor/Cargo.toml"), "cargo"),
    ("metadata_load", ("cargo", "metadata", "--locked", "--offline", "--format-version", "1", "--manifest-path", "integration/load/Cargo.toml"), "cargo"),
    ("rustsec_workspace", ("cargo", "audit", "--json", "--file", "Cargo.lock"), "cargo-audit"),
    ("rustsec_conductor", ("cargo", "audit", "--json", "--file", "integration/conductor/Cargo.lock"), "cargo-audit"),
    ("rustsec_load", ("cargo", "audit", "--json", "--file", "integration/load/Cargo.lock"), "cargo-audit"),
    ("license_and_source_policy", ("cargo", "deny", "check"), "cargo-deny"),
)


def git(repo: Path, *argv: str) -> str:
    p = subprocess.run(["git", "-C", str(repo), *argv], capture_output=True, timeout=30)
    if p.returncode:
        raise ValueError(f"git {argv[0]} failed")
    return p.stdout.decode().strip()


def sha_file(path: Path) -> str:
    d = hashlib.sha256()
    with path.open("rb") as f:
        for part in iter(lambda: f.read(1024 * 1024), b""):
            d.update(part)
    return d.hexdigest()


def stage(repo: Path, out: Path, name: str, argv: tuple[str, ...], executable: str) -> dict:
    log = out / f"{name}.log"
    if shutil.which(executable) is None:
        return {"status": "NOT RUN", "reason": f"missing {executable}", "command": list(argv)}
    start = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        with log.open("xb") as handle:
            p = subprocess.run(argv, cwd=repo, stdout=handle, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL, timeout=900, check=False)
        status = "PASS" if p.returncode == 0 else "FAIL"
        return {"status": status, "classification": "EXECUTED_COMMAND_ONLY",
                "reason": f"command exit {p.returncode}",
                "started_utc": start, "command": list(argv), "exit_code": p.returncode,
                "log": log.name, "log_sha256": sha_file(log)}
    except subprocess.TimeoutExpired:
        return {"status": "FAIL", "classification": "EXECUTED_TIMEOUT",
                "reason": "900-second execution limit", "command": list(argv),
                "log": log.name, "log_sha256": sha_file(log)}
    except OSError as exc:
        return {"status": "NOT RUN", "classification": "STARTUP_FAILURE",
                "reason": str(exc), "command": list(argv)}


def run(repo: Path, expected: str, out: Path) -> dict:
    if not SHA40.fullmatch(expected):
        raise ValueError("invalid expected SHA")
    repo = repo.resolve(strict=True)
    if git(repo, "rev-parse", "--verify", "HEAD^{commit}") != expected:
        raise ValueError("HEAD differs from expected SHA")
    if git(repo, "rev-parse", "--is-shallow-repository") != "false":
        raise ValueError("shallow Git repo")
    if git(repo, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("dirty source checkout")
    out = out.resolve()
    if out == repo or repo in out.parents or out.exists() or out.is_symlink():
        raise ValueError("report must be a new external directory")
    if not out.parent.is_dir():
        raise ValueError("report parent must already exist")
    out.mkdir(mode=0o700)
    results = {}
    try:
        for name, argv, binary in STAGES:
            results[name] = stage(repo, out, name, argv, binary)
        report = {
            "schema": SCHEMA, "source_commit": expected, "stages": results,
            "lockfiles": ["Cargo.lock", "integration/conductor/Cargo.lock",
                          "integration/load/Cargo.lock"],
            "fuzz_lockfile_assessed": False,
            "advisory_database_freshness_reviewed": False,
            "third_party_source_licenses_reviewed": False,
            "vulnerabilities_independently_assessed": False,
            "production_release_ready": False, "financial_release_allowed": False,
            "release_verdict": "NO-GO",
            "note": "PASS means command executed exit 0, not accepted vulnerability/license findings",
        }
        (out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        files = sorted(f for f in out.iterdir() if f.is_file())
        (out / "SHA256SUMS").write_text(
            "".join(f"{sha_file(f)}  {f.name}\n" for f in files), encoding="ascii"
        )
    except BaseException:
        # A partial directory is not a completed evidence package.
        shutil.rmtree(out)
        raise
    return report


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    p.add_argument("--expected-sha", required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    opts = p.parse_args()
    try:
        result = run(opts.repo, opts.expected_sha, opts.output_dir)
    except (OSError, ValueError, subprocess.TimeoutExpired) as e:
        print(json.dumps({"status": "BLOCKED", "reason": str(e), "release_ready": False}), file=sys.stderr)
        return 3
    statuses = [x["status"] for x in result["stages"].values()]
    summary = {"status": "SCAN_COMMANDS_EXECUTED_NOT_AUDITED" if all(s == "PASS" for s in statuses)
               else "SCAN_INCOMPLETE_OR_FAILED",
               "stages": {k: v["status"] for k, v in result["stages"].items()},
               "release_ready": False}
    print(json.dumps(summary, sort_keys=True))
    return 0 if all(s == "PASS" for s in statuses) else 2


if __name__ == "__main__":
    raise SystemExit(main())
