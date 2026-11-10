#!/usr/bin/env python3
"""Exact-SHA reproducible Sprint 36B metadata, license, source and advisory run."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

from license_inventory import inventory, write_csv
from source_policy import GRAPHS, check_policy_text, inspect_lock, inspect_manifests

SHA = re.compile("[0-9a-f]{40}\\Z")
SCHEMA = "hc-vtime/sprint36b-license-evidence/v1"


def git(root: Path, *args: str) -> str:
    p = subprocess.run(["git", "-C", str(root), *args],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=30)
    if p.returncode:
        raise ValueError(f"git {args[0]} failed")
    return p.stdout.decode().strip()


def digest(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def exec_stage(root: Path, out: Path, label: str, cmd: list[str], tool: str) -> tuple[dict, str | None]:
    if not shutil.which(tool):
        return {"status": "NOT RUN", "reason": f"missing {tool}", "command": cmd}, None
    logfile = out / (label + ".log")
    try:
        p = subprocess.run(cmd, cwd=root, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=900, check=False)
        logfile.write_bytes(p.stdout + b"\n--- STDERR ---\n" + p.stderr)
        result = {"status": "PASS" if p.returncode == 0 else "FAIL",
                  "exit_code": p.returncode, "command": cmd,
                  "log": logfile.name, "log_sha256": digest(logfile)}
        return result, p.stdout.decode(errors="replace") if p.returncode == 0 else None
    except subprocess.TimeoutExpired as exc:
        logfile.write_bytes((exc.stdout or b"") + b"\n--- TIMEOUT ---\n" + (exc.stderr or b""))
        return {"status": "FAIL", "reason": "900-second timeout", "command": cmd,
                "log": logfile.name, "log_sha256": digest(logfile)}, None
    except OSError as exc:
        return {"status": "NOT RUN", "reason": str(exc), "command": cmd}, None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    ap.add_argument("--expected-sha", required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    args = ap.parse_args()
    out = args.output_dir.resolve()
    root = args.repo.resolve(strict=True)
    try:
        if not SHA.fullmatch(args.expected_sha):
            raise ValueError("expected SHA must be full 40 lowercase hex characters")
        if git(root, "rev-parse", "--verify", "HEAD^{commit}") != args.expected_sha:
            raise ValueError("source SHA mismatch")
        if git(root, "rev-parse", "--is-shallow-repository") != "false":
            raise ValueError("shallow clone is not evidence")
        if git(root, "status", "--porcelain", "--untracked-files=all"):
            raise ValueError("source checkout must be clean")
        if out == root or root in out.parents or out.exists():
            raise ValueError("output directory must be new and outside source")
        if not out.parent.is_dir():
            raise ValueError("output parent must exist")
        out.mkdir(mode=0o700)
        errors = check_policy_text((root / "deny.toml").read_text())
        errors.extend(inspect_manifests(root))
        locks = {}
        for lock in GRAPHS:
            contents = (root / lock).read_text()
            locks[lock] = contents
            errors.extend(inspect_lock(contents, lock))
        stages: dict[str, dict] = {}
        all_rows = []
        graph_map = {
            "Cargo.lock": "root",
            "integration/conductor/Cargo.lock": "conductor",
            "integration/load/Cargo.lock": "load",
        }
        for lock, label in graph_map.items():
            manifest = (Path(lock).parent / "Cargo.toml").as_posix()
            if lock == "Cargo.lock":
                manifest = "Cargo.toml"
            stage, payload = exec_stage(root, out, f"metadata_{label}",
                ["cargo", "metadata", "--locked", "--offline",
                 "--all-features", "--format-version", "1",
                 "--manifest-path", manifest], "cargo")
            stages[f"metadata_{label}"] = stage
            if payload is not None:
                try:
                    all_rows.extend(inventory(lock, locks[lock], json.loads(payload)))
                except (KeyError, ValueError, TypeError) as exc:
                    stages[f"metadata_{label}"]["status"] = "FAIL"
                    stages[f"metadata_{label}"]["inventory_error"] = str(exc)
            deny, _ = exec_stage(root, out, f"deny_{label}",
                ["cargo", "deny", "--config", str(root / "deny.toml"),
                 "--manifest-path", manifest, "--locked", "check"], "cargo-deny")
            stages[f"deny_{label}"] = deny
            audit, _ = exec_stage(root, out, f"audit_{label}",
                ["cargo", "audit", "--json", "--file", lock], "cargo-audit")
            stages[f"audit_{label}"] = audit
        metadata_pass = all(stages[f"metadata_{label}"]["status"] == "PASS"
                            for label in graph_map.values())
        if metadata_pass:
            write_csv(out / "inventory-full.csv", all_rows)
        errors = sorted(set(errors))
        if errors:
            (out / "source-policy-findings.json").write_text(
                json.dumps(errors, indent=2) + "\n", encoding="utf-8")
        full_scan_pass = not errors and all(s["status"] == "PASS" for s in stages.values())
        unreviewed = sorted({r["license_review_status"] for r in all_rows
                             if r["license_review_status"] !=
                             "PROPOSED_POLICY_MATCH_APPROVAL_PENDING"})
        if unreviewed:
            errors.append("NONTRIVIAL_LICENSE_EXPRESSIONS_OR_MISSING_METADATA_REQUIRE_REVIEW")
        status = ("TECHNICAL_SCANS_PASS_POLICY_APPROVAL_PENDING" if full_scan_pass and
                  not unreviewed else "INCOMPLETE_OR_FAILED")
        source_unchanged = (git(root, "rev-parse", "--verify", "HEAD^{commit}") ==
                            args.expected_sha and
                            not git(root, "status", "--porcelain", "--untracked-files=all"))
        report = {"schema": SCHEMA, "source_sha": args.expected_sha,
                  "source_unchanged": source_unchanged, "source_policy_findings": errors,
                  "stages": stages, "full_inventory_rows": len(all_rows) if metadata_pass else None,
                  "inventory_complete": metadata_pass,
                  "license_review_flags": unreviewed,
                  "approval": "LICENSE_POLICY_APPROVAL_PENDING",
                  "security_advisories_suppressed": False,
                  "independent_approval_obtained": False,
                  "production_release_ready": False, "release_verdict": "NO-GO",
                  "status": status, "utc": datetime.now(timezone.utc).isoformat()}
        (out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        files = sorted(x for x in out.iterdir() if x.is_file())
        (out / "SHA256SUMS").write_text(
            "".join(f"{digest(f)}  {f.name}\n" for f in files), encoding="ascii")
        print(json.dumps({"status": status, "stages": {k: v["status"] for k, v in stages.items()},
                          "source_unchanged": source_unchanged,
                          "approval": "LICENSE_POLICY_APPROVAL_PENDING", "release": "NO-GO"}))
        return 0 if (full_scan_pass and metadata_pass and not unreviewed
                     and source_unchanged) else 2
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc),
                          "approval": "LICENSE_POLICY_APPROVAL_PENDING",
                          "production_release_ready": False}), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
