#!/usr/bin/env python3
"""Collect sanitized Sprint 25 incident diagnostics (no raw logs or secrets).

Only allowlisted ops-event/v1 records and SHA-256 CONFIG FINGERPRINTS are
collected. No raw registry/config contents, private keys, network addresses,
action hashes, full source identifiers, request/response bytes or environment
variables appear in outputs. The evidence folder is owner-only and immutable
at this tool's level (new path required).
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
from events import (UnsafeEvent, parse_time, read_events, require, safe_json,
                    fingerprint_bytes)
from monitor import read_policy, assess, prometheus

ROOT = Path(__file__).resolve().parents[2]
SHA = re.compile(r"[a-f0-9]{40}\Z")
MAX_EVIDENCE_AGE = timedelta(days=2)
MAX_CONFIG_SIZE = 4 * 1024 * 1024
MAX_EXCERPTS = 500


def commit_id():
    completed = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "--verify", "HEAD"],
        text=True, capture_output=True, timeout=15, check=False,
    )
    require(completed.returncode == 0 and SHA.fullmatch(completed.stdout.strip()),
            "exact checkout SHA unavailable")
    return completed.stdout.strip()


def hash_file(path, max_size=MAX_CONFIG_SIZE):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and
            path.stat().st_size <= max_size,
            "fingerprint input missing, symlinked or over size limit")
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def fingerprint_config(paths):
    require(type(paths) is list and len(paths) <= 8, "at most eight config fingerprints")
    rows = []
    for index, path in enumerate(paths):
        # No configuration contents, basename, full pathname or secret keys
        # leave the machine: only a stable slot number and digest.
        rows.append({"slot": index + 1, "sha256": hash_file(path)})
    return rows


def create_report(events, policy, out, *, source_sha, now=None, fingerprints=None,
                  observed_journal=True):
    now = now or datetime.now(timezone.utc)
    require(now.tzinfo is not None, "report time must be UTC offset aware")
    require(SHA.fullmatch(source_sha), "exact full Git SHA required")
    out = Path(out).resolve()
    require(not out.exists() and ROOT not in out.parents and out != ROOT,
            "diagnostics directory must be new and outside source checkout")
    # Validate all events before creating output. Rejecting malformed and
    # secret-bearing events must not leave partial "success" artifacts.
    from events import validate_event
    for item in events:
        validate_event(item)
    valid = [
        item for item in events
        if now - MAX_EVIDENCE_AGE <= parse_time(item["ts"]) <= now + timedelta(seconds=30)
    ]
    valid = sorted(valid, key=lambda x: (x["ts"], x["id"]))[-MAX_EXCERPTS:]
    snapshot = assess(events, policy, now)
    if not observed_journal:
        snapshot["status"] = "NOT RUN"
        snapshot["missing_signals"].append("operational_events_journal")
    out.mkdir(parents=True, mode=0o700)
    os.chmod(out, 0o700)
    try:
        report = {
            "schema": "hc-vtime/sanitized-diagnostics/v1",
            "status": "SANITIZED_INCOMPLETE" if (
                snapshot["status"] != "HEALTHY") else "SANITIZED",
            "as_of_utc": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "exact_commit_sha": source_sha,
            "operator_independence_proven": False,
            "incident_resolved": False,
            "release_ready": False,
            "telemetry_source_authenticated": False,
            "configuration_fingerprints": fingerprints or [],
            "sanitized_excerpt_count": len(valid),
            "monitor_status": snapshot["status"],
            "monitor_alert_codes": [x["code"] for x in snapshot["alerts"]],
            "sensitive_raw_logs_included": False,
            "raw_config_included": False,
        }
        files = {
            "diagnostics.json": json.dumps(report, indent=2, sort_keys=True) + "\n",
            "monitor.json": json.dumps(snapshot, indent=2, sort_keys=True) + "\n",
            "metrics.prom": prometheus(snapshot),
            "sanitized-events.jsonl": "".join(
                safe_json(event).decode("ascii") for event in valid
            ),
        }
        for name, content in files.items():
            path = out / name
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
            except BaseException:
                # open fd was transferred to fdopen; keep failure visible.
                raise
        sums = [
            f"{hash_file(out / name, 4 * 1024 * 1024)}  {name}"
            for name in sorted(files)
        ]
        (out / "SHA256SUMS").write_text("\n".join(sums) + "\n",
                                        encoding="ascii")
        os.chmod(out / "SHA256SUMS", 0o600)
        return report
    except BaseException:
        # Retain incomplete evidence privately for operator inspection rather
        # than silently converting it to a success report.
        raise


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--events", type=Path, required=True)
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--config-fingerprint", type=Path, action="append", default=[],
                    help="hash a config without copying text or filename")
    ap.add_argument("--expected-sha", required=True)
    ap.add_argument("--output-dir", required=True, type=Path,
                    help="unique new private evidence directory outside repository")
    ap.add_argument("--as-of", help="UTC ISO8601 Z; test fixtures may supply explicit time")
    args = ap.parse_args(argv)
    try:
        require(commit_id() == args.expected_sha,
                "checked-out commit differs from explicitly pinned SHA")
        now = parse_time(args.as_of) if args.as_of else datetime.now(timezone.utc)
        policy = read_policy(args.policy)
        fingerprints = fingerprint_config(
            [args.policy, *args.config_fingerprint]
        )
        observed = args.events.is_file() and not args.events.is_symlink()
        events = read_events(args.events) if observed else []
        report = create_report(
            events, policy, args.output_dir,
            source_sha=args.expected_sha, now=now,
            fingerprints=fingerprints, observed_journal=observed,
        )
        print(json.dumps({
            "status": report["status"],
            "output": str(Path(args.output_dir).resolve()),
            "sanitized_excerpt_count": report["sanitized_excerpt_count"],
            "release_ready": False
        }, sort_keys=True))
        return 0 if report["status"] == "SANITIZED" else 2
    except (UnsafeEvent, OSError, ValueError, KeyError, TypeError) as error:
        # Intentionally output no raw event or configuration bytes.
        print(json.dumps({"status": "BLOCKED", "reason": str(error)}))
        return 3


if __name__ == "__main__":
    sys.exit(main())
