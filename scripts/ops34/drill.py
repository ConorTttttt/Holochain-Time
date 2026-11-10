#!/usr/bin/env python3
"""Disposable Sprint 34 incident exercise: safely INJECTED, never real proof.

Uses test-only random HMAC secrets and a throwaway private journal. Runs the
actual authenticated admission, Sprint25 monitor, incident classification
and private alert spool. No Holochain keys, network or production source used.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
from tempfile import TemporaryDirectory

OPS34 = Path(__file__).resolve().parent
ROOT = OPS34.parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
from events import make_event
from ops34.auth import (KEYRING_SCHEMA, UnsafeEvent, append_authenticated,
                        append_supplied, keyring, read_authenticated, sign_frame, ZERO)
from ops34.alerts import (DELIVERY_SCHEMA, assess_authenticated, deliver, load_delivery)
from monitor import read_policy

ROLES = {"source": "roughtime_probe", "oracle": "oracle_runtime",
         "queue": "queue_runtime", "seal": "seal_runtime",
         "observer": "conductor_observer"}
EXPECTED = {
    "time_quorum_unavailable", "time_source_invalid_signature",
    "seal_queue_saturated", "seal_retry_exhausted", "oracle_replay_rejected",
    "conductor_not_recovered", "fork_or_warrant_warrant_observed",
    "unexpected_oracle_signing",
}


def private_json(path: Path, payload: dict):
    data = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise OSError("short private JSON write")
        os.fsync(fd)
    finally:
        os.close(fd)


def exercise(report_dir: Path) -> dict:
    result = {
        "schema": "hc-vtime/ops34-incident-exercise/v1",
        "status": "BLOCKED", "source": "SAFELY_INJECTED_TEST_ONLY",
        "real_runtime_incidents_observed": False,
        "real_fork_warrant_authenticated": False,
        "operator_independence_proven": False,
        "global_evidence_completeness_proven": False,
        "release_ready": False,
    }
    report_dir = report_dir.resolve()
    if report_dir.exists() or ROOT in report_dir.parents or report_dir == ROOT:
        raise ValueError("new incident report directory must be outside repo")
    require_dir = report_dir.parent
    if not require_dir.is_dir() or require_dir.is_symlink() or (
            require_dir.stat().st_mode & 0o077):
        raise ValueError("incident report must have an existing private parent directory")
    report_dir.mkdir(mode=0o700)
    spool = report_dir / "alerts-spool"
    spool.mkdir(mode=0o700)
    with TemporaryDirectory(prefix="vtime-sprint34-drill-") as tmp:
        home = Path(tmp)
        home.chmod(0o700)
        registry = home / "producers.json"
        private_json(registry, {
            "schema": KEYRING_SCHEMA,
            "producers": {name: {"role": role,
                                 "key_hex": secrets.token_hex(32)}
                          for name, role in ROLES.items()}
        })
        keys = keyring(registry)
        journal = home / "authenticated-events.jsonl"
        policy = read_policy(ROOT / "config" / "ops-monitor.example.json")
        delivery_file = home / "delivery.json"
        private_json(delivery_file, {
            "schema": DELIVERY_SCHEMA, "mode": "private_spool",
            "minimum_severity": "WARNING",
            "spool_directory": str(spool),
            "webhook_url": None, "webhook_hmac_key_hex": None
        })
        now = datetime.now(timezone.utc)
        def emit(producer, component, event, status, *, at=None, **fields):
            item = make_event(component, event, status, at=at or now, **fields)
            append_authenticated(journal, keys, producer, item, at=now)
            return item

        # Initial observed signals. These are forged test fixtures with valid
        # TEST HMACs, deliberately NOT actual signed runtime observations.
        for who, component in (("source", "roughtime"),
                               ("oracle", "oracle"), ("observer", "conductor")):
            emit(who, component, "heartbeat", "ok", at=now-timedelta(seconds=10))
        emit("source", "roughtime", "time_source_probe", "ok",
             at=now-timedelta(seconds=10), latency_ms=15)
        emit("source", "roughtime", "quorum_check", "ok",
             at=now-timedelta(seconds=10), available_sources=4, required_sources=3)
        # Persistent conductor restart began before restart grace but after
        # the configured event lookback, with no actual recovery transition.
        emit("observer", "conductor", "conductor", "restarting",
             at=now-timedelta(seconds=140))
        emit("source", "roughtime", "time_source_probe", "invalid_signature",
             at=now+timedelta(seconds=1))
        emit("source", "roughtime", "quorum_check", "unavailable",
             at=now+timedelta(seconds=1), available_sources=2, required_sources=3)
        emit("queue", "queue", "seal_queue", "saturated", queue_depth=8,
             queue_capacity=8)
        emit("queue", "queue", "seal_retry", "exhausted", retry_count=3)
        emit("oracle", "oracle", "oracle_state", "replay_rejected")
        emit("oracle", "oracle", "oracle_sign", "unexpected")
        emit("observer", "dht", "fork_warrant", "warrant_observed")

        rejected_auth_spoofs = 0
        forged = sign_frame("source", 1, ZERO,
                            make_event("roughtime", "heartbeat", "ok", at=now),
                            b"\x01" * 32)
        # Authenticated journal is already non-empty; this frame's MAC (as
        # well as sequence/predecessor) is invalid and must never be accepted.
        try:
            append_supplied(journal, keys, forged, at=now)
        except UnsafeEvent:
            rejected_auth_spoofs += 1
        else:
            raise AssertionError("forged producer was accepted")
        report = assess_authenticated(read_authenticated(journal, keys),
                                      policy, now + timedelta(seconds=2))
        codes = {a["code"] for a in report["alerts"]}
        missing = EXPECTED - codes
        if missing:
            raise AssertionError("injected incident alert missing: " + ",".join(sorted(missing)))
        if report["status"] != "ALERT" or report["release_ready"]:
            raise AssertionError("synthetic severe incidents did not alert")
        delivered = deliver(report, load_delivery(delivery_file))
        if delivered["status"] != "QUEUED":
            raise AssertionError("incident delivery did not write sanitized private spool")
        result.update({
            "status": "INJECTED_INCIDENT_ALERTS_PASS",
            "authenticated_test_frame_count": len(read_authenticated(journal, keys)),
            "injected_alert_codes": sorted(codes),
            "required_injected_alert_codes": sorted(EXPECTED),
            "forged_mac_rejections": rejected_auth_spoofs,
            "actual_external_pager_invoked": False,
            "private_alerts_queued": len(list(spool.glob("alert-*.json"))),
            "producer_hmac_verified_using_test_only_secrets": True,
        })
    private_json(report_dir / "exercise.json", result)
    checksums = {}
    for f in sorted(report_dir.rglob("*")):
        if f.is_file():
            checksums[f.relative_to(report_dir).as_posix()] = hashlib.sha256(f.read_bytes()).hexdigest()
    private_json(report_dir / "checksums.json", checksums)
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report-dir", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        result = exercise(args.report_dir)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, UnsafeEvent, AssertionError) as error:
        print(json.dumps({"schema": "hc-vtime/ops34-incident-exercise/v1",
                          "status": "BLOCKED",
                          "reason": "injected incident exercise failed",
                          "release_ready": False}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
