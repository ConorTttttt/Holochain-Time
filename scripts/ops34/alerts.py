#!/usr/bin/env python3
"""Sprint 34 authenticated operational monitor, incident triage and delivery.

Only verified HMAC frames from an owner-only journal enter Sprint 25's
monitor; raw ops-event/v1 inputs are never accepted on this path. An HMAC
authenticated alarm is still NOT signed Holochain evidence or operator
independence proof. Missing, corrupt or replayed telemetry fails closed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
from urllib.parse import urlsplit

OPS = Path(__file__).resolve().parents[1] / "ops"
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from events import UnsafeEvent, json_unique, parse_time, require
from monitor import read_policy, assess, prometheus
from .auth import keyring, read_authenticated, private_file, canonical

SCHEMA = "hc-vtime/ops34-alert-report/v1"
DELIVERY_SCHEMA = "hc-vtime/ops34-alert-delivery/v1"
SEVERITIES = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def category(code: str) -> tuple[str, str]:
    """Classification is triage for a telemetry CLAIM, not a security proof."""
    if "fork_or_warrant" in code:
        return "potential_dht_integrity_incident", "P0"
    if code in ("oracle_replay_rejected", "oracle_state_corrupt",
                "oracle_state_sequence_conflict",
                "invalid_signature", "time_source_invalid_signature",
                "unauthorized_oracle_signing", "unexpected_oracle_signing"):
        return "possible_signing_integrity_incident", "P0"
    if code in ("time_quorum_unavailable", "verified_outage_margin_exhausted",
                "conductor_not_recovered", "seal_queue_saturated",
                "seal_retry_exhausted", "stalled_seal_queue"):
        return "availability_or_backpressure", "P1"
    if code.startswith(("oracle_state_", "conductor_", "excess_oracle_sign_rate")):
        return "state_recovery_or_signing_anomaly", "P1"
    return "operational_degradation_or_monitoring_gap", "P2"


def assess_authenticated(frames: list[dict], policy: dict,
                         now: datetime | None = None) -> dict:
    """Input MUST be output of read_authenticated (HMAC-verified)."""
    now = now or datetime.now(timezone.utc)
    events = [frame["event"] for frame in frames]
    result = assess(events, policy, now)
    # Preserve Sprint25 status logic, but add two missing oracle runtime alerts
    # that must not silently disappear from the incident classifier.
    source_alerts = {(a["code"], a["source_ref"]) for a in result["alerts"]}
    from events import parse_time
    start = now.timestamp() - policy["window_seconds"]
    extra = []
    for frame in frames:
        row = frame["event"]
        if not start <= parse_time(row["ts"]).timestamp() <= now.timestamp():
            continue
        if row["event"] != "oracle_state":
            continue
        status = row["status"]
        if status not in ("replay_rejected", "recovery"):
            continue
        code = "oracle_replay_rejected" if status == "replay_rejected" else "oracle_state_recovery"
        source_ref = row.get("source_ref")
        if (code, source_ref) not in source_alerts:
            extra.append({"code": code, "severity":
                          "CRITICAL" if status == "replay_rejected" else "WARNING",
                          "source_ref": source_ref, "observed": None,
                          "incident_runbook": "docs/operations/INCIDENT_RESPONSE.md"})
            source_alerts.add((code, source_ref))
    result["alerts"] = sorted(result["alerts"] + extra,
        key=lambda item: (SEVERITIES[item["severity"]], item["code"], item["source_ref"] or ""))
    if extra and result["status"] != "ALERT":
        result["status"] = "ALERT"
    result["schema"] = SCHEMA
    result["producer_hmac_checked"] = True
    result["authenticated_frame_count"] = len(frames)
    result["authenticated_incident_observations_only"] = True
    result["fork_warrants_cryptographically_verified_here"] = False
    result["independent_operator_identity_proven"] = False
    result["global_evidence_completeness_proven"] = False
    result["release_ready"] = False
    result["alerts"] = [
        {**item, "incident_class": category(item["code"])[0],
         "incident_priority": category(item["code"])[1],
         "claim_scope": "authenticated_producer_telemetry_only",
         "requires_independent_security_verification": category(item["code"])[1] == "P0"}
        for item in result["alerts"]
    ]
    return result


def load_delivery(path: Path) -> dict:
    private_file(path)
    require(path.stat().st_size <= 16_384, "delivery config exceeds bounded size")
    data = json.loads(path.read_text(), object_pairs_hook=json_unique)
    require(type(data) is dict and set(data) == {
        "schema", "mode", "minimum_severity", "spool_directory",
        "webhook_url", "webhook_hmac_key_hex"},
        "delivery configuration requires exact keys (no unrecognized secrets)")
    require(data["schema"] == DELIVERY_SCHEMA and
            data["mode"] in ("disabled", "private_spool", "https_webhook") and
            data["minimum_severity"] in SEVERITIES,
            "invalid delivery mode or severity policy")
    mode = data["mode"]
    if mode == "disabled":
        require(data["spool_directory"] is None and data["webhook_url"] is None
                and data["webhook_hmac_key_hex"] is None,
                "disabled delivery cannot retain configured secrets")
    elif mode == "private_spool":
        require(type(data["spool_directory"]) is str and
                data["spool_directory"].startswith("/") and
                data["webhook_url"] is None and data["webhook_hmac_key_hex"] is None,
                "private spool requires only an absolute spool directory")
    else:
        require(data["spool_directory"] is None and
                type(data["webhook_url"]) is str and
                type(data["webhook_hmac_key_hex"]) is str and
                HEX64.fullmatch(data["webhook_hmac_key_hex"]),
                "HTTPS webhook requires URL and separate HMAC delivery secret")
        safe_webhook_target(data["webhook_url"])
    return data


def safe_webhook_target(url: str):
    require(type(url) is str and len(url) <= 512 and
            "\n" not in url and "\r" not in url,
            "invalid webhook URL")
    parsed = urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname and
            parsed.username is None and parsed.password is None and
            parsed.port in (None, 443) and not parsed.fragment,
            "webhook must use HTTPS port 443, no embedded credentials or fragments")
    # Block literal IPs and dotless internal hosts. DNS and egress policy must
    # separately prevent rebinding to private addresses.
    name = parsed.hostname
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise UnsafeEvent("literal-IP webhook destinations forbidden")
    require(re.fullmatch(r"[a-zA-Z0-9.-]{4,253}", name) and
            "." in name and not name.endswith(".local") and
            not name.endswith(".internal"),
            "only reviewed public DNS webhook hostnames permitted")
    return parsed


def alert_batch(report: dict, minimum_severity: str) -> dict | None:
    allowed = [a for a in report["alerts"]
               if SEVERITIES[a["severity"]] <= SEVERITIES[minimum_severity]]
    if not allowed:
        return None
    # Do not export source_ref, timestamps of individual events, raw keys,
    # agent/action/warrant identifiers, arbitrary errors or evidence bytes.
    notices = sorted([{"code": a["code"], "severity": a["severity"],
                      "incident_class": a["incident_class"],
                      "incident_priority": a["incident_priority"]}
                      for a in allowed], key=lambda a: (a["code"], a["severity"]))
    batch = {"schema": "hc-vtime/ops34-alert-batch/v1",
             "as_of_utc": report["as_of_utc"],
             "monitor_status": report["status"],
             "alerts": notices,
             "producer_hmac_checked": True,
             "cryptographic_incident_proof": False,
             "operator_independence_proven": False,
             "release_ready": False}
    require(len(canonical(batch)) <= 16_384, "alert batch exceeds size limit")
    batch["idempotency_key"] = hashlib.sha256(canonical(batch)).hexdigest()
    return batch


def private_spool(directory: Path, message: dict) -> str:
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink() and
            directory.stat().st_uid == os.geteuid() and
            (directory.stat().st_mode & 0o077) == 0,
            "spool must be a pre-created owner-only directory")
    target = directory / ("alert-" + message["idempotency_key"] + ".json")
    payload = canonical(message) + b"\n"
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        private_file(target)
        require(target.read_bytes() == payload,
                "existing alert idempotency key collides with different content")
        return "ALREADY_QUEUED"
    try:
        require(os.write(fd, payload) == len(payload), "short alert spool write")
        os.fsync(fd)
    finally:
        os.close(fd)
    directory_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return "QUEUED"


def send_webhook(url: str, message: dict, secret_hex: str,
                 transport_factory=None) -> str:
    parsed = safe_webhook_target(url)
    body = canonical(message)
    signature = hmac.new(bytes.fromhex(secret_hex), body, hashlib.sha256).hexdigest()
    transport_factory = transport_factory or (
        lambda host: http.client.HTTPSConnection(host, port=443, timeout=5,
                                                  context=ssl.create_default_context()))
    conn = transport_factory(parsed.hostname)
    try:
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        conn.request("POST", path, body=body, headers={
            "Content-Type": "application/json",
            "X-HC-VTime-Alert-SHA256": signature,
            "Idempotency-Key": message["idempotency_key"],
        })
        response = conn.getresponse()
        response.read(512)
        require(200 <= response.status < 300,
                "webhook rejected alert (no automatic unsafe retry)")
        return "DELIVERED_HTTP_2XX"
    finally:
        conn.close()


def deliver(report: dict, config: dict, *, sender=None) -> dict:
    mode = config["mode"]
    if mode == "disabled":
        return {"status": "DISABLED", "alert_notification_sent": False}
    batch = alert_batch(report, config["minimum_severity"])
    if batch is None:
        return {"status": "NO_MATCHING_ALERTS", "alert_notification_sent": False}
    if mode == "private_spool":
        status = private_spool(Path(config["spool_directory"]), batch)
        return {"status": status, "alert_notification_sent": False,
                "private_alert_queued": True}
    send = sender or send_webhook
    status = send(config["webhook_url"], batch, config["webhook_hmac_key_hex"])
    return {"status": status, "alert_notification_sent": True,
            "cryptographic_incident_proof": False}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--keyring", required=True, type=Path)
    ap.add_argument("--journal", required=True, type=Path)
    ap.add_argument("--policy", required=True, type=Path)
    ap.add_argument("--delivery", required=True, type=Path)
    ap.add_argument("--as-of", help="UTC timestamp for deterministic incident drills")
    ap.add_argument("--out", type=Path, help="new private 0600 JSON report")
    ap.add_argument("--metrics", type=Path,
                    help="new private 0600 low-cardinality Prometheus snapshot")
    args = ap.parse_args(argv)
    try:
        keys = keyring(args.keyring)
        frames = read_authenticated(args.journal, keys)
        policy = read_policy(args.policy)
        config = load_delivery(args.delivery)
        now = parse_time(args.as_of) if args.as_of else datetime.now(timezone.utc)
        report = assess_authenticated(frames, policy, now)
        dispatched = deliver(report, config)
        report["alert_delivery"] = dispatched
        for path, payload in (
            (args.out, canonical(report) + b"\n"),
            (args.metrics, prometheus(report).encode("utf-8")),
        ):
            if path is None:
                continue
            require(not path.exists() and not path.is_symlink() and
                    path.parent.is_dir() and
                    path.parent.stat().st_uid == os.geteuid() and
                    (path.parent.stat().st_mode & 0o077) == 0,
                    "new monitoring output must be in a private directory")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                require(os.write(fd, payload) == len(payload),
                        "short monitoring output write")
                os.fsync(fd)
            finally:
                os.close(fd)
        print(json.dumps(report, sort_keys=True))
        return {"HEALTHY": 0, "ALERT": 2, "NOT RUN": 3}[report["status"]]
    except (UnsafeEvent, OSError, ValueError, TypeError, KeyError,
            http.client.HTTPException) as error:
        # No raw webhook URL, keyring content or event material in output.
        print(json.dumps({"schema": SCHEMA, "status": "BLOCKED",
                          "reason": "authenticated telemetry, delivery or policy validation failed",
                          "event_producer_authenticated": False,
                          "release_ready": False}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
