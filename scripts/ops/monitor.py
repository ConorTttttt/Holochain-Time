#!/usr/bin/env python3
"""Sprint 25 bounded ops health evaluation and low-cardinality Prometheus metrics.

Consumes only verified-syntax (NOT cryptographically attested) ops-event/v1.
Do not treat missing telemetry as a healthy service, or untrusted warrant
notifications as authenticated fork evidence. Designed for systemd timer /
Kubernetes CronJob / external alert manager; no external paging is performed.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from events import (EVENTS, COMPONENTS, UnsafeEvent, parse_time, read_events,
                    require, SCHEMA)

POLICY_SCHEMA = "hc-vtime/ops-policy/v1"
SEVERITIES = ("CRITICAL", "WARNING", "INFO")
ALERT_STATES = {"ALERT", "NOT RUN", "HEALTHY"}
NUMBER_POLICIES = {
    "window_seconds": (60, 3600),
    "stale_seconds": (30, 3600),
    "latency_warning_ms": (1, 600_000),
    "queue_depth_warning_percent": (1, 100),
    "retries_warning_at": (1, 100),
    "seal_failures_warning_at": (1, 1000),
    "signing_rate_warning_at": (1, 100_000),
    "restart_grace_seconds": (1, 3600),
}
FIELDS = set(NUMBER_POLICIES) | {
    "schema", "expected_heartbeat_components",
    "authorized_oracle_refs", "oracle_signing_enabled"
}


def read_policy(path: Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    require(type(data) is dict and set(data) == FIELDS and
            data.get("schema") == POLICY_SCHEMA,
            "ops policy missing/unknown fields or schema")
    for key, (low, high) in NUMBER_POLICIES.items():
        value = data[key]
        require(type(value) is int and low <= value <= high,
                f"{key} must be a bounded policy integer")
    require(data["stale_seconds"] >= data["window_seconds"] // 2,
            "heartbeat stale timeout must not mask long monitoring windows")
    require(type(data["oracle_signing_enabled"]) is bool,
            "oracle_signing_enabled must be explicit boolean")
    require(type(data["authorized_oracle_refs"]) is list and
            all(type(ref) is str and len(ref) == 16 and
                all(c in "0123456789abcdef" for c in ref)
                for ref in data["authorized_oracle_refs"]) and
            len(set(data["authorized_oracle_refs"])) ==
            len(data["authorized_oracle_refs"]),
            "authorized oracle references must be distinct 16-hex identities")
    require(type(data["expected_heartbeat_components"]) is list and
            len(data["expected_heartbeat_components"]) > 0 and
            len(set(data["expected_heartbeat_components"])) ==
            len(data["expected_heartbeat_components"]) and
            all(component in COMPONENTS for component in
                data["expected_heartbeat_components"]),
            "at least one unique monitored heartbeat component required")
    return data


def alert(code: str, severity: str, *, source_ref=None, value=None):
    require(severity in SEVERITIES, "invalid alert severity")
    result = {"code": code, "severity": severity,
              "source_ref": source_ref, "observed": value,
              "incident_runbook": "docs/operations/INCIDENT_RESPONSE.md"}
    return result


def assess(events: list[dict], policy: dict, now: datetime | None = None) -> dict:
    from events import validate_event
    now = now or datetime.now(timezone.utc)
    require(now.tzinfo is not None, "as-of time must be offset aware")
    now = now.astimezone(timezone.utc)
    for item in events:
        validate_event(item)
    require(len(events) <= 100_000, "too many events for bounded health evaluation")
    ids = set()
    for item in events:
        require(item["id"] not in ids, "duplicate event ID / possible telemetry replay")
        ids.add(item["id"])
        require(parse_time(item["ts"]) <= now + timedelta(seconds=30),
                "event timestamps exceed allowed clock skew")
    start = now - timedelta(seconds=policy["window_seconds"])
    recent = [event for event in events
              if start <= parse_time(event["ts"]) <= now]
    recent.sort(key=lambda event: (event["ts"], event["id"]))
    alerts = []
    missing = []
    heartbeats = [x for x in events
                  if x["event"] == "heartbeat" and parse_time(x["ts"]) <= now]
    for component in policy["expected_heartbeat_components"]:
        last = max((parse_time(x["ts"]) for x in heartbeats
                    if x["component"] == component), default=None)
        if last is None:
            missing.append("heartbeat:" + component)
            alerts.append(alert("monitoring_gap", "WARNING", value=component))
        elif (now - last).total_seconds() > policy["stale_seconds"]:
            alerts.append(alert("stale_heartbeat", "CRITICAL", value=component))
    if not any(x["event"] == "quorum_check" for x in recent):
        missing.append("quorum_check")
        alerts.append(alert("quorum_telemetry_missing", "WARNING"))
    if not any(x["event"] == "time_source_probe" for x in recent):
        missing.append("time_source_probe")
        alerts.append(alert("source_probe_telemetry_missing", "WARNING"))
    failed_seals = 0
    signers = Counter()
    # IMPORTANT: restart/recovery liveness is NOT limited to the 5-minute
    # rolling metric window. A conductor that restarted six minutes ago but
    # never recovered must stay alerting until an actual recovery is observed.
    restarts: dict[str | None, datetime] = {}
    for item in sorted(
        (x for x in events if parse_time(x["ts"]) <= now
         and x["event"] == "conductor"),
        key=lambda x: (x["ts"], x["id"])
    ):
        source = item.get("source_ref")
        if item["status"] in ("starting", "restarting", "stopped", "failed"):
            restarts[source] = parse_time(item["ts"])
        elif item["status"] in ("running", "recovered"):
            restarts.pop(source, None)
    for event in recent:
        name, state = event["event"], event["status"]
        source = event.get("source_ref")
        if name == "time_source_probe":
            if state != "ok":
                severity = "CRITICAL" if state == "invalid_signature" else "WARNING"
                alerts.append(alert("time_source_" + state, severity, source_ref=source))
            elif event["latency_ms"] >= policy["latency_warning_ms"]:
                alerts.append(alert("roughtime_high_latency", "WARNING",
                                    source_ref=source, value=event["latency_ms"]))
        if name == "quorum_check" and state != "ok":
            alerts.append(alert("time_quorum_unavailable", "CRITICAL",
                                value={"available": event["available_sources"],
                                       "required": event["required_sources"]}))
        if name == "seal_submit" and state != "ok":
            failed_seals += 1
        if name == "seal_queue":
            if state == "saturated" or event["queue_depth"] >= event["queue_capacity"]:
                alerts.append(alert("seal_queue_saturated", "CRITICAL"))
            elif (100 * event["queue_depth"] >=
                  policy["queue_depth_warning_percent"] * event["queue_capacity"]):
                alerts.append(alert("seal_queue_high_depth", "WARNING",
                                    value=event["queue_depth"]))
            if state == "wait_timeout" or (
                    event.get("oldest_wait_ms", 0) >= policy["stale_seconds"] * 1000):
                alerts.append(alert("stalled_seal_queue", "CRITICAL"))
        if name == "seal_retry":
            if state == "exhausted":
                alerts.append(alert("seal_retry_exhausted", "CRITICAL"))
            elif event["retry_count"] >= policy["retries_warning_at"]:
                alerts.append(alert("excessive_seal_retries", "WARNING",
                                    value=event["retry_count"]))
        if name == "signature_validation" and state == "invalid":
            alerts.append(alert("invalid_signature", "CRITICAL", source_ref=source))
        if name == "oracle_sign":
            if state == "unexpected":
                alerts.append(alert("unexpected_oracle_signing", "CRITICAL", source_ref=source))
            if state == "ok":
                signers[source] += event.get("signed_count", 1)
                if (not policy["oracle_signing_enabled"] or
                        source not in policy["authorized_oracle_refs"]):
                    alerts.append(alert("unauthorized_oracle_signing", "CRITICAL",
                                        source_ref=source))
        if name == "oracle_state" and state in ("corrupt", "sequence_conflict",
                                                  "backup_failed"):
            alerts.append(alert("oracle_state_" + state, "CRITICAL", source_ref=source))
        if name == "conductor" and state in (
                "starting", "restarting", "stopped", "failed"):
            alerts.append(alert("conductor_" + state, "WARNING", source_ref=source))
        if name == "fork_warrant":
            alerts.append(alert("fork_or_warrant_" + state, "CRITICAL",
                                source_ref=source))
        if name == "dependency" and state != "ok":
            alerts.append(alert("dependency_" + state,
                                "CRITICAL" if state == "unavailable" else "WARNING",
                                source_ref=source))
    for source, started in restarts.items():
        if (now - started).total_seconds() >= policy["restart_grace_seconds"]:
            alerts.append(alert("conductor_not_recovered", "CRITICAL", source_ref=source))
    for source, count in signers.items():
        if count >= policy["signing_rate_warning_at"]:
            alerts.append(alert("excess_oracle_sign_rate", "CRITICAL",
                                source_ref=source, value=count))
    if failed_seals >= policy["seal_failures_warning_at"]:
        alerts.append(alert("seal_failures_excessive", "WARNING", value=failed_seals))
    # Keep repeat alerts for separate event observations only in counters.
    # In report output only the strongest code+source is shown to avoid a huge
    # leak of per-request event identifiers and log output.
    condensed = {}
    for item in alerts:
        key = (item["code"], item["source_ref"])
        if key not in condensed or SEVERITIES.index(item["severity"]) < (
                SEVERITIES.index(condensed[key]["severity"])):
            condensed[key] = item
    items = sorted(condensed.values(), key=lambda x: (
        SEVERITIES.index(x["severity"]), x["code"], x["source_ref"] or ""))
    # No heartbeats/quorum data is NOT operationally healthy, but absence
    # alone is not evidence that the time service itself has failed.
    missing_codes = {"monitoring_gap", "quorum_telemetry_missing",
                     "source_probe_telemetry_missing"}
    actionable = [x for x in items if x["code"] not in missing_codes]
    if actionable:
        overall = "ALERT"
    elif missing:
        overall = "NOT RUN"
    else:
        overall = "HEALTHY"
    counts = Counter((x["event"], x["status"]) for x in recent)
    signed_probe_latencies = sorted(
        float(x["latency_ms"]) for x in recent
        if x["event"] == "time_source_probe" and
        x["status"] == "ok" and "latency_ms" in x
    )
    def percentile(values, percent):
        if not values:
            return None
        # Nearest-rank percentile, with no fabricated observation for empty inputs.
        import math
        return round(values[max(0, math.ceil(percent * len(values)) - 1)], 3)
    return {
        "schema": "hc-vtime/ops-monitor-report/v1",
        "status": overall,
        "as_of_utc": now.isoformat().replace("+00:00", "Z"),
        "window_seconds": policy["window_seconds"],
        "observed_events": len(recent),
        "missing_signals": missing,
        "alerts": items,
        "event_counts": [
            {"event": k[0], "status": k[1], "count": n}
            for k, n in sorted(counts.items())
        ],
        "metric_window": {
            "seal_success": counts.get(("seal_submit", "ok"), 0),
            "seal_failure": failed_seals,
            "oracle_signatures": sum(signers.values()),
            "roughtime_probe_success": counts.get(("time_source_probe", "ok"), 0),
            "roughtime_probe_failure": sum(n for (e, s), n in counts.items()
                                          if e == "time_source_probe" and s != "ok"),
            "quorum_unavailable": sum(n for (e, s), n in counts.items()
                                      if e == "quorum_check" and s != "ok"),
            "queue_saturation": counts.get(("seal_queue", "saturated"), 0),
            "retry_exhausted": counts.get(("seal_retry", "exhausted"), 0),
            "seal_success_per_second": round(
                counts.get(("seal_submit", "ok"), 0) / policy["window_seconds"], 6),
            "oracle_signed_per_second": round(
                sum(signers.values()) / policy["window_seconds"], 6),
            "roughtime_latency_samples": len(signed_probe_latencies),
            "roughtime_latency_p50_ms": percentile(signed_probe_latencies, 0.50),
            "roughtime_latency_p95_ms": percentile(signed_probe_latencies, 0.95),
            "roughtime_latency_p99_ms": percentile(signed_probe_latencies, 0.99),
        },
        "is_release_approval": False,
        "diagnostic_events_are_authenticated": False,
        "fork_warrants_cryptographically_verified_here": False,
    }


def prometheus(report: dict) -> str:
    """Snapshot windowed counters, NOT globally monotonic Prometheus totals."""
    lines = [
        "# Snapshot counters cover only the configured monitoring window.",
        "# No per-key, per-agent, request or DNA labels to prevent high-cardinality leaks.",
        "# HELP hc_vtime_ops_healthy 1 when active checks exist and no alerts (not release approval)",
        "# TYPE hc_vtime_ops_healthy gauge",
        f"hc_vtime_ops_healthy {int(report['status'] == 'HEALTHY')}",
    ]
    for key, value in sorted(report["metric_window"].items()):
        if value is None:
            # Missing measurement is absent, never misrepresented as 0 ms.
            continue
        lines += [
            f"# TYPE hc_vtime_ops_window_{key} gauge",
            f"hc_vtime_ops_window_{key} {value}",
        ]
    for severity in SEVERITIES:
        lines.append(f'hc_vtime_ops_alerts{{severity="{severity}"}} ' +
                     str(sum(a["severity"] == severity for a in report["alerts"])))
    lines.append(f"hc_vtime_ops_missing_signals {len(report['missing_signals'])}")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--events", required=True, type=Path)
    ap.add_argument("--policy", required=True, type=Path)
    ap.add_argument("--as-of", help="UTC ISO8601 Z; defaults to actual UTC now")
    ap.add_argument("--output", type=Path, help="new JSON output; never overwritten")
    ap.add_argument("--metrics", type=Path, help="new low-cardinality metrics file")
    args = ap.parse_args(argv)
    try:
        policy = read_policy(args.policy)
        now = parse_time(args.as_of) if args.as_of else datetime.now(timezone.utc)
        events = read_events(args.events)
        result = assess(events, policy, now)
        if args.output:
            require(not args.output.exists(), "report output exists; never overwrite")
            args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        if args.metrics:
            require(not args.metrics.exists(), "metrics output exists; never overwrite")
            args.metrics.write_text(prometheus(result), encoding="utf-8")
        print(json.dumps(result, indent=2, sort_keys=True))
        return {"HEALTHY": 0, "ALERT": 2, "NOT RUN": 3}[result["status"]]
    except (UnsafeEvent, OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"status": "BLOCKED", "reason": str(error),
                          "is_release_approval": False}))
        return 3


if __name__ == "__main__":
    sys.exit(main())
