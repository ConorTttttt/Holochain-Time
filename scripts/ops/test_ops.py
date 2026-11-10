"""Sprint 25: deterministic, secret-safe offline monitoring and incident regressions.

Covers all eight local acceptance failure classes with synthetic events. These
unit tests DO NOT claim to have observed a real outage, warrant or restart.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
from events import (UnsafeEvent, append_event, make_event, read_events, reference,
                    safe_json, strict_json, pubkey_ref)
from monitor import assess, prometheus, read_policy
from ingest import import_capture, to_events
from diagnostics import create_report, fingerprint_config

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "config/ops-monitor.example.json"
CLOCK = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)


def at(seconds=0):
    return CLOCK + timedelta(seconds=seconds)


def base_events():
    return [
        make_event(c, "heartbeat", "ok", at=at(-10))
        for c in ("roughtime", "conductor", "oracle")
    ] + [
        make_event("roughtime", "quorum_check", "ok",
                   at=at(-10), available_sources=4, required_sources=3),
        make_event("roughtime", "time_source_probe", "ok",
                   at=at(-10), source_ref=reference("public-source-fixture"),
                   latency_ms=95.0)
    ]


def policy():
    return read_policy(EXAMPLE)


def codes(result):
    return {item["code"] for item in result["alerts"]}


class IncidentCases(unittest.TestCase):
    def test_operational_healthy_requires_fresh_heartbeats_and_quorum(self):
        good = assess(base_events(), policy(), CLOCK)
        self.assertEqual(good["status"], "HEALTHY")
        self.assertEqual(good["missing_signals"], [])
        self.assertEqual(good["metric_window"]["roughtime_latency_p95_ms"], 95.0)
        self.assertEqual(good["metric_window"]["roughtime_latency_samples"], 1)
        missing = assess([], policy(), CLOCK)
        self.assertEqual(missing["status"], "NOT RUN")
        self.assertIn("quorum_check", missing["missing_signals"])
        self.assertIn("heartbeat:conductor", missing["missing_signals"])
        self.assertFalse(missing["is_release_approval"])

    def test_absent_signed_latency_probe_is_not_reported_as_healthy(self):
        events = [x for x in base_events() if x["event"] != "time_source_probe"]
        result = assess(events, policy(), CLOCK)
        self.assertEqual(result["status"], "NOT RUN")
        self.assertIn("time_source_probe", result["missing_signals"])
        self.assertIsNone(result["metric_window"]["roughtime_latency_p95_ms"])
        self.assertNotIn("hc_vtime_ops_window_roughtime_latency_p95_ms",
                         prometheus(result))

    def test_failed_source_and_high_latency_are_visible(self):
        record = base_events()
        ref = reference("public-operator-alpha")
        record.append(make_event("roughtime", "time_source_probe", "timeout",
                                 at=at(-4), source_ref=ref))
        record.append(make_event("roughtime", "time_source_probe", "ok",
                                 at=at(-3), source_ref=reference("operator-beta"),
                                 latency_ms=3500.0))
        outcome = assess(record, policy(), CLOCK)
        self.assertEqual(outcome["status"], "ALERT")
        self.assertIn("time_source_timeout", codes(outcome))
        self.assertIn("roughtime_high_latency", codes(outcome))
        self.assertEqual(next(a for a in outcome["alerts"]
                         if a["code"] == "time_source_timeout")["source_ref"], ref)

    def test_no_quorum_is_critical_without_two_source_downgrade(self):
        events = base_events()
        events.append(make_event("roughtime", "quorum_check", "unavailable",
                                 at=at(-2), available_sources=2, required_sources=3))
        result = assess(events, policy(), CLOCK)
        self.assertIn("time_quorum_unavailable", codes(result))
        self.assertIn("CRITICAL", {a["severity"] for a in result["alerts"]})
        with self.assertRaises(UnsafeEvent):
            make_event("roughtime", "quorum_check", "ok",
                       at=CLOCK, available_sources=2, required_sources=3)
        with self.assertRaises(UnsafeEvent):
            make_event("roughtime", "quorum_check", "ok",
                       at=CLOCK, available_sources=2, required_sources=2)

    def test_seal_queue_saturation_and_stall(self):
        events = base_events() + [
            make_event("queue", "seal_queue", "saturated", at=at(-3),
                       queue_depth=256, queue_capacity=256, oldest_wait_ms=210000),
        ]
        result = assess(events, policy(), CLOCK)
        self.assertIn("seal_queue_saturated", codes(result))
        self.assertIn("stalled_seal_queue", codes(result))
        self.assertEqual(result["metric_window"]["queue_saturation"], 1)

    def test_retries_and_real_seal_failures(self):
        events = base_events() + [
            make_event("queue", "seal_retry", "head_moved", at=at(-5), retry_count=4),
            make_event("queue", "seal_retry", "exhausted", at=at(-4), retry_count=8),
        ] + [
            make_event("seal", "seal_submit", "failed", at=at(-i-1))
            for i in range(5)
        ]
        result = assess(events, policy(), CLOCK)
        self.assertIn("excessive_seal_retries", codes(result))
        self.assertIn("seal_retry_exhausted", codes(result))
        self.assertIn("seal_failures_excessive", codes(result))
        self.assertEqual(result["metric_window"]["seal_failure"], 5)

    def test_invalid_signatures_and_suspicious_signing(self):
        source = reference("public-approved-key-1")
        events = base_events() + [
            make_event("roughtime", "signature_validation", "invalid",
                       at=at(-7), source_ref=source),
            make_event("oracle", "oracle_sign", "ok", at=at(-6), source_ref=source),
            make_event("oracle", "oracle_sign", "unexpected", at=at(-5),
                       source_ref=source),
            make_event("oracle", "oracle_state", "sequence_conflict", at=at(-4),
                       source_ref=source),
        ]
        result = assess(events, policy(), CLOCK)
        for code in ("invalid_signature", "unauthorized_oracle_signing",
                     "unexpected_oracle_signing", "oracle_state_sequence_conflict"):
            self.assertIn(code, codes(result))
        self.assertEqual(result["metric_window"]["oracle_signatures"], 1)

    def test_excessive_oracle_signing_even_with_approved_signer(self):
        src = reference("authorized-public-oracle-alpha")
        p = policy()
        p["oracle_signing_enabled"] = True
        p["authorized_oracle_refs"] = [src]
        p["signing_rate_warning_at"] = 10
        events = base_events() + [
            make_event("oracle", "oracle_sign", "ok", at=at(-i-1),
                       source_ref=src, signed_count=1)
            for i in range(10)
        ]
        result = assess(events, p, CLOCK)
        self.assertIn("excess_oracle_sign_rate", codes(result))
        self.assertNotIn("unauthorized_oracle_signing", codes(result))

    def test_conductor_restart_alert_and_recovery(self):
        machine = reference("local-conductor-alpha")
        before = base_events() + [
            make_event("conductor", "conductor", "restarting",
                       at=at(-125), source_ref=machine)
        ]
        alerting = assess(before, policy(), CLOCK)
        self.assertIn("conductor_not_recovered", codes(alerting))
        recovered = before + [
            make_event("conductor", "conductor", "recovered",
                       at=at(-20), source_ref=machine)
        ]
        restored = assess(recovered, policy(), CLOCK)
        self.assertNotIn("conductor_not_recovered", codes(restored))
        self.assertIn("conductor_restarting", codes(restored))

    def test_stalled_restart_never_disappears_after_metric_window(self):
        src = reference("local-conductor-stalled-for-seven-minutes")
        events = base_events() + [
            make_event("conductor", "conductor", "restarting",
                       at=at(-420), source_ref=src)
        ]
        alerting = assess(events, policy(), CLOCK)
        self.assertIn("conductor_not_recovered", codes(alerting))
        recovered = events + [
            make_event("conductor", "conductor", "recovered",
                       at=at(-2), source_ref=src)
        ]
        self.assertNotIn("conductor_not_recovered",
                         codes(assess(recovered, policy(), CLOCK)))

    def test_fork_warrant_and_dependency_outage(self):
        events = base_events() + [
            make_event("conductor", "fork_warrant", "warrant_observed",
                       at=at(-2), source_ref=reference("suspected-agent")),
            make_event("dht", "dependency", "unavailable", at=at(-3)),
            make_event("storage", "oracle_state", "corrupt", at=at(-4)),
        ]
        result = assess(events, policy(), CLOCK)
        self.assertIn("fork_or_warrant_warrant_observed", codes(result))
        self.assertIn("dependency_unavailable", codes(result))
        self.assertIn("oracle_state_corrupt", codes(result))
        self.assertFalse(result["fork_warrants_cryptographically_verified_here"])

    def test_stale_heartbeat_is_not_healthy(self):
        events = base_events()
        events = [x for x in events if not (
            x["event"] == "heartbeat" and x["component"] == "conductor"
        )]
        events.append(make_event("conductor", "heartbeat", "ok", at=at(-300)))
        result = assess(events, policy(), CLOCK)
        self.assertEqual(result["status"], "ALERT")
        self.assertIn("stale_heartbeat", codes(result))

    def test_future_timestamp_or_duplicate_event_id_rejected(self):
        events = base_events()
        with self.assertRaises(UnsafeEvent):
            assess(events + [events[0]], policy(), CLOCK)
        with self.assertRaises(UnsafeEvent):
            assess(events + [make_event("oracle", "heartbeat", "ok",
                                         at=at(45))], policy(), CLOCK)


class RedactionAndAdapterTests(unittest.TestCase):
    def test_unknown_secret_fields_and_long_freeform_strings_rejected(self):
        with self.assertRaises(UnsafeEvent):
            make_event("oracle", "oracle_sign", "ok", at=CLOCK,
                       source_ref=reference("operator"),
                       private_key="never-publish")
        with self.assertRaises(UnsafeEvent):
            make_event("seal", "seal_submit", "failed", at=CLOCK,
                       exception_text="secret packet payload")
        with self.assertRaises(UnsafeEvent):
            make_event("roughtime", "time_source_probe", "ok", at=CLOCK)
        with self.assertRaises(UnsafeEvent):
            strict_json(b'{"schema":"x","schema":"y"}')
        with self.assertRaises(UnsafeEvent):
            make_event("seal", "seal_submit", "failed", at=CLOCK,
                       latency_ms=float("nan"))
        with self.assertRaises(UnsafeEvent):
            make_event("queue", "seal_queue", "saturated", at=CLOCK,
                       queue_depth=100_001, queue_capacity=300_000)

    def test_canonical_only_public_root_ref(self):
        import base64
        pub = base64.b64encode(b"\x7f"*32).decode("ascii")
        self.assertEqual(len(pubkey_ref(pub)), 16)
        with self.assertRaises(UnsafeEvent):
            pubkey_ref("plaintext-secret-do-not-leak")

    def test_actual_load_marker_ingested_without_raw_error_or_hash(self):
        incoming = {
            "kind": "queued_seal_action", "ok": False,
            "latency_ms": 256.0, "head_moved_retries": 4,
            "error": "PRIVATE-KEY-EXAMPLE-SHOULD-NOT-APPEAR",
            "action_hash": "uhCkkprivate-action-hash",
            "error_code": "queue_full", "queue_depth_at_admission": 200
        }
        events = to_events("HC_LOAD_SAMPLE " + json.dumps(incoming), CLOCK)
        self.assertEqual({x["event"] for x in events},
                         {"seal_submit", "seal_retry"})
        serialized = "".join(safe_json(item).decode() for item in events)
        self.assertNotIn("PRIVATE-KEY-EXAMPLE", serialized)
        self.assertNotIn("uhCkkprivate", serialized)
        self.assertNotIn("queue_full", serialized)
        self.assertEqual(events[0]["status"], "failed")
        self.assertEqual(events[1]["status"], "exhausted")
        # No fabricated queue capacity derived from admission-depth-only samples.
        self.assertTrue(all("queue_capacity" not in x for x in events))

    def test_fixture_markers_do_not_claim_verified_real_warrant(self):
        self.assertEqual(to_events(
            "FORK_RECOVERY_CASE=integrated_warrant_against_forked_agent:PASS", CLOCK), [])
        self.assertEqual(to_events("FORK_RECOVERY_WARRANT_COUNT=2", CLOCK), [])
        restart = to_events(
            "FORK_RECOVERY_CASE=restart_rejoin_preserves_signed_bounds:PASS", CLOCK)
        self.assertEqual(restart[0]["status"], "recovered")

    def test_roughtime_capture_hides_signed_packet_bytes(self):
        capture = {
            "schema": "hc-vtime/roughtime-receipt/v1",
            "attempts": [
                {"operator": "example-operator-alpha", "outcome": "verified"},
                {"operator": "example-operator-beta", "outcome": "invalid signature: SECRET"},
                {"operator": "example-operator-gamma", "outcome": "unreachable: SECRET"},
            ],
            "evidence": [{
                "request": "SECRET-SIGNED-REQUEST-BYTES",
                "response": "SECRET-SIGNED-RESPONSE-BYTES",
            }]
        }
        events = import_capture(capture, CLOCK)
        self.assertEqual(events[-1]["event"], "quorum_check")
        self.assertEqual(events[-1]["status"], "unavailable")
        self.assertEqual(events[-1]["required_sources"], 3)
        clean = "".join(safe_json(x).decode() for x in events)
        self.assertNotIn("SECRET", clean)
        self.assertNotIn("example-operator-alpha", clean)
        self.assertNotIn("evidence", clean)


class PrivateJournalAndDiagnostics(unittest.TestCase):
    def test_private_append_fsync_and_bounded_read(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            os.chmod(parent, 0o700)
            journal = parent / "ops.jsonl"
            items = [
                make_event("roughtime", "heartbeat", "ok", at=CLOCK)
                for _ in range(10)
            ]
            def write(item):
                append_event(journal, item)
            with ThreadPoolExecutor(max_workers=5) as pool:
                list(pool.map(write, items))
            self.assertEqual(len(read_events(journal)), 10)
            self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o600)
            symlink = parent / "danger"
            symlink.symlink_to(journal)
            with self.assertRaises(UnsafeEvent):
                append_event(symlink, items[0])
            with self.assertRaises(UnsafeEvent):
                read_events(symlink)

    def test_sanitized_report_only_sha_and_recent_allowlisted_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = Path(tmp)
            conf = private / "secret-private-config.yaml"
            conf.write_text(
                'PRIVATE-KEY=ultra-secret-literal\ntrusted_key: SECRET-BASE64-DATA\n'
            )
            output = private / "incident-report"
            events = base_events() + [
                make_event("oracle", "dependency", "unavailable", at=at(-4))
            ]
            rows = fingerprint_config([conf])
            result = create_report(events, policy(), output,
                                   source_sha="a"*40, now=CLOCK,
                                   fingerprints=rows)
            self.assertEqual(result["status"], "SANITIZED_INCOMPLETE")
            self.assertTrue((output / "SHA256SUMS").exists())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            for file in output.iterdir():
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            combined = "\n".join(path.read_text() for path in output.iterdir())
            for forbidden in ("ultra-secret-literal", "SECRET-BASE64-DATA",
                              "secret-private-config.yaml", "PRIVATE-KEY="):
                self.assertNotIn(forbidden, combined)
            self.assertEqual(rows[0]["slot"], 1)
            self.assertEqual(len(rows[0]["sha256"]), 64)
            with self.assertRaises(UnsafeEvent):
                create_report(events, policy(), output, source_sha="a"*40, now=CLOCK)

    def test_missing_journal_report_is_incomplete_not_success(self):
        with tempfile.TemporaryDirectory() as temp:
            result = create_report([], policy(), Path(temp) / "new",
                                   source_sha="b"*40, now=CLOCK,
                                   observed_journal=False)
            self.assertEqual(result["status"], "SANITIZED_INCOMPLETE")
            self.assertFalse(result["release_ready"])

    def test_low_cardinality_metrics_have_no_source_identifiers(self):
        operator = reference("PRIVATE-PERSON-OPERATOR")
        entries = base_events() + [
            make_event("oracle", "oracle_sign", "ok", at=at(-1),
                       source_ref=operator),
        ]
        text = prometheus(assess(entries, policy(), CLOCK))
        self.assertIn("hc_vtime_ops_healthy", text)
        self.assertNotIn(operator, text)
        self.assertNotIn("PRIVATE", text)
        self.assertNotIn("uhCkk", text)


if __name__ == "__main__":
    unittest.main()
