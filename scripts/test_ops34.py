"""Sprint 34 authenticated incident tests (stdlib, test-only secrets, no network)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import os
import stat
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
from ops34.auth import (KEYRING_SCHEMA, ZERO, UnsafeEvent, append_authenticated,
                        append_supplied, canonical, keyring, make_event,
                        read_authenticated, sign_frame)
from ops34.runtime_hooks import RuntimePublisher
from ops34.alerts import (assess_authenticated, alert_batch, category, deliver,
                          load_delivery, private_spool, safe_webhook_target)
from ops.monitor import read_policy

ROLES = {"source": "roughtime_probe", "oracle": "oracle_runtime",
         "queue": "queue_runtime", "seal": "seal_runtime",
         "observer": "conductor_observer"}
KEYS = {name: {"role": role, "key_hex": f"{n:02x}" * 32}
        for n, (name, role) in enumerate(ROLES.items(), 1)}
NOW = datetime(2026, 11, 10, 18, 0, tzinfo=timezone.utc)


class Ops34Tests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.keyfile = self.root / "producers.json"
        self.keyfile.write_text(json.dumps({"schema": KEYRING_SCHEMA, "producers": KEYS}))
        self.keyfile.chmod(0o600)
        self.keys = keyring(self.keyfile)
        self.journal = self.root / "telemetry.jsonl"
        self.policy = read_policy(SCRIPTS.parent / "config/ops-monitor.example.json")
        self.delivery_file = self.root / "delivery.json"
        self.spool = self.root / "spool"
        self.spool.mkdir(mode=0o700)
        self.write_delivery("private_spool")

    def write_delivery(self, mode="private_spool"):
        row = {"schema": "hc-vtime/ops34-alert-delivery/v1",
               "mode": mode, "minimum_severity": "WARNING",
               "spool_directory": str(self.spool) if mode == "private_spool" else None,
               "webhook_url": None,
               "webhook_hmac_key_hex": None}
        self.delivery_file.write_text(json.dumps(row))
        self.delivery_file.chmod(0o600)

    def emit(self, producer, component, event, status, *, at=NOW, **fields):
        row = make_event(component, event, status, at=at, **fields)
        append_authenticated(self.journal, self.keys, producer, row, at=NOW)
        return row

    def baseline(self):
        for producer, component in (("source", "roughtime"),
                                    ("oracle", "oracle"),
                                    ("observer", "conductor")):
            self.emit(producer, component, "heartbeat", "ok")
        self.emit("source", "roughtime", "time_source_probe", "ok",
                  latency_ms=12, source_ref="abcdabcdabcdabcd")
        self.emit("source", "roughtime", "quorum_check", "ok",
                  available_sources=4, required_sources=3)

    def report(self, now=NOW):
        return assess_authenticated(read_authenticated(self.journal, self.keys),
                                    self.policy, now)

    def test_authenticated_healthy_baseline_not_release_approval(self):
        self.baseline()
        report = self.report()
        self.assertEqual(report["status"], "HEALTHY")
        self.assertTrue(report["producer_hmac_checked"])
        self.assertFalse(report["fork_warrants_cryptographically_verified_here"])
        self.assertFalse(report["independent_operator_identity_proven"])
        self.assertFalse(report["release_ready"])

    def test_unsafe_raw_fields_are_rejected_not_redacted_into_journal(self):
        self.baseline()
        secret = "private-key-injection-test-SHOULD-NOT-LEAK"
        event = make_event("oracle", "oracle_sign", "ok",
                           source_ref="0123456789abcdef", signed_count=1)
        event["private_key"] = secret
        with self.assertRaises(UnsafeEvent) as raised:
            append_authenticated(self.journal, self.keys, "oracle", event)
        self.assertNotIn(secret, str(raised.exception))
        self.assertNotIn(secret, self.journal.read_text())
        self.assertNotIn(secret, json.dumps(self.report()))
        forbidden = ("signature", "nonce", "target", "request_id",
                     "raw_error", "operator_name", "secret", "ip_address")
        for field in forbidden:
            malicious = dict(event)
            malicious.pop("private_key")
            malicious[field] = secret
            with self.assertRaises(UnsafeEvent):
                append_authenticated(self.journal, self.keys, "oracle", malicious)

    def test_authenticated_journal_replay_and_mac_tampering_fail(self):
        self.baseline()
        frames = read_authenticated(self.journal, self.keys)
        last = frames[-1]
        with self.assertRaises(UnsafeEvent):
            append_supplied(self.journal, self.keys, last, at=NOW)
        wrong = dict(last)
        wrong["mac"] = "f" * 64
        with self.assertRaises(UnsafeEvent):
            append_supplied(self.journal, self.keys, wrong, at=NOW)
        text = self.journal.read_text()
        self.journal.write_text(text.replace('"quorum_check"', '"fork_warrant"'))
        with self.assertRaises(UnsafeEvent):
            read_authenticated(self.journal, self.keys)

    def test_wrong_role_cannot_inject_warrant_or_quorum(self):
        bad = make_event("dht", "fork_warrant", "warrant_observed", at=NOW)
        with self.assertRaises(UnsafeEvent):
            append_authenticated(self.journal, self.keys, "source", bad, at=NOW)
        bad2 = make_event("roughtime", "quorum_check", "unavailable", at=NOW,
                          available_sources=2, required_sources=3)
        with self.assertRaises(UnsafeEvent):
            append_authenticated(self.journal, self.keys, "observer", bad2, at=NOW)

    def test_missing_suspicious_producer_and_partial_sequence_rejected(self):
        row = make_event("roughtime", "heartbeat", "ok", at=NOW)
        frame = sign_frame("source", 2, ZERO, row, self.keys["source"][1])
        with self.assertRaises(UnsafeEvent):
            append_supplied(self.journal, self.keys, frame, at=NOW)
        with self.assertRaises(UnsafeEvent):
            append_authenticated(self.journal, self.keys, "unregistered", row, at=NOW)

    def test_incidents_alert_without_pretending_fork_proof(self):
        self.baseline()
        self.emit("source", "roughtime", "quorum_check", "unavailable",
                  at=NOW + timedelta(seconds=1),
                  available_sources=2, required_sources=3)
        self.emit("source", "roughtime", "signature_validation", "invalid")
        self.emit("oracle", "oracle", "oracle_state", "replay_rejected")
        self.emit("queue", "queue", "seal_queue", "saturated",
                  queue_depth=8, queue_capacity=8)
        self.emit("queue", "queue", "seal_retry", "exhausted", retry_count=3)
        self.emit("observer", "dht", "fork_warrant", "warrant_observed")
        report = self.report(NOW + timedelta(seconds=2))
        codes = {a["code"] for a in report["alerts"]}
        self.assertTrue({"time_quorum_unavailable", "invalid_signature",
                         "oracle_replay_rejected", "seal_queue_saturated",
                         "seal_retry_exhausted",
                         "fork_or_warrant_warrant_observed"} <= codes, codes)
        self.assertEqual(report["status"], "ALERT")
        for alert in report["alerts"]:
            self.assertEqual(alert["claim_scope"],
                             "authenticated_producer_telemetry_only")
        self.assertFalse(report["fork_warrants_cryptographically_verified_here"])
        dispatch = deliver(report, load_delivery(self.delivery_file))
        self.assertEqual(dispatch["status"], "QUEUED")
        spoolfiles = list(self.spool.glob("*.json"))
        self.assertEqual(len(spoolfiles), 1)
        spooltext = spoolfiles[0].read_text()
        self.assertNotIn("source_ref", spooltext)
        self.assertNotIn("private_key", spooltext)
        self.assertFalse(json.loads(spooltext)["cryptographic_incident_proof"])
        self.assertEqual(deliver(report, load_delivery(self.delivery_file))["status"],
                         "ALREADY_QUEUED")

    def test_state_restart_stays_alert_after_old_window(self):
        self.baseline()
        self.emit("observer", "conductor", "conductor", "restarting",
                  at=NOW - timedelta(seconds=150))
        report = self.report()
        self.assertIn("conductor_not_recovered",
                      {x["code"] for x in report["alerts"]})

    def test_negative_probe_payload_cannot_be_signed_by_wrong_role(self):
        publisher = RuntimePublisher("oracle", self.keyfile, self.journal)
        with self.assertRaises(UnsafeEvent):
            publisher.warrant_observation("warrant_observed",
                integrated_warrant_count=1, origin="local_conductor_dht_store")
        with self.assertRaises(UnsafeEvent):
            RuntimePublisher("observer", self.keyfile, self.journal).warrant_observation(
                "warrant_observed", integrated_warrant_count=0,
                origin="local_conductor_dht_store")
        with self.assertRaises(UnsafeEvent):
            RuntimePublisher("observer", self.keyfile, self.journal).warrant_observation(
                "warrant_observed", integrated_warrant_count=1,
                origin="test_fixture")
        with self.assertRaises(UnsafeEvent):
            RuntimePublisher("queue", self.keyfile, self.journal).queue_snapshot(
                depth=9, capacity=8)

    def test_private_journal_and_keyring_permissions(self):
        row = make_event("roughtime", "heartbeat", "ok", at=NOW)
        self.keyfile.chmod(0o644)
        with self.assertRaises(UnsafeEvent):
            keyring(self.keyfile)
        self.keyfile.chmod(0o600)
        append_authenticated(self.journal, self.keys, "source", row, at=NOW)
        self.journal.chmod(0o644)
        with self.assertRaises(UnsafeEvent):
            read_authenticated(self.journal, self.keys)

    def test_webhook_contract_rejects_http_and_internal_ip(self):
        for url in ("http://alerts.example.org/hook",
                    "https://127.0.0.1/hook", "https://alerts.local/hook",
                    "https://user:pw@alerts.example.org/hook"):
            with self.assertRaises((UnsafeEvent, ValueError)):
                safe_webhook_target(url)

    def test_configurable_https_delivery_stub_has_no_raw_event_data(self):
        self.baseline()
        self.emit("oracle", "oracle", "oracle_state", "replay_rejected")
        report = self.report()
        seen = []
        config = {"mode": "https_webhook", "minimum_severity": "CRITICAL",
                  "webhook_url": "https://alerts.example.org/vtime",
                  "webhook_hmac_key_hex": "ab" * 32,
                  "spool_directory": None}
        def fake_https(url, batch, key):
            seen.append(batch)
            self.assertEqual(url, config["webhook_url"])
            self.assertEqual(key, config["webhook_hmac_key_hex"])
            return "DELIVERED_HTTP_2XX"
        self.assertTrue(deliver(report, config, sender=fake_https)["alert_notification_sent"])
        self.assertTrue(seen)
        self.assertFalse(seen[0]["cryptographic_incident_proof"])
        self.assertNotIn("source_ref", json.dumps(seen[0]))


if __name__ == "__main__":
    unittest.main()
