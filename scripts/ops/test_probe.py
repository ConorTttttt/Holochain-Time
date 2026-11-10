"""Sprint 25 signed Roughtime probe adapter tests: mock subprocess, NO UDP."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
from events import UnsafeEvent, fingerprint_bytes
from probe_roughtime import (candidates, check_file, classify_failure,
                            probe_one, probe_all)

ROOT = Path(__file__).resolve().parents[2]


class ProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = json.loads(
            (ROOT / "config/roughtime-independent-sources.json").read_text()
        )

    def test_candidate_duplicate_roots_and_outage_margin(self):
        rows = candidates(self.registry, ["Cloudflare-Roughtime-2"])
        self.assertEqual(len(rows), 4)
        self.assertNotIn("Cloudflare-Roughtime-2", {x["name"] for x in rows})
        with self.assertRaisesRegex(UnsafeEvent, "fewer than 4"):
            candidates(self.registry, ["Cloudflare-Roughtime-2", "roughtime.se"])
        with self.assertRaisesRegex(UnsafeEvent, "not in pinned registry"):
            candidates(self.registry, ["nonexistent-operator"])
        dup = json.loads(json.dumps(self.registry))
        dup["sources"][1]["public_key"] = dup["sources"][0]["public_key"]
        with self.assertRaisesRegex(UnsafeEvent, "duplicate"):
            candidates(dup, [])

    def test_signed_response_success_has_only_latency_and_hashed_ref(self):
        row = self.registry["sources"][1]
        def fake_native(argv, **kwargs):
            self.assertEqual(argv[1], row["address"])
            self.assertEqual(len(argv[3]), 64)
            return SimpleNamespace(
                returncode=0,
                stdout='{"request":"PRIVATE_SIGNED_PACKET","response":"PRIVATE"}',
                stderr="")
        event = probe_one("/reviewed/roughtime_fetch", row, 4, invoke=fake_native)
        self.assertEqual(event["event"], "time_source_probe")
        self.assertEqual(event["status"], "ok")
        self.assertIn("latency_ms", event)
        self.assertEqual(len(event["source_ref"]), 16)
        serialized = json.dumps(event)
        for forbidden in ("PRIVATE", row["address"], row["public_key"], row["operator"]):
            self.assertNotIn(forbidden, serialized)

    def test_invalid_signature_and_timeout_classification_without_raw_error(self):
        row = self.registry["sources"][2]
        def fake_signature(argv, **kwargs):
            return SimpleNamespace(returncode=1,
                                   stderr="invalid delegated signature: TOP-SECRET", stdout="")
        bad = probe_one("/reviewed/client", row, 5, invoke=fake_signature)
        self.assertEqual(bad["status"], "invalid_signature")
        self.assertNotIn("TOP-SECRET", json.dumps(bad))
        def fake_timeout(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, timeout=kwargs["timeout"])
        timeout = probe_one("/reviewed/client", row, 5, invoke=fake_timeout)
        self.assertEqual(timeout["status"], "timeout")
        self.assertEqual(classify_failure("unsupported protocol version"), "unsupported_protocol")

    def test_digest_pin_refuses_mutated_or_symlinked_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "test-only-fake-client"
            good.write_bytes(b"PUBLIC-SYNTHETIC-BINARY")
            digest = fingerprint_bytes(good.read_bytes())
            self.assertEqual(check_file(good, 1000, digest), good.read_bytes())
            good.write_bytes(b"modified fake executable")
            with self.assertRaisesRegex(UnsafeEvent, "fingerprint mismatch"):
                check_file(good, 1000, digest)
            pointer = Path(tmp) / "symlink"
            pointer.symlink_to(good)
            with self.assertRaises(UnsafeEvent):
                check_file(pointer, 1000, fingerprint_bytes(good.read_bytes()))

    def test_less_than_three_signed_roots_never_reports_a_quorum(self):
        rows = self.registry["sources"][1:5]
        # Stub at the specific public boundary; do not use fake signed
        # packets to claim a real cryptographic verification test passed.
        import probe_roughtime as module
        original = module.probe_one
        def sample(client, row, timeout_seconds):
            index = rows.index(row)
            from events import make_event, pubkey_ref
            return make_event(
                "roughtime", "time_source_probe",
                "ok" if index < 2 else "timeout",
                source_ref=pubkey_ref(row["public_key"]),
                latency_ms=10.0)
        try:
            module.probe_one = sample
            recorded = []
            status = probe_all(rows, "/fake", 4, append=recorded.append)
            self.assertEqual(status["valid_signed_roots"], 2)
            self.assertEqual(status["status"], "INSUFFICIENT_SIGNED_SOURCES")
            self.assertEqual(recorded[-2]["required_sources"], 3)
            self.assertEqual(recorded[-2]["status"], "unavailable")
        finally:
            module.probe_one = original


if __name__ == "__main__":
    unittest.main()
