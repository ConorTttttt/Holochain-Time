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
                            probe_one, probe_all, reviewed_eligible)

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

    def reviewed_registry(self):
        dossier = {
            "schema": "hc-vtime/roughtime-operator-dossier/v1",
            "status": "REVIEWED_APPROVED", "min_sources": 3,
            "max_faulty": 1, "max_unavailable": 1,
            "reviewers": ["Security Reviewer 1", "Security Reviewer 2"],
            "sources": [],
        }
        for index, row in enumerate(self.registry["sources"]):
            eligible = index != 0  # Cloudflare's draft11 fixture is unsupported
            dossier["sources"].append({
                "operator_id": f"reviewed-operator-{index}",
                **{field: row[field] for field in
                   ("name", "operator", "address", "key_source", "public_key")},
                "supported_client_protocol": eligible,
                "protocol_assessment": (
                    "rfc10049-live-verified" if eligible
                    else "draft11-unsupported"
                ),
                "admin_independence_reviewed": eligible,
                "root_key_control_reviewed": eligible,
                "shared_upstream_reviewed": eligible,
                "live_signature_evidence_sha256": "a"*64 if eligible else None,
                "infrastructure_evidence_refs": (
                    ["signed-off-local-test-assertion"] if eligible else []
                ),
            })
        return dossier

    def test_only_exact_pinned_reviewed_eligible_roots_are_probed(self):
        dossier = self.reviewed_registry()
        selected = reviewed_eligible(
            self.registry, dossier, ["Cloudflare-Roughtime-2"])
        self.assertEqual(len(selected), 4)
        self.assertEqual({x["name"] for x in selected},
                         {x["name"] for x in self.registry["sources"][1:]})
        dossier["sources"][2]["protocol_assessment"] = "rfc10049-candidate"
        with self.assertRaisesRegex(UnsafeEvent, "not eligible"):
            reviewed_eligible(self.registry, dossier, ["Cloudflare-Roughtime-2"])
        dossier = self.reviewed_registry()
        dossier["sources"][3]["admin_independence_reviewed"] = False
        with self.assertRaisesRegex(UnsafeEvent, "not eligible"):
            reviewed_eligible(self.registry, dossier, ["Cloudflare-Roughtime-2"])
        dossier = self.reviewed_registry()
        dossier["sources"][2]["operator_id"] = dossier["sources"][3]["operator_id"]
        with self.assertRaisesRegex(UnsafeEvent, "duplicate"):
            reviewed_eligible(self.registry, dossier, ["Cloudflare-Roughtime-2"])
        dossier = self.reviewed_registry()
        dossier["sources"][2]["address"] = "modified-endpoint.example:5319"
        with self.assertRaisesRegex(UnsafeEvent, "not bound"):
            reviewed_eligible(self.registry, dossier, ["Cloudflare-Roughtime-2"])
        dossier = self.reviewed_registry()
        dossier["status"] = "PENDING_EXTERNAL_REVIEW"
        with self.assertRaisesRegex(UnsafeEvent, "approved"):
            reviewed_eligible(self.registry, dossier, ["Cloudflare-Roughtime-2"])

    def test_margin_follows_four_native_verified_results_not_four_names(self):
        import probe_roughtime as module
        rows = reviewed_eligible(
            self.registry, self.reviewed_registry(), ["Cloudflare-Roughtime-2"])
        old_probe = module.probe_one
        from events import make_event, pubkey_ref
        try:
            for successes in (4, 3, 2):
                def fake_crypto(client, row, timeout_seconds):
                    # Simulated native-verifier outcomes for deterministic
                    # testing, NOT proof that these public roots are real.
                    index = rows.index(row)
                    return make_event(
                        "roughtime", "time_source_probe",
                        "ok" if index < successes else "timeout",
                        source_ref=pubkey_ref(row["public_key"]),
                        latency_ms=10.0)
                module.probe_one = fake_crypto
                observations = []
                result = probe_all(rows, "/synthetic-rust", 4,
                                   append=observations.append)
                self.assertEqual(result["valid_signed_roots"], successes)
                self.assertEqual(result["eligible_signed_successes"], successes)
                self.assertEqual(result["one_source_outage_margin_met"],
                                 successes >= 4)
                self.assertEqual(result["required_outage_margin_sources"], 1)
                self.assertEqual(observations[-2]["available_sources"], successes)
                self.assertEqual(observations[-2]["required_sources"], 3)
                self.assertEqual(observations[-2]["status"],
                                 "ok" if successes >= 3 else "unavailable")
                self.assertFalse(result["operator_independence_proven"])
        finally:
            module.probe_one = old_probe

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
