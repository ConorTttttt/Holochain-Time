"""Offline Sprint 26 evidence-intake tests. NO native-network acceptance."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

try:
    from . import sprint26 as s
    from . import testnet
except ImportError:
    import sprint26 as s
    import testnet


class Sprint26NativeEvidenceIntakeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.exports = self.base / "native"
        self.exports.mkdir()
        self.manifest = {
            "schema": testnet.MANIFEST_SCHEMA,
            "manifest_sha256": "a" * 64,
            "funding_authorized": False,
            "network": {"alliance_id": "isolated-local-alliance", "vtime_dna_hash": "uhC0kTEST_DNA"},
        }
        self.index = s.scaffold(self.manifest)
        self.index["unyt_app_release"] = "v0.114.0"
        self.index["unyt_app_artifact_sha256"] = "b" * 64

    def put(self, case_id, kind, data: bytes):
        path = self.exports / f"{case_id}.{kind}.native"
        path.write_bytes(data)
        self.index["cases"][case_id]["artifacts"][kind] = {
            "file": path.name, "sha256": hashlib.sha256(data).hexdigest()
        }

    def fill(self):
        for case in s.matrix():
            for kind in s.REQUIRED[case["expected"]]:
                self.put(case["id"], kind, (case["id"] + kind).encode())

    def test_scaffold_is_non_authorizing_and_has_blocked_protocol_cases(self):
        self.assertEqual(len(s.matrix()), 11)
        self.assertEqual(set(self.index["cases"]), {c["id"] for c in s.matrix()})
        self.assertNotIn("credentials", json.dumps(self.index))
        report = s.audit(self.index, self.manifest, self.exports)
        self.assertEqual(report["financial_release_gate"], "NO_GO")
        self.assertTrue(any(c["status"] == "BLOCKED_PROTOCOL" for c in report["cases"]))
        self.assertTrue(any(c["status"] == "MISSING_NATIVE_ARTIFACTS" for c in report["cases"]))

    def test_synthetic_complete_evidence_never_proves_accepted_network_state(self):
        self.fill()
        report = s.audit(self.index, self.manifest, self.exports)
        self.assertEqual(report["financial_release_gate"], "NO_GO")
        self.assertEqual(sum(c["status"] == "BLOCKED_PROTOCOL" for c in report["cases"]), 3)
        self.assertEqual(sum(c["status"] == "READY_FOR_INDEPENDENT_NATIVE_REVIEW" for c in report["cases"]), 8)
        self.assertFalse(any(c["status"] == "PASS" for c in report["cases"]))

    def test_missing_recipient_accept_is_not_ready(self):
        self.fill()
        del self.index["cases"]["valid_verified_time_payout"]["artifacts"]["recipient_accept"]
        report = s.audit(self.index, self.manifest, self.exports)
        case = next(c for c in report["cases"] if c["scenario_id"] == "valid_verified_time_payout")
        self.assertEqual(case["status"], "MISSING_NATIVE_ARTIFACTS")
        self.assertIn("recipient_accept", case["missing_artifacts"])

    def test_mutated_export_and_wrong_network_fail_closed(self):
        self.put("forged_proof", "native_failure", b"raw export")
        (self.exports / "forged_proof.native_failure.native").write_bytes(b"tampered")
        with self.assertRaisesRegex(s.GateError, "SHA-256 changed"):
            s.audit(self.index, self.manifest, self.exports)
        self.index["cases"]["forged_proof"]["artifacts"].clear()
        self.index["network_id"] = "prod-network"
        with self.assertRaisesRegex(s.GateError, "wrong test alliance"):
            s.audit(self.index, self.manifest, self.exports)

    def test_missing_version_and_bad_artifact_hash_fail_closed(self):
        self.index["unyt_app_release"] = "REPLACE_WITH"
        with self.assertRaisesRegex(s.GateError, "pin the actual local Unyt release"):
            s.audit(self.index, self.manifest, self.exports)
        self.index["unyt_app_release"] = "v0.114.0"
        self.index["unyt_app_artifact_sha256"] = "not-a-hash"
        with self.assertRaisesRegex(s.GateError, "pin the actual Unyt app"):
            s.audit(self.index, self.manifest, self.exports)

    def test_repeated_evidence_file_is_rejected_even_when_digests_match(self):
        self.put("forged_proof", "native_failure", b"one file")
        self.index["cases"]["forged_proof"]["artifacts"]["native_sources"] = copy.deepcopy(
            self.index["cases"]["forged_proof"]["artifacts"]["native_failure"])
        with self.assertRaisesRegex(s.GateError, "reused"):
            s.audit(self.index, self.manifest, self.exports)

    def test_unsafe_paths_and_symlinks_refused(self):
        self.put("forged_proof", "native_failure", b"ref")
        slot = self.index["cases"]["forged_proof"]["artifacts"]["native_failure"]
        slot["file"] = "../elsewhere"
        with self.assertRaisesRegex(s.GateError, "unsafe filename"):
            s.audit(self.index, self.manifest, self.exports)
        slot["file"] = "symlink.native"
        (self.exports / "symlink.native").symlink_to(self.exports / "forged_proof.native_failure.native")
        with self.assertRaisesRegex(s.GateError, "outside evidence directory"):
            s.audit(self.index, self.manifest, self.exports)

    def test_extra_scenarios_and_fake_acceptance_fields_rejected(self):
        self.index["cases"]["fake_case"] = {"artifacts": {}}
        with self.assertRaisesRegex(s.GateError, "missing or extra"):
            s.audit(self.index, self.manifest, self.exports)
        del self.index["cases"]["fake_case"]
        self.index["cases"]["valid_verified_time_payout"]["pass"] = True
        with self.assertRaisesRegex(s.GateError, "unexpected case fields"):
            s.audit(self.index, self.manifest, self.exports)

    def test_cannot_overwrite_evidence_index(self):
        path = self.base / "index.json"
        s.write_once(path, self.index)
        with self.assertRaisesRegex(s.GateError, "output exists"):
            s.write_once(path, self.index)

    def test_never_authorizes_manifest_funding(self):
        self.manifest["funding_authorized"] = True
        with self.assertRaisesRegex(s.GateError, "cannot authorize funding"):
            s.scaffold(self.manifest)


if __name__ == "__main__":
    unittest.main()
