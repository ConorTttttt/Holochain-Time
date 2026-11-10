"""Negative tests: forged/missing Sprint34 evidence cannot certify live incidents."""
from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import json
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import audit_ops34 as audit


class AuditOps34Tests(unittest.TestCase):
    def make(self, root: Path):
        (root / "provenance.txt").write_text(
            "git_sha=" + "a" * 40 +
            "\nmode=injected_test_only\nrelease_ready=false\n"
            "actual_runtime_events_wired=false\n"
        )
        steps = sorted(audit.REQUIRED_STEPS | {"audit"})
        (root / "results.tsv").write_text(
            "step\texit_code\n" + "".join(f"{s}\t0\n" for s in steps)
        )
        drill = root / "drill"
        drill.mkdir()
        body = {"schema": "hc-vtime/ops34-incident-exercise/v1",
                "status": "INJECTED_INCIDENT_ALERTS_PASS",
                "source": "SAFELY_INJECTED_TEST_ONLY",
                "real_runtime_incidents_observed": False,
                "real_fork_warrant_authenticated": False,
                "operator_independence_proven": False,
                "global_evidence_completeness_proven": False,
                "release_ready": False,
                "actual_external_pager_invoked": False,
                "forged_mac_rejections": 1,
                "private_alerts_queued": 1,
                "authenticated_test_frame_count": 13,
                "injected_alert_codes": sorted(audit.REQUIRED_ALERTS)}
        raw = json.dumps(body)
        (drill / "exercise.json").write_text(raw)
        checksum = hashlib.sha256(raw.encode()).hexdigest()
        (drill / "checksums.json").write_text(json.dumps({"exercise.json": checksum}))

    def test_complete_offline_fixture_never_claims_live_event_proof(self):
        with TemporaryDirectory() as directory:
            path = Path(directory)
            self.make(path)
            result = audit.audit(path)
            self.assertEqual(result["status"], "INJECTED_INCIDENTS_PASS")
            self.assertFalse(result["real_runtime_alerting_acceptance_proven"])
            self.assertFalse(result["signed_warrant_proof_verified"])

    def test_forged_warrant_authentication_flag_is_rejected(self):
        with TemporaryDirectory() as directory:
            path = Path(directory)
            self.make(path)
            p = path / "drill" / "exercise.json"
            p.write_text(p.read_text().replace(
                '"real_fork_warrant_authenticated": false',
                '"real_fork_warrant_authenticated": true'))
            self.assertEqual(audit.audit(path)["status"], "BLOCKED")

    def test_missing_alert_code_is_rejected_even_if_pass_marked(self):
        with TemporaryDirectory() as directory:
            path = Path(directory)
            self.make(path)
            p = path / "drill" / "exercise.json"
            body = json.loads(p.read_text())
            body["injected_alert_codes"].remove("oracle_replay_rejected")
            p.write_text(json.dumps(body))
            self.assertEqual(audit.audit(path)["status"], "BLOCKED")

    def test_changed_spooled_payload_hash_blocks(self):
        with TemporaryDirectory() as directory:
            path = Path(directory)
            self.make(path)
            p = path / "drill" / "exercise.json"
            p.write_text(p.read_text() + " ")
            self.assertEqual(audit.audit(path)["status"], "BLOCKED")

    def test_missing_or_nonzero_test_gate_blocks(self):
        with TemporaryDirectory() as directory:
            path = Path(directory)
            self.make(path)
            p = path / "results.tsv"
            p.write_text(p.read_text().replace("negative_tests\t0", "negative_tests\t1"))
            self.assertEqual(audit.audit(path)["status"], "BLOCKED")
            p.write_text(p.read_text().replace("negative_tests\t1\n", ""))
            self.assertEqual(audit.audit(path)["status"], "BLOCKED")

    def test_missing_provenance_or_other_mode_blocks(self):
        with TemporaryDirectory() as directory:
            path = Path(directory)
            self.make(path)
            p = path / "provenance.txt"
            p.write_text(p.read_text().replace("mode=injected_test_only", "mode=production"))
            self.assertEqual(audit.audit(path)["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
