"""Fake/negative reports MUST never certify Sprint 33 recovery."""
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit_chaos33 as audit


class ChaosAuditTests(unittest.TestCase):
    def make(self, root: Path, full: bool) -> None:
        root.joinpath("provenance.txt").write_text(
            "git_sha=" + "a" * 40 +
            "\ntest_only_signers=true\nrelease_approved=false\nmode=" +
            ("full_same_key_fork" if full else "baseline") + "\n"
        )
        names = sorted(audit.STEPS | ({"fork_injected"} if full else set()))
        root.joinpath("results.tsv").write_text(
            "step\texit_code\n" + "".join(f"{name}\t0\n" for name in names)
        )
        payload = {
            "schema": "hc-vtime/sprint33-conductor/v1",
            "real_conductor": True, "transport_partition_proven": False,
            "unclean_sigkill_proven": False,
            "database_corruption_recovery_proven": False,
            "delayed_discovery_rejoin": True, "signed_bounds_preserved": True,
            "invalid_ancestry_rejected": True, "missing_witness_rejected": True,
            "evidence_complete": False, "release_approved": False,
        }
        self.case_log(root, "conductor_chaos", "CHAOS33_CASE",
                      audit.CHAOS_CASES,
                      "CHAOS33_CONDUCTOR_REPORT " + json.dumps(payload) + "\n")
        self.case_log(root, "fork_baseline", "FORK_RECOVERY_CASE",
                      audit.FORK_BASELINE)
        self.case_log(root, "prior_resilience", "RESILIENCE_CASE",
                      audit.RESILIENCE_CASES)
        if full:
            self.case_log(root, "fork_injected", "FORK_RECOVERY_CASE",
                          audit.FORK_FULL, "FORK_RECOVERY_WARRANT_COUNT=2\n")

    def case_log(self, root, name, prefix, cases, extra=""):
        root.joinpath(name + ".log").write_text(
            "".join(f"{prefix}={case}:PASS\n" for case in sorted(cases)) +
            extra + "test result: ok. 1 passed; 0 failed\n"
        )

    def test_good_baseline_can_never_claim_kill_or_transport_partition(self):
        with TemporaryDirectory() as path:
            root = Path(path)
            self.make(root, False)
            outcome = audit.audit(root, False)
            self.assertEqual(outcome["status"], "REAL_CONDUCTOR_BASELINE_PASS")
            self.assertFalse(outcome["physical_transport_partition_proven"])
            self.assertFalse(outcome["actual_sigkill_recovery_proven"])

    def test_valid_full_requires_positive_actual_warrant(self):
        with TemporaryDirectory() as path:
            root = Path(path)
            self.make(root, True)
            result = audit.audit(root, True)
            self.assertEqual(result["status"], "FORK_WARRANT_RESTART_PASS")
            self.assertEqual(result["same_key_integrated_warrant_count"], 2)

    def test_zero_warrant_fails(self):
        with TemporaryDirectory() as path:
            root = Path(path)
            self.make(root, True)
            file = root / "fork_injected.log"
            file.write_text(file.read_text().replace(
                "FORK_RECOVERY_WARRANT_COUNT=2", "FORK_RECOVERY_WARRANT_COUNT=0"))
            self.assertEqual(audit.audit(root, True)["status"], "BLOCKED")

    def test_duplicate_positive_markers_fail(self):
        with TemporaryDirectory() as path:
            root = Path(path)
            self.make(root, False)
            log = root / "conductor_chaos.log"
            log.write_text(log.read_text() +
                           "CHAOS33_CASE=restart_rejoin_never_trusts_conflicting_ancestry:PASS\n")
            self.assertEqual(audit.audit(root, False)["status"], "BLOCKED")

    def test_generic_timeout_cannot_substitute_for_witness_rejection(self):
        with TemporaryDirectory() as path:
            root = Path(path)
            self.make(root, False)
            log = root / "conductor_chaos.log"
            log.write_text(log.read_text().replace(
                "CHAOS33_CASE=false_ancestry_and_missing_seal_rejected:PASS", "timed out"))
            self.assertEqual(audit.audit(root, False)["status"], "BLOCKED")

    def test_forged_global_completeness_claim_is_blocked(self):
        with TemporaryDirectory() as path:
            root = Path(path)
            self.make(root, False)
            log = root / "conductor_chaos.log"
            log.write_text(log.read_text().replace(
                '"evidence_complete": false', '"evidence_complete": true'))
            self.assertEqual(audit.audit(root, False)["status"], "BLOCKED")

    def test_skipped_or_failed_step_rejected(self):
        with TemporaryDirectory() as path:
            root = Path(path)
            self.make(root, False)
            result = root / "results.tsv"
            result.write_text(result.read_text().replace("conductor_chaos\t0", "conductor_chaos\t101"))
            self.assertEqual(audit.audit(root, False)["status"], "BLOCKED")
            result.write_text(result.read_text().replace("conductor_chaos\t101\n", ""))
            self.assertEqual(audit.audit(root, False)["status"], "BLOCKED")

    def test_audit_mode_mismatch_is_blocked(self):
        with TemporaryDirectory() as path:
            root = Path(path)
            self.make(root, False)
            self.assertEqual(audit.audit(root, True)["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
