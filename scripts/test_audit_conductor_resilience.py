"""Offline stdlib checks for Sprint 12 release evidence gate.

Mock logs only test the *auditor's* fail-closed behavior, not conductors.
"""
import tempfile
import unittest
from pathlib import Path
from audit_conductor_resilience import BASELINE, LONG, FORK, audit, check_log


def log(markers):
    return "".join(f"RESILIENCE_CASE={name}:PASS\n" for name in sorted(markers)) + \
           "test result: ok. 2 passed; 0 failed; 2 ignored\n"


class EvidenceGate(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "provenance.txt").write_text(
            "commit=" + "a" * 40 + "\nrelease_approved=false\n")
        (self.root / "resilience-baseline.log").write_text(log(BASELINE))
        (self.root / "resilience-ancestry.log").write_text(log(LONG))
        (self.root / "resilience-fork.log").write_text(log(FORK))

    def test_baseline_pass_not_a_release(self):
        report = audit(self.root)
        self.assertEqual(report["status"], "BASELINE_PASS")
        self.assertFalse(report["release_ready"])
        self.assertFalse(report["physical_network_partition_proven"])

    def test_full_suite_pass_not_a_release(self):
        report = audit(self.root, full=True)
        self.assertEqual(report["status"], "FULL_FIXTURE_PASS")
        self.assertFalse(report["independent_roughtime_operators_proven"])

    def test_one_missing_case_blocks(self):
        (self.root / "resilience-baseline.log").write_text(log(BASELINE - {"offline_conductor"}))
        self.assertEqual(audit(self.root)["status"], "BLOCKED")

    def test_duplicate_case_blocks(self):
        file = self.root / "resilience-baseline.log"
        file.write_text(log(BASELINE) + "RESILIENCE_CASE=offline_conductor:PASS\n")
        self.assertEqual(audit(self.root)["status"], "BLOCKED")

    def test_summary_must_show_tests_executed(self):
        (self.root / "resilience-baseline.log").write_text(
            "\n".join(f"RESILIENCE_CASE={x}:PASS" for x in BASELINE) + "\n")
        self.assertEqual(audit(self.root)["status"], "BLOCKED")

    def test_panics_block_even_with_markers(self):
        (self.root / "resilience-baseline.log").write_text(
            log(BASELINE) + "thread panicked at mock.rs:20\n")
        self.assertEqual(audit(self.root)["status"], "BLOCKED")

    def test_missing_fork_test_only_blocks_full(self):
        (self.root / "resilience-fork.log").unlink()
        self.assertEqual(audit(self.root)["status"], "BASELINE_PASS")
        self.assertEqual(audit(self.root, full=True)["status"], "BLOCKED")

    def test_missing_ancestry_test_blocks_full(self):
        (self.root / "resilience-ancestry.log").unlink()
        self.assertEqual(audit(self.root, full=True)["status"], "BLOCKED")

    def test_bad_commit_blocks(self):
        (self.root / "provenance.txt").write_text("commit=short\nrelease_approved=false\n")
        self.assertEqual(audit(self.root)["status"], "BLOCKED")

    def test_missing_provenance_blocks(self):
        (self.root / "provenance.txt").unlink()
        self.assertEqual(audit(self.root)["status"], "BLOCKED")

    def test_empty_log_is_rejected(self):
        (self.root / "resilience-baseline.log").write_text("")
        self.assertEqual(audit(self.root)["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
