"""Offline tests: fail-closed audit cannot mistake a fake error for a warrant."""
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit_fork_recovery as auditor


class ForkAuditTests(unittest.TestCase):
    def make_report(self, path: Path, full: bool) -> None:
        (path / "provenance.txt").write_text(
            "git_sha=" + "a" * 40 + "\nfixture_keys_public=true\nrelease_approved=false\n"
        )
        base = "".join(
            f"FORK_RECOVERY_CASE={name}:PASS\n"
            for name in sorted(auditor.BASELINE_MARKERS)
        )
        (path / "fork-baseline.log").write_text(
            base + "test result: ok. 1 passed; 1 filtered out\n"
        )
        steps = ["fixture_unit", "fork_baseline", "prior_resilience", "workspace_tests", "clippy"]
        if full:
            steps += ["fork_injected"]
            fork = "".join(
                f"FORK_RECOVERY_CASE={name}:PASS\n"
                for name in sorted(auditor.FORK_MARKERS)
            )
            (path / "fork-injected.log").write_text(
                fork + "FORK_RECOVERY_WARRANT_COUNT=1\n"
                "test result: ok. 1 passed; 0 failed\n"
            )
        (path / "results.tsv").write_text(
            "step\texit_code\n" + "".join(f"{item}\t0\n" for item in steps)
        )

    def test_good_baseline_is_not_a_fork_certificate(self):
        with TemporaryDirectory() as name:
            path = Path(name)
            self.make_report(path, full=False)
            report = auditor.audit(path, require_fork=False)
            self.assertEqual(report["status"], "BASELINE_ONLY_FORK_NOT_RUN")
            self.assertFalse(report["warrant_detection_proven"])

    def test_valid_full_requires_positive_dht_warrant(self):
        with TemporaryDirectory() as name:
            path = Path(name)
            self.make_report(path, full=True)
            report = auditor.audit(path, require_fork=True)
            self.assertEqual(report["status"], "FORK_WARRANT_RESTART_PASS")
            self.assertTrue(report["warrant_detection_proven"])

    def test_timeout_text_cannot_replace_a_real_warrant(self):
        with TemporaryDirectory() as name:
            path = Path(name)
            self.make_report(path, full=True)
            log = path / "fork-injected.log"
            log.write_text(log.read_text().replace(
                "FORK_RECOVERY_WARRANT_COUNT=1", "fork error: timed out"
            ))
            self.assertEqual(auditor.audit(path, True)["status"], "BLOCKED")

    def test_duplicate_marker_cannot_forge_two_successes(self):
        with TemporaryDirectory() as name:
            path = Path(name)
            self.make_report(path, full=True)
            log = path / "fork-injected.log"
            log.write_text(
                log.read_text() + "FORK_RECOVERY_CASE=warrant_survives_observer_restart:PASS\n"
            )
            self.assertEqual(auditor.audit(path, True)["status"], "BLOCKED")

    def test_zero_or_missing_stage_is_blocked(self):
        with TemporaryDirectory() as name:
            path = Path(name)
            self.make_report(path, full=True)
            results = path / "results.tsv"
            results.write_text(results.read_text().replace(
                "fork_injected\t0", "fork_injected\t101"
            ))
            self.assertEqual(auditor.audit(path, True)["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
