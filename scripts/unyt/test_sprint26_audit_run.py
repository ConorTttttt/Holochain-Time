"""Synthetic offline audit regressions. Fake logs never certify Unyt state."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

try:
    from . import sprint26_audit_run as a
except ImportError:
    import sprint26_audit_run as a


class AuditTests(unittest.TestCase):
    def create(self, path: Path):
        (path / "provenance.txt").write_text(
            "git_sha=" + "a" * 40
            + "\nrelease_ready=false\ntestnet_transactions_performed=false\n"
              "native_unyt_peer_verified=false\n", encoding="utf-8"
        )
        (path / "results.tsv").write_text(
            "stage\texit_code\n"
            + "".join(f"{name}\t0\n" for name in sorted(a.STAGES)),
            encoding="utf-8",
        )
        (path / "offline_unittests.log").write_text(
            "Ran 21 tests in 0.5s\n\nOK\n", encoding="utf-8"
        )
        (path / "workspace_tests.log").write_text(
            "test result: ok. 8 passed; 0 failed\n", encoding="utf-8"
        )
        (path / "rust_harness.log").write_text(
            "".join(f"test {case} ... ok\n" for case in sorted(a.REQUIRED_RUST_CASES))
            + "\ntest result: ok. 9 passed; 0 failed\n", encoding="utf-8"
        )

    def test_full_offline_evidence_never_certifies_network_acceptance(self):
        with TemporaryDirectory() as temp:
            folder = Path(temp)
            self.create(folder)
            result = a.audit(folder)
            self.assertEqual(result["status"], "OFFLINE_SUITE_PASS_NO_FUNDED_UNYT_EVIDENCE")
            self.assertFalse(result["funded_unyt_network_verified"])
            self.assertFalse(result["recipient_accept_verified"])
            self.assertFalse(result["release_ready"])

    def test_forged_summary_without_named_rhai_tests_is_blocked(self):
        with TemporaryDirectory() as temp:
            folder = Path(temp)
            self.create(folder)
            (folder / "rust_harness.log").write_text(
                "test result: ok. 99 passed; 0 failed\n", encoding="utf-8"
            )
            self.assertEqual(a.audit(folder)["status"], "BLOCKED")

    def test_missing_or_failing_stage_is_blocked(self):
        with TemporaryDirectory() as temp:
            folder = Path(temp)
            self.create(folder)
            result = folder / "results.tsv"
            result.write_text(result.read_text().replace("workspace_clippy\t0\n", ""))
            self.assertEqual(a.audit(folder)["status"], "BLOCKED")
            self.create(folder)
            result.write_text(result.read_text().replace("rust_harness\t0", "rust_harness\t101"))
            self.assertEqual(a.audit(folder)["status"], "BLOCKED")

    def test_missing_python_dependency_or_skipped_tests_fails(self):
        with TemporaryDirectory() as temp:
            folder = Path(temp)
            self.create(folder)
            (folder / "offline_unittests.log").write_text(
                "Ran 17 tests\n\nOK (skipped=4)\n", encoding="utf-8"
            )
            self.assertEqual(a.audit(folder)["status"], "BLOCKED")

    def test_duplicate_rows_and_missing_provenance_fail(self):
        with TemporaryDirectory() as temp:
            folder = Path(temp)
            self.create(folder)
            with (folder / "results.tsv").open("a") as file:
                file.write("rust_harness\t0\n")
            self.assertEqual(a.audit(folder)["status"], "BLOCKED")
            (folder / "provenance.txt").unlink()
            self.assertEqual(a.audit(folder)["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
