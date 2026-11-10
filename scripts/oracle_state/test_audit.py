"""Offline audit parser tests; synthetic logs must never be release evidence."""
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit as a


class AuditTests(unittest.TestCase):
    def create(self, root: Path) -> None:
        (root / "provenance.txt").write_text(
            "git_sha=" + "a" * 40 + "\nrelease_ready=false\n"
            "external_rollback_protection_proven=false\n", encoding="utf-8"
        )
        (root / "results.tsv").write_text(
            "stage\texit_code\n"
            + "".join(f"{stage}\t0\n" for stage in sorted(a.STAGES)),
            encoding="utf-8",
        )
        for stage, names in a.REQUIRED.items():
            (root / (stage + ".log")).write_text(
                "".join(f"test {name} ... ok\n" for name in sorted(names))
                + f"\ntest result: ok. {len(names)} passed; 0 failed; 0 ignored\n",
                encoding="utf-8",
            )

    def test_correctly_executed_regressions_have_local_only_status(self):
        with TemporaryDirectory() as d:
            path = Path(d)
            self.create(path)
            result = a.audit(path)
            self.assertEqual(result["status"], "LOCAL_PERSISTENCE_REGRESSION_PASS")
            self.assertFalse(result["release_ready"])
            self.assertFalse(result["real_conductor_signing_integration_proven"])

    def test_fake_rust_success_summary_without_test_names_is_blocked(self):
        with TemporaryDirectory() as d:
            path = Path(d)
            self.create(path)
            (path / "process_crash.log").write_text(
                "test result: ok. 3 passed; 0 failed\n", encoding="utf-8"
            )
            self.assertEqual(a.audit(path)["status"], "BLOCKED")

    def test_missing_stage_is_blocked(self):
        with TemporaryDirectory() as d:
            path = Path(d)
            self.create(path)
            results = path / "results.tsv"
            results.write_text(
                results.read_text().replace("workspace_clippy\t0\n", ""),
                encoding="utf-8",
            )
            self.assertEqual(a.audit(path)["status"], "BLOCKED")

    def test_failed_process_kill_cannot_be_reported_as_pass(self):
        with TemporaryDirectory() as d:
            path = Path(d)
            self.create(path)
            results = path / "results.tsv"
            results.write_text(
                results.read_text().replace("process_crash\t0", "process_crash\t101"),
                encoding="utf-8",
            )
            self.assertEqual(a.audit(path)["status"], "BLOCKED")

    def test_duplicate_result_row_is_blocked(self):
        with TemporaryDirectory() as d:
            path = Path(d)
            self.create(path)
            results = path / "results.tsv"
            with results.open("a", encoding="utf-8") as file:
                file.write("restart_safety\t0\n")
            self.assertEqual(a.audit(path)["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
