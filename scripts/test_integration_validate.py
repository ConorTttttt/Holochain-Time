"""Sprint 17 offline tests: synthetic local Git history; NO merges into real main."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from integration_validate import (
    REQUIRED, aggregate, check_pins, check_source, ci_classification,
    git, run_command, sha_file, status, write_final,
)
from repack_test_dna import digest


def git_checked(repo, *args):
    result = git(repo, *args)
    if result.returncode:
        raise AssertionError(f"git {args!r}: {result.stderr}")
    return result.stdout.strip()


class TestIntegrationHistory(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.repo = self.directory / "clone"
        self.repo.mkdir()
        git_checked(self.repo, "init", "-q")
        git_checked(self.repo, "config", "user.name", "Test Only")
        git_checked(self.repo, "config", "user.email", "test@example.invalid")
        (self.repo / "Cargo.lock").write_text("test lock", encoding="utf-8")
        git_checked(self.repo, "add", "Cargo.lock")
        git_checked(self.repo, "commit", "-qm", "main")
        self.base = git_checked(self.repo, "rev-parse", "HEAD")
        git_checked(self.repo, "update-ref", "refs/remotes/origin/main", self.base)
        git_checked(self.repo, "checkout", "-qb", "sprint/11", self.base)
        (self.repo / "sprint.txt").write_text("sprint", encoding="utf-8")
        git_checked(self.repo, "add", "sprint.txt")
        git_checked(self.repo, "commit", "-qm", "sprint branch")
        self.tip = git_checked(self.repo, "rev-parse", "HEAD")
        git_checked(self.repo, "update-ref", "refs/remotes/origin/sprint/11", self.tip)
        git_checked(self.repo, "checkout", "-qb", "integrated", self.tip)
        (self.repo / "integrated.txt").write_text("integrated", encoding="utf-8")
        git_checked(self.repo, "add", "integrated.txt")
        git_checked(self.repo, "commit", "-qm", "candidate")
        self.candidate = git_checked(self.repo, "rev-parse", "HEAD")
        self.pins = self.directory / "pins.json"
        self.manifest = {
            "schema": "hc-vtime/integration-pins/v1",
            "candidate_sha": self.candidate,
            "base": {"branch": "main", "sha": self.base},
            "branches": [{"branch": "sprint/11", "sha": self.tip}],
        }
        self.write_pins()

    def write_pins(self):
        self.pins.write_text(json.dumps(self.manifest), encoding="utf-8")

    def test_exact_head_and_valid_tip_are_accepted(self):
        self.assertEqual(check_source(self.repo, self.candidate)["status"], "PASS")
        proof = check_pins(self.repo, self.candidate, self.pins)
        self.assertEqual(proof["status"], "PASS")
        self.assertTrue(proof["branches"][1]["included_in_candidate"])
        self.assertTrue(proof["branches"][1]["tip_matches_pin"])

    def test_stale_moving_origin_tip_blocks_provenance(self):
        git_checked(self.repo, "update-ref", "refs/remotes/origin/sprint/11",
                    self.candidate)
        finding = check_pins(self.repo, self.candidate, self.pins)
        self.assertEqual(finding["status"], "FAIL")
        self.assertIn("origin tracking ref absent/moved", finding["reason"])

    def test_pin_without_integrated_ancestry_fails(self):
        git_checked(self.repo, "checkout", "-qb", "sprint/12", self.base)
        (self.repo / "other.txt").write_text("unmerged", encoding="utf-8")
        git_checked(self.repo, "add", "other.txt")
        git_checked(self.repo, "commit", "-qm", "unmerged")
        other_tip = git_checked(self.repo, "rev-parse", "HEAD")
        git_checked(self.repo, "update-ref", "refs/remotes/origin/sprint/12",
                    other_tip)
        self.manifest["branches"].append({"branch": "sprint/12", "sha": other_tip})
        self.write_pins()
        finding = check_pins(self.repo, self.candidate, self.pins)
        self.assertEqual(finding["status"], "FAIL")
        self.assertIn("not an ancestor", finding["reason"])

    def test_missing_pins_and_weak_sha_never_pass(self):
        self.assertEqual(check_pins(self.repo, self.candidate, None)["status"],
                         "NOT RUN")
        self.manifest["branches"][0]["sha"] = self.tip[:9]
        self.write_pins()
        self.assertEqual(check_pins(self.repo, self.candidate, self.pins)["status"],
                         "FAIL")
        self.assertEqual(check_source(self.repo, self.candidate[:8])["status"],
                         "FAIL")

    def test_duplicate_pinned_tip_is_rejected(self):
        self.manifest["branches"].append(self.manifest["branches"][0].copy())
        self.write_pins()
        self.assertIn("duplicate pinned branch",
                      check_pins(self.repo, self.candidate, self.pins)["reason"])

    def test_dirty_worktree_and_wrong_head_fail_closed(self):
        self.assertEqual(check_source(self.repo, self.base)["status"], "FAIL")
        (self.repo / "untracked-secret.txt").write_text("not committed")
        self.assertEqual(check_source(self.repo, self.candidate)["status"], "FAIL")


class TestEvidence(unittest.TestCase):
    def test_required_gates_do_not_promote_missing_or_failed_checks(self):
        checks = {k: status("PASS", "simulated") for k in REQUIRED}
        self.assertEqual(aggregate(checks), "PASS")
        checks["fresh_dna"] = status("NOT RUN", "no WASM target")
        self.assertEqual(aggregate(checks), "NOT RUN")
        checks["ancestry"] = status("FAIL", "missing parent")
        self.assertEqual(aggregate(checks), "FAIL")

    def test_ci_billing_pre_runner_is_not_a_test_failure(self):
        self.assertEqual(ci_classification({
            "state": "before_runner", "reason": "no runner executed"
        })["status"], "NOT RUN")
        self.assertEqual(ci_classification({
            "state": "executed_failure", "reason": "cargo failed"
        })["status"], "FAIL")
        self.assertEqual(ci_classification({
            "state": "sha_mismatch", "reason": "different commit"
        })["status"], "FAIL")
        self.assertEqual(ci_classification({
            "state": "passed", "reason": "executed exact SHA"
        })["status"], "PASS")

    def test_command_logging_pass_fail_and_missing_tool(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            ok = run_command("ok", [sys.executable, "-c", "print('ok')"],
                             repo, repo, required_tools=())
            bad = run_command("bad", [sys.executable, "-c", "raise SystemExit(9)"],
                              repo, repo, required_tools=())
            missing = run_command("missing", ["nonexistent-command-x"],
                                  repo, repo,
                                  required_tools=("nonexistent-command-x",))
            self.assertEqual(ok["status"], "PASS")
            self.assertEqual(bad["status"], "FAIL")
            self.assertEqual(missing["status"], "NOT RUN")
            self.assertEqual(ok["log_sha256"], sha_file(repo / "ok.log"))

    def test_manifest_hashes_and_detects_modification(self):
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp)
            artifact = report / "native.log"
            artifact.write_bytes(b"original exact-commit output")
            checks = {name: status("NOT RUN", "test-only") for name in REQUIRED}
            result = {
                "candidate_sha": "b" * 40,
                "completed_at_utc": "2026-11-09T16:00:00+00:00",
                "overall": "NOT RUN",
                "checks": checks,
                "ci": status("NOT RUN", "runner not assigned"),
            }
            write_final(report, result)
            sha_entries = (report / "SHA256SUMS").read_text()
            self.assertIn("report.json", sha_entries)
            self.assertIn("native.log", sha_entries)
            self.assertNotIn("  SHA256SUMS", sha_entries)
            recorded = sha_file(artifact)
            self.assertIn(recorded, sha_entries)
            artifact.write_bytes(b"tampered")
            self.assertNotIn(sha_file(artifact), sha_entries)
            self.assertEqual(digest(artifact), hashlib.sha256(b"tampered").hexdigest())

    def test_full_cli_fails_closed_without_reviewed_branch_manifest(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root) / "repo"
            repo.mkdir()
            git_checked(repo, "init", "-q")
            git_checked(repo, "config", "user.email", "test@example.invalid")
            git_checked(repo, "config", "user.name", "Test")
            (repo / "Cargo.lock").write_text("lock")
            git_checked(repo, "add", "Cargo.lock")
            git_checked(repo, "commit", "-qm", "snapshot")
            commit = git_checked(repo, "rev-parse", "HEAD")
            report = Path(root) / "output"
            cmd = [
                sys.executable, str(Path(__file__).with_name(
                    "integration_validate.py")),
                "--repo", str(repo), "--expected-sha", commit,
                "--report-dir", str(report), "--native-only",
            ]
            process = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(process.returncode, 2, process.stderr)
            data = json.loads((report / "report.json").read_text())
            self.assertEqual(data["checks"]["source"]["status"], "PASS")
            self.assertEqual(data["checks"]["ancestry"]["status"], "NOT RUN")
            self.assertEqual(data["overall"], "NOT RUN")
            self.assertEqual(data["checks"]["native_tests"]["status"], "NOT RUN")
            self.assertEqual(data["ci"]["status"], "NOT RUN")
            self.assertTrue((report / "SHA256SUMS").is_file())


if __name__ == "__main__":
    unittest.main()
