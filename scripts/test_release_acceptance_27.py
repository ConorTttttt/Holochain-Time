"""Sprint 27 fail-closed orchestration tests. All native reports here are MOCKS."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

try:
    from . import release_acceptance_27 as s
except ImportError:
    import release_acceptance_27 as s


SHA = "a" * 40


class Sprint27UnitTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.out = self.base / "report"
        self.out.mkdir()
        self.dna = self.base / "test-vtime.dna"
        self.dna.write_bytes(b"test fixture, NOT real Holochain DNA")

    def seal_external(self, folder):
        lines = []
        for source in sorted(folder.iterdir()):
            if source.is_file() and source.name != "SHA256SUMS":
                lines.append(f"{s.sha_file(source)}  ./{source.name}")
        (folder / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def put_json(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")

    def test_overall_rejects_missing_and_failure(self):
        self.assertEqual(s.overall({"one": s.gate("PASS", "ok", "EXECUTED_PASS")}),
                         "LOCAL_TESTS_COMPLETE_NO_RELEASE_APPROVAL")
        self.assertEqual(s.overall({"one": s.missing("missing")}), "INCOMPLETE")
        self.assertEqual(s.overall({"one": s.gate("FAIL", "bad", "EXECUTED_FAILURE"),
                                    "two": s.missing("blocked")}), "FAIL")

    def test_core_rejects_fabricated_pass_without_command_log(self):
        checks = {name: {"status": "NOT RUN", "reason": "mock"}
                  for name in set(s.CORE.values())}
        checks["native_tests"] = {"status": "PASS", "reason": "fake",
                                   "log": "native_tests.log", "log_sha256": "0" * 64}
        self.put_json(self.out / "report.json", {
            "schema": "hc-vtime/local-integration-report/v1",
            "candidate_sha": SHA, "checks": checks, "ci": {"status": "NOT RUN"},
        })
        with self.assertRaisesRegex(ValueError, "log missing or modified"):
            s.audited_core(self.out, SHA, self.repo)

    def test_core_rejects_wrong_sha_and_synthetic_signed_quorum(self):
        checks = {name: {"status": "NOT RUN", "reason": "mock"}
                  for name in set(s.CORE.values())}
        log = self.out / "signed_conductor.log"
        log.write_text("ran a fake test", encoding="utf-8")
        checks["signed_conductor"] = {
            "status": "PASS", "log": log.name, "log_sha256": s.sha_file(log),
        }
        self.put_json(self.out / "report.json", {
            "schema": "hc-vtime/local-integration-report/v1",
            "candidate_sha": SHA, "checks": checks, "ci": {"status": "NOT RUN"},
        })
        with self.assertRaisesRegex(ValueError, "schema/commit mismatch"):
            s.audited_core(self.out, "b" * 40, self.repo)
        with self.assertRaisesRegex(ValueError, "signed quorum missing native evidence"):
            s.audited_core(self.out, SHA, self.repo)

    def test_core_rejects_fake_dna_repack_claim(self):
        checks = {name: {"status": "NOT RUN", "reason": "mock"}
                  for name in set(s.CORE.values())}
        log = self.out / "fresh_dna.log"
        log.write_text("not actually repacked", encoding="utf-8")
        checks["fresh_dna"] = {"status": "PASS", "log": log.name,
                               "log_sha256": s.sha_file(log)}
        self.put_json(self.out / "report.json", {
            "schema": "hc-vtime/local-integration-report/v1",
            "candidate_sha": SHA, "checks": checks, "ci": {"status": "NOT RUN"},
        })
        self.put_json(self.out / "fresh-dna/dna-comparison.json", {
            "expected_sha": SHA, "status": "PASS",
            "checks": {"archive_byte_identical": True},
        })
        with self.assertRaisesRegex(ValueError, "fresh DNA artifact differs"):
            s.audited_core(self.out, SHA, self.repo)

    def test_configuration_negative_must_reject_actual_input(self):
        success = s.gate("PASS", "unit tests executed", "EXECUTED_PASS")
        rejected = s.gate("FAIL", "exit 3", "EXECUTED_FAILURE", exit_code=3)
        (self.out / "config_invalid_example.log").write_text(
            json.dumps({"status": "BLOCKED", "safe_to_install_proven": False}))
        with mock.patch.object(s, "command", side_effect=[success, rejected]):
            result = s.negative_configuration(self.repo, self.out)
        self.assertEqual(result["status"], "PASS")
        (self.out / "config_invalid_example.log").write_text(json.dumps({"status": "PASS"}))
        with mock.patch.object(s, "command", side_effect=[success, rejected]):
            self.assertEqual(s.negative_configuration(self.repo, self.out)["status"], "FAIL")
        with mock.patch.object(s, "command", side_effect=[success, success]):
            self.assertEqual(s.negative_configuration(self.repo, self.out)["status"], "FAIL")

    def test_resilience_must_have_actual_named_conductor_tests(self):
        ok = s.gate("PASS", "fake exit 0", "EXECUTED_PASS")
        (self.out / "restart_recovery.log").write_text("test result: ok. 0 passed", encoding="utf-8")
        with mock.patch.object(s, "command", return_value=ok):
            self.assertEqual(s.rust_recovery(self.repo, self.out, self.dna)["status"], "FAIL")
        (self.out / "restart_recovery.log").write_text(
            "test stop_restart_recovers_signed_proofs_and_missing_witnesses_fail_closed ... ok\n"
            "test disabled_bootstrap_isolation_then_manual_peer_rejoin ... ok\n"
        )
        with mock.patch.object(s, "command", return_value=ok):
            self.assertEqual(s.rust_recovery(self.repo, self.out, self.dna)["status"], "PASS")

    def test_fork_baseline_cannot_pass_as_positive_warrant(self):
        script = self.repo / "scripts/run_fork_recovery.sh"
        script.parent.mkdir()
        script.write_text("# stub", encoding="utf-8")
        self.assertEqual(s.run_fork(self.repo, self.out, SHA, self.dna, enabled=False)["status"],
                         "NOT RUN")
        folder = self.base / ("hc-vtime-fork-recovery-" + SHA[:12] + "-test")
        folder.mkdir()
        (folder / "provenance.txt").write_text(f"git_sha={SHA}\n", encoding="utf-8")
        self.put_json(folder / "audit.json", {
            "schema": "hc-vtime-sprint22-audit-v1", "status": "BASELINE_ONLY_FORK_NOT_RUN",
            "warrant_detection_proven": False,
        })
        self.seal_external(folder)
        (self.out / "fork_warrant.log").write_text(
            f"Fork/recovery report: {folder} (failed steps: 0)", encoding="utf-8")
        ok = s.gate("PASS", "simulated runner finished", "EXECUTED_PASS")
        with mock.patch.object(s, "command", return_value=ok):
            result = s.run_fork(self.repo, self.out, SHA, self.dna, enabled=True)
        self.assertEqual(result["status"], "FAIL")
        self.put_json(folder / "audit.json", {
            "schema": "hc-vtime-sprint22-audit-v1", "status": "FORK_WARRANT_RESTART_PASS",
            "warrant_detection_proven": True,
        })
        self.seal_external(folder)
        with mock.patch.object(s, "command", return_value=ok):
            self.assertEqual(s.run_fork(self.repo, self.out, SHA, self.dna, enabled=True)["status"],
                             "PASS")

    def test_throughput_never_approves_99_seals_or_wrong_commit(self):
        script = self.repo / "scripts/load/run_21.py"
        script.parent.mkdir(parents=True)
        script.write_text("# stub", encoding="utf-8")
        report_dir = self.out / "throughput"
        report_dir.mkdir()
        (report_dir / "samples.csv").write_text("stub", encoding="utf-8")
        accepted = {
            "schema": "hc-vtime/sprint21-seal-throughput/v1",
            "commit": SHA, "status": "PASS", "requested": 120,
            "dna_sha256": s.sha_file(self.dna),
            "queued_gate": {"status": "PASS", "successful": 99,
                            "unique_action_hashes": 99,
                            "third_party_verified_receipts": 12},
        }
        self.put_json(report_dir / "report.json", accepted)
        ok = s.gate("PASS", "simulated runner finished", "EXECUTED_PASS")
        with mock.patch.object(s, "command", return_value=ok):
            self.assertEqual(s.run_load(self.repo, self.out, SHA, self.dna, 120)["status"], "FAIL")
        accepted["queued_gate"]["successful"] = 120
        accepted["queued_gate"]["unique_action_hashes"] = 120
        self.put_json(report_dir / "report.json", accepted)
        with mock.patch.object(s, "command", return_value=ok):
            self.assertEqual(s.run_load(self.repo, self.out, SHA, self.dna, 120)["status"], "PASS")
        accepted["commit"] = "b" * 40
        self.put_json(report_dir / "report.json", accepted)
        with mock.patch.object(s, "command", return_value=ok):
            self.assertEqual(s.run_load(self.repo, self.out, SHA, self.dna, 120)["status"], "FAIL")

    def test_oracle_native_recovery_does_not_imply_runtime_integration(self):
        script = self.repo / "scripts/oracle_state/run.sh"
        script.parent.mkdir(parents=True)
        script.write_text("# stub", encoding="utf-8")
        folder = self.base / ("hc-vtime-oracle-s24-" + SHA[:12] + "-test")
        folder.mkdir()
        self.put_json(folder / "audit.json", {
            "schema": "hc-vtime-sprint24-audit-v1",
            "status": "LOCAL_PERSISTENCE_REGRESSION_PASS", "git_sha": SHA,
            "durable_state_tests_executed": True,
            "real_conductor_signing_integration_proven": False,
        })
        self.seal_external(folder)
        (self.out / "oracle_journal.log").write_text(
            f"Sprint 24 evidence: {folder} (failed stages: 0)")
        ok = s.gate("PASS", "simulated runner finished", "EXECUTED_PASS")
        with mock.patch.object(s, "command", return_value=ok):
            result = s.run_oracle_journal(self.repo, self.out, SHA)
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["runtime_integrated"])

    def test_checksum_manifest_and_gate_table_are_reported(self):
        report = {"candidate_sha": SHA, "overall": "INCOMPLETE",
                  "ci": s.missing("CI did not start"),
                  "release_ready": False,
                  "release_blockers": [{"gate": "funded_unyt", "reason": "test funds not used",
                                        "reference": "https://example.invalid"}],
                  "checks": {gate: s.missing("not run") for gate in s.STEP_ORDER}}
        s.write_reports(self.out, report)
        self.assertFalse((self.out / "SHA256SUMS").read_text().startswith("e3b0"))
        read = json.loads((self.out / "report.json").read_text())
        self.assertEqual(read["overall"], "INCOMPLETE")
        self.assertIs(read["release_ready"], False)
        self.assertIn("funded_unyt | NOT RUN", (self.out / "report.md").read_text())
        hashes = (self.out / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(hashes), 2)
        self.assertNotIn("SHA256SUMS", "\n".join(hashes))
        for line in hashes:
            digest, name = line.split("  ", 1)
            self.assertEqual(digest, hashlib.sha256((self.out / name).read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
