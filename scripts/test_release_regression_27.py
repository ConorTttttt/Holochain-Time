"""Sprint 27 adversarial regression suite: mock artifacts, NOT Holochain acceptance."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import make_reviewed_pins_27 as pins
import release_acceptance_27 as s

SHA = "a" * 40


class DevelopmentVerdictTests(unittest.TestCase):
    @staticmethod
    def complete():
        checks = {}
        for name in s.DEVELOPMENT_GATES:
            if name == "source":
                item = s.gate("PASS", "clean verified source", "PROVENANCE_PASS",
                              evidence={"status": "PASS", "head": SHA})
            elif name == "reviewed_ancestry":
                item = s.gate("PASS", "fully pinned ancestry", "PROVENANCE_PASS",
                              evidence={"branches": [{}] * 8, "pins_sha256": "a" * 64})
            elif name == "config_negative":
                item = s.gate("PASS", "unsafe example blocked", "EXECUTED_PASS",
                              test={"status": "PASS", "exit_code": 0},
                              rejection={"status": "FAIL", "exit_code": 3})
            else:
                item = s.gate("PASS", "executed", "EXECUTED_PASS",
                              run={"status": "PASS", "exit_code": 0,
                                   "log_sha256": "f" * 64})
            checks[name] = item
        checks["fork_warrant"] = s.missing("destructive same-agent fork opt-out")
        checks["oracle_runtime_restart_replay"] = s.missing("not deployed")
        checks["funded_unyt"] = s.missing("no funded settlement")
        return checks

    def test_all_applicable_local_gates_allow_dev_but_not_release(self):
        checks = self.complete()
        ready, verdict, blockers = s.development_readiness(checks)
        self.assertTrue(ready)
        self.assertEqual(verdict, "READY")
        self.assertEqual(blockers, [])
        self.assertEqual(s.overall(checks), "INCOMPLETE")
        self.assertTrue(all(g["status"] == "NOT RUN"
                            for g in s.external_release_checks().values()))

    def test_unexecuted_green_wrapper_is_never_dev_ready(self):
        checks = self.complete()
        checks["rust_tests"] = s.gate("PASS", "self-described", "EXECUTED_PASS")
        self.assertEqual(s.development_readiness(checks)[1], "FAILED")
        self.assertFalse(s.development_readiness(checks)[0])

    def test_real_local_failure_not_downgraded_to_incomplete(self):
        for name in ("rust_tests", "monitoring_offline", "unyt_offline",
                     "roughtime_offline", "config_negative"):
            with self.subTest(gate=name):
                checks = self.complete()
                checks[name] = s.gate("FAIL", "observed test failed", "EXECUTED_FAILURE",
                                      exit_code=1)
                ready, verdict, blockers = s.development_readiness(checks)
                self.assertFalse(ready)
                self.assertEqual(verdict, "FAILED")
                self.assertEqual(blockers[0]["gate"], name)

    def test_missing_23_offline_is_not_silent_or_pass(self):
        checks = self.complete()
        del checks["roughtime_offline"]
        self.assertEqual(s.development_readiness(checks)[1], "INCOMPLETE")
        checks["roughtime_offline"] = s.missing("absent sprint23")
        self.assertEqual(s.development_readiness(checks)[1], "INCOMPLETE")

    def test_optional_fork_missing_does_not_fake_proof_and_failed_run_blocks(self):
        checks = self.complete()
        self.assertEqual(s.development_readiness(checks)[1], "READY")
        checks["fork_warrant"] = s.gate("FAIL", "real warrant absent", "EXECUTED_FAILURE")
        self.assertEqual(s.development_readiness(checks)[1], "FAILED")
        self.assertEqual(s.overall(checks), "FAIL")

    def test_independent_roughtime_antirollback_and_prod_config_still_block(self):
        ext = s.external_release_checks()
        self.assertIn("independent_roughtime_sources", ext)
        self.assertIn("external_anti_rollback", ext)
        self.assertIn("production_configuration_live", ext)
        self.assertTrue(all(v["status"] == "NOT RUN" for v in ext.values()))
        self.assertTrue(all(v["classification"].endswith("PENDING")
                            for v in ext.values()))


class PinsTests(unittest.TestCase):
    def setUp(self):
        self.prs = {number: {
            "state": "open", "head": {
                "ref": branch, "sha": format(number, "040x"),
                "repo": {"full_name": pins.REPO}},
        } for number, branch in pins.AUTHORITATIVE}
        self.tips = {"main": pins.BASE_SHA}
        self.tips.update({branch: format(number, "040x")
                          for number, branch in pins.AUTHORITATIVE})

    def test_live_heads_and_exact_ancestors_required(self):
        manifest = pins.construct_manifest(SHA, self.prs, self.tips, lambda a, b: True)
        self.assertEqual(len(manifest["branches"]), 7)
        self.assertEqual({x["pr"] for x in manifest["review_disposition"]}, {50, 60, 62})
        self.assertEqual({x["branch"] for x in manifest["branches"]},
                         {name for _, name in pins.AUTHORITATIVE})
        pins.validate_authoritative_pins(manifest, candidate=SHA)
        pr, branch = pins.AUTHORITATIVE[0]
        stale = self.tips.copy()
        stale[branch] = "b" * 40
        with self.assertRaisesRegex(ValueError, "outdated PR HEAD"):
            pins.construct_manifest(SHA, self.prs, stale, lambda a, b: True)
        with self.assertRaisesRegex(ValueError, "absent from candidate ancestry"):
            pins.construct_manifest(SHA, self.prs, self.tips,
                                    lambda a, b: a != self.tips[branch])

    def test_missing_and_wrong_authoritative_pr_ref_rejected(self):
        missing = self.prs.copy()
        del missing[65]
        with self.assertRaisesRegex(ValueError, "response missing"):
            pins.construct_manifest(SHA, missing, self.tips, lambda a, b: True)
        wrong = copy.deepcopy(self.prs)
        wrong[65]["head"]["ref"] = "review/sprint25-monitoring-validation-2026-11-10"
        with self.assertRaisesRegex(ValueError, "unexpected live PR"):
            pins.construct_manifest(SHA, wrong, self.tips, lambda a, b: True)
        valid = pins.construct_manifest(SHA, self.prs, self.tips, lambda a, b: True)
        valid["branches"].pop()
        with self.assertRaisesRegex(ValueError, "exactly seven"):
            pins.validate_authoritative_pins(valid, candidate=SHA)
        valid = pins.construct_manifest(SHA, self.prs, self.tips, lambda a, b: True)
        valid["branches"][0]["branch"] = "review/sprint25-monitoring-validation-2026-11-10"
        with self.assertRaisesRegex(ValueError, "unauthoritative"):
            pins.validate_authoritative_pins(valid, candidate=SHA)


class OfflineEvidenceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.out = self.root / "report"
        self.out.mkdir()

    def script(self, path):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

    def put_json(self, file, obj):
        file.write_text(json.dumps(obj) + "\n", encoding="utf-8")

    def checksums(self, folder):
        lines = [f"{s.sha_file(f)}  ./{f.name}"
                 for f in sorted(folder.iterdir())
                 if f.is_file() and f.name != "SHA256SUMS"]
        (folder / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")

    @staticmethod
    def success_run():
        return s.gate("PASS", "exited zero", "EXECUTED_PASS",
                      exit_code=0, command=["bash", "script"],
                      log="result.log", log_sha256="c" * 64)

    def test_23_absent_or_no_executed_tests_never_passes(self):
        self.assertEqual(s.run_roughtime_offline(self.repo, self.out, SHA)["status"], "NOT RUN")
        self.script("scripts/roughtime/check_23.sh")
        (self.out / "roughtime_offline.log").write_text("OFFLINE/COMPILE ONLY\n")
        with mock.patch.object(s, "command", return_value=self.success_run()):
            self.assertEqual(s.run_roughtime_offline(self.repo, self.out, SHA)["status"], "FAIL")
        (self.out / "roughtime_offline.log").write_text(
            "Ran 6 tests in 0.01s\nOK\n" +
            ("test result: ok. 1 passed\n" * 3) + "OFFLINE/COMPILE ONLY\n")
        with mock.patch.object(s, "command", return_value=self.success_run()):
            accepted = s.run_roughtime_offline(self.repo, self.out, SHA)
        self.assertEqual(accepted["status"], "PASS")
        self.assertFalse(accepted["external_acceptance_proven"])

    def test_25_failure_blocks_and_executed_suite_proof_required(self):
        self.script("scripts/ops/check_25.sh")
        with mock.patch.object(s, "command", return_value=s.gate(
                "FAIL", "monitoring tests failed", "EXECUTED_FAILURE", exit_code=1)):
            self.assertEqual(s.run_monitoring_offline(self.repo, self.out, SHA)["status"], "FAIL")
        (self.out / "monitoring_offline.log").write_text(
            "Ran 5 tests in 0.01s\nOK\nSprint 25 OFFLINE regression complete\n")
        with mock.patch.object(s, "command", return_value=self.success_run()):
            self.assertEqual(s.run_monitoring_offline(self.repo, self.out, SHA)["status"],
                             "FAIL")  # missing the second Python suite
        (self.out / "monitoring_offline.log").write_text(
            "Ran 5 tests in 0.01s\nOK\nRan 3 tests in 0.01s\nOK\n"
            "Sprint 25 OFFLINE regression complete\n")
        with mock.patch.object(s, "command", return_value=self.success_run()):
            self.assertEqual(s.run_monitoring_offline(self.repo, self.out, SHA)["status"],
                             "PASS")

    def make_unyt_evidence(self):
        folder = self.root / ("hc-vtime-sprint26-" + SHA[:12] + "-mock")
        folder.mkdir()
        audit = {
            "schema": "hc-vtime/unyt-sprint26-offline-audit/v1",
            "status": "OFFLINE_SUITE_PASS_NO_FUNDED_UNYT_EVIDENCE",
            "git_sha": SHA, "problems": [], "funded_unyt_network_verified": False,
            "native_signed_rave_verified": False, "recipient_accept_verified": False,
            "testnet_transactions_performed": False, "release_ready": False,
        }
        self.put_json(folder / "audit.json", audit)
        (folder / "provenance.txt").write_text(
            f"git_sha={SHA}\nfunding_authorized=false\n"
            "native_unyt_peer_verified=false\ntestnet_transactions_performed=false\n"
            "release_ready=false\nfailed_stages=0\n")
        stages = ("python_dependencies", "offline_unittests", "rust_fmt",
                  "rust_harness", "workspace_tests", "workspace_clippy",
                  "harness_clippy", "audit")
        (folder / "results.tsv").write_text(
            "stage\texit_code\n" + "".join(f"{stage}\t0\n" for stage in stages))
        (folder / "rust_harness.log").write_text(
            "test release_refuses_tampered_duplicate_and_untrusted_proofs ... ok\n"
            "test bond_refuses_forged_or_foreign_proofs ... ok\n")
        self.checksums(folder)
        return folder, audit

    def test_26_audited_signed_proof_is_offline_only(self):
        folder, _ = self.make_unyt_evidence()
        data = s.verify_unyt_offline(folder, SHA)
        self.assertFalse(data["funded_settlement_proven"])
        self.assertEqual(data["stage_exit_codes"]["audit"], "0")

    def test_26_invalid_signature_proof_or_funding_claim_fails(self):
        folder, audit = self.make_unyt_evidence()
        audit["native_signed_rave_verified"] = True  # JSON assertion is NOT native proof
        self.put_json(folder / "audit.json", audit)
        self.checksums(folder)
        with self.assertRaisesRegex(ValueError, "forged funded-acceptance"):
            s.verify_unyt_offline(folder, SHA)
        audit["native_signed_rave_verified"] = False
        self.put_json(folder / "audit.json", audit)
        (folder / "rust_harness.log").write_text("test result: ok. 0 passed\n")
        self.checksums(folder)
        with self.assertRaisesRegex(ValueError, "required adversarial"):
            s.verify_unyt_offline(folder, SHA)
        (folder / "results.tsv").write_text("stage\texit_code\nrust_harness\t1\n")
        self.checksums(folder)
        with self.assertRaisesRegex(ValueError, "missing/failed"):
            s.verify_unyt_offline(folder, SHA)

    def test_26_modified_checksum_inventory_fails(self):
        folder, _ = self.make_unyt_evidence()
        (folder / "audit.json").write_text('{"status":"PASS"}')
        with self.assertRaisesRegex(ValueError, "changed after checksum"):
            s.verify_unyt_offline(folder, SHA)

    def test_failed_26_runner_remains_failed_even_if_audit_file_is_green(self):
        self.script("scripts/unyt/run_sprint26.sh")
        with mock.patch.object(s, "command", return_value=s.gate(
                "FAIL", "invalid signed proof", "EXECUTED_FAILURE", exit_code=1)):
            self.assertEqual(s.run_unyt_offline(self.repo, self.out, SHA)["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
