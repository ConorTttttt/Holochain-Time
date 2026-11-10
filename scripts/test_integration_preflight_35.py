"""Fail-closed Sprint 28–35 acceptance regressions (synthetic; not Holochain)."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import integration_preflight_35 as a
import integration_validate as s17
import release_acceptance_27 as s27

SHA = "a" * 40


class AcceptanceRegressions(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        self.repo = self.root / "repo"
        self.out = self.root / "report"
        self.repo.mkdir()
        self.out.mkdir()

    def source(self, relative, content="test-only"):
        target = self.repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        return target

    def log(self, name, content):
        (self.out / (name + ".log")).write_text(content)

    @staticmethod
    def executed():
        return s27.gate("PASS", "mocked process completed", "EXECUTED_PASS",
                        exit_code=0, command=["test-only"], log_sha256="a" * 64)

    def test_missing_tests_cannot_produce_pass(self):
        result = a.stage(self.repo, self.out, "missing_tests",
                         ["python3", "-m", "unittest"], paths=("missing.py",))
        self.assertEqual(result["status"], "NOT RUN")
        self.assertEqual(result["classification"], "NOT_IN_CANDIDATE")

    def test_ignored_conductor_test_is_not_executed(self):
        self.source("integration/conductor/tests/chaos_recovery.rs")
        self.log("ignored", "running 1 test\n"
                 "test delayed_dht_rejoin_retains_ancestry_and_rejects_false_witnesses ... ignored\n"
                 "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured\n")
        with mock.patch.object(s27, "command", return_value=self.executed()):
            result = a.stage(self.repo, self.out, "ignored", ["cargo", "test"],
                             paths=("integration/conductor/tests/chaos_recovery.rs",),
                             kind="rust", required_names=(
                                 "delayed_dht_rejoin_retains_ancestry_and_rejects_false_witnesses",))
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["classification"], "INVALID_EVIDENCE")

    def test_python_zero_tests_or_only_json_assertions_never_pass(self):
        self.source("scripts/roughtime/test_readiness_28.py")
        self.log("no_tests", '{"status":"PASS","signed":true}\nRan 0 tests in 0s\nOK\n')
        with mock.patch.object(s27, "command", return_value=self.executed()):
            result = a.stage(self.repo, self.out, "no_tests", ["python3"],
                             paths=("scripts/roughtime/test_readiness_28.py",),
                             kind="python")
        self.assertEqual(result["status"], "FAIL")

    def test_explicit_rust_test_execution_passes_not_release(self):
        self.source("tests/integration.rs")
        self.log("positive", "running 2 tests\ntest t::first ... ok\n"
                 "test t::second ... ok\n"
                 "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured\n")
        with mock.patch.object(s27, "command", return_value=self.executed()):
            result = a.stage(self.repo, self.out, "positive", ["cargo", "test"],
                             paths=("tests/integration.rs",), kind="rust",
                             required_names=("first", "second"))
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["classification"], "EXECUTED_PASS")

    def test_feature_enabled_wasm_never_counts_as_default(self):
        for crate in ("vtime", "vtime_integrity"):
            path = self.repo / ("target/wasm32-unknown-unknown/release/" + crate + ".wasm")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"\x00asm\x01\x00\x00\x00good")
        normal = ["cargo", "build", "--release", "--locked", "--target",
                  "wasm32-unknown-unknown", "-p", "vtime_integrity", "-p", "vtime"]
        core = {"checks": {"wasm": {"status": "PASS", "command": normal}}}
        a.validate_default_wasm(self.repo, core)
        (self.repo / "target/wasm32-unknown-unknown/release/vtime.wasm").write_bytes(
            b"\x00asmtest_only_spam_anchor_links")
        self.assertRaisesRegex(ValueError, "test-only", a.validate_default_wasm,
                               self.repo, core)
        core["checks"]["wasm"]["command"] = normal + ["--features", "vtime/dht-spam-test-only"]
        self.assertRaisesRegex(ValueError, "production-default", a.validate_default_wasm,
                               self.repo, core)

    def test_missing_signed_evidence_not_replaced_by_json_pass(self):
        # Core's inherited Sprint 27 evidence auditor rejects self-declared
        # green stages even if all ten wrapper statuses say PASS.
        (self.out / "core").mkdir()
        report = {"schema": "hc-vtime/local-integration-report/v1",
                  "candidate_sha": SHA, "release_ready": False,
                  "checks": {"source": {"status": "PASS"}}}
        log = self.out / "core/fake.log"
        log.write_text("Ran 1 test in 0.01s\nOK\n"
                       "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured\n")
        for source in s27.CORE.values():
            report["checks"][source] = {"status": "PASS", "command": ["test"],
                                         "exit_code": 0, "log": "fake.log",
                                         "log_sha256": s17.sha_file(log)}
        report["checks"]["ancestry"]["branches"] = [
            {"tip_matches_pin": True, "included_in_candidate": True}] * 8
        report["checks"]["ancestry"]["pins_sha256"] = "f" * 64
        for name in ("vtime", "vtime_integrity"):
            output = self.repo / ("target/wasm32-unknown-unknown/release/" + name + ".wasm")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(b"\x00asm\x01\x00\x00\x00")
        (self.out / "core/report.json").write_text(json.dumps(report))
        self.assertRaisesRegex(ValueError, "signed quorum missing native evidence",
                               s27.audited_core, self.out / "core", SHA, self.repo)

    def test_missing_checkpoint_roughtime_funded_unyt_partition_still_unverified(self):
        for key in ("oracle_checkpoint", "live_roughtime_operators",
                    "funded_unyt", "actual_network_partition",
                    "binary_reproducibility", "independent_audit"):
            self.assertIn(key, a.EXTERNAL)
        complete = {name: s27.gate("PASS", "synthetic only", "EXECUTED_PASS")
                    for name in a.DEVELOPMENT}
        self.assertEqual(a.readiness(complete, complete=True)[1], "READY")
        self.assertTrue(a.EXTERNAL)  # Release verdict is hard NO-GO in CLI.
        self.assertEqual(a.readiness(complete, complete=False)[1], "INCOMPLETE")
        del complete["s29_runtime"]
        self.assertEqual(a.readiness(complete, complete=True)[1], "INCOMPLETE")

    def test_exact_commit_mismatch_and_bad_manifest_fail(self):
        result = a.validate_reviewed_pin(self.repo, {"schema": "forged"}, SHA, False)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["classification"], "PROVENANCE_FAILURE")
        self.assertEqual(s17.check_source(self.repo, SHA)["status"], "FAIL")

    def test_unassigned_ci_runner_is_not_run(self):
        state = s17.ci_classification({"state": "before_runner",
                                        "reason": "runner was never assigned"})
        self.assertEqual(state["status"], "NOT RUN")

    def test_source_bundle_is_not_binary_reproducibility(self):
        self.source("scripts/audit35/run_local.sh")
        bundle = self.out / "source-bundle"
        bundle.mkdir()
        (bundle / "provenance.json").write_text(json.dumps({"source_commit": SHA}))
        (bundle / "source.tar.gz").write_bytes(b"synthetic no actual archive")
        (bundle / "dependencies.json").write_text("{}")
        (bundle / "SHA256SUMS").write_text(
            "".join(f"{s17.sha_file(bundle / name)}  {name}\n"
                    for name in ("source.tar.gz", "dependencies.json", "provenance.json")))
        self.log("s35_source_package",
                 "Ran 1 test in 0.001s\nOK\n"
                 f"SOURCE_AUDIT_BUNDLE_VERIFIED_ONLY sha={SHA}\n"
                 "PRODUCTION_RELEASE=NO-GO\n")
        with mock.patch.object(s27, "command", return_value=self.executed()):
            result = a.audit_source_package(self.repo, self.out, SHA)
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["binary_reproducible"])

    def test_absent_supply_chain_tool_is_not_run(self):
        self.source("scripts/audit35/supply_chain.py")
        folder = self.out / "supply-chain"
        folder.mkdir()
        names = ("metadata_workspace", "metadata_conductor", "metadata_load",
                 "rustsec_workspace", "rustsec_conductor", "rustsec_load",
                 "license_and_source_policy")
        (folder / "report.json").write_text(json.dumps({
            "schema": "hc-vtime/sprint35-supply-chain-run/v1",
            "source_commit": SHA, "production_release_ready": False,
            "stages": {k: {"status": "NOT RUN", "reason": "missing cargo-audit"}
                       for k in names}}))
        with mock.patch.object(s27, "command", return_value=s27.gate(
                "FAIL", "scan incomplete", "EXECUTED_FAILURE")):
            result = a.audit_supply_chain(self.repo, self.out, SHA)
        self.assertEqual(result["status"], "NOT RUN")
        self.assertEqual(result["classification"], "MISSING_TOOL_OR_DEPENDENCY")


if __name__ == "__main__":
    unittest.main()
