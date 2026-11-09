#!/usr/bin/env python3
"""Offline tests for exact-commit CI evidence auditing (no GitHub access)."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from audit_ci import assess

SHA = "a" * 40


def fixture():
    run = {"id": 7, "head_sha": SHA, "status": "completed", "conclusion": "success"}
    jobs = [
        {"name": "Native tests and lint", "status": "completed", "conclusion": "success",
         "runner_name": "runner", "steps": [
             {"name": "Test Rust workspace", "conclusion": "success"},
             {"name": "Lint Rust workspace", "conclusion": "success"},
         ]},
        {"name": "Compile WASM zomes", "status": "completed", "conclusion": "success",
         "runner_name": "runner", "steps": [
             {"name": "Build zomes", "conclusion": "success"},
         ]},
    ]
    return run, jobs


class TestWorkflowAudit(unittest.TestCase):
    def test_complete_success_on_same_sha(self):
        run, jobs = fixture()
        report = assess(run, jobs, SHA)
        self.assertEqual(report["state"], "passed")
        self.assertEqual(report["exit_code"], 0)

    def test_all_pre_runner_failures_do_not_count_as_source_failures(self):
        run, jobs = fixture()
        run["conclusion"] = "failure"
        for job in jobs:
            job.update(conclusion="failure", runner_name=None, steps=None)
        report = assess(run, jobs, SHA)
        self.assertEqual(report["state"], "before_runner")
        self.assertEqual(report["exit_code"], 3)

    def test_executed_failure_classified_separately(self):
        run, jobs = fixture()
        run["conclusion"] = "failure"
        jobs[0]["conclusion"] = "failure"
        jobs[0]["steps"][1]["conclusion"] = "failure"
        self.assertEqual(assess(run, jobs, SHA)["state"], "executed_failure")

    def test_old_green_sha_cannot_validate_new_commit(self):
        run, jobs = fixture()
        self.assertEqual(assess(run, jobs, "b" * 40)["state"], "sha_mismatch")

    def test_missing_required_job_is_incomplete(self):
        run, jobs = fixture()
        self.assertEqual(assess(run, jobs[:1], SHA)["state"], "incomplete")

    def test_missing_required_step_is_incomplete(self):
        run, jobs = fixture()
        jobs[0]["steps"] = jobs[0]["steps"][:1]
        self.assertEqual(assess(run, jobs, SHA)["state"], "incomplete")

    def test_skipped_job_is_incomplete(self):
        run, jobs = fixture()
        jobs[1].update(conclusion="skipped", steps=[])
        self.assertEqual(assess(run, jobs, SHA)["state"], "incomplete")

    def test_running_workflow_is_pending(self):
        run, jobs = fixture()
        run.update(status="in_progress", conclusion=None)
        self.assertEqual(assess(run, jobs, SHA)["state"], "pending")

    def test_offline_cli_fixtures(self):
        run, jobs = fixture()
        with tempfile.TemporaryDirectory() as directory:
            rp, jp = Path(directory) / "run.json", Path(directory) / "jobs.json"
            rp.write_text(json.dumps(run))
            jp.write_text(json.dumps({"jobs": jobs}))
            cmd = [sys.executable, str(Path(__file__).with_name("audit_ci.py")),
                   "--run-id", "7", "--expected-sha", SHA,
                   "--run-json", str(rp), "--jobs-json", str(jp)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["state"], "passed")

    def test_wrong_run_id_rejected_by_cli(self):
        run, jobs = fixture()
        with tempfile.TemporaryDirectory() as directory:
            rp, jp = Path(directory) / "run.json", Path(directory) / "jobs.json"
            rp.write_text(json.dumps(run))
            jp.write_text(json.dumps(jobs))
            cmd = [sys.executable, str(Path(__file__).with_name("audit_ci.py")),
                   "--run-id", "8", "--expected-sha", SHA,
                   "--run-json", str(rp), "--jobs-json", str(jp)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
