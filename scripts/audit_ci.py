#!/usr/bin/env python3
"""Audit that required GitHub Actions steps executed on the exact commit."""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REQUIRED = {
    "Native tests and lint": ("Test Rust workspace", "Lint Rust workspace"),
    "Compile WASM zomes": ("Build zomes",),
}
EXITS = {"passed": 0, "executed_failure": 1, "incomplete": 2,
         "pending": 2, "before_runner": 3, "sha_mismatch": 4}


def assess(run, jobs, expected_sha):
    report = {
        "run_id": run.get("id"), "actual_sha": run.get("head_sha"),
        "expected_sha": expected_sha, "checks": [],
        "workflow_status": run.get("status"),
        "workflow_conclusion": run.get("conclusion"),
    }

    def finish(state, reason):
        report.update(state=state, reason=reason, exit_code=EXITS[state])
        return report

    if not re.fullmatch(r"[a-fA-F0-9]{40}", expected_sha):
        return finish("incomplete", "Expected SHA must be a full 40-character hash")
    if run.get("head_sha") != expected_sha:
        return finish("sha_mismatch", "Checks belong to another commit")
    if run.get("status") != "completed":
        return finish("pending", "Workflow is not completed")
    by_name = {job.get("name"): job for job in jobs}
    if any(name not in by_name for name in REQUIRED):
        return finish("incomplete", "Required native or WASM job is missing")

    pre_runner = 0
    executed_failure = 0
    incomplete = 0
    for name, needed_steps in REQUIRED.items():
        job = by_name[name]
        steps = job.get("steps") or []
        by_step = {step.get("name"): step.get("conclusion") for step in steps}
        no_runner = (not steps and not job.get("runner_name")
                     and job.get("conclusion") == "failure")
        passed = (job.get("status") == "completed"
                  and job.get("conclusion") == "success"
                  and all(by_step.get(step) == "success" for step in needed_steps))
        failed = bool(steps) and (
            job.get("conclusion") == "failure"
            or any(by_step.get(step) == "failure" for step in needed_steps)
        )
        pre_runner += int(no_runner)
        executed_failure += int(failed)
        incomplete += int(not passed and not failed and not no_runner)
        report["checks"].append({
            "name": name, "passed": passed,
            "executed_any_steps": bool(steps),
            "failed_before_runner": no_runner,
            "required_steps": {s: by_step.get(s) for s in needed_steps},
        })
    if pre_runner == len(REQUIRED):
        return finish("before_runner", "All jobs failed without runner or executed steps")
    if executed_failure:
        return finish("executed_failure", "A job executed and failed; inspect logs")
    if incomplete or pre_runner:
        return finish("incomplete", "One or more required steps lack passing execution evidence")
    if run.get("conclusion") != "success":
        return finish("incomplete", "Workflow not successful")
    return finish("passed", "Native, Clippy and WASM steps all passed on exact SHA")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="ConorTttttt/Holochain-Time")
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--run-json", type=Path)
    parser.add_argument("--jobs-json", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
        parser.error("--repo must be owner/repo")
    if args.run_id <= 0 or bool(args.run_json) != bool(args.jobs_json):
        parser.error("positive --run-id and either both or neither offline fixtures required")
    try:
        if args.run_json:
            run = json.loads(args.run_json.read_text())
            data = json.loads(args.jobs_json.read_text())
        else:
            def gh(endpoint):
                raw = subprocess.check_output(
                    ["gh", "api", "repos/" + args.repo + "/" + endpoint],
                    text=True, stderr=subprocess.PIPE
                )
                return json.loads(raw)
            run = gh("actions/runs/" + str(args.run_id))
            data = gh("actions/runs/" + str(args.run_id) + "/jobs?per_page=100")
        jobs = data.get("jobs") if isinstance(data, dict) else data
        if not isinstance(run, dict) or not isinstance(jobs, list):
            raise ValueError("Invalid run/job metadata")
        if run.get("id") != args.run_id:
            raise ValueError("Metadata run ID mismatch")
        result = assess(run, jobs, args.expected_sha)
    except (OSError, subprocess.CalledProcessError, ValueError, json.JSONDecodeError) as exc:
        print("Unable to check workflow evidence: " + str(exc), file=sys.stderr)
        return 2
    output = json.dumps(result, indent=2, sort_keys=True)
    print(output)
    if args.output:
        args.output.write_text(output + "\n")
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
