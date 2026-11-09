# ADR 007 — Exact-commit CI evidence and pre-runner failures

**Status:** Proposed, Sprint 7, 9 November 2026. This does not repair GitHub Actions.
**Issues:** #22 Actions runners, #7 conductor, #1 release readiness.

## Observed evidence

Sprint 2 workflow [42537239767](https://github.com/ConorTttttt/Holochain-Time/actions/runs/42537239767) passed after Rust/Clippy/WASM steps executed. Sprint 6 workflow [42590941521](https://github.com/ConorTttttt/Holochain-Time/actions/runs/42590941521), commit 172f821a4306411d3e83ff2e7443a6d41b8098f2, failed with both jobs **unassigned to runners and no executed steps**. That is not an observed Rust compiler/test failure. The actual reason for runner non-assignment remains unknown.

## Decision

The Python 3 standard-library tool scripts/audit_ci.py inspects a workflow run ID and **full expected 40-character commit SHA**. It reads GitHub API metadata using authenticated gh CLI, or offline run/jobs JSON fixtures. Only return **passed** when the workflow and BOTH jobs are successful on that exact SHA, and the required named steps all executed successfully:

- Native tests and lint: Test Rust workspace; Lint Rust workspace
- Compile WASM zomes: Build zomes

All required jobs failing with empty steps and no runner is classified as before_runner, not as executed_failure. Missing, skipped and wrong-SHA checks fail closed. Exit codes: 0 passed, 1 executed failure, 2 pending/incomplete/data error, 3 pre-runner failure, 4 SHA mismatch. Offline unit tests cover these classifications; they are not Rust source tests.

The script scripts/verify_local.sh provides a secondary path for developers with a compatible Holochain 0.7 Rust and wasm32 toolchain. It rejects a dirty checkout and expected-SHA mismatch, executes locked workspace tests, Clippy and WASM compilation, records toolchain versions, Cargo.lock checksum, job outputs and SHA-256 digests OUTSIDE the source repository. Independent reviewers must inspect these logs; they are not signed attestations.

## Commands

- Offline auditor tests: python3 -m unittest discover -s scripts -p 'test_*.py' -v
- Live metadata: python3 scripts/audit_ci.py --repo ConorTttttt/Holochain-Time --run-id 42590941521 --expected-sha 172f821a4306411d3e83ff2e7443a6d41b8098f2
- Local exact-commit checks in clean checkout: HC_VTIME_EXPECTED_SHA="$(git rev-parse HEAD)" bash scripts/verify_local.sh

The live auditor needs authenticated gh CLI; never paste or commit access tokens.

## Actions administrator investigation

Open [run 42590941521](https://github.com/ConorTttttt/Holochain-Time/actions/runs/42590941521) and inspect any workflow-level diagnostic banner. Review repository and organization **Settings → Actions**, permission policy, hosted-runner access and applicable billing/usage limits. If no explanation is visible, contact GitHub Support. Do not assume the cause from absent runner metadata. Trigger a new workflow on the current PR head and attach actual executed-job logs to issue #22. Previous green results never validate a new commit automatically.

## Non-goals

This does NOT restore CI runner assignment, execute the actual Rust compiler, verify Holochain conductors, test Unyt with funds or close the independent security audit. Release gate #1 remains NO-GO.
