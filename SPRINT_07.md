# Sprint 7 — Restore verifiable CI and release-evidence provenance

**Kickoff:** 9 November 2026 (expedited)
**Branch:** `sprint/07-ci-provenance-2026-11-09`, stacked on Sprint 6 draft PR #28
**Goal:** stop unexecuted workflows from being mistaken for source failures or successful release checks, and establish an auditable exact-commit local verification fallback.

## Completed in this draft

- [x] Inspect latest GitHub Actions runs and individual jobs; Sprint 6 run `42590941521` has no runner or executed steps (confirmed through the GitHub connection).
- [x] Add Python 3 standard-library `scripts/audit_ci.py` to classify a run with exact commit matching, required named job and step status, and pre-runner failures.
- [x] Add offline unit tests for pass, wrong-SHA, pre-runner, executed failure, missing job/step, pending, and CLI offline fixtures.
- [x] Execute offline regression suite locally (9 tests passed).
- [x] Improve `scripts/verify_local.sh` to refuse dirty worktrees, record versions/SHA/Cargo.lock checksum, capture logs and hashes, and verify both WASM zomes with Holochain 0.7 compiler flags.
- [x] Add CI job step running the standalone Python regression suite *when a runner is available*.
- [x] Record escalation procedure and boundaries in ADR 007.

## Blocked / acceptance work

- [ ] A repository administrator inspects the workflow-level error banner, runner availability, Actions/billing quotas and permissions, and reports the actual cause in #22.
- [ ] At least one run with assigned runner and the required native, Clippy and WASM steps passes on this sprint's **exact** head SHA.
- [ ] Reviewers independently verify local Holonix logs if a runner remains unavailable; do not substitute them for real Actions status.
- [ ] The stacked Sprint 3–6 PRs pass on their respective final heads after runner recovery (no inherited green status from Sprint 2).
- [ ] Run actual Holochain 0.7 multi-agent conductor tests, record fixtures and logs, and validate Unyt agreements with test funds.
- [ ] Independent security/audit review; no merge to `main` without the project's required approvals.

## Scope

No new DNA entries, trusted keys, batching format, or oracle signing policy are changed. This is a CI/release-verification sprint, not a fix for P0 #3/#4/#5/#7/#8. The wider release gate #1 remains **NO-GO** until all independent security and integration gates pass.

Holochain reference: https://github.com/Soushi888/holochain-agent-skills/tree/main/skills/holochain (0.7 integrity/coordinator boundary and conductor test guidance).

## Reconciled local-test track

The parallel Sprint 7 branch at b45b682 added the local sprint runner and
LOCAL_TESTING guide. Sprint 8 copied these files and added clean-tree and
reviewed-SHA guards. Consolidation preserves those later guards and records
the original branch as a merge ancestor without reverting the CI provenance
work above. Historical unchecked acceptance items remain release requirements;
current consolidation results are recorded separately.
