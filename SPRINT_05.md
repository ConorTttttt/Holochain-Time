# Sprint 5 — Reduce oracle signing pressure

**Started:** 9 November 2026 (expedited)
**Review target:** 20 November 2026 (conditional on runnable CI)
**Branch:** sprint/05-roughtime-first-quorum-2026-11-09
**Stacked on:** Sprint 4 draft PR #24, which depends on #21, #19 and #16.
**Tracking:** Issue #25; P0 #5; conductor #7; CI #22; master release issue #1.

## Goal

When client-supplied, independently signed Roughtime readings already meet the policy quorum, do not contact signing oracles. Preserve the existing nonce and source-binding security requirements.

## Implementation

- [x] Add a core helper that checks the complete Roughtime-only set against the same policy used by validators.
- [x] Use it for create_anchor and seal_action, skipping oracle RPCs only when the full quorum is valid.
- [x] Keep mixed-source collection as fallback for incomplete/invalid sets.
- [x] Refuse evidence sets larger than 32 before any remote oracle request.
- [x] Add native positive and negative regression tests using real roughenough-produced signed readings.
- [x] Document deployment constraints in ADR 005 and README.
- [x] Confirm Holochain 0.7 WASM getrandom flags are already present in the source CI workflow.
- [x] Add local reproducible verification commands while GitHub runner assignment is unavailable.
- [ ] Obtain green native Rust tests, clippy and WASM build on this specific head commit.
- [ ] Run real multi-conductor tests using three independently trusted test Roughtime keys and 100+ distinct seals.
- [ ] Measure no oracle log growth when all client-only readings satisfy quorum; verify mixed source fallback and outages.
- [ ] Resolve GitHub Actions pre-runner incident #22 and obtain independent review.
- [ ] Design secure batched oracle signing and caller-level admission control for deployments that cannot use Roughtime-only quorum.

## Exit gate

Do not close P0 #5 on this capacity optimization alone. The sample DNA has only two Roughtime keys but needs three sources; real deployment requires explicit trusted-key review and a new DNA or migration. True oracle batching, authenticated admission control, conductor E2E tests and Unyt financial proof tests remain open. **NO-GO for wider release.**
