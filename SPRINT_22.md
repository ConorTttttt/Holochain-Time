# Sprint 22 — Fork and recovery (Agent L, conductor security)

**Started:** 9 November 2026. **Status:** test harness implemented, real
conductor/warrant execution pending. **Release: NO-GO.**

## Objective

Show that a Holochain 0.7 agent fork is not mistaken for a clean source
chain, that actual integrated warrants remain queryable after conductor
restart, and that genuine signed time evidence still verifies after a normal
node restart. The test plan is a **strict extension** of Sprint 12, not a
replacement for its partition, ancestry or recovery evidence.

## Implemented

| Deliverable | Files / behavior |
| --- | --- |
| Fork fixtures | `integration/conductor/fixtures/fork_recovery_cases.json` — 13 deterministic logical scenarios (conflicting hash at same sequence, repeated record, mislinked parent, invalid/forked status, positive warrant, unknown warrant, incomplete ancestry). These identifiers are **not signed actions**. |
| Conservative detection | `integration/conductor/src/fork_recovery.rs` — test-only classifier never converts missing authority/warrant evidence to a clean result. A valid single path with zero observed warrants is only `supplied_evidence_only`, not global chain clearance. |
| Signed conductor restart | `integration/conductor/tests/fork_recovery.rs` — real three-conductor Sweettest, signed anchor + third-party seal, observer shutdown, survivor write, same-persistent-cell restart/rejoin, bound equivalence, unavailable witness rejection. |
| Real same-agent fork | Ignored opt-in test in `fork_recovery.rs` — two **distinct conductor databases** intentionally use the same public *test* agent key. After reconnection, the observer must obtain an actual **integrated warrant** for the forked agent from the pinned Holochain 0.7.1 DHT store API. |
| Warrant handling | Opt-in test requires `get_warrants_by_warrantee` to return a positive count, rejects a false clean classification, restarts observer, verifies persisted warrant rows and requires the existing witness endpoint to report `Some(true)` or an explicit fork/invalid-chain/warrant integrity rejection. Generic timeouts do **not** pass. |
| Repeatable acceptance | `scripts/run_fork_recovery.sh` — clean source, explicit SHA and publicly known test-only DNA acknowledgement, independent baseline/full modes, exit statuses, provenance, DHT warrant marker, checksummed logs outside checkout. |
| Fail-closed log audit | `scripts/audit_fork_recovery.py` and `scripts/test_audit_fork_recovery.py` — marks a baseline-only run as **not** a fork/warrant certificate, requires real Rust success and unique markers; synthetic Python tests for forged/missing warrant evidence. |

## What this does NOT establish

- The fixture rows are logical examples, not signed or verified Holochain
  actions. Only the opt-in real-conductor test can demonstrate a real
  locally integrated warrant.
- The targeted warrant query observes the **local DHT store** of one lab
  conductor. It does not prove globally complete warrant discovery.
- The same-key fixture uses one local Lair keystore on purpose and does not
  prove independence of real Roughtime operators (Sprint 11).
- Graceful conductor `shutdown` / `startup` is **not** an unclean process
  kill, filesystem corruption test or real transport-level network partition.
- A completed run does **not** certify the financial caller's interpretation
  of `evidence_complete=false` or global chain cleanliness.
- Any change to production coordinator's author-activity or warrant APIs
  must be coordinated with Sprint 12 and the Sprint 11 crypto interfaces.

## Local acceptance gates

1. Exact-commit Python auditor tests, Rust formatting, native classifier,
   core workspace tests and Clippy pass.
2. Packed, TEST-ONLY signed DNA is built with the existing
   `scripts/run_signed_quorum.sh` using publicly known test keys.
3. Three-conductor restart test passes with **unchanged signed bounds**,
   survivor write recovered, same cell identity retained and missing witness
   still rejected.
4. Opt-in same-key fork succeeds at generating at least **one actually
   integrated warrant** against the forked signer on the observer; marker
   and Rust PASS must both exist. No warrant in 120 seconds means BLOCKED.
5. Warrant persists after observer restart and cannot yield an unflagged
   verdict for the forked signer. Generic errors, unknown ancestry or absent
   warrants are not accepted as successful fork detection.
6. Run the prior Sprint 12 resilience regression and all integrated branch
   tests, then archive `provenance.txt`, `results.tsv`, `audit.json`,
   step logs, `SHA256SUMS` under the **exact integrated SHA**.
7. Codex reviews any forks that fail to issue a warrant, the network
   assumptions for authority placement, and any coordinator discrepancy
   before modifying shared runtime code. This branch leaves production
   Rust unchanged.

See `docs/fork-recovery/README.md` for command lines and limitations.
