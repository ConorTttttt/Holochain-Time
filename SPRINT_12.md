# Sprint 12 — Holochain Conductor Resilience (Agent B)

**Start:** 2026-11-09 · **Track:** runtime engineering, separate from cryptographic-source Sprint 11 · **Base:** current `main` SHA as verified at branch creation.  
**Status:** test implementation drafted; release acceptance requires real execution. No production coordinator changes.

## Goal

A verified proof survives actual conductor restart and a node outage; unavailable or conflicting evidence never becomes trusted by default. Retain `evidence_complete: false` and the conservative author-chain status semantics. Distinguish test harness coverage from a genuine transport partition.

## Deliverables

| Scope | Implementation | Execution requirement |
|---|---|---|
| Conductor restart/recovery | `integration/conductor/tests/resilience.rs` | Run real 3-conductor Sweettest; verify same signed bounds after Bob restart |
| Node outage, survivor writes | `resilience.rs` | Stop Bob, write/verify on Alice/Charlie, restart Bob and await consistency |
| Peer-discovery isolation/rejoin | `resilience.rs` | Disable bootstrapping, verify remote lookup fails, exchange peer info, await DHT sync |
| Missing evidence | `resilience.rs` | Explicit errors on real target with absent anchor/seal hashes |
| Conflicting ancestry | `resilience.rs` | Reject unrelated-author and later anchors |
| Real same-agent fork attempt | `resilience.rs` ignored opt-in laboratory test | Two distinct chain DBs sharing test signer; observer must never declare clean author status |
| Bounded ancestry | `resilience.rs` ignored opt-in | Actual 255-action span succeeds and 257-action span fails; coordinator native 256 succeeds |
| Failure reporting | `scripts/audit_conductor_resilience.py` | Required markers, Rust summary and exact Git SHA; absence rejects |
| Reproducible runner | `scripts/run_conductor_resilience.sh` | Regenerate throwaway DNA, build WASM, run Sweettest, keep logs/hash evidence |
| Runbook | `docs/CONDUCTOR_RESILIENCE_RUNBOOK.md` | Follow separate baseline and full fault-injection gates |

## Required real validation

- [ ] Rust standalone conductor crate compiles against Holochain 0.7.1 and pinned lockfile.
- [ ] Baseline tests actually pass against packed test-only DNA; evidence archive links exact SHA.
- [ ] Full 255/257-boundary and fork lab scenarios pass and have independently reviewed evidence.
- [ ] Add a **true transport-level** partition/rejoin test (not covered by shutdown or bootstrap isolation).
- [ ] Verify explicit 256-action boundary in native coordinator tests, plus 255/257 in conductor.
- [ ] Confirm valid evidence remains durable after actual restart and after unclean crash/fault.
- [ ] Review conflicting activity/warrant responses; neither `None` nor known conflict authorises financial action.
- [ ] Demonstrate genuine independent signed quorum separately (Sprint 11) and Unyt test-funds acceptance.

## Important caveats

This sprint is limited to test-only files. A passing smoke or harness test is not proof of global DHT evidence completeness or independent Roughtime operators. Existing safe fail-closed behavior is verified but **not changed**. Any demonstrated coordinator defect must be isolated and fixed in a separately reviewed production PR, then retested. Wider release remains **NO-GO**.
