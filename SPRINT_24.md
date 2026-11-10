# Sprint 24 — Oracle Persistence and Restart Safety

**Agent N — Oracle runtime and state management. Priority: CRITICAL.**  
**Start:** 10 November 2026. **Status:** GitHub-first implementation, native regression and integrated runtime acceptance pending.  
**Release:** **NO-GO**.

## Security objective

A sequence number, chain predecessor signature and high-water mark are not
protective if the signer or verifier forgets its last accepted statement.
Introduce a **native, append-only, fsync-backed per-(DNA, oracle) journal**
that uses Sprint 15's *unchanged* `verify_signed_batch_v3` and prevents a
signer callback from being re-invoked after the outcome becomes ambiguous.

This is an independently reviewable **candidate native runtime component**.
It does not change Holochain HDK/HDI 0.7 integrity validation, existing v2
signing, or production oracle zome behavior. Integrating the native journal
with Lair/sign_raw and Sprint 21's in-process queue still requires explicit
adapters, migration and real-conductor acceptance.

## Implemented GitHub deliverables

| Requirement | Implementation | Evidence gate |
| --- | --- | --- |
| Durable sequence | `crates/vtime_oracle_state/src/lib.rs`: append-only binary journal per DNA/oracle; complete authenticated history replay | Native restart regression |
| Persisted high-water | Every committed v3 signature is stored; `BatchChainHeadV3` and `next_floor_us` reconstructed from verified signatures | Two-commit restart plus checkpoint test |
| Previous commitment | Delegates exact seq/prev/floor trust checks to existing `verify_signed_batch_v3` | Wrong previous signature/floor, same-seq fork tests |
| Restart-safe replay | No implicit genesis when state is missing; signature/sequence duplicates rejected after restart; exclusive file lock | Replayed genesis, duplicate seq, two-writer tests |
| Uncertain signing | `PREPARE` fsync → `SIGNING` fsync → signer → verify → `COMMIT` fsync → return | Actual subprocess kill at all three boundaries |
| Conflicting histories | Reject alternate same seq, wrong floor, incorrect prior signature and invalid identity/DNA | Native negative tests |
| Corrupt/missing state | Strict magic/version, bounded journal length, length framing, hash chain and Ed25519 replay; truncated tail fails closed | Tamper, partial record, missing journal tests |
| Backup/recovery | `backup_clean` is create-new-only + fsync file/dir; `checkpoint` includes head and digest, `open_checked` enforces externally trusted exact snapshot | Backup, valid restore and rollback refusal tests |
| Deterministic regression | `restart_safety.rs`, `process_crash.rs`, `backup_migration.rs`; disposable public test signer | Exact-SHA runner and native CI |
| State migration | `docs/oracle-persistence/RECOVERY_MIGRATION.md`; no silent v2→v3 reinterpretation | Review with Sprint 15, 21 and operations |

## Critical operator contract

- `Journal::bootstrap_new(..., VerifiedNewIdentity)` may be used **once**,
  only after an independently verified newly provisioned identity. Loss of
  a journal is never a reason to call `bootstrap_new` for the same identity.
- No signature is returned before a fully persisted, cryptographically
  verified `COMMIT` record. The `SIGNING` fence is itself synced before the
  keystore callback runs. A crash with only PREPARE can retry; a crash after
  the SIGNING fence must **quarantine** the signer and must **never** blindly
  call it a second time.
- A crash after COMMIT but before acknowledgment is recoverable with
  `committed_retry(exact_statement)`, which returns the exact original
  signed payload without a second signer call. Bind real caller idempotency
  tokens to full proposals at the future Sprint 21 adapter boundary.
- A journal's cryptographic hash chain and signatures detect local
  corruption, not an attacker restoring an older *internally valid* journal.
  Production antirollback requires the external monotonic checkpoint (or
  equivalent secure counter); `open_checked` matches an authenticated
  checkpoint exactly. Stale checkpoints block and require reconciliation.
- A stale `.lock` after abrupt process death is intentionally blocking;
  clear it **only** after positively establishing no other signer process
  can write that identity's journal.
- No external receipt reconciliation is implemented for a state stuck in
  `SigningMayHaveOccurred`. It needs operator-managed evidence and a
  reviewed exact-signature reconciliation or identity retirement; no
  dangerous auto-reset is included.

## Remaining gates before acceptance

1. Run all native Rust suite, actual child-process kill, test-only backup
   and rollback exercises, Cargo --locked workspace tests, rustfmt and Clippy
   on the exact reviewed SHA.
2. Obtain full passing `scripts/oracle_state/run.sh` report and independent
   code review of file/directory fsync and Unix storage assumptions.
3. Coordinate Sprint 21's queue to serialize work **before PREPARE** and
   never retry `SigningMayHaveOccurred` even after a HeadMoved error.
4. Coordinate Sprint 15's signed-batch verifier and key/DNA trust; no
   production verifier changes in this branch.
5. Integrate the journal into an actual oracle runtime, persistent signing
   key management and conductor or native sidecar, then crash it with
   simulated real network requests. No native on-disk library test may
   substitute for that runtime integration.
6. Implement a trusted remote monotonic checkpoint, external idempotency
   keys and securely reviewed v2/v3 migration. Run backup/restore drills
   against the actual deployed filesystem.
7. Re-run integrated Sprints 11, 15, 21, 22, 23 and 24 and the complete
   release gates; real independent source validation and Unyt review still
   apply.

**Never merge this work as production-ready, nor mistake a green native
journal regression for a deployed crash-safe oracle.**
