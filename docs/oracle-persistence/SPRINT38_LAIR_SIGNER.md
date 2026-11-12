# Sprint 38: Lair-backed oracle signer and authenticated checkpoint adapter

**Status: engineering candidate. Production signer acceptance NOT claimed.
External checkpoint acceptance BLOCKED (no independent service exists).
Production NO-GO.**

Base: PR #83 candidate `18df72cd1fb7e62f85806122628f932333f58b24`. Tracks
issue #70 and Sprint 29 (`SPRINT_29.md`). Prepared by automated analysis
(Claude Code). No human or independent approval is recorded.

## What is new

Crate `integration/conductor/oracle_signer` (`hc-vtime-oracle-signer`, lib
`vtime_lair_signer`), a member of the conductor workspace. Every registry
dependency is already in the reviewed `integration/conductor/Cargo.lock`; the
lock gains only two path entries (this crate and `vtime_oracle_state`).
`cargo audit` on the updated lock reports the same 11 vulnerabilities,
2 unsound and 6 unmaintained crates as before. The root and load graphs, the
v2 `attest_time` zome, the DNA, signing formats and Unyt rules are
**unchanged**.

| Component | Purpose |
| --- | --- |
| `LairOracleSigner` | `OracleSigner` backed by a Lair keystore over authenticated IPC |
| `SharedLairSigner` | Shareable handle: the runtime signs while a monitor reads status and runs health checks |
| `AuthenticatedCheckpointAnchor<T>` | `CheckpointAnchor` over an independent checkpoint service through a `CheckpointTransport` |
| `record_signing_bytes` | Canonical, domain-separated record shared by the adapter and any service implementation |

## Security design

Invariants preserved from Sprint 24/29 (the runtime and journal are unchanged):

* canonical v3 payloads;
* DNA and oracle identity;
* request idempotency;
* PREPARE → SIGNING → COMMIT journal transitions;
* ambiguous-signature quarantine;
* restart checks;
* monotonic sequence and floor;
* no reply before the external checkpoint advances.

Added by the signer:

1. **Explicit identity binding.** `(DNA, oracle key, Lair tag)` is fixed at
   construction. The Lair entry must be an Ed25519 seed whose public key is
   the oracle key, and it must be **non-exportable** and not deep-locked. The
   check is repeated on every `health_check`.
2. **Authenticated access.** Lair IPC pins the server's public key in the
   connection URL and requires the keystore passphrase. A wrong passphrase
   fails at connect.
3. **Canonical-only signing.** Bytes must decode as exactly one
   `BatchStatementV3`, re-encode identically, validate, and name the bound DNA
   and oracle. Otherwise the call is refused before any Lair request.
4. **Sequence guard (defence in depth).** A sequence at or below one already
   sent to Lair in this process is refused before Lair. The durable journal
   and the external checkpoint enforce this across restarts.
5. **No retries; classified failures.** At most one Lair request per call.
   * `RejectedBeforeKeystore`: no signature can exist.
   * `KeystoreError`: Lair or IPC error, including a lost connection.
   * `Ambiguous`: timed out in flight.
   * `InvalidSignature`: Lair returned bytes that fail verification.

   Only the first proves that no signature exists. The runtime quarantines on
   any failure after its SIGNING fence. A lane with an ambiguous operation
   then **refuses to open** until an operator reconciles or retires it.
6. **Verified output.** A signature is returned only after Ed25519
   verification under the bound key.
7. **Rotation is a plan, not an action.** `plan_rotation` validates a
   distinct, non-exportable next key and lists the required steps: an
   owner-approved DNA/oracle-set change, a new journal, a new anchor genesis,
   and retirement of the old lane. It changes nothing.
8. **Poisoned lock.** If an earlier call panicked, `SharedLairSigner` refuses
   to sign.

Checkpoint adapter:

* every read and every compare-and-swap carries a **fresh random 32-byte
  challenge**. The service signs `(domain, DNA, oracle, version, checkpoint,
  challenge)` with its own Ed25519 key, which is pinned out of band;
* replayed old replies fail, even across restarts, because the challenge
  differs. Version regressions and same-version equivocation are rejected
  within a process;
* compare-and-swap advances only from the last authenticated record, by
  exactly one version and one sequence, to exactly the requested checkpoint.

## Executed tests (exact commit recorded in the PR)

`cargo test --locked -p hc-vtime-oracle-signer` in `integration/conductor`,
with `HC_VTIME_REQUIRE_LAIR_PROCESS=1`, ran 14 tests, all passing:

| Mission case | Test | Lair |
| --- | --- | --- |
| Successful signing | `signs_through_lair_commits_journal_and_advances_external_checkpoint` | in-process IPC server |
| Invalid request rejection | `invalid_request_rejected_before_any_lair_call`, `adapter_refuses_arbitrary_…` | in-process IPC |
| Wrong-DNA rejection | `adapter_refuses_arbitrary_wrong_dna_wrong_oracle_and_replayed_sequence` | in-process IPC |
| Duplicate request | `duplicate_request_returns_original_signature_without_new_lair_call` | in-process IPC |
| Ambiguous signing result | `ambiguous_lair_outcome_quarantines_and_restart_never_resigns`: server stalled, request in flight, client timeout | in-process IPC |
| Failed signer invocation | `separate_lair_process_sigkill_restart_and_authentication`: keystore SIGKILLed mid-operation | **separate `lair-keystore` 0.7.1 process** |
| Process crash / restart | same test, plus `restart_after_success_…` and `separate_lair_process_restart_between_successful_signatures` | separate process (persisted SQLite store) |
| Stale checkpoint rejection | `replayed_forged_and_regressed_checkpoints_are_rejected` | — |
| Backup rollback | `journal_backup_rollback_is_rejected_by_external_checkpoint` | in-process IPC |
| Key mismatch | `identity_binding_rejects_…`, `runtime_refuses_signer_for_another_oracle` | in-process IPC |
| Unauthorized signer access | wrong passphrase (in-process and separate process); exportable and unknown tags refused | both |
| Checkpoint write failure | `checkpoint_write_failure_withholds_signature_and_blocks_restart` | in-process IPC |

Also run: `cargo fmt --check`, and `cargo clippy --all-targets -D warnings`
for the crate.

All keys are **test identities** created in temporary keystores. The
checkpoint service in the tests is a **test double**.

## What this does NOT demonstrate (blockers)

| Item | Status |
| --- | --- |
| Production key custody (HSM or reviewed Lair deployment, operator separation, backup of key material) | **NOT DEMONSTRATED** |
| Sole-signer enforcement across hosts for one key | **NOT DEMONSTRATED** (journal lock is per host) |
| Independent external monotonic checkpoint service | **BLOCKED**: none exists; the in-memory double proves the protocol logic only, not anti-rollback |
| Caller authentication and globally unique request IDs (RPC) | not implemented |
| Monitored oracle clock | not implemented (test clock) |
| Live conductor integration / v2→v3 transition | not started; requires Sprint 15/21 owner decisions |
| SIGKILL of the **oracle** process at PREPARE/SIGNING/COMMIT/anchor boundaries with Lair | covered only for the keystore process here; Sprint 24 `process_crash` covers the runtime with test keys |
| Independent review | not obtained (#14) |

## Executable test plan for the external checkpoint (when a service exists)

1. Deploy the service on separate infrastructure under a different operator.
   Record its Ed25519 public key out of band, and the oracle operator's
   access credentials.
2. Implement `CheckpointTransport` for its API (TLS plus client
   authentication).
3. Re-run `replayed_forged_and_regressed_checkpoints_are_rejected`,
   `journal_backup_rollback_…` and `checkpoint_write_failure_…` against the
   real transport.
4. Restore an older oracle VM snapshot (journal **and** anchor client state)
   and show that open fails against the live service.
5. Kill the oracle between local COMMIT and CAS acknowledgement. Show that
   restart refuses to open until operator reconciliation.
6. Make the service unavailable. Show that signing stops (no reply without
   CAS) and resumes only after an authenticated read.
7. Have the service operator attempt a rollback. Show detection, which needs
   a second witness or transparency log; this protocol cannot detect a
   malicious service that signs an old state for a new challenge. This is a
   trust assumption to be reviewed.

Acceptance requires the logs, exact SHAs and SHA-256 manifests, plus
independent review.
