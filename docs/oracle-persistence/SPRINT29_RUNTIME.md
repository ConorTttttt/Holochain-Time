# Sprint 29 — Native v3 oracle runtime integration and recovery

**Candidate only; production oracle integration not established.** The active Holochain coordinator `attest_time` signs v2 `OracleTimeStatement` through `sign_raw`, and the new runtime signs different v3 batch bytes. There is no safe drop-in connection to the current coordinator or Unyt interface. Neither a private HSM key nor a trusted external checkpoint service is supplied here.

## Integration entrypoints

`crates/vtime_oracle_state/src/runtime.rs` exposes:

- `OracleSigner::public_key` and `sign_once`: adapt to a reviewed separate key service (Lair/HSM), do not load a private key into the oracle API process or permit a generic arbitrary-message signing endpoint. The signer must allow only canonical, authorized v3 batch bytes. Keep sole ownership of key/DNA identity across hosts.
- `CheckpointAnchor::load_authenticated`: fetch the **latest** independently verified checkpoint bound to expected DNA and oracle, not a self-reported local copy.
- `CheckpointAnchor::compare_and_store_monotonic`: atomically compare the previous checkpoint and commit its successor in independently administered durable storage, rejecting stale writers. Backend must implement a monotonic read/write contract and not be reset with the oracle disk.
- `OracleRuntime::open`: refuses a mismatched signer key, missing state, corrupt journal, wrong policy, stale checkpoint, uncertain SIGNING and untagged legacy journal history.
- `OracleClock::now_us`: supply an oracle-controlled, monitored and policy-bounded time source; the runtime derives the interval from its configured radius. Requesters cannot supply timestamps.
- `OracleRuntime::sign(BatchSignRequest)`: accepts a 32-byte **authenticated, globally unique** caller request ID and nonces; computes the DNA-bound Merkle root and duplicate-checked count internally. It constructs seq/prev/floor **only from the verified persisted head**, then atomically binds ID to proposal in a PREPARE_REQUEST record. The journal signs once and re-verifies the Ed25519 result before COMMIT. The trusted anchor must acknowledge the exact new checkpoint before the signed output can leave the runtime.

The oracle clock must not be sourced from untrusted caller timestamps; its uncertainty, outage handling and maximum radius must be independently reviewed. The runtime instance must be driven from one blocking per-(DNA,oracle) queue / dedicated worker thread. No async cancellation may interrupt it between SIGNING and COMMIT. An upstream authenticated transport is required; do not accept unauthenticated public clients' arbitrary statements. No in-process queue can prove multi-host single-writer key exclusivity. The Sprint 21 HeadMoved retry classification must never call this signing lane again.

## New journal record

Existing Sprint 24 format stays readable. Type `5` (`PREPARE_REQUEST`) stores `1-byte type || 32-byte request_id || canonical BatchStatementV3 signing bytes`, followed by the existing length/hash framing and file fsync. Existing `2 SIGNING` and `3 COMMIT` records are unchanged. Replay ties `COMMIT` to the preparatory ID and saves historical committed signed bytes, even after subsequent batches. A duplicate ID cannot start another signer callback. A legacy `1 PREPARE` or `4 ACCEPT` record is accepted by the low-level journal for backward compatibility but permanently marks that journal as untracked; `OracleRuntime::open` then refuses it.

Existing `Checkpoint` remains a digest of **all** journal bytes and the authenticated sequence/signature/high-water. This means v3 runtime request bindings are included in externally anchored history, without changing the v3 signing domain or Sprint 15 verifier.

## Recovery decision table

| Durable local state | Latest trusted anchor | Runtime action |
| --- | --- | --- |
| Clean, exact match | Exact journal checkpoint | Permit new ID or resend exact old committed ID without signing |
| PREPARE_REQUEST only | Exact pre-prepare committed prefix | Resume the **same** request after re-authentication; reject different ID |
| SIGNING, no COMMIT | Any | Quarantine; no signing retry; operator reviews HSM/external receipt |
| COMMIT, anchor update succeeded but response lost | Exact new checkpoint | Resend original signature for exact ID without signer callback |
| COMMIT, anchor update uncertain/failed | Old or unknown checkpoint | Withhold signature, quarantine; human-reviewed reconciliation against external receipt/source chain |
| Local journal behind a newer valid anchor | Newer than local | Block: probable rollback; restore latest independently authenticated backup or retire identity |
| Corrupt, truncated, wrong DNA/key/radius, missing journal | Any | Fail closed; no genesis bootstrap |
| Journal contains legacy untagged requests | Any | Block new runtime; migrate only after independently reviewed key/DNA and history procedure |

A local journal digest is not a trusted freshness oracle. In particular, **do not** make `CheckpointAnchor` write to a file alongside this journal and then claim rollback resistance. Matching local copies, object storage with rewritable versions, and a checkpoint without a secure monotonic freshness policy do not suffice.

## Provisioning and migration

1. Pause v2 traffic and keep existing v2 keys, statements, DNA rules and Unyt contracts unchanged. The v3 runtime is a **new protocol service** until a separate reviewed protocol upgrade happens.
2. Provision a genuinely new v3 signing identity with a separately verified key and DNA/policy mapping. Only after independent human approval use the low-level `Journal::bootstrap_new(VerifiedNewIdentity)` **once**.
3. Record the pristine journal checkpoint at a trusted monotonic external anchor. A durable anchored genesis is mandatory; `OracleRuntime::open` has **no bootstrap fallback**.
4. Connect an authenticated operator-controlled signing adapter, monitored clock adapter and independently protected checkpoint backend. Verify current checkpoint and authenticated request IDs before enabling admission.
5. Never call the legacy `Journal::prepare` / `accept_verified` APIs on a journal served by this runtime: they cannot establish the historic idempotency mapping.
6. For clean shutdown, quiesce the queue, let COMMIT + anchor finish, terminate process and reopen with the latest trusted checkpoint. After SIGKILL, establish signer death before removing stale `.lock` manually; do not auto-expire it.
7. If the outcome after SIGNING is unknown, freeze signing authority; collect verified external receipts, HSM records and source-chain facts. Do not auto-reset or guess that the signature was not issued. An updated checkpoint may be recorded only after independently reviewed reconciliation.

## Local tests — evidence is pending

On a host with the pinned Rust/Cargo toolchain, a genuine cloned checkout, and Unix fsync semantics:

```bash
git rev-parse HEAD
cargo fmt --all -- --check
cargo test -p vtime_oracle_state --locked --test runtime_integration -- --nocapture
cargo test -p vtime_oracle_state --locked --test restart_safety
cargo test -p vtime_oracle_state --locked --test process_crash -- --test-threads=1
cargo test -p vtime_oracle_state --locked --test backup_migration
cargo clippy -p vtime_oracle_state --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The in-memory test anchor and deterministic test signing seed provide no security assurance for any live service. Capture exact SHA, executed test names, exit codes, logs and checksums outside the repository. Then perform **real** HSM/Lair+conductor crash and external anti-rollback acceptance before closing the sprint.

Integration API note: `OracleRuntime::open` accepts a `RuntimePolicy` containing the DNA, oracle identity and maximum/configured radii. Signer, authenticated checkpoint anchor, oracle clock and cryptographic verifier remain explicit dependencies; all existing identity and policy checks are retained.
