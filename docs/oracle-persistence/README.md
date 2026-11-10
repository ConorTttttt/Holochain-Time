# Sprint 24 — Native persistence acceptance runbook

**Status:** source and deterministic crash tests committed; Rust, CI and
integrated oracle signing tests have not yet run in this GitHub-writing
environment. Release stays **NO-GO**.

The new native crate `vtime_oracle_state` is part of the workspace.
It intentionally reuses the *unchanged* Sprint 15 signed-batch verifier
and adds no new external Rust dependencies. `Cargo.lock` has the new
workspace package entry.

## Native test harness

Use a clean checkout of the PR SHA, Rust/Cargo with standard Unix filesystem
semantics (Linux preferred), Python 3, rustfmt and Clippy. No production keys
or Holochain conductor are used in these tests.

```bash
SHA="$(git rev-parse HEAD)"
cargo fmt --all -- --check
cargo test --locked -p vtime_oracle_state --test restart_safety -- --nocapture
cargo test --locked -p vtime_oracle_state --test process_crash -- --nocapture --test-threads=1
cargo test --locked -p vtime_oracle_state --test backup_migration -- --nocapture
cargo clippy --locked -p vtime_oracle_state --all-targets -- -D warnings
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The process-crash test uses `Child::kill()` on a **disposable subprocess**
with a publicly known test-only Ed25519 seed. It first proves the child
reached its intended signing boundary, reaps it, confirms the stale lock
blocks a second opener, then clears that lock as a simulated operator
intervention and checks the recovered state. Disable core dumps if your
host enforces a crash policy. No real Holochain conductor is killed.

## Exact-SHA report runner

```bash
bash scripts/oracle_state/run.sh --expected-sha "$SHA"
```

The runner checks a clean exact commit and refuses unsupported hosts;
executes local reporter tests, Rust formatting, nine deterministic journal
cases, three child-process death cases, three backup/rollback cases,
crate/workspace Clippy and complete workspace tests. It records exact
command and exit code for each stage. `scripts/oracle_state/audit.py`
requires **each individual Rust test name and a genuine PASS summary**;
missing or synthetic success messages never qualify.

A report directory outside the source repo contains `provenance.txt`,
`results.tsv`, individual logs, `audit.json`, and SHA256SUMS.
`LOCAL_PERSISTENCE_REGRESSION_PASS` is a **native test-only** verdict.
It is not Holochain/Unyt/runtime signing acceptance or antirollback proof.

## Boundaries for Sprint 15 and Sprint 21

The signer obtains a trusted DNA39 and oracle key, plus a verified
out-of-band monotonic checkpoint. Callers are serialized per identity
before PREPARE. Journal callback should be a separately reviewed native
Lair/HSM adapter; it may not expose the raw private key or signed payload
before COMMIT is fsynced.

Sprint 21's seal queue is an in-process front-door semaphore; it is not
a durable message queue or signing service. Treat pending/cancelled/timeout
cases as uncertain after `SIGNING`, not HeadMoved-retryable requests.
Safely resending a **committed** output requires an exact match against
`committed_retry`, plus a future externally persisted request-id key.

Read `STATE_FORMAT.md` and `RECOVERY_MIGRATION.md` before any
deployment decision. The native crate is not loaded into the coordinator
zome or signed batch runtime. Production integration remains separate.
