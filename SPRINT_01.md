# Sprint 1 — Baseline and fail-closed evidence verification

**Window:** 9–20 November 2026  
**Sprint goal:** establish a reproducible source baseline, stop inaccurate confident verdicts when a proof index is over budget, and validate quorum outage assumptions.  
**Status:** changes prepared locally; Rust toolchain / Holochain conductor not available in the review runtime. **No release approval.**

## Scope and status

- [x] Snapshot the uploaded working tree, excluding embedded Git metadata.
- [x] Add fail-closed guards for seals, anchors and ancestry candidates (#3). No query may silently truncate an index and still return a verdict.
- [x] Add an explicit liveness preflight `TimePolicy::check_outage_tolerance` and enforce it for DNA properties (#6).
- [x] Add regression tests for the above guards and outage conditions.
- [ ] Import this source snapshot to the `Holochain-Time` repository via reviewed PR (#2).
- [ ] Run `cargo test --workspace` and clippy on a machine with the Rust toolchain.
- [ ] Build both WASM zomes and run a conductor smoke test.
- [ ] Fix the remaining unbounded `get_links` fetch/index issue (#4) with a design reviewed for proof completeness.

## Evidence-index mitigation (not the final fix)

Before this sprint, queries sorted or truncated links prior to relevance checks, so noise could suppress earlier valid bounds. Sprint 1 rejects over-budget result sets rather than returning a partial `VerifiedTime`. For small result sets, the code considers all discovered seals and anchors and performs all ancestry checks within the budget.

**Residual risk:** `get_links` must retrieve all matching links before the size check. An attacker can still make a target's time query fail or exhaust resources. The fail-closed approach prioritizes correctness over availability, pending index redesign; #3 and #4 remain open until full conductor and flooding tests pass.

## Exit criteria

1. Reviewed GitHub source PR with checkable archive checksum; no credentials in repository.
2. Rust unit tests and clippy pass with pinned dependencies.
3. Signed-off regression demonstrating a noisy index cannot turn `FutureDated` into `Consistent`.
4. Recorded design for bounded, complete index supporting valid third-party seals.
5. Sprint 2 backlog prioritised: bound DHT query costs (#4), seal throughput (#5), conductor harness (#7).

## Commands to run in a Rust-enabled Holochain environment

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown -p vtime_integrity -p vtime
hc dna pack dnas/vtime/workdir
hc app pack workdir
```

The example DNA has placeholder oracle/server keys; substitute verified independent keys in a private deployment configuration before packing. This sprint does not create production-ready keys or publish a hApp.
