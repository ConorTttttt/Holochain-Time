# Sprint 15 — Signed runtime batching (Agent E)

**Date:** 9 November 2026 · **Base:** main `800a4bfb950edca8a51aeb337fc8c2bd50a88191` · **Tracking:** #46.  
**Scope:** Pure `vtime_core` cryptography and protocol design; no Holochain runtime or production zome modification.

## Implementation

- [x] New v3 statement and detached signature structures; strict fixed-size, 238-byte deterministic signed encoding and decoder.
- [x] New domain separated from legacy `oracle-statement/v2`; exact DNA hash, trusted oracle key, count, interval, prior chain reference and floor signing.
- [x] Reuse Sprint 6 Merkle root/proof, enforce 1–128 count, reject duplicate and oversized producer batches.
- [x] Prove a target-specific seal nonce, reject wrong action, wrong DNA, invalid proof, wrong signature, unknown oracle and excessive radius.
- [x] Checked `seq/prev/floor` against supplied durable previous verified head; replay/fork/out-of-order rejection. Multi-nonce verification from **one authenticated batch** does not advance the chain head repeatedly.
- [x] Positive/negative signed Ed25519 Rust tests, 128-leaf scenario, malformed decoder cases and independent Python encoding vector.
- [x] ADR 015 and explicit integration/release boundaries.
- [ ] Native `cargo test -p vtime_core --test signed_batch_protocol --locked` passes on exact PR head.
- [ ] `cargo test --workspace --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, WASM zome build on exact PR head.
- [ ] Independent review of encoding, chain-head assumptions, mutation tests and mixed-source policy integration.
- [ ] Runtime: introduce *new* v3 integrity evidence, signing queue and atomic log write, real Holochain conductor concurrency/restart/replay, test-funds Unyt proof tests. **This belongs to a later reviewed integration PR.**

## Explicit interface ownership

Only `crates/vtime_core/src/signed_batch.rs`, `crates/vtime_core/tests/signed_batch_protocol.rs`, `crates/vtime_core/src/lib.rs` (one mod line), `docs/ADR_015_SIGNED_BATCH_PROTOCOL.md` and `SPRINT_15.md` are modified. Do not modify Sprint 11's Roughtime source verification or existing evidence interfaces. Don't merge untested cryptography to `main`.

## Known limits

Merkle membership is not globally complete evidence nor a proof of uniqueness of *other* leaves. A separate durable verified head is required to stop chain replay and fork admission; it must be protected by the runtime. A signed root is not a quorum, nor a receipt that the oracle committed it to source chain. One v3 batch can serve many sealed nonces only after it was verified once and logged atomically. User's local Codex is responsible for proving those properties through the actual Holochain conductor.
