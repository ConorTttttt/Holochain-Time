# ADR 004 — Retire unsafe global evidence-index scanning

**Status:** Proposed in Sprint 4; CI, conductor verification and review pending.
**Holochain line:** HDK 0.7.1 / HDI 0.8.1.
**Related issues:** #3, #4, #7, #22 and Sprint 4 #23.

## Threat model

The legacy `get_verified_time` scanned every matching target-to-seal and
author-to-anchor link through `get_links` before imposing candidate limits.
A malicious actor could flood links and consume unbounded DHT response
resources. Partial discovery also cannot certify that contradictory valid
evidence does not exist. Sprint 1's local fail-closed cap was too late
to prevent the initial network work.

## Decision

Keep `get_verified_time(ActionHash) -> ExternResult<VerifiedTime>` as a
**fail-closed compatibility stub** that returns an explicit migration error
before any network calls. This intentionally changes behavior for existing
pre-release callers. No integrity entry/link types or DNA properties change.

Use `verify_time_with_witnesses({ target, anchors, seals })` for known proof
action hashes (at least one). It checks no more than 8 anchors and 32 seals,
rejects duplicate/invalid evidence, and verifies signatures, nonce and
source-chain ancestry. It always returns `evidence_complete: false`.
`NoContradictionInSuppliedProofs` is **not** global consistency or a
financial deadline clearance.

## Client migration

1. Stop calling `get_verified_time`; treat its error as a migration error,
   not a transient failure that should be retried.
2. Obtain evidence hashes from an authenticated proof-submission flow.
   Caller-supplied hashes cannot demonstrate completeness of all third-party
   evidence on the DHT.
3. Call `verify_time_with_witnesses` with the target and one or more anchors
   or seals. Handle unavailable/invalid proofs as failures. An
   `author_chain_flagged` result of `None` means unknown, not healthy.
4. Do not infer safety, publication time or permission to release funds
   from the absence of contradictions in submitted proofs.

## Release review

This respects the [Holochain 0.7 design reference](https://github.com/Soushi888/holochain-agent-skills/tree/main/skills/holochain):
deterministic integrity validation remains unchanged; network-dependent
queries and classification live in the coordinator. A coordinator upgrade
needs a real conductor migration test before deployment.

Run native tests, Clippy and WASM builds on the exact PR SHA. Verify in
a multi-agent conductor that the old API fails before DHT activity and
the witness API correctly checks valid, invalid, third-party and forked
proofs. A source-level no-link-scan guard is not sufficient evidence.

**Not solved:** complete resource-bounded proof discovery, per-record
DHT latency, oracle concurrency, Unyt financial acceptance, or the
independent security audit. Keep release issue #1 in NO-GO state.
