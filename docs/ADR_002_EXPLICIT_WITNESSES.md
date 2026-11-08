# ADR 002 — Bounded explicit-witness time verification

**Status:** Proposed / implementation draft; conductor and security review outstanding
**Holochain line:** HDK 0.7.1, HDI 0.8.1
**Tracking:** #3, #4, #7

## Problem
Legacy `get_verified_time` queries all links from a target and from the author's anchor index. Local truncation can suppress contradictory proofs; an abort on over-budget links prevents inaccurate verdicts but cannot bound the initial DHT fetch. The absence of a contradictory link in returned data is not proof that none exists globally.

## Decision
Add coordinator API `verify_time_with_witnesses({target, anchors, seals})` with explicit action hashes. Before network access, reject empty or duplicate evidence requests, >8 anchors or >32 seals. Every supplied proof must resolve and pass re-verification. Seals must bind to the target's nonce; anchors must belong to the author's source-chain ancestry. Network failures cause errors rather than silently omitted proofs.

This endpoint makes no `get_links` calls. It returns proven lower/upper bounds, optional author-chain health, and `evidence_complete: false`. Its conclusion is one of `Backdated`, `FutureDated`, or `NoContradictionInSuppliedProofs`—**never** a global `Consistent` verdict.

## Holochain design rules
- **Integrity zome:** immutable TimeAnchor, TimeSeal, OracleLog definitions and deterministic signature/link validation; dependency reads only through appropriate `must_get_*`.
- **Coordinator zome:** network record retrieval, source-chain ancestry, proof selection, time-bound computation and scoped results.
- **Entry/link schema:** unchanged, so this coordinator addition need not migrate the DNA's integrity hash.
- **Trust:** action hashes provided by callers are untrusted pointers; verify author, target, nonce, signature and robust bounds.
- **Threats:** forged proof, unrelated anchor, off-chain fork, third-party seal, missing chain data, index flooding, duplicate hashes, slow DHT queries, unsafe consumer interpretation.
- **Resource limits:** 8+32 is a record-request count bound, not a total memory/time/cost bound; add per-call latency, quota and response size limits before release.

## Alternatives rejected
1. Truncate `get_links`: can hide better or contradictory evidence.
2. Trust only target-author seals: excludes adversarially relevant third-party seals.
3. Call a partial scan globally consistent: false assurance.
4. Assume finite DHT path sharding by itself prevents abuse: any shard can be flooded.

## Follow-up
Legacy `get_verified_time` still performs unbounded link retrieval and must not be used alone for financial decisions. Either remove/lock down this API for consuming agreements or replace it with a sound, defensible completeness protocol. Validate the new endpoint with Sweettest and link-flood tests and obtain independent security review.

## Reference
[Soushi888 Holochain 0.7 skill](https://github.com/Soushi888/holochain-agent-skills/tree/main/skills/holochain) — architecture, patterns, deterministic validation, Sweettest and Wind-Tunnel guidance.
