# Sprint 2 — Proof-carrying time verification and conductor testing

**Kickoff:** 9 November 2026 (expedited while Sprint 1 is under review)
**Review target:** 20 November 2026
**Branch:** `sprint/02-proof-witness-api-2026-11-09` (stacked on Sprint 1; do not merge before Sprint 1 checks pass)

## Goal
Introduce an explicitly scoped, **bounded evidence-verification API**, and specify the multi-agent Holochain tests required to validate it. Never misrepresent "no contradiction found in supplied proofs" as global consistency.

## Checklist
- [x] Confirm locked Holochain versions: HDK 0.7.1, HDI 0.8.1, integrity types 0.7.1.
- [x] Apply coordinator/integrity split and deterministic-validation guidance from the supplied Holochain skill.
- [x] Add `verify_time_with_witnesses` with a cap of 8 anchor hashes and 32 seal hashes, rejecting duplicates and malformed/unavailable/unrelated proofs.
- [x] Re-verify anchor ancestry and seal nonce; never enumerate public `get_links` indexes in this endpoint.
- [x] Use `WitnessConclusion` and `evidence_complete: false` rather than global `Consistent`.
- [x] Add native classification tests.
- [x] Record ADR and multi-conductor acceptance matrix.
- [ ] Run and fix Rust native tests, Clippy and WASM build on CI.
- [ ] Implement and run Sweettest multi-agent scenarios, including third-party seals and forks.
- [ ] Run Wind-Tunnel load and link-flood scenarios.
- [ ] Restrict or safely replace old `get_verified_time` before closing #3/#4.
- [ ] Independent security review of query semantics and release suitability.

## Definition of done
1. Reviewed draft PR with source, acceptance matrix and passing native/WASM CI.
2. Recorded multi-conductor test results for all P0 matrix cases.
3. Documented old-API migration: financial consumers must not treat a partial scan as globally complete.
4. No high/critical proof-discovery issues remain.

## Source reference
[Holochain development skill](https://github.com/Soushi888/holochain-agent-skills/tree/main/skills/holochain), specifically the architecture, patterns, ReviewZome, DesignDataModel, testing and Wind-Tunnel references. Target the **locked 0.7.x** APIs, not examples from other Holochain versions.

**Limitations:** proof hashes are caller selected, so a clean result cannot establish global network consistency. Per-record fetch latency, user rate limiting and DHT-wide discovery still need work. No production funds or release approval.
