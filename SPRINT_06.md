# Sprint 6 — Secure oracle batching foundation

**Kickoff:** 9 November 2026 · **Review target:** 20 November 2026 subject to CI recovery. **Branch:** sprint/06-oracle-batch-commitments-2026-11-09. **Stacked on:** Sprint 5 PR #26 (previous stacked drafts unmerged).

## Objective

Implement and review a bounded Merkle nonce-membership primitive for a *future* signed batch statement without weakening single-nonce v2 seals or making unverified time claims.

## Checklist

- [x] no_std + alloc Merkle construction with 128-unique-nonce cap, domain-separated leaf/node/root hashes, DNA and leaf-count binding.
- [x] Canonical inclusion proof verification (exact depth, index, odd-leaf sibling).
- [x] Native Rust regression tests: 100/128 proof positions, duplicates, cross-DNA replay, target mismatch, corrupt metadata, and independent fixed vector.
- [x] ADR 006: required v3 signature, integrity validation, migration, atomic logs and authenticated fair admission queue.
- [ ] GitHub Actions native tests, Clippy, both WASM builds on exact Sprint 6 head; issue #22 still blocks runner assignment.
- [ ] Independent cryptographic review and malformed-proof fuzzing.
- [ ] Implement a real authenticated admission queue and v3 signed batch with integrity verification in a reviewed migration.
- [ ] Holochain multi-conductor + Unyt interoperability + 100+ concurrent seals with signatures/log count and tail latency measured.

## Explicit non-goals

This sprint does not enable batched signing or time-evidence acceptance, and does not solve live oracle throughput. P0 #5 remains open, as do conductor #7 and release NO-GO gate #1.
