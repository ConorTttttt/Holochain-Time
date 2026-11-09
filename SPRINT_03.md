# Sprint 3 — Roughtime packet hardening

**Status:** Code drafted; CI, interop, and review pending
**Kickoff:** 9 November 2026 (expedited, stacked on Sprint 2)
**Parent:** `sprint/02-proof-witness-api-2026-11-09`
**Related:** #10, #7, #12; release gate #1

## Goal

Bound the amount of attacker-controlled Roughtime data processed by the core RFC 10049 verifier and the standalone UDP client. This sprint does not address DHT evidence discovery or actual conductor integration.

## Completed code changes

- [x] Reject **request packets over 4096 bytes** and **response packets over 16384 bytes**, including the RFC 12-byte frame, before parsing, hashing, or Ed25519 work.
- [x] Reject top-level and nested RFC messages over 16372 bytes before allocating tag/offset vectors.
- [x] Reject empty zero-tag messages with trailing bytes.
- [x] Let the UDP example receive one extra byte to detect datagrams that exceed the response budget, then reject them.
- [x] Add positive and negative size-boundary regression tests.
- [x] Preserve existing RFC and draft-era signature contexts and statement formats.

## Acceptance checklist

- [ ] Native tests: `cargo test --workspace --locked` succeeds for latest commit.
- [ ] Clippy: `cargo clippy --workspace --all-targets --locked -- -D warnings` succeeds.
- [ ] Both Holochain zomes build for wasm32 with the pinned 0.7 toolchain.
- [ ] Test UDP interoperability with representative real RFC and draft servers.
- [ ] Independently review whether 4/16 KiB can reject any historically valid evidence and plan migrations (particularly integrity zome DNA hash) under #12.
- [ ] Execute multi-agent conductor acceptance scenarios from `docs/CONDUCTOR_TEST_MATRIX.md` under #7.

## Residual security risks

- Zome input has already been deserialized when the core verifier runs. The bounds do not cap preceding host/WASM allocation, remote call volume, DHT record retrieval or network latency.
- The legacy public `get_verified_time` still uses unbounded `get_links`; #3/#4 remain release blockers.
- Oracle seal throughput and quorum resilience #5 remain separate release blockers.
- Passing Rust/WASM CI is not a running-conductor test. Do not merge for production use without independent review.

## Holochain guidance

[Holochain 0.7 skill by Soushi888](https://github.com/Soushi888/holochain-agent-skills/tree/main/skills/holochain). Project lockfile pins HDK 0.7.1 and HDI 0.8.1. Verifier limits are deterministic and safe for integrity validation, subject to migration review.
