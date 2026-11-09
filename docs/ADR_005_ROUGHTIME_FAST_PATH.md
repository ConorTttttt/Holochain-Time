# ADR 005 — Roughtime-first anchor and seal quorum

**Status:** Proposed; Sprint 5, 9 November 2026. Requires CI, conductor testing and security review.
**Holochain version:** HDK 0.7.1 / HDI 0.8.1, per locked dependencies.
**Links:** P0 #5, conductor #7, CI incident #22, master release gate #1.

## Decision

Before calling rate-limited Holochain oracles, anchor and seal creation now check whether the client's supplied Roughtime evidence independently satisfies the time policy. The shared core helper uses the existing verify_evidence_set function. It validates **every** supplied reading, including signature and delegation, trusted public key, distinct source, uncertainty radius, fault policy, and the seal's target-specific nonce. Input is limited to 32 items; oversized sets fail before contacting oracles.

Only when this entire Roughtime-only set passes may the coordinator skip oracle RPCs. On partial, duplicated, untrusted, tampered or wrong-nonce evidence, the original mixed Roughtime/oracle path remains in use. The final evidence verification and integrity-zome rules are unchanged.

No signed evidence format, entry type, link type, cryptographic assumption or DNA property changes in this sprint. The Holochain 0.7 architecture reference (https://github.com/Soushi888/holochain-agent-skills/tree/main/skills/holochain) supports keeping dynamic calls in the coordinator and deterministic validation in integrity.

## Capacity and limitations

Each seal remains nonce-bound to one target, so one Roughtime response for another target cannot be reused. Roughtime servers can answer concurrent client requests; providing a full quorum can remove demand for Holochain oracle statements.

**Important:** The example DNA lists only **two** trusted Roughtime keys with min_sources = 3. Thus the fast path cannot work in the default deployment. Real benefit requires a reviewed test/production DNA configured with three or more genuinely independent, trusted Roughtime operators. DNA property changes change the DNA hash and require migration planning. Never insert placeholder or automatically discovered keys.

Oracle-backed seals remain limited by the existing one-statement/second rate limiter, and caller-level spam can still exhaust oracle capacity. This optimization does **not** close P0 #5. A securely batched oracle protocol, fair admission control, quorum outage testing and realistic concurrency measurements are still required.

The existing legacy global get_verified_time method stays disabled (ADR 004); verification of caller-supplied witnesses still cannot establish global evidence completeness.

## Required verification

1. Run the exact SHA through native cargo tests, all-targets clippy and both wasm32 zome builds.
2. Execute a Holochain 0.7 multi-agent conductor test with a DNA using three independent **test-only** Roughtime operators. Create 100+ distinct seals under concurrent load; observe zero new oracle log entries when every seal has a Roughtime quorum.
3. Show malformed, replayed/other-target nonce, duplicate, offline, and untrusted Roughtime answers cannot bypass oracle fallback or weaken final verification.
4. Measure p50/p95/p99 seal latency, throughput, oracle rate-limit errors and network costs; independently review before merge.
5. Verify configuration, outages, secrets, source-chain recovery and Unyt financial tests separately.

**Release decision remains NO-GO.**
