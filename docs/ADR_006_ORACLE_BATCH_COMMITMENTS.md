# ADR 006 — Bounded oracle-batch nonce commitments

**Status:** experimental, unmerged, not accepted as time evidence. **Date:** 9 November 2026. **Holochain target:** HDK 0.7.1 / HDI 0.8.1. **Related:** #5, #7, #12, #22.

## Decision

Implement a deterministic no_std + alloc Merkle primitive for 1–128 distinct nonces in vtime_core::batch. It does **not** change the existing oracle-statement/v2 signature, signed entries, DNA properties or integrity zome. Do not pass its outputs as standalone time evidence.

With H = SHA-512 truncated to 32 bytes, use:

- leaf = H("hc-vtime/oracle-batch/v1/leaf\\0" || dna_hash_39 || nonce_32)
- node = H("hc-vtime/oracle-batch/v1/node\\0" || left_32 || right_32)
- root = H("hc-vtime/oracle-batch/v1/root\\0" || count_u32_le || top_node_32)

Odd-width tree levels duplicate the final child. The inclusion verifier checks that the unpaired sibling equals the node, validates proof height/index/count, and checks root equality. The count is cryptographically committed. Reject zero/over-budget counts and repeated input nonces.

The inclusion proof alone authenticates **neither** the oracle nor its interval. The caller must authenticate a separately signed batch root before interpreting membership as time evidence. No current call path consumes a batch proof.

## Future v3 signed design — required before integration

1. New, domain-separated v3 signed statement must bind DNA, root, nonce count, interval, oracle identity, source-chain seq, prev signature, and the floor/high-water value. Never reinterpret a v2 single-nonce statement as a batch signature.
2. Integrity zome must verify v3 signature, Merkle membership of the seal_nonce(DNA,target), source trust, unique source counting, radius and the exact same quorum and fault model. Deterministic validation only, per the [Holochain 0.7 reference](https://github.com/Soushi888/holochain-agent-skills/tree/main/skills/holochain).
3. Sign and log each batch atomically under an ordered source-chain head. Do not return a signed but uncommitted statement if a concurrent write fails.
4. Operate an authenticated, bounded submission queue with per-caller fairness, idempotent nonce dedup, backlog limits and expiration. Revoke direct unrestricted attest_time access to the signing key, or malicious peers bypass admission. Do not put mutable network counters in integrity validation.
5. Explicit DNA migration (integrity type changes alter DNA hash), Unyt v3 agreement compatibility, outage/Byzantine/clock-backwards tests, 100+ concurrent seal tests, and independent review precede deployment.

## Reproducible vector

DNA = 39 bytes 0x01; nonces = three 32-byte arrays whose first u32 little-endian values are 0, 1, 2 and whose remaining bytes are zero.

Expected root: 41a92f780ccafdcba3a0c058cfaea702d4a3ea83963fa084d874c46f268fe48d

Computed independently with Python hashlib.sha512(...).digest()[:32]. Test native Rust workspace, Clippy and both WASM zomes on exact SHA once GitHub Actions runner issue #22 is resolved.

**Out of scope:** live batch signatures, deployment migration, production throughput and a complete admission queue. Issue #5 remains P0; release gate #1 remains NO-GO.
