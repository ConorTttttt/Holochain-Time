# ADR 015 — Signed oracle batch statement v3 (proposed)

**Status:** Proposed, Sprint 15, 9 November 2026. Cryptographic library implementation only; **not live runtime batching**.  
**Owner:** Agent E. **Base:** merged `main` at `800a4bfb950edca8a51aeb337fc8c2bd50a88191`.  
**Related:** ADR 006 (Merkle roots), Sprint 11 (independent external Roughtime), #5 (oracle capacity), #46 (Sprint 15), #1 (release).

## Decision and version boundary

Introduce `vtime_core::signed_batch` as a new, dependency-free `no_std + alloc` v3 protocol. It *uses* Sprint 6 `commit_nonces`, `prove_nonce` and `verify_nonce_inclusion`, but does **not** alter `vtime_core::evidence`, the Roughtime verifier, the shared Ed25519 trait, `oracle-statement/v2`, the integrity zome, coordinator or Unyt agreements. `SignedBatchStatementV3` is a candidate detached Ed25519 envelope over a fixed binary payload. The existing v2 `nonce` field must **never** be interpreted as a Merkle root.

The signer and verifier agree on these fixed-width fields, exactly in order:

| Field | Encoding | Meaning |
|---|---|---|
| Domain | ASCII `hc-vtime/oracle-batch-statement/v3` then NUL | Cryptographic separation from every v2 payload |
| DNA | 39 raw bytes | Holochain DNA hash including `0x84,0x2d,0x24` prefix and canonical DHT checksum |
| Oracle | 32 raw bytes | Ed25519 oracle public key, separately checked against trusted oracle list |
| Merkle root | 32 raw bytes | Existing v1 DNA-bound ordered Merkle root |
| Count | u16 little-endian | Signed leaf count, 1–128 |
| Earliest | i64 little-endian | Signed Unix microseconds (absolute magnitude below 2^53) |
| Latest | i64 little-endian | Signed Unix microseconds, >= earliest |
| Sequence | u64 little-endian | Per-(DNA, oracle) log position, 0 at genesis |
| Prev flag | u8 (0 or 1) | Whether previous 64-byte signature follows |
| Prev slot | 64 bytes | Signature if flagged, all zero if absent |
| Floor flag | u8 (0 or 1) | Whether the previous signed earliest high-water follows |
| Floor slot | i64 little-endian | Floor if flagged, zero bytes if absent |

**Wire length is 238 bytes**, no trailing bytes, variable-length options or alternate integer representation. The signature is **exactly 64 bytes** of Ed25519 over these 238 bytes, verified in strict mode by the existing `Ed25519Verifier` (native Dalek or a future Holochain host verifier). Only the exact sign-domain payload is accepted; canonical decoder rejects any dirty reserved option slot and wrong domain. The fixed layout does **not** rely on Serde map key ordering.

The existing Merkle scheme is preserved unchanged:

```
leaf = SHA512/32("hc-vtime/oracle-batch/v1/leaf\0" || dna39 || nonce32)
node = SHA512/32("hc-vtime/oracle-batch/v1/node\0" || left32 || right32)
root = SHA512/32("hc-vtime/oracle-batch/v1/root\0" || count_u32_le || top32)
```

Odd-level last nodes are duplicated canonically; proofs must have exact depth, count, index and duplicate sibling values. The producer rejects empty, >128, or repeated nonces. **A single membership proof does not demonstrate that *other* leaves have distinct nonces**; an untrusted signer can still commit a repeated nonce. Runtime admission must audit the entire proposed request list and record deduplication before signing.

## DNA and target binding

A verified signed envelope is accepted only against the caller's specific **canonical** expected DNA and an explicit trusted-oracle key allow-list; a raw Ed25519 signature alone is insufficient. `verify_signed_batch_seal_v3` computes `seal_nonce(expected_dna, target_action)` using the existing 39-byte Holochain `ActionHash`, then verifies membership. An inclusion proof for a different target, network, root, count or path is rejected. `verify_signed_batch_nonce_v3` supports independent non-seal nonce consumers, but does not grant permissions or financial certainty.

The `VerifiedBatchV3` type is constructed only after signature and chain checks; its fields are private. After authenticating **one** batch, `verify_authenticated_batch_seal_v3` can verify all 1–128 target proofs against that *same batch* without advancing the oracle sequence again. Replaying the signed statement as a **new batch** against its own last committed chain head must fail.

## Replay, monotonicity and durability

`verify_signed_batch_v3` **requires** the previous verified `BatchChainHeadV3` for non-genesis statements. A new batch must have `seq = prior.seq + 1`, `prev_signature = prior.signature` and `floor_us = prior.next_floor_us` on the *same oracle and DNA*. The new `next_floor_us = max(prior.floor_us, statement.earliest_us)`, and `latest_us` may never be below the authenticated prior floor. A caller cannot use a missing head to verify non-genesis history. Old/replayed/forked batch statements are rejected against the supplied durable head. **A stateless verifier cannot stop genesis replay or fork equivocation globally.** The consuming runtime must serialize concurrent requests, sign + write exactly one log entry per batch and update its durable chain head **atomically** before returning evidence. After restart it must recheck the authenticated chain head from local persistent records; no optimistic result from an uncommitted signature.

This module intentionally does not provide an admission queue, network request auth, signing keystore, persistent log, on-chain entry type or source registration. In particular a caller-supplied `BatchChainHeadV3` must come from verified, persistent prior state; this API cannot establish that provenance.

## Test vector

Use DNA core `[0x01;32]` wrapped in the canonical 39-byte Holochain DNA hash, oracle raw Ed25519 public key `[0xa5;32]`, three nonce leaves `[0x00;32]`, `[0x01;32]`, `[0x02;32]`, earliest = `1792000000000000`, latest = `1792000001000000`, seq = 0, empty previous signature and floor.

- Merkle root: `eae51522aba71db1ec3b53531dfb8f9d0fc5f4dd56aca310850295acdbbdec21`
- Signed bytes: **238**, deterministic layout above.
- `SHA512(signed_bytes)[:32]`: `06287c5cd18b7ea8516caa720859d1f5ab88f58bda29c492de1d112178fd5c8a`

These expected values were separately calculated with Python `hashlib` / BLAKE2b checksum and appear as fixed Rust assertions. **They are test vectors, not trusted oracle signatures.** All test private keys are reproducible fixtures only; never publish production signing credentials.

## Sprint 11 coordination boundary

Sprint 11 may add Roughtime sources, operator metadata and signed evidence policy. Sprint 15 modifies **no** `vtime_core::evidence` policy interfaces, no `roughtime.rs`, no verifier trait implementation, and no Holochain coordinator or integrity zome. Only `src/lib.rs` gains `pub mod signed_batch`; implementers can combine the two independently after review. If Sprint 11 requires a shared source-key type, introduce a separately reviewed adapter *after* both interfaces stabilise.

## Remaining local Holochain acceptance

The following are mandatory after GitHub review and local integration; **none** is delivered by the pure module:

1. Explicit DNA v3 entry/schema migration, typed `BatchOracleEvidence` and deterministic HDI signature + inclusion validation; no reinterpretation of v2 evidence.
2. Authorized, bounded, fairly scheduled queue; atomic one-signature/one-log-entry per batch; persistent high-water and sequence recovery.
3. Correct mixed v2/v3/Roughtime distinct-source counting and Byzantine quorum, without counting one batch as many independent sources.
4. 100+ concurrent action-specific seals on ≥3 agents, restart/replay and fork tests, network partitions, invalid membership proofs, actual resource measurements and Unyt financial compatibility.
5. Independent cryptographic and economic security review, real external trusted providers and full release gates.

**Exit gate:** green native/Clippy/WASM builds on exact reviewed SHA, and Codex conductor acceptance after integration. **Until then, PR is draft and release NO-GO.**
