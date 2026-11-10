# Cryptographic protocol and evidence-binding review guide

**Source of truth:** `crates/vtime_core/src/{keys,hash,statement,signed_batch,batch,roughtime,evidence}.rs`, `docs/oracle-persistence/STATE_FORMAT.md` and Unyt `execution_code.rhai` consumers at candidate commit. This is a documentation index, not a claim of formal verification or independent cryptographic audit.

## Identity and encoding

- Holochain `AgentPubKeyB64` and `DnaHashB64` are `u` + 52 unpadded base64url characters for 39 bytes: **3-byte typed prefix**, 32-byte value and 4 DHT location/checksum bytes. `keys.rs` enforces exact prefix, length, canonical spelling and the BLAKE2b-128 4-byte XOR-folded checksum. The raw 32-byte oracle signing key is distinct from the 39-byte Holochain hash representation.
- Roughtime Ed25519 root keys are parsed from *standard* base64, not Holochain agent text. Explicit operator allowlists must bind a root key to the operator and the supported protocol/version; malformed or re-encoded keys are not equivalent proof.
- Hash primitive `H(inputs)` is `SHA-512(inputs)[0..32]` (`hash.rs`). This is a **truncation of SHA-512**, not SHA-256. Domain separators and byte ordering are security-critical.
- Exact DNA hash binds statements and Merkle leaf commitments. Integrity properties and network seed changes alter the DNA; do not alias old and new networks.

## Oracle v2: live coordinator and Unyt compatibility

`OracleTimeStatement` is domain `hc-vtime/oracle-statement/v2`. Its Ed25519 signature is over the **canonical named-struct MessagePack** representation using `holochain_serialized_bytes::encode`/pinned `rmp-serde`, with fields in order: `dna, domain, earliest, floor, latest, nonce, oracle, prev, seq`. The decimal time, floor and sequence are canonical text; `prev` is lowercase hex of the prior 64-byte signature or empty at genesis. Nonce is 32 bytes represented as lowercase hex; `floor` is absent/empty at genesis. Implementations must recompute the exact bytes, validate DNA/key text and reject malformed numbers before trusting signatures.

The active Holochain coordinator `dnas/vtime/zomes/coordinator/vtime/src/lib.rs::attest_time` signs v2 through the HDK host `sign_raw` and source-chain logs the result. A successful native signature verification alone does not establish that an action is published, known to independent authorities, unwarranted, or final enough for financial use.

## Oracle v3: separate candidate batch format

`signed_batch.rs` defines the **distinct** domain bytes `b"hc-vtime/oracle-batch-statement/v3\\0"`. Signing payload is fixed-width:

```
domain_terminated | dna[39] | raw_oracle_pubkey[32] |
merkle_root[32] | nonce_count:u16le |
earliest_us:i64le | latest_us:i64le | seq:u64le |
prev_present:u8 | prev_signature[64] (all zero if absent) |
floor_present:u8 | floor_us:i64le (zero if absent)
```

Validation requires 1–128 nonces, a checked interval, exact previous committed signature, consecutive sequence and high-water floor; non-genesis prev/floor cannot be omitted. The detached signature is **exactly 64 bytes**. `verify_signed_batch_v3` authenticates the signer against an explicit allowlist, DNA, radius and prior trusted chain head. It does **not** independently persist state or establish a Holochain source-chain action.

The batch primitive (`batch.rs`) computes:
```
leaf = H("hc-vtime/oracle-batch/v1/leaf\\0" || dna39 || nonce32)
node = H("hc-vtime/oracle-batch/v1/node\\0" || left32 || right32)
root = H("hc-vtime/oracle-batch/v1/root\\0" || count:u32le || top32)
```
Odd leaves duplicate the final node; membership verification checks path/index/count. Roots do not independently sign time, confer quorum or prove uniqueness across distinct batches. **Never** reinterpret an old v2 nonce statement as a signed v3 Merkle root; compatibility needs a versioned signed policy and reviewed DNA/Unyt upgrade.

## Roughtime and quorum

`roughtime.rs` supports RFC 10049 and a specified legacy draft code path (verify the runtime version offered and accepted). It limits request packets to 4 KiB and response packets to 16 KiB, validates frame/tag/order/length, delegated root signature, Merkle path and nonce binding. A local cryptographic signature is not evidence of **external operator independence, freshness, network reachability or clock quality**. `evidence.rs` computes time bounds under an explicit min-sources and max-faulty policy: the application must not count one key/operator multiple times or silently downgrade quorum on outages.

Holochain `not_before` depends on authenticated action ancestry; `not_after` depends on appropriately fresh, nonce-bound evidence. Conflicting evidence changes the verdict, not the validity of an earlier positive fact by itself. The explicit witness verification endpoint **never proves global DHT completeness**, even when no contradiction is among the supplied witnesses.

## Persistent signer journal and revocation

Sprint 24's `vtime_oracle_state` is a native append-only per-(DNA, oracle) journal: synced PREPARE → synced SIGNING fence → HSM callback → verified COMMIT+high-water fsync. `SigningMayHaveOccurred` is quarantined; no automatic resigner. The journal hash chain and signed batches detect corruption/sequence forks but **cannot detect a full rollback to a valid older file without an independently authenticated latest monotonic checkpoint**. `Checkpoint` hashes the entire journal file and binds the signed head. The Sprint 29 native runtime in draft PR #69 is **not merged into this baseline** and still requires real Lair/HSM, trusted external checkpoint CAS and deployed crash/replay acceptance (#70).

## Independent cryptographic audit requests

Inspect exact v2 MessagePack byte fixtures using a separately implemented serializer and native Unyt verifier; test malicious canonical encodings, DNA location tampering and signature mutations. Independently reconstruct v3 fixed-width bytes and Merkle inclusion for known vectors, replay wrong seq/prev/floor and modified root/count. Reproduce RFC 10049 interop with genuine operator signed packets and keys; verify delegation/variant, nonce-bound response, out-of-range/overwide intervals, duplicate signers and Byzantine thresholds. Confirm HSM API authenticates **domain/caller/clock/network**, not merely arbitrary raw signing bytes.

Deliver a signed finding report with versioned test vectors, exact candidate SHA, reproducible commands, negative outcomes and all Critical/High issues tracked to closing PRs. Do not equate a passing library test with proof that financial or network side effects are final.
