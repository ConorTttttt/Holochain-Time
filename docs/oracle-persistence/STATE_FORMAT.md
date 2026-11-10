# ADR 024 — Native oracle batch journal protocol v1 (proposed)

**Scope:** candidate native durable state for signed batch v3, not a DNA
entry type or Holochain-specific source-chain format. Review with Sprint 15
before wiring a real signing endpoint. All bytes are on-disk journal records,
not network evidence.

## Domain and identity

One journal file is the exclusive authority for **one canonical DNA39,
one raw Ed25519 oracle key, one `max_radius_us` policy**. Identity, radius
and file version are immutable after creation. The file requires a trusted
local Unix filesystem that honors `fsync(file)` and `fsync(directory)`.

Header:

| Field | Size | Description |
| --- | ---: | --- |
| Magic | 8 | ASCII `VTS24J1` followed by NUL |
| DNA | 39 | Exact canonical Holochain DNA39 |
| Oracle | 32 | Raw Ed25519 oracle key |
| Radius | 8 | Nonnegative signed i64, little endian, microseconds |

**Header total: 87 bytes.** The header's initial digest is
`SHA512/32("hc-vtime/oracle-journal/v1\\0" || header)`.

## Append-only records

Each record is `length_u32_LE || payload[length] || digest32`, with
`digest32 = SHA512/32(prior_digest32 || payload)`. No short/trailing or
unknown record may be skipped; any checksum mismatch or incomplete write
blocks startup. The file has a fixed **64 MiB** maximum; reaching capacity
must trigger a reviewed checkpoint/rotation migration, not silent truncation.

| Type byte | Payload | Semantics |
| --- | --- | --- |
| 1 | `1 || BatchStatementV3::signing_bytes()` (238 bytes) | PREPARE — fsync the exact pending proposal. No signature has been requested. |
| 2 | `2` | SIGNING — fsync the irreversible keystore-invocation fence. |
| 3 | `3 || signature64` | COMMIT — verify signature against the pending statement and head; fsync before publishing. |
| 4 | `4 || signing_bytes238 || signature64` | ACCEPT — stateful verification of a signed external batch; fsync before acknowledging acceptance. |

The cryptographic journal digests protect against accidental corruption and
uncoordinated partial writes; they are not an HMAC or defense against
a privileged party rewriting the entire local journal. Every COMMIT/ACCEPT
record is **also cryptographically replay-verified** using the existing
`vtime_core::signed_batch::verify_signed_batch_v3`. This establishes correct
signature, DNA, oracle, sequence, previous signature and signed floor. Journal
sequence is 0 at genesis, never reset after a missing or corrupt file.

### State machine

```text
  Clean → PREPARE fsync → Prepared → SIGNING fsync → Signing
     ↑                                              |
     └───────── COMMIT verified & fsync ─────────────┘

  Clean → ACCEPT verified & fsync → Clean
```

Any file write/fsync failure poisons the in-process writer; no more signing.
The next startup verifies the complete on-disk log. An incomplete record
fails closed and requires forensic recovery; the runtime does not truncate it.

- **PreparedNotSigned:** safe to continue signing after restart with the
  byte-identical proposal, because this journal API has not invoked a signer.
- **SigningMayHaveOccurred:** do not re-sign, even if no signature is visible.
  The keystore callback may have executed. This is a deliberate quarantine,
  not a retryable queue error.
- **Clean / committed:** the head, high-water and the original signed
  statement can be reconstructed; a lost caller acknowledgment retrieves the
  exact original committed result via `committed_retry`. New sequence only
  after stateful continuity check.
- **Missing journal:** `open` returns `MissingState`; it never initializes
  genesis. Explicit `bootstrap_new` is only for independently verified
  fresh identities.
- **Wrong DNA/key/radius or unsupported state version:** refuse before signer.
- **Stale lock:** refuse new opens; clearing requires a proven-dead previous
  writer and operator authorization.

## Durability ordering

The journal does **not** expose raw unsigned/opaque signatures to the caller.
`sign_prepared` persistently fences the signing attempt, invokes a caller
provided signer exactly once, strictly verifies the returned Ed25519
signature, and only then writes and `sync_all`s COMMIT. It returns the
signature only after that sync succeeds. This prevents routine on-process
retries from issuing a second signed payload at the same sequence.

`accept_verified` verifies a signed batch against the persisted head and
syncs ACCEPT before acknowledging. A new process replays the entire signed
log rather than trusting cached sequence counters. Exclusive `.lock`
acquisition uses OS create-new semantics; stale locks are intentionally
blocking after an unclean process death.

**Important threat limitation:** The callback could have side effects on
remote networks; exact-once external publication is not established by
journal durability. The backing filesystem may also lie about fsync.
An external monotonic checkpoint is required to detect full local rollback.

## External checkpoint and backup

`checkpoint()` returns `(seq?, signature?, next_floor_us?,
SHA512/32("hc-vtime/oracle-journal-checkpoint/v1\\0" || complete_file))`.
`backup_clean` copies the *entire* journal to a **new** file, fsyncs it and
its parent directory, and returns its exact checkpoint. A trusted independent
service, hardware monotonic register, WORM store or separately signed,
monotonic witness must hold the current checkpoint before production
signing resumes after recovery. `open_checked` compares the complete
restored checkpoint, not merely the maximum sequence; any mismatch blocks.

A new journal can never prove its own freshness. Restoring an older but
cryptographically authentic backup does not pass a newer external checkpoint.

## Integration and unresolved implementation decisions

Native OS persistence is not available to a Holochain WASM zome. A reviewed
native oracle sidecar / durable host service must own it. The key material
must remain with Lair/HSM; this library accepts a signer callback, not a
production secret key. The caller must independently authenticate who may
bootstrap, import histories and operate the external checkpoint service.

Sprint 21's queue serializes per-author appends; it is **not** a durable
idempotency store. The future adapter must admit a request to the queue,
authenticate its idempotency identity, check the durable journal, PREPARE
then fence the signer, and never retry after uncertain signer invocation.
`HeadMoved` retries used for Holochain action writes do **not** authorize
re-signing a v3 oracle statement with a different payload.

v2 oracle statements, v3 batches and Holochain source chain actions are
distinct logs. Bridging them requires an explicit migration plan and key
rotation/sequence policy, not numeric counter reuse. See
`docs/oracle-persistence/RECOVERY_MIGRATION.md`.
