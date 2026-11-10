# Sprint 24 integration contract — Sprint 15 signing and Sprint 21 queue

**Status:** proposed integration interface. The linked Sprint 21 queue work
is a separate draft, not a durable production service. This document does not
authorize zome, DNA or public API changes.

## Existing reviewed interfaces

**Sprint 15:** `crates/vtime_core/src/signed_batch.rs` defines
`BatchStatementV3`, `SignedBatchStatementV3`, `BatchChainHeadV3`,
`verify_signed_batch_v3`, fixed-width signing bytes, signed `seq`,
`prev_signature` and `floor_us`. The exact bytes and verifier remain
unchanged by Sprint 24. The native persistence crate references these types
directly and replays **every** durable signature through the verifier.

**Sprint 21:** PR #57, `integration/load/src/seal_queue.rs`, implements a
bounded **in-process** per-agent semaphore and retries only an explicitly
recognised Holochain `SourceChainError(HeadMoved)`. It admits requests
before any source-chain write. Its unknown/transport/timeout failures are
terminal; this design intentionally provides no durable exactly-once
semantics or multi-process locking.

The concepts are distinct: a Holochain source-chain `HeadMoved` retry is
not permission to ask the oracle to **sign the same sequence a second time**.

## Required orchestration before a production oracle signer

```text
authenticated request + externally durable idempotency key
             |
       Sprint 21 queue: one lane per (DNA, oracle)
             |
 verified latest remote monotonic checkpoint / no fork
             |
 existing journal + exclusive single-writer lock
             |
  query last committed statement:
    same exact prior request -> resend exact committed bytes;
    new request -> construct seq, prev, floor from verified head
             |
  PREPARE exact candidate, durable fsync
             |
  SIGNING fence, durable fsync
             |
  Lair/HSM callback executes once (native host adapter)
             |
  Sprint 15 verify_signed_batch_v3 against saved head
             |
  COMMIT signature & trusted head, durable fsync
             |
  external checkpoint / write receipt with monotonic persistence
             |
  return signature to caller; publish only after required durability gates
```

The order of external checkpoint persistence relative to network
publication, and recovery after an external checkpoint write fails,
requires a jointly reviewed transaction/reconciliation protocol. This
prototype does not implement that distributed two-phase commit.

## Failure and retry table

| Persistent journal state | Queue behavior | Is signer re-invocation allowed? |
| --- | --- | --- |
| Clean, known committed request | Return `committed_retry(exact_statement)` (caller idempotency binding required) | **No** |
| Clean, new request with verified previous head | Prepare next seq only under per-identity lock | Yes, once after durable PREPARE + SIGNING |
| PREPARE exists but no SIGNING, authenticated trusted prior checkpoint | Recover exactly the prepared statement | Yes, once |
| SIGNING exists, COMMIT absent | Quarantine; request reconciliation with HSM or an external receipt | **No** |
| COMMIT exists but acknowledgment lost | Read exact signed committed bytes from journal | **No** |
| Wrong prev, old seq, duplicate sig, fork, bad DNA | Reject, log forensic evidence | **No** |
| Missing or corrupted persistent journal | Fail closed; never reset to genesis | **No** |
| Local journal older than independently verified checkpoint | Quarantine antirollback violation | **No** |
| Stale exclusive lock | Verify owner death; operator review before lock removal | **No** |

A future async Lair/HSM adapter must ensure cancellation of a caller's
future does not cancel COMMIT after the signing callback completes; if
storage fails it must surface a terminal, **ambiguous** outcome. No
`HeadMoved` retry branch may wrap `sign_prepared` or clone its signer
callback. The queue must not hold multiple independent journals for a
single signer identity or assume one queue per host is sufficient.

## Required contract/integration review

- **Sprint 15 owner:** sign off on v3 signature bytes, exact immutable
  prev/floor semantics, verifier trust allow-list and DNA binding.
- **Sprint 21 owner:** sign off on queue admission, cancellation behavior,
  durable idempotency identity, one signer per identity across processes
  and transport-failure retry classification.
- **Sprint 22 owner:** test native signer restart/fork with real Holochain
  node state; an oracle key restored to an incompatible source chain cannot
  silently sign ahead.
- **Sprint 23 owner:** check independent Roughtime inputs do not implicitly
  authorise oracle state recovery or override a quarantined signer.
- **Codex:** only after branch integration, test true sidecar/Lair signing,
  real conductor errors and host crash, network retries, externally verified
  checkpoint faults, and migration onto a new DNA/key when required.

Without these completed contracts and tests, the Sprint 24 native journal
is a **candidate component**, not production crash-safe infrastructure.
