# Sprint 30 — Production seal admission and queue recovery (Agent T)

**Date:** 10 November 2026. **Integration base:** `bae1e5b9380e92cbee511e07fea1681011d4d6d0`.
**PR #69 (Sprint 29) contract snapshot:** `2e46f1377e733eceb93be90d4998bf45a6a3334f`.
**Status: GitHub prototype and offline regression, NOT a production service.**
**Sprint 29 sign-off:** PENDING. **Production release:** NO-GO.

## Why a separate sidecar boundary?

Sprint 21 demonstrated 360 distinct seal writes on a *shared development host*
across three runs, with one in-process Tokio semaphore per author and zero
failed/retried writes. That evidence is reproducible but **not** a deployed
authentication service, distributed lease, SLA, or durable idempotency result.

Sprint 29's **draft** v3 `OracleRuntime::sign(BatchSignRequest)` takes a
32-byte authenticated globally unique request ID and batch nonces; it durably
binds identity and statement in PREPARE_REQUEST, then SIGNING, COMMIT,
independent external checkpoint CAS **before output**, and exact-signature
replay for a known committed request ID. A SIGNING-without-COMMIT state
quarantines signing. Its current in-memory checkpoint and signing tests do
NOT establish real cross-host safety or installed Lair/HSM service.

**This sprint deliberately changes neither Sprint 29's journal, signer or
checkpoint APIs nor Sprint 21's conductor benchmark or queue API.** It adds
`scripts/load/admission30.py` as a usable but **not network-connected**
native Python 3.12+ sidecar interface, with an independent local SQLite
WAL `synchronous=FULL` ledger, an exclusive file lock, structured
typed/native adapter protocols, bounded per-principal quota and in-flight
limits, per-**(DNA,author)** single-writer lanes and an opt-in recovery
interface. That demonstrates a **request-admission contract** suitable
for integration design, *not* real production throughput.

A Python admission sidecar is not an on-chain validator. Live Holochain
zome correctness, authenticated source-chain writes, v3 oracle signing,
external checkpoint authenticity and network evidence must be implemented
and reviewed in their respective native/HDK components.

## Proposed request identity — requires joint Sprint 29 approval

| Field | Intended producer/verifier | Safety requirement |
| --- | --- | --- |
| `request_id` | Authenticated client/gateway supplies 32 immutable bytes; Sprint 29 must accept exactly the **same ID** | Nonzero canonical 64-hex, globally unique in oracle signing scope, stable across transport retries, never reused for different payload, author, DNA or principal. Zero-byte/test fixture IDs are **not** proof of unpredictable uniqueness. |
| `payload_sha256` | Real adaptor computes SHA-256 over a **versioned, canonical, complete** Holochain seal command | Hash covers target action hash, nonce/proof digest, zome/dna, intended author, all security-critical inputs and requested oracle id/batch; not an operator-supplied `hash` field. Exact canonical byte format requires Sprint 29 + core/integrity review. |
| `dna` | Native Holochain authenticated cell identity | 39-byte typed hash with canonical base64 and location checksum; no cross-DNA routing or replay. |
| `author` | Native conductor session identity / signer allocation | Only an explicitly configured allowlisted author lane can be used. A caller-provided author string does not grant ability to sign as it. |
| `caller` | Trusted transport authentication provider | Must be the actual verified caller AgentPubKey; do not trust HTTP JSON identity, a client asserted header or raw public key without possession proof. |
| credential | Concrete **not yet implemented** adapter | Max 4 KiB, opaque, never persisted or logged; authenticate caller, caller's allowed targets and author delegation before receipt lookup or write. |

`Authenticator.authorize(credential, intent)` is a **boundary**: the
test double returns a mock key, but a production implementation must check
cryptographic possession, session expiry, caller authorization and a
privileged mapping to the source-chain author. A successful mock is NOT
authorization to call real conductor or HSM. Do not allow anonymous clients
to choose a signing identity or direct arbitrary-message signing.

**The sidecar's local request table is not Sprint 29's signing journal.**
The approved adapter MUST persist the same request ID and versioned
payload digest, reject v2/v3 confusion, and NEVER wrap Sprint 29's
`OracleRuntime::sign` in a HeadMoved retry loop.

## Admission flow (current offline implementation)

```text
trusted transport verifies caller + author permission (not implemented live)
    |
fixed allowlisted (DNA,author); explicit id+canonical input digest
    |
SQLite FULL-durable caller quota (fixed time window; monitored clock)
    |
global 128 slots + per-caller 4 in-flight (example, bounded)
    |
asyncio FIFO author lock (single instance per author scope)
    |
abort if different request ID on this author is UNKNOWN/INFLIGHT
    |
SQLite INSERT INFLIGHT; commit + fsync before any backend call
    |
increment durable attempt count BEFORE callback
    |
native trusted author-specific conductor writer
    |
  signed native action verified by trusted ReceiptVerifier?
    yes → SQLite COMMITTED with action hash, return LOCAL_COMMIT; future
          same-ID calls return CACHED_LOCAL_COMMIT (still reverify native)
    proven NOT WRITTEN / typed HeadMoved?
      yes → bounded <=2 retries **only** when native API guarantees no
            action or signature was emitted; otherwise terminal NOT_WRITTEN
    timeout, cancellation, invalid receipt, untyped error, unknown state?
      → durable INFLIGHT persists, **AMBIGUOUS**, NO AUTOMATIC RETRY
      → block ALL new writes on that (DNA,author) lane
      → audited privileged reconcile_commit verifies *actual* signed action
         with independently authenticated peer + latest signer checkpoint
      → never mark unknown as not-written merely from elapsed time or absence
```

**Fairness and exhaustion**: per-authenticated-caller durable fixed-window
quota, per-caller in-flight ceiling and per-author fair FIFO serialization
bound one caller's contribution; global capacity and bounded waiting apply
backpressure. The caller quota survives service restart, and a backwards
wall clock quarantines new admission. Admission policy and the immutable author allowlist are SHA-256-pinned in the SQLite ledger; changed policy on restart blocks until reviewed migration. A local digest does not defend against database rollback/tampering. The maximum number of remembered
callers and idempotency rows is bounded; exhausted history fails closed
until reviewed external archive/migration. These controls are **not**
a formally proven weighted fair scheduler, not a globally coordinated
rate limiter and not strong against unlimited fake identities until a
real authentication endpoint exists. An independently administered
gateway and authenticated principal cost policy are still required.

**Retry controls**: at most 2 retries after the first attempt (configurable
0–8) with capped 20/40ms backoff, **only** if a reviewed native adapter
proves `PROVEN_NOT_WRITTEN_HEAD_MOVED`; malformed input and untrusted
oracle/signature proofs must return proven NOT_WRITTEN with no retry.
Unknown transport timeout, cancellation or post-signing error is ambiguous
rather than `HeadMoved`. Do NOT simply substring-match an error, because
`SourceChainError(HeadMoved)` text is not a signed guarantee of no write.
A native source-chain read/typed error guarantee must justify this
classification. Never invoke the Sprint 29 signing callback again.

**Crash semantics**: an INFLIGHT row is a durable **safety fence**, not proof
the external writer was actually called. On process death, the SQLite
file lock is automatically released, but no new request can use the same
author lane if any earlier request remains INFLIGHT. Retrying the same
ID yields a read-only ambiguous outcome. Only an independently approved
recovery verifier can convert an ambiguous row to an existing native
COMMITTED action. Proving absence of a spend on one peer or searching only
local receipts is **insufficient** to safely reissue a write.

**State integrity limits**: SQLite WAL+FULL (checked at open), a privately owned, non-group/world-writable
absolute state directory, synced first-creation directory entry and an
exclusive local OS lock provide process crash recovery on a reviewed filesystem; they do
**not** prevent root tampering, backup rollback, a second service using
another path, two hosts sharing the same signing key, or source-chain
forks. There is no external monotonic checkpoint for this admission DB.
Production must bind the admission ledger to a separately authenticated
rollback-resistant global authority or the Sprint 29 checkpoint chain.
A tampered or restored old DB is not safely detected by local quick_check
or a local file lock. **No production durable exactly-once guarantee yet.**

## Operational metrics

`Admission.snapshot_metrics()` exposes bounded counters:

- `admitted`, `auth_denied`, `rate_limited`, `saturated`,
  `caller_saturated`, `queue_wait_timeout`, `started`;
- `committed`, `cached`, `key_conflict`, `ambiguous`,
  `head_moved_retries`, `known_not_written`, `recovered`,
  `storage_failed`, `inflight_local`, `pending_ambiguous`,
  `commits_recorded_locally`, `writer_lanes`.

Each `AdmissionResult` includes caller-observed `queue_wait_ms`,
durable `attempts`, status and an optional **local** action hash.
The counters are process-local and reset on restart; the persisted table
does not. The request table enforces UNIQUE (DNA, author, canonical payload digest), so reissuing the identical author command with a new request ID is an idempotency violation. The live adapter must calculate a full, truly canonical command digest; caller-supplied digest labels are not trusted. Do not use counter increments as evidence of native writes,
independent receipt validity, HTTP SLAs or success rates. Production
telemetry still needs external aggregation, labelled but bounded cardinality,
alerting on lane quarantine, sync latency, token exhaustion, journal
growth, queue age and operator-reviewed threshold policies.

## Regression and crash acceptance (offline contract)

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  scripts.load.test_admission30 -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts/load -p 'test_*.py' -v
```

`scripts/load/test_admission30.py` covers caller auth, author allowlist,
idempotency key binding across payload/principal, same-ID COMMITTED
read-only replay after restart, durable rate quotas, clock rollback,
per-caller fairness, different-author overlap, per-author serialization,
global full queue and timed-out waiting, bounded typed HeadMoved retries,
untrusted/missing receipt, untyped transport errors, cancellation,
independent reconciliation permission, storage exhaustion, wrong typed
hashes, exclusive lock and a **real OS SIGKILL**.

The child process (`scripts/load/crash_worker_30.py`) prints
`FENCED_BEFORE_NATIVE_WRITE` only *after* the durable INFLIGHT/attempt
transactions. The parent then uses SIGKILL; on reopen the real SQLite row
must remain INFLIGHT and must block a new author-chain write. This is a real
OS crash of the **sidecar**, but not a conductor/HSM crash, and nothing in
the tests is a genuine signed Holochain action.

All receipts, credentials, agent hashes and writer outcomes used in the
Python tests are synthetic. They do not certify a production native writer.

## Sprint 29 agreement and shared-interface hold point

Before any production or shared runtime interface change, obtain explicit
review from Sprint 29 owner (PR #69) on:

1. **Identity scope:** Who allocates the globally unique 32-byte request ID;
   how is the canonical payload digest computed across Holochain action,
   v2 vs v3 batches and author/nonce/target, and where is it authenticated?
2. **Who owns each (DNA, AgentPubKey)** across multiple processes/hosts?
   The Python lock is local. Only one signer/key/journal owner can operate
   for an identity; require external monotonic fencing.
3. **Exact response contract:** native verified COMMIT receipt vs
   proven NOT-WRITTEN HeadMoved vs error after signing vs checkpoint-CAS
   failure; a remote receipt with unknown signature commitment must not
   become a replayable request.
4. **Crash/reconciliation:** how does Sprint 30 reconcile a signed native
   source-chain action and independent peer with Sprint 29's
   `PREPARE_REQUEST`, `SIGNING`, `COMMIT`, checkpoint and the latest
   trusted signer head? What is operator-approved remediation for a signer
   that is irrecoverably ambiguous?
5. **Cancellation:** native writer must continue COMMIT/anchor safely
   independent of caller cancellation, or quarantine after unknown
   outcome. No two Holochain source-chain writers or duplicate signatures.
6. **Runtime connector:** choose reviewed Holochain 0.7.1 admin/app
   WebSocket or sidecar integration with real authentication, structured
   native status, rate limit policies, safe deadlines and metrics.
   **No such connector is included in this PR.**

## Local *real-runtime* acceptance — NOT RUN, and NOT satisfied by Sprint 21 alone

Run only after owner agreement, exact installed conductor/RPC and source
identity, and independently reviewed admission+writer integration:

1. Clean exact Sprint 30+29 compatible commit, public test fixture DNA
   and signed-quorum smoke from `scripts/run_signed_quorum.sh`.
2. Run the Sprint 30 admission **through the actual intended deployed
   app/sidecar interface**, not `seal_queue.rs` in a single Rust test
   process. Record 120+ simultaneous caller submissions (and 2,000
   adversarial capacity pushes), genuine native caller authentication
   and source-chain authors, exact request IDs, signed targets, raw
   native ActionHashes and per-author metrics.
3. Repeat the successful three-conductor benchmark *at least three
   times*; require >=100 unique successful sealed actions per run with
   third-party witness verification, zero unauthorized duplicate/partial
   writes, and real queue/latency/CPU/memory metrics. Record rejected
   requests' absence from the source chain and full idempotent replay
   behavior against signed native receipts.
4. SIGKILL the **real admission process, conductor and signing service**
   at before-write/after-write/before-ack/COMMIT/checkpoint phases.
   Demonstrate recovery from an **independently authenticated** peer and
   Sprint 29 trusted anchor, with no duplicate unauthorized writes.
5. Fault inject malicious caller key spoofing, distinct caller same ID,
   conflicting digest, forged HeadMoved, transport loss, bad native
   receipts, source-chain forks, replayed keys after rollback, flood of
   identities, full queue, clock rollback and bad checkpoint.
6. Save exact-commit machine-readable outcomes, source-chain artifacts
   and SHA256SUMS outside source. Independent operator reviews authentication,
   remote checkpoint and cross-host identity ownership. Re-run Sprint 27
   exact-SHA integration/release gates.

The older **Sprint 21** command remains useful as an *independent*
historical baseline (it does **not** run Sprint 30 admission):

```bash
python3 scripts/load/run_21.py --expected-sha FULL_SHA \
  --dna /outside-repo/signed-test-only/vtime.dna --attempts 120 \
  --insecure-test-fixtures --compare-unqueued
```

The new live gateway and signer adapter do **not** exist in the branch.
Do not report 360-Sprint-21 seal success as Sprint 30 live integration.

**Summary:** Sprint 30 GitHub prototype and contract/test harness ready
for local execution and Sprint 29 review; production admission deployment,
end-to-end 120+ runtime benchmark, external antirollback, crash recovery
with real signed native receipts, and independent review **NOT RUN**.
Master release and issue #5 remain NO-GO.
