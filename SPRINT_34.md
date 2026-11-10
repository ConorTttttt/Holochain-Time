# Sprint 34 — Authenticated monitoring and incident response (Agent X)

**Status:** GitHub-first integration candidate; production runtime deployment, external paging and independent operational acceptance **NOT YET PROVEN**. Built from development main `bae1e5b9380e92cbee511e07fea1681011d4d6d0`. Production release remains **NO-GO**. No production zome, DNA, private oracle signing key, network service or funded Unyt account modified.

## 1. First audit: Sprint 25 and dependency contracts

Sprint 25 on `main` supplies strict `ops-event/v1` allowlists, private `flock`/fsync journal, source/outage/queue/signing/fork alerts, low-cardinality Prometheus metrics, incident diagnostics and redaction tests. **Events are unsigned.** Its `scripts/ops/ingest.py` imports harness logs that are **not authenticated production runtime events**; a test PASS marker or a source's human-readable "verified" label can never become a confirmed warrant, valid time signature or independent operator identity.

- **Sprint 28** (draft `sprint/28-roughtime-source-readiness-2026-11-10`): the existing `scripts/ops/probe_roughtime.py` uses a pinned *native Rust* Roughtime verifier and externally pinned reviewed root registry/dossier. This PR adds an optional HMAC-authenticated destination to its actual `probe_all` callback **after** the native verifier and dossier checks. The unsigned Sprint 25 log remains diagnostic and must **never** be copied into the authenticated journal as-is. An individual successful signed Roughtime response does not prove independent administrative control of its operator.
- **Sprint 29** (draft `sprint/29-oracle-runtime-persistence-2026-11-10`): native `OracleRuntime::open/sign` v3 exists on its own branch and is **not** the deployed Holochain v2 `attest_time` coordinator. Only after the v3 runtime has produced a journal COMMIT and independently confirmed external monotonic checkpoint may it call the `signed_committed` telemetry hook. `SIGNING` without COMMIT, uncertain checkpoint and signer failure are quarantined; telemetry must not mark those committed. `replay_rejected` comes from the exact runtime idempotency outcome. Until integrated with a real Lair/HSM and external checkpoint service, the oracle adapter remains **a reviewable contract, not a deployed producer**.
- **Sprint 30** (production admission interface not present on current `main`): `integration/load/src/seal_queue.rs` exposes `QueueOutcome.metrics.queue_depth_at_admission` and HeadMoved retries. That depth is **not** a current production queue gauge; do not fake one. The Sprint 34 hook accepts only a separately measured live depth/capacity snapshot after Sprint 30's identity/idempotency/admission contract is finalized. Unknown or ambiguous writes must not be automatically retried or counted as successes.
- **Sprint 22/33**: an *actual* integrated warrant may be retrieved via conductor DHT-store `get_warrants_by_warrantee`. The restricted `conductor_observer` producer may report that it saw a local positive result, but HMAC authentication of the report does **not** verify the Holochain warrant bytes or establish complete DHT warrant discovery. The monitor sends urgent **investigation alerts**, not a cryptographic fork certificate.

## 2. Authenticated event producer architecture

`scripts/ops34/auth.py` defines `hc-vtime/ops-auth-frame/v1` over an already validated Sprint 25 `ops-event/v1` object:

```json
{
  "schema": "hc-vtime/ops-auth-frame/v1",
  "producer": "verified-source-probe",
  "seq": 1,
  "prev_sha256": "<64 lowercase hex; all zero for first record>",
  "event": {"schema":"hc-vtime/ops-event/v1","id":"<32 lowercase hex>",
            "ts":"<UTC ISO8601 Z>","component":"roughtime",
            "event":"quorum_check","status":"unavailable",
            "available_sources":2,"required_sources":3},
  "mac": "<HMAC-SHA256 of canonical JSON over all fields except mac>"
}
```

Only five role classes may publish: `roughtime_probe`, `oracle_runtime`, `queue_runtime`, `seal_runtime`, `conductor_observer`. Each deployment producer has its **own random 256-bit secret**, with distinct keys enforced; one producer cannot impersonate another producer role unless its key is compromised. `scripts/ops34/runtime_hooks.py` provides role-scoped production callback methods. `append_supplied` verifies an externally supplied frame without ever blessing/re-signing unauthenticated bytes.

The authenticated journal is a **separate**, current-user-owned 0600 file inside a precreated 0700 directory; no symlinks. Its exclusive append lock and fsync, fixed-size frame cap 4096 bytes, 2048-frame/8-MiB journal cap, monotonic sequence per producer, globally unique event IDs, HMAC comparison, hash predecessor and five-minute event-time tolerance protect against normal unauthorized injections, duplicate or reordered messages. A malformed/incomplete journal **blocks all assessments** rather than skipping any suspicious record.

**What this does not solve:** If an attacker controls an authorized producer, obtains its HMAC key, compromises the monitor host or rolls back/truncates the entire journal plus local state, neither HMAC nor a local hash chain proves an intact history. A separate monotonic trusted checkpoint and secure service identity/credential lifecycle are release requirements. The receiver is not a remote HTTPS ingestion server; transport should be mTLS or Unix-domain socket ACLs with appropriately isolated producer identities, and the signed frame must still be checked. Never publish producer keys in Git, metrics, logs, PRs, or alert bodies. Key rotation must preserve old journal verification until securely archived; rotate to new producer ID/key with explicit operator control.

Template `config/ops34-producers.template.json` intentionally contains **invalid placeholders**, not usable credentials. Provision a fresh owner-only keyring outside Git, for example:

```bash
umask 077
install -d -m 0700 /absolute/private/vtime-ops
python3 - <<'PY'
import json, secrets
from pathlib import Path
roles = {"verified-source-probe":"roughtime_probe",
         "oracle-service":"oracle_runtime", "admission-service":"queue_runtime",
         "seal-service":"seal_runtime", "conductor-observer":"conductor_observer"}
path = Path("/absolute/private/vtime-ops/producers.json")
with path.open("x", encoding="utf-8") as f:
    json.dump({"schema":"hc-vtime/ops-producers/v1",
               "producers":{key:{"role":role,"key_hex":secrets.token_hex(32)}
                            for key,role in roles.items()}},f)
path.chmod(0o600)
PY
```

The above is an **illustrative local provisioning step**, not a production secret-distribution or rotation design. Isolate service permissions, prevent all producer processes from reading every other producer's keys, and use a secret manager or injected per-role secret in a deployment. The example single-file keyring is an operator-controlled lab boundary, not mutually isolated identities.

## 3. Confirmed and deferred runtime wiring

**Actual code-path integration introduced now:** `scripts/ops/probe_roughtime.py` accepts optional `--authenticated-journal`, `--producer-keyring`, `--producer-id`. All three must be supplied together. The approved registry, dossier and SHA-pinned native verifier run before any successful signed-source count is reported; `probe_all` sends sanitized result/heartbeat/quorum events through `append_authenticated` instead of trusting a log importer. Errors do not fabricate verified sources. Its ordinary untrusted Sprint 25 journal is retained for existing dashboards but **must not** become an input to Sprint 34 acceptance.

```bash
python3 -B scripts/ops/probe_roughtime.py \
  --registry /absolute/reviewed/registry.json \
  --expected-registry-sha256 '<externally reviewed sha256>' \
  --dossier /absolute/reviewed/operator-dossier.json \
  --expected-dossier-sha256 '<externally reviewed sha256>' \
  --client /absolute/pinned/native-roughtime-fetch \
  --expected-client-sha256 '<externally reviewed sha256>' \
  --events /absolute/private/vtime-ops/legacy-observations.jsonl \
  --authenticated-journal /absolute/private/vtime-ops/authenticated.jsonl \
  --producer-keyring /absolute/private/vtime-ops/producers.json \
  --producer-id verified-source-probe
```

**Deferred runtime attachment contracts** until Sprints 29–30 finalize: call `RuntimePublisher.oracle_result("signed_committed", source_ref=..., signed_count=1)` only from the v3 durable commit+external checkpoint success path; `oracle_result("replay_rejected")` from a genuine rejected duplicate/conflicting signing request; `queue_snapshot(depth=..., capacity=...)` from a live admission-server gauge; `queue_retry(retries=..., exhausted=...)` from the bounded retry outcome; `seal_outcome(status=...,latency_ms=...)` after an actual seal request outcome; and `warrant_observation("warrant_observed",integrated_warrant_count=N,origin="local_conductor_dht_store")` only after a real conductor-local positive integrated warrant database query. None of these APIs accepts raw action hash, full public key, private key, HSM statement, packet bytes, unconstrained tags or exception text.

Integration claims are **conditional** until these callbacks are wired into deployed services. Preserve the queue's idempotency and signing-state contracts; do not add a second independent signer/queue or re-enable global DHT index scans.

## 4. Incident classification and delivery

`scripts/ops34/alerts.py` reads **only** the HMAC-verified journal, reruns Sprint 25's strict health policy and adds `oracle_replay_rejected` (critical) and `oracle_state_recovery` (warning) gaps. Alerts are classified:

| Triage | Examples | Initial response |
| --- | --- | --- |
| P0 possible integrity | invalid signature, unexpected signing, replay rejected, local reported fork/warrant | Freeze affected signing/financial side effects; preserve authenticated runtime receipts and DHT/HSM evidence; independently verify actual signatures and warrants |
| P1 availability/capacity | quorum lost, no outage margin, saturated queue, exhausted retries, unrecovered conductor | Pause dependent operations, diagnose source/queue/conductor recovery without replaying ambiguous writes |
| P2 ops gap | heartbeat missing, degraded dependency, latency warning | Investigate telemetry pipeline, verify reporter and source policy before treating any absence as healthy |

Alert report fields `producer_hmac_checked=true`, `fork_warrants_cryptographically_verified_here=false`, `independent_operator_identity_proven=false` and `global_evidence_completeness_proven=false` are mandatory and **must not** be overwritten by a delivery plugin. The existing Sprint25 `diagnostic_events_are_authenticated=false` is left unchanged; the new HMAC provenance is specifically producer authentication, not evidence authentication.

Delivery config `config/ops34-alert-delivery.example.json` defaults to `disabled`. An owner-only 0600 copy supports:
- `private_spool`: a reviewed 0700 directory; alarm batches are allowlisted, 0600, fsynced, idempotency-keyed and contain **only** incident codes/classes/severity. A separate secure operations system may consume files from this spool; queuing a file is **not** proof a human or pager received it.
- `https_webhook`: reviewed HTTPS-only host with TLS certificate verification and a **separate** 256-bit HMAC alert-delivery secret. No following redirects, no automatic ambiguous send replay, 5-second timeout. Recipients must validate the HMAC, idempotency key and deploy an egress/DNS policy to prevent private-IP DNS rebinding. A successful HTTP 2xx is **not** incident resolution or proof the incident is real.

Invoke from an approved private environment:

```bash
python3 -B -m scripts.ops34.alerts \
  --keyring /absolute/private/vtime-ops/producers.json \
  --journal /absolute/private/vtime-ops/authenticated.jsonl \
  --policy /absolute/private/vtime-ops/monitor-policy.json \
  --delivery /absolute/private/vtime-ops/delivery.json \
  --out /absolute/private/vtime-ops/reports/new-monitor-report.json
```

The monitor exits 0 for healthy, 2 for alerts, 3 for missing/blocked inputs. Use a service manager/timer with restricted logging, monotonic clock monitoring and manual on-call acknowledgement. Do not use a temporary simulated result to clear a real incident or release funds.

## 5. Reproducible, safely injected incident-response exercise

On clean EXACT SHA, with Python stdlib, no private runtime credentials required:

```bash
HC_VTIME_EXPECTED_SHA="$(git rev-parse HEAD)" bash scripts/run_sprint34.sh
```

The script runs the new HMAC auth/redaction/replay/alert tests, existing Sprint25 monitor/probe tests, shell preflight and an **injected-only** drill (`python3 -B -m scripts.ops34.drill`). The drill creates a disposable 0700 test journal with random test keys and injects:
- signed-source outage (2/3), invalid signature diagnostic and missing outage margin;
- oracle replay rejection, unexpected signing, conductor restart past grace;
- saturated queue/retry exhaustion;
- a **synthetic** positive warrant observation sent through a test-key producer;
- a forged producer frame which must fail authentication.

The reporter must produce correct code/severity classifications and at least one redacted private alert batch; it must reject forged HMAC and preserve the scope `SAFELY_INJECTED_TEST_ONLY`. `scripts/audit_ops34.py` verifies exact SHA, command exit statuses, distinct code coverage and artifact SHA-256 digests. All generated credentials are deleted with the temporary directory; do not attach the raw ephemeral journal or secret keyring to the PR.

**The runner does NOT run real conductors, signers, funded Unyt, external operator servers, webhooks or actual DHT warrant verification**. A test returning `INJECTED_INCIDENTS_PASS` proves only local injected alarm behavior. It cannot satisfy production runtime acceptance or independent audit.

## 6. Acceptance / remaining work

- [x] Review Sprint25 contract and Sprint28/29/30 dependency state.
- [x] HMAC-scoped producer interfaces, journal chain/sequences, bounded read/write and redaction tests.
- [x] Actual pinned Roughtime probe callback integration (opt-in auth journal).
- [x] Oracle, queue, seal, conductor/warrant callback contracts without inventing deployments.
- [x] Replay/restart/quorum/queue/fork alert classifiers and configurable sanitized delivery.
- [x] Injected incident drill, fail-closed auditor and negative regression suite.
- [ ] Run Sprint34 Python tests + injected alarm exercise on this exact PR SHA (attach actual exit logs/manifest).
- [ ] Run a **real** reviewed-source probe with pinned independent-operator dossier and native Rust verifier through the new HMAC journal. Never infer operator independence from key multiplicity.
- [ ] Integrate and validate signer callback with FINAL Sprint29 runtime, true HSM/Lair and anchored replay state. No false committed signatures.
- [ ] Integrate production admission and retry metrics against FINAL Sprint30 interface; verify queue depth is a current gauge, not an admission sample.
- [ ] Confirm real local conductor warrant via DHT query, independently inspect/warrant-verify it, and deliver an authenticated alert; do not trust a fixture marker.
- [ ] Execute a real HTTPS delivery exercise to a reviewed receiver, verifying TLS, HMAC and idempotency without leaking keys/secrets.
- [ ] Independent on-call incident drill, retention/rotation, external monotonic telemetry checkpoint, producer credential isolation and journal tamper/restart testing.
- [ ] Re-run all gates against integrated release commit, obtain independent security review and leave production NO-GO until accepted.

See `docs/operations/INCIDENT_RESPONSE.md` for current Sprint25 operating procedures. Sprint34 adds authenticated observation and scoped notification **without turning alerts into cryptographic proof**.
