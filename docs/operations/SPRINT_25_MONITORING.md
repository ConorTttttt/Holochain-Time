# Sprint 25 — Operations and Monitoring

**Agent O — infrastructure/observability. High priority. GitHub-first.**

**Status:** offline tooling and incident fixtures; no production observer wired, no live conductor alert acceptance evidence, no release clearance.

## What this branch implements

| Capability | Implementation and limitations |
| --- | --- |
| Structured diagnostic events | scripts/ops/events.py: strict versioned JSONL, bound 2048 bytes/event, only known categories and numeric fields, UTC time and 128-bit random ID |
| Emit trusted local observations | scripts/ops/emit.py: POSIX flock, append/fdatasync, owner-only directory and 0600 file, zero freeform error/event text |
| Source latency and availability | scripts/ops/probe_roughtime.py: uses externally pinned, compiled native Rust roughtime_fetch verifier; latency measures client process + UDP + signature checking, not just network RTT |
| Integration log adapters | scripts/ops/ingest.py: translates strictly whitelisted Sprint 21 HC_LOAD_SAMPLE, Sprint 23 native signer and receipt attempts, Sprint 12/22 recovery markers; no raw signed wire packet or exception text |
| Health and alert rules | scripts/ops/monitor.py: quorum outage, Roughtime failure and high latency, queue full/stalled, retry exhaustion, seal failures, bad signature, unauthorized/excess signing, state corruption, conductor restart/stall, forks/warrants and dependencies |
| Low-cardinality metrics | Same monitor command optionally writes Prometheus WINDOW GAUGES (not lifetime monotonic counters); never emits agent/public-key labels |
| Sanitized incident report | scripts/ops/diagnostics.py: latest 500 allowlisted events within 48 hours, alert codes, event counts, SHA-256 config fingerprints, exact Git SHA, SHA256SUMS. Never exports raw logs or config bytes |
| Regression tests | scripts/ops/test_ops.py and test_probe.py cover eight acceptance signal classes, missing monitoring data, malformed/replayed input, secret-field rejection and private journal access |
| Operator procedures | This file and docs/operations/INCIDENT_RESPONSE.md, plus example systemd monitoring schedule |

**Production limitation:** these are local observer/event tools. Events are not signed Holochain evidence; only a trusted, permission-controlled producer or authenticated remote ingestion path can support security alerts. Sprint 25 does not change the Sprint 11 verifier, Sprint 21 queue internals, Sprint 22 warrant protocol, Sprint 23 source acceptance or Sprint 24 oracle storage/signing rules. Codex must wire emitters to actual runtime outcomes on the integrated commit.

## Privacy by design

Allowed event data: schema, opaque 128-bit ID, UTC timestamp, component, event classification, status, optional source_ref (first 16 lowercase hex chars of SHA-256 of PUBLIC key/source label), elapsed milliseconds, numeric queue depth/capacity, retry count, available/required source count, oldest queue wait and signed action count.

**Forbidden in any emitted or uploaded event:** private/public signing-key text, Holochain agent IDs, DNA/action/target hashes, signed Roughtime packet/certificate/nonce data, raw errors or stack traces, user identities, network endpoints/IPs, environment variables, wallet transactions, arbitrary key:value tags, and original config or log contents. Unknown fields cause rejection; no best-effort regex redaction.

An opaque source_ref is a potentially linkable pseudonym, not anonymity, identity attestation, or proof of independent operators. Restrict retention and access. The event journal requires a preexisting private owner-only (0700) directory, creates mode-0600 files, uses flock/fsync and caps total size at 32 MiB. Rotate privately before full; a full journal refuses appends rather than silently discarding events.

## Example operator setup (illustrative; not a deployed service)

    install -d -m 0700 /secure/hc-vtime-ops
    export OPS_LOG=/secure/hc-vtime-ops/events.jsonl

    PYTHONDONTWRITEBYTECODE=1 python3 scripts/ops/emit.py \
      --events "$OPS_LOG" --component conductor \
      --event heartbeat --status ok

    PYTHONDONTWRITEBYTECODE=1 python3 scripts/ops/emit.py \
      --events "$OPS_LOG" --component roughtime --event quorum_check \
      --status unavailable --available-sources 2 --required-sources 3

The above examples are synthetic assertions, NOT evidence that a real time source or conductor has failed. Approved runtime producers must emit events AFTER actual operation outcomes.

## Production runtime instrumentation handoff

- Sprint 21 per-AgentPubKey queue: emit seal_queue observed/saturated/wait_timeout with depth/capacity/oldest wait; seal_retry head_moved/exhausted with count. The current HC_LOAD_SAMPLE contains ADMISSION depth only, so the adapter must NOT pretend it is a current production gauge.
- Actual seal coordinator: emit seal_submit ok/failed/rejected/timeout and measured end-to-end time only after the actual returned result. A timeout/ambiguous write is not a confirmed failure or a safe retry signal.
- Authenticated Roughtime clients: emit time_source_probe ok/timeout/unreachable/invalid_signature/unsupported_protocol (with end-to-end latency and opaque ref), quorum_check with required_sources >= 3. At least four eligible separately reviewed sources are required for one-source outage tolerance.
- Sprint 24 signing gate: emit oracle_sign ok/rejected/unexpected with approved ref and count only after actual signed event; oracle_state corrupt/sequence_conflict/recovery/backup_failed when persisted security state changes. Never dump signing state or secret seeds.
- Real conductor supervisor: emit starting/restarting/recovered/failed/stopped and heartbeat on an independent cadence; recovery must be proven by chain and signed-witness checks, not merely PID restart.
- Real warrant observer: emit fork_warrant suspected/warrant_observed/conflict only after authenticated runtime warrant observation. Sprint 22 test PASS markers or a raw Holochain error are NOT proof of a real warrant. The current ingestion adapter deliberately ignores fixture warrant-count markers.
- Service dependencies: emit dependency degraded/unavailable and reconnect/heartbeat after actual DHT, Unyt, storage or time-service operational checks. Do not include exception text.

Actual producer identity and source observation authenticity must be enforced at deployment level. Machine-generated alerts do not themselves cryptographically verify warrant signatures, root-key control or signing authority.

## Signed real Roughtime latency probe (operator enabled only)

Compile the existing native Rust verifier from the **exact reviewed commit** and review its executable digest:

    cargo build -p vtime_core --example roughtime_fetch --locked
    sha256sum target/debug/examples/roughtime_fetch
    sha256sum config/roughtime-independent-sources.json

After independently pinning BOTH SHA-256 values and reviewing actual source operators:

    PYTHONDONTWRITEBYTECODE=1 python3 scripts/ops/probe_roughtime.py \
      --client target/debug/examples/roughtime_fetch \
      --expected-client-sha256 "<reviewed binary hash>" \
      --registry config/roughtime-independent-sources.json \
      --expected-registry-sha256 "<reviewed registry hash>" \
      --dossier /secure/hc-vtime-ops/approved-sprint23-dossier.json \
      --expected-dossier-sha256 "<separately reviewed dossier SHA-256>" \
      --exclude-name Cloudflare-Roughtime-2 \
      --timeout-seconds 8 --events "$OPS_LOG"

Cloudflare is excluded because the published candidate is legacy draft11 (unsupported by the current verifier). The remaining four registry entries are **only protocol-compatible candidates**, not proven live independent signers. The probe now requires an **externally SHA-256-pinned Sprint 23 dossier** with REVIEWED_APPROVED status, two distinct human reviewer records, exact public-key/operator/endpoint binding, compatible live-verified protocol and per-operator key, infrastructure and signed-evidence review references. A pending dossier will BLOCK, not silently count its names.

Each counted success requires the reviewed eligible source root to produce a **fresh request whose response passes the pinned native Rust Ed25519/delegation/nonce/Merkle verifier**. With 4/4 successes, the three-source quorum has one verified spare and the command exits 0. With 3/4 successes, it has a usable three-source quorum **but no further outage margin**, returns status QUORUM_DEGRADED_NO_OUTAGE_MARGIN and exits 2; the monitor raises verified_outage_margin_exhausted. With 2/4 successes, the quorum is unavailable and exits 2. No two-source downgrade or count based on configured candidate labels is permitted.

These review fields are auditable *human assertions*, not machine proof of real-world operator independence. The report always says operator_independence_proven=false. All signed stdout/stderr is discarded and NEVER exported. Measured time includes Rust process launch + UDP + verification, not pure network latency.

This probe is diagnostic, not a substitute for Sprint 23 live root ownership review, signed receipt archival or real conductor acceptance.

## Monitor, metrics and alert thresholds

Customize config/ops-monitor.example.json outside version control. It deliberately sets oracle_signing_enabled=false and authorized_oracle_refs=[]; any actual signing is unexpected until someone explicitly approves the signer fingerprints.

Defaults: five-minute lookback; 180-second stale heartbeat; 2-second signed-source response latency warning; 80% queue depth warning; queue saturation CRITICAL; retry count >=3 warning and exhaustion CRITICAL; >=5 failed seals warning; >=60 signatures per source/window CRITICAL until calibrated; >=120s unrecovered conductor restart CRITICAL; invalid signatures, corrupted/sequence-conflicting oracle state, unknown signing, fork/warrant, dependency outage CRITICAL.

Missing heartbeat/quorum observations are NOT RUN, never healthy. A stale previously-seen heartbeat raises an alert. Every alert is a sanitized machine code; unauthenticated real-world claims require external investigation.

    PYTHONDONTWRITEBYTECODE=1 python3 scripts/ops/monitor.py \
      --events "$OPS_LOG" \
      --policy /secure/hc-vtime-ops/monitor-policy.json

Exit 0 HEALTHY, 2 ALERT, 3 NOT RUN/BLOCKED. Connect stdout and status to a reviewed alert delivery/paging service; **no remote pager is installed or invoked by this PR.** --metrics can write a NEW non-overwritten Prometheus text file containing only low-cardinality snapshot gauges. See systemd timer example in deployment/ops (not installed).

Historical integration tests may be projected safely:

    PYTHONDONTWRITEBYTECODE=1 python3 scripts/ops/ingest.py \
      --log /private/load/queued_real_seals.log --events "$OPS_LOG"

Alternatively use --receipt /private/sprint23/receipt.json. The adapter refuses to copy raw proofs or exceptions, and a Sprint 23 receipt without latency fields produces no invented latency.

## Sanitized diagnostic report

    install -d -m 0700 /secure/hc-vtime-ops/incidents
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/ops/diagnostics.py \
      --events "$OPS_LOG" \
      --policy /secure/hc-vtime-ops/monitor-policy.json \
      --config-fingerprint /secure/hc-vtime-ops/reviewed-operator-registry.json \
      --expected-sha "$(git rev-parse HEAD)" \
      --output-dir /secure/hc-vtime-ops/incidents/unique-id

The output is a NEW private 0700 directory OUTSIDE Git, containing diagnostics.json, monitor.json, metrics.prom, sanitized-events.jsonl and SHA256SUMS. It contains **ONLY SHA-256 fingerprints** for the policy/config files, not their names or contents. It never copies unredacted source logs. Review sensitive context before sharing even this sanitized artifact. Hashes prove integrity relative to the local recording, not authorship or monitoring authenticity.

## Review-branch integration and handoff boundaries

The Sprint 25 implementation branch is authoritative. Review PR #60 diverged from an earlier shared commit while Sprint 25 PR #64 gained new metrics, alert rules and ownership checks. Compatible review fixes have been applied to the primary branch without rebase/force-push:

- Normal Python discovery now imports Sprint 25 incident/redaction tests, probe tests and journal safety tests from `scripts/test_ops_*.py`, because `scripts/verify_local.sh` runs `python3 -m unittest discover -s scripts -p 'test_*.py'` and does not recurse into a non-package `scripts/ops/` directory.
- Private JSONL readers use no-follow opens, owner-only file/directory checks and shared `flock` for full read snapshots; writers preserve exclusive `flock` and check the 32-MiB limit AFTER acquiring it.
- Sprint 23 receipt attempt labels are duplicate-normalized and rejected if reused, but their human-readable "verified" strings are **not** promoted to cryptographic quorum telemetry. They yield dependency diagnostics only. Genuine signed-source observation must originate in the pinned native probe.
- Quorum outage-margin acceptance requires four freshly verified **eligible reviewed roots**, not four configurations. Even a completed human dossier does not turn those four into machine-proven organizationally independent operators.
- New `config/ops-event.schema.json` describes the strict versioned allowlist; `scripts/test_ops_schema_contract.py` checks runtime/schema alignment.
- Sprint 21 queue depth at admission is not the live queue-depth gauge, Sprint 22 fixture warrants are not authenticated production warrants, Sprint 24 oracle journal signatures are not inferred from monitoring messages. Codex must wire actual trusted emitters after integration.

**Deferred (not overwritten):** the review branch's older snapshot omits newer Sprint 25 source-latency percentiles, signer rates, stale-restart persistence and main-branch ownership checks. Those older definitions were not copied wholesale. A later local integration must review actual production emitter wiring, cross-process journal rotation, remote authenticated alert delivery and on-DHT replay/warrant evidence rather than claiming those are included here.

## Local Codex acceptance — explicit simulated and real gates

Offline simulated matrix (no live proof):

    bash scripts/ops/check_25.sh

Then on an integrated exact-SHA candidate, connect actual emitters and demonstrate:
1. Real time source timeout/unreachable => source failure alert; two remaining signed roots => quorum unavailable, never downgrade 3.
2. Real Sprint 21 queue saturation => seal_queue_saturated and stalled_seal_queue; no secret payload.
3. Bounded retries exhausted => seal_retry_exhausted; no blind replay of ambiguous transport errors.
4. Invalid signature rejected by Holochain/core => invalid_signature; no false successful seal.
5. Unapproved signing or excessive signatures => unauthorized_oracle_signing/excess_oracle_sign_rate; Sprint 24 durable journal still enforces replay fences.
6. Genuine conductor restart and recovery => restarting then recovered; missed grace period => conductor_not_recovered.
7. An actual Sprint 22 fork or warrant => fork/warrant CRITICAL, based on real signed warrant; fixture test markers alone do not prove it.
8. Dependency outage => dependency_unavailable; recovery observed and audited.
9. Sanitized report excludes keys, wire proofs, target/DNA hashes and raw errors; validate SHA256SUMS, file modes, telemetry gaps.
10. Separate Sprint 17 exact-SHA gate, Sprint 20 deploy preflight, Sprint 23 independence and Sprint 24 durable state acceptance remain mandatory.

**No automatic main merge, production deployment, secret access or release approval occurs.**
