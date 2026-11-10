# Sprint 25 — Incident response, restart, compromised keys and rollback

**Use with docs/operations/SPRINT_25_MONITORING.md.**
**Safety rule:** preserve the three-independent-source minimum and the trusted source-chain/replay state. Never mask an outage by weakening signatures, accepting two time sources, bypassing key review or restoring an oracle signing key without its durable high-water mark and chain.

The Sprint 25 monitor reports observations, not authenticated incident evidence. An unauthenticated event can be missing, forged or incorrectly classified. Independently confirm each high-impact signal using Holochain conductor status, signed Roughtime packets, authoritative oracle security state, a real warrant and separate host/system telemetry before key revocation or destructive recovery.

## Initial triage (every alert)

1. Acknowledge page, assign an incident commander and security responder, preserve exact UTC time, exact deployed source Git SHA, active DNA bundle fingerprint, policy/config SHA-256 (NEVER raw secrets) and observed quorum counts. Do not restart everything blindly.
2. Run the private sanitized report command (see monitoring runbook), then verify SHA256SUMS. Never upload raw conductor logs, Roughtime signed responses, keystore backups, signer seeds or Unyt financial records to open issues/chat.
3. Check observability itself: last heartbeat age, failed journal append/rotation, corrupt JSONL, host clock skew, source/policy mismatch, full filesystem and observer process permissions. A missing signal is NOT RUN, not a healthy service.
4. Determine whether evidence comes from real signed/conductor execution, or only a test-fixture marker. Test synthetic warrants must not trigger irreversible root-key actions.
5. Mark the affected component DEGRADED/PAUSED; prefer stopping NEW signing or NEW irreversible financial actions while preserving historical proof verification. Archive original signed incident evidence in a separately approved secure store with digest, retention controls and an auditable chain of custody.

## Alert response table

| Alert codes | Suspected issue | First safe response | Evidence required before clearing |
| --- | --- | --- | --- |
| time_source_timeout, time_source_unreachable, roughtime_high_latency | UDP/provider/downstream outage or high client+verify latency | Probe from second authorized vantage point; check UDP, DNS, source key and compatible protocol. Leave min_sources=3 unchanged | Three current native-verifiable responses plus authorized provider review |
| time_source_invalid_signature, invalid_signature | Root rotation, spoofed/forged packet, wrong nonce/delegation or compromised signing key | Quarantine suspect root from NEW deployment review, pause trust-dependent actions if <3 eligible signed roots remain | Signed raw packet reviewed by native Rust verifier and independent root-controller checks; new DNA if roots change |
| time_quorum_unavailable, quorum_telemetry_missing | Fewer than 3 authenticated source responses, or no valid monitoring signal | Stop new time seals that require independent quorum, investigate spare 4th operator; never lower quorum | Min 3 valid signed responses from approved roots, one-outage case re-tested |
| seal_queue_saturated, stalled_seal_queue | Per-agent source-chain queue saturation, dead writer or backpressure | Apply bounded admission, stop issuing new requests, inspect per-author chain and active conductor; avoid unbounded retries | Queue drains, bounded wait/retry and distinct persisted seal hashes validated |
| excessive_seal_retries, seal_retry_exhausted, seal_failures_excessive | HeadMoved conflicts, chain contention or ambiguous write status | Confirm exact failure classifier; use Sprint 21 one-writer-per-agent queue, investigate external writers. NEVER auto-replay an ambiguous success | Event-to-action reconciliation, no duplicate side effect, stable queue latency |
| unauthorized_oracle_signing, unexpected_oracle_signing, excess_oracle_sign_rate | Unknown signer process, compromise or duplicate account, unapproved deployment | Disable NEW signing for affected identity, retain on-disk journal/keystore and operator audit logs, check installed grants | Independent owner confirms key control, Sprint 24 high-water mark continuity and absence of conflicting signatures |
| oracle_state_corrupt, oracle_state_sequence_conflict, oracle_state_backup_failed | Lost journal, forked signer history, stale snapshot or failed durability | Stop signing immediately, image durable state, do not reset sequence or rebuild from untrusted signature alone | Deterministic restore/replay tests, migration and backup procedure signed off |
| conductor_restarting, conductor_not_recovered, stale_heartbeat | Unexpected reboot, unavailable peers or failed state recovery | Check persistence and peer rejoin, actual source chain, witness hash/ancestry and keystore; do not delete conductor data | Genuine conductor restart/rejoin with retained trusted signed evidence and no false ancestry clearance |
| fork_or_warrant_suspected, fork_or_warrant_warrant_observed, fork_or_warrant_conflict | Possible same-agent forks or authority-issued warrant | Stop affected author from NEW signing, preserve conflicting action chains and native warrant objects; verify independent witnesses | Real authenticated Holochain warrant, cross-conductor convergence and Sprint 22 runbook acceptance |
| dependency_unavailable, dependency_degraded | DHT, storage, networking, Unyt or external service failure | Block dependent irreversible work; mark service degraded, verify which dependency failed and isolate blast radius | Native dependency health, reconciliation of submitted work, validated recovery |

Alerts are intentionally codes without raw freeform messages. The report never contains proof that a warrant was cryptographically verified, or an endorsement of operator administrative independence.

## Compromised Roughtime or oracle key

**Never place private signing keys in GitHub, logs, examples, diagnostic bundles or team chat.**

1. Revoke/suspend the compromised runtime signer or oracle capability grant on authorized infrastructure. Keep the authenticated historical signing evidence and chain so it can be independently verified; do not destructively erase it.
2. Identify exactly which public key root, operator and DNA cell is compromised using approved external records. Avoid treating a hash-collision-resistant telemetry source_ref as proof of ownership.
3. Obtain a replacement key from a genuinely independent operator, directly authenticate the root, and verify shared hosting/upstreams and supported RFC10049/draft15. To tolerate one unavailable source with a three-source quorum, still require **at least four approved eligible roots**.
4. Changing trusted source keys, max faulty count, min_sources or network seed changes the Holochain DNA hash. Use Sprint 20 guarded config migration/preflight and new isolated DNA, never silently patch an installed DNA or downgrade quorum.
5. For oracle private key compromise, Sprint 24 durable signer sequence, previous-commitment chain and high-water state must remain preserved. Do not restore signer key with a lost/old source chain, reset sequence to zero, or resume before conflict and equivocation review.
6. Review agreements / Unyt evidence separately; no release/rollback script should move funds automatically. Keep compromised-era evidence tagged and allow read-only historical re-verification where valid.

## Oracle restart and backup recovery (Sprint 24 dependency)

1. Capture authoritative high-water mark and previous-commitment digest from the durable signed journal, plus source-chain DHT state and peer quorum. Snapshot encrypted backups with trusted access controls.
2. Use Sprint 24 deterministic crash and backup validation to restore into an isolated environment, checking journal format/migration, uninterrupted sequence numbers and duplicate/conflicting histories. Any corrupted state blocks signing; recovery must not guess missing sequence.
3. Ensure exactly one authorized writer per agent source chain (see Sprint 21), and distinguish an ambiguous signed operation from a definitively uncommitted one. Reconcile actual ActionHash or signed commitment before retrying.
4. Only then reopen signing, monitor oracle_sign and oracle_state events, watch for unauthorized source refs and excessive signer throughput.

The current monitoring stack cannot perform these state transitions or authenticate a ledger by itself; it can only signal operator-confirmed observations.

## Conductor restart / network rejoin / warrant recovery

1. Snapshot precise DNA identifier, keystore presence, relevant source-chain storage and conductor version. Distinguish planned restart from fork or recovery after a partial write.
2. Start the conductor with its **original persisted source chain** and keystore, not a fresh fork reusing the same agent key. Verify peer exchange, DHT consistency, signed anchors/seals and missing-witness rejection after restart.
3. If fork/warrant observed, use Sprint 22 real warrant acceptance. Do not classify a generic HeadMoved or a fixture FORK_RECOVERY_CASE marker as a real signed warrant. Quarantine conflicted signer until review.
4. Emit conductor/recovered only after all independent checks have passed. A running process/PID alone does not clear conductor_not_recovered.

## Controlled rollback and failed release

1. Stop rollout and NEW signed/seal/Unyt execution in the affected cells. Preserve old and new DNA hashes, signed evidence and configuration fingerprint. Do not deploy a different DNA under the same identifier.
2. Verify that the previous rollout is **still safe**: a release that trusts compromised key material or insufficient sources is not a valid rollback target.
3. Use Sprint 17 exact-commit integration evidence and Sprint 20 guarded release pack/preflight before enabling a prior compatible build. Restore only correctly matched state snapshots, keys and sequence journals; never reset oracle replay high-water.
4. Replay queued operations only after an idempotent operation-id/action-hash reconciliation (Sprint 21/23/24). A local SQLite receipt claim is not network-wide exactly-once.
5. Validate three genuine independent external Roughtime signed responses and expected conductor/witness states before marking degraded service recovered.
6. Archive sanitized incident report + independently held signed cryptographic incident evidence, time/source reviewer signatures and a postmortem covering outage duration, recovery, loss, false negative/positive monitoring and remaining release gates.

## Diagnostic evidence custody and retention

- Sanitize by allowlist; never upload raw response bytes or private logs automatically.
- Store 0700 directories and 0600 files on encrypted, access-controlled storage with appropriate retention. Rotate the 32 MiB event journal by an approved exclusive writer protocol and preserve SHA-256 fingerprints of archived segments.
- A SHA256SUMS file detects later accidental modification relative to the captured manifest, but it is not a cryptographic signature. Sign incident records separately through authorized security processes if attestation is needed.
- Record expected recovery time and verification by a second operator; never mark services HEALTHY solely because the pager stopped generating events.
- Test all eight alert categories with safe, deterministic fixtures first. Repeat using genuine local conductors/operators, and check that each alert is sourced from real validated outcomes rather than arbitrary text.

**No operational incident, key revocation, conductor restart, migration, rollback, or funded transfer is executed by these GitHub deliverables.**
