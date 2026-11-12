# Sprint 38: production acceptance matrix (live, financial, resilience, operations)

**Pilot BLOCKED · Production NO-GO.** Every item below is outstanding. None
was executed in Sprint 38: each needs either external infrastructure or an
explicit authorisation that has not been given. This table records the
existing tool, the safe executable plan, and who must authorise it.

Rules that apply to every row:

* run on the exact candidate SHA from a clean checkout;
* use disposable data roots and network namespaces only;
* use test keys only, and no production funds;
* never touch other projects' conductors running on a shared host (an
  inventory of 9 unrelated conductors was taken 2026-11-12);
* use the **reviewed holochain 0.7.1 conductor** (checked with
  `scripts/security/conductor_release_profile.py --binary`). The installed
  0.7.0 binary fails the profile.

| # | Acceptance item | Issue | Existing tooling | Executable plan (summary) | Authorisation / infrastructure needed | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Independent Roughtime operators | #39, #67 | `scripts/roughtime/readiness_28.py`, `accept.py`, `config/roughtime-independent-sources.json` | Owner signs the source dossier (operator identity, key provenance, administrative independence). Then run the readiness check against live sources and record transcripts. | Agreements with ≥ 4 independent operators; owner approval of the dossier | BLOCKED (no agreed operators) |
| 2 | Four-to-three source outage tolerance | #6, #67 | Sprint 28 outage evidence path in `readiness_28.py`; signed-quorum tests | With 4 live sources, block 1 at the network layer (namespace or firewall on the test host only) and show the quorum still forms within the radius; block 2 and show fail-closed. | Item 1; host network authorisation | BLOCKED |
| 3 | Genuine conductor network partitions | #73, #43 | `scripts/chaos33_netns.py --ack-disposable-netns-lab`, `run_chaos33.sh` | Three reviewed-0.7.1 conductors in separate netns; partition/heal; check that no seal or warrant is lost and that the anchor does not regress. | Root/netns on a dedicated host; explicit go-ahead to create namespaces | NOT RUN |
| 4 | Standalone conductor SIGKILL/recovery | #73 | `scripts/chaos33_sigkill.py --ack-disposable-test-data` | SIGKILL at write boundaries on a disposable data root; restart and audit with `chaos33_db_audit.py`; add `datastore_guard.py audit-root`. | Authorisation for destructive tests on a disposable root | NOT RUN |
| 5 | Database corruption and restore | #73, #12 | `chaos33_db_audit.py`; **new** `scripts/security/datastore_guard.py` | Checkpointed backup, then `make-manifest`; corrupt or truncate a copy; `verify-restore` must refuse stray `-wal`/tampered sets; restore a clean set; the conductor must open it and refuse a corrupted one. | Same as 4; SQLCipher review open (`HCVT-S37-SQLCIPHER-CORE`) | NOT RUN (guard tested synthetically) |
| 6 | DHT 10,000-link stress | #68, #4 | `scripts/run_sprint31_dht_spam.sh`, `integration/conductor/tests/dht_spam.rs` | 10k links across 3 conductors with witness budgets; record CPU, memory and latency; production WASM must have no spam entrypoints. | Dedicated host (this host has ~5 GB free and shared conductors) | NOT RUN at full scale |
| 7 | Real fork/warrant persistence | #43 | `scripts/run_fork_recovery.sh` (fork lab is **destructive opt-in**: `--enable-fork-lab`) | Duplicate test agent key across two disposable conductors; observer must not trust either branch; warrant persists across restart. | Explicit authorisation for the fork lab | NOT RUN |
| 8 | Authenticated monitoring delivery | #78, #13 | `scripts/ops34/` (`auth.py`, `alerts.py`, `drill.py`), `run_sprint34.sh` | Deliver signed runtime events to a real alert endpoint; run injected incident drills; show rejection of unauthenticated or replayed events. | A real alert endpoint and an on-call owner | NOT RUN (offline tests only) |
| 9 | Unyt funded testnet acceptance | #8, #61, #50 | `scripts/unyt/testnet.py`, `sprint32_protocol.py`, `run_sprint26.sh` | Isolated alliance with test units only; RAVE + Accept natively authenticated; negative tests for every item #61 decides. | **#61 owner decisions** (see `docs/unyt/SPRINT38_UNYT_OWNER_DECISIONS.md`); test-unit funding; economic reviewer | BLOCKED (policy undecided) |
| 10 | Production oracle signer | #70 | **new** `integration/conductor/oracle_signer` (PR #85) | Reviewed key custody; sole-signer enforcement; SIGKILL at journal boundaries with Lair | HSM/Lair deployment; operator separation | NOT DEMONSTRATED |
| 11 | External monotonic checkpoint | #70 | **new** `AuthenticatedCheckpointAnchor` (PR #85) | The 7-step plan in `docs/oracle-persistence/SPRINT38_LAIR_SIGNER.md` | An independently operated checkpoint service | BLOCKED |
| 12 | Independent security and economic review | #14, #75 | `docs/audit35/INDEPENDENT_REVIEW_CHECKLIST.md` | Reviewer reproduces the exact-SHA bundle and signs off | An independent reviewer | NOT OBTAINED |
| 13 | Supply-chain clearance | #1 | `sprint37_supply_chain_gate.py`, Sprint 38 matrix | Approvals or upstream fixes | Owner/security approvals; upstream Holochain | BLOCKED |
| 14 | License/legal clearance | — | `docs/license38/LICENSE_OWNER_DECISIONS.md` | Ten decisions plus counsel | Owner and legal | `LICENSE_POLICY_APPROVAL_PENDING` |

## Order recommended once authorisations exist

The ordering follows dependencies, not urgency.

1. 13 and 14 (they block integration at all).
2. 4, 5, 3 and 7 on a dedicated host with the reviewed 0.7.1 binary.
3. 6.
4. 1 and 2 (need external operators).
5. 10 and 11 (need custody and checkpoint infrastructure).
6. 8.
7. #61 decisions, then 9.
8. 12 last, on the final SHA.
