# Sprint 29 — Production Oracle Persistence Integration

**Agent S — oracle runtime engineering. Priority: CRITICAL.**  
**Status:** native v3 runtime integration candidate on a draft PR; production acceptance **NOT RUN**.  
**Release decision:** **NO-GO**.

## Objective and existing production boundary

Connect Sprint 24's crash-safe signing journal to the oracle signing **runtime**, not merely a disposable callback test. In this repository, the callable Holochain coordinator endpoint `attest_time` still signs **v2** `OracleTimeStatement` via `hdk::sign_raw`. Sprint 24's journal operates on domain-separated **v3** `BatchStatementV3`. Directly reinterpreting v2 writes or replacing that endpoint would invalidate existing DNA/financial contracts and is **prohibited** here.

Sprint 29 adds a native, embeddable **v3 signing runtime** in `crates/vtime_oracle_state/src/runtime.rs`. It is the boundary for a future external Lair/HSM signer and independent monotonic checkpoint operator; neither production adapter nor the conductor endpoint has been connected. The new code must NOT be represented as a deployed oracle.

## Implemented changes

| Requirement | Candidate implementation | Limitation |
| --- | --- | --- |
| Journal wired into signing admission | `OracleRuntime::sign` serializes admission, enforces the existing PREPARE → SIGNING → verified COMMIT path | Native embeddable service only, not the v2 Holochain zome |
| Durable sequence/high-water/predecessor | `Journal::head` drives v3 `seq`, `prev_signature`, `floor_us` | Must compare with live conductor source-chain state |
| Crash-safe signing | Reuses Sprint 24 fsync fence and verifier without changing signature format | Full real signer crash/restart remains untested |
| Durable deduplication | New atomic `PREPARE_REQUEST` journal record binds 32-byte authenticated request ID to the complete canonical signed proposal; replay rebuilds full historical id → statement/signature map | Caller authentication and stable ID generation not implemented in repository |
| Duplicate/replay rejection | Same ID, identical content → exact stored signature, no callback; same ID/different content → hard conflict; unknown ID advances only from journal head | Valid old requests from untagged v2/v3 histories require migration |
| Legacy migration safety | Runtime refuses any journal containing untagged Sprint 24 `prepare` or `accept_verified` entries | No automatic old-identity migration |
| Key isolation | `OracleSigner` trait exposes only public key + one-shot canonical-bytes signing; the runtime stores no private bytes | Needs reviewed Lair/HSM adapter + sole key custodian enforcement |
| Anti-rollback interface | `CheckpointAnchor` requires independently authenticated read and durable monotonic compare-and-store; no reply before anchor acknowledges COMMIT | No trusted external backend; in-memory test doubles do not prove independence |
| Failure quarantine | Callback, journal or anchor uncertainty closes the signing lane; restart checks exact trusted checkpoint | SIGNING without COMMIT needs external receipt reconciliation or retirement |
| Regression | `tests/runtime_integration.rs`: live Rust signing lane, restart, request history, pre-sign recovery, ambiguous signing, anchor errors, rollback/corruption, wrong key, concurrent writer | Requires actual execution, reviewed infrastructure, process-kill and conductor runs |
| Documentation | `docs/oracle-persistence/SPRINT29_RUNTIME.md` | Not an operational deployment authorization |

## Mandatory acceptance (unchecked)

- [ ] Run `cargo fmt --all -- --check`, `cargo test -p vtime_oracle_state --locked --test runtime_integration`, Sprint 24 native process-kill tests, all workspace tests and Clippy against the exact PR HEAD; save genuine logs and checksums.
- [ ] Demonstrate a live **deployed** v3 oracle signer using independently held HSM/Lair key, audited RPC authentication, and a durable globally unique caller ID.
- [ ] SIGKILL the real signer at prepared/fenced/committed/anchor-update boundaries. Recover without a second signature or a contradictory output; show replay attacks rejected after restarts.
- [ ] Independently review directory fsync, loss/torn writes, single-writer ownership and the actual filesystem/storage settings; retain human-operated stale lock remediation.
- [ ] Implement a separately protected, authenticated **monotonic** checkpoint store with atomic compare-and-swap and provably current reads; prove local journal/backup rollback is rejected.
- [ ] Agree a reconciliation transaction for COMMIT-success/remote-checkpoint-failure, including external receipts and source-chain verification; do not auto-promote local state.
- [ ] Review v2→v3 key/DNA migration with the Sprint 15 and Sprint 21 owners. Do **not** silently reinterpret existing v2 signatures or change the live zome.
- [ ] Verify 3+ real agents and a real conductor after any future deployment adapter, plus Sprint 27 exact-SHA acceptance, independent security/economic review and the master release gate.

**Pass criteria:** the real oracle can be stopped/killed, restarted and restored from reviewed state without conflicting signed histories or invalid replay acceptance. The native mock tests alone cannot establish that outcome.

**Failure policy:** signer may have acted → quarantine, **never retry sign**. Journal COMMIT but anchor not acknowledged → withhold response, quarantine, compare to the newest authenticated external checkpoint, and require reviewed reconciliation. Missing or corrupt journal → no genesis fallback; retire or restore only from authenticated backup and trusted monotonic anchor.
