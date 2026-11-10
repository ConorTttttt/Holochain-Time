# Security invariants and verification inventory

**Snapshot:** integrated development main `bae1e5b9380e92cbee511e07fea1681011d4d6d0`. **Evidence status is not auto-populated**; the table identifies executable assertions and outstanding independent checks. Each reviewer must cite the exact tested SHA, test name, raw output hash and any relevant runtime deployment IDs.

| ID | Property required before production | Implementation/test evidence to inspect | Remaining gate |
| --- | --- | --- | --- |
| INV-01 | Holochain integrity validation is deterministic and independent of wall clock, mutable local store and nondeterministic DHT reads | `dnas/vtime/zomes/integrity/vtime_integrity/src/lib.rs`, Cargo HDK=0.7.1 / HDI=0.8.1 | Compile WASM and review host import table on exact SHA |
| INV-02 | No accepted statement crosses a different DNA/network or oracle identity | `crates/vtime_core/src/statement.rs`, `keys.rs`; `evidence_policy.rs` | Cross-DNA/agent adversarial conductor tests |
| INV-03 | Text-form AgentPubKey/DNA hash checks prefix, full bytes and BLAKE2b location checksum | `crates/vtime_core/src/keys.rs`; key canonicality tests | Independent Rust/Unyt same-key interop |
| INV-04 | v2 detached Ed25519 signed bytes are canonical MessagePack, `domain=hc-vtime/oracle-statement/v2` | `crates/vtime_core/src/statement.rs` | Reproduce fixture vectors on external verifier and live Unyt |
| INV-05 | v3 nonce-batch signature is distinct from v2 and binds DNA, root, count, interval, seq, prev, floor | `crates/vtime_core/src/signed_batch.rs`; signed-batch protocol tests | HSM and integrity/Unyt v3 migration not approved |
| INV-06 | Merkle nonce commitments bind DNA and count, reject duplicates, and check actual inclusion | `crates/vtime_core/src/batch.rs`, `signed_batch.rs` | End-to-end v3 consumer acceptance, not merely a native primitive |
| INV-07 | Roughtime response is nonce-bound with validated root delegation, signature, packet bounds and protocol version | `crates/vtime_core/src/roughtime.rs`; Sprint 11/23 interop suites | Operator-authenticated live roots and non-correlated upstream sources |
| INV-08 | Quorum counts distinct independently approved sources and tolerates stated failure budget | `crates/vtime_core/src/evidence.rs`; signed three-agent scripts | Independent real-source outage and shared-operator audit |
| INV-09 | Bad/missing supplied evidence fails closed rather than silently elevating confidence | `evidence.rs`, `dnas/vtime/zomes/coordinator/vtime/src/lib.rs` | Real DHT timeout/resource denial and partial-authority responses |
| INV-10 | Caller-supplied witness verdict NEVER claims global absence of hidden contradictions | `verify_time_with_witnesses`; `evidence_complete=false` | Audit downstream consumers and economic contract decisions |
| INV-11 | `not_before` is supported only by authenticated source-chain ancestry and correct author/target | Coordinator and `integration/conductor/tests/security_witness.rs` | Negative warrants/forks/partitions across real conductors |
| INV-12 | Warrant/fork observations persist and cannot be cleared by a partial remote answer | Sprint 22 fork recovery and Sprint 25 observer integration | Multi-conductor partition/rejoin regression with real warrants |
| INV-13 | Resource limits cannot suppress relevant *provided* evidence or report completeness after truncation | Core evidence limits and Sprint 31 draft #68 | 10k+ DHT link stress, request/byte budgets, no false-clean verdict |
| INV-14 | Oracle signing serializes per identity and no request signs twice across crash/restart | `crates/vtime_oracle_state/src/lib.rs` (Sprint 24) | Deployed Lair/HSM + runtime draft #69 not on main; issue #70 |
| INV-15 | High-water/seq/commitment recovery refuses old or corrupt journal state | Sprint 24 `restart_safety`, `process_crash`, `backup_migration` | External monotonic anchor, real filesystem and key-service crash drills |
| INV-16 | No private production keys, fixture roots or operator credentials enter release DNA or public audit archive | `scripts/deployment_preflight.py`; `deployment/known_insecure_keys.json` | Signed two-person operator key inventory and actual production scan |
| INV-17 | Production DNA is built only from approved, pinned configuration and WASM digests | `scripts/pack_release_dna.py`, `docs/SPRINT_20_RELEASE_CONFIGURATION.md` | Review of actual production approvals and independently reproduced hApp |
| INV-18 | Unyt proof target, identity, expiry and replay rules are explicitly agreed before live use | `scripts/unyt/sprint26_proof.py`, `docs/unyt/SPRINT26_INTERFACES.md` | Issue #61 economic/security policy authorization |
| INV-19 | Financial execution distinguishes a native signed RAVE from separate recipient Accept and validates source consumption | Sprint 26 native evidence schema, `integration/unyt/sprint26_scenarios.json` | Actual funded RAVE, distinct recipient Accept and spend-source conflicts |
| INV-20 | Slashing and refund conserve funds and enforce term/challenge/role policy | `unyt/*/execution_code.rhai`, `unyt/harness/tests/templates.rs` | Installed Unyt version + real funded scenarios + independent economics review |
| INV-21 | Build evidence names ONE exact Git SHA and cannot call unexecuted stages PASS | `scripts/integration_validate.py`, `scripts/release_acceptance_27.py`, `scripts/audit35/{package,verify}.py` | Reviewer reproduces same SHA, inspects raw logs and checksums |
| INV-22 | CI failures before runner assignment are NOT RUN, never a code-test failure or pass | `scripts/audit_ci.py`; issue #22 | Local/Codex or isolated self-hosted exact-SHA execution |
| INV-23 | Dependency graph, license and advisories are independently inventoried and reviewed | Cargo.lock set + `scripts/security/inventory.py` + Sprint 35 dependency-lock bundle | Actual recent `cargo audit`/`cargo deny`, provenance for registry packages, fuzz lock |
| INV-24 | A safety-critical rollback never reuses a compromised signing key or restores an earlier trusted counter | `docs/oracle-persistence/RECOVERY_MIGRATION.md` and `docs/audit35/MIGRATION_ROLLBACK.md` | External checkpoint witness and operator-supervised retirement |

**Classification:** The “implementation/test evidence to inspect” column is a *pointer to code or existing harnesses*, not a list of PASS claims. Reviewers must record `PASS`, `FAIL`, `NOT RUN` individually for every invariant on the **final candidate**. Earlier development validation (PR #66) does not transfer to a changed SHA.

## Evidence worksheet fields

`invariant_id | candidate_sha | finding_id | scope/component | reviewer | expected_assertion | test_name_and_command | raw_log_sha256 | signed_artifact_sha256_if_any | executed_status | independent_reproduction | residual_risk | mitigation_pr | signoff_date`

A reviewer should fail INV-09/10 if an application incorrectly interprets incomplete DHT discovery as a globally clean history, even if every supplied signature is correct. Financial INV-18/19/20 remain blocking regardless of core Rust test results.

## Reviewer coverage allocation

- **Cryptographer:** INV-02–08, INV-14–15; canonical domain, cross-DNA and signing-fence analysis.
- **Holochain/DHT specialist:** INV-01, INV-09–13; source chain, forks, partial DHT and resource limits.
- **Unyt/economic reviewer:** INV-16–20; money conservation, target binding, challenge/refund/slashing.
- **Release/supply-chain reviewer:** INV-21–24; exact commit, provenance, dependency and rollback.

All four roles need independent evidence; the same developer self-marking every row is not a security audit.
