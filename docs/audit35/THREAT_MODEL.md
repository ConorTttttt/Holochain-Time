# Threat model — Holochain Time and Unyt release candidate

**Model revision:** S35-1, 10 November 2026. **Evidence baseline:** `main` at `bae1e5b9380e92cbee511e07fea1681011d4d6d0`. This is a *review hypothesis*, not proof that every threat is mitigated.

## Assets and intended security properties

Assets: canonical time bounds on genuine Holochain actions, signed oracle and Roughtime source identities, authenticated DNA configuration, source-chain ancestry and warrants, durable oracle sequencing and journals, Unyt parked balances/bond funds and RAVE/Accept outcomes, audit logs/provenance, and private operator signing keys. Required properties: **no unjustified bounds**, **no hidden relevant contradiction that is represented as globally absent**, **no duplicate economic redemption**, **no invalid re-sign after crash**, and **no replacement of a reviewed artifact with a different SHA**. Availability remains a separately stated goal, not proof of soundness.

## Actors, boundaries and threat assumptions

| Boundary | Trusted input needed | Adversary / failure to consider |
| --- | --- | --- |
| Client → coordinator | Caller nonce and explicitly supplied witnesses, capped by policy | Forged/malformed proofs, duplicate records, flooding, biased witness selection |
| DHT → verifier | Typed author/target, authenticated ancestor dependencies, cryptographic proof; DHT responses may be incomplete | Spam, eclipse/isolation, delayed sync, false completeness and resource exhaustion |
| Roughtime provider → verifier | Independently authenticated root key, supported protocol/delegation, nonce-bound signed response | Forged/expired/delegated key, correlated providers, wrong network, withheld or delayed packets |
| Oracle → key service | Approved DNA, identity, bounded time/nonce, persistent seq/floor and authorized request | Malicious signer, local crash, disk rollback, duplicate callback, compromised key, remote timeout |
| Holochain source-chain → remote peers | Valid chain ancestry and observed fork/warrant state | Equivocation, withheld activity, inconsistent validators, locally unknown warrants |
| Holochain time proof → Unyt agreement | Versioned agreement-target binding, chain/proof authenticity, replay/expiry policy, economic rules | Reuse across agreements, fabricated settlement, conflicting funding sources, expiry race |
| RAVE → recipient Accept | Actual native signed receipts and recipient chain evidence | Partial or rejected payouts, forged off-chain JSON, withheld recipient acceptance |
| Developer checkout → builder → operator | Full reviewed SHA, clean provenance, lockfiles, WASM/DNA/policy pins, secured CI runner | Dependency substitution, malicious actions, stale CI, compromised maintainer, key/approval leakage |
| Operator → external audit/release board | Independent reviews, signed exceptions, unmodified raw logs and signatures | False PASS reports, premature approval, unrecognized independent-system dependencies |

Attackers can operate Holochain clients, malicious DHT authorities and oracle identities, send malformed packets, cause partitions, withhold evidence or compromise *one* operator; **do not assume** all providers are independent without verifying their infrastructure. Also consider a privileged local actor restoring an internally valid older journal or CI evidence bundle. A Byzantine majority or compromise of all independently trusted signers is outside the baseline security assumption and must be explicitly discussed in risk acceptance; do not silently promise such conditions are safe.

## Ranked scenarios and audit questions

| ID | Severity if triggered | Scenario and security impact | Control / tests on baseline | Remaining review |
| --- | --- | --- | --- | --- |
| TM-01 | Critical | DHT link spam/missing old relevant anchor produces falsely confident bounds | Explicit witness verifier, `AGENTS.md`, `crates/vtime_core/src/evidence.rs`, `dnas/vtime/zomes/coordinator/vtime/src/lib.rs` | #3/#4; Sprint 31 draft #68; prove resource budgets and no suppressed *provided* evidence on real conductors |
| TM-02 | High | Caller interprets `NoContradictionInSuppliedProofs` as no global fork | Endpoint explicitly says `evidence_complete=false` | App/API consumers must be audited for absence-of-evidence misuse |
| TM-03 | Critical | Forged ancestor/fork evidence yields false `not_before` | Explicit chain witness checks and Sprint 22 fork tests | Real partition/rejoin and remote-warrant persistence, source availability under faults |
| TM-04 | High | Roughtime single operator masquerades as several independent sources | `vtime_core/src/roughtime.rs`, Sprint 23 configured operator dossiers | Production roots/protocol/hosting/delegation/time captures must be independently confirmed; #67 draft |
| TM-05 | Critical | Oracle crash after signing but before commit leads to conflicting signature or replay | Sprint 24 journal has PREPARE/SIGNING/COMMIT fences, native process-kill suite | **Not live oracle service**: HSM + anchor/CAS + external reconciliation gate #70, Sprint 29 draft #69 |
| TM-06 | Critical | Restoring an authentic older journal bypasses high-water; same key re-signs | `Journal::open_checked` can compare an externally authenticated checkpoint | Require independently durable, monotonic latest anchor; local file copy does not suffice |
| TM-07 | High | v2 proof treated as v3 batch or noncanonical key creates wrong actor/bond | `statement.rs`, `signed_batch.rs`, `keys.rs`; domain-separated formats | Review every consumer/migration, including Unyt Rhai and integrity zomes |
| TM-08 | Critical | Reuse of signed time proof across two Unyt agreements/targets | Sprint 26 offline checks and published interface gap | **Issue #61** agreement binding/replay/expiry unapproved; no funded acceptance |
| TM-09 | Critical | Double spending / inappropriate settlement inferred from untrusted JSON | Sprint 26 native-evidence schema distinguishes RAVE from recipient Accept | Run real funded RAVE and recipient Accept with independently verified native actions |
| TM-10 | High | Incorrect refund/slash timing or permissive challenge policy steals funds | `unyt/*/execution_code.rhai`, `unyt/harness/tests/templates.rs` | Approve challenge windows, term and collateral policy; test actual engine/app versions |
| TM-11 | High | Reused fixture/placeholder key installed in production DNA | Sprint 20 strict `deployment_preflight.py`, blocked config tests | Authenticated independent operator key ceremonies, installation proof and rotation drill |
| TM-12 | High | Wrong-source code or crafted green reports become release evidence | Sprint 17/27 SHA/pins audit, Sprint 35 reproducible tracked-source archive | Independently rebuild WASM/DNA/hApp, compare checksums; verify CI jobs ran real steps |
| TM-13 | High | Vulnerable/crate-swap or malicious CI job runner yields compromised release | Cargo lockfiles and source inventory; supply-chain reports in Sprint 35 | Fresh advisory/license scan, transitive review, pinned toolchain/actions, clean isolated builders |
| TM-14 | High | Recovery procedure destroys evidence or advances conflicting chains after network fault | Sprint 12/22 runbooks, `docs/operations/INCIDENT_RESPONSE.md` | Sprint 33 conductor chaos pending; prove real partition vs simulated isolation |
| TM-15 | High | Operator rotates Roughtime/oracle key without changing DNA/agreement identity | `deployment/policy.schema.json`, Sprint 20 production preflight | Separate DNA migration, trust overlap, fixed Unyt agreement rules and identity retirement |
| TM-16 | Medium–High | Valid-but-expensive cryptographic input exhausts CPU/RAM while cheap input is bounded | Sprint 16 unsafe/resource inventory, Sprint 21 seal queue | Load/limit evidence under realistic 10k+ DHT link stress and scheduling |

## Design restrictions imposed on any remediation

Integrity validation must stay deterministic; mutable I/O, clocks and HSM calls stay outside integrity zomes. Adding an LRU cutoff of *security-relevant witnesses* is not proof-complete evidence handling. Never change DNA integrity properties or v2 signed serialization without a migration ADR and re-review. A `PASS` from native tests or mock Unyt receipts cannot replace real conductor, independently operated sources, HSM or funded acceptance.

## Risk acceptance register to complete in audit

For each TM item record: affected git commit and component, attack prerequisites, exploit/witness fixture, reproduction command and raw report checksum, severity and likelihood, impact on soundness/liveness/financial safety, proposed mitigation, implementing PR, reviewer identity and independent retest SHA. Explicitly mark **OPEN**, **MITIGATED_WITH_EVIDENCE** or **ACCEPTED_WITH_SIGNED_EXCEPTION**; never mark an issue closed merely because a document exists.
