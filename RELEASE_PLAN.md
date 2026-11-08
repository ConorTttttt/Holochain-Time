# hc-vtime — Wider Release Readiness Plan

**Status:** NO-GO for public/production release  
**Prepared:** 2026-11-08  
**Basis:** static review of the uploaded `hc-vtime (1).zip` snapshot; findings require reproduction/validation in the deployed Holochain + Unyt stack.  
**Important:** This GitHub repository was empty when the plan was created. The project source must be imported from the supplied archive before these checks can run in GitHub. Do not treat the existence of this document as evidence of a completed source push.

## Release criteria

The project may move from private technical pilot to wider release only when:

- [ ] Every **P0 release blocker** below has a passing regression test and independent reviewer approval.
- [ ] `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` pass on the exact tagged commit.
- [ ] Both zomes compile for `wasm32-unknown-unknown`; `hc dna pack` and `hc app pack` succeed, and the resulting hApp runs in a real conductor.
- [ ] Multi-agent conductor tests cover anchor/seal, oracle outages, source-chain ancestry/forks, invalid proofs, recovery and malicious traffic.
- [ ] The evidence-discovery tests demonstrate that thousands of duplicate/irrelevant links cannot hide a relevant older anchor or seal **or** cause unacceptable query resource use.
- [ ] A documented concurrent-seal load test meets a published capacity/latency/error budget.
- [ ] Both Unyt agreements have been exercised on a live/test network with test funds, including success, challenge, refund, replay and interruption paths.
- [ ] Production DNA and agreement configuration has verified public keys, no placeholders, key custody/rotation procedure and recovery runbooks.
- [ ] An independent post-fix security review has no unresolved Critical/High findings, and the release is reproducible, tagged and has a rollback procedure.
- [ ] A time-limited pilot with monitoring completes successfully before financial or broad public use.

## Priority 0 — Must fix before wider release

| ID | Workstream | Problem | Exit evidence |
| --- | --- | --- | --- |
| P0-01 | Evidence correctness | `get_verified_time` truncates anchors/seals before evaluating relevance; link flooding can suppress older valid evidence | Deterministic adversarial tests preserve known bounds and verdicts under noisy links |
| P0-02 | Resource exhaustion | `get_links` materialises all matching links before local truncation | Bounded/partitioned discovery, measured memory/latency under 10k+ links, defined limits |
| P0-03 | Seal throughput | Unique per-seal nonce vs 1 statement/second/oracle; quorum of 3 impossible with only 2 configured Roughtime servers under oracle saturation | Scalable/batched or scheduled signing, admission control, 100+ concurrent seal test |
| P0-04 | Quorum availability | Policy accepts `N_trusted=3, min_sources=3, f=1` although one unavailable source prevents progress | Separate correctness/availability constraints; tests for every tolerated outage combination |
| P0-05 | Holochain integration | Native tests are not a WASM build or real conductor test | WASM/packaging success, ≥3 independent agents, malicious and recovery scenarios pass |
| P0-06 | Unyt money safety | Agreement harness tests are not real-network financial execution tests | Test-funded end-to-end acceptance and explicit cross-DNA bond/slashing policy |

Source anchors for P0-01 and P0-02: `dnas/vtime/zomes/coordinator/vtime/src/lib.rs` around link retrieval, sorting and truncation. P0-03: same file around rate limits and oracle calls. P0-04: `crates/vtime_core/src/evidence.rs` policy validation. P0-06: `unyt/*/execution_code.rhai`.

## Priority 1 — Required for a controlled production launch

- **P1-01 CI and supply-chain:** pinned toolchain, native tests, clippy, WASM build, hApp pack, dependency/security checks, release artifacts, protected branch.
- **P1-02 Parser/packet hardening:** explicit request/response size limits for Roughtime, fuzz/property tests and negative malformed-input tests.
- **P1-03 Configuration and keys:** prevent placeholder keys reaching a built DNA; verify trusted Roughtime keys and oracle agent keys; document independence and rotation.
- **P1-04 Migration/compatibility:** v1→v2 statement format behavior, oracle log recovery, funded agreement compatibility, migration and rollback drills.
- **P1-05 Operations/abuse:** metrics and alerts for quorum misses, signing frequency, query failures, chain forks, key loss and financial events; backpressure and incident response.
- **P1-06 Independent review:** third-party review of evidence discoverability, time bounds, oracle/bond economics, cryptography, and deployed Unyt execution.

## Priority 2 — Post-pilot improvements

- Developer integration quickstart and copy/paste examples for a consuming hApp.
- Published SLO/SLA, capacity envelope, cost and retention assumptions.
- API ergonomics: clarify that `Consistent` means consistent with **discovered** evidence, not complete independent proof of validity. Applications must check sufficient evidence and chain-health status.
- Historical upgrade/migration simulations and deterministic release provenance.

## Execution order / gates

### Gate 0 — Source baseline (repo hygiene)
Import only the actual project working tree from the uploaded archive into a review branch; exclude its embedded `.git` and local secrets. Record that the archive contains modified tracked files and one untracked `oracle.rs`; commit exactly what has been reviewed. Review any credential-like strings and dependency lockfile. Merge through PR, not a force push.

### Gate 1 — Security invariants
Complete P0-01, P0-02 and P0-04, with exploit-reproduction tests committed first where practical. No release while known time bounds can disappear from query results. Perform threat-model review of proof-index assumptions.

### Gate 2 — Liveness and capacity
Complete P0-03, P0-05; define target throughput and tolerated outages. Exercise real multi-conductor topologies, Byzantine oracles, partitions, restarts, recovery and long-lived chains.

### Gate 3 — Economic and deployment confidence
Complete P0-06 and P1 work. Validate Unyt test-money scenarios and bond scope; verify deployment properties/keys. Obtain independent audit sign-off. Produce a tagged candidate, SBOM/provenance and incident runbook.

### Gate 4 — Limited pilot
Time-boxed invite-only pilot using independent oracle operators; instrument error rate, quorum availability, p50/p95 latency, link query size, signing rate and recovery. Resolve any P0/P1 regression before next gate.

### Gate 5 — Wider release decision
Named engineering, security and operations owners approve the release checklist in writing. Only then publish a version or enable financial exposure. Keep a rollback and key-revocation plan.

## Suggested issue order

1. Import source snapshot with reproducible checksum and no embedded `.git`.
2. P0-01/P0-02 together: trustworthy *and* bounded evidence discovery.
3. P0-04 quorum-policy availability.
4. P0-03 oracle seal capacity.
5. P0-05 Holochain integration test infrastructure.
6. P0-06 Unyt execution and economic policy.
7. P1-01 through P1-06, audit and pilot.

## Risk register

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Relevant evidence suppressed by unrelated links | Incorrect `Consistent`/weakened verdict | Proof-complete bounded indexing and adversarial test |
| All oracles rate-limited simultaneously | Seals fail under load | Batching, queuing, independent oracle capacity |
| Configured time providers unavailable | Quorum cannot form | N ≥ min_sources + tolerated unavailable; diversify providers |
| Native tests pass but zome fails in conductor | Nonfunctional release | End-to-end conductor acceptance |
| Unyt slashing differs from operator assumptions | Financial loss | Cross-DNA scope decision, operator disclosure and live test-money tests |
| Key loss or incorrect DNA properties | Service interruption, unverifiable proof | Key validation, recovery exercise and documented rotation |

## Responsibilities

Assign an **engineering DRI** to evidence and protocol correctness, a **QA/integration DRI** to multi-agent testing, an **operations DRI** to keys and reliability, and an independent **security reviewer**. Do not close a blocker without an artefact (test, run log, PR or audit note) linked in the issue.

## Limits of the review

This is a release plan based on source-level findings, not a certification or completed audit. The supplied repository documentation reports native Rust test results; they were **not independently rerun** during this review. Validate environment-specific behavior against the versions ultimately deployed.
