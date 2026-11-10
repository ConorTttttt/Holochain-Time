# Independent audit checklist and release sign-off record

**Status: UNASSIGNED / NOT RUN.** This is a reviewer checklist template, not the outcome of an audit. All findings, especially Critical/High, must be triaged by independent reviewers on the **same final exact commit SHA**. No approval checkbox may be checked merely because a script or test file exists.

## Candidate identification (complete before review)

- [ ] Candidate full 40-character SHA, repository/remote provenance and signature/branch protection recorded; SHA revalidated from fresh independent clone.
- [ ] Committed branch ancestry includes the *reviewed versions* of all required production sprints; outstanding PR #67 (Sprint 28), #69 (Sprint 29), #68 (Sprint 31) and future sprint work explicitly reconciled or documented excluded. Mainline has integrated Sprints 21–27 only at Sprint 35 branch creation.
- [ ] Two reproducible `source.tar.gz` archives match SHA-256; `verify.py` independently verifies extracted lockfile graph and rejects forged evidence. Include exact tool versions and raw output.
- [ ] Release inventory enumerates manifests/policies, all WASM binaries, DNA/hApp bundles, signer key identities, external checkpoint, Unyt code/rules, toolchain containers and source archive hash; private credentials excluded.

## Cryptography and protocol audit

- [ ] Independent cryptographer reproduces v2 named-MessagePack signed bytes and Ed25519 vectors, DNA/key checksum rejection, lowercase canonicality, prev/seq/floor continuity and cross-DNA negatives.
- [ ] Independently reproduces v3 fixed-width domain-separated batch bytes and Merkle nonce inclusion; no v2 signatures accepted by v3 consumer.
- [ ] Reviews Roughtime RFC 10049 plus supported draft versions, root delegation/key provenance, nonce/interval verification, malformed/tag/packet caps, non-independent operators, and failure tolerance.
- [ ] Reviews signed source-chain ancestry, fork/warrant persistence, explicit evidence incompleteness, quorum unique-source counting, denial and DHT resource-limit semantics.
- [ ] Reviews real oracle HSM signer and persistent idempotency journal, SIGNING uncertainty quarantine, same-key single-writer and externally trusted monotonic checkpoint; `Journal` native test alone is **not** acceptance.
- [ ] Reviews v2→v3, API, DNA and Unyt consumer compatibility, signature/domain migration and identity retirement plan.

## Financial/economic audit

- [ ] Issue #61: approvers sign a versioned agreement-target binding and clarify proof replay versus double-spent source, expiry/refund, challenge boundary, slashing/bond scope and migration.
- [ ] Independent economic reviewer models collateral sufficiency, incentive/collusion risk, source withholding, honest oracle liveness, reward racing and loss/compensation.
- [ ] Real authorized Unyt app version, code/rules hashes, RAVE engine, alliance/DNA and account IDs are pinned and reconciled.
- [ ] Every funded positive scenario includes **native signed RAVE AND separate recipient Accept**, plus spent-source account reconciliation; negative replay/target/expiry/double-spend scenarios fail.
- [ ] No production keys or real funds used in general CI/audit fixtures.

## Build, supply chain and provenance audit

- [ ] Exact candidate SHA and clean non-shallow source verified; no moving branch or stale external pins accepted.
- [ ] Locked workspace/conductor/load dependency graphs inventoried; fuzz lock graph pinned or explicitly disclosed missing.
- [ ] Fresh RustSec advisory scan, license/ban/source scan, third-party unsafe/FI and native Unyt/Holochain binary review executed with raw logs + update/version metadata.
- [ ] Toolchains and third-party CI actions are independently pinned/reviewed, including any reusable workflows, binaries, build containers and dependency caches.
- [ ] Cargo workspace native tests, Clippy, rustfmt, WASM and byte-identical clean DNA pack; 3+ real conductors, signed-quorum, restart/fork/rejoin, load, malformed inputs and source-exhaustion tests **executed**, not merely declared.
- [ ] Cross-builder source/WASM/DNA/hApp artifact hashes match or differences have independently accepted deterministic explanation; preflight production manifest/policy/approval actually validated.
- [ ] GitHub Actions with `steps=[]` / no assigned runner classified `NOT RUN/CI_BEFORE_RUNNER`; local/Codex/self-hosted actual logs provided in lieu of hosted runners.
- [ ] Provenance/receipt inventory uses SHA256SUMS, authentic Git SHAs, executed test names/exit codes and no fabricated PASS claim.

## Operations and rollout audit

- [ ] Real independent Roughtime and oracle operator key custody confirmed; HSM provisioning, revocation and distinct failure domains recorded without secret exposure.
- [ ] Multi-conductor partition/chaos, signer crash at each fence, rollback/corruption and remote checkpoint outage tested in disposable environments and reviewed.
- [ ] Migration rehearsal demonstrates v2/v3, changed DNA, outstanding Unyt agreements and old/new key separation; no replay/downgrade loophole.
- [ ] Incident runbook exercised: stalled quorum, compromised key, unavailable witness, partial evidence, wrong DNA, failed RAVE/Accept and lost journal.
- [ ] Production monitoring, measured capacity/error budget, backup/restore drill, recovery-time objectives and time-limited pilot plan independently accepted.

## Finding management and final disposition

For every discovered problem record `finding_id, affected_sha, evidence_sha256, impact, severity, attack preconditions, raw reproduction link, recommended change, fix_pr_sha, independent_retest_sha, disposition, reviewer, date`. **Critical/High findings cannot be resolved by a documentation-only exception** without a written, separately authorized residual-risk decision in the master release process. A commit after audit requires impact analysis and relevant regression re-run against the new SHA; do not transfer PASS.

| Role | Reviewer (independent person) | Evidence link/hash | Signature and date | State |
| --- | --- | --- | --- | --- |
| Cryptography | TBD | TBD | TBD | NOT RUN |
| Holochain/DHT/network | TBD | TBD | TBD | NOT RUN |
| Unyt financial/economic | TBD | TBD | TBD | NOT RUN |
| Supply chain/release engineering | TBD | TBD | TBD | NOT RUN |
| Operations/keys | TBD | TBD | TBD | NOT RUN |
| Final engineering/security/finance approval (#1) | TBD | TBD | TBD | NO-GO |

**Release decision: NO-GO** until independent reviewers reproduce the candidate, confirm no unresolved material findings, and issue #1 has separately recorded explicit approval. A draft Sprint 35 PR must not auto-close release/security/financial issues.
