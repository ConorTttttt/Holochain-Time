# Sprint 35 — Independent security audit dossier and release evidence index

**Agent Y — Release and assurance engineering.** Baseline: merged development `main` at `bae1e5b9380e92cbee511e07fea1681011d4d6d0`, as observed on 10 November 2026. This directory is an **audit preparation deliverable**, not an independent audit or production approval. The Sprint 35 PR must remain a **draft** until reviewed.

## Review scope and missing integrations

The current mainline contains integrated Sprints 21–27 (PR #66) including native journal regressions, Roughtime acceptance tooling, conductor/load tests, guarded DNA packer and offline Unyt evidence interfaces. It is **development integration only**. Do not attribute anything from other unmerged sprint branches to mainline: Sprint 28 PR #67, Sprint 29 PR #69 and Sprint 31 PR #68 were separate draft candidates at this baseline. The mainline still has a **v2** Holochain oracle `attest_time`; Sprint 24 native **v3** journal is not a deployed signer. A completed ledger RAVE and separate recipient Accept have not been established.

## What reviewers receive

| Artifact | Purpose / status |
| --- | --- |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Assets, trust boundaries, attacker capabilities, abuse paths and unresolved controls |
| [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md) | Implemented assertions vs evidence still required, each with source/test anchors |
| [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) | Exact domains/encodings, trust decisions, v2/v3 and Merkle/Roughtime separation |
| [UNYT_ECONOMICS.md](UNYT_ECONOMICS.md) | Financial adversaries, slashing/refund incentives and nonfinal native evidence |
| [KEY_CUSTODY_ROTATION.md](KEY_CUSTODY_ROTATION.md) | Fresh-key provisioning, external operator approval, compromise/rotation runbook |
| [MIGRATION_ROLLBACK.md](MIGRATION_ROLLBACK.md) | DNA/agreement transitions, safe fallback and data backup/antirollback obligations |
| [PROVENANCE_AND_RUNNERS.md](PROVENANCE_AND_RUNNERS.md) | Source packaging, dependency evidence, checked rebuild and zero-paid-runner paths |
| [INDEPENDENT_REVIEW_CHECKLIST.md](INDEPENDENT_REVIEW_CHECKLIST.md) | Reviewer assignment, required raw evidence, blocker/severity disposition |

## Existing authority — reuse, do not overwrite

- [`RELEASE_PLAN.md`](../../RELEASE_PLAN.md), master [issue #1](https://github.com/ConorTttttt/Holochain-Time/issues/1) and `SECURITY_REVIEW.md` are the wider release gates.
- `scripts/release_acceptance_27.py` + `docs/SPRINT_27_RELEASE_ACCEPTANCE.md` define the combined exact-SHA **development acceptance** report and explicitly never authorize production.
- `scripts/deployment_preflight.py` and `scripts/pack_release_dna.py` are the guarded **DNA** packer; do not replace these with the Sprint 35 source bundle.
- `scripts/security/inventory.py` inventories tracked dependencies/possible unsafe markers; it does **not** run a security advisory scan.
- `docs/unyt/SPRINT26_INTERFACES.md`, `docs/unyt/SPRINT26_RUNBOOK.md` and `integration/unyt/sprint26_scenarios.json` govern proof/native receipt coverage. Issue #61 is unresolved policy.
- `docs/oracle-persistence/RECOVERY_MIGRATION.md`, `SPRINT_24.md` and draft PR #69 govern signer crash and externally anchored checkpoints. A local journal does not protect against privileged rollback.
- `docs/operations/INCIDENT_RESPONSE.md` is the operator incident baseline.

## Status lexicon and non-substitution rules

**PASS** means a specified command/test actually executed against one full reviewed SHA and has inspectable logs, exit codes and checksum inventory; **FAIL** means executed failure, invalid evidence or failed source match; **NOT RUN** means no executable evidence or dependency/approval unavailable. GitHub Actions with zero executed job steps is `NOT RUN/CI_BEFORE_RUNNER` even if GitHub shows a red badge (see #22). No source-only findings or checklist tick can turn a `NOT RUN` into `PASS`.

A Sprint 35 source bundle is only a deterministic **tracked source snapshot and lockfile inventory**. It does **not** contain independently built WASM, hApp, production DNA, attested live oracle/HSM, Roughtime operator receipts, funded Unyt RAVE/Accept, fresh advisory results or a signed external auditor opinion. Code, tests and documentation are available for inspection; they are not a security warranty.

**Release and financial rollout remain NO-GO** until issue #1 owners independently accept all P0/P1 evidence, significant audit findings are resolved, funded native Unyt acceptance and operator/clock/key/counter controls are proven, and a separate signed release decision is recorded.
