# Sprint 35 — Independent Audit Preparation and Release Infrastructure

**Agent Y — release/assurance engineering. Priority: CRITICAL.**  
**Base:** merged development `main` at `bae1e5b9380e92cbee511e07fea1681011d4d6d0` (10 November 2026).  
**Status:** audit-preparation GitHub implementation; local reproducibility and independent audit **NOT RUN**.  
**Production / financial release:** **NO-GO**. No merge or deployment authorization.

## Deliverables committed to candidate branch

| Requirement | Artifact | What it establishes | What it does NOT establish |
| --- | --- | --- | --- |
| Updated threat model | `docs/audit35/THREAT_MODEL.md` | Actors, trust boundaries, ranked attacks and residual review obligations | Vulnerabilities exploited, fixed or independently resolved |
| Security invariants | `docs/audit35/SECURITY_INVARIANTS.md` | 24 properties cross-referenced to implementation/test locations and open evidence | 24 independently passing assertions |
| Crypto protocol docs | `docs/audit35/CRYPTOGRAPHY.md` | v2 MessagePack Ed25519, v3 fixed bytes, Merkle, Roughtime and persistence assumptions | Formal verification or cryptographic sign-off |
| Unyt economics | `docs/audit35/UNYT_ECONOMICS.md` | Agreement replay, target, collateral, expiry, challenge/slash/Accept threats | Issue #61 policy approval or funded settlement |
| Source provenance | `scripts/audit35/package.py`, `verify.py` | Fail-closed full-SHA clean-checkout tracked-source archive and independent archive+lock verification | Actual WASM/hApp reproducibility or production DNA approval |
| Supply-chain | `scripts/audit35/supply_chain.py` and dependency inventory | All three committed Cargo.lock graphs plus honest optional scanner/metadata stage logs | Fresh security advisory database, vetted licenses/unsafe dependencies |
| Reproducible packaging | `source.tar.gz` recipe, gzip mtime zero, `SHA256SUMS`; existing Sprint 27/20 tools reused | Independent binary compiler/hc pack determinism without real execution |
| Key generation/rotation | `docs/audit35/KEY_CUSTODY_ROTATION.md` | Operator/HSM ceremony, public fingerprint, independence, compromise and retirement SOP | Physical HSM setup or externally controlled antirollback |
| Migration and rollback | `docs/audit35/MIGRATION_ROLLBACK.md` | DNA/v2-v3/Unyt transitions and rollback-safe restrictions | Reversal of signed actions, financial RAVEs or monotonic state |
| Independent audit | `docs/audit35/INDEPENDENT_REVIEW_CHECKLIST.md` | Role assignment template, evidence/finding closure bar, unsigned signoff matrix | Actual independent audit |
| Runner independence | `scripts/audit35/run_local.sh`, `.github/workflows/sprint35-self-hosted-audit.yml` | Portable local/Codex source-audit command and manually gated dedicated self-hosted runner | GitHub-hosted Actions becoming functional, or full Sprint 27 runtime acceptance |
| Negative tests | `scripts/audit35/test_bundle.py` | Synthetic Git fixture tests for duplicate outputs, wrong/dirty SHA, forged manifests/hashes, missing locks, false PASS and scanner NOT RUN | No tests are recorded PASS until independently executed |

## Local Codex acceptance — REQUIRED, NOT YET CLAIMED

With clean full source clone, Python 3.11+, Git and no production secrets:

```sh
SHA="$(git rev-parse HEAD)"
bash scripts/audit35/run_local.sh "$SHA" ../s35-verified-source
python3 -B scripts/audit35/supply_chain.py --expected-sha "$SHA" \
  --output-dir ../s35-supply-chain
```

The source runner MUST reproduce source archive bytes and validate all lockfile contents and negative tests; the optional supply-chain scanner must preserve actual executed command/logs, classify missing tools NOT RUN, record database freshness for independent inspection and never claim approval. Then execute the separate authoritative Sprint 27 exact-SHA runner with **externally reviewed branch pins**, repeat native Rust/WASM/DNA/hApp outputs on independent machines, and verify existing `scripts/pack_release_dna.py` production preflight. Collect sanitized raw logs, SHA256SUMS and source SHA in secure storage *outside Git*. Never pass disposable test DNA, keys or time sources into a live/funded deployment.

## Mandatory remaining production gates

1. Merge/reconcile only selected reviewed Sprint 28/29/31/32/33/34 candidates into a **new separately validated exact-SHA candidate**; as at this branch, draft PRs #67/#69/#68 are **not part of main**. No stale test evidence transfers automatically.
2. Execute independent Roughtime operator/clock/root/key verification, real ≥3-conductor chaos and DHT resource-limit tests, actual HSM oracle crash/replay with trusted external monotonic checkpoint and operator-reviewed migration.
3. Resolve issue #61 target binding/proof replay/expiry/refund/challenge/slashing scope by explicit financial/security decision; run actual authorized Unyt native RAVE **and distinct recipient Accept** acceptance.
4. Perform actual Rust toolchain/Cargo advisory/licensing/unsafe source checks, pin standalone fuzz dependencies, review tracked generated bytecode and third-party build actions.
5. Independent cryptography, Holochain/DHT, Unyt economics, supply-chain and operations reviewers reproduce evidence, track every finding, and independently retest fixes on the final SHA.
6. Obtain signed release authorization from issue #1 owners and complete limited monitored pilot before any broad/financial launch.

**Risk declaration:** `source_packaged=true` merely means a clean tracked-source bundle was created from Git. Neither `source_reproduced_independently` nor `rust_tests_executed` nor `independent_audit_completed` may be inferred from a green GitHub PR, static source review or a CI job that ran zero steps. Source bundles intentionally never mark `production_release_ready=true`.

**Master gate #1 remains open; no production go-live, funds, secret keys or deployments are authorized by this sprint.**
