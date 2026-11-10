# Sprint 26 — PR #62 / #63 reconciliation disposition

**Review date:** 10 November 2026. **Baseline:**
`cd0fae92929c9c56fc5e6b099ef2ad09ac70c2ad`.
**Primary:** PR [#63](https://github.com/ConorTttttt/Holochain-Time/pull/63)
at `56164945a58e86773c38366eb22d79a70b38be9d`.
**Alternative:** PR [#62](https://github.com/ConorTttttt/Holochain-Time/pull/62)
at `9c3e9b9081efeb7dfe4e2485fa50de22207d988c`.
**Earlier alternative:** PR [#50](https://github.com/ConorTttttt/Holochain-Time/pull/50).
**Issue:** [#61](https://github.com/ConorTttttt/Holochain-Time/issues/61) (OPEN).

This document is the **file-by-file source review and integration
disposition**. No branch has been merged into `main`. A PR's normalized
receipt/finality JSON must never be treated as a signed Unyt action.

## PR #62 — all four changed files reviewed

| PR #62 path | Unique safeguard / behavior | Reconciliation disposition |
| --- | --- | --- |
| `docs/SPRINT_26_UNYT_FINANCIAL_INTEGRATION.md` | Accurate Unyt agent-centric RAVE vs separate payee Accept model, release-matched `unyt_cli` caveat, independent-native-review-only meaning of opaque exports, issue #61 target/replay/expiry gap | **Ported conceptually** into `docs/unyt/SPRINT26_INTERFACES.md`, the authoritative runbook and this document. The older 86-line duplicate runbook is **not** separately added. A release-matched CLI's mere existence does not establish supported commands. |
| `integration/unyt/sprint26_scenarios.json` | 11 simple acceptance names, explicit `protocol_blocked` for target/replayed-proof/expiry, missing native Accept for successful payout | **Superseded** by PR #63's larger 18-case **v2** manifest. Required money amounts, recipients, predecessor links and native slots are now **all in this one manifest**; the older Sprint 14A matrix is historical reference only, not another authority for Sprint 26 settlement expectations. Issue #61 blockers cannot be relabeled available. |
| `scripts/unyt/sprint26.py` | `prepare` partial native evidence index, `audit` reports missing slots, one native filename cannot be reused across distinct evidence slots, strict basename/length/symlink/size/hash rules, create-only output, permanent `NO_GO` with `READY_FOR_INDEPENDENT_NATIVE_REVIEW` maximum | **Compatible safeguards ported** into the **single PR #63-derived `scripts/unyt/sprint26.py`**: `inventory` command (partial per-case statuses), `checked_file`, stricter file/JSON checks, `write_once`, `NO_GO`/unverified status. PR #63's **4 MiB bound is retained** instead of #62's weaker 8 MiB. **Not ported:** separate index/scaffold and `--manifest --index` CLI, since that would create a competing acceptance source. |
| `scripts/unyt/test_sprint26.py` | 10 offline tests for exact scenario coverage, missing recipient Accept, tampered digest, wrong network, missing app version/digest, reuse across native slots, symlinks/path traversal, extra scenario/fake `pass`, overwrites and unauthorized funding | **Ported and extended** to `scripts/unyt/test_sprint26_reconcile.py`, which imports the actual merged Sprint 14A planner rather than PR #62's test-only stub. Retain PR #63's existing independent Ed25519 vectors and reporter tests. Never copy the alternative same-named test module over the primary. |

### Alternative #62 scenario-to-authoritative v2 mapping

| #62 case | One canonical #63 v2 scenario or scenarios |
| --- | --- |
| `valid_verified_time_payout` | `release_first`, `release_second`, `release_final` |
| `forged_proof` | `release_invalid_signature` |
| `wrong_dna` | `release_wrong_dna` |
| `wrong_target` | `release_wrong_target` (**issue #61 BLOCKED**) |
| `replayed_proof` | `release_replayed_proof` (**issue #61 BLOCKED**) |
| `expired_release_agreement` | `release_expired` (**issue #61 BLOCKED**) |
| `valid_bond_refund` | `bond_refund_authorized` |
| `valid_challenge_slash` | `bond_slash_reversal`, `bond_slash_equivocation`; `bond_challenge_within_window` (**network contract BLOCKED**) |
| `invalid_slashing_request` | `bond_slash_invalid_proof`, `bond_slash_honest_pair` |
| `early_refund` | `bond_refund_early` |
| `unapproved_refund_executor` | `bond_refund_unapproved_executor` |

The #63 v2 matrix also retains `release_duplicate_oracle` and
`release_schedule_mismatch` from the merged Sprint 14A coverage.
One monetary policy and one set of proof expectations are applied.

## PR #63 — all fourteen changed files reviewed

| PR #63 path | Disposition |
| --- | --- |
| `.github/workflows/sprint26-unyt-offline.yml` | **Retain** one no-wallet workflow; do not add a second competing PR #62 workflow. Workflow execution still requires a working runner. |
| `SPRINT_26.md` | **Retain**, update to point to this reconciliation and explicit authoritative v2 manifest. |
| `docs/unyt/SPRINT26_INTERFACES.md` | **Retain** native model and PR #50 warning. Add issue #61 and PR #62 review disposition; installed native query API remains unverified. |
| `docs/unyt/SPRINT26_RESULTS.md` | **Retain**, update to NOT RUN/integration candidate state. No fabricated funded receipts. |
| `docs/unyt/SPRINT26_RUNBOOK.md` | **Retain**, update CLI to `inventory --interface-review` and `audit --interface-review`; preserve local funded-testnet handoff without automating wallet use. |
| `integration/unyt/sprint26_event.example.json` | **Retain and tighten**: add native `sources` export; accepted payout still requires distinct raw recipient Accept. Deliberately invalid example cannot be used to satisfy a real event. |
| `integration/unyt/sprint26_interface.example.json` | **Retain** pinned distribution/source provenance and reviewer; remains intentionally invalid without operator input. |
| `integration/unyt/sprint26_scenarios.json` | **Authoritative v2 manifest** with 18 scenarios, explicit payout/locked/input/previous links and seven required native artifact slots. **No second Sprint 26 scenario manifest.** |
| `scripts/unyt/run_sprint26.sh` | **Retain**, exact clean Git SHA and checksummed offline output. `--locked` Rust unit tests/Clippy expected from local Codex; no funds/keys. |
| `scripts/unyt/sprint26.py` | **Authoritative entrypoint.** Retain `prepare`, `stage-proof`, `audit`; port PR #62 partial `inventory`, immutability, file non-reuse and path checks. Bind audit/inventory to the exact interface-review SHA, public config, agreement manifest and authoritative scenarios. |
| `scripts/unyt/sprint26_audit_run.py` | **Retain** Rust scenario-name and Python PASS checks with permanent `funded_unyt_network_verified=false`. |
| `scripts/unyt/sprint26_proof.py` | **Retain** real v2 Ed25519/MessagePack evidence preflight, nonce equality/quorum, incorrect DNA and signed bond misbehavior checks. **Not** agreement-target or network-replay verification. |
| `scripts/unyt/test_sprint26.py` | **Retain and update** for v2 seven-artifact requirement; signed-interoperability fixture and negative proof tests stay. |
| `scripts/unyt/test_sprint26_audit_run.py` | **Retain** fake/skipped result rejection. Integrate the additional PR #62 intake regressions under a *new* distinct test filename so both discover. |

## Issue #61 and economic protocol blockers (UNRESOLVED)

1. **Target binding:** current `unyt_time_proof()` signs a random
   nonce and time interval. No agreement instance or specific Unyt
   target action is signed, and existing release Rhai does not enforce
   one. Wrong-target rejection cannot be accepted.
2. **Replay semantics:** a prior genuine signed time lower bound may
   be legitimately reused by the existing release template. Rejection
   of a repeated *Unyt parked spend/RAVE source* is distinct. Whether
   signatures themselves must be one-use requires a signed
   agreement-bound scope and durable replay policy. No claim made.
3. **Expiry:** tranche unlock times are not a full agreement expiry
   or expiry refund policy. No authenticated economics, penalties or
   expirations have been implemented. Bond refund challenge timing
   does not define release expiry.
4. **Challenge window:** an eligible signed malicious-pair claim is
   a model for slashing; its actual in-window network execution and
   terminal bond state remain unproven on a version-pinned app.

**Do not silently patch production Rhai or decide these economics in
this reconciliation.** Issue #61 remains OPEN pending a reviewed
protocol/financial decision, versioned migration and local execution.

## PR #50 negative disposition

Its receipt fields including 64-hex `network_genesis`, `tx_hash`,
`finality_verified=true` and `independent_record=sha256:...`
are normalized assertions, **not verified native Unyt API fields**.
Its linear blockchain-like journal is not proof of a globally finalized
agent-centric network. The existing Sprint 14A `rave_engine` financial
Rhai tests and strict public-role config/plan are retained from `main`;
the alternative receipt/journal assumptions are **not imported**.

## One authoritative workflow and evidence trust contract

1. **`sprint26.py prepare`:** immutable reviewed build/config/rules
   and 18-case manifest SHA, no transaction.
2. **`sprint26.py stage-proof`:** preflight canonical signed v2
   oracle statements and prepare existing Rhai parked-data input.
   No automatic parking, funding or accepted RAVE.
3. **`sprint26.py inventory`:** partial, missing/ready/blocked
   *opaque file inventory*, with immutable report output, uniqueness
   and hashes. `READY_FOR_INDEPENDENT_NATIVE_REVIEW` **is not PASS**.
4. **`sprint26.py audit`:** conservative offline ledger/proof
   consistency of a complete operator-supplied set. Unknown/native
   signer validity and peer/account state never become authenticated
   through JSON labels, action-like strings or SHA-256 alone.
5. **Separate local operator:** authorized test-only Unyt app/Build
   Panel or versioned reviewed adapter, native signed RAVE/source/
   Accept validation, second-peer state and independent economic
   audit. **Not implemented by GitHub agents.**

Neither partial inventory nor offline audit proves native signatures,
recipient settlement, spent-input uniqueness across the network,
valid peer identity, actual balance change, absence of a rejected
RAVE, or consensus finality. All financial release and production
claims remain **NO-GO**.

## Validation and handoff

Use one exact PR reconciliation head SHA and clean checkout:
`bash scripts/unyt/run_sprint26.sh --expected-sha "$(git rev-parse HEAD)"`.
The exact-SHA report will be generated externally and checksummed.
Complete all standard release integration gates with a real Rust/Holochain
toolchain and run the approved native testnet adapter locally. Funded
network acceptance and an independent security/economic decision
remain **not performed**. Do not merge this branch into `main`.
