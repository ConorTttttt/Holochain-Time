# Unyt economic threat model — release and oracle-bond agreements

**Scope:** `unyt/verified_time_release/execution_code.rhai`, `unyt/time_oracle_bond/execution_code.rhai`, rules/signature JSON and `unyt/harness`; Sprint 26 `docs/unyt/*`; unresolved [issue #61](https://github.com/ConorTttttt/Holochain-Time/issues/61). **Policy status: NOT APPROVED. No real funded execution or recipient acceptance established by this document.**

## Assets and environment

Financial assets are locked tranches, parked spend sources, bond collateral, reporter reward and slash beneficiary allocation. A verified Unyt **RAVE** is an executed Smart Agreement event, but the recipient must separately **Accept** its allocation on their own agent/account chain. A runner's synthetic JSON receipt, template simulation, offline signature check or a RAVE without recipient Accept is **not financial finality or evidence of spend completion**. Operators must pin the actual installed Unyt app version, alliance/DNA, smart-agreement engine, code and input-rule digests, native export format and account roles before any acceptance run.

## Economic actors and incentives

- **Grantor/payer:** wants only intended tranches released after an honestly demonstrated time bound, no double draw or invalid target.
- **Receiver:** benefits from early/repeated release; may delay or reject Accept; must not bypass a failed agreement.
- **Executor/reporter:** can submit proofs, race a slash/refund, spend compute resources and claim reporter rewards. A reporter may front-run another when signatures are public.
- **Bonded oracle:** can collude, issue equivocal/backdated statements, hide conflicting receipts, sign honestly but be unavailable, or lose a key; could benefit from unjustified early payout if reward exceeds realistic slash risk.
- **Witness oracles/Roughtime operators:** may collude, have shared hosting/delegation, give stale readings or become unavailable.
- **Unyt peers and external ledger adapter:** can reorder, withhold, reject or mislabel native actions. Account-level history and RAVE/Accept must be independently checked, not inferred from local logs.

## Attack matrix and tests the auditor must demand

| ID | High-impact loss path | Mandatory policy/mitigation decision | Native acceptance proof required |
| --- | --- | --- | --- |
| UE-01 | Reusing a time proof for an unrelated agreement, fund source or recipient | **#61:** versioned signed target binding (agreement instance, executor/receiver, source, policy, network and unique nonce) | Cross-agreement and wrong recipient/source negatives against *installed* Unyt app |
| UE-02 | Replaying a legitimate proof to claim more than one tranche | **#61:** distinguish **signed-proof replay** from double-spending a Unyt source; enforce durable agreement execution identity | Same signature retried; valid new proof for already consumed input must not double spend |
| UE-03 | Agreement expires before or during execution | **#61:** explicit expiry, grace/refund and timezone/clock semantics | Before, at, after expiry; stalled chain, rejected/late RAVE; recipient Accept ordering |
| UE-04 | Refund competes with a slash during the challenge interval | **#61:** authority and inclusive/exclusive boundaries of `bond_until + challenge_period_us` | Race and boundary tests with real native signed source actions |
| UE-05 | Reporter profits from bogus equivocation or cross-DNA statements | Canonical v2 signing bytes, bonded identity, same-chain vs cross-chain fork rules and explicit slash scope | Invalid signatures, same-key/wrong DNA, genuine contradictory pair, honest reordering |
| UE-06 | Bond is smaller than potential gain or slash costs exceed reward | Approve exposure/bond ratio, reporter reward, treasury distribution and maximum simultaneous obligations | Economic sensitivity table for collateral 0.1x/1x/10x exposure and independent sign-off |
| UE-07 | Quorum of non-independent witnesses authorizes early release/refund | Require independent key custody/upstream service, minimum sources and Byzantine budget | Withholding, collusion, one provider impersonating multiple keys, stale evidence |
| UE-08 | Native RAVE displayed as a paid transfer without recipient Accept | Require separate verified payee-chain `Accept` and actual balance/source accounting | Each payee Accept successful/rejected/unavailable; no phantom finality |
| UE-09 | Multiple signers race to consume one parked spend | Source lineage, spend uniqueness, native peer rejection and interrupt handling | Double-spent source, duplicate RAVE, conflicting chain, rejoin validation |
| UE-10 | Incorrect template/code/JSON rules or agent IDs allow role forgery | Pin code/rules hashes; strict role/field validation; no demo keys/IDs | Wrong executor, contributor, unit index, amount, template version and mutated fields |
| UE-11 | Version mismatch between `rave_engine` offline tests and installed application | Pin installed Unyt app and RAVE engine; reconcile actual exported bytes/API | Execute with the real client and inspect signed RAVE+Accept raw exports |
| UE-12 | Late-discovered contradictory oracle evidence after refund irreversibly succeeds | Explicit bond term, retained receipts and challenge/appeal policy; operator incident process | Simulate delayed DHT sync, withheld contradiction, refund/late slash; document residual loss |
| UE-13 | Key rotation or DNA migration strands existing agreements | Fixed keys/DNA per agreement, reviewed replacement agreements and funding reconciliation | Old/new proof non-interchangeability, stable parked source accounting and no fallback bypass |

## Example amounts are not approved policy

The repository's Sprint 14A isolated-test planner has example values for deposit, bond and reporter reward (300/500/50 test units, unit index 0), and an example seven-day challenge interval. These are **fixtures**, not recommended real-money collateral ratios or approved expiry terms. Their economic assumptions must be reviewed alongside project-specific loss exposure, real fee costs, liveness and slash recoverability.

To approve a risk policy, security/economic signatories must document: worst-case payout exposure per oracle; slashing probability under evidence withholding; whether bonds are per DNA, per signer, per agreement or cross-network; cooldown/challenge window endpoints; refund authorization; time-proof target; proof validity period; replay/nonce scope; native recipient Accept; and treatment of network partitions. The agent implementing tests must not silently decide these values.

## Required funded-test evidence

Record native RAVE and **separate recipient Accept** for each applicable scenario, account identity/author, agreement instance, source lineage, action/hash/signature bytes, installed app+engine version and reviewed template/rules digests. Reconcile balances and spent sources from at least two independently validating account views. Exercise invalid proof, replay, wrong target, expired claim, over-release, challenge success/failure, double spend, source exhaustion, interruption and rejection. Use *authorized disposable test units only*, never real funds or public hardcoded keys.

Independent audit cannot sign off financial launch while issue #61 or real funded tests remain open; `docs/unyt/SPRINT26_INTERFACES.md` and `docs/unyt/SPRINT26_RUNBOOK.md` remain authoritative operational references.
