# Sprint 38: Unyt financial-policy decisions for issue #61 (none taken)

**Status: OWNER DECISION REQUIRED. No financial rule, Rhai template or DNA
code was changed in Sprint 38.** This document consolidates the nine topics
the release mission lists. It maps each to the existing Sprint 32A proposals
(`integration/unyt/sprint32_policy_options.json`,
`docs/unyt/SPRINT32_PROTOCOL_AND_NATIVE_INTEGRATION.md`) and adds the three
that had no decision entry. Prepared by automated analysis (Claude Code). An
economic reviewer must take part before any funded test.

Facts that constrain every option (from #61 and Sprint 32A):

* `unyt_time_proof()` returns a randomly nonced `{ statements }` payload.
* `verified_time_release/execution_code.rhai` checks trusted oracles, the
  DNA and a robust lower bound, but **no action target**.
* The release template has **no agreement expiry**.
* The current Rhai checks time on bond **refund**, not on **slash**.
* An old signed lower bound shows only that time is *at least* that value.
  It cannot show that something happened *before* a deadline.

| # | Topic | Options (existing ID or new) | Consequence of each | Must also decide |
| --- | --- | --- | --- | --- |
| 1 | **Target binding** | `release_target_binding`: (a) generic conservative v2 time bound; (b) signed v3 agreement/instance/target commitment | (a) keeps today's semantics; any agreement can reuse any proof. (b) needs a new signed v3 domain, a verifier change and new agreement hashes | Which target: Holochain action, agreement instance or both |
| 2 | **Agreement identity** *(new entry)* | (a) Unyt agreement action hash; (b) content hash of the template plus parameters; (c) both | (a) is unique per instance but available only after creation; (b) is reproducible but collides across identical instances | Whether v3 proofs commit to it, and how migrated agreements get one |
| 3 | **Signed time-proof reuse** | `signed_proof_reuse`: (a) allow re-verification of immutable proofs; (b) one use per agreement execution with durable state | (a) is safe under the fault model and needs no state. (b) needs an enforceable state transition and a migration | Must not be called "double spending"; see 4 |
| 4 | **Native source double-spend prevention** *(new entry)* | (a) rely on native Unyt source-chain/spend-link validation only; (b) also require independent peer reads of the source chain before Accept | A local "used-source" set is **not** global protection under either option. (b) adds latency and reviewer-visible evidence | Which component is authoritative; evidence retained per release |
| 5 | **Expiry** | `release_expiry`: (a) no expiry (legacy); (b) freeze unreleased for governance; (c) refund unreleased to grantor | (b) and (c) need an authenticated deadline, and a rule for proving the deadline passed (a lower bound shows *after*, not *before*) | Treatment of paid tranches and outstanding Accepts |
| 6 | **Refunds** *(split from expiry)* | (a) refund = new reviewed native allocation + Accept; (b) no refunds | A refund is never an accounting label. (a) needs reclaiming `locked` from a predecessor RAVE without grantor/beneficiary races | Who pays fees; abandoned agreements |
| 7 | **Challenge periods** | `bond_challenge_close`: (a) slash until bond spent (legacy); (b) close at `bond_until + challenge_period_us` | (b) needs authenticated native execution ordering at the boundary. The current Rhai does not enforce a slash cutoff | Boundary race resolution and prioritisation |
| 8 | **Bond scope** | `slashing_and_bond_scope`: (a) only attested oracle v2 malfeasance; (b) expand after a new reviewed agreement | (a) is today's evidence: a signer-specific malicious statement or pair. The bond does not insure outages, honest error or payment faults | Reporter reward, beneficiary, multiplier (current 50/450 of 500 units is test-only) |
| 9 | **Cross-DNA slashing** *(new entry)* | (a) slash evidence valid only for the DNA the bond names; (b) evidence from any DNA where the same oracle key signed; (c) an explicit list of DNAs per bond | (b) increases deterrence, but an oracle could be slashed for a DNA it never bonded for. Key rotation complicates attribution. (c) needs governance of the list | How the DNA set is committed in the bond agreement |

Migration of existing agreements (`legacy_agreement_migration`) applies to
every row. An existing v2 signature can never be reinterpreted as a v3 target
commitment.

## Decision record (owner and economic reviewer)

| Topic | Option chosen | Approver / role | Date (UTC) | Reviewed commit |
| --- | --- | --- | --- | --- |
| 1–9 | — | — | — | — |

After approval, implement only the approved rules on a separate branch, with
negative tests for wrong target, wrong agreement, wrong DNA, expired,
not-expired, boundary and cross-DNA cases, before any funded test (#8).
