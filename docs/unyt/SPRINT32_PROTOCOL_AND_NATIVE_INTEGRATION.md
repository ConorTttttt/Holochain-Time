# Sprint 32A / 32B — Unyt financial protocol and native integration (Agent V)

**Date:** 10 November 2026. **Development base:** `bae1e5b9380e92cbee511e07fea1681011d4d6d0`.
**Issue:** [#61](https://github.com/ConorTttttt/Holochain-Time/issues/61) (OPEN).
**State:** DRAFT PROPOSALS + TEST-ONLY INTERFACES. **NO APPROVED ECONOMIC POLICY. NO FUNDED TESTNET ACCEPTANCE. PRODUCTION NO-GO.**

This sprint makes a clear **32A/32B cut**. It reuses Sprint 14A's published
`rave_engine =0.15.0` offline Rust tests and Sprint 26's 18-case v2 scenario
manifest, strict v2 Ed25519 preflight and native-artifact reconciliation. No
new competing acceptance manifest, no synthetic finality receipts, no changes
to either production Rhai template, no network calls, wallet or secrets.

## 1. Observed facts and approval decisions

Current `unyt_time_proof()` produces **random-nonce, v2 signed oracle
statements** containing DNA, oracle, nonce, time bound and signed chain link,
but no agreement or action target. The existing
`unyt/verified_time_release/execution_code.rhai` checks signatures, trusted
DNA/oracles and a robust lower bound; it explicitly permits an old lower bound
to be reused. Tranche unlocks are not release expiry.

The bond template checks `bond_until + challenge_period_us` to prevent an
**early REFUND**. Its **SLASH** branch does *not* enforce a closing deadline.
A slash may therefore remain executable beyond the example challenge period
if the parked bond has not already been spent on a refund. Approval of a
strict slash deadline needs an authenticated, enforceable execution-time
source; comparing an old signed lower bound to the deadline does **not**
prove that the slash occurred before the deadline.

See `integration/unyt/sprint32_policy_options.json` for the six
**unapproved** decisions, alternative policies, and explicit reviewer questions.
The JSON deliberately has no selected policy. Required signoff includes the
financial/economic owner, independent security reviewer, and installed-Unyt
protocol owner, each on the same immutable policy digest. A GitHub agent may
propose/test consequences but cannot decide final economics.

| Decision | Alternative A | Alternative B / C | Risk / unresolved signoff |
| --- | --- | --- | --- |
| Release proof purpose | **Legacy:** generic historical lower-bound evidence | **New v3:** signed context for particular agreement instance + target + DNA | New cryptographic domain and actual signature-verifying Rhai/integrity policy required. |
| Reuse of signed proof bytes | Historical verification of lower bound allowed | One-use per agreement execution with durable, consensus-enforced consumption | Do **not** confuse with double-spent Unyt sources. |
| Expired unreleased tranche | Freeze until governance/recovery | Refund unreleased to grantor; legacy no-expiry also possible | Who owns locked value, pending Accept, costs, custody and expiry authority? |
| Bond slash deadline | Existing behavior: slash until bond spent | Proposed `[bond_until, bond_until+challenge_period)` closure | Need actual signed native execution time or equally trusted bound and race handling. |
| Slash/bond scope | Existing: signed v2 equivocation, time reversal, floor-drop, contradiction | New broader scope only by separate reviewed contract | No automatic slash for downtime, false positive time source or unapproved behavior. |
| Migration | Keep legacy agreement intact | New explicit v3 template/rules hash and new agreements | Cannot retrofit binding into existing v2 signatures or mutate parked agreements. |

**Example numbers are fixture-only, not approved network economics:** release
deposit 300 test units, three 100-unit tranches; independent 500-unit bond
instances with 50 reporter / 450 treasury on valid slash, or 500 refund after
challenge; test unit index `0`. Fees, unit supply, balance ownership,
concurrent funding and revoked/rotated signers need independent review.

## 2. Versioned agreement/target commitment proposal (NOT yet signed)

The **candidate** `hc-vtime/unyt-agreement-target-proposal/v1` is a
deterministically serialized context carrying:

- **Unyt identity:** isolated `alliance_id`, real agreement instance ID,
  native signed agreement action hash, agreement-template SHA-256, rules
  SHA-256 and separately authenticated schedule SHA-256.
- **Holochain identity:** typed vtime DNA hash and the **actual target
  ActionHash**, not a human label or unsigned proof metadata.
- **Domain/purpose:** verified-time release vs bonded-refund witness,
  per-request 32-byte hex nonce and schema version.

`scripts/unyt/sprint32_protocol.py` checks exact field sets, typed Holochain
hashes/checksums, SHA-256 and canonical identifiers; it emits a deterministic
SHA-256 of `hc-vtime/unyt-target-commitment/v1\0 || canonical JSON`.
A mismatch for target, agreement, DNA, rules or schedule fails. **Every
result says `target_binding_authenticated_by_current_v2=false`,
`release_authorized=false`.** This is a candidate preimage, **not signed
oracle evidence**.

**Implementation proposal for policy approval:**

1. Define a **new, separately versioned** v3 oracle statement (or independent
   purpose-specific signature domain) in which the signer actually signs the
   commitment bytes in its canonical payload alongside DNA, nonce, earliest,
   latest, oracle and durable monotonic signing-chain metadata.
2. The native verifier and **new** Rhai rules must reject the old v2
   message for target-bound purposes, authenticate the v3 commitment,
   recalculate it from **authenticated** agreement/source/target records,
   check nonce agreement across the quorum, trusted keys/DNA, and enforce
   the reviewed freshness and replay policy. Signing a digest in an unsigned
   envelope, or storing a claimed signature check result in JSON, is unsafe.
3. Review changed integrity entry/schema and DNA migration requirements,
   old signed oracle chains, deterministic witness validation, key rotation,
   per-agreement signatures, new template/rule hashes, existing parked
   deposits and carryover. **No automatic legacy transformation**.
4. After economic/security approval, add version-gated acceptance vectors
   for wrong target, wrong agreement instance/action, wrong DNA, wrong
   schedule/template, signature mutation, cross-alliance replay, old v2
   instead of v3, duplicate signer, quorum loss and replay from another
   agreement. Until then `release_wrong_target` remains issue #61 BLOCKED.

A generic-time-policy decision is also legitimate if explicitly approved:
then it must **not** claim target binding or wrong-target rejection. Both
alternatives keep signatures authenticated against their true signed fields.

## 3. Two distinct meanings of replay

| Scenario | Current status | Enforceable verification needed |
| --- | --- | --- |
| Repeat identical valid **v2 time proof** on the **same** agreement | Cryptographically repeatable; old conservative lower bound is valid history | Decide whether this is allowed/rejected for *business* idempotency. An old proof alone cannot release early under the stated fault assumption. |
| Reuse signed time proof for **different target/instance** | **Not currently bound/rejected** | If required, only genuine signed v3 context and a real verifier can bind target/instance. |
| Spend the same **Unyt parked source** in two RAVEs | Invalid economic double consumption | Native Unyt source-chain/action/spend-link validation, replay of agreement execution and independently read peer evidence. A local used-source set is insufficient globally. |
| Reuse or forge the recipient's **Accept** | Invalid payout-settlement claim | Distinct recipient-signed Accept with correct action/author, RAVE allocation, unit, amount and source lineage; independent recipient-chain read. |
| Repeat a valid RAVE's allocation with a second/incorrect recipient | Invalid settlement | Compare the native executed RAVE to every native recipient Accept and current recipient source chain. |

A receipt/status label such as `finality_verified=true`, a hash string,
or a normalized JSON record is not native Unyt authentication or proof of a
global ledger. There is no universal consensus block confirmation in the
agent-centric Unyt model.

## 4. Expiry, refunds, challenge windows, slash scope

**Release expiry is unimplemented:** proposed `freeze` or `refund
unreleased` must decide whether previously paid tranches remain final, how
pending recipient Accepts resolve, who can reclaim `locked` from a predecessor
RAVE, whether the grantor can race a beneficiary, who pays fees, and what
signed evidence establishes the deadline. A hold must not accidentally mint
a payout; a refund is a **new reviewed native allocation and Accept**, not an
accounting label. No expiry is also a possible reviewed legacy choice.

**Bond window currently differs from release expiry.** In the current
example, bond refund requires witness lower bound
`>= bond_until + challenge_period_us`. A proposed strict slash window is
`[bond_until, bond_until + challenge_period_us)` for claims after term end,
with slash possibly allowed during the earlier bond term; the boundary
`bond_until + period` is the first refund-eligible moment. Whether the
window closes slash submissions at that instant requires authenticated
native ordering and reviewed race/conflict resolution. The **current Rhai
does not enforce such a slash cutoff**; do not describe it as implemented.

The bond is not automatically insurance against a faulty Unyt payment, every
time error, operator outage or general financial fraud. Existing slash
evidence is a verified signer-specific malicious v2 statement/pair, and its
test-only 50/450 payout is limited to one independently parked 500-unit bond.
The economic reviewer must approve scope, beneficiary and multiplier before
any rule changes or funded operation. Avoid deriving a trustworthy
**before-deadline** conclusion from a stale signed lower bound: old
lower-bound evidence establishes only that time is *at least* the recorded
value, not that a submitted action was performed before a deadline.

`economic_counterfactual()` compares hypothetical expiry/refund and
bond-window boundaries and **always** marks the result unapproved,
non-authoritative and no native settlement. It never drives Rhai execution.

## 5. Test-only native Unyt RAVE + Accept validation interface

`unyt/harness/src/native32.rs` defines a `NativeUnytVerifier` trait and a
strict `review_native_evidence` structural gate with no network adapter.
A real release-matched, independently audited implementation must supply:

1. `verify_signed_rave(native_bytes)`: decode the **actual** signed native
   execution/action, authorize executor and agreement instance/rules,
   verify a replayed deterministic execution, native action hash, chain
   predecessor, consumed sources, resulting allocation and locked state.
2. `verify_recipient_accept(native_bytes)`: authenticate the **separate**
   recipient's signed action and matching RAVE allocation, unit and amount.
3. `verify_source_spend(source, rave)`: verify native parked spend/source
   lineage, one-time consumption, conflicting known RAVEs, missing/invalid
   dependencies and chain forks. Source uniqueness in one local report is
   only a necessary **offline** condition, not a proof of global absence.
4. `verify_independent_peer(rave, peer)`: a distinct peer's authenticated
   source-chain and accounting view, not a string field or same-process copy.

The structural gate rejects wrong agreement, predecessor, duplicated sources,
missing/mismatched/duplicated Accept, funds creation
(`input != accepted payouts + locked`), and missing peer checks. All
unit tests use **mock native bytes**. Its result permanently says
`production_settlement_proven=false` and
`economic_policy_approved=false` even when the mock trait checks pass.

`scripts/unyt/sprint32_protocol.py::offline_observation()` supplies a
parallel **normalized, operator-asserted** cross-check with typed Holochain
hashes, bounded exact decimals, per-payout Accept references and local
source reuse checks. It refuses invented `global_finality_verified` fields.
This is not a native signature parser.

The intentionally invalid mapping template
`integration/unyt/sprint32_native_adapter_review.example.json` requires
a **separately approved** installed Unyt release, binary SHA-256, full source
commit, installed DNA hash, real decoder source, signed/action schema and
zome calls, source-chain and peer read procedures, independent reviewers,
and explicit before/after account queries. **No generic RPC or native RAVE
wire schema has been invented.**

## 6. Installed Unyt version reconciliation

As of 10 November 2026 the public Unyt Sandbox releases page lists
**v0.114.0**, dated 20 October 2026; the exact repo's installed local
app version is **UNKNOWN**. `rave_engine =0.15.0` is pinned in the
**offline test harness only**, and must not be interpreted as a matching
installed Sandbox API. The existing Sprint 26 interface-review example
contains a **placeholder** v0.114.0 entry, not proof of installation.

External primary references:
- [Unyt documentation, RAVE and per-recipient Accept](https://unyt.co/docs/)
- [Unyt Sandbox releases](https://github.com/unytco/unyt-sandbox/releases)
- [Unyt Sandbox source](https://github.com/unytco/unyt-sandbox)
- [Unyt Smart Agreement Library](https://github.com/unytco/smart_agreement_library)

The local operator must pin `unyt.happ`/distribution SHA and installed
DNA, confirm the exact source commit, map genuine RAVE/source/Accept
types and zome calls in source, run a read-only comparison of installed
module hash and operator peer, then record the reviewed adapter in an
**external** immutable evidence directory. Even upstream documentation of
a command is not assurance that this particular installed app supports it.

## 7. Sprint 32A gates (offline only)

From a clean exact-commit checkout on a machine with Python 3.12+, the
pinned Rust toolchain and installed cached `rave_engine` dependencies:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  scripts.unyt.test_sprint32_protocol -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts/unyt -p 'test_*.py' -v
cargo test -p unyt_harness --locked
cargo fmt --all -- --check
cargo clippy -p unyt_harness --all-targets --locked -- -D warnings
bash scripts/unyt/run_sprint26.sh --expected-sha "$(git rev-parse HEAD)"
```

Test vectors: deterministic commitment and context mismatches, wrong
typed hash/DNA, malformed nonce/signature claim, separate v2-proof replay
versus double-spent Unyt source, duplicate Accept, wrong recipient/RAVE/unit,
fund conservation, unapproved policy and upper-bound time, pre-expiry/at-expiry,
bond-end and challenge-close boundaries, missing native adapter/source/peer
behavior. **All are offline contract/engine tests.** No passing mock should
be labeled native signed RAVE verification.

The Sprint 26 18-case manifest remains authoritative. Its four issue #61
cases (`release_wrong_target`, `release_replayed_proof`,
`release_expired`, `bond_challenge_within_window`) remain
`requires_network_contract`; do not relabel them `available` or
alter expected outcomes to make tests pass.

## 8. Sprint 32B — blocked local funded acceptance

**Only after explicit written policy/financial, security and testnet
operator approvals**, a separately reviewed adapter and production-rule
migration proposal: use *authorized isolated test-only units* with public
role permissions, approved spending caps and a fresh exact-SHA source/ABI
review. Never use mainnet, real monetary funds, wallet seed material or
private keys in GitHub. No background autonomous funding is authorized.

For each approved scenario: snapshot issuer and participants' canonical
pre-state, park/verify signed sources, execute via the **actual installed
Unyt app**, obtain native signed RAVE or authenticated rejection, fetch
independent peer/source-chain reads, obtain every recipient's separate
signed Accept, fetch post-state and reconcile source lineage and balances.
A rejected RAVE must not consume funds or change financial state. A
successful source may be spent once, with no fork or duplicate allocation;
verify `input_units = accepted_payout_units + locked_units` including
protocol-defined fees separately. Verify that accepted recipient
allocations are actually signed and reflected in the recipient's account.

Keep separate acceptance evidence for 100/100/100 release and
200/100/0 locked carryover, 50/450 malicious slash, 500 post-window
refund, early/unauthorized refund, forged signature, wrong DNA/target,
wrong agreement, replayed source, expired release, and in-window/
post-window challenge. Include exact installed app/adapter/DNA/commit,
sources/RAVE/Accept native bytes, both agents' signed source-chain
references, logs, timestamps plus provenance (not a trust substitute),
peer-validation output, SHA256SUMS, and independently signed review.

**No signed actual RAVE, native Accept, peer-spent-source check or money
movement has been observed by this sprint.** Sprint 32B is NOT RUN.
Issue #61 remains OPEN and production release remains NO-GO.
