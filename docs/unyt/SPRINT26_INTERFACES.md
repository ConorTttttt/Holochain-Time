# Sprint 26 — Reviewed Unyt native interfaces and evidence model

**Agent P. Priority CRITICAL. Status: source review completed, native interface
mapping and testnet confirmation still outstanding. No funded testnet evidence.**

## 1. Verified from upstream sources (10 November 2026)

The public [Unyt documentation](https://unyt.co/docs/) and
[Unyt Sandbox](https://github.com/unytco/unyt-sandbox) describe a
peer-to-peer **accounting alliance**, not a universal EVM-style testnet.
Each participant signs their own source chain and independently validates
other participants' actions. A Smart Agreement consists of a Rhai code
template, configured agreement/input rules, and an executed **RAVE
(Recorded Agreement Verifiably Executed)**. A payout recipient must separately
**Accept** the allocation on their own account/agent chain. There is **no
global blockchain block height, transaction finality or single consensus
receipt** to query.

The [Unyt Sandbox v0.114.0 release](https://github.com/unytco/unyt-sandbox/releases/tag/v0.114.0)
is the most recent public release found at review time (released
20 October 2026). This **does not** establish the installed version
on the user's isolated alliance. Pin the actual app release, distribution
SHA-256 and upstream source commit in an external review record.

The [Smart Agreement Code Library](https://github.com/unytco/smart_agreement_library)
documents the Rhai template/rules architecture and RAVE engine. The
repository's existing Rust offline harness pins `rave_engine =0.15.0`.
An engine version does **not** imply binary/API compatibility with the
latest Unyt Sandbox app or an operator's installed alliance.

**Not confirmed:** a stable, documented general-purpose Unyt deployment
or transaction submission RPC/CLI, exact installed zome names/functions,
native RAVE record layout for that app build, authoritative balance query,
signed peer-validation export format, and how a rejected RAVE is reported
on that exact installed client. The program does not fabricate any of these.
A local authorized operator must inspect the actual Holochain/Unyt app
version and its published integration surfaces before implementing the
read/write adapter.

## 2. What this repository does know (separate from upstream)

Existing `scripts/unyt/testnet.py` in merged Sprint 14A checks an
**isolated-test-alliance** config, eight public agent roles, distinct oracle
keys, test-unit index 0, exact 300-unit release deposit, 500-unit bond and
50-unit reporter reward, challenge timing and pinned template/rules file
hashes. It can render a plan, and optionally call a **separately reviewed,
SHA-pinned local adapter** with its own `deploy` wrapper protocol. That
`deploy` subcommand is **our local adapter contract**, not a documented
Unyt native command. It never funds accounts.

`unyt/verified_time_release/execution_code.rhai` and
`unyt/time_oracle_bond/execution_code.rhai` consume the **v2**
`UnytTimeProof` and `claim` Rhai-shaped data. The coordinator's
`unyt_time_proof()` generates a random nonce shared by freshly gathered
statements, signs canonical v2 fields, and returns
`{"statements":[{"statement":{...},"signature":[64 integer bytes]},...]}`.

The v2 signature domain is `hc-vtime/oracle-statement/v2` with fixed
canonical named-MessagePack fields in order:
`dna, domain, earliest, floor, latest, nonce, oracle, prev, seq`.
`scripts/unyt/sprint26_proof.py` performs independently implemented
Ed25519 verification against the canonical Holochain key/DNA checksum
and a caller-specified allowlist. This preflight establishes **only
cryptographic evidence authenticity**; it cannot establish that Unyt
actually consumed it.

### CRITICAL contract gaps that block full Sprint 26 acceptance

1. **Wrong target:** the existing `unyt_time_proof()` random nonce
   is not a signature over the Unyt agreement instance or the intended
   RAVE/parked source. The Rhai release template checks the DNA and
   oracle key but **not agreement-target binding**. Rejecting the
   `release_wrong_target` scenario cannot be claimed.
2. **Proof replay:** the release template intentionally treats an old
   valid signature as a permanently valid conservative `earliest`
   lower bound. Reusing it may cause a *hold* or later payout based on
   the same lower bound. The app must establish source/previous-execution
   one-time-consumption independently. **It is incorrect to assert that
   every reused oracle proof is rejected** without a reviewed change
   to protocol semantics and target-specific replay state.
3. **Expiration:** `verified_time_release` uses tranche unlock times,
   not a separately authenticated global agreement expiry guarantee.
   Sprint 26 needs an explicit expiry policy and peer-validated behavior.
4. **Challenge:** `time_oracle_bond` supports signed malicious behavior
   claims and a `bond_until + challenge_period_us` refund guard.
   A new `bond_challenge_within_window` end-to-end network scenario
   still needs a reviewed source/input and lifecycle definition.

The Sprint 26 scenario matrix marks these as
`requires_network_contract`. **Do not change them to `available`
to manufacture passing test results.** Coordinate a separately reviewed
Rhai/input migration (including agreement template hashes, existing
parked-data compatibility and any Holochain DNA consequences) before
claiming all eight required scenarios.

## 3. Sprint 26 adapter boundary, not an invented Unyt API

`integration/unyt/sprint26_interface.example.json` is a **nondeployable
provenance template**. Operators must independently review installed
Unyt source/binary and then provide the exact release tag, app binary
hash, full source commit, alliance ID, public reviewer ID and whether
the interface is the Build Panel or a pinned local wrapper.

**Our normalized evidence export is not the native Unyt schema.** Each
`*.event.json` is a local reviewer index identifying:

- the actual externally read agreement and RAVE action IDs (only for
  accepted executions);
- native bytes of the agreement, RAVE/failed execution, parked signed
  proof, before/after canonical **accounting projection** and a distinct
  observer's native verification (all referenced by SHA-256);
- each positive allocation's distinct recipient **Accept** action plus
  raw native Accept bytes and SHA-256;
- the referenced input sources, preceding RAVE and agreement instance,
  so a consumer can detect local duplicates and cross-run inconsistencies.

The JSON `outcome`, `rave_action_hash`, `peer_agent`, `input_units`,
`payouts` and `locked_units` are **operator-normalized assertions**.
They are not claims that Unyt exposes these exact field names.
`sprint26.py audit` checks their consistency and referenced file
fingerprints only. For rejected operations, pre/post accounting
projections must be byte-identical (exclude log timestamps, observation
metadata, nonfinancial gossip state). It does **not** verify native Unyt
signatures, DHT authority correctness, accepted network state, global
absence of a spend, or recipient Accept signatures.

A production acceptance tool must implement a separately audited native
decoder/validator for the *actual installed* Unyt app release, from
supported source/API calls, then have a distinct peer repeat the
authenticity and state-transition checks. Do not mint self-signed
`"finality": true` or external-attestation fields to satisfy the gate.

## 4. Review of alternative PR #50

The alternate Sprint 14A PR #50 assumes a normalized
client/peer receipt, and may assume verifiable journal/finality fields.
A reviewer must first map every asserted field to a documented
**native entry, action, signature or independently readable app state**
of the specific pinned Unyt version. Claims derived solely from JSON
attestations or hashes are insufficient. Prefer the merged Sprint 14A
manifest / engine test fixture coverage as offline inputs, without
merging incompatible alternative receipt schemas into live acceptance.

## 5. Review checklist before any authorized test funds

- [ ] Record independently verified alliance and application DNA, installed
      Unyt app build and exact distribution/source SHA.
- [ ] Review actual native template registration, agreement creation,
      parked-source, execution, RAVE, Accept, rejection, refund and warrant
      APIs for that app build and the native schema/code paths.
- [ ] Verify template/Rhai and **deployed** agreement rules from a second
      independently operated Unyt peer, including oracle allowlist and DNA.
- [ ] Document a real host-side native verifier for signature and hash
      linkage, peer validation and accounting state queries.
- [ ] Approve any target/replay/expiry/challenge protocol migration with
      security and economics reviewers.
- [ ] Approve isolated test-unit budget, local roles, non-mainnet routes,
      failure abort plan and independent financial reviewer.
- [ ] Keep all credentials, Lair files, auth tokens, funded amounts and
      actual execution logs in an operator-controlled, git-ignored external
      directory, never in GitHub or ChatGPT.

**Decision:** Native interface review and full financial network acceptance
are **BLOCKED** pending the verified installed API and these four contract
gaps. Offline preparation is allowed; funded submission is out of scope
for this GitHub branch.
