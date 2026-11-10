# Sprint 26 — Unyt Financial Integration

**Agent P — Financial agreement engineering. Priority: CRITICAL.**  
**Started:** 10 November 2026. **Status:** GitHub-first code,
independent signature checks, offline agreement preparation and native
evidence reconciliation implemented; funded testnet **NOT RUN**.
**Release:** NO-GO.

## Scope and ownership

This branch extends the merged Sprint 14A preparation code without
altering the production Unyt Rhai agreement templates or Holochain
coordinator/cryptographic verifier. Its first dependency is confirmed
Unyt native schema and deployment API, **not** a guessed HTTP/REST
contract.

## Deliverables

| User deliverable | Implementation | Current limit |
| --- | --- | --- |
| 1. Reviewed Unyt contract | `docs/unyt/SPRINT26_INTERFACES.md` and pinned, fail-closed `sprint26_interface.example.json` | Installed app API/source still needs operator review |
| 2. Agreement deployment | Existing `scripts/unyt/testnet.py plan/submit` used by new Sprint 26 `prepare`; approved Build Panel or local pinned adapter only | No generic Unyt native CLI verified; nothing deployed |
| 3. Testnet validation | Reuse Sprint 14A strict isolated alliance, test funds, trusted roles/DNA and file digests; pin actual Unyt release and distribution | Public-role config does not authenticate live network |
| 4. Signed evidence submission | `scripts/unyt/sprint26_proof.py` checks canonical v2 genuine Ed25519; `sprint26.py stage-proof` prepares exact Rhai `time_proof` / `claim` shape | Does not actually park/submit; target binding missing |
| 5. Valid payouts | Existing rave_engine Rust fixtures + new explicit accepted native RAVE/Accept/artifact requirements | Funded payouts not run |
| 6. Invalid proofs | Independent forged/wrong-DNA/duplicate oracle tests; 18-scenario matrix; rejection must preserve accounting | Native peer rejection not observed |
| 7. Refund/challenge | Signed witness quorum checks after challenge end; slash claim preflight | Native in-window challenge still needs API contract |
| 8. Bond/slash | Signed genuine equivocation/reversal proof checks, reporter/treasury 50/450 validation | No funded bond/slash transactions |
| 9. State transitions | Off-chain unique source, one-time bond resolution, linked RAVE, payout conservation, zero-spend rejection and separate Accept evidence | No native signatures/DHT state verified |
| 10. Transaction report | Exact-SHA runner, no-wallet offline audit and `sprint26.py audit` with SHA-linked native files | Always explicitly **OFFLINE ONLY** |

## Four blocking protocol mismatches

The current release agreement validates v2 signatures and signed time
lower bounds but does **not** bind `unyt_time_proof()`'s random nonce to
a particular Unyt target. Old valid proofs remain conservative evidence
rather than guaranteed rejected replay. The release script does not
define full target-specific expiry. Bond in-window challenge handling
needs native contract confirmation. These cases are marked
`requires_network_contract` in the matrix and **cannot satisfy
Sprint 26 acceptance without a reviewed policy/code migration**.

Review against the latest pinned Unyt client/Build Panel before changing
Rhai. The alternate PR #50's 64-hex `tx_hash` and JSON
`finality_verified=true` are **not confirmed Unyt native fields**.

## Local Codex gates

1. Python Ed25519/msgpack dependencies installed in a temporary venv.
2. Offline Python, pinned Rust rave_engine harness, workspace and Clippy
   pass with exact clean SHA; retain source-pinned checksummed logs.
3. Independent peer verifies actually deployed rules/DNA against source
   SHA and approved test operator identities.
4. Operators with disposable **authorized testnet units only** carry out
   the payout, forged/DNA/target/replay, expiry, refund, challenge,
   slash and invalid-slash scenarios on an isolated alliance.
5. Collect actual signer, source, RAVE, separate recipient Accept,
   before/after financial state and distinct peer action bytes; run
   offline reconciliation **then** a separately reviewed native Unyt
   verifier. The offline audit cannot establish native acceptance.
6. Have security and economic reviewers audit source-code validation,
   source uniqueness, acceptance, fees, payouts and requested migration.

**No funded credentials, transactions, mainnet or EVM bridge actions
belong in this PR, GitHub Actions or automated chat tools.** Until all
native and economic gates pass, keep **DRAFT / NO-GO**.

See `docs/unyt/SPRINT26_RUNBOOK.md` and
`docs/unyt/SPRINT26_RESULTS.md`.
