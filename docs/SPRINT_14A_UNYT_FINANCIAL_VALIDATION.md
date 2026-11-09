# Sprint 14A — Unyt financial correctness and funded-testnet handoff

**Status: GitHub implementation only. No deployment, wallet access, fund transfer, RAVE receipt, or actual financial acceptance is claimed.** Sprint 14B is a separate local, human-authorized funded gate.

Unyt does not offer one universal EVM-style testnet. Use a **specific isolated, disposable Unyt test alliance** with a known Holochain DNA, identities, unit index and app version. A RAVE is a signed source-chain execution record, **not** a blockchain transaction hash. The beneficiary must separately Accept incoming value. See https://unyt.co/docs/.

## Security and ownership

Only scripts/unyt/, integration/unyt/, this document and financial tests in unyt/harness/tests/templates.rs are part of Sprint 14A. Production Rhai and coordinator logic are untouched.

**Do not give GitHub agents or CI private keys, seed phrases, wallet backups, Lair keystore contents, funded credentials, access tokens, or money-moving signatures.** The checked-in example configuration contains deliberately invalid placeholders. No funding is authorized by a plan.

## Offline reproducibility: Sprint 14A

Run on a clean, exact repository SHA, recording Cargo.lock SHA-256, Rust/Python versions, logs and exit codes outside the repository:

    cargo test -p unyt_harness --test templates --locked
    cargo clippy -p unyt_harness --tests --locked -- -D warnings
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/unyt -p 'test_*.py' -v

The existing harness runs the original Rhai templates through rave_engine 0.15.0 and signs proof fixtures with **deterministic test-only Ed25519 keys**. Tests cover multi-step vesting, exact fund conservation, held/locked value, invalid schedule, wrong-DNA/duplicate/forged oracle evidence, challenge periods, slashing, and refunds. The Python suite tests receipt formatting and invariants with **synthetic mock exports only**; they are never live financial evidence.

The tracked example config MUST fail until local public bindings are provided:

    python3 scripts/unyt/testnet.py validate --config integration/unyt/testnet.example.json

## Prepare candidate deployment (still 14A)

1. Provision an isolated test alliance and disposable Holochain time DNA. Obtain public keys for grantor, beneficiary, bonded oracle, three separate witnesses, reporter and treasury. Verify public key checksums in the actual client: Python only validates shape and anti-placeholder controls.
2. Copy integration/unyt/testnet.example.json to **integration/unyt/private/testnet.json** (git-ignored). Supply only public IDs, three strictly increasing tranche unlock timestamps in Unix microseconds, and bond end/challenge-period microseconds. All times must be canonical strings less than 2^53. Use disposable test value only.
3. The example amounts intentionally stay **300** release, **500** bond, **50** reporter reward, in unit index **0**. The 800–1000 unit funding cap is an exposure cap per simultaneous funds at risk, NOT authorization to spend. Multiple independent bond scenarios require multiple separate funding operations, with value recycled only after verified settlement.
4. Validate and render immutable artifacts:

    python3 scripts/unyt/testnet.py validate --config integration/unyt/private/testnet.json
    python3 scripts/unyt/testnet.py plan --config integration/unyt/private/testnet.json --output-dir integration/unyt/private/plan-1
    sha256sum integration/unyt/private/plan-1/deployment_manifest.json

The plan contains the two rendered role-restricted agreement rules, source SHA-256 checksums of Rhai/input/output/definition files, scenario matrix fingerprint, sample three-tranche parked schedule, manifest digest, and explicit funding_authorized=false. Mutation after planning is rejected.

### Local adapter contract — optional, explicit, no fabricated API

Current Unyt documentation describes template/agreement creation through its Build Panel, rather than a stable public generic deployment CLI. scripts/unyt/testnet.py does **not** invent that API. An operator may separately install/review a LOCAL executable adapter which interacts only with an already-authorized Unyt application, without any funding operations.

Pin an approved local executable's absolute path and SHA-256 in the untracked config. Then, with explicit approval of the **exact isolated alliance ID**:

    python3 scripts/unyt/testnet.py submit --config integration/unyt/private/testnet.json --manifest integration/unyt/private/plan-1/deployment_manifest.json --output integration/unyt/private/plan-1/deployment-result.json --confirm-test-alliance '<exact alliance ID>' --ack-no-funding

The adapter receives fixed arguments in a subprocess (no shell):

    <approved local executable> deploy --manifest <absolute manifest.json> --output <absolute result.json>

It must write a JSON result with schema hc-vtime/unyt-deployment-result/v1, matching network_id, and two maps named template_action_hashes and agreement_action_hashes, each containing real Holochain action hashes for verified_time_release and time_oracle_bond. This output is **self-reported**, not independent network confirmation. Independently read both deployed code templates and configured agreement role rules on a second Unyt peer before accepting deployment.

## Sprint 14B: only with local authorized test credentials

1. Obtain explicit human approval, confirm test-only alliance and participants, review all template hashes and trusted oracle/DNA bindings; separately record initial account balances and parked input sources. No production/funded credentials go into GitHub.
2. Deploy or confirm the two agreement templates on the isolated alliance. Fund a 300-unit grantor deposit and park a schedule of three 100-unit tranches. Fund one 500-unit bond at a time in **separate agreement instances** for each slash/refund scenario; do not exceed the documented simultaneous test-unit cap.
3. Produce authentic signed Holochain oracle statements from permitted network/oracles, execute release_first, release_second and release_final at the appropriate times, and confirm *each* signed RAVE, source and previous_execution link. Expect payouts 100/100/100, locked 200/100/0. Verify beneficiary's separate Accept records. Re-execution after full release must fail.
4. Execute valid signed time-reversal and equivocation slashes on separate bonds: reporter receives 50 and treasury 450. On a different legitimate bond, refund 500 exclusively to the bonded oracle once independently proven time passes bond_until + challenge_period_us. Verify spent-bond double-claim rejection and subsequent acceptance records.
5. Run each negative case in integration/unyt/scenarios.json: forged signatures, duplicated oracle, foreign DNA, deposit/schedule mismatch, early or unauthorized refund, forged slash, honest (non-slashable) pair. Preserve exact errors plus before/after canonical state snapshots, no accepted RAVE or allocations.
6. Collect actual Holochain action records and native Unyt client exports, signer identities, network/DNA and version hashes, parked sources, previous RAVE, transaction Accept records, and a separate peer's revalidation. Record all artifact SHA-256 values and exact Git SHA. Consider fees and transactions outside the defined agreement outputs separately.
7. Require independent financial review of conservation, signer/source authorization, rejection, one-time consumption, recipient acceptance, network/DNA isolation, and code fingerprints before declaring the 14B gate green.

## Receipt audit contract

The command below checks an operator-normalized JSON report against every defined scenario:

    python3 scripts/unyt/testnet.py verify --manifest integration/unyt/private/plan-1/deployment_manifest.json --receipts /local/evidence/receipts.json --evidence-dir /local/evidence/exports

Receipt report top-level fields: schema=hc-vtime/unyt-testnet-receipts/v1, network_id, manifest_sha256, records=[...]. Each record must contain: scenario_id, agreement, agreement_instance_id, status, peer_verdict, unit_index, rave_action_hash (null on rejection), previous_rave_action_hash (null on first), and payouts=[{recipient,unit_index,amount_units}]. Accepted records additionally have input_units, locked_units and outcome.

For every scenario, provide two SHA-256 pinned files **under the designated local evidence directory**, named by the record's client_export_file/client_export_sha256 and peer_check_file/peer_check_sha256.

Client export normalized JSON must have schema hc-vtime/unyt-client-export/v1, network_id, scenario_id, status, rave_action_hash. Peer recheck normalized JSON must have schema hc-vtime/unyt-peer-check/v1, network_id, scenario_id, rave_action_hash, client_export_sha256, verdict and peer_agent public key. The operator must preserve the original native signed exports outside those normalized envelopes.

For rejected records, also provide pre_state_file/pre_state_sha256 and post_state_file/post_state_sha256, representing *byte-identical* normalized parked-balance snapshots before and after the attempt. The second synced peer must independently establish there was no valid payout; the offline tool cannot prove a global absence of DHT records.

The checker insists on the complete **14-scenario matrix**, exact recipients and amounts, conservation (payouts + locked = consumed), unique RAVE hashes, correct release-chain predecessor and agreement-instance continuity, and a bond instance resolving at most once.

### Never misinterpret receipt output

The Python checker only validates file checksums, normalized export consistency and financial arithmetic. It **cannot** authenticate RAVE Ed25519 signatures, attest to an independent peer from a JSON claim, establish global evidence completeness, prove source-chain acceptance or confirm actual value transfers. A synthetically constructed JSON report can pass structural validation. Unyt/Holochain validation on the authorized actual test alliance, plus third-party review of signed native action/Accept records, is mandatory for 14B.

## Merge and acceptance gates

- [ ] 14A: exact-commit native cargo tests/clippy and Python unit suite pass with retained logs.
- [ ] 14A: placeholders/unsafe alliance, role/budget changes, edited scripts/rules and tampered mock receipts fail closed.
- [ ] 14A: signed-fixture tests demonstrate 300=100+100+100 and 500=50+450 without paying invalid proofs.
- [ ] 14A: code/security review, no keys/secrets or funded credentials committed.
- [ ] 14B: actual funded execution on an isolated alliance, successful and negative signed records, independent peer/Accept/financial review. **Not satisfied by 14A.**
