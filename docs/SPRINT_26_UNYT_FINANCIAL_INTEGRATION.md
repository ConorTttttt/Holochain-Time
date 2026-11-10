# Sprint 26 — Unyt financial integration (Agent P)

**Status: GitHub/offline evidence intake only. FUNDED TESTNET NOT RUN. Financial release NO-GO.**

This sprint separates deterministic Rhai/fixture tests, native Unyt client validation, and independently reviewed financial acceptance. A fixture, adapter output, or JSON report is not a real transfer.

## Reviewed supported interface — 10 November 2026

Sources:
- https://unyt.co/docs/ (Transactions, Smart Agreements, Architecture).
- https://github.com/unytco/unyt-sandbox/blob/main/README.md (Unyt releases, alliance DNA, matching release-specific `unyt_cli`).
- https://github.com/unytco/smart_agreement_library and https://docs.rs/rave_engine (agreement templates, execution).
- In this repo: `dnas/vtime/zomes/coordinator/vtime/src/lib.rs`, `unyt/verified_time_release/execution_code.rhai`, `unyt/time_oracle_bond/execution_code.rhai`, `unyt/harness/tests/templates.rs`, `scripts/unyt/testnet.py`.

**Documented:** Unyt is an *agent-centric Holochain alliance*, not a blockchain with global consensus, blockchain confirmations, a canonical block height or universal finality. Build Panel publishes agreement templates and configured Smart Agreements. Agreement executors consume parked input and spend sources. Their execution produces a RAVE, verified by peers from signed records, inputs, code and outputs. Recipients must separately **Accept** allocated funds. Payment acceptance is not inferred from RAVE allocation alone. Multiple unrelated source chains cannot be treated as one globally ordered transaction journal.

**Not established for the target deployment:** a stable versioned general-purpose headless deployment/funding/RAVE execution/native-receipt query API, the precise field names of native receipt/Accept exports, or any universal transaction finality model. The existence of release-matched `unyt_cli` does not establish support for arbitrary commands. Sprint 26 MUST verify the actual installed app/client version and supported calls before writing a transport implementation. No imaginary RPC or CLI is used.

**PR #50 and #49:** their normalized JSON receipts/journals, finality metadata and peer attestations are *offline format and arithmetic assumptions*, not independently authenticated signed Unyt source-chain records. `scripts/unyt/testnet.py verify` is an internal consistency check only; it cannot prove valid signatures, source-chain acceptance or that a recipient accepted value. Do not merge PR #50 on the premise that `verify_receipt.py` or `verify_journal.py` demonstrates real network finality. The supported chain evidence format has to be independently reviewed against the deployed Unyt release.

## Protocol blockers found in current code

1. **Wrong target:** `unyt_time_proof()` generates a random nonce and returns only `{ statements }`; it accepts no target action. `verified_time_release` checks oracle signature, trusted DNA, robust time lower bound and spend/carryover semantics, but does *not* bind proof to a target. A wrong-target rejection is not currently supported.
2. **Replay:** the release template intentionally permits reuse of an old *signed lower time bound* because it cannot unlock early. Double consumption of an already-spent Unyt *source* is a different attack and must be validated by the native network. If “replayed proof” means a one-use proof, design an agreement/target-bound nonce, replay store, validation semantics and migrations; do not label the existing time evidence replay protection as complete.
3. **Expired release agreement:** release tranches specify unlock times, not a general agreement expiry or automatic expired-refund rule. Decide the economic policy, implement it, then test it. `time_oracle_bond` has a separate `bond_until + challenge_period_us` refund condition; this does not implement a release expiry.
4. **Recipient acceptance:** even an authorized successful RAVE is not proof of financial settlement without recipient Accept and signed source-chain/account state validation.

The 11-case `integration/unyt/sprint26_scenarios.json` matrix marks target, raw-proof replay and release expiry as `protocol_blocked`. Do not silently substitute foreign DNA for wrong target, duplicate spend for proof reuse, or bond expiry for release expiry.

## Implemented GitHub-first components

The existing `scripts/unyt/testnet.py validate` and `plan` pin public identities, isolated alliance, DNA, role bindings, a 300-unit release and a 500-unit bond, and immutable source/rules fingerprints. Existing `submit` invokes a separately reviewed, SHA-pinned **local deployment-only adapter** against an authorized Unyt application, with no funding or network confirmation claim. These remain the deployment preparation scripts; Sprint 26 does not invent a wallet API.

New `scripts/unyt/sprint26.py prepare` creates a non-overwriting, manifest-bound index of **opaque native exports**. New `audit` checks version/build pin, alliance/DNA, exact scenario set, required evidence kinds, SHA-256 integrity and path isolation. It does not parse, cryptographically validate, or interpret the native files. Its result ALWAYS has `financial_release_gate=NO_GO`; with all files present the status can reach only `READY_FOR_INDEPENDENT_NATIVE_REVIEW`, never PASS. `scripts/unyt/test_sprint26.py` provides adversarial offline unit tests. Mock bytes are explicitly not network evidence.

Required files for an accepted payout: native RAVE, underlying source records, recipient's separate Accept, separate peer revalidation, balances before and after. For a slash, require separate Accept evidence for reporter and treasury. For a rejection: native failure response, source records, peer revalidation and both balance snapshots. File/sha256 index keys are **our manifest format**, not alleged native Unyt receipt fields. A listed `independent_peer_check` does NOT prove an independent human or identity; confirm that on a separate client, with a separate authenticated source chain. Native RAVE verification, double-spend rejection, unchanged balance on failure and actual acceptance must be independently verified.

## Reproducible offline preparation

Run on an exact reviewed repository SHA, in a clean environment. The tracked testnet example intentionally fails validation until replaced with real public values *in ignored local configuration*.

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/unyt -p 'test_*.py' -v
cargo test -p unyt_harness --test templates --locked
cargo clippy -p unyt_harness --tests --locked -- -D warnings

python3 scripts/unyt/testnet.py validate --config integration/unyt/private/testnet.json
python3 scripts/unyt/testnet.py plan --config integration/unyt/private/testnet.json \
  --output-dir integration/unyt/private/plan-26
python3 scripts/unyt/sprint26.py prepare \
  --manifest integration/unyt/private/plan-26/deployment_manifest.json \
  --output integration/unyt/private/sprint26-index.json
```

Populate only version and build SHA-256 plus native file basename/SHA-256 references in the generated index. Keep raw exports locally under ignored `integration/unyt/local-evidence/`. Then:

```bash
python3 scripts/unyt/sprint26.py audit \
  --manifest integration/unyt/private/plan-26/deployment_manifest.json \
  --index integration/unyt/private/sprint26-index.json \
  --evidence-dir integration/unyt/local-evidence \
  --output integration/unyt/private/sprint26-audit.json
```

Both commands refuse to overwrite prior output. Never commit keystores, wallet/production credentials, secret inputs, funded auth, or sensitive native evidence. Never authorize funding from a GitHub/CI job.

## Authorized local funded-network acceptance (NOT executed)

1. Obtain written scope/amount/agent approval, an isolated disposable Unyt alliance, public Holochain identity and DNA bindings, exact app artifact hash, matching Unyt client, and reviewed supported native call signatures. Use the Build Panel or reviewed pinned adapter to publish the two templates and agreement rules; independently read and compare their source/role binding from a different peer before funding.
2. Use **test units only** and do not exceed the Sprint 14A **800-unit simultaneous funding** budget (300 release plus one 500 bond). A 50-unit reporter reward is paid out of the existing 500-unit bond, not extra issuance. Separate refund/slash scenarios require separate funded bond instances, with review between them.
3. Park 300 deposit and three 100 tranches. Execute signed time proofs and real RAVEs with verified source/carryover ancestry. Check exact locked 200 → 100 → 0 and recipient Accept for 100/100/100. Capture signed actions and balances on two separate peers.
4. Test forged signature and foreign-DNA no-debit rejection, duplicate spent-source rejection, early/unauthorized bond-refund rejection and invalid honest-pair slash rejection. Then prove and execute a genuine contradictory-pair slash (50 reporter + 450 treasury, separate Accepts), and post-challenge eligible refund of 500 to bonded oracle in a separate bond instance. Keep native negative responses, signed source snapshots and peer checks.
5. Fix target, one-use proof and release-expiry blockers before claiming those acceptance scenarios. A negative case passes ONLY when the real local network has independently validated the relevant action or rejection and state.
6. Require independent financial **and** security review of signers, identities, agreement code hashes, source consumption, RAVE re-execution, recipient Accept, financial conservation, challenge timing, fee behavior, errors, and restart/peer disagreement. Record exact Git SHA, versioned client, native export digest and reviewer decision.

## Acceptance state

- [x] Interface assumptions checked and undocumented receipt/finality fields excluded.
- [x] Scenario inventory, immutable artifact index and fail-closed offline test coverage prepared.
- [ ] Exact-commit full Python, Cargo, Clippy and Holochain conductor tests and CI evidence attached.
- [ ] Native API/adapter mapped and reviewed against actual installed release.
- [ ] Target binding, replay definition and release-expiry semantics repaired and tested.
- [ ] Funded local testnet executions and independently authenticated source-chain/recipient acceptance evidence gathered.
- [ ] Independent financial/security/economic sign-off.

**NO-GO remains mandatory. No production funds, credentials or mainnet interactions.**
