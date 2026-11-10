# Sprint 26 — Unyt authorized testnet runbook

**Agent P. Critical priority. Current phase: GitHub-first preparation only.**
No network calls, financial credentials or funded execution have occurred.
The local operator must carry out actual test-unit deployment and settlement
only after reviewing [INTERFACES.md](INTERFACES.md).

## GitHub-first offline validation (no credentials)

Use a clean checkout at this PR's exact SHA with Rust/Holochain's pinned
workspace toolchain and Python 3.11+. To run independently verified v2
Ed25519 tests, set up a *local virtual environment*:

```bash
python3 -m venv /tmp/hc-vtime-s26-venv
. /tmp/hc-vtime-s26-venv/bin/activate
python3 -m pip install 'msgpack==1.1.2' 'cryptography==46.0.4'
SHA="$(git rev-parse HEAD)"
bash scripts/unyt/run_sprint26.sh --expected-sha "$SHA"
```

The runner records tool versions, package checks, Python fixture tests
(including independent signed Ed25519 vectors), full Rust rave_engine
financial fixture tests, workspace tests, formatting/Clippy and an
**offline-only** SHA-pinned audit report outside the checkout.
`OFFLINE_SUITE_PASS_NO_FUNDED_UNYT_EVIDENCE` never grants release.

## 1. Provision isolated, operator-controlled Unyt alliance

With approved disposable testnet identities only, obtain the installed
Unyt application version and verify its upstream hash/source. The public
Sandbox's latest release observed in this research was
[v0.114.0](https://github.com/unytco/unyt-sandbox/releases/tag/v0.114.0)
(20 October 2026). Choose and **pin what is actually installed**, not
automatically the newest version.

Copy placeholder configs to an **external private directory** (outside
Git, ideally separate volume); replace *only public identifiers* in the
checked-in example. A locked deployment manifest contains:
release deposit 300 test units, separate bonded-oracle bond 500 test
units, reporter reward 50 test units, at most 800 simultaneous
test units at risk (the cap is **not authorization to fund**), zero
Unyt transaction fees if verified/configured locally, exact roles/DNA
and the three 100-unit unlock times. Example templates are intentionally
not deployable.

```bash
python3 scripts/unyt/testnet.py validate \
  --config /outside-repo/private/unyt-testnet.json

python3 scripts/unyt/sprint26.py prepare \
  --config /outside-repo/private/unyt-testnet.json \
  --interface-review /outside-repo/private/unyt-interface-review.json \
  --expected-sha "$SHA" \
  --output-dir /outside-repo/private/sprint26-stage-1
```

The interface-review file must pin the actual client release, distribution
digest, reviewed source commit, isolated alliance and native query
strategy; see `integration/unyt/sprint26_interface.example.json`.
The stage output contains immutable rendered agreement rules,
the template/input/output/Rhai hashes and `sprint26_session.json`.
It records `financial_execution_authorized=false` and that no
submission occurred.

## 2. Agreement deployment — NO invented Unyt RPC

Unyt's public documentation describes creating templates and agreements
in the Build Panel; no generic public deployment API was verified.
An authorized operator may use Build Panel with stage-rendered
`verified_time_release` and `time_oracle_bond` rules.

Alternatively, reuse the **existing** strict Sprint 14A local deploy
wrapper if an operator independently implements, reviews and pins a
compatible local adapter. That adapter's `deploy` command is a
project-defined interface, **NOT an Unyt native command**:

```bash
python3 scripts/unyt/testnet.py submit \
  --config /outside-repo/private/unyt-testnet.json \
  --manifest /outside-repo/private/sprint26-stage-1/agreements/deployment_manifest.json \
  --output /outside-repo/private/sprint26-stage-1/deployment-result.json \
  --confirm-test-alliance '<exact isolated alliance ID>' \
  --ack-no-funding
```

This wrapper does **not fund** and its own output proves only what the
adapter reported. Query deployed agreement and template hashes, role
bindings, Rhai code, input sources and relevant DNA from **a second
Unyt peer** before authorizing any test-unit funding.

## 3. Signed Holochain Time proof → staged Unyt input

Use an actual signed `unyt_time_proof()` response from the approved
Holochain Time DNA; this includes multiple `OracleTimeStatement` v2
signatures with one shared request nonce. The normal release shape is:

```json
{"statements":[{"statement":{"dna":"...","domain":"hc-vtime/oracle-statement/v2",
"earliest":"...","floor":"","latest":"...","nonce":"...",
"oracle":"...","prev":"","seq":"0"},"signature":[0,1]}]}
```

The two-byte signature above is **illustrative and deliberately invalid**.
Real signatures are exactly 64 integer bytes and are checked by
`sprint26_proof.py` using genuine Ed25519 and Holochain hash checks.

```bash
python3 scripts/unyt/sprint26_proof.py \
  --proof /outside-repo/private/signed-proof.json \
  --dna '<approved vtime DNA>' \
  --oracle '<approved oracle 1>' --oracle '<approved oracle 2>'

python3 scripts/unyt/sprint26.py stage-proof \
  --config /outside-repo/private/unyt-testnet.json \
  --scenario release_first \
  --proof /outside-repo/private/signed-proof.json \
  --output /outside-repo/private/release-first-parked.json
```

The staged payload preserves the existing Rhai input rule `time_proof`
or `claim`, but **does not park it**. Submit it manually via the
reviewed Unyt app/client/parked-data route, checking the actual native
entry and signer. The random v2 nonce is **not agreement-target bound**;
therefore the staged file reports `network_target_authenticated=false`.
No accepted financial conclusion can be drawn from this alone.

For valid refund, use `{"kind":"refund","time_proof":{"statements":[...]}}`
with three distinct witness-oracle public keys (min quorum 2, f=1).
The signed lower bound must be at or after
`bond_until_us+challenge_period_us`. For a slash claim, use
`{"kind":"slash","a":<signed-v2-entry>,"b":<signed-v2-entry>}`
with two genuinely signed contradictory statements. The gate proves
Ed25519 and signed malfeasance consistency, not network slashing.

## 4. Authorized local funded testnet acceptance

Only after explicit human approval for **test units**:
park the 300-unit release grant and matching tranche schedule;
separately park one 500-unit bond per slash/refund instance, never
exceeding the approved simultaneous 800-unit cap. Use isolated
oracles, grantor/beneficiary, reporter and treasury. No mainnet, funded
live alliance, real credentials, EVM or bridge transactions.

Execute each scenario in `integration/unyt/sprint26_scenarios.json`
using the **actual approved Unyt API/UI**, with true source-chain
records and independent peer validation. Expected positive outcomes:
100/100/100 tranche payouts with locks 200/100/0;
50 reporter plus 450 treasury on proven slash (each separate bond);
500 refunded only after the challenge period on another bond.
Each payee must separately **Accept** and the native Accept action
must be recorded. A RAVE alone is not final recipient settlement.

Every forged/wrong-DNA/duplicate-oracle/early-refund/unauthorized
refund/invalid-slashing scenario must be rejected with unchanged
canonical financial state, no RAVE accepted, and no source consumed.
The wrong-target, old-proof replay, agreement expiry and in-window
challenge scenarios are **explicit protocol blockers** until reviewers
agree what the deployed templates actually enforce and implement any
necessary migration. Do not mark them as `available` to force a PASS.

For every scenario preserve actual source-chain records, RAVE if
accepted, native proof bytes, native recipient Accept, exact spend
sources, observed previous RAVE, before/after balance snapshots
excluding timestamp metadata, local client logs and a second peer's
native verified records. No credentials or private keys belong in
the report.

## 5. External evidence and independent review

Copy the **invalid example only as a schema guide** from
`integration/unyt/sprint26_event.example.json`; fill an
`<scenario_id>.event.json` for **every** planned scenario, with
hash-linked opaque native files *from the actual installed client*.
Every native file must be nonempty, <=4 MiB and SHA-256 pinned. A
successful payout additionally requires a separate referenced
recipient Accept action **and its raw native bytes**.

```bash
python3 scripts/unyt/sprint26.py audit \
  --session /outside-repo/private/sprint26-stage-1/sprint26_session.json \
  --config /outside-repo/private/unyt-testnet.json \
  --evidence-dir /outside-repo/private/native-evidence-1 \
  > /outside-repo/private/native-evidence-1/reconciliation.json
```

`audit` verifies pinned agreements, native-file hashes, Ed25519-signed
payout/refund/slash proof preflight, duplicate spent-source/RAVE/Accept
ids, exact role payments, lock conservation, linked tranche history,
and rejection-no-debit canonical before/after comparisons.
**A successful audit result is OFFLINE_RECONCILIATION_ONLY**, because
it cannot prove those native records genuinely came from the Unyt
network or that a peer verified them.

A truly accepted testnet trial requires a **separately implemented,
source-reviewed native Unyt verifier**, matching app/DNA version and
schema, to authenticate native signatures, action hashes, spent
sources, RAVE output, agreement code identity, DHT validation and
every beneficiary's Accept. An independent peer must reproduce
these checks and the initial/final account state; then independent
security and economic reviewers must sign off. Neither the audit
JSON nor a shared client read is independent consensus finality.

## Acceptance tracker

See `RESULTS.md`. Without full native adapter/source review, live
funded execution and independent financial approval, Sprint 26
remains **NOT ACCEPTED** and release **NO-GO**.
