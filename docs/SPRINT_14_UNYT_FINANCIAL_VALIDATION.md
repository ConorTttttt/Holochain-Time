# Sprint 14 — Unyt agreement financial validation

**Status:** 14A GitHub preparation only; **14B funded testnet execution is NOT complete**.
All funds, wallet credentials, encrypted mnemonics and production secrets remain
off GitHub and outside this sprint. Do not copy wallet files into the repository,
CI, issue comments or logs. Production deployment is not authorized by this plan.

## Existing execution model and invariants

The checked-in agreement definitions are
`unyt/verified_time_release/` (vesting) and `unyt/time_oracle_bond/`
(bonding). The existing `unyt/harness/tests/templates.rs` executes the
real Rhai programs through `rave_engine 0.15.0` with Ed25519-signed Holochain
oracle statements. Existing harness coverage includes honest/faulty quorum,
multi-tranche release, oracle signature tampering, self-contradiction,
equivocation, time reversal, challenged refunds and unauthorized refunds.

Financial invariants for EVERY funded test: (1) no release before honest
quorum's proven lower time bound; (2) invalid/insufficient proofs cannot debit
funds; (3) payout + locked remainder equals the consumed deposit/bond in the
same unyt index; (4) allocations always cite actually consumed parked source
links; (5) no same source is consumed twice; (6) later tranche executions
reference the previous execution's carryover; (7) a bond resolves once into
either slashing or refund, never both; (8) authorized beneficiary/claimant rules
must be enforced by the network, not just Rhai tests.

## Offline 14A deployment preparation

The repository does **not** establish a public supported, version-pinned Unyt
deployment CLI, RPC API, finality proof schema, or wallet interface. Therefore
Sprint 14A deliberately uses an **offline agreement bundle generator**, not an
invented live deployment client. The generator checks all required Fixed inputs
and authorized roles against checked-in templates, produces concrete agreement
rules, and records SHA-256 digests for Rhai/schema files. It never signs,
broadcasts, imports keys or funds agreements.

1. Copy `config/unyt/testnet.example.json` to a **locally held** configuration
   file. Set the precise authorized network name and its independently
   verified genesis hash, real Holochain agent and DNA hashes, non-production
   denominations and small test amount; never paste secret keys. The example
   placeholders intentionally fail validation.
2. Run `python3 scripts/unyt/validate_testnet.py my-testnet.json --output
   my-deployment-plan.json`. Review both the plan and the paired
   `my-deployment-plan-agreement-rules.json` plus the five template SHA-256
   values. A valid plan means **NOT DEPLOYED**.
3. Run `python3 -m unittest discover -s scripts -p 'test_unyt_sprint14a.py' -v`,
   `cargo test -p unyt_harness --locked`, `cargo test --workspace --locked`,
   and all-targets Clippy before accepting the exact Git SHA. If CI runners are
   unavailable, run locally and retain command logs/SHA; never mark CI green
   merely because a workflow entry exists.
4. Examine `config/unyt/financial-scenarios.json` and set up independent
   expected transaction effects for **every** case before sending anything.
5. Use a versioned **authorized Unyt testnet client** only after independently
   confirming its contract for agreement definitions, parked spend inputs,
   execution, receipts, re-org/finality handling, and funding. Copy the
   rendered agreement rules (not the plan) into that client's supported
   deployment interface. Confirm roles, units, trusted DNAs, signer identities
   and executable code SHA before approving.

There is deliberately **no automatic GitHub Actions wallet deployment**.
Testnet signing, faucet requests and funded transfers require a separate local
approval step in 14B. Never set a CI secret containing a funded wallet key.

## Sprint 14B funded-testnet procedure (separate acceptance gate)

Record testnet chain ID/genesis, node implementation/version, trusted RPC,
agreement ID, template hashes, release SHA, account role authorizations and
starting balances. Create *two new* funded agreements, one for each template,
using the testnet's officially supported client and low-value test assets.
Obtain and independently archive the raw transaction/consensus evidence for
each execution, including transaction hash, source/parked balance, executor,
agreement ID, observed allocations, locked carryover, block height/hash,
finality proof, and post-state balance. Keep the raw chain evidence in an
access-controlled artifact store outside GitHub if it contains sensitive
metadata. Do not use a screenshot or an explorer's success label as sole
proof of execution.

For vesting, execute initial hold (nothing due), first due tranche, remaining
tranches with correct chained `previous_execution`, rejected premature proof,
malformed proof, duplicate oracle and wrong-DNA proof. Verify that the
unauthorized executor cannot change either schedule or receiver, and that
replayed execution cannot consume the same parked source a second time.
For bonding, execute a valid slashing proof (record the reporter reward and
beneficiary remainder), try a forged proof on a fresh bond (must not debit),
test refund during the challenge period (must fail), and refund a separate
eligible bond after distinct witness quorum shows the challenge period ended.
Attempt a second terminal operation after a slash/refund (must fail).

Write an independent expected-result JSON (not derived from the receipt
itself) and a canonical receipt JSON per transaction following
`config/unyt/receipt.schema.example.json`. Obtain a second node's
authenticated finalized receipt and archive the underlying evidence; record
its SHA-256 in a distinct chain attestation. Run:

```sh
python3 scripts/unyt/verify_receipt.py \
  receipt.json expectation.json chain-attestation.json
```

For a series of receipts, assemble a chronological journal with the
schema `hc-vtime/unyt-receipt-journal/v1` using the independently verified
transaction records, including each execution ID, predecessor ID, paid
amount, locked remainder and consumed sources. Then run
`python3 scripts/unyt/verify_journal.py journal.json`. This rejects
re-consumed parked links, broken carryover, missing predecessors and attempts
to spend after terminal release, slash or refund. It does **not** establish
ledger-wide uniqueness outside the provided journal: verify that separately
against the actual node state.

The verifier checks field whitelists, genesis, agreement/transaction identity,
explicitly expected outcome and allocations, amounts, conservation, unique
spent sources, no consumption on rejection, terminal accounting and a
separately supplied attestation claiming independent finality. **This JSON
attestation is not a cryptographic chain proof**: anyone can forge the JSON,
so an operator MUST authenticate it against the independent node's original
finality proof. Without an actual independently validated finality artifact,
the receipt remains **UNVERIFIED** even when local reconciliation passes.
Do not infer transaction success from Rhai outputs alone.

## Case matrix and acceptance criteria

| ID | Agreement | Scenario | Expected financial outcome |
| --- | --- | --- | --- |
| V1 | release | all tranches in future | 0 paid, deposit locked, no premature unlock |
| V2 | release | signed honest quorum proves tranche 1 due | first tranche paid, remainder locked |
| V3 | release | later proof and previous execution | next tranche paid, reduced carryover |
| V4 | release | all due | entire deposit paid, zero locked |
| V5 | release | altered/duplicate/wrong-DNA or insufficient quorum | no funds moved or proof explicitly rejected |
| V6 | release | unauthorized executor / replayed spent source | network rejects, balances unchanged |
| B1 | bond | signed self-contradiction/time reversal/equivocation/floor-drop | bond slashed once, reporter + beneficiary exactly bond |
| B2 | bond | honest pair/foreign DNA/forged signature | slash rejected, bond remains locked |
| B3 | bond | premature or unauthorized refund | refund rejected, bond remains locked |
| B4 | bond | eligible bonded oracle + independent witness quorum | full bond refunded once |
| B5 | bond | second slash/refund after terminal action | double consumption rejected |

**14A acceptance** requires correct-generated bundles, passing Python and Rust
tests, proper negative fixtures, and a reviewed deployment/runbook contract.
**14B acceptance** additionally requires authenticated testnet execution,
independent finality, transaction receipts, source-link checks and documented
balance deltas for each case. No 14B item may be inferred from 14A simulations.

## Limitations and security notes

No real funded agreement has been deployed here. Role and key text
validation is syntactic; ownership requires a locally authorized signing
challenge and independently verified testnet identity. Network name checks
cannot prove a network is actually a testnet; check pinned genesis using a
second trusted node. The local receipt checker enforces accounting, but does
not validate Unyt consensus or on-chain spend-link authorship. It is possible
for two individually balanced fabricated receipts to claim the same source:
the node must verify global source uniqueness and finalized chain state.

The published agreement scripts are not a substitute for the network's
authoritative asset conservation, executor or finalized spend validation. The
bond harness stubs `get_spend_links_author`; verifying this real DHT
relationship on testnet is mandatory before money is at risk.
