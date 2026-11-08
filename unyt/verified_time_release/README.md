# Verified Time Release

Releases a locked deposit in tranches, each unlocking at a Unix time, where "now" is **proven by
signatures from several Holochain time oracles** instead of claimed by one attestor. It is the
library's `time_locked_vesting` pattern with its single trust point removed.

This is an **example template**: its agreement lives in `agreements/example_agreement_rules_1.json`
and is never instantiated automatically. Replace every placeholder key before use.

## Where "now" comes from

Rhai has no clock, and must not: every peer re-runs the code later and must agree. So time arrives
as data. The `time_prover` role parks the output of the hc-vtime coordinator zome's
`unyt_time_proof()`:

```json
{
  "statements": [
    {
      "statement": {
        "dna": "uhC0k... (the hc-vtime network that signed it)",
        "domain": "hc-vtime/oracle-statement/v2",
        "earliest": "1792000000000000",
        "floor": "<largest earliest signed before on this chain, or empty at seq 0>",
        "latest": "1792000002000000",
        "nonce": "<64 hex characters>",
        "oracle": "uhCAk...",
        "prev": "<hex of this oracle's previous signature, or empty>",
        "seq": "41"
      },
      "signature": [12, 201, "... 64 integers ..."]
    }
  ]
}
```

Each entry is judged on its own. It counts only if:

- its oracle is in the fixed `oracle_keys` list and its `dna` is in `oracle_dnas`;
- its fields are canonical (decimals as hc-vtime signs them, `prev` and `floor` empty exactly at
  seq 0);
- it is not below its own chain's floor (such a statement is a confession, not evidence);
- `hdi_verify_signature(oracle, signature, statement)` holds;
- that oracle has not already been counted.

An entry that fails any check is **skipped, not fatal**, so up to f faulty oracles cannot block a
release the honest ones support. At most 32 entries are examined. Listing the DNAs matters for
accountability: every statement that counts sits on a chain the oracle's `time_oracle_bond`
covers, so an oracle cannot sign lies under an invented network that no proof can tie to its real
chain. A
statement signed at true time *t* says *t* ≥ `earliest`, and time only moves forward, so the
statement stays a valid lower bound on "now" forever. Replaying an old proof can only understate
the time; it can never release a tranche early.

With at most `max_faulty` (f) lying oracles, the code takes the **(f+1)-th largest `earliest`**.
At least one of the f+1 largest values comes from an honest oracle, so f liars cannot move the
bound forward. A tranche is released when its `unlock_time` is at or below that bound.

## Participants

| Role | Parks | Who should hold it |
| --- | --- | --- |
| `grantor_spender` | `ParkedSpendBalance`, the full deposit | The grantor |
| `grantor` | `ParkedData`, the schedule | The grantor |
| `time_prover` | `ParkedData`, a time proof, consumed every run | The beneficiary in the example; see below |

Only the latest parked proof is read. Because the signatures carry the trust, opening `time_prover`
to `Any` is safe for correctness, but then anyone can park a later, malformed proof and make the next
execution fail until a good one is parked again. The example restricts it to the beneficiary.

Executor: `AuthorizedExecutor`, the beneficiary in the example. Required, because the template can
emit `locked`, and `previous_execution` (which carries the lock) is derived from the executor's
own chain.

## Inputs

| Name | Instruction | Shape |
| --- | --- | --- |
| `deposit` | `ProvidedBy: grantor_spender` | `{ amount: unit map, source }`, first run only |
| `schedule` | `ProvidedBy: grantor` | `{ unyt_index, receiver, tranches: [{ unlock_time, amount }] }`, first run only |
| `time_proof` | `ProvidedBy: time_prover` | see above |
| `oracle_keys` | `Fixed` | array of `AgentPubKeyB64` strings |
| `oracle_dnas` | `Fixed` | array of `DnaHashB64` strings: the hc-vtime networks whose statements count |
| `max_faulty` | `Fixed` | integer f |
| `min_oracles` | `Fixed` | integer, at least f + 1 |
| `previous_execution` | `Custom: GetPreviousExecution` | `{ id, output }` or absent |

`unlock_time` and every statement time are **Unix microseconds** as decimal strings. Values stay
below 2^53, so Rhai's `to_num` (an f64) compares them exactly.

## Code execution flow

1. First run: read the deposit and schedule, check every tranche has string fields, and check the
   tranches sum exactly to the deposit. Later runs: restore and type-check `carryover`, and name the
   previous execution as the source of the carried lock.
2. Judge each time-proof entry, skipping invalid ones, and compute the robust lower bound on "now"
   from the valid ones (it throws only if fewer than `min_oracles` remain).
3. Release every tranche with `unlock_time` ≤ the bound; keep the rest.
4. Pay the released total, or on the first run with nothing due, hold the deposit with an
   empty-amounts allocation (never a zero amount).
5. Carry the remainder forward as `locked` + `carryover`.
6. Record the bound, the number of oracles counted and the amounts in `computed_values`.

## Output structure

- `unyt_allocation`: the payout to `receiver`, or a hold on the first run.
- `locked` and `carryover`: only while tranches remain.
- `computed_values`: `unyt_index`, `receiver`, `proven_time_lower_bound_us`, `oracles_counted`,
  `released_this_execution`, `remaining_locked`, `tranches_remaining`, `fully_released`.

## Trust assumptions and open questions

- **Oracle honesty is bounded, not assumed.** Up to `max_faulty` listed oracles may lie. Pair this
  template with `time_oracle_bond` so a lying oracle also loses money.
- **Signature encoding.** The oracle signs Holochain's MessagePack encoding of the statement
  (`rmp_serde` with struct maps, fields in alphabetical order, all strings). `hdi_verify_signature`
  turns the Rhai map back into JSON and encodes it through HDI, which gives the same bytes. The
  hc-vtime harness (`unyt/harness`) runs this template through the published `rave_engine` 0.15.0
  with real Ed25519 signatures and confirms honest statements verify, altered ones are skipped,
  and a 40-entry proof stays within the engine's operation budget. The
  Unyt DNA's own rules (conservation, executor checks) are not public, so still run one execution
  on your network before moving real value.
- **Oracle keys are fixed per agreement.** Rotating oracles means a new agreement instance.
