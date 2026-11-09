# Time Oracle Bond

A bond posted by one hc-vtime time oracle. Anyone holding statements the oracle signed that prove
it lied can claim a reward from it; the rest goes to a fixed beneficiary. If the oracle stays honest
through the bond term and a challenge period after it, it reclaims the bond with a time proof from
other oracles.

This is an **example template**: `agreements/example_agreement_rules_1.json` is never instantiated
automatically. Replace every placeholder before use.

## Why this works without a judge

hc-vtime oracles keep one statement chain per network (statement format v2). Each statement names
its network in `dna`. `seq` goes up by one, `prev` carries the hex of the previous signature, and
`floor` carries the largest `earliest` signed before on that chain. Four kinds of lie are then
self-evident from the oracle's own signatures:

- **Self-contradiction** (one statement). `latest < floor`: the statement says the time is at most
  `latest`, but the oracle's own chain already showed the time reached `floor`.
- **Time reversal** (two). `b.prev` is the signature of `a`, so `b` was signed after `a` existed.
  If `b.latest < a.earliest`, then t_b ≤ b.latest < a.earliest ≤ t_a < t_b, which is impossible.
- **Floor dropped** (two). `b` chains after `a` but `b.floor < max(a.floor, a.earliest)`.
- **Equivocation** (two). Different statements with the same `dna`, `seq` and `prev`: the oracle
  forked its chain in one network.

Together these make any backwards movement of the oracle's clock provable from at most two
statements, however gradually it is done. Without `floor`, a clock walked back by up to twice the
radius per statement left every adjacent pair consistent.

Equivocation requires the same `dna` because one agent key may honestly serve several networks
(a DNA upgrade, a clone cell, another hApp), each with its own chain starting at seq 0. The other
three proofs are contradictions inside a single chain, so they are accepted from any network: an
honest oracle never signs them anywhere.

The hc-vtime coordinator refuses to sign below its floor and logs every statement in the same
atomic commit that produces it, so an honest oracle running the reference code never creates any of
these proofs. A compromised key or a modified oracle does. An operator must never run two cells of
one DNA with one key; Holochain treats that as a chain fork too.

## Participants

| Role | Parks | Holder |
| --- | --- | --- |
| `bond_oracle_spender` | `ParkedSpendBalance`, the bond | The bonded oracle only (`Authorized`) |

The id contains `oracle` and `spender`, so the app treats it as a spend-parking send action.

Executor: `Any`. A reporter executes with `kind: "slash"`; the oracle executes with
`kind: "refund"`. No `locked` output is produced, so `Any` is safe.

## Inputs

| Name | Instruction | Meaning |
| --- | --- | --- |
| `bond` | `ProvidedBy: bond_oracle_spender` | The bond, `{ amount, source }` |
| `bonded_oracle` | `Fixed` | The oracle's `AgentPubKeyB64` |
| `unyt_index` | `Fixed` | Unit of the bond |
| `reporter_reward` | `Fixed` | Amount paid to a successful reporter, at most the bond |
| `slash_beneficiary` | `Fixed` | Receives the rest of a slashed bond (a treasury, the harmed parties) |
| `bond_until` | `Fixed` | Unix microseconds at which the bond term ends |
| `challenge_period_us` | `Fixed` | Microseconds after `bond_until` during which the bond can be slashed but not refunded (7 days in the example) |
| `witness_oracles` | `Fixed` | Other oracles that can prove the term and challenge period have passed |
| `oracle_dnas` | `Fixed` | `DnaHashB64` of the hc-vtime networks whose witness statements count |
| `max_faulty`, `min_oracles` | `Fixed` | Fault bound and quorum for that proof |
| `claim` | `ExecutorProvided` | `{ kind: "slash", a, b? }` or `{ kind: "refund", time_proof }` |

Statement entries have the shape `{ statement: { dna, domain, earliest, floor, latest, nonce,
oracle, prev, seq }, signature: [64 integers] }`, which the hc-vtime zome returns from
`unyt_time_proof()`. A reporter gets statements the oracle gave out or that appear in anchors and
seals. `check_oracle_statements` in the zome runs the same tests before anyone spends a transaction
on them (pass `b: null` for a single self-contradicting statement).

## Code execution flow

1. Read the bond and confirm it was parked by `bonded_oracle` (`get_spend_links_author`).
2. **Slash:** verify `a` (and `b`, if given) against `bonded_oracle` with `hdi_verify_signature`,
   after checking its form (domain, canonical decimals, `prev`/`floor` empty exactly at seq 0).
   Test for self-contradiction, then, for a pair, rebuild each signature's hex in Rhai and test for
   time reversal or a dropped floor in either order, then for equivocation. If proven, pay
   `reporter_reward` to the executor and the rest to `slash_beneficiary`.
3. **Refund:** require the executor to be the bonded oracle and exclude it from the witnesses.
   Compute the (f+1)-th largest `earliest` from distinct, valid witness statements on listed
   networks; invalid witness entries are skipped, not fatal. Require that bound to reach
   `bond_until + challenge_period_us`. Return the whole bond.
4. Anything else throws: nothing is consumed and the bond stays parked.

## Output structure

- `unyt_allocation`: reward and remainder (slash) or the full bond (refund), all citing the bond's
  parked source, never a zero amount.
- `computed_values`: `outcome` (`slashed: self-contradiction`, `slashed: time reversal`,
  `slashed: floor dropped`, `slashed: equivocation` or `refunded`), `bonded_oracle`, `bond_amount`,
  `proven_time_lower_bound_us` (0 on a slash).

## Trust assumptions and open questions

- **Forward lies.** A lie forward in time is not self-contradictory by itself. It binds the oracle,
  though: every later statement must stay at or above the lie until real time catches up, or it is
  a confession. The bond deters backwards lies and forks directly. For forward lies it gives
  deterrence only once the oracle tries to return to the true time.
- **Self-reporting.** An oracle that lies and then reports itself through another agent recovers
  only `reporter_reward`; size the reward well below the bond.
- **Racing reporters.** The reward goes to whoever executes first with a valid proof. Statements
  are public once handed out, so several reporters may race; only one execution consumes the bond.
- **`claim` is executor-provided**, which the engine checks for shape only. That is acceptable here
  because every decision rests on signatures the code verifies, never on the claim's assertions.
- **One-time run.** The bond resolves once, by slash or refund. A new term needs a new agreement.
- **Signature encoding.** Checked against `rave_engine` 0.15.0 in `unyt/harness`, including every
  slash condition, the two-network case that must not slash, honest pairs that must not slash,
  forged and foreign statements, the challenge window and a faulty witness. The harness replaces
  only `get_spend_links_author` (a DHT read) with a script stub. Run one execution on your network
  before relying on it.
