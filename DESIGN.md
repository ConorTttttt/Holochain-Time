# hc-vtime: design and research basis

hc-vtime gives Holochain actions **time bounds that every peer can verify**: "this action was
created no earlier than L" and "this action existed no later than U". It does so by combining
signed readings from Roughtime servers (RFC 10049) and from Holochain *oracle agents*, tolerating
up to `f` lying sources, and making lying oracles provably and economically accountable through
Unyt. It never asks validators to trust a clock.

## 1. The problem

Every Holochain action carries a timestamp its author writes. Validators can check that timestamps
increase along one source chain, but not when anything happened in the world. A hApp that needs
deadlines, expiries, auctions, vesting or time-bounded credit therefore either trusts authors'
clocks or trusts one attestor (as the Unyt library's `time_locked_vesting` example does, and says
so). Validation also cannot read a clock itself: it must be a deterministic function of data, so
time can only enter validation as **signed evidence inside entries**.

## 2. Research review

### 2.1 Fault-tolerant clock agreement

- **Lamport and Melliar-Smith (1985), *Synchronizing Clocks in the Presence of Faults*, JACM 32(1).**
  Generalises Byzantine agreement to clocks and proves algorithms correct when some clocks are
  arbitrarily faulty. Lesson: assume a bounded number of liars, and size the quorum for it.
- **Marzullo (1984) and NTP's intersection algorithm.** Each source reports an interval; the
  algorithm finds the region consistent with the most sources, and NTP's variant is valid only
  when fewer than half the sources are falsetickers. Lesson: reason in intervals, not points, and
  state the fault bound explicitly. hc-vtime implements this intersection for simultaneous
  readings and requires n ≥ 2f + 1 for it.
- **Chronos (Deutsch, Schiff, Dolev, Schapira, NDSS 2018).** An NTP client that samples many
  servers (m = 15 from a pool of hundreds), discards the d = m/3 highest and lowest, and falls back
  to querying the whole pool. Under its model, shifting a client by 100 ms takes an attacker
  controlling 1/7 of the pool decades in expectation. Lesson: trimmed order statistics over many
  independent sources defeat a minority of liars. hc-vtime's bound rules are the one-sided form of
  this trimming.

### 2.2 Authenticated time

- **Roughtime, RFC 10049 (Experimental, October 2026).** A server signs (with a delegated online
  key certified by its long-term key) a Merkle root over a batch of client requests together with a
  midpoint and radius; the client's request nonce is a leaf. The response is therefore bound to the
  exact request, verifiable offline, and cheap to serve. Clients can chain requests
  (nonce = H(previous response ‖ random)) so later responses are provably later, and two
  inconsistent signed responses form a transferable proof of server malfeasance. Version 1 differs
  from the late drafts (0x8000000c) only in the capitalisation of the signature context strings.
  Lesson: time evidence can be **self-authenticating bytes**, which is exactly what Holochain
  validation needs, and misbehaviour can be made **provable rather than suspected**.

### 2.3 Timestamping by linking

- **Haber and Stornetta (1991), *How to Time-Stamp a Digital Document*.** Proposes linking each
  timestamp to its predecessor with a hash so documents cannot be back- or forward-dated relative to
  each other, and distributing trust across independently chosen witnesses. Lesson: a Holochain
  source chain already *is* a hash-linked log, so one proven bound propagates along it: an anchor
  bounds every later action of that agent, and a seal bounds every earlier one.

### 2.4 The oracle problem

- **Caldarelli (2025), *Frontiers in Blockchain* 8.** Surveys mitigations for the oracle problem:
  multiple independent oracles with aggregation (vulnerable to collusion and Sybils), reputation,
  staking and slashing, trusted hardware, and cryptographic proofs, which show data was not altered
  but "cannot prove that the data was truthful". Lesson: no single mechanism closes the gap, so
  combine them: independent sources, a fault-bounded aggregate, signed accountability, and money
  at stake.
- **Randomness beacons (drand quicknet: a BLS signature every 3 s).** A beacon value cannot be
  predicted before its round, so embedding one proves "created after round r". Considered as an
  anchor source; deferred because verifying BLS12-381 in WASM is costly and Roughtime already
  provides "not before" evidence with Ed25519 alone.

### 2.5 Lessons applied

| Lesson | Where it shows up in hc-vtime |
| --- | --- |
| Bound the number of liars and size quorums for it | `max_faulty` (f), `min_sources` ≥ f + 1; intersection needs 2f + 1 |
| Reason in intervals | every reading is `[earliest, latest]`; verdicts compare intervals |
| Trim extremes instead of averaging | (f+1)-th largest lower bound, (f+1)-th smallest upper bound |
| Make evidence self-authenticating | raw Roughtime packets and signed oracle statements stored in entries |
| Bind evidence to the thing being dated | seal nonces commit to DNA hash + action hash |
| Use the hash-linked chain | anchors propagate forward, seals backward (`chain::propagate`) |
| Make misbehaviour provable | chained oracle statements with a signed high-water mark (`floor`); self-contradiction, time-reversal, floor-dropped and equivocation proofs |
| Put money at stake | Unyt `time_oracle_bond`: proof pays a reporter and a beneficiary |

## 3. Design

### 3.1 Two kinds of proof

**Anchor ("not before").** A `TimeAnchor` entry embeds a set of readings. Each reading existed
before the entry (the entry's hash commits to it), so the anchor action, and every later action
on the author's chain, happened after the readings. With at most f lying sources the
**(f+1)-th largest `earliest`** is a sound lower bound: among the f+1 largest values at least one
is honest, and that honest source's reading preceded the anchor.

**Seal ("not after").** A `TimeSeal` entry holds readings whose nonce is
`seal_nonce = H("hc-vtime/seal/v1\0" ‖ len ‖ dna_hash ‖ len ‖ action_hash)`. A source can only sign
that nonce after the action hash exists, and the hash covers the action's timestamp, author,
sequence and entry. So the action existed before every honest reading, and the
**(f+1)-th smallest `latest`** is a sound upper bound. Anyone may seal anyone's action.

"Existed" means *its content was fixed*: whoever knows an action's hash can have it sealed before
publishing the action, because seal validation waits for the target to appear. An author can
therefore seal several alternative actions in advance and publish only one later. A seal proves
neither publication by T nor that no alternatives were prepared. For deadlines over visible data
(open auctions, first-come claims), applications need a commit–reveal step with one published
commitment per participant (see SECURITY_REVIEW.md, finding P3-seal).

Together they bracket an action: `not_before ≤ t(action) ≤ not_after`. The coordinator's
`get_verified_time` reports both and classifies the action's own timestamp as `Consistent`,
`Backdated` or `FutureDated` against them, with `max_skew_ms` tolerance.

### 3.2 Sources

| Source | Evidence | How it is checked |
| --- | --- | --- |
| Roughtime server | framed request + response packets | full RFC 10049 verification: framing, tag order, nonce echo, version negotiation, delegation and response signatures, MINT ≤ MIDP ≤ MAXT, Merkle inclusion of the exact request |
| Oracle agent | `SignedOracleStatement` | Ed25519 over the statement's MessagePack bytes; canonical decimal fields; oracle listed in DNA properties |

Zomes cannot open UDP sockets, so a client fetches Roughtime readings
(`crates/vtime_core/examples/roughtime_fetch.rs`, or the same few lines in a Tauri backend) using a
request the zome builds (`build_roughtime_request`). The bytes are self-authenticating, so the
client is not trusted.

### 3.3 Oracle agents

An oracle is an agent listed in the `oracles` DNA property. Its coordinator answers
`attest_time(nonce)` with `[now − r, now + r]` from its host clock (`oracle_radius_ms`), which its
operator keeps disciplined (NTS, GPS or a Roughtime client). Statement format v2
(`hc-vtime/oracle-statement/v2`) carries:

- `dna`: the network whose cell signed it. One agent key may serve several networks, each with its
  own chain from seq 0, and validation only accepts statements naming its own DNA;
- `seq` and `prev` (the previous signature);
- `floor`: the largest `earliest` signed before on this chain. A statement's `latest` may never be
  below it.

Each statement is written to a private `OracleLog` entry in the same atomic commit that produces it:

- the oracle refuses to sign below its floor, so honest oracles never contradict themselves;
- two concurrent requests cannot both be answered at one `seq`: Holochain's default `Strict` chain
  ordering fails the second commit on the moved chain head, so its statement is never returned;
- if the latest log entry cannot be read, the oracle refuses to sign rather than restart at seq 0;
- answers are spaced at least 1 s apart (coordinator constant, tunable without a new DNA hash), so
  no caller can grow the oracle's chain faster than 86,400 actions a day. The read-only
  `latest_attestation` returns the last statement without writing, and anchors and Unyt proofs fall
  back to it when an oracle is rate limited, so spam cannot block them. Seals need a statement for
  their own nonce, so they still compete for the slots (see future work).

Statements the oracle signed prove misbehaviour when they show:

- **self-contradiction**: one statement with `latest < floor`;
- **time reversal**: b chains after a, yet `b.latest < a.earliest`;
- **floor dropped**: b chains after a, yet `b.floor < max(a.floor, a.earliest)`;
- **equivocation**: different statements with the same `dna`, `seq` and `prev`.

The floor makes this complete for backwards time. In any chain s0 → … → sk with
`sk.latest < s0.earliest`, either every link carried the floor, so sk contradicts itself, or some
adjacent link dropped it. So any backwards walk, however gradual, leaves a proof of at most two
statements. Without the floor each step could go back 2r with every adjacent pair consistent.

### 3.4 Statement encoding shared with Unyt

All statement fields are strings, declared in alphabetical order. The oracle signs the MessagePack
encoding Holochain uses for any value. Unyt's `hdi_verify_signature` re-encodes a JSON object
through the same encoder; JSON maps come back key-sorted and strings encode identically, so the
same signature verifies in both systems. This is tested twice: in `vtime_core` (struct vs JSON
object encoding) and in `unyt/harness`, which runs both templates through the published
`rave_engine` 0.15.0 with real signatures. Times are microseconds kept below 2^53 so Rhai's f64
`to_num` reads them exactly.

### 3.5 Unyt integration

- **`verified_time_release`.** The library's vesting pattern with "now" proven by m-of-n oracle
  signatures instead of one attestor. Replayed proofs are harmless because a statement only ever
  understates the current time. Each entry is judged on its own. Malformed, unlisted-oracle,
  unlisted-network, below-floor and badly signed entries are skipped rather than fatal, and at most
  32 entries are examined. Only statements naming a listed DNA (`oracle_dnas`) count, so every
  statement that moves money sits on a chain the bond covers.
- **`time_oracle_bond`.** An oracle bonds funds. Any of the four proofs above pays a fixed reporter
  reward and sends the rest to a fixed beneficiary, which limits how much a lying oracle can recover
  by reporting itself. The proofs are accepted from any network, because an honest oracle never
  signs them anywhere. After the term plus `challenge_period_us`, the oracle reclaims the bond
  with a time proof from *other* oracles, so a lie told just before the term ends can still be
  reported.
- **Oracle fees** need no new template: the library's `aggregate_payment` pattern can pay oracles.

## 4. Threat model and guarantees

**Guaranteed, if at most f trusted sources in a set lie and keys are not forged:**

1. An anchored action, and every later action on that author's chain that descends from the anchor
   by `prev_action` links, happened no earlier than the anchor's robust lower bound.
   `get_verified_time` checks that ancestry with `must_get_agent_activity`, so an anchor on one
   branch of a forked chain does not lend its bound to another branch. Holochain sys validation
   requires each action's timestamp to be no earlier than its predecessor's (`check_prev_timestamp`,
   Holochain 0.7.0).
2. A sealed action's content was fixed no later than the seal's robust upper bound.
3. An anchor whose own timestamp precedes its proven lower bound by more than `max_skew_ms` is
   invalid, so provable backdating is rejected network-wide.
4. An oracle whose clock goes backwards on one network's chain, or that forks that chain, produces
   a transferable proof of at most two statements against itself. An honest oracle running the
   reference coordinator never does, even when one key serves several networks.
5. Up to f faulty oracles or Roughtime servers cannot stop anchoring, sealing, Unyt releases or
   refunds: each answer is checked on its own and bad ones are dropped.

**Not guaranteed:**

- *Tight bounds.* A seal requested late gives a loose upper bound; the author controls when to
  anchor and seal.
- *Publication or uniqueness.* A seal shows content existed, not that it was published or that the
  author prepared no alternatives (§3.1). Open-auction style deadlines need commit–reveal.
- *More than f liars.* Bounds can then be wrong. Choose sources run by independent organisations.
- *Liveness.* Oracles and servers can be offline; anchoring then fails rather than weakening.
  Under sustained spam, seals compete for each oracle's one-per-second statement slots.
- *Forward lies within f.* A lie forward in time is not self-contradictory on its own. It binds the
  oracle: until real time catches up, every later honest-looking statement is provably below the
  floor.
- *Policy changes.* Trusted keys live in DNA properties, so changing them creates a new network.
  A FROST-governed oracle registry is the natural next step (see the primitives review).

## 5. Verification status

| Check | Status |
| --- | --- |
| Core unit tests (parsing, intervals incl. 5,000 randomized adversary trials, keys and checksums, statements v2, oracle signing policy, chain, verdicts) | 28 passing |
| Roughtime cross-implementation tests against the independent `roughenough` 2.2.0 server code (single, 13-request Merkle batch, our requests accepted by their parser, every response byte flipped, 30,000 mutated and random inputs) | 5 passing |
| Evidence policy tests (mixed sets, seals, network binding, per-response filtering, untrusted/duplicate/insufficient sources, forged statements, every malfeasance proof, honest chains never self-incriminate) | 15 passing |
| Unyt templates executed by `rave_engine` 0.15.0 with real Ed25519 signatures, incl. a 40-statement proof within engine limits, and key text cross-checked against `holo_hash` | 14 passing |
| Integrity and coordinator zomes type-check against HDI 0.8.1 / HDK 0.7.1, clippy clean with `-D warnings` | done |
| Security review (SECURITY_REVIEW.md) and baseline proofs of concept for every finding | done |
| `dna.yaml`, `happ.yaml` and DNA properties decode with `holochain_types` 0.7.1 | done |
| WASM build and conductor (sweettest) tests | **not run**: the `wasm32-unknown-unknown` target could not be installed in the build environment |
| Live Roughtime servers, live Unyt network | **not run**: no outbound UDP; Unyt DNA rules are not public |

## 6. Future work

1. Merkle-batched oracle statements (the Roughtime trick) so one signature answers many seal
   nonces. This is the lasting fix for seal throughput under spam.
2. A conductor host function that fetches Roughtime itself, removing the client step.
3. Seal propagation backwards along a chain inside `get_verified_time`.
4. drand beacons as an extra anchor source once a BLS12-381 host function exists.
5. FROST-signed oracle registry entries instead of DNA properties.

## Sources

- [RFC 10049: Roughtime](https://www.rfc-editor.org/rfc/rfc10049) and [draft-ietf-ntp-roughtime-19](https://www.ietf.org/archive/id/draft-ietf-ntp-roughtime-19.html)
- [roughenough 2.2.0](https://crates.io/crates/roughenough-protocol) (independent implementation used in tests)
- [Lamport and Melliar-Smith, Synchronizing Clocks in the Presence of Faults](https://www.microsoft.com/en-us/research/publication/synchronizing-clocks-presence-faults/)
- [Intersection algorithm (Marzullo, NTP)](https://en.wikipedia.org/wiki/Intersection_algorithm)
- [Deutsch et al., Preventing (Network) Time Travel with Chronos, NDSS 2018](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_02A-2_Deutsch_paper.pdf)
- [Haber and Stornetta, How to Time-Stamp a Digital Document](https://nakamotoinstitute.org/library/time-stamp-digital-document) ([DOI](https://doi.org/10.1007/BF00196791))
- [Caldarelli, Can AI solve the blockchain oracle problem?, Frontiers in Blockchain 2025](https://www.frontiersin.org/journals/blockchain/articles/10.3389/fbloc.2025.1682623/full)
- [drand quicknet](https://docs.drand.love/blog/2023/10/16/quicknet-is-live)
- [HDK 0.7.1](https://docs.rs/hdk/latest/hdk/), [HDI 0.8.1](https://docs.rs/hdi/latest/hdi/), [rave_engine 0.15.0](https://crates.io/crates/rave_engine)
