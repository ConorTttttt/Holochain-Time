# hc-vtime security review

Reviewed against the supplied *Crypto Holochain Security Reviewer* instructions, with
`security-profile.yaml` (filled for this project) as the review contract. Sections 1–5 describe the
baseline exactly as reviewed, before any change. Section 6 records the remediation made afterwards
and re-assesses the result.

The review ran in two passes. The first pass produced findings F1–F8. A second pass, run before
any fix was accepted, re-read the baseline independently and added F9–F11. Every finding with a
runnable trigger has a proof of concept that passes against the baseline, confirming the defect.

## 1. Verdict

**Verdict:** BLOCK
**Mode:** RELEASE (no diff was supplied; the whole component at baseline commit `f5e257d` is in scope, including existing issues)
**Scope:** every file in the repository at `f5e257d`: `crates/vtime_core` (all modules, tests, example), both zomes, `dna.yaml`/`happ.yaml`, both Unyt templates (Rhai and JSON schemas), the Unyt harness, `DESIGN.md`, `README.md`. Dependency sources were read from the local cargo registry: `hdi` 0.8.1, `hdk` 0.7.1, `holochain_integrity_types`/`holochain_zome_types` 0.7.1, `holo_hash` 0.7.1. Sources fetched from crates.io and read, not built: `holochain` 0.7.0 (sys validation), `holochain_keystore` 0.7.0, `lair_keystore_api` 0.7.1, `sodoken` 0.1.0.
**Findings:** P0: 0 / P1: 1 / P2: 5 / P3: 5
**Bottom line:** No finding produces a wrong time bound while at most f sources lie. But the slashing logic can take an honest oracle's bond, dishonest oracles have three ways to avoid slashing, and one faulty source or any peer can stop the service, so the baseline is not fit to ship.

## 2. Findings

### [P1] F1. An honest oracle that uses one agent key in two vtime cells can be slashed for "equivocation"

- **Location:** `crates/vtime_core/src/malfeasance.rs:50-52`, `crates/vtime_core/src/statement.rs:34-50`, `unyt/time_oracle_bond/execution_code.rhai:151-153`, `dnas/vtime/zomes/coordinator/vtime/src/lib.rs:97-114`
- **Confidence:** HIGH
- **Violated property:** Accountability: an honest oracle never produces a malfeasance proof (DESIGN.md §3.3 and guarantee 4 in §4).
- **Evidence:** Each cell keeps its own private `OracleLog`, so a second cell with the same agent key starts again at `seq "0"`, `prev ""`. Statements carry no network or cell identifier. The equivocation rule is `va.seq == vb.seq && va.prev == vb.prev && a.statement != b.statement`, and the Rhai rule is the same, so two honest seq-0 statements from different cells satisfy it.
- **Trigger or attack path:**
  1. The oracle keeps its agent key when it joins a second vtime network. This happens on a DNA change (any change to trusted keys, f or tolerances is a new DNA hash), with a clone cell, or with a parallel deployment.
  2. It answers one request in each network.
  3. Anyone holding both statements runs `time_oracle_bond` with `kind: "slash"`. Statements are handed to every requester and published inside anchors, so obtaining them is easy.
- **Impact:** The honest oracle loses its bond: `reporter_reward` goes to the reporter and the rest to `slash_beneficiary`. `check_oracle_statements` also labels it malicious.
- **Fix:** Bind every statement to the signing cell's DNA with a signed `dna` field. Equivocation then requires the same `dna`, validation requires `dna == dna_info().hash`, and the Unyt templates count only statements from listed DNAs. Bump the statement domain to v2.
- **Regression test:** Two chains with one key and different `dna`, both at seq 0: no proof, and the bond refuses to slash. The same `dna` with a fork is `Equivocation`.

### [P2] F2. An oracle can walk its clock backwards without ever producing a slashable pair

- **Location:** `crates/vtime_core/src/malfeasance.rs:44-49`, `dnas/vtime/zomes/coordinator/vtime/src/lib.rs:101-106`, `unyt/time_oracle_bond/execution_code.rhai:149-150`
- **Confidence:** HIGH
- **Violated property:** Guarantee 4 (DESIGN.md §4): an oracle that signs contradictory statements produces a transferable proof against itself.
- **Evidence:** The honest-oracle guard and both slash rules only compare a statement with its direct predecessor (`b.latest < a.earliest`). Every adjacent pair stays consistent while each statement moves the clock back by up to 2r, where r is the oracle radius.
- **Trigger or attack path:** A compromised or modified oracle signs intervals with midpoints t, t−2r, t−4r, and so on. With r = 1 s, 1,800 statements move the clock back an hour and `check_pair` finds nothing at any step. The bond refuses all three pairs of a→b→c even though c lies wholly before a.
- **Impact:** Backward lies carry no slashing risk, so the bond does not deter them, and they make seals look earlier than they were. The safety of the bounds still rests on at most f liars.
- **Fix:** Add a signed high-water mark, `floor`, holding the largest `earliest` signed so far on this chain.
  - The honest oracle sets `floor = max(prev.floor, prev.earliest)` and refuses to sign if `latest < floor`.
  - One statement with `latest < floor` is a proof on its own.
  - A chained pair with `b.floor < max(a.floor, a.earliest)` is a proof.
  - Any backwards chain then contains one of these, so drift is capped at 2r in total.
- **Regression test:** The same backwards walk yields a proof within two steps, whether the oracle carries the floor forward or drops it. Honest chains with random spacing and clock jitter never yield a proof.

### [P2] F3. One faulty source within the fault budget blocks anchors, seals and Unyt releases

- **Location:**
  - `dnas/vtime/zomes/coordinator/vtime/src/lib.rs:156-166` (gather), `:230-231` and `:253-254` (oracle answers and client Roughtime readings verified as one set), `:385-388` (export unchecked).
  - `crates/vtime_core/src/evidence.rs:144-147`.
  - `unyt/verified_time_release/execution_code.rhai:59-64`.
- **Confidence:** HIGH
- **Violated property:** Liveness under the declared fault model ("tolerant of up to `f` lying sources", README).
- **Evidence:**
  - `gather_oracle_statements` appends whatever each oracle returns, and the client's Roughtime readings are appended unchecked.
  - `verify_evidence_set` fails on the first bad item.
  - `unyt_time_proof` exports responses without verifying them.
  - The release template throws on the first trusted statement whose signature fails.
- **Trigger or attack path:** One listed oracle returns a bad signature, a statement for another nonce, an over-wide interval, or a copy of another oracle's statement (a duplicate source). One listed Roughtime server sends a malformed reply.
- **Impact:** Every `create_anchor` and `seal_action` fails while that source is reachable, and release executions fail whenever its statement is in the proof. No unsound bound results.
- **Fix:**
  - Verify each answer on its own: it must come from the oracle asked and pass the nonce, signature, radius and `dna` checks. Drop answers that fail.
  - Filter client Roughtime readings the same way.
  - In Rhai, skip invalid statements instead of throwing, and cap the number of entries examined.
- **Regression test:**
  - Forged, stale, wide, wrong-network and forwarded oracle answers are dropped, and the two honest answers still make a valid seal.
  - A corrupted, stale or duplicated Roughtime reply is dropped.
  - A release whose first entries are a bad signature, a short signature, a non-canonical number and a non-map still pays.

### [P2] F4. Any peer can make an oracle write unbounded chain entries, and every call scans the whole log

- **Location:** `dnas/vtime/zomes/coordinator/vtime/src/lib.rs:41-55` (unrestricted grant), `:61-74` (`query` returns every `OracleLog` record with entries), `:84-127`
- **Confidence:** HIGH (code path); MEDIUM (practical rate, which depends on conductor throughput)
- **Violated property:** Resource bounds on untrusted input; oracle availability.
- **Evidence:** Each `attest_time` call, for any caller and any nonce, commits an `OracleLog` action, which is published to agent-activity authorities. `latest_oracle_log` loads every `OracleLog` record on every call, so per-call cost grows linearly with history and total cost grows quadratically.
- **Trigger or attack path:** Any peer in the network loops `call_remote(oracle, "attest_time", random_nonce)`.
- **Impact:** The oracle's chain, and the storage of its authorities, grow permanently. `attest_time` slows until callers time out, which takes that oracle out of service.
- **Fix:**
  - Find the last log entry with a bounded, descending query near the chain head.
  - Enforce a minimum spacing between statements, returning a retryable refusal inside it.
  - Since spacing alone would let spam take every slot, serve the last statement read-only (`latest_attestation`) and let anchors and Unyt proofs, which do not need a bound nonce, fall back to it.
  - The root-cause fix for seals, one signature over a Merkle batch of nonces, is future work.
- **Regression test:**
  - Unit tests: the spacing rule (10 simulated seconds of spam produce exactly 10 answers), and the lookup windows always reaching back to seq 0.
  - Conductor test (not runnable here): 1,000 rapid calls produce at most duration ÷ spacing log entries, per-call latency stays flat, and `create_anchor` succeeds while `attest_time` is saturated.

### [P2] F5. `get_verified_time` uses sequence numbers, not hash ancestry, to pick the anchor for `not_before`

- **Location:** `dnas/vtime/zomes/coordinator/vtime/src/lib.rs:321-341` (comparison at `:329`)
- **Confidence:** MEDIUM. The code path is clear, but the fork scenario could not be run on a conductor here.
- **Violated property:** `not_before` soundness ("every later action on that author's chain", DESIGN.md §4.1).
- **Evidence:** An anchor counts if `anchor.action_seq() <= target.action_seq()`, and nothing checks that the anchor is an ancestor of the target. A doc comment tells callers to check warrants, but the field is labelled "Proven" and no fork or warrant state is returned.
- **Trigger or attack path:** The author forks its own chain, putting action X (seq 12, created at t0) on branch B. Later, branch A gains an anchor at seq 10 whose evidence dates from t1 > t0. `get_verified_time(X)` then reports `not_before = t1`.
- **Impact:** An application that relies on "created after T" accepts an action made earlier.
- **Fix:** Accept an anchor only if `must_get_agent_activity(author, ChainFilter::until_hash(target, anchor))` walks from the target back to the anchor along `prev_action`. Report the author's fork and warrant status.
- **Regression test (sweettest, not runnable here):** With the forked author above, `not_before_us` for X is `None`. On a linear chain the anchor is accepted.

### [P2] F9. Non-canonical key text lets a lying oracle's statements count on Holochain but never be slashed

- **Location:** `crates/vtime_core/src/keys.rs:19-32` (only the 32 key bytes are read; the 4 location bytes are ignored), used by `crates/vtime_core/src/statement.rs:168`; `unyt/time_oracle_bond/execution_code.rhai:59` (`st.oracle != oracle` text comparison)
- **Confidence:** HIGH
- **Violated property:** Guarantee 4: an oracle that signs contradictory statements produces a transferable proof. More generally, one key must have one identity across every verifier.
- **Evidence:**
  - `AgentPubKeyB64` text ends with 4 location bytes that `holo_hash` checks as a checksum (`holo_hash_decode_unchecked` returns `BadChecksum`). `agent_key_from_b64` does not check them, so 2^32 spellings decode to the same key.
  - The statement signs the `oracle` text. Holochain validation identifies the source by the decoded key, while the bond compares the text with `bonded_oracle`.
- **Trigger or attack path:** A compromised or modified oracle signs its lies with `oracle` set to a respelling of its key (one location byte changed).
  1. Anchors and seals accept them as that oracle's evidence.
  2. `check_pair` even reports `TimeReversal`.
  3. The bond rejects every such statement with "not signed by the expected oracle", and the canonical spelling cannot be substituted without invalidating the signature.
- **Impact:** Accountability is bypassed with no cost to the liar. Its lies count, within f, and its bond is never at risk.
- **Fix:** Decode only the canonical text: recompute the location bytes (BLAKE2b-128 folded to 4 bytes, exactly as `holo_hash`) and reject a mismatch. Build key text with the computed bytes.
- **Regression test:**
  - A respelled statement is refused as evidence and as a proof.
  - Every one-bit change of the location bytes is refused.
  - `agent_key_to_b64` and `dna_hash_to_b64` match `holo_hash` for 256 keys.

### [P3] F6. Unchecked integer arithmetic on attacker- and configuration-controlled values

- **Location:** `crates/vtime_core/src/statement.rs:94`; `crates/vtime_core/src/interval.rs:50`, `:69`, `:140`, `:150`, `:164`; `crates/vtime_core/src/evidence.rs:63-67`, `:86`; `crates/vtime_core/src/roughtime.rs:205`
- **Confidence:** HIGH
- **Violated property:** No panics on untrusted input; checked arithmetic on bounds.
- **Evidence:**
  - `i64::abs()` on a parsed `i64::MIN` panics in debug builds and returns `i64::MIN` in release builds. That bypasses the 2^53 bound, and `radius_us` then overflows. Statement fields are parsed before the signature is checked, so anyone can reach the debug panic.
  - `max_faulty + 1` (u32), `max_faulty + 1` and `2 * max_faulty + 1` (usize) all wrap in release builds. With f = u32::MAX, `check()` passes, and on wasm32 `robust_lower_bound` then indexes out of bounds.
  - `12 + len` in `unframe` can wrap on 32-bit targets.
- **Trigger or attack path:** Anyone can submit evidence whose `earliest` is `"-9223372036854775808"`. A DNA author can mistakenly set `max_faulty: 4294967295`.
- **Impact:**
  - Debug builds: validation or a native tool panics.
  - Release builds: a range check is bypassed. No unsound result was found, because the item still needs a trusted signature.
  - Release builds with f = u32::MAX: every validation traps.
- **Fix:** Use `unsigned_abs`, `checked_add`/`checked_mul`, and saturating width.
- **Regression test:** The inputs above return errors, and do not panic, in both debug and release builds.

### [P3] F7. Bond refund has no challenge window

- **Location:** `unyt/time_oracle_bond/execution_code.rhai:178-189`
- **Confidence:** HIGH
- **Violated property:** Bond deterrence covers the whole bond term.
- **Evidence:** A refund only needs witnesses to prove `bond_until` has passed. With witness statements 1 µs after `bond_until`, the refund succeeds.
- **Trigger or attack path:** The oracle lies just before `bond_until`, then refunds as soon as the witnesses can prove `bond_until` has passed.
- **Impact:** Lies near the end of the term go effectively unpunished, because reporters have no time to submit.
- **Fix:** Add a fixed input `challenge_period_us`. A refund requires `proven_time ≥ bond_until + challenge_period_us`.
- **Regression test:** A refund inside the window is refused and one after it is allowed. Slashing still works inside the window.

### [P3] F8. Unbounded verification work for readers

- **Location:**
  - `dnas/vtime/zomes/coordinator/vtime/src/lib.rs:304-319`: every `ActionToSeals` link is verified, duplicates included; every anchor link is fetched.
  - `crates/vtime_core/src/evidence.rs:112-118`: an oracle signature is verified before its key is checked against the policy.
- **Confidence:** HIGH
- **Violated property:** Resource bounds on untrusted input.
- **Evidence:** Anyone may link any number of valid seals to a target, including many links to one seal, because servers and oracles sign any nonce. `get_verified_time` fetches and re-verifies each one, at up to 32 items × 2 Ed25519 checks per seal.
- **Trigger or attack path:** An attacker links thousands of seals to a popular action.
- **Impact:** `get_verified_time` for that action slows down or times out. The result stays sound.
- **Fix:** Deduplicate seal hashes, cap seals and anchors verified (the target author's seals first), and check the policy before verifying signatures.
- **Regression test:**
  - Unit test: a statement from an untrusted key or a foreign network is rejected without any verifier call.
  - Conductor test for the caps (not runnable here).

### [P3] F10. Policy check accepts a key in both source lists and quorums no set can meet

- **Location:** `crates/vtime_core/src/evidence.rs:62-80`
- **Confidence:** HIGH (code path); LOW likelihood (needs a DNA author mistake)
- **Violated property:** "At most f faulty *sources*": one Ed25519 key is one source.
- **Evidence:**
  - `SourceId::Roughtime(k)` and `SourceId::Oracle(k)` are distinct, so a key listed as both a Roughtime server and an oracle counts twice towards the quorum.
  - `trusted` counts listed keys, not distinct ones.
  - `min_sources` above `MAX_EVIDENCE_ITEMS` (32) passes `check()`, but no set can ever meet it.
- **Trigger or attack path:** A DNA lists one operator's key in both lists. That operator then holds two votes, so f + 1 apparent sources can be one party plus f others.
- **Impact:** The effective fault tolerance silently drops by one per doubled key. An unreachable quorum makes the DNA unusable.
- **Fix:** Refuse a key that appears in both lists, count distinct keys, and refuse `min_sources > MAX_EVIDENCE_ITEMS`.
- **Regression test:** Each of these policies is `InvalidPolicy`.

### [P3] F11. Documentation recommends seals for deadlines they cannot enforce

- **Location:** `README.md:52` ("a bid is invalid unless sealed before the auction's close"), `DESIGN.md:96` and `:168`; mechanism in `dnas/vtime/zomes/integrity/vtime_integrity/src/lib.rs:207` (`must_get_action` defers a seal until its target appears)
- **Confidence:** MEDIUM (the impact depends on the application)
- **Violated property:** Documented semantics: "the action existed no later than U".
- **Evidence:** A seal binds to the target's hash. An author can compute the hash of an action before publishing it, have it sealed, and publish later; validation of the seal simply waits. The author can do this for several alternative actions and publish only the most favourable one. Roughtime servers answer any number of nonces, so this costs almost nothing.
- **Trigger or attack path:** In an open auction following the README rule, a bidder seals bids at many prices before the close. After seeing rivals' bids, it publishes only the best one, and that bid passes "sealed before the close".
- **Impact:** A deadline rule built on the documented pattern can be bypassed by pre-committed alternatives. Time bounds themselves remain sound for what they prove (content fixed by U).
- **Fix:** State the precise semantics (content fixed by U; not publication, not uniqueness) in the README, DESIGN.md and the `VerifiedTime`/integrity docs, and recommend commit–reveal with one published, sealed commitment per participant for deadline rules.
- **Regression test:** Not applicable (documentation). A sweettest showing a seal validating before its target is published would document the behaviour.

## 3. Unresolved security questions

1. **Host Ed25519 strictness. Partly resolved.** The host verifier (`verify_signature_raw` in `holochain_keystore` 0.7.0) calls `lair_keystore_api` 0.7.1 `verify_detached`, which calls `sodoken` 0.1.0 `sign::verify_detached`, i.e. libsodium `crypto_sign_verify_detached`. Current libsodium rejects small-order public keys and non-canonical `S`, so a weak key listed in DNA properties is a dead source, not a forgery risk. Edge cases where libsodium and `ed25519-dalek` `verify_strict` (used by native tools) differ could make a native pre-check disagree with validators. All in-zome checks use the host, so validators agree with each other. Still open: the libsodium version bundled by `libsodium-sys-stable`.
2. **Timestamp monotonicity. Resolved.** Holochain 0.7.0 `sys_validation_workflow.rs:1382` calls `check_prev_timestamp`, which rejects an action timestamped before its predecessor.
3. **Unyt semantics.** It is unknown whether Unyt enforces `runtime_input_signature.json` limits (for example `maxItems: 32`) on parked data before the script runs. If it does, a malformed entry would fail the whole run at schema validation rather than being skipped by the script. It is also unknown what happens to parts of a consumed `ParkedSpendBalance` in units the script does not allocate. Resolving either needs the Unyt DNA rules, which are not public.
4. **Draft-version Roughtime.** `0x8000000c` was never tested against a draft-era server. By analysis, a unit mismatch fails closed (overflow or radius rejection).

## 4. Verification

- **Read:** all project sources, the manifests and `Cargo.lock`, and the dependency sources listed in §1.
- **Specifications:** RFC 10049 as summarised in the code and DESIGN.md. The RFC text was not re-fetched during this review.
- **Ran on the baseline:**
  - `cargo test --workspace --offline`: 33 passed.
  - A scratch proof-of-concept crate built against an exported copy of `f5e257d`. Its 11 tests each assert the defective behaviour, and all 11 pass, confirming F1, F2, F3, F6 (also under `--release`), F7, F9 and F10.
  - F4, F5, F8 and F11 rest on code reading; they need a conductor or are documentation.
- **Not available:**
  - WASM toolchain: `rustup target add wasm32-unknown-unknown` failed twice, so there is no zome build.
  - Holochain conductor and sweettest.
  - Live Roughtime servers (no UDP egress) and a live Unyt network.
  - Repository history: the baseline is a single commit made for this review.

## 5. Final assessment (baseline)

Do not deploy the baseline. Honest oracles can be slashed (F1), dishonest ones can avoid slashing (F2, F7, F9), and one faulty source stops anchoring network-wide (F3). The main remaining assurance gap is that no zome code has run in a conductor. A pass on fixed code would still not be cryptographic certification.

## 6. Remediation

All fixes are in the working tree after `79b5f52`. Statement format v2 (`hc-vtime/oracle-statement/v2`) adds the signed fields `dna` and `floor`. Oracle chains, DNA hashes and Unyt agreements made with v1 statements must be recreated.

| Finding | Fix | Regression tests | Status |
| --- | --- | --- | --- |
| F1 | Signed `dna`. Equivocation needs equal `dna`. `TimePolicy::oracle_dna`, set by the integrity zome to its own DNA hash, rejects other networks (`WrongNetwork`). Release counts only listed `oracle_dnas`. | `review_one_key_in_two_networks_is_not_equivocation`, `review_statements_for_another_network_are_rejected`, `review_bond_does_not_slash_one_key_in_two_networks`, `review_release_counts_only_listed_networks_and_never_confessions` | Fixed |
| F2 | Signed `floor`. The oracle refuses to sign below it (`ClockBehind`). New proofs: `SelfContradiction`, `FloorDropped`. Below-floor statements are never evidence. Bond slashes all four kinds. | `review_backwards_walk_is_caught_within_two_steps`, `review_honest_chains_never_prove_malfeasance` (property), `oracle_proofs_of_each_kind`, `review_bond_slashes_a_backwards_walk` | Fixed |
| F3 | `accept_oracle_response` / `filter_oracle_responses` (answer must come from the oracle asked), `filter_evidence` for Roughtime readings, at most 32 items per set. Rhai skips invalid entries (try/catch around verification) and examines at most 32. | `review_faulty_oracle_answers_are_filtered_out`, `review_faulty_roughtime_replies_are_filtered_out`, `review_release_skips_a_faulty_trusted_oracle`, `review_bond_refund_skips_faulty_witnesses`, `release_handles_a_full_proof_within_engine_limits` | Fixed (core and Rhai); the zome wiring is type-checked only |
| F4 | Windowed descending log lookup. 1 s minimum spacing (`RateLimited`). Read-only `latest_attestation` in the grant; anchors and Unyt proofs fall back to it (at most 60 s old) when an oracle is busy. | `rate_limit`, `lookup_windows_end_with_the_whole_chain` | Mitigated: chain growth bounded at 86,400 actions/day per oracle; seal throughput under spam is limited (Merkle batching is future work) |
| F5 | `is_ancestor` via `must_get_agent_activity(until_hash)`; at most 8 ancestry checks; `author_chain_flagged` reports forks, invalid actions and warrants | none runnable natively | Fixed in code; unverified without a conductor |
| F6 | `unsigned_abs`, checked `f + 1`, `2f + 1` and `12 + len`, saturating width | `extreme_decimals_are_rejected_without_panicking`, `extreme_values_are_rejected_not_wrapped`, `review_huge_fault_bound_is_an_invalid_policy`, `mutated_and_random_inputs_never_panic_or_verify` (30,000 cases) | Fixed |
| F7 | `challenge_period_us` input (7 days in the example). A refund needs `bound ≥ bond_until + challenge_period_us`. | `review_bond_refund_waits_for_the_challenge_period` | Fixed |
| F8 | Policy checks (key, network) before any signature check; seal hashes deduplicated; seals capped at 32 (author's first, then oldest link); anchors capped at 64 (newest first) | `review_policy_checks_run_before_signature_checks` | Fixed in code. The caps are unverified without a conductor. Link spam can push a third party's seal past the cap, which loosens `not_after` but never makes it unsound. |
| F9 | `keys.rs` verifies the `holo_hash` location checksum and builds canonical text. Respelled keys are `Malformed`. | `wrong_location_bytes_are_rejected`, `review_non_canonical_oracle_key_text_is_refused`, `key_text_matches_holo_hash` (256 keys against `holo_hash`) | Fixed |
| F10 | `check()` refuses a key in both lists, counts distinct keys, and refuses `min_sources > 32` | `review_key_in_both_roles_is_an_invalid_policy` | Fixed |
| F11 | README, DESIGN.md §3.1/§4 and the zome docs state "content fixed by U, not publication or uniqueness" and recommend commit–reveal | none (documentation) | Fixed (documentation) |

**Hardening beyond the findings:**
- The coordinator now fails closed when the latest `OracleLog` entry is unreadable. Restarting at seq 0 would look like equivocation.
- Both templates check canonical decimals, signature byte ranges and the `prev`/`floor`/`seq` consistency in Rhai.
- `check_oracle_statements` accepts a single statement.

**How the regression tests show "fails before, passes after":** The tests use v2 statements, which the baseline cannot parse, so running them unchanged on the baseline would fail for the wrong reason. Instead, each runnable finding has a twin proof of concept in the same scenario, run against an exported copy of `f5e257d`. It asserts the defective outcome, and passes there (11/11). Its regression test asserts the opposite and passes on the fixed tree.

**Results after remediation:**
- `cargo test --workspace --offline`: 62 passed. vtime_core: 28 unit, 15 evidence policy, 5 Roughtime interop. Unyt harness: 14.
- `cargo clippy --workspace --all-targets --offline -- -D warnings`: clean.
- The Unyt skill's `check_template.py` finds only its heuristic item-17 warning, which does not apply: the bound is compared to `unlock_time`, not to an amount.

**Re-assessment:**
- **`vtime_core` and both Unyt templates: PASS_WITH_CAVEATS.** Every finding there is fixed and regression-tested.
- **Zome-level fixes (F3 wiring, F4, F5, F8 caps, fail-closed lookup): INCONCLUSIVE.** They type-check against HDK 0.7.1 and HDI 0.8.1 but have never run in a conductor.
- **Before production:**
  - Build the zomes to WASM.
  - Run sweettest scenarios for F4 (spam vs anchors), F5 (forked author) and F8 (link spam).
  - Run one live Unyt execution of each template.

This review, including the re-assessment, was performed by the same agent that wrote the code. An independent review is advisable before real value depends on it.
