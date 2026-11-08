/// Subject: Bond a Holochain time oracle forfeits if it signs contradictory time statements (hc-vtime)
///
/// Inputs:
/// bond: consumed ParkedSpendBalance from "bond_oracle_spender" -- the oracle's bond.
/// bonded_oracle: Fixed AgentPubKeyB64 of the bonded oracle.
/// unyt_index: Fixed unit index string of the bond.
/// reporter_reward: Fixed amount string paid to whoever proves misbehaviour (at most the bond).
/// slash_beneficiary: Fixed AgentPubKeyB64 that receives the rest of a slashed bond.
/// bond_until: Fixed Unix microseconds (decimal string): the end of the bond term.
/// challenge_period_us: Fixed microseconds (decimal string) after bond_until during which the bond
///   can still be slashed but not refunded, so a lie told near the end of the term can be reported.
/// witness_oracles: Fixed array of other oracles' AgentPubKeyB64, used to prove the term has passed.
/// oracle_dnas: Fixed array of DnaHashB64: the hc-vtime networks whose witness statements count.
/// max_faulty: Fixed integer f for that proof.
/// min_oracles: Fixed integer, distinct witness statements required (at least f + 1).
/// claim: ExecutorProvided -- either { kind: "slash", a: <statement entry>, b: <statement entry,
///   optional> } or { kind: "refund", time_proof: { statements: [ <statement entry>, ... ] } }, where
///   a statement entry is { statement: { dna, domain, earliest, floor, latest, nonce, oracle, prev,
///   seq }, signature: [64 ints] }.
///
/// Summary:
/// An hc-vtime oracle keeps one statement chain per network (dna): seq goes up by one, prev holds the
/// hex of the previous signature, and floor holds the largest earliest signed before on that chain.
/// Statements the oracle signed itself prove it lied when:
///   - self-contradiction (one statement): latest < floor -- it says the time is at most latest after
///     its own chain showed the time reached floor;
///   - time reversal (chained pair): b.prev is a's signature (b was signed after a existed), yet
///     b.latest < a.earliest;
///   - floor dropped (chained pair): b.floor < max(a.floor, a.earliest);
///   - equivocation (pair): a and b differ but share dna, seq and prev -- a fork of one chain.
/// Together these make any backwards step of the oracle's clock provable from at most two statements.
/// Equivocation needs the same dna because one key may honestly serve several networks, each with its
/// own chain starting at seq 0. The other proofs are contradictions inside one chain, so they count
/// in any network: an honest oracle never signs them anywhere.
/// "slash" verifies the statements against bonded_oracle and checks these conditions. If proven,
/// reporter_reward goes to the executor and the rest to slash_beneficiary, not to the reporter, so an
/// oracle reporting itself through a sock puppet recovers at most the reward.
/// "refund" lets the bonded oracle (and only it) reclaim the bond once statements from witness_oracles
/// in oracle_dnas prove the time is past bond_until + challenge_period_us, using the same
/// (f+1)-th-largest lower bound as verified_time_release. The bonded oracle may not witness for itself.
/// Anything else throws, so nothing is consumed and the bond stays parked.

fn latest_envelope(input) {
    if type_of(input) == "map" { return input; }
    if type_of(input) == "array" && input.len() > 0 { return input[0]; }
    ()
}

// Canonical decimal as hc-vtime signs it: optional '-', no '+', no leading zeros, |v| < 2^53.
fn is_canonical_int(s) {
    if type_of(s) != "string" { return false; }
    let neg = s.starts_with("-");
    let body = s;
    if neg { body = s.sub_string(1); }
    if body.len() == 0 || body.len() > 16 { return false; }
    if body.len() > 1 && body.starts_with("0") { return false; }
    if neg && body == "0" { return false; }
    for ch in body {
        if ch < '0' || ch > '9' { return false; }
    }
    let v = to_num(s);
    v > -9007199254740992.0 && v < 9007199254740992.0
}

fn signature_bytes_ok(sig) {
    if type_of(sig) != "array" || sig.len() != 64 { return false; }
    for b in sig {
        if type_of(b) != "i64" || b < 0 || b > 255 { return false; }
    }
    true
}

fn sig_hex(sig) {
    let digits = "0123456789abcdef";
    let out = "";
    for b in sig {
        out += digits[b >> 4];
        out += digits[b & 15];
    }
    out
}

// Check the form shared by evidence and proofs: domain, canonical numbers, and prev/floor present
// exactly when seq is not 0. Returns an error message, or "" when the form is valid.
fn form_error(st) {
    if st.domain != "hc-vtime/oracle-statement/v2" { return "statement has an unexpected domain"; }
    if type_of(st.dna) != "string" || st.dna == "" { return "statement has no dna"; }
    if type_of(st.nonce) != "string" || type_of(st.prev) != "string" || type_of(st.floor) != "string" {
        return "statement nonce, prev and floor must be strings";
    }
    if !is_canonical_int(st.earliest) || !is_canonical_int(st.latest) {
        return "statement times are not canonical decimals";
    }
    if !is_canonical_int(st.seq) || st.seq.starts_with("-") { return "statement seq is not canonical"; }
    if to_num(st.earliest) > to_num(st.latest) { return "statement interval is inverted"; }
    let genesis = st.seq == "0";
    if genesis != (st.prev == "") || genesis != (st.floor == "") {
        return "prev and floor must be empty exactly when seq is 0";
    }
    if !genesis && !is_canonical_int(st.floor) { return "statement floor is not canonical"; }
    ""
}

// A statement entry offered as proof: it must be well formed and signed by `oracle`. Throws otherwise,
// because a slash claim built on a statement that is not genuine proves nothing.
fn proof_statement(entry, oracle) {
    if type_of(entry) != "map" || type_of(entry.statement) != "map" {
        throw "a statement entry needs a statement map and a signature array";
    }
    let st = entry.statement;
    if st.oracle != oracle {
        throw "statement was not signed by the expected oracle";
    }
    let err = form_error(st);
    if err != "" { throw err; }
    if !signature_bytes_ok(entry.signature) {
        throw "oracle signature must be 64 integers from 0 to 255";
    }
    if !hdi_verify_signature(oracle, entry.signature, st) {
        throw "oracle signature does not verify";
    }
    st
}

fn self_contradictory(st) {
    st.floor != "" && to_num(st.latest) < to_num(st.floor)
}

// What a statement chained directly after `earlier` (whose signature hex is `sig_earlier`) proves.
fn chained_violation(earlier, sig_earlier, later) {
    if later.prev != sig_earlier { return ""; }
    if to_num(later.latest) < to_num(earlier.earliest) { return "time reversal"; }
    let carried = to_num(earlier.earliest);
    if earlier.floor != "" && to_num(earlier.floor) > carried { carried = to_num(earlier.floor); }
    if later.floor == "" || to_num(later.floor) < carried { return "floor dropped"; }
    ""
}

// The oracle and `earliest` of a witness statement that counts, or () if it does not. Invalid
// entries are skipped, never fatal, so one faulty witness cannot block a refund.
fn countable(item, oracle_keys, oracle_dnas) {
    if type_of(item) != "map" || type_of(item.statement) != "map" { return (); }
    let st = item.statement;
    if type_of(st.oracle) != "string" || !oracle_keys.contains(st.oracle) { return (); }
    if type_of(st.dna) != "string" || !oracle_dnas.contains(st.dna) { return (); }
    if form_error(st) != "" || self_contradictory(st) { return (); }
    if !signature_bytes_ok(item.signature) { return (); }
    let ok = false;
    try {
        ok = hdi_verify_signature(st.oracle, item.signature, st);
    } catch {
        ok = false;
    }
    if !ok { return (); }
    #{ "oracle": st.oracle, "earliest": to_num(st.earliest) }
}

fn proven_time_lower_bound(proof, oracle_keys, oracle_dnas, max_faulty, min_oracles) {
    if type_of(proof) != "map" || type_of(proof.statements) != "array" {
        throw "time_proof must be a map with a statements array";
    }
    if type_of(oracle_keys) != "array" || type_of(oracle_dnas) != "array" {
        throw "witness_oracles and oracle_dnas must be arrays";
    }
    if type_of(max_faulty) != "i64" || type_of(min_oracles) != "i64" || max_faulty < 0 || min_oracles < max_faulty + 1 {
        throw "min_oracles must be at least max_faulty + 1";
    }
    let seen = [];
    let lows = [];
    let examined = 0;
    for item in proof.statements {
        if examined == 32 { break; }
        examined += 1;
        let c = countable(item, oracle_keys, oracle_dnas);
        if type_of(c) == "()" || seen.contains(c.oracle) { continue; }
        seen.push(c.oracle);
        lows.push(c.earliest);
    }
    if lows.len() < min_oracles {
        throw "need " + min_oracles + " valid witness statements, have " + lows.len();
    }
    let bound = ();
    for v in lows {
        let greater = 0;
        let at_least = 0;
        for w in lows {
            if w > v { greater += 1; }
            if w >= v { at_least += 1; }
        }
        if greater <= max_faulty && at_least >= max_faulty + 1 {
            bound = v;
            break;
        }
    }
    if type_of(bound) == "()" {
        throw "could not compute a robust time bound";
    }
    bound
}

let bonded_oracle = inputs.bonded_oracle.data;
let unyt_index = inputs.unyt_index.data;

let bond_env = latest_envelope(consumed_inputs.bond);
if type_of(bond_env) == "()" || type_of(bond_env.data) != "map" {
    throw "No bond has been parked yet";
}
let bond = bond_env.data;
if get_spend_links_author(bond_env.link_hash) != bonded_oracle {
    throw "The parked bond was not posted by the bonded oracle";
}
let amount = bond.amount[unyt_index] ?? "";
if type_of(amount) != "string" || amount == "" || !(to_num(amount) > 0.0) {
    throw "The bond holds nothing at unyt_index " + unyt_index;
}

let claim = inputs.claim.data;
if type_of(claim) != "map" || type_of(claim.kind) != "string" {
    throw "claim must be a map with a kind";
}

let allocation = [];
let outcome = "";
let proven_time = 0.0;

if claim.kind == "slash" {
    let a = proof_statement(claim.a, bonded_oracle);
    if self_contradictory(a) {
        outcome = "slashed: self-contradiction";
    } else if type_of(claim.b) == "map" {
        let b = proof_statement(claim.b, bonded_oracle);
        if self_contradictory(b) {
            outcome = "slashed: self-contradiction";
        } else {
            let kind = chained_violation(a, sig_hex(claim.a.signature), b);
            if kind == "" {
                kind = chained_violation(b, sig_hex(claim.b.signature), a);
            }
            if kind != "" {
                outcome = "slashed: " + kind;
            } else {
                let differs = a.earliest != b.earliest || a.latest != b.latest || a.nonce != b.nonce
                    || a.floor != b.floor;
                if a.dna == b.dna && a.seq == b.seq && a.prev == b.prev && differs {
                    outcome = "slashed: equivocation";
                }
            }
        }
    }
    if outcome == "" {
        throw "The statements do not prove misbehaviour";
    }

    let reward = inputs.reporter_reward.data;
    if !is_greater_than_eq(amount, reward) {
        throw "reporter_reward " + reward + " exceeds the bond " + amount;
    }
    if to_num(reward) > 0.0 {
        let r = #{};
        r[unyt_index] = reward;
        allocation.push(#{ "receiver": executor_pub_key, "amounts": r, "sources": [bond.source] });
    }
    let rest = sub_fuel(amount, reward);
    if to_num(rest) > 0.0 {
        let s = #{};
        s[unyt_index] = rest;
        allocation.push(#{ "receiver": inputs.slash_beneficiary.data, "amounts": s, "sources": [bond.source] });
    }
} else if claim.kind == "refund" {
    if executor_pub_key != bonded_oracle {
        throw "Only the bonded oracle may reclaim its bond";
    }
    let witnesses = inputs.witness_oracles.data;
    if witnesses.contains(bonded_oracle) {
        throw "The bonded oracle cannot witness its own refund";
    }
    // (`until` is a reserved word in Rhai.)
    let term_end = inputs.bond_until.data;
    let challenge = inputs.challenge_period_us.data;
    if !is_canonical_int(term_end) || term_end.starts_with("-") || !is_canonical_int(challenge) || challenge.starts_with("-") {
        throw "bond_until and challenge_period_us must be non-negative decimal strings";
    }
    proven_time = proven_time_lower_bound(
        claim.time_proof,
        witnesses,
        inputs.oracle_dnas.data,
        inputs.max_faulty.data,
        inputs.min_oracles.data
    );
    if proven_time < to_num(term_end) + to_num(challenge) {
        throw "The bond term and its challenge period have not provably ended";
    }
    let r = #{};
    r[unyt_index] = amount;
    allocation.push(#{ "receiver": bonded_oracle, "amounts": r, "sources": [bond.source] });
    outcome = "refunded";
} else {
    throw "claim.kind must be slash or refund";
}

return #{
    "output": #{
        "unyt_allocation": allocation,
        "computed_values": #{
            "outcome": outcome,
            "bonded_oracle": bonded_oracle,
            "bond_amount": amount,
            "proven_time_lower_bound_us": proven_time
        }
    }
};
