/// Subject: Time-locked, multi-tranche release gated on oracle-verified time (hc-vtime)
///
/// Inputs:
/// deposit: consumed ParkedSpendBalance from "grantor_spender" -- the total amount being released.
///   Only read on the first execution.
/// schedule: consumed ParkedData from "grantor" -- { unyt_index, receiver, tranches: [ { unlock_time,
///   amount }, ... ] }, unlock_time in Unix microseconds as a decimal string. Only read on the first
///   execution; carryover replaces it afterwards.
/// time_proof: consumed ParkedData from "time_prover" -- { statements: [ { statement: { dna, domain,
///   earliest, floor, latest, nonce, oracle, prev, seq }, signature: [64 integers] }, ... ] }, as
///   returned by the hc-vtime coordinator's unyt_time_proof(). Required fresh before every execution.
/// oracle_keys: Fixed array of AgentPubKeyB64 strings -- the oracles whose statements count.
/// oracle_dnas: Fixed array of DnaHashB64 strings -- the hc-vtime networks whose statements count.
/// max_faulty: Fixed integer f -- how many of those oracles may lie at once.
/// min_oracles: Fixed integer -- distinct valid statements required, at least f + 1.
/// previous_execution: Custom GetPreviousExecution -- { id, output } of this executor's last run.
///
/// Summary:
/// Same release mechanics as the library's time_locked_vesting example, with one change: "now" is
/// no longer one attestor's claim. Each oracle statement is an Ed25519 signature by a listed oracle
/// over "the time is within [earliest, latest]", checked here with hdi_verify_signature. A statement
/// signed at true time t proves t >= earliest forever after, so an old proof can only understate the
/// time and replaying it never releases anything early. With at most max_faulty lying oracles, the
/// (f+1)-th largest `earliest` among distinct trusted oracles is a lower bound on the current time
/// that no f liars can push forward. Tranches whose unlock_time is at or below that bound are paid;
/// the rest stay locked and carry forward.
///
/// Statement entries are judged one at a time. One that is malformed, from an unlisted oracle or
/// network, below its own chain's floor, or badly signed is skipped, never fatal, so up to f faulty
/// oracles cannot stop a release that the honest ones support. Only statements naming a listed
/// network count, so a statement that counts here always sits on a chain the oracle's bond covers.
/// At most 32 entries are examined. The signatures, not the submitter, carry the trust, so who
/// holds time_prover is a liveness choice, not a security one.

fn latest_payload(input) {
    if type_of(input) == "map" { return input.data; }
    if type_of(input) == "array" && input.len() > 0 { return input[0].data; }
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

// The oracle and `earliest` of a statement entry that counts as evidence, or () if it does not.
fn countable(item, oracle_keys, oracle_dnas) {
    if type_of(item) != "map" || type_of(item.statement) != "map" { return (); }
    let st = item.statement;
    if st.domain != "hc-vtime/oracle-statement/v2" { return (); }
    if type_of(st.oracle) != "string" || !oracle_keys.contains(st.oracle) { return (); }
    if type_of(st.dna) != "string" || !oracle_dnas.contains(st.dna) { return (); }
    if type_of(st.nonce) != "string" || type_of(st.prev) != "string" || type_of(st.floor) != "string" { return (); }
    if !is_canonical_int(st.earliest) || !is_canonical_int(st.latest) { return (); }
    if !is_canonical_int(st.seq) || st.seq.starts_with("-") { return (); }
    let lo = to_num(st.earliest);
    let hi = to_num(st.latest);
    if lo > hi { return (); }
    let genesis = st.seq == "0";
    if genesis != (st.prev == "") || genesis != (st.floor == "") { return (); }
    // A statement below its own chain's floor is a confession, not evidence.
    if !genesis && (!is_canonical_int(st.floor) || hi < to_num(st.floor)) { return (); }
    if !signature_bytes_ok(item.signature) { return (); }
    let ok = false;
    try {
        ok = hdi_verify_signature(st.oracle, item.signature, st);
    } catch {
        ok = false;
    }
    if !ok { return (); }
    #{ "oracle": st.oracle, "earliest": lo }
}

// The (f+1)-th largest `earliest` among valid statements from distinct trusted oracles.
fn proven_time_lower_bound(proof, oracle_keys, oracle_dnas, max_faulty, min_oracles) {
    if type_of(proof) != "map" || type_of(proof.statements) != "array" {
        throw "time_proof must be a map with a statements array";
    }
    if type_of(oracle_keys) != "array" || type_of(oracle_dnas) != "array" {
        throw "oracle_keys and oracle_dnas must be arrays";
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
        throw "need " + min_oracles + " valid statements from distinct trusted oracles, have " + lows.len();
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
    #{ "bound": bound, "counted": lows.len() }
}

let is_first_execution = true;
let unyt_index = ();
let receiver = ();
let remaining_tranches = [];
let sources = [];

if type_of(inputs.previous_execution.data) == "map" {
    is_first_execution = false;
    let prev = inputs.previous_execution.data;
    let carryover = prev.output.carryover ?? #{};
    if type_of(carryover) != "map" || type_of(carryover.unyt_index) != "string"
        || type_of(carryover.receiver) != "string" || type_of(carryover.remaining_tranches) != "array" {
        throw "Invalid carryover from previous execution: missing unyt_index, receiver or remaining_tranches";
    }
    unyt_index = carryover.unyt_index;
    receiver = carryover.receiver;
    remaining_tranches = carryover.remaining_tranches;

    let locked = prev.output.locked ?? #{};
    let carried_amount = locked[unyt_index] ?? "0";
    if to_num(carried_amount) > 0.0 {
        sources.push(prev.id);
    }
} else {
    let deposit = latest_payload(consumed_inputs.deposit);
    if type_of(deposit) == "()" {
        throw "No grantor deposit has been parked yet";
    }
    let schedule = latest_payload(consumed_inputs.schedule);
    if type_of(schedule) == "()" {
        throw "No release schedule has been parked yet";
    }
    if type_of(schedule.unyt_index) != "string" || type_of(schedule.receiver) != "string"
        || type_of(schedule.tranches) != "array" {
        throw "Invalid schedule: needs unyt_index, receiver and tranches";
    }
    unyt_index = schedule.unyt_index;
    receiver = schedule.receiver;
    remaining_tranches = schedule.tranches;
    sources.push(deposit.source);

    if !deposit.amount.contains(unyt_index) {
        throw "Deposit does not cover unyt_index " + unyt_index;
    }
    let schedule_total = "0";
    for tranche in remaining_tranches {
        if type_of(tranche.amount) != "string" || type_of(tranche.unlock_time) != "string" {
            throw "Invalid schedule: every tranche needs string amount and unlock_time";
        }
        schedule_total = add_fuel(schedule_total, tranche.amount);
    }
    let deposit_amount = deposit.amount[unyt_index];
    if !(is_greater_than_eq(schedule_total, deposit_amount) && is_greater_than_eq(deposit_amount, schedule_total)) {
        throw "Release schedule totals " + schedule_total + " but the deposit is " + deposit_amount;
    }
}

if remaining_tranches.len() == 0 {
    throw "Nothing left to release: the schedule is empty or fully released";
}

let proof = latest_payload(consumed_inputs.time_proof);
if type_of(proof) == "()" {
    throw "No time proof has been parked yet";
}
let proven = proven_time_lower_bound(
    proof,
    inputs.oracle_keys.data,
    inputs.oracle_dnas.data,
    inputs.max_faulty.data,
    inputs.min_oracles.data
);
let now_lower = proven.bound;

let released = "0";
let still_locked = [];
for tranche in remaining_tranches {
    if to_num(tranche.unlock_time) <= now_lower {
        released = add_fuel(released, tranche.amount);
    } else {
        still_locked.push(tranche);
    }
}

let allocation = [];
if to_num(released) > 0.0 {
    let amt = #{};
    amt[unyt_index] = released;
    allocation.push(#{ "receiver": receiver, "amounts": amt, "sources": sources });
} else if is_first_execution {
    // Pure hold of the fresh deposit: empty amounts, never a zero amount.
    allocation.push(#{ "receiver": receiver, "amounts": #{}, "sources": sources });
}

let remaining_amount = "0";
for tranche in still_locked {
    remaining_amount = add_fuel(remaining_amount, tranche.amount);
}

let output = #{ "unyt_allocation": allocation };
if to_num(remaining_amount) > 0.0 {
    let locked = #{};
    locked[unyt_index] = remaining_amount;
    output.locked = locked;
    output.carryover = #{
        "unyt_index": unyt_index,
        "receiver": receiver,
        "remaining_tranches": still_locked
    };
}

output.computed_values = #{
    "unyt_index": unyt_index,
    "receiver": receiver,
    "proven_time_lower_bound_us": now_lower,
    "oracles_counted": proven.counted,
    "released_this_execution": released,
    "remaining_locked": remaining_amount,
    "tranches_remaining": still_locked.len(),
    "fully_released": to_num(remaining_amount) == 0.0
};

return #{ "output": output };
