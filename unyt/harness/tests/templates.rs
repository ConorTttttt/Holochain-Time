//! Executes the two Unyt templates with the published `rave_engine` 0.15.0
//! (the same HDK 0.7.1 / HDI 0.8.1 line as hc-vtime). Oracle statements are
//! signed exactly as the hc-vtime coordinator signs them; the mocked host
//! verifies Ed25519 over whatever bytes `hdi_verify_signature` hands it. So
//! these tests check the cross-system claim the templates rely on: a
//! statement signed by an oracle verifies after travelling through Unyt's
//! JSON -> Rhai -> JSON -> MessagePack path.
//!
//! Tests named `review_*` are regression tests for SECURITY_REVIEW.md; each
//! fails against the baseline templates.

use ed25519_dalek::{Signer, SigningKey};
use hdk::prelude::*;
use rave_engine::prelude::{PresetVariables, RhaiEngine};
use serde_json::{json, Value};

use vtime_core::keys::{agent_key_to_b64, dna_hash_to_b64};
use vtime_core::{ChainLink, DalekVerifier, Ed25519Verifier, OracleTimeStatement, SignedOracleStatement, TimeInterval};

const HOUR_US: i64 = 3_600_000_000;
const NOW_US: i64 = 1_792_000_000_000_000;
const R: i64 = 1_000_000;

fn install_verifying_host() {
    let mut mock = MockHdkT::new();
    mock.expect_verify_signature().returning(|vs: VerifySignature| {
        let pk: [u8; 32] = vs.key.get_raw_32().try_into().unwrap();
        Ok(DalekVerifier.verify(&pk, &vs.data, &vs.signature.0).unwrap())
    });
    set_hdk(mock);
}

fn dna(n: u8) -> String {
    DnaHash::from_raw_32(vec![n; 32]).to_string()
}

/// One oracle key's statement chain in one network.
struct Oracle {
    key: SigningKey,
    dna: String,
    last: Option<SignedOracleStatement>,
}

impl Oracle {
    fn new(seed: u8) -> Self {
        Self::in_network(seed, dna(1))
    }
    fn in_network(seed: u8, dna: String) -> Self {
        Self { key: SigningKey::from_bytes(&[seed; 32]), dna, last: None }
    }
    fn b64(&self) -> String {
        AgentPubKey::from_raw_32(self.key.verifying_key().to_bytes().to_vec()).to_string()
    }
    fn next_link(&self) -> ChainLink {
        self.last.as_ref().map(|l| ChainLink::after(l).unwrap()).unwrap_or_else(ChainLink::genesis)
    }
    /// A statement entry exactly as `unyt_time_proof` exports it, carrying
    /// the floor forward (a liar can still sign below it).
    fn attest(&mut self, earliest: i64, latest: i64) -> Value {
        let link = self.next_link();
        self.sign_at(earliest, latest, link)
    }
    /// Sign at an explicit chain position, as a modified oracle could.
    fn sign_at(&mut self, earliest: i64, latest: i64, link: ChainLink) -> Value {
        let st = OracleTimeStatement::new(
            self.b64(),
            self.dna.clone(),
            &[link.seq as u8; 32],
            TimeInterval::new(earliest, latest).unwrap(),
            link,
        );
        let sig = self.key.sign(&st.signing_bytes().unwrap()).to_bytes();
        let signed = SignedOracleStatement { statement: st, signature: sig.to_vec() };
        self.last = Some(signed.clone());
        json!({ "statement": signed.statement, "signature": signed.signature })
    }
}

fn hash(n: u8) -> String {
    ActionHash::from_raw_32(vec![n; 32]).to_string()
}

fn agent(n: u8) -> AgentPubKey {
    AgentPubKey::from_raw_32(vec![n; 32])
}

fn run(script_path: &str, input: Value, executor: &AgentPubKey) -> ExternResult<Value> {
    run_source(std::fs::read_to_string(script_path).unwrap(), input, executor)
}

fn run_source(source: String, input: Value, executor: &AgentPubKey) -> ExternResult<Value> {
    install_verifying_host();
    let code = rmp_serde::to_vec(&source).unwrap();
    let preset = PresetVariables {
        ea_id: ActionHash::from_raw_32(vec![200; 32]),
        executor: executor.clone(),
        executed_timestamp: Timestamp::from_micros(NOW_US),
    };
    let out = RhaiEngine::new().execute(&input, code, Some(preset))?;
    Ok(serde_json::to_value(&out.output).unwrap())
}

fn err_text(r: ExternResult<Value>) -> String {
    format!("{:?}", r.expect_err("expected the execution to fail"))
}

const RELEASE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../verified_time_release/execution_code.rhai");
const BOND: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../time_oracle_bond/execution_code.rhai");

fn release_input_f(statements: Vec<Value>, oracle_keys: Vec<String>, previous: Value, f: i64, min: i64) -> Value {
    let beneficiary = agent(77).to_string();
    let mut consumed = json!({
        "time_proof": { "data": { "statements": statements }, "link_hash": hash(3) }
    });
    if previous.is_null() {
        consumed["deposit"] = json!({ "data": { "amount": { "0": "300" }, "source": hash(1) }, "link_hash": hash(1) });
        consumed["schedule"] = json!({ "data": {
            "unyt_index": "0",
            "receiver": beneficiary,
            "tranches": [
                { "unlock_time": (NOW_US - HOUR_US).to_string(), "amount": "100" },
                { "unlock_time": (NOW_US + HOUR_US).to_string(), "amount": "100" },
                { "unlock_time": (NOW_US + 2 * HOUR_US).to_string(), "amount": "100" }
            ]
        }, "link_hash": hash(2) });
    }
    json!({
        "consumed_inputs": consumed,
        "inputs": {
            "previous_execution": { "data": previous },
            "oracle_keys": { "data": oracle_keys },
            "oracle_dnas": { "data": [dna(1)] },
            "max_faulty": { "data": f },
            "min_oracles": { "data": min }
        }
    })
}

fn release_input(statements: Vec<Value>, oracle_keys: Vec<String>, previous: Value) -> Value {
    release_input_f(statements, oracle_keys, previous, 1, 2)
}

fn allocations(out: &Value) -> Vec<(String, String)> {
    out["unyt_allocation"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            let amt = a["amounts"].get("0").and_then(|v| v.as_str()).unwrap_or("").to_string();
            (a["receiver"].as_str().unwrap().to_string(), amt)
        })
        .collect()
}

/// The checksum code in vtime_core::keys must agree with holo_hash exactly,
/// or honest oracles' statements would be refused (or respelled ones
/// accepted). Checked here because this crate links holo_hash.
#[test]
fn key_text_matches_holo_hash() {
    for seed in 0u8..=255 {
        let core: [u8; 32] = std::array::from_fn(|i| seed.wrapping_mul(31).wrapping_add(i as u8));
        assert_eq!(agent_key_to_b64(&core), AgentPubKey::from_raw_32(core.to_vec()).to_string());
        assert_eq!(dna_hash_to_b64(&core), DnaHash::from_raw_32(core.to_vec()).to_string());
        let parsed = vtime_core::keys::agent_key_from_b64(&AgentPubKey::from_raw_32(core.to_vec()).to_string());
        assert_eq!(parsed.unwrap(), core);
    }
}

#[test]
fn release_pays_only_tranches_the_honest_quorum_proves() {
    let mut a = Oracle::new(1);
    let mut b = Oracle::new(2);
    let mut liar = Oracle::new(3);
    let keys = vec![a.b64(), b.b64(), liar.b64()];
    let statements = vec![
        a.attest(NOW_US - 1_000_000, NOW_US + 1_000_000),
        b.attest(NOW_US - 500_000, NOW_US + 1_500_000),
        // Claims it is three hours later, which would release everything.
        liar.attest(NOW_US + 3 * HOUR_US, NOW_US + 3 * HOUR_US + 1_000_000),
    ];
    let out = run(RELEASE, release_input(statements, keys, Value::Null), &agent(77)).expect("runs");
    assert_eq!(allocations(&out), vec![(agent(77).to_string(), "100".to_string())]);
    assert_eq!(out["locked"]["0"], "200");
    let cv = &out["computed_values"];
    assert_eq!(cv["oracles_counted"], 3);
    // The liar is outvoted: the bound is b's lower edge, not the liar's.
    assert_eq!(cv["proven_time_lower_bound_us"].as_f64().unwrap(), (NOW_US - 500_000) as f64);
}

#[test]
fn release_carries_forward_and_releases_later_tranches() {
    let mut a = Oracle::new(1);
    let mut b = Oracle::new(2);
    let keys = vec![a.b64(), b.b64()];
    let first = run(
        RELEASE,
        release_input(
            vec![a.attest(NOW_US - 1_000_000, NOW_US + 1_000_000), b.attest(NOW_US, NOW_US + 1_000_000)],
            keys.clone(),
            Value::Null,
        ),
        &agent(77),
    )
    .unwrap();
    let previous = json!({ "id": hash(9), "output": first });
    let later = NOW_US + 90 * 60 * 1_000_000; // 90 minutes later
    let second = run(
        RELEASE,
        release_input(
            vec![a.attest(later, later + 1_000_000), b.attest(later - 1_000_000, later + 1_000_000)],
            keys,
            previous,
        ),
        &agent(77),
    )
    .unwrap();
    assert_eq!(allocations(&second), vec![(agent(77).to_string(), "100".to_string())]);
    assert_eq!(second["locked"]["0"], "100");
    assert_eq!(second["computed_values"]["tranches_remaining"], 1);
}

#[test]
fn release_refuses_tampered_duplicate_and_untrusted_proofs() {
    let mut a = Oracle::new(1);
    let mut b = Oracle::new(2);
    let mut stranger = Oracle::new(9);
    let keys = vec![a.b64(), b.b64()];

    // Tampered: someone moves an honest statement three hours forward. It no
    // longer counts, leaving one valid statement.
    let mut forged = a.attest(NOW_US, NOW_US + 1);
    forged["statement"]["earliest"] = json!((NOW_US + 3 * HOUR_US).to_string());
    forged["statement"]["latest"] = json!((NOW_US + 3 * HOUR_US + 1).to_string());
    let e = err_text(run(RELEASE, release_input(vec![forged, b.attest(NOW_US, NOW_US + 1)], keys.clone(), Value::Null), &agent(77)));
    assert!(e.contains("need 2"), "{e}");

    // One oracle twice does not make a quorum of two.
    let e = err_text(run(
        RELEASE,
        release_input(vec![a.attest(NOW_US, NOW_US + 1), a.attest(NOW_US, NOW_US + 2)], keys.clone(), Value::Null),
        &agent(77),
    ));
    assert!(e.contains("need 2"), "{e}");

    // An untrusted oracle is ignored, leaving one valid statement.
    let e = err_text(run(
        RELEASE,
        release_input(vec![a.attest(NOW_US, NOW_US + 1), stranger.attest(NOW_US, NOW_US + 1)], keys, Value::Null),
        &agent(77),
    ));
    assert!(e.contains("need 2"), "{e}");
}

/// Regression (review P2, faulty oracle): a listed oracle's bad entry is
/// skipped. The baseline threw on the first trusted statement whose signature
/// failed, so one faulty oracle stopped every release it appeared in.
#[test]
fn review_release_skips_a_faulty_trusted_oracle() {
    let mut a = Oracle::new(1);
    let mut b = Oracle::new(2);
    let mut faulty = Oracle::new(3);
    let keys = vec![a.b64(), b.b64(), faulty.b64()];
    let mut bad_sig = faulty.attest(NOW_US, NOW_US + 1);
    bad_sig["signature"][0] = json!(bad_sig["signature"][0].as_u64().unwrap() ^ 1);
    let mut short_sig = faulty.attest(NOW_US, NOW_US + 1);
    short_sig["signature"].as_array_mut().unwrap().pop();
    let mut garbage = faulty.attest(NOW_US, NOW_US + 1);
    garbage["statement"]["earliest"] = json!("1e300");
    let statements = vec![
        bad_sig,
        short_sig,
        garbage,
        json!({ "statement": "not a map", "signature": [] }),
        a.attest(NOW_US - R, NOW_US + R),
        b.attest(NOW_US - R, NOW_US + R),
    ];
    let out = run(RELEASE, release_input(statements, keys, Value::Null), &agent(77)).expect("honest quorum releases");
    assert_eq!(allocations(&out), vec![(agent(77).to_string(), "100".to_string())]);
    assert_eq!(out["computed_values"]["oracles_counted"], 2);
}

/// Regression (review P1 and P2): only statements on a listed network count,
/// and a statement below its own chain's floor is a confession, not evidence.
#[test]
fn review_release_counts_only_listed_networks_and_never_confessions() {
    let mut a = Oracle::new(1);
    let mut b_elsewhere = Oracle::in_network(2, dna(2));
    let mut c = Oracle::new(3);
    let keys = vec![a.b64(), b_elsewhere.b64(), c.b64()];
    c.attest(NOW_US + 3 * HOUR_US, NOW_US + 3 * HOUR_US + R);
    // Chained after a forward lie, with the floor carried: latest < floor.
    let confession = c.attest(NOW_US - R, NOW_US + R);
    let statements = vec![
        b_elsewhere.attest(NOW_US + 3 * HOUR_US, NOW_US + 3 * HOUR_US + R),
        confession,
        a.attest(NOW_US - R, NOW_US + R),
    ];
    let e = err_text(run(RELEASE, release_input(statements, keys, Value::Null), &agent(77)));
    assert!(e.contains("need 2") && e.contains("have 1"), "{e}");
}

/// The template examines at most 32 entries and stays inside the engine's
/// operation and host-call budgets with a full proof.
#[test]
fn release_handles_a_full_proof_within_engine_limits() {
    let mut oracles: Vec<Oracle> = (1..=40).map(Oracle::new).collect();
    let keys: Vec<String> = oracles.iter().map(|o| o.b64()).collect();
    let statements: Vec<Value> = oracles.iter_mut().map(|o| o.attest(NOW_US - R, NOW_US + R)).collect();
    let out = run(RELEASE, release_input_f(statements, keys, Value::Null, 10, 11), &agent(77)).expect("runs");
    assert_eq!(out["computed_values"]["oracles_counted"], 32, "only 32 entries are examined");
}

// --- time_oracle_bond -------------------------------------------------------

/// `get_spend_links_author` reads a parked-link record from the DHT. The test
/// shadows it with a script function returning the bonded oracle; every other
/// line of the template runs unchanged.
fn bond_source(bond_author: &str) -> String {
    format!(
        "fn get_spend_links_author(h) {{ \"{bond_author}\" }}\n{}",
        std::fs::read_to_string(BOND).unwrap()
    )
}

const CHALLENGE_US: i64 = 7 * 24 * HOUR_US;

fn bond_input(oracle: &Oracle, witnesses: Vec<String>, claim: Value) -> Value {
    json!({
        "consumed_inputs": {
            "bond": { "data": { "amount": { "0": "500" }, "source": hash(5) }, "link_hash": hash(5) }
        },
        "inputs": {
            "bonded_oracle": { "data": oracle.b64() },
            "unyt_index": { "data": "0" },
            "reporter_reward": { "data": "50" },
            "slash_beneficiary": { "data": agent(88).to_string() },
            "bond_until": { "data": NOW_US.to_string() },
            "challenge_period_us": { "data": CHALLENGE_US.to_string() },
            "witness_oracles": { "data": witnesses },
            "oracle_dnas": { "data": [dna(1)] },
            "max_faulty": { "data": 1 },
            "min_oracles": { "data": 2 },
            "claim": { "data": claim }
        }
    })
}

fn slash(o: &Oracle, a: &Value, b: Option<&Value>) -> ExternResult<Value> {
    let claim = match b {
        Some(b) => json!({ "kind": "slash", "a": a, "b": b }),
        None => json!({ "kind": "slash", "a": a }),
    };
    run_source(bond_source(&o.b64()), bond_input(o, vec![], claim), &agent(61))
}

#[test]
fn bond_is_slashed_for_time_reversal() {
    let mut o = Oracle::new(4);
    let first = o.attest(NOW_US, NOW_US + 1_000_000);
    // A modified oracle that drops its floor and reports an hour earlier.
    let mut link = o.next_link();
    link.floor = Some(NOW_US - 2 * HOUR_US);
    let reversed = o.sign_at(NOW_US - HOUR_US, NOW_US - HOUR_US + 1_000_000, link);
    let out = slash(&o, &first, Some(&reversed)).expect("slash runs");
    assert_eq!(
        allocations(&out),
        vec![(agent(61).to_string(), "50".to_string()), (agent(88).to_string(), "450".to_string())]
    );
    assert_eq!(out["computed_values"]["outcome"], "slashed: time reversal");
    // Order does not matter.
    let out = slash(&o, &reversed, Some(&first)).unwrap();
    assert_eq!(out["computed_values"]["outcome"], "slashed: time reversal");
}

#[test]
fn bond_is_slashed_for_equivocation_but_not_for_honest_statements() {
    let mut o = Oracle::new(4);
    let genesis = o.attest(NOW_US, NOW_US + 1);
    let mut fork = Oracle::new(4);
    fork.last = o.last.clone();
    let one = o.attest(NOW_US + 10, NOW_US + 20);
    let other = fork.attest(NOW_US + 30, NOW_US + 40);
    let out = slash(&o, &one, Some(&other)).unwrap();
    assert_eq!(out["computed_values"]["outcome"], "slashed: equivocation");

    let next = o.attest(NOW_US + 50, NOW_US + 60);
    for (x, y) in [(&genesis, &next), (&genesis, &one), (&one, &next)] {
        let e = err_text(slash(&o, x, Some(y)));
        assert!(e.contains("do not prove misbehaviour"), "{e}");
    }
    let e = err_text(slash(&o, &next, None));
    assert!(e.contains("do not prove misbehaviour"), "{e}");
}

/// Regression (review P1): one key serving two networks keeps two chains,
/// both starting at seq 0, and that is not equivocation. The baseline slashed
/// the honest oracle here.
#[test]
fn review_bond_does_not_slash_one_key_in_two_networks() {
    let mut cell_a = Oracle::in_network(4, dna(1));
    let mut cell_b = Oracle::in_network(4, dna(2));
    let a = cell_a.attest(NOW_US - R, NOW_US + R);
    let b = cell_b.attest(NOW_US + 10 * R, NOW_US + 12 * R);
    assert_eq!(a["statement"]["seq"], b["statement"]["seq"]);
    let e = err_text(slash(&cell_a, &a, Some(&b)));
    assert!(e.contains("do not prove misbehaviour"), "{e}");

    // A real fork in one network still is equivocation.
    let mut fork = Oracle::in_network(4, dna(1));
    let f = fork.attest(NOW_US + 30 * R, NOW_US + 31 * R);
    let out = slash(&cell_a, &a, Some(&f)).unwrap();
    assert_eq!(out["computed_values"]["outcome"], "slashed: equivocation");
}

/// Regression (review P2, backwards walk): the baseline could not slash a
/// clock walked back 2r per statement (every adjacent pair consistent). Now
/// the second step is provable, whether the oracle carries its floor or not.
#[test]
fn review_bond_slashes_a_backwards_walk() {
    let mut o = Oracle::new(7);
    let a = o.attest(NOW_US - R, NOW_US + R);
    let b = o.attest(NOW_US - 3 * R, NOW_US - R);
    let e = err_text(slash(&o, &a, Some(&b)));
    assert!(e.contains("do not prove misbehaviour"), "one step of 2r is within tolerance: {e}");
    let c = o.attest(NOW_US - 5 * R, NOW_US - 3 * R);
    let out = slash(&o, &c, None).expect("one statement suffices");
    assert_eq!(out["computed_values"]["outcome"], "slashed: self-contradiction");

    // Dropping the floor instead: provable from the adjacent pair.
    let mut o2 = Oracle::new(7);
    o2.last = Some(serde_json::from_value(json!({
        "statement": b["statement"], "signature": b["signature"]
    })).unwrap());
    let mut link = o2.next_link();
    link.floor = Some(NOW_US - 3 * R);
    let c2 = o2.sign_at(NOW_US - 5 * R, NOW_US - 3 * R, link);
    let e = err_text(slash(&o2, &c2, None));
    assert!(e.contains("do not prove misbehaviour"), "{e}");
    let out = slash(&o2, &b, Some(&c2)).unwrap();
    assert_eq!(out["computed_values"]["outcome"], "slashed: floor dropped");
}

#[test]
fn bond_refuses_forged_or_foreign_proofs() {
    let mut o = Oracle::new(4);
    let mut other = Oracle::new(5);
    let first = o.attest(NOW_US, NOW_US + R);
    // Altered after signing into a time reversal of `first`.
    let mut forged = o.attest(NOW_US + 2 * R, NOW_US + 3 * R);
    forged["statement"]["earliest"] = json!((NOW_US - HOUR_US).to_string());
    forged["statement"]["latest"] = json!((NOW_US - HOUR_US + R).to_string());
    forged["statement"]["floor"] = json!((NOW_US - HOUR_US).to_string());
    let e = err_text(slash(&o, &first, Some(&forged)));
    assert!(e.contains("does not verify"), "{e}");
    // Another oracle's statements do not slash this bond.
    let x = other.attest(NOW_US, NOW_US + R);
    let e = err_text(slash(&o, &x, None));
    assert!(e.contains("not signed by the expected oracle"), "{e}");
}

/// Regression (review P3, challenge window): a refund now waits until the
/// term plus the challenge period has provably passed, and slashing still
/// works in that window. The baseline refunded 1 us after bond_until.
#[test]
fn review_bond_refund_waits_for_the_challenge_period() {
    let mut o = Oracle::new(4);
    let mut w1 = Oracle::new(5);
    let mut w2 = Oracle::new(6);
    let witnesses = vec![w1.b64(), w2.b64()];
    let bonded = AgentPubKey::try_from(o.b64()).unwrap();
    let refund = |proof: Value, executor: &AgentPubKey| {
        run_source(
            bond_source(&o.b64()),
            bond_input(&o, witnesses.clone(), json!({ "kind": "refund", "time_proof": proof })),
            executor,
        )
    };

    let just_after_term = json!({ "statements": [w1.attest(NOW_US + 1, NOW_US + 2), w2.attest(NOW_US + 1, NOW_US + 2)] });
    let e = err_text(refund(just_after_term, &bonded));
    assert!(e.contains("challenge period have not provably ended"), "{e}");

    let t = NOW_US + CHALLENGE_US;
    let after_window = json!({ "statements": [w1.attest(t + 10, t + 20), w2.attest(t + 5, t + 25)] });
    let out = refund(after_window.clone(), &bonded).unwrap();
    assert_eq!(allocations(&out), vec![(o.b64(), "500".to_string())]);

    // Someone else cannot take the refund.
    let e = err_text(refund(after_window, &agent(61)));
    assert!(e.contains("Only the bonded oracle"), "{e}");

    // Inside the window a lie is still slashable.
    o.attest(NOW_US + HOUR_US, NOW_US + HOUR_US + R);
    let late_lie = o.attest(NOW_US - R, NOW_US + R);
    let out = slash(&o, &late_lie, None).unwrap();
    assert_eq!(out["computed_values"]["outcome"], "slashed: self-contradiction");
}

/// Regression (review P2, faulty witness): a bad witness entry is skipped
/// instead of failing the refund.
#[test]
fn review_bond_refund_skips_faulty_witnesses() {
    let o = Oracle::new(4);
    let mut w1 = Oracle::new(5);
    let mut w2 = Oracle::new(6);
    let mut w3 = Oracle::new(7);
    let witnesses = vec![w1.b64(), w2.b64(), w3.b64()];
    let bonded = AgentPubKey::try_from(o.b64()).unwrap();
    let t = NOW_US + CHALLENGE_US + R;
    let mut bad = w3.attest(t, t + R);
    bad["signature"][5] = json!(bad["signature"][5].as_u64().unwrap() ^ 1);
    let proof = json!({ "statements": [bad, w1.attest(t, t + R), w2.attest(t, t + R)] });
    let out = run_source(
        bond_source(&o.b64()),
        bond_input(&o, witnesses, json!({ "kind": "refund", "time_proof": proof })),
        &bonded,
    )
    .unwrap();
    assert_eq!(out["computed_values"]["outcome"], "refunded");
}
