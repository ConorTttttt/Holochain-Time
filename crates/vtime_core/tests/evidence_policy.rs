//! End-to-end evidence handling: oracle statements signed with real Ed25519
//! keys, Roughtime responses from the roughenough server code, mixed sets,
//! nonce and network binding, policy enforcement, per-response filtering and
//! malfeasance proofs. Tests named `review_*` are regression tests for the
//! findings in SECURITY_REVIEW.md.

use std::cell::Cell;
use std::net::SocketAddr;

use ed25519_dalek::{Signer, SigningKey};
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::Request;
use roughenough_protocol::tags::ProtocolVersion;
use roughenough_protocol::FromFrame;
use roughenough_server::test_utils::TestContext;

use vtime_core::evidence::{
    accept_oracle_response, anchor_lower_bound, filter_evidence, filter_oracle_responses, seal_upper_bound,
    verify_evidence_set,
};
use vtime_core::keys::{agent_key_to_b64, dna_hash_to_b64};
use vtime_core::malfeasance::{check_pair, check_statement, OracleMalfeasance};
use vtime_core::oracle::plan_statement;
use vtime_core::roughtime::{build_request, VERSION_RFC};
use vtime_core::seal::seal_nonce;
use vtime_core::{
    ChainLink, DalekVerifier, Ed25519Verifier, Error, OracleTimeStatement, RoughtimeEvidence, SignedOracleStatement,
    TimeEvidence, TimeInterval, TimePolicy,
};

const NOW_S: i64 = 1_792_000_000;
const NOW_US: i64 = NOW_S * 1_000_000;
const R: i64 = 1_000_000;

fn dna(n: u8) -> String {
    dna_hash_to_b64(&[n; 32])
}

struct Oracle {
    key: SigningKey,
    b64: String,
    dna: String,
    last: Option<SignedOracleStatement>,
}

impl Oracle {
    fn new(seed: u8) -> Self {
        Self::in_network(seed, dna(1))
    }
    /// One cell of this oracle key, in the network `dna`.
    fn in_network(seed: u8, dna: String) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let b64 = agent_key_to_b64(&key.verifying_key().to_bytes());
        Self { key, b64, dna, last: None }
    }
    fn pk(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
    fn next_link(&self) -> ChainLink {
        self.last.as_ref().map(|l| ChainLink::after(l).unwrap()).unwrap_or_else(ChainLink::genesis)
    }
    /// Sign the next statement on this chain, carrying the floor forward
    /// (whatever the interval: a liar can still sign below it).
    fn attest(&mut self, nonce: [u8; 32], earliest: i64, latest: i64) -> SignedOracleStatement {
        let link = self.next_link();
        self.sign_at(nonce, earliest, latest, link)
    }
    /// Sign at an explicit chain position, as a modified oracle could.
    fn sign_at(&mut self, nonce: [u8; 32], earliest: i64, latest: i64, link: ChainLink) -> SignedOracleStatement {
        let st = OracleTimeStatement::new(
            self.b64.clone(),
            self.dna.clone(),
            &nonce,
            TimeInterval::new(earliest, latest).unwrap(),
            link,
        );
        let sig = self.key.sign(&st.signing_bytes().unwrap()).to_bytes();
        let s = SignedOracleStatement { statement: st, signature: sig.to_vec() };
        self.last = Some(s.clone());
        s
    }
}

fn roughtime_reading(nonce: [u8; 32]) -> ([u8; 32], RoughtimeEvidence) {
    let mut ctx = TestContext::new_at(8, NOW_S as u64);
    let key = ctx.key_source.public_key_bytes();
    let request = build_request(&nonce, &[VERSION_RFC], Some(&key));
    let mut copy = request.clone();
    let parsed = Request::from_frame(&mut ParseCursor::new(&mut copy)).unwrap();
    let addr: SocketAddr = "127.0.0.1:2002".parse().unwrap();
    ctx.response_handler.add_request(&request, parsed, ProtocolVersion::RFC, addr);
    let mut response = Vec::new();
    ctx.response_handler.process_responses(|_, r| response = r.to_vec());
    (key, RoughtimeEvidence { server_public_key: key.to_vec(), request, response })
}

fn policy(oracles: &[&Oracle], servers: &[[u8; 32]], f: u32, min: u32) -> TimePolicy {
    TimePolicy {
        roughtime_servers: servers.to_vec(),
        oracles: oracles.iter().map(|o| o.pk()).collect(),
        max_faulty: f,
        min_sources: min,
        max_radius_us: 10_000_000,
        oracle_dna: Some(dna(1)),
    }
}

/// Counts verifier calls, to show which checks happen before any signature work.
struct Counting(Cell<usize>);

impl Ed25519Verifier for Counting {
    fn verify(&self, pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> vtime_core::Result<bool> {
        self.0.set(self.0.get() + 1);
        DalekVerifier.verify(pk, msg, sig)
    }
}

#[test]
fn mixed_anchor_gives_robust_lower_bound() {
    let mut a = Oracle::new(1);
    let mut b = Oracle::new(2);
    let (srv, rt) = roughtime_reading([5; 32]);
    let set = vec![
        TimeEvidence::Oracle(a.attest([1; 32], NOW_US - R, NOW_US + R)),
        // b is a liar claiming it is an hour later.
        TimeEvidence::Oracle(b.attest([2; 32], NOW_US + 3_600 * R, NOW_US + 3_601 * R)),
        TimeEvidence::Roughtime(rt),
    ];
    let p = policy(&[&a, &b], &[srv], 1, 3);
    let lower = anchor_lower_bound(&set, &p, &DalekVerifier).unwrap();
    // The liar is outvoted: the bound comes from an honest source.
    assert!(lower <= NOW_US, "lower bound {lower} is after the true time");
    assert!(lower >= NOW_US - 10 * R);
}

#[test]
fn seal_requires_every_item_bound_to_the_action() {
    let dna_raw = [0x84u8; 39];
    let action = [0x29u8; 39];
    let nonce = seal_nonce(&dna_raw, &action);
    let mut a = Oracle::new(1);
    let mut b = Oracle::new(2);
    let (srv, rt) = roughtime_reading(nonce);
    let p = policy(&[&a, &b], &[srv], 1, 2);

    let good = vec![TimeEvidence::Oracle(a.attest(nonce, NOW_US - R / 2, NOW_US + R / 2)), TimeEvidence::Roughtime(rt)];
    let upper = seal_upper_bound(&good, &p, &DalekVerifier, &nonce).unwrap();
    assert!(upper >= NOW_US);

    // A reading for some other nonce cannot be swapped in.
    let other = vec![
        TimeEvidence::Oracle(a.attest(nonce, NOW_US, NOW_US + R / 2)),
        TimeEvidence::Oracle(b.attest([0; 32], NOW_US - R / 2, NOW_US + R / 2)),
    ];
    assert_eq!(seal_upper_bound(&other, &p, &DalekVerifier, &nonce), Err(Error::NonceMismatch));
}

#[test]
fn policy_rejects_untrusted_duplicate_and_too_few_sources() {
    let mut a = Oracle::new(1);
    let mut stranger = Oracle::new(9);
    let p = policy(&[&a, &Oracle::new(2)], &[], 1, 2);

    let one = vec![TimeEvidence::Oracle(a.attest([1; 32], NOW_US, NOW_US))];
    assert!(matches!(
        verify_evidence_set(&one, &p, &DalekVerifier, None),
        Err(Error::NotEnoughSources { have: 1, need: 2 })
    ));

    let dup = vec![
        TimeEvidence::Oracle(a.attest([1; 32], NOW_US, NOW_US)),
        TimeEvidence::Oracle(a.attest([2; 32], NOW_US, NOW_US)),
    ];
    assert!(matches!(verify_evidence_set(&dup, &p, &DalekVerifier, None), Err(Error::DuplicateSource(_))));

    let foreign = vec![
        TimeEvidence::Oracle(a.attest([1; 32], NOW_US, NOW_US)),
        TimeEvidence::Oracle(stranger.attest([1; 32], NOW_US, NOW_US)),
    ];
    assert!(matches!(verify_evidence_set(&foreign, &p, &DalekVerifier, None), Err(Error::UnknownSource(_))));

    // A policy promising f = 2 with only 2 required sources is refused.
    let unsound = policy(&[&a, &stranger], &[], 2, 2);
    assert!(matches!(unsound.check(), Err(Error::InvalidPolicy(_))));
}

#[test]
fn forged_or_altered_statements_fail() {
    let mut a = Oracle::new(1);
    let b = Oracle::new(2);
    let p = policy(&[&a, &b], &[], 0, 1);
    let mut s = a.attest([1; 32], NOW_US, NOW_US + 1);
    s.statement.latest = (NOW_US + 3_600 * R).to_string();
    assert!(matches!(
        verify_evidence_set(&[TimeEvidence::Oracle(s)], &p, &DalekVerifier, None),
        Err(Error::BadSignature(_))
    ));

    let wide = a.attest([1; 32], NOW_US - 60 * R, NOW_US + 60 * R);
    assert!(matches!(
        verify_evidence_set(&[TimeEvidence::Oracle(wide)], &p, &DalekVerifier, None),
        Err(Error::RadiusTooLarge { .. })
    ));

    // A statement below its own floor is a confession, never evidence.
    let below = a.attest([1; 32], NOW_US - 300 * R, NOW_US - 299 * R);
    assert!(matches!(
        verify_evidence_set(&[TimeEvidence::Oracle(below)], &p, &DalekVerifier, None),
        Err(Error::InvalidStatement(_))
    ));
}

#[test]
fn oracle_proofs_of_each_kind() {
    let mut o = Oracle::new(4);
    let first = o.attest([1; 32], NOW_US, NOW_US + R);

    // Chained after `first` with the floor carried, yet ten minutes earlier:
    // the statement contradicts itself.
    let below = o.attest([2; 32], NOW_US - 600 * R, NOW_US - 599 * R);
    assert_eq!(check_statement(&below, &DalekVerifier).unwrap(), Some(OracleMalfeasance::SelfContradiction));
    assert_eq!(check_pair(&first, &below, &DalekVerifier).unwrap(), Some(OracleMalfeasance::SelfContradiction));

    // The same lie with the floor dropped: a time reversal against `first`.
    let mut link = ChainLink::after(&first).unwrap();
    link.floor = Some(NOW_US - 700 * R);
    let reversed = o.sign_at([3; 32], NOW_US - 600 * R, NOW_US - 599 * R, link);
    assert_eq!(check_statement(&reversed, &DalekVerifier).unwrap(), None);
    assert_eq!(check_pair(&first, &reversed, &DalekVerifier).unwrap(), Some(OracleMalfeasance::TimeReversal));
    assert_eq!(check_pair(&reversed, &first, &DalekVerifier).unwrap(), Some(OracleMalfeasance::TimeReversal));

    // A plausible interval that silently lowers the floor.
    let mut link = ChainLink::after(&first).unwrap();
    link.floor = Some(NOW_US - 1);
    let dropped = o.sign_at([4; 32], NOW_US + R / 2, NOW_US + 3 * R / 2, link);
    assert_eq!(check_pair(&first, &dropped, &DalekVerifier).unwrap(), Some(OracleMalfeasance::FloorDropped));

    // Two different statements at the same position in one network.
    let mut fork = Oracle::new(4);
    fork.last = Some(first.clone());
    let fork_stmt = fork.attest([5; 32], NOW_US + 2 * R, NOW_US + 3 * R);
    assert_eq!(check_pair(&dropped, &fork_stmt, &DalekVerifier).unwrap(), Some(OracleMalfeasance::Equivocation));

    // Honest successive statements prove nothing.
    let mut honest = Oracle::new(5);
    let h1 = honest.attest([1; 32], NOW_US, NOW_US + R);
    let h2 = honest.attest([2; 32], NOW_US + R / 2, NOW_US + 3 * R / 2);
    assert_eq!(check_pair(&h1, &h2, &DalekVerifier).unwrap(), None);
}

/// Regression (review P1): one agent key serving as an oracle in two cells
/// keeps two chains that both start at seq 0. That is not equivocation. The
/// baseline reported `Equivocation` here.
#[test]
fn review_one_key_in_two_networks_is_not_equivocation() {
    let mut cell_a = Oracle::in_network(4, dna(1));
    let mut cell_b = Oracle::in_network(4, dna(2));
    let a = cell_a.attest([1; 32], NOW_US - R, NOW_US + R);
    let b = cell_b.attest([2; 32], NOW_US + 10 * R, NOW_US + 12 * R);
    assert_eq!(a.statement.seq, b.statement.seq);
    assert_eq!(a.statement.prev, b.statement.prev);
    assert_eq!(check_pair(&a, &b, &DalekVerifier).unwrap(), None);

    // Their later statements are not equivocation either.
    let a1 = cell_a.attest([3; 32], NOW_US + 20 * R, NOW_US + 22 * R);
    let b1 = cell_b.attest([4; 32], NOW_US + 20 * R, NOW_US + 22 * R);
    assert_eq!(check_pair(&a1, &b1, &DalekVerifier).unwrap(), None);

    // A real fork inside one network still is.
    let mut fork_a = Oracle::in_network(4, dna(1));
    let f = fork_a.attest([9; 32], NOW_US + 30 * R, NOW_US + 31 * R);
    assert_eq!(check_pair(&a, &f, &DalekVerifier).unwrap(), Some(OracleMalfeasance::Equivocation));
}

/// Regression (review P1): validation only accepts statements signed for its
/// own network, so an oracle cannot keep side chains under invented DNA hashes
/// and still have them count.
#[test]
fn review_statements_for_another_network_are_rejected() {
    let mut a = Oracle::new(1);
    let mut b_elsewhere = Oracle::in_network(2, dna(2));
    let p = policy(&[&a, &b_elsewhere], &[], 1, 2);
    let set = vec![
        TimeEvidence::Oracle(a.attest([1; 32], NOW_US, NOW_US + 1)),
        TimeEvidence::Oracle(b_elsewhere.attest([1; 32], NOW_US, NOW_US + 1)),
    ];
    assert_eq!(verify_evidence_set(&set, &p, &DalekVerifier, None), Err(Error::WrongNetwork));
    // An off-chain auditor that does not pin a network accepts both.
    let any = TimePolicy { oracle_dna: None, ..p };
    assert!(verify_evidence_set(&set, &any, &DalekVerifier, None).is_ok());
}

/// Regression (review P2, backwards walk): the baseline let an oracle move its
/// clock back 2r per statement with no provable pair; 1,800 steps moved it an
/// hour. Now the second step back is always a proof, whether the oracle
/// carries its floor forward or drops it.
#[test]
fn review_backwards_walk_is_caught_within_two_steps() {
    // Carrying the floor: the second step contradicts itself.
    let mut o = Oracle::new(7);
    let a = o.attest([0; 32], NOW_US - R, NOW_US + R);
    let b = o.attest([1; 32], NOW_US - 3 * R, NOW_US - R);
    assert_eq!(check_pair(&a, &b, &DalekVerifier).unwrap(), None, "one step of 2r is within tolerance");
    let c = o.attest([2; 32], NOW_US - 5 * R, NOW_US - 3 * R);
    assert_eq!(check_statement(&c, &DalekVerifier).unwrap(), Some(OracleMalfeasance::SelfContradiction));

    // Dropping the floor to keep each statement self-consistent: the drop is
    // provable from the adjacent pair.
    let mut link = ChainLink::after(&b).unwrap();
    link.floor = Some(NOW_US - 3 * R);
    let mut o2 = Oracle::new(7);
    o2.last = Some(b.clone());
    let c2 = o2.sign_at([3; 32], NOW_US - 5 * R, NOW_US - 3 * R, link);
    assert_eq!(check_statement(&c2, &DalekVerifier).unwrap(), None);
    assert_eq!(check_pair(&b, &c2, &DalekVerifier).unwrap(), Some(OracleMalfeasance::FloorDropped));
}

/// Property: an honest oracle (plan_statement, clock error below r/2,
/// arbitrary spacing) never produces a proof against itself, for any pair of
/// its statements.
#[test]
fn review_honest_chains_never_prove_malfeasance() {
    let mut seed = 0x2545f4914f6cdd1du64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for round in 0..4 {
        let mut o = Oracle::new(20 + round);
        let mut truth = NOW_US;
        let mut chain = Vec::new();
        while chain.len() < 25 {
            truth += 1 + (next() % (3 * R as u64)) as i64;
            let jitter = (next() % R as u64) as i64 - R / 2;
            match plan_statement(o.last.as_ref(), truth + jitter, R, 0) {
                Ok(plan) => {
                    let s = o.sign_at([chain.len() as u8; 32], plan.interval.earliest_us, plan.interval.latest_us, plan.link);
                    chain.push(s);
                }
                Err(Error::RateLimited { .. }) => {}
                Err(e) => panic!("honest oracle refused: {e}"),
            }
        }
        for (i, x) in chain.iter().enumerate() {
            assert_eq!(check_statement(x, &DalekVerifier).unwrap(), None);
            for y in &chain[i + 1..] {
                assert_eq!(check_pair(x, y, &DalekVerifier).unwrap(), None);
            }
        }
    }
}

/// Regression (review P2, faulty oracle): one faulty oracle no longer fails the
/// set. Its forged, stale, wrong-network, forwarded and below-floor answers
/// are dropped and the honest answers still make a valid seal.
#[test]
fn review_faulty_oracle_answers_are_filtered_out() {
    let nonce = [9; 32];
    let mut a = Oracle::new(1);
    let mut b = Oracle::new(2);
    let mut faulty = Oracle::new(3);
    let p = policy(&[&a, &b, &faulty], &[], 1, 2);
    let good_a = a.attest(nonce, NOW_US - R, NOW_US + R);
    let good_b = b.attest(nonce, NOW_US - R, NOW_US + R);

    let mut forged = faulty.attest(nonce, NOW_US - R, NOW_US + R);
    forged.signature[0] ^= 1;
    let stale = faulty.attest([8; 32], NOW_US - R, NOW_US + R);
    let wide = faulty.attest(nonce, NOW_US - 60 * R, NOW_US + 60 * R);
    let mut faulty_elsewhere = Oracle::in_network(3, dna(2));
    let wrong_network = faulty_elsewhere.attest(nonce, NOW_US - R, NOW_US + R);

    // Before: any one of these in the set failed it.
    for bad in [&forged, &stale, &wide, &wrong_network, &good_a] {
        let set = vec![TimeEvidence::Oracle(good_a.clone()), TimeEvidence::Oracle(good_b.clone()), TimeEvidence::Oracle(bad.clone())];
        assert!(verify_evidence_set(&set, &p, &DalekVerifier, Some(&nonce)).is_err());
    }

    // After: the gatherer filters each answer against the oracle it asked.
    let responses = vec![
        (faulty.pk(), forged),
        (faulty.pk(), stale),
        (faulty.pk(), wide),
        (faulty.pk(), wrong_network),
        (faulty.pk(), good_a.clone()), // forwarded copy of a's answer
        (a.pk(), good_a.clone()),
        (b.pk(), good_b.clone()),
        (b.pk(), good_b.clone()), // repeated answer
    ];
    let kept = filter_oracle_responses(responses, &p, &DalekVerifier, Some(&nonce));
    assert_eq!(kept, vec![good_a.clone(), good_b.clone()]);
    let set: Vec<TimeEvidence> = kept.into_iter().map(TimeEvidence::Oracle).collect();
    assert!(seal_upper_bound(&set, &p, &DalekVerifier, &nonce).is_ok());

    assert!(matches!(
        accept_oracle_response(&faulty.pk(), &good_a, &p, &DalekVerifier, Some(&nonce)),
        Err(Error::UnknownSource(_))
    ));
}

/// Regression (review P3, verification work): untrusted keys and foreign
/// networks are rejected before any signature verification.
#[test]
fn review_policy_checks_run_before_signature_checks() {
    let mut a = Oracle::new(1);
    let mut stranger = Oracle::new(9);
    let mut a_elsewhere = Oracle::in_network(1, dna(2));
    let p = policy(&[&a], &[], 0, 1);
    let v = Counting(Cell::new(0));
    let untrusted = vec![TimeEvidence::Oracle(stranger.attest([1; 32], NOW_US, NOW_US))];
    assert!(matches!(verify_evidence_set(&untrusted, &p, &v, None), Err(Error::UnknownSource(_))));
    let foreign = vec![TimeEvidence::Oracle(a_elsewhere.attest([1; 32], NOW_US, NOW_US))];
    assert_eq!(verify_evidence_set(&foreign, &p, &v, None), Err(Error::WrongNetwork));
    assert_eq!(v.0.get(), 0);
    let ok = vec![TimeEvidence::Oracle(a.attest([1; 32], NOW_US, NOW_US))];
    assert!(verify_evidence_set(&ok, &p, &v, None).is_ok());
    assert_eq!(v.0.get(), 1);
}

/// Regression (review P3, arithmetic): a fault bound that would wrap is a
/// policy error, not a panic (debug) or an accepted policy (release).
#[test]
fn review_huge_fault_bound_is_an_invalid_policy() {
    let a = Oracle::new(1);
    let p = TimePolicy { max_faulty: u32::MAX, min_sources: 1, ..policy(&[&a], &[], 0, 1) };
    assert!(matches!(p.check(), Err(Error::InvalidPolicy(_))));
    assert!(!p.supports_intersection(3), "3 sources never support f = u32::MAX");
}

/// Regression (review P2, non-canonical key text): a statement whose `oracle`
/// field spells the oracle's key with other location bytes is refused. The
/// baseline counted it as the oracle's own (only the 32 key bytes were read),
/// while the bond template, which compares the text, could never slash it.
#[test]
fn review_non_canonical_oracle_key_text_is_refused() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let a = Oracle::new(1);
    let mut b = Oracle::new(2);
    let p = policy(&[&a, &b], &[], 0, 1);

    let mut raw = URL_SAFE_NO_PAD.decode(&b.b64[1..]).unwrap();
    raw[38] ^= 0x01;
    b.b64 = format!("u{}", URL_SAFE_NO_PAD.encode(&raw));
    let lie = b.attest([1; 32], NOW_US + 3_600 * R, NOW_US + 3_601 * R);
    // The signature is genuine: b really signed this text.
    assert!(DalekVerifier.verify(&b.pk(), &lie.statement.signing_bytes().unwrap(), lie.signature.as_slice().try_into().unwrap()).unwrap());
    let set = vec![TimeEvidence::Oracle(lie.clone())];
    assert!(matches!(verify_evidence_set(&set, &p, &DalekVerifier, None), Err(Error::Malformed(_))));
    assert!(check_statement(&lie, &DalekVerifier).is_err(), "not a statement at all, so not a proof either");
}

/// Regression (review P3, policy): one key listed as both a Roughtime server
/// and an oracle would count as two sources towards f; such a policy is
/// refused. Repeated keys count once towards the trusted total.
#[test]
fn review_key_in_both_roles_is_an_invalid_policy() {
    let a = Oracle::new(1);
    let b = Oracle::new(2);
    let both = policy(&[&a, &b], &[a.pk()], 1, 2);
    assert!(matches!(both.check(), Err(Error::InvalidPolicy(_))));

    let mut repeated = policy(&[&a, &b], &[], 1, 3);
    repeated.oracles.push(a.pk());
    assert!(matches!(repeated.check(), Err(Error::InvalidPolicy(_))), "3 listed but only 2 distinct");
}

/// Regression (review P2, faulty source): a corrupted or duplicated Roughtime
/// reply among the client's readings is dropped instead of failing the set.
#[test]
fn review_faulty_roughtime_replies_are_filtered_out() {
    let nonce = [6; 32];
    let (srv, good) = roughtime_reading(nonce);
    let mut a = Oracle::new(1);
    let p = policy(&[&a], &[srv], 1, 2);
    let mut corrupted = good.clone();
    let last = corrupted.response.len() - 1;
    corrupted.response[last - 40] ^= 0xff;
    let (_, stale) = roughtime_reading([7; 32]); // answers another nonce
    let items = vec![
        TimeEvidence::Roughtime(corrupted),
        TimeEvidence::Roughtime(stale),
        TimeEvidence::Roughtime(good.clone()),
        TimeEvidence::Roughtime(good.clone()),
    ];
    let kept = filter_evidence(items, &p, &DalekVerifier, Some(&nonce));
    assert_eq!(kept, vec![TimeEvidence::Roughtime(good)]);
    let mut set = kept;
    set.push(TimeEvidence::Oracle(a.attest(nonce, NOW_US - R, NOW_US + R)));
    assert!(seal_upper_bound(&set, &p, &DalekVerifier, &nonce).is_ok());
}

/// Sprint 1: avoid returning a confident verdict from a truncated evidence
/// index. The coordinator uses this before examining seals, anchors and
/// ancestry candidates. It fails closed even when all extra links are spam.
#[test]
fn sprint1_evidence_index_must_fail_closed() {
    use vtime_core::evidence::require_complete_index;
    assert_eq!(require_complete_index(0, 32), Ok(()));
    assert_eq!(require_complete_index(32, 32), Ok(()));
    assert_eq!(require_complete_index(33, 32), Err(Error::EvidenceIndexIncomplete { found: 33, limit: 32 }));
    assert_eq!(require_complete_index(65, 64), Err(Error::EvidenceIndexIncomplete { found: 65, limit: 64 }));
    assert_eq!(require_complete_index(9, 8), Err(Error::EvidenceIndexIncomplete { found: 9, limit: 8 }));
    assert_eq!(require_complete_index(100_000, 64), Err(Error::EvidenceIndexIncomplete { found: 100_000, limit: 64 }));
}

/// A Byzantine fault bound is distinct from the number of time sources that
/// can be offline while the deployment still meets its quorum.
#[test]
fn sprint1_quorum_outage_preflight() {
    let a = Oracle::new(11);
    let b = Oracle::new(12);
    let c = Oracle::new(13);
    let d = Oracle::new(14);
    let p = policy(&[&a, &b, &c], &[], 1, 3);
    // Mathematically sound with three available; not live through one outage.
    assert_eq!(p.check(), Ok(()));
    assert!(matches!(p.check_outage_tolerance(1), Err(Error::InvalidPolicy(_))));
    assert_eq!(p.check_outage_tolerance(0), Ok(()));
    let resilient = policy(&[&a, &b, &c, &d], &[], 1, 3);
    assert_eq!(resilient.check_outage_tolerance(1), Ok(()));
    assert!(matches!(resilient.check_outage_tolerance(2), Err(Error::InvalidPolicy(_))));
    assert!(matches!(resilient.check_outage_tolerance(u32::MAX), Err(Error::InvalidPolicy(_))));
}
