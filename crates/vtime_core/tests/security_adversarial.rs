//! Sprint 16 adversarial evidence regressions.
//! These deterministic signatures use publicly known test material, NOT real keys.
use ed25519_dalek::{Signer, SigningKey};
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::Request;
use roughenough_protocol::tags::ProtocolVersion;
use roughenough_protocol::FromFrame;
use roughenough_server::test_utils::TestContext;
use std::net::SocketAddr;

use vtime_core::evidence::{require_complete_index, verify_evidence_set, MAX_EVIDENCE_ITEMS};
use vtime_core::keys::{agent_key_to_b64, dna_hash_to_b64};
use vtime_core::roughtime::{
    build_request, frame, unframe, verify_response, Message, MAX_REQUEST_PACKET_SIZE,
    MAX_RESPONSE_PACKET_SIZE, VERSION_RFC,
};
use vtime_core::{
    ChainLink, DalekVerifier, Ed25519Verifier, Error, OracleTimeStatement, RoughtimeEvidence,
    SignedOracleStatement, TimeEvidence, TimeInterval, TimePolicy,
};

const WHEN: u64 = 1_792_000_000;
const NONCE: [u8; 32] = [0x5A; 32];

fn signed_rt() -> ([u8; 32], RoughtimeEvidence) {
    let mut context = TestContext::new_at(8, WHEN);
    let key = context.key_source.public_key_bytes();
    let request = build_request(&NONCE, &[VERSION_RFC], Some(&key));
    let mut copy = request.clone();
    let parsed = Request::from_frame(&mut ParseCursor::new(&mut copy))
        .expect("our request must be parseable by an independent server");
    let addr: SocketAddr = "127.0.0.1:2002".parse().unwrap();
    context.response_handler.add_request(&request, parsed, ProtocolVersion::RFC, addr);
    let mut response = Vec::new();
    context.response_handler.process_responses(|_, r| response = r.to_vec());
    assert!(!response.is_empty());
    (
        key,
        RoughtimeEvidence { server_public_key: key.to_vec(), request, response },
    )
}

fn signed_oracle(seed: u8, network: u8, nonce: [u8; 32]) -> ([u8; 32], SignedOracleStatement) {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let key = signing.verifying_key().to_bytes();
    let statement = OracleTimeStatement::new(
        agent_key_to_b64(&key),
        dna_hash_to_b64(&[network; 32]),
        &nonce,
        TimeInterval::new((WHEN as i64) * 1_000_000, (WHEN as i64) * 1_000_000 + 1).unwrap(),
        ChainLink::genesis(),
    );
    let signature = signing.sign(&statement.signing_bytes().unwrap()).to_bytes().to_vec();
    (key, SignedOracleStatement { statement, signature })
}

fn policy(servers: Vec<[u8; 32]>, oracles: Vec<[u8; 32]>) -> TimePolicy {
    TimePolicy {
        roughtime_servers: servers, oracles, max_faulty: 0, min_sources: 1,
        max_radius_us: 10_000_000, oracle_dna: Some(dna_hash_to_b64(&[1; 32])),
    }
}

#[test]
fn genuine_roughtime_response_and_every_one_bit_signature_region_mutation() {
    let (key, evidence) = signed_rt();
    assert_eq!(verify_response(&key, &evidence.request, &evidence.response, &DalekVerifier)
        .unwrap().nonce, NONCE);

    // Verify that *every* byte of the signed response is authenticated. A
    // parser rejection also counts as fail-closed; never assume tail == SIG.
    for byte in 12..evidence.response.len() {
        let mut mutated = evidence.response.clone();
        mutated[byte] ^= 1;
        assert!(verify_response(&key, &evidence.request, &mutated, &DalekVerifier).is_err(),
            "mutated Roughtime response byte {byte} accepted");
    }
    let wrong_key = [0xBB; 32];
    assert!(verify_response(&wrong_key, &evidence.request, &evidence.response, &DalekVerifier).is_err());
    let mut replay_request = evidence.request.clone();
    let i = replay_request.len() - 1;
    replay_request[i] ^= 1;
    assert!(verify_response(&key, &replay_request, &evidence.response, &DalekVerifier).is_err());
}

#[test]
fn oracle_signature_mutations_and_canonical_field_binding() {
    let (key, genuine) = signed_oracle(7, 1, NONCE);
    let p = policy(vec![], vec![key]);
    assert!(verify_evidence_set(&[TimeEvidence::Oracle(genuine.clone())],
        &p, &DalekVerifier, Some(&NONCE)).is_ok());
    for i in 0..64 {
        let mut broken = genuine.clone();
        broken.signature[i] ^= 1;
        assert!(verify_evidence_set(&[TimeEvidence::Oracle(broken)],
            &p, &DalekVerifier, Some(&NONCE)).is_err(), "signature byte {i} accepted");
    }
    for altered in [
        ("earliest", "1792000000000001"),
        ("latest", "1792000000000002"),
        ("seq", "01"),
        ("nonce", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    ] {
        let mut broken = genuine.clone();
        match altered.0 {
            "earliest" => broken.statement.earliest = altered.1.to_string(),
            "latest" => broken.statement.latest = altered.1.to_string(),
            "seq" => broken.statement.seq = altered.1.to_string(),
            "nonce" => broken.statement.nonce = altered.1.to_string(),
            _ => unreachable!(),
        }
        assert!(verify_evidence_set(&[TimeEvidence::Oracle(broken)],
            &p, &DalekVerifier, Some(&NONCE)).is_err(),
            "altered {} accepted", altered.0);
    }
    let mut broken = genuine.clone();
    broken.signature.truncate(63);
    assert!(matches!(verify_evidence_set(&[TimeEvidence::Oracle(broken)],
        &p, &DalekVerifier, Some(&NONCE)), Err(Error::Malformed(_))));
}

#[test]
fn replay_duplicate_sources_and_cross_network_signatures_reject() {
    let (oracle_key, correct) = signed_oracle(7, 1, NONCE);
    let p = policy(vec![], vec![oracle_key]);
    let item = TimeEvidence::Oracle(correct.clone());
    assert!(matches!(
        verify_evidence_set(&[item.clone(), item], &p, &DalekVerifier, Some(&NONCE)),
        Err(Error::DuplicateSource(_))
    ));
    assert_eq!(
        verify_evidence_set(&[TimeEvidence::Oracle(correct)], &p, &DalekVerifier, Some(&[7; 32])),
        Err(Error::NonceMismatch)
    );
    let (_, foreign_network) = signed_oracle(7, 2, NONCE);
    assert_eq!(
        verify_evidence_set(&[TimeEvidence::Oracle(foreign_network)], &p, &DalekVerifier, Some(&NONCE)),
        Err(Error::WrongNetwork)
    );
    let (key, rt) = signed_rt();
    let rp = policy(vec![key], vec![]);
    let evidence = TimeEvidence::Roughtime(rt);
    assert!(matches!(
        verify_evidence_set(&[evidence.clone(), evidence.clone()], &rp, &DalekVerifier, Some(&NONCE)),
        Err(Error::DuplicateSource(_))
    ));
    assert_eq!(
        verify_evidence_set(&[evidence], &rp, &DalekVerifier, Some(&[3; 32])),
        Err(Error::NonceMismatch)
    );
    // Same Ed25519 key playing both roles is unsound and refused at policy setup.
    assert!(matches!(policy(vec![key], vec![key]).check(), Err(Error::InvalidPolicy(_))));
}

struct MustNotVerify;
impl Ed25519Verifier for MustNotVerify {
    fn verify(&self, _: &[u8; 32], _: &[u8], _: &[u8; 64]) -> vtime_core::Result<bool> {
        panic!("oversized input reached cryptographic verification");
    }
}

#[test]
fn attack_sizes_and_header_overflow_are_bounded_before_crypto() {
    let (key, rt) = signed_rt();
    let rp = policy(vec![key], vec![]);
    let oversized_set = vec![TimeEvidence::Roughtime(rt.clone()); MAX_EVIDENCE_ITEMS + 1];
    assert!(matches!(
        verify_evidence_set(&oversized_set, &rp, &MustNotVerify, Some(&NONCE)),
        Err(Error::Malformed(_))
    ));
    let mut too_large_request = rt.request.clone();
    too_large_request.resize(MAX_REQUEST_PACKET_SIZE + 1, 0);
    let mut too_large_response = rt.response.clone();
    too_large_response.resize(MAX_RESPONSE_PACKET_SIZE + 1, 0);
    for _ in 0..128 {
        assert!(matches!(
            verify_response(&key, &too_large_request, &rt.response, &MustNotVerify),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            verify_response(&key, &rt.request, &too_large_response, &MustNotVerify),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            verify_evidence_set(&oversized_set, &rp, &MustNotVerify, Some(&NONCE)),
            Err(Error::Malformed(_))
        ));
    }
    assert!(matches!(require_complete_index(9, 8), Err(Error::EvidenceIndexIncomplete { .. })));
    assert!(matches!(require_complete_index(33, 32), Err(Error::EvidenceIndexIncomplete { .. })));
    assert!(matches!(
        require_complete_index(usize::MAX, 32), Err(Error::EvidenceIndexIncomplete { .. })
    ));
    assert!(require_complete_index(8, 8).is_ok());

    // Invalid RFC headers: u32::MAX size, overflowing tag count, and truncated
    // framed payload; none may be treated as a valid signed response.
    let mut frame_with_max_len = frame(&[0, 0, 0, 0]);
    frame_with_max_len[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(unframe(&frame_with_max_len).is_err());
    assert!(Message::parse(&u32::MAX.to_le_bytes()).is_err());
    assert!(unframe(&[0; 11]).is_err());
}
