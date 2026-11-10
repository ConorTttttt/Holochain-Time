//! Sprint 23 -- deterministic cryptographic negative/outage acceptance matrix.
//! Uses publicly known Roughenough signing fixtures. The *real* conductor
//! acceptance is integration/conductor/tests/live_roughtime.rs, opt-in only.
use std::net::SocketAddr;
use std::time::Duration;

use roughenough_keys::seed::MemoryBackend;
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::Request;
use roughenough_protocol::tags::ProtocolVersion;
use roughenough_protocol::util::ClockSource;
use roughenough_protocol::FromFrame;
use roughenough_server::keysource::KeySource;
use roughenough_server::responses::ResponseHandler;
use vtime_core::evidence::{
    check_independent_roughtime_sources, verify_independent_roughtime_quorum,
    IndependentRoughtimeSource,
};
use vtime_core::roughtime::{build_request, verify_response, MAX_RESPONSE_PACKET_SIZE, VERSION_RFC};
use vtime_core::seal::seal_nonce;
use vtime_core::{DalekVerifier, Error, RoughtimeEvidence, TimePolicy};

const SEEDS: [u8; 4] = [81, 82, 83, 84];
const TIME_S: u64 = 1_794_000_000;

fn signed(seed: u8, nonce: [u8; 32]) -> RoughtimeEvidence {
    let key_source = KeySource::new(
        Box::new(MemoryBackend::from_value(&[seed; 32])),
        ClockSource::new_mock(TIME_S),
        Duration::from_secs(8_000_000),
    );
    let key = key_source.public_key_bytes();
    let request = build_request(&nonce, &[VERSION_RFC], Some(&key));
    let mut cursor_bytes = request.clone();
    let parsed = Request::from_frame(&mut ParseCursor::new(&mut cursor_bytes))
        .expect("valid fixture request");
    let mut server = ResponseHandler::new(8, key_source);
    let addr: SocketAddr = "127.0.0.1:2002".parse().unwrap();
    server.add_request(&request, parsed, ProtocolVersion::RFC, addr);
    let mut response = Vec::new();
    server.process_responses(|_, frame| response = frame.to_vec());
    assert!(!response.is_empty(), "no genuine test signature was produced");
    verify_response(&key, &request, &response, &DalekVerifier)
        .expect("local fixture must verify before test mutations");
    RoughtimeEvidence {
        server_public_key: key.to_vec(),
        request,
        response,
    }
}

fn model(nonce: [u8; 32]) -> (Vec<RoughtimeEvidence>, Vec<IndependentRoughtimeSource>, TimePolicy) {
    let evidence: Vec<_> = SEEDS.iter().map(|seed| signed(*seed, nonce)).collect();
    let registry: Vec<_> = evidence.iter().enumerate().map(|(i, p)| {
        IndependentRoughtimeSource {
            operator: format!("fictional-operator-{i}"),
            public_key: p.server_public_key.as_slice().try_into().unwrap(),
        }
    }).collect();
    let policy = TimePolicy {
        roughtime_servers: registry.iter().map(|s| s.public_key).collect(),
        oracles: Vec::new(),
        max_faulty: 1, min_sources: 3,
        max_radius_us: 10_000_000, oracle_dna: None,
    };
    check_independent_roughtime_sources(&registry, &policy)
        .expect("four genuinely different synthetic roots");
    (evidence, registry, policy)
}

#[test]
fn valid_three_signatures_and_one_outage_still_satisfy_unchanged_three_source_quorum() {
    let nonce = seal_nonce(&[1; 39], &[2; 39]);
    let (records, trusted, policy) = model(nonce);
    let no_outage = verify_independent_roughtime_quorum(
        &records[..3], &trusted, &policy, &DalekVerifier, &nonce,
    ).expect("three genuine distinct signed sources");
    assert_eq!(no_outage.len(), 3);
    let first_offline = verify_independent_roughtime_quorum(
        &records[1..], &trusted, &policy, &DalekVerifier, &nonce,
    ).expect("three remaining genuine signatures with first source unavailable");
    assert_eq!(first_offline.len(), 3);
    assert!(matches!(
        verify_independent_roughtime_quorum(
            &records[2..], &trusted, &policy, &DalekVerifier, &nonce,
        ),
        Err(Error::NotEnoughSources { have: 2, need: 3 })
    ));
}

#[test]
fn wrong_dna_and_wrong_target_replay_are_rejected_but_exact_same_target_stays_valid() {
    let dna = [11; 39];
    let target = [12; 39];
    let nonce = seal_nonce(&dna, &target);
    let (records, trusted, policy) = model(nonce);
    for wrong_nonce in [
        seal_nonce(&[13; 39], &target),
        seal_nonce(&dna, &[14; 39]),
    ] {
        assert!(matches!(
            verify_independent_roughtime_quorum(
                &records[..3], &trusted, &policy, &DalekVerifier, &wrong_nonce,
            ),
            Err(Error::NonceMismatch)
        ));
    }
    // This is not a freshness bug in Ed25519 or Merkle verification: the
    // nonce is deterministic for identical DNA/target bytes. An app needs
    // its own replay/idempotency state for side effects.
    for _ in 0..2 {
        assert!(verify_independent_roughtime_quorum(
            &records[..3], &trusted, &policy, &DalekVerifier, &nonce,
        ).is_ok());
    }
}

#[test]
fn forged_response_malformed_packet_and_wrong_long_term_key_fail() {
    let nonce = [51; 32];
    let (records, trusted, policy) = model(nonce);
    let mut mutated = records[..3].to_vec();
    let len = mutated[0].response.len();
    assert!(len > 32);
    mutated[0].response[len - 8] ^= 0x01;
    assert!(verify_independent_roughtime_quorum(
        &mutated, &trusted, &policy, &DalekVerifier, &nonce,
    ).is_err(), "forged signed response was accepted");

    let mut truncated = records[..3].to_vec();
    truncated[1].response.truncate(15);
    assert!(verify_independent_roughtime_quorum(
        &truncated, &trusted, &policy, &DalekVerifier, &nonce,
    ).is_err(), "malformed truncated delegated packet was accepted");

    let mut oversized = records[..3].to_vec();
    oversized[2].response = vec![0x21; MAX_RESPONSE_PACKET_SIZE + 1];
    assert!(verify_independent_roughtime_quorum(
        &oversized, &trusted, &policy, &DalekVerifier, &nonce,
    ).is_err(), "oversized packet reached acceptance");

    let mut forged_root = records[..3].to_vec();
    forged_root[0].server_public_key = [0xAA; 32].to_vec();
    assert!(matches!(
        verify_independent_roughtime_quorum(
            &forged_root, &trusted, &policy, &DalekVerifier, &nonce,
        ),
        Err(Error::UnknownSource(_))
    ));
}

#[test]
fn same_operator_and_duplicate_key_never_count_as_distinct_quorum() {
    let nonce = [93; 32];
    let (records, mut trusted, policy) = model(nonce);
    trusted[3].operator = "  FICTIONAL-OPERATOR-1 ".to_string();
    assert!(matches!(
        check_independent_roughtime_sources(&trusted, &policy),
        Err(Error::DuplicateSource(_))
    ));
    trusted[3].operator = "fictional-operator-3".to_string();
    let duplicates = vec![records[0].clone(), records[1].clone(), records[1].clone()];
    assert!(matches!(
        verify_independent_roughtime_quorum(
            &duplicates, &trusted, &policy, &DalekVerifier, &nonce,
        ),
        Err(Error::DuplicateSource(_))
    ));
    let mut downgrade = policy.clone();
    downgrade.min_sources = 2;
    assert!(matches!(
        verify_independent_roughtime_quorum(
            &records[..3], &trusted, &downgrade, &DalekVerifier, &nonce,
        ),
        Err(Error::InvalidPolicy(_))
    ));
}
