//! Cryptographic quorum tests against independent Roughenough signer instances.
//! These distinct test keys are NOT evidence of independent real-world operators.

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
use vtime_core::roughtime::{build_request, verify_response, VERSION_RFC};
use vtime_core::seal::seal_nonce;
use vtime_core::{DalekVerifier, Error, RoughtimeEvidence, TimePolicy};

const SIGNED_AT: u64 = 1_794_000_000;
const SEEDS: [u8; 4] = [71, 72, 73, 74];

fn signed(seed: u8, nonce: [u8; 32]) -> RoughtimeEvidence {
    let key_source = KeySource::new(
        Box::new(MemoryBackend::from_value(&[seed; 32])),
        ClockSource::new_mock(SIGNED_AT),
        Duration::from_secs(8_000_000),
    );
    let key = key_source.public_key_bytes();
    let mut handler = ResponseHandler::new(8, key_source);
    let request = build_request(&nonce, &[VERSION_RFC], Some(&key));
    let mut for_parser = request.clone();
    let parsed = Request::from_frame(&mut ParseCursor::new(&mut for_parser))
        .expect("Roughenough must parse our request");
    let address: SocketAddr = "127.0.0.1:2002".parse().unwrap();
    handler.add_request(&request, parsed, ProtocolVersion::RFC, address);
    let mut response = Vec::new();
    handler.process_responses(|_, bytes| response = bytes.to_vec());
    assert!(!response.is_empty());
    verify_response(&key, &request, &response, &DalekVerifier).expect("genuine signature");
    RoughtimeEvidence {
        server_public_key: key.to_vec(),
        request,
        response,
    }
}

fn setup(nonce: [u8; 32]) -> (
    Vec<RoughtimeEvidence>,
    Vec<IndependentRoughtimeSource>,
    TimePolicy,
) {
    let evidence: Vec<_> = SEEDS.iter().map(|seed| signed(*seed, nonce)).collect();
    let sources: Vec<_> = evidence
        .iter()
        .enumerate()
        .map(|(i, item)| IndependentRoughtimeSource {
            operator: format!("fixture-operator-{i}"),
            public_key: item.server_public_key.as_slice().try_into().unwrap(),
        })
        .collect();
    let policy = TimePolicy {
        roughtime_servers: sources.iter().map(|s| s.public_key).collect(),
        oracles: vec![],
        max_faulty: 1,
        min_sources: 3,
        max_radius_us: 10_000_000,
        oracle_dna: None,
    };
    (evidence, sources, policy)
}

#[test]
fn three_genuine_signatures_from_distinct_configured_operators_pass() {
    let nonce = seal_nonce(&[1; 39], &[2; 39]);
    let (evidence, sources, policy) = setup(nonce);
    let verified = verify_independent_roughtime_quorum(
        &evidence[..3], &sources, &policy, &DalekVerifier, &nonce,
    ).unwrap();
    assert_eq!(verified.len(), 3);
    for v in verified {
        assert!(v.interval.contains((SIGNED_AT as i64) * 1_000_000));
    }
}

#[test]
fn one_source_outage_uses_spare_but_two_sources_never_suffice() {
    let nonce = seal_nonce(&[1; 39], &[2; 39]);
    let (evidence, sources, policy) = setup(nonce);
    // Source 0 is offline: use three other independent operators.
    assert!(verify_independent_roughtime_quorum(
        &evidence[1..], &sources, &policy, &DalekVerifier, &nonce,
    ).is_ok());
    assert!(matches!(
        verify_independent_roughtime_quorum(
            &evidence[2..], &sources, &policy, &DalekVerifier, &nonce,
        ),
        Err(Error::NotEnoughSources { have: 2, need: 3 })
    ));
}

#[test]
fn duplicate_keys_or_operators_cannot_form_a_quorum() {
    let nonce = seal_nonce(&[1; 39], &[2; 39]);
    let (evidence, mut sources, policy) = setup(nonce);
    let duplicate = vec![evidence[0].clone(), evidence[1].clone(), evidence[0].clone()];
    assert!(matches!(
        verify_independent_roughtime_quorum(
            &duplicate, &sources, &policy, &DalekVerifier, &nonce,
        ),
        Err(Error::DuplicateSource(_))
    ));
    sources[1].operator = "  FIXTURE-OPERATOR-0  ".into();
    assert!(matches!(
        check_independent_roughtime_sources(&sources, &policy),
        Err(Error::DuplicateSource(_))
    ));
}

#[test]
fn rejected_when_operator_metadata_or_policy_is_not_a_three_source_commitment() {
    let nonce = [42; 32];
    let (evidence, sources, mut policy) = setup(nonce);
    policy.min_sources = 2;
    assert!(matches!(
        verify_independent_roughtime_quorum(
            &evidence[..3], &sources, &policy, &DalekVerifier, &nonce,
        ),
        Err(Error::InvalidPolicy(_))
    ));
    policy.min_sources = 3;
    let mut unknown = sources.clone();
    unknown[2].public_key = [13; 32];
    assert!(matches!(
        check_independent_roughtime_sources(&unknown, &policy),
        Err(Error::UnknownSource(_))
    ));
    let mut incomplete = sources.clone();
    incomplete.truncate(2);
    assert!(matches!(
        check_independent_roughtime_sources(&incomplete, &policy),
        Err(Error::NotEnoughSources { have: 2, need: 3 })
    ));
}

#[test]
fn wrong_dna_wrong_target_and_replay_from_other_context_fail_closed() {
    let dna = [8; 39];
    let target = [9; 39];
    let nonce = seal_nonce(&dna, &target);
    let (evidence, sources, policy) = setup(nonce);
    let other_dna = seal_nonce(&[7; 39], &target);
    let other_target = seal_nonce(&dna, &[10; 39]);
    for wrong_nonce in [other_dna, other_target, [0; 32]] {
        assert!(matches!(
            verify_independent_roughtime_quorum(
                &evidence[..3], &sources, &policy, &DalekVerifier, &wrong_nonce,
            ),
            Err(Error::NonceMismatch)
        ));
    }
    // The same seal nonce is intentionally deterministic. Signatures cannot
    // tell whether the SAME target's valid response was supplied before.
    assert!(verify_independent_roughtime_quorum(
        &evidence[..3], &sources, &policy, &DalekVerifier, &nonce,
    ).is_ok());
}

#[test]
fn forged_packets_and_unreviewed_signers_rejected() {
    let nonce = seal_nonce(&[8; 39], &[9; 39]);
    let (mut evidence, sources, policy) = setup(nonce);
    let n = evidence[2].response.len();
    evidence[2].response[n - 8] ^= 1;
    assert!(verify_independent_roughtime_quorum(
        &evidence[..3], &sources, &policy, &DalekVerifier, &nonce,
    ).is_err());

    let (mut evidence, sources, policy) = setup(nonce);
    evidence[2].server_public_key = [0x55; 32].to_vec();
    assert!(matches!(
        verify_independent_roughtime_quorum(
            &evidence[..3], &sources, &policy, &DalekVerifier, &nonce,
        ),
        Err(Error::UnknownSource(_))
    ));
}

#[test]
fn candidate_public_keys_have_correct_form_and_distinct_owners() {
    let value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../config/roughtime-independent-sources.json"
    )).unwrap();
    let sources = value["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 5);
    let keys: Vec<_> = sources
        .iter()
        .map(|s| {
            vtime_core::keys::roughtime_key_from_b64(
                s["public_key"].as_str().unwrap(),
            )
            .unwrap()
        })
        .collect();
    let operators: Vec<_> = sources
        .iter()
        .map(|s| s["operator"].as_str().unwrap())
        .collect();
    for (i, key) in keys.iter().enumerate() {
        assert!(!keys[..i].contains(key));
        assert!(!operators[..i].contains(&operators[i]));
    }
}
