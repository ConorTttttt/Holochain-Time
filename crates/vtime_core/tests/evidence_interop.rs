//! Sprint 18: versioned interop envelope, cross-language golden vectors and
//! genuine responses from the independent Roughenough implementation.
#[path = "../../../integration/interop/wire.rs"]
mod wire;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::Request;
use roughenough_protocol::tags::ProtocolVersion;
use roughenough_protocol::FromFrame;
use roughenough_server::test_utils::TestContext;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use vtime_core::evidence::verify_evidence_set;
use vtime_core::hash::{from_hex, hex32, to_hex};
use vtime_core::roughtime::{build_request, verify_response, VERSION_RFC};
use vtime_core::{
    DalekVerifier, Error, RoughtimeEvidence, SignedOracleStatement, TimeEvidence, TimePolicy,
};
use wire::{Envelope, FORMAT, VERSION};

const ORACLE_JSON: &str = include_str!("../../../integration/interop/fixtures/v1_oracle.json");
const RT_JSON: &str = include_str!("../../../integration/interop/fixtures/roughtime_rfc_v1.json");

#[derive(Deserialize)]
struct OracleFixture {
    schema: String,
    wire_base64: String,
    wire_sha256: String,
    statement_signing_bytes_sha256: String,
    public_key_hex: String,
    nonce_hex: String,
    dna: String,
}

#[derive(Deserialize)]
struct RoughtimeFixture {
    schema: String,
    server_public_key_hex: String,
    request_b64: String,
    response_b64: String,
    request_sha256: String,
    response_sha256: String,
    nonce_hex: String,
    expected_midpoint_s: u64,
    expected_radius_s: u32,
    invalid_cases: Vec<InvalidCase>,
}
#[derive(Deserialize)]
struct InvalidCase {
    id: String,
    operation: String,
    expected: String,
    offset: Option<usize>,
    response_b64: Option<String>,
}

fn oracle_fixture() -> (OracleFixture, Vec<u8>, Vec<TimeEvidence>) {
    let fixture: OracleFixture = serde_json::from_str(ORACLE_JSON).unwrap();
    assert_eq!(fixture.schema, "hc-vtime-sprint18-canonical-v1");
    let bytes = STANDARD.decode(&fixture.wire_base64).unwrap();
    assert_eq!(to_hex(&Sha256::digest(&bytes)), fixture.wire_sha256);
    let envelope = Envelope::decode(&bytes).expect("foreign MessagePack oracle vector rejected");
    assert_eq!(envelope.format, FORMAT);
    assert_eq!(envelope.version, VERSION);
    let evidence = envelope.into_core().unwrap();
    (fixture, bytes, evidence)
}

fn rt_fixture() -> (RoughtimeFixture, [u8; 32], RoughtimeEvidence) {
    let fixture: RoughtimeFixture = serde_json::from_str(RT_JSON).unwrap();
    assert_eq!(fixture.schema, "hc-vtime-sprint18-roughtime-v1");
    let key = hex32(&fixture.server_public_key_hex).unwrap();
    let request = STANDARD.decode(&fixture.request_b64).unwrap();
    let response = STANDARD.decode(&fixture.response_b64).unwrap();
    assert_eq!(to_hex(&Sha256::digest(&request)), fixture.request_sha256);
    assert_eq!(to_hex(&Sha256::digest(&response)), fixture.response_sha256);
    assert_eq!(request.len(), 1024);
    (
        fixture,
        key,
        RoughtimeEvidence {
            server_public_key: key.to_vec(),
            request,
            response,
        },
    )
}

fn policy(servers: Vec<[u8; 32]>, oracles: Vec<[u8; 32]>, dna: String, min: u32) -> TimePolicy {
    TimePolicy {
        roughtime_servers: servers,
        oracles,
        min_sources: min,
        max_faulty: 0,
        max_radius_us: 10_000_000,
        oracle_dna: Some(dna),
    }
}

#[test]
fn python_signed_oracle_golden_matches_holochain_signing_bytes_and_core() {
    let (fixture, wire_bytes, evidence) = oracle_fixture();
    assert_eq!(
        Envelope::from_core(&evidence).unwrap().encode().unwrap(),
        wire_bytes
    );
    let oracle: &SignedOracleStatement = match &evidence[0] {
        TimeEvidence::Oracle(o) => o,
        _ => panic!("golden vector should contain a signed oracle statement"),
    };
    assert_eq!(
        to_hex(&Sha256::digest(oracle.statement.signing_bytes().unwrap())),
        fixture.statement_signing_bytes_sha256
    );
    assert_eq!(oracle.statement.dna, fixture.dna);
    let pk = hex32(&fixture.public_key_hex).unwrap();
    let nonce = hex32(&fixture.nonce_hex).unwrap();
    let p = policy(vec![], vec![pk], fixture.dna, 1);
    let direct = verify_evidence_set(&evidence, &p, &DalekVerifier, Some(&nonce)).unwrap();
    let via_wire = Envelope::verify(&wire_bytes, &p, &DalekVerifier, Some(&nonce)).unwrap();
    assert_eq!(direct, via_wire);
}

#[test]
fn independently_signed_rfc_roughtime_golden_verifies_in_both_paths() {
    let (fixture, key, rt) = rt_fixture();
    let nonce = hex32(&fixture.nonce_hex).unwrap();
    let verified = verify_response(&key, &rt.request, &rt.response, &DalekVerifier)
        .expect("cross-language RFC 10049 vector must pass strict Rust verification");
    assert_eq!(verified.nonce, nonce);
    assert_eq!(verified.midpoint_s, fixture.expected_midpoint_s);
    assert_eq!(verified.radius_s, fixture.expected_radius_s);
    let (_, _, oracle) = oracle_fixture();
    let dna = match &oracle[0] {
        TimeEvidence::Oracle(s) => s.statement.dna.clone(),
        _ => unreachable!(),
    };
    let p = policy(vec![key], vec![], dna, 1);
    let raw = vec![TimeEvidence::Roughtime(rt)];
    let envelope_bytes = Envelope::from_core(&raw).unwrap().encode().unwrap();
    assert_eq!(
        Envelope::decode(&envelope_bytes)
            .unwrap()
            .into_core()
            .unwrap(),
        raw
    );
    let direct = verify_evidence_set(&raw, &p, &DalekVerifier, Some(&nonce)).unwrap();
    let via_wire = Envelope::verify(&envelope_bytes, &p, &DalekVerifier, Some(&nonce)).unwrap();
    assert_eq!(via_wire, direct);
}

#[test]
fn mixed_source_quorum_uses_identical_trusted_policy_for_direct_and_wire() {
    let (fixture, key, rt) = rt_fixture();
    let (oracle_fixture, _, mut oracle) = oracle_fixture();
    let oracle_key = hex32(&oracle_fixture.public_key_hex).unwrap();
    let nonce = hex32(&fixture.nonce_hex).unwrap();
    let mut items = vec![TimeEvidence::Roughtime(rt)];
    items.append(&mut oracle);
    let p = policy(vec![key], vec![oracle_key], oracle_fixture.dna, 2);
    let raw = verify_evidence_set(&items, &p, &DalekVerifier, Some(&nonce)).unwrap();
    let wire_bytes = Envelope::from_core(&items).unwrap().encode().unwrap();
    assert_eq!(
        raw,
        Envelope::verify(&wire_bytes, &p, &DalekVerifier, Some(&nonce)).unwrap()
    );
    assert_eq!(
        items,
        Envelope::decode(&wire_bytes).unwrap().into_core().unwrap()
    );
    assert!(Envelope::verify(&wire_bytes, &p, &DalekVerifier, Some(&[9; 32])).is_err());
}

#[test]
fn roughtime_invalid_mutations_fail_closed_with_expected_error_family() {
    let (fixture, key, rt) = rt_fixture();
    assert_eq!(fixture.invalid_cases.len(), 7);
    let nonce = hex32(&fixture.nonce_hex).unwrap();
    for case in fixture.invalid_cases {
        let mut request = rt.request.clone();
        let mut response = rt.response.clone();
        match case.operation.as_str() {
            "flip_response_byte" => {
                let at = case.offset.expect("fixture needs byte offset");
                assert!(at >= 12 && at < response.len());
                response[at] ^= 1;
            }
            "flip_response_nonce" => {
                let at = response
                    .windows(nonce.len())
                    .position(|window| window == nonce.as_slice())
                    .expect("signed response contains nonce");
                response[at] ^= 1;
            }
            "overwrite_frame_length_max" => {
                response[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
            }
            "truncate_response_by_one" => {
                response.pop();
            }
            "flip_request_nonce" => {
                let at = request
                    .windows(nonce.len())
                    .position(|window| window == nonce.as_slice())
                    .expect("signed request contains nonce");
                request[at] ^= 1;
            }
            "pad_response_to_16385" => {
                response.resize(16_385, 0);
            }
            "replace_response" => {
                response = STANDARD
                    .decode(case.response_b64.as_ref().unwrap())
                    .unwrap();
            }
            other => panic!("unrecognized mutation {other}"),
        }
        let result = verify_response(&key, &request, &response, &DalekVerifier)
            .expect_err(&format!("{} unexpectedly accepted", case.id));
        let matches_family = match case.expected.as_str() {
            "bad_signature" => matches!(result, Error::BadSignature(_)),
            "nonce_mismatch" => matches!(result, Error::NonceMismatch),
            "malformed" => matches!(result, Error::Malformed(_)),
            "unsupported_version" => matches!(result, Error::UnsupportedVersion(2)),
            "invalid" => {
                matches!(result, Error::MerkleMismatch)
                    || matches!(result, Error::NonceMismatch)
                    || matches!(result, Error::BadSignature(_))
            }
            _ => false,
        };
        assert!(
            matches_family,
            "{} wrong rejection family: {result:?}",
            case.id
        );
    }
}

#[test]
fn roughenough_reference_server_exchanges_survive_v1_roundtrip() {
    let (_, _, oracle) = oracle_fixture();
    let dna = match &oracle[0] {
        TimeEvidence::Oracle(s) => s.statement.dna.clone(),
        _ => unreachable!(),
    };
    let mut context = TestContext::new_at(32, 1_792_000_000);
    let server_key = context.key_source.public_key_bytes();
    let address: SocketAddr = "127.0.0.1:2002".parse().unwrap();
    let nonces: Vec<_> = (0..13u8).map(|b| [b; 32]).collect();
    let mut requests = Vec::new();
    for nonce in &nonces {
        let packet = build_request(nonce, &[VERSION_RFC], Some(&server_key));
        let mut packet_copy = packet.clone();
        let parsed = Request::from_frame(&mut ParseCursor::new(&mut packet_copy)).unwrap();
        context
            .response_handler
            .add_request(&packet, parsed, ProtocolVersion::RFC, address);
        requests.push(packet);
    }
    let mut responses = Vec::new();
    context
        .response_handler
        .process_responses(|_, packet| responses.push(packet.to_vec()));
    assert_eq!(responses.len(), nonces.len());
    for (i, (request, response)) in requests.into_iter().zip(responses).enumerate() {
        let rt = RoughtimeEvidence {
            server_public_key: server_key.to_vec(),
            request,
            response,
        };
        let items = vec![TimeEvidence::Roughtime(rt)];
        let p = policy(vec![server_key], vec![], dna.clone(), 1);
        let direct = verify_evidence_set(&items, &p, &DalekVerifier, Some(&nonces[i])).unwrap();
        let bytes = Envelope::from_core(&items).unwrap().encode().unwrap();
        let through_envelope =
            Envelope::verify(&bytes, &p, &DalekVerifier, Some(&nonces[i])).unwrap();
        assert_eq!(direct, through_envelope, "reference exchange {i} diverged");
        assert_eq!(
            Envelope::decode(&bytes).unwrap().into_core().unwrap(),
            items
        );
    }
}

#[test]
fn strict_envelope_rejects_unsupported_versions_unknown_fields_and_bad_binary() {
    let (oracle_fixture, valid, evidence) = oracle_fixture();
    let envelope = Envelope::decode(&valid).unwrap();
    let mut unsupported = envelope.clone();
    unsupported.version = 2;
    // Manually encode the unsupported typed schema without Envelope::encode,
    // which deliberately rejects a future version.
    let unknown_version = rmp_serde::to_vec_named(&unsupported).unwrap();
    assert!(Envelope::decode(&unknown_version)
        .unwrap_err()
        .contains("unsupported"));
    let mut wrong_format = envelope.clone();
    wrong_format.format = "another/protocol".into();
    assert!(Envelope::decode(&rmp_serde::to_vec_named(&wrong_format).unwrap()).is_err());

    // Unknown fields are rejected at the outer and every nested level, even
    // if an upstream serializer supplies them in otherwise valid MessagePack.
    let top = serde_json::json!({"format": FORMAT, "version": 1, "items": [], "future": 1});
    assert!(Envelope::decode(&rmp_serde::to_vec_named(&top).unwrap()).is_err());
    let nested = serde_json::json!({"format": FORMAT, "version": 1,
    "items": [{"kind": "roughtime", "roughtime": {
        "server_public_key": vec![1u8; 32], "request": [1], "response": [2],
        "future": "unexpected"
    }}]});
    assert!(Envelope::decode(&rmp_serde::to_vec_named(&nested).unwrap()).is_err());
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(Envelope::decode(&trailing).is_err());

    for len in 0..valid.len() {
        assert!(
            Envelope::decode(&valid[..len]).is_err(),
            "accepted truncated length {len}"
        );
    }
    assert!(Envelope::decode(&vec![0xFF; wire::MAX_WIRE_BYTES + 1]).is_err());
    let mut mutation = valid.clone();
    let at = mutation.len() - 8;
    mutation[at] ^= 1;
    let p = policy(
        vec![],
        vec![hex32(&oracle_fixture.public_key_hex).unwrap()],
        oracle_fixture.dna,
        1,
    );
    let nonce = hex32(&oracle_fixture.nonce_hex).unwrap();
    assert!(Envelope::verify(&mutation, &p, &DalekVerifier, Some(&nonce)).is_err());

    let mut invalid_tag = envelope.clone();
    invalid_tag.items[0].kind = "oracle_v9".into();
    assert!(invalid_tag.encode().is_err());
    let mut malformed = envelope.clone();
    malformed.items[0].roughtime = Some(wire::WireRoughtime {
        server_public_key: serde_bytes::ByteBuf::from(vec![0; 32]),
        request: serde_bytes::ByteBuf::from(vec![]),
        response: serde_bytes::ByteBuf::from(vec![]),
    });
    assert!(malformed.encode().is_err());
    let mut extra = evidence;
    let duplicate = extra[0].clone();
    extra.resize(33, duplicate);
    assert!(Envelope::from_core(&extra).is_err());
}

#[test]
fn oracle_stated_dna_is_authenticated_not_rewritten_by_envelope() {
    let (fixture, raw, _) = oracle_fixture();
    let pk: [u8; 32] = from_hex(&fixture.public_key_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let nonce = hex32(&fixture.nonce_hex).unwrap();
    let incorrect_dna = vtime_core::keys::dna_hash_to_b64(&[2u8; 32]);
    let p = policy(vec![], vec![pk], incorrect_dna, 1);
    assert!(Envelope::verify(&raw, &p, &DalekVerifier, Some(&nonce)).is_err());
}
