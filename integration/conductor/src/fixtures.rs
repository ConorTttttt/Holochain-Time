//! Insecure, deterministic RFC 10049 test signers. NEVER use these
//! publicly-known seeds as production trusted time source keys.
use roughenough_keys::seed::MemoryBackend;
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::Request;
use roughenough_protocol::tags::ProtocolVersion;
use roughenough_protocol::util::ClockSource;
use roughenough_protocol::FromFrame;
use roughenough_server::keysource::KeySource;
use roughenough_server::responses::ResponseHandler;
use std::net::SocketAddr;
use std::time::Duration;
use vtime_core::evidence::RoughtimeEvidence;
use vtime_core::roughtime::{build_request, VERSION_RFC};

pub const INSECURE_TEST_SEEDS: [u8; 4] = [51, 52, 53, 54];

fn signer(seed: u8, epoch_seconds: u64) -> KeySource {
    assert!(INSECURE_TEST_SEEDS.contains(&seed));
    KeySource::new(
        Box::new(MemoryBackend::from_value(&[seed; 32])),
        ClockSource::new_mock(epoch_seconds),
        Duration::from_secs(8_000_000),
    )
}

pub fn test_public_keys() -> Vec<[u8; 32]> {
    let keys: Vec<[u8; 32]> = INSECURE_TEST_SEEDS
        .iter()
        .map(|seed| signer(*seed, 1_800_000_000).public_key_bytes())
        .collect();
    for (i, key) in keys.iter().enumerate() {
        assert!(!keys[..i].contains(key), "duplicate test signing source");
    }
    keys
}

pub fn signed_roughtime(seed: u8, nonce: [u8; 32], epoch_seconds: u64) -> RoughtimeEvidence {
    let source = signer(seed, epoch_seconds);
    let key = source.public_key_bytes();
    let mut handler = ResponseHandler::new(8, source);
    let request = build_request(&nonce, &[VERSION_RFC], Some(&key));
    let mut owned = request.clone();
    let parsed = Request::from_frame(&mut ParseCursor::new(&mut owned))
        .expect("test RFC request must parse");
    let addr: SocketAddr = "127.0.0.1:2002".parse().unwrap();
    handler.add_request(&request, parsed, ProtocolVersion::RFC, addr);
    let mut response = Vec::new();
    handler.process_responses(|_, bytes| response = bytes.to_vec());
    assert!(!response.is_empty(), "Roughenough signed no response");
    RoughtimeEvidence {
        server_public_key: key.to_vec(),
        request,
        response,
    }
}

pub fn signed_three(nonce: [u8; 32], epoch_seconds: u64) -> Vec<RoughtimeEvidence> {
    INSECURE_TEST_SEEDS[..3]
        .iter()
        .map(|seed| signed_roughtime(*seed, nonce, epoch_seconds))
        .collect()
}
