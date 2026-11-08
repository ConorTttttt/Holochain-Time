//! Cross-implementation tests: responses produced by the independent
//! `roughenough` server code (RFC 10049 version 1) must verify with our
//! verifier, including Merkle paths from batched requests, and requests built
//! by our client code must be accepted by roughenough's parser.

use std::net::SocketAddr;

use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::Request;
use roughenough_protocol::tags::{Nonce, ProtocolVersion};
use roughenough_protocol::{FromFrame, ToFrame};
use roughenough_server::test_utils::TestContext;

use vtime_core::roughtime::{build_request, verify_response, VERSION_RFC};
use vtime_core::{DalekVerifier, Error};

const MIDPOINT: u64 = 1_792_000_000; // late October 2026

fn addr() -> SocketAddr {
    "127.0.0.1:2002".parse().unwrap()
}

/// Run one batch through the real response handler and return
/// (server key, [(request bytes, response bytes)]).
type Exchange = (Vec<u8>, Vec<u8>);

fn batch(requests: Vec<Vec<u8>>) -> ([u8; 32], Vec<Exchange>) {
    let mut ctx = TestContext::new_at(64, MIDPOINT);
    ctx.clock.set_time(MIDPOINT);
    let server_key = ctx.key_source.public_key_bytes();
    let handler = &mut ctx.response_handler;
    handler.clear();
    for bytes in &requests {
        let mut copy = bytes.clone();
        let mut cursor = ParseCursor::new(&mut copy);
        let parsed = Request::from_frame(&mut cursor).expect("roughenough parses the request");
        handler.add_request(bytes, parsed, ProtocolVersion::RFC, addr());
    }
    let mut responses = Vec::new();
    handler.process_responses(|_, resp| responses.push(resp.to_vec()));
    assert_eq!(responses.len(), requests.len());
    (server_key, requests.into_iter().zip(responses).collect())
}

fn roughenough_request(nonce: [u8; 32]) -> Vec<u8> {
    Request::new(&Nonce::from(nonce)).as_frame_bytes().unwrap()
}

#[test]
fn single_roughenough_response_verifies() {
    let (key, pairs) = batch(vec![roughenough_request([1; 32])]);
    let (req, resp) = &pairs[0];
    let v = verify_response(&key, req, resp, &DalekVerifier).expect("verifies");
    assert_eq!(v.version, VERSION_RFC);
    assert_eq!(v.nonce, [1; 32]);
    assert_eq!(v.midpoint_s, MIDPOINT);
    let i = v.interval().unwrap();
    assert!(i.contains(MIDPOINT as i64 * 1_000_000));
}

#[test]
fn batched_responses_with_merkle_paths_verify() {
    let reqs: Vec<Vec<u8>> = (0..13u8).map(|i| roughenough_request([i; 32])).collect();
    let (key, pairs) = batch(reqs);
    for (i, (req, resp)) in pairs.iter().enumerate() {
        let v = verify_response(&key, req, resp, &DalekVerifier)
            .unwrap_or_else(|e| panic!("request {i} failed: {e}"));
        assert_eq!(v.nonce, [i as u8; 32]);
    }
    // A response does not verify against a different request in the batch.
    assert!(verify_response(&key, &pairs[1].0, &pairs[2].1, &DalekVerifier).is_err());
}

#[test]
fn our_requests_are_accepted_and_verified() {
    let nonce = [0x5a; 32];
    let ours = build_request(&nonce, &[VERSION_RFC], None);
    let (key, pairs) = batch(vec![ours.clone(), roughenough_request([9; 32])]);
    let (req, resp) = &pairs[0];
    assert_eq!(req, &ours);
    let v = verify_response(&key, req, resp, &DalekVerifier).unwrap();
    assert_eq!(v.nonce, nonce);
}

#[test]
fn tampering_is_detected() {
    let (key, pairs) = batch(vec![roughenough_request([3; 32]), roughenough_request([4; 32])]);
    let (req, resp) = &pairs[0];

    // Wrong long-term key.
    let err = verify_response(&[0x11; 32], req, resp, &DalekVerifier).unwrap_err();
    assert!(matches!(err, Error::BadSignature(_)), "{err}");

    // Flip every byte of the response in turn: nothing may verify.
    for i in 12..resp.len() {
        let mut bad = resp.clone();
        bad[i] ^= 0x01;
        assert!(
            verify_response(&key, req, &bad, &DalekVerifier).is_err(),
            "flipping response byte {i} still verified"
        );
    }

    // A changed request (even in padding) breaks the Merkle inclusion.
    let mut bad_req = req.clone();
    let last = bad_req.len() - 1;
    bad_req[last] ^= 0x01;
    assert!(verify_response(&key, &bad_req, resp, &DalekVerifier).is_err());
}

/// Property test (deterministic, 30,000 cases): random structural mutations
/// of genuine exchanges, and random byte strings, never panic the parser or
/// verifier and never verify. Mutations include byte flips, truncation,
/// extension, overwritten length/count/offset words, and u32::MAX lengths,
/// which on 32-bit targets used to wrap `12 + len` in `unframe`.
#[test]
fn mutated_and_random_inputs_never_panic_or_verify() {
    use vtime_core::roughtime::{unframe, Message};

    let (key, pairs) = batch((0..4u8).map(|i| roughenough_request([i; 32])).collect());
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let interesting = [0u32, 1, 3, 4, 8, 64, 1024, 0x7fff_ffff, u32::MAX];
    for case in 0..30_000u32 {
        let (req, resp) = &pairs[case as usize % pairs.len()];
        let (mut req, mut resp) = (req.clone(), resp.clone());
        let target = if next() % 4 == 0 { &mut req } else { &mut resp };
        for _ in 0..1 + next() % 3 {
            match next() % 5 {
                0 if !target.is_empty() => {
                    let i = (next() as usize) % target.len();
                    target[i] ^= 1 << (next() % 8);
                }
                1 => target.truncate((next() as usize) % (target.len() + 1)),
                2 => target.extend(std::iter::repeat_n((next() & 0xff) as u8, 1 + (next() % 8) as usize)),
                _ if target.len() >= 4 => {
                    let at = ((next() as usize) % (target.len() / 4)) * 4;
                    let v = interesting[(next() as usize) % interesting.len()];
                    target[at..at + 4].copy_from_slice(&v.to_le_bytes());
                }
                _ => {}
            }
        }
        let original = &pairs[case as usize % pairs.len()];
        let changed = req != original.0 || resp != original.1;
        let result = verify_response(&key, &req, &resp, &DalekVerifier);
        if changed {
            assert!(result.is_err(), "case {case}: a mutated exchange verified");
        }

        // Random bytes straight into the low-level parsers.
        let len = (next() % 300) as usize;
        let mut junk: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        if len >= 12 && next() % 2 == 0 {
            junk[0..8].copy_from_slice(b"ROUGHTIM");
            let claimed = interesting[(next() as usize) % interesting.len()];
            junk[8..12].copy_from_slice(&claimed.to_le_bytes());
        }
        if let Ok(inner) = unframe(&junk) {
            let _ = Message::parse(inner);
        }
        let _ = Message::parse(&junk);
    }
}
