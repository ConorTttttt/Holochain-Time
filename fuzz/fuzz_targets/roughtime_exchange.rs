#![no_main]
//! Arbitrary request/response pairs through the actual cryptographic verifier.
use libfuzzer_sys::fuzz_target;
use vtime_core::roughtime::{build_request, verify_response, VERSION_RFC};
use vtime_core::DalekVerifier;

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    // The first two bytes choose the split. Include edge cases: empty,
    // truncated and oversized requests/responses, including response-only.
    let (request, response): (&[u8], &[u8]) = if data.len() >= 2 {
        let split = (u16::from_le_bytes([data[0], data[1]]) as usize)
            .min(data.len() - 2);
        let bytes = &data[2..];
        bytes.split_at(split)
    } else {
        (data, &[])
    };
    let _ = verify_response(&[0u8; 32], request, response, &DalekVerifier);
    // Also exercise response checking with a well-formed RFC request so mutated
    // responses can reach deeper certificate/delegation/Merkle parsing.
    let good_request = build_request(&[0x73; 32], &[VERSION_RFC], None);
    let _ = verify_response(&[0u8; 32], &good_request, data, &DalekVerifier);
});
