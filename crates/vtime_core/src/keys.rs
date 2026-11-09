//! Holochain's text form of 39-byte hashes (`AgentPubKeyB64`, `DnaHashB64`):
//! the letter `u` followed by unpadded base64url of 3-byte type prefix ||
//! 32-byte core || 4 DHT location bytes.
//!
//! The location bytes are a checksum of the core (BLAKE2b-128 folded to four
//! bytes, exactly as `holo_hash` computes them), and decoding here checks
//! them, as `holo_hash` does. Without that check, 2^32 different strings would
//! decode to the same key. Statements sign the key *text*, and Unyt templates
//! compare it as text, so a lenient decoder here would let one oracle sign
//! under spellings that Holochain validation counts as its own but a bond
//! never matches (see SECURITY_REVIEW.md, finding on non-canonical keys).

use alloc::string::String;
use alloc::vec::Vec;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;

use crate::error::{malformed, Result};

/// Type prefix of an agent public key in Holochain's 39-byte hash format.
pub const AGENT_PREFIX: [u8; 3] = [0x84, 0x20, 0x24];
/// Type prefix of a DNA hash in Holochain's 39-byte hash format ("uhC0k").
pub const DNA_PREFIX: [u8; 3] = [0x84, 0x2d, 0x24];

/// The 4 DHT location bytes `holo_hash` appends to a 32-byte core:
/// BLAKE2b with a 16-byte output, XOR-folded into 4 bytes.
pub fn location_bytes(core: &[u8; 32]) -> [u8; 4] {
    let hash = blake2b_simd::Params::new().hash_length(16).hash(core);
    let h = hash.as_bytes();
    let mut out = [h[0], h[1], h[2], h[3]];
    for i in (4..16).step_by(4) {
        out[0] ^= h[i];
        out[1] ^= h[i + 1];
        out[2] ^= h[i + 2];
        out[3] ^= h[i + 3];
    }
    out
}

/// Decode Holochain's text form of a 39-byte hash with the given type prefix,
/// accepting only the one canonical spelling of each hash.
fn holo_hash_from_b64(s: &str, prefix: [u8; 3], what: &str) -> Result<[u8; 39]> {
    let Some(rest) = s.strip_prefix('u') else {
        return malformed(alloc::format!("{what} text must start with 'u'"));
    };
    // 39 bytes encode to exactly 52 characters with no spare bits, so this
    // decoding has one accepted text form per byte string.
    if rest.len() != 52 {
        return malformed(alloc::format!(
            "{what} must be 52 base64url characters after 'u'"
        ));
    }
    let raw = URL_SAFE_NO_PAD
        .decode(rest)
        .or_else(|_| malformed(alloc::format!("{what} is not base64url")))?;
    let raw: [u8; 39] = raw
        .try_into()
        .or_else(|_| malformed(alloc::format!("{what} is not 39 bytes")))?;
    if raw[0..3] != prefix {
        return malformed(alloc::format!("{what} has the wrong hash type prefix"));
    }
    let mut core = [0u8; 32];
    core.copy_from_slice(&raw[3..35]);
    if raw[35..39] != location_bytes(&core) {
        return malformed(alloc::format!("{what} has a bad location checksum"));
    }
    Ok(raw)
}

/// Extract the raw Ed25519 key from an `AgentPubKeyB64` string.
pub fn agent_key_from_b64(s: &str) -> Result<[u8; 32]> {
    let raw = holo_hash_from_b64(s, AGENT_PREFIX, "agent key")?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw[3..35]);
    Ok(key)
}

/// Check a `DnaHashB64` string and return its 39 raw bytes.
pub fn dna_hash_from_b64(s: &str) -> Result<[u8; 39]> {
    holo_hash_from_b64(s, DNA_PREFIX, "DNA hash")
}

fn to_holo_b64(prefix: [u8; 3], core: &[u8; 32]) -> String {
    let mut raw = Vec::with_capacity(39);
    raw.extend_from_slice(&prefix);
    raw.extend_from_slice(core);
    raw.extend_from_slice(&location_bytes(core));
    let mut s = String::from("u");
    s.push_str(&URL_SAFE_NO_PAD.encode(raw));
    s
}

/// The canonical `AgentPubKeyB64` string of a raw Ed25519 key (identical to
/// `holo_hash`'s `AgentPubKey::from_raw_32(key).to_string()`).
pub fn agent_key_to_b64(key: &[u8; 32]) -> String {
    to_holo_b64(AGENT_PREFIX, key)
}

/// The canonical `DnaHashB64` string of a 32-byte DNA hash core.
pub fn dna_hash_to_b64(core: &[u8; 32]) -> String {
    to_holo_b64(DNA_PREFIX, core)
}

/// Decode a Roughtime server key as operators publish it: standard base64 of
/// the 32-byte Ed25519 public key (e.g. in a Roughtime server list).
pub fn roughtime_key_from_b64(s: &str) -> Result<[u8; 32]> {
    let raw = STANDARD
        .decode(s.trim())
        .or_else(|_| malformed("Roughtime server key is not standard base64"))?;
    raw.try_into()
        .or_else(|_| malformed("Roughtime server key must be 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_key_round_trip() {
        let key = [9u8; 32];
        let s = agent_key_to_b64(&key);
        assert!(s.starts_with("uhCAk"), "{s}");
        assert_eq!(s.len(), 53);
        assert_eq!(agent_key_from_b64(&s).unwrap(), key);
    }

    /// Regression (review: non-canonical key text). Every spelling of a key
    /// other than the one with the right location bytes is refused, so a key
    /// has exactly one accepted text form. The baseline accepted all 2^32.
    #[test]
    fn wrong_location_bytes_are_rejected() {
        let key = [9u8; 32];
        let good = agent_key_to_b64(&key);
        let mut raw = URL_SAFE_NO_PAD.decode(&good[1..]).unwrap();
        for byte in 35..39 {
            for flip in [0x01u8, 0x80] {
                raw[byte] ^= flip;
                let variant = alloc::format!("u{}", URL_SAFE_NO_PAD.encode(&raw));
                raw[byte] ^= flip;
                assert_ne!(variant, good);
                assert!(agent_key_from_b64(&variant).is_err(), "accepted {variant}");
            }
        }
        // The old fixture style (zero location bytes) is no longer accepted.
        let mut zero = raw.clone();
        zero[35..39].copy_from_slice(&[0; 4]);
        assert!(agent_key_from_b64(&alloc::format!("u{}", URL_SAFE_NO_PAD.encode(&zero))).is_err());
    }

    #[test]
    fn rejects_other_hash_types() {
        // An ActionHash prefix (84 29 24) must not pass as an agent key.
        let mut raw = alloc::vec![0x84, 0x29, 0x24];
        raw.extend_from_slice(&[0u8; 32]);
        raw.extend_from_slice(&location_bytes(&[0u8; 32]));
        let s = alloc::format!("u{}", URL_SAFE_NO_PAD.encode(raw));
        assert!(agent_key_from_b64(&s).is_err());
        assert!(dna_hash_from_b64(&s).is_err());
        // Agent keys and DNA hashes do not stand in for each other.
        let agent = agent_key_to_b64(&[1; 32]);
        let dna = dna_hash_to_b64(&[1; 32]);
        assert!(dna.starts_with("uhC0k"), "{dna}");
        assert!(dna_hash_from_b64(&agent).is_err());
        assert!(agent_key_from_b64(&dna).is_err());
        assert_eq!(dna_hash_from_b64(&dna).unwrap()[3..35], [1; 32]);
        // Trailing data is not tolerated.
        assert!(dna_hash_from_b64(&alloc::format!("{dna}A")).is_err());
    }
}
