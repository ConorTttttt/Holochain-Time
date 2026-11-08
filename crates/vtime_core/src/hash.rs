//! The hash function Roughtime (RFC 10049 section 5.3) uses everywhere:
//! SHA-512 truncated to its first 32 bytes. We reuse it for seal nonces so a
//! single primitive covers every commitment in this crate.

use alloc::string::String;
use alloc::vec::Vec;
use sha2::{Digest, Sha512};

use crate::error::{malformed, Result};

/// A 32-byte truncated SHA-512 digest.
pub type Hash32 = [u8; 32];

/// `H(parts[0] || parts[1] || ...)`, SHA-512 truncated to 32 bytes.
pub fn h(parts: &[&[u8]]) -> Hash32 {
    let mut digest = Sha512::new();
    for part in parts {
        digest.update(part);
    }
    let full = digest.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex. Statements use lowercase only, so encodings are canonical.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Strict lowercase hex decoding. Upper case is rejected so that every byte
/// string has exactly one accepted text form.
pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return malformed("hex string has odd length");
    }
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        match (nibble(pair[0]), nibble(pair[1])) {
            (Some(hi), Some(lo)) => out.push((hi << 4) | lo),
            _ => return malformed("hex string has a non-lowercase-hex character"),
        }
    }
    Ok(out)
}

/// Decode exactly 32 bytes of lowercase hex.
pub fn hex32(s: &str) -> Result<[u8; 32]> {
    let v = from_hex(s)?;
    v.try_into().or_else(|_| malformed("expected 32 bytes of hex"))
}
