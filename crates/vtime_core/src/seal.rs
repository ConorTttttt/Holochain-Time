//! Binding readings to a specific Holochain action.
//!
//! A seal's readings are requested with a nonce derived from the DNA hash and
//! the target action hash. A trusted source can only sign that nonce after the
//! action hash exists, and the action hash covers the action's timestamp,
//! author, chain position and entry, so the reading bounds the action from
//! above. Including the DNA hash keeps a seal from being replayed into another
//! network that happens to contain the same action bytes.

use crate::hash::{h, Hash32};

/// Domain separation for seal nonces.
pub const SEAL_DOMAIN: &[u8] = b"hc-vtime/seal/v1\0";

/// H(SEAL_DOMAIN || len(dna) || dna || len(action) || action), lengths as
/// u32 little-endian, over the 39-byte Holochain hash encodings.
pub fn seal_nonce(dna_hash: &[u8], action_hash: &[u8]) -> Hash32 {
    h(&[
        SEAL_DOMAIN,
        &(dna_hash.len() as u32).to_le_bytes(),
        dna_hash,
        &(action_hash.len() as u32).to_le_bytes(),
        action_hash,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_nonce_separates_inputs() {
        let a = seal_nonce(&[1; 39], &[2; 39]);
        assert_ne!(a, seal_nonce(&[2; 39], &[1; 39]));
        // Moving a byte across the boundary changes the nonce (length prefixes).
        let mut action = [2u8; 40];
        action[0] = 1;
        assert_ne!(a, seal_nonce(&[1; 38], &action));
        assert_eq!(a, seal_nonce(&[1; 39], &[2; 39]));
    }
}
