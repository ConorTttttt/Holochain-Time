//! Ed25519 verification is abstracted so the same evidence logic can run
//! natively (tests, oracles, off-chain tools) with `ed25519-dalek`, and inside
//! an integrity zome through the Holochain host, which is faster than
//! interpreted WASM on iOS (wasmi) and is the verifier every peer shares.

use crate::error::Result;

/// Verifies a detached Ed25519 signature over raw bytes.
pub trait Ed25519Verifier {
    /// `Ok(false)` for a well-formed but wrong signature; `Err` only when the
    /// verifier itself cannot run.
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<bool>;
}

/// Pure-Rust verifier using `ed25519-dalek` in strict mode.
#[cfg(feature = "dalek")]
#[derive(Debug, Default, Clone, Copy)]
pub struct DalekVerifier;

#[cfg(feature = "dalek")]
impl Ed25519Verifier for DalekVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<bool> {
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
            return Ok(false);
        };
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        Ok(key.verify_strict(message, &sig).is_ok())
    }
}
