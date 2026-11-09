//! Experimental, bounded Merkle commitments for oracle nonce batches.
//!
//! This module proves *membership* in an independently authenticated root.
//! It DOES NOT authenticate an oracle signature or attest time. Current v2
//! statements, integrity validation and seals must not consume batch proofs.
//! A new signed v3 format and new DNA validation require separate review.

use alloc::format;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use crate::error::{malformed, Result};
use crate::hash::{h, Hash32};

/// Maximum count of distinct nonces in a future signed batch.
pub const MAX_BATCH_NONCES: usize = 128;
const LEAF: &[u8] = b"hc-vtime/oracle-batch/v1/leaf\0";
const NODE: &[u8] = b"hc-vtime/oracle-batch/v1/node\0";
const ROOT: &[u8] = b"hc-vtime/oracle-batch/v1/root\0";

/// A bounded Merkle membership proof; a signature on the root is also needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceInclusionProof {
    /// Zero-based position in the original batch.
    pub index: u16,
    /// Committed number of distinct requested nonces.
    pub count: u16,
    /// Sibling nodes from leaf to root; length must equal tree height.
    pub siblings: Vec<Hash32>,
}

fn leaf(dna: &[u8; 39], nonce: &[u8; 32]) -> Hash32 {
    h(&[LEAF, dna, nonce])
}
fn parent(left: &Hash32, right: &Hash32) -> Hash32 {
    h(&[NODE, left, right])
}
fn final_root(count: usize, top: &Hash32) -> Hash32 {
    h(&[ROOT, &(count as u32).to_le_bytes(), top])
}
fn validate(nonces: &[[u8; 32]]) -> Result<()> {
    if nonces.is_empty() || nonces.len() > MAX_BATCH_NONCES {
        return malformed(format!("batch requires 1 to {MAX_BATCH_NONCES} distinct nonces"));
    }
    // Bounded O(n²) check avoids another attacker-controlled allocation.
    for (i, nonce) in nonces.iter().enumerate() {
        if nonces[..i].contains(nonce) {
            return malformed("duplicate nonce in batch");
        }
    }
    Ok(())
}
fn next_level(nodes: &[Hash32]) -> Vec<Hash32> {
    let mut out = Vec::with_capacity(nodes.len().div_ceil(2));
    for pair in nodes.chunks(2) {
        out.push(parent(&pair[0], pair.get(1).unwrap_or(&pair[0])));
    }
    out
}

/// Commit to ordered, unique nonces and a Holochain DNA's 39-byte hash.
/// Roots also commit to the exact leaf count to prevent odd-node ambiguity.
pub fn commit_nonces(dna: &[u8; 39], nonces: &[[u8; 32]]) -> Result<Hash32> {
    validate(nonces)?;
    let mut nodes: Vec<Hash32> = nonces.iter().map(|n| leaf(dna, n)).collect();
    while nodes.len() > 1 {
        nodes = next_level(&nodes);
    }
    Ok(final_root(nonces.len(), &nodes[0]))
}

/// Produce an inclusion proof for trusted batch construction/test fixtures.
/// This is not a signature or time-attestation API.
pub fn prove_nonce(dna: &[u8; 39], nonces: &[[u8; 32]], index: usize) -> Result<NonceInclusionProof> {
    validate(nonces)?;
    if index >= nonces.len() {
        return malformed("nonce index outside the batch");
    }
    let mut nodes: Vec<Hash32> = nonces.iter().map(|n| leaf(dna, n)).collect();
    let mut at = index;
    let mut siblings = Vec::with_capacity(7);
    while nodes.len() > 1 {
        siblings.push(*nodes.get(at ^ 1).unwrap_or(&nodes[at]));
        nodes = next_level(&nodes);
        at /= 2;
    }
    Ok(NonceInclusionProof { index: index as u16, count: nonces.len() as u16, siblings })
}

/// Test nonce membership against a separately verified signed root.
/// Invalid metadata is an error, while an incorrect proof/root is false.
/// Never interpret true as an authenticated timestamp by itself.
pub fn verify_nonce_inclusion(
    dna: &[u8; 39],
    nonce: &[u8; 32],
    expected_root: &Hash32,
    proof: &NonceInclusionProof,
) -> Result<bool> {
    let mut width = usize::from(proof.count);
    let mut index = usize::from(proof.index);
    if width == 0 || width > MAX_BATCH_NONCES || index >= width {
        return malformed("invalid nonce proof index or count");
    }
    let mut height = 0;
    let mut w = width;
    while w > 1 {
        w = w.div_ceil(2);
        height += 1;
    }
    if proof.siblings.len() != height {
        return malformed("invalid nonce proof depth");
    }
    let mut node = leaf(dna, nonce);
    for sibling in &proof.siblings {
        // At an odd width the unpaired last node MUST duplicate itself.
        if width % 2 == 1 && index == width - 1 && sibling != &node {
            return Ok(false);
        }
        node = if index & 1 == 0 { parent(&node, sibling) } else { parent(sibling, &node) };
        index /= 2;
        width = width.div_ceil(2);
    }
    Ok(final_root(usize::from(proof.count), &node) == *expected_root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonces(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| {
            let mut nonce = [0u8; 32];
            nonce[..4].copy_from_slice(&(i as u32).to_le_bytes());
            nonce
        }).collect()
    }

    #[test]
    fn proof_for_every_index_at_edge_sizes() {
        let dna = [8u8; 39];
        for count in [1, 2, 3, 4, 5, 7, 8, 9, 31, 32, 33, 63, 64, 65, 100, 127, 128] {
            let batch = nonces(count);
            let root = commit_nonces(&dna, &batch).unwrap();
            for (index, nonce) in batch.iter().enumerate() {
                let p = prove_nonce(&dna, &batch, index).unwrap();
                assert!(verify_nonce_inclusion(&dna, nonce, &root, &p).unwrap(),
                    "count={count} index={index}");
            }
        }
    }

    #[test]
    fn forged_proofs_and_replays_fail() {
        let dna = [5u8; 39];
        let batch = nonces(5);
        let root = commit_nonces(&dna, &batch).unwrap();
        let proof = prove_nonce(&dna, &batch, 4).unwrap();
        assert!(verify_nonce_inclusion(&dna, &batch[4], &root, &proof).unwrap());
        assert!(!verify_nonce_inclusion(&[6; 39], &batch[4], &root, &proof).unwrap());
        assert!(!verify_nonce_inclusion(&dna, &batch[3], &root, &proof).unwrap());
        assert!(!verify_nonce_inclusion(&dna, &batch[4], &[3; 32], &proof).unwrap());
        let mut broken = proof.clone();
        broken.siblings[0] = [0x57; 32];
        assert!(!verify_nonce_inclusion(&dna, &batch[4], &root, &broken).unwrap());
        let mut index = proof.clone();
        index.index = 3;
        assert!(!verify_nonce_inclusion(&dna, &batch[4], &root, &index).unwrap());
        let mut count = proof.clone();
        count.count = 6;
        assert!(!verify_nonce_inclusion(&dna, &batch[4], &root, &count).unwrap());
        let mut extra = proof.clone();
        extra.siblings.push([1; 32]);
        assert!(verify_nonce_inclusion(&dna, &batch[4], &root, &extra).is_err());
    }

    #[test]
    fn invalid_batches_and_proofs_are_errors() {
        let dna = [0u8; 39];
        assert!(commit_nonces(&dna, &[]).is_err());
        assert!(commit_nonces(&dna, &nonces(129)).is_err());
        let mut batch = nonces(3);
        batch[2] = batch[0];
        assert!(commit_nonces(&dna, &batch).is_err());
        assert!(prove_nonce(&dna, &batch, 0).is_err());
        assert!(prove_nonce(&dna, &nonces(3), 3).is_err());
        for (count, index) in [(0, 0), (129, 0), (3, 3)] {
            let bad = NonceInclusionProof { count, index, siblings: Vec::new() };
            assert!(verify_nonce_inclusion(&dna, &[1; 32], &[0; 32], &bad).is_err());
        }
    }

    #[test]
    fn seals_cannot_reuse_another_targets_nonce() {
        let dna = [0x10u8; 39];
        let n1 = crate::seal::seal_nonce(&dna, &[0x21u8; 39]);
        let n2 = crate::seal::seal_nonce(&dna, &[0x22u8; 39]);
        let batch = [n1, [0x44; 32], [0x55; 32]];
        let root = commit_nonces(&dna, &batch).unwrap();
        let proof = prove_nonce(&dna, &batch, 0).unwrap();
        assert!(verify_nonce_inclusion(&dna, &n1, &root, &proof).unwrap());
        assert!(!verify_nonce_inclusion(&dna, &n2, &root, &proof).unwrap());
    }

    #[test]
    fn stable_cross_language_vector_and_count_binding() {
        let dna = [1u8; 39];
        let batch = nonces(3);
        let root = commit_nonces(&dna, &batch).unwrap();
        assert_eq!(crate::hash::to_hex(&root),
            "41a92f780ccafdcba3a0c058cfaea702d4a3ea83963fa084d874c46f268fe48d");
        assert_ne!(root, commit_nonces(&dna, &batch[..2]).unwrap());
        let mut reversed = batch.clone();
        reversed.reverse();
        assert_ne!(root, commit_nonces(&dna, &reversed).unwrap());
    }
}
