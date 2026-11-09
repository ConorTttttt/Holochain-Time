//! Candidate v3 signed Merkle-batch envelope for oracle nonces.
//!
//! This is a **pure** cryptographic contract, NOT a Holochain entry type,
//! signed source-chain log, quorum verifier, or network admission controller.
//! It does not change v2 evidence validation. Runtime integration requires a
//! separately reviewed integrity-zome and atomic oracle-log migration.
//!
//! In particular, a membership proof cannot establish that a signer did not
//! repeat another nonce elsewhere in the batch. Producers must enforce
//! distinctness and a full-batch audit needs the complete leaf list.

use alloc::format;
use alloc::vec::Vec;

use crate::batch::{commit_nonces, verify_nonce_inclusion, NonceInclusionProof, MAX_BATCH_NONCES};
use crate::error::{malformed, Error, Result};
use crate::hash::{to_hex, Hash32};
use crate::interval::TimeInterval;
use crate::keys::{location_bytes, DNA_PREFIX};
use crate::seal::seal_nonce;
use crate::verifier::Ed25519Verifier;

/// Signature domain. No existing `oracle-statement/v2` signature can authorize
/// this payload: even the first byte of its signing format is different.
pub const BATCH_STATEMENT_DOMAIN_V3: &[u8] = b"hc-vtime/oracle-batch-statement/v3\0";

/// Exactly this many bytes are signed, independent of the presence of optional
/// chain fields (which use explicit flags and zero-filled reserved slots).
pub const BATCH_SIGNING_BYTES_LEN: usize =
    BATCH_STATEMENT_DOMAIN_V3.len() + 39 + 32 + 32 + 2 + 8 + 8 + 8 + 1 + 64 + 1 + 8;

/// Signed batch statement. All multibyte integers are little-endian on wire;
/// `dna` is a canonical **39-byte** Holochain DNA hash including type prefix
/// and location checksum. `oracle` is the 32-byte Ed25519 key, not a claim of
/// trust: verifiers must also check an explicit allow-list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchStatementV3 {
    /// The Holochain network (39-byte typed DNA hash).
    pub dna: [u8; 39],
    /// Raw Ed25519 public key of the signing Holochain oracle.
    pub oracle: [u8; 32],
    /// Root of the v1 DNA-bound Merkle commitment to requested nonces.
    pub merkle_root: Hash32,
    /// Number of committed nonce leaves, between 1 and 128 inclusive.
    pub nonce_count: u16,
    /// Earliest claimed Unix time, in microseconds.
    pub earliest_us: i64,
    /// Latest claimed Unix time, in microseconds.
    pub latest_us: i64,
    /// Monotonically increasing statement number, starting with zero.
    pub seq: u64,
    /// Signature of the previous statement; absent only for seq zero.
    pub prev_signature: Option<[u8; 64]>,
    /// Prior largest signed earliest_us; absent only for seq zero.
    pub floor_us: Option<i64>,
}

/// One detached Ed25519 signature on the canonical statement bytes. A
/// variable-length vector is used for transport, but verification requires
/// **exactly 64 bytes**, before any signature operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedBatchStatementV3 {
    /// The signed v3 payload.
    pub statement: BatchStatementV3,
    /// Exactly 64 Ed25519 signature bytes.
    pub signature: Vec<u8>,
}

/// The durable, previously verified state of one oracle's ordered batch log.
/// An implementation must atomically persist this head with the signed batch.
/// Supplying no head only authorizes a **genesis** statement (`seq = 0`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchChainHeadV3 {
    /// Network (DNA) that owns this source chain.
    pub dna: [u8; 39],
    /// Oracle public key this source chain belongs to.
    pub oracle: [u8; 32],
    /// Sequence number of the last *accepted* statement.
    pub seq: u64,
    /// Signature of the last accepted statement.
    pub signature: [u8; 64],
    /// High-water earliest time for the next statement.
    pub next_floor_us: i64,
}

/// Facts established by checking a trusted signature and a strict log head.
/// This is not proof of a distributed quorum or published Holochain action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBatchV3 {
    /// The interval asserted by this oracle.
    interval: TimeInterval,
    /// The authenticated commitment root.
    merkle_root: Hash32,
    /// Signed number of committed leaves.
    nonce_count: u16,
    /// The new head to commit atomically when this batch is accepted.
    next_head: BatchChainHeadV3,
}

impl VerifiedBatchV3 {
    /// Authenticated time interval; not a distributed quorum by itself.
    pub fn interval(&self) -> TimeInterval {
        self.interval
    }

    /// Verified root of the signed v3 statement.
    pub fn merkle_root(&self) -> Hash32 {
        self.merkle_root
    }

    /// Number of nonce leaves signed by the oracle.
    pub fn nonce_count(&self) -> u16 {
        self.nonce_count
    }

    /// Durable next head. Persist it atomically with the accepted batch log.
    pub fn next_head(&self) -> &BatchChainHeadV3 {
        &self.next_head
    }
}

fn validate_dna(dna: &[u8; 39]) -> Result<()> {
    if dna[..3] != DNA_PREFIX[..] {
        return malformed("v3 batch DNA has wrong hash type prefix");
    }
    let mut core = [0u8; 32];
    core.copy_from_slice(&dna[3..35]);
    if dna[35..39] != location_bytes(&core) {
        return malformed("v3 batch DNA has invalid location checksum");
    }
    Ok(())
}

impl BatchStatementV3 {
    /// Validate all canonical, bounded fields before signing or verifying.
    pub fn validate(&self) -> Result<TimeInterval> {
        validate_dna(&self.dna)?;
        if self.nonce_count == 0 || usize::from(self.nonce_count) > MAX_BATCH_NONCES {
            return malformed(format!("v3 batch requires 1..={MAX_BATCH_NONCES} nonces"));
        }
        let interval = TimeInterval::new(self.earliest_us, self.latest_us)?;
        match (self.seq, self.prev_signature.as_ref(), self.floor_us) {
            (0, None, None) => (),
            (0, _, _) => return malformed("genesis batch must not carry prev/floor"),
            (_, Some(_), Some(floor)) => {
                // A batch may be slightly earlier than the old floor, but must
                // never *finish* before time already certified by this key.
                TimeInterval::new(floor, floor)?;
                if self.latest_us < floor {
                    return malformed("v3 batch time is behind its signed floor");
                }
            }
            _ => return malformed("non-genesis batch requires prev and floor"),
        }
        Ok(interval)
    }

    /// Canonical, fixed-width signed bytes; **never** use serde map encoding
    /// or reinterpret a v2 `nonce` field as a Merkle root.
    ///
    /// Layout: domain NUL | DNA 39 | oracle 32 | root 32 | count u16 LE |
    /// earliest i64 LE | latest i64 LE | seq u64 LE | prev-present u8 |
    /// prev 64 (zero when absent) | floor-present u8 | floor i64 LE
    /// (zero when absent). No padding, trailing data or alternate encoding.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::with_capacity(BATCH_SIGNING_BYTES_LEN);
        out.extend_from_slice(BATCH_STATEMENT_DOMAIN_V3);
        out.extend_from_slice(&self.dna);
        out.extend_from_slice(&self.oracle);
        out.extend_from_slice(&self.merkle_root);
        out.extend_from_slice(&self.nonce_count.to_le_bytes());
        out.extend_from_slice(&self.earliest_us.to_le_bytes());
        out.extend_from_slice(&self.latest_us.to_le_bytes());
        out.extend_from_slice(&self.seq.to_le_bytes());
        match &self.prev_signature {
            Some(sig) => {
                out.push(1);
                out.extend_from_slice(sig);
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 64]);
            }
        }
        match self.floor_us {
            Some(floor) => {
                out.push(1);
                out.extend_from_slice(&floor.to_le_bytes());
            }
            None => {
                out.push(0);
                out.extend_from_slice(&0i64.to_le_bytes());
            }
        }
        debug_assert_eq!(out.len(), BATCH_SIGNING_BYTES_LEN);
        Ok(out)
    }

    /// Decode exactly one canonical signing payload. Refuses wrong domains,
    /// lengths, nonzero reserved bytes, invalid flags and invalid fields.
    /// This does not verify a signature: use [`verify_signed_batch_v3`].
    pub fn from_signing_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BATCH_SIGNING_BYTES_LEN || !bytes.starts_with(BATCH_STATEMENT_DOMAIN_V3) {
            return malformed("v3 batch has wrong size or signature domain");
        }
        let mut pos = BATCH_STATEMENT_DOMAIN_V3.len();
        let mut take = |n: usize| {
            let slice = &bytes[pos..pos + n];
            pos += n;
            slice
        };
        let dna: [u8; 39] = take(39).try_into().expect("bounded DNA");
        let oracle: [u8; 32] = take(32).try_into().expect("bounded key");
        let merkle_root: [u8; 32] = take(32).try_into().expect("bounded root");
        let nonce_count = u16::from_le_bytes(take(2).try_into().expect("bounded count"));
        let earliest_us = i64::from_le_bytes(take(8).try_into().expect("bounded earliest"));
        let latest_us = i64::from_le_bytes(take(8).try_into().expect("bounded latest"));
        let seq = u64::from_le_bytes(take(8).try_into().expect("bounded seq"));
        let prev_flag = take(1)[0];
        let prev_bytes: [u8; 64] = take(64).try_into().expect("bounded prev");
        let floor_flag = take(1)[0];
        let floor_bytes: [u8; 8] = take(8).try_into().expect("bounded floor");
        debug_assert_eq!(pos, bytes.len());
        let prev_signature = match prev_flag {
            0 if prev_bytes == [0; 64] => None,
            1 => Some(prev_bytes),
            _ => return malformed("invalid v3 previous-signature flag or empty slot"),
        };
        let floor_us = match floor_flag {
            0 if floor_bytes == [0; 8] => None,
            1 => Some(i64::from_le_bytes(floor_bytes)),
            _ => return malformed("invalid v3 floor flag or empty slot"),
        };
        let statement = Self {
            dna,
            oracle,
            merkle_root,
            nonce_count,
            earliest_us,
            latest_us,
            seq,
            prev_signature,
            floor_us,
        };
        statement.validate()?;
        Ok(statement)
    }
}

/// Produce a candidate commitment with checked count and duplicate-nonce
/// rejection. The caller still must sign the resulting statement and commit
/// the signed source-chain log atomically; this is not a signing service.
pub fn prepare_batch_root(dna: &[u8; 39], nonces: &[[u8; 32]]) -> Result<(Hash32, u16)> {
    validate_dna(dna)?;
    let root = commit_nonces(dna, nonces)?;
    Ok((root, nonces.len() as u16)) // commit_nonces limited len to 128
}

/// Verify signature, source trust, DNA, time radius and the *expected* head.
///
/// This rejects replay/out-of-order statements against a durable previous
/// head, but does not make the head durable. A caller must store it atomically
/// and reject races; a stateless verifier cannot detect a network-wide replay.
pub fn verify_signed_batch_v3(
    signed: &SignedBatchStatementV3,
    expected_dna: &[u8; 39],
    trusted_oracles: &[[u8; 32]],
    max_radius_us: i64,
    previous_head: Option<&BatchChainHeadV3>,
    verifier: &dyn Ed25519Verifier,
) -> Result<VerifiedBatchV3> {
    validate_dna(expected_dna)?;
    let st = &signed.statement;
    if &st.dna != expected_dna {
        return Err(Error::WrongNetwork);
    }
    let interval = st.validate()?;
    if !trusted_oracles.contains(&st.oracle) {
        return Err(Error::UnknownSource(to_hex(&st.oracle)));
    }
    if max_radius_us < 0 {
        return malformed("negative v3 maximum time radius");
    }
    if interval.radius_us() > max_radius_us {
        return Err(Error::RadiusTooLarge { radius_us: interval.radius_us(), max_us: max_radius_us });
    }
    match previous_head {
        None if st.seq == 0 => (),
        None => return malformed("v3 batch lacks durable prior chain head"),
        Some(head) => {
            if head.dna != st.dna || head.oracle != st.oracle {
                return malformed("v3 batch previous head belongs to a different chain");
            }
            let next = head.seq.checked_add(1).ok_or(Error::Overflow)?;
            if st.seq != next
                || st.prev_signature.as_ref() != Some(&head.signature)
                || st.floor_us != Some(head.next_floor_us)
            {
                return malformed("v3 batch replay, fork or incorrect chain high-water mark");
            }
        }
    }
    let signature: &[u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .or_else(|_| malformed("v3 batch signature must be exactly 64 bytes"))?;
    if !verifier.verify(&st.oracle, &st.signing_bytes()?, signature)? {
        return Err(Error::BadSignature("v3 oracle batch statement"));
    }
    Ok(VerifiedBatchV3 {
        interval,
        merkle_root: st.merkle_root,
        nonce_count: st.nonce_count,
        next_head: BatchChainHeadV3 {
            dna: st.dna,
            oracle: st.oracle,
            seq: st.seq,
            signature: *signature,
            next_floor_us: st.floor_us.unwrap_or(st.earliest_us).max(st.earliest_us),
        },
    })
}

/// Verify that a specific nonce was in a trusted signed batch, following
/// authentication and chain-head checks. Does not prove all batch leaves are
/// unique, a multi-source quorum, or source-chain persistence.
pub fn verify_signed_batch_nonce_v3(
    signed: &SignedBatchStatementV3,
    proof: &NonceInclusionProof,
    expected_dna: &[u8; 39],
    nonce: &[u8; 32],
    trusted_oracles: &[[u8; 32]],
    max_radius_us: i64,
    previous_head: Option<&BatchChainHeadV3>,
    verifier: &dyn Ed25519Verifier,
) -> Result<VerifiedBatchV3> {
    let verified = verify_signed_batch_v3(
        signed, expected_dna, trusted_oracles, max_radius_us, previous_head, verifier,
    )?;
    verify_authenticated_batch_nonce_v3(&verified, proof, expected_dna, nonce)?;
    Ok(verified)
}

/// Check nonce membership in an **already verified** batch. Multiple target
/// nonces may be checked against the same cached, signed batch without
/// pretending that every inclusion is a new source-chain commit. The
/// `VerifiedBatchV3` object can only be constructed by this module's trusted
/// verification function; persisting it across processes requires re-checking
/// its original signature and authenticated prior chain state.
pub fn verify_authenticated_batch_nonce_v3(
    verified: &VerifiedBatchV3,
    proof: &NonceInclusionProof,
    expected_dna: &[u8; 39],
    nonce: &[u8; 32],
) -> Result<()> {
    validate_dna(expected_dna)?;
    if &verified.next_head.dna != expected_dna {
        return Err(Error::WrongNetwork);
    }
    if proof.count != verified.nonce_count {
        return malformed("v3 inclusion proof leaf count differs from signed count");
    }
    if !verify_nonce_inclusion(expected_dna, nonce, &verified.merkle_root, proof)? {
        return Err(Error::MerkleMismatch);
    }
    Ok(())
}

fn validate_action_hash(target: &[u8; 39]) -> Result<()> {
    const ACTION_PREFIX: [u8; 3] = [0x84, 0x29, 0x24];
    if target[..3] != ACTION_PREFIX[..] {
        return malformed("v3 seal target is not a Holochain ActionHash");
    }
    let mut core = [0u8; 32];
    core.copy_from_slice(&target[3..35]);
    if target[35..] != location_bytes(&core)[..] {
        return malformed("v3 seal target hash checksum invalid");
    }
    Ok(())
}

/// Verify a seal's action-specific nonce. A proof for a different action or
/// DNA cannot be used for this target, even if the oracle signature is real.
pub fn verify_signed_batch_seal_v3(
    signed: &SignedBatchStatementV3,
    proof: &NonceInclusionProof,
    expected_dna: &[u8; 39],
    target_action: &[u8; 39],
    trusted_oracles: &[[u8; 32]],
    max_radius_us: i64,
    previous_head: Option<&BatchChainHeadV3>,
    verifier: &dyn Ed25519Verifier,
) -> Result<VerifiedBatchV3> {
    validate_action_hash(target_action)?;
    let nonce = seal_nonce(expected_dna, target_action);
    verify_signed_batch_nonce_v3(
        signed, proof, expected_dna, &nonce, trusted_oracles, max_radius_us, previous_head, verifier,
    )
}

/// Verify a target's membership in a previously authenticated batch, without
/// consuming a new sequence position or verifying the batch signature again.
pub fn verify_authenticated_batch_seal_v3(
    verified: &VerifiedBatchV3,
    proof: &NonceInclusionProof,
    expected_dna: &[u8; 39],
    target_action: &[u8; 39],
) -> Result<()> {
    validate_action_hash(target_action)?;
    let nonce = seal_nonce(expected_dna, target_action);
    verify_authenticated_batch_nonce_v3(verified, proof, expected_dna, &nonce)
}
