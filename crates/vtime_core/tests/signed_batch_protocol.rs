//! Sprint 15: real Ed25519 signatures, deterministic v3 bytes and Merkle
//! inclusion. These native tests are not Holochain conductor acceptance.
use ed25519_dalek::{Signer, SigningKey};
use vtime_core::batch::{prove_nonce, NonceInclusionProof};
use vtime_core::hash::{h, to_hex};
use vtime_core::keys::{dna_hash_from_b64, dna_hash_to_b64, location_bytes};
use vtime_core::seal::seal_nonce;
use vtime_core::signed_batch::{
    prepare_batch_root, verify_authenticated_batch_seal_v3, verify_signed_batch_seal_v3,
    verify_signed_batch_v3, BatchChainHeadV3, BatchStatementV3, SignedBatchStatementV3,
    BATCH_SIGNING_BYTES_LEN, BATCH_STATEMENT_DOMAIN_V3,
};
use vtime_core::{DalekVerifier, Error};

const TIME: i64 = 1_792_000_000_000_000;
const RADIUS: i64 = 10_000_000;

fn dna(seed: u8) -> [u8; 39] {
    dna_hash_from_b64(&dna_hash_to_b64(&[seed; 32])).unwrap()
}

fn action(seed: u8) -> [u8; 39] {
    let mut hash = [0u8; 39];
    hash[0..3].copy_from_slice(&[0x84, 0x29, 0x24]);
    hash[3..35].fill(seed);
    hash[35..39].copy_from_slice(&location_bytes(&[seed; 32]));
    hash
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn statement(
    dna: [u8; 39],
    nonces: &[[u8; 32]],
    head: Option<&BatchChainHeadV3>,
) -> BatchStatementV3 {
    let (root, count) = prepare_batch_root(&dna, nonces).unwrap();
    BatchStatementV3 {
        dna,
        oracle: key().verifying_key().to_bytes(),
        merkle_root: root,
        nonce_count: count,
        earliest_us: TIME,
        latest_us: TIME + 1_000_000,
        seq: head.map_or(0, |h| h.seq + 1),
        prev_signature: head.map(|h| h.signature),
        floor_us: head.map(|h| h.next_floor_us),
    }
}

fn signed(st: BatchStatementV3) -> SignedBatchStatementV3 {
    let signature = key().sign(&st.signing_bytes().unwrap()).to_bytes().to_vec();
    SignedBatchStatementV3 {
        statement: st,
        signature,
    }
}

fn verify(
    s: &SignedBatchStatementV3,
    head: Option<&BatchChainHeadV3>,
) -> vtime_core::Result<vtime_core::signed_batch::VerifiedBatchV3> {
    verify_signed_batch_v3(
        s,
        &s.statement.dna,
        &[key().verifying_key().to_bytes()],
        RADIUS,
        head,
        &DalekVerifier,
    )
}

#[test]
fn genuine_signature_and_each_nonce_at_capacity() {
    let dna = dna(1);
    let targets: Vec<_> = (0..128u8).map(action).collect();
    let nonces: Vec<_> = targets.iter().map(|t| seal_nonce(&dna, t)).collect();
    let st = signed(statement(dna, &nonces, None));
    let verified = verify(&st, None).unwrap();
    assert_eq!(verified.nonce_count(), 128);
    assert_eq!(verified.interval().earliest_us, TIME);
    assert_eq!(verified.next_head().seq, 0);
    assert_eq!(verified.next_head().next_floor_us, TIME);
    // One verified statement is used for all 128 proofs; no additional
    // source-chain sequence positions are consumed.
    for (i, target) in targets.iter().enumerate() {
        let proof = prove_nonce(&dna, &nonces, i).unwrap();
        verify_authenticated_batch_seal_v3(&verified, &proof, &dna, target).unwrap();
    }
    let proof = prove_nonce(&dna, &nonces, 0).unwrap();
    let through_combined_path = verify_signed_batch_seal_v3(
        &st,
        &proof,
        &dna,
        &targets[0],
        &[key().verifying_key().to_bytes()],
        RADIUS,
        None,
        &DalekVerifier,
    )
    .unwrap();
    assert_eq!(through_combined_path.merkle_root(), verified.merkle_root());
}

#[test]
fn two_batches_have_ordered_verified_heads_and_old_batches_are_replays() {
    let dna = dna(4);
    let first_nonce = seal_nonce(&dna, &action(1));
    let first = signed(statement(dna, &[first_nonce], None));
    let state1 = verify(&first, None).unwrap();
    let head1 = state1.next_head().clone();
    assert!(
        verify(&first, Some(&head1)).is_err(),
        "replaying a previous signed head is prohibited"
    );
    let mut next = statement(dna, &[seal_nonce(&dna, &action(2))], Some(&head1));
    next.earliest_us = TIME + 200_000;
    next.latest_us = TIME + 1_200_000;
    let second = signed(next.clone());
    let state2 = verify(&second, Some(&head1)).unwrap();
    assert_eq!(state2.next_head().seq, 1);
    assert_eq!(state2.next_head().next_floor_us, TIME + 200_000);
    assert!(verify(&second, None).is_err());
    assert!(verify(&second, Some(state2.next_head())).is_err());
    // Fork from a stale head, even when signed with the legitimate key.
    let mut fork = next;
    fork.prev_signature = Some([77; 64]);
    assert!(verify(&signed(fork), Some(&head1)).is_err());
    let mut wrong_floor = second.statement.clone();
    wrong_floor.floor_us = Some(TIME - 1);
    assert!(verify(&signed(wrong_floor), Some(&head1)).is_err());
}

#[test]
fn honest_signature_on_other_dna_or_action_never_authorizes_this_target() {
    let d = dna(7);
    let target = action(8);
    let nonce = seal_nonce(&d, &target);
    let nonces = [nonce, [0x22; 32], [0x33; 32]];
    let st = signed(statement(d, &nonces, None));
    let proof = prove_nonce(&d, &nonces, 0).unwrap();
    assert!(matches!(
        verify_signed_batch_seal_v3(
            &st,
            &proof,
            &dna(9),
            &target,
            &[key().verifying_key().to_bytes()],
            RADIUS,
            None,
            &DalekVerifier
        ),
        Err(Error::WrongNetwork)
    ));
    assert!(matches!(
        verify_signed_batch_seal_v3(
            &st,
            &proof,
            &d,
            &action(9),
            &[key().verifying_key().to_bytes()],
            RADIUS,
            None,
            &DalekVerifier
        ),
        Err(Error::MerkleMismatch)
    ));
    let good = verify(&st, None).unwrap();
    assert!(matches!(
        verify_authenticated_batch_seal_v3(&good, &proof, &dna(2), &target),
        Err(Error::WrongNetwork)
    ));
    let mut wrong_target = action(8);
    wrong_target[0] = 0xff;
    assert!(verify_authenticated_batch_seal_v3(&good, &proof, &d, &wrong_target).is_err());
    let mut invalid_checksum = action(8);
    invalid_checksum[38] ^= 1;
    assert!(verify_authenticated_batch_seal_v3(&good, &proof, &d, &invalid_checksum).is_err());
}

#[test]
fn tamper_bad_signature_and_untrusted_source_rejected() {
    let d = dna(5);
    let n = seal_nonce(&d, &action(1));
    let st = signed(statement(d, &[n], None));
    let mut altered = st.clone();
    altered.statement.latest_us += 100;
    assert!(matches!(
        verify(&altered, None),
        Err(Error::BadSignature(_))
    ));
    let mut changed_root = st.clone();
    changed_root.statement.merkle_root[0] ^= 1;
    assert!(matches!(
        verify(&changed_root, None),
        Err(Error::BadSignature(_))
    ));
    let mut changed_count = st.clone();
    changed_count.statement.nonce_count = 2;
    assert!(matches!(
        verify(&changed_count, None),
        Err(Error::BadSignature(_))
    ));
    let mut wrong_sig = st.clone();
    wrong_sig.signature[0] ^= 0x80;
    assert!(matches!(
        verify(&wrong_sig, None),
        Err(Error::BadSignature(_))
    ));
    let mut short_sig = st.clone();
    short_sig.signature.pop();
    assert!(verify(&short_sig, None).is_err());
    let mut long_sig = st.clone();
    long_sig.signature.push(1);
    assert!(verify(&long_sig, None).is_err());
    assert!(matches!(
        verify_signed_batch_v3(&st, &d, &[[9; 32]], RADIUS, None, &DalekVerifier),
        Err(Error::UnknownSource(_))
    ));
}

#[test]
fn rejected_invalid_proof_and_inconsistent_signed_count() {
    let d = dna(10);
    let n = [seal_nonce(&d, &action(5)), [0x66; 32], [0x77; 32]];
    let st = signed(statement(d, &n, None));
    let authenticated = verify(&st, None).unwrap();
    let good = prove_nonce(&d, &n, 0).unwrap();
    let mut wrong = good.clone();
    wrong.siblings[0][0] ^= 1;
    assert!(matches!(
        verify_authenticated_batch_seal_v3(&authenticated, &wrong, &d, &action(5)),
        Err(Error::MerkleMismatch)
    ));
    let mut bad_count = good.clone();
    bad_count.count = 4;
    assert!(
        verify_authenticated_batch_seal_v3(&authenticated, &bad_count, &d, &action(5)).is_err()
    );
    let mut too_deep = good.clone();
    too_deep.siblings.push([0; 32]);
    assert!(verify_authenticated_batch_seal_v3(&authenticated, &too_deep, &d, &action(5)).is_err());
    let bogus = NonceInclusionProof {
        index: 3,
        count: 3,
        siblings: vec![],
    };
    assert!(verify_authenticated_batch_seal_v3(&authenticated, &bogus, &d, &action(5)).is_err());
}

#[test]
fn producer_rejects_duplicate_and_out_of_budget_leaf_lists() {
    let d = dna(1);
    assert!(prepare_batch_root(&d, &[]).is_err());
    assert!(prepare_batch_root(&d, &[[7; 32], [7; 32]]).is_err());
    let too_many: Vec<_> = (0..129u32)
        .map(|i| {
            let mut n = [0; 32];
            n[..4].copy_from_slice(&i.to_le_bytes());
            n
        })
        .collect();
    assert!(prepare_batch_root(&d, &too_many).is_err());
    let mut invalid_dna = d;
    invalid_dna[35] ^= 1;
    assert!(prepare_batch_root(&invalid_dna, &[[4; 32]]).is_err());
}

#[test]
fn policy_radius_floor_and_clock_regression_rejected() {
    let d = dna(3);
    let n = [seal_nonce(&d, &action(3))];
    let st = signed(statement(d, &n, None));
    assert!(matches!(
        verify_signed_batch_v3(&st, &d, &[st.statement.oracle], 1, None, &DalekVerifier),
        Err(Error::RadiusTooLarge { .. })
    ));
    assert!(
        verify_signed_batch_v3(&st, &d, &[st.statement.oracle], -1, None, &DalekVerifier).is_err()
    );
    let head = verify(&st, None).unwrap().next_head().clone();
    let mut backwards = statement(d, &n, Some(&head));
    backwards.earliest_us = head.next_floor_us - 4_000_000;
    backwards.latest_us = head.next_floor_us - 1;
    assert!(backwards.validate().is_err());
    let mut invalid = st.statement.clone();
    invalid.earliest_us = i64::MIN;
    assert!(invalid.signing_bytes().is_err());
    let mut invalid = st.statement.clone();
    invalid.earliest_us = TIME + 1_000_001;
    assert!(invalid.validate().is_err());
    let mut invalid = st.statement.clone();
    invalid.nonce_count = 129;
    assert!(invalid.validate().is_err());
    invalid.nonce_count = 0;
    assert!(invalid.validate().is_err());
}

#[test]
fn deterministic_wire_roundtrip_and_canonical_rejections() {
    let d = dna(1);
    let n = [[1; 32], [2; 32], [3; 32]];
    let st = statement(d, &n, None);
    let bytes = st.signing_bytes().unwrap();
    assert_eq!(bytes.len(), BATCH_SIGNING_BYTES_LEN);
    assert!(bytes.starts_with(BATCH_STATEMENT_DOMAIN_V3));
    assert_eq!(BatchStatementV3::from_signing_bytes(&bytes).unwrap(), st);
    let mut duplicate_bytes = bytes.clone();
    duplicate_bytes.push(0);
    assert!(BatchStatementV3::from_signing_bytes(&duplicate_bytes).is_err());
    let mut v2 = bytes.clone();
    v2[0] ^= 1;
    assert!(BatchStatementV3::from_signing_bytes(&v2).is_err());
    // Canonical genesis must have zeroed payloads in both disabled slots.
    let prev_offset = BATCH_STATEMENT_DOMAIN_V3.len() + 39 + 32 + 32 + 2 + 8 + 8 + 8 + 1;
    let mut dirty_zero_slot = bytes.clone();
    dirty_zero_slot[prev_offset] = 1;
    assert!(BatchStatementV3::from_signing_bytes(&dirty_zero_slot).is_err());
    let mut invalid_prev_flag = bytes.clone();
    invalid_prev_flag[prev_offset - 1] = 2;
    assert!(BatchStatementV3::from_signing_bytes(&invalid_prev_flag).is_err());
    let floor_slot = prev_offset + 64 + 1;
    let mut invalid_floor_flag = bytes.clone();
    invalid_floor_flag[floor_slot - 1] = 2;
    assert!(BatchStatementV3::from_signing_bytes(&invalid_floor_flag).is_err());
    let mut dirty_floor_slot = bytes.clone();
    dirty_floor_slot[floor_slot] = 1;
    assert!(BatchStatementV3::from_signing_bytes(&dirty_floor_slot).is_err());
    let mut unsupported_dna = bytes.clone();
    unsupported_dna[BATCH_STATEMENT_DOMAIN_V3.len()] = 1;
    assert!(BatchStatementV3::from_signing_bytes(&unsupported_dna).is_err());
}

#[test]
fn stable_cross_language_v3_encoding_vector() {
    let d = dna(1);
    let n = [[0; 32], [1; 32], [2; 32]];
    let st = BatchStatementV3 {
        dna: d,
        oracle: [0xa5; 32],
        merkle_root: prepare_batch_root(&d, &n).unwrap().0,
        nonce_count: 3,
        earliest_us: TIME,
        latest_us: TIME + 1_000_000,
        seq: 0,
        prev_signature: None,
        floor_us: None,
    };
    let payload = st.signing_bytes().unwrap();
    // Python hashlib.sha512(payload).digest()[:32] from the ADR vectors.
    assert_eq!(
        to_hex(&h(&[&payload])),
        "06287c5cd18b7ea8516caa720859d1f5ab88f58bda29c492de1d112178fd5c8a"
    );
}
