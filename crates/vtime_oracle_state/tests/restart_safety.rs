//! Sprint 24 deterministic on-disk recovery / signing-fence acceptance.
//! Public Ed25519 test seeds only, no production signing identities.
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use vtime_core::keys::{dna_hash_from_b64, dna_hash_to_b64};
use vtime_core::signed_batch::{
    prepare_batch_root, BatchChainHeadV3, BatchStatementV3, SignedBatchStatementV3,
};
use vtime_core::DalekVerifier;
use vtime_oracle_state::{BootstrapAuthorization, Journal, PendingPhase, StoreError};

const NOW_US: i64 = 1_792_000_000_000_000;
const MAX_RADIUS: i64 = 10_000_000;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Lab {
    directory: PathBuf,
    path: PathBuf,
    dna: [u8; 39],
    signing: SigningKey,
}
impl Lab {
    fn new() -> Self {
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hc-vtime-sprint24-{}-{nanos}-{index}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let dna = dna_hash_from_b64(&dna_hash_to_b64(&[1u8; 32])).unwrap();
        Self {
            path: directory.join("oracle.journal"),
            directory,
            dna,
            signing: SigningKey::from_bytes(&[42u8; 32]),
        }
    }
    fn key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }
    fn bootstrap(&self) -> Journal {
        Journal::bootstrap_new(
            &self.path,
            self.dna,
            self.key(),
            MAX_RADIUS,
            BootstrapAuthorization::VerifiedNewIdentity,
        )
        .unwrap()
    }
    fn open(&self) -> Journal {
        Journal::open(&self.path, self.dna, self.key(), MAX_RADIUS, &DalekVerifier).unwrap()
    }
    fn proposal(&self, previous: Option<&BatchChainHeadV3>, salt: u8) -> BatchStatementV3 {
        let nonces = [[salt; 32], [salt.wrapping_add(1); 32]];
        let (merkle_root, nonce_count) = prepare_batch_root(&self.dna, &nonces).unwrap();
        let ordinal = previous.map_or(0, |head| head.seq + 1);
        BatchStatementV3 {
            dna: self.dna,
            oracle: self.key(),
            merkle_root,
            nonce_count,
            earliest_us: NOW_US + (ordinal as i64) * 1_000_000,
            latest_us: NOW_US + (ordinal as i64) * 1_000_000 + 1_000_000,
            seq: ordinal,
            prev_signature: previous.map(|head| head.signature),
            floor_us: previous.map(|head| head.next_floor_us),
        }
    }
    fn sign(&self, statement: BatchStatementV3) -> SignedBatchStatementV3 {
        let bytes = statement.signing_bytes().unwrap();
        let signature = self.signing.sign(&bytes).to_bytes().to_vec();
        SignedBatchStatementV3 {
            statement,
            signature,
        }
    }
    fn commit(&self, journal: &mut Journal, statement: BatchStatementV3) -> SignedBatchStatementV3 {
        journal.prepare(statement).unwrap();
        journal
            .sign_prepared(
                |bytes| Ok(self.signing.sign(bytes).to_bytes()),
                &DalekVerifier,
            )
            .unwrap()
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn normal_restart_preserves_verified_chain_seq_and_highwater() {
    let lab = Lab::new();
    let mut writer = lab.bootstrap();
    let genesis = lab.commit(&mut writer, lab.proposal(None, 10));
    let first = writer.head().unwrap().clone();
    assert_eq!(first.seq, 0);
    assert_eq!(first.next_floor_us, NOW_US);
    drop(writer);

    let mut restored = lab.open();
    assert_eq!(restored.head(), Some(&first));
    assert!(restored.pending_phase().is_none());
    let second = lab.commit(&mut restored, lab.proposal(Some(&first), 20));
    let final_head = restored.head().unwrap().clone();
    assert_eq!(final_head.seq, 1);
    assert_eq!(final_head.next_floor_us, NOW_US + 1_000_000);
    assert_eq!(final_head.signature.as_slice(), second.signature.as_slice());
    drop(restored);

    let mut restarted = lab.open();
    assert_eq!(restarted.head(), Some(&final_head));
    assert!(matches!(
        restarted.accept_verified(&genesis, &DalekVerifier),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        restarted.accept_verified(&second, &DalekVerifier),
        Err(StoreError::Invalid(_))
    ));
}

#[test]
fn crash_before_signing_fence_allows_exact_prepared_retry() {
    let lab = Lab::new();
    let statement = lab.proposal(None, 31);
    let mut first = lab.bootstrap();
    first.prepare(statement.clone()).unwrap();
    assert_eq!(first.pending_phase(), Some(PendingPhase::PreparedNotSigned));
    drop(first); // Simulated process boundary: only PREPARE was durably written.

    let mut reopened = lab.open();
    assert_eq!(
        reopened.pending_phase(),
        Some(PendingPhase::PreparedNotSigned)
    );
    assert!(matches!(
        reopened.prepare(statement.clone()),
        Err(StoreError::Pending)
    ));
    let saved = reopened
        .sign_prepared(
            |bytes| Ok(lab.signing.sign(bytes).to_bytes()),
            &DalekVerifier,
        )
        .unwrap();
    assert_eq!(saved.statement, statement);
    assert!(reopened.pending_phase().is_none());
    drop(reopened);
    assert_eq!(lab.open().head().unwrap().seq, 0);
}

#[test]
fn signer_invoked_then_failure_or_uncertain_commit_never_resigns() {
    let lab = Lab::new();
    let statement = lab.proposal(None, 40);
    let mut store = lab.bootstrap();
    store.prepare(statement.clone()).unwrap();
    let mut invocations = 0;
    let error = store
        .sign_prepared(
            |bytes| {
                let _lost_signature = lab.signing.sign(bytes).to_bytes();
                invocations += 1;
                Err("simulated crash after keystore signing".to_string())
            },
            &DalekVerifier,
        )
        .unwrap_err();
    assert!(matches!(error, StoreError::Signer(_)));
    assert_eq!(invocations, 1);
    assert_eq!(
        store.pending_phase(),
        Some(PendingPhase::SigningMayHaveOccurred)
    );
    drop(store);

    let mut restarted = lab.open();
    assert_eq!(
        restarted.pending_phase(),
        Some(PendingPhase::SigningMayHaveOccurred)
    );
    assert!(restarted.head().is_none());
    assert!(matches!(
        restarted.sign_prepared(|_| panic!("must not re-invoke signer"), &DalekVerifier),
        Err(StoreError::AmbiguousSigning)
    ));
    assert!(matches!(
        restarted.prepare(statement),
        Err(StoreError::Pending)
    ));
}

#[test]
fn committed_but_lost_response_resends_exact_signature_without_signing() {
    let lab = Lab::new();
    let proposal = lab.proposal(None, 51);
    let mut store = lab.bootstrap();
    let signed = lab.commit(&mut store, proposal.clone());
    drop(store); // Response lost, but COMMIT was durably fsync'd.

    let mut restarted = lab.open();
    let recovered = restarted.committed_retry(&proposal).unwrap();
    assert_eq!(recovered, &signed);
    let another = lab.proposal(None, 52);
    assert!(restarted.committed_retry(&another).is_none());
    assert!(matches!(
        restarted.prepare(proposal),
        Err(StoreError::Invalid(_))
    ));
    // There is no mechanism to sign a second candidate at sequence 0.
}

#[test]
fn stateful_verifier_denies_duplicate_signed_seq_and_conflicting_histories() {
    let lab = Lab::new();
    let genesis = lab.sign(lab.proposal(None, 61));
    let mut verifier_store = lab.bootstrap();
    let verified = verifier_store
        .accept_verified(&genesis, &DalekVerifier)
        .unwrap();
    let first_head = verified.next_head().clone();
    assert_eq!(first_head.seq, 0);
    drop(verifier_store);

    let mut recovered = lab.open();
    assert!(matches!(
        recovered.accept_verified(&genesis, &DalekVerifier),
        Err(StoreError::Invalid(_))
    ));
    let alternate_zero = lab.sign(lab.proposal(None, 62));
    assert!(matches!(
        recovered.accept_verified(&alternate_zero, &DalekVerifier),
        Err(StoreError::Invalid(_))
    ));
    let good_next = lab.sign(lab.proposal(Some(&first_head), 63));
    let mut bad_prev = good_next.clone();
    bad_prev.statement.prev_signature = Some([0xCC; 64]);
    bad_prev = lab.sign(bad_prev.statement);
    assert!(matches!(
        recovered.accept_verified(&bad_prev, &DalekVerifier),
        Err(StoreError::Invalid(_))
    ));
    let mut bad_floor = good_next.clone();
    bad_floor.statement.floor_us = Some(first_head.next_floor_us - 1);
    bad_floor = lab.sign(bad_floor.statement);
    assert!(matches!(
        recovered.accept_verified(&bad_floor, &DalekVerifier),
        Err(StoreError::Invalid(_))
    ));
    let next_head = recovered
        .accept_verified(&good_next, &DalekVerifier)
        .unwrap()
        .next_head()
        .clone();
    assert_eq!(next_head.seq, 1);
    drop(recovered);
    assert_eq!(lab.open().head(), Some(&next_head));
}

#[test]
fn corruption_partial_append_policy_change_and_missing_state_fail_closed() {
    let lab = Lab::new();
    assert!(matches!(
        Journal::open(&lab.path, lab.dna, lab.key(), MAX_RADIUS, &DalekVerifier),
        Err(StoreError::MissingState)
    ));
    let mut writer = lab.bootstrap();
    lab.commit(&mut writer, lab.proposal(None, 71));
    assert!(matches!(
        Journal::bootstrap_new(
            &lab.path,
            lab.dna,
            lab.key(),
            MAX_RADIUS,
            BootstrapAuthorization::VerifiedNewIdentity
        ),
        Err(StoreError::AlreadyExists)
    ));
    drop(writer);
    assert!(matches!(
        Journal::open(
            &lab.path,
            lab.dna,
            lab.key(),
            MAX_RADIUS + 1,
            &DalekVerifier
        ),
        Err(StoreError::WrongPolicy)
    ));
    assert!(matches!(
        Journal::open(&lab.path, lab.dna, [1; 32], MAX_RADIUS, &DalekVerifier),
        Err(StoreError::WrongIdentity)
    ));

    let mut bytes = Vec::new();
    fs::File::open(&lab.path)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    let target = bytes.len() - 33;
    bytes[target] ^= 1;
    fs::write(&lab.path, &bytes).unwrap();
    assert!(matches!(
        Journal::open(&lab.path, lab.dna, lab.key(), MAX_RADIUS, &DalekVerifier),
        Err(StoreError::Corrupt(_))
    ));
}

#[test]
fn truncated_tail_is_not_silently_ignored_or_replayed() {
    let lab = Lab::new();
    let mut writer = lab.bootstrap();
    lab.commit(&mut writer, lab.proposal(None, 81));
    drop(writer);
    let mut file = OpenOptions::new().append(true).open(&lab.path).unwrap();
    file.write_all(&[3u8, 0, 0]).unwrap();
    file.sync_all().unwrap();
    assert!(matches!(
        Journal::open(&lab.path, lab.dna, lab.key(), MAX_RADIUS, &DalekVerifier),
        Err(StoreError::Corrupt(_))
    ));
}

#[test]
fn same_identity_cannot_be_opened_by_two_writers_at_once() {
    let lab = Lab::new();
    let first = lab.bootstrap();
    assert!(matches!(
        Journal::open(&lab.path, lab.dna, lab.key(), MAX_RADIUS, &DalekVerifier),
        Err(StoreError::Busy)
    ));
    drop(first);
    assert!(lab.open().head().is_none());
}

#[test]
fn forged_signature_is_not_durable_or_returned() {
    let lab = Lab::new();
    let mut writer = lab.bootstrap();
    writer.prepare(lab.proposal(None, 91)).unwrap();
    assert!(matches!(
        writer.sign_prepared(|_| Ok([0x01; 64]), &DalekVerifier),
        Err(StoreError::Invalid(_))
    ));
    drop(writer);
    let restored = lab.open();
    assert_eq!(
        restored.pending_phase(),
        Some(PendingPhase::SigningMayHaveOccurred)
    );
    assert!(restored.head().is_none());
}
