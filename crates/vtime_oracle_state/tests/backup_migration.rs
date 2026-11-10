//! Backup, migration fencing and external checkpoint / rollback tests.
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use vtime_core::keys::{dna_hash_from_b64, dna_hash_to_b64};
use vtime_core::signed_batch::{prepare_batch_root, BatchChainHeadV3, BatchStatementV3};
use vtime_core::DalekVerifier;
use vtime_oracle_state::{BootstrapAuthorization, Journal, StoreError};

const MAX_RADIUS: i64 = 10_000_000;
const NOW: i64 = 1_792_000_000_000_000;
struct Lab {
    directory: PathBuf,
    source: PathBuf,
    backup: PathBuf,
    dna: [u8; 39],
    key: SigningKey,
}
impl Lab {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hc-vtime-s24-backup-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let dna = dna_hash_from_b64(&dna_hash_to_b64(&[1; 32])).unwrap();
        Self {
            source: directory.join("journal.db"),
            backup: directory.join("journal.backup"),
            directory,
            dna,
            key: SigningKey::from_bytes(&[42; 32]),
        }
    }
    fn boot(&self) -> Journal {
        Journal::bootstrap_new(
            &self.source,
            self.dna,
            self.key.verifying_key().to_bytes(),
            MAX_RADIUS,
            BootstrapAuthorization::VerifiedNewIdentity,
        )
        .unwrap()
    }
    fn open(&self, path: &std::path::Path) -> Journal {
        Journal::open(
            path,
            self.dna,
            self.key.verifying_key().to_bytes(),
            MAX_RADIUS,
            &DalekVerifier,
        )
        .unwrap()
    }
    fn statement(&self, head: Option<&BatchChainHeadV3>, salt: u8) -> BatchStatementV3 {
        let (root, count) = prepare_batch_root(&self.dna, &[[salt; 32]]).unwrap();
        let seq = head.map_or(0, |h| h.seq + 1);
        BatchStatementV3 {
            dna: self.dna,
            oracle: self.key.verifying_key().to_bytes(),
            merkle_root: root,
            nonce_count: count,
            earliest_us: NOW + (seq as i64) * 1_000_000,
            latest_us: NOW + (seq as i64) * 1_000_000 + 1_000_000,
            seq,
            prev_signature: head.map(|h| h.signature),
            floor_us: head.map(|h| h.next_floor_us),
        }
    }
    fn sign(&self, store: &mut Journal, statement: BatchStatementV3) {
        store.prepare(statement).unwrap();
        store
            .sign_prepared(|bytes| Ok(self.key.sign(bytes).to_bytes()), &DalekVerifier)
            .unwrap();
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn safe_backup_matches_exact_externally_recorded_checkpoint_and_resumes() {
    let lab = Lab::new();
    let mut original = lab.boot();
    lab.sign(&mut original, lab.statement(None, 10));
    let saved_head = original.head().unwrap().clone();
    let checkpoint = original.backup_clean(&lab.backup).unwrap();
    assert_eq!(checkpoint.seq, Some(0));
    assert_eq!(checkpoint.signature, Some(saved_head.signature));
    assert_eq!(checkpoint.next_floor_us, Some(NOW));
    assert_eq!(checkpoint, original.checkpoint().unwrap());
    assert!(matches!(
        original.backup_clean(&lab.backup),
        Err(StoreError::Io(_))
    )); // immutable backup must never be overwritten
    drop(original);

    // Simulated operator restore of a checked backup: no running signer and
    // the backup's head equals an EXTERNAL trusted monotonic checkpoint.
    fs::remove_file(&lab.source).unwrap();
    fs::rename(&lab.backup, &lab.source).unwrap();
    #[cfg(unix)]
    std::fs::File::open(&lab.directory)
        .unwrap()
        .sync_all()
        .unwrap();
    let mut restored = Journal::open_checked(
        &lab.source,
        lab.dna,
        lab.key.verifying_key().to_bytes(),
        MAX_RADIUS,
        &checkpoint,
        &DalekVerifier,
    )
    .expect("exact trusted backup checkpoint should permit recovery");
    assert_eq!(restored.head(), Some(&saved_head));
    lab.sign(&mut restored, lab.statement(Some(&saved_head), 11));
    assert_eq!(restored.head().unwrap().seq, 1);
}

#[test]
fn rolling_back_a_valid_backup_fails_against_newer_checkpoint() {
    let lab = Lab::new();
    let mut journal = lab.boot();
    lab.sign(&mut journal, lab.statement(None, 20));
    journal.backup_clean(&lab.backup).unwrap();
    let old = journal.head().unwrap().clone();
    lab.sign(&mut journal, lab.statement(Some(&old), 21));
    let external_newer_checkpoint = journal.checkpoint().unwrap();
    assert_eq!(external_newer_checkpoint.seq, Some(1));
    drop(journal);

    // Valid old signatures alone DO NOT prove this restored state is fresh.
    fs::remove_file(&lab.source).unwrap();
    fs::rename(&lab.backup, &lab.source).unwrap();
    #[cfg(unix)]
    std::fs::File::open(&lab.directory)
        .unwrap()
        .sync_all()
        .unwrap();
    assert!(matches!(
        Journal::open_checked(
            &lab.source,
            lab.dna,
            lab.key.verifying_key().to_bytes(),
            MAX_RADIUS,
            &external_newer_checkpoint,
            &DalekVerifier,
        ),
        Err(StoreError::Invalid(_))
    ));
    let restored = lab.open(&lab.source);
    assert_eq!(restored.head().unwrap().seq, 0);
    // Production caller MUST NOT continue signing after that failed check.
}

#[test]
fn backup_is_blocked_while_a_signed_commit_may_be_in_flight() {
    let lab = Lab::new();
    let mut journal = lab.boot();
    journal.prepare(lab.statement(None, 32)).unwrap();
    assert!(matches!(
        journal.backup_clean(&lab.backup),
        Err(StoreError::Pending)
    ));
    assert!(!lab.backup.exists());
    let _ = journal.sign_prepared(
        |_| Err("unknown signer outcome".to_string()),
        &DalekVerifier,
    );
    assert!(matches!(
        journal.backup_clean(&lab.backup),
        Err(StoreError::Pending)
    ));
    assert!(!lab.backup.exists());
}

#[test]
fn checked_restart_recovers_unsigned_prepare_against_last_committed_checkpoint() {
    let lab = Lab::new();
    let mut journal = lab.boot();
    lab.sign(&mut journal, lab.statement(None, 41));
    let prior = journal.head().unwrap().clone();
    let external_checkpoint = journal.checkpoint().unwrap();
    let next = lab.statement(Some(&prior), 42);
    journal.prepare(next.clone()).unwrap();
    drop(journal); // The signer was never called for the pending statement.

    let mut recovered = Journal::open_checked(
        &lab.source,
        lab.dna,
        lab.key.verifying_key().to_bytes(),
        MAX_RADIUS,
        &external_checkpoint,
        &DalekVerifier,
    )
    .expect("a verified committed prefix should allow PREPARE-only recovery");
    assert_eq!(
        recovered.pending_phase(),
        Some(vtime_oracle_state::PendingPhase::PreparedNotSigned)
    );
    let signed = recovered
        .sign_prepared(|bytes| Ok(lab.key.sign(bytes).to_bytes()), &DalekVerifier)
        .unwrap();
    assert_eq!(signed.statement, next);
    assert_eq!(recovered.head().unwrap().seq, 1);
}
