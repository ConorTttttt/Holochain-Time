//! Real child-process termination at each fsynced signing boundary.
//! Unix test-only sandbox. These tests kill a disposable process, not a
//! deployed Holochain conductor or the live signing keystore.
#![cfg(unix)]
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use vtime_core::keys::{dna_hash_from_b64, dna_hash_to_b64};
use vtime_core::signed_batch::{prepare_batch_root, BatchStatementV3};
use vtime_core::DalekVerifier;
use vtime_oracle_state::{
    BootstrapAuthorization, Journal, PendingPhase, StoreError,
};

const TIME_US: i64 = 1_792_000_000_000_000;
const MAX_RADIUS: i64 = 10_000_000;

struct Lab {
    directory: PathBuf,
    file: PathBuf,
    dna: [u8; 39],
    signer: SigningKey,
}
impl Lab {
    fn new() -> Self {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(
            format!("hc-vtime-s24-kill-{}-{unique}", std::process::id())
        );
        fs::create_dir(&directory).unwrap();
        let file = directory.join("oracle.journal");
        let dna = dna_hash_from_b64(&dna_hash_to_b64(&[1u8; 32])).unwrap();
        let signer = SigningKey::from_bytes(&[42u8; 32]);
        let writer = Journal::bootstrap_new(
            &file, dna, signer.verifying_key().to_bytes(),
            MAX_RADIUS, BootstrapAuthorization::VerifiedNewIdentity,
        ).unwrap();
        drop(writer);
        Self { directory, file, dna, signer }
    }
    fn open(&self) -> Journal {
        Journal::open(
            &self.file, self.dna, self.signer.verifying_key().to_bytes(),
            MAX_RADIUS, &DalekVerifier,
        ).unwrap()
    }
    fn proposal(&self) -> BatchStatementV3 {
        let (root, count) = prepare_batch_root(&self.dna, &[[0xAA; 32], [0xAB; 32]]).unwrap();
        BatchStatementV3 {
            dna: self.dna, oracle: self.signer.verifying_key().to_bytes(),
            merkle_root: root, nonce_count: count,
            earliest_us: TIME_US, latest_us: TIME_US + 1_000_000,
            seq: 0, prev_signature: None, floor_us: None,
        }
    }
    fn kill_after_marker(&self, mode: &str, expected: &str) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_oracle_crash_worker"))
            .arg(mode).arg(&self.file)
            .stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().expect("failed to start signing child");
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
        let marker = rx.recv_timeout(Duration::from_secs(30));
        // Always kill the process even if it never reached its boundary.
        child.kill().expect("could not terminate disposable signer process");
        let _ = child.wait().expect("could not reap test child");
        let _ = reader.join();
        assert_eq!(marker.expect("child never reached signing boundary").trim(), expected);

        // A SIGKILL leaves an exclusive lock on disk. A *human operator*
        // normally establishes that the process is dead and reviews state
        // before clearing it. Here the child is demonstrably reaped.
        assert!(matches!(
            Journal::open(&self.file, self.dna, self.signer.verifying_key().to_bytes(),
                MAX_RADIUS, &DalekVerifier),
            Err(StoreError::Busy)
        ));
        let locked = self.directory.join("oracle.journal.lock");
        fs::remove_file(locked).unwrap();
        File::open(&self.directory).unwrap().sync_all().unwrap();
    }
}
impl Drop for Lab {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.directory); }
}

#[test]
fn actual_process_kill_before_signer_fence_allows_retry() {
    let lab = Lab::new();
    lab.kill_after_marker("before_signer", "READY_PREPARED");
    let mut recovered = lab.open();
    assert_eq!(recovered.pending_phase(), Some(PendingPhase::PreparedNotSigned));
    let verified = recovered.sign_prepared(
        |bytes| Ok(lab.signer.sign(bytes).to_bytes()), &DalekVerifier
    ).unwrap();
    assert_eq!(verified.statement, lab.proposal());
    assert_eq!(recovered.head().unwrap().seq, 0);
}

#[test]
fn actual_process_kill_after_signer_call_blocks_second_signature() {
    let lab = Lab::new();
    lab.kill_after_marker("inside_signer", "READY_SIGNING");
    let mut recovered = lab.open();
    assert_eq!(recovered.pending_phase(), Some(PendingPhase::SigningMayHaveOccurred));
    assert!(recovered.head().is_none());
    assert!(matches!(
        recovered.sign_prepared(|_| panic!("MUST NOT sign again"), &DalekVerifier),
        Err(StoreError::AmbiguousSigning)
    ));
    assert!(matches!(recovered.prepare(lab.proposal()), Err(StoreError::Pending)));
}

#[test]
fn actual_process_kill_after_durable_commit_returns_original_receipt() {
    let lab = Lab::new();
    lab.kill_after_marker("after_commit", "READY_COMMITTED");
    let recovered = lab.open();
    let existing = recovered.committed_retry(&lab.proposal())
        .expect("fully committed signed output was not durable");
    assert_eq!(existing.statement.seq, 0);
    assert_eq!(recovered.head().unwrap().signature.as_slice(), existing.signature.as_slice());
    let original_sig = lab.signer.sign(&lab.proposal().signing_bytes().unwrap()).to_bytes();
    assert_eq!(existing.signature.as_slice(), original_sig);
}
