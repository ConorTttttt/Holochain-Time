//! Native oracle runtime integration regression. Test-only signing keys and
//! in-memory checkpoint store; NOT trusted external antirollback evidence.
use std::cell::{Cell, RefCell};
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use vtime_core::keys::{dna_hash_from_b64, dna_hash_to_b64};
use vtime_core::signed_batch::BatchStatementV3;
use vtime_core::DalekVerifier;
use vtime_oracle_state::runtime::{
    BatchSignRequest, CheckpointAnchor, OracleRuntime, OracleSigner, RuntimeError,
};
use vtime_oracle_state::{BootstrapAuthorization, Checkpoint, Journal, StoreError};

const MAX_RADIUS: i64 = 10_000_000;
const T: i64 = 1_792_000_000_000_000;
static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
struct TestAnchor {
    latest: Rc<RefCell<Checkpoint>>,
    fail_write: Rc<Cell<bool>>,
}
impl CheckpointAnchor for TestAnchor {
    fn load_authenticated(
        &mut self,
        _dna: &[u8; 39],
        _oracle: &[u8; 32],
    ) -> Result<Checkpoint, String> {
        Ok(self.latest.borrow().clone())
    }

    fn compare_and_store_monotonic(
        &mut self,
        _dna: &[u8; 39],
        _oracle: &[u8; 32],
        expected: &Checkpoint,
        next: &Checkpoint,
    ) -> Result<(), String> {
        if self.fail_write.get() {
            return Err("simulated remote checkpoint write failure".into());
        }
        let mut current = self.latest.borrow_mut();
        if &*current != expected
            || next.seq != Some(expected.seq.map_or(0, |seq| seq + 1))
            || next.journal_hash == expected.journal_hash
        {
            return Err("CAS failed or checkpoint did not advance".into());
        }
        *current = next.clone();
        Ok(())
    }
}

#[derive(Clone)]
struct TestSigner {
    calls: Rc<Cell<usize>>,
}
impl OracleSigner for TestSigner {
    fn public_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(&[42u8; 32]).verifying_key().to_bytes()
    }
    fn sign_once(&mut self, message: &[u8]) -> Result<[u8; 64], String> {
        self.calls.set(self.calls.get() + 1);
        Ok(SigningKey::from_bytes(&[42u8; 32]).sign(message).to_bytes())
    }
}

struct Fixture {
    dir: PathBuf,
    path: PathBuf,
    dna: [u8; 39],
    oracle: [u8; 32],
    anchor: TestAnchor,
    signer: TestSigner,
}

impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "vtime-sprint29-runtime-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("oracle.journal");
        let dna = dna_hash_from_b64(&dna_hash_to_b64(&[7u8; 32])).unwrap();
        let signer = TestSigner {
            calls: Rc::new(Cell::new(0)),
        };
        let oracle = signer.public_key();
        let mut journal = Journal::bootstrap_new(
            &path, dna, oracle, MAX_RADIUS,
            BootstrapAuthorization::VerifiedNewIdentity,
        )
        .unwrap();
        let checkpoint = journal.checkpoint().unwrap();
        drop(journal);
        Self {
            dir,
            path,
            dna,
            oracle,
            anchor: TestAnchor {
                latest: Rc::new(RefCell::new(checkpoint)),
                fail_write: Rc::new(Cell::new(false)),
            },
            signer,
        }
    }
    fn open(&self) -> Result<OracleRuntime<TestSigner, TestAnchor>, RuntimeError> {
        OracleRuntime::open(
            &self.path, self.dna, self.oracle, MAX_RADIUS,
            self.signer.clone(), self.anchor.clone(), Box::new(DalekVerifier),
        )
    }
    fn request(&self, id: u8, time: i64) -> BatchSignRequest {
        BatchSignRequest {
            request_id: [id; 32],
            merkle_root: [id.wrapping_add(1); 32],
            nonce_count: 2,
            earliest_us: time,
            latest_us: time + 1_000_000,
        }
    }
    fn statement(&self, req: &BatchSignRequest) -> BatchStatementV3 {
        BatchStatementV3 {
            dna: self.dna,
            oracle: self.oracle,
            merkle_root: req.merkle_root,
            nonce_count: req.nonce_count,
            earliest_us: req.earliest_us,
            latest_us: req.latest_us,
            seq: 0,
            prev_signature: None,
            floor_us: None,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn actual_signing_lane_restarts_and_preserves_idempotency_across_later_commits() {
    let f = Fixture::new();
    let first = f.request(1, T);
    let second = f.request(2, T + 2_000_000);
    let mut runtime = f.open().unwrap();
    let a = runtime.sign(first.clone()).unwrap();
    assert_eq!(a.statement.seq, 0);
    let b = runtime.sign(second).unwrap();
    assert_eq!(b.statement.seq, 1);
    assert_eq!(b.statement.prev_signature.as_ref(), Some(&a.signature.as_slice().try_into().unwrap()));
    assert_eq!(runtime.verified_head().unwrap().next_floor_us, T + 2_000_000);
    drop(runtime);

    let mut restarted = f.open().unwrap();
    assert_eq!(restarted.sign(first.clone()).unwrap(), a); // historical commit, no new sign
    assert_eq!(f.signer.calls.get(), 2);
    let mut changed = first;
    changed.merkle_root = [0xFF; 32];
    assert!(matches!(restarted.sign(changed), Err(RuntimeError::ConflictingRequest)));
    assert_eq!(f.signer.calls.get(), 2);
    let c = restarted.sign(f.request(3, T + 4_000_000)).unwrap();
    assert_eq!(c.statement.seq, 2);
    assert_eq!(f.signer.calls.get(), 3);
}

#[test]
fn prepared_but_unsigned_request_recovers_once_without_losing_token() {
    let f = Fixture::new();
    let request = f.request(11, T);
    let mut journal =
        Journal::open(&f.path, f.dna, f.oracle, MAX_RADIUS, &DalekVerifier).unwrap();
    journal
        .prepare_request(request.request_id, f.statement(&request))
        .unwrap();
    drop(journal);
    let mut runtime = f.open().unwrap();
    assert!(matches!(
        runtime.sign(f.request(99, T)),
        Err(RuntimeError::Journal(StoreError::Pending))
    ));
    assert_eq!(f.signer.calls.get(), 0);
    let result = runtime.sign(request.clone()).unwrap();
    assert_eq!(result.statement.seq, 0);
    drop(runtime);
    let mut again = f.open().unwrap();
    assert_eq!(again.sign(request).unwrap(), result);
    assert_eq!(f.signer.calls.get(), 1);
}

#[test]
fn uncertain_signer_outcome_never_reenters_callback_on_restart() {
    let f = Fixture::new();
    let req = f.request(12, T);
    let mut journal =
        Journal::open(&f.path, f.dna, f.oracle, MAX_RADIUS, &DalekVerifier).unwrap();
    journal.prepare_request(req.request_id, f.statement(&req)).unwrap();
    assert!(matches!(
        journal.sign_prepared(|_| Err("HSM transport timed out".into()), &DalekVerifier),
        Err(StoreError::Signer(_))
    ));
    drop(journal);
    assert!(matches!(
        f.open(),
        Err(RuntimeError::Journal(StoreError::AmbiguousSigning))
    ));
    assert_eq!(f.signer.calls.get(), 0);
}

#[test]
fn unanchored_commit_is_withheld_and_quarantined() {
    let f = Fixture::new();
    f.anchor.fail_write.set(true);
    let mut runtime = f.open().unwrap();
    assert!(matches!(
        runtime.sign(f.request(1, T)),
        Err(RuntimeError::Anchor(_))
    ));
    assert_eq!(f.signer.calls.get(), 1); // it DID sign; COMMIT is durable
    assert!(matches!(
        runtime.sign(f.request(1, T)),
        Err(RuntimeError::Quarantined)
    ));
    drop(runtime);
    assert!(matches!(
        f.open(),
        Err(RuntimeError::Journal(StoreError::Invalid(_)))
    )); // authenticated older anchor does not authorize a signed response
}

#[test]
fn old_valid_backup_and_corrupt_journal_are_rejected_before_signing() {
    let f = Fixture::new();
    let backup = f.dir.join("old.snapshot");
    let mut runtime = f.open().unwrap();
    runtime.sign(f.request(1, T)).unwrap();
    fs::copy(&f.path, &backup).unwrap();
    runtime.sign(f.request(2, T + 2_000_000)).unwrap();
    drop(runtime);
    fs::copy(&backup, &f.path).unwrap();
    assert!(matches!(
        f.open(), Err(RuntimeError::Journal(StoreError::Invalid(_)))
    )); // external anchor has a newer committed snapshot
    assert_eq!(f.signer.calls.get(), 2);

    let bytes = fs::read(&f.path).unwrap();
    let mut corrupted = bytes.clone();
    *corrupted.last_mut().unwrap() ^= 0x01;
    fs::write(&f.path, corrupted).unwrap();
    assert!(matches!(
        f.open(), Err(RuntimeError::Journal(StoreError::Corrupt(_)))
    ));
    assert_eq!(f.signer.calls.get(), 2);
}

#[test]
fn legacy_untagged_signing_history_cannot_be_silently_migrated() {
    let f = Fixture::new();
    let req = f.request(1, T);
    let mut journal =
        Journal::open(&f.path, f.dna, f.oracle, MAX_RADIUS, &DalekVerifier).unwrap();
    journal.prepare(f.statement(&req)).unwrap();
    journal
        .sign_prepared(
            |msg| Ok(SigningKey::from_bytes(&[42u8; 32]).sign(msg).to_bytes()),
            &DalekVerifier,
        )
        .unwrap();
    *f.anchor.latest.borrow_mut() = journal.checkpoint().unwrap();
    drop(journal);
    assert!(matches!(f.open(), Err(RuntimeError::UntrackedHistory)));
}

#[test]
fn mismatched_signer_and_concurrent_journal_writer_are_refused() {
    let f = Fixture::new();
    let first = f.open().unwrap();
    assert!(matches!(
        f.open(), Err(RuntimeError::Journal(StoreError::Busy))
    ));
    drop(first);
    assert!(matches!(
        OracleRuntime::open(
            &f.path, f.dna, [9; 32], MAX_RADIUS,
            f.signer.clone(), f.anchor.clone(), Box::new(DalekVerifier),
        ),
        Err(RuntimeError::WrongSignerKey)
    ));
}
