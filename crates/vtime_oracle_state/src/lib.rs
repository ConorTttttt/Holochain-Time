//! Native, fail-closed journal for the proposed Sprint 15 signed-batch v3 log.
//!
//! This crate is NOT wired into the Holochain coordinator or a production
//! signing service. It intentionally forbids auto-reset, automatic rollback
//! recovery, and retry of an operation after the signer may have been called.
#![forbid(unsafe_code)]

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use vtime_core::hash::h;
use vtime_core::signed_batch::{
    verify_signed_batch_v3, BatchChainHeadV3, BatchStatementV3, SignedBatchStatementV3,
    VerifiedBatchV3, BATCH_SIGNING_BYTES_LEN,
};
use vtime_core::Ed25519Verifier;

const MAGIC: &[u8; 8] = b"VTS24J1\0";
const HEADER_LEN: usize = MAGIC.len() + 39 + 32 + 8;
const MAX_RECORD: usize = 1 + BATCH_SIGNING_BYTES_LEN + 64;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const CHAIN_DOMAIN: &[u8] = b"hc-vtime/oracle-journal/v1\0";

#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    MissingState,
    AlreadyExists,
    Busy,
    Corrupt(&'static str),
    WrongIdentity,
    WrongPolicy,
    Invalid(String),
    Pending,
    AmbiguousSigning,
    Signer(String),
    Poisoned,
    Exhausted,
    UnsupportedPlatform,
}
impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "durable journal I/O failure: {err}"),
            Self::MissingState => write!(f, "missing durable oracle state; refusing genesis"),
            Self::AlreadyExists => write!(f, "state exists; refusing reinitialization"),
            Self::Busy => write!(f, "exclusive oracle journal lock exists"),
            Self::Corrupt(reason) => write!(f, "corrupt/incomplete durable journal: {reason}"),
            Self::WrongIdentity => write!(f, "journal belongs to a different DNA or oracle"),
            Self::WrongPolicy => write!(f, "journal has a different verification policy"),
            Self::Invalid(reason) => write!(f, "invalid batch or history: {reason}"),
            Self::Pending => write!(f, "journal has an uncommitted operation"),
            Self::AmbiguousSigning => write!(f, "signer may have been invoked; quarantine pending operation"),
            Self::Signer(reason) => write!(f, "signer failed after durable signing fence: {reason}"),
            Self::Poisoned => write!(f, "durability error: close and inspect journal; no further signing"),
            Self::Exhausted => write!(f, "bounded journal capacity reached; reviewed migration required"),
            Self::UnsupportedPlatform => write!(f, "directory fsync is required on a supported Unix filesystem"),
        }
    }
}
impl std::error::Error for StoreError {}
impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self { Self::Io(error) }
}
pub type Result<T> = std::result::Result<T, StoreError>;

/// Explicit operator attestation required only for a genuinely NEW identity.
/// A missing journal must never silently trigger this path. A trusted external
/// checkpoint is required to exclude rollback/re-bootstrap of an old identity.
#[derive(Clone, Copy, Debug)]
pub enum BootstrapAuthorization { VerifiedNewIdentity }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingPhase { PreparedNotSigned, SigningMayHaveOccurred }

#[derive(Clone, Debug)]
struct Pending {
    statement: BatchStatementV3,
    phase: PendingPhase,
}

/// Externally serialized, single-process writer for one (DNA, oracle) identity.
/// All mutations are append-only, checksummed and fsync'd *before* returning.
/// Both committed signatures and signed high-water marks are revalidated on open.
pub struct Journal {
    file: File,
    path: PathBuf,
    lock_path: PathBuf,
    dna: [u8; 39],
    oracle: [u8; 32],
    max_radius_us: i64,
    head: Option<BatchChainHeadV3>,
    pending: Option<Pending>,
    checksum: [u8; 32],
    poisoned: bool,
}

fn io_parent_sync(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let directory = path.parent().ok_or(StoreError::Corrupt("missing parent directory"))?;
        File::open(directory)?.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(StoreError::UnsupportedPlatform)
    }
}
fn lock_path(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().ok_or(StoreError::Corrupt("journal has no filename"))?;
    let mut locked = name.to_os_string();
    locked.push(".lock");
    Ok(path.with_file_name(locked))
}
fn lock_file(path: &Path) -> Result<PathBuf> {
    let locked = lock_path(path)?;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    match options.open(&locked) {
        Ok(file) => {
            if let Err(error) = file.sync_all().and_then(|_| {
                io_parent_sync(&locked).map_err(|e| std::io::Error::other(e.to_string()))
            }) {
                let _ = fs::remove_file(&locked);
                return Err(StoreError::Io(error));
            }
            Ok(locked)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Err(StoreError::Busy),
        Err(error) => Err(StoreError::Io(error)),
    }
}
fn header(dna: &[u8; 39], oracle: &[u8; 32], max_radius_us: i64) -> Vec<u8> {
    let mut output = Vec::with_capacity(HEADER_LEN);
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(dna);
    output.extend_from_slice(oracle);
    output.extend_from_slice(&max_radius_us.to_le_bytes());
    output
}

impl Drop for Journal {
    fn drop(&mut self) {
        // If the process dies uncleanly, the lock remains and *blocks* open.
        // Operator must establish no running signer before clearing stale lock.
        let _ = fs::remove_file(&self.lock_path);
        let _ = io_parent_sync(&self.lock_path);
    }
}

impl Journal {
    /// Create a journal only for a newly provisioned, externally reviewed
    /// identity. NEVER use this automatically on a missing file during restart.
    pub fn bootstrap_new(
        path: impl AsRef<Path>,
        dna: [u8; 39],
        oracle: [u8; 32],
        max_radius_us: i64,
        _authorization: BootstrapAuthorization,
    ) -> Result<Self> {
        if max_radius_us < 0 { return Err(StoreError::WrongPolicy); }
        let path = path.as_ref();
        if path.exists() { return Err(StoreError::AlreadyExists); }
        let lock = lock_file(path)?;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) => {
                let _ = fs::remove_file(&lock);
                return Err(StoreError::Io(error));
            }
        };
        let hdr = header(&dna, &oracle, max_radius_us);
        if let Err(error) = file.write_all(&hdr).and_then(|_| file.sync_all()) {
            let _ = fs::remove_file(&lock);
            return Err(StoreError::Io(error));
        }
        // Even after an acknowledged write the directory entry may not be
        // crash durable until its containing directory is synced.
        if let Err(error) = io_parent_sync(path) {
            let _ = fs::remove_file(&lock);
            return Err(error);
        }
        Ok(Self {
            file, path: path.to_path_buf(), lock_path: lock,
            dna, oracle, max_radius_us, head: None, pending: None,
            checksum: h(&[CHAIN_DOMAIN, &hdr]), poisoned: false,
        })
    }

    /// Restore an existing state; missing, truncated, corrupt, reordered or
    /// unauthenticated logs fail closed. Never infer a new genesis from absence.
    pub fn open(
        path: impl AsRef<Path>,
        dna: [u8; 39],
        oracle: [u8; 32],
        max_radius_us: i64,
        verifier: &dyn Ed25519Verifier,
    ) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() { return Err(StoreError::MissingState); }
        let lock = lock_file(path)?;
        let outcome = (|| {
            let mut file = OpenOptions::new().read(true).write(true).open(path)?;
            let size = file.metadata()?.len();
            if size < HEADER_LEN as u64 || size > MAX_JOURNAL_BYTES {
                return Err(StoreError::Corrupt("journal size outside allowed bounds"));
            }
            let mut bytes = Vec::with_capacity(size as usize);
            file.read_to_end(&mut bytes)?;
            let expected = header(&dna, &oracle, max_radius_us);
            if &bytes[..MAGIC.len()] != MAGIC {
                return Err(StoreError::Corrupt("wrong journal magic/version"));
            }
            if bytes[MAGIC.len()..MAGIC.len() + 39] != dna
                || bytes[MAGIC.len() + 39..MAGIC.len() + 71] != oracle
            {
                return Err(StoreError::WrongIdentity);
            }
            if bytes[..HEADER_LEN] != expected {
                return Err(StoreError::WrongPolicy);
            }
            let mut store = Self {
                file, path: path.to_path_buf(), lock_path: lock.clone(),
                dna, oracle, max_radius_us, head: None, pending: None,
                checksum: h(&[CHAIN_DOMAIN, &expected]), poisoned: false,
            };
            let mut pos = HEADER_LEN;
            while pos < bytes.len() {
                if bytes.len() - pos < 4 { return Err(StoreError::Corrupt("truncated record length")); }
                let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into()
                    .map_err(|_| StoreError::Corrupt("bad length"))?) as usize;
                pos += 4;
                if len == 0 || len > MAX_RECORD || bytes.len() - pos < len + 32 {
                    return Err(StoreError::Corrupt("invalid or truncated record body"));
                }
                let payload = &bytes[pos..pos + len];
                let observed = &bytes[pos + len..pos + len + 32];
                let computed = h(&[&store.checksum, payload]);
                if observed != computed {
                    return Err(StoreError::Corrupt("record checksum mismatch"));
                }
                store.apply(payload, verifier)?;
                store.checksum = computed;
                pos += len + 32;
            }
            Ok(store)
        })();
        if outcome.is_err() { let _ = fs::remove_file(&lock); }
        outcome
    }

    pub fn head(&self) -> Option<&BatchChainHeadV3> { self.head.as_ref() }
    pub fn pending_phase(&self) -> Option<PendingPhase> {
        self.pending.as_ref().map(|pending| pending.phase)
    }
    pub fn is_poisoned(&self) -> bool { self.poisoned }

    fn check_proposal(&self, st: &BatchStatementV3) -> Result<()> {
        st.validate().map_err(|error| StoreError::Invalid(error.to_string()))?;
        if st.dna != self.dna || st.oracle != self.oracle {
            return Err(StoreError::WrongIdentity);
        }
        if st.latest_us - st.earliest_us > self.max_radius_us.saturating_mul(2) {
            // For full verification the core's exact radius semantics apply.
            // This cheap check is only an early (conservative) bound.
            return Err(StoreError::WrongPolicy);
        }
        match &self.head {
            None if st.seq == 0 && st.prev_signature.is_none() && st.floor_us.is_none() => Ok(()),
            None => Err(StoreError::Invalid("no persisted prior head".into())),
            Some(head) if head.seq.checked_add(1) == Some(st.seq)
                && st.prev_signature == Some(head.signature)
                && st.floor_us == Some(head.next_floor_us) => Ok(()),
            Some(_) => Err(StoreError::Invalid("replay, duplicate seq, fork or wrong high-water".into())),
        }
    }

    fn append_record(&mut self, payload: &[u8]) -> Result<()> {
        if self.poisoned { return Err(StoreError::Poisoned); }
        if payload.is_empty() || payload.len() > MAX_RECORD {
            return Err(StoreError::Corrupt("invalid record length"));
        }
        let end = self.file.seek(SeekFrom::End(0))?;
        let write_len = 4 + payload.len() as u64 + 32;
        if end.checked_add(write_len).is_none_or(|new| new > MAX_JOURNAL_BYTES) {
            return Err(StoreError::Exhausted);
        }
        let digest = h(&[&self.checksum, payload]);
        self.poisoned = true; // Any I/O ambiguity must quarantine this handle.
        self.file.write_all(&(payload.len() as u32).to_le_bytes())?;
        self.file.write_all(payload)?;
        self.file.write_all(&digest)?;
        self.file.sync_all()?;
        self.checksum = digest;
        self.poisoned = false;
        Ok(())
    }

    fn apply(&mut self, payload: &[u8], verifier: &dyn Ed25519Verifier) -> Result<()> {
        match payload {
            [1, rest @ ..] if rest.len() == BATCH_SIGNING_BYTES_LEN => {
                if self.pending.is_some() { return Err(StoreError::Corrupt("nested signing intent")); }
                let statement = BatchStatementV3::from_signing_bytes(rest)
                    .map_err(|error| StoreError::Invalid(error.to_string()))?;
                self.check_proposal(&statement)?;
                self.pending = Some(Pending { statement, phase: PendingPhase::PreparedNotSigned });
            }
            [2] => {
                let pending = self.pending.as_mut()
                    .ok_or(StoreError::Corrupt("signing stage without intent"))?;
                if pending.phase != PendingPhase::PreparedNotSigned {
                    return Err(StoreError::Corrupt("duplicate signing stage"));
                }
                pending.phase = PendingPhase::SigningMayHaveOccurred;
            }
            [3, rest @ ..] if rest.len() == 64 => {
                let pending = self.pending.as_ref()
                    .ok_or(StoreError::Corrupt("commit without intent"))?;
                if pending.phase != PendingPhase::SigningMayHaveOccurred {
                    return Err(StoreError::Corrupt("commit without signer fence"));
                }
                let signed = SignedBatchStatementV3 {
                    statement: pending.statement.clone(), signature: rest.to_vec()
                };
                let verified = self.verify_next(&signed, verifier)?;
                self.head = Some(verified.next_head().clone());
                self.pending = None;
            }
            [4, rest @ ..] if rest.len() == BATCH_SIGNING_BYTES_LEN + 64 => {
                if self.pending.is_some() { return Err(StoreError::Corrupt("external accept while signing")); }
                let statement = BatchStatementV3::from_signing_bytes(
                    &rest[..BATCH_SIGNING_BYTES_LEN]
                ).map_err(|error| StoreError::Invalid(error.to_string()))?;
                let signature = rest[BATCH_SIGNING_BYTES_LEN..].to_vec();
                let signed = SignedBatchStatementV3 { statement, signature };
                let verified = self.verify_next(&signed, verifier)?;
                self.head = Some(verified.next_head().clone());
            }
            _ => return Err(StoreError::Corrupt("unknown journal record type/length")),
        }
        Ok(())
    }

    fn verify_next(&self, signed: &SignedBatchStatementV3, verifier: &dyn Ed25519Verifier)
        -> Result<VerifiedBatchV3>
    {
        verify_signed_batch_v3(
            signed, &self.dna, &[self.oracle], self.max_radius_us,
            self.head.as_ref(), verifier,
        ).map_err(|error| StoreError::Invalid(error.to_string()))
    }

    /// Reserve an unsigned statement durably. Re-issue of a different request
    /// while this is pending is rejected. Pre-sign crash is safely restartable.
    pub fn prepare(&mut self, statement: BatchStatementV3) -> Result<()> {
        if self.poisoned { return Err(StoreError::Poisoned); }
        if self.pending.is_some() { return Err(StoreError::Pending); }
        self.check_proposal(&statement)?;
        let bytes = statement.signing_bytes()
            .map_err(|error| StoreError::Invalid(error.to_string()))?;
        let mut payload = Vec::with_capacity(1 + bytes.len());
        payload.push(1);
        payload.extend_from_slice(&bytes);
        self.append_record(&payload)?;
        self.pending = Some(Pending { statement, phase: PendingPhase::PreparedNotSigned });
        Ok(())
    }

    /// The signing fence is synced BEFORE the keystore is called. The
    /// signature is returned to the caller ONLY AFTER authenticating it and
    /// fsync'ing the committed signature + high-water in the journal.
    ///
    /// Once this method starts, ANY signer/callback/I/O failure leaves a
    /// quarantine state. Calling it again cannot create a second signature.
    pub fn sign_prepared<F>(
        &mut self,
        signer: F,
        verifier: &dyn Ed25519Verifier,
    ) -> Result<SignedBatchStatementV3>
    where
        F: FnOnce(&[u8]) -> std::result::Result<[u8; 64], String>,
    {
        if self.poisoned { return Err(StoreError::Poisoned); }
        let pending = self.pending.as_ref().ok_or(StoreError::Pending)?;
        if pending.phase == PendingPhase::SigningMayHaveOccurred {
            return Err(StoreError::AmbiguousSigning);
        }
        let statement = pending.statement.clone();
        let bytes = statement.signing_bytes()
            .map_err(|error| StoreError::Invalid(error.to_string()))?;
        self.append_record(&[2])?;
        self.pending.as_mut().expect("prepared intent").phase = PendingPhase::SigningMayHaveOccurred;
        let signature = signer(&bytes).map_err(StoreError::Signer)?;
        let signed = SignedBatchStatementV3 { statement, signature: signature.to_vec() };
        self.verify_next(&signed, verifier)?;
        let mut record = Vec::with_capacity(65);
        record.push(3);
        record.extend_from_slice(&signature);
        self.append_record(&record)?;
        let verified = self.verify_next(&signed, verifier)?;
        self.head = Some(verified.next_head().clone());
        self.pending = None;
        Ok(signed)
    }

    /// Stateful verifier ingestion, with signature and continuity checks.
    /// The accepted head is durable BEFORE success is returned. A duplicate
    /// signature/sequence, old head, foreign network or a fork fails closed.
    pub fn accept_verified(
        &mut self, signed: &SignedBatchStatementV3,
        verifier: &dyn Ed25519Verifier,
    ) -> Result<VerifiedBatchV3> {
        if self.poisoned { return Err(StoreError::Poisoned); }
        if self.pending.is_some() { return Err(StoreError::Pending); }
        let verified = self.verify_next(signed, verifier)?;
        let encoded = signed.statement.signing_bytes()
            .map_err(|error| StoreError::Invalid(error.to_string()))?;
        let mut payload = Vec::with_capacity(1 + encoded.len() + signed.signature.len());
        payload.push(4);
        payload.extend_from_slice(&encoded);
        payload.extend_from_slice(&signed.signature);
        self.append_record(&payload)?;
        self.head = Some(verified.next_head().clone());
        Ok(verified)
    }
}
