//! Lair-backed [`OracleSigner`] for the native v3 oracle runtime.
//!
//! Security properties this adapter adds on top of `OracleRuntime`:
//!
//! * **Explicit identity binding.** A signer is bound to one `(DNA, oracle
//!   public key, Lair tag)` triple. On connect and on every health check, the
//!   Lair entry for the tag must be a non-exportable, non-deep-locked Ed25519
//!   seed whose public key equals the configured oracle key.
//! * **Authenticated access.** The connection uses Lair's IPC handshake
//!   (server public key pinned in the connection URL plus the keystore
//!   passphrase). A wrong passphrase or URL fails before any signing.
//! * **Canonical payloads only.** Bytes are signed only if they decode as
//!   exactly one canonical `BatchStatementV3`, re-encode to the identical
//!   bytes, validate, and name the bound DNA and oracle. Arbitrary data, other
//!   DNAs and other oracle identities are rejected before Lair is contacted.
//! * **In-process monotonic sequence guard.** A second request for a sequence
//!   number at or below one already sent to Lair is refused. The durable
//!   journal and the external checkpoint provide this guarantee across
//!   restarts; this guard is defence in depth.
//! * **No retries.** Every call makes at most one Lair request. Failures are
//!   classified for operators ([`FailureClass`]). The runtime's journal
//!   treats any failure after the SIGNING fence as ambiguous and quarantines
//!   the lane. Nothing here re-signs automatically.
//! * **Verified output.** A Lair signature is returned only after it verifies
//!   under the bound key.
//!
//! Not provided: production key custody (HSM, operator separation), RPC
//! authentication of callers, or proof that this is the sole signer for the
//! key across hosts. Those are deployment acceptance items (issue #70).
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lair_keystore_api::dependencies::url::Url;
use lair_keystore_api::prelude::{Ed25519PubKey, LairEntryInfo, SharedLockedArray};
use lair_keystore_api::{ipc_keystore_connect, LairClient};
use vtime_core::signed_batch::BatchStatementV3;
use vtime_core::{DalekVerifier, Ed25519Verifier};
use vtime_oracle_state::runtime::OracleSigner;

/// The identity a signer instance is allowed to sign for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerIdentity {
    pub dna: [u8; 39],
    pub oracle: [u8; 32],
    pub lair_tag: Arc<str>,
}

/// Errors that prevent a signer from being created or bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignerError {
    /// No authenticated Lair session (bad URL, wrong passphrase, server down).
    Connect(String),
    /// Lair has no entry for the configured tag.
    UnknownTag(String),
    /// The entry exists but is not an Ed25519 seed.
    NotASeed,
    /// Deep-locked seeds need a per-signature passphrase; not supported.
    DeepLockedUnsupported,
    /// Exportable seeds are refused for oracle signing keys.
    ExportableKey,
    /// The Lair key for the tag is not the configured oracle key.
    KeyMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// A rotation target is not a distinct key.
    RotationToSameKey,
    /// Local async runtime could not be created or the call timed out.
    Runtime(String),
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "no authenticated Lair session: {e}"),
            Self::UnknownTag(e) => write!(f, "Lair tag not found: {e}"),
            Self::NotASeed => write!(f, "Lair entry is not an Ed25519 seed"),
            Self::DeepLockedUnsupported => write!(f, "deep-locked seeds are not supported"),
            Self::ExportableKey => write!(f, "exportable Lair seeds are refused for oracle keys"),
            Self::KeyMismatch { .. } => write!(f, "Lair key does not match the configured oracle"),
            Self::RotationToSameKey => write!(f, "rotation target must be a different key"),
            Self::Runtime(e) => write!(f, "signer runtime failure: {e}"),
        }
    }
}
impl std::error::Error for SignerError {}

/// Classification of a failed `sign_once`. The adapter never retries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureClass {
    /// Refused before any Lair request was sent: no signature can exist.
    RejectedBeforeKeystore,
    /// Lair, or the IPC transport to it, returned an error instead of a
    /// signature. A broken connection lands here too, so this does NOT prove
    /// that no signature was produced.
    KeystoreError,
    /// Timed out or lost the connection after the request may have been sent.
    Ambiguous,
    /// Lair returned bytes that do not verify for the bound identity.
    InvalidSignature,
}

impl FailureClass {
    /// Only a pre-keystore rejection proves that no signature exists. Every
    /// other class requires operator reconciliation before the lane signs again.
    pub fn proves_no_signature(self) -> bool {
        matches!(self, Self::RejectedBeforeKeystore)
    }

    fn tag(self) -> &'static str {
        match self {
            Self::RejectedBeforeKeystore => "REJECTED_BEFORE_KEYSTORE",
            Self::KeystoreError => "KEYSTORE_ERROR",
            Self::Ambiguous => "AMBIGUOUS",
            Self::InvalidSignature => "INVALID_SIGNATURE",
        }
    }
}

/// Availability and outcome counters for monitoring.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignerStatus {
    pub identity_bound: bool,
    /// Lair signing requests actually sent.
    pub keystore_requests: u64,
    pub successes: u64,
    pub last_success_unix_ms: Option<u64>,
    pub last_failure: Option<FailureClass>,
    pub last_failure_detail: Option<String>,
    pub last_health_ok: Option<bool>,
    /// Highest statement sequence sent to Lair by this process.
    pub highest_seq_sent: Option<u64>,
}

/// Validated description of a key rotation. Executing it is an operator
/// procedure: a rotated key is a NEW oracle identity with its own journal
/// (`Journal::bootstrap_new`), its own genesis checkpoint at the external
/// anchor, and a DNA oracle-set change that only the project owner can make.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationPlan {
    pub dna: [u8; 39],
    pub retiring_oracle: [u8; 32],
    pub next_oracle: [u8; 32],
    pub next_tag: Arc<str>,
    pub required_steps: &'static [&'static str],
}

const ROTATION_STEPS: &[&str] = &[
    "owner-approved DNA/oracle-set change that admits the next key",
    "bootstrap a new journal for the next key (BootstrapAuthorization::VerifiedNewIdentity)",
    "store the next key's genesis checkpoint at the independent anchor",
    "retire the old lane only after its final checkpoint is anchored",
    "never run both lanes for the same DNA/sequence space",
];

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Lair-backed signer bound to one oracle identity. Use from a synchronous
/// thread (it owns a private Tokio runtime); do not call from async code.
pub struct LairOracleSigner {
    rt: tokio::runtime::Runtime,
    client: LairClient,
    identity: SignerIdentity,
    pub_key: Ed25519PubKey,
    timeout: Duration,
    status: SignerStatus,
}

impl LairOracleSigner {
    /// Open an authenticated Lair IPC session and bind the identity.
    pub fn connect(
        connection_url: Url,
        passphrase: SharedLockedArray,
        identity: SignerIdentity,
        timeout: Duration,
    ) -> Result<Self, SignerError> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(|e| SignerError::Runtime(e.to_string()))?;
        let connecting = ipc_keystore_connect(connection_url, passphrase);
        let client = rt
            .block_on(async { tokio::time::timeout(timeout, connecting).await })
            .map_err(|_| SignerError::Connect("timed out".into()))?
            .map_err(|e| SignerError::Connect(e.to_string()))?;
        let mut signer = Self {
            rt,
            client,
            pub_key: Ed25519PubKey::from(identity.oracle),
            identity,
            timeout,
            status: SignerStatus::default(),
        };
        signer.bind()?;
        Ok(signer)
    }

    fn seed_key(&self, tag: Arc<str>) -> Result<[u8; 32], SignerError> {
        let entry = self
            .rt
            .block_on(async {
                tokio::time::timeout(self.timeout, self.client.get_entry(tag)).await
            })
            .map_err(|_| SignerError::Runtime("Lair get_entry timed out".into()))?
            .map_err(|e| SignerError::UnknownTag(e.to_string()))?;
        match entry {
            LairEntryInfo::Seed { seed_info, .. } => {
                if seed_info.exportable {
                    return Err(SignerError::ExportableKey);
                }
                Ok(*seed_info.ed25519_pub_key)
            }
            LairEntryInfo::DeepLockedSeed { .. } => Err(SignerError::DeepLockedUnsupported),
            _ => Err(SignerError::NotASeed),
        }
    }

    fn bind(&mut self) -> Result<(), SignerError> {
        self.status.identity_bound = false;
        let actual = self.seed_key(self.identity.lair_tag.clone())?;
        if actual != self.identity.oracle {
            return Err(SignerError::KeyMismatch {
                expected: self.identity.oracle,
                actual,
            });
        }
        self.status.identity_bound = true;
        Ok(())
    }

    /// Re-check that Lair is reachable and the tag still maps to the bound,
    /// non-exportable key. Does not sign.
    pub fn health_check(&mut self) -> Result<(), SignerError> {
        let result = self.bind();
        self.status.last_health_ok = Some(result.is_ok());
        result
    }

    pub fn status(&self) -> &SignerStatus {
        &self.status
    }

    /// Bound on each Lair round trip. A timeout is classified as ambiguous.
    pub fn set_request_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub fn identity(&self) -> &SignerIdentity {
        &self.identity
    }

    /// Validate a rotation target without changing anything.
    pub fn plan_rotation(&mut self, next_tag: Arc<str>) -> Result<RotationPlan, SignerError> {
        let next = self.seed_key(next_tag.clone())?;
        if next == self.identity.oracle {
            return Err(SignerError::RotationToSameKey);
        }
        Ok(RotationPlan {
            dna: self.identity.dna,
            retiring_oracle: self.identity.oracle,
            next_oracle: next,
            next_tag,
            required_steps: ROTATION_STEPS,
        })
    }

    /// Canonical-payload, identity and sequence checks. Returns the sequence.
    fn admit(&self, bytes: &[u8]) -> Result<u64, String> {
        let statement = BatchStatementV3::from_signing_bytes(bytes)
            .map_err(|e| format!("not a canonical v3 batch statement: {e}"))?;
        match statement.signing_bytes() {
            Ok(again) if again == bytes => {}
            _ => return Err("payload does not re-encode canonically".into()),
        }
        statement
            .validate()
            .map_err(|e| format!("invalid statement: {e}"))?;
        if statement.dna != self.identity.dna {
            return Err("statement is for a different DNA".into());
        }
        if statement.oracle != self.identity.oracle {
            return Err("statement names a different oracle".into());
        }
        if let Some(highest) = self.status.highest_seq_sent {
            if statement.seq <= highest {
                return Err(format!(
                    "sequence {} not above {highest} already sent to Lair",
                    statement.seq
                ));
            }
        }
        Ok(statement.seq)
    }

    fn fail(&mut self, class: FailureClass, detail: String) -> String {
        self.status.last_failure = Some(class);
        self.status.last_failure_detail = Some(detail.clone());
        format!("{}: {detail}", class.tag())
    }
}

impl OracleSigner for LairOracleSigner {
    fn public_key(&self) -> [u8; 32] {
        self.identity.oracle
    }

    fn sign_once(&mut self, canonical_bytes: &[u8]) -> Result<[u8; 64], String> {
        if !self.status.identity_bound {
            return Err(self.fail(
                FailureClass::RejectedBeforeKeystore,
                "identity not bound".into(),
            ));
        }
        let seq = match self.admit(canonical_bytes) {
            Ok(seq) => seq,
            Err(reason) => return Err(self.fail(FailureClass::RejectedBeforeKeystore, reason)),
        };
        // From here a request may reach Lair: record the sequence first so a
        // second request for it is refused even if this one fails.
        self.status.highest_seq_sent = Some(seq);
        self.status.keystore_requests += 1;
        let request = self.client.sign_by_pub_key(
            self.pub_key.clone(),
            None,
            Arc::from(canonical_bytes.to_vec().into_boxed_slice()),
        );
        let limit = self.timeout;
        let reply = self
            .rt
            .block_on(async { tokio::time::timeout(limit, request).await });
        let signature: [u8; 64] = match reply {
            Err(_) => {
                return Err(self.fail(FailureClass::Ambiguous, "Lair request timed out".into()))
            }
            Ok(Err(e)) => return Err(self.fail(FailureClass::KeystoreError, e.to_string())),
            Ok(Ok(signature)) => *signature,
        };
        match DalekVerifier.verify(&self.identity.oracle, canonical_bytes, &signature) {
            Ok(true) => {}
            _ => {
                return Err(self.fail(
                    FailureClass::InvalidSignature,
                    "Lair signature does not verify for the bound key".into(),
                ))
            }
        }
        self.status.successes += 1;
        self.status.last_success_unix_ms = Some(now_ms());
        Ok(signature)
    }
}

/// Shareable handle so a monitor can read [`SignerStatus`] and run health
/// checks while an `OracleRuntime` owns the signer. All calls are serialised.
#[derive(Clone)]
pub struct SharedLairSigner(std::sync::Arc<std::sync::Mutex<LairOracleSigner>>);

impl SharedLairSigner {
    pub fn new(signer: LairOracleSigner) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(signer)))
    }

    /// For reads and checks. A poisoned lock (panic during an earlier call)
    /// still allows monitoring; signing refuses it (see `sign_once`).
    fn lock(&self) -> std::sync::MutexGuard<'_, LairOracleSigner> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn status(&self) -> SignerStatus {
        self.lock().status().clone()
    }

    pub fn health_check(&self) -> Result<(), SignerError> {
        self.lock().health_check()
    }

    pub fn set_request_timeout(&self, timeout: Duration) {
        self.lock().set_request_timeout(timeout)
    }

    pub fn plan_rotation(&self, next_tag: Arc<str>) -> Result<RotationPlan, SignerError> {
        self.lock().plan_rotation(next_tag)
    }
}

impl OracleSigner for SharedLairSigner {
    fn public_key(&self) -> [u8; 32] {
        self.lock().public_key()
    }

    fn sign_once(&mut self, canonical_bytes: &[u8]) -> Result<[u8; 64], String> {
        match self.0.lock() {
            Ok(mut signer) => signer.sign_once(canonical_bytes),
            // An earlier call panicked part-way through: its outcome is unknown.
            Err(_) => Err(format!(
                "{}: signer state poisoned by an earlier panic",
                FailureClass::RejectedBeforeKeystore.tag()
            )),
        }
    }
}
