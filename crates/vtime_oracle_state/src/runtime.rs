//! Native v3 oracle admission and signing runtime.
//!
//! This is an embeddable native service boundary, NOT the v2 Holochain
//! `attest_time` zome and NOT a deployed HSM or trusted checkpoint service.
//! Every output passes through a synced journal COMMIT and a monotonic
//! external checkpoint before it is returned to the caller.
use std::fmt;
use std::path::Path;

use vtime_core::interval::TimeInterval;
use vtime_core::signed_batch::{
    prepare_batch_root, BatchChainHeadV3, BatchStatementV3, SignedBatchStatementV3,
};
use vtime_core::Ed25519Verifier;

use crate::{Checkpoint, Journal, PendingPhase, RequestRecord, StoreError};

/// Implement with an external key service (for example, a reviewed Lair/HSM
/// adapter). The native runtime never requires or exports private key bytes.
/// Do not use a signing key in a process-local test fixture for deployment.
pub trait OracleSigner {
    fn public_key(&self) -> [u8; 32];
    fn sign_once(&mut self, canonical_bytes: &[u8]) -> std::result::Result<[u8; 64], String>;
}

/// MUST authenticate the most recent checkpoint and implement a durable,
/// atomic, monotonic compare-and-swap in a failure domain independent of
/// the journal and backups. A process-local or same-volume implementation is
/// useful for unit tests only. This trait cannot itself attest trust.
pub trait CheckpointAnchor {
    fn load_authenticated(
        &mut self,
        dna: &[u8; 39],
        oracle: &[u8; 32],
    ) -> std::result::Result<Checkpoint, String>;

    fn compare_and_store_monotonic(
        &mut self,
        dna: &[u8; 39],
        oracle: &[u8; 32],
        expected: &Checkpoint,
        next: &Checkpoint,
    ) -> std::result::Result<(), String>;
}

/// The oracle samples its own checked time source, NOT the requester's
/// timestamps. Production implementations must validate clock health,
/// uncertainty bounds and monotonicity under the configured oracle policy.
pub trait OracleClock {
    fn now_us(&mut self) -> std::result::Result<i64, String>;
}

/// Authenticated globally unique idempotency token + raw nonces. A caller may
/// NOT supply a timestamp, radius, nonce count or arbitrary commitment root.
/// The runtime derives the v1 DNA-bound Merkle root from these nonces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchSignRequest {
    pub request_id: [u8; 32],
    pub nonces: Vec<[u8; 32]>,
}

#[derive(Debug)]
pub enum RuntimeError {
    Journal(StoreError),
    Anchor(String),
    Clock(String),
    WrongClockPolicy,
    WrongSignerKey,
    UntrackedHistory,
    ConflictingRequest,
    Quarantined,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => write!(f, "{error}"),
            Self::Anchor(reason) => write!(f, "trusted checkpoint unavailable: {reason}"),
            Self::Clock(reason) => write!(f, "oracle clock unavailable: {reason}"),
            Self::WrongClockPolicy => write!(f, "oracle radius exceeds the verified maximum"),
            Self::WrongSignerKey => write!(f, "signer key does not match configured oracle"),
            Self::UntrackedHistory => write!(
                f,
                "journal has untracked legacy requests; migration required"
            ),
            Self::ConflictingRequest => {
                write!(f, "idempotency token has different request content")
            }
            Self::Quarantined => write!(f, "oracle runtime quarantined after uncertain outcome"),
        }
    }
}
impl std::error::Error for RuntimeError {}
impl From<StoreError> for RuntimeError {
    fn from(error: StoreError) -> Self {
        Self::Journal(error)
    }
}
pub type RuntimeResult<T> = std::result::Result<T, RuntimeError>;

/// Immutable identity and uncertainty policy for one oracle lane.
#[derive(Clone, Debug)]
pub struct RuntimePolicy {
    pub dna: [u8; 39],
    pub oracle: [u8; 32],
    pub max_radius_us: i64,
    pub radius_us: i64,
}

/// Exactly one instance per DNA/oracle identity. The journal holds a local
/// filesystem exclusive lock; operators MUST also enforce single-writer key
/// ownership across hosts. Do not put signer invocation in a retry loop.
pub struct OracleRuntime<S: OracleSigner, A: CheckpointAnchor, C: OracleClock> {
    journal: Journal,
    signer: S,
    anchor: A,
    clock: C,
    verifier: Box<dyn Ed25519Verifier>,
    dna: [u8; 39],
    oracle: [u8; 32],
    radius_us: i64,
    blocked: bool,
}

impl<S: OracleSigner, A: CheckpointAnchor, C: OracleClock> OracleRuntime<S, A, C> {
    /// Bootstrap is deliberately NOT available through this runtime.
    /// Provision a genuinely new identity out of band, persist its genesis
    /// checkpoint to the trusted anchor, then open it here.
    pub fn open(
        path: impl AsRef<Path>,
        policy: RuntimePolicy,
        signer: S,
        mut anchor: A,
        clock: C,
        verifier: Box<dyn Ed25519Verifier>,
    ) -> RuntimeResult<Self> {
        let RuntimePolicy {
            dna,
            oracle,
            max_radius_us,
            radius_us,
        } = policy;
        if radius_us < 0 || radius_us > max_radius_us {
            return Err(RuntimeError::WrongClockPolicy);
        }
        if signer.public_key() != oracle {
            return Err(RuntimeError::WrongSignerKey);
        }
        let authenticated = anchor
            .load_authenticated(&dna, &oracle)
            .map_err(RuntimeError::Anchor)?;
        let journal = Journal::open_checked(
            path,
            dna,
            oracle,
            max_radius_us,
            &authenticated,
            verifier.as_ref(),
        )?;
        if journal.has_untracked_history() {
            return Err(RuntimeError::UntrackedHistory);
        }
        Ok(Self {
            journal,
            signer,
            anchor,
            clock,
            verifier,
            dna,
            oracle,
            radius_us,
            blocked: false,
        })
    }

    pub fn verified_head(&self) -> Option<&BatchChainHeadV3> {
        self.journal.head()
    }

    /// Single admission lane: verify trusted anchor, resolve exact durable
    /// idempotency, PREPARE + SIGNING + COMMIT, then advance external anchor.
    /// No signature leaves this method if either durability step fails.
    pub fn sign(&mut self, request: BatchSignRequest) -> RuntimeResult<SignedBatchStatementV3> {
        if self.blocked {
            return Err(RuntimeError::Quarantined);
        }
        let before = match self.anchor.load_authenticated(&self.dna, &self.oracle) {
            Ok(checkpoint) => checkpoint,
            Err(reason) => {
                self.blocked = true;
                return Err(RuntimeError::Anchor(reason));
            }
        };
        if let Err(error) = self.journal.require_exact_checkpoint(&before) {
            self.blocked = true;
            return Err(RuntimeError::Journal(error));
        }
        // Recalculate a DNA-bound commitment, including duplicate and size
        // validation, regardless of whether this is a new or retried ID.
        let (merkle_root, nonce_count) = prepare_batch_root(&self.dna, &request.nonces)
            .map_err(|error| RuntimeError::Journal(StoreError::Invalid(error.to_string())))?;
        let matches =
            |st: &BatchStatementV3| st.merkle_root == merkle_root && st.nonce_count == nonce_count;
        match self.journal.request_record(&request.request_id).cloned() {
            Some(RequestRecord::Committed(signed)) => {
                return if matches(&signed.statement) {
                    Ok(signed) // Original signature only. No signer callback.
                } else {
                    Err(RuntimeError::ConflictingRequest)
                };
            }
            Some(RequestRecord::Prepared(statement)) => {
                if !matches(&statement) {
                    return Err(RuntimeError::ConflictingRequest);
                }
                if self.journal.pending_phase() != Some(PendingPhase::PreparedNotSigned) {
                    self.blocked = true;
                    return Err(RuntimeError::Quarantined);
                }
            }
            None => {
                // Another prepared/ambiguous operation blocks ALL newer work.
                match self.journal.pending_phase() {
                    Some(PendingPhase::SigningMayHaveOccurred) => {
                        self.blocked = true;
                        return Err(RuntimeError::Journal(StoreError::AmbiguousSigning));
                    }
                    Some(PendingPhase::PreparedNotSigned) => {
                        return Err(RuntimeError::Journal(StoreError::Pending));
                    }
                    None => {}
                }
                let (seq, prev_signature, floor_us) = match self.journal.head() {
                    Some(head) => (
                        head.seq.checked_add(1).ok_or(StoreError::Exhausted)?,
                        Some(head.signature),
                        Some(head.next_floor_us),
                    ),
                    None => (0, None, None),
                };
                let now_us = match self.clock.now_us() {
                    Ok(time) => time,
                    Err(reason) => return Err(RuntimeError::Clock(reason)),
                };
                let interval =
                    TimeInterval::from_midpoint(now_us, self.radius_us).map_err(|error| {
                        RuntimeError::Journal(StoreError::Invalid(error.to_string()))
                    })?;
                let statement = BatchStatementV3 {
                    dna: self.dna,
                    oracle: self.oracle,
                    merkle_root,
                    nonce_count,
                    earliest_us: interval.earliest_us,
                    latest_us: interval.latest_us,
                    seq,
                    prev_signature,
                    floor_us,
                };
                self.journal
                    .prepare_request(request.request_id, statement)?;
            }
        }

        // The callback can be invoked only after the fsynced SIGNING fence.
        // Cancellation or key-service failure is permanently ambiguous until
        // operator-supervised reconciliation/identity retirement.
        let signer = &mut self.signer;
        let signed = match self
            .journal
            .sign_prepared(|bytes| signer.sign_once(bytes), self.verifier.as_ref())
        {
            Ok(signed) => signed,
            Err(error) => {
                self.blocked = true;
                return Err(RuntimeError::Journal(error));
            }
        };
        let after = match self.journal.checkpoint() {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                self.blocked = true;
                return Err(RuntimeError::Journal(error));
            }
        };
        if let Err(reason) =
            self.anchor
                .compare_and_store_monotonic(&self.dna, &self.oracle, &before, &after)
        {
            // Local COMMIT may already exist. Never return it without a
            // durable anchor; on restart a stale anchor blocks open_checked.
            self.blocked = true;
            return Err(RuntimeError::Anchor(reason));
        }
        Ok(signed)
    }
}
