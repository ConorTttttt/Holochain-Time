//! Authenticated, challenge-bound external checkpoint adapter.
//!
//! [`AuthenticatedCheckpointAnchor`] implements the runtime's
//! `CheckpointAnchor` against an independently operated checkpoint service
//! reached through a [`CheckpointTransport`]. The service holds its own
//! Ed25519 key and keeps, per `(DNA, oracle)`, a version counter and the
//! latest journal checkpoint.
//!
//! What the adapter enforces:
//!
//! * every reply is signed by the pinned service key over a domain-separated
//!   record that includes the DNA, the oracle, the version, the checkpoint
//!   and a **fresh random challenge** chosen by this process. A replayed
//!   older reply fails verification, even after a restart, so a stale journal
//!   restored together with a stale reply cannot be accepted;
//! * versions never go backwards, and the same version never carries a
//!   different checkpoint (equivocation) within one process;
//! * compare-and-swap only advances from the last authenticated record, by
//!   exactly one version and one journal sequence, to exactly the requested
//!   checkpoint.
//!
//! What it cannot provide: the independence, durability and honesty of the
//! service itself. **A test double or a same-host service is not external
//! anti-rollback evidence.** External checkpoint acceptance is BLOCKED until
//! a separately operated service exists and is reviewed (issue #70).
use lair_keystore_api::dependencies::sodoken;
use vtime_core::{DalekVerifier, Ed25519Verifier};
use vtime_oracle_state::runtime::CheckpointAnchor;
use vtime_oracle_state::Checkpoint;

pub const CHECKPOINT_RECORD_DOMAIN: &[u8] = b"hc-vtime/oracle-checkpoint-record/v1\0";

/// The service's statement about one oracle lane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointRecord {
    pub dna: [u8; 39],
    pub oracle: [u8; 32],
    pub version: u64,
    pub checkpoint: Checkpoint,
}

/// A record signed by the service together with the caller's challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpointReply {
    pub record: CheckpointRecord,
    pub challenge: [u8; 32],
    pub signature: [u8; 64],
}

/// Canonical bytes the service signs. Shared by the adapter and any service
/// implementation so both sides agree byte-for-byte.
pub fn record_signing_bytes(record: &CheckpointRecord, challenge: &[u8; 32]) -> Vec<u8> {
    let cp = &record.checkpoint;
    let mut out =
        Vec::with_capacity(CHECKPOINT_RECORD_DOMAIN.len() + 39 + 32 + 8 + 9 + 65 + 9 + 32 + 32);
    out.extend_from_slice(CHECKPOINT_RECORD_DOMAIN);
    out.extend_from_slice(&record.dna);
    out.extend_from_slice(&record.oracle);
    out.extend_from_slice(&record.version.to_be_bytes());
    match cp.seq {
        Some(seq) => {
            out.push(1);
            out.extend_from_slice(&seq.to_be_bytes());
        }
        None => out.extend_from_slice(&[0; 9]),
    }
    match cp.signature {
        Some(sig) => {
            out.push(1);
            out.extend_from_slice(&sig);
        }
        None => out.extend_from_slice(&[0; 65]),
    }
    match cp.next_floor_us {
        Some(floor) => {
            out.push(1);
            out.extend_from_slice(&floor.to_be_bytes());
        }
        None => out.extend_from_slice(&[0; 9]),
    }
    out.extend_from_slice(&cp.journal_hash);
    out.extend_from_slice(challenge);
    out
}

/// Network/IPC access to the independent checkpoint service.
pub trait CheckpointTransport {
    fn read_latest(
        &mut self,
        dna: &[u8; 39],
        oracle: &[u8; 32],
        challenge: [u8; 32],
    ) -> Result<SignedCheckpointReply, String>;

    /// Atomically replace version `expected_version` (holding `expected`) with
    /// `next` as version `expected_version + 1`, or fail without change.
    fn compare_and_swap(
        &mut self,
        dna: &[u8; 39],
        oracle: &[u8; 32],
        expected_version: u64,
        expected: &Checkpoint,
        next: &Checkpoint,
        challenge: [u8; 32],
    ) -> Result<SignedCheckpointReply, String>;
}

pub struct AuthenticatedCheckpointAnchor<T: CheckpointTransport> {
    transport: T,
    service_key: [u8; 32],
    last: Option<CheckpointRecord>,
}

fn fresh_challenge() -> Result<[u8; 32], String> {
    let mut challenge = [0u8; 32];
    sodoken::random::randombytes_buf(&mut challenge).map_err(|e| e.to_string())?;
    Ok(challenge)
}

fn successor(expected: &Checkpoint, next: &Checkpoint) -> bool {
    next.seq == Some(expected.seq.map_or(0, |s| s + 1))
        && next.journal_hash != expected.journal_hash
}

impl<T: CheckpointTransport> AuthenticatedCheckpointAnchor<T> {
    /// `service_key` must be obtained out of band from the service operator.
    pub fn new(transport: T, service_key: [u8; 32]) -> Self {
        Self {
            transport,
            service_key,
            last: None,
        }
    }

    pub fn last_authenticated(&self) -> Option<&CheckpointRecord> {
        self.last.as_ref()
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    fn verify(
        &self,
        reply: &SignedCheckpointReply,
        dna: &[u8; 39],
        oracle: &[u8; 32],
        challenge: &[u8; 32],
    ) -> Result<(), String> {
        if &reply.challenge != challenge {
            return Err("checkpoint reply is not bound to this request (replay?)".into());
        }
        if &reply.record.dna != dna || &reply.record.oracle != oracle {
            return Err("checkpoint reply is for a different DNA or oracle".into());
        }
        let bytes = record_signing_bytes(&reply.record, challenge);
        match DalekVerifier.verify(&self.service_key, &bytes, &reply.signature) {
            Ok(true) => Ok(()),
            _ => Err("checkpoint reply signature invalid for the pinned service key".into()),
        }
    }

    fn accept(&mut self, record: CheckpointRecord) -> Result<(), String> {
        if let Some(last) = &self.last {
            if record.version < last.version {
                return Err(format!(
                    "stale checkpoint: version {} is older than {}",
                    record.version, last.version
                ));
            }
            if record.version == last.version && record.checkpoint != last.checkpoint {
                return Err("checkpoint service equivocated for one version".into());
            }
        }
        self.last = Some(record);
        Ok(())
    }
}

impl<T: CheckpointTransport> CheckpointAnchor for AuthenticatedCheckpointAnchor<T> {
    fn load_authenticated(
        &mut self,
        dna: &[u8; 39],
        oracle: &[u8; 32],
    ) -> Result<Checkpoint, String> {
        let challenge = fresh_challenge()?;
        let reply = self.transport.read_latest(dna, oracle, challenge)?;
        self.verify(&reply, dna, oracle, &challenge)?;
        let checkpoint = reply.record.checkpoint.clone();
        self.accept(reply.record)?;
        Ok(checkpoint)
    }

    fn compare_and_store_monotonic(
        &mut self,
        dna: &[u8; 39],
        oracle: &[u8; 32],
        expected: &Checkpoint,
        next: &Checkpoint,
    ) -> Result<(), String> {
        let last = self
            .last
            .clone()
            .ok_or("no authenticated checkpoint read before compare-and-swap")?;
        if &last.dna != dna || &last.oracle != oracle || &last.checkpoint != expected {
            return Err("expected checkpoint is not the last authenticated one".into());
        }
        if !successor(expected, next) {
            return Err("next checkpoint does not advance by exactly one sequence".into());
        }
        let challenge = fresh_challenge()?;
        let reply = self.transport.compare_and_swap(
            dna,
            oracle,
            last.version,
            expected,
            next,
            challenge,
        )?;
        self.verify(&reply, dna, oracle, &challenge)?;
        if reply.record.version != last.version + 1 || &reply.record.checkpoint != next {
            return Err("service did not store exactly the requested successor".into());
        }
        self.accept(reply.record)
    }
}
