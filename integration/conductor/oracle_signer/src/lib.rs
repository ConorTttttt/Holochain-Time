//! Sprint 38: Lair-backed oracle signer and authenticated external
//! checkpoint adapter for the native v3 `OracleRuntime`.
//!
//! **Not a deployment authorisation.** The adapters connect the reviewed
//! runtime to real Lair key custody and to an authenticated checkpoint
//! protocol. Production acceptance still needs reviewed key custody, a
//! separately operated checkpoint service, caller authentication, and live
//! crash/restore drills (issue #70).
pub mod checkpoint;
pub mod lair;

pub use checkpoint::{
    record_signing_bytes, AuthenticatedCheckpointAnchor, CheckpointRecord, CheckpointTransport,
    SignedCheckpointReply, CHECKPOINT_RECORD_DOMAIN,
};
pub use lair::{
    FailureClass, LairOracleSigner, RotationPlan, SharedLairSigner, SignerError, SignerIdentity,
    SignerStatus,
};
