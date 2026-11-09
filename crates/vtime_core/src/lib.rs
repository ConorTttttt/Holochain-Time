//! # vtime_core: verifiable time for Holochain
//!
//! Holochain action timestamps are written by their authors, so validators
//! cannot tell when anything really happened. This crate turns signed time
//! readings into bounds that every peer can check deterministically:
//!
//! - [`roughtime`]: verify Roughtime (RFC 10049) exchanges captured by a client.
//! - [`statement`]: time statements signed by Holochain oracle agents, encoded
//!   so the same signature verifies in Holochain and in Unyt Smart Agreements.
//! - [`evidence`]: mixed evidence sets judged against a [`evidence::TimePolicy`].
//! - [`interval`]: fault-tolerant combination: with at most `f` lying sources,
//!   robust lower/upper bounds need f + 1 sources and the NTP-style
//!   intersection needs 2f + 1.
//! - [`seal`]: nonces that bind readings to one action ("existed by").
//! - [`chain`]: propagating bounds along a source chain.
//! - [`malfeasance`]: self-signed proofs of oracle misbehaviour.
//! - [`oracle`]: what an oracle may sign next (floor guard, rate limit).
//! - [`batch`]: experimental Merkle nonce commitment for future signed batches (NOT current time evidence).
//! - [`verdict`]: comparing a claimed timestamp with proven bounds.
//!
//! The crate is `no_std` + `alloc`, deterministic, and has no Holochain
//! dependency, so integrity zomes, coordinator zomes, oracle services and
//! off-chain auditors all run the same code.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod batch;
pub mod chain;
pub mod error;
pub mod evidence;
pub mod hash;
pub mod interval;
pub mod keys;
pub mod malfeasance;
pub mod oracle;
pub mod roughtime;
pub mod seal;
pub mod signed_batch;
pub mod statement;
pub mod verdict;
pub mod verifier;

pub use error::{Error, Result};
pub use evidence::{RoughtimeEvidence, TimeEvidence, TimePolicy};
pub use interval::{SourceId, SourcedInterval, TimeInterval};
pub use statement::{ChainLink, OracleTimeStatement, SignedOracleStatement};
#[cfg(feature = "dalek")]
pub use verifier::DalekVerifier;
pub use verifier::Ed25519Verifier;
