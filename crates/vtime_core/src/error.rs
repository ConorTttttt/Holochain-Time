//! Error type shared by every module.

use alloc::string::String;
use core::fmt;

/// Every way a piece of time evidence can fail verification.
///
/// Errors are deterministic: the same bytes produce the same error on every
/// peer, which is what Holochain validation requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Wire data that does not parse (bad framing, offsets, lengths, encodings).
    Malformed(String),
    /// A signature did not verify. The string names which one.
    BadSignature(&'static str),
    /// The nonce in the evidence is not the one the verifier required.
    NonceMismatch,
    /// A Roughtime protocol version this crate does not verify.
    UnsupportedVersion(u32),
    /// The Roughtime delegation certificate does not cover the signed midpoint.
    DelegationOutOfRange {
        /// Signed midpoint, Unix seconds.
        midpoint: u64,
        /// Delegation start, Unix seconds.
        mint: u64,
        /// Delegation end, Unix seconds.
        maxt: u64,
    },
    /// The Roughtime Merkle path does not lead from the request to the signed root.
    MerkleMismatch,
    /// The evidence was produced by a key the policy does not trust.
    UnknownSource(String),
    /// The same source appears more than once in one evidence set.
    DuplicateSource(String),
    /// Fewer distinct trusted sources than the policy (or fault bound) requires.
    NotEnoughSources {
        /// Distinct sources present.
        have: usize,
        /// Distinct sources required.
        need: usize,
    },
    /// The source's uncertainty radius exceeds the policy maximum.
    RadiusTooLarge {
        /// The source's radius.
        radius_us: i64,
        /// The policy maximum.
        max_us: i64,
    },
    /// An oracle statement whose fields are not canonical.
    InvalidStatement(String),
    /// An oracle statement signed in a network (DNA) other than the one
    /// the policy accepts.
    WrongNetwork,
    /// An oracle refuses to sign: its previous statement is too recent.
    RateLimited {
        /// Microseconds until the oracle will answer again.
        retry_after_us: i64,
    },
    /// An oracle refuses to sign: its clock is behind what it already signed,
    /// so a new statement would contradict its own chain.
    ClockBehind {
        /// The latest time the new statement could claim.
        latest_us: i64,
        /// The chain's high-water mark that it would fall below.
        floor_us: i64,
    },
    /// An evidence query returned more links/candidates than can safely be
    /// examined. Callers must not interpret a truncated result as complete.
    EvidenceIndexIncomplete {
        /// Total discovered index records/candidates.
        found: usize,
        /// Maximum records that this query can fully examine.
        limit: usize,
    },
    /// A policy that cannot give the guarantees it claims.
    InvalidPolicy(String),
    /// Arithmetic left the representable range.
    Overflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(m) => write!(f, "malformed evidence: {m}"),
            Error::BadSignature(which) => write!(f, "signature does not verify: {which}"),
            Error::NonceMismatch => write!(f, "evidence nonce does not match the required nonce"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported Roughtime version 0x{v:08x}"),
            Error::DelegationOutOfRange { midpoint, mint, maxt } => write!(
                f,
                "Roughtime midpoint {midpoint} is outside the delegation window [{mint}, {maxt}]"
            ),
            Error::MerkleMismatch => write!(f, "Roughtime Merkle path does not match the signed root"),
            Error::UnknownSource(s) => write!(f, "evidence source is not trusted by policy: {s}"),
            Error::DuplicateSource(s) => write!(f, "source appears more than once: {s}"),
            Error::NotEnoughSources { have, need } => {
                write!(f, "need {need} distinct trusted sources, have {have}")
            }
            Error::RadiusTooLarge { radius_us, max_us } => {
                write!(f, "uncertainty radius {radius_us} us exceeds policy maximum {max_us} us")
            }
            Error::InvalidStatement(m) => write!(f, "invalid oracle statement: {m}"),
            Error::WrongNetwork => write!(f, "oracle statement was signed for another network (DNA)"),
            Error::RateLimited { retry_after_us } => {
                write!(f, "oracle is rate limited; retry in {retry_after_us} us")
            }
            Error::ClockBehind { latest_us, floor_us } => write!(
                f,
                "oracle clock is behind its own statement chain: latest {latest_us} us < floor {floor_us} us"
            ),
            Error::EvidenceIndexIncomplete { found, limit } => write!(
                f,
                "time evidence query incomplete: {found} records exceed safe limit {limit}; refusing a partial verdict"
            ),
            Error::InvalidPolicy(m) => write!(f, "invalid time policy: {m}"),
            Error::Overflow => write!(f, "time arithmetic overflow"),
        }
    }
}

impl core::error::Error for Error {}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

pub(crate) fn malformed<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Malformed(msg.into()))
}
