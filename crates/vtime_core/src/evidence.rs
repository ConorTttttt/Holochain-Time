//! Evidence sets and the policy that judges them.
//!
//! An evidence set is a list of readings from distinct trusted sources:
//! Roughtime exchanges and oracle statements can be mixed freely. A policy
//! names the trusted keys, the number of sources that may be faulty (`f`), the
//! minimum set size and the largest uncertainty accepted from one source.

use alloc::format;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::hash::to_hex;
use crate::interval::{
    check_distinct, robust_lower_bound, robust_upper_bound, SourceId, SourcedInterval,
};
use crate::keys::agent_key_from_b64;
use crate::roughtime::verify_response;
use crate::statement::{verify_signed_statement, SignedOracleStatement};
use crate::verifier::Ed25519Verifier;

/// Upper limit on items in one evidence set, to bound validation work.
pub const MAX_EVIDENCE_ITEMS: usize = 32;

/// Fail closed when a query cannot consider *every* discovered candidate.
///
/// A coordinator must never silently truncate seals, anchors or candidate
/// ancestry checks: selection by author, link timestamp or proof value is not
/// completeness-preserving. This guards correctness but **does not** bound
/// the cost of fetching the DHT index itself; a bounded index is still needed.
pub fn require_complete_index(found: usize, limit: usize) -> Result<()> {
    if found > limit {
        return Err(Error::EvidenceIndexIncomplete { found, limit });
    }
    Ok(())
}

/// A Roughtime exchange captured by a client.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RoughtimeEvidence {
    /// The server's long-term Ed25519 key (32 bytes).
    #[serde(with = "serde_bytes")]
    pub server_public_key: Vec<u8>,
    /// The full framed request packet, exactly as sent.
    #[serde(with = "serde_bytes")]
    pub request: Vec<u8>,
    /// The full framed response packet, exactly as received.
    #[serde(with = "serde_bytes")]
    pub response: Vec<u8>,
}

/// One reading of the time.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TimeEvidence {
    /// A Roughtime server's signed response.
    Roughtime(RoughtimeEvidence),
    /// A Holochain oracle agent's signed statement.
    Oracle(SignedOracleStatement),
}

/// Which keys to trust and how much.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TimePolicy {
    /// Trusted Roughtime long-term keys.
    pub roughtime_servers: Vec<[u8; 32]>,
    /// Trusted oracle agent keys (raw 32 bytes).
    pub oracles: Vec<[u8; 32]>,
    /// Maximum number of sources in one set that may be lying (f).
    pub max_faulty: u32,
    /// Minimum number of distinct sources per set; must be at least f + 1.
    pub min_sources: u32,
    /// Largest accepted uncertainty radius from a single source, microseconds.
    pub max_radius_us: i64,
    /// The `DnaHashB64` oracle statements must name. Integrity zomes set it
    /// to their own DNA hash; `None` (off-chain tools) accepts any network.
    pub oracle_dna: Option<alloc::string::String>,
}

impl TimePolicy {
    /// Reject policies that cannot deliver a sound bound.
    pub fn check(&self) -> Result<()> {
        let need = self
            .max_faulty
            .checked_add(1)
            .ok_or_else(|| Error::InvalidPolicy("max_faulty is too large".into()))?;
        if self.min_sources < need {
            return Err(Error::InvalidPolicy(format!(
                "min_sources {} must be at least max_faulty + 1 = {need}",
                self.min_sources
            )));
        }
        // One Ed25519 key is one source. Listed as both a Roughtime server and
        // an oracle it would count twice towards f (SourceId keeps the two
        // roles apart), so such a policy is refused outright.
        if let Some(k) = self
            .roughtime_servers
            .iter()
            .find(|k| self.oracles.contains(k))
        {
            return Err(Error::InvalidPolicy(format!(
                "key {} is listed as both a Roughtime server and an oracle",
                to_hex(k)
            )));
        }
        let mut distinct: Vec<&[u8; 32]> = self
            .roughtime_servers
            .iter()
            .chain(self.oracles.iter())
            .collect();
        distinct.sort_unstable();
        distinct.dedup();
        let trusted = distinct.len();
        if trusted < self.min_sources as usize {
            return Err(Error::InvalidPolicy(format!(
                "only {trusted} trusted sources but min_sources is {}",
                self.min_sources
            )));
        }
        if self.max_radius_us <= 0 {
            return Err(Error::InvalidPolicy(
                "max_radius_us must be positive".into(),
            ));
        }
        // A set may hold at most MAX_EVIDENCE_ITEMS readings, so a larger
        // quorum could never be met.
        if self.min_sources as usize > MAX_EVIDENCE_ITEMS {
            return Err(Error::InvalidPolicy(format!(
                "min_sources {} exceeds the {MAX_EVIDENCE_ITEMS} readings a set may hold",
                self.min_sources
            )));
        }
        Ok(())
    }

    /// Enforce a separate *availability* promise for this deployment.
    ///
    /// `max_faulty` controls malicious source toleration and does not by
    /// itself promise progress through offline sources. A deployment that
    /// advertises tolerance of `unavailable` offline sources must have enough
    /// *distinct trusted* sources to satisfy `min_sources` after those losses.
    pub fn check_outage_tolerance(&self, unavailable: u32) -> Result<()> {
        self.check()?;
        let required = self
            .min_sources
            .checked_add(unavailable)
            .ok_or_else(|| Error::InvalidPolicy("min_sources + unavailable overflows".into()))?;
        let mut distinct: Vec<&[u8; 32]> = self
            .roughtime_servers
            .iter()
            .chain(self.oracles.iter())
            .collect();
        distinct.sort_unstable();
        distinct.dedup();
        if distinct.len() < required as usize {
            return Err(Error::InvalidPolicy(format!(
                "{} trusted sources cannot guarantee min_sources {} with {unavailable} unavailable; need at least {required}",
                distinct.len(), self.min_sources
            )));
        }
        Ok(())
    }

    /// True when `n` sources are enough for the near-simultaneous
    /// intersection to be sound (n >= 2f + 1).
    pub fn supports_intersection(&self, n: usize) -> bool {
        (self.max_faulty as usize)
            .checked_mul(2)
            .is_some_and(|two_f| n > two_f)
    }
}

/// Verify one item against the policy. With `expected_nonce`, the item must be
/// bound to that nonce (a seal); without it, any genuine reading counts (an
/// anchor, which only needs to exist before the thing that embeds it).
pub fn verify_evidence(
    evidence: &TimeEvidence,
    policy: &TimePolicy,
    verifier: &dyn Ed25519Verifier,
    expected_nonce: Option<&[u8; 32]>,
) -> Result<SourcedInterval> {
    let (source, interval, nonce) = match evidence {
        TimeEvidence::Roughtime(rt) => {
            let key: [u8; 32] =
                rt.server_public_key.as_slice().try_into().map_err(|_| {
                    Error::Malformed("Roughtime server key must be 32 bytes".into())
                })?;
            if !policy.roughtime_servers.contains(&key) {
                return Err(Error::UnknownSource(format!("roughtime:{}", to_hex(&key))));
            }
            let v = verify_response(&key, &rt.request, &rt.response, verifier)?;
            (SourceId::Roughtime(key), v.interval()?, v.nonce)
        }
        TimeEvidence::Oracle(signed) => {
            // Cheap policy checks first, so untrusted keys and foreign
            // networks cost no signature verification.
            let key = agent_key_from_b64(&signed.statement.oracle)?;
            if !policy.oracles.contains(&key) {
                return Err(Error::UnknownSource(format!("oracle:{}", to_hex(&key))));
            }
            if let Some(dna) = &policy.oracle_dna {
                if &signed.statement.dna != dna {
                    return Err(Error::WrongNetwork);
                }
            }
            let v = verify_signed_statement(signed, verifier)?;
            (SourceId::Oracle(v.oracle_key), v.interval, v.nonce)
        }
    };
    if let Some(expected) = expected_nonce {
        if &nonce != expected {
            return Err(Error::NonceMismatch);
        }
    }
    let radius = interval.radius_us();
    if radius > policy.max_radius_us {
        return Err(Error::RadiusTooLarge {
            radius_us: radius,
            max_us: policy.max_radius_us,
        });
    }
    Ok(SourcedInterval { source, interval })
}

/// Verify a whole set: every item valid, all sources distinct, at least
/// `min_sources` of them.
pub fn verify_evidence_set(
    items: &[TimeEvidence],
    policy: &TimePolicy,
    verifier: &dyn Ed25519Verifier,
    expected_nonce: Option<&[u8; 32]>,
) -> Result<Vec<SourcedInterval>> {
    policy.check()?;
    if items.len() > MAX_EVIDENCE_ITEMS {
        return Err(Error::Malformed(format!(
            "more than {MAX_EVIDENCE_ITEMS} evidence items"
        )));
    }
    let verified = items
        .iter()
        .map(|e| verify_evidence(e, policy, verifier, expected_nonce))
        .collect::<Result<Vec<_>>>()?;
    check_distinct(&verified)?;
    if verified.len() < policy.min_sources as usize {
        return Err(Error::NotEnoughSources {
            have: verified.len(),
            need: policy.min_sources as usize,
        });
    }
    Ok(verified)
}

/// True if a client supplied a complete verified Roughtime-only quorum.
///
/// Uses the same signature verifier, distinct trusted keys, policy and
/// seal nonce binding as integrity validation. Invalid, duplicate, wrong-nonce
/// and over-budget input cannot qualify. This is not global evidence discovery.
pub fn roughtime_quorum_satisfied(
    readings: &[RoughtimeEvidence],
    policy: &TimePolicy,
    verifier: &dyn Ed25519Verifier,
    expected_nonce: Option<&[u8; 32]>,
) -> bool {
    if readings.is_empty() || readings.len() > MAX_EVIDENCE_ITEMS {
        return false;
    }
    let evidence: Vec<TimeEvidence> = readings
        .iter()
        .cloned()
        .map(TimeEvidence::Roughtime)
        .collect();
    verify_evidence_set(&evidence, policy, verifier, expected_nonce).is_ok()
}

/// Check one oracle's answer to a request before it joins an evidence set:
/// it must verify under the policy, answer `nonce` (when given), and come from
/// the oracle that was asked (a faulty oracle could otherwise forward another
/// oracle's statement and make the set fail as a duplicate source).
pub fn accept_oracle_response(
    asked: &[u8; 32],
    signed: &SignedOracleStatement,
    policy: &TimePolicy,
    verifier: &dyn Ed25519Verifier,
    nonce: Option<&[u8; 32]>,
) -> Result<SourcedInterval> {
    // Cheapest check first: an answer naming another oracle is refused
    // before any signature work.
    if agent_key_from_b64(&signed.statement.oracle)? != *asked {
        return Err(Error::UnknownSource(format!(
            "answer from oracle:{} is not from the oracle asked",
            to_hex(asked)
        )));
    }
    let item = TimeEvidence::Oracle(signed.clone());
    verify_evidence(&item, policy, verifier, nonce)
}

/// Keep the oracle answers that pass [`accept_oracle_response`], one per
/// oracle, in order. Up to f faulty oracles then cost only their own entries
/// instead of failing the whole set.
pub fn filter_oracle_responses(
    responses: impl IntoIterator<Item = ([u8; 32], SignedOracleStatement)>,
    policy: &TimePolicy,
    verifier: &dyn Ed25519Verifier,
    nonce: Option<&[u8; 32]>,
) -> Vec<SignedOracleStatement> {
    let mut seen: Vec<[u8; 32]> = Vec::new();
    let mut out = Vec::new();
    for (asked, signed) in responses {
        if seen.contains(&asked) {
            continue;
        }
        if accept_oracle_response(&asked, &signed, policy, verifier, nonce).is_ok() {
            seen.push(asked);
            out.push(signed);
        }
    }
    out
}

/// Keep the items of an untrusted list (for example Roughtime readings a
/// client supplies) that verify on their own under `policy`, the first per
/// source, at most [`MAX_EVIDENCE_ITEMS`] of them. A faulty server's reply
/// then costs only its own entry instead of failing the whole set.
pub fn filter_evidence(
    items: impl IntoIterator<Item = TimeEvidence>,
    policy: &TimePolicy,
    verifier: &dyn Ed25519Verifier,
    expected_nonce: Option<&[u8; 32]>,
) -> Vec<TimeEvidence> {
    let mut seen: Vec<SourceId> = Vec::new();
    let mut out = Vec::new();
    for item in items {
        if out.len() == MAX_EVIDENCE_ITEMS {
            break;
        }
        let Ok(v) = verify_evidence(&item, policy, verifier, expected_nonce) else {
            continue;
        };
        if seen.contains(&v.source) {
            continue;
        }
        seen.push(v.source);
        out.push(item);
    }
    out
}

/// "Not before": the robust lower bound for something created after every
/// reading in the set (an entry that embeds the set).
pub fn anchor_lower_bound(
    items: &[TimeEvidence],
    policy: &TimePolicy,
    verifier: &dyn Ed25519Verifier,
) -> Result<i64> {
    let v = verify_evidence_set(items, policy, verifier, None)?;
    robust_lower_bound(&v, policy.max_faulty as usize)
}

/// "Not after": the robust upper bound for something that existed before every
/// reading in the set (an action whose hash every reading's nonce commits to).
pub fn seal_upper_bound(
    items: &[TimeEvidence],
    policy: &TimePolicy,
    verifier: &dyn Ed25519Verifier,
    seal_nonce: &[u8; 32],
) -> Result<i64> {
    let v = verify_evidence_set(items, policy, verifier, Some(seal_nonce))?;
    robust_upper_bound(&v, policy.max_faulty as usize)
}
