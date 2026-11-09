//! Test-only result classification for recovery and potentially unsafe evidence.
//!
//! A cryptographically verified bound is not automatically safe for financial
//! execution: the explicit-witness API deliberately cannot establish global
//! DHT evidence completeness, and unavailable author activity is unknown.
//! This helper is exclusively for the conductor tests and release gate.
use holochain::prelude::ActionHash;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct WitnessResult {
    pub target: ActionHash,
    pub not_before_us: Option<i64>,
    pub not_after_us: Option<i64>,
    pub author_chain_flagged: Option<bool>,
    pub evidence_complete: bool,
    pub conclusion: WitnessConclusion,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub enum WitnessConclusion {
    Backdated { by_us: i64 },
    FutureDated { by_us: i64 },
    NoContradictionInSuppliedProofs,
}

/// Conservatively evaluate the limited result. This is deliberately NOT a
/// positive global-trust verdict, even for valid author activity.
#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryAssessment {
    UntrustedConflict,
    UntrustedUnknownAncestry,
    VerifiedSuppliedBoundsOnly,
}

pub fn assess(w: &WitnessResult) -> RecoveryAssessment {
    if w.author_chain_flagged == Some(true)
        || matches!(w.conclusion, WitnessConclusion::Backdated { .. } | WitnessConclusion::FutureDated { .. })
    {
        RecoveryAssessment::UntrustedConflict
    } else if w.author_chain_flagged.is_none() {
        RecoveryAssessment::UntrustedUnknownAncestry
    } else {
        // Even with clean activity, `evidence_complete` is false, so there
        // is no globally trusted outcome to return here.
        RecoveryAssessment::VerifiedSuppliedBoundsOnly
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(chain: Option<bool>, conclusion: WitnessConclusion) -> WitnessResult {
        WitnessResult {
            target: ActionHash::from_raw_32(vec![1; 32]),
            not_before_us: Some(100),
            not_after_us: Some(200),
            author_chain_flagged: chain,
            evidence_complete: false,
            conclusion,
        }
    }

    #[test]
    fn unknown_author_health_is_never_treated_as_safe() {
        assert_eq!(assess(&reading(None, WitnessConclusion::NoContradictionInSuppliedProofs)),
                   RecoveryAssessment::UntrustedUnknownAncestry);
    }

    #[test]
    fn flagged_author_or_proven_backdating_is_a_conflict() {
        assert_eq!(assess(&reading(Some(true), WitnessConclusion::NoContradictionInSuppliedProofs)),
                   RecoveryAssessment::UntrustedConflict);
        assert_eq!(assess(&reading(Some(false), WitnessConclusion::Backdated { by_us: 5 })),
                   RecoveryAssessment::UntrustedConflict);
    }

    #[test]
    fn a_clean_reading_only_proves_the_submitted_bounds() {
        assert_eq!(assess(&reading(Some(false), WitnessConclusion::NoContradictionInSuppliedProofs)),
                   RecoveryAssessment::VerifiedSuppliedBoundsOnly);
    }
}
