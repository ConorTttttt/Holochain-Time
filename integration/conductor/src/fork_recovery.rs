//! Sprint 22 test-only conflict and warrant adjudication.
//!
//! This deliberately does NOT claim to independently authenticate Holochain
//! actions or warrants. Inputs are observations made elsewhere. It models
//! fail-closed behavior at the consumer boundary until an authority reports
//! sufficient evidence. Never turn an incomplete fork view into "clean".
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActivityHealth {
    Valid,
    Forked,
    Invalid,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    RejectConflict,
    BlockUnknown,
    SuppliedEvidenceOnly,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionFixture {
    /// Logical test identifier, NOT a signed ActionHash or certificate.
    pub hash: String,
    pub seq: u32,
    pub prev: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForkFixture {
    pub id: String,
    pub dna: String,
    pub author: String,
    /// Holochain authority status. Unavailable is NOT valid.
    pub activity_health: ActivityHealth,
    /// None = failed/unavailable warrant query, not zero warrants.
    pub warrants_observed: Option<u32>,
    pub actions: Vec<ActionFixture>,
    pub expected: Decision,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureSet {
    pub schema: String,
    pub cases: Vec<ForkFixture>,
}

/// Detect concrete incompatible branches in a bounded local observation.
/// This is a small test oracle for synthetic fixtures, not a replacement
/// for Holochain agent activity/warrant validation.
fn has_explicit_fork(actions: &[ActionFixture]) -> bool {
    let mut seq_to_hash = BTreeMap::<u32, &str>::new();
    let mut hash_to_identity = BTreeMap::<&str, (u32, Option<&str>)>::new();
    for action in actions {
        if let Some(existing) = seq_to_hash.insert(action.seq, &action.hash) {
            if existing != action.hash {
                return true;
            }
        }
        let prior = hash_to_identity.insert(
            &action.hash,
            (action.seq, action.prev.as_deref()),
        );
        if let Some(existing) = prior {
            if existing != (action.seq, action.prev.as_deref()) {
                return true;
            }
        }
        // If a claimed parent is *observed* at the previous sequence number,
        // two different hashes cannot both occupy that exact chain position.
        // An unobserved parent is incomplete, not proof of a fork.
        if let Some(previous_seq) = action.seq.checked_sub(1) {
            if let Some(previous) = seq_to_hash.get(&previous_seq) {
                if action.prev.as_deref() != Some(*previous) {
                    return true;
                }
            }
        }
    }
    false
}

fn is_complete_observed_segment(actions: &[ActionFixture]) -> bool {
    if actions.is_empty() {
        return false;
    }
    let mut sorted: Vec<&ActionFixture> = actions.iter().collect();
    sorted.sort_by_key(|item| item.seq);
    sorted.dedup_by(|a, b| a.hash == b.hash && a.seq == b.seq && a.prev == b.prev);
    sorted.windows(2).all(|pair| {
        pair[0].seq.checked_add(1) == Some(pair[1].seq)
            && pair[1].prev.as_deref() == Some(pair[0].hash.as_str())
    })
}

/// A warrant, invalid activity, or observed fork blocks reliance on evidence.
/// Missing warrant/activity information is UNKNOWN, never a clean result.
/// Even the "supplied" outcome cannot establish global chain completeness.
pub fn classify(input: &ForkFixture) -> Decision {
    if input.warrants_observed.is_some_and(|count| count > 0)
        || matches!(input.activity_health, ActivityHealth::Forked | ActivityHealth::Invalid)
        || has_explicit_fork(&input.actions)
    {
        return Decision::RejectConflict;
    }
    if input.activity_health != ActivityHealth::Valid
        || input.warrants_observed.is_none()
        || !is_complete_observed_segment(&input.actions)
    {
        return Decision::BlockUnknown;
    }
    Decision::SuppliedEvidenceOnly
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_fork_fixtures_match_conservative_decisions() {
        let set: FixtureSet = serde_json::from_str(include_str!(
            "../fixtures/fork_recovery_cases.json"
        )).expect("invalid committed test fixtures");
        assert_eq!(set.schema, "hc-vtime-sprint22-fork-recovery-v1");
        assert!(set.cases.len() >= 9);
        for case in set.cases {
            assert!(!case.dna.is_empty() && !case.author.is_empty());
            assert_eq!(
                classify(&case), case.expected,
                "fixture {} changed verdict", case.id
            );
        }
    }

    #[test]
    fn positive_warrants_override_a_valid_chain() {
        let fixture = ForkFixture {
            id: "warrant".into(),
            dna: "test-dna".into(),
            author: "test-agent".into(),
            activity_health: ActivityHealth::Valid,
            warrants_observed: Some(1),
            actions: vec![ActionFixture {hash:"a".into(), seq: 4, prev: None}],
            expected: Decision::RejectConflict,
        };
        assert_eq!(classify(&fixture), Decision::RejectConflict);
    }

    #[test]
    fn missing_authority_warrant_response_never_means_zero_warrants() {
        let fixture = ForkFixture {
            id: "unknown".into(),
            dna: "test-dna".into(),
            author: "test-agent".into(),
            activity_health: ActivityHealth::Valid,
            warrants_observed: None,
            actions: vec![ActionFixture {hash:"a".into(), seq: 4, prev: None}],
            expected: Decision::BlockUnknown,
        };
        assert_eq!(classify(&fixture), Decision::BlockUnknown);
    }

    #[test]
    fn arithmetic_edges_and_empty_sequences_fail_closed() {
        let fixture = ForkFixture {
            id: "edge".into(),
            dna: "test-dna".into(),
            author: "test-agent".into(),
            activity_health: ActivityHealth::Valid,
            warrants_observed: Some(0),
            actions: vec![],
            expected: Decision::BlockUnknown,
        };
        assert_eq!(classify(&fixture), Decision::BlockUnknown);
    }
}
