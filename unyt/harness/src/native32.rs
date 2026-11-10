//! Sprint 32A — versioned *interface* for a release-matched native Unyt reader.
//!
//! No native decoder, network API or deployment capability is implemented
//! here. The real installed Unyt application must supply an independently
//! reviewed adapter implementing all methods, including signature validation,
//! signed source-chain ancestry, RAVE replay protection and recipient Accept.
//! A mock implementor may exercise consistency but NEVER establishes funds.
//! This module is test-harness-only; no integrity zome or Rhai calls it.

use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeRave {
    /// Native-derived values AFTER the adapter has validated signatures.
    pub action_hash: String,
    pub author: String,
    pub alliance_id: String,
    pub agreement_action_hash: String,
    pub agreement_instance_id: String,
    pub unit_index: String,
    pub input_units: u64,
    pub locked_units: u64,
    pub payouts: Vec<NativeAllocation>,
    pub consumed_source_actions: Vec<String>,
    pub previous_rave_action: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeAllocation {
    pub recipient: String,
    pub unit_index: String,
    pub amount_units: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeAccept {
    pub action_hash: String,
    pub signed_recipient: String,
    pub rave_action_hash: String,
    pub unit_index: String,
    pub amount_units: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedAgreement<'a> {
    pub alliance_id: &'a str,
    pub agreement_action_hash: &'a str,
    pub agreement_instance_id: &'a str,
    pub unit_index: &'a str,
    pub rave_action_hash: &'a str,
    pub previous_rave_action: Option<&'a str>,
    pub independent_peer_agent: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeGateError {
    AdapterUnavailableOrInvalid,
    WrongAgreementOrInstance,
    WrongRaveOrPredecessor,
    InvalidSources,
    DuplicateSource,
    MissingOrDuplicateAccept,
    WrongRecipientAccept,
    UnitConservation,
    TooManyEntries,
}

/// Review and source-code mapping MUST establish all of these operations for
/// the exact installed Unyt release. There is intentionally no default
/// implementation, invented RPC, or accept-on-true JSON attestation.
pub trait NativeUnytVerifier {
    /// Decode + authenticate signed RAVE/action and author source-chain
    /// ownership; check agreement execution's native rules and references.
    fn verify_signed_rave(&self, raw_native_rave: &[u8]) -> Result<NativeRave, NativeGateError>;

    /// Decode + authenticate a DISTINCT recipient-signed Accept action;
    /// check signer belongs to recipient and it references a real allocation.
    fn verify_recipient_accept(
        &self,
        raw_native_accept: &[u8],
    ) -> Result<NativeAccept, NativeGateError>;

    /// Independently inspect the source action's native authenticated
    /// predecessor/successor chain and spend links, ensuring it is spent
    /// exactly once in this RAVE and not also in conflicting known RAVEs.
    /// Local observation can never guarantee global absence of a spend.
    fn verify_source_spend(
        &self,
        source_action: &str,
        rave_action: &str,
    ) -> Result<(), NativeGateError>;

    /// Query a DISTINCT authenticated peer's source-chain/account view.
    /// Do not accept an actor label or normalized JSON as peer verification.
    fn verify_independent_peer(
        &self,
        rave_action: &str,
        independent_peer: &str,
    ) -> Result<(), NativeGateError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeContractPreflight {
    pub accounted_input_units: u64,
    pub accounted_payout_units: u64,
    pub accounted_locked_units: u64,
    pub recipient_accepts_checked: usize,
    pub source_actions_checked: usize,
    /// Always false: a production acceptance report must independently
    /// authenticate the *specific installed* implementation, peer, economic
    /// policy and real funded state, not this structural harness.
    pub production_settlement_proven: bool,
    pub economic_policy_approved: bool,
}

/// Structural constraints around the native adapter, never a funds verdict.
/// Both the v2 statement's agreement-binding gap and lifecycle review remain
/// unresolved even when the adapter verifies all RAVE/Accept/source bytes.
pub fn review_native_evidence<V: NativeUnytVerifier>(
    reader: &V,
    expected: &ExpectedAgreement<'_>,
    rave_raw: &[u8],
    accepts_raw: &[Vec<u8>],
) -> Result<NativeContractPreflight, NativeGateError> {
    if rave_raw.is_empty() || accepts_raw.is_empty() || accepts_raw.len() > 32 {
        return Err(NativeGateError::MissingOrDuplicateAccept);
    }
    if expected.independent_peer_agent.is_empty() {
        return Err(NativeGateError::AdapterUnavailableOrInvalid);
    }
    let rave = reader.verify_signed_rave(rave_raw)?;
    if rave.alliance_id != expected.alliance_id
        || rave.agreement_action_hash != expected.agreement_action_hash
        || rave.agreement_instance_id != expected.agreement_instance_id
        || rave.unit_index != expected.unit_index
    {
        return Err(NativeGateError::WrongAgreementOrInstance);
    }
    if rave.action_hash != expected.rave_action_hash
        || rave.previous_rave_action.as_deref() != expected.previous_rave_action
    {
        return Err(NativeGateError::WrongRaveOrPredecessor);
    }
    if rave.payouts.len() != accepts_raw.len() || rave.payouts.len() > 32 {
        return Err(NativeGateError::MissingOrDuplicateAccept);
    }
    if rave.consumed_source_actions.is_empty() || rave.consumed_source_actions.len() > 32 {
        return Err(NativeGateError::InvalidSources);
    }
    let mut source_seen = HashSet::new();
    for source in &rave.consumed_source_actions {
        if source.is_empty() || !source_seen.insert(source) {
            return Err(NativeGateError::DuplicateSource);
        }
        reader.verify_source_spend(source, &rave.action_hash)?;
    }
    let mut accepted_seen = HashSet::new();
    let mut amount = 0_u64;
    for (allocation, raw) in rave.payouts.iter().zip(accepts_raw) {
        if allocation.amount_units == 0 || allocation.unit_index != rave.unit_index {
            return Err(NativeGateError::WrongRecipientAccept);
        }
        amount = amount
            .checked_add(allocation.amount_units)
            .ok_or(NativeGateError::UnitConservation)?;
        if raw.is_empty() {
            return Err(NativeGateError::MissingOrDuplicateAccept);
        }
        let accept = reader.verify_recipient_accept(raw)?;
        if accept.action_hash.is_empty() || !accepted_seen.insert(accept.action_hash.clone()) {
            return Err(NativeGateError::MissingOrDuplicateAccept);
        }
        if accept.signed_recipient != allocation.recipient
            || accept.rave_action_hash != rave.action_hash
            || accept.unit_index != allocation.unit_index
            || accept.amount_units != allocation.amount_units
        {
            return Err(NativeGateError::WrongRecipientAccept);
        }
    }
    let conserved = amount
        .checked_add(rave.locked_units)
        .ok_or(NativeGateError::UnitConservation)?;
    if conserved != rave.input_units {
        return Err(NativeGateError::UnitConservation);
    }
    reader.verify_independent_peer(&rave.action_hash, expected.independent_peer_agent)?;
    Ok(NativeContractPreflight {
        accounted_input_units: rave.input_units,
        accounted_payout_units: amount,
        accounted_locked_units: rave.locked_units,
        recipient_accepts_checked: accepted_seen.len(),
        source_actions_checked: source_seen.len(),
        production_settlement_proven: false,
        economic_policy_approved: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure mock of a version-specific adapter. ALL records in these tests
    // are synthetic and must NEVER be called native network test evidence.
    struct Fixture {
        rave: NativeRave,
        accept: NativeAccept,
        reject_source: bool,
        reject_peer: bool,
    }

    impl NativeUnytVerifier for Fixture {
        fn verify_signed_rave(&self, raw: &[u8]) -> Result<NativeRave, NativeGateError> {
            if raw != b"MOCK-RAVE" {
                return Err(NativeGateError::AdapterUnavailableOrInvalid);
            }
            Ok(self.rave.clone())
        }
        fn verify_recipient_accept(
            &self,
            raw: &[u8],
        ) -> Result<NativeAccept, NativeGateError> {
            if raw != b"MOCK-ACCEPT" {
                return Err(NativeGateError::AdapterUnavailableOrInvalid);
            }
            Ok(self.accept.clone())
        }
        fn verify_source_spend(
            &self,
            _source: &str,
            _rave: &str,
        ) -> Result<(), NativeGateError> {
            if self.reject_source {
                Err(NativeGateError::InvalidSources)
            } else {
                Ok(())
            }
        }
        fn verify_independent_peer(
            &self,
            _rave: &str,
            _peer: &str,
        ) -> Result<(), NativeGateError> {
            if self.reject_peer {
                Err(NativeGateError::AdapterUnavailableOrInvalid)
            } else {
                Ok(())
            }
        }
    }

    fn expected() -> ExpectedAgreement<'static> {
        ExpectedAgreement {
            alliance_id: "test-alliance",
            agreement_action_hash: "agreement",
            agreement_instance_id: "instance",
            unit_index: "0",
            rave_action_hash: "rave",
            previous_rave_action: None,
            independent_peer_agent: "independent-peer",
        }
    }

    fn fixture() -> Fixture {
        Fixture {
            rave: NativeRave {
                action_hash: "rave".into(),
                author: "rave-executor".into(),
                alliance_id: "test-alliance".into(),
                agreement_action_hash: "agreement".into(),
                agreement_instance_id: "instance".into(),
                unit_index: "0".into(),
                input_units: 300,
                locked_units: 200,
                payouts: vec![NativeAllocation {
                    recipient: "beneficiary".into(),
                    unit_index: "0".into(),
                    amount_units: 100,
                }],
                consumed_source_actions: vec!["source-1".into()],
                previous_rave_action: None,
            },
            accept: NativeAccept {
                action_hash: "accept-1".into(),
                signed_recipient: "beneficiary".into(),
                rave_action_hash: "rave".into(),
                unit_index: "0".into(),
                amount_units: 100,
            },
            reject_source: false,
            reject_peer: false,
        }
    }

    fn review(f: &Fixture) -> Result<NativeContractPreflight, NativeGateError> {
        review_native_evidence(f, &expected(), b"MOCK-RAVE", &[b"MOCK-ACCEPT".to_vec()])
    }

    #[test]
    fn mock_contract_never_proves_real_settlement_or_policy() {
        let result = review(&fixture()).unwrap();
        assert_eq!(result.accounted_input_units, 300);
        assert_eq!(result.accounted_locked_units, 200);
        assert_eq!(result.recipient_accepts_checked, 1);
        assert!(!result.production_settlement_proven);
        assert!(!result.economic_policy_approved);
    }

    #[test]
    fn wrong_agreement_and_previous_rave_rejected() {
        let mut f = fixture();
        f.rave.agreement_instance_id = "other-instance".into();
        assert_eq!(review(&f), Err(NativeGateError::WrongAgreementOrInstance));
        let mut f = fixture();
        f.rave.previous_rave_action = Some("different-predecessor".into());
        assert_eq!(review(&f), Err(NativeGateError::WrongRaveOrPredecessor));
    }

    #[test]
    fn missing_mismatched_or_reused_accept_rejected() {
        let f = fixture();
        assert_eq!(
            review_native_evidence(&f, &expected(), b"MOCK-RAVE", &[]),
            Err(NativeGateError::MissingOrDuplicateAccept)
        );
        let mut f = fixture();
        f.accept.signed_recipient = "impostor".into();
        assert_eq!(review(&f), Err(NativeGateError::WrongRecipientAccept));
        let mut f = fixture();
        f.accept.rave_action_hash = "other-rave".into();
        assert_eq!(review(&f), Err(NativeGateError::WrongRecipientAccept));
        let mut f = fixture();
        f.rave.payouts.push(f.rave.payouts[0].clone());
        f.rave.locked_units = 100;
        assert_eq!(
            review_native_evidence(
                &f,
                &expected(),
                b"MOCK-RAVE",
                &[b"MOCK-ACCEPT".to_vec(), b"MOCK-ACCEPT".to_vec()]
            ),
            Err(NativeGateError::MissingOrDuplicateAccept)
        );
    }

    #[test]
    fn source_spend_and_independent_peer_must_be_checked() {
        let mut f = fixture();
        f.rave.consumed_source_actions.push("source-1".into());
        assert_eq!(review(&f), Err(NativeGateError::DuplicateSource));
        let mut f = fixture();
        f.reject_source = true;
        assert_eq!(review(&f), Err(NativeGateError::InvalidSources));
        let mut f = fixture();
        f.reject_peer = true;
        assert_eq!(review(&f), Err(NativeGateError::AdapterUnavailableOrInvalid));
    }

    #[test]
    fn no_money_creation_and_native_adapter_errors_fail_closed() {
        let mut f = fixture();
        f.rave.payouts[0].amount_units = 101;
        f.accept.amount_units = 101;
        assert_eq!(review(&f), Err(NativeGateError::UnitConservation));
        let f = fixture();
        assert_eq!(
            review_native_evidence(&f, &expected(), b"UNVERIFIED", &[b"MOCK-ACCEPT".to_vec()]),
            Err(NativeGateError::AdapterUnavailableOrInvalid)
        );
    }
}
