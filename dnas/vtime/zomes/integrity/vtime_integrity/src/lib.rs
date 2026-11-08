//! # vtime_integrity
//!
//! Validation rules for verifiable time on Holochain.
//!
//! - `TimeAnchor`: an evidence set embedded in an entry. Every reading existed
//!   before the anchor action, so the anchor (and every later action by the
//!   same agent) is **not before** the set's robust lower bound. The anchor's
//!   own timestamp may not precede that bound by more than the allowed skew,
//!   which makes provable backdating invalid.
//! - `TimeSeal`: an evidence set whose every reading answers
//!   `seal_nonce(dna_hash, target)`. The target action's content was therefore
//!   fixed **not after** the set's robust upper bound (publication may come
//!   later, see DESIGN.md 3.1). Anyone may seal any action.
//! - `OracleLog`: a private entry where an oracle keeps its signed statements,
//!   so its statement chain (`seq`, `prev`, `floor`) survives restarts.
//!
//! Oracle statements count only if they name this DNA in their `dna` field,
//! so an oracle's chains in other networks never mix with this one.
//!
//! Evidence, anchors and seals are immutable: updates and deletes are invalid.
//! Everything that decides validity is in DNA properties, so changing the
//! trusted sources or fault bound creates a new network (new DNA hash).

use hdi::prelude::*;
use vtime_core::evidence::{verify_evidence_set, TimeEvidence, TimePolicy};
use vtime_core::interval::robust_lower_bound;
use vtime_core::keys::roughtime_key_from_b64;
use vtime_core::seal::seal_nonce;
use vtime_core::statement::SignedOracleStatement;
use vtime_core::Ed25519Verifier;

pub use vtime_core;

/// DNA properties. Example (dna.yaml):
///
/// ```yaml
/// properties:
///   roughtime_servers: ["<server long-term key, standard base64>"]
///   oracles: ["<oracle AgentPubKeyB64>"]
///   max_faulty: 1
///   min_sources: 3
///   max_radius_ms: 10000
///   max_skew_ms: 5000
///   oracle_radius_ms: 1000
/// ```
#[dna_properties]
pub struct VtimeProperties {
    /// Trusted Roughtime long-term keys, standard base64 as servers publish them.
    pub roughtime_servers: Vec<String>,
    /// Agents trusted to sign time statements.
    pub oracles: Vec<AgentPubKey>,
    /// How many sources in one evidence set may be lying (f).
    pub max_faulty: u32,
    /// Distinct sources required per evidence set (at least f + 1).
    pub min_sources: u32,
    /// Largest uncertainty radius accepted from one source, milliseconds.
    pub max_radius_ms: u64,
    /// Clock skew tolerated between an action's own timestamp and its proven
    /// bounds, milliseconds.
    pub max_skew_ms: u64,
    /// Radius an oracle states around its own clock reading, milliseconds.
    /// Operators should keep their clocks disciplined well inside this.
    pub oracle_radius_ms: u64,
}

impl VtimeProperties {
    /// Load and convert the properties into a checked [`TimePolicy`] that
    /// accepts oracle statements signed for this DNA only.
    pub fn load() -> ExternResult<(Self, TimePolicy)> {
        let props = Self::try_from_dna_properties()?;
        let policy = props.policy(Some(this_dna_b64()?))?;
        Ok((props, policy))
    }

    /// The evidence policy these properties describe. `oracle_dna` is the
    /// network oracle statements must name (`None` accepts any).
    pub fn policy(&self, oracle_dna: Option<String>) -> ExternResult<TimePolicy> {
        let roughtime_servers = self
            .roughtime_servers
            .iter()
            .map(|k| roughtime_key_from_b64(k))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| wasm_error!(WasmErrorInner::Guest(e.to_string())))?;
        let oracles = self.oracles.iter().map(raw_key).collect::<ExternResult<Vec<_>>>()?;
        let policy = TimePolicy {
            roughtime_servers,
            oracles,
            max_faulty: self.max_faulty,
            min_sources: self.min_sources,
            max_radius_us: ms_to_us(self.max_radius_ms)?,
            oracle_dna,
        };
        // Production DNA properties promise a valid quorum despite up to
        // `max_faulty` sources being unreachable as well as protecting bounds
        // against that many Byzantine readings. This is deliberately stricter
        // than the mathematical soundness check alone.
        policy
            .check_outage_tolerance(self.max_faulty)
            .map_err(|e| wasm_error!(WasmErrorInner::Guest(e.to_string())))?;
        Ok(policy)
    }

    /// Allowed skew in microseconds.
    pub fn max_skew_us(&self) -> ExternResult<i64> {
        ms_to_us(self.max_skew_ms)
    }
}

/// This DNA's hash in the text form oracle statements carry in `dna`.
pub fn this_dna_b64() -> ExternResult<String> {
    Ok(DnaHashB64::from(dna_info()?.hash).to_string())
}

fn ms_to_us(ms: u64) -> ExternResult<i64> {
    i64::try_from(ms)
        .ok()
        .and_then(|v| v.checked_mul(1000))
        .ok_or_else(|| wasm_error!(WasmErrorInner::Guest("milliseconds value too large".into())))
}

/// The 32 raw Ed25519 bytes of an agent key.
pub fn raw_key(agent: &AgentPubKey) -> ExternResult<[u8; 32]> {
    agent
        .get_raw_32()
        .try_into()
        .map_err(|_| wasm_error!(WasmErrorInner::Guest("agent key is not 32 bytes".into())))
}

/// Ed25519 verification through the Holochain host. Any Ed25519 key can be
/// wrapped as an `AgentPubKey`, so Roughtime server and delegation keys go
/// through the same native verifier as agent signatures. Every validator uses
/// the host's verifier, so verdicts agree across peers and run at native speed
/// even under the interpreted wasmi engine on iOS.
pub struct HostVerifier;

impl Ed25519Verifier for HostVerifier {
    fn verify(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> vtime_core::Result<bool> {
        let key = AgentPubKey::from_raw_32(public_key.to_vec());
        verify_signature_raw(key, Signature::from(*signature), message.to_vec())
            .map_err(|e| vtime_core::Error::Malformed(format!("host verifier failed: {e:?}")))
    }
}

/// An evidence set embedded in an entry: proves the entry is not before the
/// set's robust lower bound.
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
pub struct TimeAnchor {
    /// Readings from distinct trusted sources, any nonces.
    pub evidence: Vec<TimeEvidence>,
}

/// Readings bound to one action: proves the action is not after the set's
/// robust upper bound.
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
pub struct TimeSeal {
    /// The sealed action.
    pub target: ActionHash,
    /// Readings whose nonce is `seal_nonce(dna_hash, target)`.
    pub evidence: Vec<TimeEvidence>,
}

/// An oracle's private record of a statement it signed.
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
pub struct OracleLogEntry {
    /// The statement and its signature.
    pub signed: SignedOracleStatement,
}

#[hdk_entry_types]
#[unit_enum(UnitEntryTypes)]
pub enum EntryTypes {
    TimeAnchor(TimeAnchor),
    TimeSeal(TimeSeal),
    #[entry_type(visibility = "private")]
    OracleLog(OracleLogEntry),
}

#[hdk_link_types]
pub enum LinkTypes {
    /// Sealed action -> TimeSeal action. Anyone may create one.
    ActionToSeals,
    /// Agent -> that agent's own TimeAnchor actions.
    AgentToAnchors,
}

fn invalid(msg: impl Into<String>) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Invalid(msg.into()))
}

/// Validate an anchor authored at `authored_at`.
pub fn validate_time_anchor(anchor: &TimeAnchor, authored_at: Timestamp) -> ExternResult<ValidateCallbackResult> {
    let (props, policy) = VtimeProperties::load()?;
    let verified = match verify_evidence_set(&anchor.evidence, &policy, &HostVerifier, None) {
        Ok(v) => v,
        Err(e) => return invalid(format!("anchor evidence rejected: {e}")),
    };
    let lower = match robust_lower_bound(&verified, policy.max_faulty as usize) {
        Ok(l) => l,
        Err(e) => return invalid(format!("anchor evidence rejected: {e}")),
    };
    let claimed = authored_at.as_micros();
    if claimed < lower.saturating_sub(props.max_skew_us()?) {
        return invalid(format!(
            "anchor is backdated: authored at {claimed} us but its evidence proves not before {lower} us"
        ));
    }
    Ok(ValidateCallbackResult::Valid)
}

/// Validate a seal. The target must exist; every reading must answer the
/// target's seal nonce.
pub fn validate_time_seal(seal: &TimeSeal) -> ExternResult<ValidateCallbackResult> {
    let (_, policy) = VtimeProperties::load()?;
    // Unavailable target -> host defers validation until it can be fetched.
    must_get_action(seal.target.clone())?;
    let dna_hash = dna_info()?.hash;
    let nonce = seal_nonce(dna_hash.get_raw_39(), seal.target.get_raw_39());
    match verify_evidence_set(&seal.evidence, &policy, &HostVerifier, Some(&nonce)) {
        Ok(_) => Ok(ValidateCallbackResult::Valid),
        Err(e) => invalid(format!("seal evidence rejected: {e}")),
    }
}

fn record_entry<T: TryFrom<SerializedBytes, Error = SerializedBytesError>>(
    record: &Record,
) -> ExternResult<Option<T>> {
    record
        .entry()
        .to_app_option::<T>()
        .map_err(|e| wasm_error!(e))
}

fn validate_create_link(
    link_type: LinkTypes,
    action: &TypedAction<CreateLinkData>,
) -> ExternResult<ValidateCallbackResult> {
    if !action.tag.0.is_empty() {
        return invalid("time links carry no tag");
    }
    let Some(target) = action.target_address.clone().into_action_hash() else {
        return invalid("link target must be an action hash");
    };
    let record = must_get_valid_record(target)?;
    match link_type {
        LinkTypes::ActionToSeals => {
            let Some(base) = action.base_address.clone().into_action_hash() else {
                return invalid("ActionToSeals base must be the sealed action's hash");
            };
            match record_entry::<TimeSeal>(&record)? {
                Some(seal) if seal.target == base => Ok(ValidateCallbackResult::Valid),
                Some(_) => invalid("seal does not target the link base"),
                None => invalid("ActionToSeals must point at a TimeSeal"),
            }
        }
        LinkTypes::AgentToAnchors => {
            let Some(base) = action.base_address.clone().into_agent_pub_key() else {
                return invalid("AgentToAnchors base must be an agent key");
            };
            if &base != action.author() || record.action().author() != action.author() {
                return invalid("agents may only index their own anchors");
            }
            match record_entry::<TimeAnchor>(&record)? {
                Some(_) => Ok(ValidateCallbackResult::Valid),
                None => invalid("AgentToAnchors must point at a TimeAnchor"),
            }
        }
    }
}

fn validate_delete(action: &TypedAction<DeleteData>) -> ExternResult<ValidateCallbackResult> {
    let original = must_get_action(action.deletes_address.clone())?;
    match original.action().entry_data() {
        Some((_, EntryType::App(_))) => invalid("time evidence is immutable: deletes are not allowed"),
        _ => Ok(ValidateCallbackResult::Valid),
    }
}

fn validate_entry(app_entry: EntryTypes, authored_at: Timestamp) -> ExternResult<ValidateCallbackResult> {
    match app_entry {
        EntryTypes::TimeAnchor(anchor) => validate_time_anchor(&anchor, authored_at),
        EntryTypes::TimeSeal(seal) => validate_time_seal(&seal),
        // Private: only the author ever sees it.
        EntryTypes::OracleLog(_) => Ok(ValidateCallbackResult::Valid),
    }
}

#[hdk_extern]
pub fn validate(op: Op) -> ExternResult<ValidateCallbackResult> {
    match op.flattened::<EntryTypes, LinkTypes>()? {
        FlatOp::CreateEntry(OpEntry::CreateEntry { app_entry, action }) => {
            validate_entry(app_entry, action.timestamp())
        }
        FlatOp::CreateRecord(OpRecord::CreateEntry { app_entry, action }) => {
            validate_entry(app_entry, action.timestamp())
        }
        // App entries are immutable. System entries (cap grants and claims)
        // stay updatable and deletable so oracles can manage access.
        FlatOp::CreateEntry(OpEntry::UpdateEntry { .. })
        | FlatOp::CreateRecord(OpRecord::UpdateEntry { .. })
        | FlatOp::CreateRecord(OpRecord::UpdatePrivateEntry { .. })
        | FlatOp::Update(OpUpdate::Entry { .. })
        | FlatOp::Update(OpUpdate::PrivateEntry { .. }) => {
            invalid("time evidence is immutable: updates are not allowed")
        }
        FlatOp::CreateRecord(OpRecord::DeleteEntry { action }) => validate_delete(&action),
        FlatOp::Delete(OpDelete { action }) => validate_delete(&action),
        FlatOp::Link(OpLink::CreateLink { link_type, action })
        | FlatOp::CreateRecord(OpRecord::CreateLink { link_type, action }) => {
            validate_create_link(link_type, &action)
        }
        FlatOp::Link(OpLink::DeleteLink { .. }) | FlatOp::CreateRecord(OpRecord::DeleteLink { .. }) => {
            invalid("time links cannot be deleted")
        }
        _ => Ok(ValidateCallbackResult::Valid),
    }
}
