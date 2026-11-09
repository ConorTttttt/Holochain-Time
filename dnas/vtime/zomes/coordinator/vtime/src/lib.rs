//! # vtime coordinator
//!
//! Three jobs:
//!
//! 1. **Oracle service.** An agent listed in the DNA's `oracles` property
//!    answers `attest_time(nonce)` with a signed statement about its clock.
//!    Statements are chained (`seq`, `prev`, `floor`), bound to this DNA and
//!    logged privately. The oracle refuses to sign anything below its chain's
//!    floor, so an honest oracle never produces a malfeasance proof, and it
//!    spaces its answers so no caller can grow its chain without bound.
//! 2. **Anchoring and sealing.** `create_anchor` gathers readings into a
//!    `TimeAnchor` ("everything I write after this is not before T");
//!    `seal_action` gathers readings bound to an action into a `TimeSeal`
//!    ("this action existed by T"). Each oracle answer is checked on its own,
//!    so up to f faulty oracles cannot block either. Roughtime readings come
//!    from the client, because zomes cannot open UDP sockets; the zome builds
//!    the exact request bytes for it.
//! 3. **Queries and export.** `verify_time_with_witnesses` verifies explicitly
//!    supplied evidence without global DHT link scans. The legacy
//!    `get_verified_time` endpoint is disabled pending a complete bounded
//!    discovery design; `unyt_time_proof` packages Unyt statements.

use std::collections::BTreeSet;

use hdk::prelude::*;
use vtime_core::evidence::{
    accept_oracle_response, filter_evidence, require_complete_index, roughtime_quorum_satisfied,
    verify_evidence_set,
    RoughtimeEvidence, TimeEvidence, TimePolicy, MAX_EVIDENCE_ITEMS,
};
use vtime_core::hash::{hex32, to_hex};
use vtime_core::interval::{robust_lower_bound, robust_upper_bound};
use vtime_core::malfeasance::{check_pair, check_statement, OracleMalfeasance};
use vtime_core::oracle::{log_lookup_windows, plan_statement, DEFAULT_MIN_SPACING_US};
use vtime_core::roughtime::{build_request, VERSION_DRAFT, VERSION_RFC};
use vtime_core::seal::seal_nonce;
use vtime_core::statement::{OracleTimeStatement, SignedOracleStatement};
use vtime_core::verdict::{classify, TimestampVerdict};
use vtime_integrity::*;

/// Minimum spacing between two statements by this oracle. Coordinator-only,
/// so an operator can tune it without changing the DNA hash.
const MIN_STATEMENT_SPACING_US: i64 = DEFAULT_MIN_SPACING_US;
/// How old an oracle's latest statement may be when it stands in for a fresh
/// one in an anchor or Unyt proof (used when the oracle is rate limited).
const FALLBACK_MAX_AGE_US: i64 = 60_000_000;
/// Proof-hash budgets for explicit witness verification; these are not
/// completeness or latency guarantees. The unbounded DHT index query is disabled.
const MAX_SEALS_CHECKED: usize = 32;
const MAX_ANCESTRY_CHECKS: usize = 8;

fn guest(msg: impl Into<String>) -> WasmError {
    wasm_error!(WasmErrorInner::Guest(msg.into()))
}

fn core_err(e: vtime_core::Error) -> WasmError {
    guest(e.to_string())
}

#[hdk_extern]
pub fn init() -> ExternResult<InitCallbackResult> {
    // Anyone on the network may ask an oracle for the time. Agents that are
    // not oracles refuse inside attest_time, so the grant is harmless there.
    // Oracles bound the cost with MIN_STATEMENT_SPACING_US; an operator under
    // sustained abuse can revoke this grant and issue assigned grants instead.
    let mut functions = BTreeSet::new();
    let zome = zome_info()?.name;
    functions.insert((zome.clone(), "attest_time".into()));
    // Read-only: returns a statement already signed, writes nothing.
    functions.insert((zome, "latest_attestation".into()));
    create_cap_grant(CapGrant {
        tag: "vtime_attest_time".into(),
        constraint: GrantConstraint::Unrestricted,
        capability: Capability::ZomeCall(ZomeCallGrant {
            functions: GrantedFunctions::Listed(functions.into_iter().collect()),
        }),
    })?;
    Ok(InitCallbackResult::Pass)
}

// ---------------------------------------------------------------------------
// Oracle service
// ---------------------------------------------------------------------------

/// This oracle's most recent logged statement. Searches a few actions back
/// from the chain head first, widening only if needed, instead of loading
/// every log entry on every call.
fn latest_oracle_log() -> ExternResult<Option<SignedOracleStatement>> {
    let (_, head_seq, _) = agent_info()?.chain_head;
    for (start, _) in log_lookup_windows(head_seq) {
        // Open-ended so entries written earlier in this same call are seen.
        let filter = ChainQueryFilter::new()
            .sequence_range(ChainQueryFilterRange::ActionSeqRange(start, u32::MAX))
            .entry_type(UnitEntryTypes::OracleLog.try_into()?)
            .include_entries(true)
            .descending();
        let newest = query(filter)?.into_iter().max_by_key(|r| r.action().action_seq());
        if let Some(record) = newest {
            // Fail closed: a log action whose entry cannot be read must never
            // be treated as "no log", or the next statement would restart
            // the chain at seq 0 and look like a fork of the oracle's chain.
            return match record.entry().to_app_option::<OracleLogEntry>().map_err(|e| wasm_error!(e))? {
                Some(log) => Ok(Some(log.signed)),
                None => Err(guest(
                    "the latest oracle log entry is unreadable; refusing to sign until the chain is repaired",
                )),
            };
        }
        if start == 0 {
            break;
        }
    }
    Ok(None)
}

/// Sign the current time for `nonce_hex` (64 lowercase hex characters).
///
/// Only agents listed in the `oracles` DNA property answer. The statement is
/// written to this agent's private log in the same atomic commit, so two
/// concurrent requests cannot both be answered at one sequence number: the
/// second commit fails on the moved chain head and its statement is never
/// returned. Refusals (rate limit, clock behind) are errors the caller treats
/// as "no answer"; the rate limit clears after MIN_STATEMENT_SPACING_US.
#[hdk_extern]
pub fn attest_time(nonce_hex: String) -> ExternResult<SignedOracleStatement> {
    let (props, policy) = VtimeProperties::load()?;
    let me = agent_info()?.agent_initial_pubkey;
    if !policy.oracles.contains(&raw_key(&me)?) {
        return Err(guest("this agent is not a configured time oracle"));
    }
    let nonce = hex32(&nonce_hex).map_err(core_err)?;
    let radius_us = i64::try_from(props.oracle_radius_ms)
        .ok()
        .and_then(|ms| ms.checked_mul(1000))
        .ok_or_else(|| guest("oracle_radius_ms too large"))?;
    let last = latest_oracle_log()?;
    let plan = plan_statement(last.as_ref(), sys_time()?.as_micros(), radius_us, MIN_STATEMENT_SPACING_US)
        .map_err(core_err)?;

    let statement = OracleTimeStatement::new(
        AgentPubKeyB64::from(me.clone()).to_string(),
        this_dna_b64()?,
        &nonce,
        plan.interval,
        plan.link,
    );
    let signature = sign_raw(me, statement.signing_bytes().map_err(core_err)?)?;
    let signed = SignedOracleStatement { statement, signature: signature.0.to_vec() };
    create_entry(&EntryTypes::OracleLog(OracleLogEntry { signed: signed.clone() }))?;
    Ok(signed)
}

/// This oracle's most recent statement, as already signed and logged. Writes
/// nothing, so it is safe to serve at any rate. A statement proves "the time
/// is at least `earliest`" to anyone, whoever's nonce it answered, so anchors
/// and Unyt proofs can use it when `attest_time` is rate limited; seals cannot,
/// because they need a statement bound to their own nonce.
#[hdk_extern]
pub fn latest_attestation() -> ExternResult<Option<SignedOracleStatement>> {
    let (_, policy) = VtimeProperties::load()?;
    if !policy.oracles.contains(&raw_key(&agent_info()?.agent_initial_pubkey)?) {
        return Err(guest("this agent is not a configured time oracle"));
    }
    latest_oracle_log()
}

/// Ask one oracle for a statement. Returns `None` if it is offline, refuses or
/// is not an oracle, so callers can collect from whoever answers. The answer
/// is not checked here; [`gather_oracle_statements`] checks it.
#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationRequest {
    pub oracle: AgentPubKey,
    pub nonce_hex: String,
}

#[hdk_extern]
pub fn request_attestation(input: AttestationRequest) -> ExternResult<Option<SignedOracleStatement>> {
    if input.oracle == agent_info()?.agent_initial_pubkey {
        return Ok(attest_time(input.nonce_hex).ok());
    }
    let response = call_remote(
        input.oracle,
        zome_info()?.name,
        "attest_time".into(),
        None,
        input.nonce_hex,
    )?;
    match response {
        ZomeCallResponse::Ok(io) => Ok(io.decode::<SignedOracleStatement>().ok()),
        _ => Ok(None),
    }
}

/// One oracle's latest logged statement, or `None` if it is unreachable,
/// has none or is not an oracle.
fn fetch_latest_attestation(oracle: AgentPubKey) -> Option<SignedOracleStatement> {
    if oracle == agent_info().ok()?.agent_initial_pubkey {
        return latest_attestation(()).ok().flatten();
    }
    match call_remote(oracle, zome_info().ok()?.name, "latest_attestation".into(), None, ()).ok()? {
        ZomeCallResponse::Ok(io) => io.decode::<Option<SignedOracleStatement>>().ok().flatten(),
        _ => None,
    }
}

/// What an evidence set needs from each oracle.
#[derive(Clone, Copy)]
enum Need<'a> {
    /// A seal: every answer must answer this nonce.
    Bound(&'a [u8; 32]),
    /// An anchor or a Unyt proof: any recent genuine statement will do. A fresh
    /// one for this nonce is asked for first; if the oracle cannot give one
    /// (for example it is rate limited), its latest statement is used instead
    /// when that is at most FALLBACK_MAX_AGE_US old. Spam that keeps an oracle
    /// rate limited then cannot block anchors or Unyt proofs.
    Recent(&'a [u8; 32]),
}

/// Collect one statement per configured oracle that answers, keeping only
/// answers that verify under `policy`, meet `need` and come from the oracle
/// asked. A faulty oracle loses only its own answer.
fn gather_oracle_statements(need: Need, policy: &TimePolicy) -> ExternResult<Vec<SignedOracleStatement>> {
    let props = VtimeProperties::try_from_dna_properties()?;
    let nonce = match need {
        Need::Bound(n) | Need::Recent(n) => n,
    };
    let nonce_hex = to_hex(nonce);
    let now = sys_time()?.as_micros();
    let mut seen: Vec<[u8; 32]> = Vec::new();
    let mut out = Vec::new();
    for oracle in props.oracles {
        if out.len() == MAX_EVIDENCE_ITEMS {
            break;
        }
        let asked = raw_key(&oracle)?;
        if seen.contains(&asked) {
            continue;
        }
        let fresh = request_attestation(AttestationRequest { oracle: oracle.clone(), nonce_hex: nonce_hex.clone() })
            .ok()
            .flatten();
        let mut accepted = fresh.filter(|s| accept_oracle_response(&asked, s, policy, &HostVerifier, Some(nonce)).is_ok());
        if accepted.is_none() && matches!(need, Need::Recent(_)) {
            accepted = fetch_latest_attestation(oracle).filter(|s| {
                accept_oracle_response(&asked, s, policy, &HostVerifier, None)
                    .is_ok_and(|v| v.interval.latest_us >= now.saturating_sub(FALLBACK_MAX_AGE_US))
            });
        }
        if let Some(s) = accepted {
            seen.push(asked);
            out.push(s);
        }
    }
    Ok(out)
}

/// Oracle answers (already checked) plus the client's Roughtime readings,
/// each checked on its own so one faulty server's reply is dropped rather
/// than failing the set, within MAX_EVIDENCE_ITEMS in total.
fn assemble(
    oracle: Vec<SignedOracleStatement>,
    roughtime: Vec<RoughtimeEvidence>,
    policy: &TimePolicy,
    expected_nonce: Option<&[u8; 32]>,
) -> Vec<TimeEvidence> {
    let mut items: Vec<TimeEvidence> = oracle.into_iter().map(TimeEvidence::Oracle).collect();
    let room = MAX_EVIDENCE_ITEMS.saturating_sub(items.len());
    let readings = roughtime.into_iter().take(2 * MAX_EVIDENCE_ITEMS).map(TimeEvidence::Roughtime);
    items.extend(filter_evidence(readings, policy, &HostVerifier, expected_nonce).into_iter().take(room));
    items
}

fn random_nonce() -> ExternResult<[u8; 32]> {
    random_bytes(32)?
        .to_vec()
        .try_into()
        .map_err(|_| guest("host returned the wrong number of random bytes"))
}

// ---------------------------------------------------------------------------
// Roughtime helpers for clients
// ---------------------------------------------------------------------------

/// Input for [`build_roughtime_request`].
#[derive(Serialize, Deserialize, Debug)]
pub struct RoughtimeRequestInput {
    /// 64 lowercase hex characters: from `seal_nonce_for` for a seal, or any
    /// fresh random value for an anchor.
    pub nonce_hex: String,
    /// The server's long-term key (standard base64), to include SRV.
    pub server_public_key_b64: Option<String>,
}

/// The exact 1024-byte request packet a client should send to a Roughtime
/// server over UDP. The client returns the request and the response packet in
/// a `RoughtimeEvidence`.
#[hdk_extern]
pub fn build_roughtime_request(input: RoughtimeRequestInput) -> ExternResult<Vec<u8>> {
    let nonce = hex32(&input.nonce_hex).map_err(core_err)?;
    let server = match input.server_public_key_b64 {
        Some(k) => Some(vtime_core::keys::roughtime_key_from_b64(&k).map_err(core_err)?),
        None => None,
    };
    Ok(build_request(&nonce, &[VERSION_RFC, VERSION_DRAFT], server.as_ref()))
}

/// The nonce every reading in a seal of `target` must answer, as hex.
#[hdk_extern]
pub fn seal_nonce_for(target: ActionHash) -> ExternResult<String> {
    let dna = dna_info()?.hash;
    Ok(to_hex(&seal_nonce(dna.get_raw_39(), target.get_raw_39())))
}

// ---------------------------------------------------------------------------
// Anchors and seals
// ---------------------------------------------------------------------------

/// Input for [`create_anchor`].
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct CreateAnchorInput {
    /// Roughtime readings the client already took (any nonces).
    pub roughtime: Vec<RoughtimeEvidence>,
}

/// Anchor this agent's chain in time: everything it writes after this action
/// is provably not before the returned anchor's lower bound.
#[hdk_extern]
pub fn create_anchor(input: CreateAnchorInput) -> ExternResult<ActionHash> {
    let (_, policy) = VtimeProperties::load()?;
    if input.roughtime.len() > MAX_EVIDENCE_ITEMS {
        return Err(guest("too many Roughtime readings for an anchor"));
    }
    // Valid client evidence already satisfying quorum needs no oracle RPC.
    let oracle = if roughtime_quorum_satisfied(&input.roughtime, &policy, &HostVerifier, None) {
        Vec::new()
    } else {
        let nonce = random_nonce()?;
        gather_oracle_statements(Need::Recent(&nonce), &policy)?
    };
    let evidence = assemble(oracle, input.roughtime, &policy, None);
    verify_evidence_set(&evidence, &policy, &HostVerifier, None).map_err(core_err)?;
    let hash = create_entry(&EntryTypes::TimeAnchor(TimeAnchor { evidence }))?;
    let me = agent_info()?.agent_initial_pubkey;
    create_link(me, hash.clone(), LinkTypes::AgentToAnchors, LinkTag::new(Vec::<u8>::new()))?;
    Ok(hash)
}

/// Input for [`seal_action`].
#[derive(Serialize, Deserialize, Debug)]
pub struct SealActionInput {
    /// The action to seal; it must already exist on the DHT.
    pub target: ActionHash,
    /// Roughtime readings whose request nonce is `seal_nonce_for(target)`.
    pub roughtime: Vec<RoughtimeEvidence>,
}

/// Prove `target` existed by now. Anyone may seal any action.
#[hdk_extern]
pub fn seal_action(input: SealActionInput) -> ExternResult<ActionHash> {
    let (_, policy) = VtimeProperties::load()?;
    if input.roughtime.len() > MAX_EVIDENCE_ITEMS {
        return Err(guest("too many Roughtime readings for a seal"));
    }
    let dna = dna_info()?.hash;
    let nonce = seal_nonce(dna.get_raw_39(), input.target.get_raw_39());
    // An independent nonce-bound Roughtime quorum saves scarce signing capacity.
    let oracle = if roughtime_quorum_satisfied(&input.roughtime, &policy, &HostVerifier, Some(&nonce)) {
        Vec::new()
    } else {
        gather_oracle_statements(Need::Bound(&nonce), &policy)?
    };
    let evidence = assemble(oracle, input.roughtime, &policy, Some(&nonce));
    verify_evidence_set(&evidence, &policy, &HostVerifier, Some(&nonce)).map_err(core_err)?;
    let hash = create_entry(&EntryTypes::TimeSeal(TimeSeal { target: input.target.clone(), evidence }))?;
    create_link(input.target, hash.clone(), LinkTypes::ActionToSeals, LinkTag::new(Vec::<u8>::new()))?;
    Ok(hash)
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/// What the network can prove about when an action happened.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifiedTime {
    pub target: ActionHash,
    pub author: AgentPubKey,
    /// The action's self-declared timestamp, microseconds.
    pub claimed_us: i64,
    /// Proven: the action is not before this. Comes from an anchor by the
    /// author that is an ancestor of the action in its source chain (checked
    /// by hash links, so a fork cannot lend an anchor to another branch).
    pub not_before_us: Option<i64>,
    pub not_before_anchor: Option<ActionHash>,
    /// Proven: the action's content was fixed no later than this (tightest
    /// seal checked). Not proof of publication: an author can have an action
    /// sealed before publishing it, and can prepare alternatives.
    pub not_after_us: Option<i64>,
    pub not_after_seals: Vec<ActionHash>,
    pub verdict: TimestampVerdict,
    /// Whether the author's agent-activity authorities report a fork, an
    /// invalid action or warrants; `None` if that could not be fetched.
    pub author_chain_flagged: Option<bool>,
}

fn fetch(hash: ActionHash) -> ExternResult<Option<Record>> {
    get(hash, GetOptions::network())
}

/// True when `ancestor` lies on the hash-linked path from `descendant` back
/// towards genesis in `author`'s chain.
fn author_chain_flagged(author: &AgentPubKey) -> Option<bool> {
    let status =
        get_agent_activity(author.clone(), ChainQueryFilter::new(), ActivityRequest::Status, GetOptions::network())
            .ok()?;
    Some(!status.warrants.is_empty() || !matches!(status.status, ChainStatus::Valid(_) | ChainStatus::Empty))
}

/// This legacy DHT-index query is disabled in the pre-release.
///
/// The old method scanned all matching DHT links before enforcing a local
/// limit. It could exhaust network resources and could not certify that all
/// contradictory proofs had been found. Retain the wire signature so callers
/// receive a clear migration error without issuing any network queries.
///
/// Use `verify_time_with_witnesses` for bounded, explicitly supplied proofs.
/// Its clean result is NOT evidence of global timestamp consistency.
const LEGACY_QUERY_DISABLED_MESSAGE: &str =
    "get_verified_time is disabled: global evidence discovery cannot be bounded or proven complete; use verify_time_with_witnesses with explicit proof hashes; its result cannot prove global consistency";

fn legacy_global_query_disabled() -> ExternResult<VerifiedTime> {
    Err(guest(LEGACY_QUERY_DISABLED_MESSAGE))
}

#[hdk_extern]
pub fn get_verified_time(_target: ActionHash) -> ExternResult<VerifiedTime> {
    legacy_global_query_disabled()
}

// ---------------------------------------------------------------------------
// Explicit-witness verification (bounded alternative to DHT link enumeration)
// ---------------------------------------------------------------------------

/// Proof hashes supplied by the caller. This endpoint never enumerates the
/// public link index; it performs at most 8 anchor and 32 seal lookups. Proofs
/// from other agents may be supplied, including third-party seals.
///
/// The caller controls what is supplied, so this can establish a real
/// contradiction but CANNOT establish that no contradictory proof exists.
#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyTimeWithWitnessesInput {
    pub target: ActionHash,
    pub anchors: Vec<ActionHash>,
    pub seals: Vec<ActionHash>,
}

/// Deliberately does not contain a Consistent variant. Unlike the legacy
/// index scan, these responses make no completeness claim about the DHT.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum WitnessConclusion {
    Backdated { by_us: i64 },
    FutureDated { by_us: i64 },
    NoContradictionInSuppliedProofs,
}

fn witness_conclusion(
    claimed_us: i64,
    lower_us: Option<i64>,
    upper_us: Option<i64>,
    tolerance_us: i64,
) -> WitnessConclusion {
    match classify(claimed_us, lower_us, upper_us, tolerance_us) {
        TimestampVerdict::Backdated { by_us } => WitnessConclusion::Backdated { by_us },
        TimestampVerdict::FutureDated { by_us } => WitnessConclusion::FutureDated { by_us },
        TimestampVerdict::Consistent | TimestampVerdict::Unverified => {
            WitnessConclusion::NoContradictionInSuppliedProofs
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WitnessVerifiedTime {
    pub target: ActionHash,
    pub author: AgentPubKey,
    pub claimed_us: i64,
    pub not_before_us: Option<i64>,
    pub not_before_anchor: Option<ActionHash>,
    pub not_after_us: Option<i64>,
    pub not_after_seals: Vec<ActionHash>,
    pub conclusion: WitnessConclusion,
    /// An unavailable chain health query returns None. Financial consumers
    /// must never treat None as proof that the chain is valid.
    pub author_chain_flagged: Option<bool>,
    /// Always false: the caller may omit any number of DHT proofs.
    pub evidence_complete: bool,
}

/// Classify a target against an explicit, bounded set of caller-supplied
/// evidence. Every submitted hash must resolve and must prove its claimed
/// relationship to target; invalid or unavailable proofs fail the call.
///
/// No get_links is used here. This bounds the count of DHT record requests
/// but not their end-to-end latency or the size of an individual record.
#[hdk_extern]
pub fn verify_time_with_witnesses(input: VerifyTimeWithWitnessesInput) -> ExternResult<WitnessVerifiedTime> {
    require_complete_index(input.anchors.len(), MAX_ANCESTRY_CHECKS).map_err(core_err)?;
    require_complete_index(input.seals.len(), MAX_SEALS_CHECKED).map_err(core_err)?;
    if input.anchors.is_empty() && input.seals.is_empty() {
        return Err(guest("at least one explicit anchor or seal witness is required"));
    }

    // Reject duplicates before any network lookups; even duplicates
    // count towards the request budget to avoid amplification.
    let mut seen = BTreeSet::new();
    for hash in input.anchors.iter().chain(input.seals.iter()) {
        if !seen.insert(hash.clone()) {
            return Err(guest("duplicate witness action hash"));
        }
    }

    let (props, policy) = VtimeProperties::load()?;
    let target = input.target;
    let record = fetch(target.clone())?.ok_or_else(|| guest("target action not found"))?;
    let action = record.action();
    let author = action.author().clone();
    let claimed_us = action.timestamp().as_micros();
    let dna = dna_info()?.hash;
    let nonce = seal_nonce(dna.get_raw_39(), target.get_raw_39());
    let f = policy.max_faulty as usize;
    let mut not_after_us: Option<i64> = None;
    let mut not_after_seals = Vec::new();

    for seal_hash in input.seals {
        let seal_record = fetch(seal_hash.clone())?
            .ok_or_else(|| guest("supplied seal action is unavailable"))?;
        let seal = seal_record.entry().to_app_option::<TimeSeal>().map_err(|e| wasm_error!(e))?
            .ok_or_else(|| guest("supplied seal action does not contain a TimeSeal"))?;
        if seal.target != target {
            return Err(guest("supplied seal is bound to a different target"));
        }
        let verified = verify_evidence_set(&seal.evidence, &policy, &HostVerifier, Some(&nonce))
            .map_err(core_err)?;
        let upper = robust_upper_bound(&verified, f).map_err(core_err)?;
        not_after_us = Some(not_after_us.map_or(upper, |old| old.min(upper)));
        not_after_seals.push(seal_hash);
    }

    let mut not_before_us: Option<i64> = None;
    let mut not_before_anchor = None;
    for anchor_hash in input.anchors {
        let anchor_record = fetch(anchor_hash.clone())?
            .ok_or_else(|| guest("supplied anchor action is unavailable"))?;
        let anchor_action = anchor_record.action();
        if anchor_action.author() != &author || anchor_action.action_seq() > action.action_seq() {
            return Err(guest("supplied anchor is not an eligible action by the target author"));
        }
        let anchor = anchor_record.entry().to_app_option::<TimeAnchor>().map_err(|e| wasm_error!(e))?
            .ok_or_else(|| guest("supplied anchor action does not contain a TimeAnchor"))?;
        // Do not mistake unavailable source-chain proof for an unrelated anchor.
        if anchor_hash != target {
            let activity = must_get_agent_activity(
                author.clone(), ChainFilter::until_hash(target.clone(), anchor_hash.clone()),
            )?;
            if !activity.iter().any(|item| item.action.as_hash() == &anchor_hash) {
                return Err(guest("supplied anchor is not on the target's source-chain ancestry"));
            }
        }
        let verified = verify_evidence_set(&anchor.evidence, &policy, &HostVerifier, None)
            .map_err(core_err)?;
        let lower = robust_lower_bound(&verified, f).map_err(core_err)?;
        if not_before_us.is_none_or(|current| lower > current) {
            not_before_us = Some(lower);
            not_before_anchor = Some(anchor_hash);
        }
    }

    Ok(WitnessVerifiedTime {
        target,
        author_chain_flagged: author_chain_flagged(&author),
        author,
        claimed_us,
        not_before_us,
        not_before_anchor,
        not_after_us,
        not_after_seals,
        conclusion: witness_conclusion(claimed_us, not_before_us, not_after_us, props.max_skew_us()?),
        evidence_complete: false,
    })
}

#[cfg(test)]
mod witness_unit_tests {
    use super::*;

    #[test]
    fn legacy_global_query_is_rejected_before_network_access() {
        let err = legacy_global_query_disabled().unwrap_err().to_string();
        assert!(err.contains("verify_time_with_witnesses"));
        assert!(err.contains("cannot prove global consistency"));
    }

    #[test]
    fn coordinator_has_no_unbounded_link_scan_calls() {
        // Split pattern so the test does not match itself. Any coordinator
        // global index scan needs a formally reviewed resource budget.
        let forbidden_call = ["get_", "links("].concat();
        assert!(!include_str!("lib.rs").contains(&forbidden_call));
    }

    #[test]
    fn witness_assessment_never_claims_global_consistency() {
        assert_eq!(witness_conclusion(100, Some(80), Some(120), 0),
                   WitnessConclusion::NoContradictionInSuppliedProofs);
        assert_eq!(witness_conclusion(100, None, None, 0),
                   WitnessConclusion::NoContradictionInSuppliedProofs);
        assert_eq!(witness_conclusion(100, Some(105), None, 0),
                   WitnessConclusion::Backdated { by_us: 5 });
        assert_eq!(witness_conclusion(100, None, Some(95), 0),
                   WitnessConclusion::FutureDated { by_us: 5 });
    }
}

// ---------------------------------------------------------------------------
// Unyt export and accountability
// ---------------------------------------------------------------------------

/// One oracle statement in the shape a Unyt Smart Agreement reads: the
/// statement as a JSON object and the signature as an array of 64 integers,
/// which is what Rhai's `hdi_verify_signature` expects.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnytStatement {
    pub statement: OracleTimeStatement,
    /// Plain `Vec<u8>` (no serde_bytes) so it serializes as an integer array.
    pub signature: Vec<u8>,
}

/// The payload to park as `ParkedData` for the `verified_time_release` and
/// `time_oracle_bond` templates.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnytTimeProof {
    pub statements: Vec<UnytStatement>,
}

/// Fresh, individually verified statements from every reachable oracle, ready
/// for Unyt. Each one proves "the time is at least `earliest`" whenever it is
/// checked later, so a proof can be parked now and used to release funds
/// afterwards.
#[hdk_extern]
pub fn unyt_time_proof() -> ExternResult<UnytTimeProof> {
    let (_, policy) = VtimeProperties::load()?;
    let nonce = random_nonce()?;
    let statements = gather_oracle_statements(Need::Recent(&nonce), &policy)?
        .into_iter()
        .map(|s| UnytStatement { statement: s.statement, signature: s.signature })
        .collect();
    Ok(UnytTimeProof { statements })
}

/// Input for [`check_oracle_statements`]: one statement (self-contradiction)
/// or two (time reversal, floor dropped, equivocation).
#[derive(Serialize, Deserialize, Debug)]
pub struct StatementPair {
    pub a: SignedOracleStatement,
    pub b: Option<SignedOracleStatement>,
}

/// Do these statements prove an oracle misbehaved? The same checks the
/// `time_oracle_bond` Unyt template runs before paying out a bond.
#[hdk_extern]
pub fn check_oracle_statements(pair: StatementPair) -> ExternResult<Option<OracleMalfeasance>> {
    match &pair.b {
        None => check_statement(&pair.a, &HostVerifier).map_err(core_err),
        Some(b) => check_pair(&pair.a, b, &HostVerifier).map_err(core_err),
    }
}
