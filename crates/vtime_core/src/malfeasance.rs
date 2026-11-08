//! Signed proofs that an oracle misbehaved.
//!
//! Accountability, not trust, is what makes oracles usable on Holochain, and
//! it is what Unyt bonds rely on: a proof here is one or two statements the
//! oracle signed itself, so anyone can verify it and no judgement is needed.
//!
//! - **Self-contradiction** (one statement). `latest < floor`: the statement
//!   says the time is at most `latest`, yet the oracle's own chain already
//!   showed the time reached `floor`.
//! - **Time reversal** (chained pair). `later.prev` is the signature of
//!   `earlier`, so `later` was signed after `earlier` existed, yet
//!   `later.latest < earlier.earliest`.
//! - **Floor dropped** (chained pair). `later.floor < max(earlier.floor,
//!   earlier.earliest)`: the oracle did not carry its high-water mark forward.
//! - **Equivocation** (pair). Two different statements with the same `dna`,
//!   `seq` and `prev`: the oracle forked its chain in one network.
//!
//! Why this is complete for backwards time: take any chain s0 -> ... -> sk
//! with sk.latest < s0.earliest. If every link carries the floor forward, then
//! sk.floor >= s0.earliest > sk.latest and sk contradicts itself; otherwise
//! some adjacent link dropped the floor. So walking the clock back, however
//! gradually, always leaves a proof of at most two statements. (Without the
//! floor, each step could move back by up to twice the radius with every
//! adjacent pair consistent.)
//!
//! Why `dna` matters: one agent key may serve as an oracle in several cells
//! (a DNA upgrade, a clone cell, another network). Each cell keeps its own
//! chain, so each starts at seq 0; without `dna` those honest first
//! statements would look like equivocation.

use alloc::string::String;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::hash::to_hex;
use crate::statement::{verify_signed_statement_for_proof, SignedOracleStatement, VerifiedStatement};
use crate::verifier::Ed25519Verifier;

/// The kind of misbehaviour a statement or pair of statements proves.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum OracleMalfeasance {
    /// One statement whose `latest` is below its own `floor`.
    SelfContradiction,
    /// A statement chained after another reports an interval entirely before it.
    TimeReversal,
    /// A statement chained after another lowers the chain's floor.
    FloorDropped,
    /// Two different statements occupy the same place in one network's chain.
    Equivocation,
}

/// Check one statement on its own. `Err` means it is not a valid signed
/// statement at all, which proves nothing about the oracle.
pub fn check_statement(a: &SignedOracleStatement, verifier: &dyn Ed25519Verifier) -> Result<Option<OracleMalfeasance>> {
    let va = verify_signed_statement_for_proof(a, verifier)?;
    Ok(va.self_contradictory().then_some(OracleMalfeasance::SelfContradiction))
}

fn chained_violation(
    earlier: &SignedOracleStatement,
    ve: &VerifiedStatement,
    later: &SignedOracleStatement,
    vl: &VerifiedStatement,
) -> Option<OracleMalfeasance> {
    if later.statement.prev != to_hex(&earlier.signature) {
        return None;
    }
    if vl.interval.latest_us < ve.interval.earliest_us {
        return Some(OracleMalfeasance::TimeReversal);
    }
    let carried = ve.floor.map_or(ve.interval.earliest_us, |f| f.max(ve.interval.earliest_us));
    // A chained statement always has a floor; a missing one counts as dropped.
    if vl.floor.is_none_or(|f| f < carried) {
        return Some(OracleMalfeasance::FloorDropped);
    }
    None
}

/// Check a pair of statements by one oracle. `Ok(None)` means no proof (either
/// unrelated statements or consistent ones); an `Err` means a statement is not
/// valid at all, which proves nothing about the oracle.
pub fn check_pair(
    a: &SignedOracleStatement,
    b: &SignedOracleStatement,
    verifier: &dyn Ed25519Verifier,
) -> Result<Option<OracleMalfeasance>> {
    let va = verify_signed_statement_for_proof(a, verifier)?;
    let vb = verify_signed_statement_for_proof(b, verifier)?;
    if va.oracle_key != vb.oracle_key {
        return Ok(None);
    }
    if va.self_contradictory() || vb.self_contradictory() {
        return Ok(Some(OracleMalfeasance::SelfContradiction));
    }
    if let Some(kind) = chained_violation(a, &va, b, &vb).or_else(|| chained_violation(b, &vb, a, &va)) {
        return Ok(Some(kind));
    }
    if va.dna == vb.dna && va.seq == vb.seq && va.prev == vb.prev && a.statement != b.statement {
        return Ok(Some(OracleMalfeasance::Equivocation));
    }
    Ok(None)
}

/// A short human-readable description of a proof.
pub fn describe(kind: &OracleMalfeasance, oracle: &str) -> String {
    match kind {
        OracleMalfeasance::SelfContradiction => {
            alloc::format!("oracle {oracle} signed a statement below its own chain's floor")
        }
        OracleMalfeasance::TimeReversal => {
            alloc::format!("oracle {oracle} signed a chained statement whose time runs backwards")
        }
        OracleMalfeasance::FloorDropped => {
            alloc::format!("oracle {oracle} lowered its chain's floor in a chained statement")
        }
        OracleMalfeasance::Equivocation => {
            alloc::format!("oracle {oracle} signed two different statements at one place in its chain")
        }
    }
}
