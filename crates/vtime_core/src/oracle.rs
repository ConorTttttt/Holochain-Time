//! What an oracle may sign next, decided without Holochain so it can be
//! tested natively. The coordinator zome feeds in its last logged statement
//! and its clock; this module returns the interval and chain link to sign, or
//! a refusal.
//!
//! Two refusals protect the oracle:
//!
//! - **Clock behind.** A statement whose `latest` would fall below the chain's
//!   floor would be a signed confession (see [`crate::malfeasance`]), so an
//!   honest oracle with a bad clock stops instead of incriminating itself.
//! - **Rate limit.** `attest_time` is open to every peer and each answer is a
//!   chain action, so answers are spaced at least `min_spacing_us` apart. That
//!   bounds how fast anyone can grow the oracle's chain; refused callers retry.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::interval::TimeInterval;
use crate::statement::{ChainLink, SignedOracleStatement};

/// Default minimum spacing between two statements by one oracle: 1 s, so at
/// most one chain action per second (86,400 a day) however many peers call.
/// Raising throughput means lowering this in the coordinator, which does not
/// change the DNA hash; the lasting fix is one statement per batch of nonces.
pub const DEFAULT_MIN_SPACING_US: i64 = 1_000_000;

/// The interval and chain position for the next statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// What to attest.
    pub interval: TimeInterval,
    /// Where it goes in the chain.
    pub link: ChainLink,
}

/// Decide the next statement for an oracle whose clock reads `now_us`, given
/// its last logged statement (if any).
pub fn plan_statement(
    last: Option<&SignedOracleStatement>,
    now_us: i64,
    radius_us: i64,
    min_spacing_us: i64,
) -> Result<Plan> {
    let interval = TimeInterval::from_midpoint(now_us, radius_us)?;
    let Some(last) = last else {
        return Ok(Plan { interval, link: ChainLink::genesis() });
    };
    let link = ChainLink::after(last)?;
    let floor = link.floor.ok_or(Error::Overflow)?;
    if interval.latest_us < floor {
        return Err(Error::ClockBehind { latest_us: interval.latest_us, floor_us: floor });
    }
    let p = last.statement.parse_fields()?;
    let last_reading = p.interval.earliest_us + p.interval.radius_us();
    let elapsed = now_us.saturating_sub(last_reading);
    if elapsed < min_spacing_us {
        return Err(Error::RateLimited { retry_after_us: min_spacing_us.saturating_sub(elapsed) });
    }
    Ok(Plan { interval, link })
}

/// Sequence ranges (inclusive) to search, newest first, for an oracle's last
/// log entry when its chain head is at `head_seq`: a few actions back, then
/// wider, ending with the whole chain. The last log entry is normally among
/// the newest actions, so lookups stay O(1) instead of loading every entry.
pub fn log_lookup_windows(head_seq: u32) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for width in [16u32, 256, 4096] {
        let start = head_seq.saturating_sub(width - 1);
        out.push((start, head_seq));
        if start == 0 {
            return out;
        }
    }
    out.push((0, head_seq));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{agent_key_to_b64, dna_hash_to_b64};
    use crate::statement::OracleTimeStatement;

    const R: i64 = 1_000_000;
    const T: i64 = 1_792_000_000_000_000;

    fn signed(plan: &Plan) -> SignedOracleStatement {
        let st = OracleTimeStatement::new(
            agent_key_to_b64(&[1; 32]),
            dna_hash_to_b64(&[2; 32]),
            &[0; 32],
            plan.interval,
            plan.link,
        );
        SignedOracleStatement { statement: st, signature: alloc::vec![plan.link.seq as u8; 64] }
    }

    #[test]
    fn genesis_then_chained() {
        let p0 = plan_statement(None, T, R, DEFAULT_MIN_SPACING_US).unwrap();
        assert_eq!(p0.link, ChainLink::genesis());
        let s0 = signed(&p0);
        let p1 = plan_statement(Some(&s0), T + 1_000_000, R, DEFAULT_MIN_SPACING_US).unwrap();
        assert_eq!(p1.link.seq, 1);
        assert_eq!(p1.link.floor, Some(T - R));
    }

    /// Regression (review P2, attest_time spam): answers closer together than
    /// the spacing are refused with a retry hint.
    #[test]
    fn rate_limit() {
        let s0 = signed(&plan_statement(None, T, R, DEFAULT_MIN_SPACING_US).unwrap());
        let err = plan_statement(Some(&s0), T + 50_000, R, DEFAULT_MIN_SPACING_US).unwrap_err();
        assert_eq!(err, Error::RateLimited { retry_after_us: DEFAULT_MIN_SPACING_US - 50_000 });
        assert!(plan_statement(Some(&s0), T + DEFAULT_MIN_SPACING_US, R, DEFAULT_MIN_SPACING_US).is_ok());
        // Spam over ten simulated seconds yields at most 10 s / spacing answers.
        let mut last = s0;
        let mut answered = 0;
        for i in 1..=10_000i64 {
            if let Ok(p) = plan_statement(Some(&last), T + i * 1_000, R, DEFAULT_MIN_SPACING_US) {
                last = signed(&p);
                answered += 1;
            }
        }
        assert_eq!(answered, 10_000_000 / DEFAULT_MIN_SPACING_US);
    }

    /// Regression (review P2, backwards walk): an honest oracle never signs
    /// below its floor, so a clock stepping back is refused.
    #[test]
    fn clock_behind_is_refused() {
        let s0 = signed(&plan_statement(None, T, R, 0).unwrap());
        // A clock that stepped back is never signed: within 2r it waits (the
        // spacing rule measures from the last reading), beyond it the floor
        // guard refuses outright.
        let err = plan_statement(Some(&s0), T - R, R, 0).unwrap_err();
        assert_eq!(err, Error::RateLimited { retry_after_us: R });
        let err = plan_statement(Some(&s0), T - 2 * R - 1, R, 0).unwrap_err();
        assert_eq!(err, Error::ClockBehind { latest_us: T - R - 1, floor_us: T - R });
        assert!(plan_statement(Some(&s0), T, R, 0).is_ok());
    }

    #[test]
    fn lookup_windows_end_with_the_whole_chain() {
        for head in [0u32, 1, 15, 16, 17, 255, 256, 4095, 4096, 100_000, u32::MAX] {
            let w = log_lookup_windows(head);
            assert_eq!(*w.last().unwrap(), (0, head), "head {head}: {w:?}");
            assert!(w.iter().all(|&(s, e)| s <= e && e == head));
            assert!(w.windows(2).all(|p| p[0].0 > p[1].0), "windows must widen: {w:?}");
            assert_eq!(w[0].0, head.saturating_sub(15));
        }
    }
}
