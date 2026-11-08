//! Time intervals and fault-tolerant combination of many sources.
//!
//! Every source reports a closed interval [earliest, latest] in microseconds
//! since the Unix epoch that should contain the true time at the moment it
//! signed. A *faulty* source (a "falseticker" in NTP terms) may report any
//! interval. With at most `f` faulty sources:
//!
//! - **Lower bound for an event that happened after every reading** ("not
//!   before"): the (f+1)-th largest `earliest`. Among the f+1 sources with the
//!   largest lower bounds at least one is honest, its reading happened before
//!   the event, and the (f+1)-th largest value is no greater than its bound.
//! - **Upper bound for an event that happened before every reading** ("not
//!   after"): symmetrically, the (f+1)-th smallest `latest`.
//! - **Simultaneous readings** ("what time is it now"): the intersection
//!   algorithm used by NTP (a refinement of Marzullo's algorithm) returns the
//!   hull of all points covered by at least n - f intervals. If n >= 2f + 1 the
//!   result contains the true time and lies inside the hull of honest intervals.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::hash::to_hex;

/// Largest magnitude, in microseconds, accepted anywhere in this crate.
///
/// 2^53 microseconds is about 285 years after 1970. Keeping every value below
/// it means Unyt's Rhai `to_num` (an f64) reads these numbers exactly.
pub const MAX_ABS_MICROS: i64 = 1 << 53;

/// A closed interval of Unix time in microseconds.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TimeInterval {
    /// No earlier than this.
    pub earliest_us: i64,
    /// No later than this.
    pub latest_us: i64,
}

impl TimeInterval {
    /// A checked interval: earliest <= latest, both within +-2^53 microseconds.
    pub fn new(earliest_us: i64, latest_us: i64) -> Result<Self> {
        if earliest_us > latest_us {
            return Err(Error::Malformed(format!(
                "interval earliest {earliest_us} is after latest {latest_us}"
            )));
        }
        // unsigned_abs: i64::MIN.abs() overflows (a panic in debug builds and
        // i64::MIN, which passes the check, in release builds).
        if earliest_us.unsigned_abs() >= MAX_ABS_MICROS as u64 || latest_us.unsigned_abs() >= MAX_ABS_MICROS as u64 {
            return Err(Error::Overflow);
        }
        Ok(Self { earliest_us, latest_us })
    }

    /// The interval midpoint +- radius.
    pub fn from_midpoint(midpoint_us: i64, radius_us: i64) -> Result<Self> {
        if radius_us < 0 {
            return Err(Error::Malformed("negative radius".into()));
        }
        Self::new(
            midpoint_us.checked_sub(radius_us).ok_or(Error::Overflow)?,
            midpoint_us.checked_add(radius_us).ok_or(Error::Overflow)?,
        )
    }

    /// Half the width, rounded up: the uncertainty radius. The fields are
    /// public, so the width saturates rather than trusting `new`'s invariant.
    pub fn radius_us(&self) -> i64 {
        let w = self.latest_us.saturating_sub(self.earliest_us);
        w / 2 + w % 2
    }

    /// True when `t` lies within the interval.
    pub fn contains(&self, t: i64) -> bool {
        self.earliest_us <= t && t <= self.latest_us
    }
}

/// Who vouched for a reading. Keys are raw Ed25519 public keys.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceId {
    /// A Roughtime server's long-term key.
    Roughtime([u8; 32]),
    /// A Holochain oracle agent's key (the 32 core bytes of its AgentPubKey).
    Oracle([u8; 32]),
}

impl SourceId {
    /// Human-readable label used in error messages.
    pub fn label(&self) -> String {
        match self {
            SourceId::Roughtime(k) => format!("roughtime:{}", to_hex(k)),
            SourceId::Oracle(k) => format!("oracle:{}", to_hex(k)),
        }
    }

    /// The raw key regardless of kind. Roughtime servers and oracles are
    /// separate trust lists, but one key must not count twice even if an
    /// operator lists it in both.
    pub fn key(&self) -> &[u8; 32] {
        match self {
            SourceId::Roughtime(k) | SourceId::Oracle(k) => k,
        }
    }
}

/// One verified reading.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourcedInterval {
    /// Who produced it.
    pub source: SourceId,
    /// What it says.
    pub interval: TimeInterval,
}

/// Fail if any key appears twice.
pub fn check_distinct(items: &[SourcedInterval]) -> Result<()> {
    let mut keys: Vec<&[u8; 32]> = items.iter().map(|i| i.source.key()).collect();
    keys.sort_unstable();
    for w in keys.windows(2) {
        if w[0] == w[1] {
            let dup = items.iter().find(|i| i.source.key() == w[0]).unwrap();
            return Err(Error::DuplicateSource(dup.source.label()));
        }
    }
    Ok(())
}

fn need(items: &[SourcedInterval], need: usize) -> Result<()> {
    if items.len() < need {
        return Err(Error::NotEnoughSources { have: items.len(), need });
    }
    Ok(())
}

/// f + 1 without wrapping (on wasm32, `usize` is 32 bits).
fn f_plus_one(max_faulty: usize) -> Result<usize> {
    max_faulty.checked_add(1).ok_or(Error::Overflow)
}

/// Lower bound on the time of an event that happened after every reading,
/// assuming at most `max_faulty` sources lie: the (f+1)-th largest `earliest`.
pub fn robust_lower_bound(items: &[SourcedInterval], max_faulty: usize) -> Result<i64> {
    check_distinct(items)?;
    need(items, f_plus_one(max_faulty)?)?;
    let mut lows: Vec<i64> = items.iter().map(|i| i.interval.earliest_us).collect();
    lows.sort_unstable_by(|a, b| b.cmp(a));
    Ok(lows[max_faulty])
}

/// Upper bound on the time of an event that happened before every reading,
/// assuming at most `max_faulty` sources lie: the (f+1)-th smallest `latest`.
pub fn robust_upper_bound(items: &[SourcedInterval], max_faulty: usize) -> Result<i64> {
    check_distinct(items)?;
    need(items, f_plus_one(max_faulty)?)?;
    let mut highs: Vec<i64> = items.iter().map(|i| i.interval.latest_us).collect();
    highs.sort_unstable();
    Ok(highs[max_faulty])
}

/// Fault-tolerant intersection of near-simultaneous readings: the smallest
/// interval holding every point covered by at least n - f readings.
///
/// Requires n >= 2f + 1 distinct sources. Under that condition, if at most f
/// sources are faulty, the true time is inside the result and the result lies
/// inside the hull of the honest readings.
pub fn fault_tolerant_intersection(items: &[SourcedInterval], max_faulty: usize) -> Result<TimeInterval> {
    check_distinct(items)?;
    let two_f_plus_one = max_faulty.checked_mul(2).and_then(|v| v.checked_add(1)).ok_or(Error::Overflow)?;
    need(items, two_f_plus_one)?;
    let n = items.len();
    let quorum = n - max_faulty;

    // Endpoints sorted by position; at equal positions starts come first so
    // closed intervals that only touch still count as overlapping.
    let mut events: Vec<(i64, i8)> = Vec::with_capacity(2 * n);
    for it in items {
        events.push((it.interval.earliest_us, -1));
        events.push((it.interval.latest_us, 1));
    }
    events.sort_unstable();

    let mut count = 0usize;
    let mut lo = None;
    let mut hi = None;
    for &(pos, kind) in &events {
        if kind == -1 {
            count += 1;
            if count >= quorum && lo.is_none() {
                lo = Some(pos);
            }
        } else {
            if count >= quorum {
                hi = Some(pos);
            }
            count -= 1;
        }
    }
    match (lo, hi) {
        (Some(lo), Some(hi)) if lo <= hi => TimeInterval::new(lo, hi),
        _ => Err(Error::NotEnoughSources { have: 0, need: quorum }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(i: u8, lo: i64, hi: i64) -> SourcedInterval {
        SourcedInterval {
            source: SourceId::Oracle([i; 32]),
            interval: TimeInterval::new(lo, hi).unwrap(),
        }
    }

    #[test]
    fn lower_and_upper_ignore_f_outliers() {
        // True time ~1000. Source 3 is a liar pushing the clock forward.
        let s = [src(1, 990, 1010), src(2, 995, 1005), src(3, 5000, 5010)];
        assert_eq!(robust_lower_bound(&s, 1).unwrap(), 995);
        assert_eq!(robust_upper_bound(&s, 1).unwrap(), 1010);
        // With f = 0 the liar is believed.
        assert_eq!(robust_lower_bound(&s, 0).unwrap(), 5000);
    }

    #[test]
    fn duplicates_are_rejected() {
        let s = [src(1, 0, 10), src(1, 0, 10)];
        assert!(matches!(robust_lower_bound(&s, 0), Err(Error::DuplicateSource(_))));
        // Same key listed as both kinds still counts once.
        let s = [
            src(1, 0, 10),
            SourcedInterval { source: SourceId::Roughtime([1; 32]), interval: TimeInterval::new(0, 10).unwrap() },
        ];
        assert!(matches!(robust_upper_bound(&s, 0), Err(Error::DuplicateSource(_))));
    }

    #[test]
    fn intersection_matches_marzullo_example() {
        // Classic example: [8,12], [11,13], [10,12] with f = 0 -> [11,12].
        let s = [src(1, 8, 12), src(2, 11, 13), src(3, 10, 12)];
        assert_eq!(fault_tolerant_intersection(&s, 0).unwrap(), TimeInterval::new(11, 12).unwrap());
        // With f = 1 any point covered by two intervals: [10, 12].
        assert_eq!(fault_tolerant_intersection(&s, 1).unwrap(), TimeInterval::new(10, 12).unwrap());
    }

    #[test]
    fn intersection_excludes_a_falseticker() {
        let s = [src(1, 99, 101), src(2, 98, 102), src(3, 500, 510)];
        let r = fault_tolerant_intersection(&s, 1).unwrap();
        assert_eq!(r, TimeInterval::new(99, 101).unwrap());
        assert!(fault_tolerant_intersection(&s[..2], 1).is_err(), "n < 2f+1 must fail");
    }

    /// Regression (review P3, arithmetic): extreme values return errors in
    /// debug and release builds instead of panicking or wrapping.
    #[test]
    fn extreme_values_are_rejected_not_wrapped() {
        assert_eq!(TimeInterval::new(i64::MIN, 0), Err(Error::Overflow));
        assert_eq!(TimeInterval::new(0, i64::MAX), Err(Error::Overflow));
        assert_eq!(TimeInterval::new(-MAX_ABS_MICROS, 0), Err(Error::Overflow));
        assert!(TimeInterval::new(-MAX_ABS_MICROS + 1, MAX_ABS_MICROS - 1).is_ok());
        let odd = TimeInterval { earliest_us: i64::MIN, latest_us: i64::MAX };
        assert_eq!(odd.radius_us(), i64::MAX / 2 + 1);
        let s = [src(1, 0, 10)];
        assert_eq!(robust_lower_bound(&s, usize::MAX), Err(Error::Overflow));
        assert_eq!(robust_upper_bound(&s, usize::MAX), Err(Error::Overflow));
        assert_eq!(fault_tolerant_intersection(&s, usize::MAX / 2 + 1), Err(Error::Overflow));
    }

    /// Property check: for many random worlds with at most f liars among
    /// n >= 2f+1 sources, the true time is always inside the intersection and
    /// always between the robust lower and upper bounds.
    #[test]
    fn bounds_hold_under_random_adversaries() {
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..5000 {
            let f = (next() % 4) as usize;
            let n = 2 * f + 1 + (next() % 3) as usize;
            let truth = 1_700_000_000_000_000i64 + (next() % 1_000_000) as i64;
            let mut items = Vec::new();
            for i in 0..n {
                let (lo, hi) = if i < f {
                    // Liar: anything at all.
                    let a = truth + (next() % 20_000_000) as i64 - 10_000_000;
                    let w = (next() % 5_000_000) as i64;
                    (a, a + w)
                } else {
                    let r = 1 + (next() % 2_000_000) as i64;
                    let off = (next() % (2 * r as u64 + 1)) as i64 - r;
                    (truth + off - r, truth + off + r)
                };
                items.push(src(i as u8, lo, hi));
            }
            let x = fault_tolerant_intersection(&items, f).unwrap();
            assert!(x.contains(truth), "intersection {x:?} misses truth {truth}");
            assert!(robust_lower_bound(&items, f).unwrap() <= truth);
            assert!(robust_upper_bound(&items, f).unwrap() >= truth);
        }
    }
}
