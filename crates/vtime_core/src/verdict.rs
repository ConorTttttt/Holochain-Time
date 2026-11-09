//! Comparing an action's self-declared timestamp with proven bounds.

use serde::{Deserialize, Serialize};

/// How an action's own timestamp relates to what the evidence proves.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimestampVerdict {
    /// No bound is known on either side.
    Unverified,
    /// The claimed time lies within the proven bounds (plus tolerance).
    Consistent,
    /// The claimed time is earlier than the proven lower bound.
    Backdated {
        /// By how many microseconds beyond the tolerance.
        by_us: i64,
    },
    /// The claimed time is later than the proven upper bound.
    FutureDated {
        /// By how many microseconds beyond the tolerance.
        by_us: i64,
    },
}

/// Classify `claimed_us` against optional bounds, allowing `tolerance_us` of
/// clock skew on either side.
pub fn classify(
    claimed_us: i64,
    lower_us: Option<i64>,
    upper_us: Option<i64>,
    tolerance_us: i64,
) -> TimestampVerdict {
    if let Some(lo) = lower_us {
        let gap = lo.saturating_sub(tolerance_us).saturating_sub(claimed_us);
        if gap > 0 {
            return TimestampVerdict::Backdated { by_us: gap };
        }
    }
    if let Some(hi) = upper_us {
        let gap = claimed_us.saturating_sub(hi.saturating_add(tolerance_us));
        if gap > 0 {
            return TimestampVerdict::FutureDated { by_us: gap };
        }
    }
    if lower_us.is_none() && upper_us.is_none() {
        TimestampVerdict::Unverified
    } else {
        TimestampVerdict::Consistent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification() {
        assert_eq!(classify(50, None, None, 0), TimestampVerdict::Unverified);
        assert_eq!(
            classify(50, Some(40), Some(60), 0),
            TimestampVerdict::Consistent
        );
        assert_eq!(
            classify(30, Some(40), None, 5),
            TimestampVerdict::Backdated { by_us: 5 }
        );
        assert_eq!(
            classify(70, None, Some(60), 5),
            TimestampVerdict::FutureDated { by_us: 5 }
        );
        assert_eq!(
            classify(64, None, Some(60), 5),
            TimestampVerdict::Consistent
        );
    }
}
