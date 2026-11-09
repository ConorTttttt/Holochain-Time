//! Propagating bounds along a source chain.
//!
//! A Holochain source chain is a hash-linked log, the structure Haber and
//! Stornetta proposed for timestamping in 1991: every action commits to the
//! previous one. So a lower bound proven for action k (an anchor) also holds
//! for every later action of that agent, and an upper bound proven for action
//! k (a seal) also holds for every earlier one. This turns a few anchors and
//! seals into bounds for a whole chain.
//!
//! Soundness needs a fork-free chain. Holochain's agent-activity authorities
//! detect forks and issue warrants, so a caller should check the author has no
//! warrants before relying on propagated bounds.

use serde::{Deserialize, Serialize};

/// Bounds known for one action, identified by its sequence number.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainPoint {
    /// Position in the source chain.
    pub seq: u32,
    /// Proven lower bound for this action, if any.
    pub lower_us: Option<i64>,
    /// Proven upper bound for this action, if any.
    pub upper_us: Option<i64>,
}

/// Tighten every point's bounds using its neighbours. `points` must be sorted
/// by `seq` and come from one fork-free chain.
pub fn propagate(points: &mut [ChainPoint]) {
    debug_assert!(points.windows(2).all(|w| w[0].seq < w[1].seq));
    let mut best_lower: Option<i64> = None;
    for p in points.iter_mut() {
        best_lower = match (best_lower, p.lower_us) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        p.lower_us = best_lower;
    }
    let mut best_upper: Option<i64> = None;
    for p in points.iter_mut().rev() {
        best_upper = match (best_upper, p.upper_us) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        p.upper_us = best_upper;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchors_flow_forward_and_seals_flow_backward() {
        let mut pts = [
            ChainPoint {
                seq: 3,
                lower_us: None,
                upper_us: None,
            },
            ChainPoint {
                seq: 4,
                lower_us: Some(100),
                upper_us: None,
            },
            ChainPoint {
                seq: 7,
                lower_us: None,
                upper_us: None,
            },
            ChainPoint {
                seq: 9,
                lower_us: Some(90),
                upper_us: Some(500),
            },
            ChainPoint {
                seq: 12,
                lower_us: None,
                upper_us: Some(800),
            },
        ];
        propagate(&mut pts);
        assert_eq!(
            pts[0],
            ChainPoint {
                seq: 3,
                lower_us: None,
                upper_us: Some(500)
            }
        );
        assert_eq!(
            pts[2],
            ChainPoint {
                seq: 7,
                lower_us: Some(100),
                upper_us: Some(500)
            }
        );
        // A weaker later anchor (90) does not loosen the earlier one (100).
        assert_eq!(pts[3].lower_us, Some(100));
        assert_eq!(
            pts[4],
            ChainPoint {
                seq: 12,
                lower_us: Some(100),
                upper_us: Some(800)
            }
        );
    }
}
