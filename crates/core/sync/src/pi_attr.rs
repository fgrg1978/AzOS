// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The order of scheduling attributes: what the wait graph compares
//! (`waitgraph.rs`, which re-exports this) and what the micro kernel's
//! priority ceiling computes an effective priority with (`micro/`).
//!
//! Pure and free of statics, locks and limits, so the host suites and the
//! 32-bit kernel compile this file as is (`#[path]`).

/// A task's scheduling attribute as the graph compares it. The scheduler
/// (N6a) converts its SchedContext into this; the graph never reads the SC.
///
/// Order (most urgent first, the fixed class precedence of N6):
/// `Stop > Dl > Rt > Fair > Idle`; inside `Dl` the earlier absolute deadline
/// wins; inside `Rt` the lower priority number wins. `Fair` and `Idle` carry
/// nothing: a fair donor does not boost a fair owner (no weight
/// inheritance in stage 1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PiAttr {
    Idle,
    Fair,
    /// Real-time priority, lower number more urgent.
    Rt { prio: u8 },
    /// Deadline class, absolute deadline in nanoseconds of the monotonic
    /// clock. A boosted owner **inherits this deadline** (Q4 stage 1).
    Dl { deadline_ns: u64 },
    Stop,
}

impl PiAttr {
    const fn rank(self) -> u8 {
        match self {
            PiAttr::Idle => 0,
            PiAttr::Fair => 1,
            PiAttr::Rt { .. } => 2,
            PiAttr::Dl { .. } => 3,
            PiAttr::Stop => 4,
        }
    }

    /// The more urgent of `self` and `o` (the effective-attribute rule).
    #[inline]
    pub fn max_urgent(self, o: PiAttr) -> PiAttr {
        if o > self { o } else { self }
    }

    /// `self` as one integer for the lock-free quiet test ([`quiet_le`]):
    /// `rank << 8`, plus `255 - prio` inside `Rt`, so that for two attributes
    /// that are not `Dl` the integer order IS [`Ord`] (host test
    /// `quiet_key_matches_ord` enumerates every pair). `Dl` cannot be encoded
    /// (its order is the deadline, which the scheduler reads on the
    /// reservation's own hart): it is [`QUIET_DL`], which [`quiet_le`] never
    /// calls quiet on either side.
    #[inline]
    pub const fn quiet_key(self) -> u32 {
        match self {
            PiAttr::Dl { .. } => QUIET_DL,
            PiAttr::Rt { prio } => ((self.rank() as u32) << 8) | (255 - prio as u32),
            _ => (self.rank() as u32) << 8,
        }
    }
}

/// [`PiAttr::quiet_key`] of any `Dl` attribute.
pub const QUIET_DL: u32 = u32::MAX;

/// The quiet test on two [`PiAttr::quiet_key`]s: `waiter <= owner` for two
/// attributes that are not `Dl`, `false` when either is. One add and one
/// unsigned compare: `owner + 1` wraps to 0 for a `Dl` owner (nothing is
/// below 0), and a `Dl` waiter (`u32::MAX`) is below no `owner + 1`, the
/// largest other key being `Stop`'s 1024.
#[inline(always)]
pub const fn quiet_le(waiter: u32, owner: u32) -> bool {
    waiter < owner.wrapping_add(1)
}

impl Ord for PiAttr {
    /// `a > b` iff `a` is more urgent than `b`.
    fn cmp(&self, o: &Self) -> core::cmp::Ordering {
        use core::cmp::Ordering;
        match self.rank().cmp(&o.rank()) {
            Ordering::Equal => match (*self, *o) {
                (PiAttr::Rt { prio: a }, PiAttr::Rt { prio: b }) => b.cmp(&a),
                (PiAttr::Dl { deadline_ns: a }, PiAttr::Dl { deadline_ns: b }) => b.cmp(&a),
                _ => Ordering::Equal,
            },
            r => r,
        }
    }
}

impl PartialOrd for PiAttr {
    fn partial_cmp(&self, o: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
