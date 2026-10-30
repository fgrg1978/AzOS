// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Clock math: a hardware counter's rate to Kconfig `TIMER_FREQ`, the rate
//! every `N * TIMER_FREQ` timeout in the tree is written in, and back.

/// A rate conversion `out = in * mult >> 32` (Linux's clocksource
/// mult/shift with the shift fixed at 32): one 64x64->128 `mul` per call.
/// Exact to 2^-32 relative; `mult` fits 64 bits for any ratio below 2^32.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Scale {
    pub mult: u64,
}

impl Scale {
    /// 1:1.
    pub const IDENTITY: Scale = Scale { mult: 1 << 32 };

    /// The conversion from a `from_hz` counter to `to_hz` ticks. `None` for a
    /// zero rate or a ratio of 2^32 or more.
    pub const fn new(from_hz: u64, to_hz: u64) -> Option<Scale> {
        if from_hz == 0 || to_hz == 0 {
            return None;
        }
        let m = ((to_hz as u128) << 32) / from_hz as u128;
        if m == 0 || m > u64::MAX as u128 {
            return None;
        }
        Some(Scale { mult: m as u64 })
    }

    /// As [`Self::new`] with `mult` rounded up, for a duration that must not
    /// come out short: an inexact ratio never rounds a timeout early.
    pub const fn new_up(from_hz: u64, to_hz: u64) -> Option<Scale> {
        if from_hz == 0 || to_hz == 0 {
            return None;
        }
        let m = (((to_hz as u128) << 32) + from_hz as u128 - 1) / from_hz as u128;
        if m > u64::MAX as u128 {
            return None;
        }
        Some(Scale { mult: m as u64 })
    }

    /// `x` converted, rounded down, saturating at `u64::MAX`.
    #[inline(always)]
    pub const fn apply(self, x: u64) -> u64 {
        let p = (x as u128 * self.mult as u128) >> 32;
        if p > u64::MAX as u128 { u64::MAX } else { p as u64 }
    }

    /// `x` converted, rounded up: a deadline converted this way is never
    /// earlier than the one asked for.
    #[inline(always)]
    pub const fn apply_ceil(self, x: u64) -> u64 {
        let p = (x as u128 * self.mult as u128 + 0xFFFF_FFFF) >> 32;
        if p > u64::MAX as u128 { u64::MAX } else { p as u64 }
    }
}
