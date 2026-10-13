// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_ipc`, reduced to `cap::degrade_level`.
//!
//! **WHY.** The real crate is RV64-heavy — capability tables, fast-IPC slots,
//! scheduler hooks — so `#[path]`-pulling `safety.rs` stops at the first
//! reference to it. Only one function is reached, and it returns a number.
//!
//! The shim adds a control surface the real crate has no reason to offer:
//! [`shim_set_level`], so the graded-degrade ceiling can be exercised at every
//! level including ones the runtime would never reach. That is the point of a
//! shim rather than a stub returning a constant — a constant would make the
//! degrade cap untestable and the test would silently assert nothing.

use core::sync::atomic::{AtomicU8, Ordering};

static LEVEL: AtomicU8 = AtomicU8::new(0);

/// Set the degrade level the next `degrade_level()` will report.
pub fn shim_set_level(l: u8) { LEVEL.store(l, Ordering::Relaxed); }

pub mod cap {
    use super::*;
    pub fn degrade_level() -> u8 { LEVEL.load(Ordering::Relaxed) }
    // `azos_ipc::cap`'s level numbers (wave 11), which `safety.rs` checks
    // against `azos_degrade_policy`'s at compile time.
    pub const DEGRADE_LEVEL_FULL: u8 = 0;
    pub const DEGRADE_LEVEL_CAUTIOUS: u8 = 1;
    pub const DEGRADE_LEVEL_SLOW: u8 = 2;
    pub const DEGRADE_LEVEL_CONTAINED: u8 = 3;
    pub const DEGRADE_LEVEL_MAX: u8 = DEGRADE_LEVEL_CONTAINED;
}
