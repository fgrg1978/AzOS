// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! How the motor command resolves against the stop latch.
//!
//! Pure, so the host suite (`tests/host/behavior-tests`) runs the same source
//! the kernel links. `lib.rs` owns the statics; this file only decides.

/// The command `rt_motor` must apply: `stop` when a stop request is at least
/// as recent as the last published command (a tie goes to the stop), else the
/// published command. `zero_at == 0` means no stop was ever requested.
#[inline]
pub fn resolve<T: Copy>(cmd: T, cmd_ts: u64, zero_at: u64, stop: T) -> T {
    if zero_at != 0 && zero_at >= cmd_ts { stop } else { cmd }
}

/// Ticks since the last command or stop request, whichever is newer.
/// `cmd_age` is the channel's own age (`u64::MAX` when never published).
#[inline]
pub fn age(cmd_age: u64, now: u64, zero_at: u64) -> u64 {
    if zero_at == 0 { cmd_age } else { cmd_age.min(now.saturating_sub(zero_at)) }
}
