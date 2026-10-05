// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Conversions between nanoseconds and the RISC-V `time` counter (RFC-0044).
//!
//! The ABI speaks nanoseconds; the counter ticks at a per-board frequency
//! (4, 10 and 24 MHz today). The kernel and ring 3 convert with the same two
//! functions, so a deadline computed from a clock read means the same instant
//! on both sides.
//!
//! Both split the value at the second so no intermediate product needs 128
//! bits. They are exact for any frequency up to 10^8 Hz and saturate, rather
//! than wrap, above that.

/// Nanoseconds in one second.
pub const NS_PER_SEC: u64 = 1_000_000_000;

/// The first counter value at or after `ns` nanoseconds, on a counter that
/// ticks `freq_hz` times per second. Rounds up, so a deadline converted here
/// is never reached early.
pub const fn ns_to_ticks_ceil(ns: u64, freq_hz: u64) -> u64 {
    let whole = (ns / NS_PER_SEC).saturating_mul(freq_hz);
    let part = ((ns % NS_PER_SEC).saturating_mul(freq_hz)).saturating_add(NS_PER_SEC - 1) / NS_PER_SEC;
    whole.saturating_add(part)
}

/// Nanoseconds elapsed at counter value `ticks`, rounded down.
///
/// `freq_hz` must not be 0; a zero frequency (a vDSO page that does not
/// publish one) returns 0.
pub const fn ticks_to_ns(ticks: u64, freq_hz: u64) -> u64 {
    if freq_hz == 0 {
        return 0;
    }
    let whole = (ticks / freq_hz).saturating_mul(NS_PER_SEC);
    let part = (ticks % freq_hz).saturating_mul(NS_PER_SEC) / freq_hz;
    whole.saturating_add(part)
}
