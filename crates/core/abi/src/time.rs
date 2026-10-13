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

/// A clock a deadline or a timestamp is read on (RFC-0044 follow-up).
///
/// One `u32`: the kind in bits 24..32, the index in bits 0..24. [`ClockId::MONO`]
/// is raw `0`, so a zero-filled field (a default descriptor)
/// names the monotonic boot clock. Only `MONO` is served today; the other
/// kinds are reserved numbers so a caller can name them and be refused
/// (`Unsupported`) instead of silently read on the wrong clock.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ClockId(pub u32);

impl ClockId {
    /// Bits of the index.
    pub const INDEX_BITS: u32 = 24;
    /// Mask of the index.
    pub const INDEX_MASK: u32 = (1 << Self::INDEX_BITS) - 1;

    /// Kind: the monotonic boot clock (the vDSO's, `azos_libsys::vdso_now_ns`).
    pub const KIND_MONO: u8 = 0;
    /// Kind (reserved): wall-clock time.
    pub const KIND_REAL: u8 = 1;
    /// Kind (reserved): the raw hardware counter, unscaled.
    pub const KIND_TSC_RAW: u8 = 2;
    /// Kind (reserved): PTP hardware clock number `index`.
    pub const KIND_PTP: u8 = 3;
    /// Kind (reserved): time-sensitive-networking domain `index`.
    pub const KIND_TSN_DOMAIN: u8 = 4;
    /// Kind (reserved): the virtual time of vCPU `index`.
    pub const KIND_VCPU: u8 = 5;

    /// The monotonic boot clock.
    pub const MONO: ClockId = ClockId::new(Self::KIND_MONO, 0);
    /// Wall-clock time (reserved).
    pub const REAL: ClockId = ClockId::new(Self::KIND_REAL, 0);
    /// The raw hardware counter (reserved).
    pub const TSC_RAW: ClockId = ClockId::new(Self::KIND_TSC_RAW, 0);

    /// `kind` and `index` (an index past 24 bits is truncated).
    pub const fn new(kind: u8, index: u32) -> ClockId {
        ClockId((kind as u32) << Self::INDEX_BITS | (index & Self::INDEX_MASK))
    }
    /// PTP hardware clock `n` (reserved).
    pub const fn ptp(n: u32) -> ClockId {
        ClockId::new(Self::KIND_PTP, n)
    }
    /// TSN domain `n` (reserved).
    pub const fn tsn_domain(n: u32) -> ClockId {
        ClockId::new(Self::KIND_TSN_DOMAIN, n)
    }
    /// Virtual time of vCPU `n` (reserved).
    pub const fn vcpu(n: u32) -> ClockId {
        ClockId::new(Self::KIND_VCPU, n)
    }
    /// The kind (high bits).
    pub const fn kind(self) -> u8 {
        (self.0 >> Self::INDEX_BITS) as u8
    }
    /// The index (low bits).
    pub const fn index(self) -> u32 {
        self.0 & Self::INDEX_MASK
    }
    /// The raw `u32`, as it travels in a message descriptor.
    pub const fn raw(self) -> u32 {
        self.0
    }
    /// Is this the monotonic boot clock (the one clock served today)?
    pub const fn is_mono(self) -> bool {
        self.0 == Self::MONO.0
    }
}

/// Why a clock read was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockError {
    /// The clock is a reserved number no kernel serves yet.
    Unsupported,
}
