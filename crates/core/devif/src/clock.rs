// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Clock` interface: how a time source steers the wall clock, and how a
//! task reads how well it is steered.
//!
//! The kernel hosts it on the `clock` endpoint (`endpoint = "clock"`). The
//! SNTP client in the kernel feeds the same discipline directly; the PTP
//! daemon, a ring-3 task, holds the endpoint and calls [`Clock::sample`] once
//! per measurement.
//!
//! A measurement is the reference's reading minus the wall clock's at the same
//! instant (`offset_ns`, positive when the wall clock is behind) and the round
//! trip of the exchange that gave it (`delay_ns`). What the discipline does with
//! it (slew, filter, step, refuse) is `azos_drv_sys::clockdisc`'s; this
//! interface only carries the numbers and says what was done.
//!
//! The wall clock is the only clock a source can move: the monotonic one never
//! does, so no op names a clock.
//!
//! The board's real-time clock is the persistent clock behind the wall clock
//! (`azos_rtc`): the kernel reads it once at boot to seed the wall clock
//! before any network reference exists, and writes it back when a reference
//! steps the wall clock. [`Clock::rtc_read`] and [`Clock::rtc_set`] are the
//! chip itself, for a task that wants the persistent time or has a better one
//! (a GPS time sync, an operator setting an offline machine).

use crate::outcome::Out;
use azos_idl::{azos_interface, Reader, Wire, Writer};

/// The interface id (ASCII "CLCK").
pub const CLOCK_ID: u32 = 0x434C_434B;

/// [`Clock::sample`]'s answer: the offset will be slewed out.
pub const SLEWED: u32 = 0;
/// ... the wall clock was stepped by the offset.
pub const STEPPED: u32 = 1;
/// ... the sample was not used (a delay out of range, or the first of a step
/// that needs confirming).
pub const FILTERED: u32 = 2;

/// [`Status::state`]: no source has set the clock; `REAL` and `TAI` read like
/// the monotonic clock.
pub const STATE_UNSET: u32 = 0;
/// ... a source set it and the loops keep it.
pub const STATE_SYNCED: u32 = 1;
/// ... the wall clock was seeded from the real-time clock at boot and no
/// reference has measured it yet: `REAL` and `TAI` read the RTC's time, and
/// the first sample is stepped without confirmation (the RTC may be years
/// off).
pub const STATE_SEEDED: u32 = 2;

/// Sources a sample may name (`azos_drv_sys::clockdisc::source`).
pub const SOURCE_NTP: u32 = 1;
pub const SOURCE_PTP: u32 = 2;

/// How the discipline stands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// [`STATE_UNSET`] or [`STATE_SYNCED`].
    pub state: u32,
    /// The source of the latest sample used (0: none yet).
    pub source: u32,
    /// The standing frequency correction, ppb: positive when the counter runs
    /// slow against the reference.
    pub freq_ppb: i64,
    /// The phase not yet slewed out, nanoseconds.
    pub phase_ns: i64,
    /// Steps made since boot.
    pub steps: u32,
    /// Samples filtered or refused since boot.
    pub rejected: u32,
}

impl Wire for Status {
    const WORDS: usize = 6;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.state.put(w);
        self.source.put(w);
        self.freq_ppb.put(w);
        self.phase_ns.put(w);
        self.steps.put(w);
        self.rejected.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let state = u32::get(r);
        let source = u32::get(r);
        let freq_ppb = i64::get(r);
        let phase_ns = i64::get(r);
        let steps = u32::get(r);
        Status { state, source, freq_ppb, phase_ns, steps, rejected: u32::get(r) }
    }
}

#[azos_interface(id = 0x434C_434B, level = 1)]
pub trait Clock {
    /// Offer a measurement: `offset_ns` (reference minus wall clock, signed),
    /// `delay_ns` (the exchange's round trip) and `source` ([`SOURCE_NTP`] or
    /// [`SOURCE_PTP`]; else `BAD_ARGUMENT`). Answers [`SLEWED`], [`STEPPED`] or
    /// [`FILTERED`]; `REFUSED` when the offset is a step the clock will not
    /// make (a clock that was set does not jump by a thousand seconds). A step
    /// is recorded (`Rule::ClockStep`). Needs `WRITE`: it moves time.
    fn sample(&mut self, offset_ns: i64, delay_ns: u64, source: u32) -> Out<u32>;
    /// How the discipline stands. Needs `READ`.
    #[idempotent]
    fn status(&self) -> Out<Status>;
    /// The real-time clock's time, UTC seconds since 1970-01-01. `NO_RESOURCE`
    /// when the machine has no RTC, `NOT_READY` when the chip says its time is
    /// lost (a dead battery, a stopped oscillator), `FAULT` when the bus
    /// failed. Needs `READ`.
    #[idempotent]
    fn rtc_read(&self) -> Out<u64>;
    /// Set the real-time clock to `unix_secs`. The wall clock is not moved
    /// (only a reference does that, through [`Clock::sample`]); the RTC is the
    /// time the next boot starts from. A persistent state change, so it is an
    /// effect (`KIND_CLOCK`): its record is written before the chip is.
    /// `BAD_ARGUMENT` for a time the chip cannot hold (before 1970, past its
    /// last year), `NO_RESOURCE` without an RTC, `FAULT` on a bus failure,
    /// `REFUSED` when the effect gate refuses the record. Needs `WRITE`.
    fn rtc_set(&mut self, unix_secs: u64) -> Out<()>;
}
