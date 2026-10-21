// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Adc` interface: one channel of an analog-to-digital converter.
//!
//! The endpoint's badge is the channel (`endpoint = "adc.2"`): the capability
//! names the input, so the task that holds the battery divider cannot read the
//! analog sensor next to it. Every op observes except `set_rate`, which
//! retunes the converter every channel shares and needs `EXEC`.
//!
//! **A stream of samples is a ring, not a series of calls.** `read` is the
//! one-shot. A task that wants samples at the converter's rate hands the
//! driver the producer end of a queue (`start_batch`: the client first
//! attenuates its own queue to a write-only copy, and moves that copy) and
//! reads [`Record`]s from its own end with no further call. A sample the ring
//! had no room for is dropped, counted, and flagged on the next record that
//! does fit ([`RECORD_LOST`]), so a consumer sees the gap.

use crate::outcome::Out;
use azos_idl::{azos_interface, Cap, Reader, Wire, Writer};

/// The interface id (ASCII "ADC ").
pub const ADC_ID: u32 = 0x4144_4320;

/// Channels the interface can name (the ABI maximum; a converter has the
/// channels of its part, and the driver refuses the others).
pub const CHANNELS: u32 = 8;
/// Fastest sample rate the interface names, Hz.
pub const RATE_MAX_HZ: u32 = 1_000_000;

/// What a `Cap<SampleQueue>` names: a queue of [`Record`]s, the driver its
/// producer.
pub struct SampleQueue;

/// A one-shot reading.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reading {
    /// The converter's signed code.
    pub raw: i32,
    /// The same, in millivolts at the input, at the current gain.
    pub mv: i32,
}

impl Wire for Reading {
    const WORDS: usize = 2;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.raw.put(w);
        self.mv.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        Reading { raw: i32::get(r), mv: i32::get(r) }
    }
}

/// Bytes of one slot of a sample queue.
pub const RECORD_BYTES: usize = 16;
/// `Record::flags`: samples were dropped before this one.
pub const RECORD_LOST: u8 = 1;

/// One slot of a sample queue.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Record {
    /// When the sample was taken, nanoseconds on the vDSO clock.
    pub acq_ns: u64,
    pub mv: i32,
    pub raw: i16,
    pub channel: u8,
    /// `RECORD_*`.
    pub flags: u8,
}

impl Record {
    /// The slot's bytes, little-endian.
    pub fn encode(&self) -> [u8; RECORD_BYTES] {
        let mut b = [0u8; RECORD_BYTES];
        b[0..8].copy_from_slice(&self.acq_ns.to_le_bytes());
        b[8..12].copy_from_slice(&self.mv.to_le_bytes());
        b[12..14].copy_from_slice(&self.raw.to_le_bytes());
        b[14] = self.channel;
        b[15] = self.flags;
        b
    }

    /// The record a slot holds.
    pub fn decode(b: &[u8; RECORD_BYTES]) -> Record {
        Record {
            acq_ns: u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            mv: i32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            raw: i16::from_le_bytes([b[12], b[13]]),
            channel: b[14],
            flags: b[15],
        }
    }
}

/// The producer end of a sample queue, as the host resolved the handle the
/// client moved. `true` when the record fit.
pub trait RecordSink {
    fn push(&mut self, record: &Record) -> bool;
}

/// The schedule of one batch: when the next sample is due, how many are left,
/// what was delivered and what was lost. Pure arithmetic over the host's
/// clock, so every converter's driver paces a batch the same way.
#[derive(Clone, Copy, Debug)]
pub struct Batch {
    active: bool,
    /// Samples still to take; `u32::MAX` = until stopped.
    left: u32,
    period_ns: u64,
    /// `None`: the first sample, due as soon as the host asks.
    next_ns: Option<u64>,
    delivered: u32,
    lost_pending: bool,
}

impl Batch {
    /// No batch running.
    pub const fn idle() -> Batch {
        Batch { active: false, left: 0, period_ns: 0, next_ns: None, delivered: 0, lost_pending: false }
    }

    /// Start a batch of `count` samples (0 = until stopped) at `rate_hz`
    /// (1..=[`RATE_MAX_HZ`]); the first is due at the host's next look, and
    /// the period counts from it.
    pub fn start(&mut self, rate_hz: u32, count: u32) {
        *self = Batch {
            active: true,
            left: if count == 0 { u32::MAX } else { count },
            period_ns: 1_000_000_000 / rate_hz.clamp(1, RATE_MAX_HZ) as u64,
            next_ns: None,
            delivered: 0,
            lost_pending: false,
        };
    }

    /// Is a batch running?
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Is a sample due at `now_ns`?
    pub fn due(&self, now_ns: u64) -> bool {
        self.active && self.next_ns.map_or(true, |n| now_ns >= n)
    }

    /// When the next sample is due (0: at once); `None` when no batch runs.
    /// The host sleeps until then.
    pub fn next_due_ns(&self) -> Option<u64> {
        self.active.then(|| self.next_ns.unwrap_or(0))
    }

    /// The sample due now was taken at `now_ns`: build its record, flagged
    /// when samples were lost before it.
    pub fn record(&mut self, now_ns: u64, channel: u8, raw: i16, mv: i32) -> Record {
        let flags = if core::mem::take(&mut self.lost_pending) { RECORD_LOST } else { 0 };
        Record { acq_ns: now_ns, mv, raw, channel, flags }
    }

    /// The sample due now is done: `delivered` is whether the ring took it.
    /// The next one is due a period after this one was due; a host that woke
    /// late skips the periods it missed (they are lost), it does not burst.
    pub fn done(&mut self, now_ns: u64, delivered: bool) {
        if delivered {
            self.delivered = self.delivered.wrapping_add(1);
        } else {
            self.lost_pending = true;
        }
        if self.left != u32::MAX {
            self.left -= 1;
            if self.left == 0 {
                self.active = false;
                return;
            }
        }
        let mut next = self.next_ns.unwrap_or(now_ns) + self.period_ns;
        if next <= now_ns {
            let missed = (now_ns - next) / self.period_ns.max(1) + 1;
            next += missed * self.period_ns;
            self.lost_pending = true;
        }
        self.next_ns = Some(next);
    }

    /// Stop; the samples the ring took.
    pub fn stop(&mut self) -> u32 {
        let n = self.delivered;
        self.active = false;
        n
    }
}

#[azos_interface(id = 0x4144_4320, level = 1)]
pub trait Adc {
    /// Convert the channel once. `NOT_READY` while the converter is not
    /// initialized, `FAULT` when the bus under it failed, `NO_RESOURCE` for a
    /// channel the part does not have. Needs `READ`.
    #[idempotent]
    fn read(&mut self) -> Out<Reading>;
    /// Set the sample rate to the converter's nearest rate at or above `hz`
    /// (1..=[`RATE_MAX_HZ`], else `BAD_ARGUMENT`); the value is the rate set.
    /// `UNSUPPORTED` when the converter is slower than `hz`. Needs `EXEC`.
    #[idempotent]
    fn set_rate(&mut self, hz: u32) -> Out<u32>;
    /// The sample rate in force, Hz. Needs `READ`.
    #[idempotent]
    fn rate(&self) -> Out<u32>;
    /// Take `count` samples (0 = until `stop_batch`) at the sample rate into
    /// `queue`, the producer end the client moves. `BUSY` while a batch runs.
    /// Needs `READ`.
    #[at_most_once]
    fn start_batch(&mut self, queue: Cap<SampleQueue>, count: u32) -> Out<()>;
    /// Stop the batch; the value is how many samples the queue took. Needs
    /// `READ`.
    #[idempotent]
    fn stop_batch(&mut self) -> Out<u32>;
}
