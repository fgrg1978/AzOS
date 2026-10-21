// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `beep [MS]`: a short tone on the kernel's sound device.
//!
//! This file is the arithmetic and the text of the tool, with no system call in
//! it, so a host test can pull it in with `#[path]` (`tests/host/drivers-tests`,
//! `beep_tests.rs`): how long the tone is in periods, the tone itself (a sine
//! in integer arithmetic: the image runs on cores with no floating point), the
//! size of the queues the kernel will accept, and the words of the report.
//! `sound.rs` is the flow over `Sound`: it makes the three objects, opens a
//! playback stream, posts the periods, drains it and counts what came back.

use azos_devif::outcome;
use core::fmt::{self, Write};

/// The pitch, Hz (concert A).
pub const FREQ_HZ: u32 = 440;
/// Longest tone `beep MS` asks for, milliseconds.
pub const MS_MAX: u32 = 5_000;
/// The tone when no length is given, milliseconds.
pub const MS_DEFAULT: u32 = 250;
/// Frames of one period: 21 ms at 48 kHz, a period of 4 KiB in stereo S16.
pub const PERIOD_FRAMES: u32 = 1024;
/// Periods in the arena: the one playing, the ones queued behind it, and room to post.
pub const PERIODS: u32 = 4;
/// Peak of the tone, of 32767.
pub const AMPLITUDE: i64 = 9_000;
/// Frames the tone fades in and out over, so it begins and ends without a click.
pub const RAMP_FRAMES: u64 = 96;

/// `beep`'s argument: the length in milliseconds, 1 to [`MS_MAX`]; no argument
/// is [`MS_DEFAULT`]. `None` for anything that is not such a number.
pub fn parse_ms(arg: Option<&[u8]>) -> Option<u32> {
    let Some(a) = arg else { return Some(MS_DEFAULT) };
    if a.is_empty() || a.len() > 5 {
        return None;
    }
    let mut v = 0u32;
    for &c in a {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u32::from(c - b'0');
    }
    (1..=MS_MAX).contains(&v).then_some(v)
}

/// How long the tone is, in frames and in periods of `period_frames`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub rate_hz: u32,
    pub period_frames: u32,
    pub total_frames: u64,
}

impl Plan {
    /// A tone of `ms` milliseconds at `rate_hz` (at least one frame).
    pub fn new(rate_hz: u32, period_frames: u32, ms: u32) -> Plan {
        Plan { rate_hz, period_frames, total_frames: (u64::from(rate_hz) * u64::from(ms) / 1000).max(1) }
    }

    /// Periods the tone takes: the last one may be short.
    pub fn periods(&self) -> u32 {
        self.total_frames.div_ceil(u64::from(self.period_frames)) as u32
    }

    /// Frames of period number `n` of the tone (counted from 0 in the order
    /// they are played): a whole period, or what is left for the last one;
    /// 0 past the end.
    pub fn frames_of(&self, n: u32) -> u32 {
        let start = u64::from(n) * u64::from(self.period_frames);
        self.total_frames.saturating_sub(start).min(u64::from(self.period_frames)) as u32
    }
}

/// `sin` of a phase, `phase` being a turn in 32 bits: -2^30..=2^30 (a quarter
/// of the 32-bit range either way), by the parabola `4x(1 - |x|)`. Its error
/// is under 6%, which for a beep is a tone with a few harmonics.
pub fn sine(phase: u32) -> i64 {
    const HALF: i64 = 1 << 31;
    let x = i64::from(phase as i32);
    (4 * x * (HALF - x.abs())) >> 32
}

/// The tone as signed 16-bit frames.
#[derive(Clone, Copy, Debug)]
pub struct Tone {
    phase: u32,
    step: u32,
    played: u64,
    total: u64,
}

impl Tone {
    /// The tone of `plan` at `freq_hz`.
    pub fn new(plan: &Plan, freq_hz: u32) -> Tone {
        let step = (u64::from(freq_hz) << 32) / u64::from(plan.rate_hz.max(1));
        Tone { phase: 0, step: step as u32, played: 0, total: plan.total_frames }
    }

    /// The next `frames` frames into `out` (`channels` interleaved samples of 2
    /// bytes each, little endian). `out` is `frames * channels * 2` bytes or
    /// more; the rest of it is silence.
    pub fn fill(&mut self, out: &mut [u8], frames: u32, channels: u32) {
        let frame_bytes = channels as usize * 2;
        out.fill(0);
        for f in 0..frames as usize {
            let into = self.played;
            let left = self.total.saturating_sub(into + 1);
            let ramp = into.min(left).min(RAMP_FRAMES) as i64;
            // `sine` is within +-2^30 of a unit of 2^30: 2^30 is full scale.
            let v = (sine(self.phase) * AMPLITUDE >> 30) * ramp / RAMP_FRAMES as i64;
            let s = (v as i16).to_le_bytes();
            for c in 0..channels as usize {
                let at = f * frame_bytes + c * 2;
                out[at..at + 2].copy_from_slice(&s);
            }
            self.phase = self.phase.wrapping_add(self.step);
            self.played += 1;
        }
    }
}

/// The slots of a ring the kernel finds in a region of `bytes` bytes: the most
/// a power of two the region holds after the 256-byte header (the same rule as
/// the kernel's `slots_for`, which sizes its end of the queue the same way).
/// `None` below two.
pub fn queue_slots(bytes: usize, slot_words: usize) -> Option<u32> {
    let room = bytes.checked_sub(azos_rings::region::RING_SLOTS)? / (slot_words * 8);
    if room < 2 {
        return None;
    }
    Some(1u32 << (usize::BITS - 1 - room.leading_zeros()).min(31))
}

/// Why an op of the `Sound` interface answered `code`.
pub fn why(code: u32) -> &'static str {
    match code {
        outcome::DENIED => "the sound endpoint refused (rights or containment)",
        outcome::NOT_READY => "no sound device",
        outcome::NO_RESOURCE => "no such sound device",
        outcome::BUSY => "the sound device is in use",
        outcome::UNSUPPORTED => "the device cannot play this stream",
        outcome::BAD_ARGUMENT => "the stream was refused as malformed",
        outcome::REFUSED => "refused",
        outcome::FAULT => "the sound device failed",
        outcome::NO_SERVER => "the call did not reach the kernel's sound interface",
        _ => "the sound interface failed the call",
    }
}

/// The one line `beep` prints when the tone has played.
pub fn write_report(w: &mut dyn Write, played: u32, wanted: u32, frames: u64, rate_hz: u32, channels: u32, xruns: u32) -> fmt::Result {
    writeln!(w, "beep: {} of {} periods played ({} frames, {} Hz, {} ch, {} xruns)", played, wanted, frames, rate_hz, channels, xruns)
}
