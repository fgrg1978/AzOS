// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of `beep`'s arithmetic (`userspace/services/toolbox/src/beep.rs`):
//! the argument, the length of the tone in periods, the tone, the sizing of the
//! queues and the report. The flow over the `Sound` interface is
//! `tests/host/syscall-tests` (`sound_guards`) and the gate's QEMU row.
//!
//! Each test names its canary: the one-line change to `beep.rs` that must turn
//! it red.

use super::beep::*;

/// Frames of a period that carry a tone, 48 kHz.
const RATE: u32 = 48_000;

fn tone_of(ms: u32) -> (Plan, Vec<i16>) {
    let plan = Plan::new(RATE, PERIOD_FRAMES, ms);
    let mut tone = Tone::new(&plan, FREQ_HZ);
    let mut samples = Vec::new();
    for n in 0..plan.periods() {
        let frames = plan.frames_of(n);
        let mut out = vec![0u8; PERIOD_FRAMES as usize * 4];
        tone.fill(&mut out, frames, 2);
        for f in 0..frames as usize {
            let l = i16::from_le_bytes([out[f * 4], out[f * 4 + 1]]);
            let r = i16::from_le_bytes([out[f * 4 + 2], out[f * 4 + 3]]);
            assert_eq!(l, r, "both channels carry the same sample");
            samples.push(l);
        }
    }
    (plan, samples)
}

/// The argument is a whole number of milliseconds in range, or nothing.
///
/// **Canary.** Accept 0 (`(0..=MS_MAX)`): the zero-length row goes red.
#[test]
fn the_argument_is_milliseconds_in_range_or_nothing() {
    assert_eq!(parse_ms(None), Some(MS_DEFAULT));
    assert_eq!(parse_ms(Some(b"1")), Some(1));
    assert_eq!(parse_ms(Some(b"250")), Some(250));
    assert_eq!(parse_ms(Some(b"5000")), Some(MS_MAX));
    for bad in [&b""[..], b"0", b"5001", b"99999", b"-1", b"1x", b" 5", b"1.5", b"123456"] {
        assert_eq!(parse_ms(Some(bad)), None, "{:?}", core::str::from_utf8(bad));
    }
}

/// The periods of a tone add up to its frames: whole periods, then what is left,
/// and nothing after the last.
///
/// **Canary.** Round the period count down (`div_ceil` -> `/`): the short last
/// period is dropped and the sum is short.
#[test]
fn the_periods_of_a_tone_add_up_to_its_frames() {
    for ms in [1, 21, 22, 250, 1000, 5000] {
        let plan = Plan::new(RATE, PERIOD_FRAMES, ms);
        let sum: u64 = (0..plan.periods()).map(|n| u64::from(plan.frames_of(n))).sum();
        assert_eq!(sum, plan.total_frames, "{ms} ms");
        assert_eq!(plan.total_frames, u64::from(RATE) * u64::from(ms) / 1000, "{ms} ms");
        assert_eq!(plan.frames_of(plan.periods()), 0, "nothing past the end");
        let last = plan.frames_of(plan.periods() - 1);
        assert!((1..=PERIOD_FRAMES).contains(&last), "{ms} ms: the last period has {last}");
        for n in 0..plan.periods() - 1 {
            assert_eq!(plan.frames_of(n), PERIOD_FRAMES, "every period before the last is whole");
        }
    }
    // A tone shorter than a frame is still one.
    assert_eq!(Plan::new(8_000, PERIOD_FRAMES, 1).total_frames, 8);
    assert_eq!(Plan::new(1, PERIOD_FRAMES, 1).total_frames, 1);
}

/// The tone is the pitch asked for: a sine has two zero crossings a cycle.
///
/// **Canary.** Double the phase step (`<< 32` -> `<< 33`): 880 Hz, the count
/// doubles.
#[test]
fn the_tone_has_the_pitch_it_was_asked() {
    let (_, s) = tone_of(1000);
    assert_eq!(s.len(), RATE as usize);
    // Sign changes between non-zero samples (the fades start and end on zeros).
    let mut crossings = 0;
    let mut last = 0i16;
    for v in s.iter().copied().filter(|v| *v != 0) {
        crossings += usize::from(last != 0 && (last < 0) != (v < 0));
        last = v;
    }
    // 440 cycles in a second, two crossings each, +- the fades and the rounding.
    assert!((870..=890).contains(&crossings), "{crossings} zero crossings");
}

/// The tone is a bounded sine that fades in and out: it never exceeds the
/// amplitude, begins and ends at silence, and reaches the amplitude between.
///
/// **Canary.** Drop the ramp (`/ RAMP_FRAMES as i64` and its factor): the first
/// sample is no longer silent.
#[test]
fn the_tone_is_bounded_and_fades_in_and_out() {
    let (plan, s) = tone_of(250);
    assert_eq!(s.len() as u64, plan.total_frames);
    let peak = s.iter().map(|v| i64::from(*v).abs()).max().unwrap();
    assert!(peak <= AMPLITUDE, "peak {peak}");
    assert!(peak >= AMPLITUDE * 95 / 100, "peak {peak}: the tone reaches its level");
    assert_eq!(s[0], 0, "begins at silence");
    assert_eq!(s[s.len() - 1], 0, "ends at silence");
    // The fade is gentle: the first RAMP_FRAMES samples stay under the level
    // the ramp allows.
    for (i, v) in s.iter().take(RAMP_FRAMES as usize).enumerate() {
        assert!(i64::from(*v).abs() <= AMPLITUDE * i as i64 / RAMP_FRAMES as i64 + 1, "frame {i}: {v}");
    }
}

/// A short last period leaves the rest of the buffer silent, and a mono tone
/// has one sample a frame.
///
/// **Canary.** Skip the `out.fill(0)`: a reused period keeps the old tone past
/// the new frames.
#[test]
fn a_short_period_leaves_silence_after_it() {
    let plan = Plan::new(RATE, PERIOD_FRAMES, 250);
    let mut tone = Tone::new(&plan, FREQ_HZ);
    let mut out = vec![0x55u8; 64 * 2];
    tone.fill(&mut out, 10, 1);
    assert!(out[20..].iter().all(|b| *b == 0), "everything after the 10 frames is silence");
    assert!(out[..20].iter().any(|b| *b != 0x55), "the frames were written");
}

/// The sine is odd and bounded by a quarter of the 32-bit turn.
///
/// **Canary.** Use `x * (HALF + x.abs())`: the peak overshoots 2^30.
#[test]
fn the_sine_is_odd_and_peaks_at_a_quarter_turn() {
    assert_eq!(sine(0), 0);
    assert_eq!(sine(1 << 30), 1 << 30, "a quarter turn is the peak");
    assert_eq!(sine(3 << 30), -(1 << 30), "three quarters is the trough");
    for p in (0..u32::MAX / 2).step_by(997_001) {
        // The shift rounds down: the two halves differ by at most one.
        assert!((sine(p) + sine(p.wrapping_neg())).abs() <= 1, "odd at {p}");
        assert!(sine(p).abs() <= 1 << 30);
    }
}

/// The queue holds the slots the kernel finds in its region (its `slots_for`:
/// the most a power of two fits after the 256-byte header), and a page holds the
/// periods and the end marker with room to spare on every granule.
///
/// **Canary.** Count the header out (`checked_sub(RING_SLOTS)` -> `Some`): a
/// region of exactly two slots' bytes claims two slots it does not hold.
#[test]
fn the_queue_has_the_slots_the_kernel_finds_in_its_region() {
    let words = azos_devif::sound::SLOT_WORDS;
    assert_eq!(queue_slots(4096, words), Some(64));
    assert_eq!(queue_slots(16384, words), Some(256));
    assert_eq!(queue_slots(65536, words), Some(1024));
    assert_eq!(queue_slots(256 + 2 * 32, words), Some(2));
    assert_eq!(queue_slots(256 + 2 * 32 - 1, words), None);
    assert_eq!(queue_slots(256, words), None);
    assert_eq!(queue_slots(100, words), None);
    for page in [4096, 16384, 65536] {
        let slots = queue_slots(page, words).unwrap();
        assert!(slots.is_power_of_two());
        assert!(azos_rings::region::SpscSlots::<4>::bytes(slots) <= page);
        assert!(slots >= (PERIODS + 1).next_power_of_two(), "{page}: the periods and the end marker fit");
    }
}

/// Every outcome has its own words, and the report names the counts.
///
/// **Canary.** Map `BUSY` to the default text: the distinct-text check goes red.
#[test]
fn the_outcomes_and_the_report_have_their_words() {
    use azos_devif::outcome::*;
    let codes = [DENIED, BAD_ARGUMENT, NOT_READY, FAULT, UNSUPPORTED, BUSY, NO_RESOURCE, REFUSED, NO_SERVER];
    for (i, a) in codes.iter().enumerate() {
        for b in &codes[i + 1..] {
            assert_ne!(why(*a), why(*b), "{a} and {b}");
        }
        assert_ne!(why(*a), why(0xFFFF), "{a} has a text of its own");
    }
    let mut s = String::new();
    write_report(&mut s, 12, 12, 11_900, 48_000, 2, 0).unwrap();
    assert_eq!(s, "beep: 12 of 12 periods played (11900 frames, 48000 Hz, 2 ch, 0 xruns)\n");
}
