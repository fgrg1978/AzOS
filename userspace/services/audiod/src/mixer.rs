// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The mix: signed 16-bit PCM from several streams summed into the one device
//! period.
//!
//! No system call, no allocation and no floating point (the image runs on
//! cores with none), so a host test pulls this file in with `#[path]`
//! (`tests/host/audiod-tests`). A mix pass is `clear`, one [`accumulate`] per
//! stream that has samples for the pass, then [`finish`]: the sum is held in
//! 32 bits, so any number of streams adds without wrapping, and it is clamped
//! to the 16-bit range once, at the end. **A mix saturates; it never wraps**:
//! two loud streams are a flat top, not a click of the opposite sign.
//!
//! A stream's gain is Q15 ([`GAIN_UNITY`] is 1.0). The server sets it from
//! [`headroom_gain`] as streams come and go, so the sum of several streams
//! has room before it clips.

/// Gain of 1.0, Q15.
pub const GAIN_UNITY: u32 = 1 << 15;

/// Samples one mix pass can hold (`period_frames * channels`). A device whose
/// period would be longer is run with a shorter one.
pub const ACC_MAX: usize = 8192;

/// The gain each of `live` streams is mixed at: 1.0 alone, and `2 / (n + 1)`
/// with `n` live streams (2/3, 1/2, 2/5, ...). The sum of `n` equal streams
/// is then `2n / (n + 1)` of one stream's full scale: under 2.0 however many
/// there are, and for two streams of the same level 1.33, which a saturating
/// mix clips only when both are near full scale.
pub const fn headroom_gain(live: usize) -> u32 {
    if live <= 1 {
        GAIN_UNITY
    } else {
        2 * GAIN_UNITY / (live as u32 + 1)
    }
}

/// Add `pcm` (little-endian signed 16-bit samples) times `gain` into `acc`,
/// from `acc[0]`. Samples past either end are not touched: a source shorter
/// than the pass leaves the rest of it as the other sources made it (silence
/// from this one: an underrun is not an error here). `gain` above
/// [`GAIN_UNITY`] is taken as unity: a stream is never louder than it was
/// written.
pub fn accumulate(acc: &mut [i32], pcm: &[u8], gain: u32) {
    let g = i32::try_from(gain.min(GAIN_UNITY)).unwrap_or(1 << 15);
    for (a, s) in acc.iter_mut().zip(pcm.chunks_exact(2)) {
        let v = i32::from(i16::from_le_bytes([s[0], s[1]]));
        *a += (v * g) >> 15;
    }
}

/// Write `acc` into `out` as little-endian signed 16-bit samples, clamped to
/// the 16-bit range. `out` is written for `min(acc.len(), out.len() / 2)`
/// samples; the rest of `out` is left as it was.
pub fn finish(acc: &[i32], out: &mut [u8]) {
    for (a, o) in acc.iter().zip(out.chunks_exact_mut(2)) {
        let v = (*a).clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
        o.copy_from_slice(&v.to_le_bytes());
    }
}

/// One source of [`mix`].
#[cfg(test)]
#[derive(Clone, Copy)]
pub struct Source<'a> {
    pub pcm: &'a [u8],
    pub gain: u32,
}

/// `out` = the saturating sum of `sources`, each at its gain: [`accumulate`]
/// and [`finish`] for a caller that has all its sources at once (the tests; the
/// server mixes a stream at a time into its own pass).
#[cfg(test)]
pub fn mix(out: &mut [u8], sources: &[Source<'_>]) {
    let mut acc = [0i32; 512];
    let mut at = 0usize;
    while at + 1 < out.len() {
        let n = ((out.len() - at) / 2).min(acc.len());
        acc[..n].fill(0);
        for s in sources {
            if s.pcm.len() > at {
                accumulate(&mut acc[..n], &s.pcm[at..], s.gain);
            }
        }
        finish(&acc[..n], &mut out[at..at + 2 * n]);
        at += 2 * n;
    }
}
