// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The two pixel formats the compositor composes into and out of, and the
//! 8-bit-per-channel colour they meet in.
//!
//! A colour in flight is a `u32` `0x00RRGGBB`. [`FORMAT_XRGB8888`] stores it as
//! a little-endian word (blue in the first byte); [`FORMAT_RGB565`] drops the
//! low bits of each channel and widens them back by replicating the high
//! bits, so a 565 pixel read and written back is the same pixel and white
//! stays white.
//!
//! [`FORMAT_XRGB8888`]: azos_devif::display::FORMAT_XRGB8888
//! [`FORMAT_RGB565`]: azos_devif::display::FORMAT_RGB565

use azos_devif::display::{FORMAT_RGB565, FORMAT_XRGB8888};

/// A pixel format the compositor handles. The Display interface names two
/// more (`XBGR8888`, `RGB888`); a scanout in one of those is not composed
/// ([`Format::from_display`] answers `None`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Xrgb8888,
    Rgb565,
}

impl Format {
    /// The format a `FORMAT_*` value of the Display interface names.
    pub const fn from_display(format: u32) -> Option<Format> {
        match format {
            FORMAT_XRGB8888 => Some(Format::Xrgb8888),
            FORMAT_RGB565 => Some(Format::Rgb565),
            _ => None,
        }
    }

    /// Bytes per pixel.
    pub const fn bytes(self) -> usize {
        match self {
            Format::Xrgb8888 => 4,
            Format::Rgb565 => 2,
        }
    }

    /// The pixel at the start of `px` as `0x00RRGGBB`. `px` holds at least
    /// [`Format::bytes`] bytes.
    pub fn load(self, px: &[u8]) -> u32 {
        match self {
            Format::Xrgb8888 => Xrgb::load(px),
            Format::Rgb565 => Rgb565::load(px),
        }
    }

    /// Write `rgb` (`0x00RRGGBB`) as the pixel at the start of `px`.
    pub fn store(self, px: &mut [u8], rgb: u32) {
        match self {
            Format::Xrgb8888 => Xrgb::store(px, rgb),
            Format::Rgb565 => Rgb565::store(px, rgb),
        }
    }
}

/// A format as a type, so that a row loop is compiled once per pair of
/// formats and carries no per-pixel `match`.
pub(crate) trait Px {
    const BYTES: usize;
    fn load(px: &[u8]) -> u32;
    fn store(px: &mut [u8], rgb: u32);
}

pub(crate) struct Xrgb;
pub(crate) struct Rgb565;

impl Px for Xrgb {
    const BYTES: usize = 4;
    #[inline(always)]
    fn load(px: &[u8]) -> u32 {
        u32::from_le_bytes([px[0], px[1], px[2], px[3]]) & 0x00FF_FFFF
    }
    #[inline(always)]
    fn store(px: &mut [u8], rgb: u32) {
        px[..4].copy_from_slice(&(rgb & 0x00FF_FFFF).to_le_bytes());
    }
}

impl Px for Rgb565 {
    const BYTES: usize = 2;
    #[inline(always)]
    fn load(px: &[u8]) -> u32 {
        let v = u16::from_le_bytes([px[0], px[1]]) as u32;
        let (r, g, b) = (v >> 11, (v >> 5) & 0x3F, v & 0x1F);
        ((r << 3 | r >> 2) << 16) | ((g << 2 | g >> 4) << 8) | (b << 3 | b >> 2)
    }
    #[inline(always)]
    fn store(px: &mut [u8], rgb: u32) {
        let (r, g, b) = ((rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF);
        let v = ((r >> 3) << 11 | (g >> 2) << 5 | b >> 3) as u16;
        px[..2].copy_from_slice(&v.to_le_bytes());
    }
}

/// `round(t / 255)` for `t` up to 255 * 255, with no division.
#[inline(always)]
const fn div255(t: u32) -> u32 {
    (t + 128 + ((t + 128) >> 8)) >> 8
}

/// `src` over `dst` with coverage `a` (0..=255), per channel, both `0x00RRGGBB`.
#[inline(always)]
pub fn mix(src: u32, dst: u32, a: u32) -> u32 {
    let ch = |shift: u32| {
        let s = (src >> shift) & 0xFF;
        let d = (dst >> shift) & 0xFF;
        div255(s * a + d * (255 - a))
    };
    ch(16) << 16 | ch(8) << 8 | ch(0)
}
