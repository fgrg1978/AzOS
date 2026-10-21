// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pixel formats and the drawing surface: pack an RGB triple for a format,
//! fill a rectangle, blit an 8x16 glyph. Pure `core`, so the host tests drive
//! it over a `Vec<u8>`.

use crate::font::{self, CELL_H, CELL_W};

/// How a pixel sits in memory: a little-endian word of `bpp` bits with each
/// colour channel at `shift` and `size` bits wide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PixelFormat {
    pub bpp: u8,
    pub r_shift: u8,
    pub r_size: u8,
    pub g_shift: u8,
    pub g_size: u8,
    pub b_shift: u8,
    pub b_size: u8,
}

impl PixelFormat {
    pub const XRGB8888: Self = Self::new(32, 16, 8, 8, 8, 0, 8);
    pub const XBGR8888: Self = Self::new(32, 0, 8, 8, 8, 16, 8);
    pub const RGB888: Self = Self::new(24, 16, 8, 8, 8, 0, 8);
    pub const RGB565: Self = Self::new(16, 11, 5, 5, 6, 0, 5);

    pub const fn new(bpp: u8, r_shift: u8, r_size: u8, g_shift: u8, g_size: u8, b_shift: u8, b_size: u8) -> Self {
        Self { bpp, r_shift, r_size, g_shift, g_size, b_shift, b_size }
    }

    /// Bytes per pixel.
    pub const fn bytes(&self) -> usize {
        (self.bpp / 8) as usize
    }

    /// 16, 24 or 32 bits with every channel inside the word.
    pub const fn valid(&self) -> bool {
        (self.bpp == 16 || self.bpp == 24 || self.bpp == 32)
            && self.r_shift as u32 + self.r_size as u32 <= self.bpp as u32
            && self.g_shift as u32 + self.g_size as u32 <= self.bpp as u32
            && self.b_shift as u32 + self.b_size as u32 <= self.bpp as u32
            && self.r_size <= 8 && self.g_size <= 8 && self.b_size <= 8
    }

    /// The device-tree `simple-framebuffer` `format` strings.
    pub fn from_dt(name: &[u8]) -> Option<Self> {
        let name = match name.iter().position(|&b| b == 0) {
            Some(n) => &name[..n],
            None => name,
        };
        Some(match name {
            b"a8r8g8b8" | b"x8r8g8b8" => Self::XRGB8888,
            b"a8b8g8r8" | b"x8b8g8r8" => Self::XBGR8888,
            b"r8g8b8" => Self::RGB888,
            b"r5g6b5" => Self::RGB565,
            _ => return None,
        })
    }

    /// The pixel word for an 8-bit-per-channel colour.
    pub const fn pack(&self, r: u8, g: u8, b: u8) -> u32 {
        chan(r, self.r_shift, self.r_size) | chan(g, self.g_shift, self.g_size) | chan(b, self.b_shift, self.b_size)
    }
}

/// One 8-bit channel reduced to `size` bits and placed at `shift`.
const fn chan(v: u8, shift: u8, size: u8) -> u32 {
    if size == 0 { 0 } else { ((v as u32) >> (8 - size as u32)) << shift }
}

/// A mapped framebuffer to draw on.
#[derive(Clone, Copy)]
pub struct Surface {
    pub base: *mut u8,
    pub width: usize,
    pub height: usize,
    /// Bytes per row.
    pub stride: usize,
    pub fmt: PixelFormat,
}

impl Surface {
    /// Bytes the surface covers (the last row may be shorter than a stride).
    pub fn len(&self) -> usize {
        if self.height == 0 { 0 } else { (self.height - 1) * self.stride + self.width * self.fmt.bytes() }
    }

    /// Write `n` pixels of colour `px` starting at (`x`, `y`), clipped to the
    /// surface. `row` is a scratch the caller builds once per call.
    fn put_row(&self, x: usize, y: usize, pixels: &[u32]) {
        if y >= self.height || x >= self.width {
            return;
        }
        let n = pixels.len().min(self.width - x);
        let bpp = self.fmt.bytes();
        let mut row = [0u8; CELL_W * 4];
        let n = n.min(CELL_W);
        for (i, &p) in pixels[..n].iter().enumerate() {
            let b = p.to_le_bytes();
            row[i * bpp..(i + 1) * bpp].copy_from_slice(&b[..bpp]);
        }
        // SAFETY: (x, y) is inside the surface and `n` pixels stay inside the
        // row, so the copy lies within `len()` bytes of `base`, which the
        // creator of the `Surface` promised is writable.
        unsafe {
            core::ptr::copy_nonoverlapping(row.as_ptr(), self.base.add(y * self.stride + x * bpp), n * bpp);
        }
    }

    /// Fill the rectangle with `px`, clipped.
    pub fn fill_rect(&self, x: usize, y: usize, w: usize, h: usize, px: u32) {
        let row = [px; CELL_W];
        let mut yy = y;
        while yy < (y + h).min(self.height) {
            let mut xx = x;
            while xx < (x + w).min(self.width) {
                let n = ((x + w).min(self.width) - xx).min(CELL_W);
                self.put_row(xx, yy, &row[..n]);
                xx += CELL_W;
            }
            yy += 1;
        }
    }

    /// Draw `ch` in the 8x16 cell whose top-left pixel is (`x`, `y`).
    pub fn draw_glyph(&self, x: usize, y: usize, ch: u8, fg: u32, bg: u32) {
        let g = font::glyph(ch);
        for (r, &bits) in g.iter().enumerate().take(CELL_H) {
            let mut row = [bg; CELL_W];
            for (c, p) in row.iter_mut().enumerate() {
                if bits & (0x80 >> c) != 0 {
                    *p = fg;
                }
            }
            self.put_row(x, y + r, &row);
        }
    }
}
