// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Where pixels are read from and written to, as rows of bytes.
//!
//! The compositor never sees an address range. A display surface is a set of
//! bands (separate memory objects that each hold whole rows,
//! `azos_devif::display`) and a client's image may be too, so a [`Sink`] and a
//! [`Source`] answer one ROW at a time and the server decides what is behind
//! a row. [`Image`] and [`ImageMut`] are the plain case: one slice.

use crate::pixel::Format;

/// An image the compositor reads: a client's buffer.
pub trait Source {
    /// Pixels per row.
    fn width(&self) -> u32;
    /// Rows.
    fn height(&self) -> u32;
    fn format(&self) -> Format;
    /// Row `y`: at least `width * bytes` bytes, `None` when it cannot be read.
    fn row(&self, y: u32) -> Option<&[u8]>;
}

/// The image the compositor writes: a display surface.
pub trait Sink {
    fn format(&self) -> Format;
    /// Row `y`: at least the output's `width * bytes` bytes, `None` when it
    /// cannot be written (a band that is not attached). A frame counts it in
    /// [`crate::Frame::missing`].
    fn row_mut(&mut self, y: u32) -> Option<&mut [u8]>;
}

/// The size a row slice must have: `None` when the geometry is not one an
/// image can have (an empty side, a row shorter than its pixels, a slice that
/// does not reach the last pixel).
fn check(len: usize, width: u32, height: u32, stride: usize, format: Format) -> Option<usize> {
    let row = (width as usize).checked_mul(format.bytes())?;
    if width == 0 || height == 0 || stride < row {
        return None;
    }
    let need = (height as usize - 1).checked_mul(stride)?.checked_add(row)?;
    if len < need { None } else { Some(row) }
}

/// One slice as a [`Source`].
#[derive(Clone, Copy)]
pub struct Image<'a> {
    data: &'a [u8],
    width: u32,
    height: u32,
    stride: usize,
    format: Format,
    row_bytes: usize,
}

impl<'a> Image<'a> {
    /// `data` holds `height` rows of `width` pixels, `stride` bytes apart.
    pub fn new(data: &'a [u8], width: u32, height: u32, stride: usize, format: Format) -> Option<Image<'a>> {
        let row_bytes = check(data.len(), width, height, stride, format)?;
        Some(Image { data, width, height, stride, format, row_bytes })
    }
}

impl Source for Image<'_> {
    fn width(&self) -> u32 {
        self.width
    }
    fn height(&self) -> u32 {
        self.height
    }
    fn format(&self) -> Format {
        self.format
    }
    fn row(&self, y: u32) -> Option<&[u8]> {
        if y >= self.height {
            return None;
        }
        let at = y as usize * self.stride;
        self.data.get(at..at + self.row_bytes)
    }
}

/// One slice as a [`Sink`].
pub struct ImageMut<'a> {
    data: &'a mut [u8],
    height: u32,
    stride: usize,
    format: Format,
    row_bytes: usize,
}

impl<'a> ImageMut<'a> {
    /// `data` holds `height` rows of `width` pixels, `stride` bytes apart.
    pub fn new(data: &'a mut [u8], width: u32, height: u32, stride: usize, format: Format) -> Option<ImageMut<'a>> {
        let row_bytes = check(data.len(), width, height, stride, format)?;
        Some(ImageMut { data, height, stride, format, row_bytes })
    }
}

impl Sink for ImageMut<'_> {
    fn format(&self) -> Format {
        self.format
    }
    fn row_mut(&mut self, y: u32) -> Option<&mut [u8]> {
        if y >= self.height {
            return None;
        }
        let at = y as usize * self.stride;
        self.data.get_mut(at..at + self.row_bytes)
    }
}
