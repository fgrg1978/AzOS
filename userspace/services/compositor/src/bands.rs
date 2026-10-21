// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The display surface as bands: how many, and the rows behind each.
//!
//! A surface is an image of the whole screen made of memory objects of at most
//! 64 pages (`azos_devif::display`); band `i` holds `rows` whole rows, the last
//! only what is left. [`plan`] decides the object size and count; [`Bands`] is
//! the `azos_compose` sink over their mappings: a row is a slice of one band.

use azos_compose::{Format, Sink};

/// Bands the compositor keeps at most (one MemObj each).
pub const BANDS_MAX: usize = 32;

/// How a surface of `height` rows of `stride` bytes is cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Pages of each band's memory object.
    pub pages: u64,
    /// Whole rows each band holds.
    pub rows: u32,
    /// Bands.
    pub count: u32,
}

/// Cut a surface of `height` rows of `stride` bytes into bands of at most
/// `max_pages` pages of `page_bytes`. The pages of a band are as many as its rows
/// need (the largest whole number of rows that fits `max_pages`), so no memory
/// is held beyond the last band's needs. `None` for a geometry that cannot be cut
/// (a row longer than a band, nothing to show) or that needs more than
/// [`BANDS_MAX`] bands.
pub fn plan(height: u32, stride: u32, page_bytes: usize, max_pages: u64) -> Option<Plan> {
    if height == 0 || stride == 0 || page_bytes == 0 || max_pages == 0 {
        return None;
    }
    let rows = (max_pages * page_bytes as u64 / stride as u64).min(height as u64) as u32;
    if rows == 0 {
        return None;
    }
    let count = height.div_ceil(rows);
    if count as usize > BANDS_MAX {
        return None;
    }
    let pages = (rows as u64 * stride as u64).div_ceil(page_bytes as u64);
    Some(Plan { pages, rows, count })
}

/// The bands' mappings as an `azos_compose` sink.
pub struct Bands {
    bases: [usize; BANDS_MAX],
    plan: Plan,
    stride: usize,
    height: u32,
    format: Format,
}

impl Bands {
    /// `bases[i]` is where band `i` is mapped (`plan.count` of them, each at
    /// least `plan.rows * stride` bytes long, writable).
    pub fn new(bases: [usize; BANDS_MAX], plan: Plan, stride: u32, height: u32, format: Format) -> Bands {
        Bands { bases, plan, stride: stride as usize, height, format }
    }
}

impl Sink for Bands {
    fn format(&self) -> Format {
        self.format
    }

    fn row_mut(&mut self, y: u32) -> Option<&mut [u8]> {
        if y >= self.height {
            return None;
        }
        let band = (y / self.plan.rows) as usize;
        let base = *self.bases.get(band)?;
        if band >= self.plan.count as usize || base == 0 {
            return None;
        }
        let off = (y % self.plan.rows) as usize * self.stride;
        // SAFETY: `new`'s contract: band `band` is mapped at `base` for
        // `plan.rows * stride` writable bytes, and `off + stride` is within that
        // (`y % rows < rows`). The slice is borrowed from `&mut self`, so only one
        // row is alive at a time; the mapping lives as long as the server (it is
        // never unmapped).
        Some(unsafe { core::slice::from_raw_parts_mut((base + off) as *mut u8, self.stride) })
    }
}
