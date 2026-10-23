// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Where a server puts each module: its text and data regions, one after the
//! other, inside the module window (Kconfig `LX_MODULE_WINDOW_BASE` and
//! `LX_MODULE_WINDOW_SIZE`).
//!
//! The kernel maps a region only at an exact address inside the window
//! (`SYS_MO_MAP` with `MAP_FIXED_NOREPLACE`) and makes text executable only
//! there (`DOMAIN_MODULE_MAP_X`); the build checks that the window lies
//! within every relocation's reach of the server image on all three ISAs
//! (`crates/core/sched/src/process.rs`). This planner decides the addresses:
//!
//! * text first, at the next page (or the text's alignment, if larger);
//! * data at the first page after the text, so no page holds both: text
//!   becomes read-execute and data stays read-write, and a page cannot be
//!   both (W^X);
//! * one unmapped guard page after the data, so a module's overrun faults
//!   instead of reaching the next module's text.
//!
//! Addresses are never reused: a server loads its modules once, at start.

use crate::Layout;

/// A region the planner gave a module, in bytes, page-rounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    /// Base of the text region.
    pub text_base: u64,
    /// Bytes of the text region (0 when the module has no text).
    pub text_len: u64,
    /// Base of the data region.
    pub data_base: u64,
    /// Bytes of the data region (at least one page).
    pub data_len: u64,
}

/// [`Window`] refusals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowError {
    /// The window or the page size is not page-aligned or not a power of
    /// two, the window is empty, or it wraps the address space.
    Misaligned,
    /// The module does not fit in what is left of the window.
    Full,
}

/// The module window and how much of it is taken.
#[derive(Clone, Copy, Debug)]
pub struct Window {
    end: u64,
    cursor: u64,
    page: u64,
}

fn align_up(x: u64, a: u64) -> Option<u64> {
    Some(x.checked_add(a - 1)? & !(a - 1))
}

impl Window {
    /// `[base, base + size)`, with pages of `page` bytes.
    pub const fn new(base: u64, size: u64, page: u64) -> Result<Self, WindowError> {
        if !page.is_power_of_two() || base % page != 0 || size % page != 0 || size == 0 {
            return Err(WindowError::Misaligned);
        }
        match base.checked_add(size) {
            Some(end) => Ok(Window { end, cursor: base, page }),
            None => Err(WindowError::Misaligned),
        }
    }

    /// Place a module of this layout. Nothing is taken on a refusal.
    pub fn place(&mut self, l: &Layout) -> Result<Placement, WindowError> {
        let page = self.page;
        let full = WindowError::Full;
        let text_base = align_up(self.cursor, l.text_align.max(page)).ok_or(full)?;
        let text_len = align_up(l.text_size, page).ok_or(full)?;
        let data_base = align_up(text_base.checked_add(text_len).ok_or(full)?, l.data_align.max(page)).ok_or(full)?;
        let data_len = align_up(l.data_size, page).ok_or(full)?.max(page);
        let data_end = data_base.checked_add(data_len).ok_or(full)?;
        let next = data_end.checked_add(page).ok_or(full)?;
        if data_end > self.end {
            return Err(full);
        }
        self.cursor = next.min(self.end);
        Ok(Placement { text_base, text_len, data_base, data_len })
    }

    /// The lowest address the next placement may use.
    pub fn cursor(&self) -> u64 {
        self.cursor
    }
}
