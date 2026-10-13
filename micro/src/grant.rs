// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Grants: the kernel's own data, kept inside the task it serves.
//!
//! A task's Anon region is split once, at boot, into the part the task owns
//! (`[base, app_break)`, covered by its PMP entries) and the part the kernel
//! keeps for it (`[kernel_break, end)`, covered by none). The kernel's
//! per-task state, the capability table and the queue of an endpoint the
//! task serves, is carved from the top of that second part downwards, the
//! way Tock allocates a driver's per-process state. Nothing is a static
//! table sized for the worst case: a task that holds no endpoint pays for
//! none, a task that is gone takes its state with it, and the memory is
//! charged to the row's `mem_pages` like the rest of what it uses.
//!
//! The task cannot read or write a grant (no entry covers it) and the
//! kernel, which PMP does not constrain in M-mode, reaches it through the
//! address [`Grants::alloc`] returns.

/// The split of one region and the allocator over its kernel part.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Grants {
    base: usize,
    app_break: usize,
    kernel_break: usize,
    end: usize,
}

impl Grants {
    /// Nothing split yet.
    pub const EMPTY: Self = Self { base: 0, app_break: 0, kernel_break: 0, end: 0 };

    /// Split `[base, base + size)`: `reserve` bytes at the top are kept for
    /// grants (rounded up to the granularity `1 << grain_log2`, so the task's
    /// part ends where a PMP entry can end). `None` when `reserve` leaves the
    /// task less than `min_app` bytes (its stack).
    pub fn split(base: usize, size: usize, reserve: usize, min_app: usize, grain_log2: u32) -> Option<Self> {
        let end = base.checked_add(size)?;
        let reserve = crate::domain::round_up(reserve, grain_log2);
        let app_break = end.checked_sub(reserve)?;
        if app_break < base || app_break - base < min_app {
            return None;
        }
        Some(Self { base, app_break, kernel_break: end, end })
    }

    /// The task's part: `[base, app_break)`.
    pub fn app(&self) -> (usize, usize) {
        (self.base, self.app_break - self.base)
    }

    /// The kernel's part: `[app_break, end)`.
    pub fn kernel(&self) -> (usize, usize) {
        (self.app_break, self.end - self.app_break)
    }

    /// Carve `size` bytes aligned to `align` (a power of two) from the top
    /// of the kernel's part; the address, or `None` when it does not fit.
    /// Nothing is consumed on `None`.
    pub fn alloc(&mut self, size: usize, align: usize) -> Option<usize> {
        let at = self.kernel_break.checked_sub(size)? & !(align - 1);
        if at < self.app_break {
            return None;
        }
        self.kernel_break = at;
        Some(at)
    }

    /// Bytes of the kernel's part not yet carved.
    pub fn left(&self) -> usize {
        self.kernel_break - self.app_break
    }

    /// The bytes `sizes` (each `(size, align)`) need from the top of a fresh
    /// kernel part: every alignment pad counted, so a `split` with this
    /// `reserve` makes every `alloc` of them succeed.
    pub fn need(sizes: &[(usize, usize)]) -> usize {
        // Worst case: the top is aligned to nothing, so each item can lose
        // up to `align - 1` to padding.
        sizes.iter().map(|&(s, a)| s + (a - 1)).sum()
    }
}
