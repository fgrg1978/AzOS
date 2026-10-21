// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The memory a tree lives in.

use crate::format::Error;
use core::sync::atomic::AtomicU64;

/// A block of aligned 64-bit atomic words: the kernel's view of a MemObj it
/// created, or a reader's view of the read-only mapping of one.
#[derive(Clone, Copy)]
pub struct Region<'a> {
    pub(crate) w: &'a [AtomicU64],
}

impl<'a> Region<'a> {
    /// A region over words the caller already holds as atomics.
    pub fn from_atomics(w: &'a [AtomicU64]) -> Region<'a> {
        Region { w }
    }

    /// A region over `len` bytes at `base`.
    ///
    /// # Safety
    /// `base..base+len` must be mapped for as long as `'a`, and nothing may
    /// access it except as aligned 64-bit atomics (the writer is the kernel's
    /// [`Writer`](crate::Writer); every reader only loads, so a read-only
    /// mapping is fine).
    pub unsafe fn from_raw(base: *const u8, len: usize) -> Result<Region<'a>, Error> {
        if base.is_null() || base as usize % 8 != 0 || len < 8 {
            return Err(Error::BadRegion);
        }
        // SAFETY: the caller's contract; an `AtomicU64` has the size and the
        // alignment of a `u64`, and `len / 8` words fit the mapping.
        Ok(Region { w: unsafe { core::slice::from_raw_parts(base as *const AtomicU64, len / 8) } })
    }

    /// The region's size in bytes.
    pub fn len(&self) -> usize {
        self.w.len() * 8
    }

    pub fn is_empty(&self) -> bool {
        self.w.is_empty()
    }
}
