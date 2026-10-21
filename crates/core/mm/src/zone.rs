// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Type zones for physical frames (Kconfig `PMM_TYPE_ZONES`; the kalloc_type
//! lesson, Apple XNU).
//!
//! A use-after-free is worth most when the freed memory comes back as another
//! type: a stale pointer to a freed page-table frame, whose frame is next
//! handed out as a user data page, lets the attacker write page-table entries.
//! A zoned frame therefore **never leaves its type**: it is tagged with its
//! [`Zone`] on first use (`FrameDesc::zone`), and `pmm::free` of a tagged
//! frame puts it on the zone's own free list instead of the per-hart cache or
//! the buddy lists. Only a zoned allocation of the same zone takes it back
//! out. Memory handed to a zone is sequestered for good: a burst of page
//! tables leaves its high-water mark as page tables (bounded by Kconfig
//! `PMM_ZONE_MAX_PAGES`, per zone). `pmm::free_pages` counts those frames
//! free, as it counts a frame in another hart's cache: not leaked, but not
//! available to a general allocation either.
//!
//! **Why frames and not the kernel heap.** The security-sensitive kernel
//! objects of the plan (task, capability table, endpoint, MemObj header) are
//! fixed static tables: a freed slot can only be reused as the same type, so
//! they are type-isolated by construction. What the kernel does allocate and
//! free dynamically, through one allocator that hands one type's memory to
//! any other, is physical frames: page-table pages, io_ring pages, ring-3
//! data. That is where the zones are.
//!
//! **Not covered.** Only order-0 frames are zoned; `alloc_contiguous` runs
//! are not. A frame that was not tagged at allocation (a user data page that
//! the buddy lists later give to a zone) is not protected against a stale
//! reference *to the data page*: the zones stop the other direction, a zoned
//! frame becoming data.
//!
//! This file is pure data-structure code over a [`FrameTable`] (no lock, no
//! CPU state): `pmm.rs` owns the lists, their locks and the allocation path,
//! and the host builds this file with `#[path]` (`tests/host/mm-tests`).

use core::sync::atomic::Ordering;
use crate::frame::{FrameTable, Pfn, F_ALLOCATED, F_CACHED, NIL};

/// A frame type with a free list of its own. The tag is the value stored in
/// `FrameDesc::zone`; `0` is "no zone".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Zone {
    /// Page-table pages (every level, user and kernel-half copies).
    PageTable = 1,
    /// io_ring pages: the shared submission/completion rings the kernel parses.
    Ring = 2,
}

/// Number of zones.
pub const ZONES: usize = 2;

impl Zone {
    /// Every zone, by index.
    pub const ALL: [Zone; ZONES] = [Zone::PageTable, Zone::Ring];

    /// The value in `FrameDesc::zone`.
    #[inline(always)]
    pub const fn tag(self) -> u32 { self as u32 }

    /// Position in per-zone tables.
    #[inline(always)]
    pub const fn index(self) -> usize { self as usize - 1 }

    /// The zone a descriptor tag names; `None` for `0` and any unknown tag.
    #[inline(always)]
    pub const fn of_tag(tag: u32) -> Option<Zone> {
        match tag {
            1 => Some(Zone::PageTable),
            2 => Some(Zone::Ring),
            _ => None,
        }
    }
}

/// One zone's free frames: a stack linked through the descriptors' `next`,
/// plus how many frames the zone owns in all (free and handed out).
pub struct ZoneList {
    head: u32,
    pooled: u32,
    total: u32,
}

impl ZoneList {
    pub const fn new() -> ZoneList { ZoneList { head: NIL, pooled: 0, total: 0 } }

    /// Forget everything (the descriptors are rebuilt by the caller).
    pub fn reset(&mut self) { *self = ZoneList::new(); }

    /// Free frames held by the zone.
    #[inline(always)]
    pub fn pooled(&self) -> usize { self.pooled as usize }

    /// Frames the zone owns: those on its list and those handed out.
    #[inline(always)]
    pub fn total(&self) -> usize { self.total as usize }

    /// Take the newest free frame: `F_ALLOCATED`, unshared, still tagged.
    #[inline]
    pub fn pop(&mut self, t: &FrameTable) -> Option<Pfn> {
        if self.head == NIL { return None; }
        let idx = self.head as usize;
        let d = t.at(idx);
        self.head = d.next.load(Ordering::Relaxed);
        self.pooled -= 1;
        d.next.store(NIL, Ordering::Relaxed);
        d.flags.store(F_ALLOCATED, Ordering::Relaxed);
        d.refcount.store(0, Ordering::Relaxed);
        Some(t.pfn(idx))
    }

    /// Keep the frame at array index `idx`, which `pmm::free` claimed
    /// (`F_CACHED`: free, in nobody's list), for this zone.
    #[inline]
    pub fn push(&mut self, t: &FrameTable, idx: usize) {
        let d = t.at(idx);
        d.flags.store(F_CACHED, Ordering::Relaxed);
        d.next.store(self.head, Ordering::Relaxed);
        self.head = idx as u32;
        self.pooled += 1;
    }

    /// Room for one more frame in the zone's total? `limit == 0` is no
    /// bound. On `true` the total has grown by one; the caller either tags a
    /// frame it then gets from the buddy lists, or calls [`ZoneList::ungrow`].
    #[inline]
    pub fn grow(&mut self, limit: usize) -> bool {
        if limit != 0 && self.total as usize >= limit { return false; }
        self.total += 1;
        true
    }

    /// Undo a [`ZoneList::grow`] whose frame could not be had.
    #[inline]
    pub fn ungrow(&mut self) { self.total -= 1; }
}

/// A frame to tag: the tag of `z`, stored on a frame the caller owns.
#[inline]
pub fn tag_frame(t: &FrameTable, pfn: Pfn, z: Zone) {
    if let Some(d) = t.get(pfn) { d.zone.store(z.tag(), Ordering::Relaxed); }
}
