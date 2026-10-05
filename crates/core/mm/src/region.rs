// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Region records for demand-paged mappings (wave 14, DEMANDPAGE).
//!
//! An address space's reserved-but-not-yet-backed ranges, as plain data: no
//! page table, no lock, no allocator. [`crate::pager`] owns the table of these
//! sets (one per user page-table root) and the fault path that consults them;
//! everything here is arithmetic over sorted, non-overlapping ranges, so the
//! host tests pull this file in with `#[path]` and exercise the real code.
//!
//! A region says three things about every page in `[start, end)`: that it is
//! reserved (and, under the reserve-time charging model, already paid for),
//! the permissions its page gets when it is committed, and which pager
//! supplies that page. Committed pages are not recorded here: the page table
//! is the record of what is backed.
//!
//! The permission model is deliberately narrow: a region is readable, and
//! writable or not. It is never executable (W^X: `mmap` and `mprotect` refuse
//! `PROT_EXEC` before a region is made), and a `PROT_NONE` range is not a
//! region at all.

use azos_arch_api::PAGE_SHIFT;

/// Which pager supplies a region's pages.
///
/// Only the anonymous zero-fill pager exists. The enum, and the `obj`/`off`
/// fields of [`Region`], are the shape a file pager or an IPC pager (a ring-3
/// server answering page requests) needs: an object to name and a page offset
/// within it. Neither is implemented; see `crate::pager`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PagerKind {
    /// Zero-filled anonymous memory.
    Anon,
}

/// One reserved range. `start`/`end` are page-aligned; `end` is exclusive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Region {
    pub start: usize,
    pub end: usize,
    /// Committed pages are mapped writable. Read is always granted.
    pub write: bool,
    pub pager: PagerKind,
    /// Pager object id (0 for anonymous memory).
    pub obj: u32,
    /// Object page offset of `start` (0 for anonymous memory).
    pub off: usize,
}

impl Region {
    /// An anonymous region.
    pub const fn anon(start: usize, end: usize, write: bool) -> Self {
        Region { start, end, write, pager: PagerKind::Anon, obj: 0, off: 0 }
    }

    const EMPTY: Region = Region::anon(0, 0, false);

    /// Pages in the region.
    pub fn pages(&self) -> usize {
        (self.end - self.start) >> PAGE_SHIFT
    }

    /// The pager's page index for `va` (inside the region).
    pub fn page_index(&self, va: usize) -> usize {
        self.off + ((va - self.start) >> PAGE_SHIFT)
    }

    /// May `next` (which starts where this one ends) be folded into this one?
    /// Same permissions and pager, and for an object pager the object pages
    /// continue too. Anonymous memory has no offsets to line up.
    fn joins(&self, next: &Region) -> bool {
        self.end == next.start
            && self.write == next.write
            && self.pager == next.pager
            && self.obj == next.obj
            && (self.pager == PagerKind::Anon || self.off + self.pages() == next.off)
    }

    /// The part of the region in `[s, e)`, if any.
    fn clip(&self, s: usize, e: usize) -> Option<Region> {
        let a = self.start.max(s);
        let b = self.end.min(e);
        if a >= b {
            return None;
        }
        Some(Region { start: a, end: b, off: self.page_index(a), ..*self })
    }
}

/// Why a set refused a change. A refused change leaves the set untouched.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegionError {
    /// No slot for the record (or for the split it needs).
    Full,
    /// The new range overlaps a region already in the set.
    Overlap,
    /// Empty, inverted or misaligned range.
    Invalid,
}

/// The regions of one address space, sorted by `start`, never overlapping,
/// adjacent compatible regions always folded into one. At most `N` records.
pub struct RegionSet<const N: usize> {
    n: usize,
    r: [Region; N],
}

const PAGE_MASK: usize = (1usize << PAGE_SHIFT) - 1;

fn range_ok(s: usize, e: usize) -> bool {
    s < e && s & PAGE_MASK == 0 && e & PAGE_MASK == 0
}

impl<const N: usize> RegionSet<N> {
    pub const fn new() -> Self {
        RegionSet { n: 0, r: [Region::EMPTY; N] }
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn as_slice(&self) -> &[Region] {
        &self.r[..self.n]
    }

    pub fn clear(&mut self) {
        self.n = 0;
    }

    /// The region holding `va`, if any. This is the fault path's lookup.
    #[inline]
    pub fn find(&self, va: usize) -> Option<&Region> {
        // Sorted: the first region ending above `va` is the only candidate.
        for r in &self.r[..self.n] {
            if va < r.end {
                return if va >= r.start { Some(r) } else { None };
            }
        }
        None
    }

    /// Pages of `[s, e)` that some region covers.
    pub fn covered_pages(&self, s: usize, e: usize) -> usize {
        let mut n = 0;
        self.for_each_overlap(s, e, |a, b, _| n += (b - a) >> PAGE_SHIFT);
        n
    }

    /// Total reserved pages.
    pub fn reserved_pages(&self) -> usize {
        self.r[..self.n].iter().map(Region::pages).sum()
    }

    /// Call `f(a, b, region)` for each `[a, b)` = `[s, e)` ∩ region.
    pub fn for_each_overlap(&self, s: usize, e: usize, mut f: impl FnMut(usize, usize, &Region)) {
        for r in &self.r[..self.n] {
            if let Some(c) = r.clip(s, e) {
                f(c.start, c.end, r);
            }
        }
    }

    /// Add `reg`, folding it into a neighbour when they join.
    pub fn insert(&mut self, reg: Region) -> Result<(), RegionError> {
        if !range_ok(reg.start, reg.end) {
            return Err(RegionError::Invalid);
        }
        // Insertion point: first region starting at or after `reg.end`'s
        // neighbourhood; checked for overlap on both sides.
        let mut i = 0;
        while i < self.n && self.r[i].end <= reg.start {
            i += 1;
        }
        if i < self.n && self.r[i].start < reg.end {
            return Err(RegionError::Overlap);
        }
        let joins_prev = i > 0 && self.r[i - 1].joins(&reg);
        let joins_next = i < self.n && reg.joins(&self.r[i]);
        match (joins_prev, joins_next) {
            (true, true) => {
                self.r[i - 1].end = self.r[i].end;
                self.remove_at(i);
            }
            (true, false) => self.r[i - 1].end = reg.end,
            (false, true) => {
                let next = &mut self.r[i];
                next.start = reg.start;
                next.off = reg.off;
            }
            (false, false) => {
                if self.n == N {
                    return Err(RegionError::Full);
                }
                let mut j = self.n;
                while j > i {
                    self.r[j] = self.r[j - 1];
                    j -= 1;
                }
                self.r[i] = reg;
                self.n += 1;
            }
        }
        Ok(())
    }

    fn remove_at(&mut self, i: usize) {
        for j in i..self.n - 1 {
            self.r[j] = self.r[j + 1];
        }
        self.n -= 1;
    }

    /// Does one region strictly contain `addr` (so cutting there splits it)?
    fn splits_at(&self, addr: usize) -> bool {
        self.r[..self.n].iter().any(|r| r.start < addr && addr < r.end)
    }

    /// Drop `[s, e)` from every region; returns the pages dropped. A region
    /// straddling the whole range is cut in two, which needs a free slot:
    /// `Full` (and nothing changed) when there is none — `munmap` answers
    /// that the way Linux does past its map count, with `ENOMEM`.
    pub fn remove_range(&mut self, s: usize, e: usize) -> Result<usize, RegionError> {
        if !range_ok(s, e) {
            return Err(RegionError::Invalid);
        }
        let straddles = self.r[..self.n].iter().any(|r| r.start < s && e < r.end);
        if straddles && self.n == N {
            return Err(RegionError::Full);
        }
        let mut out = [Region::EMPTY; N];
        let mut m = 0;
        let mut dropped = 0;
        for r in &self.r[..self.n] {
            if r.end <= s || r.start >= e {
                out[m] = *r;
                m += 1;
                continue;
            }
            dropped += r.clip(s, e).map_or(0, |c| c.pages());
            if let Some(lo) = r.clip(r.start, s) {
                out[m] = lo;
                m += 1;
            }
            if let Some(hi) = r.clip(e, r.end) {
                out[m] = hi;
                m += 1;
            }
        }
        self.r = out;
        self.n = m;
        Ok(dropped)
    }

    /// Give every region page in `[s, e)` write permission `write` (pages
    /// outside every region are not touched). Cuts at `s` and `e` take up to
    /// two slots, checked before anything changes; neighbours that join
    /// afterwards are folded back together.
    pub fn protect_range(&mut self, s: usize, e: usize, write: bool) -> Result<(), RegionError> {
        if !range_ok(s, e) {
            return Err(RegionError::Invalid);
        }
        let extra = self.splits_at(s) as usize + self.splits_at(e) as usize;
        if self.n + extra > N {
            return Err(RegionError::Full);
        }
        let mut out = [Region::EMPTY; N];
        let mut m = 0;
        for r in &self.r[..self.n] {
            for (a, b) in [(r.start, s.max(r.start)), (s.max(r.start), e.min(r.end)), (e.max(r.start), r.end)] {
                if let Some(mut piece) = r.clip(a, b) {
                    if piece.start >= s && piece.end <= e {
                        piece.write = write;
                    }
                    out[m] = piece;
                    m += 1;
                }
            }
        }
        self.r = out;
        self.n = m;
        self.coalesce();
        Ok(())
    }

    fn coalesce(&mut self) {
        let mut i = 0;
        while i + 1 < self.n {
            if self.r[i].joins(&self.r[i + 1]) {
                self.r[i].end = self.r[i + 1].end;
                self.remove_at(i + 1);
            } else {
                i += 1;
            }
        }
    }

    /// Make this set a copy of `other` (a fork's child inherits the
    /// reservation, not the pages).
    pub fn copy_from(&mut self, other: &RegionSet<N>) {
        self.r = other.r;
        self.n = other.n;
    }
}

impl<const N: usize> Default for RegionSet<N> {
    fn default() -> Self {
        Self::new()
    }
}
