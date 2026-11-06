// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The mappings of an address space: which object backs each reserved range,
//! from which page of it, with which permission.
//!
//! Plain data: no page table, no lock, no allocator. One set lives in each
//! address space (`crate::aspace`), and [`crate::pager`] runs the fault path
//! that consults it; everything here is arithmetic over sorted,
//! non-overlapping ranges, so the host tests pull this file in with `#[path]`
//! and exercise the real code.
//!
//! A mapping says three things about every page in `[start, end)`: that it is
//! reserved (and, under the reserve-time charging model, already paid for),
//! the permission its page gets when it is installed, and which page of which
//! object it is ([`Backing`], [`Mapping::off`]). What a page holds is the
//! object's business: an anonymous object's slots (`crate::anon_obj`), a file
//! window's page cache.
//!
//! The permission model is deliberately narrow: a mapping is readable, and
//! writable or not. It is never executable (W^X: `mmap` and `mprotect` refuse
//! `PROT_EXEC` before a mapping is made), and a `PROT_NONE` range is not a
//! mapping at all.
//!
//! **Anonymous mappings.** `obj` is the address of the space's own object,
//! whose pages are numbered by address (`off` is the page number of `start`).
//! Neighbours fold when they are consecutive pages of one object with one
//! permission: a cut (`munmap`, `mprotect`) leaves pieces of the same object,
//! and the pager maps a new range next to an anonymous mapping as more pages
//! of its object, so a task that only grows its mappings, up or down, holds
//! one record.
//!
//! **File mappings.** A [`Backing::File`] mapping is one piece of a file
//! mapping: `obj` names the page-cache object (a `MemKind::Paged` MemObj, one
//! per 64-page window of a file) and `off` is the page within it. One record is
//! one piece of one `mmap` call, so the records never fold (a neighbour with
//! the next pages of the same object is still another mapping) and a cut may
//! only take whole ones ([`MapSet::whole_cut_ok`]): the page cache counts
//! mappings, and one that split in two would be counted once.
//!
//! **Shared-object mappings.** A [`Backing::Obj`] mapping is a named shared
//! object (`SYS_MO_MAP`) mapped by this space: the object's frames are mapped
//! as they are, and the object's own list of mappers (its holder table) is the
//! reverse map reclaim, revoke and teardown reach this space's leaves by. A
//! shared file mapping is the same thing for a cache object. Like a file
//! piece, one goes whole or not at all, and the space never owns the frames.

use azos_arch_api::PAGE_SHIFT;

/// What backs a mapping's pages.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Backing {
    /// The address space's own anonymous object, by address
    /// (`crate::anon_obj::AnonObj`): zero-filled on first touch.
    Anon { obj: usize },
    /// A window of a file, through its page cache: the packed reference of the
    /// page-cache object, and `MAP_SHARED`. A shared mapping's pages are the
    /// cache's own frames, written back to the file; a private one holds a
    /// copy of each page it touched, owned and charged like anonymous memory.
    File { obj: u32, shared: bool },
    /// A named shared object (`SYS_MO_MAP`): its packed reference. The pages
    /// are the object's own frames, mapped when the mapping was made.
    Obj { obj: u32 },
}

/// One reserved range. `start`/`end` are page-aligned; `end` is exclusive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Mapping {
    pub start: usize,
    pub end: usize,
    /// Installed pages are mapped writable. Read is always granted.
    pub write: bool,
    pub backing: Backing,
    /// The object's page that `start` is.
    pub off: usize,
}

impl Mapping {
    /// Pages `off..` of the anonymous object `obj`.
    pub const fn anon(start: usize, end: usize, write: bool, obj: usize, off: usize) -> Self {
        Mapping { start, end, write, backing: Backing::Anon { obj }, off }
    }

    /// A piece of a file mapping: pages `off..` of the page-cache object `obj`.
    pub const fn file(start: usize, end: usize, write: bool, shared: bool, obj: u32, off: usize) -> Self {
        Mapping { start, end, write, backing: Backing::File { obj, shared }, off }
    }

    /// A mapping of a named shared object: pages `off..` of `obj`.
    pub const fn obj(start: usize, end: usize, write: bool, obj: u32, off: usize) -> Self {
        Mapping { start, end, write, backing: Backing::Obj { obj }, off }
    }

    /// The anonymous object, if the mapping is one.
    #[inline(always)]
    pub const fn anon_obj(&self) -> Option<usize> {
        match self.backing {
            Backing::Anon { obj } => Some(obj),
            Backing::File { .. } | Backing::Obj { .. } => None,
        }
    }

    /// Are the pages the mapping maps another owner's frames, which this space
    /// maps and never frees (a shared file's cache frames, a shared object's)?
    #[inline(always)]
    pub const fn maps_shared_frames(&self) -> bool {
        matches!(self.backing, Backing::File { shared: true, .. } | Backing::Obj { .. })
    }

    /// Does the task pay for this mapping's pages when it reserves them (and
    /// get the charge back when they go)? A shared mapping maps frames of the
    /// page cache or of a shared object, memory the task never owns: it is not
    /// charged, and neither is anything of it discharged.
    pub const fn charged(&self) -> bool {
        !self.maps_shared_frames()
    }

    const EMPTY: Mapping = Mapping::anon(0, 0, false, 0, 0);

    /// Pages in the mapping.
    pub fn pages(&self) -> usize {
        (self.end - self.start) >> PAGE_SHIFT
    }

    /// The object's page for `va` (inside the mapping).
    #[inline(always)]
    pub fn page_index(&self, va: usize) -> usize {
        self.off + ((va - self.start) >> PAGE_SHIFT)
    }

    /// May `next` (which starts where this one ends) be folded into this one?
    /// The next pages of the same anonymous object with the same permission. A
    /// file mapping never folds: it is one piece of one `mmap` (module doc).
    fn joins(&self, next: &Mapping) -> bool {
        matches!((self.backing, next.backing), (Backing::Anon { obj: a }, Backing::Anon { obj: b }) if a == b)
            && self.end == next.start
            && self.write == next.write
            && self.off + self.pages() == next.off
    }

    /// The part of the mapping in `[s, e)`, if any.
    fn clip(&self, s: usize, e: usize) -> Option<Mapping> {
        let a = self.start.max(s);
        let b = self.end.min(e);
        if a >= b {
            return None;
        }
        Some(Mapping { start: a, end: b, off: self.page_index(a), ..*self })
    }

    /// Does the mapping go whole or not at all (a file piece or a shared
    /// object's mapping)?
    fn is_whole(&self) -> bool {
        !matches!(self.backing, Backing::Anon { .. })
    }
}

/// Why a set refused a change. A refused change leaves the set untouched.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MapError {
    /// No record for the mapping (or for the split it needs).
    Full,
    /// The new range overlaps a mapping already in the set.
    Overlap,
    /// Empty, inverted or misaligned range.
    Invalid,
}

/// The mappings of one address space, sorted by `start`, never overlapping,
/// adjacent mappings that join always folded into one. At most `N` records.
pub struct MapSet<const N: usize> {
    n: usize,
    r: [Mapping; N],
}

const PAGE_MASK: usize = (1usize << PAGE_SHIFT) - 1;

/// The largest set [`MapSet::find`] scans; a larger one is searched.
pub const SCAN_MAX: usize = 32;

fn range_ok(s: usize, e: usize) -> bool {
    s < e && s & PAGE_MASK == 0 && e & PAGE_MASK == 0
}

impl<const N: usize> MapSet<N> {
    pub const fn new() -> Self {
        MapSet { n: 0, r: [Mapping::EMPTY; N] }
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn as_slice(&self) -> &[Mapping] {
        &self.r[..self.n]
    }

    pub fn clear(&mut self) {
        self.n = 0;
    }

    /// The mapping holding `va`, if any. This is the fault path's lookup: the
    /// first mapping ending above `va` is the only candidate in a sorted set.
    /// Found by a scan up to [`SCAN_MAX`] records and a binary search past
    /// them: on riscv64 a scan costs 5 instructions a record and a search 11
    /// a halving over 26, so the scan is the cheaper one up to about 30.
    #[inline]
    pub fn find(&self, va: usize) -> Option<&Mapping> {
        let rs = &self.r[..self.n];
        let m = if N <= SCAN_MAX {
            rs.iter().find(|m| va < m.end)
        } else {
            rs.get(rs.partition_point(|m| m.end <= va))
        };
        m.filter(|m| va >= m.start)
    }

    /// The mapping that ends at `va`, if any (the one a new mapping at `va`
    /// would continue).
    pub fn ending_at(&self, va: usize) -> Option<&Mapping> {
        let rs = &self.r[..self.n];
        let i = rs.partition_point(|m| m.end < va);
        rs.get(i).filter(|m| m.end == va)
    }

    /// How many mappings name the anonymous object `obj`?
    pub fn naming(&self, obj: usize) -> usize {
        self.r[..self.n].iter().filter(|m| m.anon_obj() == Some(obj)).count()
    }

    /// Pages of `[s, e)` that some mapping covers.
    pub fn covered_pages(&self, s: usize, e: usize) -> usize {
        let mut n = 0;
        self.for_each_overlap(s, e, |a, b, _| n += (b - a) >> PAGE_SHIFT);
        n
    }

    /// Total reserved pages.
    pub fn reserved_pages(&self) -> usize {
        self.r[..self.n].iter().map(Mapping::pages).sum()
    }

    /// Reserved pages the task paid for ([`Mapping::charged`]).
    pub fn charged_pages(&self) -> usize {
        self.r[..self.n].iter().filter(|r| r.charged()).map(Mapping::pages).sum()
    }

    /// Does `[s, e)` touch a mapping of a shared object?
    pub fn has_obj(&self, s: usize, e: usize) -> bool {
        self.r[..self.n].iter().any(|r| matches!(r.backing, Backing::Obj { .. }) && r.start < e && s < r.end)
    }

    /// Does `[s, e)` touch a file piece or a shared object's mapping?
    pub fn has_whole(&self, s: usize, e: usize) -> bool {
        self.r[..self.n].iter().any(|r| r.is_whole() && r.start < e && s < r.end)
    }

    /// May `[s, e)` be cut out of the set without splitting or trimming a file
    /// or shared-object mapping? Those are taken whole or not at all (module
    /// doc).
    pub fn whole_cut_ok(&self, s: usize, e: usize) -> bool {
        self.r[..self.n]
            .iter()
            .filter(|r| r.is_whole() && r.start < e && s < r.end)
            .all(|r| s <= r.start && r.end <= e)
    }

    /// Call `f(a, b, mapping)` for each `[a, b)` = `[s, e)` ∩ mapping.
    pub fn for_each_overlap(&self, s: usize, e: usize, mut f: impl FnMut(usize, usize, &Mapping)) {
        for r in &self.r[..self.n] {
            if let Some(c) = r.clip(s, e) {
                f(c.start, c.end, r);
            }
        }
    }

    /// Add `m`, folding it into a neighbour when they join.
    pub fn insert(&mut self, m: Mapping) -> Result<(), MapError> {
        if !range_ok(m.start, m.end) {
            return Err(MapError::Invalid);
        }
        let i = self.r[..self.n].partition_point(|r| r.end <= m.start);
        if i < self.n && self.r[i].start < m.end {
            return Err(MapError::Overlap);
        }
        let joins_prev = i > 0 && self.r[i - 1].joins(&m);
        let joins_next = i < self.n && m.joins(&self.r[i]);
        match (joins_prev, joins_next) {
            (true, true) => {
                self.r[i - 1].end = self.r[i].end;
                self.remove_at(i);
            }
            (true, false) => self.r[i - 1].end = m.end,
            (false, true) => {
                let next = &mut self.r[i];
                next.start = m.start;
                next.off = m.off;
            }
            (false, false) => {
                if self.n == N {
                    return Err(MapError::Full);
                }
                let mut j = self.n;
                while j > i {
                    self.r[j] = self.r[j - 1];
                    j -= 1;
                }
                self.r[i] = m;
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

    /// Does one mapping strictly contain `addr` (so cutting there splits it)?
    fn splits_at(&self, addr: usize) -> bool {
        self.r[..self.n].iter().any(|r| r.start < addr && addr < r.end)
    }

    /// Drop `[s, e)` from every mapping; returns the pages dropped. A mapping
    /// straddling the whole range is cut in two, which needs a free record:
    /// `Full` (and nothing changed) when there is none — `munmap` answers
    /// that the way Linux does past its map count, with `ENOMEM`.
    pub fn remove_range(&mut self, s: usize, e: usize) -> Result<usize, MapError> {
        if !range_ok(s, e) {
            return Err(MapError::Invalid);
        }
        let straddles = self.r[..self.n].iter().any(|r| r.start < s && e < r.end);
        if straddles && self.n == N {
            return Err(MapError::Full);
        }
        let mut out = [Mapping::EMPTY; N];
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

    /// Give every mapped page in `[s, e)` write permission `write` (pages
    /// outside every mapping are not touched). Cuts at `s` and `e` take up to
    /// two records, checked before anything changes; neighbours that join
    /// afterwards are folded back together.
    pub fn protect_range(&mut self, s: usize, e: usize, write: bool) -> Result<(), MapError> {
        if !range_ok(s, e) {
            return Err(MapError::Invalid);
        }
        let extra = self.splits_at(s) as usize + self.splits_at(e) as usize;
        if self.n + extra > N {
            return Err(MapError::Full);
        }
        let mut out = [Mapping::EMPTY; N];
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
}

impl<const N: usize> Default for MapSet<N> {
    fn default() -> Self {
        Self::new()
    }
}
