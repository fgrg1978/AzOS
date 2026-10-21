// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Page generations for the reclaimer (Kconfig `MM_RECLAIM_COMPRESS`): which of
//! a Domain's resident anonymous pages has gone longest without being used.
//! MGLRU-lite: Linux's multi-generational LRU keeps four generations per
//! cgroup and walks the oldest first; this keeps the same four, in 2 bits a
//! page, fed by the Accessed bit (`Mmu::harvest_accessed`).
//!
//! **Why generations.** The reclaimer used to walk a Domain's pages by address
//! with a clock hand, so the page it compressed first was the lowest one, not
//! the coldest. A page that is used again a moment after it left costs an
//! unmap, a shoot-down on every hart, a compression, a decryption and a
//! decompression for nothing; the Accessed bit says which pages are about to
//! be that.
//!
//! **The four generations** are an age, 0 (used since the last pass) to 3
//! (idle for three passes or more). A pass ([`AgeTable::observe`]) moves every
//! page it sees one older and sends the pages the harvest reports accessed
//! back to 0. A page first seen is not young merely because it is new: it
//! starts at [`FIRST_IDLE`] when its Accessed bit is clear (not used since it
//! was mapped, but not yet watched idle), and at 0 when it is set. Reclaim
//! walks from the oldest generation ([`AgeTable::pick`]): the pages of age 3
//! first, then 2, 1 and, only when the Domain still has to give memory back,
//! 0. A model whose `Mmu` keeps no Accessed bit (`pte_accessed_bit() == 0`)
//! reports nothing as accessed, every page ages to 3 and the walk is address
//! order again, which is what it was before this file.
//!
//! **Incompressible pages skip the compressor.** A page the coder gave up on
//! (`Packed::Skip`, above `MM_ZPOOL_MAX_RATIO_PCT`) used to be offered again by
//! every storm: an unmap, a shoot-down, a full compression attempt and a put
//! back, each time. [`AgeTable::mark_incompressible`] flags it, [`AgeTable::pick`]
//! no longer offers it, and the flag is dropped when a pass sees the page
//! accessed: a page nobody touched has the bytes it had. (Zero and
//! same-filled pages need no such rule: `zpool::Codec::pack` looks for one
//! repeated word before it compresses anything, and they cost an index entry.)
//!
//! **The table.** Pages are tracked in chunks of [`WINDOW`] pages (exactly what
//! one `harvest_accessed` call reports): per chunk the owning space, the two
//! bit-planes of the 2-bit ages, a valid mask and the skip mask, 48 bytes for
//! 64 pages. The chunks are kept sorted by `(space, chunk)` so a lookup is a
//! binary search and a pass over a space meets them in address order. The
//! table is bounded (`MM_AGING_CHUNKS`); a chunk that does not fit is not
//! tracked, its pages are never offered (so the Domain's reclaim is bounded by
//! the table, not by the walk), and [`Tally::overflow`] says so. Only the
//! reclaim task touches it.
//!
//! This file depends on `core` and `azos_limits` alone, and knows page numbers,
//! not addresses or page tables; the walk that feeds it is `pager::age_space`.
//! `tests/host/mm-tests` pulls it with `#[path]`.

/// Pages per chunk: what one `Mmu::harvest_accessed` call reports.
pub const WINDOW: usize = 64;

/// log2 of [`WINDOW`].
pub const WINDOW_SHIFT: u32 = 6;

/// Generations: ages 0 (youngest) ..= [`OLDEST`].
pub const GENS: u8 = 4;

/// The oldest generation: where a page that stays idle stops.
pub const OLDEST: u8 = GENS - 1;

/// The age of a page first seen with its Accessed bit clear.
pub const FIRST_IDLE: u8 = GENS - 2;

/// Reclaim is on (`MM_RECLAIM_COMPRESS`): without it no table is built.
pub const ENABLED: bool = azos_limits::MM_RECLAIM_COMPRESS;

/// Chunks the kernel's table holds (zero with reclaim off).
pub const CHUNKS: usize = if ENABLED { azos_limits::MM_AGING_CHUNKS } else { 0 };

/// One chunk: 64 consecutive pages of one space.
#[derive(Clone, Copy)]
struct Chunk {
    space: usize,
    /// Bit `i` of the age of page `i`: the planes `a1:a0` hold age `2*a1 + a0`.
    a1: u64,
    a0: u64,
    /// Pages tracked (resident, ours to offer).
    valid: u64,
    /// Pages flagged incompressible.
    skip: u64,
    chunk: u32,
    owner: u16,
    /// Seen by the current pass of `owner` ([`AgeTable::begin`]).
    visited: bool,
}

impl Chunk {
    const EMPTY: Chunk = Chunk { space: 0, a1: 0, a0: 0, valid: 0, skip: 0, chunk: 0, owner: 0, visited: false };

    /// The pages (bits) of age `age`, tracked or not.
    const fn of_age(&self, age: u8) -> u64 {
        match age {
            0 => !self.a1 & !self.a0,
            1 => !self.a1 & self.a0,
            2 => self.a1 & !self.a0,
            _ => self.a1 & self.a0,
        }
    }
}

/// What a pass left in the table for one Domain ([`AgeTable::end`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    /// Pages tracked.
    pub pages: u32,
    /// Chunks that held them.
    pub chunks: u32,
    /// Chunks the pass could not track for want of room: their pages are not
    /// offered to the reclaimer until the table has room (`MM_AGING_CHUNKS`).
    pub overflow: u32,
}

/// Where a reclaim storm stands in the walk of the table ([`AgeTable::pick`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cursor {
    /// Generations already walked: the walk is at age `OLDEST - level`.
    level: u8,
    /// The chunk it is in, and the next page of it to look at.
    idx: usize,
    bit: u32,
}

/// The ages of the pages of up to `N` chunks.
pub struct AgeTable<const N: usize> {
    chunks: [Chunk; N],
    len: usize,
    /// Chunks the pass in progress could not add.
    overflow: u32,
}

impl<const N: usize> AgeTable<N> {
    pub const fn new() -> Self {
        Self { chunks: [Chunk::EMPTY; N], len: 0, overflow: 0 }
    }

    /// Where `(space, chunk)` is, or the index it would be inserted at.
    fn find(&self, space: usize, chunk: u32) -> Result<usize, usize> {
        self.chunks[..self.len].binary_search_by(|c| (c.space, c.chunk).cmp(&(space, chunk)))
    }

    /// Open a pass over the spaces of Domain slot `owner`: every chunk of it
    /// counts as not seen until [`observe`](Self::observe) sees it.
    pub fn begin(&mut self, owner: usize) {
        let owner = owner_tag(owner);
        for c in &mut self.chunks[..self.len] {
            if c.owner == owner {
                c.visited = false;
            }
        }
        self.overflow = 0;
    }

    /// One pass's look at the pages of `chunk` of `space` named by `scope`
    /// (bit `i`: page `i` of the chunk is in the region the pass is walking):
    /// `resident` (a subset of `scope`) are the pages the reclaimer may take
    /// now, `accessed` the ones the harvest found used since the last pass.
    ///
    /// * a tracked page still resident moves one generation older, or back to
    ///   0 when accessed (and loses its incompressible flag);
    /// * a page not tracked yet starts at 0 when accessed, at [`FIRST_IDLE`]
    ///   when not;
    /// * a tracked page of `scope` that is no longer resident is forgotten.
    ///
    /// `false`: the chunk is new and the table is full, so it is not tracked.
    pub fn observe(&mut self, owner: usize, space: usize, chunk: u32, scope: u64, resident: u64, accessed: u64) -> bool {
        let resident = resident & scope;
        let accessed = accessed & resident;
        let i = match self.find(space, chunk) {
            Ok(i) => i,
            Err(_) if resident == 0 => return true,
            Err(_) if self.len == N => {
                self.overflow = self.overflow.saturating_add(1);
                return false;
            }
            Err(at) => {
                self.chunks.copy_within(at..self.len, at + 1);
                self.chunks[at] = Chunk { space, chunk, ..Chunk::EMPTY };
                self.len += 1;
                at
            }
        };
        let c = &mut self.chunks[i];
        c.owner = owner_tag(owner);
        c.visited = true;
        let seen = c.valid & resident;
        let fresh = resident & !c.valid;
        let gone = scope & !resident;
        let idle_seen = seen & !accessed;
        let idle_fresh = fresh & !accessed;
        // One generation older, saturating at 3, on both planes at once:
        // 00 -> 01 -> 10 -> 11 -> 11.
        let older1 = c.a1 | c.a0;
        let older0 = !c.a0 | c.a1;
        let rewritten = idle_seen | idle_fresh | ((seen | fresh) & accessed) | gone;
        // A page touched, or one that has left, is age 0 (planes clear); a page first seen idle
        // is `FIRST_IDLE` = 2 = `10`.
        const _: () = assert!(FIRST_IDLE == 2);
        c.a1 = (c.a1 & !rewritten) | (older1 & idle_seen) | idle_fresh;
        c.a0 = (c.a0 & !rewritten) | (older0 & idle_seen);
        c.valid = (c.valid & !gone) | fresh;
        c.skip &= !(gone | accessed);
        true
    }

    /// Close the pass over `owner`'s spaces: drop the chunks it did not see (a
    /// region that is gone, a space that ended) and the ones with no page
    /// left, and say what is tracked.
    pub fn end(&mut self, owner: usize) -> Tally {
        let owner = owner_tag(owner);
        let mut tally = Tally { overflow: self.overflow, ..Tally::default() };
        let mut w = 0;
        for r in 0..self.len {
            let c = self.chunks[r];
            if c.owner == owner {
                if !c.visited || c.valid == 0 {
                    continue;
                }
                tally.pages += c.valid.count_ones();
                tally.chunks += 1;
            }
            self.chunks[w] = c;
            w += 1;
        }
        self.len = w;
        tally
    }

    /// Drop the chunks of every Domain slot `keep` refuses, and say how many.
    /// A pass closes only its own Domain's chunks ([`end`](Self::end)); the
    /// ones of a Domain that is gone, locked, or back under its low watermark
    /// are never closed by anyone, and would sit in the table against the
    /// Domains still aged.
    pub fn retain_owners(&mut self, keep: impl Fn(usize) -> bool) -> usize {
        let before = self.len;
        let mut w = 0;
        for r in 0..self.len {
            let c = self.chunks[r];
            if keep(usize::from(c.owner)) {
                self.chunks[w] = c;
                w += 1;
            }
        }
        self.len = w;
        before - w
    }

    /// The next page to offer the reclaimer: of the spaces `spaces`, tracked,
    /// not flagged incompressible, oldest generation first and by address
    /// within one. `(space, page number)`. The cursor moves past the page it
    /// answers, so a storm that keeps a page (it was busy, or did not
    /// compress) is not handed it again.
    pub fn pick(&self, cur: &mut Cursor, spaces: &[usize]) -> Option<(usize, usize)> {
        while cur.level < GENS {
            let age = OLDEST - cur.level;
            while cur.idx < self.len {
                let c = &self.chunks[cur.idx];
                if spaces.contains(&c.space) {
                    let m = c.of_age(age) & c.valid & !c.skip;
                    let m = if cur.bit >= 64 { 0 } else { m & (u64::MAX << cur.bit) };
                    if m != 0 {
                        let bit = m.trailing_zeros();
                        cur.bit = bit + 1;
                        return Some((c.space, ((c.chunk as usize) << WINDOW_SHIFT) | bit as usize));
                    }
                }
                cur.idx += 1;
                cur.bit = 0;
            }
            cur.level += 1;
            cur.idx = 0;
            cur.bit = 0;
        }
        None
    }

    /// The page left the Domain's frames (it is in the pool now): stop
    /// tracking it.
    pub fn evicted(&mut self, space: usize, page: usize) {
        if let Some((i, bit)) = self.locate(space, page) {
            let c = &mut self.chunks[i];
            c.valid &= !bit;
            c.skip &= !bit;
            c.a1 &= !bit;
            c.a0 &= !bit;
        }
    }

    /// The coder gave up on the page: [`pick`](Self::pick) leaves it alone
    /// until a pass sees it accessed.
    pub fn mark_incompressible(&mut self, space: usize, page: usize) {
        if let Some((i, bit)) = self.locate(space, page) {
            let c = &mut self.chunks[i];
            c.skip |= bit & c.valid;
        }
    }

    /// The age of a tracked page (`None`: not tracked).
    #[must_use]
    pub fn age_of(&self, space: usize, page: usize) -> Option<u8> {
        let (i, bit) = self.locate(space, page)?;
        let c = &self.chunks[i];
        (c.valid & bit != 0).then(|| (0..GENS).find(|&a| c.of_age(a) & bit != 0).unwrap_or(0))
    }

    /// Is the tracked page flagged incompressible?
    #[must_use]
    pub fn is_incompressible(&self, space: usize, page: usize) -> bool {
        self.locate(space, page).is_some_and(|(i, bit)| self.chunks[i].skip & bit != 0)
    }

    /// Chunks in the table.
    #[must_use]
    pub fn chunks(&self) -> usize {
        self.len
    }

    fn locate(&self, space: usize, page: usize) -> Option<(usize, u64)> {
        let chunk = u32::try_from(page >> WINDOW_SHIFT).ok()?;
        let i = self.find(space, chunk).ok()?;
        Some((i, 1u64 << (page & (WINDOW - 1))))
    }
}

impl<const N: usize> Default for AgeTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// A Domain slot as the table keeps it (slots are far below 65536).
fn owner_tag(owner: usize) -> u16 {
    u16::try_from(owner).unwrap_or(u16::MAX)
}
