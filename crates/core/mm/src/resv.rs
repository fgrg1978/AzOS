// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Superpage reservations (Kconfig `MM_THP_RESV`), as plain data.
//!
//! FreeBSD's idea: the first fault in a block-aligned part of an anonymous
//! region takes a physically contiguous, block-aligned run, hands its frames
//! out one 4 KiB page at a time, and when every frame has been handed out and
//! installed the level-0 table is swapped for one level-1 leaf. A block is
//! one level-1 leaf: 2 MiB at a 4 KiB base page.
//!
//! This file is the bookkeeping only: which block of which address space holds
//! which run, which frames of it have been handed out, which installed, and
//! what is left to give back when the reservation is broken. No page table,
//! no lock, no allocator: [`crate::pager`] owns the one table (under its own
//! IRQ-safe lock) and the allocator calls, [`crate::vmm`] the page-table
//! surgery, and the host tests pull this file in with `#[path]` and run the
//! real code.
//!
//! **Who owns a frame of a run.** Exactly one of: the reservation (bit clear:
//! never handed out), a faulting thread (bit set, not yet installed: it
//! zeroes the frame and installs it, or gives it back), or the page table
//! (installed). [`ResvTable::take`] and its relatives remove an entry and
//! name the first kind only, through [`Resv::unused`]; a thread that holds a
//! frame of a removed entry frees it itself when its install fails
//! ([`ResvTable::unclaim`] says the entry is gone). A frame of the third kind
//! is an ordinary frame from then on: it is freed with `free_page` like any
//! other, never as part of a run.

use azos_arch_api::PAGE_SIZE;

/// Frames in a block: the entries of one page table, so a block is exactly
/// the span of a level-0 table and one level-1 leaf maps it.
pub const BLOCK_PAGES: usize = PAGE_SIZE / 8;
/// Bytes in a block (2 MiB at a 4 KiB base page).
pub const BLOCK_SIZE: usize = BLOCK_PAGES * PAGE_SIZE;
/// Largest block the fill map holds. A 16 KiB or 64 KiB granule has 32 MiB or
/// 512 MiB blocks, too coarse to reserve, and does not use this file.
pub const MAX_BLOCK_PAGES: usize = 512;
const WORDS: usize = MAX_BLOCK_PAGES / 64;

/// Kconfig `MM_THP_RESV`, and a block the fill map holds. Every reservation
/// path tests this first and folds to nothing when it is false.
pub const ENABLED: bool = azos_limits::MM_THP_RESV && BLOCK_PAGES <= MAX_BLOCK_PAGES;

/// The block-aligned base of `va`.
#[inline]
pub const fn block_of(va: usize) -> usize {
    va & !(BLOCK_SIZE - 1)
}

/// Frame index of `va` within its block.
#[inline]
pub const fn index_of(va: usize) -> usize {
    (va & (BLOCK_SIZE - 1)) / PAGE_SIZE
}

/// Does `[start, end)` hold the whole block at `block_va`? A reservation is
/// made only in a block one region record covers entirely: one set of
/// permissions, and a level-1 leaf can map it without mapping a hole.
#[inline]
pub const fn covers(start: usize, end: usize, block_va: usize) -> bool {
    start <= block_va && block_va + BLOCK_SIZE <= end
}

/// One reservation: the run `[pa, pa + BLOCK_SIZE)` for the block `[va, ..)`
/// of the address space `root`. `root == 0` is a free slot.
#[derive(Clone, Copy)]
pub struct Resv {
    pub root: usize,
    pub va: usize,
    pub pa: usize,
    /// Frames handed out (claimed or installed), by index.
    handed: [u64; WORDS],
    /// Frames installed in the page table, by index. A subset of `handed`.
    done: [u64; WORDS],
    /// Popcount of `done`.
    installed: u16,
}

impl Resv {
    const EMPTY: Resv = Resv { root: 0, va: 0, pa: 0, handed: [0; WORDS], done: [0; WORDS], installed: 0 };

    #[inline]
    fn is_handed(&self, idx: usize) -> bool {
        self.handed[idx / 64] >> (idx % 64) & 1 != 0
    }

    #[inline]
    fn is_done(&self, idx: usize) -> bool {
        self.done[idx / 64] >> (idx % 64) & 1 != 0
    }

    #[inline]
    fn set(&mut self, idx: usize, on: bool) {
        let m = 1u64 << (idx % 64);
        if on { self.handed[idx / 64] |= m } else { self.handed[idx / 64] &= !m }
    }

    /// Frames handed out so far.
    pub fn handed(&self) -> usize {
        self.handed.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Physical addresses of the frames never handed out: what breaking the
    /// reservation gives back to the allocator.
    pub fn unused(&self) -> impl Iterator<Item = usize> + '_ {
        (0..BLOCK_PAGES).filter(move |&i| !self.is_handed(i)).map(move |i| self.pa + i * PAGE_SIZE)
    }
}

/// What [`ResvTable::claim`] found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Claim {
    /// The frame at this physical address is the caller's: zero it, install
    /// it, then [`ResvTable::installed`] (or [`ResvTable::unclaim`]).
    Frame { run: usize, pa: usize },
    /// Another thread has this frame in hand; its page is about to appear.
    /// The caller does not wait for it (that thread may be preempted): it
    /// takes a plain page and the install race has one winner.
    Busy,
    /// The frame was installed already and the page is unmapped again (it is
    /// an ordinary frame, maybe freed): the caller takes a plain page.
    Installed,
    /// No reservation for the block.
    None,
}

/// What [`ResvTable::installed`] found.
pub enum Filled {
    /// The reservation is gone (broken meanwhile): the page is an ordinary one.
    Gone,
    /// Frames of the block are still to come.
    Partial,
    /// Every frame is installed. The entry is removed: nothing is left to
    /// give back, and what follows (the promotion) is the page table's.
    Complete(Resv),
}

/// A fixed pool of `N` reservations.
pub struct ResvTable<const N: usize> {
    slots: [Resv; N],
}

impl<const N: usize> ResvTable<N> {
    pub const fn new() -> Self {
        ResvTable { slots: [Resv::EMPTY; N] }
    }

    fn position(&self, root: usize, block_va: usize) -> Option<usize> {
        self.slots.iter().position(|s| s.root == root && s.va == block_va)
    }

    /// The reservation for the block at `block_va` of `root`, if any.
    pub fn find(&self, root: usize, block_va: usize) -> Option<&Resv> {
        self.position(root, block_va).map(|i| &self.slots[i])
    }

    /// Record the run at `pa` for the block at `block_va` of `root`. Refused
    /// (the caller frees the run) when the pool is full or the block already
    /// has a reservation.
    pub fn insert(&mut self, root: usize, block_va: usize, pa: usize) -> Result<(), ()> {
        if root == 0 || block_va != block_of(block_va) || pa & (BLOCK_SIZE - 1) != 0 {
            return Err(());
        }
        if self.position(root, block_va).is_some() {
            return Err(());
        }
        let slot = self.slots.iter_mut().find(|s| s.root == 0).ok_or(())?;
        *slot = Resv { root, va: block_va, pa, ..Resv::EMPTY };
        Ok(())
    }

    /// Hand out frame `idx` of the block's run, once.
    pub fn claim(&mut self, root: usize, block_va: usize, idx: usize) -> Claim {
        let Some(i) = self.position(root, block_va) else { return Claim::None };
        let s = &mut self.slots[i];
        if idx >= BLOCK_PAGES {
            return Claim::None;
        }
        if s.is_done(idx) {
            return Claim::Installed;
        }
        if s.is_handed(idx) {
            return Claim::Busy;
        }
        s.set(idx, true);
        Claim::Frame { run: s.pa, pa: s.pa + idx * PAGE_SIZE }
    }

    /// Take back a frame handed out by [`claim`] whose install did not
    /// happen. `true`: the reservation holds it again. `false`: the entry is
    /// gone or is another run's (broken, maybe made again meanwhile), so the
    /// frame is the caller's to free.
    pub fn unclaim(&mut self, root: usize, block_va: usize, run: usize, idx: usize) -> bool {
        match self.position(root, block_va) {
            Some(i) if self.slots[i].pa == run && idx < BLOCK_PAGES => {
                self.slots[i].set(idx, false);
                true
            }
            _ => false,
        }
    }

    /// Note that a frame handed out by [`claim`] is now installed.
    pub fn installed(&mut self, root: usize, block_va: usize, run: usize, idx: usize) -> Filled {
        let Some(i) = self.position(root, block_va) else { return Filled::Gone };
        if self.slots[i].pa != run || idx >= BLOCK_PAGES || !self.slots[i].is_handed(idx) {
            return Filled::Gone;
        }
        let s = &mut self.slots[i];
        if s.is_done(idx) {
            return Filled::Partial;
        }
        s.done[idx / 64] |= 1u64 << (idx % 64);
        s.installed += 1;
        if s.installed as usize == BLOCK_PAGES {
            let done = *s;
            *s = Resv::EMPTY;
            Filled::Complete(done)
        } else {
            Filled::Partial
        }
    }

    fn take_at(&mut self, i: usize) -> Resv {
        let r = self.slots[i];
        self.slots[i] = Resv::EMPTY;
        r
    }

    /// Remove one reservation of `root` whose block overlaps `[s, e)`. Call
    /// until `None`: a cut of a region (`munmap`, `mprotect` of a part)
    /// breaks every block it touches.
    pub fn take_overlapping(&mut self, root: usize, s: usize, e: usize) -> Option<Resv> {
        let i = self.slots.iter().position(|r| r.root == root && r.va < e && s < r.va + BLOCK_SIZE)?;
        Some(self.take_at(i))
    }

    /// Remove one reservation of `root`, whatever its block: a fork or an
    /// exit breaks them all.
    pub fn take_root(&mut self, root: usize) -> Option<Resv> {
        if root == 0 {
            return None;
        }
        let i = self.slots.iter().position(|r| r.root == root)?;
        Some(self.take_at(i))
    }

    /// Remove the reservation holding the most unused frames, of any
    /// address space: what an allocator that ran dry reclaims first.
    pub fn take_richest(&mut self) -> Option<Resv> {
        let mut best: Option<(usize, usize)> = None;
        for (i, s) in self.slots.iter().enumerate().filter(|(_, s)| s.root != 0) {
            let unused = BLOCK_PAGES - s.handed();
            if best.map_or(true, |(_, u)| unused > u) {
                best = Some((i, unused));
            }
        }
        let (i, _) = best?;
        Some(self.take_at(i))
    }
}
