// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Accessed-bit seam of page aging (MM-MGLRU): the walk behind
//! [`Mmu::harvest_accessed`] and [`Mmu::resolve_accessed_fault`].
//!
//! One walker for every ISA, built only from the word-level methods the
//! three ports already implement ([`Mmu::vpn`], [`Mmu::pte_is_leaf`],
//! [`Mmu::pte_phys`], [`Mmu::pte_perms`], the contiguous-run family) and the
//! two aging primitives each port adds ([`Mmu::pte_accessed_bit`] and
//! [`Mmu::table_word`]). A port cannot disagree with another on what a run or
//! a block does, because there is one copy of the rule.
//!
//! The rules:
//! * **Only user leaves.** A table word, an empty or marker word, and a leaf
//!   with `user = false` are never touched: the kernel half a user root
//!   shares is not aged through a user root.
//! * **Atomic read-modify-write, never a store.** A CPU with hardware
//!   dirty-state updates may set D in the same word while A is cleared; a
//!   compare-and-swap that retries on a changed word cannot lose it (a plain
//!   store would, and the reclaimer would then drop a dirty page as clean).
//! * **A run is one unit.** The sixteen words of an aarch64 contiguous run
//!   or a riscv64 Svnapot run must stay equal, so the run's A is the OR of its
//!   members' and clearing or setting it touches every member.
//! * **A block is one unit.** A 2 MiB or 1 GiB leaf has one A bit: it is
//!   reported for every page of the range the leaf covers.

use crate::Mmu;
use core::sync::atomic::{AtomicU64, Ordering};

/// Most pages one [`Mmu::harvest_accessed`] call reports: one bit each in the
/// `u64` it returns.
pub const HARVEST_MAX_PAGES: usize = 64;

/// Where a walk toward one address stopped.
enum Slot {
    /// A leaf word at `level`, translating `span` bytes.
    Leaf { word: *const AtomicU64, level: usize, span: usize },
    /// No leaf: an empty (or marker, or demand) word covering `span` bytes,
    /// none of them mapped.
    Hole { span: usize },
}

/// Bytes one entry at `level` translates.
#[inline]
fn level_span<M: Mmu + ?Sized>(m: &M, level: usize) -> usize {
    M::PAGE_SIZE << (level * m.entries_per_table().trailing_zeros() as usize)
}

/// Walk `root_phys` toward `va` and stop at the first leaf or hole.
fn find<M: Mmu + ?Sized>(m: &M, root_phys: usize, va: usize) -> Slot {
    let mut table = root_phys;
    let mut level = m.levels() - 1;
    loop {
        let word = m.table_word(table + m.vpn(va, level) * 8);
        // SAFETY: `table` is a live page-table frame (the caller holds the
        // address space), so the word is an aligned entry of it.
        let w = unsafe { (*word).load(Ordering::Acquire) };
        let span = level_span(m, level);
        if m.pte_is_valid(w) && m.pte_is_leaf(w, level) {
            return Slot::Leaf { word, level, span };
        }
        if level == 0 || !m.pte_is_table(w, level) {
            return Slot::Hole { span };
        }
        table = m.pte_phys(w);
        level -= 1;
    }
}

/// Apply `f` atomically to the user leaf at `word`, a leaf of `level`: `f`
/// sees the current word and returns the new one, or `None` to leave it. The
/// compare-and-swap is retried while the word changes under it, and every
/// attempt re-checks that the word is still a user leaf, so a slot unmapped or
/// repointed since the walk is left alone.
///
/// Returns `(had_accessed, changed)`: whether the word `f` last saw had A set,
/// and whether `f`'s result was written.
fn rmw_leaf<M: Mmu + ?Sized>(m: &M, level: usize, word: &AtomicU64, f: &impl Fn(u64) -> Option<u64>) -> (bool, bool) {
    let bit = m.pte_accessed_bit();
    let mut cur = word.load(Ordering::Acquire);
    loop {
        if !(m.pte_is_valid(cur) && m.pte_is_leaf(cur, level) && m.pte_perms(cur).user) {
            return (false, false);
        }
        let had = cur & bit != 0;
        let Some(new) = f(cur) else { return (had, false) };
        match word.compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return (had, true),
            Err(now) => cur = now,
        }
    }
}

/// Run `f` (see [`rmw_leaf`]) on the leaf at `word` and, when it is a member
/// of a contiguous run, on every other member too. Returns `(any_had_accessed,
/// any_changed, span_bytes)`: the span is the run's, or the leaf's own `span`
/// for a plain leaf or a block.
fn rmw_unit<M: Mmu + ?Sized>(
    m: &M, word: *const AtomicU64, level: usize, va: usize, span: usize, f: impl Fn(u64) -> Option<u64>,
) -> (bool, bool, usize) {
    // SAFETY: `word` was returned by `find` for a live table.
    let w = unsafe { &*word };
    let run = m.contig_run_pages();
    if level != 0 || run == 0 || !m.pte_is_contig(w.load(Ordering::Acquire)) {
        let (had, changed) = rmw_leaf(m, level, w, &f);
        return (had, changed, span);
    }
    let idx = m.vpn(va, 0);
    let first = idx & !(run - 1);
    // SAFETY: the run is `run` aligned slots of the one level-0 table `word` is in.
    let head = unsafe { word.sub(idx - first) };
    let (mut had, mut changed) = (false, false);
    for k in 0..run {
        // SAFETY: as above.
        let member = unsafe { &*head.add(k) };
        let (h, c) = rmw_leaf(m, 0, member, &f);
        had |= h;
        changed |= c;
    }
    (had, changed, run * M::PAGE_SIZE)
}

/// [`Mmu::harvest_accessed`].
pub(crate) fn harvest<M: Mmu + ?Sized>(m: &M, root_phys: usize, va: usize, pages: usize) -> u64 {
    let bit = m.pte_accessed_bit();
    if bit == 0 {
        return 0;
    }
    let start = va & !(M::PAGE_SIZE - 1);
    let end = start + pages.min(HARVEST_MAX_PAGES) * M::PAGE_SIZE;
    let mut bitmap = 0u64;
    let mut cur = start;
    while cur < end {
        let (accessed, span) = match find(m, root_phys, cur) {
            Slot::Hole { span } => (false, span),
            Slot::Leaf { word, level, span } => {
                let (had, _, span) = rmw_unit(m, word, level, cur, span, |c| (c & bit != 0).then_some(c & !bit));
                (had, span)
            }
        };
        let next = (cur & !(span - 1)) + span;
        if accessed {
            // Every page of [cur, next) inside the range: one A covers them all.
            let n = (next.min(end) - cur) / M::PAGE_SIZE;
            let ones = if n >= 64 { u64::MAX } else { (1u64 << n) - 1 };
            bitmap |= ones << ((cur - start) / M::PAGE_SIZE);
        }
        cur = next;
    }
    bitmap
}

/// [`Mmu::resolve_accessed_fault`].
pub(crate) fn resolve<M: Mmu + ?Sized>(m: &M, root_phys: usize, va: usize) -> bool {
    let bit = m.pte_accessed_bit();
    if bit == 0 {
        return false;
    }
    let Slot::Leaf { word, level, span } = find(m, root_phys, va) else { return false };
    let (_, changed, _) = rmw_unit(m, word, level, va, span, |c| (c & bit == 0).then_some(c | bit));
    if changed {
        m.flush_tlb_page(va);
    }
    changed
}
