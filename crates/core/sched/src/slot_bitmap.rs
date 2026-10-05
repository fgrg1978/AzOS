// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A bitmap over task-pool slots, sized from the slot count at compile time,
//! and the claim pass of `scheduler::ring_claim_audit` written over it.
//!
//! The audit used one `u64` over task slots, which holds 64 slots; the fleet
//! profile has 4096 (`config/Kconfig.limits` `MAX_TASKS`). The bitmap here is
//! `[u64; W]` with `W = words_for(MAX_TASKS)`, one word at the edge value.
//!
//! **Why a file of its own.** `scheduler.rs` does not compile for the host
//! (static `PER_CPU`, CSR reads, `kprintln!`), so nothing it computes can be
//! executed by a host test. This file depends on `core` alone:
//! `tests/host/sched-policy-tests` pulls it in with `#[path]` and runs the pass
//! with slot indices past 64. `scheduler.rs` declares it with `#[path]` too, so
//! the kernel and the test compile the same text.
//!
//! **No panics.** The pass runs from the timer ISR, where a panic resets the
//! board. Every index into the words is `get`/`get_mut`, and every shift is
//! reduced mod 64 first, so no input panics or indexes out of range.

/// Bits in one word of a [`SlotBitmap`].
pub const WORD_BITS: usize = u64::BITS as usize;

/// The number of words that hold `slots` bits.
pub const fn words_for(slots: usize) -> usize {
    slots.div_ceil(WORD_BITS)
}

/// The in-word bit of slot `idx`: its position within its word.
#[inline(always)]
const fn bit(idx: usize) -> u64 {
    1u64 << (idx % WORD_BITS)
}

/// A set of task-pool slots, `W` words of 64 bits.
#[derive(Clone, Copy)]
pub struct SlotBitmap<const W: usize> {
    words: [u64; W],
}

impl<const W: usize> SlotBitmap<W> {
    /// The empty set.
    pub const fn new() -> Self {
        Self { words: [0; W] }
    }

    /// The number of slots the bitmap can name, `W × 64`.
    pub const fn capacity() -> usize {
        W * WORD_BITS
    }

    /// Adds slot `idx` and returns whether it was already present. A slot past
    /// [`capacity`](Self::capacity) is not stored and reads as not present.
    #[inline(always)]
    pub fn insert(&mut self, idx: usize) -> bool {
        match self.words.get_mut(idx / WORD_BITS) {
            Some(w) => {
                let was = *w & bit(idx) != 0;
                *w |= bit(idx);
                was
            }
            None => false,
        }
    }

    /// Whether slot `idx` is present. A slot past the capacity never is.
    #[inline(always)]
    pub fn contains(&self, idx: usize) -> bool {
        match self.words.get(idx / WORD_BITS) {
            Some(w) => *w & bit(idx) != 0,
            None => false,
        }
    }
}

/// What one claim pass found. The first two are counts over slots 0..`slots`;
/// `persistent` counts the slots reported through `report`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimCounts {
    /// Slots whose `queued` claim is set while no ring holds an entry for them.
    pub claim_no_entry: u32,
    /// Slots some ring holds an entry for while their claim is clear.
    pub entry_no_claim: u32,
    /// Slots in `claim_no_entry` in this sample and in the previous one.
    pub persistent: u32,
}

/// The claim half of `ring_claim_audit`: compares each slot's `queued` claim
/// with `present`, the set of slots some ring holds an entry for, one word of
/// 64 slots at a time.
///
/// * `claim(i)` is `None` for a slot that holds no task, and otherwise whether
///   slot `i` claims a queue entry.
/// * `swap_prev(w, mask)` stores `mask`, word `w` of this sample's
///   claim-without-entry set, and returns the word it replaces (the kernel's
///   `PREV_CLAIM_NO_ENTRY[w].swap`).
/// * `persistent_of(prev, cur)` is the two-sample filter
///   (`task::claim_audit_persistent`), applied to each word.
/// * `report(i)` is called once for each slot in the persistent set, in
///   ascending order.
///
/// Word by word, so the only per-sample storage is `present` (the caller's)
/// and one `u64`: the persistent set is never held whole.
#[inline(always)]
pub fn claim_pass<const W: usize>(
    present: &SlotBitmap<W>,
    slots: usize,
    mut claim: impl FnMut(usize) -> Option<bool>,
    mut swap_prev: impl FnMut(usize, u64) -> u64,
    persistent_of: impl Fn(u64, u64) -> u64,
    mut report: impl FnMut(usize),
) -> ClaimCounts {
    let slots = if slots < SlotBitmap::<W>::capacity() { slots } else { SlotBitmap::<W>::capacity() };
    let mut counts = ClaimCounts { claim_no_entry: 0, entry_no_claim: 0, persistent: 0 };
    let mut w = 0;
    while w * WORD_BITS < slots {
        let base = w * WORD_BITS;
        let end = if slots - base < WORD_BITS { slots } else { base + WORD_BITS };
        let mut mask: u64 = 0;
        let mut i = base;
        while i < end {
            if let Some(claimed) = claim(i) {
                let listed = present.contains(i);
                if claimed && !listed {
                    mask |= bit(i);
                    counts.claim_no_entry += 1;
                }
                if listed && !claimed {
                    counts.entry_no_claim += 1;
                }
            }
            i += 1;
        }
        let persistent = persistent_of(swap_prev(w, mask), mask);
        if persistent != 0 {
            let mut rest = persistent;
            while rest != 0 {
                let b = rest.trailing_zeros() as usize;
                rest &= rest - 1;
                counts.persistent += 1;
                report(base + b);
            }
        }
        w += 1;
    }
    counts
}
