// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-hart TLB generation: what lets a user address-space switch skip the
//! TLB flush (Kconfig `TLB_RETAIN`, N12).
//!
//! An ASID is unique among the address spaces allocated in one generation
//! (`azos_sched::asid`). [`HART_TLB_GEN`]`[h]` is the generation whose
//! entries hart `h`'s TLB may hold, or [`STALE`]: it may hold entries some
//! shootdown did not reach. A switch into an address space of generation
//! `g` flushes iff the hart's value is not `g` (a rollover, or a stale
//! hart), then records `g`. So a hart never runs an ASID with entries left
//! by another address space that carried the same ASID in another
//! generation, nor with entries a shootdown skipped.
//!
//! **Shootdowns.** A hart that ran an address space and switched away keeps
//! its entries. The ISA shootdowns reach only the harts running the space
//! now (riscv64, x86_64) or flush only the current PCID locally (x86_64
//! `invlpg`), so they call [`mark_all_stale`] after the PTE store: every
//! other hart flushes at its next user switch. aarch64 invalidates with a
//! broadcast `TLBI ... IS` over every ASID and needs no mark.
//!
//! **Ordering (store-buffering, fenced on both sides).**
//!   shooter:  store PTE; store STALE (all); fence; load published roots
//!   switcher: publish root; fence; swap HART_TLB_GEN; csrw/msr/mov root
//! Either the shooter sees the published root and signals the hart, or the
//! switcher's swap reads STALE and the switch flushes.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Size of the per-hart arrays: Kconfig `NR_CPUS`.
pub const HARTS: usize = azos_limits::NR_CPUS;

/// "This hart's TLB may hold entries a shootdown skipped." Generations
/// start at 1, so no address space ever carries it.
pub const STALE: u32 = 0;

/// Per hart: the generation its TLB is clean for, or [`STALE`].
pub static HART_TLB_GEN: [AtomicU32; HARTS] = [const { AtomicU32::new(STALE) }; HARTS];

/// Per hart, read by `context_switch.S` right after it installs a new user
/// root: nonzero means flush (riscv64 `sfence.vma`, aarch64 `tlbi vmalle1`;
/// on x86_64 zero sets the CR3 no-flush bit). Written by
/// `azos_sched::asid::prepare_switch` on the same hart just before the
/// switch, so plain loads suffice in the assembly.
#[no_mangle]
pub static AZOS_TLB_SWITCH_FLUSH: [AtomicU64; HARTS] = [const { AtomicU64::new(1) }; HARTS];

/// Hart `h`'s TLB may hold entries a shootdown skipped (or it installed a
/// root outside the generation scheme): its next user switch flushes.
#[inline]
pub fn mark_stale(h: usize) {
    if azos_limits::TLB_RETAIN && h < HARTS {
        HART_TLB_GEN[h].store(STALE, Ordering::Release);
    }
}

/// Every hart but `except` (`usize::MAX`: every hart) flushes at its next
/// user switch. Called by a shootdown after its PTE store and before the
/// fence that orders it against the published roots.
#[inline]
pub fn mark_all_stale(except: usize) {
    if !azos_limits::TLB_RETAIN {
        return;
    }
    for (h, g) in HART_TLB_GEN.iter().enumerate() {
        if h != except {
            g.store(STALE, Ordering::Release);
        }
    }
}

/// The switch on hart `h` into a root of generation `gen`: record `gen` and
/// return the hart's previous value. The TLB must be flushed unless it
/// equals `gen` ([`STALE`]: a shootdown skipped this hart; another
/// generation: a rollover). The caller has published the root and fenced
/// (module doc).
#[inline]
pub fn enter(h: usize, gen: u32) -> u32 {
    if h >= HARTS {
        return STALE;
    }
    HART_TLB_GEN[h].swap(gen, Ordering::AcqRel)
}

/// Set this hart's switch-flush word for `context_switch.S`: 0 keep the TLB,
/// 1 flush when the root changes (the old behaviour), 2 flush even when
/// it does not.
#[inline]
pub fn set_switch_flush_word(h: usize, w: u64) {
    if h < HARTS {
        AZOS_TLB_SWITCH_FLUSH[h].store(w, Ordering::Relaxed);
    }
}
