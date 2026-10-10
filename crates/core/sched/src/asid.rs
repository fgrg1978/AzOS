// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ASIDs with generations: user address-space switches keep the TLB
//! (Kconfig `TLB_RETAIN`, N12; Linux arm64 `asid.c` is the same scheme).
//!
//! **Allocation.** [`new_root_word`] hands out ASIDs 1, 2, ... up to the
//! highest the hardware and Kconfig `ASID_BITS` allow, all in the current
//! generation; past the last one the generation advances (a rollover,
//! counted) and allocation starts again at 1. Within one generation an ASID
//! names at most one address space.
//!
//! **The per-address-space object (P1a-core).** Slot `a` (`SLOT_WORD`, `SLOT_GEN`)
//! records the root word that holds ASID `a` and the generation it was
//! given in. An address space whose word no longer owns its slot in the
//! current generation (a rollover happened since) takes a fresh ASID the
//! next time it is switched in ([`prepare_switch`]); the word is rewritten
//! in the incoming task only, so threads of one space may carry different
//! ASIDs until each is switched in once. That is safe: every shootdown
//! names the root, not the ASID (riscv64 `sfence.vma va, zero` and
//! aarch64 `TLBI VAAE1IS` cover every ASID; x86_64 marks every CPU stale,
//! `azos_arch_api::tlb_gen`).
//!
//! **The switch.** A hart records the generation its TLB is clean for
//! (`tlb_gen::HART_TLB_GEN`). Switching into an address space of
//! generation `g` flushes iff the hart's value is not `g`: after a
//! rollover, every hart flushes once before it runs any ASID of the new
//! generation, so an ASID reused across generations never meets the old
//! owner's entries. A shootdown that cannot reach a hart marks it stale,
//! which forces the same flush.
//!
//! **Boards with no ASID bits** (and `TLB_RETAIN=n`) keep flush-on-switch:
//! [`prepare_switch`] asks `context_switch.S` to flush whenever the root
//! changes, as before.

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};

use azos_arch::{ArchPlatform, Cpu, ARCH};
use azos_arch_api::tlb_gen;

use crate::task::Task;

/// Kconfig `TLB_RETAIN`.
pub const RETAIN: bool = azos_limits::TLB_RETAIN;

/// Highest ASID [`new_root_word`] hands out: `2^ASID_BITS - 1` (Kconfig)
/// until the boot narrows it to what the hardware implements
/// ([`set_hw_asid_bits`]); 0 when the hardware has no ASID bits.
static ASID_MAX: AtomicU16 = AtomicU16::new(asid_max_for_bits(azos_limits::ASID_BITS as u32));

/// Next ASID to hand out (ASID 0 is the kernel's root). Under [`LOCK`].
static NEXT_ASID: AtomicU16 = AtomicU16::new(1);

/// The current generation. Starts at 1: `tlb_gen::STALE` is 0.
static GEN: AtomicU32 = AtomicU32::new(1);

/// Times the ASID space ran out and the generation advanced.
static ASID_ROLLOVERS: AtomicU32 = AtomicU32::new(0);

/// Serialises allocation (fork, exec, a stale switch-in): rare.
static LOCK: AtomicBool = AtomicBool::new(false);

/// Slot count: one per ASID with `TLB_RETAIN`, else one unused slot.
const NSLOTS: usize = if RETAIN { 1usize << azos_limits::ASID_BITS } else { 1 };

/// Per ASID: the root word that holds it (`ArchPlatform::user_root_word`).
static SLOT_WORD: [AtomicU64; NSLOTS] = [const { AtomicU64::new(0) }; NSLOTS];
/// Per ASID: the generation it was handed out in (0: never).
static SLOT_GEN: [AtomicU32; NSLOTS] = [const { AtomicU32::new(0) }; NSLOTS];

/// Runtime canary `asid-rollover-noflush` (`kernel/src/canary_rt.rs`): a
/// generation change does not flush, so the rollover ktest must read the
/// previous owner's translation.
pub static CANARY_NO_ROLLOVER_FLUSH: AtomicBool = AtomicBool::new(false);

const fn asid_max_for_bits(bits: u32) -> u16 {
    if bits == 0 { 0 } else if bits >= 16 { u16::MAX } else { ((1u32 << bits) - 1) as u16 }
}

/// Narrow the ASID space to the `bits` the boot hart's MMU implements (never
/// widen it past Kconfig `ASID_BITS`). Boot only, before the first user task.
/// Returns the highest ASID [`new_root_word`] will hand out.
pub fn set_hw_asid_bits(bits: u32) -> u16 {
    let max = asid_max_for_bits(bits.min(azos_limits::ASID_BITS as u32));
    ASID_MAX.store(max, Ordering::Relaxed);
    max
}

/// Times the ASID space ran out and the generation advanced.
pub fn asid_rollovers() -> u32 {
    ASID_ROLLOVERS.load(Ordering::Relaxed)
}

/// The current ASID generation.
pub fn generation() -> u32 {
    GEN.load(Ordering::Acquire)
}

/// Whether switches keep the TLB on this boot: `TLB_RETAIN` and an MMU with
/// ASID bits.
#[inline]
pub fn retaining() -> bool {
    RETAIN && ASID_MAX.load(Ordering::Relaxed) != 0
}

fn lock() {
    while LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
}

fn unlock() {
    LOCK.store(false, Ordering::Release);
}

/// Hand out the next ASID and its generation; `word_of` builds the root word
/// that owns it, recorded in its slot under the same lock.
fn alloc(word_of: impl FnOnce(u16) -> usize) -> usize {
    let max = ASID_MAX.load(Ordering::Relaxed);
    if max == 0 {
        return word_of(0);
    }
    lock();
    let mut a = NEXT_ASID.load(Ordering::Relaxed);
    if a == 0 || a > max {
        // Rollover: a new generation. Every hart's recorded generation is
        // now old, so each flushes before it runs an ASID handed out below.
        GEN.fetch_add(1, Ordering::AcqRel);
        ASID_ROLLOVERS.fetch_add(1, Ordering::Relaxed);
        a = 1;
    }
    NEXT_ASID.store(a.wrapping_add(1), Ordering::Relaxed);
    let word = word_of(a);
    if RETAIN && (a as usize) < NSLOTS {
        // Word before generation (Release): a reader that sees this
        // generation also sees this word (`owns`).
        SLOT_WORD[a as usize].store(word as u64, Ordering::Relaxed);
        SLOT_GEN[a as usize].store(GEN.load(Ordering::Relaxed), Ordering::Release);
    }
    unlock();
    word
}

/// The highest ASID this boot hands out (0: no ASID bits).
pub fn asid_max() -> u16 {
    ASID_MAX.load(Ordering::Relaxed)
}

/// Test hook (ktest `asid_rollover_no_stale_translation`): the next
/// allocation rolls the generation over, whatever `ASID_BITS` is.
pub fn force_rollover_next() {
    lock();
    NEXT_ASID.store(0, Ordering::Relaxed);
    unlock();
}

/// Allocate an ASID for a new user root and return its root word.
pub fn new_root_word(root_phys: usize) -> usize {
    alloc(|a| ARCH.user_root_word(root_phys, a))
}

/// Legacy entry point: an ASID with no recorded owner. Kept for callers that
/// build the word themselves; their space re-tags at its first switch-in.
pub fn alloc_asid() -> u16 {
    let mut out = 0;
    alloc(|a| {
        out = a;
        0
    });
    out
}

/// Whether `word` owns its ASID `a` in generation `g`.
#[inline]
fn owns(a: u16, word: usize, g: u32) -> bool {
    let i = a as usize;
    i < NSLOTS
        && SLOT_GEN[i].load(Ordering::Acquire) == g
        && SLOT_WORD[i].load(Ordering::Relaxed) == word as u64
}

/// The flush words `context_switch.S` reads (`tlb_gen::AZOS_TLB_SWITCH_FLUSH`).
const KEEP: u64 = 0;
/// Flush when the root changes: the old behaviour.
const ON_CHANGE: u64 = 1;
/// Flush even when the root does not change.
const ALWAYS: u64 = 2;

/// Prepare this hart's switch into `next`: re-tag its root word if a
/// rollover took its ASID, and tell `context_switch.S` whether to flush
/// (`tlb_gen::AZOS_TLB_SWITCH_FLUSH`). Call with interrupts masked, right
/// before `context_switch`, on the hart that will switch.
///
/// # Safety
/// `next` must be a live task the caller is about to switch to.
#[inline]
pub unsafe fn prepare_switch(next: *mut Task) {
    let h = ARCH.hart_id();
    if !retaining() {
        tlb_gen::set_switch_flush_word(h, ON_CHANGE);
        return;
    }
    let mut word = (*next).task_satp as usize;
    let a = ARCH.user_root_asid(word);
    if word == 0 || word as u64 == crate::kernel_task_satp() {
        // The kernel's own root (ASID 0, or "keep the live root"): nothing
        // a user ASID can collide with, nothing to record.
        tlb_gen::set_switch_flush_word(h, KEEP);
        return;
    }
    if a == 0 {
        // A user root built without an ASID (a smoke's hand-made root):
        // outside the scheme, so flush and leave the hart stale.
        tlb_gen::mark_stale(h);
        tlb_gen::set_switch_flush_word(h, ALWAYS);
        return;
    }
    let mut g = GEN.load(Ordering::Acquire);
    if !owns(a, word, g) {
        word = alloc(|na| ARCH.user_root_with_asid(word, na));
        (*next).task_satp = word as u64;
        g = generation();
        // `alloc` recorded the word with the generation it read under the
        // lock; a rollover racing past it makes `g` newer, which only
        // forces a flush below and a re-tag at the next switch-in.
    }
    // Publish the root before reading the hart's generation: a shooter that
    // misses the publication has already marked this hart stale
    // (`tlb_gen` module doc). The publish carries its own full fence
    // (riscv64 `tlb::publish`, x86_64 `tlb::publish`); aarch64 publishes
    // nothing and is never marked by another hart (broadcast TLBI).
    ARCH.publish_user_root(word);
    let prev = tlb_gen::enter(h, g);
    let mut flush = prev != g;
    if flush && prev != tlb_gen::STALE && CANARY_NO_ROLLOVER_FLUSH.load(Ordering::Relaxed) {
        // The canary skips the generation (rollover) flush only; a stale
        // hart still flushes.
        flush = false;
    }
    if flush {
        // Every context's entries go (x86_64: all PCIDs; a no-op where the
        // switch's own flush already covers every ASID).
        ARCH.flush_tlb_all_contexts_local();
    }
    tlb_gen::set_switch_flush_word(h, if flush { ALWAYS } else { KEEP });
}
