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
//! next time it is switched in ([`prepare_switch`]).
//!
//! **One ASID per address space (owner decision 10-10).** The space's ASID
//! lives in the per-space record `tlb_gen::SPACES`, keyed by the root frame
//! (`ArchPlatform::user_root_frame`), not in the threads: a re-tag looks the
//! record up under [`LOCK`] and adopts the space's ASID when another thread
//! already took one this generation, so the first thread of a space to be
//! switched in after a rollover re-tags the whole space and the rest follow
//! it. Within one generation a space has exactly one ASID, so a hart whose
//! live ASID for a space is `a` holds that space's entries under `a` only;
//! that is what makes an ASID-scoped invalidation sound (riscv64, Kconfig
//! `TLB_ASID_SCOPED`). A thread's word is rewritten when it is switched in,
//! so a thread still RUNNING across a rollover keeps the old generation's
//! ASID on its hart until then; a scoped shootdown flushes such a hart in
//! full (its published ASID differs from the record).
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

use azos_arch::{ArchPlatform, Cpu, Interrupts, ARCH};
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

/// Serialises allocation (fork, exec, a stale switch-in): rare. Held with
/// interrupts masked ([`lock`]): the switch path takes it with interrupts
/// off, so a holder preempted on its own hart would leave that hart
/// spinning on it forever.
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

/// Take [`LOCK`] with this hart's interrupts masked; returns the state
/// [`unlock`] restores. Masked because `prepare_switch_slow` takes the lock
/// inside the scheduler with interrupts off: a holder in a preemptible task
/// (fork, exec, a ktest) that a tick switched out between taking and
/// releasing it would leave its hart spinning in that switch for the lock
/// it can no longer release. A forced or natural rollover makes it likely:
/// the holder advances the generation, so every user task the switch picks
/// next needs the lock (ktest `asid_one_per_space_across_rollover`, the
/// disk boot on aarch64).
fn lock() -> azos_arch_api::InterruptState {
    let irq = ARCH.disable_all();
    while LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
    irq
}

fn unlock(irq: azos_arch_api::InterruptState) {
    LOCK.store(false, Ordering::Release);
    ARCH.restore(irq);
}

/// Rollover: a new generation. Under [`LOCK`]. Every hart's recorded
/// generation is now old, so each flushes before it runs an ASID handed
/// out after this. The per-space table empties first (`tlb_gen` module
/// doc): a hart that reads the new generation records after the reset.
fn rollover_locked() {
    if tlb_gen::SPACE_RECORD {
        tlb_gen::SPACES.reset(GEN.load(Ordering::Relaxed).wrapping_add(1));
    }
    GEN.fetch_add(1, Ordering::AcqRel);
    ASID_ROLLOVERS.fetch_add(1, Ordering::Relaxed);
    NEXT_ASID.store(1, Ordering::Relaxed);
}

/// Record `word` as the owner of ASID `a` in the current generation.
fn record_slot(a: u16, word: usize) {
    if RETAIN && (a as usize) < NSLOTS {
        // Word before generation (Release): a reader that sees this
        // generation also sees this word (`owns`).
        SLOT_WORD[a as usize].store(word as u64, Ordering::Relaxed);
        SLOT_GEN[a as usize].store(GEN.load(Ordering::Relaxed), Ordering::Release);
    }
}

/// Runtime canary `asid-per-thread` (`kernel/src/canary_rt.rs`): a re-tag
/// ignores the space's record and takes a fresh ASID per thread, the
/// pre-10-10 behaviour (ktest `asid_one_per_space_across_rollover`).
pub static CANARY_ASID_PER_THREAD: AtomicBool = AtomicBool::new(false);

/// Hand out the next ASID and its generation; `word_of` builds the root word
/// that owns it, recorded in its slot under the same lock. `key` (the root
/// frame, 0: none) names the address space: with `adopt`, a space that
/// already holds an ASID this generation gets that one back (a re-tag);
/// otherwise the new ASID becomes the space's record (a new space, or a
/// reused root frame). A full record table rolls the generation over.
fn alloc(key: usize, adopt: bool, word_of: impl Fn(u16) -> usize) -> usize {
    let max = ASID_MAX.load(Ordering::Relaxed);
    if max == 0 {
        return word_of(0);
    }
    let irq = lock();
    let rec = tlb_gen::SPACE_RECORD && key != 0;
    if rec && adopt && !CANARY_ASID_PER_THREAD.load(Ordering::Relaxed) {
        let a = tlb_gen::SPACES.asid_of(key);
        if a != 0 {
            let word = word_of(a);
            record_slot(a, word);
            unlock(irq);
            return word;
        }
    }
    let mut a = NEXT_ASID.load(Ordering::Relaxed);
    if a == 0 || a > max {
        rollover_locked();
        a = 1;
    }
    if rec && !tlb_gen::SPACES.assign(key, a) {
        // Every slot is taken: a new generation empties the table, so the
        // space never runs unrecorded (and with two ASIDs).
        rollover_locked();
        a = 1;
        let _ = tlb_gen::SPACES.assign(key, a);
    }
    NEXT_ASID.store(a.wrapping_add(1), Ordering::Relaxed);
    let word = word_of(a);
    record_slot(a, word);
    unlock(irq);
    word
}

/// The highest ASID this boot hands out (0: no ASID bits).
pub fn asid_max() -> u16 {
    ASID_MAX.load(Ordering::Relaxed)
}

/// Test hook (ktest `asid_rollover_no_stale_translation`): the next
/// allocation rolls the generation over, whatever `ASID_BITS` is.
pub fn force_rollover_next() {
    let irq = lock();
    NEXT_ASID.store(0, Ordering::Relaxed);
    unlock(irq);
}

/// Allocate an ASID for a new user root and return its root word.
pub fn new_root_word(root_phys: usize) -> usize {
    alloc(root_phys >> 12, false, |a| ARCH.user_root_word(root_phys, a))
}

/// The word a thread whose root word is `word` switches in with: `word`
/// itself while it owns its ASID this generation, else re-tagged to the
/// space's ASID (taking a new one when no thread of the space has yet this
/// generation). What [`prepare_switch`] does to the incoming task; public
/// for the ktest `asid_one_per_space_across_rollover`.
pub fn switch_word(word: usize) -> usize {
    let a = ARCH.user_root_asid(word);
    if owns(a, word, GEN.load(Ordering::Acquire)) {
        return word;
    }
    alloc(ARCH.user_root_frame(word), true, |na| ARCH.user_root_with_asid(word, na))
}

/// Legacy entry point: an ASID with no recorded owner. Kept for callers that
/// build the word themselves; their space re-tags at its first switch-in.
pub fn alloc_asid() -> u16 {
    let out = core::cell::Cell::new(0u16);
    alloc(0, false, |a| {
        out.set(a);
        0
    });
    out.get()
}

/// Whether `word` owns its ASID `a` in generation `g`.
#[inline]
fn owns(a: u16, word: usize, g: u32) -> bool {
    let i = a as usize;
    i < NSLOTS
        && SLOT_GEN[i].load(Ordering::Acquire) == g
        && SLOT_WORD[i].load(Ordering::Relaxed) == word as u64
}

/// Exec's install of its new user root on this hart (owner decision 10-10):
/// through the generation scheme, as [`prepare_switch`] does for a switch,
/// so the hart leaves exec tracked (`tlb_gen::enter_installed`) instead of
/// stale (riscv64, x86_64) or untracked (aarch64) until its next switch, and
/// an ASID-scoped shootdown in that window no longer falls back to every
/// ASID. A word whose ASID a rollover took since exec built it is re-tagged
/// first (the space's record, as at a switch-in) and becomes the current
/// task's `task_satp`. Returns the word installed: the hand-off's.
pub fn install_exec_root(word: usize) -> usize {
    let tracked = retaining()
        && word != 0
        && word as u64 != crate::kernel_task_satp()
        && ARCH.user_root_asid(word) != 0;
    if !tracked {
        ARCH.install_user_root_local(word);
        return word;
    }
    // One hart from the hart-id read to the generation entry.
    let irq = ARCH.disable_all();
    let h = ARCH.hart_id();
    let mut w = word;
    let mut g = GEN.load(Ordering::Acquire);
    if !owns(ARCH.user_root_asid(w), w, g) {
        w = switch_word(w);
        g = generation();
        crate::scheduler::set_current_task_satp(w as u64);
    }
    // As `prepare_switch`: record the hart for the space's shootdowns, then
    // the install (it flushes this hart's ASIDs and marks it outside the
    // scheme), then publish with its fence before the generation swap.
    tlb_gen::note_ran(ARCH.tlb_space_key(w), h);
    ARCH.install_user_root_local(w);
    ARCH.publish_user_root(w);
    if tlb_gen::enter_installed(h, g) {
        ARCH.flush_tlb_all_contexts_local();
    }
    ARCH.restore(irq);
    w
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
/// The hot case (wave 15, TLBC) is a task whose memo (`Task::tlb_memo_*`)
/// names its current word in the current generation with this hart
/// recorded: the word still owns its ASID (an ASID is handed out once per
/// generation, and a re-tag of the same space re-records the same word)
/// and the space's ran-mask still holds this hart (the table is emptied
/// only by a rollover, which advances the generation), so the switch only
/// publishes the root and swaps the hart's generation, the two steps of the
/// shootdown ordering (`tlb_gen` module doc). Everything else (a first
/// switch-in this generation, a re-tag, the kernel's root, a hand-made
/// root, a stale hart) takes [`prepare_switch_slow`].
///
/// # Safety
/// `next` must be a live task the caller is about to switch to.
#[inline(always)]
pub unsafe fn prepare_switch(next: *mut Task) {
    if !RETAIN {
        // The flush word stays at its initial "flush when the root changes"
        // (`tlb_gen::AZOS_TLB_SWITCH_FLUSH`): every writer is under
        // `TLB_RETAIN`.
        return;
    }
    let h = ARCH.hart_id();
    let t = &*next;
    let word = t.task_satp;
    let g = GEN.load(Ordering::Acquire);
    if word == t.tlb_memo_word
        && g == t.tlb_memo_gen
        && h < tlb_gen::HARTS
        && (t.tlb_memo_harts >> h) & 1 != 0
    {
        // The note is already in the table; publish (with its fence), then
        // read the hart's generation.
        ARCH.publish_user_root(word as usize);
        let prev = tlb_gen::enter(h, g);
        if prev == g {
            tlb_gen::set_switch_flush_word(h, KEEP);
            return;
        }
        enter_flush(h, prev);
        return;
    }
    prepare_switch_slow(next, h);
}

/// The hart's TLB was not clean for the generation it just entered
/// (`prev`: [`tlb_gen::STALE`], [`tlb_gen::UNTRACKED`] or an older
/// generation): flush every context and ask `context_switch.S` to flush.
#[inline(never)]
fn enter_flush(h: usize, prev: u32) {
    let mut flush = true;
    if prev != tlb_gen::STALE && CANARY_NO_ROLLOVER_FLUSH.load(Ordering::Relaxed) {
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

/// [`prepare_switch`] when the memo does not answer: the full protocol,
/// then the memo for the next switch-in.
#[inline(never)]
unsafe fn prepare_switch_slow(next: *mut Task, h: usize) {
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
        // outside the scheme, so flush and leave the hart untracked (stale,
        // and no ASID-scoped broadcast counts on it).
        tlb_gen::mark_untracked(h);
        tlb_gen::set_switch_flush_word(h, ALWAYS);
        return;
    }
    let mut g = GEN.load(Ordering::Acquire);
    if !owns(a, word, g) {
        word = switch_word(word);
        (*next).task_satp = word as u64;
        g = generation();
        // `alloc` recorded the word with the generation it read under the
        // lock; a rollover racing past it makes `g` newer, which only
        // forces a flush below and a re-tag at the next switch-in (the
        // memo is written only for a word that owns its ASID in `g`).
    }
    // Record this hart for the space's shootdowns (Kconfig `TLB_SPACE_MASK`),
    // before the publish's fence: a shooter that misses the record sees the
    // published root, or this hart's walk sees the shooter's PTE store.
    let noted = tlb_gen::note_ran(ARCH.tlb_space_key(word), h);
    // Publish the root before reading the hart's generation: a shooter that
    // misses the publication has already marked this hart stale
    // (`tlb_gen` module doc). The publish carries its own full fence
    // (riscv64 `tlb::publish`, x86_64 `tlb::publish`); aarch64 publishes
    // nothing and is never marked by another hart (broadcast TLBI).
    ARCH.publish_user_root(word);
    let prev = tlb_gen::enter(h, g);
    if prev == g {
        tlb_gen::set_switch_flush_word(h, KEEP);
    } else {
        enter_flush(h, prev);
    }
    // The memo: only facts true until `g` ends (the word owns its ASID in
    // `g`, this hart is in the space's ran-mask for `g`).
    if noted && h < tlb_gen::HARTS && owns(ARCH.user_root_asid(word), word, g) {
        let t = &mut *next;
        if t.tlb_memo_word != word as u64 || t.tlb_memo_gen != g {
            t.tlb_memo_word = word as u64;
            t.tlb_memo_gen = g;
            t.tlb_memo_harts = 0;
        }
        t.tlb_memo_harts |= 1u64 << h;
    }
}
