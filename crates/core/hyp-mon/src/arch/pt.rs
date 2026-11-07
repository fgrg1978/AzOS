// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel half's page tables (I3). `pt_lock_pool` takes the pool the kernel
//! built them in, checks every word already there, and makes the pool
//! read-only for the host; from then on a word changes only through `pt_set`,
//! which checks it (`ptcheck.rs`), keeps the level each pool page serves, and
//! refuses any change to a slot that maps the locked image or leads to one.
//! Canaries: `hyp-pt-pool-open-canary` leaves the pool writable,
//! `hyp-pt-check-skip-canary` writes whatever it is asked.

use super::pin;
use super::ptcheck::*;
use super::s2;
use crate::state::HYP;
use azos_hyp_api::{
    pt_entry_error, pt_pool_error, DENIED, INVALID, INV_KERNEL_TABLES, NOT_SUPPORTED, OK, PT_POOL_PAGES_MAX, RACED,
};
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

const LEVELS: usize = pte_fmt::LEVELS;

static ONCE: AtomicU64 = AtomicU64::new(0);
/// The pool `[base, end)` and its granule, published once the pool is read-only.
static POOL: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static SHIFT: AtomicU64 = AtomicU64::new(0);
static READY: AtomicU64 = AtomicU64::new(0);
/// The kernel half's `TTBR1_EL1` root and the `TCR_EL1` the pool was locked
/// under, which every PE that pins afterwards must have.
static LOCKED_TTBR1: AtomicU64 = AtomicU64::new(0);
static LOCKED_TCR: AtomicU64 = AtomicU64::new(0);
static LOCKED_SCTLR: AtomicU64 = AtomicU64::new(0);
static TAGS: [AtomicU8; PT_POOL_PAGES_MAX as usize] = [const { AtomicU8::new(0) }; PT_POOL_PAGES_MAX as usize];

fn page_index(pa: u64, base: u64, shift: u32) -> usize {
    ((pa - base) >> shift) as usize
}

fn claim_tag(idx: usize, level: usize) -> Result<(), &'static str> {
    let t = &TAGS[idx];
    loop {
        let cur = t.load(Ordering::Acquire);
        let new = claim(cur, level)?;
        if new == cur || t.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return Ok(());
        }
    }
}

fn in_pool(pa: u64, base: u64, end: u64, shift: u32) -> bool {
    pa >= base && pa < end && (pa - base) % (1 << shift) == 0
}

/// Check the table at `pa` (level `level`) and everything below it, tagging
/// the pages on the way. `Ok(true)`: it maps the image or leads to a table
/// that does.
fn scan(pa: u64, level: usize, base: u64, end: u64, shift: u32, image: &[[u64; 2]]) -> Result<bool, &'static str> {
    let idx = page_index(pa, base, shift);
    claim_tag(idx, level)?;
    let mut has_image = false;
    for i in 0..1u64 << (shift - 3) {
        // SAFETY: the EL2 identity map covers RAM; the page is in the pool, the kernel's until the pool is locked.
        let word = unsafe { core::ptr::read_volatile((pa + i * 8) as *const u64) };
        let w = classify(word, level, shift)?;
        if let Some(e) = lock_word_error(w, word, level, image) { return Err(e); }
        match w {
            Word::Table(t) => {
                if !in_pool(t, base, end, shift) { return Err("table outside the pool"); }
                has_image |= scan(t, level - 1, base, end, shift, image)?;
            }
            leaf => has_image |= maps_image(leaf, image),
        }
    }
    if has_image {
        TAGS[idx].fetch_or(TAG_IMAGE, Ordering::AcqRel);
    }
    Ok(has_image)
}

/// Is any page of the pool that the scan did not reach not empty? A page with
/// words in it that nothing checked would go live unchecked when it is linked.
fn unreached_not_empty(base: u64, pages: u64, shift: u32) -> bool {
    (0..pages as usize).any(|i| {
        let words = (0..1u64 << (shift - 3)).map(|w| {
            // SAFETY: the EL2 identity map covers RAM; the page is in the pool.
            unsafe { core::ptr::read_volatile((base + ((i as u64) << shift) + w * 8) as *const u64) }
        });
        unreached_error(TAGS[i].load(Ordering::Acquire), words).is_some()
    })
}

/// The registers the pool was locked under, once it is locked.
pub fn locked_regs() -> Option<Locked> {
    (READY.load(Ordering::Acquire) != 0).then(|| Locked {
        ttbr1: LOCKED_TTBR1.load(Ordering::Relaxed),
        tcr: LOCKED_TCR.load(Ordering::Relaxed),
        sctlr: LOCKED_SCTLR.load(Ordering::Relaxed),
    })
}

/// Why this PE may not run the kernel half: after the pool lock, its
/// `TTBR1_EL1`, `TCR_EL1` and `SCTLR_EL1` must be the locked ones.
pub fn pe_error() -> Option<&'static str> {
    pe_regs_error(pin::walk_regs(), locked_regs()?)
}

/// A core entering EL1 at the secondary or resume entry, after the pool lock:
/// it gets the locked `TTBR1_EL1` and `TCR_EL1` and the writes to them are
/// trapped before it runs, so the kernel's own load of them (writable data) does
/// not reach the MMU.
pub fn enter_pe() {
    let Some(plan) = entry_plan(locked_regs()) else { return };
    // SAFETY: this PE's EL1 registers, set while it is at EL2 and its MMU is off.
    unsafe { core::arch::asm!("msr TTBR1_EL1, {a}", "msr TCR_EL1, {b}", "isb", a = in(reg) plan.ttbr1, b = in(reg) plan.tcr) };
    pin::arm_entry();
}

/// `pt_lock_pool(pool_pa, pages | page_shift << 32, root_pa)`.
pub fn lock_pool(pool_pa: u64, packed: u64, root_pa: u64) -> i64 {
    if !s2::locked() || crate::PES_UP.load(Ordering::Acquire) > 1 { return DENIED; }
    if ONCE.swap(1, Ordering::AcqRel) != 0 { return DENIED; }
    let (pages, shift) = (packed & 0xffff_ffff, packed >> 32);
    let image = s2::image();
    if s2::with_guard_ram(|guarded, ram, hole, hole_end| {
        pt_pool_error(pool_pa, pages, shift, root_pa, ram, &image, hole, hole_end, guarded)
    })
    .is_some()
    {
        return INVALID;
    }
    let live = pin::walk_regs();
    if lock_regs_error(pin::this_pe_pinned(), live.ttbr1, root_pa).is_some() { return INVALID; }
    // SAFETY: ID registers.
    let (mmfr1, mmfr3) = unsafe { pin::id_mmfr1_mmfr3() };
    if extensions(mmfr1, mmfr3) == Extensions::Unenforceable { return NOT_SUPPORTED; }
    let (shift, end) = (shift as u32, pool_pa + (pages << shift));
    if scan(root_pa, LEVELS - 1, pool_pa, end, shift, &image).is_err() { return INVALID; }
    if unreached_not_empty(pool_pa, pages, shift) { return INVALID; }
    // SAFETY: the EL2 identity map covers RAM; the tables are the kernel's until the pool is locked.
    let read = |pa: u64| unsafe { core::ptr::read_volatile(pa as *const u64) };
    for (i, va) in s2::image_va().into_iter().enumerate() {
        if image_error(read, root_pa, va, image[i][0], image[i][1] - image[i][0], i == 0, shift).is_some() { return INVALID; }
    }
    if !cfg!(feature = "hyp-pt-pool-open-canary") {
        let r = s2::pool_read_only(pool_pa, end - pool_pa);
        if r != OK { return r; }
    }
    POOL[0].store(pool_pa, Ordering::Relaxed);
    POOL[1].store(end, Ordering::Relaxed);
    SHIFT.store(shift as u64, Ordering::Relaxed);
    LOCKED_TTBR1.store(live.ttbr1, Ordering::Relaxed);
    LOCKED_TCR.store(live.tcr, Ordering::Relaxed);
    LOCKED_SCTLR.store(live.sctlr, Ordering::Relaxed);
    READY.store(1, Ordering::Release);
    if !cfg!(feature = "hyp-pt-pool-open-canary") && !cfg!(feature = "hyp-pt-check-skip-canary") {
        HYP.set_invariant(INV_KERNEL_TABLES);
    }
    OK
}

/// `pt_set(entry_pa, expected, new, level) -> (status, observed)`.
pub fn set(entry_pa: u64, expected: u64, new: u64, level: u64) -> (i64, u64) {
    if READY.load(Ordering::Acquire) == 0 { return (DENIED, 0); }
    let (base, end, shift) = (POOL[0].load(Ordering::Relaxed), POOL[1].load(Ordering::Relaxed), SHIFT.load(Ordering::Relaxed) as u32);
    if pt_entry_error(entry_pa, level, base, (end - base) >> shift, shift as u64, LEVELS as u64).is_some() { return (DENIED, 0); }
    if !cfg!(feature = "hyp-pt-check-skip-canary") && check(entry_pa, expected, new, level as usize, base, end, shift).is_err() {
        return (DENIED, 0);
    }
    // SAFETY: an 8-aligned word inside the pool (checked above), which the EL2 identity map covers.
    let slot = unsafe { &*(entry_pa as *const AtomicU64) };
    match slot.compare_exchange(expected, new, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {
            // SAFETY: a barrier.
            unsafe { core::arch::asm!("dsb ishst", options(nostack)) };
            (OK, expected)
        }
        Err(cur) => (RACED, cur),
    }
}

fn check(entry_pa: u64, expected: u64, new: u64, level: usize, base: u64, end: u64, shift: u32) -> Result<(), &'static str> {
    let tag = |pa: u64| TAGS[page_index(pa, base, shift)].load(Ordering::Acquire);
    let c = write_error(expected, new, level, tag(entry_pa & !((1 << shift) - 1)), shift, &s2::image(), |pa| in_pool(pa, base, end, shift), tag)?;
    claim_tag(page_index(entry_pa & !((1 << shift) - 1), base, shift), c.entry)?;
    if let Some((t, l)) = c.target {
        claim_tag(page_index(t, base, shift), l)?;
    }
    Ok(())
}
