// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel half's page-table pool (VIRT_SPLIT or PT_PROTECTION, Kconfig
//! `PT_POOL_PAGES`).
//!
//! The tables under the kernel root come from one contiguous run, carved at
//! boot, so exactly those pages can be made read-only (the monitor's
//! `pt_lock_pool`, or the kernel's own mapping) and every later word into them
//! goes through the pool's writer ([`crate::pt`] is the only caller). A table is never freed: the kernel half
//! only grows, and a page handed back is one a lost race left unlinked and empty,
//! which goes to the next table of the same level (the monitor fixes the level a
//! page serves at its first use).

use crate::addr::{phys_to_virt, virt_to_phys, PhysAddr};
use azos_arch_api::PAGE_SIZE;
use azos_common::error::{KResult, KernelError};
use azos_sync::SpinLock;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

/// The most pages a pool can hold (Kconfig `PT_POOL_PAGES`); the run itself
/// is sized at boot from the RAM and the layout ([`pages_for`]).
pub const MAX_PAGES: usize = azos_limits::PT_POOL_PAGES as usize;
/// The most levels any ISA walks (x86_64 with five-level paging).
const MAX_LEVELS: usize = 5;
const NONE: u16 = u16::MAX;

struct Pool {
    next: usize,
    /// Per level, the head of the chain of pages handed back; `link` chains them.
    free: [u16; MAX_LEVELS],
    link: [u16; MAX_PAGES],
}

static POOL: SpinLock<Pool> = SpinLock::new(Pool { next: 0, free: [NONE; MAX_LEVELS], link: [NONE; MAX_PAGES] });
static BASE: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);
/// The level each handed-out page serves, read without the lock by every write.
static LEVEL: [AtomicU8; MAX_PAGES] = [const { AtomicU8::new(0) }; MAX_PAGES];

/// The pool's range in the direct map, set when it has been made read-only.
static ARMED_LO: AtomicUsize = AtomicUsize::new(0);
static ARMED_LEN: AtomicUsize = AtomicUsize::new(0);

/// What the pool's writer (the monitor, or the kernel in its write window) does for a word in the pool: replace `expected` by `new` in
/// the entry at physical `entry_pa`, a table of `level`. `Err` carries the word
/// found when it was not `expected`; a refusal never returns.
pub type PoolWriter = fn(entry_pa: usize, expected: u64, new: u64, level: usize) -> Result<(), u64>;

azos_common::ro_hook! {
    static POOL_WRITER: PoolWriter;
}

/// Route every word in the armed pool through `f`. Before the seal.
pub fn set_writer_hook(f: PoolWriter) {
    POOL_WRITER.set(f);
}

/// Pages the kernel half's tables need for `ram` bytes of RAM, one table of
/// each level a span of the direct map reaches, `stack_tables` for the kernel
/// stack window, and `margin` for the device windows, the image's splits and
/// later splits. `levels` and `entries` are the walk's; `None` past
/// [`MAX_PAGES`].
pub fn pages_for(ram: usize, levels: usize, entries: usize, stack_tables: usize, margin: usize) -> Option<usize> {
    let mut span = PAGE_SIZE * entries;
    let mut pages = 1;
    // The direct map is blocks of the level-1 span, one table of each level above it per span reached.
    for _ in 1..levels - 1 {
        span *= entries;
        pages += ram.div_ceil(span) + 1;
    }
    let total = pages + stack_tables + margin;
    (total <= MAX_PAGES).then_some(total)
}

/// The pool is the `count` zeroed contiguous pages at physical `base`. Before
/// the kernel root is built.
pub fn init(base: PhysAddr, count: usize) {
    debug_assert!(count <= MAX_PAGES);
    COUNT.store(count, Ordering::Relaxed);
    BASE.store(base.as_usize(), Ordering::Relaxed);
}

/// A zeroed table page for a table of `level`.
pub fn take(level: usize) -> KResult<PhysAddr> {
    let mut p = POOL.lock_irqsave();
    let head = p.free[level];
    let idx = if head != NONE {
        p.free[level] = p.link[head as usize];
        head as usize
    } else if p.next < COUNT.load(Ordering::Relaxed) {
        p.next += 1;
        p.next - 1
    } else {
        return Err(KernelError::OutOfMemory);
    };
    LEVEL[idx].store(level as u8, Ordering::Relaxed);
    Ok(PhysAddr::new(BASE.load(Ordering::Relaxed) + idx * PAGE_SIZE))
}

/// Hand back a page `take` gave, never linked and still zero.
pub fn give_back(page: PhysAddr) {
    let idx = (page.as_usize() - BASE.load(Ordering::Relaxed)) / PAGE_SIZE;
    let mut p = POOL.lock_irqsave();
    let level = LEVEL[idx].load(Ordering::Relaxed) as usize;
    p.link[idx] = p.free[level];
    p.free[level] = idx as u16;
}

/// Is `page` one of the pool's?
pub fn contains(page: PhysAddr) -> bool {
    let base = BASE.load(Ordering::Relaxed);
    base != 0 && (base..base + COUNT.load(Ordering::Relaxed) * PAGE_SIZE).contains(&page.as_usize())
}

/// Does `[pa, pa + bytes)` touch a page of the pool?
pub fn overlaps(pa: usize, bytes: usize) -> bool {
    let base = BASE.load(Ordering::Relaxed);
    base != 0 && pa < base + COUNT.load(Ordering::Relaxed) * PAGE_SIZE && base < pa.saturating_add(bytes)
}

/// `(base, pages in use, pages)`: the run, for the lock and the census.
pub fn extent() -> (usize, usize, usize) {
    (BASE.load(Ordering::Relaxed), POOL.lock_irqsave().next, COUNT.load(Ordering::Relaxed))
}

/// Words in the pool go through the writer from here on.
pub fn arm() {
    ARMED_LEN.store(COUNT.load(Ordering::Relaxed) * PAGE_SIZE, Ordering::Relaxed);
    ARMED_LO.store(phys_to_virt(BASE.load(Ordering::Relaxed)), Ordering::Release);
}

/// Is the entry at `slot` (a direct-map address) in the armed pool?
#[inline(always)]
pub(crate) fn owns(slot: usize) -> bool {
    !cfg!(feature = "ptpool-unrouted-canary") && slot.wrapping_sub(ARMED_LO.load(Ordering::Relaxed)) < ARMED_LEN.load(Ordering::Relaxed)
}

#[inline(always)]
pub(crate) fn route(slot: usize, seen: u64, new: u64) -> Option<Result<u64, u64>> {
    if !owns(slot) {
        return None;
    }
    Some(through_writer(slot, seen, new))
}

#[cold]
#[inline(never)]
fn through_writer(slot: usize, seen: u64, new: u64) -> Result<u64, u64> {
    let pa = virt_to_phys(slot);
    let level = LEVEL[(pa - BASE.load(Ordering::Relaxed)) / PAGE_SIZE].load(Ordering::Relaxed) as usize;
    let set = POOL_WRITER.get().expect("the pool is armed after the hook is set");
    match set(pa, seen, new, level) {
        Ok(()) => Ok(seen),
        Err(cur) => Err(cur),
    }
}

/// Store `word` over whatever the slot holds: swapped until it takes.
#[cold]
#[inline(never)]
pub(crate) fn replace(slot: &core::sync::atomic::AtomicU64, word: u64) {
    let mut cur = slot.load(Ordering::Relaxed);
    while let Err(now) = through_writer(slot as *const _ as usize, cur, word) {
        cur = now;
    }
}
