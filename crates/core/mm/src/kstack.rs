// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel task stacks in a window of their own, outside the linear map.
//!
//! Slot `i` of the window spans `STRIDE = 2P` bytes (P: `STACK_SIZE` rounded
//! up to a power of two), aligned to `2P`. Its stack is the first
//! `STACK_SIZE` bytes, mapped from order-0 frames; the rest is never mapped,
//! and is the guard of the slot above. An SP inside a stack has bit `P`
//! clear, one that ran off a stack's bottom has it set: the trap entry tests
//! that one bit (riscv64, aarch64). Slot 0 is never handed out, so every
//! stack has a guard below it inside the window.
//!
//! Create and reap stay off the TLB and the page allocator in the common
//! case: a reaped stack goes to a small per-CPU cache, still mapped, and the
//! next create on that CPU takes it. Past the cache a reaped stack is
//! unmapped on this CPU and its frames go back at once, but its slot waits in
//! a pending list: another CPU may still hold its translations. A create
//! that finds the list half full, with interrupts on, invalidates those
//! slots on every CPU and frees them, with no lock held. When the list is
//! full a reaped stack is kept mapped in a spare list instead.

use core::sync::atomic::{AtomicUsize, Ordering};
use azos_arch::{ArchPlatform, ARCH};
use azos_arch_api::{Cpu, Mmu, PagePerms, PAGE_SIZE};
use azos_sync::SpinLock;
use crate::addr::PhysAddr;
use crate::pmm;
use crate::vmm;

pub const SIZE: usize = azos_limits::KERNEL_STACK_SIZE_BYTES;
const P: usize = SIZE.next_power_of_two();
pub const STRIDE: usize = 2 * P;
const PAGES: usize = SIZE / PAGE_SIZE;
const CPUS: usize = azos_limits::NR_CPUS;
/// Mapped stacks each CPU keeps for its next creates.
const CACHE: usize = 2;
/// Slots waiting for a TLB invalidation on every CPU; a create flushes them
/// once half are waiting, and past this a reaped stack stays mapped as a
/// spare. The list has room for one more per CPU and path, the stacks that
/// passed that check and are being unmapped.
const PENDING_MAX: usize = 32;
const PENDING_ROOM: usize = PENDING_MAX + 2 * CPUS;
/// Every live task's stack, every CPU's cache, the pending list, and slot 0.
pub const SLOTS: usize = azos_limits::MAX_TASKS + CPUS * CACHE + PENDING_ROOM + 1;
/// At least 1 GiB of address space (it costs no memory), so the window's tag
/// (`BASE >> WINDOW_SHIFT`) fits the trap entry's immediates.
pub const WINDOW: usize = {
    let w = (SLOTS * STRIDE).next_power_of_two();
    if w < 1 << 30 { 1 << 30 } else { w }
};

#[cfg(target_os = "none")]
const END: usize = azos_arch::mmu::KSTACK_WINDOW_END;
#[cfg(not(target_os = "none"))]
const END: usize = 1 << 46;
const BASE: usize = END - WINDOW;

const _: () = assert!(SIZE % PAGE_SIZE == 0, "KERNEL_STACK_SIZE_KB must be a whole number of pages");
const _: () = assert!(BASE % WINDOW == 0, "the stack window must be aligned to its size");
// arch-only: the 64-slot limit is Sv39's; the other ISAs' kernel halves are wider.
#[cfg(all(target_os = "none", target_arch = "riscv64"))]
const _: () = assert!(WINDOW <= 64 << 30, "the stack window must stay in the top 64 kernel-only slots of Sv39");

/// The bit an SP inside a stack has clear and one past its bottom has set.
pub const OVERFLOW_BIT: u32 = P.trailing_zeros();
/// `sp >> WINDOW_SHIFT` names the window: `BASE >> WINDOW_SHIFT` for an SP
/// inside it (the trap entry's test, with [`OVERFLOW_BIT`]).
pub const WINDOW_SHIFT: u32 = WINDOW.trailing_zeros();
pub const WINDOW_TAG: usize = BASE >> WINDOW_SHIFT;
/// The same tag as the arithmetic shift of a kernel-half SP sees it: the
/// negation of this (aarch64, where the window is in the upper half).
pub const WINDOW_NEG_TAG: usize = BASE.wrapping_neg() >> WINDOW_SHIFT;

struct Lists {
    /// Unmapped slots no CPU can hold a translation of.
    free: [u32; SLOTS],
    nfree: usize,
    /// Slots unmapped here whose translations other CPUs may still hold.
    pending: [u32; PENDING_ROOM],
    npending: usize,
    /// Mapped stacks nobody uses (the pending list was full).
    spare: [u32; SLOTS],
    nspare: usize,
}

static LISTS: SpinLock<Lists> = SpinLock::new(Lists {
    free: [0; SLOTS], nfree: 0, pending: [0; PENDING_ROOM], npending: 0, spare: [0; SLOTS], nspare: 0,
});

/// Per CPU: up to `CACHE` mapped stack bases (0: empty).
static CPU_CACHE: [[AtomicUsize; CACHE]; CPUS] = [const { [const { AtomicUsize::new(0) }; CACHE] }; CPUS];
static READY: AtomicUsize = AtomicUsize::new(0);

#[inline]
fn slot_base(slot: u32) -> usize { BASE + slot as usize * STRIDE }
#[inline]
fn slot_of(base: usize) -> u32 { ((base - BASE) / STRIDE) as u32 }

/// Whether `va` is in the stack window: no `virt_to_phys` of it is meaningful.
#[inline]
pub fn in_window(va: usize) -> bool { va.wrapping_sub(BASE) < WINDOW }

/// The slot whose stack holds `sp`, `usize::MAX` when none does.
pub fn slot_holding(sp: usize) -> usize {
    if !in_window(sp) || sp == BASE { return usize::MAX; }
    let off = (sp - 1 - BASE) % STRIDE;
    if off >= SIZE { return usize::MAX; }
    (sp - 1 - BASE) / STRIDE
}

/// Build the window's upper page-table levels in the kernel root (one map
/// and unmap at its first stack page), before any user root copies the
/// kernel half, and fill the free list. False when the window overlaps a
/// mapping (the boot then has no task stacks). Canary `stack-guard-skip`
/// (`guard_too`): every stack is mapped with its guard as well, so an
/// overflow runs into the slot above unseen.
pub fn init(guard_too: bool) -> bool {
    let kpt = vmm::kernel_pagetable();
    if kpt == 0 { return false; }
    let mut probe = BASE;
    while probe < END {
        if vmm::translate(kpt, probe).is_some() { return false; }
        probe += vmm::MEGA_SIZE.max(STRIDE);
    }
    let Ok(pa) = pmm::alloc_page() else { return false };
    let first = slot_base(1);
    let ok = vmm::map(kpt, first, pa.as_usize(), PagePerms::KERNEL_RW).is_ok();
    vmm::unmap_kernel(kpt, first);
    ARCH.flush_tlb_page(first);
    let _ = pmm::free_page(pa);
    if !ok { return false; }
    {
        let mut l = LISTS.lock_irqsave();
        // Highest slot first, so the stack pops the lowest.
        let mut n = 0;
        for s in (1..SLOTS as u32).rev() {
            l.free[n] = s;
            n += 1;
        }
        l.nfree = n;
    }
    GUARD_TOO.store(guard_too as usize, Ordering::Relaxed);
    READY.store(1, Ordering::Release);
    true
}

static GUARD_TOO: AtomicUsize = AtomicUsize::new(0);

/// An address in the guard below the window's first stack.
pub fn first_guard() -> usize { slot_base(1) - 1 }

/// Whether [`init`] ran: before it, task stacks cannot be made.
pub fn ready() -> bool { READY.load(Ordering::Acquire) != 0 }

/// A stack: its base (lowest mapped byte; the top is `base + SIZE`), or
/// `None` when no slot or no frame is left.
pub fn alloc() -> Option<usize> {
    if !ready() { return None; }
    flush_pending_if_due();
    if let Some(b) = cache_pop() { return Some(b); }
    let slot = {
        let mut l = LISTS.lock_irqsave();
        if l.nspare > 0 {
            l.nspare -= 1;
            return Some(slot_base(l.spare[l.nspare]));
        }
        if l.nfree == 0 { return None; }
        l.nfree -= 1;
        l.free[l.nfree]
    };
    let base = slot_base(slot);
    let pages = if GUARD_TOO.load(Ordering::Relaxed) != 0 { STRIDE / PAGE_SIZE } else { PAGES };
    if map_pages(base, pages) { return Some(base); }
    // Some pages may have been mapped and so be cached anywhere: the slot
    // waits for an invalidation like a reaped one.
    unmap_pages(base, pages);
    park(slot);
    None
}

/// Give a stack back. Its task never runs on it again.
pub fn free(base: usize) {
    if base == 0 || !in_window(base) { return; }
    if cache_push(base) { return; }
    let slot = slot_of(base);
    {
        let mut l = LISTS.lock_irqsave();
        if l.npending >= PENDING_MAX {
            let n = l.nspare;
            l.spare[n] = slot;
            l.nspare = n + 1;
            return;
        }
    }
    let pages = if GUARD_TOO.load(Ordering::Relaxed) != 0 { STRIDE / PAGE_SIZE } else { PAGES };
    unmap_pages(base, pages);
    park(slot);
}

fn map_pages(base: usize, pages: usize) -> bool {
    let kpt = vmm::kernel_pagetable();
    for i in 0..pages {
        let Ok(pa) = pmm::alloc_page() else { return false };
        if vmm::map(kpt, base + i * PAGE_SIZE, pa.as_usize(), PagePerms::KERNEL_RW).is_err() {
            let _ = pmm::free_page(pa);
            return false;
        }
    }
    true
}

/// Unmap on this CPU and give the frames back. Other CPUs' stale entries
/// name frames reused elsewhere, but only an access through this window
/// would use them, and no stack lives in the slot until its invalidation.
fn unmap_pages(base: usize, pages: usize) {
    let kpt = vmm::kernel_pagetable();
    for i in 0..pages {
        let va = base + i * PAGE_SIZE;
        if let Some(pa) = vmm::translate(kpt, va) {
            vmm::unmap_kernel(kpt, va);
            let _ = pmm::free_page(PhysAddr::new(pa & !(PAGE_SIZE - 1)));
        }
    }
}

/// Add an unmapped slot to the pending list. It always fits: past
/// `PENDING_MAX` only the stacks already being unmapped arrive.
fn park(slot: u32) {
    let mut l = LISTS.lock_irqsave();
    let n = l.npending;
    l.pending[n] = slot;
    l.npending = n + 1;
}

fn invalidate(slot: u32) {
    let base = slot_base(slot);
    for i in 0..STRIDE / PAGE_SIZE {
        ARCH.flush_tlb_page_all(base + i * PAGE_SIZE);
    }
}

/// With interrupts on and half the pending list waiting: invalidate those
/// slots on every CPU, then free them. No lock is held while flushing, so a
/// CPU that waits for the flush with interrupts masked cannot be waited on.
fn flush_pending_if_due() {
    if LISTS.lock_irqsave().npending < PENDING_MAX / 2 || !irqs_on() { return; }
    flush_pending();
}

/// Invalidate and free every slot pending now. Interrupts on, no lock held.
pub fn flush_pending() {
    let mut batch = [0u32; PENDING_ROOM];
    let n = {
        let l = LISTS.lock_irqsave();
        batch[..l.npending].copy_from_slice(&l.pending[..l.npending]);
        l.npending
    };
    // Canary `kstack-reuse-no-shootdown-canary`: the slots are freed with
    // no invalidation, so a stale translation on another CPU can reach a
    // new task's stack through the old frames.
    if !cfg!(feature = "kstack-reuse-no-shootdown-canary") {
        for &s in &batch[..n] { invalidate(s); }
    }
    let mut l = LISTS.lock_irqsave();
    // Slots parked since the copy sit after the first `n`.
    let left = l.npending - n;
    for i in 0..left { l.pending[i] = l.pending[n + i]; }
    l.npending = left;
    for &s in &batch[..n] {
        let k = l.nfree;
        l.free[k] = s;
        l.nfree = k + 1;
    }
}

fn irqs_on() -> bool {
    let t = crate::kheap::irq_off();
    let on = crate::kheap::irq_was_on(t);
    crate::kheap::irq_restore(t);
    on
}

fn cache_pop() -> Option<usize> {
    let t = crate::kheap::irq_off();
    let cpu = ARCH.hart_id();
    let mut got = None;
    if cpu < CPUS {
        for e in &CPU_CACHE[cpu] {
            let b = e.swap(0, Ordering::Relaxed);
            if b != 0 { got = Some(b); break; }
        }
    }
    crate::kheap::irq_restore(t);
    got
}

fn cache_push(base: usize) -> bool {
    let t = crate::kheap::irq_off();
    let cpu = ARCH.hart_id();
    let mut put = false;
    if cpu < CPUS {
        for e in &CPU_CACHE[cpu] {
            if e.load(Ordering::Relaxed) == 0 {
                e.store(base, Ordering::Relaxed);
                put = true;
                break;
            }
        }
    }
    crate::kheap::irq_restore(t);
    put
}

/// `(slots in use, pending, spare, cached)`, for the boot line and ktests.
pub fn census() -> (usize, usize, usize, usize) {
    let (free, pending, spare) = {
        let l = LISTS.lock_irqsave();
        (l.nfree, l.npending, l.nspare)
    };
    let cached = CPU_CACHE.iter().flatten().filter(|e| e.load(Ordering::Relaxed) != 0).count();
    (SLOTS - 1 - free, pending, spare, cached)
}

/// Kconfig KTEST: the pending list's length.
#[cfg(feature = "ktest")]
pub fn ktest_pending() -> usize { LISTS.lock_irqsave().npending }

/// Kconfig KTEST: give a stack back past the CPU cache and the spare list,
/// so its slot is unmapped and waits for the invalidation.
#[cfg(feature = "ktest")]
pub fn ktest_free_uncached(base: usize) {
    let pages = if GUARD_TOO.load(Ordering::Relaxed) != 0 { STRIDE / PAGE_SIZE } else { PAGES };
    unmap_pages(base, pages);
    park(slot_of(base));
}

/// Kconfig KTEST: a stack from the free list only (no cache, no spare): the
/// slot freed last comes back first.
#[cfg(feature = "ktest")]
pub fn ktest_alloc_uncached() -> Option<usize> {
    let slot = {
        let mut l = LISTS.lock_irqsave();
        if l.nfree == 0 { return None; }
        l.nfree -= 1;
        l.free[l.nfree]
    };
    let base = slot_base(slot);
    if map_pages(base, PAGES) { return Some(base); }
    unmap_pages(base, PAGES);
    park(slot);
    None
}
