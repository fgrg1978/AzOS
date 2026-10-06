// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `kheap-census` (vsbench diagnostic, off in every build that ships): who
//! allocates from the kernel heap, how much, and what each call costs. The
//! model is `spawn.rs`'s `spawn-census`; read it under `-icount shift=0`,
//! where a nanosecond of guest time is one guest instruction.
//!
//! Every `alloc`/`dealloc` through the global allocator is counted by
//! power-of-two size bucket and by the syscall the calling hart is inside
//! (`set_tag`, set by `azos_syscall::syscall_dispatch_checked`; a hart that
//! is not inside a syscall counts under [`TAG_KERNEL`]). A task that blocks
//! inside a syscall leaves its tag on the hart until the next syscall entry,
//! so a few allocations of a resumed task can land under the wrong number:
//! good enough to find the hot paths, not an exact attribution.
//!
//! Costs are summed timer ticks around the allocator call itself, census
//! bookkeeping excluded, with the cost of an empty interval (`EMPTY`)
//! recorded alongside so the reader can subtract it. The dump is driven by
//! the syscall layer (it can print; this crate cannot).
//!
//! Without the feature none of this exists.

use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering::Relaxed};
use azos_arch_api::Cpu;

/// Power-of-two buckets: `<=8, 16, 32, ... 4096, 8192, >8192`.
pub const NB: usize = 12;
/// Tags: a syscall number masked to this range; the last one is "no syscall".
pub const NT: usize = 1024;
/// The tag of a hart that is not inside a syscall.
pub const TAG_KERNEL: u16 = (NT - 1) as u16;
/// Fine histogram: sizes up to `FINE_MAX` in 8-byte steps.
pub const FINE_MAX: usize = 2048;
const NF: usize = FINE_MAX / 8 + 1;
const HARTS: usize = azos_sync::isr_depth::MAX_HARTS;

static TAG: [AtomicU16; HARTS] = [const { AtomicU16::new(TAG_KERNEL) }; HARTS];
/// Allocations per (tag, bucket).
pub static CNT: [[AtomicU32; NB]; NT] = [const { [const { AtomicU32::new(0) }; NB] }; NT];
/// Allocations per 8-byte size step.
pub static FINE: [AtomicU32; NF] = [const { AtomicU32::new(0) }; NF];
/// Per bucket: alloc calls, alloc ticks, free calls, free ticks, refused.
pub static A_N: [AtomicU64; NB] = [const { AtomicU64::new(0) }; NB];
pub static A_T: [AtomicU64; NB] = [const { AtomicU64::new(0) }; NB];
pub static F_N: [AtomicU64; NB] = [const { AtomicU64::new(0) }; NB];
pub static F_T: [AtomicU64; NB] = [const { AtomicU64::new(0) }; NB];
pub static REFUSED: AtomicU64 = AtomicU64::new(0);
/// Allocations made with the hart inside an interrupt handler.
pub static IN_ISR: AtomicU64 = AtomicU64::new(0);
/// Allocations with alignment above 16.
pub static BIG_ALIGN: AtomicU64 = AtomicU64::new(0);
/// Sum of empty intervals (`now(); now()`), and how many.
pub static EMPTY_T: AtomicU64 = AtomicU64::new(0);
pub static EMPTY_N: AtomicU64 = AtomicU64::new(0);
/// Live bytes and their peak.
pub static LIVE: AtomicU64 = AtomicU64::new(0);
pub static PEAK: AtomicU64 = AtomicU64::new(0);
static LAST_DUMP: AtomicU64 = AtomicU64::new(0);

#[inline(always)]
fn hart() -> usize { azos_arch::ARCH.hart_id() }

/// Timer ticks now.
#[inline(always)]
pub fn now() -> u64 { azos_arch::ARCH.now_ticks() }

/// The bucket of a size.
#[inline(always)]
pub fn bucket(size: usize) -> usize {
    if size <= 8 { return 0; }
    let b = (usize::BITS - (size - 1).leading_zeros()) as usize - 3;
    if b >= NB { NB - 1 } else { b }
}

/// The calling hart entered syscall `nr`.
pub fn set_tag(nr: u64) {
    let h = hart();
    if h < HARTS { TAG[h].store((nr as usize % (NT - 1)) as u16, Relaxed); }
}

/// The calling hart left its syscall.
pub fn clear_tag() {
    let h = hart();
    if h < HARTS { TAG[h].store(TAG_KERNEL, Relaxed); }
}

/// One allocation of `size` that took `t` ticks; `ok` false when refused.
pub fn on_alloc(size: usize, align: usize, t: u64, ok: bool) {
    let h = hart();
    let tag = if h < HARTS { TAG[h].load(Relaxed) as usize } else { NT - 1 };
    let b = bucket(size);
    CNT[tag][b].fetch_add(1, Relaxed);
    if size <= FINE_MAX { FINE[(size + 7) / 8].fetch_add(1, Relaxed); }
    A_N[b].fetch_add(1, Relaxed);
    A_T[b].fetch_add(t, Relaxed);
    if !ok { REFUSED.fetch_add(1, Relaxed); }
    if align > 16 { BIG_ALIGN.fetch_add(1, Relaxed); }
    if azos_sync::isr_depth::in_isr(h) { IN_ISR.fetch_add(1, Relaxed); }
    if ok {
        let live = LIVE.fetch_add(size as u64, Relaxed) + size as u64;
        PEAK.fetch_max(live, Relaxed);
    }
    let t0 = now();
    let t1 = now();
    EMPTY_T.fetch_add(t1.wrapping_sub(t0), Relaxed);
    EMPTY_N.fetch_add(1, Relaxed);
}

/// One free of `size` that took `t` ticks.
pub fn on_free(size: usize, t: u64) {
    let b = bucket(size);
    F_N[b].fetch_add(1, Relaxed);
    F_T[b].fetch_add(t, Relaxed);
    LIVE.fetch_sub(size as u64, Relaxed);
}

/// Whether `every` ticks have passed since the last dump (claims the dump).
pub fn due(every: u64) -> bool {
    let n = now();
    let last = LAST_DUMP.load(Relaxed);
    n.wrapping_sub(last) >= every
        && LAST_DUMP.compare_exchange(last, n, Relaxed, Relaxed).is_ok()
}
