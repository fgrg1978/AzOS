// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cache maintenance for aarch64.
//!
//! ARMv8 is mostly hardware-cache-coherent for normal RAM ops
//! through Inner-Shareable cacheable mappings, but three classes
//! of code still need explicit cache maintenance:
//!
//!   1. **DMA buffer hand-off**: a non-coherent master reads RAM, not the
//!      CPU's caches, so the kernel cleans (`dcache_clean`) what it wrote
//!      before the device reads it and cleans-and-invalidates
//!      (`dcache_clean_and_invalidate`) around a transfer the device writes
//!      (`cbo::cmo_clean` / `cbo::cmo_flush` behind `DMA_NONCOHERENT`).
//!
//!   2. **JIT / dynamic code**: after the kernel writes instructions into a
//!      Normal-WB page it cleans the writes out to the point of unification
//!      (`dcache_clean`), then `icache_invalidate_all` so the I-cache reloads
//!      from RAM.
//!
//!   3. **Hand-off to another observer** (`kernel/src/pstore.rs`, the
//!      secondary harts' stacks): clean to the point of coherency before the
//!      other observer reads.
//!
//! Every loop strides by the D-cache line size the CPU reports in
//! `CTR_EL0.DminLine`, read per call (one `mrs`): a hard-coded 64 bytes
//! would skip or misalign lines on a core with 32- or 128-byte lines and
//! corrupt DMA data silently. The architecture defines `DminLine` as the
//! smallest D-cache line any cache the PE uses has, so the stride never
//! skips a line.
//!
//! Operation reference: Arm ARM §D7 "Memory cache and TLB
//! maintenance instructions".

/// The D-cache line size in bytes, from `CTR_EL0.DminLine` (bits 19:16,
/// log2 of the size in 32-bit words).
#[cfg(target_arch = "aarch64")]
#[inline]
fn line_size_bytes() -> usize {
    let ctr: u64;
    // SAFETY: a read of an ID register, no memory or flags involved.
    unsafe {
        core::arch::asm!(
            "mrs {0}, CTR_EL0",
            out(reg) ctr,
            options(nomem, nostack, preserves_flags),
        );
    }
    4usize << ((ctr >> 16) & 0xf)
}

/// `DSB ISH` — wait for all preceding memory accesses (across
/// the Inner Shareable domain) to complete.
#[cfg(target_arch = "aarch64")]
#[inline]
fn dsb_ish() {
    // SAFETY: a barrier.
    unsafe {
        core::arch::asm!("dsb ish", options(nostack, nomem, preserves_flags));
    }
}

/// **Clean** the D-cache range `[va, va + len)` to Point of
/// Coherency (PoC) — writes dirty lines back to RAM but keeps
/// them in cache. Use before handing a buffer to a non-coherent
/// DMA-out device.
///
/// # Safety
/// `[va, va + len)` must be mapped.
#[cfg(target_arch = "aarch64")]
pub unsafe fn dcache_clean(va: usize, len: usize) {
    let line = line_size_bytes();
    let mut p = va & !(line - 1);
    let end = va + len;
    while p < end {
        unsafe {
            core::arch::asm!(
                "dc cvac, {0}",
                in(reg) p,
                options(nostack, preserves_flags),
            );
        }
        p += line;
    }
    dsb_ish();
}

/// **Clean and invalidate** the D-cache range — writes dirty lines back and
/// drops them, so the next read pulls fresh data from RAM. Use when handing
/// a buffer off entirely, or before reading memory a non-coherent device
/// wrote.
///
/// # Safety
/// `[va, va + len)` must be mapped.
#[cfg(target_arch = "aarch64")]
pub unsafe fn dcache_clean_and_invalidate(va: usize, len: usize) {
    let line = line_size_bytes();
    let mut p = va & !(line - 1);
    let end = va + len;
    while p < end {
        unsafe {
            core::arch::asm!(
                "dc civac, {0}",
                in(reg) p,
                options(nostack, preserves_flags),
            );
        }
        p += line;
    }
    dsb_ish();
}

/// Invalidate **all** of this PE's I-cache (Inner Shareable —
/// broadcasts to other PEs). Use after writing instructions to
/// a page so cores fetch the new code instead of the stale
/// cached copy.
#[cfg(target_arch = "aarch64")]
pub fn icache_invalidate_all() {
    // SAFETY: cache maintenance and barriers.
    unsafe {
        core::arch::asm!(
            "ic ialluis",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags),
        );
    }
}

// ── Host-build stubs ────────────────────────────────────────

#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn dcache_clean(_va: usize, _len: usize) {}
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn dcache_clean_and_invalidate(_va: usize, _len: usize) {}
#[cfg(not(target_arch = "aarch64"))]
pub fn icache_invalidate_all() {}
