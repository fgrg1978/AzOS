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
//!      (`cache::cmo_clean` / `cache::cmo_flush` behind `DMA_NONCOHERENT`).
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

// ── Bulk zeroing and the ISA-neutral cache-op names ──────────
//
// Bulk page zeroing — the aarch64 side of `azos_arch::cache`.
//
// RISC-V's `crates/core/arch-riscv64/src/cache.rs` dispatches to `cbo.zero`
// (Zicboz) behind a DTB-driven, trap-verified probe, with a scalar
// `core::ptr::write_bytes` fallback whenever the extension is absent or
// unproven. `crates/core/mm` (`pmm::alloc_page`, `demand::handle_demand_fault`,
// `vdso::vdso_init`) calls `azos_arch::cache::zero_memory` expecting
// that same signature on every ISA — this module gives aarch64 the
// fallback half of that contract.
//
// **What this is not, honestly.** VMSAv8-A's answer to the same problem
// is `DC ZVA` (Data Cache Zero by Virtual Address), gated by `DCZID_EL0`
// for whether it is permitted and at what block size. That fast path is
// not implemented here — this always takes the scalar route. Per the
// project's rule for an ISA-specific fast path with no arch-api
// equivalent yet ("route through arch-api if an equivalent exists;
// otherwise an honest aarch64 side that never fakes success"): a plain
// `write_bytes` genuinely zeroes the memory, correctly, every time — it is
// slower than `DC ZVA` would be, never wrong. Wiring up `DC ZVA` (with the
// same "probe it, don't just trust the ID register" discipline
// `zicboz_select` uses) is a follow-up, not a correctness gap.

/// Zero `len` bytes at `addr`. See the module doc for why this is always
/// the scalar path on aarch64 today.
///
/// # Safety
/// `addr` must be a valid, writable address for `len` bytes, with no
/// other live reference to that memory — the same contract
/// `core::ptr::write_bytes` has, since that is exactly what this calls.
#[inline]
pub unsafe fn zero_memory(addr: usize, len: usize) {
    unsafe { core::ptr::write_bytes(addr as *mut u8, 0, len) };
}

/// aarch64 side of `azos_arch::cache::zicboz_select`
/// (`kernel/src/entry/riscv64/boot_hooks.rs` calls it, unconditionally, once at boot).
///
/// Zicboz is a RISC-V extension name — there is nothing to select on this
/// ISA, so this always answers `false` (no fast path taken) rather than
/// reusing the RISC-V name for a probe that would be meaningless here.
/// [`zero_memory`] above is always the scalar path regardless of this
/// return value; see the module doc for why `DC ZVA` (the real aarch64
/// fast path) isn't wired up yet. Arguments are accepted and ignored so a
/// caller written against the RISC-V signature (DTB-declared extension +
/// block size) compiles unchanged on this ISA.
#[inline]
pub fn zicboz_select(_dt_zicboz: bool, _dt_block_size: u32) -> bool {
    false
}

/// ISA-neutral name of RISC-V's Zicbom check: can the CPU write back and
/// drop a range of its data cache for a DMA master? Always, with
/// `DC CVAC` / `DC CIVAC`.
#[inline]
pub fn cmo_available() -> bool {
    true
}

/// Write back every dirty cache line of `[va, va + len)` to the point of
/// coherency; they stay cached (`DC CVAC`).
///
/// # Safety
/// `[va, va + len)` must be mapped.
#[inline]
pub unsafe fn cmo_clean(va: usize, len: usize) {
    unsafe { dcache_clean(va, len) }
}

/// Write back and drop every cache line of `[va, va + len)` (`DC CIVAC`).
///
/// # Safety
/// `[va, va + len)` must be mapped.
#[inline]
pub unsafe fn cmo_flush(va: usize, len: usize) {
    unsafe { dcache_clean_and_invalidate(va, len) }
}
