// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cache maintenance + memory barriers for aarch64.
//!
//! ARMv8 is mostly hardware-cache-coherent for normal RAM ops
//! through Inner-Shareable cacheable mappings, but three classes
//! of code still need explicit cache maintenance:
//!
//!   1. **DMA buffer hand-off**: when a non-coherent device
//!      writes into RAM, the kernel must `dcache_invalidate` the
//!      buffer before reading it; when it hands a kernel-written
//!      buffer to such a device, it must `dcache_clean` first.
//!
//!   2. **JIT / dynamic code**: after the kernel writes
//!      instructions into a Normal-WB page it must `dcache_clean`
//!      the writes out to the point of unification, then
//!      `icache_invalidate` so the I-cache reloads from RAM.
//!
//!   3. **Suspend-to-RAM**: before WFI-to-sleep the kernel must
//!      clean every D-cache way (DC CISW or one of the
//!      "clean all" sysreg sequences) so power loss doesn't
//!      eat dirty cache lines.
//!
//! Operation reference: Arm ARM §D7 "Memory cache and TLB
//! maintenance instructions".

#![allow(dead_code)]

/// Standard ARMv8 line size — 64 bytes on cortex-a72 / -a53 /
/// most server cores. The actual size lives in CTR_EL0[19:16]
/// (DminLine = log2(line size in words)); we hard-code the
/// common 64-byte default and assert in [`line_size_bytes`].
pub const LINE_SIZE_BYTES: usize = 64;

/// Read the data cache line size from CTR_EL0 (validates the
/// `LINE_SIZE_BYTES` assumption). Returns 64 on stock cortex-a72.
#[cfg(target_arch = "aarch64")]
pub fn line_size_bytes() -> usize {
    let ctr: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, CTR_EL0",
            out(reg) ctr,
            options(nomem, nostack, preserves_flags),
        );
    }
    // DminLine in bits [19:16]: log2(line size in 32-bit words).
    let log2_words = ((ctr >> 16) & 0xF) as usize;
    let line = 1usize << (log2_words + 2); // bytes
    // U10-15 (audit): this doc comment promised an assert that was never
    // written — every `dc`/`ic` maintenance loop in this file (dcache_*,
    // icache_invalidate) strides by the hard-coded `LINE_SIZE_BYTES`
    // regardless of what CTR_EL0 actually reports, so a part with a
    // 32-byte line would have every other cache line silently un-cleaned/
    // un-invalidated with no signal. Debug-only: a release kernel on a
    // part this assumption is wrong for should still boot (a maintenance
    // gap, not a correctness trap on the fast path), but any dev/QEMU run
    // catches the mismatch loudly the first time this function is called.
    debug_assert_eq!(line, LINE_SIZE_BYTES,
        "CTR_EL0 reports a {}-byte D-cache line, LINE_SIZE_BYTES assumes {} \
         — every dc/ic loop in this file strides by the wrong amount", line, LINE_SIZE_BYTES);
    line
}

/// `DSB ISH` — wait for all preceding memory accesses (across
/// the Inner Shareable domain) to complete.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn dsb_ish() {
    unsafe {
        core::arch::asm!("dsb ish", options(nostack, nomem, preserves_flags));
    }
}

/// `DSB ISHST` — store-only variant; cheaper than full DSB when
/// the caller only needs prior stores to be visible.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn dsb_ishst() {
    unsafe {
        core::arch::asm!("dsb ishst", options(nostack, nomem, preserves_flags));
    }
}

/// `ISB` — instruction synchronisation barrier. Required after
/// changes to system registers / page tables that affect
/// instruction execution.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn isb() {
    unsafe {
        core::arch::asm!("isb", options(nostack, nomem, preserves_flags));
    }
}

/// **Clean** the D-cache range `[va, va + len)` to Point of
/// Coherency (PoC) — writes dirty lines back to RAM but keeps
/// them in cache. Use before handing a buffer to a non-coherent
/// DMA-out device.
#[cfg(target_arch = "aarch64")]
pub unsafe fn dcache_clean(va: usize, len: usize) {
    let line = LINE_SIZE_BYTES;
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

/// **Invalidate** the D-cache range `[va, va + len)` — discards
/// any cached copies so the next read pulls fresh data from RAM.
/// Use after a non-coherent DMA-in device has written the buffer.
///
/// # Safety
/// Discards dirty lines without writing them back — if the
/// region holds modified data the caller hasn't already cleaned,
/// that data is lost. Pair with [`dcache_clean`] in the
/// round-trip sequence (clean → DMA → invalidate).
#[cfg(target_arch = "aarch64")]
pub unsafe fn dcache_invalidate(va: usize, len: usize) {
    let line = LINE_SIZE_BYTES;
    let mut p = va & !(line - 1);
    let end = va + len;
    while p < end {
        unsafe {
            core::arch::asm!(
                "dc ivac, {0}",
                in(reg) p,
                options(nostack, preserves_flags),
            );
        }
        p += line;
    }
    dsb_ish();
}

/// **Clean and invalidate** the D-cache range — combined op,
/// useful when handing a buffer off entirely (kernel won't read
/// it again after the device touches it).
#[cfg(target_arch = "aarch64")]
pub unsafe fn dcache_clean_and_invalidate(va: usize, len: usize) {
    let line = LINE_SIZE_BYTES;
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
    unsafe {
        core::arch::asm!(
            "ic ialluis",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags),
        );
    }
}

/// Canonical "I just wrote new instructions to RAM" sequence:
/// clean the data cache for the affected range, invalidate I-
/// cache (broadcast), and serialise instruction fetches. Equivalent
/// of POSIX `__clear_cache()`.
#[cfg(target_arch = "aarch64")]
pub unsafe fn sync_dcache_to_icache(va: usize, len: usize) {
    unsafe {
        dcache_clean(va, len);
        icache_invalidate_all();
    }
}

// ── Host-build stubs ────────────────────────────────────────

#[cfg(not(target_arch = "aarch64"))]
pub fn line_size_bytes() -> usize { LINE_SIZE_BYTES }
#[cfg(not(target_arch = "aarch64"))]
pub fn dsb_ish() {}
#[cfg(not(target_arch = "aarch64"))]
pub fn dsb_ishst() {}
#[cfg(not(target_arch = "aarch64"))]
pub fn isb() {}
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn dcache_clean(_va: usize, _len: usize) {}
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn dcache_invalidate(_va: usize, _len: usize) {}
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn dcache_clean_and_invalidate(_va: usize, _len: usize) {}
#[cfg(not(target_arch = "aarch64"))]
pub fn icache_invalidate_all() {}
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn sync_dcache_to_icache(_va: usize, _len: usize) {}
