// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The order of a driver's writes to memory a device reads (a ring, a
//! descriptor, a command block) before the register write that tells the
//! device to read it (a doorbell).
//!
//! The portable fences do not give it. `fence(Release)` is `fence rw,w` on
//! riscv64 and `dmb ish` on aarch64: both order memory against memory as other
//! harts see it, and neither orders a memory write before a device write (no
//! `o` bit; the inner-shareable domain). A device that reads the ring after the
//! doorbell could then read it stale. Linux puts the barrier in `writel`:
//! `fence w,o` on riscv64 (`__io_bw`), `dmb oshst` on arm64 (`__iowmb`).
//!
//! x86_64 needs no instruction: stores retire in order (TSO) and an uncached
//! register write is not passed by an earlier write-back store, so Linux's
//! `writel` is a plain `mov`. An `sfence` would only matter for non-temporal
//! or write-combining stores to the ring, and no ring here is mapped that
//! way. The compiler is still kept from moving the ring writes past the
//! doorbell.

/// Order every earlier memory write before the next device (MMIO) write.
/// Call it immediately before a doorbell.
#[inline(always)]
pub fn io_wmb() {
    #[cfg(target_arch = "riscv64")]
    // SAFETY: a fence has no operands; it orders, and changes nothing else.
    // Not `nomem`: it is also a compiler barrier for the ring writes.
    unsafe {
        core::arch::asm!("fence w, o", options(nostack, preserves_flags))
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: as above. Outer shareable, stores: the device observes them.
    unsafe {
        core::arch::asm!("dmb oshst", options(nostack, preserves_flags))
    }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Order every earlier memory write before every later memory write, as a
/// device reading that memory sees them: a descriptor's body before the word
/// that hands it over (an ownership bit, a cycle bit, a valid bit). Not a
/// doorbell barrier: [`io_wmb`] is.
///
/// On riscv64 `fence w,o` (the doorbell barrier) does not order a memory write
/// before another memory write, so this one is `fence w,w` (Linux
/// `dma_wmb`). On aarch64 the two are the same `dmb oshst`: `fence(Release)`
/// (`dmb ish`) covers only the inner-shareable domain, and a device observes
/// from the outer one. x86_64: stores retire in order; the compiler is kept
/// from reordering them.
#[inline(always)]
pub fn dma_wmb() {
    #[cfg(target_arch = "riscv64")]
    // SAFETY: as `io_wmb`.
    unsafe {
        core::arch::asm!("fence w, w", options(nostack, preserves_flags))
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: as `io_wmb`.
    unsafe {
        core::arch::asm!("dmb oshst", options(nostack, preserves_flags))
    }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Order the read of a word a device wrote last (an ownership, done or phase
/// bit) before every later memory read: the rest of the descriptor, the
/// buffer it describes. Call it after the check that says the device is done.
///
/// Without it the CPU may read the buffer before the word that says it is
/// ready, and see what was there before the device wrote it. riscv64
/// `fence r,r`, aarch64 `dmb oshld` (Linux `dma_rmb`; `fence(Acquire)` is
/// `dmb ishld`, the inner-shareable domain only). x86_64 does not reorder a
/// load with an older load; the compiler is kept from doing it.
#[inline(always)]
pub fn dma_rmb() {
    #[cfg(target_arch = "riscv64")]
    // SAFETY: as `io_wmb`.
    unsafe {
        core::arch::asm!("fence r, r", options(nostack, preserves_flags))
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: as `io_wmb`.
    unsafe {
        core::arch::asm!("dmb oshld", options(nostack, preserves_flags))
    }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
