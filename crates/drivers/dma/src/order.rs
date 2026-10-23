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
