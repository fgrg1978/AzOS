// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DMA mapping API: the [`DmaDomain`] a driver maps its
//! buffers through, the domains that implement it without hardware
//! ([`IdentityDomain`], [`SoftState`]), the registry that tells a driver
//! which domain its device sits in, cache maintenance for non-coherent
//! masters, the bounce-buffer decision and allocation under a device's DMA
//! mask ([`alloc_below`]), and the order of ring writes before a doorbell
//! ([`order::io_wmb`]). Pure logic, no allocator and no
//! locks: `azos_dma_tests` exercises the real bookkeeping on the host, and
//! the kernel wraps the `&mut self` states in a lock
//! (`kernel/src/boot/dma.rs`) to make them `&self` domains.
//!
//! # Why `DmaAddr` is not just "the physical address"
//!
//! With no IOMMU the bus address a device must be given IS the physical
//! address. With an IOMMU domain, the bus address is an IOVA the domain chose
//! (the IOMMU domain of `azos_iommu` happens to choose IOVA == PA, with the
//! page table permitting only the mapped pages, but a driver must not rely
//! on that). Callers take a [`DmaAddr`] from `DmaDomain::map` and hand THAT
//! to the device, never `virt_to_phys` directly, so turning the IOMMU on is
//! a change in what this crate returns, not a change in every driver.
#![no_std]

pub mod alloc;
pub mod cache;
pub mod ccache;
pub mod domain;
pub mod order;
pub mod registry;

pub use alloc::{alloc_below, PageSource};
pub use domain::{DmaDomain, DomainKind, DomainOps, IdentityDomain, SoftState};

/// A bus address, as seen by the device. IOVA when an IOMMU domain is
/// active for that device, physical otherwise — see the module doc.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaAddr(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    ToDevice,
    FromDevice,
    Bidirectional,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaError {
    /// The domain's mapping table (fixed capacity) is full.
    TableFull,
    /// `unmap` named a range that is not currently mapped: never mapped, or
    /// already unmapped once. Callers should treat this as a driver bug, not
    /// retry.
    NotMapped,
    /// Zero length, or `addr + len` overflows.
    BadRange,
    /// The buffer is not inside memory the domain may hand to a device.
    OutsideRam,
    /// The buffer is outside what the device can address and the domain has
    /// no IOMMU to remap it; a bounce buffer would be needed.
    NeedsBounce,
    /// The domain could not get memory for its own tables.
    NoMemory,
    /// The IOMMU refused a command or did not answer.
    Iommu,
}

// ---------------------------------------------------------------------
// AddrRange — the pure geometry the bounce decision and IOMMU-off
// single-mapping both need
// ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddrRange {
    pub start: u64,
    /// Exclusive end.
    pub end: u64,
}

impl AddrRange {
    pub const fn new(start: u64, end: u64) -> Self {
        AddrRange { start, end }
    }

    /// `true` iff `[addr, addr+len)` fits entirely inside this range.
    ///
    /// Uses `checked_add`, not a plain `+` or a saturating add: a plain
    /// add wraps and can under-report the end (says "fits" when it
    /// wrapped below `start`); a *saturating* add is just as wrong the
    /// other way when `end == u64::MAX` — it clamps the overflowed sum
    /// back down to something `<= end` and reports "fits" for a buffer
    /// that actually ran off the end of the address space. Overflow here
    /// only means "this buffer is not a valid range at all", so it must
    /// report "does not fit", full stop.
    pub const fn contains_range(&self, addr: u64, len: u64) -> bool {
        match addr.checked_add(len) {
            Some(far_end) => addr >= self.start && far_end <= self.end,
            None => false,
        }
    }
}

/// Every device on every board this crate has to plan for today is a
/// 32-bit DMA master or better on QEMU `virt` (virtio has no addressing
/// limit) — so the "no IOMMU" default capable range is the full 64-bit
/// space, and a caller with a narrower device (legacy 32-bit-only
/// hardware) passes its own range. Not a hardware fact, just a sane
/// default so callers that don't know better don't spuriously bounce.
pub const FULL_RANGE: AddrRange = AddrRange::new(0, u64::MAX);

// ---------------------------------------------------------------------
// Bounce-buffer decision — pure function of the inputs
// ---------------------------------------------------------------------

/// `true` iff a streaming DMA of `[phys, phys+len)` needs to go through a
/// bounce buffer instead of being mapped in place.
///
/// - IOMMU on: never bounces — the IOMMU driver can map any physical
///   page to an IOVA within the device's addressable range (that is the
///   whole point of stage 1b), so `iommu_active` short-circuits to
///   `false` regardless of the buffer's physical address.
/// - IOMMU off: bounces iff the buffer does not fit entirely inside the
///   device's addressable range — the CPU cannot change where its own
///   memory lives, so this is the only remaining tool.
///
/// Cache-coherency bouncing (non-coherent SoCs needing cache maintenance
/// instead of a copy) is deliberately NOT this function's concern — that
/// is a `cache.rs`-style cache-op decision, not an addressability one; a
/// caller combines both, but conflating them here would hide which
/// reason applied when someone asks "why did this bounce".
pub const fn needs_bounce(iommu_active: bool, device_capable: AddrRange, phys: u64, len: u64) -> bool {
    if iommu_active {
        return false;
    }
    !device_capable.contains_range(phys, len)
}
