// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DMA mapping API (RFC-0046 stage 1): map/unmap single, a coherent pool
//! allocator, and the bounce-buffer decision — all as pure logic against
//! an injected [`AddrTranslate`], so `azos_dma_tests` exercises real
//! bookkeeping (double-unmap, exhaustion, reuse) on the host.
//!
//! # Why `DmaAddr` is not just "the physical address"
//!
//! With the IOMMU off (today, on VF2/K1, and on QEMU until stage 1b's
//! driver exists) the bus address a device must be given IS the physical
//! address — `virtio/mod.rs`'s existing `dma_addr_of` already does
//! exactly that. With the IOMMU on (stage 1b), the bus address is an
//! IOVA the IOMMU driver chose, which may not equal the physical address
//! at all. Callers (starting with `virtio/pci.rs`) take a [`DmaAddr`]
//! from this crate's `map_*` functions and hand THAT to the device —
//! never `virt_to_phys` directly — so turning the IOMMU on later is a
//! change in what this crate returns, not a change in every driver.
#![no_std]

// ---------------------------------------------------------------------
// Address translation seam
// ---------------------------------------------------------------------

/// The two address-space conversions any DMA mapping needs. The kernel
/// implements this over `azos_mm::addr::{virt_to_phys,phys_to_virt}`
/// (see `virtio/mod.rs` doc for why those two differ once aarch64 is not
/// identity-mapped); `azos_dma_tests` implements it over a fake
/// identity-with-offset scheme so the arithmetic is checkable without a
/// real MMU.
pub trait AddrTranslate {
    fn virt_to_phys(&self, va: usize) -> usize;
    fn phys_to_virt(&self, pa: usize) -> usize;
}

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
    /// The mapping table (fixed capacity) is full.
    TableFull,
    /// `unmap_single` was called with a handle that is not currently
    /// mapped — either it was never mapped, or it was already unmapped
    /// once (double-unmap). Callers should treat this as a driver bug,
    /// not retry.
    NotMapped,
    /// The pool has no free block of the requested size.
    PoolExhausted,
    /// A coherent-pool handle was freed twice, or freed without ever
    /// being allocated.
    DoubleFree,
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
// Bounce-buffer decision — pure function of the inputs, per RFC-0046 §2.3
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
/// is a `cbo.rs`-style cache-op decision, not an addressability one; a
/// caller combines both, but conflating them here would hide which
/// reason applied when someone asks "why did this bounce".
pub const fn needs_bounce(iommu_active: bool, device_capable: AddrRange, phys: u64, len: u64) -> bool {
    if iommu_active {
        return false;
    }
    !device_capable.contains_range(phys, len)
}

// ---------------------------------------------------------------------
// map_single / unmap_single — fixed-capacity bookkeeping table
// ---------------------------------------------------------------------

/// An opaque handle to an active single-buffer mapping. Callers hold
/// this instead of the `DmaAddr` so `unmap_single` can detect
/// double-unmap (the `DmaAddr` alone can't — two different mappings can
/// legitimately share a bus address after one is freed and the slot
/// reused).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapHandle(usize);

#[derive(Clone, Copy, Debug)]
struct MapEntry {
    va: usize,
    len: usize,
    bus: DmaAddr,
    direction: Direction,
}

/// Fixed-capacity table of active `map_single` mappings. `N` is a
/// compile-time cap so this never allocates — sized per board/profile by
/// the caller (a handful of in-flight virtqueue buffers is typical).
pub struct DmaMapTable<const N: usize> {
    slots: [Option<MapEntry>; N],
}

impl<const N: usize> DmaMapTable<N> {
    pub const fn new() -> Self {
        DmaMapTable { slots: [None; N] }
    }

    /// Map `[va, va+len)` for `direction`. With no IOMMU domain
    /// (`iommu_active = false`) the returned [`DmaAddr`] is the physical
    /// address (`AddrTranslate::virt_to_phys`); a real IOMMU-on path is
    /// stage 1b's job (`crates/drivers/iommu` chooses the IOVA) and is not
    /// implemented by this function — pass `iommu_active = false` until
    /// that lands, which is every caller today.
    pub fn map_single<A: AddrTranslate>(
        &mut self,
        xlate: &A,
        va: usize,
        len: usize,
        direction: Direction,
    ) -> Result<(DmaAddr, MapHandle), DmaError> {
        let slot = self.slots.iter().position(|s| s.is_none()).ok_or(DmaError::TableFull)?;
        let pa = xlate.virt_to_phys(va);
        let bus = DmaAddr(pa as u64);
        self.slots[slot] = Some(MapEntry { va, len, bus, direction });
        Ok((bus, MapHandle(slot)))
    }

    pub fn unmap_single(&mut self, handle: MapHandle) -> Result<(), DmaError> {
        let slot = self.slots.get_mut(handle.0).ok_or(DmaError::NotMapped)?;
        if slot.take().is_none() {
            return Err(DmaError::NotMapped);
        }
        Ok(())
    }

    /// Look up an active mapping's `(virtual address, length, direction)`
    /// without unmapping it — for a caller that needs to re-derive the
    /// CPU-side slice from a handle (e.g. after a completion) instead of
    /// carrying the triple around itself.
    pub fn lookup(&self, handle: MapHandle) -> Result<(usize, usize, Direction), DmaError> {
        let entry = self.slots.get(handle.0).and_then(|s| s.as_ref()).ok_or(DmaError::NotMapped)?;
        Ok((entry.va, entry.len, entry.direction))
    }

    /// The bus address an active mapping was given. Separate from
    /// `lookup` so a caller that only needs the address (the common
    /// case: feeding a virtqueue descriptor) doesn't have to destructure
    /// the triple.
    pub fn bus_addr(&self, handle: MapHandle) -> Result<DmaAddr, DmaError> {
        let entry = self.slots.get(handle.0).and_then(|s| s.as_ref()).ok_or(DmaError::NotMapped)?;
        Ok(entry.bus)
    }

    /// Number of currently-active mappings. Exposed for host tests and
    /// for a health-check row (a leaked mapping shows up as this never
    /// returning to 0 between requests).
    pub fn active_count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }
}

// ---------------------------------------------------------------------
// Coherent pool — fixed backing region, block allocator
// ---------------------------------------------------------------------

/// A fixed pool of `COUNT` blocks of `BLOCK_SIZE` bytes each, handed out
/// whole. Meant to back `virtq_init`'s page allocations and similar
/// "coherent memory, known fixed size, allocated once" needs without
/// going through `mm::kheap` (the brief: don't allocate on hot paths —
/// this is a boot/setup-time allocator, and a fixed pool means no
/// fragmentation to worry about either).
///
/// This crate does not own the backing bytes — `base_pa`/`base_va` are
/// supplied by the caller (kernel: a `pmm`-reserved region; host tests: a
/// fake offset) so the crate stays free of any real memory-mapping
/// concern and is fully host-testable.
pub struct CoherentPool<const COUNT: usize> {
    base_pa: u64,
    base_va: usize,
    block_size: usize,
    /// `true` = free. Bitmap-as-bool-array rather than a real bitmap:
    /// COUNT is small (tens, not thousands) for every known caller, and
    /// the clarity is worth more than the few bytes saved.
    free: [bool; COUNT],
}

impl<const COUNT: usize> CoherentPool<COUNT> {
    pub const fn new(base_pa: u64, base_va: usize, block_size: usize) -> Self {
        CoherentPool { base_pa, base_va, block_size, free: [true; COUNT] }
    }

    /// Allocate one block. Returns (virtual address the CPU writes
    /// through, bus address the device is told) or `PoolExhausted`.
    pub fn alloc(&mut self) -> Result<(usize, DmaAddr, PoolHandle), DmaError> {
        let idx = self.free.iter().position(|&f| f).ok_or(DmaError::PoolExhausted)?;
        self.free[idx] = false;
        let off = idx * self.block_size;
        Ok((self.base_va + off, DmaAddr(self.base_pa + off as u64), PoolHandle(idx)))
    }

    pub fn free(&mut self, handle: PoolHandle) -> Result<(), DmaError> {
        let slot = self.free.get_mut(handle.0).ok_or(DmaError::DoubleFree)?;
        if *slot {
            // Already free — this is a double-free, not a silent no-op:
            // silently accepting it would hide a caller bug that, on a
            // real pool, corrupts the free list instead.
            return Err(DmaError::DoubleFree);
        }
        *slot = true;
        Ok(())
    }

    pub fn free_count(&self) -> usize {
        self.free.iter().filter(|&&f| f).count()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolHandle(usize);
