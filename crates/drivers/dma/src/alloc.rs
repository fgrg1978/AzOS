// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Memory a device can reach: allocation under a device's DMA mask.
//!
//! A device whose DMA stops short of the top of RAM (a 32-bit master on a
//! board with memory above 4 GiB, a bus whose device-tree `dma-ranges` end
//! early) must be given memory under its limit. QEMU hides the need: its
//! virtio devices address everything. [`alloc_below`] takes the memory from
//! the page allocator the caller already has ([`PageSource`]) and keeps only
//! what fits; the identity path (no mask: `u64::MAX`) is one allocation and
//! no check.
//!
//! The page allocator has no address-ranged allocation, so the pages that do
//! not fit are held until one does and then given back. That is bounded
//! ([`MAX_MISSES`]): a source whose free memory is mostly above the mask is
//! refused ([`DmaError::NeedsBounce`]) rather than drained. A ranged
//! allocation in the page allocator would make the bound unnecessary.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::{AddrRange, DmaAddr, DmaDomain, DmaError};

/// Bytes kept from the allocator because a device may still reach them.
static LEAKED_BYTES: AtomicU64 = AtomicU64::new(0);

/// Runtime canary: pages go back even when their unmap failed.
static CANARY_FREE_ANYWAY: AtomicBool = AtomicBool::new(false);

/// See [`CANARY_FREE_ANYWAY`].
pub fn canary_free_anyway(on: bool) {
    CANARY_FREE_ANYWAY.store(on, Ordering::Relaxed);
}

/// Is [`canary_free_anyway`] on?
pub(crate) fn free_anyway() -> bool {
    CANARY_FREE_ANYWAY.load(Ordering::Relaxed)
}

/// Bytes [`note_leak`] has counted since boot.
pub fn leaked_bytes() -> u64 {
    LEAKED_BYTES.load(Ordering::Relaxed)
}

/// `len` bytes stay out of the allocator for good: a device may still reach them.
pub fn note_leak(len: usize) {
    LEAKED_BYTES.fetch_add(len as u64, Ordering::Relaxed);
}

/// Undo the mapping at `bus` and give the `len` bytes at `pa` back to `src`. An
/// unmap that failed may have left a translation the device can still use (the
/// IOTLB flush did not complete): the pages then stay out for good, counted.
pub fn unmap_and_free<S: PageSource>(domain: &dyn DmaDomain, src: &S, pa: u64, bus: DmaAddr, len: usize) -> Result<(), DmaError> {
    let r = domain.unmap(bus, len);
    if r.is_err() && !free_anyway() {
        note_leak(len);
        return r;
    }
    src.free(pa, len);
    r
}

/// Blocks [`alloc_below`] holds at once while it looks for one under the
/// mask. More than this above the mask and it gives up.
pub const MAX_MISSES: usize = 32;

/// Where [`alloc_below`] gets memory: the kernel's page allocator.
pub trait PageSource {
    /// A block of `len` bytes (a multiple of the page size, aligned the way
    /// the allocator aligns it) and its physical address; `None` when there
    /// is none.
    fn alloc(&self, len: usize) -> Option<u64>;
    /// Give back a block `alloc` returned (same address and length).
    fn free(&self, pa: u64, len: usize);
}

/// A block of `len` bytes lying entirely at or below `mask` (the highest
/// address the device can reach, inclusive), from `src`.
///
/// - `mask == u64::MAX`: no limit; one allocation and nothing else.
/// - `mask < len - 1`: a block cannot lie under it at all; [`DmaError::NeedsBounce`] without touching the source.
/// - No block under the mask among the first [`MAX_MISSES`] + 1 the source
///   hands out: [`DmaError::NeedsBounce`], with every block taken given back.
/// - The source has none: [`DmaError::NoMemory`], likewise.
pub fn alloc_below<S: PageSource>(src: &S, mask: u64, len: usize) -> Result<u64, DmaError> {
    if len == 0 {
        return Err(DmaError::BadRange);
    }
    if mask == u64::MAX {
        return src.alloc(len).ok_or(DmaError::NoMemory);
    }
    // Not even a block at address 0 fits (a mask of `DMA_UNREACHABLE`): no
    // allocation can help, so none is made.
    if mask < len as u64 - 1 {
        return Err(DmaError::NeedsBounce);
    }
    // The blocks above the mask stay allocated until a fit is found: freeing
    // each at once would hand the same one straight back.
    let reach = AddrRange::new(0, mask.saturating_add(1));
    let mut held = [0u64; MAX_MISSES];
    let mut n = 0;
    let found = loop {
        let Some(pa) = src.alloc(len) else { break Err(DmaError::NoMemory) };
        if reach.contains_range(pa, len as u64) {
            break Ok(pa);
        }
        if n == MAX_MISSES {
            src.free(pa, len);
            break Err(DmaError::NeedsBounce);
        }
        held[n] = pa;
        n += 1;
    };
    for &pa in &held[..n] {
        src.free(pa, len);
    }
    found
}
