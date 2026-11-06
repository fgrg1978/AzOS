// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Memory a ring-3 driver's device may reach: a physically contiguous memory
//! object bound to one device and that device's domain.
//!
//! The device sees the object and nothing else. [`map`] puts the object's run
//! in the device's domain and answers the bus address the driver programs; an
//! IOMMU domain then reaches those pages only, a software-checked one checks
//! them against RAM, and memory that was never bound is never in a domain
//! through this path. The kernel keeps a reference on the object for as long
//! as the binding lives, so its frames cannot go back to the allocator under
//! the device.
//!
//! [`release`] is the one way a binding ends, whatever ended it (the driver's
//! unmap, its exit, the device's unbind): the domain's unmap first, which
//! for an IOMMU domain flushes the unit's cached translations, and only
//! then the kernel's reference, after which the frames may be freed. An unmap
//! that failed may have left a translation the device can still use: the
//! reference is then kept for good and its bytes counted
//! ([`crate::leaked_bytes`]), as [`crate::unmap_and_free`] does for the
//! kernel's own buffers.
//!
//! [`Table`] is the bookkeeping, pure so a host test drives it: one binding
//! per object, recorded with the task that made it.

use crate::{Direction, DmaAddr, DmaDomain, DmaError};

/// One live binding: `obj` mapped for device `dev` by task `owner`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The task that made the binding (its exit ends it).
    pub owner: u32,
    /// The device, as the hardware bus names it.
    pub dev: u32,
    /// The memory object (its packed reference).
    pub obj: u32,
    /// The object's physical run.
    pub pa: u64,
    pub len: usize,
    /// What the device was told.
    pub bus: DmaAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindError {
    /// The object is bound already (to this device or another).
    Busy,
    /// The table has no free record.
    Full,
    /// The domain refused the mapping.
    Domain(DmaError),
}

/// Runtime canary: [`map`] records the binding without putting the object in
/// the domain, so behind an IOMMU the device's first access to it faults.
#[cfg(feature = "dma-bind-skip-map-canary")]
const SKIP_MAP: bool = true;
#[cfg(not(feature = "dma-bind-skip-map-canary"))]
const SKIP_MAP: bool = false;

/// Put `[pa, pa + len)` in `domain` for `dir`: the bus address the device is
/// told.
pub fn map(domain: &dyn DmaDomain, pa: u64, len: usize, dir: Direction) -> Result<DmaAddr, DmaError> {
    if SKIP_MAP {
        return Ok(DmaAddr(pa));
    }
    domain.map(pa, len, dir)
}

/// End binding `b`: take the object out of `domain`, then call `drop_ref`,
/// which gives the kernel's reference back (the frames may go). A failed
/// unmap keeps the reference: `drop_ref` is not called and the bytes are
/// counted as leaked.
pub fn release(domain: &dyn DmaDomain, b: &Binding, drop_ref: impl FnOnce(u32)) -> Result<(), DmaError> {
    let r = if SKIP_MAP { Ok(()) } else { domain.unmap(b.bus, b.len) };
    if r.is_err() && !crate::alloc::free_anyway() {
        crate::note_leak(b.len);
        return r;
    }
    drop_ref(b.obj);
    r
}

/// Up to `N` live bindings.
pub struct Table<const N: usize> {
    slots: [Option<Binding>; N],
}

impl<const N: usize> Default for Table<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Table<N> {
    pub const fn new() -> Self {
        Table { slots: [None; N] }
    }

    /// Record `b`. An object is bound to one device at a time.
    pub fn insert(&mut self, b: Binding) -> Result<(), BindError> {
        if self.slots.iter().flatten().any(|s| s.obj == b.obj) {
            return Err(BindError::Busy);
        }
        let slot = self.slots.iter_mut().find(|s| s.is_none()).ok_or(BindError::Full)?;
        *slot = Some(b);
        Ok(())
    }

    /// Is there room for one more, and is `obj` free to bind?
    pub fn can_insert(&self, obj: u32) -> Result<(), BindError> {
        if self.slots.iter().flatten().any(|s| s.obj == obj) {
            return Err(BindError::Busy);
        }
        if self.slots.iter().all(Option::is_some) {
            return Err(BindError::Full);
        }
        Ok(())
    }

    /// Take the binding `owner` made of `obj` for `dev`.
    pub fn take(&mut self, owner: u32, dev: u32, obj: u32) -> Option<Binding> {
        let slot = self.slots.iter_mut().find(|s| matches!(s, Some(b) if b.owner == owner && b.dev == dev && b.obj == obj))?;
        slot.take()
    }

    /// Take one binding `owner` made, any: the exit path takes them one at a
    /// time and releases each outside the table's lock.
    pub fn take_owned(&mut self, owner: u32) -> Option<Binding> {
        let slot = self.slots.iter_mut().find(|s| matches!(s, Some(b) if b.owner == owner))?;
        slot.take()
    }

    /// Live bindings.
    pub fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
