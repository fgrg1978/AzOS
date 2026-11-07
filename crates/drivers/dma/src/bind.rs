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
//! per object, recorded with the thread that made it and the domain it was
//! mapped through (its end unmaps from that domain, never from one looked up
//! again), at most a share of the table per process. A binding whose device
//! could not be shown stopped is *parked*: it keeps its pages and its record,
//! ends for nobody, and no new binding is made for that device, so a driver
//! that crashes and restarts keeps at most one object's worth of memory out
//! of the allocator. A binding being ended keeps its record until it is
//! freed or parked, so parking cannot fail.
//!
//! [`reuse_for_ring3`] is the rule the kernel hands an IOMMU domain out to
//! ring 3 by.

use crate::{Direction, DmaAddr, DmaDomain, DmaError};

/// One live binding: `obj` mapped for device `dev` by thread `owner` of
/// process `group`, through `domain`.
#[derive(Clone, Copy)]
pub struct Binding {
    /// The thread that made the binding (its exit ends it).
    pub owner: u32,
    /// Its process: the table's share is counted per process.
    pub group: u32,
    /// The device, as the hardware bus names it.
    pub dev: u32,
    /// The memory object (its packed reference).
    pub obj: u32,
    /// The object's physical run.
    pub pa: u64,
    pub len: usize,
    /// What the device was told.
    pub bus: DmaAddr,
    /// The domain the object was mapped through.
    pub domain: &'static dyn DmaDomain,
}

impl PartialEq for Binding {
    fn eq(&self, o: &Self) -> bool {
        (self.owner, self.group, self.dev, self.obj, self.pa, self.len, self.bus)
            == (o.owner, o.group, o.dev, o.obj, o.pa, o.len, o.bus)
            && core::ptr::addr_eq(self.domain as *const dyn DmaDomain, o.domain as *const dyn DmaDomain)
    }
}

impl core::fmt::Debug for Binding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Binding")
            .field("owner", &self.owner)
            .field("group", &self.group)
            .field("dev", &self.dev)
            .field("obj", &self.obj)
            .field("pa", &self.pa)
            .field("len", &self.len)
            .field("bus", &self.bus)
            .field("domain", &self.domain.kind())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindError {
    /// The object is bound already (to this device or another), or a binding
    /// of the device is being ended.
    Busy,
    /// The table has no free record.
    Full,
    /// The process holds its share of the table already.
    Quota,
    /// A binding of the device is parked: its pages are kept.
    Parked,
    /// The domain refused the mapping.
    Domain(DmaError),
}

/// May the kernel hand ring 3 a device's existing IOMMU domain: one ring 3
/// was handed and still has live bindings in (`ring3_live`), or one that
/// translates and maps nothing (a kernel driver's, after an unbind, with
/// nothing it left behind; ring 3's own once its bindings ended).
pub const fn reuse_for_ring3(enabled: bool, empty: bool, ring3_live: bool) -> bool {
    if cfg!(feature = "ring3-reuse-canary") {
        return enabled && empty;
    }
    (enabled && ring3_live) || (enabled && empty)
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

/// End binding `b`: take the object out of the domain it was mapped through,
/// then call `drop_ref`, which gives the kernel's reference back (the frames
/// may go). A failed unmap keeps the reference: `drop_ref` is not called and
/// the bytes are counted as leaked.
pub fn release(b: &Binding, drop_ref: impl FnOnce(u32)) -> Result<(), DmaError> {
    let r = if SKIP_MAP { Ok(()) } else { b.domain.unmap(b.bus, b.len) };
    if r.is_err() && !crate::alloc::free_anyway() {
        crate::note_leak(b.len);
        return r;
    }
    drop_ref(b.obj);
    r
}

/// Where a record stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum State {
    Free = 0,
    Live,
    /// Taken by an end that has not said yet whether it frees or parks it.
    Ending,
    Parked,
}

/// A binding taken out for its end: [`Table::finish`] frees or parks its
/// record.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Taken {
    slot: usize,
    pub binding: Binding,
}

/// Up to `N` bindings.
pub struct Table<const N: usize> {
    slots: [Option<Binding>; N],
    state: [State; N],
}

impl<const N: usize> Default for Table<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Table<N> {
    pub const fn new() -> Self {
        Table { slots: [None; N], state: [State::Free; N] }
    }

    /// Bindings one process may hold: a quarter of the table, so one driver,
    /// however many threads it has, cannot take every record from the others.
    pub const PER_PROCESS: usize = if N >= 4 { N / 4 } else { 1 };

    fn with(&self, st: State) -> impl Iterator<Item = &Binding> + '_ {
        (0..N).filter(move |&i| self.state[i] == st).filter_map(move |i| self.slots[i].as_ref())
    }

    /// May process `group` bind `obj` to `dev`: the object is free, the device
    /// has no parked binding and none being ended, the process is under its
    /// share and there is room.
    pub fn can_insert(&self, group: u32, dev: u32, obj: u32) -> Result<(), BindError> {
        if self.slots.iter().flatten().any(|s| s.obj == obj) || self.with(State::Ending).any(|s| s.dev == dev) {
            return Err(BindError::Busy);
        }
        if self.with(State::Parked).any(|s| s.dev == dev) {
            return Err(BindError::Parked);
        }
        if self.with(State::Live).filter(|s| s.group == group).count() >= Self::PER_PROCESS {
            return Err(BindError::Quota);
        }
        if self.state.iter().all(|s| *s != State::Free) {
            return Err(BindError::Full);
        }
        Ok(())
    }

    /// Record `b` (checked first with [`Self::can_insert`]).
    pub fn insert(&mut self, b: Binding) -> Result<(), BindError> {
        self.can_insert(b.group, b.dev, b.obj)?;
        let i = self.state.iter().position(|s| *s == State::Free).ok_or(BindError::Full)?;
        self.slots[i] = Some(b);
        self.state[i] = State::Live;
        Ok(())
    }

    /// Record `b` parked at once: a map the unit did not confirm taking back
    /// may have left the object in the domain, so its pages are kept and the
    /// device gets no new binding, as for one whose end could not stop it.
    /// `b.bus` is what the object would have been told; no end ever unmaps it.
    pub fn insert_parked(&mut self, b: Binding) -> Result<(), BindError> {
        self.can_insert(b.group, b.dev, b.obj)?;
        let i = self.state.iter().position(|s| *s == State::Free).ok_or(BindError::Full)?;
        self.slots[i] = Some(b);
        self.state[i] = State::Parked;
        Ok(())
    }

    fn take_where(&mut self, f: impl Fn(&Binding) -> bool) -> Option<Taken> {
        let slot = (0..N).find(|&i| self.state[i] == State::Live && self.slots[i].as_ref().is_some_and(&f))?;
        self.state[slot] = State::Ending;
        Some(Taken { slot, binding: self.slots[slot]? })
    }

    /// Take the binding `owner` made of `obj` for `dev` for its end; its
    /// record stays until [`Self::finish`].
    pub fn take(&mut self, owner: u32, dev: u32, obj: u32) -> Option<Taken> {
        self.take_where(|b| b.owner == owner && b.dev == dev && b.obj == obj)
    }

    /// Take one binding `owner` made, any: the exit path takes them one at a
    /// time and ends each outside the table's lock.
    pub fn take_owned(&mut self, owner: u32) -> Option<Taken> {
        self.take_where(|b| b.owner == owner)
    }

    /// The end of `t` is over: its record goes, or, with `park`, stays for
    /// good (its pages kept, its device given nothing new).
    pub fn finish(&mut self, t: Taken, park: bool) {
        if park && !cfg!(feature = "park-drop-canary") {
            self.state[t.slot] = State::Parked;
        } else {
            self.slots[t.slot] = None;
            self.state[t.slot] = State::Free;
        }
    }

    /// Has `dev` a live binding?
    pub fn has_live(&self, dev: u32) -> bool {
        self.with(State::Live).any(|b| b.dev == dev)
    }

    /// Live bindings.
    pub fn len(&self) -> usize {
        self.with(State::Live).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
