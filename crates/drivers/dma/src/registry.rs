// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Which domain a device sits in.
//!
//! A device is named by its PCI requester id (`bus << 8 | device << 3 |
//! function`), the number every IOMMU flavour keys on; a platform device
//! (virtio-mmio) has none and uses the default domain. The boot installs
//! the default and one domain per device an IOMMU translates; a driver asks
//! [`domain_for`] at probe and keeps the answer.
//!
//! A platform device may also differ from the default in two respects: its
//! cache coherence, and the bus between it and memory. The firmware says so
//! per device (device tree `dma-coherent`, and `dma-ranges` on a bus above
//! it: a Raspberry Pi's VideoCore bus sees RAM at 0xc000_0000), the boot
//! records the difference with [`declare_mmio`], and [`domain_for_mmio`]
//! returns the default domain seen through it: same mapping rules, the
//! device's own answer to `coherent()`, and every bus address moved by the
//! bus's offset within the window it reaches.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::domain::{DmaDomain, IdentityDomain};

/// Devices that can have a domain of their own at once.
pub const MAX_BOUND: usize = 16;

const EMPTY: u8 = 0;
const WRITING: u8 = 1;
const READY: u8 = 2;

struct Slot {
    state: AtomicU8,
    dev: UnsafeCell<u32>,
    domain: UnsafeCell<Option<&'static dyn DmaDomain>>,
}

// SAFETY: `dev` and `domain` are written only by the one installer that won
// the EMPTY -> WRITING transition, and read only after READY (Acquire).
unsafe impl Sync for Slot {}

impl Slot {
    const fn new() -> Self {
        Slot { state: AtomicU8::new(EMPTY), dev: UnsafeCell::new(0), domain: UnsafeCell::new(None) }
    }

    fn install(&self, dev: u32, d: &'static dyn DmaDomain) -> bool {
        if self.state.compare_exchange(EMPTY, WRITING, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return false;
        }
        // SAFETY: we own the slot between WRITING and READY.
        unsafe {
            *self.dev.get() = dev;
            *self.domain.get() = Some(d);
        }
        self.state.store(READY, Ordering::Release);
        true
    }

    fn get(&self) -> Option<(u32, &'static dyn DmaDomain)> {
        if self.state.load(Ordering::Acquire) != READY {
            return None;
        }
        // SAFETY: READY means the installer finished; the fields never change again.
        unsafe { (*self.domain.get()).map(|d| (*self.dev.get(), d)) }
    }
}

static DEFAULT: Slot = Slot::new();
static BOUND: [Slot; MAX_BOUND] = [const { Slot::new() }; MAX_BOUND];

/// What a device with no domain of its own gets before the boot installs a
/// default: unchecked, and coherent (the only machines without a boot-time
/// answer are the ones that never asked).
static FALLBACK: IdentityDomain = IdentityDomain::new(true);

/// The domain of a device nobody installed one for, usable in a `const`
/// initialiser (a driver's `static` state starts out with it).
pub const fn fallback() -> &'static dyn DmaDomain {
    &FALLBACK
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallError {
    /// A domain is already installed for that device (or as the default).
    Taken,
    /// `MAX_BOUND` devices already have one.
    Full,
}

/// Install the domain of every device that has none of its own. Once.
pub fn install_default(d: &'static dyn DmaDomain) -> Result<(), InstallError> {
    if DEFAULT.install(0, d) { Ok(()) } else { Err(InstallError::Taken) }
}

/// Install the domain of the PCI device `requester_id`. Once per device.
pub fn install_for(requester_id: u32, d: &'static dyn DmaDomain) -> Result<(), InstallError> {
    if BOUND.iter().filter_map(Slot::get).any(|(dev, _)| dev == requester_id) {
        return Err(InstallError::Taken);
    }
    for s in BOUND.iter() {
        if s.install(requester_id, d) {
            return Ok(());
        }
    }
    Err(InstallError::Full)
}

/// The domain of a device: its own if one was installed, else the default,
/// else an unchecked identity domain.
pub fn domain_for(requester_id: Option<u32>) -> &'static dyn DmaDomain {
    if let Some(id) = requester_id {
        if let Some((_, d)) = BOUND.iter().filter_map(Slot::get).find(|(dev, _)| *dev == id) {
            return d;
        }
    }
    match DEFAULT.get() {
        Some((_, d)) => d,
        None => &FALLBACK,
    }
}

// ---------------------------------------------------------------------
// Platform devices whose coherence differs from the default's
// ---------------------------------------------------------------------

/// Platform devices that can differ from the default at once.
pub const MAX_MMIO: usize = 16;

/// How a platform device differs from the default domain ([`declare_mmio`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioView {
    /// Its coherence, `None` for the default's.
    pub coherent: Option<bool>,
    /// What its bus adds to a CPU physical address (device tree `dma-ranges`).
    pub offset: u64,
    /// The highest CPU physical address (inclusive) its bus reaches.
    pub cpu_limit: u64,
}

impl MmioView {
    /// The default domain with only the coherence changed.
    pub const fn coherent(coherent: bool) -> Self {
        MmioView { coherent: Some(coherent), offset: 0, cpu_limit: u64::MAX }
    }

    /// The default domain behind a bus that adds `offset` to a CPU address
    /// at or below `cpu_limit`.
    pub const fn translated(offset: u64, cpu_limit: u64) -> Self {
        MmioView { coherent: None, offset, cpu_limit }
    }

    /// The bus address of CPU address `pa` mapped `len` bytes long by the
    /// default to `bus` (its CPU-side address in the default's numbering);
    /// `None` past the window.
    pub const fn bus_of(&self, bus: u64, len: usize) -> Option<u64> {
        match bus.checked_add(len as u64 - 1) {
            Some(end) if end <= self.cpu_limit => Some(bus.wrapping_add(self.offset)),
            _ => None,
        }
    }

    /// See [`DmaDomain::cpu_limit`].
    pub const fn cpu_limit_for(&self, bus_limit: u64) -> u64 {
        if self.offset == 0 {
            return if bus_limit < self.cpu_limit { bus_limit } else { self.cpu_limit };
        }
        // The window is CPU [0, cpu_limit] at bus [offset, offset + cpu_limit].
        if bus_limit < self.offset {
            return 0;
        }
        let reach = bus_limit - self.offset;
        if reach < self.cpu_limit { reach } else { self.cpu_limit }
    }
}

/// The platform devices whose registers start in `[lo, hi]` and their view
/// of the default domain.
struct MmioSlot {
    state: AtomicU8,
    range: UnsafeCell<(u64, u64)>,
    view: UnsafeCell<MmioView>,
}

// SAFETY: as `Slot`: written only by the installer that won EMPTY -> WRITING,
// read only after READY (Acquire).
unsafe impl Sync for MmioSlot {}

impl MmioSlot {
    const fn new() -> Self {
        MmioSlot { state: AtomicU8::new(EMPTY), range: UnsafeCell::new((0, 0)), view: UnsafeCell::new(MmioView::translated(0, u64::MAX)) }
    }

    fn declare(&self, range: (u64, u64), view: MmioView) -> bool {
        if self.state.compare_exchange(EMPTY, WRITING, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return false;
        }
        // SAFETY: we own the slot between WRITING and READY.
        unsafe {
            *self.range.get() = range;
            *self.view.get() = view;
        }
        self.state.store(READY, Ordering::Release);
        true
    }

    fn range(&self) -> Option<(u64, u64)> {
        // SAFETY: READY means the installer finished; the fields never change again.
        (self.state.load(Ordering::Acquire) == READY).then(|| unsafe { *self.range.get() })
    }

    fn holds(&self, base: u64) -> bool {
        self.range().is_some_and(|(lo, hi)| lo <= base && base <= hi)
    }

    fn view(&self) -> MmioView {
        // SAFETY: only read through `domain_for_mmio`, after READY.
        unsafe { *self.view.get() }
    }
}

static MMIO: [MmioSlot; MAX_MMIO] = [const { MmioSlot::new() }; MAX_MMIO];

impl DmaDomain for MmioSlot {
    fn map(&self, pa: u64, len: usize, dir: crate::Direction) -> Result<crate::DmaAddr, crate::DmaError> {
        let v = self.view();
        let b = domain_for(None).map(pa, len, dir)?;
        match v.bus_of(b.0, len) {
            Some(bus) => Ok(crate::DmaAddr(bus)),
            None => {
                let _ = domain_for(None).unmap(b, len);
                Err(crate::DmaError::NeedsBounce)
            }
        }
    }
    fn unmap(&self, bus: crate::DmaAddr, len: usize) -> Result<(), crate::DmaError> {
        domain_for(None).unmap(crate::DmaAddr(bus.0.wrapping_sub(self.view().offset)), len)
    }
    fn coherent(&self) -> bool {
        self.view().coherent.unwrap_or_else(|| domain_for(None).coherent())
    }
    fn cpu_limit(&self, bus_limit: u64) -> u64 {
        self.view().cpu_limit_for(domain_for(None).cpu_limit(bus_limit))
    }
    fn phys_of(&self, bus: u64) -> u64 {
        domain_for(None).phys_of(bus.wrapping_sub(self.view().offset))
    }
    fn kind(&self) -> crate::DomainKind {
        domain_for(None).kind()
    }
    fn enable(&self) -> Result<(), crate::DmaError> {
        domain_for(None).enable()
    }
    fn allow_msi(&self, doorbell: u64) -> Result<(), crate::DmaError> {
        domain_for(None).allow_msi(doorbell)
    }
}

/// Record how the platform devices whose registers start in `[lo, hi]` differ
/// from the default domain (`view`: their coherence, their bus's offset and
/// window): one device (`lo == hi`), or every device of a bus that moves
/// their DMA alike (a Raspberry Pi's `/soc`). Once per device; the boot
/// records only the devices that differ, and never a range with another
/// device inside that does not share the view.
pub fn declare_mmio(lo: u64, hi: u64, view: MmioView) -> Result<(), InstallError> {
    if lo > hi || MMIO.iter().any(|s| s.range().is_some_and(|(a, b)| a <= hi && lo <= b)) {
        return Err(InstallError::Taken);
    }
    for s in MMIO.iter() {
        if s.declare((lo, hi), view) {
            return Ok(());
        }
    }
    Err(InstallError::Full)
}

/// The domain of the platform device whose registers start at `base`: the
/// default seen through what the device declared, else the default.
pub fn domain_for_mmio(base: u64) -> &'static dyn DmaDomain {
    match MMIO.iter().find(|s| s.holds(base)) {
        Some(s) => s,
        None => domain_for(None),
    }
}
