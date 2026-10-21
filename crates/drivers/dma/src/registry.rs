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
//! A platform device may also differ from the default in one respect: its
//! cache coherence. The firmware says so per device (device tree
//! `dma-coherent`), the boot records the difference with [`declare_mmio`],
//! and [`domain_for_mmio`] returns the default domain seen through it: same
//! mapping rules, the device's own answer to `coherent()`.

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

/// One platform device's view of the default domain.
struct MmioSlot {
    state: AtomicU8,
    base: UnsafeCell<u64>,
    coherent: UnsafeCell<bool>,
}

// SAFETY: as `Slot`: written only by the installer that won EMPTY -> WRITING,
// read only after READY (Acquire).
unsafe impl Sync for MmioSlot {}

impl MmioSlot {
    const fn new() -> Self {
        MmioSlot { state: AtomicU8::new(EMPTY), base: UnsafeCell::new(0), coherent: UnsafeCell::new(true) }
    }

    fn declare(&self, base: u64, coherent: bool) -> bool {
        if self.state.compare_exchange(EMPTY, WRITING, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return false;
        }
        // SAFETY: we own the slot between WRITING and READY.
        unsafe {
            *self.base.get() = base;
            *self.coherent.get() = coherent;
        }
        self.state.store(READY, Ordering::Release);
        true
    }

    fn base(&self) -> Option<u64> {
        // SAFETY: READY means the installer finished; the fields never change again.
        (self.state.load(Ordering::Acquire) == READY).then(|| unsafe { *self.base.get() })
    }
}

static MMIO: [MmioSlot; MAX_MMIO] = [const { MmioSlot::new() }; MAX_MMIO];

impl DmaDomain for MmioSlot {
    fn map(&self, pa: u64, len: usize, dir: crate::Direction) -> Result<crate::DmaAddr, crate::DmaError> {
        domain_for(None).map(pa, len, dir)
    }
    fn unmap(&self, bus: crate::DmaAddr, len: usize) -> Result<(), crate::DmaError> {
        domain_for(None).unmap(bus, len)
    }
    fn coherent(&self) -> bool {
        // SAFETY: only handed out by `domain_for_mmio`, after READY.
        unsafe { *self.coherent.get() }
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

/// Record that the platform device whose registers start at `base` is
/// `coherent` (or not) whatever the default domain says. Once per device;
/// the boot records only the devices that differ from the default.
pub fn declare_mmio(base: u64, coherent: bool) -> Result<(), InstallError> {
    if MMIO.iter().any(|s| s.base() == Some(base)) {
        return Err(InstallError::Taken);
    }
    for s in MMIO.iter() {
        if s.declare(base, coherent) {
            return Ok(());
        }
    }
    Err(InstallError::Full)
}

/// The domain of the platform device whose registers start at `base`: the
/// default seen with the coherence the device declared, else the default.
pub fn domain_for_mmio(base: u64) -> &'static dyn DmaDomain {
    match MMIO.iter().find(|s| s.base() == Some(base)) {
        Some(s) => s,
        None => domain_for(None),
    }
}
