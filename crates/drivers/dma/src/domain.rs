// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DMA domains: what a driver maps its buffers through.
//!
//! A domain turns a physical buffer into the bus address a device is told
//! ([`DmaDomain::map`]) and takes the mapping back ([`DmaDomain::unmap`]).
//! Three kinds exist:
//!
//! - [`IdentityDomain`]: no IOMMU and no checking; the bus address is the
//!   physical address (what every driver did before domains existed).
//! - [`SoftState`]: no IOMMU, but every mapping is checked in software
//!   against the RAM the kernel may share and against what the device can
//!   address, and recorded so a double unmap is caught. It cannot stop a
//!   device that ignores its descriptors; it stops the driver bug that
//!   would hand a device the wrong page.
//! - the IOMMU domain of `azos_iommu`, which also makes the hardware refuse
//!   every page that is not mapped.
//!
//! Two traits split the work: [`DomainOps`] is the `&mut self` logic a host
//! test drives, [`DmaDomain`] is the `&self` object a driver holds. The
//! kernel makes one from the other with a lock.

use crate::{needs_bounce, AddrRange, Direction, DmaAddr, DmaError};

/// What kind of domain this is, for the boot report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainKind {
    Identity,
    Soft,
    /// A hardware IOMMU domain; the string names the flavour
    /// (`"riscv-iommu"`, `"smmuv3"`, `"vt-d"`, `"amd-vi"`).
    Iommu(&'static str),
}

/// The `&mut self` side: the bookkeeping of one domain.
pub trait DomainOps {
    /// Make `[pa, pa + len)` reachable by the device for `dir` and return the
    /// bus address of its first byte. Contiguous in bus space.
    fn map(&mut self, pa: u64, len: usize, dir: Direction) -> Result<DmaAddr, DmaError>;
    /// Take back a mapping made by `map` (same bus address and length).
    fn unmap(&mut self, bus: DmaAddr, len: usize) -> Result<(), DmaError>;
    /// Are the devices of this domain cache-coherent with the CPU? When not,
    /// the driver brackets every transfer with `cache::sync_for_device` and
    /// `cache::sync_for_cpu`.
    fn coherent(&self) -> bool;
    fn kind(&self) -> DomainKind;
    /// Start enforcing: from now on the device reaches what is mapped and
    /// nothing else. A domain with no hardware behind it has nothing to
    /// start. A driver calls this once its buffers are mapped and before it
    /// starts the device.
    fn enable(&mut self) -> Result<(), DmaError> {
        Ok(())
    }
    /// Let the device write the interrupt doorbell page that contains the
    /// physical address `doorbell` (a message-signalled interrupt is a DMA
    /// write: a translating domain would refuse it as it refuses any page
    /// not mapped). A domain with nothing to refuse has nothing to open.
    fn allow_msi(&mut self, _doorbell: u64) -> Result<(), DmaError> {
        Ok(())
    }
}

/// The `&self` side: what a driver holds for its device.
pub trait DmaDomain: Sync {
    fn map(&self, pa: u64, len: usize, dir: Direction) -> Result<DmaAddr, DmaError>;
    fn unmap(&self, bus: DmaAddr, len: usize) -> Result<(), DmaError>;
    fn coherent(&self) -> bool;
    fn kind(&self) -> DomainKind;
    /// See [`DomainOps::enable`].
    fn enable(&self) -> Result<(), DmaError>;
    /// See [`DomainOps::allow_msi`].
    fn allow_msi(&self, doorbell: u64) -> Result<(), DmaError>;
    /// The highest CPU physical address (inclusive) whose mapping lands at or
    /// below the bus address `bus_limit`: what to allocate under for a device
    /// that reaches `bus_limit`. The bus address is the physical one in every
    /// domain but a translated bus's (`registry::declare_mmio` with an offset).
    fn cpu_limit(&self, bus_limit: u64) -> u64 {
        bus_limit
    }
    /// The CPU physical address behind bus address `bus` in a domain that
    /// remaps nothing but may move the bus (the inverse of what `map` added):
    /// `bus` itself everywhere but a translated bus's. Meaningful only for an
    /// identity or software-checked domain; an IOMMU's bus address names no
    /// physical address by arithmetic.
    fn phys_of(&self, bus: u64) -> u64 {
        bus
    }
}

fn end_of(pa: u64, len: usize) -> Result<u64, DmaError> {
    if len == 0 {
        return Err(DmaError::BadRange);
    }
    pa.checked_add(len as u64).ok_or(DmaError::BadRange)
}

// ---------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------

/// No IOMMU, no checks: bus address = physical address. Stateless, so it is
/// a [`DmaDomain`] by itself, without a lock; it is also the registry's
/// answer for a device nobody installed a domain for.
#[derive(Clone, Copy, Debug)]
pub struct IdentityDomain {
    coherent: bool,
}

impl IdentityDomain {
    pub const fn new(coherent: bool) -> Self {
        IdentityDomain { coherent }
    }
}

impl DomainOps for IdentityDomain {
    fn map(&mut self, pa: u64, len: usize, _dir: Direction) -> Result<DmaAddr, DmaError> {
        end_of(pa, len)?;
        Ok(DmaAddr(pa))
    }
    fn unmap(&mut self, _bus: DmaAddr, len: usize) -> Result<(), DmaError> {
        if len == 0 {
            return Err(DmaError::BadRange);
        }
        Ok(())
    }
    fn coherent(&self) -> bool {
        self.coherent
    }
    fn kind(&self) -> DomainKind {
        DomainKind::Identity
    }
}

impl DmaDomain for IdentityDomain {
    fn map(&self, pa: u64, len: usize, dir: Direction) -> Result<DmaAddr, DmaError> {
        let mut s = *self;
        DomainOps::map(&mut s, pa, len, dir)
    }
    fn unmap(&self, bus: DmaAddr, len: usize) -> Result<(), DmaError> {
        let mut s = *self;
        DomainOps::unmap(&mut s, bus, len)
    }
    fn coherent(&self) -> bool {
        self.coherent
    }
    fn kind(&self) -> DomainKind {
        DomainKind::Identity
    }
    fn enable(&self) -> Result<(), DmaError> {
        Ok(())
    }
    fn allow_msi(&self, _doorbell: u64) -> Result<(), DmaError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Software-checked
// ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct SoftEntry {
    pa: u64,
    len: usize,
}

/// The software-checked domain for a board with no IOMMU (VisionFive 2, K1,
/// a QEMU machine without `-device riscv-iommu-pci`/`intel-iommu`/SMMU, or
/// a device the IOMMU does not sit in front of, such as virtio-mmio).
///
/// `ram` is the memory the kernel may let a device touch, `device` what the
/// device can address. `N` mappings can be live at once.
pub struct SoftState<const N: usize> {
    ram: AddrRange,
    device: AddrRange,
    coherent: bool,
    entries: [Option<SoftEntry>; N],
}

impl<const N: usize> SoftState<N> {
    pub const fn new(ram: AddrRange, device: AddrRange, coherent: bool) -> Self {
        SoftState { ram, device, coherent, entries: [None; N] }
    }
}

impl<const N: usize> DomainOps for SoftState<N> {
    fn map(&mut self, pa: u64, len: usize, _dir: Direction) -> Result<DmaAddr, DmaError> {
        end_of(pa, len)?;
        if !self.ram.contains_range(pa, len as u64) {
            return Err(DmaError::OutsideRam);
        }
        // No IOMMU in this domain: the device either reaches the buffer or
        // it does not.
        if needs_bounce(false, self.device, pa, len as u64) {
            return Err(DmaError::NeedsBounce);
        }
        let slot = self.entries.iter().position(|e| e.is_none()).ok_or(DmaError::TableFull)?;
        self.entries[slot] = Some(SoftEntry { pa, len });
        Ok(DmaAddr(pa))
    }

    fn unmap(&mut self, bus: DmaAddr, len: usize) -> Result<(), DmaError> {
        let slot = self
            .entries
            .iter()
            .position(|e| matches!(e, Some(e) if e.pa == bus.0 && e.len == len))
            .ok_or(DmaError::NotMapped)?;
        self.entries[slot] = None;
        Ok(())
    }

    fn coherent(&self) -> bool {
        self.coherent
    }
    fn kind(&self) -> DomainKind {
        DomainKind::Soft
    }
}
