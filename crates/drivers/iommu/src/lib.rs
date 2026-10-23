// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! IOMMU support: four IOMMU flavours behind one
//! interface.
//!
//! ```text
//!   driver ──map/unmap──▶ IoDomain (one device's page table, `domain`)
//!                              │ builds PTEs (`pgtable`: Sv39/48, LPAE, VT-d SL, AMD-Vi)
//!                              └─flush──▶ UnitHandle ──▶ IommuUnit (`riscv`, `smmuv3`, `vtd`, `amdvi`)
//!                                                          programs device table, queues, faults
//! ```
//!
//! # Scope
//!
//! One translation stage. Per device the unit is told one of three things
//! ([`DomainMode`]): block every access, pass every access through
//! untranslated, or translate through a page table. No ATS, no PASID, no
//! nested translation, no interrupt remapping (MSI goes through untouched:
//! the units are left with interrupt generation off and their fault queues
//! are polled).
//!
//! # What is verified
//!
//! Every register offset, bit position and record layout in this crate was
//! checked against the Linux headers (`drivers/iommu/riscv/iommu-bits.h`,
//! `arm/arm-smmu-v3/arm-smmu-v3.h`, `intel/iommu.h`, `amd/amd_iommu_types.h`)
//! and the QEMU models (`hw/riscv/riscv-iommu*.c`, `hw/arm/smmuv3*.h`,
//! `hw/i386/intel_iommu_internal.h`) when this crate was written, and the
//! encoders are tested against vectors computed by hand from the field
//! positions (`tests/host/iommu-tests`), not from this crate's own
//! constants. What is NOT verified is a real device accepting what the units
//! program: that is the QEMU rows of the gate and the board testing.
#![no_std]

pub mod amdvi;
pub mod domain;
pub mod pgtable;
pub mod riscv;
pub mod smmuv3;
pub mod vtd;

pub use pgtable::{IoPageTable, Perm, PtFormat, PtKind};

/// Page size of the I/O page tables and of every table the units read.
pub const PAGE: u64 = 4096;

/// Where a device's DMA traffic lands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainMode {
    /// Every access is refused (and recorded).
    Block,
    /// Every access passes through untranslated: bus address == physical.
    Bypass,
    /// Translate through the page table whose root is at `root_pa`.
    Translate { root_pa: u64 },
}

/// Which IOMMU a unit is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flavour {
    Riscv,
    Smmuv3,
    Vtd,
    AmdVi,
}

impl Flavour {
    pub const fn name(self) -> &'static str {
        match self {
            Flavour::Riscv => "riscv-iommu",
            Flavour::Smmuv3 => "smmuv3",
            Flavour::Vtd => "vt-d",
            Flavour::AmdVi => "amd-vi",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IommuError {
    /// A table or queue page could not be allocated.
    NoMemory,
    /// The unit lacks something this crate needs (the string says what).
    Unsupported(&'static str),
    /// A register did not reach the state the bring-up waits for.
    Timeout(&'static str),
    /// The device id does not fit the device table the unit was set up with.
    DeviceOutOfRange,
    /// The unit reported an error while executing a command.
    Hardware(&'static str),
}

/// Register access to one unit. The kernel implements it with volatile
/// loads and stores at the unit's mapped base; the tests with a model of
/// the registers.
pub trait Mmio {
    fn read32(&self, off: usize) -> u32;
    fn write32(&self, off: usize, val: u32);
    fn read64(&self, off: usize) -> u64;
    fn write64(&self, off: usize, val: u64);
}

/// Memory the units read: device tables, queues, page tables. All 4 KiB
/// zeroed pages, addressed by physical address; `ptr` is the CPU's pointer to
/// the same bytes (they differ on aarch64 and x86_64).
pub trait TableMem: Sync {
    /// One zeroed page, or `None`.
    fn alloc_page(&self) -> Option<u64>;
    /// `bytes` of zeroed, physically contiguous memory whose address is a
    /// multiple of `align` (a power of two).
    fn alloc_aligned(&self, bytes: usize, align: usize) -> Option<u64>;
    /// The CPU's pointer to physical address `pa`.
    fn ptr(&self, pa: u64) -> *mut u8;
    /// Make CPU stores to `[pa, pa + len)` visible to a unit that does not
    /// snoop the CPU's caches. A no-op for a coherent one.
    fn clean(&self, pa: u64, len: usize);
    /// Drop the CPU's cached copy of `[pa, pa + len)` so the next load reads
    /// what the unit wrote there (a fault or event queue, the AMD-Vi
    /// completion semaphore). A no-op for a coherent one. The range must be
    /// clean in the CPU's cache: the allocator's zeroing leaves dirty lines,
    /// so a structure the unit writes is `clean`ed once before the unit is
    /// enabled and the CPU never stores to it afterwards (otherwise the
    /// write-back would land over the unit's record).
    fn invalidate(&self, pa: u64, len: usize);
}

/// Read the `idx`-th 64-bit word at `pa`.
pub fn rd64(mem: &dyn TableMem, pa: u64, idx: usize) -> u64 {
    // SAFETY: `pa` names memory this crate allocated through `mem`; `idx`
    // stays inside the structure the caller sized.
    unsafe { core::ptr::read_volatile((mem.ptr(pa) as *const u64).add(idx)) }
}

/// Write the `idx`-th 64-bit word at `pa`.
pub fn wr64(mem: &dyn TableMem, pa: u64, idx: usize, val: u64) {
    // SAFETY: as `rd64`.
    unsafe { core::ptr::write_volatile((mem.ptr(pa) as *mut u64).add(idx), val) }
}

/// Spin until `cond` holds, for at most `tries` polls.
pub(crate) fn wait_for(tries: u32, mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..tries {
        if cond() {
            return true;
        }
        core::hint::spin_loop();
    }
    cond()
}

/// Polls a handshake bit waits before it calls the unit dead.
pub(crate) const POLL: u32 = 2_000_000;

/// Translating devices a unit holds at once.
pub(crate) const TAGS: usize = 16;

/// The cache tag of each translating device: the ASID (SMMUv3), PSCID
/// (RISC-V) or domain id (VT-d, AMD-Vi) the unit tags every translation it
/// caches with. A device's domain is its own page table (`domain::IoDomain`),
/// so each translating device gets a tag of its own: a device never hits a
/// translation cached for another one's table, and a flush names one
/// device's tag only. Tags are `first..first + len`; a device keeps its tag
/// while it translates and gives it back when it stops, once the unit has
/// dropped what it cached under it.
pub(crate) struct Tags {
    first: u16,
    len: usize,
    /// The device holding tag `first + i`; `FREE` for none.
    owners: [u32; TAGS],
}

const FREE: u32 = u32::MAX;

impl Tags {
    /// Tags `first..first + len`, at most [`TAGS`] of them.
    pub(crate) const fn new(first: u16, len: usize) -> Self {
        Tags { first, len: if len < TAGS { len } else { TAGS }, owners: [FREE; TAGS] }
    }

    /// The tag device `dev` holds, if it translates.
    pub(crate) fn of(&self, dev: u32) -> Option<u16> {
        self.owners[..self.len].iter().position(|&d| d == dev).map(|i| self.first + i as u16)
    }

    /// The tag of device `dev`, taking a free one when it holds none; `None`
    /// when every tag is held.
    pub(crate) fn take(&mut self, dev: u32) -> Option<u16> {
        if let Some(tag) = self.of(dev) {
            return Some(tag);
        }
        let i = self.owners[..self.len].iter().position(|&d| d == FREE)?;
        self.owners[i] = dev;
        Some(self.first + i as u16)
    }

    /// Device `dev` stopped translating: its tag is free for another device.
    pub(crate) fn release(&mut self, dev: u32) {
        if let Some(d) = self.owners[..self.len].iter_mut().find(|d| **d == dev) {
            *d = FREE;
        }
    }
}

/// A DMA fault, flavour-independent: the durable record the kernel keeps is
/// built from this, not from the unit's raw record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaFault {
    /// PCI requester id of the device.
    pub device_id: u32,
    /// The IOVA that faulted (for a table-structure fault, the address the
    /// access was walking).
    pub fault_addr: u64,
    pub kind: FaultKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind {
    /// The access was blocked by the page table: no translation, or the
    /// translation does not permit the access (VT-d reports a non-present
    /// entry as the missing read/write permission, RISC-V as a page fault).
    UnmappedIova,
    /// The device's table entry is missing, invalid or malformed: a
    /// configuration bug, not a rogue DMA.
    BadDeviceEntry,
    /// Anything the narrow cause map does not name. Recorded rather than
    /// dropped: an unrecognised cause is still evidence the fault path fired.
    Other(u32),
}

/// One IOMMU, whatever the flavour.
pub trait IommuUnit: Send {
    fn flavour(&self) -> Flavour;
    /// The page-table format the unit walks (and how many levels it was set
    /// up for).
    fn pt_format(&self) -> PtFormat;
    /// Put device `dev` (a PCI requester id) in `mode`. Returns once the unit
    /// has executed it.
    fn attach(&mut self, dev: u32, mode: DomainMode) -> Result<(), IommuError>;
    /// Drop whatever the unit cached about device `dev`'s translations. Called
    /// after a mapping went away or lost a permission.
    fn flush(&mut self, dev: u32) -> Result<(), IommuError>;
    /// Hand every pending fault record to `sink`; returns how many.
    fn poll_faults(&mut self, sink: &mut dyn FnMut(DmaFault)) -> usize;
}

/// A unit shared between domains, behind whatever lock the kernel puts on
/// it. The domain calls these without knowing the flavour.
pub trait UnitHandle: Sync {
    fn attach(&self, dev: u32, mode: DomainMode) -> Result<(), IommuError>;
    fn flush(&self, dev: u32) -> Result<(), IommuError>;
    /// See [`IommuUnit::poll_faults`].
    fn poll_faults(&self, sink: &mut dyn FnMut(DmaFault)) -> usize;
}
