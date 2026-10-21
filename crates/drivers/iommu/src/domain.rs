// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The IOMMU domain of one device: its I/O page table and the mappings in it.
//!
//! IOVA == physical address. The page table holds exactly the pages a
//! driver mapped, with the permission its transfer direction needs, so the
//! device cannot reach any other page, and a driver can keep using the
//! physical addresses it already has. A page shared by two mappings is
//! mapped for the union of their permissions and stays until the last one
//! goes.
//!
//! The granularity is the page, as the hardware's: a buffer that shares a
//! page with other data (a driver's `static` state) leaves that data
//! reachable by the device. Page-aligning the buffers closes it; the virtio
//! drivers align what a non-coherent device needs aligned, not more.

use azos_dma::{DmaAddr, DmaError, Direction, DomainKind, DomainOps};

use crate::pgtable::{IoPageTable, Perm, PtError, PtFormat};
use crate::{DomainMode, Flavour, TableMem, UnitHandle, PAGE};

#[derive(Clone, Copy, Debug)]
struct Entry {
    /// First byte and length as the driver gave them.
    pa: u64,
    len: usize,
    perm: Perm,
}

impl Entry {
    fn first_page(&self) -> u64 {
        self.pa & !(PAGE - 1)
    }
    fn last_page(&self) -> u64 {
        (self.pa + self.len as u64 - 1) & !(PAGE - 1)
    }
    fn covers(&self, page: u64) -> bool {
        page >= self.first_page() && page <= self.last_page()
    }
}

/// One device's translation domain with room for `N` live mappings.
pub struct IoDomain<const N: usize> {
    dev: u32,
    flavour: Flavour,
    unit: &'static dyn UnitHandle,
    mem: &'static dyn TableMem,
    pt: IoPageTable,
    coherent: bool,
    entries: [Option<Entry>; N],
}

fn pt_err(e: PtError) -> DmaError {
    match e {
        PtError::NoMemory => DmaError::NoMemory,
        PtError::OutOfRange => DmaError::OutsideRam,
        PtError::Corrupt => DmaError::Iommu,
    }
}

impl<const N: usize> IoDomain<N> {
    /// An empty domain for requester id `dev`. It translates nothing, and
    /// the unit does not know it, until `enable`.
    ///
    /// `fmt` is the page-table format the unit walks (`IommuUnit::pt_format`).
    pub fn new(
        dev: u32,
        flavour: Flavour,
        fmt: PtFormat,
        unit: &'static dyn UnitHandle,
        mem: &'static dyn TableMem,
        coherent: bool,
    ) -> Result<Self, DmaError> {
        let pt = IoPageTable::new(fmt, mem).map_err(pt_err)?;
        Ok(IoDomain { dev, flavour, unit, mem, pt, coherent, entries: [None; N] })
    }

    /// Make the table agree with `entries` for pages `first..=last`: each
    /// page gets the union of the permissions of the entries covering it, or
    /// is unmapped when none does. Returns whether any entry changed: the unit
    /// may hold a stale translation, or (caching mode on VT-d, `NpCache` on
    /// AMD-Vi) a cached "not present" for a page that is mapped now.
    fn sync_pages(&mut self, first: u64, last: u64) -> Result<bool, DmaError> {
        let mut changed = false;
        let mut page = first;
        loop {
            let perm = self
                .entries
                .iter()
                .flatten()
                .filter(|e| e.covers(page))
                .fold(Perm::NONE, |acc, e| acc.union(e.perm));
            changed |= if perm.is_none() {
                self.pt.unmap_page(self.mem, page).map_err(pt_err)?
            } else {
                self.pt.map_page(self.mem, page, page, perm).map_err(pt_err)?
            };
            if page == last {
                return Ok(changed);
            }
            page += PAGE;
        }
    }

    fn flush(&self) -> Result<(), DmaError> {
        self.unit.flush(self.dev).map_err(|_| DmaError::Iommu)
    }
}

impl<const N: usize> DomainOps for IoDomain<N> {
    fn map(&mut self, pa: u64, len: usize, dir: Direction) -> Result<DmaAddr, DmaError> {
        if len == 0 {
            return Err(DmaError::BadRange);
        }
        pa.checked_add(len as u64).ok_or(DmaError::BadRange)?;
        let slot = self.entries.iter().position(|e| e.is_none()).ok_or(DmaError::TableFull)?;
        let entry = Entry { pa, len, perm: Perm::of(dir) };
        self.entries[slot] = Some(entry);
        match self.sync_pages(entry.first_page(), entry.last_page()) {
            Ok(changed) => {
                if changed {
                    self.flush()?;
                }
                Ok(DmaAddr(pa))
            }
            Err(e) => {
                // Put the table back the way the other mappings want it.
                self.entries[slot] = None;
                let _ = self.sync_pages(entry.first_page(), entry.last_page());
                Err(e)
            }
        }
    }

    fn unmap(&mut self, bus: DmaAddr, len: usize) -> Result<(), DmaError> {
        let slot = self
            .entries
            .iter()
            .position(|e| matches!(e, Some(e) if e.pa == bus.0 && e.len == len))
            .ok_or(DmaError::NotMapped)?;
        let entry = self.entries[slot].take().unwrap();
        if self.sync_pages(entry.first_page(), entry.last_page())? {
            self.flush()?;
        }
        Ok(())
    }

    fn coherent(&self) -> bool {
        self.coherent
    }

    fn kind(&self) -> DomainKind {
        DomainKind::Iommu(self.flavour.name())
    }

    /// Point the device at this domain's page table. Until now it was in
    /// whatever mode the unit had it (bypass, from the boot's sweep over
    /// every function).
    fn allow_msi(&mut self, doorbell: u64) -> Result<(), DmaError> {
        let page = doorbell & !(PAGE - 1);
        if self.entries.iter().flatten().any(|e| e.pa == page && e.len == PAGE as usize) {
            return Ok(());
        }
        // The device WRITES the doorbell.
        self.map(page, PAGE as usize, Direction::FromDevice).map(|_| ())
    }

    fn enable(&mut self) -> Result<(), DmaError> {
        self.unit
            .attach(self.dev, DomainMode::Translate { root_pa: self.pt.root_pa() })
            .map_err(|_| DmaError::Iommu)
    }
}
