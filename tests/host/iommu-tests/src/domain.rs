// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The IO domain: bookkeeping of mappings over the page table, and when it
//! tells the unit to drop cached translations.

use crate::common::{read64, TestMem};
use azos_dma::{Direction, DmaAddr, DmaError, DomainKind, DomainOps};
use azos_iommu::domain::IoDomain;
use azos_iommu::pgtable::{Perm, PtFormat, PtKind};
use azos_iommu::{DomainMode, Flavour, IommuError, UnitHandle};
use std::sync::Mutex;

struct FakeUnit {
    fmt: PtFormat,
    attached: Mutex<Vec<(u32, DomainMode)>>,
    flushes: Mutex<Vec<u32>>,
    fail_flush: Mutex<bool>,
}

impl FakeUnit {
    fn leak(kind: PtKind, levels: u8) -> &'static FakeUnit {
        Box::leak(Box::new(FakeUnit {
            fmt: PtFormat::new(kind, levels),
            attached: Mutex::new(vec![]),
            flushes: Mutex::new(vec![]),
            fail_flush: Mutex::new(false),
        }))
    }
    fn flushed(&self) -> usize {
        self.flushes.lock().unwrap().len()
    }
}

impl UnitHandle for FakeUnit {
    fn attach(&self, dev: u32, mode: DomainMode) -> Result<(), IommuError> {
        self.attached.lock().unwrap().push((dev, mode));
        Ok(())
    }
    fn poll_faults(&self, _sink: &mut dyn FnMut(azos_iommu::DmaFault)) -> usize {
        0
    }
    fn flush(&self, dev: u32) -> Result<(), IommuError> {
        if *self.fail_flush.lock().unwrap() {
            return Err(IommuError::Timeout("fake"));
        }
        self.flushes.lock().unwrap().push(dev);
        Ok(())
    }
}

const RO: Perm = Perm { read: true, write: false };
const WO: Perm = Perm { read: false, write: true };
const RW: Perm = Perm { read: true, write: true };
/// Sv39 cannot express write-only, so the doorbell reads back read-write.
const WO_OR_RW: Perm = RW;

/// What the page table of the domain (its root is the first page the memory
/// handed out) lets the device do at `iova`, read through the format's public
/// accessors and not through the crate's own table walker.
fn walk(mem: &TestMem, fmt: PtFormat, iova: u64) -> Option<(u64, Perm)> {
    let mut table = mem.page(0);
    for level in (0..fmt.levels).rev() {
        let e = read64(table, ((iova >> (12 + 9 * level as u32)) & 0x1ff) as usize);
        if !fmt.is_present(e) {
            return None;
        }
        if level == 0 {
            return Some((fmt.entry_pa(e), fmt.leaf_perm(e)));
        }
        table = fmt.entry_pa(e);
    }
    None
}

fn domain<const N: usize>(unit: &'static FakeUnit, mem: &'static TestMem) -> IoDomain<N> {
    IoDomain::new(0x18, Flavour::Riscv, unit.fmt, unit, mem, true).unwrap()
}

#[test]
fn enable_points_the_device_at_the_tables_root() {
    let (mem, unit) = (TestMem::leak(), FakeUnit::leak(PtKind::RiscvSv, 3));
    let mut d: IoDomain<4> = domain(unit, mem);
    assert!(unit.attached.lock().unwrap().is_empty(), "nothing is attached before enable()");
    d.enable().unwrap();
    assert_eq!(*unit.attached.lock().unwrap(), vec![(0x18, DomainMode::Translate { root_pa: mem.page(0) })]);
    assert_eq!(DomainOps::kind(&d), DomainKind::Iommu("riscv-iommu"));
}

#[test]
fn an_interrupt_doorbell_is_one_writable_page_opened_once() {
    let (mem, unit) = (TestMem::leak(), FakeUnit::leak(PtKind::RiscvSv, 3));
    // One record: a second one would be TableFull.
    let mut d: IoDomain<1> = domain(unit, mem);
    // The IMSIC file of hart 0 on QEMU virt: an MMIO page, not RAM.
    d.allow_msi(0x2800_0010).unwrap();
    assert_eq!(walk(mem, unit.fmt, 0x2800_0000), Some((0x2800_0000, WO_OR_RW)));
    assert_eq!(walk(mem, unit.fmt, 0x2800_1000), None, "only that page");
    // Three vectors, one doorbell: one record.
    d.allow_msi(0x2800_0010).unwrap();
    d.allow_msi(0x2800_0ff8).unwrap();
}

#[test]
fn map_reaches_exactly_the_pages_of_the_buffer_with_the_direction_s_permission() {
    let (mem, unit) = (TestMem::leak(), FakeUnit::leak(PtKind::RiscvSv, 3));
    let mut d: IoDomain<4> = domain(unit, mem);
    // 0x8000_0f00 + 0x300 straddles two pages.
    let bus = d.map(0x8000_0f00, 0x300, Direction::ToDevice).unwrap();
    assert_eq!(bus, DmaAddr(0x8000_0f00), "IOVA == physical");
    assert_eq!(walk(mem, unit.fmt, 0x8000_0000), Some((0x8000_0000, RO)));
    assert_eq!(walk(mem, unit.fmt, 0x8000_1000), Some((0x8000_1000, RO)));
    assert_eq!(walk(mem, unit.fmt, 0x7fff_f000), None, "the page before is not reachable");
    assert_eq!(walk(mem, unit.fmt, 0x8000_2000), None, "nor the page after");
    assert_eq!(unit.flushed(), 1, "one flush for the whole mapping, though it changed two pages");
}

#[test]
fn unmap_removes_the_pages_and_flushes() {
    let (mem, unit) = (TestMem::leak(), FakeUnit::leak(PtKind::Vtd, 4));
    let mut d: IoDomain<4> = domain(unit, mem);
    let bus = d.map(0x8000_0000, 0x2000, Direction::FromDevice).unwrap();
    assert_eq!(walk(mem, unit.fmt, 0x8000_0000), Some((0x8000_0000, WO)));
    d.unmap(bus, 0x2000).unwrap();
    assert_eq!(walk(mem, unit.fmt, 0x8000_0000), None);
    assert_eq!(walk(mem, unit.fmt, 0x8000_1000), None);
    assert_eq!(unit.flushed(), 2, "the mapping and the unmapping");
    assert_eq!(d.unmap(bus, 0x2000), Err(DmaError::NotMapped), "double unmap");
    assert_eq!(unit.flushed(), 2, "a refused unmap flushes nothing");
}

#[test]
fn a_shared_page_stays_until_the_last_mapping_and_takes_the_union_of_permissions() {
    let (mem, unit) = (TestMem::leak(), FakeUnit::leak(PtKind::Vtd, 4));
    let mut d: IoDomain<4> = domain(unit, mem);
    // Two buffers in one page: one the device reads, one it writes.
    let a = d.map(0x8000_0000, 0x100, Direction::ToDevice).unwrap();
    assert_eq!(walk(mem, unit.fmt, 0x8000_0000), Some((0x8000_0000, RO)));
    let b = d.map(0x8000_0800, 0x100, Direction::FromDevice).unwrap();
    assert_eq!(walk(mem, unit.fmt, 0x8000_0000), Some((0x8000_0000, RW)), "union");
    assert_eq!(unit.flushed(), 2, "the permission of a present page changed");
    d.unmap(a, 0x100).unwrap();
    assert_eq!(walk(mem, unit.fmt, 0x8000_0000), Some((0x8000_0000, WO)), "the reader went, the writer stays");
    assert_eq!(unit.flushed(), 3);
    d.unmap(b, 0x100).unwrap();
    assert_eq!(walk(mem, unit.fmt, 0x8000_0000), None);
}

#[test]
fn mapping_the_same_buffer_twice_changes_nothing_the_unit_could_have_cached() {
    let (mem, unit) = (TestMem::leak(), FakeUnit::leak(PtKind::ArmLpae, 4));
    let mut d: IoDomain<2> = domain(unit, mem);
    d.map(0x8000_0000, 0x1000, Direction::Bidirectional).unwrap();
    assert_eq!(unit.flushed(), 1);
    d.map(0x8000_0000, 0x1000, Direction::Bidirectional).unwrap();
    assert_eq!(unit.flushed(), 1, "the entry did not change");
    // Both records are live.
    assert_eq!(d.map(0x8000_4000, 0x1000, Direction::ToDevice), Err(DmaError::TableFull));
}

#[test]
fn a_page_that_was_not_present_is_flushed_when_it_becomes_present() {
    // A unit in caching mode (VT-d CAP.CM, AMD-Vi NpCache) may hold a
    // cached "not present" for the page: every flavour's first mapping of a
    // page, with nothing there before, asks the unit to drop it.
    for (kind, levels) in [(PtKind::Vtd, 4), (PtKind::AmdVi, 4), (PtKind::RiscvSv, 3), (PtKind::ArmLpae, 4)] {
        let (mem, unit) = (TestMem::leak(), FakeUnit::leak(kind, levels));
        let mut d: IoDomain<4> = domain(unit, mem);
        d.map(0x8000_0000, 0x1000, Direction::ToDevice).unwrap();
        assert_eq!(unit.flushed(), 1, "{kind:?}");
        d.map(0x9000_0000, 0x1000, Direction::ToDevice).unwrap();
        assert_eq!(unit.flushed(), 2, "{kind:?} a second fresh page");
    }
}

#[test]
fn table_full_and_bad_ranges_are_reported() {
    let (mem, unit) = (TestMem::leak(), FakeUnit::leak(PtKind::RiscvSv, 3));
    let mut d: IoDomain<2> = domain(unit, mem);
    assert_eq!(d.map(0x8000_0000, 0, Direction::ToDevice), Err(DmaError::BadRange));
    assert_eq!(d.map(u64::MAX - 8, 64, Direction::ToDevice), Err(DmaError::BadRange));
    d.map(0x8000_0000, 8, Direction::ToDevice).unwrap();
    d.map(0x8000_1000, 8, Direction::ToDevice).unwrap();
    assert_eq!(d.map(0x8000_2000, 8, Direction::ToDevice), Err(DmaError::TableFull));
    assert_eq!(walk(mem, unit.fmt, 0x8000_2000), None, "the refused mapping left nothing behind");
}

#[test]
fn an_address_the_table_cannot_cover_is_refused_and_leaves_no_entry() {
    let (mem, unit) = (TestMem::leak(), FakeUnit::leak(PtKind::RiscvSv, 3));
    let mut d: IoDomain<1> = domain(unit, mem);
    assert_eq!(d.map(1 << 40, 0x1000, Direction::ToDevice), Err(DmaError::OutsideRam));
    // The refused mapping kept no record: the only one is free.
    assert_eq!(d.map(0x8000_0000, 0x1000, Direction::ToDevice), Ok(DmaAddr(0x8000_0000)));
}

#[test]
fn running_out_of_table_memory_rolls_the_mapping_back() {
    let (mem, unit) = (TestMem::leak(), FakeUnit::leak(PtKind::RiscvSv, 3));
    // Two records: the failed mapping, if it were kept, would fill the second.
    let mut d: IoDomain<2> = domain(unit, mem);
    d.map(0x8000_0000, 0x1000, Direction::ToDevice).unwrap(); // root + 2 tables
    mem.set_limit(mem.count());
    // A buffer in another 1 GiB region needs new tables.
    assert_eq!(d.map(0xc000_0000, 0x1000, Direction::ToDevice), Err(DmaError::NoMemory));
    assert_eq!(d.map(0x8000_2000, 0x1000, Direction::ToDevice), Ok(DmaAddr(0x8000_2000)), "the failed mapping is not recorded");
    assert_eq!(walk(mem, unit.fmt, 0xc000_0000), None);
    assert_eq!(walk(mem, unit.fmt, 0x8000_0000), Some((0x8000_0000, RO)), "the earlier mapping is intact");
}

#[test]
fn a_unit_that_will_not_flush_fails_the_unmap_loudly() {
    let (mem, unit) = (TestMem::leak(), FakeUnit::leak(PtKind::RiscvSv, 3));
    let mut d: IoDomain<2> = domain(unit, mem);
    let bus = d.map(0x8000_0000, 0x1000, Direction::ToDevice).unwrap();
    *unit.fail_flush.lock().unwrap() = true;
    assert_eq!(d.unmap(bus, 0x1000), Err(DmaError::Iommu));
}

#[test]
fn a_flush_is_due_when_any_page_changed_not_only_the_last() {
    let (mem, unit) = (TestMem::leak(), FakeUnit::leak(PtKind::Vtd, 4));
    let mut d: IoDomain<4> = domain(unit, mem);
    // X covers two pages, Y re-covers the second with the same permission.
    let x = d.map(0x8000_0000, 0x2000, Direction::ToDevice).unwrap();
    d.map(0x8000_1000, 0x1000, Direction::ToDevice).unwrap();
    assert_eq!(unit.flushed(), 1, "only the first mapping changed anything");
    // Dropping X removes the first page and leaves the second as it was.
    d.unmap(x, 0x2000).unwrap();
    assert_eq!(walk(mem, unit.fmt, 0x8000_0000), None);
    assert_eq!(walk(mem, unit.fmt, 0x8000_1000), Some((0x8000_1000, RO)));
    assert_eq!(unit.flushed(), 2, "the first page's translation went away");
}
