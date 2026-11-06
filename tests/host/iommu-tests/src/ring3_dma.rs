// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The memory a ring-3 driver's device reaches (`azos_dma::bind`) behind an
//! IOMMU domain: the object's pages and no other, and a binding that ends
//! takes them out of the table and flushes the unit before the kernel's
//! reference on the object, after which its frames may be freed, goes.

use crate::common::TestMem;
use crate::domain::{walk, FakeUnit};
use azos_dma::bind::{self, Binding, BindError, Table};
use azos_dma::{Direction, DmaAddr, DmaDomain, DmaError, DomainKind, DomainOps};
use azos_iommu::domain::IoDomain;
use azos_iommu::pgtable::PtKind;
use azos_iommu::{DomainMode, Flavour};
use std::sync::Mutex;

const PAGE: u64 = 0x1000;

/// The kernel's `&self` face of a domain: the `&mut self` logic behind a lock.
struct Locked(Mutex<IoDomain<8>>);

impl DmaDomain for Locked {
    fn map(&self, pa: u64, len: usize, dir: Direction) -> Result<DmaAddr, DmaError> {
        self.0.lock().unwrap().map(pa, len, dir)
    }
    fn unmap(&self, bus: DmaAddr, len: usize) -> Result<(), DmaError> {
        self.0.lock().unwrap().unmap(bus, len)
    }
    fn coherent(&self) -> bool {
        true
    }
    fn kind(&self) -> DomainKind {
        DomainOps::kind(&*self.0.lock().unwrap())
    }
    fn enable(&self) -> Result<(), DmaError> {
        self.0.lock().unwrap().enable()
    }
    fn allow_msi(&self, doorbell: u64) -> Result<(), DmaError> {
        self.0.lock().unwrap().allow_msi(doorbell)
    }
}

/// A ring-3 function's domain as the kernel hands it out: translating, its
/// table empty.
fn ring3_domain() -> (&'static TestMem, &'static FakeUnit, Locked) {
    let (mem, unit) = (TestMem::leak(), FakeUnit::leak(PtKind::RiscvSv, 3));
    let d = Locked(Mutex::new(IoDomain::new(0x20, Flavour::Riscv, unit.fmt, unit, mem, true).unwrap()));
    d.enable().unwrap();
    assert_eq!(unit.attached.lock().unwrap()[0], (0x20, DomainMode::Translate { root_pa: mem.page(0) }));
    (mem, unit, d)
}

/// A two-page object at `pa`.
fn object(pa: u64) -> Binding {
    Binding { owner: 7, dev: 3, obj: 0x101, pa, len: 2 * PAGE as usize, bus: DmaAddr(0) }
}

/// **The device reaches the object it was given, read and write, and no page
/// beside it.** Before the map nothing is reachable; after it the object's
/// two pages are, and the page before, the page after and any other RAM are
/// not: an access there finds no translation and the unit faults it.
///
/// **Canary.** `dma-bind-skip-map-canary` (`bind::map` records the object
/// without putting it in the domain): the object's own pages read as
/// unreachable, so the device's first read of it faults.
#[test]
fn a_device_reaches_its_object_and_no_other_page() {
    let (mem, unit, d) = ring3_domain();
    let mut b = object(0x8010_0000);
    assert_eq!(walk(mem, unit.fmt, b.pa), None, "an empty domain reaches nothing");
    b.bus = bind::map(&d, b.pa, b.len, Direction::Bidirectional).unwrap();
    assert_eq!(b.bus, DmaAddr(b.pa));
    for page in [b.bus.0, b.bus.0 + PAGE] {
        let (pa, perm) = walk(mem, unit.fmt, page).expect("a page of the object is not reachable: the device read faults");
        assert_eq!(pa, page);
        assert!(perm.read && perm.write, "bidirectional");
    }
    for outside in [b.bus.0 - PAGE, b.bus.0 + 2 * PAGE, 0x8000_0000, 0x9000_0000] {
        assert_eq!(walk(mem, unit.fmt, outside), None, "{outside:#x} outside the object is reachable");
    }
}

/// **A binding ends with the object out of the table and the unit flushed
/// before the kernel's reference goes.** When `drop_ref` runs (the frames may
/// be freed right after it) the device can no longer translate any page of the
/// object, and the unit has been told to drop what it cached.
///
/// **Canary.** Call `drop_ref` before the domain's unmap in `bind::release`:
/// the reference goes while the pages are still mapped.
#[test]
fn a_binding_ends_unmapped_and_flushed_before_its_frames_go() {
    let (mem, unit, d) = ring3_domain();
    let mut b = object(0x8020_0000);
    b.bus = bind::map(&d, b.pa, b.len, Direction::FromDevice).unwrap();
    let flushes = unit.flushed();
    let mut seen = None;
    bind::release(&d, &b, |obj| {
        let reachable = [b.bus.0, b.bus.0 + PAGE].iter().any(|&p| walk(mem, unit.fmt, p).is_some());
        seen = Some((obj, reachable, unit.flushed()));
    })
    .unwrap();
    let (obj, reachable, flushed) = seen.expect("the reference was not given back");
    assert_eq!(obj, b.obj);
    assert!(!reachable, "the frames' reference went while the device could still reach them");
    assert!(flushed > flushes, "the reference went before the unit dropped its cached translations");
}

/// **An unmap that failed keeps the frames.** The unit did not confirm the
/// flush, so the device may still hold a translation: the reference is not
/// given back and the object's bytes are counted as kept from the allocator.
///
/// **Canary.** `azos_dma::canary_free_anyway(true)`: the reference goes.
#[test]
fn a_failed_flush_keeps_the_frames() {
    let (_mem, unit, d) = ring3_domain();
    let mut b = object(0x8030_0000);
    b.bus = bind::map(&d, b.pa, b.len, Direction::ToDevice).unwrap();
    *unit.fail_flush.lock().unwrap() = true;
    let kept = azos_dma::leaked_bytes();
    let mut dropped = false;
    assert_eq!(bind::release(&d, &b, |_| dropped = true), Err(DmaError::Iommu));
    assert!(!dropped, "the frames' reference went though the unit may still translate them");
    assert!(azos_dma::leaked_bytes() >= kept + b.len as u64, "the kept bytes were not counted");
}

/// **One binding per object, and a binding is ended only by the task that
/// made it.** The exit path drains a task's bindings one at a time and leaves
/// the others'.
///
/// **Canary.** Drop the `owner` match in `Table::take`: another task ends the
/// first one's binding.
#[test]
fn the_table_keeps_one_binding_per_object_and_its_owner() {
    let mut t: Table<3> = Table::new();
    let a = object(0x8040_0000);
    let b = Binding { owner: 9, obj: 0x102, ..object(0x8050_0000) };
    t.insert(a).unwrap();
    assert_eq!(t.insert(Binding { dev: 4, ..a }), Err(BindError::Busy), "an object bound to a second device");
    assert_eq!(t.can_insert(a.obj), Err(BindError::Busy));
    t.insert(b).unwrap();
    t.insert(Binding { obj: 0x103, ..b }).unwrap();
    assert_eq!(t.insert(Binding { obj: 0x104, ..b }), Err(BindError::Full));
    assert_eq!(t.take(b.owner, a.dev, a.obj), None, "another task ended the binding");
    assert_eq!(t.take(a.owner, a.dev, a.obj), Some(a));
    let mut drained = 0;
    while t.take_owned(b.owner).is_some() {
        drained += 1;
    }
    assert_eq!(drained, 2);
    assert!(t.is_empty());
}
