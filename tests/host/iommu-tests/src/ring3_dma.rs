// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The memory a ring-3 driver's device reaches (`azos_dma::bind`) behind an
//! IOMMU domain: the object's pages and no other, and a binding that ends
//! takes them out of the table and flushes the unit before the kernel's
//! reference on the object, after which its frames may be freed, goes.

use crate::common::TestMem;
use crate::domain::{walk, FakeUnit};
use azos_dma::bind::{self, Binding, BindError, Table};
use azos_dma::IdentityDomain;
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
fn ring3_domain() -> (&'static TestMem, &'static FakeUnit, &'static Locked) {
    let (mem, unit) = (TestMem::leak(), FakeUnit::leak(PtKind::RiscvSv, 3));
    let d: &'static Locked =
        Box::leak(Box::new(Locked(Mutex::new(IoDomain::new(0x20, Flavour::Riscv, unit.fmt, unit, mem, true).unwrap()))));
    d.enable().unwrap();
    assert_eq!(unit.attached.lock().unwrap()[0], (0x20, DomainMode::Translate { root_pa: mem.page(0) }));
    (mem, unit, d)
}

static NO_IOMMU: IdentityDomain = IdentityDomain::new(true);

/// A two-page object at `pa`, of thread 7 of process 7.
fn object(pa: u64) -> Binding {
    Binding { owner: 7, group: 7, dev: 3, obj: 0x101, pa, len: 2 * PAGE as usize, bus: DmaAddr(0), domain: &NO_IOMMU }
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
    b.bus = bind::map(d, b.pa, b.len, Direction::Bidirectional).unwrap();
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
    let mut b = Binding { domain: d, ..object(0x8020_0000) };
    b.bus = bind::map(d, b.pa, b.len, Direction::FromDevice).unwrap();
    let flushes = unit.flushed();
    let mut seen = None;
    bind::release(&b, |obj| {
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
    let mut b = Binding { domain: d, ..object(0x8030_0000) };
    b.bus = bind::map(d, b.pa, b.len, Direction::ToDevice).unwrap();
    *unit.fail_flush.lock().unwrap() = true;
    let kept = azos_dma::leaked_bytes();
    let mut dropped = false;
    assert_eq!(bind::release(&b, |_| dropped = true), Err(DmaError::Iommu));
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
    let mut t: Table<8> = Table::new();
    let a = object(0x8040_0000);
    let b = Binding { owner: 9, group: 9, obj: 0x102, ..object(0x8050_0000) };
    t.insert(a).unwrap();
    assert_eq!(t.insert(Binding { dev: 4, ..a }), Err(BindError::Busy), "an object bound to a second device");
    assert_eq!(t.can_insert(a.group, 4, a.obj), Err(BindError::Busy));
    t.insert(b).unwrap();
    t.insert(Binding { obj: 0x103, ..b }).unwrap();
    for (owner, obj) in [(20u32, 0x110u32), (21, 0x111), (22, 0x112), (23, 0x113), (24, 0x114)] {
        t.insert(Binding { owner, group: owner, obj, ..a }).unwrap();
    }
    assert_eq!(t.insert(Binding { owner: 25, group: 25, obj: 0x115, ..a }), Err(BindError::Full));
    assert_eq!(t.take(b.owner, a.dev, a.obj), None, "another task ended the binding");
    let ta = t.take(a.owner, a.dev, a.obj).expect("the owner's take");
    assert_eq!(ta.binding, a);
    t.finish(ta, false);
    let mut drained = 0;
    while let Some(tb) = t.take_owned(b.owner) {
        t.finish(tb, false);
        drained += 1;
    }
    assert_eq!(drained, 2);
    assert_eq!(t.len(), 5, "the others' bindings stay");
}

/// **A function's earlier domain (a kernel driver's, unbound) is handed to
/// ring 3 only empty.** The kernel hands out a pool slot again only when
/// `is_empty` says no mapping is left in it: one the kernel driver did not
/// take back stays reachable by a device ring 3 then programs.
///
/// **Canary.** `domain-empty-canary` (`is_empty` always true): the domain
/// with a mapping left reads as empty.
#[test]
fn a_domain_with_a_mapping_left_is_not_handed_to_ring_3() {
    let (_mem, _unit, d) = ring3_domain();
    assert!(d.0.lock().unwrap().is_empty(), "a fresh domain");
    let bus = d.map(0x8060_0000, PAGE as usize, Direction::ToDevice).unwrap();
    assert!(!d.0.lock().unwrap().is_empty(), "a domain with a mapping left reads as empty");
    d.unmap(bus, PAGE as usize).unwrap();
    assert!(d.0.lock().unwrap().is_empty(), "and empty again once it is taken back");
}

/// **A kernel unmap whose flush failed leaves the domain not empty:** the
/// unit may still hold the translation the table dropped, so the domain is
/// never handed to ring 3 again.
///
/// **Canary.** `domain-stale-canary`: the domain reads empty after the
/// failed flush.
#[test]
fn a_failed_flush_leaves_the_domain_not_empty() {
    let (_mem, unit, d) = ring3_domain();
    let bus = d.map(0x8068_0000, PAGE as usize, Direction::ToDevice).unwrap();
    *unit.fail_flush.lock().unwrap() = true;
    assert_eq!(d.unmap(bus, PAGE as usize), Err(DmaError::Iommu));
    assert!(!d.0.lock().unwrap().is_empty(), "a domain whose flush failed reads as empty");
}

/// **The kernel's reuse rule: a domain ring 3 holds live bindings in is
/// handed to its second map; any other only translating and empty.**
///
/// **Canary.** `ring3-reuse-canary` (empty only): the second map of a live
/// device is refused.
#[test]
fn ring_3_gets_its_own_live_domain_again_and_another_only_empty() {
    use azos_dma::bind::reuse_for_ring3;
    assert!(reuse_for_ring3(true, false, true), "ring 3's own domain, its bindings live");
    assert!(reuse_for_ring3(true, true, false), "an empty translating domain");
    assert!(!reuse_for_ring3(true, false, false), "a kernel driver's with a mapping left");
    assert!(!reuse_for_ring3(false, true, true), "one that does not translate");
}

/// **A device whose binding is parked gets no new one, the park cannot fail
/// though the table filled during the end, and a process holds at most its
/// share whatever its threads.** A crash loop of a driver whose device
/// cannot be stopped keeps one object's pages, not one per restart.
///
/// **Canaries.** Drop the `Parked` test in `Table::can_insert`, or
/// `park-drop-canary` (the end frees the record): the restarted driver binds
/// again.
#[test]
fn a_parked_device_takes_no_new_binding_and_a_process_has_a_share() {
    let mut t: Table<8> = Table::new();
    let a = object(0x8070_0000);
    t.insert(a).unwrap();
    let ending = t.take_owned(a.owner).unwrap();
    // Others fill the table while the end runs outside its lock.
    for g in 0..7u32 {
        t.insert(Binding { owner: 100 + g, group: 100 + g, dev: 50 + g, obj: 0x400 + g, ..a }).unwrap();
    }
    t.finish(ending, true);
    assert!(t.take_owned(a.owner).is_none(), "a parked binding ends for nobody");
    let mut t2: Table<8> = Table::new();
    let restarted = Binding { owner: 8, group: 8, obj: 0x200, ..a };
    t2.insert(a).unwrap();
    let e = t2.take_owned(a.owner).unwrap();
    t2.finish(e, true);
    assert_eq!(t2.insert(restarted), Err(BindError::Parked), "the device of a parked binding took a new one");
    assert_eq!(t.can_insert(8, a.dev, 0x201), Err(BindError::Parked), "the park was lost when the table filled");
    assert_eq!(Table::<8>::PER_PROCESS, 2);
    for (i, owner) in [9u32, 10].into_iter().enumerate() {
        t2.insert(Binding { owner, group: 9, dev: 10 + i as u32, obj: 0x300 + i as u32, ..a }).unwrap();
    }
    assert_eq!(
        t2.insert(Binding { owner: 11, group: 9, dev: 20, obj: 0x302, ..a }),
        Err(BindError::Quota),
        "a third thread of the process past its share"
    );
}
