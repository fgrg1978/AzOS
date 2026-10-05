// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![cfg(test)]

use azos_dma::*;

/// Identity-with-offset translator: VA = PA + OFFSET. Enough to prove the
/// mapping table calls through `AddrTranslate` rather than hardcoding
/// identity, without needing a real MMU.
struct FakeXlate {
    offset: usize,
}

impl AddrTranslate for FakeXlate {
    fn virt_to_phys(&self, va: usize) -> usize {
        va - self.offset
    }
    fn phys_to_virt(&self, pa: usize) -> usize {
        pa + self.offset
    }
}

// -----------------------------------------------------------------------
// map_single / unmap_single
// -----------------------------------------------------------------------

#[test]
fn map_single_returns_physical_address_via_translate() {
    let xlate = FakeXlate { offset: 0xffff_0000 };
    let mut table: DmaMapTable<4> = DmaMapTable::new();

    let (bus, _handle) = table.map_single(&xlate, 0xffff_1000, 0x1000, Direction::ToDevice).unwrap();
    assert_eq!(bus, DmaAddr(0x1000));
    assert_eq!(table.active_count(), 1);
}

#[test]
fn unmap_then_unmap_again_is_rejected() {
    let xlate = FakeXlate { offset: 0 };
    let mut table: DmaMapTable<4> = DmaMapTable::new();

    let (_bus, handle) = table.map_single(&xlate, 0x2000, 0x100, Direction::FromDevice).unwrap();
    assert_eq!(table.active_count(), 1);

    table.unmap_single(handle).expect("first unmap must succeed");
    assert_eq!(table.active_count(), 0);

    let err = table.unmap_single(handle).expect_err("double-unmap must be rejected, not silently accepted");
    assert_eq!(err, DmaError::NotMapped);
}

#[test]
fn map_single_table_full_is_reported_not_panicked() {
    let xlate = FakeXlate { offset: 0 };
    let mut table: DmaMapTable<2> = DmaMapTable::new();

    table.map_single(&xlate, 0x1000, 0x10, Direction::ToDevice).unwrap();
    table.map_single(&xlate, 0x2000, 0x10, Direction::ToDevice).unwrap();

    let err = table.map_single(&xlate, 0x3000, 0x10, Direction::ToDevice).unwrap_err();
    assert_eq!(err, DmaError::TableFull);
}

#[test]
fn lookup_and_bus_addr_reflect_the_active_mapping() {
    let xlate = FakeXlate { offset: 0 };
    let mut table: DmaMapTable<4> = DmaMapTable::new();

    let (bus, handle) = table.map_single(&xlate, 0x3000, 0x40, Direction::Bidirectional).unwrap();
    let (va, len, dir) = table.lookup(handle).unwrap();
    assert_eq!(va, 0x3000);
    assert_eq!(len, 0x40);
    assert_eq!(dir, Direction::Bidirectional);
    assert_eq!(table.bus_addr(handle).unwrap(), bus);

    table.unmap_single(handle).unwrap();
    assert_eq!(table.lookup(handle).unwrap_err(), DmaError::NotMapped);
}

#[test]
fn freed_slot_can_be_reused() {
    let xlate = FakeXlate { offset: 0 };
    let mut table: DmaMapTable<1> = DmaMapTable::new();

    let (_b1, h1) = table.map_single(&xlate, 0x1000, 0x10, Direction::ToDevice).unwrap();
    table.unmap_single(h1).unwrap();

    // Table was full (capacity 1); freeing must make room again.
    let (b2, _h2) = table.map_single(&xlate, 0x2000, 0x10, Direction::ToDevice).unwrap();
    assert_eq!(b2, DmaAddr(0x2000));
}

// -----------------------------------------------------------------------
// Coherent pool
// -----------------------------------------------------------------------

#[test]
fn pool_alloc_free_roundtrip_and_exhaustion() {
    let mut pool: CoherentPool<2> = CoherentPool::new(0x8000_0000, 0x4000_0000, 0x1000);
    assert_eq!(pool.free_count(), 2);

    let (va0, pa0, h0) = pool.alloc().unwrap();
    assert_eq!(va0, 0x4000_0000);
    assert_eq!(pa0, DmaAddr(0x8000_0000));

    let (va1, pa1, _h1) = pool.alloc().unwrap();
    assert_eq!(va1, 0x4000_1000);
    assert_eq!(pa1, DmaAddr(0x8000_1000));

    assert_eq!(pool.free_count(), 0);
    let err = pool.alloc().unwrap_err();
    assert_eq!(err, DmaError::PoolExhausted);

    pool.free(h0).unwrap();
    assert_eq!(pool.free_count(), 1);
}

#[test]
fn pool_double_free_is_rejected() {
    let mut pool: CoherentPool<1> = CoherentPool::new(0, 0, 0x1000);
    let (_va, _pa, h) = pool.alloc().unwrap();
    pool.free(h).expect("first free must succeed");
    let err = pool.free(h).expect_err("double-free must be rejected, not silently accepted");
    assert_eq!(err, DmaError::DoubleFree);
}

// -----------------------------------------------------------------------
// Bounce-buffer decision — truth table from RFC-0046 §2.3
// -----------------------------------------------------------------------

#[test]
fn iommu_on_never_bounces_regardless_of_address() {
    let narrow = AddrRange::new(0, 0x1000); // deliberately too small to fit
    assert!(!needs_bounce(true, narrow, 0x1_0000_0000, 0x1000));
}

#[test]
fn iommu_off_bounces_only_when_buffer_does_not_fit_device_range() {
    let range_32bit = AddrRange::new(0, 0x1_0000_0000); // classic 32-bit-only device

    // Fits entirely below 4 GiB -> no bounce.
    assert!(!needs_bounce(false, range_32bit, 0x1000_0000, 0x1000));

    // Starts below 4 GiB but extends past it -> must bounce.
    assert!(needs_bounce(false, range_32bit, 0xffff_f000, 0x2000));

    // Entirely above 4 GiB -> must bounce.
    assert!(needs_bounce(false, range_32bit, 0x2_0000_0000, 0x1000));
}

#[test]
fn addr_range_contains_range_does_not_overflow_near_u64_max() {
    let range = AddrRange::new(0, u64::MAX);
    // addr + len would overflow without the saturating add; the range
    // covers everything, so this must report "fits", not silently wrap
    // to a small number and report "fits" for the wrong reason.
    assert!(range.contains_range(u64::MAX - 10, 5));
    assert!(!range.contains_range(u64::MAX - 3, 10));
}
