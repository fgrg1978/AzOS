// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The radix tree, walked by hand through raw memory.

use crate::common::{read64, TestMem};
use azos_iommu::pgtable::{IoPageTable, Perm, PtError, PtFormat, PtKind};
use azos_iommu::TableMem;

const RW: Perm = Perm { read: true, write: true };
const RO: Perm = Perm { read: true, write: false };

fn all_formats() -> [PtFormat; 5] {
    [
        PtFormat::new(PtKind::RiscvSv, 3),
        PtFormat::new(PtKind::RiscvSv, 4),
        PtFormat::new(PtKind::ArmLpae, 4),
        PtFormat::new(PtKind::Vtd, 3),
        PtFormat::new(PtKind::AmdVi, 4),
    ]
}

#[test]
fn a_mapping_is_laid_out_level_by_level() {
    // Sv39, IOVA 0x8000_1000: VPN[2] = (iova >> 30) & 0x1ff = 2,
    // VPN[1] = (iova >> 21) & 0x1ff = 0, VPN[0] = (iova >> 12) & 0x1ff = 1.
    let mem = TestMem::leak();
    let f = PtFormat::new(PtKind::RiscvSv, 3);
    let mut pt = IoPageTable::new(f, mem).unwrap();
    assert_eq!(pt.map_page(mem, 0x8000_1000, 0x8000_1000, RW), Ok(true));
    let (root, l1, l0) = (mem.page(0), mem.page(1), mem.page(2));
    assert_eq!(pt.root_pa(), root);
    assert_eq!(read64(root, 2), ((l1 >> 12) << 10) | 1, "root[2] -> the level-1 table");
    assert_eq!(read64(l1, 0), ((l0 >> 12) << 10) | 1, "level-1[0] -> the leaf table");
    assert_eq!(read64(l0, 1), 0x2000_04D7, "leaf[1]");
    assert_eq!(mem.count(), 3);
    // A neighbour in the same leaf table adds no table.
    pt.map_page(mem, 0x8000_2000, 0x8000_2000, RO).unwrap();
    assert_eq!(mem.count(), 3);
    assert_eq!(read64(l0, 2), 0x2000_0800 | 0xD3);
}

#[test]
fn lookup_unmap_and_remap_for_every_format() {
    for f in all_formats() {
        let mem = TestMem::leak();
        let mut pt = IoPageTable::new(f, mem).unwrap();
        let iova = 0x8765_4000;
        assert_eq!(pt.lookup(mem, iova), None, "{f:?} empty");
        // A page that was not present changes too: a unit in caching mode
        // may hold the "not present".
        assert_eq!(pt.map_page(mem, iova, iova, RO), Ok(true), "{f:?}");
        assert_eq!(pt.lookup(mem, iova), Some((iova, RO)), "{f:?}");
        // The same entry again is not a change.
        assert_eq!(pt.map_page(mem, iova, iova, RO), Ok(false));
        // A different permission replaces a present translation.
        assert_eq!(pt.map_page(mem, iova, iova, RW), Ok(true), "{f:?}");
        assert_eq!(pt.lookup(mem, iova), Some((iova, RW)));
        // Another page elsewhere is untouched by the unmap.
        pt.map_page(mem, 0x1000, 0x1000, RW).unwrap();
        assert_eq!(pt.unmap_page(mem, iova), Ok(true));
        assert_eq!(pt.lookup(mem, iova), None, "{f:?} after unmap");
        assert_eq!(pt.unmap_page(mem, iova), Ok(false), "second unmap");
        assert_eq!(pt.lookup(mem, 0x1000), Some((0x1000, RW)));
        // An address under an absent upper table unmaps to nothing.
        assert_eq!(pt.unmap_page(mem, 0x2000_0000), Ok(false));
    }
}

#[test]
fn iova_range_follows_the_levels() {
    let mem = TestMem::leak();
    // Sv39 takes the positive half only: below 2^38.
    let mut sv39 = IoPageTable::new(PtFormat::new(PtKind::RiscvSv, 3), mem).unwrap();
    assert!(sv39.map_page(mem, (1 << 38) - 0x1000, 0x1000, RW).is_ok());
    assert_eq!(sv39.map_page(mem, 1 << 38, 0x1000, RW), Err(PtError::OutOfRange));
    // Arm 4 levels: 48 bits.
    let mut arm = IoPageTable::new(PtFormat::new(PtKind::ArmLpae, 4), mem).unwrap();
    assert!(arm.map_page(mem, (1 << 48) - 0x1000, 0x1000, RW).is_ok());
    assert_eq!(arm.map_page(mem, 1 << 48, 0x1000, RW), Err(PtError::OutOfRange));
    // VT-d 3 levels: 39 bits.
    let mut vtd = IoPageTable::new(PtFormat::new(PtKind::Vtd, 3), mem).unwrap();
    assert!(vtd.map_page(mem, (1 << 39) - 0x1000, 0x1000, RW).is_ok());
    assert_eq!(vtd.map_page(mem, 1 << 39, 0x1000, RW), Err(PtError::OutOfRange));
    // A format with a level count the kind does not have is refused.
    assert!(IoPageTable::new(PtFormat::new(PtKind::ArmLpae, 5), mem).is_err());
    assert!(IoPageTable::new(PtFormat::new(PtKind::AmdVi, 2), mem).is_err());
}

#[test]
fn running_out_of_pages_leaves_no_half_linked_table() {
    let mem = TestMem::leak();
    let f = PtFormat::new(PtKind::RiscvSv, 3);
    let mut pt = IoPageTable::new(f, mem).unwrap();
    mem.set_limit(2); // the root and one more
    assert_eq!(pt.map_page(mem, 0x8000_1000, 0x8000_1000, RW), Err(PtError::NoMemory));
    // The level-1 table was linked (its page exists and is empty); the leaf
    // table was not, so a lookup finds nothing rather than a bad pointer.
    assert_eq!(pt.lookup(mem, 0x8000_1000), None);
    mem.set_limit(usize::MAX);
    assert_eq!(pt.map_page(mem, 0x8000_1000, 0x8000_1000, RW), Ok(true));
    assert_eq!(pt.lookup(mem, 0x8000_1000), Some((0x8000_1000, RW)));
}

#[test]
fn a_superpage_in_an_upper_table_is_corruption_not_a_walk() {
    let mem = TestMem::leak();
    let f = PtFormat::new(PtKind::Vtd, 3);
    let mut pt = IoPageTable::new(f, mem).unwrap();
    // Plant an SP entry (bit 7) where an upper table pointer belongs.
    crate::common::write64(pt.root_pa(), 2, 0x4000_0000 | 0x83);
    assert_eq!(pt.map_page(mem, 0x8000_1000, 0x8000_1000, RW), Err(PtError::Corrupt));
    assert_eq!(pt.unmap_page(mem, 0x8000_1000), Err(PtError::Corrupt));
    assert_eq!(pt.lookup(mem, 0x8000_1000), None);
    let _ = mem.alloc_page();
}
