// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_pci::rp1`: the blocks of the Raspberry Pi 5's south bridge inside its
//! peripheral BAR.

use azos_pci::rp1::{block_at, Block, BLOCKS, CHIP_ID, PERIPHERAL_BAR};

/// The RP1's BAR 1 as Linux's `rp1.dtsi` sizes its window (4 MiB).
const BAR_LEN: usize = 0x40_0000;
/// Where `pcie2`'s 32-bit window puts it on a Pi 5 (representative).
const BAR: usize = 0x1f_0000_0000;

#[test]
fn the_blocks_sit_inside_bar1_without_overlapping() {
    assert_eq!(PERIPHERAL_BAR, 1);
    for (i, a) in BLOCKS.iter().enumerate() {
        assert!(a.offset + a.size <= BAR_LEN, "{} past the BAR", a.name);
        for b in &BLOCKS[i + 1..] {
            assert!(a.offset + a.size <= b.offset || b.offset + b.size <= a.offset, "{} overlaps {}", a.name, b.name);
        }
    }
}

#[test]
fn a_block_is_the_bar_plus_its_offset() {
    let uart0 = BLOCKS.iter().find(|b| b.name == "uart0").unwrap();
    assert_eq!(block_at(BAR, BAR_LEN, uart0), Some(0x1f_0003_0000));
    let eth = BLOCKS.iter().find(|b| b.name == "ethernet").unwrap();
    assert_eq!(block_at(BAR, BAR_LEN, eth), Some(0x1f_0010_0000));
    // A BAR too small for the block (a different chip at the id) names none,
    // and an offset that would overflow is refused rather than wrapped.
    assert_eq!(block_at(BAR, 0x1_0000, eth), None);
    let huge = Block { name: "x", offset: usize::MAX, size: 2 };
    assert_eq!(block_at(BAR, BAR_LEN, &huge), None);
    assert_eq!(CHIP_ID, 0x2000_1927);
}
