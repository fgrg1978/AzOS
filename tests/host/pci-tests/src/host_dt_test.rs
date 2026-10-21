// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The device-tree reading the kernel's host-bridge bring-up does before a
//! controller's `init` (`azos_pci::host::dt`): fixture properties taken from
//! the JH7110 (`jh7110.dtsi`, `pcie@940000000`) and the Raspberry Pi 5.

use azos_pci::host::dt::*;
use azos_pci::host::{plda, InboundWindow, MemSpace, OutboundWindow};
use azos_pci::HostWindow;

fn bytes(cells: &[u32]) -> Vec<u8> {
    cells.iter().flat_map(|c| c.to_be_bytes()).collect()
}

fn blank_out() -> OutboundWindow {
    OutboundWindow { space: MemSpace::Mem32, window: HostWindow { cpu_base: 0, bus_base: 0, size: 0 } }
}

/// `ranges` of the JH7110 PCIe0 node: a 128 MiB 32-bit window at 0x3000_0000
/// and a 1 GiB 64-bit prefetchable one at 0x9_0000_0000.
fn jh7110_ranges() -> Vec<u8> {
    bytes(&[
        0x8200_0000, 0x0, 0x3000_0000, 0x0, 0x3000_0000, 0x0, 0x0800_0000,
        0xc300_0000, 0x9, 0x0000_0000, 0x9, 0x0000_0000, 0x0, 0x4000_0000,
    ])
}

#[test]
fn the_controller_is_chosen_by_compatible() {
    assert_eq!(Controller::from_compatible("starfive,jh7110-pcie"), Some(Controller::Plda));
    assert_eq!(Controller::from_compatible("brcm,bcm2712-pcie"), Some(Controller::Brcmstb));
    // The generic ECAM host and a near miss are not SoC controllers.
    assert_eq!(Controller::from_compatible("pci-host-ecam-generic"), None);
    assert_eq!(Controller::from_compatible("starfive,jh7110-pcie-phy"), None);
    assert_eq!(Controller::from_compatible(""), None);
}

#[test]
fn the_stg_block_follows_the_pci_domain() {
    assert_eq!(plda_stg_base(0), Some(plda::STG_PCIE0_BASE));
    assert_eq!(plda_stg_base(1), Some(plda::STG_PCIE1_BASE));
    assert_eq!(plda_stg_base(2), None);
}

#[test]
fn reg_is_found_by_name_whatever_the_order() {
    // jh7110.dtsi lists "cfg" first and "apb" second.
    let reg = bytes(&[0x9, 0x4000_0000, 0x0, 0x0100_0000, 0x0, 0x2b00_0000, 0x0, 0x0010_0000]);
    let names = b"cfg\0apb\0";
    assert_eq!(reg_named(&reg, Some(names), "cfg", 2, 2), Some((0x9_4000_0000, 0x0100_0000)));
    assert_eq!(reg_named(&reg, Some(names), "apb", 2, 2), Some((0x2b00_0000, 0x0010_0000)));
    // A name the node does not have is not "the first entry".
    assert_eq!(reg_named(&reg, Some(names), "stg", 2, 2), None);
    // A prefix is not the name.
    assert_eq!(reg_named(&reg, Some(b"cfgx\0apb\0"), "cfg", 2, 2), None);
    // A truncated entry is refused whole.
    assert_eq!(reg_named(&reg[..28], Some(names), "apb", 2, 2), None);
}

#[test]
fn a_node_without_reg_names_has_one_block() {
    // The BCM2712 node: one range, no names.
    let reg = bytes(&[0x10, 0x0012_0000, 0x0, 0x9310]);
    assert_eq!(reg_named(&reg, None, "apb", 2, 2), Some((0x10_0012_0000, 0x9310)));
}

#[test]
fn the_jh7110_ranges_become_a_mem32_and_a_mem64_window() {
    let mut out = [blank_out(); 8];
    let n = parse_ranges(&jh7110_ranges(), 2, 2, &mut out).unwrap();
    assert_eq!(n, 2);
    assert_eq!(out[0].space, MemSpace::Mem32);
    assert_eq!(out[0].window, HostWindow { cpu_base: 0x3000_0000, bus_base: 0x3000_0000, size: 0x0800_0000 });
    assert_eq!(out[1].space, MemSpace::Mem64);
    assert_eq!(out[1].window, HostWindow { cpu_base: 0x9_0000_0000, bus_base: 0x9_0000_0000, size: 0x4000_0000 });
}

#[test]
fn a_translated_window_keeps_both_addresses() {
    // The Pi 5's: PCI address 0, CPU address 0x1f_0000_0000.
    let r = bytes(&[0x0200_0000, 0x0, 0x0, 0x1f, 0x0, 0x0, 0xffff_fffc]);
    let mut out = [blank_out(); 4];
    assert_eq!(parse_ranges(&r, 2, 2, &mut out), Ok(1));
    assert_eq!(out[0].window, HostWindow { cpu_base: 0x1f_0000_0000, bus_base: 0, size: 0xffff_fffc });
}

#[test]
fn io_and_config_entries_are_not_memory_windows() {
    let r = bytes(&[
        0x0100_0000, 0x0, 0x0, 0x0, 0x2000_0000, 0x0, 0x0001_0000, // I/O
        0x0000_0000, 0x0, 0x0, 0x0, 0x2001_0000, 0x0, 0x0001_0000, // config
        0x8200_0000, 0x0, 0x3000_0000, 0x0, 0x3000_0000, 0x0, 0x0800_0000,
    ]);
    let mut out = [blank_out(); 4];
    assert_eq!(parse_ranges(&r, 2, 2, &mut out), Ok(1));
    assert_eq!(out[0].window.cpu_base, 0x3000_0000);
}

#[test]
fn a_one_cell_parent_address_is_read() {
    // A 32-bit parent bus: hi, mid, lo, one CPU cell, two size cells.
    let r = bytes(&[0x8200_0000, 0x0, 0x4000_0000, 0x4000_0000, 0x0, 0x1000_0000]);
    let mut out = [blank_out(); 2];
    assert_eq!(parse_ranges(&r, 1, 2, &mut out), Ok(1));
    assert_eq!(out[0].window, HostWindow { cpu_base: 0x4000_0000, bus_base: 0x4000_0000, size: 0x1000_0000 });
}

#[test]
fn malformed_ranges_are_refused_and_a_full_table_is_reported() {
    let mut out = [blank_out(); 1];
    // Not a whole number of entries.
    let mut r = jh7110_ranges();
    r.truncate(r.len() - 4);
    assert_eq!(parse_ranges(&r, 2, 2, &mut out), Err(DtError::Malformed));
    // A cell count the flow cannot read.
    assert_eq!(parse_ranges(&jh7110_ranges(), 3, 2, &mut out), Err(DtError::Malformed));
    assert_eq!(parse_ranges(&jh7110_ranges(), 2, 0, &mut out), Err(DtError::Malformed));
    // Two memory windows, room for one.
    assert_eq!(parse_ranges(&jh7110_ranges(), 2, 2, &mut out), Err(DtError::TooMany));
    // No property is no window.
    assert_eq!(parse_ranges(&[], 2, 2, &mut out), Ok(0));
}

#[test]
fn dma_ranges_map_pci_addresses_to_cpu_memory() {
    // The Pi 5's first inbound window: PCI 0x10_0000_0000 -> CPU 0, 64 GiB;
    // and one covering the low 4 GiB.
    let r = bytes(&[
        0x4200_0000, 0x10, 0x0, 0x0, 0x0, 0x10, 0x0,
        0x0200_0000, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0,
    ]);
    let mut out = [InboundWindow { bus_base: 0, cpu_base: 0, size: 0 }; 4];
    assert_eq!(parse_dma_ranges(&r, 2, 2, &mut out), Ok(2));
    assert_eq!(out[0], InboundWindow { bus_base: 0x10_0000_0000, cpu_base: 0, size: 0x10_0000_0000 });
    assert_eq!(out[1], InboundWindow { bus_base: 0, cpu_base: 0, size: 0x1_0000_0000 });
    let mut one = [InboundWindow { bus_base: 0, cpu_base: 0, size: 0 }; 1];
    assert_eq!(parse_dma_ranges(&r, 2, 2, &mut one), Err(DtError::TooMany));
}

#[test]
fn the_dma_mask_covers_the_highest_inbound_address() {
    let w = |bus_base, size| InboundWindow { bus_base, cpu_base: 0, size };
    // No window: the bridge's reset translation, no limit.
    assert_eq!(dma_mask(&[]), u64::MAX);
    // The low 4 GiB: a 32-bit mask.
    assert_eq!(dma_mask(&[w(0, 1 << 32)]), 0xffff_ffff);
    // Not a power of two: the next mask up.
    assert_eq!(dma_mask(&[w(0, 0xffff_fffc)]), 0xffff_ffff);
    assert_eq!(dma_mask(&[w(0, 0x1_0000_0001)]), 0x1_ffff_ffff);
    // The highest end wins, whatever the order.
    assert_eq!(dma_mask(&[w(0x10_0000_0000, 0x10_0000_0000), w(0, 1 << 32)]), 0x1f_ffff_ffff);
}
