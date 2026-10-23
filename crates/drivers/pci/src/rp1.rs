// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The RP1, the Raspberry Pi 5's south bridge: a PCIe endpoint (`1de4:0001`,
//! Raspberry Pi Ltd; the hardware bus binds it, `hwbus.ids`)
//! behind the BCM2712's `pcie2`, whose BAR 1 is a window onto its own bus's
//! `0x4000_0000` (UARTs, GPIO, the Ethernet MAC, the USB hosts, ...). It is
//! found on the bus by its id, not by a device-tree path: Linux's tree and the
//! firmware's describe it differently. What is here is the map the kernel
//! needs to reach a block once BAR 1 is assigned: offsets into the BAR as
//! Linux's `rp1.dtsi` places the blocks, and the chip-id check. The blocks
//! have no driver yet, and their interrupts are MSI-X through the BCM2712's
//! MIP, which is not wired.

/// The BAR that maps the peripherals.
pub const PERIPHERAL_BAR: usize = 1;

/// `SYSINFO.CHIP_ID`, the first word of the peripheral window, and the value
/// the RP1 (revision C0) reads back.
pub const SYSINFO_CHIP_ID: usize = 0x0;
pub const CHIP_ID: u32 = 0x2000_1927;

/// A block of the RP1 the kernel names at boot: its offset in BAR 1 and the
/// bytes of its registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Block {
    pub name: &'static str,
    pub offset: usize,
    pub size: usize,
}

/// The blocks named at boot (the first users to come: the 40-pin header's
/// UART and GPIO, and the Ethernet MAC): `uart0` (a PL011), GPIO bank 0's
/// control, set/clear (`sys_rio0`) and pad registers, the Cadence GEM and its
/// glue (`eth_cfg`).
pub const BLOCKS: [Block; 6] = [
    Block { name: "uart0", offset: 0x3_0000, size: 0x100 },
    Block { name: "gpio-bank0", offset: 0xd_0000, size: 0xc000 },
    Block { name: "rio-bank0", offset: 0xe_0000, size: 0xc000 },
    Block { name: "pads-bank0", offset: 0xf_0000, size: 0xc000 },
    Block { name: "ethernet", offset: 0x10_0000, size: 0x4000 },
    Block { name: "eth-cfg", offset: 0x10_4000, size: 0x100 },
];

/// The CPU address of `block` with BAR 1 at `bar` (`bar_len` bytes), `None`
/// when the BAR is too small to hold it.
pub const fn block_at(bar: usize, bar_len: usize, block: &Block) -> Option<usize> {
    match block.offset.checked_add(block.size) {
        Some(end) if end <= bar_len => Some(bar + block.offset),
        _ => None,
    }
}
