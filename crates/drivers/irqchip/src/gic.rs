// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Which GIC an aarch64 boot drives, from the device tree.
//!
//! The controllers are code in `azos_arch::irq` (`gic`: GICv3 and its ITS;
//! `gicv2`: GIC-400 and the Cortex-A15 GIC). What is decided here is which of
//! the two a node of the tree names, and where a GICv2's two windows are. Boot
//! walks the device nodes, asks [`from_node`] about each, and on a
//! [`Gic::V2`] hands the windows to `azos_arch::irq::gicv2::select`; a boot
//! that finds a GICv3 (or no GIC at all) changes nothing and drives the GICv3
//! at QEMU `virt`'s fixed addresses.
//!
//! Pure, no `azos_arch` call: the host tests run it as written.

/// The page size the windows are rounded to.
const PAGE: u64 = 0x1000;

/// The device-tree names of the GICv2 controllers (the `arm,gic` binding's
/// two this kernel drives: the ARM GIC-400 and the Cortex-A15's).
const GICV2_COMPATIBLE: [&[u8]; 2] = [b"arm,gic-400", b"arm,cortex-a15-gic"];

/// The GICv3's name in the tree.
const GICV3_COMPATIBLE: &[u8] = b"arm,gic-v3";

/// What a GIC node names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gic {
    /// `arm,gic-v3`: driven at the fixed QEMU-`virt` addresses (the node's
    /// windows are not read).
    V3,
    /// `arm,gic-400` / `arm,cortex-a15-gic`: the distributor and the CPU
    /// interface, each `(base, bytes)` rounded out to whole pages.
    V2 { gicd: (usize, usize), gicc: (usize, usize) },
}

fn lists(compatible: &[u8], name: &[u8]) -> bool {
    compatible.split(|&b| b == 0).any(|s| s == name)
}

/// `window` rounded out to the pages it touches: `(base, bytes)`.
fn pages(window: (u64, u64)) -> Option<(usize, usize)> {
    let (base, size) = window;
    if size == 0 {
        return None;
    }
    let start = base & !(PAGE - 1);
    let end = base.checked_add(size)?.checked_add(PAGE - 1)? & !(PAGE - 1);
    Some((usize::try_from(start).ok()?, usize::try_from(end - start).ok()?))
}

/// The GIC a device node names, from its `compatible` (the NUL-separated
/// strings), its first `reg` entry and its second. A GICv2 node needs both
/// entries (distributor, then CPU interface); one without them is no GIC this
/// kernel can drive and gives `None`, as does any other node.
pub fn from_node(compatible: &[u8], reg: (u64, u64), reg2: Option<(u64, u64)>) -> Option<Gic> {
    if lists(compatible, GICV3_COMPATIBLE) {
        return Some(Gic::V3);
    }
    if GICV2_COMPATIBLE.iter().any(|n| lists(compatible, n)) {
        return Some(Gic::V2 { gicd: pages(reg)?, gicc: pages(reg2?)? });
    }
    None
}
