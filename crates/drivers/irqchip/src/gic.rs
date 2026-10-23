// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Which interrupt controller an aarch64 boot drives, from the device tree.
//!
//! The controllers are code in `azos_arch::irq` (`gic`: GICv3 and its ITS;
//! `gicv2`: GIC-400 and the Cortex-A15 GIC; `bcm2836`: the Raspberry Pi 2/3's
//! ARM-local controller and the armctrl behind it, a machine with no GIC).
//! What is decided here is which of them the tree names, and where their
//! windows are. Boot walks the device nodes, hands each to a [`Finder`], and
//! on a [`Gic::V2`] or [`Gic::Bcm2836`] selects that backend with the
//! windows; a boot that finds a GICv3 (or no controller at all) changes
//! nothing and drives the GICv3 at QEMU `virt`'s fixed addresses.
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
    /// `brcm,bcm2836-l1-intc` and `brcm,bcm2836-armctrl-ic`, both present:
    /// the ARM-local block and the peripheral controller, each `(base, bytes)`
    /// as the node's `reg` gives it (armctrl starts inside its page).
    Bcm2836 { local: (usize, usize), armctrl: (usize, usize) },
}

/// The BCM2836 ARM-local controller's name in the tree.
const BCM2836_LOCAL_COMPATIBLE: &[u8] = b"brcm,bcm2836-l1-intc";
/// The BCM2835 armctrl as a BCM2836/7 tree names it (cascaded off the local
/// block's GPU line).
const BCM2836_ARMCTRL_COMPATIBLE: &[u8] = b"brcm,bcm2836-armctrl-ic";

/// The interrupt controller of a tree, from its device nodes in any order.
/// The first GIC node wins, as [`from_node`] decides; with none, a tree that
/// names both halves of the BCM2836 pair is that pair. One half alone is no
/// controller this kernel can drive.
#[derive(Clone, Copy, Debug, Default)]
pub struct Finder {
    gic: Option<Gic>,
    local: Option<(usize, usize)>,
    armctrl: Option<(usize, usize)>,
}

impl Finder {
    pub const fn new() -> Self {
        Finder { gic: None, local: None, armctrl: None }
    }

    /// One device node: its `compatible`, first and second `reg` entries.
    pub fn node(&mut self, compatible: &[u8], reg: (u64, u64), reg2: Option<(u64, u64)>) {
        if self.gic.is_none() {
            self.gic = from_node(compatible, reg, reg2);
        }
        if self.local.is_none() && lists(compatible, BCM2836_LOCAL_COMPATIBLE) {
            self.local = window(reg);
        }
        if self.armctrl.is_none() && lists(compatible, BCM2836_ARMCTRL_COMPATIBLE) {
            self.armctrl = window(reg);
        }
    }

    /// What the walk found.
    pub fn done(&self) -> Option<Gic> {
        match (self.gic, self.local, self.armctrl) {
            (Some(g), _, _) => Some(g),
            (None, Some(local), Some(armctrl)) => Some(Gic::Bcm2836 { local, armctrl }),
            _ => None,
        }
    }
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

/// `window` as it is, when it is one: the registers' own address (armctrl's
/// start 0x200 into its page), which the boot's device mapping rounds out.
fn window(window: (u64, u64)) -> Option<(usize, usize)> {
    let (base, size) = window;
    if size == 0 {
        return None;
    }
    Some((usize::try_from(base).ok()?, usize::try_from(size).ok()?))
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
