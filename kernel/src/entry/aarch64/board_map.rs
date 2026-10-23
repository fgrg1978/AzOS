// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 QEMU `virt` device windows `boot::early_main` maps before the
//! kernel table goes live (the `kernel_mmio_windows` hook).

use azos_arch::irq::{bcm2836, gic, gicv2};

/// The GICv3 distributor, every redistributor frame and the ITS. All
/// `MAX_HARTS` 128 KiB redistributor frames: `smp::secondary_init` walks
/// `find_redistributor` up to `MAX_HARTS` frames looking for its own
/// affinity, and a walk past a mapped frame data-aborts on unmapped Device
/// space. The ITS takes its control and translation frames (0x2_0000, see
/// `azos_arch::irq::its::translater_address`). A GICv2 (`irq::gicv2`, selected
/// from the tree) has the two windows the tree gave and no ITS, and so has the
/// BCM2836 pair (`irq::bcm2836`, a Raspberry Pi 2/3). Mapped before
/// the kernel table goes live, and recorded, so the device-only TTBR0
/// (`restrict_low_half`) gets them too; VirtIO comes later
/// (`arch_map_late_mmio`).
#[inline(always)]
pub(crate) fn kernel_mmio_windows() -> impl Iterator<Item = (usize, usize)> {
    let [gicd, gicc] = gicv2::windows();
    let [local, armctrl] = bcm2836::windows();
    let windows = if bcm2836::active() {
        [local, armctrl, (0, 0)]
    } else if gicv2::active() {
        [gicd, gicc, (0, 0)]
    } else {
        [
            (gic::GICD_BASE, 0x1_0000),
            (gic::GICR_BASE, gic::GICR_STRIDE * crate::MAX_HARTS),
            (azos_arch::irq::its::ITS_BASE, 0x2_0000),
        ]
    };
    windows.into_iter().filter(|&(_, bytes)| bytes != 0)
}
