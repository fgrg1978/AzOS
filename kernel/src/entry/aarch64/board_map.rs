// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 QEMU `virt` device windows `boot::early_main` maps before the
//! kernel table goes live (the `kernel_mmio_windows` hook).

use azos_arch::gic;

/// The GICv3 distributor, every redistributor frame and the ITS. All
/// `MAX_HARTS` 128 KiB redistributor frames: `smp::secondary_init` walks
/// `find_redistributor` up to `MAX_HARTS` frames looking for its own
/// affinity, and a walk past a mapped frame data-aborts on unmapped Device
/// space. The ITS takes its control and translation frames (0x2_0000, see
/// `azos_arch::its::translater_address`). Mapped before the kernel table goes
/// live, and recorded, so the device-only TTBR0 (`restrict_low_half`) gets
/// them too; VirtIO comes later (`arch_map_late_mmio`).
#[inline(always)]
pub(crate) fn kernel_mmio_windows() -> impl Iterator<Item = (usize, usize)> {
    [
        (gic::GICD_BASE, 0x1_0000),
        (gic::GICR_BASE, gic::GICR_STRIDE * crate::MAX_HARTS),
        (azos_arch::its::ITS_BASE, 0x2_0000),
    ]
    .into_iter()
}
