// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! riscv64 device windows `boot::early_main` maps before the kernel table
//! goes live (the `kernel_mmio_windows` hook): the interrupt controller,
//! then the board's fixed windows (QEMU virt, VF2, K1).

/// The interrupt controller, the timer block and the board's devices,
/// identity-mapped by `early_main` before `enable_paging` (after the
/// console).
#[inline(always)]
pub(crate) fn kernel_mmio_windows() -> impl Iterator<Item = (usize, usize)> {
    use azos_drv_base::platform::hw;
    // PLIC (all platforms — up to 4 MiB is sufficient for enable/threshold/claim),
    // then the S-domain APLIC (32 KiB), only when the DTB selected AIA. The
    // IMSIC needs no mapping: the kernel reaches its own file through CSRs;
    // only devices write the file's physical page.
    let aplic = azos_drv_irqchip::irqchip::aplic_mmio_base().map(|b| (b, 0x8000));
    core::iter::once((hw::PLIC_BASE, 0x40_0000))
        .chain(aplic)
        .chain(BOARD_WINDOWS.iter().copied())
}

/// The board's fixed device windows, after the interrupt controller.
const BOARD_WINDOWS: &[(usize, usize)] = {
    #[allow(unused_imports)]
    use azos_drv_base::platform::hw;
    &[
        // QEMU: VirtIO MMIO 0x10001000 - 0x10008000 (8 devices); CLINT
        // 0x02000000 (64 KiB, mtime/mtimecmp via SBI but read rdtime);
        // fw_cfg (--features ramfb only, crates/drivers/display/src/ramfb.rs:
        // found by booting with ramfb and faulting at 0x10100008).
        #[cfg(not(any(feature = "vf2", feature = "k1")))]
        (0x1000_1000, 0x8000),
        #[cfg(not(any(feature = "vf2", feature = "k1")))]
        (0x0200_0000, 0x1_0000),
        #[cfg(all(feature = "ramfb", not(any(feature = "vf2", feature = "k1"))))]
        (hw::FW_CFG_BASE, 0x1000),
        // VF2. Display (--features hdmi only, crates/drivers/display), added
        // after the same class of missing mapping was caught on QEMU's ramfb.
        #[cfg(feature = "vf2")] (0x0200_0000, 0x1_0000), // CLINT
        #[cfg(feature = "vf2")] (hw::GPIO_BASE, 0x1000),
        #[cfg(feature = "vf2")] (hw::PWM_BASE, 0x1000),
        #[cfg(feature = "vf2")] (hw::I2C0_BASE, 0x1000),
        #[cfg(feature = "vf2")] (hw::I2C1_BASE, 0x1000),
        #[cfg(feature = "vf2")] (hw::MMC0_BASE, 0x1000),
        #[cfg(feature = "vf2")] (hw::MMC1_BASE, 0x1000),
        #[cfg(feature = "vf2")] (hw::ETH0_BASE, 0x1000),
        #[cfg(feature = "vf2")] (hw::UART1_BASE, 0x1000),
        #[cfg(feature = "vf2")] (hw::WDT_BASE, 0x1000),
        #[cfg(all(feature = "vf2", feature = "hdmi"))] (hw::DC8200_TOP_BASE, 0x1000),
        #[cfg(all(feature = "vf2", feature = "hdmi"))] (hw::DC8200_MAIN_BASE, 0x2000),
        #[cfg(all(feature = "vf2", feature = "hdmi"))] (hw::HDMI_TX_BASE, 0x1000),
        // K1. F14: NPU MMIO (1 MiB, covers all command/data registers).
        #[cfg(feature = "k1")] (hw::GPIO_BASE, 0x1000),
        #[cfg(feature = "k1")] (hw::PWM_BASE, 0x1000),
        #[cfg(feature = "k1")] (hw::I2C0_BASE, 0x1000),
        #[cfg(feature = "k1")] (hw::I2C1_BASE, 0x1000),
        #[cfg(feature = "k1")] (hw::MMC0_BASE, 0x2000),
        #[cfg(feature = "k1")] (hw::WDT_BASE, 0x1000),
        #[cfg(feature = "k1")] (hw::NPU_BASE, hw::NPU_SIZE),
    ]
};
