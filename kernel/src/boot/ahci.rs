// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AHCI wiring (Kconfig `DRV_AHCI`): attach the SATA host as the boot block
//! device, then let its waiters sleep.
//!
//! [`attach_ahci`] runs from the PCI bring-up in `kernel_main` (the hardware
//! bus binds the `ahci` driver to the controller its table names), BEFORE
//! `blkdev::init`: that is what makes the disk the block device (the FAT32
//! mount that follows reads from it). The driver (`azos_drv_block::ahci`)
//! names no PCI type; this file does the PCI half: BAR 5 (the AHCI base
//! address register) is mapped, and the one MSI message is programmed through
//! the machine's route (the IMSIC on riscv64, the ITS on aarch64, the local
//! APIC on x86_64). A function without MSI, or a machine without a route,
//! leaves the driver polled. [`wire_ahci_irq`] runs with `wire_nvme_irq`, once
//! the scheduler exists: it hands the driver the two scheduler hooks the other
//! block drivers use, so a task waiting for a command sleeps until the MSI
//! (each ISA's interrupt arm calls `ahci::msi_irq`) wakes it.

use crate::kprintln;
use azos_drv_virtio::virtio::pci::msix_selftest::{map_bars, MsiRoute};

/// The AHCI base address register (ABAR): BAR 5 of the function.
const ABAR: usize = 5;

/// Attach controller `f`. `route` delivers its MSI; `dma_mask` is the hardware
/// bus's record of how high its DMA reaches. A refusal is a line, and the
/// block device stays what it was. `true`: a disk is up.
pub(crate) fn attach_ahci<C, R>(
    cfg: &mut C,
    f: &azos_pci::FunctionInfo,
    window: &mut azos_pci::BarWindow,
    route: &mut R,
    dma_mask: u64,
) -> bool
where
    C: azos_pci::ConfigSpace,
    R: MsiRoute,
{
    let bars = match map_bars(cfg, f, window) {
        Ok(b) => b,
        Err(e) => {
            kprintln!("[AHCI] controller {} not used: {:?}", f.bdf, e);
            return false;
        }
    };
    let abar = bars[ABAR];
    if abar == 0 {
        kprintln!("[AHCI] controller {} not used: BAR {} is not a memory BAR", f.bdf, ABAR);
        return false;
    }
    // One MSI, programmed before the HBA's interrupts are enabled (the driver
    // enables them last).
    let token = f.msi.and_then(|msi| {
        if !route.prepare(1) {
            return None;
        }
        let (addr, data) = route.target(0);
        (azos_pci::program_msi(cfg, f.bdf, &msi, addr, data) && azos_pci::msi_is_enabled(cfg, f.bdf, &msi))
            .then(|| route.isr_token(0))
    });
    match azos_drv_block::ahci::attach(abar, dma_mask, token) {
        Ok(()) => true,
        Err(e) => {
            kprintln!("[AHCI] controller {} not used: {:?}", f.bdf, e);
            false
        }
    }
}

static HOOKS: azos_drv_block::ahci::Hooks = azos_drv_block::ahci::Hooks {
    tid: azos_sync::waitqueue::caller_tid,
    block_until: super::blk_block_until,
    wake: super::blk_wake,
};

/// Let the AHCI driver's waiters sleep. A no-op without a controller.
pub(crate) fn wire_ahci_irq() {
    if !azos_drv_block::ahci::active() {
        return;
    }
    azos_drv_block::ahci::set_irq_hooks(&HOOKS);
    kprintln!("[AHCI] completions by {}",
        if azos_drv_block::ahci::irq_mode() { "interrupt" } else { "polling (no MSI route)" });
}
