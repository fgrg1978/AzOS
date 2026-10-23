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
//! [`ahci_queue_selftest`] is the evidence the q35 row reads for the queue,
//! FUA and TRIM.

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

/// Evidence for the command queue and the disk's features, from task context
/// once the disk is the block device (the `fs-wb` task, after the interrupt
/// evidence). A read of four commands' worth from sector 0: the request layer
/// starts them together, so where the disk queues more than one is in it at
/// once. Then FAT32's own users of FUA and TRIM: a scratch file written and
/// synced, removed and synced. The sync's write-back commit is a FUA write
/// where `blkdev::fua_commit` says the disk has one (write then flush
/// otherwise), and the removed file's chain is discarded (Kconfig
/// `BLK_DISCARD`) where the disk TRIMs. One `[AHCI] queue:` line says what the
/// driver counted.
pub(crate) fn ahci_queue_selftest() {
    const NAME: [u8; 11] = *b"AHCIQTSTTMP";
    let n = (4 * azos_drv_block::ahci::XFER_SECTORS as u64).min(azos_drv_block::blkdev::capacity_sectors()) as u32;
    let mut big = alloc::vec![0u8; n as usize * 512];
    let rd = azos_drv_block::blkdev::read_quiet(0, n, &mut big).is_ok();
    let data = alloc::vec![0x5Au8; 64 * 1024];
    let wr = azos_fs::fat32_write_file(&NAME, &data).is_ok() && azos_fs::fat32_sync().is_ok();
    let rm = azos_fs::fat32_unlink_root(&NAME).is_ok() && azos_fs::fat32_sync().is_ok();
    let (slots, deepest, fua, trims) = azos_drv_block::ahci::queue_counts();
    kprintln!(
        "[AHCI] queue: {} slot(s), {} in the disk at once (read of {} sectors {}); fua commit {} ({} FUA writes); {} TRIMs; scratch file write {} remove {}",
        slots,
        deepest,
        n,
        if rd { "ok" } else { "FAILED" },
        if azos_drv_block::blkdev::fua_commit() { "y" } else { "n" },
        fua,
        trims,
        if wr { "ok" } else { "FAILED" },
        if rm { "ok" } else { "FAILED" }
    );
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
