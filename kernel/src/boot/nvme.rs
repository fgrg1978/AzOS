// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! NVMe wiring (Kconfig `DRV_NVME`): attach the controller as the boot block
//! device, then let its waiters sleep.
//!
//! [`attach_nvme`] runs from the PCI bring-up in `kernel_main` (the hardware
//! bus binds the `nvme` driver to the controller its table names), BEFORE
//! `blkdev::init`: that is what makes the controller the block device (the
//! FAT32 mount that follows reads from it). [`wire_nvme_irq`] runs with
//! `wire_virtio_blk_irq`, once the scheduler exists: it hands the driver the
//! two scheduler hooks the virtio-blk driver uses (`blk_block_until`,
//! `blk_wake`), so a task waiting for a command sleeps until the MSI-X
//! handler of any queue's vector (each ISA's interrupt arm calls
//! `nvme::msi_irq`) wakes it. A controller with no MSI route stays polled, as
//! virtio-blk does.

use crate::kprintln;

/// Attach controller `f`. `route` delivers its MSI-X vectors (the admin
/// queue's and one per I/O queue: each hart's IMSIC file, each CPU's local
/// APIC, the ITS's boot collection); `dma_mask` is the hardware bus's record
/// of how high its DMA reaches; `cpus` bounds the I/O queue pairs. A refusal
/// is a line, and the block device stays virtio-blk.
pub(crate) fn attach_nvme<C, R>(
    cfg: &mut C,
    f: &azos_pci::FunctionInfo,
    window: &mut azos_pci::BarWindow,
    route: &mut R,
    dma_mask: u64,
    cpus: usize,
) where
    C: azos_pci::ConfigSpace,
    R: azos_drv_block::nvme::QueueRoute,
{
    if let Err(e) = azos_drv_block::nvme::attach(cfg, f, window, route, dma_mask, cpus) {
        kprintln!("[NVME] controller {} not used: {:?}", f.bdf, e);
    }
}

/// Let the NVMe driver's waiters sleep. A no-op without a controller.
pub(crate) fn wire_nvme_irq() {
    if !azos_drv_block::nvme::active() {
        return;
    }
    azos_drv_block::nvme::set_irq_hooks(super::blk_block_until, super::blk_wake);
    kprintln!("[NVME] completions by {}",
        if azos_drv_block::nvme::irq_mode() { "interrupt" } else { "polling (no MSI-X route)" });
}

/// Boot evidence that a transfer over a PRP list reads the right bytes: 64
/// sectors (32 KiB, eight pages: PRP1 and a seven-entry list) from the FAT
/// region in ONE command, against the same 64 sectors as single-sector
/// reads (one page, no list). Prints one line, `PASS` or the first
/// difference. The pages must not all be alike or the comparison proves
/// nothing, so it also counts the pages that differ from their predecessor.
/// Read-only. With `nvme-prp-canary` the list pointer is wrong and this must
/// say `FAIL`.
pub(crate) fn nvme_prp_selftest() {
    const FIRST: u64 = 32;
    const N: usize = 64;
    if azos_drv_block::blkdev::capacity_sectors() < FIRST + N as u64 {
        return;
    }
    let mut big = alloc::vec![0u8; N * 512];
    if azos_drv_block::blkdev::read_quiet(FIRST, N as u32, &mut big).is_err() {
        kprintln!("[NVME] prp selftest FAIL: the {}-sector read failed", N);
        return;
    }
    let mut one = [0u8; 512];
    for i in 0..N {
        if azos_drv_block::blkdev::read_quiet(FIRST + i as u64, 1, &mut one).is_err() {
            kprintln!("[NVME] prp selftest FAIL: single read of sector {} failed", FIRST + i as u64);
            return;
        }
        if big[i * 512..(i + 1) * 512] != one {
            kprintln!("[NVME] prp selftest FAIL: sector {} differs between the list read and the single read",
                FIRST + i as u64);
            return;
        }
    }
    let distinct = (1..N * 512 / 4096).filter(|&p| big[p * 4096..(p + 1) * 4096] != big[(p - 1) * 4096..p * 4096]).count();
    kprintln!("[NVME] prp selftest PASS: {} sectors in {} pages over a PRP list match {} single reads, {} of {} pages differ from their predecessor",
        N, N * 512 / 4096, N, distinct, N * 512 / 4096 - 1);
}
