// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Disk completion by interrupt (wave 15): virtio-blk on every ISA, and the
//! SD/eMMC host (`wire_mmc_irq`) where the board or the QEMU row has one.
//!
//! The block driver (`azos_drv_virtio::virtio::blk`) found its device in a
//! virtio-mmio slot; this maps that slot to its interrupt line, routes the
//! line to the boot CPU at the interrupt controller, and hands the driver
//! the line and two scheduler hooks. From then on a task waiting for a disk
//! request sleeps until the line's handler (each ISA's external-interrupt
//! arm calls `blk::irq`) wakes it, bounded by the request's deadline.
//!
//! Lines: riscv64 `virt` PLIC/APLIC source `VIRTIO_IRQ_BASE + slot`; aarch64
//! `virt` SPI INTID `VIRTIO_IRQ_BASE + slot` (level: the device holds it
//! until its interrupt is acknowledged, which the handler does first); x86_64
//! microvm, the GSI the boot discovered for the transport (already routed to
//! this CPU and masked by `irqchip_init`; unmasked here).

use crate::kprintln;

/// The driver's sleep: block the caller until a TID wake or `deadline`
/// (timebase ticks). Refused (`false`, the driver then spins) where a task
/// cannot block: before the scheduler, with interrupts or preemption off.
pub(crate) fn blk_block_until(deadline: u64) -> bool {
    let tid = azos_sync::waitqueue::caller_tid();
    if tid == 0 || tid == u32::MAX
        || !azos_sync::preempt::irqs_enabled()
        || azos_sync::preempt::disabled()
    {
        return false;
    }
    if azos_drv_sys::timebase::now() >= deadline {
        return true;
    }
    azos_sched::task_block(azos_sched::WaitReason::Timer(deadline));
    true
}

/// The driver's wake (interrupt context): a TID wake of a `Timer` sleeper,
/// stamped when the task has not blocked yet.
pub(crate) fn blk_wake(tid: u32) {
    azos_sched::scheduler::wake_task_by_tid(tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
}

/// Route the block device's line and switch the driver to it. A no-op
/// without a block device, or where the line cannot be routed (the driver
/// then stays polled, as before).
pub(crate) fn wire_virtio_blk_irq() {
    let Some((slot, base)) = azos_drv_virtio::virtio::blk::mmio_slot() else { return; };
    let Some(line) = line_of(slot, base) else {
        kprintln!("[VIRTIO-BLK] no interrupt line for slot {}: polled", slot);
        return;
    };
    // Each virtio-mmio transport has its own line (slot -> PLIC source /
    // GIC SPI, per-transport GSI on microvm), so the NIC's cannot be this
    // one; a firmware that shared them would make both handlers claim the
    // same interrupt, so the disk then stays polled.
    if azos_drv_virtio::virtio::net::mmio_irq_line() == Some(line) {
        kprintln!("[VIRTIO-BLK] line {} is the NIC's: polled", line);
        return;
    }
    // The handler must know the line (and the device's stale interrupt be
    // acknowledged) before the controller enables it: a level line already
    // asserted would otherwise be taken, unrecognised, forever.
    azos_drv_virtio::virtio::blk::set_irq_mode(line, blk_block_until, blk_wake);
    if !enable_line(line) {
        kprintln!("[VIRTIO-BLK] line {} not routable: polled", line);
        return;
    }
    kprintln!("[VIRTIO-BLK] completions by interrupt on line {} (slot {}){}", line, slot,
        if azos_drv_virtio::virtio::blk::irq_mode() { "" } else { " — NOT taken (polled)" });
    if azos_drv_virtio::virtio::blk::irq_mode() {
        crate::irq_thread::register(line);
    }
}

/// The SD/eMMC drivers' hooks (`mmc.rs`, `dwmshc.rs`): the caller's TID, the
/// same sleep and wake the virtio-blk driver gets.
#[cfg(any(feature = "vf2", feature = "k1", feature = "mmc-flush-smoke"))]
static MMC_HOOKS: azos_drv_block::dev_queue::IrqHooks = azos_drv_block::dev_queue::IrqHooks {
    tid: azos_sync::waitqueue::caller_tid,
    block_until: blk_block_until,
    wake: blk_wake,
};

/// Route the interrupt line of the initialised SD/eMMC slots and switch their
/// drivers to completions by interrupt (Kconfig `IRQ_THREADED`: served by the
/// `irq-thread`, as the virtio disk's line is). A slot with no known line, or
/// whose line cannot be routed, stays polled.
#[cfg(any(feature = "k1", feature = "mmc-flush-smoke"))]
pub(crate) fn wire_mmc_irq() {
    use azos_drv_block::mmc::{self, MmcSlot};
    for slot in [MmcSlot::Emmc, MmcSlot::Sd] {
        let Some(line) = mmc::mmc_irq_line(slot) else { continue; };
        // The handler must know the line before the controller enables it: a
        // level line already asserted would otherwise be taken, unrecognised,
        // forever.
        if !mmc::mmc_set_irq_mode(slot, line, &MMC_HOOKS) {
            kprintln!("[MMC] slot {}: line {} not taken: polled", slot as usize, line);
            continue;
        }
        if !enable_line(line) {
            mmc::mmc_irq_off(slot);
            kprintln!("[MMC] slot {}: line {} not routable: polled", slot as usize, line);
            continue;
        }
        kprintln!("[MMC] slot {}: completions by interrupt on line {}", slot as usize, line);
        crate::irq_thread::register(line);
    }
}

/// [`wire_mmc_irq`] for the VisionFive 2's DesignWare MSHC: the line is the
/// one its device-tree node named when the hardware bus bound it.
#[cfg(feature = "vf2")]
pub(crate) fn wire_mmc_irq() {
    use azos_drv_block::dwmshc;
    let Some(line) = dwmshc::irq_line() else { return; };
    if !dwmshc::set_irq_mode(line, &MMC_HOOKS) {
        kprintln!("[SDMMC] line {} not taken: polled", line);
        return;
    }
    if !enable_line(line) {
        dwmshc::irq_off();
        kprintln!("[SDMMC] line {} not routable: polled", line);
        return;
    }
    kprintln!("[SDMMC] completions by interrupt on line {}", line);
    crate::irq_thread::register(line);
}

/// The line of the device's virtio-mmio slot: the same per-ISA mapping the
/// NIC uses (`boot_hooks::virtio_mmio_line`), including its `None` on a
/// board without a virtio-mmio window (VF2, K1), where the device stays polled.
#[cfg(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64"))]
fn line_of(slot: usize, base: usize) -> Option<u32> {
    crate::boot_hooks::virtio_mmio_line(slot, base)
}

#[cfg(target_arch = "riscv64")]
pub(super) fn enable_line(irq: u32) -> bool {
    let hart = azos_arch::Cpu::hart_id(&azos_arch::ARCH) as u32;
    let _ = azos_drv_irqchip::irqchip::wire_aia_source(irq, hart);
    azos_drv_irqchip::irqchip::enable_irq(hart, irq);
    true
}

#[cfg(target_arch = "aarch64")]
pub(super) fn enable_line(intid: u32) -> bool {
    let mpidr = azos_arch::cpu::read_mpidr().raw;
    azos_arch::irq::gic::route_spi(intid, mpidr, false);
    true
}

#[cfg(target_arch = "x86_64")]
pub(super) fn enable_line(gsi: u32) -> bool {
    azos_drv_irqchip::user_irq::mark_kernel(gsi);
    azos_arch::irq::ioapic::set_masked(gsi, false)
}

#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
fn line_of(_slot: usize, _base: usize) -> Option<u32> {
    None
}

#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
pub(super) fn enable_line(_line: u32) -> bool {
    false
}
