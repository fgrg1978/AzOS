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

// Two reapers at one slot, the second run while the first is between its check
// and its set, and only if nothing keeps it out. If it reports, the layer
// releases the slot and starts the next command, which the first then ends
// early with the old status.
#[cfg(feature = "ktest")]
azos_ktest::ktest_late! {
    fn blk_reap_reports_once() {
        use azos_drv_virtio::virtio::blk::{report_once, ReportFlags};
        use core::sync::atomic::{AtomicBool, Ordering};
        let lock = azos_sync::kmutex::Mutex::new(());
        let (inflight, done, reported) = (AtomicBool::new(true), AtomicBool::new(true), AtomicBool::new(false));
        let f = || ReportFlags { inflight: &inflight, done: &done, reported: &reported };

        let mut second = None;
        let first = report_once(&lock, f(), false, || {
            if lock.try_lock().is_some() {
                second = report_once(&lock, f(), false, || ());
                done.store(false, Ordering::Relaxed);
                reported.store(false, Ordering::Relaxed);
            }
        });
        if second.is_some() {
            return Err("a second reaper reported a slot the first had checked");
        }
        if first != Some(true) {
            return Err("the first reaper did not report a finished command");
        }
        if report_once(&lock, f(), false, || ()).is_some() {
            return Err("a slot already reported was reported again");
        }

        reported.store(false, Ordering::Relaxed);
        done.store(false, Ordering::Relaxed);
        if report_once(&lock, f(), false, || ()).is_some() {
            return Err("a command in the device was reported");
        }
        if report_once(&lock, f(), true, || ()) != Some(false) {
            return Err("a command in a dead device was not reported");
        }
        reported.store(false, Ordering::Relaxed);
        inflight.store(false, Ordering::Relaxed);
        if report_once(&lock, f(), true, || ()).is_some() {
            return Err("an idle slot was reported");
        }
        Ok(())
    }
}

/// The boot has reached the stage that wires the disk's line: a rebind after
/// it wires the line again (`boot::driver_records`).
static BLK_WIRED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Is the disk's line wired by now (its stage has run)?
pub(crate) fn virtio_blk_irq_stage_ran() -> bool {
    BLK_WIRED.load(core::sync::atomic::Ordering::Acquire)
}

/// Route the block device's line and switch the driver to it. A no-op
/// without a block device, or where the line cannot be routed (the driver
/// then stays polled, as before). The line is booked to the device's bus
/// handle (`driver_records::hold`), which its unbind gives back.
pub(crate) fn wire_virtio_blk_irq() {
    BLK_WIRED.store(true, core::sync::atomic::Ordering::Release);
    if canary!("blk-reap-unlocked") {
        azos_drv_virtio::virtio::blk::set_reap_unlocked(true);
        kprintln!("[CANARY] blk-reap-unlocked: reapers check and set a slot's report with no lock");
    }
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
    let Some(target) = crate::boot_hooks::kernel_line_enable(line) else {
        // No interrupt will come: a wait that slept to its deadline would run
        // the disk at timeout speed.
        azos_drv_virtio::virtio::blk::irq_mode_off();
        kprintln!("[VIRTIO-BLK] line {} not routable: polled", line);
        return;
    };
    kprintln!("[VIRTIO-BLK] completions by interrupt on line {} (slot {}){}", line, slot,
        if azos_drv_virtio::virtio::blk::irq_mode() { "" } else { " — NOT taken (polled)" });
    if azos_drv_virtio::virtio::blk::irq_mode() {
        crate::irq_thread::register(line);
    }
    if let Some(h) = super::driver_records::handle_at(base) {
        super::driver_records::hold_line(h, line, target);
    }
}

/// Give back a line enabled for `target` (what `boot_hooks::kernel_line_enable`
/// returned): the IRQ thread lets go of it (a late event finds no binding,
/// and its ACK unmasks nothing), the controller masks it on the context it
/// was enabled on, whichever CPU this runs on, and it is no longer the
/// kernel's, so ring 3 may be granted it. The driver stops naming the line
/// after this (the caller's next step), so an event already latched is still
/// recognised meanwhile.
pub(crate) fn unwire_line(line: u32, target: u32) {
    crate::irq_thread::unregister(line);
    crate::boot_hooks::kernel_line_release(line, target);
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

#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
fn line_of(_slot: usize, _base: usize) -> Option<u32> {
    None
}

/// Enable a kernel driver's line on this CPU (`boot_hooks::kernel_line_enable`,
/// each ISA's): `false` when the controller would not.
pub(super) fn enable_line(line: u32) -> bool {
    crate::boot_hooks::kernel_line_enable(line).is_some()
}
