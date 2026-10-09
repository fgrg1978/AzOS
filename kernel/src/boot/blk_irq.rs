// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! virtio-blk completion by interrupt (wave 15), on every ISA.
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
fn blk_block_until(deadline: u64) -> bool {
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
fn blk_wake(tid: u32) {
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
}

#[cfg(target_arch = "riscv64")]
fn line_of(slot: usize, _base: usize) -> Option<u32> {
    Some(azos_drv_base::platform::hw::VIRTIO_IRQ_BASE + slot as u32)
}

#[cfg(target_arch = "riscv64")]
fn enable_line(irq: u32) -> bool {
    let hart = azos_arch::Cpu::hart_id(&azos_arch::ARCH) as u32;
    let _ = azos_drv_irqchip::irqchip::wire_aia_source(irq, hart);
    azos_drv_irqchip::irqchip::enable_irq(hart, irq);
    true
}

#[cfg(target_arch = "aarch64")]
fn line_of(slot: usize, _base: usize) -> Option<u32> {
    Some(azos_drv_base::platform::hw::VIRTIO_IRQ_BASE + slot as u32)
}

#[cfg(target_arch = "aarch64")]
fn enable_line(intid: u32) -> bool {
    let mpidr = azos_arch::mpidr::read_mpidr().raw;
    azos_arch::gic::route_spi(intid, mpidr, false);
    true
}

#[cfg(target_arch = "x86_64")]
fn line_of(_slot: usize, base: usize) -> Option<u32> {
    azos_arch::platform_impl::platform().virtio_gsi(base as u64)
}

#[cfg(target_arch = "x86_64")]
fn enable_line(gsi: u32) -> bool {
    azos_drv_irqchip::user_irq::mark_kernel(gsi);
    azos_arch::ioapic::set_masked(gsi, false)
}

#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
fn line_of(_slot: usize, _base: usize) -> Option<u32> {
    None
}

#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
fn enable_line(_line: u32) -> bool {
    false
}
