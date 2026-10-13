// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! virtio-input events by interrupt, on every ISA (Kconfig `DRV_VIRTIO_INPUT`).
//!
//! The hardware bus bound the input driver (`azos_drv_virtio::virtio::input`)
//! to the virtio-mmio devices it admits, which posted their event buffers; this maps each slot to
//! its interrupt line (the same per-ISA mapping the block device and the NIC
//! use), routes the line to the boot CPU and hands the driver the line. Each
//! ISA's external-interrupt arm then calls `input::irq`, which reaps the
//! events: key presses become bytes in the console's RX ring (the user
//! shell reads a virtio keyboard with no UART input), the rest is published
//! to the driver's event ring, the Phase 7 input server's hook.

use crate::kprintln;

/// Bring up every virtio-input device and take its events by interrupt. A
/// no-op without one (the usual case: nothing prints), or where the
/// transport has no routable line (the device is then left idle).
pub(crate) fn wire_virtio_input_irq() {
    // The hardware bus brings up the input devices it admits, in task context
    // and before any line is enabled: this is their stage.
    crate::boot::hwbus::bind(&["virtio-input"]);
    // The last stage: whatever the rules now in force did not let it bind is
    // settled, and the bus reports.
    crate::boot::hwbus::settle(&[]);
    let n = azos_drv_virtio::virtio::input::device_count();
    for i in 0..n {
        let Some((slot, base, kind)) = azos_drv_virtio::virtio::input::device(i) else { continue };
        let Some(line) = crate::boot_hooks::virtio_mmio_line(slot, base) else {
            kprintln!("[VIRTIO-INPUT] no interrupt line for slot {}: idle", slot);
            continue;
        };
        // The handler must know the line (and the device's stale interrupt be
        // acknowledged) before the controller enables it.
        if !azos_drv_virtio::virtio::input::set_irq_line(i, line) {
            continue;
        }
        if !enable_line(line) {
            kprintln!("[VIRTIO-INPUT] line {} not routable: idle", line);
            continue;
        }
        kprintln!("[VIRTIO-INPUT] {} events by interrupt on line {} (slot {})",
            kind.name(), line, slot);
        crate::irq_thread::register(line);
    }
}

#[cfg(target_arch = "riscv64")]
fn enable_line(irq: u32) -> bool {
    let hart = azos_arch::Cpu::hart_id(&azos_arch::ARCH) as u32;
    let _ = azos_drv_irqchip::irqchip::wire_aia_source(irq, hart);
    azos_drv_irqchip::irqchip::enable_irq(hart, irq);
    true
}

#[cfg(target_arch = "aarch64")]
fn enable_line(intid: u32) -> bool {
    let mpidr = azos_arch::mpidr::read_mpidr().raw;
    azos_arch::gic::route_spi(intid, mpidr, false);
    true
}

#[cfg(target_arch = "x86_64")]
fn enable_line(gsi: u32) -> bool {
    azos_drv_irqchip::user_irq::mark_kernel(gsi);
    azos_arch::ioapic::set_masked(gsi, false)
}

#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
fn enable_line(_line: u32) -> bool {
    false
}
