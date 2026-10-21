// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The virtio-sound device's completions by interrupt, on every ISA (Kconfig
//! `DRV_VIRTIO_SND`).
//!
//! The hardware bus brings the device up (`virtio-snd` for a virtio-mmio
//! window, in the settle stage; `virtio-snd-pci` for a PCI function, with its
//! MSI-X vector routed, in the PCI stage): `azos_drv_virtio::virtio::snd`
//! reads the device and opens nothing. What only exists once the scheduler
//! does is done here: the driver is handed the block and wake hooks the disk
//! driver uses (a control request then sleeps until the interrupt instead of
//! polling), and a virtio-mmio device's line is routed to the boot CPU and
//! given to the driver, exactly as `input_irq.rs` does for the input devices.
//!
//! The interrupt handlers take no lock: [`line`] and [`msi`] ask the driver
//! whether the interrupt is its, which acknowledges the device and says
//! whether a stream is open, and then wake the device pump
//! (`azos_syscall::devices::wake_pump`), the task that reaps the completed
//! periods and returns them to the clients (`sound_host::pump`).

use crate::kprintln;

/// Hand the driver the scheduler's sleep and wake, and take a virtio-mmio
/// device's completions by interrupt. A no-op without a sound device, and for
/// a PCI one (its vector was armed when the bus bound it) beyond the hooks.
pub(crate) fn wire_virtio_snd_irq() {
    use azos_drv_virtio::virtio::snd;
    if snd::caps().is_none() {
        return;
    }
    snd::set_hooks(crate::boot::blk_block_until, crate::boot::blk_wake);
    let Some(base) = snd::mmio_window() else { return };
    use azos_drv_virtio::virtio::{VIRTIO_MMIO_BASE, VIRTIO_MMIO_STRIDE};
    let Some(slot) = base.checked_sub(VIRTIO_MMIO_BASE).map(|off| off / VIRTIO_MMIO_STRIDE) else {
        kprintln!("[VIRTIO-SND] window {:#x} is no virtio-mmio slot: polled", base);
        return;
    };
    let Some(line) = crate::boot_hooks::virtio_mmio_line(slot, base) else {
        kprintln!("[VIRTIO-SND] no interrupt line for slot {}: polled", slot);
        return;
    };
    // The handler must know the line (and the device's stale interrupt be
    // acknowledged) before the controller enables it.
    if !snd::set_irq_line(line) {
        return;
    }
    if !super::blk_irq::enable_line(line) {
        kprintln!("[VIRTIO-SND] line {} not routable: polled", line);
        return;
    }
    kprintln!("[VIRTIO-SND] completions by interrupt on line {} (slot {})", line, slot);
    crate::irq_thread::register(line);
}

/// A kernel line (a virtio-mmio slot's interrupt): `None` when it is not the
/// sound device's; otherwise the device is acknowledged and the pump woken
/// when a stream is open. `true` when a task was made ready.
pub(crate) fn line(line: u32) -> Option<bool> {
    let open = azos_drv_virtio::virtio::snd::irq(line)?;
    Some(open && azos_syscall::devices::wake_pump())
}

/// A PCI vector (`token`: what the interrupt controller reports for it):
/// `None` when it is not the sound device's.
pub(crate) fn msi(token: u32) -> Option<bool> {
    let open = azos_drv_virtio::virtio::snd::msi_irq(token)?;
    Some(open && azos_syscall::devices::wake_pump())
}
