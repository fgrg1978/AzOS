// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! LAPIC / IOAPIC behind `user_irq` (ring-3 line ownership), the x86_64
//! counterpart of `plic`/`aplic`/`imsic` (riscv64) and the GIC in
//! `azos_arch_aarch64::gic`. The chips themselves are
//! `azos_arch::{apic, ioapic}`: here only the ownership bookkeeping and
//! the routing call.
//!
//! * The LAPIC is per-CPU (x2APIC or xAPIC MMIO), brought up by the boot
//!   hooks (`apic::init_local`).
//! * A ring-3 line is an IOAPIC GSI: one redirection entry (vector =
//!   `IRQ_VECTOR_BASE` + GSI, destination = the hart's APIC ID, trigger
//!   from the binder, else the MADT override / virtio / ISA / PCI default).
//! * MSI/MSI-X target a LAPIC directly (`azos_arch::apic::msi`).

use azos_arch::ioapic;

/// This CPU's LAPIC (the boot hooks already do this; kept for callers that
/// bring a hart up through the irqchip API).
pub fn init(hart: u32) {
    azos_arch::apic::init_local(hart as usize)
}

/// The boot CPU takes external lines from now on.
pub fn set_boot_hart(hart: u32) {
    hart_ready(hart)
}

/// This CPU may now be a ring-3 line's destination.
pub fn hart_ready(hart: u32) {
    crate::user_irq::note_hart_ready(hart)
}

/// Take GSI `irq` for ring 3 and route it to `hart` (`edge`: the binder's
/// trigger, else the line's default), unmasked.
pub fn bind(irq: u32, hart: u32, edge: Option<bool>) -> bool {
    if !crate::user_irq::mark(irq) {
        return false;
    }
    let dest = azos_arch::platform_impl::platform().apic_id(hart as usize);
    let (level, active_low) = ioapic::default_trigger(irq);
    let level = edge.map_or(level, |e| !e);
    let routed = dest.is_some_and(|d| ioapic::route(irq, d, level, active_low, false));
    if !routed {
        let _ = crate::user_irq::unmark(irq);
        return false;
    }
    crate::user_irq::set_route(irq, hart);
    true
}

/// Mask GSI `irq` (redirection entry bit 16).
pub fn mask(irq: u32) {
    ioapic::set_masked(irq, true);
}

/// Unmask GSI `irq`.
pub fn unmask(irq: u32) {
    ioapic::set_masked(irq, false);
}

/// Return a ring-3 GSI to its masked, unrouted state and drop the
/// ownership (riscv64's `release`); a line ring 3 does not own is untouched.
pub fn release(irq: u32) {
    if !crate::user_irq::owned(irq) {
        return;
    }
    ioapic::release(irq);
    let _ = crate::user_irq::unmark(irq);
}
