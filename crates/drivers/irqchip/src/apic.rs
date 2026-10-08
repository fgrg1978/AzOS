// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! LAPIC / IOAPIC — x86_64 port SKELETON, the counterpart of `plic`/`aplic`/
//! `imsic`/`irqchip` (riscv64) and the GIC in `azos_arch_aarch64::gic`.
//! Every body is a `todo!()` naming the mechanism; nothing here runs.
//!
//! * The LAPIC is per-CPU (x2APIC: MSRs 0x800+, Kconfig `X86_X2APIC`; else MMIO
//!   at IA32_APIC_BASE): spurious vector, TPR, EOI, the timer
//!   (TSC-deadline) and IPIs (ICR).
//! * IOAPICs (addresses and GSI bases from the ACPI MADT) route external
//!   lines: one 64-bit redirection entry per GSI (vector, destination APIC
//!   ID, mask, trigger/polarity from the MADT interrupt source overrides).
//! * MSI/MSI-X (PCIe) target a LAPIC directly (address 0xFEEx_xxxx).

/// This CPU's LAPIC: enable (x2APIC mode), spurious vector, TPR 0.
pub fn init(_hart: u32) {
    todo!("x86_64: apic::init: x2APIC enable via IA32_APIC_BASE, SVR, TPR 0")
}

/// Record the CPU external lines go to by default (the IOAPIC destination).
pub fn set_boot_hart(_hart: u32) {
    todo!("x86_64: apic::set_boot_hart: default IOAPIC destination APIC ID")
}

/// This CPU may now be a ring-3 line's destination.
pub fn hart_ready(_hart: u32) {
    todo!("x86_64: apic::hart_ready: CPU joins the IOAPIC destination set")
}

/// Route GSI `irq` to CPU `hart` (`edge`: trigger mode, else the MADT's).
pub fn bind(_irq: u32, _hart: u32, _edge: Option<bool>) -> bool {
    todo!("x86_64: apic::bind: IOAPIC redirection entry (vector, dest APIC ID, trigger)")
}

/// Mask GSI `irq` (redirection entry bit 16).
pub fn mask(_irq: u32) {
    todo!("x86_64: apic::mask: IOAPIC RTE mask bit")
}

/// Unmask GSI `irq`.
pub fn unmask(_irq: u32) {
    todo!("x86_64: apic::unmask: IOAPIC RTE mask bit clear")
}

/// Return GSI `irq` to its masked, unrouted state.
pub fn release(_irq: u32) {
    todo!("x86_64: apic::release: mask and reset the RTE")
}
