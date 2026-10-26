// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The interrupt controllers of this ISA: the PLIC, and the AIA pair (APLIC
//! for wired sources, IMSIC for message-signalled ones), and how the timer
//! comparator is programmed (`clint`).
//!
//! Every ISA crate has an `irq` module holding its controller code
//! (aarch64: GIC, ITS; x86_64: LAPIC, IOAPIC), so a reader finds the chip at
//! `azos_arch::irq::<chip>` whichever ISA is built. Which of PLIC and AIA a
//! boot uses is `azos_drv_irqchip::irqchip`'s decision, made from the device
//! tree.

pub mod aplic;
pub mod clint;
pub mod imsic;
pub mod plic;

/// The hardware hart id (`mhartid`) of logical CPU `cpu`: how the AIA names a
/// hart (the APLIC target's hart index, the IMSIC file index). The kernel's
/// `hart` arguments are logical ids (`tp`); `azos_percpu` holds the map the
/// boot built from the device tree. A CPU the map lacks (nothing installed
/// yet) keeps its logical id.
pub(crate) fn hw_hart(cpu: u32) -> u32 {
    azos_percpu::hw_id(cpu as usize).map_or(cpu, |h| h as u32)
}
