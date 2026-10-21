// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The interrupt controllers of this ISA: the GICv3 and its ITS, or a GICv2
//! (GIC-400) when the device tree names one.
//!
//! Every ISA crate has an `irq` module holding its controller code
//! (riscv64: PLIC, APLIC, IMSIC; x86_64: LAPIC, IOAPIC), so a reader finds
//! the chip at `azos_arch::irq::<chip>` whichever ISA is built.

pub mod gic;
/// GICv2 (GIC-400, Cortex-A15 GIC): a distributor and a memory-mapped CPU
/// interface, selected at boot from the device tree. `gic` hands over to it.
pub mod gicv2;
/// GICv3 ITS — PCI MSI/MSI-X → LPI delivery. See the module doc for scope
/// (one collection, direct device table, no Indirect).
pub mod its;
