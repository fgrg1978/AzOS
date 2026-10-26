// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The interrupt controllers of this ISA: the LAPIC (per CPU, with the MSI
//! vector pool) and the IOAPIC (device lines, by GSI).
//!
//! Every ISA crate has an `irq` module holding its controller code
//! (riscv64: PLIC, APLIC, IMSIC; aarch64: GIC, ITS), so a reader finds the
//! chip at `azos_arch::irq::<chip>` whichever ISA is built.

/// The LAPIC (per CPU).
pub mod apic;
/// The IOAPIC (device lines, by GSI).
pub mod ioapic;
/// The pure half: the vector map, LAPIC/IOAPIC/MSI register words and the
/// clock conversions (host-tested through `#[path]`).
pub mod encode;
