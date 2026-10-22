// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Which interrupt controller a boot uses and who owns each external line.
//!
//! The controllers themselves — PLIC, APLIC, IMSIC; GIC, ITS; LAPIC, IOAPIC —
//! are code for one ISA each and live in that ISA's crate, `azos_arch::irq`.
//! What is left here is above them: the PLIC-or-AIA choice a riscv64 boot
//! makes from the device tree (`irqchip`), the GICv3-or-GICv2 choice an
//! aarch64 boot makes from it (`gic`), and ring-3 ownership of external
//! lines, mask-until-ACK (`user_irq`). `irqchip` and `user_irq` call each
//! other, so they share one crate.

#![no_std]
#![forbid(unsafe_code)]

// arch-only: PLIC or AIA is a RISC-V device-tree decision; x86_64 has one
// controller and no selection to make.
#[cfg(target_arch = "riscv64")]
pub mod irqchip;

/// MSI identities requested for a hart that is not up yet. Pure, so it builds
/// everywhere (host tests); `irqchip` is its user.
pub mod msi_pending;

/// GICv3 or GICv2: what an aarch64 device-tree node names. Pure, so it builds
/// everywhere (host tests).
pub mod gic;

/// Ring-3 ownership of riscv64 external interrupt lines (mask-until-ACK).
/// The bitmaps build everywhere (host tests); the controller half is
/// riscv64-only.
pub mod user_irq;
