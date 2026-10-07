// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Interrupt controllers: PLIC, AIA (APLIC + IMSIC) and the selection between
//! them (`irqchip`), ring-3 ownership of external lines (`user_irq`), and the
//! CLINT (machine timer compare and software interrupts).
//!
//! `irqchip`, `plic` and `user_irq` call each other, so they share one crate.

#![no_std]

// PLIC (Platform-Level Interrupt Controller) — RISC-V only. aarch64 uses
// the GIC instead (`azos_arch_aarch64::gic`), a different enough
// register model that there is no shared abstraction to route this
// through yet (RFC-0045 aarch64 track); see `crates/core/syscall/src/dispatch.rs`
// SYS_DRV_IRQ_ACK for the one caller outside this crate that is gated to
// match.
#[cfg(target_arch = "riscv64")]
pub mod plic;

#[cfg(target_arch = "riscv64")]
pub mod aplic;

#[cfg(target_arch = "riscv64")]
pub mod imsic;

#[cfg(target_arch = "riscv64")]
pub mod irqchip;

// x86_64 skeleton (and any further ISA): LAPIC + IOAPIC. aarch64's GIC lives
// in its arch crate, so it has no arm here.
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
pub mod apic;

/// Ring-3 ownership of riscv64 external interrupt lines (mask-until-ACK).
/// The bitmaps build everywhere (host tests); the controller half is
/// riscv64-only.
pub mod user_irq;

pub mod clint;
