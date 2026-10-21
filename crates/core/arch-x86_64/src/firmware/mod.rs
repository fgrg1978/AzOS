// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the firmware hands over: the boot information (PVH start info,
//! Limine responses) and the ACPI tables. The counterpart of riscv64's SBI
//! and aarch64's PSCI `firmware.rs`; pure parsers, host-tested through
//! `#[path]` (`tests/host/x86-platform-tests`).

/// ACPI tables: RSDP, MADT, SRAT/SLIT/PPTT, DMAR/IVRS.
pub mod acpi;
/// The PVH start info and the memory map every boot protocol is converted to.
pub mod bootinfo;
/// System suspend (ACPI S3): where it is available, and why not.
pub mod suspend;
pub use suspend::SystemSuspendMissing;
/// The Limine boot protocol's responses, converted to the same shapes.
pub mod limine;

/// Whether the kernel can suspend this machine to RAM: the platform's FADT
/// through [`suspend::s3_available`]. The same name and shape as riscv64's
/// and aarch64's.
pub fn system_suspend_support() -> Result<(), SystemSuspendMissing> {
    suspend::s3_available(crate::platform_impl::platform().acpi.fadt.as_ref())
}
