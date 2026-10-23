// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the CPU needs to take a trap: the GDT/TSS and the IDT, as pure
//! encoders and tables (the instructions that load them are `cpu`'s), and
//! the TSS I/O permission bitmap a ring-3 port access is checked against.

/// GDT and TSS: the per-CPU segment table.
pub mod gdt;
/// IDT: vector numbering, the exception table, the gate encoder.
pub mod idt;
/// Ring-3 port I/O: the TSS I/O permission bitmap and its switch.
pub mod iomap;
