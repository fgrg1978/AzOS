// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The chip's memory-mapped regions: what a `mmio.N` capability of the
//! topology names. Index N is a position in this table, the way the main
//! kernel indexes its board's MMIO table (`mmio_cap.rs`), so a topology
//! row means the same thing as long as the chip is the same. A new chip is a
//! new `MICRO_CHIP_*` member (`config/Kconfig.micro`) and a new table.

use crate::pmp_core::{R, W};

/// One device window.
#[derive(Clone, Copy, Debug)]
pub struct Mmio {
    /// First byte.
    pub base: usize,
    /// Length in bytes.
    pub size: usize,
    /// Rights a capability may carry for it (`pmp_core::{R, W}`).
    pub perm: u8,
}

/// QEMU virt: the 16550 console UART and the test finisher (writing a magic
/// value powers the machine off; a task that holds it can end the run).
pub const MMIO: [Mmio; 2] = [
    Mmio { base: azos_limits::MICRO_UART_BASE, size: 0x100, perm: R | W },
    Mmio { base: 0x0010_0000, size: 0x1000, perm: W },
];
