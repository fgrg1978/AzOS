// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Spi` interface: one chip select on one bus.
//!
//! The endpoint's badge is `bus << 8 | cs` (`endpoint = "spi.0.1"`): the
//! capability names the device, so a task that holds the flash on chip select
//! 0 cannot clock bytes into the LIDAR on chip select 1. There is no
//! observe-only SPI op: the first byte on the wire is a command the device
//! acts on (a flash erase or program opcode is as good a "register" as a status
//! read), so every op that puts bytes on the wire, `read` included, needs
//! `WRITE`. `EXEC` configures the port (mode and speed change the electrical
//! contract with the device, so they are not a write). A task that only
//! observes a part (its identity, a sample) does it through the higher-level
//! interface of that part, never through raw SPI.
//!
//! A transfer is at most [`MAX_BYTES`] bytes, the same bound as the I2C
//! interface: the data travels inline in the message and the bound is the
//! message's. Bulk data (a flash image, a LIDAR scan) does not belong here; it
//! travels on a ring the board's stream owns.
//!
//! # Failure contract
//!
//! `transfer`, `write` and `read` clock bytes into a device that may act on
//! them (a flash page program, a CAN controller command): a lost reply must not
//! make the client send them again, so all three are `once_only`, and a bus
//! that does not answer is reported (`FAULT`) and the client carries on without
//! the device (`degrade`). The configuration ops are idempotent.
//!
//! # Setup
//!
//! Mode, clock and chip-select hold belong to a chip select. A controller is
//! shared by every chip select of its bus, so the port applies its chip
//! select's setup before each transfer and serialises the bus.

use crate::i2c::Bytes;
use crate::outcome::Out;
use azos_idl::azos_interface;

/// The interface id (ASCII "SPI ").
pub const SPI_ID: u32 = 0x5350_4920;

/// Most bytes one transfer carries (the I2C interface's bound).
pub const MAX_BYTES: usize = crate::i2c::MAX_BYTES;
/// SPI modes: 0..=3, `CPOL << 1 | CPHA`.
pub const MODES: u32 = 4;
/// Slowest clock a port accepts, Hz.
pub const SPEED_MIN_HZ: u32 = 1_000;
/// Fastest clock a port accepts, Hz.
pub const SPEED_MAX_HZ: u32 = 50_000_000;
/// The clock of a port nobody has configured, Hz.
pub const SPEED_DEFAULT_HZ: u32 = 1_000_000;

/// The badge of chip select `cs` on `bus`.
pub const fn badge(bus: u8, cs: u8) -> u32 {
    ((bus as u32) << 8) | cs as u32
}

/// The bus and the chip select a badge names.
pub const fn unbadge(badge: u32) -> (u8, u8) {
    ((badge >> 8) as u8, badge as u8)
}

#[azos_interface(id = 0x5350_4920, level = 1)]
pub trait Spi {
    /// Full duplex: clock `data` (1..=[`MAX_BYTES`] bytes, else
    /// `BAD_ARGUMENT`) out and answer the bytes clocked in, as many as were
    /// sent. `NO_RESOURCE` when no device answers the chip select, `FAULT`
    /// when the bus transfer failed. Needs `WRITE`.
    #[once_only]
    #[on_failure(degrade)]
    #[deadline_ns = 5_000_000]
    #[budget_us = 500]
    fn transfer(&mut self, data: Bytes) -> Out<Bytes>;
    /// Clock `data` out and discard what comes in. Same bounds and refusals as
    /// `transfer`. Needs `WRITE`.
    #[once_only]
    #[on_failure(degrade)]
    #[deadline_ns = 5_000_000]
    #[budget_us = 500]
    fn write(&mut self, data: Bytes) -> Out<()>;
    /// Send the byte `reg` (0..=255, else `BAD_ARGUMENT`) and read `len`
    /// (1..=[`MAX_BYTES`], else `BAD_ARGUMENT`) bytes after it. `reg` goes on
    /// the wire as given and the device may take it for any command, so this
    /// is `transfer` with a one-byte request: it needs `WRITE`.
    #[once_only]
    #[on_failure(degrade)]
    #[deadline_ns = 5_000_000]
    #[budget_us = 500]
    fn read(&mut self, reg: u32, len: u32) -> Out<Bytes>;
    /// Set the clock mode (`0..`[`MODES`], else `BAD_ARGUMENT`). `UNSUPPORTED`
    /// when the controller cannot run it. Needs `EXEC`.
    #[idempotent]
    fn set_mode(&mut self, mode: u32) -> Out<()>;
    /// Set the clock ([`SPEED_MIN_HZ`]..=[`SPEED_MAX_HZ`], else
    /// `BAD_ARGUMENT`). `UNSUPPORTED` when the controller cannot run it.
    /// Needs `EXEC`.
    #[idempotent]
    fn set_speed(&mut self, hz: u32) -> Out<()>;
    /// Keep the chip select asserted between calls (`true`) so several
    /// transfers are one transaction, or give it back (`false`). `UNSUPPORTED`
    /// when the controller releases it after every transfer. Needs `WRITE`.
    #[idempotent]
    fn hold_cs(&mut self, hold: bool) -> Out<()>;
}
