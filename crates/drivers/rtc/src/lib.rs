// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]
//! Real-time clock drivers: the [`Rtc`] trait and the four chips behind it.
//!
//! | Chip | Where | Time as | Module |
//! |---|---|---|---|
//! | goldfish RTC (`google,goldfish-rtc`) | QEMU `virt`, riscv64 | 64-bit nanoseconds | [`goldfish`] |
//! | PL031 (`arm,pl031`) | QEMU `virt`, aarch64 | 32-bit seconds | [`pl031`] |
//! | MC146818 CMOS clock | every PC, x86_64 | BCD or binary calendar | [`mc146818`] |
//! | PCF8563 | boards, over I2C | BCD calendar | [`pcf8563`] |
//!
//! Every chip reads and sets **UTC seconds since 1970-01-01** (the same count
//! `azos_abi::time` calls the Unix second); a chip that keeps a calendar goes
//! through [`civil`]. A sub-second part is dropped on a read and zero on a set:
//! an RTC is the clock the machine had before any reference, good for seconds.
//!
//! The crate is pure: no unsafe, no statics, no allocation, no clock. The
//! environment hands each chip what it reaches the hardware through: an
//! [`Mmio`] window (goldfish, PL031), the [`Ports`] of a PC (MC146818) or an
//! [`I2c`] bus (PCF8563). The kernel's adapters are `kernel/src/boot/rtc.rs`;
//! `tests/host/drivers-tests` runs each chip against a model that behaves like
//! it.
//!
//! **What a chip says about itself is the chip's; what the time is worth is
//! not.** A chip that knows its time is gone (a PCF8563 whose oscillator
//! stopped, a CMOS whose battery died, a calendar that is not a date) answers
//! [`Error::Lost`]. A chip that holds a wrong but valid-looking time (a dead
//! battery that reset it to 2000, a clock nobody ever set) is read as it is:
//! the floor under which the kernel does not believe it is Kconfig
//! `RTC_FLOOR_YEAR`, applied by the boot step, not here.

pub mod civil;
pub mod goldfish;
pub mod mc146818;
pub mod pcf8563;
pub mod pl031;

/// Why a chip did not give or take a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The chip says its time cannot be trusted (power lost, oscillator
    /// stopped, a register that is not a date), or has none to give.
    Lost,
    /// The bus did not complete the transfer, or the chip never settled.
    Bus,
    /// The time does not fit the chip: before 1970, past the year the chip
    /// counts to, or a calendar chip outside 2000..=2099.
    Range,
    /// The window answers, but not as this chip.
    NoDevice,
}

/// A real-time clock.
pub trait Rtc {
    /// The chip's name, for the boot line.
    fn name(&self) -> &'static str;
    /// UTC seconds since 1970-01-01.
    fn read(&mut self) -> Result<u64, Error>;
    /// Set the chip to `unix_secs`. The chip counts on from the instant of the
    /// write.
    fn set(&mut self, unix_secs: u64) -> Result<(), Error>;
}

/// A 32-bit register window: `off` is the byte offset from the window's base.
pub trait Mmio {
    fn read32(&mut self, off: u32) -> u32;
    fn write32(&mut self, off: u32, v: u32);
}

/// The I/O ports of a PC.
pub trait Ports {
    fn inb(&mut self, port: u16) -> u8;
    fn outb(&mut self, port: u16, v: u8);
}

/// An I2C bus, seen as register reads and writes of one device.
pub trait I2c {
    /// Read `buf.len()` bytes from `addr` starting at register `reg`.
    fn read_regs(&mut self, addr: u8, reg: u8, buf: &mut [u8]) -> Result<(), Error>;
    /// Write `data` to `addr`: the first byte is the register.
    fn write_regs(&mut self, addr: u8, data: &[u8]) -> Result<(), Error>;
}

/// Nanoseconds in a second.
pub const NS_PER_SEC: u64 = 1_000_000_000;
