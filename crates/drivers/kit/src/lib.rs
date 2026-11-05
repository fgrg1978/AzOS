// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What a driver reaches the machine through, as three traits the driver is
//! written over: [`Mmio`] (a block of device registers), [`PortIo`] (x86 port
//! space) and [`Ticks`] (the time a bounded wait is measured in).
//!
//! The traits are pure and always present. An implementation exists only where
//! the machine has the thing: [`Window`] (feature `window`) is the one
//! [`Mmio`] of the kernel and of a ring-3 driver, over
//! `azos_arch_api::mmio`; a port space has an implementer on x86_64 only, the
//! kernel's and the ring-3 host's own adapters over the grants they hold.
//! A driver generic over the traits compiles and is host-tested on every ISA;
//! with the implementation inlined it is the same code as one that spelled
//! the access out.
//!
//! The fakes (feature `fake`) are what `tests/host` drives a driver through: a
//! register file backed by an array, a port space with scripted reads, a clock
//! that moves on each read. All of them log every access, so a test asserts
//! the register sequence a driver produced, not only its result.

#![no_std]

#[cfg(feature = "fake")]
extern crate alloc;

#[cfg(feature = "fake")]
pub mod fake;
#[cfg(feature = "window")]
mod window;
#[cfg(feature = "window")]
pub use window::Window;

/// How many bytes one register access moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    W8,
    W16,
    W32,
    W64,
}

impl Width {
    pub const fn bytes(self) -> usize {
        match self {
            Width::W8 => 1,
            Width::W16 => 2,
            Width::W32 => 4,
            Width::W64 => 8,
        }
    }
}

macro_rules! typed_accessors {
    ($($t:ty, $read:ident, $write:ident, $w:ident;)*) => {$(
        #[inline(always)]
        fn $read(&self, off: usize) -> $t {
            self.load(off, Width::$w) as $t
        }
        #[inline(always)]
        fn $write(&self, off: usize, v: $t) {
            self.store(off, Width::$w, v as u64)
        }
    )*};
}

/// A block of device registers: `off` is the byte offset from the block's
/// base, aligned to the access width. An implementer provides the two
/// accesses; every `read*`/`write*` is exactly one access of that width, so a
/// driver that means a 32-bit register never reads it as four bytes, and with
/// the width a constant the match inside `load`/`store` folds away.
pub trait Mmio {
    /// One read of `w` bytes at `off`, zero-extended.
    fn load(&self, off: usize, w: Width) -> u64;
    /// One write of the low `w` bytes of `v` at `off`.
    fn store(&self, off: usize, w: Width, v: u64);
    /// The address the block is mapped at: what the DMA registry names the
    /// device by. A fake has the address its test gives it.
    fn base(&self) -> usize;

    typed_accessors! {
        u8,  read8,  write8,  W8;
        u16, read16, write16, W16;
        u32, read32, write32, W32;
        u64, read64, write64, W64;
    }
}

impl<T: Mmio + ?Sized> Mmio for &T {
    #[inline(always)]
    fn load(&self, off: usize, w: Width) -> u64 {
        (**self).load(off, w)
    }
    #[inline(always)]
    fn store(&self, off: usize, w: Width, v: u64) {
        (**self).store(off, w, v)
    }
    #[inline(always)]
    fn base(&self) -> usize {
        (**self).base()
    }
}

/// The x86 I/O port space. Other ISAs have no port space and no implementer.
pub trait PortIo {
    fn inb(&self, port: u16) -> u8;
    fn outb(&self, port: u16, v: u8);
}

impl<T: PortIo + ?Sized> PortIo for &T {
    #[inline(always)]
    fn inb(&self, port: u16) -> u8 {
        (**self).inb(port)
    }
    #[inline(always)]
    fn outb(&self, port: u16, v: u8) {
        (**self).outb(port, v)
    }
}

/// A monotonic clock a driver bounds its waits by.
pub trait Ticks {
    /// The count now. Never goes back; wraps after 2^64 ticks.
    fn now(&self) -> u64;
    /// Ticks per second.
    fn freq_hz(&self) -> u64;

    /// `us` microseconds in ticks, rounded up, saturating.
    fn ticks_for_us(&self, us: u64) -> u64 {
        (us as u128 * self.freq_hz() as u128).div_ceil(1_000_000).min(u64::MAX as u128) as u64
    }

    /// Poll `done` until it is true or `us` microseconds have passed. `done` is
    /// polled at least once, and once more after the deadline, so a wait that
    /// is descheduled past its bound still sees an event that happened inside
    /// it. True when `done` was seen.
    fn wait_us(&self, us: u64, mut done: impl FnMut() -> bool) -> bool {
        let start = self.now();
        let span = self.ticks_for_us(us);
        loop {
            if done() {
                return true;
            }
            if self.now().wrapping_sub(start) >= span {
                return done();
            }
        }
    }
}

impl<T: Ticks + ?Sized> Ticks for &T {
    #[inline(always)]
    fn now(&self) -> u64 {
        (**self).now()
    }
    #[inline(always)]
    fn freq_hz(&self) -> u64 {
        (**self).freq_hz()
    }
}
