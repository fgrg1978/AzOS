// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The GPIO controllers the `Gpio` interface serves, by controller number
//! (the badge's `ctrl`, `azos_devif::gpio::badge`).
//!
//! Controller 0 is the board's ([`crate::gpio`]): the e-stop's and the
//! motors' pins are on it, and the kernel drives those through its free
//! functions, lock-free, never through this table. A second controller (an
//! expander, a companion chip's bank) registers here from its driver's probe
//! and withdraws from its unbind. How many the kernel keeps is Kconfig
//! `GPIO_CONTROLLERS`.

use crate::gpio::{self, GpioDir};
use crate::instances::Instances;
pub use crate::instances::{DeviceId, Lease, RegisterError, UnregisterError};

/// A controller's op failed: the pin is not usable as asked (not an output,
/// held by the kernel's stop, unread), or the controller is not bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault;

/// One GPIO controller.
///
/// An op runs on a [`Lease`] with no lock held, so the controller may be
/// called from several harts at once. Its driver's unbind withdraws it with
/// [`unregister`], which returns only when no op is inside it: after that
/// the driver may power the device down, and no op reaches it again.
pub trait GpioChip: Sync {
    /// Its pins, `0..pins()`.
    fn pins(&self) -> u32;
    /// The level of `pin`, 0 or 1.
    fn read(&self, pin: u32) -> Result<u32, Fault>;
    /// Drive output `pin` to `level` (the low bit).
    fn write(&self, pin: u32, level: u32) -> Result<(), Fault>;
    /// Make `pin` an input or an output.
    fn set_dir(&self, pin: u32, dir: GpioDir) -> Result<(), Fault>;
    /// May an op of this controller sleep (a transfer on a bus that waits for
    /// its completion)? `false` only for a controller whose every op is a
    /// bounded register access: an io_ring pass serves its pins
    /// (`OP_CALL`), and a controller that may sleep is the typed call's.
    fn may_sleep(&self) -> bool;
}

/// The board's controller, through the backend the board selects.
struct Board;

fn done(rc: i32) -> Result<(), Fault> {
    if rc == 0 { Ok(()) } else { Err(Fault) }
}

impl GpioChip for Board {
    fn pins(&self) -> u32 {
        gpio::GPIO_MAX_PINS as u32
    }
    fn read(&self, pin: u32) -> Result<u32, Fault> {
        u32::try_from(gpio::gpio_read(pin)).map_err(|_| Fault)
    }
    fn write(&self, pin: u32, level: u32) -> Result<(), Fault> {
        done(gpio::gpio_write(pin, level & 1))
    }
    fn set_dir(&self, pin: u32, dir: GpioDir) -> Result<(), Fault> {
        done(gpio::gpio_set_direction(pin, dir))
    }
    fn may_sleep(&self) -> bool {
        false
    }
}

static BOARD: Board = Board;

static CHIPS: Instances<dyn GpioChip, { azos_limits::GPIO_CONTROLLERS as usize }> = Instances::with_board(&BOARD);

/// Controller `ctrl`, if one is registered: held for the op while the lease
/// lives.
pub fn chip(ctrl: u32) -> Option<Lease<'static, dyn GpioChip>> {
    CHIPS.get(ctrl)
}

/// Register bound device `dev`'s controller; its controller number.
pub fn register(dev: DeviceId, ctrl: &'static dyn GpioChip) -> Result<u32, RegisterError> {
    CHIPS.register(dev, ctrl)
}

/// Withdraw device `dev`'s controller once no op is inside it; the number it
/// had. `patience` says how long to wait for the ops in flight.
pub fn unregister(dev: DeviceId, patience: &mut dyn FnMut() -> bool) -> Result<u32, UnregisterError> {
    CHIPS.unregister(dev, patience)
}

/// How many controllers are registered.
pub fn count() -> usize {
    CHIPS.count()
}
