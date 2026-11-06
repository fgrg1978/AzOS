// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The controllers of a class by instance number (`instances.rs`), the GPIO
//! class over it (`chips.rs`) and the soft expander (`expander.rs`), the real
//! files.
//!
//! The class's table is a process-wide static: only
//! `the_gpio_class_keeps_kconfig_gpio_controllers_controllers` touches it, and
//! the other tests use tables of their own.

use super::chips::{self, Fault, GpioChip};
use super::expander::{SoftExpander, PINS};
use super::gpio::GpioDir;
use super::instances::{Instances, RegisterError};

static BOARD: SoftExpander = SoftExpander::new();
static A: SoftExpander = SoftExpander::new();
static B: SoftExpander = SoftExpander::new();

fn same(x: Option<&'static dyn GpioChip>, y: &'static SoftExpander) -> bool {
    x.is_some_and(|c| core::ptr::addr_eq(c as *const dyn GpioChip, y as *const SoftExpander))
}

/// Instance 0 is the board's from the start; a device gets the lowest number
/// no device has had, and the same number again after its unbind.
///
/// **Canary.** Make `register` ignore the device's own slot (always take a
/// fresh one): the duplicate is not refused, and `A` comes back as 2.
#[test]
fn a_device_gets_its_own_number_back_after_an_unbind() {
    let t: Instances<dyn GpioChip, 3> = Instances::with_board(&BOARD);
    assert!(same(t.get(0), &BOARD));
    assert_eq!(t.get(1).map(|_| ()), None);
    assert_eq!(t.register(7, &A), Ok(1));
    assert!(same(t.get(1), &A));
    assert_eq!(t.register(7, &A), Err(RegisterError::Registered));
    assert_eq!(t.unregister(7), Some(1));
    assert_eq!(t.get(1).map(|_| ()), None, "an unbound controller is absent");
    assert_eq!(t.unregister(7), None);
    assert_eq!(t.register(7, &A), Ok(1));
    assert_eq!(t.count(), 2);
}

/// **A freed number is never another device's**: while `A` is unbound, `B`
/// gets the next fresh number, and once the numbers run out a new device is
/// refused rather than handed `A`'s. A capability on instance 1 can name only
/// `A`.
///
/// **Canary.** Let `register` take any slot without a controller: `B` gets 1,
/// `A`'s number.
#[test]
fn a_freed_number_is_never_another_devices() {
    let t: Instances<dyn GpioChip, 3> = Instances::with_board(&BOARD);
    assert_eq!(t.register(7, &A), Ok(1));
    assert_eq!(t.unregister(7), Some(1));
    assert_eq!(t.register(8, &B), Ok(2));
    assert_eq!(t.register(9, &B), Err(RegisterError::Full));
    assert_eq!(t.get(1).map(|_| ()), None);
    assert_eq!(t.register(7, &A), Ok(1));
}

/// The class keeps Kconfig `GPIO_CONTROLLERS` controllers, the board's
/// among them: one more is refused, and the board's is never taken.
///
/// **Canary.** Size the class's table with a literal other than the Kconfig
/// value: the count differs.
#[test]
fn the_gpio_class_keeps_kconfig_gpio_controllers_controllers() {
    let limit = azos_limits::GPIO_CONTROLLERS as u32;
    let first = chips::count() as u32;
    assert_eq!(first, 1, "only the board's controller to start with");
    for dev in 1..limit {
        assert_eq!(chips::register(100 + dev, &A), Ok(dev));
    }
    assert_eq!(chips::register(100 + limit, &A), Err(RegisterError::Full));
    assert_eq!(chips::count() as u32, limit);
    assert!(chips::chip(0).is_some_and(|c| c.pins() == super::gpio::GPIO_MAX_PINS as u32));
    for dev in 1..limit {
        assert_eq!(chips::unregister(100 + dev), Some(dev));
    }
    assert_eq!(chips::count(), 1);
}

/// The expander's lines start as inputs, which read low and refuse a write;
/// an output reads back what it drives; a pin past its last is refused.
///
/// **Canary.** Let `write` drive an input line: the first write answers `Ok`.
#[test]
fn the_soft_expander_drives_only_its_outputs() {
    let x = SoftExpander::new();
    assert_eq!(x.pins(), PINS);
    assert_eq!(x.write(3, 1), Err(Fault));
    assert_eq!(x.read(3), Ok(0));
    assert_eq!(x.set_dir(3, GpioDir::Output), Ok(()));
    assert_eq!(x.write(3, 3), Ok(()));
    assert_eq!((x.read(3), x.read(2)), (Ok(1), Ok(0)));
    assert_eq!(x.write(3, 0), Ok(()));
    assert_eq!(x.read(3), Ok(0));
    assert_eq!(x.set_dir(PINS, GpioDir::Output), Err(Fault));
    assert_eq!(x.read(PINS), Err(Fault));
}
