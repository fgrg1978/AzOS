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
use super::instances::{DeviceId, Instances, Lease, RegisterError, UnregisterError};
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{mpsc, Arc};
use std::time::Duration;

static BOARD: SoftExpander = SoftExpander::new();
static A: SoftExpander = SoftExpander::new();
static B: SoftExpander = SoftExpander::new();

type Table = Instances<dyn GpioChip, 3>;

const fn dev(handle: u32) -> DeviceId {
    DeviceId { handle, generation: 1 }
}

fn same(x: Option<Lease<'_, dyn GpioChip>>, y: &'static SoftExpander) -> bool {
    x.is_some_and(|c| core::ptr::addr_eq(&*c as *const dyn GpioChip, y as *const SoftExpander))
}

/// An unregistration with no op in flight: it never has to wait.
fn unregister(t: &Table, d: DeviceId) -> Result<u32, UnregisterError> {
    t.unregister(d, &mut || panic!("no op is in flight"))
}

/// Instance 0 is the board's from the start; a device gets the lowest number
/// no device has had, and the same number again after its unbind.
///
/// **Canary.** Make `register` ignore the device's own slot (always take a
/// fresh one): the duplicate is not refused, and `A` comes back as 2.
#[test]
fn a_device_gets_its_own_number_back_after_an_unbind() {
    let t: Table = Instances::with_board(&BOARD);
    assert!(same(t.get(0), &BOARD));
    assert!(t.get(1).is_none());
    assert_eq!(t.register(dev(7), &A), Ok(1));
    assert!(same(t.get(1), &A));
    assert_eq!(t.register(dev(7), &A), Err(RegisterError::Registered));
    assert_eq!(unregister(&t, dev(7)), Ok(1));
    assert!(t.get(1).is_none(), "an unbound controller is absent");
    assert_eq!(unregister(&t, dev(7)), Err(UnregisterError::NotRegistered));
    assert_eq!(t.register(dev(7), &A), Ok(1));
    assert_eq!(t.count(), 2);
}

/// **A freed number is never another device's**: while `A` is unbound, `B`
/// gets the next fresh number, and once the numbers run out a new device is
/// refused rather than handed `A`'s. A device that later takes `A`'s bus slot
/// (the same handle, the next generation) is another device too. A capability
/// on instance 1 can name only `A`.
///
/// **Canary.** `instances-reuse-canary` (any slot without a controller is
/// free): `B` gets 1, `A`'s number.
#[test]
fn a_freed_number_is_never_another_devices() {
    let t: Table = Instances::with_board(&BOARD);
    assert_eq!(t.register(dev(7), &A), Ok(1));
    assert_eq!(unregister(&t, dev(7)), Ok(1));
    assert_eq!(t.register(dev(8), &B), Ok(2));
    assert_eq!(t.register(dev(9), &B), Err(RegisterError::Full));
    let next = DeviceId { handle: 7, generation: 2 };
    assert_eq!(t.register(next, &B), Err(RegisterError::Full), "a reused bus slot is another device");
    assert!(t.get(1).is_none());
    assert_eq!(t.register(dev(7), &A), Ok(1));
}

/// **An unbind waits for the op inside the controller**: with a lease out on
/// another thread, `unregister` does not return; a new lease is refused at
/// once; it returns only after the lease is dropped, and then the controller
/// is gone.
///
/// **Canary.** `instances-no-drain-canary` (no wait): `unregister` returns
/// while the op is still inside.
#[test]
fn an_unbind_waits_for_the_op_inside_the_controller() {
    static T: Table = Instances::with_board(&BOARD);
    assert_eq!(T.register(dev(7), &A), Ok(1));
    let inside = Arc::new(AtomicBool::new(true));
    let (held, ready) = mpsc::channel();
    let op = {
        let inside = inside.clone();
        std::thread::spawn(move || {
            let lease = T.get(1).expect("registered");
            held.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(100));
            inside.store(false, SeqCst);
            drop(lease);
        })
    };
    ready.recv().unwrap();
    let mut asked = 0u32;
    let r = T.unregister(dev(7), &mut || {
        asked += 1;
        if asked == 1 {
            assert!(T.get(1).is_none(), "a new op got in while the unbind waited");
        }
        std::thread::yield_now();
        true
    });
    assert!(!inside.load(SeqCst), "the unbind returned while an op was inside the controller");
    assert_eq!(r, Ok(1));
    assert!(T.get(1).is_none());
    op.join().unwrap();
}

/// An unbind whose patience runs out leaves the controller registered and
/// usable, and says which one: the device stays bound with its driver.
///
/// **Canary.** Clear `ctrl` before the wait instead of after it: the second
/// `get` finds nothing.
#[test]
fn an_unbind_that_runs_out_of_patience_keeps_the_controller() {
    let t: Table = Instances::with_board(&BOARD);
    assert_eq!(t.register(dev(7), &A), Ok(1));
    let lease = t.get(1).expect("registered");
    if !cfg!(feature = "instances-no-drain-canary") {
        let mut tries = 0;
        let r = t.unregister(dev(7), &mut || {
            tries += 1;
            tries < 3
        });
        assert_eq!(r, Err(UnregisterError::InFlight { instance: 1 }));
        assert_eq!(tries, 3);
        assert!(same(t.get(1), &A), "the controller left after a refused unbind");
    }
    drop(lease);
    assert_eq!(unregister(&t, dev(7)), Ok(1));
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
    for d in 1..limit {
        assert_eq!(chips::register(dev(100 + d), &A), Ok(d));
    }
    assert_eq!(chips::register(dev(100 + limit), &A), Err(RegisterError::Full));
    assert_eq!(chips::count() as u32, limit);
    assert!(chips::chip(0).is_some_and(|c| c.pins() == super::gpio::GPIO_MAX_PINS as u32));
    for d in 1..limit {
        assert_eq!(chips::unregister(dev(100 + d), &mut || false), Ok(d));
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
