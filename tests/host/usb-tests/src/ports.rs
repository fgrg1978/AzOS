// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A device or hub that never answers costs a bounded number of enumeration
//! attempts, not one per connection event.

use azos_usb::usbcore::desc::REQ_GET_DESCRIPTOR;

use crate::devices::*;
use crate::harness::Rig;

const ENABLE_SLOT: u8 = 9;
/// GET_DESCRIPTOR to the device.
const DEVICE_GET: (u8, u8) = (0x80, REQ_GET_DESCRIPTOR);

fn enable_slots(rig: &Rig) -> usize {
    rig.hw.commands().iter().filter(|&&c| c == ENABLE_SLOT).count()
}

/// A device that is plugged, never answers, and is plugged again.
fn replug_a_deaf_device(rig: &mut Rig, port: usize, times: usize) {
    for _ in 0..times {
        let deaf = keyboard();
        deaf.borrow_mut().nak_requests.push(DEVICE_GET);
        rig.hw.attach_root(port, deaf);
        rig.run(1_400);
        rig.hw.detach_root(port);
        rig.run(50);
    }
}

#[test]
fn a_port_that_keeps_failing_is_left_alone_for_a_while() {
    let mut rig = Rig::new();
    replug_a_deaf_device(&mut rig, 1, 10);
    assert_eq!(enable_slots(&rig), 3, "the budget is three attempts");
    assert_eq!(rig.usb.stats().failed, 3);
    assert_eq!(rig.usb.devices().count(), 0);
    assert!(rig.hw.fault().is_none(), "{:?}", rig.hw.fault());
}

#[test]
fn another_port_is_not_held_back_and_the_ignored_one_is_tried_again_later() {
    let mut rig = Rig::new();
    replug_a_deaf_device(&mut rig, 1, 6);
    let before = enable_slots(&rig);
    let st = stick();
    rig.hw.attach_root(2, st.clone());
    rig.settle();
    assert_eq!(rig.usb.devices().count(), 1, "port 2 enumerates");
    assert_eq!(enable_slots(&rig), before + 1);
    // After the ban, a device that answers comes up on port 1.
    rig.run(35_000);
    let kb = keyboard();
    rig.hw.attach_root(1, kb.clone());
    rig.settle();
    assert_eq!(rig.usb.devices().count(), 2);
}

#[test]
fn a_failure_backs_the_port_off_and_the_connection_is_tried_again_after_it() {
    let mut rig = Rig::new();
    let deaf = keyboard();
    deaf.borrow_mut().nak_requests.push(DEVICE_GET);
    rig.hw.attach_root(1, deaf);
    while rig.usb.stats().failed == 0 {
        rig.run(1);
    }
    rig.hw.detach_root(1);
    rig.run(5);
    let one = enable_slots(&rig);
    // A keyboard plugged in right after the failure: inside the back-off.
    rig.hw.attach_root(1, keyboard());
    rig.run(500);
    assert_eq!(enable_slots(&rig), one, "no attempt inside the back-off");
    assert_eq!(rig.usb.devices().count(), 0);
    rig.run(2_000);
    assert_eq!(enable_slots(&rig), one + 1, "the held-back connection is tried once the back-off is over");
    assert_eq!(rig.usb.devices().count(), 1);
}

#[test]
fn a_hub_port_that_keeps_failing_is_left_alone_too() {
    let mut rig = Rig::new();
    let h = hub_device(false, 4, 3, false);
    rig.hw.attach_root(1, h.clone());
    rig.settle();
    for _ in 0..8 {
        let deaf = keyboard();
        deaf.borrow_mut().nak_requests.push(DEVICE_GET);
        rig.hw.hub_attach(&h, 1, deaf);
        rig.run(1_400);
        rig.hw.hub_detach(&h, 1);
        rig.run(50);
    }
    // The hub's own slot, then three attempts below it.
    assert_eq!(enable_slots(&rig), 1 + 3);
    rig.hw.hub_attach(&h, 2, keyboard());
    rig.settle();
    assert_eq!(rig.usb.devices().count(), 2, "another port of the hub is not held back");
}
