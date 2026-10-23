// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's injection point for a controller that stops answering
//! (Kconfig CHAOS, `chaos=xhci-command-drop:1:1` on the command line), on
//! the real driver over the mock: the command whose doorbell the point
//! skips times out, the controller is reset once and the device comes back,
//! and the point, capped at one firing, disarms itself. A process of its
//! own: an armed point is global, and the other suites must not lose
//! commands to it.

use azos_chaos::Point;
use azos_usb::class::Match;
use azos_usb::usbcore::OpenError;
use azos_usb::Claim;
use azos_usb_tests::devices::keyboard;
use azos_usb_tests::harness::Rig;

#[test]
fn a_dropped_command_resets_the_controller_once() {
    let mut rig = Rig::new();
    let d = rig.add_driver(Match::interface_class(3), true);
    rig.hw.attach_root(1, keyboard());
    rig.settle();
    let claim = Claim(rig.driver(d).attached[0].0);
    azos_chaos::arm_times(Point::XhciCommandDrop, 1, 0, 1);
    assert_eq!(rig.usb.open_pipe(claim, 0x81), Err(OpenError::Fault), "the dropped command must time out");
    assert_eq!(azos_chaos::fired(Point::XhciCommandDrop), 1);
    assert_eq!(azos_chaos::stats(Point::XhciCommandDrop).0, 0, "a point capped at one firing stays armed");
    assert!(!rig.usb.controller().is_dead());
    assert_eq!(rig.hw.hc_resets(), 2, "bring-up and one reset");
    rig.settle();
    let again = Claim(rig.driver(d).attached[1].0);
    assert!(rig.usb.open_pipe(again, 0x81).is_ok(), "the controller does not serve after its reset");
    assert_eq!(azos_chaos::fired(Point::XhciCommandDrop), 1, "the point fired again after its cap");
}
