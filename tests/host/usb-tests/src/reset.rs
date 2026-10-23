// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A controller that stops answering: the device timeout policy
//! (`azos_drv_api::recovery`, Kconfig `DEVICE_TIMEOUT_RESETS` = 1). A
//! command the mock never answers, or a host system error it raises,
//! resets the controller once and the devices come back; the next fault of
//! either cause latches it dead; a reset that does not complete latches it
//! at once.

use std::cell::RefCell;

use azos_drv_api::recovery::{Action, Class};
use azos_rings::Push;
use azos_usb::class::Match;
use azos_usb::usbcore::pipe::{Completion, Dir, Status, Transfer};
use azos_usb::usbcore::OpenError;
use azos_usb::xhci::Fault;
use azos_usb::{Claim, EventKind};

use crate::devices::*;
use crate::harness::Rig;

/// Configure Endpoint, the command `open_pipe` sends (xHCI 1.2 table 6-91).
const CONFIGURE_ENDPOINT: u8 = 12;
/// Enable Slot, the first command of an enumeration.
const ENABLE_SLOT: u8 = 9;

/// The record's first field for a timeout of a command of type `ty`.
fn timeout(ty: u8) -> u64 {
    Fault::Timeout.detail(ty)
}
/// Disable Slot, which a removal sends for a slot the controller holds.
const DISABLE_SLOT: u8 = 10;

thread_local! {
    static RECORDS: RefCell<Vec<(Class, &'static str, Action, u64)>> = const { RefCell::new(Vec::new()) };
}

fn sink(class: Class, device: &'static str, action: Action, detail: u64, _waited_ms: u64) {
    RECORDS.with(|r| r.borrow_mut().push((class, device, action, detail)));
}

/// Route the policy's records to this thread (the hook is one per process;
/// each test reads only what its own thread recorded).
fn listen() {
    azos_drv_api::recovery::set_sink(sink);
    RECORDS.with(|r| r.borrow_mut().clear());
}

fn records() -> Vec<(Class, &'static str, Action, u64)> {
    RECORDS.with(|r| r.borrow().clone())
}

/// A keyboard on port 1, bound by a driver of interface class 3: the rig,
/// the driver's index and its claim.
fn with_keyboard() -> (Rig, usize, Claim) {
    let mut rig = Rig::new();
    let d = rig.add_driver(Match::interface_class(3), true);
    rig.hw.attach_root(1, keyboard());
    rig.settle();
    let claim = Claim(rig.driver(d).attached[0].0);
    rig.drain_events();
    (rig, d, claim)
}

#[test]
fn a_command_timeout_resets_the_controller_and_the_device_comes_back() {
    listen();
    let (mut rig, d, claim) = with_keyboard();
    let before = rig.hw.commands().len();
    rig.hw.lose_commands(1);
    assert_eq!(rig.usb.open_pipe(claim, 0x81), Err(OpenError::Fault), "the unanswered command must fail");
    assert!(!rig.usb.controller().is_dead(), "one timeout latched the controller: no reset");
    assert_eq!(rig.hw.hc_resets(), 2, "bring-up and one reset");
    rig.settle();
    // The core removed the device the reset controller forgot without a
    // command for its slot (the port's connect change, raised again by the
    // reset, would have sent one to a controller that no longer has it).
    assert!(!rig.hw.commands()[before..].contains(&DISABLE_SLOT), "a forgotten slot was disabled: {:?}", &rig.hw.commands()[before..]);
    assert_eq!(rig.driver(d).detached, vec![claim.0], "the class driver was not told its device went away");
    assert_eq!(rig.driver(d).attached.len(), 2, "the device did not come back");
    let again = Claim(rig.driver(d).attached[1].0);
    assert_ne!(again.generation(), claim.generation(), "a device after a reset is a new generation");
    assert_eq!(rig.usb.open_pipe(claim, 0x81), Err(OpenError::NoDevice), "the old claim outlived the reset");
    assert!(rig.usb.open_pipe(again, 0x81).is_ok(), "the controller does not serve after its reset");
    let kinds: Vec<EventKind> = rig.drain_events().iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![EventKind::Detached, EventKind::Attached]);
    assert_eq!(rig.usb.devices().count(), 1);
    assert_eq!(records(), vec![(Class::Usb, "xhci", Action::Reset, timeout(CONFIGURE_ENDPOINT))]);
    assert!(rig.hw.fault().is_none(), "{:?}", rig.hw.fault());
}

#[test]
fn transfers_in_flight_at_a_reset_end_disconnected() {
    listen();
    let (mut rig, d, claim) = with_keyboard();
    let id = rig.usb.open_pipe(claim, 0x81).unwrap();
    let mut end = rig.pipe_end(id);
    let buf = rig.buffer(4096);
    // The keyboard has nothing to send: the transfer stays in flight.
    assert!(matches!(end.sq.push(Transfer { tag: 5, dir: Dir::In, setup: [0; 8], buf: buf.bus(), len: 8 }), Push::Pushed));
    rig.service();
    assert_eq!(end.cq.pop(), None);
    // A stick on port 2: its Enable Slot goes unanswered.
    rig.hw.lose_commands(1);
    rig.hw.attach_root(2, stick());
    rig.settle();
    assert_eq!(end.cq.pop(), Some(Completion { tag: 5, status: Status::Disconnected, actual: 0 }));
    assert!(!rig.usb.pipe_in_use(id), "the pipe outlived the reset");
    assert_eq!(rig.driver(d).detached, vec![claim.0]);
    assert_eq!(rig.usb.devices().count(), 2, "both devices are enumerated after the reset");
    assert_eq!(records(), vec![(Class::Usb, "xhci", Action::Reset, timeout(ENABLE_SLOT))]);
}

#[test]
fn a_second_timeout_latches_the_controller_dead() {
    listen();
    let (mut rig, d, claim) = with_keyboard();
    rig.hw.lose_commands(1);
    assert_eq!(rig.usb.open_pipe(claim, 0x81), Err(OpenError::Fault));
    rig.settle();
    let again = Claim(rig.driver(d).attached[1].0);
    rig.hw.lose_commands(1);
    assert_eq!(rig.usb.open_pipe(again, 0x81), Err(OpenError::Fault));
    assert!(rig.usb.controller().is_dead(), "the second timeout reset the controller again");
    assert_eq!(rig.hw.hc_resets(), 2, "a latched controller is not reset");
    assert_eq!(
        records(),
        vec![
            (Class::Usb, "xhci", Action::Reset, timeout(CONFIGURE_ENDPOINT)),
            (Class::Usb, "xhci", Action::Latched, timeout(CONFIGURE_ENDPOINT)),
        ]
    );
    // Dead until reboot: the next command is refused, not sent.
    let sent = rig.hw.commands().len();
    assert_eq!(rig.usb.open_pipe(again, 0x81), Err(OpenError::Fault));
    rig.settle();
    assert_eq!(rig.hw.commands().len(), sent, "a dead controller was given a command");
}

#[test]
fn a_reset_that_does_not_complete_latches_the_controller() {
    listen();
    let (mut rig, _, claim) = with_keyboard();
    rig.hw.stick_hcrst();
    rig.hw.lose_commands(1);
    assert_eq!(rig.usb.open_pipe(claim, 0x81), Err(OpenError::Fault));
    assert!(rig.usb.controller().is_dead());
    assert_eq!(rig.hw.hc_resets(), 1, "the stuck reset completed");
    assert_eq!(records(), vec![(Class::Usb, "xhci", Action::ResetFailed, timeout(CONFIGURE_ENDPOINT))]);
}

#[test]
fn a_host_system_error_resets_the_controller_and_a_second_latches_it() {
    listen();
    let (mut rig, d, claim) = with_keyboard();
    let hse = Fault::HostSystemError.detail(0);
    rig.hw.raise_hse();
    rig.service();
    assert!(!rig.usb.controller().is_dead(), "a host system error latched the controller: no reset");
    assert_eq!(rig.hw.hc_resets(), 2, "bring-up and one reset");
    assert_eq!(records(), vec![(Class::Usb, "xhci", Action::Reset, hse)]);
    rig.settle();
    assert_eq!(rig.driver(d).detached, vec![claim.0], "the class driver was not told its device went away");
    assert_eq!(rig.driver(d).attached.len(), 2, "the device did not come back");
    let again = Claim(rig.driver(d).attached[1].0);
    assert!(rig.usb.open_pipe(again, 0x81).is_ok(), "the controller does not serve after its reset");
    // The reset is spent: the next error latches the controller.
    rig.hw.raise_hse();
    rig.service();
    assert!(rig.usb.controller().is_dead(), "the second host system error reset the controller again");
    assert_eq!(rig.hw.hc_resets(), 2, "a latched controller is not reset");
    assert_eq!(records(), vec![(Class::Usb, "xhci", Action::Reset, hse), (Class::Usb, "xhci", Action::Latched, hse)]);
}
