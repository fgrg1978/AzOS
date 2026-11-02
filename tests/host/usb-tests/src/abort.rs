// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A buffer goes back only once the controller can no longer write it: a
//! transfer the device has not finished is stopped before its pipe closes, a
//! refused stop resets the controller, and a dead controller keeps what it
//! was given. The mock faults on DMA to memory the driver freed, so a device
//! that answers late turns the missing stop into a red test.

use azos_rings::Push;
use azos_usb::class::Match;
use azos_usb::hw::Memory;
use azos_usb::usbcore::desc::REQ_GET_DESCRIPTOR;
use azos_usb::usbcore::pipe::{Dir, Status, Transfer};
use azos_usb::usbcore::OpenError;
use azos_usb::Claim;

use crate::devices::*;
use crate::harness::Rig;

const CONFIGURE_ENDPOINT: u8 = 12;
const RESET_ENDPOINT: u8 = 14;
const STOP_ENDPOINT: u8 = 15;
const SET_TR_DEQUEUE: u8 = 16;
/// A refusal that is not "wrong state": TRB Error.
const REFUSED: u8 = 5;
/// GET_DESCRIPTOR to an interface.
const IFACE_GET: (u8, u8) = (0x81, REQ_GET_DESCRIPTOR);
/// GET_STATUS to a hub port.
const PORT_STATUS: (u8, u8) = (0xa3, 0);

fn with_keyboard() -> (Rig, DevRef, Claim) {
    let mut rig = Rig::new();
    let d = rig.add_driver(Match::interface_class(3), true);
    let kb = keyboard();
    rig.hw.attach_root(1, kb.clone());
    rig.settle();
    let claim = Claim(rig.driver(d).attached[0].0);
    (rig, kb, claim)
}

fn get_descriptor(buf: u64, tag: u32) -> Transfer {
    let setup = [IFACE_GET.0, IFACE_GET.1, 0, 0x22, 0, 0, 0, 8];
    Transfer { tag, dir: Dir::In, setup, buf, len: 2048 }
}

#[test]
fn closing_a_control_pipe_stops_what_it_has_queued() {
    let (mut rig, kb, claim) = with_keyboard();
    kb.borrow_mut().nak_requests.push(IFACE_GET);
    let id = rig.usb.open_pipe(claim, 0).unwrap();
    let mut end = rig.pipe_end(id);
    let buf = rig.buffer(4096);
    assert!(matches!(end.sq.push(get_descriptor(buf.bus(), 1)), Push::Pushed));
    rig.service();
    assert_eq!(end.cq.pop(), None, "the device is NAKing");
    rig.usb.close_pipe(claim, id).unwrap();
    let c = end.cq.pop().expect("the stopped transfer completes before the close returns");
    assert_eq!((c.tag, c.status), (1, Status::Other(26)));
    drop(end);
    rig.usb.controller().mem().free_region(buf);
    kb.borrow_mut().nak_requests.clear();
    rig.hw.kick_dev(&kb);
    assert!(rig.hw.fault().is_none(), "{:?}", rig.hw.fault());

    // Endpoint 0 serves the next pipe.
    let id = rig.usb.open_pipe(claim, 0).unwrap();
    let mut end = rig.pipe_end(id);
    let buf = rig.buffer(4096);
    assert!(matches!(end.sq.push(get_descriptor(buf.bus(), 2)), Push::Pushed));
    rig.run(5);
    let c = end.cq.pop().expect("endpoint 0 is wedged after the abort");
    assert_eq!(c.tag, 2);
    assert_ne!(c.status, Status::Other(26));
    assert_eq!(rig.hw.hc_resets(), 1, "stopping a transfer reset the controller");
}

#[test]
fn a_core_control_that_times_out_is_taken_off_endpoint_0() {
    let mut rig = Rig::new();
    let h = hub_device(false, 4, 3, false);
    rig.hw.attach_root(1, h.clone());
    rig.settle();
    h.borrow_mut().nak_requests.push(PORT_STATUS);
    rig.hw.hub_attach(&h, 1, keyboard());
    rig.run(1_500);
    assert!(rig.hw.commands().contains(&STOP_ENDPOINT), "nothing stopped the request");
    assert!(rig.hw.commands().contains(&SET_TR_DEQUEUE));
    let slot = rig.hw.slot_of(&h).unwrap() as u8;
    let before = rig.hw.xfer_events().iter().filter(|e| (e.0, e.1, e.2) == (slot, 1, 1)).count();
    // Late: nothing is left on the ring for the answer to land from.
    h.borrow_mut().nak_requests.clear();
    rig.hw.kick_dev(&h);
    let after = rig.hw.xfer_events().iter().filter(|e| (e.0, e.1, e.2) == (slot, 1, 1)).count();
    assert_eq!(after, before, "the late answer was written to the shared control buffer");
    assert!(rig.hw.fault().is_none(), "{:?}", rig.hw.fault());
}

#[test]
fn a_refused_stop_resets_the_controller() {
    let (mut rig, kb, claim) = with_keyboard();
    kb.borrow_mut().nak_requests.push(IFACE_GET);
    let id = rig.usb.open_pipe(claim, 0).unwrap();
    let mut end = rig.pipe_end(id);
    let buf = rig.buffer(4096);
    assert!(matches!(end.sq.push(get_descriptor(buf.bus(), 1)), Push::Pushed));
    rig.service();
    rig.hw.refuse_command(STOP_ENDPOINT, REFUSED);
    rig.usb.close_pipe(claim, id).unwrap();
    assert_eq!(rig.hw.hc_resets(), 2, "bring-up and the reset the refusal asks for");
    assert!(!rig.usb.controller().is_dead());
    while end.cq.pop().is_some() {}
    drop(end);
    rig.usb.controller().mem().free_region(buf);
    assert!(rig.hw.fault().is_none(), "{:?}", rig.hw.fault());
}

#[test]
fn a_refused_drop_resets_the_controller() {
    let (mut rig, _kb, claim) = with_keyboard();
    let id = rig.usb.open_pipe(claim, 0x81).unwrap();
    let mut end = rig.pipe_end(id);
    let buf = rig.buffer(4096);
    let t = Transfer { tag: 1, dir: Dir::In, setup: [0; 8], buf: buf.bus(), len: 8 };
    assert!(matches!(end.sq.push(t), Push::Pushed));
    rig.service();
    rig.hw.refuse_command(CONFIGURE_ENDPOINT, REFUSED);
    rig.usb.close_pipe(claim, id).unwrap();
    assert_eq!(rig.hw.hc_resets(), 2, "the endpoint still runs on a ring the driver freed");
    assert!(!rig.usb.controller().is_dead());
    assert_eq!(rig.usb.open_pipe(claim, 0x81), Err(OpenError::Fault), "the reset controller refuses until the core catches up");
}

#[test]
fn a_refused_reset_endpoint_resets_the_controller() {
    let (mut rig, kb, claim) = with_keyboard();
    let id = rig.usb.open_pipe(claim, 0x81).unwrap();
    let mut end = rig.pipe_end(id);
    let buf = rig.buffer(4096);
    let slot = rig.hw.slot_of(&kb).unwrap();
    // The first transfer halts the endpoint; the second stays queued behind it.
    for tag in 1..=2 {
        let t = Transfer { tag, dir: Dir::In, setup: [0; 8], buf: buf.bus_at(64 * tag as usize), len: 8 };
        assert!(matches!(end.sq.push(t), Push::Pushed));
    }
    rig.hw.refuse_command(RESET_ENDPOINT, REFUSED);
    rig.hw.inject_error(slot, 3, 6);
    rig.service();
    rig.hw.kick_dev(&kb);
    rig.service();
    assert_eq!(rig.hw.hc_resets(), 2, "a refused Reset Endpoint was taken for done");
    assert!(!rig.usb.controller().is_dead());
    rig.settle();
    let mut tags = Vec::new();
    while let Some(c) = end.cq.pop() {
        tags.push((c.tag, c.status));
    }
    assert_eq!(tags[0], (1, Status::Stall));
    assert_eq!(tags[1], (2, Status::Disconnected), "the transfer behind the halt ended before the controller let go");
}

#[test]
fn a_dead_controller_keeps_the_memory_it_was_given() {
    let (mut rig, _kb, claim) = with_keyboard();
    let buf = rig.buffer(4096);
    rig.hw.stick_hcrst();
    rig.hw.lose_commands(1);
    assert_eq!(rig.usb.open_pipe(claim, 0x81), Err(OpenError::Fault));
    assert!(rig.usb.controller().is_dead());
    rig.usb.controller().mem().free_region(buf);
    assert!(rig.hw.mapped(buf.bus()), "a controller nobody saw stop can still write this");
    assert_eq!(rig.hw.leaked(), 1);
}
