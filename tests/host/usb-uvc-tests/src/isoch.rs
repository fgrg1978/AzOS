// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Isochronous pipes of the USB core: the alternate-setting endpoint table,
//! the endpoint context a setting's endpoint is configured with, the Isoch
//! TRB a transfer becomes, and what an interval's completion looks like.

use azos_rings::Push;
use azos_usb::class::{Match, Scope};
use azos_usb::usbcore::desc::parse_config;
use azos_usb::usbcore::pipe::{Completion, Dir, Status, Transfer};
use azos_usb::usbcore::OpenError;
use azos_usb::xhci::trb::cc;
use azos_usb::Claim;
use azos_usb_tests::devices::DevRef;
use azos_usb_tests::harness::Rig;

use crate::fixtures::*;

/// The rule of a video streaming interface.
fn vs_rule() -> Match {
    Match { scope: Scope::Interface, vid_pid: None, class: Some(14), subclass: Some(2), protocol: None }
}

/// A rig with `cam` plugged in and the streaming interface claimed.
fn with_cam(cam: &Cam, psiv: u32) -> (Rig, DevRef, u8, Claim) {
    let mut rig = Rig::new();
    let d = rig.add_driver(vs_rule(), true);
    let dev = cam.device(psiv);
    rig.hw.attach_root(1, dev.clone());
    rig.settle();
    let slot = rig.slot_of(&dev);
    let claim = Claim(rig.driver(d).attached[0].0);
    assert_eq!(claim.iface(), cam.vs, "the streaming interface is the one claimed");
    (rig, dev, slot, claim)
}

fn xfer(tag: u32, buf: u64, len: u32) -> Transfer {
    Transfer { tag, dir: Dir::In, setup: [0; 8], buf, len }
}

#[test]
fn the_config_parser_keeps_the_endpoint_of_every_alternate_setting() {
    let mut cam = Cam::new();
    if let Streaming::Isoch(alts) = &mut cam.streaming {
        alts[2].companion = Some((2, 1, 3072));
    }
    let c = parse_config(&cam.config()).expect("config");
    let vs = c.interfaces().iter().find(|i| i.number == 1).unwrap();
    // Setting 0 has no endpoint: the interface's own table holds setting 1's.
    assert_eq!((vs.alt_setting, vs.num_endpoints, vs.alternates), (1, 1, 3));
    let alts = c.alt_endpoints();
    assert_eq!(alts.len(), 3);
    assert_eq!(alts.iter().map(|a| (a.iface, a.alt, a.ep.mps)).collect::<Vec<_>>(), [(1, 1, 192), (1, 2, 512), (1, 3, 1024)]);
    // The companion follows the endpoint it belongs to, not its neighbour.
    assert!(!alts[1].ep.has_companion);
    assert_eq!((alts[2].ep.burst, alts[2].ep.ss_attrs, alts[2].ep.bytes_per_interval), (2, 1, 3072));
    assert_eq!(c.endpoint(1, 2, 0x81).map(|e| e.mps), Some(512));
    assert_eq!(c.endpoint(1, 9, 0x81), None);
    assert_eq!(c.endpoint(0, 1, 0x81), None, "another interface's setting");
}

#[test]
fn an_endpoint_of_a_setting_the_device_does_not_have_is_denied() {
    let cam = Cam::new();
    let (mut rig, _dev, _slot, claim) = with_cam(&cam, 3);
    // Setting 0 of this interface has no endpoint at all.
    assert_eq!(rig.usb.open_pipe_alt(claim, 0x81, 7), Err(OpenError::Denied));
    assert_eq!(rig.usb.open_pipe_alt(claim, 0x83, 1), Err(OpenError::Denied), "an address no setting has");
}

#[test]
fn a_settings_endpoint_is_configured_with_that_settings_parameters() {
    let mut cam = Cam::new();
    // Setting 3: 1024-byte packets, two more transactions per microframe.
    if let Streaming::Isoch(alts) = &mut cam.streaming {
        alts[2].mps_word = 1024 | 2 << 11;
        alts[2].interval = 1;
        alts[1].interval = 4;
    }
    let (mut rig, _dev, slot, claim) = with_cam(&cam, 3);
    let id = rig.usb.open_pipe_alt(claim, 0x81, 3).expect("setting 3");
    let c = rig.hw.ep_ctx(slot as usize, 3);
    // Endpoint context: type isochronous IN, max burst 2 (the extra
    // transactions), max packet 1024, bytes per interval 3072, interval 0.
    assert_eq!((c[1] >> 3) & 7, 5, "isochronous IN");
    assert_eq!((c[1] >> 8) & 0xff, 2, "max burst size");
    assert_eq!(c[1] >> 16, 1024, "max packet size");
    assert_eq!(c[4] >> 16 | (c[0] >> 24) << 16, 3072, "max ESIT payload");
    assert_eq!((c[0] >> 16) & 0xff, 0, "interval: bInterval 1 is every microframe");
    assert_eq!((c[0] >> 8) & 3, 0, "mult is a SuperSpeed field");
    rig.usb.close_pipe(claim, id).unwrap();
    // Setting 2 with bInterval 4: every 8 microframes, 2^3.
    rig.usb.open_pipe_alt(claim, 0x81, 2).expect("setting 2");
    let c = rig.hw.ep_ctx(slot as usize, 3);
    assert_eq!((c[0] >> 16) & 0xff, 3);
    assert_eq!(c[1] >> 16, 512);
    assert_eq!((c[1] >> 8) & 0xff, 0);
}

#[test]
fn a_full_speed_isochronous_interval_counts_in_frames() {
    let mut cam = Cam::new();
    if let Streaming::Isoch(alts) = &mut cam.streaming {
        alts[0].mps_word = 128;
        alts[0].interval = 1;
        alts[1].interval = 3;
    }
    let (mut rig, _dev, slot, claim) = with_cam(&cam, 1);
    let id = rig.usb.open_pipe_alt(claim, 0x81, 1).unwrap();
    // bInterval 1 at full speed is one 1 ms frame: 8 microframes, 2^3.
    assert_eq!((rig.hw.ep_ctx(slot as usize, 3)[0] >> 16) & 0xff, 3);
    rig.usb.close_pipe(claim, id).unwrap();
    rig.usb.open_pipe_alt(claim, 0x81, 2).unwrap();
    // bInterval 3: every 4 frames, 2^2 frames, 2^5 microframes.
    assert_eq!((rig.hw.ep_ctx(slot as usize, 3)[0] >> 16) & 0xff, 5);
}

#[test]
fn a_superspeed_endpoint_takes_its_burst_mult_and_bytes_from_the_companion() {
    let mut cam = Cam::new();
    cam.streaming = Streaming::Isoch(vec![Alt { mps_word: 1024, interval: 1, companion: Some((15, 2, 49152)) }]);
    let (mut rig, _dev, slot, claim) = with_cam(&cam, 4);
    rig.usb.open_pipe_alt(claim, 0x81, 1).unwrap();
    let c = rig.hw.ep_ctx(slot as usize, 3);
    assert_eq!((c[1] >> 8) & 0xff, 15, "max burst");
    assert_eq!((c[0] >> 8) & 3, 2, "mult");
    assert_eq!(c[4] >> 16 | (c[0] >> 24) << 16, 49152, "max ESIT payload");
}

#[test]
fn an_isochronous_out_endpoint_is_refused() {
    let mut cam = Cam::new();
    cam.endpoint = 0x01;
    let (mut rig, _dev, _slot, claim) = with_cam(&cam, 3);
    assert_eq!(rig.usb.open_pipe_alt(claim, 0x01, 1), Err(OpenError::Unsupported));
}

/// A TD is one service interval: one Isoch TRB, SIA, the burst count and the
/// packets of the last burst from the length.
#[test]
fn an_interval_is_one_isoch_trb_with_its_burst_fields() {
    let mut cam = Cam::new();
    if let Streaming::Isoch(alts) = &mut cam.streaming {
        alts[2].mps_word = 1024 | 2 << 11;
    }
    let (mut rig, dev, slot, claim) = with_cam(&cam, 3);
    let id = rig.usb.open_pipe_alt(claim, 0x81, 3).unwrap();
    let mut end = rig.pipe_end(id);
    let buf = rig.buffer(16384);
    // 2500 bytes: three packets of up to 1024, one burst of three.
    assert!(matches!(end.sq.push(xfer(1, buf.bus(), 2500)), Push::Pushed));
    // 1024 bytes: one packet.
    assert!(matches!(end.sq.push(xfer(2, buf.bus_at(4096), 1024)), Push::Pushed));
    rig.service();
    rig.hw.inject_in(&dev, 1, &vec![0xaa; 2500]);
    rig.hw.inject_in(&dev, 1, &vec![0xbb; 1024]);
    rig.service();
    let first = rig.hw.first_trbs(slot as usize, 3);
    assert_eq!(first.len(), 2);
    for (t, (len, tlbpc)) in first.iter().zip([(2500u32, 2u32), (1024, 0)]) {
        assert_eq!((t[3] >> 10) & 0x3f, 5, "an Isoch TRB");
        assert_eq!(t[2] & 0x1_ffff, len);
        assert_ne!(t[3] & 1 << 31, 0, "SIA");
        assert_ne!(t[3] & 1 << 5, 0, "IOC");
        assert_ne!(t[3] & 1 << 2, 0, "ISP: a short interval is reported");
        assert_eq!((t[3] >> 7) & 3, 0, "TBC");
        assert_eq!((t[3] >> 16) & 0xf, tlbpc, "TLBPC");
        assert_eq!(t[3] & 1 << 4, 0, "one TRB, no chain");
    }
    assert_eq!(end.cq.pop(), Some(Completion { tag: 1, status: Status::Ok, actual: 2500 }));
    assert_eq!(end.cq.pop(), Some(Completion { tag: 2, status: Status::Ok, actual: 1024 }));
}

#[test]
fn a_superspeed_interval_counts_bursts_and_the_packets_of_the_last() {
    let mut cam = Cam::new();
    cam.streaming = Streaming::Isoch(vec![Alt { mps_word: 1024, interval: 1, companion: Some((15, 2, 49152)) }]);
    let (mut rig, dev, slot, claim) = with_cam(&cam, 4);
    let id = rig.usb.open_pipe_alt(claim, 0x81, 1).unwrap();
    let mut end = rig.pipe_end(id);
    let buf = rig.buffer(65536);
    // 40 packets of 1024 in bursts of 16: three bursts, the last of 8 packets.
    assert!(matches!(end.sq.push(xfer(1, buf.bus(), 40 * 1024)), Push::Pushed));
    // A full 3 x 16 x 1024: three bursts, the last full.
    rig.service();
    rig.hw.inject_in(&dev, 1, &vec![1; 40 * 1024]);
    rig.service();
    assert!(matches!(end.sq.push(xfer(2, buf.bus(), 49152)), Push::Pushed));
    rig.service();
    rig.hw.inject_in(&dev, 1, &vec![2; 49152]);
    rig.service();
    let first = rig.hw.first_trbs(slot as usize, 3);
    let f = |t: &[u32; 4]| ((t[3] >> 7) & 3, (t[3] >> 16) & 0xf);
    assert_eq!(f(&first[0]), (2, 7), "40 packets: TBC 2, TLBPC 7");
    assert_eq!(f(&first[1]), (2, 15), "48 packets: TBC 2, TLBPC 15");
    assert_eq!(end.cq.pop().map(|c| c.actual), Some(40 * 1024));
    assert_eq!(end.cq.pop().map(|c| c.actual), Some(49152));
}

#[test]
fn a_lost_interval_completes_with_its_code_and_the_endpoint_keeps_running() {
    let cam = Cam::new();
    let (mut rig, dev, slot, claim) = with_cam(&cam, 3);
    let id = rig.usb.open_pipe_alt(claim, 0x81, 2).unwrap();
    let mut end = rig.pipe_end(id);
    let buf = rig.buffer(8192);
    // The controller reports a missed service interval for the first TD.
    rig.hw.inject_error(slot as usize, 3, cc::MISSED_SERVICE);
    assert!(matches!(end.sq.push(xfer(1, buf.bus(), 512)), Push::Pushed));
    assert!(matches!(end.sq.push(xfer(2, buf.bus_at(4096), 512)), Push::Pushed));
    rig.service();
    assert_eq!(end.cq.pop(), Some(Completion { tag: 1, status: Status::Other(cc::MISSED_SERVICE), actual: 0 }));
    // Not halted: the next interval's data arrives as usual.
    rig.hw.inject_in(&dev, 1, &[7; 300]);
    rig.service();
    assert_eq!(end.cq.pop(), Some(Completion { tag: 2, status: Status::Ok, actual: 300 }));
    assert_eq!(rig.hw.ep_info(slot as usize, 3).3, 1, "the endpoint is running");
}

#[test]
fn an_empty_interval_is_a_completion_with_no_bytes() {
    let cam = Cam::new();
    let (mut rig, dev, _slot, claim) = with_cam(&cam, 3);
    let id = rig.usb.open_pipe_alt(claim, 0x81, 1).unwrap();
    let mut end = rig.pipe_end(id);
    let buf = rig.buffer(4096);
    assert!(matches!(end.sq.push(xfer(1, buf.bus(), 192)), Push::Pushed));
    rig.service();
    rig.hw.inject_in(&dev, 1, &[]);
    rig.service();
    assert_eq!(end.cq.pop(), Some(Completion { tag: 1, status: Status::Ok, actual: 0 }));
}

#[test]
fn closing_an_isochronous_pipe_drops_its_endpoint() {
    let cam = Cam::new();
    let (mut rig, _dev, slot, claim) = with_cam(&cam, 3);
    let id = rig.usb.open_pipe_alt(claim, 0x81, 1).unwrap();
    assert_eq!(rig.hw.ep_info(slot as usize, 3).3, 1);
    rig.usb.close_pipe(claim, id).unwrap();
    assert_eq!(rig.hw.ep_info(slot as usize, 3).3, 0, "disabled");
    // And it opens again, in another setting.
    assert!(rig.usb.open_pipe_alt(claim, 0x81, 3).is_ok());
}
