// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! CDC-ECM and CDC-NCM functions (`azos_usb::class::cdc::CdcNet`) against a
//! fake gadget behind the register-level xHCI mock.

use std::cell::RefCell;

use azos_devif::Out;
use azos_usb::class::cdc::ntb::{Rx16, NDP16_SIG, NTH16_SIG};
use azos_usb::class::cdc::{CdcAcm, CdcNet, Fail, Kind, SendError, State, FRAME_MAX};
use azos_usb::class::{Registry, UsbClass, UsbClassDirect};
use azos_usb::hw::Clock;
use azos_usb_tests::devices::{DevRef, MockDev};
use azos_usb_tests::harness::Rig;
use azos_usb_tests::mock::{MockClock, MockMem};

use crate::fixtures::*;

pub type Net = CdcNet<'static, MockMem, MockClock>;
pub type Acm = CdcAcm<'static, MockMem, MockClock>;

/// One driver behind two registry entries, as the kernel's lock gives it.
pub struct NetHandle<'a>(pub &'a RefCell<Net>);

impl UsbClass for NetHandle<'_> {
    fn attach(&mut self, claim: u32, vid_pid: u32, triple: u32, speed_port: u32) -> Out<u32> {
        self.0.borrow_mut().attach(claim, vid_pid, triple, speed_port)
    }
    fn detach(&mut self, claim: u32) -> Out<u32> {
        self.0.borrow_mut().detach(claim)
    }
}

pub struct Bench {
    pub rig: Rig,
    pub net: RefCell<Net>,
    pub dev: DevRef,
}

impl Bench {
    pub fn new(dev: DevRef) -> Bench {
        let rig = Rig::new();
        let net = RefCell::new(CdcNet::new(rig.hw.mem(), rig.hw.clock(), u64::MAX, &rig.rings[..]));
        rig.hw.attach_root(1, dev.clone());
        let mut b = Bench { rig, net, dev };
        b.until(|b| !matches!(b.state(), State::Idle | State::Claimed | State::Setup), 3000);
        b
    }

    pub fn state(&self) -> State {
        self.net.borrow().state()
    }

    /// One millisecond of everything.
    pub fn turn(&mut self) {
        let (mut h1, mut h2) = (UsbClassDirect(NetHandle(&self.net)), UsbClassDirect(NetHandle(&self.net)));
        let mut reg = Registry::new();
        reg.register(0, Net::comm_rule(), &mut h1).unwrap();
        reg.register(1, Net::data_rule(), &mut h2).unwrap();
        self.rig.usb.service(&mut reg);
        drop(reg);
        self.crank();
        self.rig.hw.clock().delay_us(1_000);
    }

    /// What the `usb` task does after the core's turn.
    pub fn crank(&mut self) {
        loop {
            let c = self.net.borrow().session_wanted();
            let Some(c) = c else { break };
            let mut s = self.rig.usb.session(c);
            self.net.borrow_mut().open(&mut s);
        }
        self.net.borrow_mut().service();
    }

    pub fn until(&mut self, mut done: impl FnMut(&mut Bench) -> bool, max: u32) -> bool {
        for _ in 0..max {
            if done(self) {
                return true;
            }
            self.turn();
        }
        done(self)
    }

    pub fn run(&mut self, turns: u32) {
        for _ in 0..turns {
            self.turn();
        }
    }

    /// The control requests the device saw after SET_CONFIGURATION.
    pub fn setup_requests(&self) -> Vec<([u8; 8], Vec<u8>)> {
        let d = self.dev.borrow();
        let at = d.requests.iter().position(|(s, _)| s[0] == 0x00 && s[1] == 9).expect("configured");
        d.requests[at + 1..].to_vec()
    }

    pub fn inject(&mut self, ep: usize, data: &[u8]) {
        self.rig.hw.inject_in(&self.dev, ep, data);
    }

    /// Everything received so far, frame by frame.
    pub fn drain(&mut self) -> Vec<Vec<u8>> {
        let mut out = vec![];
        let mut buf = vec![0u8; 2048];
        loop {
            let n = self.net.borrow_mut().recv(&mut buf);
            if n == 0 {
                break;
            }
            out.push(buf[..n].to_vec());
        }
        out
    }

    /// What was sent to bulk OUT endpoint `ep`, transfer by transfer.
    pub fn sent(&self, ep: u8) -> Vec<Vec<u8>> {
        self.dev.borrow().out_log.iter().filter(|(e, _)| *e == ep).map(|(_, d)| d.clone()).collect()
    }
}

pub fn eth(n: usize, tag: u8) -> Vec<u8> {
    let mut f = vec![0u8; n];
    f[..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(&MAC_BYTES);
    f[12..14].copy_from_slice(&[0x08, 0x00]);
    for (i, b) in f.iter_mut().enumerate().skip(14) {
        *b = tag.wrapping_add(i as u8);
    }
    f
}

/// A block as a gadget sends it: the NTH, the NDP, the datagrams.
pub fn ncm_block(seq: u16, dgs: &[&[u8]]) -> Vec<u8> {
    let ndp_len = 8 + 4 * (dgs.len() + 1);
    let mut off = 12 + ndp_len;
    let (mut entries, mut body) = (vec![], vec![]);
    for d in dgs {
        entries.push((off, d.len()));
        body.extend(*d);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        off = 12 + ndp_len + body.len();
    }
    let mut b = vec![];
    b.extend(NTH16_SIG.to_le_bytes());
    b.extend(12u16.to_le_bytes());
    b.extend(seq.to_le_bytes());
    b.extend(((12 + ndp_len + body.len()) as u16).to_le_bytes());
    b.extend(12u16.to_le_bytes());
    b.extend(NDP16_SIG.to_le_bytes());
    b.extend((ndp_len as u16).to_le_bytes());
    b.extend(0u16.to_le_bytes());
    for (i, l) in entries {
        b.extend((i as u16).to_le_bytes());
        b.extend((l as u16).to_le_bytes());
    }
    b.extend([0u8; 4]);
    b.extend(body);
    b
}

/// The datagrams of a block the host sent, read by hand (not by the
/// parser under test): the NTH names the NDP, the NDP lists the datagrams.
pub fn datagrams(b: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(&b[0..4], &NTH16_SIG.to_le_bytes(), "NTH signature");
    assert_eq!(u16::from_le_bytes([b[4], b[5]]), 12);
    let ndp = u16::from_le_bytes([b[10], b[11]]) as usize;
    assert_eq!(&b[ndp..ndp + 4], &NDP16_SIG.to_le_bytes(), "NDP signature");
    let mut out = vec![];
    let mut e = ndp + 8;
    loop {
        let (i, l) = (u16::from_le_bytes([b[e], b[e + 1]]) as usize, u16::from_le_bytes([b[e + 2], b[e + 3]]) as usize);
        if i == 0 && l == 0 {
            break;
        }
        out.push(b[i..i + l].to_vec());
        e += 4;
    }
    out
}

const BUFS: usize = azos_limits::USB_CDC_BUFS as usize;

// ---- Bring-up ----

#[test]
fn an_ecm_function_comes_up_with_the_devices_mac() {
    let b = Bench::new(ecm_device());
    assert_eq!(b.state(), State::Ready);
    let n = b.net.borrow();
    assert_eq!(n.kind(), Some(Kind::Ecm));
    assert_eq!(n.mac(), MAC_BYTES);
    assert_eq!(n.vid_pid(), 0x0525_a4a2);
}

#[test]
fn setup_is_the_requests_a_cdc_host_makes_in_order() {
    let b = Bench::new(ecm_device());
    let r = b.setup_requests();
    let seq: Vec<(u8, u8)> = r.iter().map(|(s, _)| (s[0], s[1])).collect();
    // The configuration again (for the class-specific descriptors), the MAC
    // string, SET_INTERFACE on the data interface, the packet filter.
    assert_eq!(seq, vec![(0x80, 6), (0x80, 6), (0x01, 11), (0x21, 0x43)]);
    let (s, _) = &r[0];
    assert_eq!((s[2], s[3]), (0, 2), "configuration descriptor 0");
    let (s, _) = &r[1];
    assert_eq!((s[2], s[3], s[4], s[5]), (3, 3, 0x09, 0x04), "string 3, US English");
    let (s, _) = &r[2];
    assert_eq!((s[2], s[3], s[4], s[5]), (1, 0, 1, 0), "alternate setting 1 of interface 1");
    let (s, _) = &r[3];
    // Directed | broadcast | all multicast, to the communications interface.
    assert_eq!((u16::from_le_bytes([s[2], s[3]]), s[4]), (0x000e, 0));
}

#[test]
fn a_device_with_its_endpoints_in_setting_zero_is_not_asked_to_switch() {
    let d = device(2, NetFn { eps_in_alt0: true, ..NetFn::ecm() }.bytes(), MAC);
    let b = Bench::new(d);
    assert_eq!(b.state(), State::Ready);
    assert!(b.setup_requests().iter().all(|(s, _)| !(s[0] == 0x01 && s[1] == 11)));
}

#[test]
fn an_ncm_function_reads_the_block_parameters_and_limits_the_devices_blocks() {
    let b = Bench::new(ncm_device(32768, 16384));
    assert_eq!(b.state(), State::Ready);
    assert_eq!(b.net.borrow().kind(), Some(Kind::Ncm));
    let r = b.setup_requests();
    let seq: Vec<(u8, u8)> = r.iter().map(|(s, _)| (s[0], s[1])).collect();
    // ... GET_NTB_PARAMETERS, then SET_NTB_INPUT_SIZE because the device's
    // blocks (32 KiB) are larger than our buffers.
    assert_eq!(seq, vec![(0x80, 6), (0x80, 6), (0xa1, 0x80), (0x21, 0x86), (0x01, 11), (0x21, 0x43)]);
    assert_eq!(r[2].0[6], 28, "the whole table");
    let ntb = azos_limits::USB_CDC_NTB_KB as u32 * 1024;
    assert_eq!(r[3].1, ntb.to_le_bytes().to_vec(), "dwNtbInMaxSize is our buffer");
}

#[test]
fn a_device_whose_blocks_fit_is_not_told_a_size() {
    let b = Bench::new(ncm_device(8192, 8192));
    assert_eq!(b.state(), State::Ready);
    assert!(b.setup_requests().iter().all(|(s, _)| s[1] != 0x86));
}

#[test]
fn an_ncm_device_without_the_packet_filter_is_not_sent_one() {
    let d = device(2, NetFn { ncm: Some(0), ..NetFn::ncm() }.bytes(), MAC);
    d.borrow_mut().canned.push((0xa1, 0x80, ntb_params(1, 8192, 8192, 4, 0, 4, 0)));
    let b = Bench::new(d);
    assert_eq!(b.state(), State::Ready);
    assert!(b.setup_requests().iter().all(|(s, _)| s[1] != 0x43));
}

#[test]
fn a_device_that_refuses_the_packet_filter_is_used_anyway() {
    let d = ecm_device();
    d.borrow_mut().stall_requests.push(0x43);
    let b = Bench::new(d);
    assert_eq!(b.state(), State::Ready);
}

fn failed(dev: DevRef) -> Fail {
    match Bench::new(dev).state() {
        State::Failed(f) => f,
        s => panic!("expected a failure, got {s:?}"),
    }
}

#[test]
fn a_function_that_is_not_what_it_says_is_failed_not_driven() {
    // The union names another data interface than the one claimed.
    assert_eq!(failed(device(2, NetFn { union_data: 4, ..NetFn::ecm() }.bytes(), MAC)), Fail::Mismatch);
    // No MAC string.
    assert_eq!(failed(device(2, NetFn { mac_idx: 0, ..NetFn::ecm() }.bytes(), MAC)), Fail::Descriptor);
    // A MAC string that is not twelve hex digits.
    assert_eq!(failed(device(2, NetFn::ecm().bytes(), "not a mac")), Fail::Descriptor);
    // An NCM interface with no NCM descriptor.
    assert_eq!(failed(device(2, NetFn { ncm: None, ..NetFn::ncm() }.bytes(), MAC)), Fail::Descriptor);
    // An NCM device with no NTB-16 (NTB-32 only).
    let d = device(2, NetFn::ncm().bytes(), MAC);
    d.borrow_mut().canned.push((0xa1, 0x80, ntb_params(2, 8192, 8192, 4, 0, 4, 0)));
    assert_eq!(failed(d), Fail::Params);
    // A device that cannot take one frame in a block.
    let d = device(2, NetFn::ncm().bytes(), MAC);
    d.borrow_mut().canned.push((0xa1, 0x80, ntb_params(1, 8192, 700, 4, 0, 4, 0)));
    assert_eq!(failed(d), Fail::Params);
    // GET_NTB_PARAMETERS answered with a table too short.
    let d = device(2, NetFn::ncm().bytes(), MAC);
    d.borrow_mut().canned.push((0xa1, 0x80, vec![0; 12]));
    assert_eq!(failed(d), Fail::Descriptor);
}

#[test]
fn a_setup_request_the_device_stalls_fails_the_function() {
    let d = ncm_device(8192, 8192);
    d.borrow_mut().stall_requests.push(0x80); // GET_NTB_PARAMETERS (and GET_DESCRIPTOR is 6)
    assert_eq!(failed(d), Fail::Control(3));
    let d = ecm_device();
    d.borrow_mut().canned.clear();
    assert_eq!(failed(d), Fail::Control(5), "SET_INTERFACE refused");
}

#[test]
fn a_data_interface_with_no_bulk_pair_is_failed() {
    let mut body = NetFn::ecm().bytes();
    // Replace the bulk pair of setting 1 with one endpoint.
    let n = body.len();
    body.truncate(n - 14);
    body.extend(ep(0x81, 2, 512, 0));
    let at = body.len() - 7 - 9;
    body[at + 4] = 1;
    assert_eq!(failed(device(2, body, MAC)), Fail::NoEndpoints);
}

// ---- ECM data path ----

#[test]
fn an_ecm_frame_arrives_whole() {
    let mut b = Bench::new(ecm_device());
    let f = eth(98, 1);
    b.inject(1, &f);
    b.run(5);
    assert_eq!(b.drain(), vec![f]);
    assert_eq!(b.net.borrow().stats().rx_frames, 1);
}

#[test]
fn frames_arrive_in_order_and_the_buffers_are_posted_again() {
    let mut b = Bench::new(ecm_device());
    let mut want = vec![];
    // More frames than there are buffers: each taken buffer goes back to the device.
    for round in 0..4 {
        for k in 0..BUFS {
            let f = eth(60 + round * 7 + k, (round * 16 + k) as u8);
            b.inject(1, &f);
            want.push(f);
        }
        b.run(6);
        let got = b.drain();
        assert_eq!(got.len(), BUFS, "round {round}");
        assert_eq!(got, want[want.len() - BUFS..]);
    }
    assert_eq!(b.net.borrow().stats().rx_frames as usize, 4 * BUFS);
}

#[test]
fn a_frame_larger_than_the_callers_buffer_is_dropped_and_counted() {
    let mut b = Bench::new(ecm_device());
    b.inject(1, &eth(1000, 1));
    b.inject(1, &eth(100, 2));
    b.run(5);
    let mut small = [0u8; 200];
    let n = b.net.borrow_mut().recv(&mut small);
    assert_eq!(n, 100, "the next frame that fits");
    assert_eq!(b.net.borrow().stats().rx_dropped, 1);
}

#[test]
fn a_runt_is_dropped_and_counted() {
    let mut b = Bench::new(ecm_device());
    b.inject(1, &[1, 2, 3, 4, 5]);
    b.run(5);
    assert_eq!(b.drain(), Vec::<Vec<u8>>::new());
    assert_eq!(b.net.borrow().stats().rx_dropped, 1);
}

#[test]
fn an_ecm_frame_is_sent_as_one_transfer() {
    let mut b = Bench::new(ecm_device());
    let f = eth(98, 5);
    assert_eq!(b.net.borrow_mut().send(&f), Ok(()));
    b.run(5);
    assert_eq!(b.sent(2), vec![f]);
    assert_eq!(b.net.borrow().stats().tx_frames, 1);
}

#[test]
fn a_frame_ending_on_a_packet_boundary_gets_a_pad_byte() {
    // The core queues no zero-length packet, so a transfer of 512 bytes would
    // never end at the device: one zero byte follows it.
    let mut b = Bench::new(ecm_device());
    let f = eth(512, 5);
    b.net.borrow_mut().send(&f).unwrap();
    b.run(5);
    let sent = b.sent(2);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].len(), 513, "padded");
    assert_eq!(&sent[0][..512], &f[..]);
    assert_eq!(sent[0][512], 0);
    // One that does not end on a boundary is sent as it is.
    let g = eth(513, 6);
    b.net.borrow_mut().send(&g).unwrap();
    b.run(5);
    assert_eq!(b.sent(2)[1], g);
}

#[test]
fn sending_refuses_what_cannot_go_and_says_why() {
    let mut b = Bench::new(ecm_device());
    assert_eq!(b.net.borrow_mut().send(&[0; 10]), Err(SendError::BadLength), "under an Ethernet header");
    assert_eq!(b.net.borrow_mut().send(&eth(1515, 0)), Err(SendError::BadLength), "over the device's segment size");
    // Every buffer in flight.
    for _ in 0..BUFS {
        assert_eq!(b.net.borrow_mut().send(&eth(60, 0)), Ok(()));
    }
    assert_eq!(b.net.borrow_mut().send(&eth(60, 0)), Err(SendError::QueueFull));
    b.run(5);
    assert_eq!(b.net.borrow_mut().send(&eth(60, 0)), Ok(()), "completions free the buffers");
    assert_eq!(b.sent(2).len(), BUFS);
}

#[test]
fn nothing_goes_before_the_function_is_ready() {
    let rig = Rig::new();
    let mut n: Net = CdcNet::new(rig.hw.mem(), rig.hw.clock(), u64::MAX, &rig.rings[..]);
    assert_eq!(n.send(&eth(60, 0)), Err(SendError::NotReady));
    assert_eq!(n.recv(&mut [0u8; 100]), 0);
    assert_eq!(n.mac(), [0; 6]);
    assert!(!n.is_ready());
}

#[test]
fn a_halted_bulk_pipe_is_cleared_and_reception_goes_on() {
    let mut b = Bench::new(ecm_device());
    let slot = b.rig.slot_of(&b.dev);
    // The device stalls the next IN transfer (code 6: STALL).
    b.rig.hw.inject_error(slot as usize, 3, 6);
    b.inject(1, &eth(60, 1));
    b.run(20);
    let cleared = b.dev.borrow().requests.iter().any(|(s, _)| s[0] == 0x02 && s[1] == 1 && s[4] == 0x81);
    assert!(cleared, "CLEAR_FEATURE(ENDPOINT_HALT) on the IN endpoint");
    // Reception continues afterwards.
    let f = eth(70, 2);
    b.inject(1, &f);
    b.run(10);
    assert!(b.drain().contains(&f));
    assert_eq!(b.state(), State::Ready);
}

// ---- NCM data path ----

#[test]
fn an_ncm_block_gives_its_frames_one_by_one() {
    let mut b = Bench::new(ncm_device(8192, 8192));
    let (x, y, z) = (eth(60, 1), eth(99, 2), eth(1514, 3));
    b.inject(1, &ncm_block(1, &[&x, &y, &z]));
    b.run(5);
    assert_eq!(b.drain(), vec![x, y, z]);
    let s = b.net.borrow().stats();
    assert_eq!((s.rx_frames, s.rx_transfers, s.ntb_malformed), (3, 1, 0));
}

#[test]
fn blocks_are_taken_in_order_and_each_buffer_goes_back_when_it_is_empty() {
    let mut b = Bench::new(ncm_device(8192, 8192));
    let mut want = vec![];
    for round in 0..5usize {
        for k in 0..BUFS {
            let f1 = eth(60 + k, (round * 30 + k) as u8);
            let f2 = eth(70 + k, (round * 30 + k + 9) as u8);
            b.inject(1, &ncm_block((round * BUFS + k) as u16, &[&f1, &f2]));
            want.extend([f1, f2]);
        }
        b.run(6);
        let got = b.drain();
        assert_eq!(got.len(), 2 * BUFS, "round {round}");
    }
    assert_eq!(b.net.borrow().stats().rx_frames as usize, want.len());
}

#[test]
fn a_malformed_block_is_counted_and_the_frames_before_the_fault_are_kept() {
    let mut b = Bench::new(ncm_device(8192, 8192));
    // Not a block at all.
    b.inject(1, &[0x55; 64]);
    // A block whose second datagram runs past its end.
    let (x, y) = (eth(60, 1), eth(60, 2));
    let mut blk = ncm_block(2, &[&x, &y]);
    let e2 = 12 + 8 + 4;
    blk[e2 + 2..e2 + 4].copy_from_slice(&900u16.to_le_bytes());
    b.inject(1, &blk);
    // A good one after them.
    let z = eth(61, 3);
    b.inject(1, &ncm_block(3, &[&z]));
    b.run(8);
    let got = b.drain();
    assert_eq!(got, vec![x, z]);
    let s = b.net.borrow().stats();
    assert_eq!(s.ntb_malformed, 2);
    assert_eq!(b.state(), State::Ready);
}

#[test]
fn an_ncm_frame_alone_is_a_block_of_one_datagram() {
    let mut b = Bench::new(ncm_device(8192, 8192));
    let f = eth(60, 9);
    b.net.borrow_mut().send(&f).unwrap();
    b.run(5);
    let sent = b.sent(2);
    assert_eq!(sent.len(), 1);
    assert_eq!(datagrams(&sent[0]), vec![f.clone()]);
    // The exact block: NTH, the frame at 12, the NDP at 72, wBlockLength 88.
    assert_eq!(sent[0].len(), 88);
    assert_eq!(u16::from_le_bytes([sent[0][8], sent[0][9]]), 88);
    assert_eq!(u16::from_le_bytes([sent[0][10], sent[0][11]]), 72);
    assert_eq!(&sent[0][12..72], &f[..]);
}

#[test]
fn a_batch_shares_one_block_and_the_sequence_counts_blocks() {
    let mut b = Bench::new(ncm_device(8192, 8192));
    let fs = [eth(60, 1), eth(61, 2), eth(900, 3)];
    b.net.borrow_mut().tx_begin();
    for f in &fs {
        b.net.borrow_mut().send(f).unwrap();
    }
    b.run(5);
    assert!(b.sent(2).is_empty(), "nothing leaves before the batch ends");
    b.net.borrow_mut().tx_end();
    b.run(5);
    let sent = b.sent(2);
    assert_eq!(sent.len(), 1);
    assert_eq!(datagrams(&sent[0]), fs.to_vec());
    assert_eq!(u16::from_le_bytes([sent[0][6], sent[0][7]]), 0);
    // The next block is number 1.
    b.net.borrow_mut().send(&fs[0]).unwrap();
    b.run(5);
    assert_eq!(u16::from_le_bytes([b.sent(2)[1][6], b.sent(2)[1][7]]), 1);
    assert_eq!(b.net.borrow().stats().tx_frames, 4);
    assert_eq!(b.net.borrow().stats().tx_transfers, 2);
}

#[test]
fn a_batch_is_cut_where_the_block_is_full() {
    let mut b = Bench::new(ncm_device(8192, 4000));
    b.net.borrow_mut().tx_begin();
    // 1514 + 1514 + header and table fit in 4000 - 1; a third does not.
    for i in 0..3 {
        b.net.borrow_mut().send(&eth(1514, i)).unwrap();
    }
    b.net.borrow_mut().tx_end();
    b.run(5);
    let sent = b.sent(2);
    assert_eq!(sent.iter().map(|s| datagrams(s).len()).collect::<Vec<_>>(), vec![2, 1]);
    assert!(sent.iter().all(|s| s.len() <= 4000));
}

#[test]
fn the_devices_datagram_limit_and_alignment_are_kept() {
    let d = device(2, NetFn::ncm().bytes(), MAC);
    // At most 2 datagrams a block, datagrams at 2 modulo 8, NDP on 16.
    d.borrow_mut().canned.push((0xa1, 0x80, ntb_params(1, 8192, 8192, 8, 2, 16, 2)));
    let mut b = Bench::new(d);
    b.net.borrow_mut().tx_begin();
    let fs: Vec<Vec<u8>> = (0..5).map(|i| eth(61 + i, i as u8)).collect();
    for f in &fs {
        b.net.borrow_mut().send(f).unwrap();
    }
    b.net.borrow_mut().tx_end();
    b.run(8);
    let sent = b.sent(2);
    assert_eq!(sent.iter().map(|s| datagrams(s).len()).collect::<Vec<_>>(), vec![2, 2, 1]);
    let all: Vec<Vec<u8>> = sent.iter().flat_map(|s| datagrams(s)).collect();
    assert_eq!(all, fs);
    for s in &sent {
        assert_eq!(u16::from_le_bytes([s[10], s[11]]) % 16, 0, "NDP alignment");
        let ndp = u16::from_le_bytes([s[10], s[11]]) as usize;
        let mut e = ndp + 8;
        while u16::from_le_bytes([s[e], s[e + 1]]) != 0 {
            assert_eq!(u16::from_le_bytes([s[e], s[e + 1]]) % 8, 2, "datagram alignment");
            e += 4;
        }
    }
}

#[test]
fn a_block_ending_on_a_packet_boundary_gets_a_pad_byte_outside_its_length() {
    let mut b = Bench::new(ncm_device(8192, 8192));
    // 12 + 484 + 16 = 512: one packet exactly.
    let f = eth(484, 3);
    b.net.borrow_mut().send(&f).unwrap();
    b.run(5);
    let s = &b.sent(2)[0];
    assert_eq!(s.len(), 513);
    assert_eq!(u16::from_le_bytes([s[8], s[9]]), 512, "wBlockLength does not count the pad");
    assert_eq!(s[512], 0);
    assert_eq!(datagrams(s), vec![f]);
}

#[test]
fn a_frame_over_the_segment_size_is_refused_before_it_is_batched() {
    let mut b = Bench::new(ncm_device(8192, 8192));
    assert_eq!(b.net.borrow_mut().send(&eth(FRAME_MAX, 0)), Err(SendError::BadLength));
    assert!(b.net.borrow_mut().flush().is_ok(), "nothing open, nothing to flush");
    b.run(3);
    assert!(b.sent(2).is_empty());
}

// ---- Unplug ----

#[test]
fn an_unplugged_function_is_cleaned_up_and_the_next_device_is_driven() {
    let mut b = Bench::new(ecm_device());
    let f = eth(60, 1);
    b.inject(1, &f);
    b.run(3);
    b.rig.hw.detach_root(1);
    b.until(|b| b.state() == State::Idle, 500);
    assert_eq!(b.state(), State::Idle);
    assert_eq!(b.net.borrow().mac(), [0; 6]);
    assert_eq!(b.net.borrow_mut().send(&eth(60, 0)), Err(SendError::NotReady));
    // Another device on the same port: the pipes and the memory were given back.
    let second = ncm_device(8192, 8192);
    b.dev = second.clone();
    b.rig.hw.attach_root(1, second);
    b.until(|b| b.state() == State::Ready, 3000);
    assert_eq!(b.state(), State::Ready);
    assert_eq!(b.net.borrow().kind(), Some(Kind::Ncm));
    let g = eth(70, 2);
    b.inject(1, &ncm_block(0, &[&g]));
    b.run(5);
    assert_eq!(b.drain(), vec![g]);
}

#[test]
fn a_second_network_function_is_declined_busy() {
    let mut body = NetFn::ecm().bytes();
    body.extend(NetFn { comm: 2, data: 3, union_data: 3, base: 4, ..NetFn::ecm() }.bytes());
    let mut b = Bench::new(device(4, body, MAC));
    assert_eq!(b.state(), State::Ready);
    // The first function is the driver's; the second is nobody's, and the
    // first still works.
    let f = eth(60, 1);
    b.inject(1, &f);
    b.run(5);
    assert_eq!(b.drain(), vec![f]);
}

#[test]
fn an_acm_function_is_not_taken_by_the_network_driver() {
    let b = Bench::new(acm_device());
    assert_eq!(b.state(), State::Idle);
}

#[test]
fn a_dev_that_is_not_cdc_is_ignored() {
    let dd = azos_usb_tests::devices::device_desc(0x0200, 0, 0, 0, 64, 1, 2, 0, 0);
    let cfg = azos_usb_tests::devices::config_desc(
        1,
        &[azos_usb_tests::devices::iface(0, 3, 1, 1, vec![azos_usb_tests::devices::ep(0x81, 3, 8, 10)])],
    );
    let b = Bench::new(MockDev::new(3, dd, cfg).into_ref());
    assert_eq!(b.state(), State::Idle);
}

#[test]
fn the_rx_buffers_are_not_lost_while_the_stack_is_slow() {
    // The stack takes nothing for a while: the device is throttled (its
    // transfers wait), nothing is dropped, and everything is there later.
    let mut b = Bench::new(ecm_device());
    let fs: Vec<Vec<u8>> = (0..3 * BUFS).map(|i| eth(60 + i, i as u8)).collect();
    for f in &fs {
        b.inject(1, f);
    }
    b.run(30);
    let mut got = vec![];
    for _ in 0..10 {
        got.extend(b.drain());
        b.run(3);
    }
    assert_eq!(got, fs);
}

#[allow(dead_code)]
fn _uses(_: &Acm, _: Rx16) {}

// ---- What the core keeps of alternate settings ----

#[test]
fn the_core_keeps_the_endpoints_of_the_first_alternate_setting_that_has_some() {
    use azos_usb::usbcore::desc::parse_config;
    // ECM: setting 0 of the data interface has none, setting 1 has the pair.
    let c = parse_config(&config(2, NetFn::ecm().bytes())).unwrap();
    let (comm, data) = (&c.interfaces()[0], &c.interfaces()[1]);
    assert_eq!((comm.alt_setting, comm.num_endpoints, comm.alternates), (0, 1, 0));
    assert_eq!((data.alt_setting, data.num_endpoints, data.alternates), (1, 2, 1));
    assert_eq!(data.endpoints().iter().map(|e| e.address).collect::<Vec<_>>(), vec![0x81, 0x02]);
    // Endpoints in setting 0: the later setting's are not merged in.
    let mut body = iface(0, 0, 1, 0x0a, 0);
    body.extend(ep(0x81, 2, 512, 0));
    body.extend(iface(0, 1, 1, 0x0a, 0));
    body.extend(ep(0x82, 2, 512, 0));
    let c = parse_config(&config(1, body)).unwrap();
    let i = &c.interfaces()[0];
    assert_eq!((i.alt_setting, i.num_endpoints, i.alternates), (0, 1, 1));
    // Settings 1 and 2 have none, 2 has endpoints and 3 more: the first with some.
    let mut body = iface(0, 0, 0, 0x0a, 0);
    body.extend(iface(0, 1, 0, 0x0a, 0));
    body.extend(iface(0, 2, 2, 0x0a, 0));
    body.extend(ep(0x81, 2, 512, 0));
    body.extend(ep(0x02, 2, 512, 0));
    body.extend(iface(0, 3, 1, 0x0a, 0));
    body.extend(ep(0x83, 2, 512, 0));
    let c = parse_config(&config(1, body)).unwrap();
    let i = &c.interfaces()[0];
    assert_eq!((i.alt_setting, i.num_endpoints, i.alternates), (2, 2, 3));
    // No setting has any: it stays at 0.
    let mut body = iface(0, 0, 0, 0x0a, 0);
    body.extend(iface(0, 1, 0, 0x0a, 0));
    let c = parse_config(&config(1, body)).unwrap();
    assert_eq!((c.interfaces()[0].alt_setting, c.interfaces()[0].num_endpoints), (0, 0));
}

#[test]
fn a_driver_is_told_which_setting_its_endpoints_belong_to() {
    use azos_usb::class::UsbDevice;
    let b = Bench::new(ecm_device());
    let slot = b.rig.slot_of(&b.dev);
    let mut usb = b.rig.usb;
    let s = usb.session(azos_usb::Claim::new(slot, 1, usb.device(slot).unwrap().generation));
    assert_eq!(s.info(6).value, 1, "alternate setting 1");
    assert_eq!(s.info(4).value, 2, "two endpoints");
    let s = usb.session(azos_usb::Claim::new(slot, 0, usb.device(slot).unwrap().generation));
    assert_eq!(s.info(6).value, 0);
}
