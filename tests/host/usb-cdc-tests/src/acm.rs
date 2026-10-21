// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! CDC-ACM (`azos_usb::class::cdc::CdcAcm`) as a `Uart`, against a fake
//! serial gadget behind the xHCI mock; and an ACM plus an ECM function on one
//! device, each reaching its own driver.

use std::cell::RefCell;
use std::collections::VecDeque;

use azos_devif::outcome::{BAD_ARGUMENT, BUSY, NOT_READY, OK, UNSUPPORTED};
use azos_devif::uart::{self, Chunk, ChunkSink, ChunkSource};
use azos_devif::{Cap, Out, Uart};
use azos_usb::class::cdc::{CdcAcm, Fail, State};
use azos_usb::class::{Registry, UsbClass, UsbClassDirect};
use azos_usb::hw::Clock;
use azos_usb_tests::devices::DevRef;
use azos_usb_tests::harness::Rig;

use crate::fixtures::*;
use crate::net::{eth, Acm, Net, NetHandle};

pub struct AcmHandle<'a>(pub &'a RefCell<Acm>);

impl UsbClass for AcmHandle<'_> {
    fn attach(&mut self, claim: u32, vid_pid: u32, triple: u32, speed_port: u32) -> Out<u32> {
        UsbClass::attach(&mut *self.0.borrow_mut(), claim, vid_pid, triple, speed_port)
    }
    fn detach(&mut self, claim: u32) -> Out<u32> {
        UsbClass::detach(&mut *self.0.borrow_mut(), claim)
    }
}

/// The client's queues: a receive side with room for `room` chunks and a
/// transmit side holding what the client queued.
struct Sink {
    chunks: Vec<Chunk>,
    room: usize,
}

impl ChunkSink for Sink {
    fn push(&mut self, c: &Chunk) -> bool {
        if self.chunks.len() >= self.room {
            return false;
        }
        self.chunks.push(*c);
        true
    }
}

struct Source(VecDeque<Chunk>);

impl ChunkSource for Source {
    fn pop(&mut self) -> Option<Chunk> {
        self.0.pop_front()
    }
}

struct Bench {
    rig: Rig,
    acm: RefCell<Acm>,
    dev: DevRef,
    sink: Sink,
    source: Source,
}

impl Bench {
    fn new(dev: DevRef) -> Bench {
        let rig = Rig::new();
        let acm = RefCell::new(CdcAcm::new(rig.hw.mem(), rig.hw.clock(), u64::MAX, &rig.rings[..]));
        rig.hw.attach_root(1, dev.clone());
        let mut b = Bench {
            rig,
            acm,
            dev,
            sink: Sink { chunks: vec![], room: usize::MAX },
            source: Source(VecDeque::new()),
        };
        b.until(|b| !matches!(b.state(), State::Idle | State::Claimed | State::Setup), 3000);
        b
    }

    fn state(&self) -> State {
        self.acm.borrow().state()
    }

    fn turn(&mut self) {
        let (mut h1, mut h2) = (UsbClassDirect(AcmHandle(&self.acm)), UsbClassDirect(AcmHandle(&self.acm)));
        let mut reg = Registry::new();
        reg.register(0, Acm::comm_rule(), &mut h1).unwrap();
        reg.register(1, Acm::data_rule(), &mut h2).unwrap();
        self.rig.usb.service(&mut reg);
        drop(reg);
        loop {
            let c = self.acm.borrow().session_wanted();
            let Some(c) = c else { break };
            let mut s = self.rig.usb.session(c);
            self.acm.borrow_mut().open(&mut s);
        }
        self.acm.borrow_mut().pump(&mut self.sink, &mut self.source);
        self.rig.hw.clock().delay_us(1_000);
    }

    fn until(&mut self, mut done: impl FnMut(&mut Bench) -> bool, max: u32) -> bool {
        for _ in 0..max {
            if done(self) {
                return true;
            }
            self.turn();
        }
        done(self)
    }

    fn run(&mut self, turns: u32) {
        for _ in 0..turns {
            self.turn();
        }
    }

    fn attach(&mut self) {
        let r = Uart::attach(&mut *self.acm.borrow_mut(), Cap::from_raw(1), Cap::from_raw(2));
        assert_eq!(r.code, OK);
        self.run(5);
    }

    fn received(&self) -> Vec<u8> {
        self.sink.chunks.iter().flat_map(|c| c.bytes().to_vec()).collect()
    }

    /// The class requests the device saw, by bRequest.
    fn class_requests(&self, req: u8) -> Vec<([u8; 8], Vec<u8>)> {
        self.dev.borrow().requests.iter().filter(|(s, _)| s[0] == 0x21 && s[1] == req).cloned().collect()
    }

    fn queue_tx(&mut self, bytes: &[u8]) {
        for c in bytes.chunks(uart::CHUNK_DATA) {
            self.source.0.push_back(Chunk::new(c, 0));
        }
    }
}

#[test]
fn an_acm_function_comes_up() {
    let b = Bench::new(acm_device());
    assert_eq!(b.state(), State::Ready);
    assert_eq!(b.acm.borrow().vid_pid(), 0x0525_a4a2);
    // The configuration is read once; the data interface has its endpoints in
    // setting 0, so there is no SET_INTERFACE.
    let d = b.dev.borrow();
    let at = d.requests.iter().position(|(s, _)| s[0] == 0 && s[1] == 9).unwrap();
    let after: Vec<(u8, u8)> = d.requests[at + 1..].iter().map(|(s, _)| (s[0], s[1])).collect();
    assert_eq!(after, vec![(0x80, 6)]);
}

#[test]
fn a_function_whose_union_names_another_data_interface_is_failed() {
    let mut f = AcmFn::new();
    f.data = 1;
    let mut body = f.bytes();
    // Make the union (the last class-specific descriptor before the endpoint) name interface 5.
    let at = body.windows(5).position(|w| w == [5, 0x24, 6, 0, 1]).unwrap();
    body[at + 4] = 5;
    let b = Bench::new(device(2, body, ""));
    assert_eq!(b.state(), State::Failed(Fail::Mismatch));
}

#[test]
fn the_line_is_set_with_set_line_coding() {
    let mut b = Bench::new(acm_device());
    assert_eq!(Uart::configure(&mut *b.acm.borrow_mut(), 115_200, 8, uart::PARITY_NONE, 1).code, OK);
    b.run(5);
    let r = b.class_requests(0x20);
    assert_eq!(r.len(), 1);
    // dwDTERate, bCharFormat (0: one stop bit), bParityType, bDataBits.
    assert_eq!(r[0].1, vec![0x00, 0xc2, 0x01, 0x00, 0, 0, 8]);
    assert_eq!((r[0].0[4], r[0].0[6]), (0, 7), "to the communications interface, seven bytes");
    assert_eq!(Uart::configure(&mut *b.acm.borrow_mut(), 9600, 7, uart::PARITY_EVEN, 2).code, OK);
    b.run(5);
    assert_eq!(b.class_requests(0x20)[1].1, vec![0x80, 0x25, 0x00, 0x00, 2, 2, 7]);
}

#[test]
fn configure_checks_its_arguments_and_the_state() {
    let mut b = Bench::new(acm_device());
    let mut u = b.acm.borrow_mut();
    assert_eq!(Uart::configure(&mut *u, 100, 8, 0, 1).code, BAD_ARGUMENT, "baud");
    assert_eq!(Uart::configure(&mut *u, 9600, 4, 0, 1).code, BAD_ARGUMENT, "data bits");
    assert_eq!(Uart::configure(&mut *u, 9600, 8, 3, 1).code, BAD_ARGUMENT, "parity");
    assert_eq!(Uart::configure(&mut *u, 9600, 8, 0, 3).code, BAD_ARGUMENT, "stop bits");
    drop(u);
    b.run(5);
    assert!(b.class_requests(0x20).is_empty(), "nothing was sent for a refused line");
    let rig = Rig::new();
    let mut idle: Acm = CdcAcm::new(rig.hw.mem(), rig.hw.clock(), u64::MAX, &rig.rings[..]);
    assert_eq!(Uart::configure(&mut idle, 9600, 8, 0, 1).code, NOT_READY);
    assert_eq!(Uart::attach(&mut idle, Cap::from_raw(1), Cap::from_raw(2)).code, NOT_READY);
}

#[test]
fn a_device_without_line_coding_cannot_be_configured() {
    let mut f = AcmFn::new();
    f.caps = Some(0);
    let mut b = Bench::new(device(2, f.bytes(), ""));
    assert_eq!(b.state(), State::Ready);
    assert_eq!(Uart::configure(&mut *b.acm.borrow_mut(), 9600, 8, 0, 1).code, UNSUPPORTED);
    b.attach();
    assert!(b.class_requests(0x22).is_empty(), "no control line state either");
}

#[test]
fn attaching_raises_dtr_and_rts_and_detaching_drops_them() {
    let mut b = Bench::new(acm_device());
    b.attach();
    let r = b.class_requests(0x22);
    assert_eq!(r.len(), 1);
    assert_eq!(u16::from_le_bytes([r[0].0[2], r[0].0[3]]), 0b11);
    assert_eq!(Uart::attach(&mut *b.acm.borrow_mut(), Cap::from_raw(3), Cap::from_raw(4)).code, BUSY);
    assert_eq!(b.acm.borrow().queues(), Some((Cap::from_raw(1), Cap::from_raw(2))));
    assert_eq!(Uart::detach(&mut *b.acm.borrow_mut()).code, OK);
    b.run(5);
    let r = b.class_requests(0x22);
    assert_eq!(r.len(), 2);
    assert_eq!(u16::from_le_bytes([r[1].0[2], r[1].0[3]]), 0);
    assert_eq!(b.acm.borrow().queues(), None);
}

/// **The kernel can hold the line without queues** (the serial console): the
/// hold raises DTR and RTS like a client's, is exclusive both ways, is not a
/// queue pair a host could resolve, moves bytes through `pump` like a client
/// (both directions), and is let go by an unplug so the next device can be
/// taken again.
///
/// **Canary.** Make `attach_kernel` return `OK` without recording the holder:
/// the `BUSY` after it fails and no byte moves.
#[test]
fn the_kernel_can_hold_the_port_without_queues_and_an_unplug_lets_it_go() {
    let mut b = Bench::new(acm_device());
    assert_eq!(b.acm.borrow_mut().attach_kernel().code, OK);
    b.run(5);
    let r = b.class_requests(0x22);
    assert_eq!(r.len(), 1, "the kernel's hold raises DTR and RTS too");
    assert_eq!(u16::from_le_bytes([r[0].0[2], r[0].0[3]]), 0b11);
    assert_eq!(b.acm.borrow().queues(), None, "there are no queues to resolve");
    assert_eq!(b.acm.borrow_mut().attach_kernel().code, BUSY);
    assert_eq!(Uart::attach(&mut *b.acm.borrow_mut(), Cap::from_raw(1), Cap::from_raw(2)).code, BUSY);
    b.rig.hw.inject_in(&b.dev, 1, b"login:");
    b.queue_tx(b"root\r");
    b.run(5);
    assert_eq!(b.received(), b"login:");
    assert_eq!(b.dev.borrow().out_log.last().unwrap().1, b"root\r");
    // The device goes: the hold goes with it, and a task can take the next one.
    b.rig.hw.detach_root(1);
    b.until(|b| b.state() == State::Idle, 500);
    assert_eq!(b.acm.borrow_mut().attach_kernel().code, NOT_READY);
    let second = acm_device();
    b.dev = second.clone();
    b.rig.hw.attach_root(1, second);
    b.until(|b| b.state() == State::Ready, 3000);
    assert_eq!(Uart::attach(&mut *b.acm.borrow_mut(), Cap::from_raw(1), Cap::from_raw(2)).code, OK);
}

#[test]
fn received_bytes_become_chunks_in_order() {
    let mut b = Bench::new(acm_device());
    b.attach();
    let data: Vec<u8> = (0..70).collect();
    b.rig.hw.inject_in(&b.dev, 1, &data);
    b.run(5);
    assert_eq!(b.sink.chunks.iter().map(|c| c.len).collect::<Vec<_>>(), vec![32, 32, 6]);
    assert_eq!(b.received(), data);
    assert!(b.sink.chunks.iter().all(|c| c.flags == 0));
    // And more, in later transfers.
    b.rig.hw.inject_in(&b.dev, 1, b"again");
    b.run(5);
    assert_eq!(&b.received()[70..], b"again");
}

#[test]
fn nothing_is_asked_of_the_device_while_no_client_holds_the_port() {
    let mut b = Bench::new(acm_device());
    b.rig.hw.inject_in(&b.dev, 1, b"early");
    b.run(10);
    assert!(b.sink.chunks.is_empty());
    assert_eq!(b.dev.borrow().in_queue[1].len(), 1, "the device still holds it");
    b.attach();
    assert_eq!(b.received(), b"early");
}

#[test]
fn a_full_receive_queue_loses_chunks_and_flags_the_gap() {
    let mut b = Bench::new(acm_device());
    b.attach();
    b.sink.room = 1;
    let data: Vec<u8> = (0..70).collect();
    b.rig.hw.inject_in(&b.dev, 1, &data);
    b.run(5);
    assert_eq!(b.sink.chunks.len(), 1);
    assert_eq!(Uart::status(&*b.acm.borrow()).value, uart::Status { rx_lost: 2, tx_lost: 0 });
    // Room again: the next chunk says bytes are missing before it, once.
    b.sink.room = usize::MAX;
    b.rig.hw.inject_in(&b.dev, 1, &[7u8; 70]);
    b.run(5);
    let flags: Vec<u32> = b.sink.chunks[1..].iter().map(|c| c.flags).collect();
    assert_eq!(flags, vec![uart::CHUNK_OVERRUN, 0, 0]);
}

#[test]
fn queued_chunks_are_packed_into_transfers_in_order() {
    let mut b = Bench::new(acm_device());
    b.attach();
    let data: Vec<u8> = (0..1280u32).map(|i| (i * 7) as u8).collect();
    b.queue_tx(&data);
    b.run(5);
    let out = b.dev.borrow().out_log.iter().filter(|(e, _)| *e == 2).map(|(_, d)| d.clone()).collect::<Vec<_>>();
    // A buffer holds 1 KiB: 32 chunks, then the rest.
    assert_eq!(out.iter().map(|d| d.len()).collect::<Vec<_>>(), vec![1024, 256]);
    assert_eq!(out.concat(), data);
    // Small writes go out as they come.
    b.queue_tx(b"ok\n");
    b.run(5);
    assert_eq!(b.dev.borrow().out_log.last().unwrap().1, b"ok\n");
}

#[test]
fn an_unplugged_port_is_cleaned_up_and_can_be_taken_again() {
    let mut b = Bench::new(acm_device());
    b.attach();
    b.rig.hw.detach_root(1);
    b.until(|b| b.state() == State::Idle, 500);
    assert_eq!(b.state(), State::Idle);
    assert_eq!(b.acm.borrow().queues(), None, "the client's queues are let go");
    assert_eq!(Uart::attach(&mut *b.acm.borrow_mut(), Cap::from_raw(1), Cap::from_raw(2)).code, NOT_READY);
    let second = acm_device();
    b.dev = second.clone();
    b.rig.hw.attach_root(1, second);
    b.until(|b| b.state() == State::Ready, 3000);
    assert_eq!(b.state(), State::Ready);
    b.attach();
    b.rig.hw.inject_in(&b.dev, 1, b"back");
    b.run(5);
    assert_eq!(b.received(), b"back");
}

#[test]
fn an_ethernet_function_is_not_taken_by_the_serial_driver() {
    let b = Bench::new(ecm_device());
    assert_eq!(b.state(), State::Idle);
}

// ---- One device, two functions ----

#[test]
fn a_composite_device_gives_each_function_to_its_own_driver() {
    let rig = Rig::new();
    let net: RefCell<Net> = RefCell::new(azos_usb::class::cdc::CdcNet::new(rig.hw.mem(), rig.hw.clock(), u64::MAX, &rig.rings[..]));
    let acm: RefCell<Acm> = RefCell::new(CdcAcm::new(rig.hw.mem(), rig.hw.clock(), u64::MAX, &rig.rings[..]));
    let mut body = AcmFn::new().bytes();
    body.extend(NetFn { comm: 2, data: 3, union_data: 3, base: 4, ..NetFn::ecm() }.bytes());
    let dev = device(4, body, MAC);
    rig.hw.attach_root(1, dev.clone());
    let mut rig = rig;
    let mut sink = Sink { chunks: vec![], room: usize::MAX };
    let mut source = Source(VecDeque::new());
    for _ in 0..3000 {
        let (mut n1, mut n2) = (UsbClassDirect(NetHandle(&net)), UsbClassDirect(NetHandle(&net)));
        let (mut a1, mut a2) = (UsbClassDirect(AcmHandle(&acm)), UsbClassDirect(AcmHandle(&acm)));
        let mut reg = Registry::new();
        reg.register(0, Net::comm_rule(), &mut n1).unwrap();
        reg.register(1, Net::data_rule(), &mut n2).unwrap();
        reg.register(2, Acm::comm_rule(), &mut a1).unwrap();
        reg.register(3, Acm::data_rule(), &mut a2).unwrap();
        rig.usb.service(&mut reg);
        drop(reg);
        loop {
            let c = net.borrow().session_wanted();
            let Some(c) = c else { break };
            let mut s = rig.usb.session(c);
            net.borrow_mut().open(&mut s);
        }
        loop {
            let c = acm.borrow().session_wanted();
            let Some(c) = c else { break };
            let mut s = rig.usb.session(c);
            acm.borrow_mut().open(&mut s);
        }
        net.borrow_mut().service();
        acm.borrow_mut().pump(&mut sink, &mut source);
        rig.hw.clock().delay_us(1_000);
    }
    assert_eq!(net.borrow().state(), State::Ready);
    assert_eq!(acm.borrow().state(), State::Ready);
    assert_eq!(net.borrow().mac(), MAC_BYTES);
    // Each function's bytes reach its own driver.
    assert_eq!(Uart::attach(&mut *acm.borrow_mut(), Cap::from_raw(1), Cap::from_raw(2)).code, OK);
    let f = eth(60, 3);
    rig.hw.inject_in(&dev, 4, &f);
    rig.hw.inject_in(&dev, 1, b"serial");
    for _ in 0..10 {
        net.borrow_mut().service();
        acm.borrow_mut().pump(&mut sink, &mut source);
        let mut s = rig.usb.session(azos_usb::Claim::new(0, 0xff, 0));
        let _ = &mut s;
        let mut reg = Registry::new();
        rig.usb.service(&mut reg);
        rig.hw.clock().delay_us(1_000);
    }
    let mut buf = [0u8; 2048];
    let n = net.borrow_mut().recv(&mut buf);
    assert_eq!(&buf[..n], &f[..]);
    let got: Vec<u8> = sink.chunks.iter().flat_map(|c| c.bytes().to_vec()).collect();
    assert_eq!(got, b"serial");
}
