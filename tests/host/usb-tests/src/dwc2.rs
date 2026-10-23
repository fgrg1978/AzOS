// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The DWC2 host driver (crates/drivers/usb/src/dwc2.rs) under the same USB
//! core as the xHCI one, against the register-level DWC2 mock
//! ([`crate::dwc2_mock`]). See the canary table in `lib.rs`.

use std::rc::Rc;

use azos_rings::{Full, Push, Queue};
use azos_usb::class::{Match, Registry, UsbClassDirect};
use azos_usb::dwc2::Dwc2;
use azos_usb::hw::{Clock, DmaBuf, Memory};
use azos_usb::listing::Lister;
use azos_usb::usbcore::pipe::{Completion, Dir, PipeEnd, PipeRings, Status, Transfer};
use azos_usb::usbcore::Usb;
use azos_usb::xhci::{Error, Speed};
use azos_usb::{Claim, EventKind, UsbEvent, EVENT_DEPTH, MAX_PIPES};

use crate::devices::*;
use crate::dwc2_mock::{Clock2, Config2, Hw2, Mem2, Regs2};
use crate::harness::TestDriver;

type Usb2 = Usb<'static, Regs2, Mem2, Clock2>;

struct Rig2 {
    hw: Rc<Hw2>,
    usb: Box<Usb2>,
    rings: &'static [PipeRings; MAX_PIPES],
    events: azos_rings::Consumer<'static, UsbEvent, EVENT_DEPTH>,
    lister: UsbClassDirect<Lister>,
    drivers: Vec<(Match, UsbClassDirect<TestDriver>)>,
}

impl Rig2 {
    fn new() -> Rig2 {
        Rig2::with(Config2::default())
    }

    fn with(cfg: Config2) -> Rig2 {
        let hw = Hw2::new(cfg);
        let rings: &'static [PipeRings; MAX_PIPES] = Box::leak(Box::new(std::array::from_fn(|_| PipeRings::new())));
        let queue: &'static Queue<UsbEvent, EVENT_DEPTH> = Box::leak(Box::new(Queue::new(Full::Backpressure)));
        let mut slot = Box::<Usb2>::new_uninit();
        Usb::init_dwc2(&mut slot, hw.regs(), hw.mem(), hw.clock(), u64::MAX, rings, queue.producer().unwrap())
            .expect("dwc2 start");
        // SAFETY: `init_dwc2` returned `Ok`: every field is written.
        let usb = unsafe { slot.assume_init() };
        Rig2 { hw, usb, rings, events: queue.consumer().unwrap(), lister: UsbClassDirect(Lister::new()), drivers: Vec::new() }
    }

    fn add_driver(&mut self, rule: Match) -> usize {
        self.drivers.push((rule, UsbClassDirect(TestDriver { accept: true, ..TestDriver::default() })));
        self.drivers.len() - 1
    }

    fn driver(&self, i: usize) -> &TestDriver {
        &self.drivers[i].1 .0
    }

    fn service(&mut self) {
        let mut reg = Registry::new();
        reg.register(0, Lister::rule(), &mut self.lister).unwrap();
        for (i, (rule, d)) in self.drivers.iter_mut().enumerate() {
            reg.register(i as u8 + 1, *rule, d).unwrap();
        }
        self.usb.service(&mut reg);
    }

    fn run(&mut self, ms: u32) {
        for _ in 0..ms {
            self.service();
            self.hw.clock().delay_us(1_000);
        }
    }

    fn settle(&mut self) {
        for _ in 0..40 {
            self.run(60);
        }
    }

    fn drain_events(&mut self) -> Vec<UsbEvent> {
        let mut v = Vec::new();
        while let Some(e) = self.events.pop() {
            v.push(e);
        }
        v
    }

    /// The slot of `dev`: the USB address the core gave it.
    fn slot_of(&self, dev: &DevRef) -> u8 {
        self.hw.address_of(dev).expect("device has no address")
    }

    fn buffer(&self, len: usize) -> DmaBuf {
        self.hw.mem().alloc_region(len.next_multiple_of(4096), 4096, u64::MAX).expect("buffer")
    }

    fn pipe_end(&self, id: u8) -> PipeEnd<'static> {
        PipeEnd::take(&self.rings[id as usize], id).expect("pipe ends free")
    }

    fn claim(&self, slot: u8, iface: u8) -> Claim {
        let g = self.usb.device(slot).expect("device").generation;
        Claim::new(slot, iface, g)
    }
}

fn xfer(tag: u32, dir: Dir, buf: u64, len: u32) -> Transfer {
    Transfer { tag, dir, setup: [0; 8], buf, len }
}

/// A rig with the stick on the root port and a driver on its interfaces.
fn with_stick() -> (Rig2, DevRef, u8) {
    let mut rig = Rig2::new();
    rig.add_driver(Match::interface_class(8));
    let st = stick();
    rig.hw.attach_root(st.clone());
    rig.settle();
    let slot = rig.slot_of(&st);
    (rig, st, slot)
}

// ---- Start ----

#[test]
fn the_core_is_reset_put_in_host_mode_and_its_port_powered() {
    let rig = Rig2::new();
    assert_eq!(rig.hw.soft_resets(), 1);
    assert!(rig.hw.host_mode());
    assert!(rig.hw.port_powered());
    let ahb = rig.hw.gahbcfg();
    assert_ne!(ahb & azos_usb::dwc2::regs::GAHBCFG_DMAEN, 0, "buffer DMA on");
    let d = rig.usb.controller().as_dwc2().expect("a DWC2");
    assert_eq!((rig.usb.controller().ports(), d.channels()), (1, 8));
    assert!(rig.usb.controller().dma_mask() <= u32::MAX as u64);
    assert_eq!(rig.hw.fault(), None);
}

#[test]
fn a_window_that_is_not_a_dwc2_is_refused() {
    let hw = Hw2::new(Config2 { snpsid: 0, ..Config2::default() });
    let r = Dwc2::new(hw.regs(), hw.mem(), hw.clock(), u64::MAX);
    assert!(matches!(r, Err(Error::BadCaps)));
}

// ---- Enumeration ----

#[test]
fn a_full_speed_device_on_the_root_port_is_addressed_and_configured() {
    let mut rig = Rig2::new();
    let kb = keyboard();
    rig.hw.attach_root(kb.clone());
    rig.settle();
    assert_eq!(rig.hw.fault(), None);
    let slot = rig.slot_of(&kb);
    let d = rig.usb.device(slot).expect("enumerated");
    assert_eq!((d.desc.vendor, d.desc.product), (0x046d, 0xc31c));
    assert_eq!(d.speed, Speed::Full);
    assert_eq!(d.root_port, 1);
    assert_eq!(d.product.as_str(), "USB Keyboard");
    assert_eq!(kb.borrow().configuration, 1);
    // SET_ADDRESS gave the device its slot number.
    assert!(kb.borrow().requests.iter().any(|(s, _)| s[0] == 0 && s[1] == 5 && s[2] == slot));
    let ev = rig.drain_events();
    assert_eq!(ev.len(), 1);
    assert_eq!((ev[0].kind, ev[0].slot, ev[0].vid_pid), (EventKind::Attached, slot, 0x046d_c31c));
}

#[test]
fn a_high_speed_device_comes_up_at_high_speed() {
    let (rig, st, slot) = with_stick();
    assert_eq!(rig.hw.fault(), None);
    let d = rig.usb.device(slot).expect("enumerated");
    assert_eq!(d.speed, Speed::High);
    assert_eq!(d.manufacturer.as_str(), "SanDisk");
    assert_eq!(st.borrow().configuration, 1);
}

#[test]
fn a_dwc2_unplug_drops_the_device_and_a_replug_enumerates_it_again() {
    let mut rig = Rig2::new();
    let w = rig.add_driver(Match::every_device());
    let kb = keyboard();
    rig.hw.attach_root(kb.clone());
    rig.settle();
    let first = rig.slot_of(&kb);
    let g1 = rig.usb.device(first).unwrap().generation;
    rig.hw.detach_root();
    rig.settle();
    assert!(rig.usb.device(first).is_none(), "the device stayed after the port said gone");
    assert_eq!(rig.driver(w).detached.len(), 1);
    assert_eq!(rig.lister.0.present(), 0);
    rig.hw.attach_root(kb.clone());
    rig.settle();
    let again = rig.slot_of(&kb);
    let d = rig.usb.device(again).expect("enumerated again");
    assert!(again != first || d.generation != g1);
    assert_eq!(rig.hw.fault(), None);
    let kinds: Vec<_> = rig.drain_events().iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![EventKind::Attached, EventKind::Detached, EventKind::Attached]);
}

#[test]
fn a_high_speed_device_behind_a_high_speed_hub_is_enumerated() {
    let mut rig = Rig2::new();
    let hub = hub_device(false, 4, 3, false);
    rig.hw.attach_root(hub.clone());
    rig.settle();
    let st = stick();
    rig.hw.hub_attach(&hub, 1, st.clone());
    rig.settle();
    assert_eq!(rig.hw.fault(), None);
    let slot = rig.slot_of(&st);
    let d = rig.usb.device(slot).expect("enumerated");
    assert_eq!((d.parent, d.port, d.tier), (rig.slot_of(&hub), 1, 1));
    assert_eq!(st.borrow().configuration, 1);
}

#[test]
fn a_full_speed_device_behind_a_high_speed_hub_is_refused_without_a_split() {
    let mut rig = Rig2::new();
    let hub = hub_device(false, 4, 3, false);
    rig.hw.attach_root(hub.clone());
    rig.settle();
    let before = rig.usb.stats().failed;
    let kb = keyboard();
    rig.hw.hub_attach(&hub, 2, kb.clone());
    rig.settle();
    assert_eq!(rig.hw.fault(), None);
    assert!(rig.hw.address_of(&kb).is_none());
    assert!(rig.usb.stats().failed > before);
    // The hub and the rest of the bus go on.
    let st = stick();
    rig.hw.hub_attach(&hub, 3, st.clone());
    rig.settle();
    assert!(rig.usb.device(rig.slot_of(&st)).is_some());
}

// ---- Pipes ----

#[test]
fn bulk_out_and_in_with_a_short_packet() {
    let (mut rig, st, slot) = with_stick();
    let claim = rig.claim(slot, 0);
    let pin = rig.usb.open_pipe(claim, 0x81).unwrap();
    let pout = rig.usb.open_pipe(claim, 0x02).unwrap();
    let (mut ein, mut eout) = (rig.pipe_end(pin), rig.pipe_end(pout));
    let buf = rig.buffer(8192);
    let payload: Vec<u8> = (0..100u8).collect();
    buf.write_bytes(0, &payload);
    assert!(matches!(eout.sq.push(xfer(1, Dir::Out, buf.bus(), 100)), Push::Pushed));
    rig.service();
    assert_eq!(eout.cq.pop(), Some(Completion { tag: 1, status: Status::Ok, actual: 100 }));
    assert_eq!(st.borrow().out_log, vec![(2, payload.clone())]);
    // Nothing to read yet: the transfer waits on the channel.
    assert!(matches!(ein.sq.push(xfer(2, Dir::In, buf.bus_at(4096), 512)), Push::Pushed));
    rig.run(3);
    assert!(ein.cq.pop().is_none());
    rig.hw.inject_in(&st, 1, &payload);
    rig.run(1);
    assert_eq!(ein.cq.pop(), Some(Completion { tag: 2, status: Status::Ok, actual: 100 }));
    let mut got = vec![0u8; 100];
    buf.read_bytes(4096, &mut got);
    assert_eq!(got, payload);
    assert_eq!(rig.hw.fault(), None);
}

#[test]
fn consecutive_bulk_transfers_keep_the_data_toggle() {
    let (mut rig, st, slot) = with_stick();
    let claim = rig.claim(slot, 0);
    let pout = rig.usb.open_pipe(claim, 0x02).unwrap();
    let mut eout = rig.pipe_end(pout);
    let buf = rig.buffer(4096);
    for tag in 0..5 {
        assert!(matches!(eout.sq.push(xfer(tag, Dir::Out, buf.bus(), 64)), Push::Pushed));
        rig.run(1);
        assert_eq!(eout.cq.pop().map(|c| (c.tag, c.status)), Some((tag, Status::Ok)));
    }
    assert_eq!(st.borrow().out_log.len(), 5);
    assert_eq!(rig.hw.fault(), None, "a packet went with the wrong data PID");
}

#[test]
fn a_transfer_longer_than_a_channel_run_is_split_into_runs() {
    // 11-bit transfer size: 2047 bytes, three 512-byte packets, per run.
    let mut rig = Rig2::with(Config2 { hwcfg3: 0x0ff0_0000, ..Config2::default() });
    rig.add_driver(Match::interface_class(8));
    let st = stick();
    rig.hw.attach_root(st.clone());
    rig.settle();
    let slot = rig.slot_of(&st);
    let claim = rig.claim(slot, 0);
    let pout = rig.usb.open_pipe(claim, 0x02).unwrap();
    let mut eout = rig.pipe_end(pout);
    let buf = rig.buffer(8192);
    let payload: Vec<u8> = (0..6144u32).map(|i| (i % 251) as u8).collect();
    buf.write_bytes(0, &payload);
    assert!(matches!(eout.sq.push(xfer(9, Dir::Out, buf.bus(), 6144)), Push::Pushed));
    // One run per look at the channel: four looks, two per turn of the core.
    rig.run(3);
    assert_eq!(eout.cq.pop(), Some(Completion { tag: 9, status: Status::Ok, actual: 6144 }));
    let got: Vec<u8> = st.borrow().out_log.iter().flat_map(|(_, d)| d.clone()).collect();
    assert_eq!(got, payload);
    assert!(st.borrow().out_log.len() >= 4, "runs: {:?}", rig.hw.runs());
    assert_eq!(rig.hw.fault(), None);
}

#[test]
fn an_in_shorter_than_a_packet_is_bounced_and_never_overruns() {
    let (mut rig, st, slot) = with_stick();
    let claim = rig.claim(slot, 0);
    let pin = rig.usb.open_pipe(claim, 0x81).unwrap();
    let mut ein = rig.pipe_end(pin);
    let buf = rig.buffer(4096);
    buf.write_bytes(0, &[0xee; 64]);
    // A 13-byte status block, as a mass-storage CSW is.
    let csw: Vec<u8> = (1..=13u8).collect();
    assert!(matches!(ein.sq.push(xfer(1, Dir::In, buf.bus(), 13)), Push::Pushed));
    rig.hw.inject_in(&st, 1, &csw);
    rig.run(2);
    assert_eq!(ein.cq.pop(), Some(Completion { tag: 1, status: Status::Ok, actual: 13 }));
    let mut got = [0u8; 16];
    buf.read_bytes(0, &mut got);
    assert_eq!(&got[..13], &csw[..]);
    assert_eq!(&got[13..], &[0xee; 3], "bytes past the buffer were written");
    // A device that sends more than asked: babble, and still nothing past it.
    assert!(matches!(ein.sq.push(xfer(2, Dir::In, buf.bus(), 13)), Push::Pushed));
    rig.hw.inject_in(&st, 1, &[0x55; 20]);
    rig.run(2);
    assert_eq!(ein.cq.pop().map(|c| c.status), Some(Status::Babble));
    buf.read_bytes(0, &mut got);
    assert_eq!(&got[13..], &[0xee; 3], "a babbling device wrote past the buffer");
    assert_eq!(rig.hw.fault(), None);
}

#[test]
fn interrupt_in_nak_then_data() {
    let mut rig = Rig2::new();
    let d = rig.add_driver(Match::interface_class(3));
    let kb = keyboard();
    rig.hw.attach_root(kb.clone());
    rig.settle();
    let claim = Claim(rig.driver(d).attached[0].0);
    let id = rig.usb.open_pipe(claim, 0x81).unwrap();
    let mut end = rig.pipe_end(id);
    let buf = rig.buffer(4096);
    assert!(matches!(end.sq.push(xfer(7, Dir::In, buf.bus(), 8)), Push::Pushed));
    rig.run(30);
    assert!(end.cq.pop().is_none(), "completed with no data");
    rig.hw.inject_in(&kb, 1, &[0, 0, 4, 0, 0, 0, 0, 0]);
    rig.run(20);
    assert_eq!(end.cq.pop(), Some(Completion { tag: 7, status: Status::Ok, actual: 8 }));
    let mut got = [0u8; 8];
    buf.read_bytes(0, &mut got);
    assert_eq!(got, [0, 0, 4, 0, 0, 0, 0, 0]);
    assert_eq!(rig.hw.fault(), None);
}

#[test]
fn a_stalled_bulk_pipe_is_reported_and_recovers() {
    let (mut rig, st, slot) = with_stick();
    let claim = rig.claim(slot, 0);
    let pout = rig.usb.open_pipe(claim, 0x02).unwrap();
    let mut eout = rig.pipe_end(pout);
    let buf = rig.buffer(4096);
    rig.hw.st.borrow_mut().stall_next.push((slot, 0x02));
    assert!(matches!(eout.sq.push(xfer(1, Dir::Out, buf.bus(), 64)), Push::Pushed));
    rig.run(1);
    assert_eq!(eout.cq.pop().map(|c| (c.tag, c.status)), Some((1, Status::Stall)));
    assert!(matches!(eout.sq.push(xfer(2, Dir::Out, buf.bus(), 64)), Push::Pushed));
    rig.run(1);
    assert_eq!(eout.cq.pop(), Some(Completion { tag: 2, status: Status::Ok, actual: 64 }));
    assert_eq!(st.borrow().out_log.len(), 1);
}

#[test]
fn a_transaction_error_is_retried_then_reported() {
    let (mut rig, st, slot) = with_stick();
    let claim = rig.claim(slot, 0);
    let pout = rig.usb.open_pipe(claim, 0x02).unwrap();
    let mut eout = rig.pipe_end(pout);
    let buf = rig.buffer(4096);
    // One error: retried, and the transfer goes through.
    rig.hw.st.borrow_mut().xacterr_next.push((slot, 0x02));
    assert!(matches!(eout.sq.push(xfer(1, Dir::Out, buf.bus(), 64)), Push::Pushed));
    rig.run(3);
    assert_eq!(eout.cq.pop().map(|c| (c.tag, c.status)), Some((1, Status::Ok)));
    // Three in a row: the transfer fails as a transaction error.
    for _ in 0..3 {
        rig.hw.st.borrow_mut().xacterr_next.push((slot, 0x02));
    }
    assert!(matches!(eout.sq.push(xfer(2, Dir::Out, buf.bus(), 64)), Push::Pushed));
    rig.run(5);
    assert_eq!(eout.cq.pop().map(|c| (c.tag, c.status)), Some((2, Status::Transaction)));
    assert_eq!(st.borrow().out_log.len(), 1);
}

#[test]
fn a_buffer_the_engine_cannot_take_is_refused_as_bounce() {
    let (mut rig, _, slot) = with_stick();
    let claim = rig.claim(slot, 0);
    let pout = rig.usb.open_pipe(claim, 0x02).unwrap();
    let mut eout = rig.pipe_end(pout);
    let buf = rig.buffer(4096);
    // Not 4-byte aligned.
    assert!(matches!(eout.sq.push(xfer(1, Dir::Out, buf.bus() + 2, 64)), Push::Pushed));
    // Above 4 GiB.
    assert!(matches!(eout.sq.push(xfer(2, Dir::Out, 0x1_0000_0000, 64)), Push::Pushed));
    rig.run(1);
    assert_eq!(eout.cq.pop().map(|c| (c.tag, c.status)), Some((1, Status::Bounce)));
    assert_eq!(eout.cq.pop().map(|c| (c.tag, c.status)), Some((2, Status::Bounce)));
    assert_eq!(rig.hw.fault(), None);
}


#[test]
fn a_dwc2_is_a_host_unless_the_device_tree_makes_it_a_gadget_port() {
    use azos_usb::dwc2::may_host;
    // The OTG default (and no property at all, which means it) is driven as a
    // host, as the Raspberry Pis wire it; `peripheral` is the gadget stack's.
    for v in [Some(&b"host\0"[..]), Some(b"otg\0"), Some(b""), None] {
        assert!(may_host(v), "{v:?}");
    }
    assert!(!may_host(Some(b"peripheral\0")));
    assert!(!may_host(Some(b"peripheral")));
}
