// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's adapter (`crates/drivers/net/src/usb_net.rs`): a network
//! function as the `NetDevice` the stack addresses, driven the way the `usb`
//! task drives it.

use std::cell::Cell;

use azos_drv_api::net::{NetDevice, NetError};
use azos_usb::class::cdc::State;
use azos_usb::class::{Registry, UsbClassDirect};
use azos_usb::hw::{Clock, DmaBuf, Memory};
use azos_usb_tests::devices::DevRef;
use azos_usb_tests::harness::Rig;
use azos_usb_tests::mock::{MockClock, MockMem};

use crate::fixtures::*;
use crate::net::{datagrams, eth, ncm_block};
use crate::usb_net::{Event, UsbNic};
use azos_usb::class::net::NetFunction;

thread_local! {
    static KICKS: Cell<u32> = const { Cell::new(0) };
}

fn kick() {
    KICKS.with(|k| k.set(k.get() + 1));
}

fn kicks() -> u32 {
    KICKS.with(|k| k.get())
}

/// The mock's memory and clock are `Rc`s; the adapter wants `Send` (the
/// kernel's are). Everything here runs on the test's own thread.
pub(crate) struct SendMem(pub(crate) MockMem);
pub(crate) struct SendClock(pub(crate) MockClock);

// SAFETY: the test never moves a bench to another thread.
unsafe impl Send for SendMem {}
// SAFETY: as above.
unsafe impl Send for SendClock {}

impl Memory for SendMem {
    fn alloc_region(&self, len: usize, align: usize, mask: u64) -> Option<DmaBuf> {
        self.0.alloc_region(len, align, mask)
    }
    fn free_region(&self, b: DmaBuf) {
        self.0.free_region(b)
    }
    fn enable(&self) -> bool {
        self.0.enable()
    }
    fn to_device(&self, cpu: *const u8, len: usize) {
        self.0.to_device(cpu, len)
    }
    fn from_device(&self, cpu: *const u8, len: usize) {
        self.0.from_device(cpu, len)
    }
}

impl Clock for SendClock {
    fn now_us(&self) -> u64 {
        self.0.now_us()
    }
    fn delay_us(&self, us: u32) {
        self.0.delay_us(us)
    }
}

type Cdc = azos_usb::class::cdc::CdcNet<'static, SendMem, SendClock>;
type Nic = UsbNic<Cdc>;

fn nic_over(rig: &Rig) -> Nic {
    UsbNic::new(
        azos_usb::class::cdc::CdcNet::new(SendMem(rig.hw.mem()), SendClock(rig.hw.clock()), u64::MAX, &rig.rings[..]),
        kick,
    )
}

struct Bench {
    rig: Rig,
    nic: Nic,
    dev: DevRef,
    events: Vec<Event>,
}

impl Bench {
    fn new(dev: DevRef) -> Bench {
        let rig = Rig::new();
        let nic = nic_over(&rig);
        rig.hw.attach_root(1, dev.clone());
        let mut b = Bench { rig, nic, dev, events: vec![] };
        b.until(|b| b.events.contains(&Event::Up) || b.nic.inspect(|f| matches!(f.state(), State::Failed(_))), 3000);
        b
    }

    fn turn(&mut self) {
        let [r0, r1] = [Cdc::RULES[0], Cdc::RULES[1]];
        let (mut a, mut b) = (UsbClassDirect(self.nic.class()), UsbClassDirect(self.nic.class()));
        let mut reg = Registry::new();
        reg.register(0, r0, &mut a).unwrap();
        reg.register(1, r1, &mut b).unwrap();
        self.rig.usb.service(&mut reg);
        drop(reg);
        let e = self.nic.drive(&mut self.rig.usb);
        if e != Event::None {
            self.events.push(e);
        }
        self.rig.hw.clock().delay_us(1_000);
    }

    fn until(&mut self, mut done: impl FnMut(&mut Bench) -> bool, max: u32) {
        for _ in 0..max {
            if done(self) {
                return;
            }
            self.turn();
        }
    }

    fn run(&mut self, n: u32) {
        for _ in 0..n {
            self.turn();
        }
    }
}

#[test]
fn the_function_comes_up_once_and_is_a_nic() {
    let mut b = Bench::new(ecm_device());
    assert_eq!(b.events, vec![Event::Up]);
    b.run(20);
    assert_eq!(b.events, vec![Event::Up], "reported once");
    assert!(NetDevice::is_ready(&b.nic));
    assert_eq!(NetDevice::mac(&b.nic), MAC_BYTES);
}

#[test]
fn frames_go_out_and_come_in_through_the_trait_and_the_usb_task_is_woken() {
    let mut b = Bench::new(ecm_device());
    let before = kicks();
    let f = eth(98, 4);
    assert_eq!(NetDevice::send(&b.nic, &f), Ok(98));
    assert!(kicks() > before, "a queued transfer wakes the usb task");
    b.run(5);
    assert_eq!(b.dev.borrow().out_log.iter().filter(|(e, _)| *e == 2).map(|(_, d)| d.clone()).collect::<Vec<_>>(), vec![f]);
    // And in: two frames, taken by the default batch loop.
    let (x, y) = (eth(60, 1), eth(61, 2));
    b.rig.hw.inject_in(&b.dev, 1, &x);
    b.rig.hw.inject_in(&b.dev, 1, &y);
    b.run(5);
    let mut got = vec![];
    assert_eq!(NetDevice::recv_batch(&b.nic, 8, &mut |fr| got.push(fr.to_vec())), 2);
    assert_eq!(got, vec![x, y]);
    let mut buf = [0u8; 2048];
    assert_eq!(NetDevice::recv(&b.nic, &mut buf), Ok(0), "nothing queued is not an error");
}

#[test]
fn errors_are_the_stacks_errors() {
    let mut b = Bench::new(ecm_device());
    assert_eq!(NetDevice::send(&b.nic, &[0; 4]), Err(NetError::BadLength));
    for _ in 0..azos_limits::USB_CDC_BUFS {
        NetDevice::send(&b.nic, &eth(60, 0)).unwrap();
    }
    assert_eq!(NetDevice::send(&b.nic, &eth(60, 0)), Err(NetError::QueueFull));
    b.run(5);
    assert_eq!(NetDevice::send(&b.nic, &eth(60, 0)), Ok(60));
}

#[test]
fn nothing_works_before_the_function_is_up() {
    let rig = Rig::new();
    let nic = nic_over(&rig);
    assert!(!NetDevice::is_ready(&nic));
    assert_eq!(NetDevice::send(&nic, &eth(60, 0)), Err(NetError::NotReady));
    assert_eq!(NetDevice::recv(&nic, &mut [0u8; 100]), Err(NetError::NotReady));
    assert_eq!(NetDevice::mac(&nic), [0; 6]);
}

#[test]
fn an_unplugged_function_goes_down_once() {
    let mut b = Bench::new(ecm_device());
    b.rig.hw.detach_root(1);
    b.until(|b| b.events.len() >= 2, 500);
    assert_eq!(b.events, vec![Event::Up, Event::Down]);
    b.run(50);
    assert_eq!(b.events, vec![Event::Up, Event::Down]);
    assert_eq!(NetDevice::send(&b.nic, &eth(60, 0)), Err(NetError::NotReady));
    // The next device comes up again.
    let d = ncm_device(8192, 8192);
    b.dev = d.clone();
    b.rig.hw.attach_root(1, d);
    b.until(|b| b.events.len() >= 3, 3000);
    assert_eq!(b.events, vec![Event::Up, Event::Down, Event::Up]);
}

#[test]
fn a_batch_through_the_trait_shares_a_block() {
    let mut b = Bench::new(ncm_device(8192, 8192));
    NetDevice::tx_batch_begin(&b.nic);
    let fs = [eth(60, 1), eth(70, 2)];
    for f in &fs {
        NetDevice::send(&b.nic, f).unwrap();
    }
    b.run(3);
    assert!(b.dev.borrow().out_log.is_empty());
    let before = kicks();
    NetDevice::tx_batch_end(&b.nic);
    assert!(kicks() > before);
    b.run(5);
    let log: Vec<Vec<u8>> = b.dev.borrow().out_log.iter().filter(|(e, _)| *e == 2).map(|(_, d)| d.clone()).collect();
    assert_eq!(log.len(), 1);
    assert_eq!(datagrams(&log[0]), fs.to_vec());
    // Blocks in.
    let g = eth(80, 3);
    b.rig.hw.inject_in(&b.dev, 1, &ncm_block(0, &[&g]));
    b.run(5);
    let mut buf = [0u8; 2048];
    let n = NetDevice::recv(&b.nic, &mut buf).unwrap();
    assert_eq!(&buf[..n], &g[..]);
}

/// **Discriminates.** What the `usb` task wakes the network poller on: frames
/// the turn reaped and the stack has not taken. False before anything came in
/// and again once the stack took the last one; an `rx_pending` that is always
/// true wakes the poller on every turn, one that is always false leaves a
/// machine with no interrupt-driven NIC deaf until a TCP deadline.
#[test]
fn frames_waiting_for_the_stack_are_reported_until_they_are_taken() {
    let mut b = Bench::new(ecm_device());
    b.run(3);
    assert!(!b.nic.rx_pending(), "nothing came in");
    b.rig.hw.inject_in(&b.dev, 1, &eth(60, 1));
    b.rig.hw.inject_in(&b.dev, 1, &eth(61, 2));
    b.run(5);
    assert!(b.nic.rx_pending(), "two frames wait");
    let mut buf = [0u8; 2048];
    assert_eq!(NetDevice::recv(&b.nic, &mut buf), Ok(60));
    assert!(b.nic.rx_pending(), "one is left");
    assert_eq!(NetDevice::recv(&b.nic, &mut buf), Ok(61));
    assert_eq!(NetDevice::recv(&b.nic, &mut buf), Ok(0));
    assert!(!b.nic.rx_pending(), "the stack took them all");
}
