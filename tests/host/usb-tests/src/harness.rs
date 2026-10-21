// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The rig: a mock controller, the driver over it, a lister and test class
//! drivers, and the helpers the suites share.

use std::rc::Rc;

use azos_devif::outcome::{OK, UNSUPPORTED};
use azos_devif::Out;
use azos_rings::{Consumer, Full, Queue};
use azos_usb::class::{Match, Registry, UsbClass, UsbClassDirect};
use azos_usb::hw::{Clock, DmaBuf, Memory};
use azos_usb::listing::Lister;
use azos_usb::usbcore::pipe::{PipeEnd, PipeRings};
use azos_usb::usbcore::Usb;
use azos_usb::xhci::Xhci;
use azos_usb::{Claim, UsbEvent, EVENT_DEPTH, MAX_PIPES};

use crate::devices::DevRef;
use crate::mock::{Config, Hw, MockClock, MockMem, MockRegs};

pub type TestUsb = Usb<'static, MockRegs, MockMem, MockClock>;

/// A class driver that records what the core tells it.
#[derive(Default)]
pub struct TestDriver {
    pub accept: bool,
    pub attached: Vec<(u32, u32, u32, u32)>,
    pub detached: Vec<u32>,
}

impl UsbClass for TestDriver {
    fn attach(&mut self, claim: u32, vid_pid: u32, triple: u32, speed_port: u32) -> Out<u32> {
        if !self.accept {
            return Out::new(UNSUPPORTED, 0);
        }
        self.attached.push((claim, vid_pid, triple, speed_port));
        Out::new(OK, 0)
    }
    fn detach(&mut self, claim: u32) -> Out<u32> {
        self.detached.push(claim);
        Out::new(OK, 0)
    }
}

pub struct Rig {
    pub hw: Rc<Hw>,
    pub usb: TestUsb,
    pub rings: &'static [PipeRings; MAX_PIPES],
    pub events: Consumer<'static, UsbEvent, EVENT_DEPTH>,
    pub lister: UsbClassDirect<Lister>,
    /// (rule, driver): registered after the lister, ids 1, 2, ...
    pub drivers: Vec<(Match, UsbClassDirect<TestDriver>)>,
}

impl Rig {
    pub fn new() -> Rig {
        Rig::with(Config::default())
    }

    pub fn with(cfg: Config) -> Rig {
        Rig::try_with(cfg).expect("controller start")
    }

    pub fn try_with(cfg: Config) -> Result<Rig, azos_usb::xhci::Error> {
        let hw = Hw::new(cfg);
        let hc = Xhci::new(hw.regs(), hw.mem(), hw.clock(), u64::MAX, false)?;
        let rings: &'static [PipeRings; MAX_PIPES] = Box::leak(Box::new(std::array::from_fn(|_| PipeRings::new())));
        let queue: &'static Queue<UsbEvent, EVENT_DEPTH> = Box::leak(Box::new(Queue::new(Full::Backpressure)));
        let usb = Usb::new(hc, rings, queue.producer().unwrap()).expect("usb core");
        Ok(Rig {
            hw,
            usb,
            rings,
            events: queue.consumer().unwrap(),
            lister: UsbClassDirect(Lister::new()),
            drivers: Vec::new(),
        })
    }

    pub fn add_driver(&mut self, rule: Match, accept: bool) -> usize {
        self.drivers.push((rule, UsbClassDirect(TestDriver { accept, ..TestDriver::default() })));
        self.drivers.len() - 1
    }

    pub fn driver(&self, i: usize) -> &TestDriver {
        &self.drivers[i].1 .0
    }

    pub fn service(&mut self) {
        let mut reg = Registry::new();
        reg.register(0, Lister::rule(), &mut self.lister).unwrap();
        for (i, (rule, d)) in self.drivers.iter_mut().enumerate() {
            reg.register(i as u8 + 1, *rule, d).unwrap();
        }
        self.usb.service(&mut reg);
    }

    /// Run the core for `ms` milliseconds of virtual time, one service a
    /// millisecond.
    pub fn run(&mut self, ms: u32) {
        for _ in 0..ms {
            self.service();
            self.hw.clock().delay_us(1_000);
        }
    }

    /// Run until nothing more happens: enough time for debounce, reset and a
    /// few hub levels.
    pub fn settle(&mut self) {
        for _ in 0..40 {
            self.run(60);
        }
    }

    pub fn drain_events(&mut self) -> Vec<UsbEvent> {
        let mut v = Vec::new();
        while let Some(e) = self.events.pop() {
            v.push(e);
        }
        v
    }

    /// The slot a device was given, by what the controller knows.
    pub fn slot_of(&self, dev: &DevRef) -> u8 {
        self.hw.slot_of(dev).expect("device has no slot") as u8
    }

    /// A DMA buffer the controller can reach (the mock's memory), `len` bytes.
    pub fn buffer(&self, len: usize) -> DmaBuf {
        self.hw.mem().alloc_region(len.next_multiple_of(4096), 4096, u64::MAX).expect("buffer")
    }

    /// The driver's ends of pipe `id`.
    pub fn pipe_end(&self, id: u8) -> PipeEnd<'static> {
        PipeEnd::take(&self.rings[id as usize], id).expect("pipe ends free")
    }

    /// A claim on interface `iface` of the device in `slot`, as the core would
    /// have handed a driver (the generation of the slot's current device).
    pub fn claim(&self, slot: u8, iface: u8) -> Claim {
        let g = self.usb.device(slot).expect("device").generation;
        Claim::new(slot, iface, g)
    }
}

impl Default for Rig {
    fn default() -> Self {
        Rig::new()
    }
}
