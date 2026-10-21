// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A scripted TPM: one TIS/FIFO state machine, reached directly, through an
//! MMIO window or through a SPI bus. Each command it receives is compared to
//! the script's next command and answered with the script's response; every
//! protocol violation by the driver is logged instead of panicking, so a test
//! can assert on the log.

use azos_tpm::mmio::MmioAccess;
use azos_tpm::spi::Spi;
use azos_tpm::tis::{Clock, TisRegs, REG_ACCESS, REG_DATA_FIFO, REG_DID_VID, REG_RID, REG_STS};
use azos_tpm::BusError;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

pub fn h(s: &str) -> Vec<u8> {
    s.split_whitespace().map(|x| u8::from_str_radix(x, 16).unwrap()).collect()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Idle,
    Ready,
    Reception,
    Execution,
    Completion,
}

pub struct Dev {
    pub present: bool,
    pub family: u8,
    pub burst: u16,
    /// STS reads that report burstCount 0 before the real value.
    pub zero_burst_reads: u32,
    /// STS reads in Execution before dataAvail.
    pub exec_polls: u32,
    pub never_data_avail: bool,
    pub deny_locality: bool,
    /// expect drops after the first command byte.
    pub early_expect_clear: bool,
    /// expect stays set after the last command byte.
    pub stuck_expect: bool,
    /// dataAvail stays set after the last response byte.
    pub trailing_avail: bool,
    /// dataAvail drops after this many response bytes.
    pub truncate_at: Option<usize>,
    pub script: VecDeque<(Vec<u8>, Vec<u8>)>,
    pub seen: Vec<Vec<u8>>,
    pub violations: Vec<String>,
    pub active: Option<u8>,
    pub release_count: u32,
    pub cmd_ready_writes: u32,
    state: State,
    rx: Vec<u8>,
    rsp: Vec<u8>,
    rpos: usize,
    used: u32,
    reported: u32,
    polls_left: u32,
}

impl Dev {
    pub fn new() -> Dev {
        Dev {
            present: true,
            family: 1,
            burst: 8,
            zero_burst_reads: 0,
            exec_polls: 2,
            never_data_avail: false,
            deny_locality: false,
            early_expect_clear: false,
            stuck_expect: false,
            trailing_avail: false,
            truncate_at: None,
            script: VecDeque::new(),
            seen: Vec::new(),
            violations: Vec::new(),
            active: None,
            release_count: 0,
            cmd_ready_writes: 0,
            state: State::Idle,
            rx: Vec::new(),
            rsp: Vec::new(),
            rpos: 0,
            used: 0,
            reported: 0,
            polls_left: 0,
        }
    }

    pub fn expect(&mut self, cmd: &str, rsp: &str) {
        self.script.push_back((h(cmd), h(rsp)));
    }

    fn v(&mut self, s: &str) {
        self.violations.push(s.to_string());
    }

    fn needs_more(&self) -> bool {
        if self.stuck_expect {
            return true;
        }
        if self.early_expect_clear && !self.rx.is_empty() {
            return false;
        }
        if self.rx.len() < 6 {
            return true;
        }
        let want = u32::from_be_bytes([self.rx[2], self.rx[3], self.rx[4], self.rx[5]]) as usize;
        self.rx.len() < want
    }

    fn data_avail(&self) -> bool {
        if self.state != State::Completion {
            return false;
        }
        if let Some(t) = self.truncate_at {
            if self.rpos >= t {
                return false;
            }
        }
        self.rpos < self.rsp.len() || self.trailing_avail
    }

    fn sts(&mut self) -> u32 {
        if self.state == State::Execution && !self.never_data_avail {
            if self.polls_left == 0 {
                self.state = State::Completion;
            } else {
                self.polls_left -= 1;
            }
        }
        let mut b: u8 = 0x80;
        match self.state {
            State::Ready => b |= 0x40,
            State::Reception if self.needs_more() => b |= 0x08,
            State::Completion if self.data_avail() => b |= 0x10,
            _ => {}
        }
        let burst = if self.zero_burst_reads > 0 {
            self.zero_burst_reads -= 1;
            0
        } else {
            self.burst as u32
        };
        self.reported = burst;
        self.used = 0;
        (self.family as u32) << 26 | burst << 8 | b as u32
    }

    fn have_locality(&mut self, loc: u8, what: &str) -> bool {
        if self.active == Some(loc) {
            true
        } else {
            self.v(&format!("{what} without locality {loc}"));
            false
        }
    }

    pub fn reg_read(&mut self, loc: u8, reg: u16, n: usize) -> Vec<u8> {
        if !self.present {
            return vec![0xFF; n];
        }
        match reg {
            REG_ACCESS => {
                let mut a = 0x80u8;
                if self.active == Some(loc) {
                    a |= 0x20;
                }
                vec![a; n]
            }
            REG_STS => {
                if !self.have_locality(loc, "STS read") {
                    return vec![0xFF; n];
                }
                let s = self.sts().to_le_bytes();
                s[..n.min(4)].to_vec()
            }
            REG_DATA_FIFO => {
                let mut out = Vec::new();
                if !self.have_locality(loc, "FIFO read") {
                    return vec![0xFF; n];
                }
                for _ in 0..n {
                    self.used += 1;
                    if self.used > self.reported {
                        self.v("FIFO read beyond burstCount");
                    }
                    if self.state == State::Completion && self.rpos < self.rsp.len() {
                        out.push(self.rsp[self.rpos]);
                        self.rpos += 1;
                    } else {
                        self.v("FIFO read with no response");
                        out.push(0xFF);
                    }
                }
                out
            }
            REG_DID_VID => 0x001B_15D1u32.to_le_bytes()[..n.min(4)].to_vec(),
            REG_RID => vec![0x16; n],
            _ => vec![0; n],
        }
    }

    pub fn reg_write(&mut self, loc: u8, reg: u16, data: &[u8]) {
        if !self.present {
            return;
        }
        match reg {
            REG_ACCESS => {
                for b in data {
                    if b & 0x02 != 0 && self.active.is_none() && !self.deny_locality {
                        self.active = Some(loc);
                    }
                    if b & 0x20 != 0 && self.active == Some(loc) {
                        self.active = None;
                        self.release_count += 1;
                    }
                }
            }
            REG_STS => {
                if !self.have_locality(loc, "STS write") {
                    return;
                }
                for b in data {
                    if b & 0x40 != 0 {
                        self.cmd_ready_writes += 1;
                        self.state = State::Ready;
                        self.rx.clear();
                        self.rsp.clear();
                        self.rpos = 0;
                    }
                    if b & 0x20 != 0 {
                        self.go();
                    }
                }
            }
            REG_DATA_FIFO => {
                if !self.have_locality(loc, "FIFO write") {
                    return;
                }
                for b in data {
                    self.used += 1;
                    if self.used > self.reported {
                        self.v("FIFO write beyond burstCount");
                        continue;
                    }
                    match self.state {
                        State::Ready | State::Reception => {
                            if self.state == State::Reception && !self.needs_more() {
                                self.v("FIFO write after the command was complete");
                                continue;
                            }
                            self.state = State::Reception;
                            self.rx.push(*b);
                        }
                        _ => self.v("FIFO write outside Ready/Reception"),
                    }
                }
            }
            _ => {}
        }
    }

    fn go(&mut self) {
        if self.state != State::Reception || self.needs_more() && !self.stuck_expect {
            self.v("tpmGo before the command was complete");
            return;
        }
        let got = std::mem::take(&mut self.rx);
        self.seen.push(got.clone());
        match self.script.pop_front() {
            Some((cmd, rsp)) if cmd == got => self.rsp = rsp,
            Some((cmd, _)) => {
                self.v(&format!("command mismatch: want {cmd:02x?} got {got:02x?}"));
                self.rsp = h("80 01 00 00 00 0A 00 00 01 01");
            }
            None => {
                self.v(&format!("unscripted command {got:02x?}"));
                self.rsp = h("80 01 00 00 00 0A 00 00 01 01");
            }
        }
        self.rpos = 0;
        self.polls_left = self.exec_polls;
        self.state = State::Execution;
    }
}

pub type SharedDev = Rc<RefCell<Dev>>;

pub fn shared() -> SharedDev {
    Rc::new(RefCell::new(Dev::new()))
}

#[derive(Clone)]
pub struct FakeClock(pub Rc<Cell<u64>>);

impl FakeClock {
    pub fn new() -> FakeClock {
        FakeClock(Rc::new(Cell::new(0)))
    }
}

impl Clock for FakeClock {
    fn now_us(&mut self) -> u64 {
        self.0.get()
    }
    fn pause_us(&mut self, us: u32) {
        self.0.set(self.0.get() + us as u64);
    }
}

/// The device reached straight through the register trait.
pub struct Direct(pub SharedDev);

impl TisRegs for Direct {
    fn read(&mut self, locality: u8, reg: u16, buf: &mut [u8]) -> Result<(), BusError> {
        let v = self.0.borrow_mut().reg_read(locality, reg, buf.len());
        buf.copy_from_slice(&v);
        Ok(())
    }
    fn write(&mut self, locality: u8, reg: u16, data: &[u8]) -> Result<(), BusError> {
        self.0.borrow_mut().reg_write(locality, reg, data);
        Ok(())
    }
}

/// Lets a test pick the transport at run time.
pub struct Dyn(pub Box<dyn TisRegs>);

impl TisRegs for Dyn {
    fn read(&mut self, locality: u8, reg: u16, buf: &mut [u8]) -> Result<(), BusError> {
        self.0.read(locality, reg, buf)
    }
    fn write(&mut self, locality: u8, reg: u16, data: &[u8]) -> Result<(), BusError> {
        self.0.write(locality, reg, data)
    }
}

/// An MMIO window onto the device at `base`; records every access.
pub struct FakeMmio {
    pub dev: SharedDev,
    pub base: u64,
    pub log: Rc<RefCell<Vec<(u64, u8, bool)>>>,
}

impl FakeMmio {
    fn decode(&self, addr: u64) -> (u8, u16) {
        assert!(addr >= self.base && addr < self.base + 5 * 0x1000, "access outside the window: {addr:#x}");
        let off = addr - self.base;
        ((off / 0x1000) as u8, (off % 0x1000) as u16)
    }
}

impl MmioAccess for FakeMmio {
    fn read8(&mut self, addr: u64) -> u8 {
        let (l, r) = self.decode(addr);
        self.log.borrow_mut().push((addr, 1, false));
        self.dev.borrow_mut().reg_read(l, r, 1)[0]
    }
    fn read32(&mut self, addr: u64) -> u32 {
        let (l, r) = self.decode(addr);
        self.log.borrow_mut().push((addr, 4, false));
        let v = self.dev.borrow_mut().reg_read(l, r, 4);
        u32::from_le_bytes([v[0], v[1], v[2], v[3]])
    }
    fn write8(&mut self, addr: u64, v: u8) {
        let (l, r) = self.decode(addr);
        self.log.borrow_mut().push((addr, 1, true));
        self.dev.borrow_mut().reg_write(l, r, &[v]);
    }
}

/// One SPI transaction as seen on the wire.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frame {
    pub hdr: Vec<u8>,
    pub wait_bytes: usize,
    pub data: Vec<u8>,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Phase {
    Header,
    Wait,
    Data,
}

/// A TPM on a SPI bus: PTP framing, `wait_states` zero bytes before the ready
/// byte, chip select checked.
pub struct FakeSpi {
    pub dev: SharedDev,
    pub wait_states: usize,
    /// The ready byte never comes.
    pub never_ready: bool,
    pub frames: Rc<RefCell<Vec<Frame>>>,
    pub bus_violations: Rc<RefCell<Vec<String>>>,
    selected: bool,
    phase: Phase,
    cur: Frame,
    wait_left: usize,
    prefetch: Vec<u8>,
}

impl FakeSpi {
    pub fn new(dev: SharedDev, wait_states: usize) -> FakeSpi {
        FakeSpi {
            dev,
            wait_states,
            never_ready: false,
            frames: Rc::new(RefCell::new(Vec::new())),
            bus_violations: Rc::new(RefCell::new(Vec::new())),
            selected: false,
            phase: Phase::Header,
            cur: Frame::default(),
            wait_left: 0,
            prefetch: Vec::new(),
        }
    }

    fn bad(&mut self, s: &str) {
        self.bus_violations.borrow_mut().push(s.to_string());
    }

    fn len(&self) -> usize {
        (self.cur.hdr[0] & 0x3F) as usize + 1
    }

    fn is_read(&self) -> bool {
        self.cur.hdr[0] & 0x80 != 0
    }

    fn loc_reg(&self) -> (u8, u16) {
        let a = (self.cur.hdr[2] as u16) << 8 | self.cur.hdr[3] as u16;
        ((a >> 12) as u8, a & 0xFFF)
    }

    fn byte(&mut self, tx: u8) -> u8 {
        match self.phase {
            Phase::Header => {
                self.cur.hdr.push(tx);
                if self.cur.hdr.len() < 4 {
                    return 0;
                }
                if self.cur.hdr[1] != 0xD4 {
                    self.bad("address does not start with 0xD4");
                }
                if self.wait_states == 0 && !self.never_ready {
                    self.phase = Phase::Data;
                    self.begin_data();
                    1
                } else {
                    self.phase = Phase::Wait;
                    self.wait_left = self.wait_states;
                    0
                }
            }
            Phase::Wait => {
                self.cur.wait_bytes += 1;
                if self.never_ready {
                    return 0;
                }
                if self.wait_left > 0 {
                    self.wait_left -= 1;
                    0
                } else {
                    self.phase = Phase::Data;
                    self.begin_data();
                    1
                }
            }
            Phase::Data => {
                let n = self.cur.data.len();
                if n >= self.len() {
                    self.bad("more data bytes than the header declared");
                    return 0;
                }
                if self.is_read() {
                    let b = self.prefetch.get(n).copied().unwrap_or(0xFF);
                    self.cur.data.push(b);
                    b
                } else {
                    self.cur.data.push(tx);
                    if self.cur.data.len() == self.len() {
                        let (l, r) = self.loc_reg();
                        let d = self.cur.data.clone();
                        self.dev.borrow_mut().reg_write(l, r, &d);
                    }
                    0
                }
            }
        }
    }

    fn begin_data(&mut self) {
        if self.is_read() {
            let (l, r) = self.loc_reg();
            let n = self.len();
            self.prefetch = self.dev.borrow_mut().reg_read(l, r, n);
        }
    }
}

impl Spi for FakeSpi {
    fn select(&mut self, on: bool) {
        if on {
            if self.selected {
                self.bad("chip select asserted twice");
            }
            self.selected = true;
            self.phase = Phase::Header;
            self.cur = Frame::default();
            self.prefetch.clear();
        } else {
            if !self.selected {
                self.bad("chip select released while idle");
            }
            self.selected = false;
            if self.cur.hdr.len() == 4 && self.phase == Phase::Data && self.cur.data.len() != self.len() {
                self.bad("transaction ended before the declared length");
            }
            let f = std::mem::take(&mut self.cur);
            self.frames.borrow_mut().push(f);
        }
    }

    fn xfer(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<(), BusError> {
        assert_eq!(tx.len(), rx.len());
        if !self.selected {
            self.bad("transfer without chip select");
            return Err(BusError);
        }
        for (t, r) in tx.iter().zip(rx.iter_mut()) {
            *r = self.byte(*t);
        }
        Ok(())
    }
}
