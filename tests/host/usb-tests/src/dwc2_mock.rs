// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A register-level DesignWare USB 2.0 OTG core in host mode, buffer DMA.
//!
//! Behind the register window is a core that does what the databook says the
//! hardware does with what the driver programs: the global registers (soft
//! reset, forced host mode, FIFO sizes), the root port (`HPRT0`: power,
//! connect detect, a reset the software times, enable, the write-1-to-clear
//! bits), and host channels that run a control stage or a bulk/interrupt
//! transfer to the device at the address `HCCHAR` names, move the data by DMA
//! from and to `HCDMA`, keep the data toggle in `HCTSIZ.PID`, and halt with
//! the reason in `HCINT`. A NAKed bulk transfer stays on the channel (the core
//! retries it); a NAKed interrupt one halts. The devices are the fake devices
//! of [`crate::devices`], found by address; address 0 is the device whose port
//! was reset last.
//!
//! It is strict where hardware is: a DMA address that is not 4-byte aligned
//! or not memory, an IN transfer size that is not whole packets, a data PID
//! that is not the endpoint's toggle, a port reset shorter than 10 ms, the
//! port enable bit written back as read (which disables the port), a
//! full-speed device behind a high-speed hub reached without a split: each
//! one is recorded as a fault (`Hw2::fault`), and the canary for the matching
//! driver bug turns a test red.

use std::alloc::{alloc_zeroed, Layout};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use azos_usb::dwc2::regs::*;
use azos_usb::hw::{Clock, DmaBuf, Memory, Regs};

use crate::devices::DevRef;

pub struct Config2 {
    pub channels: u32,
    /// `GHWCFG3`: transfer-size and packet-count widths, FIFO depth.
    pub hwcfg3: u32,
    pub snpsid: u32,
}

impl Default for Config2 {
    fn default() -> Config2 {
        // The BCM2835's core: 8 channels, 19-bit transfer size, 10-bit packet
        // count, 4080 words of FIFO.
        Config2 { channels: 8, hwcfg3: 0x0ff0_00e8, snpsid: 0x4f54_280a }
    }
}

struct Region {
    bus: u64,
    ptr: *mut u8,
    len: usize,
}

#[derive(Clone, Copy, Default)]
struct Channel {
    hcchar: u32,
    hcint: u32,
    hcintmsk: u32,
    hctsiz: u32,
    hcdma: u32,
    hcsplt: u32,
    /// A bulk IN the device NAKed: retried until data comes.
    pending: bool,
}

/// A control transfer in progress at one address.
#[derive(Default)]
struct Ctl {
    setup: [u8; 8],
    resp: Option<Result<Vec<u8>, ()>>,
    in_pos: usize,
    out: Vec<u8>,
}

pub struct St2 {
    cfg: Config2,
    regions: Vec<Region>,
    next_bus: u64,
    gahbcfg: u32,
    gusbcfg: u32,
    gintsts: u32,
    hcfg: u32,
    host_mode: bool,
    soft_resets: u32,
    chans: Vec<Channel>,
    // The root port.
    root: Option<DevRef>,
    pwr: bool,
    ena: bool,
    connsts: bool,
    conndet: bool,
    enchng: bool,
    rst: bool,
    rst_at: u64,
    /// Devices by address; address 0 is `default_dev`.
    addrs: HashMap<u8, DevRef>,
    default_dev: Option<DevRef>,
    /// Is a device high speed behind a high-speed hub (no split needed), or
    /// low/full speed behind one (a split is)? Keyed by device pointer.
    behind_hs_hub: Vec<DevRef>,
    ctl: HashMap<u8, Ctl>,
    /// Data toggles by (address, endpoint address).
    toggles: HashMap<(u8, u8), u8>,
    /// Injected: the next transfer to (address, endpoint address) stalls, or
    /// fails with a transaction error (`n` times).
    pub stall_next: Vec<(u8, u8)>,
    pub xacterr_next: Vec<(u8, u8)>,
    pub fault: Option<String>,
    /// Channel runs started: (address, endpoint address, transfer size).
    pub runs: Vec<(u8, u8, u32)>,
}

pub struct Hw2 {
    pub st: RefCell<St2>,
    pub now: Cell<u64>,
}

impl St2 {
    fn fault(&mut self, why: String) {
        if self.fault.is_none() {
            self.fault = Some(why);
        }
    }

    fn region_of(&self, bus: u64, len: usize) -> Option<*mut u8> {
        self.regions.iter().find_map(|r| {
            (bus >= r.bus && bus + len as u64 <= r.bus + r.len as u64)
                // SAFETY: inside a live leaked region.
                .then(|| unsafe { r.ptr.add((bus - r.bus) as usize) })
        })
    }

    fn dma_read(&mut self, bus: u64, len: usize) -> Vec<u8> {
        if len == 0 {
            return Vec::new();
        }
        match self.region_of(bus, len) {
            // SAFETY: `len` bytes of a live region.
            Some(p) => unsafe { std::slice::from_raw_parts(p, len).to_vec() },
            None => {
                self.fault(format!("DMA read of {len} bytes at {bus:#x}: not memory"));
                vec![0; len]
            }
        }
    }

    fn dma_write(&mut self, bus: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        match self.region_of(bus, data.len()) {
            // SAFETY: `data.len()` bytes of a live region.
            Some(p) => unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len()) },
            None => self.fault(format!("DMA write of {} bytes at {bus:#x}: not memory", data.len())),
        }
    }

    fn hprt(&self) -> u32 {
        let mut v = 0;
        if self.connsts {
            v |= HPRT_CONNSTS;
            let psiv = self.root.as_ref().map_or(1, |d| d.borrow().speed_psiv);
            let spd = match psiv {
                3 => HPRT_SPD_HIGH,
                2 => HPRT_SPD_LOW,
                _ => HPRT_SPD_FULL,
            };
            v |= spd << HPRT_SPD_SHIFT;
        }
        if self.conndet {
            v |= HPRT_CONNDET;
        }
        if self.ena {
            v |= HPRT_ENA;
        }
        if self.enchng {
            v |= HPRT_ENCHNG;
        }
        if self.rst {
            v |= HPRT_RST;
        }
        if self.pwr {
            v |= HPRT_PWR;
        }
        v
    }

    fn write_hprt(&mut self, val: u32, now: u64) {
        if val & HPRT_CONNDET != 0 {
            self.conndet = false;
        }
        if val & HPRT_ENCHNG != 0 {
            self.enchng = false;
        }
        if val & HPRT_ENA != 0 && self.ena {
            self.fault("HPRT0 written with PRTENA set: the port was disabled".into());
            self.ena = false;
            self.enchng = true;
        }
        let pwr = val & HPRT_PWR != 0;
        if pwr && !self.pwr && self.root.is_some() {
            self.connsts = true;
            self.conndet = true;
        }
        if !pwr {
            self.connsts = false;
            self.ena = false;
        }
        self.pwr = pwr;
        let rst = val & HPRT_RST != 0;
        if rst && !self.rst {
            self.rst_at = now;
            self.ena = false;
        }
        if !rst && self.rst {
            if now < self.rst_at + 10_000 {
                self.fault(format!("port reset of {} us: shorter than 10 ms", now - self.rst_at));
            }
            if self.connsts {
                self.ena = true;
                self.enchng = true;
                self.default_dev = self.root.clone();
            }
        }
        self.rst = rst;
    }

    fn read(&mut self, off: usize) -> u32 {
        match off {
            GSNPSID => self.cfg.snpsid,
            GHWCFG2 => HWCFG2_ARCH_INTERNAL_DMA << HWCFG2_ARCH_SHIFT | (self.cfg.channels - 1) << HWCFG2_NUM_HOST_CHAN_SHIFT,
            GHWCFG3 => self.cfg.hwcfg3,
            GAHBCFG => self.gahbcfg,
            GUSBCFG => self.gusbcfg,
            GRSTCTL => GRSTCTL_AHBIDLE,
            GINTSTS => {
                let mut v = self.gintsts;
                if self.host_mode {
                    v |= GINTSTS_CURMOD_HOST;
                }
                if self.conndet || self.enchng {
                    v |= GINTSTS_PRTINT;
                }
                v
            }
            HCFG => self.hcfg,
            HFNUM => 0,
            HPRT0 => self.hprt(),
            o if (0x500..0x500 + 0x20 * self.cfg.channels as usize).contains(&o) => {
                let (ch, reg) = ((o - 0x500) / 0x20, (o - 0x500) % 0x20);
                if reg == HCINT && self.chans[ch].pending {
                    self.execute(ch);
                }
                let c = &self.chans[ch];
                match reg {
                    HCCHAR => c.hcchar,
                    HCSPLT => c.hcsplt,
                    HCINT => c.hcint,
                    HCINTMSK => c.hcintmsk,
                    HCTSIZ => c.hctsiz,
                    HCDMA => c.hcdma,
                    _ => 0,
                }
            }
            _ => 0,
        }
    }

    fn write(&mut self, off: usize, val: u32, now: u64) {
        match off {
            GAHBCFG => self.gahbcfg = val,
            GUSBCFG => {
                self.gusbcfg = val;
                if val & GUSBCFG_FORCEHOSTMODE != 0 {
                    self.host_mode = true;
                }
            }
            GRSTCTL => {
                if val & GRSTCTL_CSFTRST != 0 {
                    self.soft_resets += 1;
                }
            }
            GINTSTS => self.gintsts &= !val,
            HCFG => self.hcfg = val,
            HPRT0 => self.write_hprt(val, now),
            o if (0x500..0x500 + 0x20 * self.cfg.channels as usize).contains(&o) => {
                let (ch, reg) = ((o - 0x500) / 0x20, (o - 0x500) % 0x20);
                match reg {
                    HCCHAR => self.write_hcchar(ch, val),
                    HCSPLT => self.chans[ch].hcsplt = val,
                    HCINT => self.chans[ch].hcint &= !val,
                    HCINTMSK => self.chans[ch].hcintmsk = val,
                    HCTSIZ => self.chans[ch].hctsiz = val,
                    HCDMA => self.chans[ch].hcdma = val,
                    _ => {}
                }
            }
            _ => {}
        }
    }

    fn write_hcchar(&mut self, ch: usize, val: u32) {
        let was = self.chans[ch].hcchar;
        if val & HCCHAR_CHDIS != 0 && was & HCCHAR_CHENA != 0 {
            // Halt a running channel.
            let c = &mut self.chans[ch];
            c.hcchar = val & !(HCCHAR_CHENA | HCCHAR_CHDIS);
            c.hcint |= HCINT_CHHLTD;
            c.pending = false;
            return;
        }
        self.chans[ch].hcchar = val & !HCCHAR_CHDIS;
        if val & HCCHAR_CHENA != 0 && was & HCCHAR_CHENA == 0 {
            if self.gahbcfg & GAHBCFG_DMAEN == 0 {
                self.fault("channel enabled with DMA off".into());
            }
            self.execute(ch);
        }
    }

    fn halt(&mut self, ch: usize, int: u32) {
        let c = &mut self.chans[ch];
        c.hcint |= int | HCINT_CHHLTD;
        c.hcchar &= !HCCHAR_CHENA;
        c.pending = false;
    }

    /// Run what channel `ch` was programmed with.
    fn execute(&mut self, ch: usize) {
        let c = self.chans[ch];
        let mps = (c.hcchar & HCCHAR_MPS_MASK).max(1);
        let epnum = ((c.hcchar >> HCCHAR_EPNUM_SHIFT) & 0xf) as u8;
        let dir_in = c.hcchar & HCCHAR_EPDIR_IN != 0;
        let ty = (c.hcchar >> HCCHAR_EPTYPE_SHIFT) & 3;
        let addr = ((c.hcchar >> HCCHAR_DEVADDR_SHIFT) & 0x7f) as u8;
        let size = c.hctsiz & HCTSIZ_XFERSIZE_MASK;
        let pkts = (c.hctsiz >> HCTSIZ_PKTCNT_SHIFT) & HCTSIZ_PKTCNT_MASK;
        let pid = (c.hctsiz >> HCTSIZ_PID_SHIFT) & 3;
        let bus = c.hcdma as u64;
        if !c.pending {
            self.runs.push((addr, epnum | if dir_in { 0x80 } else { 0 }, size));
        }
        if bus & 3 != 0 {
            self.fault(format!("HCDMA {bus:#x} is not 4-byte aligned"));
        }
        if dir_in && size % mps != 0 {
            self.fault(format!("IN transfer size {size} is not whole {mps}-byte packets"));
        }
        if pkts == 0 || (size > 0 && pkts != size.div_ceil(mps)) {
            self.fault(format!("packet count {pkts} for {size} bytes of {mps}"));
        }
        let dev = if addr == 0 { self.default_dev.clone() } else { self.addrs.get(&addr).cloned() };
        let Some(dev) = dev else {
            // Nobody answers: a timeout, the core's transaction error.
            self.halt(ch, HCINT_XACTERR);
            return;
        };
        if self.behind_hs_hub.iter().any(|d| Rc::ptr_eq(d, &dev)) && dev.borrow().speed_psiv != 3 && c.hcsplt == 0 {
            self.fault("a full- or low-speed device behind a high-speed hub reached without a split".into());
        }
        let ep_addr = epnum | if dir_in { 0x80 } else { 0 };
        if let Some(i) = self.xacterr_next.iter().position(|&k| k == (addr, ep_addr)) {
            self.xacterr_next.remove(i);
            self.halt(ch, HCINT_XACTERR);
            return;
        }
        if ty == EPTYPE_CONTROL {
            self.control(ch, &dev, addr, pid, dir_in, bus, size, mps);
            return;
        }
        if let Some(i) = self.stall_next.iter().position(|&k| k == (addr, ep_addr)) {
            self.stall_next.remove(i);
            self.halt(ch, HCINT_STALL);
            return;
        }
        // The endpoint's toggle.
        let t = *self.toggles.entry((addr, ep_addr)).or_insert(0);
        let want_pid = if t == 0 { PID_DATA0 } else { PID_DATA1 };
        if pid != want_pid {
            self.fault(format!("addr {addr} ep {ep_addr:#x}: PID {pid}, the toggle is DATA{t}"));
        }
        let (moved, sent) = if dir_in {
            let is_hub = dev.borrow().hub.is_some() && epnum == 1;
            let data = dev.borrow_mut().poll_in(epnum, is_hub);
            let Some(data) = data else {
                if ty == EPTYPE_INTR {
                    self.halt(ch, HCINT_NAK);
                } else {
                    self.chans[ch].pending = true;
                }
                return;
            };
            if data.len() > size as usize {
                self.dma_write(bus, &data[..size as usize]);
                self.halt(ch, HCINT_BBLERR);
                return;
            }
            self.dma_write(bus, &data);
            (data.len() as u32, (data.len() as u32).div_ceil(mps).max(1))
        } else {
            let data = self.dma_read(bus, size as usize);
            dev.borrow_mut().out_log.push((epnum, data));
            (size, pkts)
        };
        let nt = t ^ (sent & 1) as u8;
        self.toggles.insert((addr, ep_addr), nt);
        let next_pid = if nt == 0 { PID_DATA0 } else { PID_DATA1 };
        let c = &mut self.chans[ch];
        c.hctsiz = (size - moved) | pkts.saturating_sub(sent) << HCTSIZ_PKTCNT_SHIFT | next_pid << HCTSIZ_PID_SHIFT;
        self.halt(ch, HCINT_XFERCOMPL);
    }

    #[allow(clippy::too_many_arguments)]
    fn control(&mut self, ch: usize, dev: &DevRef, addr: u8, pid: u32, dir_in: bool, bus: u64, size: u32, mps: u32) {
        let done = |s: &mut St2, moved: u32, next: u32| {
            let c = &mut s.chans[ch];
            let pk = (c.hctsiz >> HCTSIZ_PKTCNT_SHIFT) & HCTSIZ_PKTCNT_MASK;
            c.hctsiz = (size - moved) | pk.saturating_sub(moved.div_ceil(mps).max(1)) << HCTSIZ_PKTCNT_SHIFT | next << HCTSIZ_PID_SHIFT;
            s.halt(ch, HCINT_XFERCOMPL);
        };
        if pid == PID_SETUP {
            if dir_in || size != 8 {
                self.fault(format!("setup stage: dir_in {dir_in}, {size} bytes"));
            }
            let b = self.dma_read(bus, 8);
            let mut setup = [0u8; 8];
            setup.copy_from_slice(&b);
            let wlen = u16::from_le_bytes([setup[6], setup[7]]) as usize;
            let mut st = Ctl { setup, ..Ctl::default() };
            if (setup[0], setup[1]) == (0x00, 5) {
                // SET_ADDRESS is the bus's: every device takes it (the xHCI
                // mock's controller sends it itself). Logged like the rest.
                dev.borrow_mut().requests.push((setup, Vec::new()));
                st.resp = Some(Ok(Vec::new()));
            } else if setup[0] & 0x80 != 0 || wlen == 0 {
                st.resp = Some(dev.borrow_mut().control(setup, &[]).map(|mut v| {
                    v.truncate(wlen);
                    v
                }));
            }
            self.ctl.insert(addr, st);
            done(self, 8, PID_DATA1);
            return;
        }
        let Some(mut st) = self.ctl.remove(&addr) else {
            self.fault(format!("addr {addr}: a control data or status stage with no setup"));
            self.halt(ch, HCINT_STALL);
            return;
        };
        let req_in = st.setup[0] & 0x80 != 0;
        let wlen = u16::from_le_bytes([st.setup[6], st.setup[7]]) as usize;
        let status = size == 0 && (wlen == 0 || dir_in != req_in);
        if !status {
            // Data stage.
            if dir_in != req_in {
                self.fault(format!("addr {addr}: data stage the wrong way"));
            }
            if st.in_pos == 0 && st.out.is_empty() && pid != PID_DATA1 {
                self.fault(format!("addr {addr}: first data packet PID {pid}, not DATA1"));
            }
            if dir_in {
                match st.resp.clone() {
                    Some(Ok(v)) => {
                        let rest = &v[st.in_pos.min(v.len())..];
                        let n = rest.len().min(size as usize);
                        self.dma_write(bus, &rest[..n]);
                        st.in_pos += n;
                        self.ctl.insert(addr, st);
                        let packets = (n as u32).div_ceil(mps).max(1);
                        done(self, n as u32, if packets % 2 == 1 { PID_DATA0 } else { PID_DATA1 });
                    }
                    _ => {
                        self.halt(ch, HCINT_STALL);
                    }
                }
            } else {
                let b = self.dma_read(bus, size as usize);
                st.out.extend(b);
                self.ctl.insert(addr, st);
                done(self, size, PID_DATA0);
            }
            return;
        }
        // Status stage.
        if pid != PID_DATA1 {
            self.fault(format!("addr {addr}: status stage PID {pid}, not DATA1"));
        }
        let resp = match st.resp.take() {
            Some(r) => r,
            None => dev.borrow_mut().control(st.setup, &st.out),
        };
        if resp.is_err() {
            self.halt(ch, HCINT_STALL);
            return;
        }
        // What the request did to the bus: an address, a reset hub port.
        let (rt, req) = (st.setup[0], st.setup[1]);
        let value = u16::from_le_bytes([st.setup[2], st.setup[3]]);
        let index = u16::from_le_bytes([st.setup[4], st.setup[5]]) as usize;
        if (rt, req) == (0x00, 5) {
            if addr == 0 {
                self.default_dev = None;
            }
            self.addrs.retain(|_, d| !Rc::ptr_eq(d, dev));
            self.addrs.insert(value as u8, dev.clone());
        }
        if (rt, req, value) == (0x23, 3, 4) {
            let hub_hs = dev.borrow().speed_psiv == 3;
            let child = dev.borrow().hub.as_ref().and_then(|h| h.children.get(index.wrapping_sub(1)).cloned().flatten());
            if let Some(c) = child {
                if hub_hs && !self.behind_hs_hub.iter().any(|d| Rc::ptr_eq(d, &c)) {
                    self.behind_hs_hub.push(c.clone());
                }
                self.default_dev = Some(c);
            }
        }
        done(self, 0, PID_DATA1);
    }
}

impl Hw2 {
    pub fn new(cfg: Config2) -> Rc<Hw2> {
        let n = cfg.channels as usize;
        Rc::new(Hw2 {
            st: RefCell::new(St2 {
                cfg,
                regions: Vec::new(),
                next_bus: 0x0010_0000,
                gahbcfg: 0,
                gusbcfg: 0,
                gintsts: 0,
                hcfg: 0,
                host_mode: false,
                soft_resets: 0,
                chans: vec![Channel::default(); n],
                root: None,
                pwr: false,
                ena: false,
                connsts: false,
                conndet: false,
                enchng: false,
                rst: false,
                rst_at: 0,
                addrs: HashMap::new(),
                default_dev: None,
                behind_hs_hub: Vec::new(),
                ctl: HashMap::new(),
                toggles: HashMap::new(),
                stall_next: Vec::new(),
                xacterr_next: Vec::new(),
                fault: None,
                runs: Vec::new(),
            }),
            now: Cell::new(0),
        })
    }

    pub fn regs(self: &Rc<Hw2>) -> Regs2 {
        Regs2(self.clone())
    }
    pub fn clock(self: &Rc<Hw2>) -> Clock2 {
        Clock2(self.clone())
    }
    pub fn mem(self: &Rc<Hw2>) -> Mem2 {
        Mem2(self.clone())
    }

    pub fn attach_root(&self, dev: DevRef) {
        let mut st = self.st.borrow_mut();
        st.root = Some(dev);
        if st.pwr {
            st.connsts = true;
            st.conndet = true;
        }
    }

    pub fn detach_root(&self) {
        let mut st = self.st.borrow_mut();
        if let Some(d) = st.root.take() {
            st.addrs.retain(|_, x| !Rc::ptr_eq(x, &d));
        }
        st.connsts = false;
        if st.ena {
            st.ena = false;
            st.enchng = true;
        }
        st.gintsts |= GINTSTS_DISCONNINT;
    }

    /// Plug `child` into port `port` of `hub` (its status bitmap shows it).
    pub fn hub_attach(&self, hub: &DevRef, port: usize, child: DevRef) {
        let mut h = hub.borrow_mut();
        let psiv = child.borrow().speed_psiv;
        let hm = h.hub.as_mut().unwrap();
        hm.children[port - 1] = Some(child);
        let p = &mut hm.ports[port - 1];
        p.connected = true;
        p.low = psiv == 2;
        p.high = psiv == 3;
        p.change |= 1;
    }

    pub fn inject_in(&self, dev: &DevRef, ep: usize, data: &[u8]) {
        dev.borrow_mut().in_queue[ep].push_back(data.to_vec());
    }

    /// The address the core has given `dev`.
    pub fn address_of(&self, dev: &DevRef) -> Option<u8> {
        self.st.borrow().addrs.iter().find(|(_, d)| Rc::ptr_eq(d, dev)).map(|(a, _)| *a)
    }

    pub fn fault(&self) -> Option<String> {
        self.st.borrow().fault.clone()
    }
    pub fn gahbcfg(&self) -> u32 {
        self.st.borrow().gahbcfg
    }
    pub fn host_mode(&self) -> bool {
        self.st.borrow().host_mode
    }
    pub fn soft_resets(&self) -> u32 {
        self.st.borrow().soft_resets
    }
    pub fn port_powered(&self) -> bool {
        self.st.borrow().pwr
    }
    pub fn runs(&self) -> Vec<(u8, u8, u32)> {
        self.st.borrow().runs.clone()
    }
}

pub struct Regs2(Rc<Hw2>);
pub struct Clock2(Rc<Hw2>);
pub struct Mem2(Rc<Hw2>);

impl Regs for Regs2 {
    fn read32(&self, off: usize) -> u32 {
        self.0.st.borrow_mut().read(off)
    }
    fn write32(&self, off: usize, val: u32) {
        let now = self.0.now.get();
        self.0.st.borrow_mut().write(off, val, now)
    }
}

impl Clock for Clock2 {
    fn now_us(&self) -> u64 {
        self.0.now.get()
    }
    fn delay_us(&self, us: u32) {
        self.0.now.set(self.0.now.get() + us as u64);
    }
}

impl Memory for Mem2 {
    fn alloc_region(&self, len: usize, align: usize, mask: u64) -> Option<DmaBuf> {
        let mut st = self.0.st.borrow_mut();
        let align = align.max(4096);
        let layout = Layout::from_size_align(len, align).ok()?;
        // SAFETY: a non-zero size; the memory is leaked, as a test wants.
        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            return None;
        }
        let bus = st.next_bus.next_multiple_of(align as u64);
        st.next_bus = bus + len as u64;
        if bus + len as u64 - 1 > mask {
            return None;
        }
        st.regions.push(Region { bus, ptr, len });
        // SAFETY: `ptr` is `len` bytes of live, leaked memory.
        Some(unsafe { DmaBuf::new(ptr, bus, len) })
    }
    fn free_region(&self, b: DmaBuf) {
        self.0.st.borrow_mut().regions.retain(|r| r.bus != b.bus());
    }
    fn enable(&self) -> bool {
        true
    }
    fn to_device(&self, _cpu: *const u8, _len: usize) {}
    fn from_device(&self, _cpu: *const u8, _len: usize) {}
    fn cpu_of(&self, bus: u64, len: usize) -> Option<*mut u8> {
        self.0.st.borrow().region_of(bus, len)
    }
}
