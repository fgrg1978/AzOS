// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A register-level xHCI controller.
//!
//! What the driver sees is a register window and DMA memory; what is behind
//! them here is a controller that does what the specification says the
//! hardware does: it executes the command ring (Enable Slot, Address Device,
//! Configure Endpoint, ...), keeps the output device contexts in the memory
//! the driver gave it, walks the transfer rings by cycle bit and Link TRB,
//! posts events into the event ring with the right cycle bit, runs the port
//! state machine (connect, reset, enable), and talks to a tree of fake
//! devices and hubs ([`crate::devices`]). It is strict where hardware is: a
//! DMA address above 4 GiB on a controller without AC64, a TRB that crosses a
//! 64 KiB boundary, a scratchpad array that does not hold what the controller
//! asked for, contexts read at the wrong stride, a ring entry with the wrong
//! cycle bit: each one wedges or fails the controller, the way it would
//! hardware, and the canary for the matching driver bug turns a test red.

use std::alloc::{alloc_zeroed, Layout};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use azos_usb::hw::{Clock, DmaBuf, Memory, Regs};

use crate::devices::DevRef;

const CAPLENGTH: usize = 0x20;
const RTSOFF: usize = 0x1800;
const DBOFF: usize = 0x2000;
const OP: usize = CAPLENGTH;
const PORT0: usize = OP + 0x400;
const IR0: usize = RTSOFF + 0x20;
/// The extended capability list: USB Legacy Support, alone.
const XECP: usize = 0x1c00;

pub struct Config {
    pub ac64: bool,
    pub csz64: bool,
    pub scratch: u32,
    pub max_slots: u32,
    pub ports: u32,
    pub ppc: bool,
    /// PAGESIZE register: bit n = 2^(n+12).
    pub pagesize: u32,
    /// Microseconds a port reset takes.
    pub reset_us: u64,
    /// The firmware owns the controller at power-on (USB Legacy Support).
    pub bios_owned: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config { ac64: true, csz64: false, scratch: 0, max_slots: 32, ports: 4, ppc: false, pagesize: 1, reset_us: 20_000, bios_owned: false }
    }
}

struct Region {
    bus: u64,
    ptr: *mut u8,
    len: usize,
}

#[derive(Clone, Copy, Default)]
struct EpState {
    ptr: u64,
    ccs: bool,
    /// 0 disabled, 1 running, 2 halted, 3 stopped.
    state: u8,
    ep_type: u8,
    mps: u16,
    interval: u8,
    /// The endpoint context the driver configured it with.
    ctx: [u32; 8],
}

#[derive(Default)]
struct Slot {
    enabled: bool,
    dev: Option<DevRef>,
    address: u8,
    out_ctx: u64,
    eps: Vec<EpState>,
    slot_ctx: [u32; 8],
}

#[derive(Default)]
struct RootPort {
    dev: Option<DevRef>,
    ccs: bool,
    ped: bool,
    pp: bool,
    reset_done_at: Option<u64>,
    changes: u32,
}

pub struct St {
    cfg: Config,
    regions: Vec<Region>,
    next_low: u64,
    next_high: u64,
    usbcmd: u32,
    usbsts: u32,
    crcr: u64,
    cmd_ptr: u64,
    cmd_ccs: bool,
    dcbaap: u64,
    config: u32,
    iman: u32,
    erstsz: u32,
    erstba: u64,
    erdp: u64,
    ev_base: u64,
    ev_size: usize,
    ev_enq: usize,
    ev_cycle: bool,
    ehb: bool,
    slots: Vec<Slot>,
    ports: Vec<RootPort>,
    legsup: u32,
    legctl: u32,
    inject: Vec<(usize, usize, u8)>,
    /// Commands the controller takes off its ring and never answers.
    lose_commands: u32,
    /// HCRST never completes (the bit stays set).
    hcrst_stuck: bool,
    /// Host controller resets done (HCRST writes that completed).
    pub hc_resets: u32,
    /// Command TRB types executed, in order.
    pub commands: Vec<u8>,
    /// Interrupts the controller raised (an event posted with EHB clear).
    pub interrupts_raised: u32,
    pub fault: Option<String>,
    /// Transfer events posted: (slot, dci, completion code).
    pub xfer_events: Vec<(u8, u8, u8)>,
    /// The first TRB of every data transfer descriptor the controller ran:
    /// (slot, dci, TRB words).
    pub td_first: Vec<(u8, u8, [u32; 4])>,
}

pub struct Hw {
    pub st: RefCell<St>,
    pub now: Cell<u64>,
}

// ---- Memory and the DMA discipline ----

impl St {
    fn translate(&self, bus: u64, n: usize) -> Option<*mut u8> {
        self.regions
            .iter()
            .find(|r| bus >= r.bus && bus + n as u64 <= r.bus + r.len as u64)
            .map(|r| r.ptr.wrapping_add((bus - r.bus) as usize))
    }

    fn fault(&mut self, why: String) {
        if self.fault.is_none() {
            self.fault = Some(why);
        }
        self.usbsts |= 1 << 2; // HSE
    }

    /// A DMA access: the controller must be able to address it, and it must be
    /// the driver's memory.
    fn dma(&mut self, bus: u64, n: usize) -> Option<*mut u8> {
        if !self.cfg.ac64 && bus + n as u64 > 1 << 32 {
            self.fault(format!("DMA to {bus:#x} on a controller without AC64"));
            return None;
        }
        let p = self.translate(bus, n);
        if p.is_none() {
            self.fault(format!("DMA to unmapped {bus:#x}+{n}"));
        }
        p
    }

    fn rd(&mut self, bus: u64, n: usize) -> Option<Vec<u8>> {
        let p = self.dma(bus, n)?;
        let mut v = vec![0u8; n];
        for (i, b) in v.iter_mut().enumerate() {
            *b = unsafe { std::ptr::read_volatile(p.add(i)) };
        }
        Some(v)
    }

    fn wr(&mut self, bus: u64, data: &[u8]) -> bool {
        let Some(p) = self.dma(bus, data.len()) else { return false };
        for (i, b) in data.iter().enumerate() {
            unsafe { std::ptr::write_volatile(p.add(i), *b) };
        }
        true
    }

    fn rd32(&mut self, bus: u64) -> u32 {
        self.rd(bus, 4).map_or(0, |v| u32::from_le_bytes(v.try_into().unwrap()))
    }
    fn rd64(&mut self, bus: u64) -> u64 {
        self.rd(bus, 8).map_or(0, |v| u64::from_le_bytes(v.try_into().unwrap()))
    }

    fn read_trb(&mut self, bus: u64) -> Option<[u32; 4]> {
        let v = self.rd(bus, 16)?;
        let w = |i: usize| u32::from_le_bytes(v[i * 4..i * 4 + 4].try_into().unwrap());
        Some([w(0), w(1), w(2), w(3)])
    }

    // ---- Event ring ----

    fn post(&mut self, trb: [u32; 4]) {
        if self.ev_size == 0 || self.usbcmd & 1 == 0 {
            return;
        }
        let at = self.ev_base + (self.ev_enq * 16) as u64;
        let ctrl = (trb[3] & !1) | self.ev_cycle as u32;
        let mut b = Vec::new();
        for w in [trb[0], trb[1], trb[2], ctrl] {
            b.extend(w.to_le_bytes());
        }
        self.wr(at, &b);
        self.ev_enq += 1;
        if self.ev_enq == self.ev_size {
            self.ev_enq = 0;
            self.ev_cycle = !self.ev_cycle;
        }
        // Event Handler Busy: an interrupt only when the handler was idle.
        if !self.ehb {
            self.interrupts_raised += 1;
            self.iman |= 1;
            self.usbsts |= 1 << 3;
        }
        self.ehb = true;
    }

    fn post_psc(&mut self, port: usize) {
        self.post([((port + 1) as u32) << 24, 0, 1u32 << 24, 34 << 10]);
    }

    fn post_xfer(&mut self, slot: usize, dci: usize, trb_bus: u64, code: u8, residue: u32) {
        self.xfer_events.push((slot as u8, dci as u8, code));
        self.post([
            trb_bus as u32,
            (trb_bus >> 32) as u32,
            (code as u32) << 24 | (residue & 0xff_ffff),
            32 << 10 | (dci as u32) << 16 | (slot as u32) << 24,
        ]);
    }

    // ---- Contexts ----

    fn csz(&self) -> u64 {
        if self.cfg.csz64 { 64 } else { 32 }
    }

    fn ctx(&mut self, base: u64, idx: u64) -> [u32; 8] {
        let at = base + idx * self.csz();
        let mut out = [0u32; 8];
        if let Some(v) = self.rd(at, 32) {
            for (i, w) in out.iter_mut().enumerate() {
                *w = u32::from_le_bytes(v[i * 4..i * 4 + 4].try_into().unwrap());
            }
        }
        out
    }

    fn put_ctx(&mut self, base: u64, idx: u64, c: &[u32; 8]) {
        let at = base + idx * self.csz();
        let mut b = Vec::new();
        for w in c {
            b.extend(w.to_le_bytes());
        }
        self.wr(at, &b);
    }

    fn set_ep_state(&mut self, slot: usize, dci: usize, state: u8) {
        self.slots[slot].eps[dci].state = state;
        let out = self.slots[slot].out_ctx;
        if out != 0 {
            let mut c = self.ctx(out, dci as u64);
            c[0] = (c[0] & !7) | state as u32;
            self.put_ctx(out, dci as u64, &c);
        }
    }

    // ---- Commands ----

    fn find_dev(&self, root_port: usize, route: u32) -> Option<DevRef> {
        let mut cur = self.ports.get(root_port.checked_sub(1)?)?.dev.clone()?;
        let mut r = route;
        while r != 0 {
            let n = (r & 0xf) as usize;
            r >>= 4;
            let next = cur.borrow().hub.as_ref()?.children.get(n.checked_sub(1)?)?.clone()?;
            cur = next;
        }
        Some(cur)
    }

    fn commands(&mut self) {
        if self.fault.is_some() || self.usbcmd & 1 == 0 {
            return;
        }
        loop {
            let Some(t) = self.read_trb(self.cmd_ptr) else { return };
            if (t[3] & 1 != 0) != self.cmd_ccs {
                return;
            }
            let ty = ((t[3] >> 10) & 0x3f) as u8;
            if ty == 6 {
                let target = (t[0] as u64 | (t[1] as u64) << 32) & !0xf;
                if t[3] & 2 != 0 {
                    self.cmd_ccs = !self.cmd_ccs;
                }
                self.cmd_ptr = target;
                continue;
            }
            let at = self.cmd_ptr;
            self.cmd_ptr += 16;
            if self.lose_commands > 0 {
                self.lose_commands -= 1;
                continue;
            }
            self.commands.push(ty);
            let (code, slot) = self.exec_cmd(ty, &t);
            self.post([at as u32, (at >> 32) as u32, (code as u32) << 24, 33 << 10 | (slot as u32) << 24]);
        }
    }

    fn exec_cmd(&mut self, ty: u8, t: &[u32; 4]) -> (u8, usize) {
        let param = t[0] as u64 | (t[1] as u64) << 32;
        let slot = (t[3] >> 24) as usize;
        let dci = ((t[3] >> 16) & 0x1f) as usize;
        const OK: u8 = 1;
        const NO_SLOTS: u8 = 9;
        const SLOT_NOT_ENABLED: u8 = 11;
        const PARAM_ERR: u8 = 17;
        const CTX_STATE: u8 = 19;
        let valid = slot >= 1 && slot < self.slots.len() && self.slots[slot].enabled;
        match ty {
            23 => (OK, 0),
            9 => match (1..self.slots.len()).find(|&i| !self.slots[i].enabled) {
                Some(i) => {
                    self.slots[i] = Slot { enabled: true, eps: vec![EpState::default(); 32], ..Slot::default() };
                    (OK, i)
                }
                None => (NO_SLOTS, 0),
            },
            10 => {
                if !valid {
                    return (SLOT_NOT_ENABLED, slot);
                }
                self.slots[slot] = Slot::default();
                (OK, slot)
            }
            11 => {
                if !valid {
                    return (SLOT_NOT_ENABLED, slot);
                }
                let icc = self.ctx(param, 0);
                let sc = self.ctx(param, 1);
                let ep0 = self.ctx(param, 2);
                // The input control context must add the slot and endpoint 0,
                // and endpoint 0 must be a control endpoint with a ring.
                if icc[1] & 3 != 3 || (ep0[1] >> 3) & 7 != 4 || ep0[2] & !0xf == 0 && ep0[3] == 0 {
                    return (PARAM_ERR, slot);
                }
                let route = sc[0] & 0xf_ffff;
                let root_port = ((sc[1] >> 16) & 0xff) as usize;
                let Some(dev) = self.find_dev(root_port, route) else { return (4, slot) };
                let out = {
                    let a = self.dcbaap + 8 * slot as u64;
                    self.rd64(a)
                };
                if out == 0 {
                    return (PARAM_ERR, slot);
                }
                let addr = slot as u8;
                let mut oc = sc;
                oc[3] = (oc[3] & !0xf800_00ff) | 2 << 27 | addr as u32;
                self.put_ctx(out, 0, &oc);
                let mut e0 = ep0;
                e0[0] = (e0[0] & !7) | 1;
                self.put_ctx(out, 1, &e0);
                let s = &mut self.slots[slot];
                s.dev = Some(dev);
                s.address = addr;
                s.out_ctx = out;
                s.slot_ctx = sc;
                s.eps[1] = EpState {
                    ptr: (ep0[2] as u64 | (ep0[3] as u64) << 32) & !0xf,
                    ccs: ep0[2] & 1 != 0,
                    state: 1,
                    ep_type: 4,
                    mps: (ep0[1] >> 16) as u16,
                    interval: 0,
                    ctx: ep0,
                };
                (OK, slot)
            }
            12 => {
                if !valid || self.slots[slot].out_ctx == 0 {
                    return (SLOT_NOT_ENABLED, slot);
                }
                let icc = self.ctx(param, 0);
                let (drop, add) = (icc[0], icc[1]);
                let out = self.slots[slot].out_ctx;
                for d in 2..32 {
                    if drop & 1 << d != 0 {
                        self.set_ep_state(slot, d, 0);
                    }
                }
                for d in 2..32usize {
                    if add & 1 << d != 0 {
                        let mut c = self.ctx(param, d as u64 + 1);
                        if (c[1] >> 3) & 7 == 0 {
                            return (PARAM_ERR, slot);
                        }
                        c[0] = (c[0] & !7) | 1;
                        self.put_ctx(out, d as u64, &c);
                        self.slots[slot].eps[d] = EpState {
                            ptr: (c[2] as u64 | (c[3] as u64) << 32) & !0xf,
                            ccs: c[2] & 1 != 0,
                            state: 1,
                            ep_type: ((c[1] >> 3) & 7) as u8,
                            mps: (c[1] >> 16) as u16,
                            interval: (c[0] >> 16) as u8,
                            ctx: c,
                        };
                    }
                }
                if add & 1 != 0 {
                    let sc = self.ctx(param, 1);
                    let mut oc = self.ctx(out, 0);
                    oc[3] = (oc[3] & !0xf800_0000) | 3 << 27;
                    oc[0] = (oc[0] & !(0x1f << 27)) | (sc[0] & 0x1f << 27);
                    self.put_ctx(out, 0, &oc);
                    self.slots[slot].slot_ctx = sc;
                }
                (OK, slot)
            }
            13 => {
                if !valid || self.slots[slot].out_ctx == 0 {
                    return (SLOT_NOT_ENABLED, slot);
                }
                let icc = self.ctx(param, 0);
                let out = self.slots[slot].out_ctx;
                if icc[1] & 1 != 0 {
                    let sc = self.ctx(param, 1);
                    self.slots[slot].slot_ctx = sc;
                    let mut oc = self.ctx(out, 0);
                    // Hub fields and the max exit latency are evaluated.
                    oc[0] = (oc[0] & !(1 << 26 | 1 << 25)) | (sc[0] & (1 << 26 | 1 << 25));
                    oc[1] = sc[1];
                    oc[2] = sc[2];
                    self.put_ctx(out, 0, &oc);
                }
                if icc[1] & 2 != 0 {
                    let c = self.ctx(param, 2);
                    let mps = (c[1] >> 16) as u16;
                    let mut oc = self.ctx(out, 1);
                    oc[1] = (oc[1] & 0xffff) | (mps as u32) << 16;
                    self.put_ctx(out, 1, &oc);
                    self.slots[slot].eps[1].mps = mps;
                }
                (OK, slot)
            }
            14 => {
                if !valid || dci < 1 {
                    return (SLOT_NOT_ENABLED, slot);
                }
                if self.slots[slot].eps[dci].state != 2 {
                    return (CTX_STATE, slot);
                }
                self.set_ep_state(slot, dci, 3);
                (OK, slot)
            }
            15 => {
                if valid && dci >= 1 {
                    self.set_ep_state(slot, dci, 3);
                }
                (OK, slot)
            }
            16 => {
                if !valid || dci < 1 {
                    return (SLOT_NOT_ENABLED, slot);
                }
                let e = &mut self.slots[slot].eps[dci];
                if e.state != 3 {
                    return (CTX_STATE, slot);
                }
                e.ptr = param & !0xf;
                e.ccs = param & 1 != 0;
                self.set_ep_state(slot, dci, 1);
                (OK, slot)
            }
            _ => (PARAM_ERR, slot),
        }
    }

    // ---- Transfers ----

    fn process_ring(&mut self, slot: usize, dci: usize) {
        if self.fault.is_some() || slot >= self.slots.len() || !self.slots[slot].enabled || dci >= 32 {
            return;
        }
        loop {
            let ep = self.slots[slot].eps[dci];
            if ep.state != 1 {
                return;
            }
            let Some(td) = self.read_td(ep.ptr, ep.ccs) else { return };
            // The 64 KiB rule is the controller's: a TRB may not cross one.
            for (bus, t) in &td.trbs {
                let ty = (t[3] >> 10) & 0x3f;
                let len = (t[2] & 0x1_ffff) as u64;
                let buf = t[0] as u64 | (t[1] as u64) << 32;
                if matches!(ty, 1 | 3 | 5) && len > 0 && (buf & 0xffff) + len > 0x1_0000 {
                    self.post_xfer(slot, dci, *bus, 5, 0);
                    self.set_ep_state(slot, dci, 2);
                    return;
                }
            }
            if let Some(pos) = self.inject.iter().position(|&(s, d, _)| s == slot && d == dci) {
                let (_, _, code) = self.inject.remove(pos);
                if ep.ep_type == 5 {
                    // An isochronous endpoint does not halt on an error: the
                    // interval's descriptor completes with the code and the
                    // ring moves on to the next.
                    self.post_xfer(slot, dci, td.trbs.last().unwrap().0, code, 0);
                    let e = &mut self.slots[slot].eps[dci];
                    e.ptr = td.end_ptr;
                    e.ccs = td.end_ccs;
                    continue;
                }
                self.post_xfer(slot, dci, td.trbs[0].0, code, 0);
                self.set_ep_state(slot, dci, 2);
                return;
            }
            match self.exec_td(slot, dci, &td) {
                Exec::Pending => return,
                Exec::Halted => return,
                Exec::Done => {
                    if dci != 1 {
                        self.td_first.push((slot as u8, dci as u8, td.trbs[0].1));
                    }
                    let e = &mut self.slots[slot].eps[dci];
                    e.ptr = td.end_ptr;
                    e.ccs = td.end_ccs;
                }
            }
        }
    }

    fn read_td(&mut self, ptr: u64, ccs: bool) -> Option<Td> {
        let (mut p, mut c) = (ptr, ccs);
        let mut trbs: Vec<(u64, [u32; 4])> = Vec::new();
        let mut hops = 0;
        loop {
            let t = self.read_trb(p)?;
            if (t[3] & 1 != 0) != c {
                return None;
            }
            let ty = ((t[3] >> 10) & 0x3f) as u8;
            if ty == 6 {
                hops += 1;
                if hops > 4 {
                    return None;
                }
                p = (t[0] as u64 | (t[1] as u64) << 32) & !0xf;
                if t[3] & 2 != 0 {
                    c = !c;
                }
                continue;
            }
            trbs.push((p, t));
            p += 16;
            let first_ty = ((trbs[0].1[3] >> 10) & 0x3f) as u8;
            let end = if first_ty == 2 { ty == 4 } else { t[3] & (1 << 4) == 0 };
            if end {
                return Some(Td { trbs, end_ptr: p, end_ccs: c });
            }
        }
    }

    fn exec_td(&mut self, slot: usize, dci: usize, td: &Td) -> Exec {
        let dev = self.slots[slot].dev.clone();
        let Some(dev) = dev else { return Exec::Halted };
        let first = td.trbs[0].1;
        let is_ctl = ((first[3] >> 10) & 0x3f) == 2;
        let data_trbs: Vec<&(u64, [u32; 4])> = td
            .trbs
            .iter()
            .filter(|(_, t)| matches!((t[3] >> 10) & 0x3f, 1 | 3 | 5))
            .collect();
        let total: usize = data_trbs.iter().map(|(_, t)| (t[2] & 0x1_ffff) as usize).sum();
        let last = td.trbs.last().unwrap();

        // The data this TD sends, if it is an OUT.
        let gather = |st: &mut St| -> Vec<u8> {
            let mut out = Vec::new();
            for (_, t) in &data_trbs {
                let buf = t[0] as u64 | (t[1] as u64) << 32;
                let n = (t[2] & 0x1_ffff) as usize;
                if let Some(v) = st.rd(buf, n) {
                    out.extend(v);
                }
            }
            out
        };
        // Spread `data` over the data TRBs; the TRB where it ran out, and how
        // many of its bytes it got.
        let scatter = |st: &mut St, data: &[u8]| -> usize {
            let mut off = 0;
            for (_, t) in &data_trbs {
                let buf = t[0] as u64 | (t[1] as u64) << 32;
                let n = ((t[2] & 0x1_ffff) as usize).min(data.len() - off);
                if n > 0 {
                    st.wr(buf, &data[off..off + n]);
                }
                off += n;
            }
            off
        };
        // Report a short transfer: an event on the TRB where the data ended, if
        // that TRB asked for one (ISP).
        let short_event = |st: &mut St, moved: usize| -> bool {
            let mut acc = 0;
            for (bus, t) in &data_trbs {
                let n = (t[2] & 0x1_ffff) as usize;
                if moved <= acc + n {
                    if t[3] & (1 << 2) != 0 {
                        st.post_xfer(slot, dci, *bus, 13, (acc + n - moved) as u32);
                        return true;
                    }
                    return false;
                }
                acc += n;
            }
            false
        };

        if is_ctl {
            let setup = first[0..2].iter().fold([0u8; 8], |mut a, w| {
                let i = if a == [0u8; 8] && *w == first[0] { 0 } else { 4 };
                a[i..i + 4].copy_from_slice(&w.to_le_bytes());
                a
            });
            let mut setup_bytes = [0u8; 8];
            setup_bytes[..4].copy_from_slice(&first[0].to_le_bytes());
            setup_bytes[4..].copy_from_slice(&first[1].to_le_bytes());
            let _ = setup;
            let dir_in = setup_bytes[0] & 0x80 != 0;
            let out = if !dir_in && total > 0 { gather(self) } else { Vec::new() };
            let res = dev.borrow_mut().control(setup_bytes, &out);
            match res {
                Err(()) => {
                    let at = data_trbs.first().map_or(last.0, |(b, _)| *b);
                    self.post_xfer(slot, dci, at, 6, total as u32);
                    self.set_ep_state(slot, dci, 2);
                    Exec::Halted
                }
                Ok(resp) => {
                    if dir_in {
                        let n = scatter(self, &resp);
                        if n < total {
                            short_event(self, n);
                        }
                    }
                    self.post_xfer(slot, dci, last.0, 1, 0);
                    Exec::Done
                }
            }
        } else {
            let ep = self.slots[slot].eps[dci];
            let epnum = (dci / 2) as u8;
            if matches!(ep.ep_type, 5 | 6 | 7) {
                let is_hub_status = dev.borrow().hub.is_some() && epnum == 1;
                let data = dev.borrow_mut().poll_in(epnum, is_hub_status);
                let Some(data) = data else { return Exec::Pending };
                if data.len() > total {
                    self.post_xfer(slot, dci, td.trbs[0].0, 3, 0);
                    self.set_ep_state(slot, dci, 2);
                    return Exec::Halted;
                }
                let n = scatter(self, &data);
                if n < total {
                    if !short_event(self, n) {
                        self.post_xfer(slot, dci, last.0, 1, (total - n) as u32);
                    }
                } else {
                    self.post_xfer(slot, dci, last.0, 1, 0);
                }
            } else {
                let out = gather(self);
                dev.borrow_mut().out_log.push((epnum, out));
                self.post_xfer(slot, dci, last.0, 1, 0);
            }
            Exec::Done
        }
    }
}

struct Td {
    trbs: Vec<(u64, [u32; 4])>,
    end_ptr: u64,
    end_ccs: bool,
}

enum Exec {
    Done,
    Pending,
    Halted,
}

// ---- Registers ----

impl St {
    fn portsc(&self, i: usize) -> u32 {
        let p = &self.ports[i];
        let mut v = 0u32;
        if p.ccs {
            v |= 1;
        }
        if p.ped {
            v |= 2;
        }
        if p.reset_done_at.is_some() {
            v |= 1 << 4;
        }
        let pls = if p.ped { 0 } else if p.ccs { 7 } else { 5 };
        v |= pls << 5;
        if p.pp {
            v |= 1 << 9;
        }
        if p.ccs && p.ped {
            let psiv = p.dev.as_ref().map_or(0, |d| d.borrow().speed_psiv);
            v |= psiv << 10;
        }
        v | p.changes
    }

    fn read(&mut self, off: usize) -> u32 {
        let cfg = &self.cfg;
        match off {
            0x00 => CAPLENGTH as u32 | 0x0120 << 16,
            0x04 => cfg.max_slots | 1 << 8 | cfg.ports << 24,
            0x08 => ((cfg.scratch >> 5) & 0x1f) << 21 | (cfg.scratch & 0x1f) << 27,
            0x0c => 0,
            0x10 => cfg.ac64 as u32 | (cfg.csz64 as u32) << 2 | (cfg.ppc as u32) << 3 | ((XECP / 4) as u32) << 16,
            0x14 => DBOFF as u32,
            0x18 => RTSOFF as u32,
            XECP => self.legsup,
            o if o == XECP + 4 => self.legctl,
            o if o == OP => self.usbcmd,
            o if o == OP + 0x04 => self.usbsts,
            o if o == OP + 0x08 => cfg.pagesize,
            o if o == OP + 0x18 => self.crcr as u32,
            o if o == OP + 0x1c => (self.crcr >> 32) as u32,
            o if o == OP + 0x30 => self.dcbaap as u32,
            o if o == OP + 0x34 => (self.dcbaap >> 32) as u32,
            o if o == OP + 0x38 => self.config,
            o if (PORT0..PORT0 + 16 * cfg.ports as usize).contains(&o) => {
                let i = (o - PORT0) / 16;
                if (o - PORT0) % 16 == 0 { self.portsc(i) } else { 0 }
            }
            o if o == IR0 => self.iman,
            o if o == IR0 + 0x08 => self.erstsz,
            o if o == IR0 + 0x10 => self.erstba as u32,
            o if o == IR0 + 0x14 => (self.erstba >> 32) as u32,
            o if o == IR0 + 0x18 => self.erdp as u32 | (self.ehb as u32) << 3,
            o if o == IR0 + 0x1c => (self.erdp >> 32) as u32,
            _ => 0,
        }
    }

    fn write(&mut self, off: usize, v: u32) {
        match off {
            XECP => {
                // The OS-owned semaphore: the firmware lets go at once.
                self.legsup = (self.legsup & !(1 << 24)) | (v & 1 << 24);
                if v & 1 << 24 != 0 {
                    self.legsup &= !(1 << 16);
                }
            }
            o if o == XECP + 4 => {
                // Enables are plain bits; the status bits (31:29) are RW1C.
                self.legctl = (v & !(7 << 29)) | (self.legctl & !v & (7 << 29));
            }
            o if o == OP => {
                let was = self.usbcmd;
                if v & 2 != 0 {
                    if self.hcrst_stuck {
                        self.usbcmd |= 2;
                        return;
                    }
                    self.hc_reset();
                    return;
                }
                self.usbcmd = v & !2;
                if v & 1 != 0 && was & 1 == 0 {
                    self.start();
                }
                if v & 1 == 0 && was & 1 != 0 {
                    self.usbsts |= 1;
                }
            }
            o if o == OP + 0x04 => {
                // RW1C: HSE, EINT, PCD.
                self.usbsts &= !(v & (1 << 2 | 1 << 3 | 1 << 4));
            }
            o if o == OP + 0x18 => {
                self.crcr = (self.crcr & !0xffff_ffff) | v as u64;
            }
            o if o == OP + 0x1c => {
                self.crcr = (self.crcr & 0xffff_ffff) | (v as u64) << 32;
                self.cmd_ptr = self.crcr & !0x3f;
                self.cmd_ccs = self.crcr & 1 != 0;
            }
            o if o == OP + 0x30 => self.dcbaap = (self.dcbaap & !0xffff_ffff) | v as u64,
            o if o == OP + 0x34 => self.dcbaap = (self.dcbaap & 0xffff_ffff) | (v as u64) << 32,
            o if o == OP + 0x38 => self.config = v,
            o if (PORT0..PORT0 + 16 * self.cfg.ports as usize).contains(&o) && (o - PORT0) % 16 == 0 => {
                let i = (o - PORT0) / 16;
                self.write_portsc(i, v);
            }
            o if o == IR0 => {
                if v & 1 != 0 {
                    self.iman &= !1;
                }
                self.iman = (self.iman & !2) | (v & 2);
            }
            o if o == IR0 + 0x08 => self.erstsz = v,
            o if o == IR0 + 0x10 => self.erstba = (self.erstba & !0xffff_ffff) | v as u64,
            o if o == IR0 + 0x14 => {
                self.erstba = (self.erstba & 0xffff_ffff) | (v as u64) << 32;
                // Writing the base arms the ring: read the one segment.
                let base = self.erstba & !0x3f;
                let seg = self.rd64(base);
                let size = self.rd32(base + 8) as usize;
                self.ev_base = seg;
                self.ev_size = size.min(self.erstsz as usize * 4096 / 16).max(size);
                self.ev_enq = 0;
                self.ev_cycle = true;
            }
            o if o == IR0 + 0x18 => {
                if v & 8 != 0 {
                    self.ehb = false;
                }
                self.erdp = (self.erdp & !0xffff_ffff) | (v & !0xf) as u64;
            }
            o if o == IR0 + 0x1c => self.erdp = (self.erdp & 0xffff_ffff) | (v as u64) << 32,
            _ => {}
        }
    }

    fn hc_reset(&mut self) {
        self.hc_resets += 1;
        self.usbcmd = 0;
        self.usbsts = 1;
        self.ev_size = 0;
        self.ehb = false;
        self.iman = 0;
        for s in &mut self.slots {
            *s = Slot::default();
        }
        // Every port back to its default state: disabled, and a device still
        // connected reports its connection again.
        for p in &mut self.ports {
            p.ped = false;
            p.reset_done_at = None;
            p.changes = if p.ccs { 1 << 17 } else { 0 };
        }
    }

    /// Run/Stop set: the controller starts. It checks what it was given.
    fn start(&mut self) {
        self.usbsts &= !1;
        // Scratchpad buffers: the array in DCBAA[0] must hold every entry.
        if self.cfg.scratch > 0 {
            let arr = self.rd64(self.dcbaap);
            let psz = 4096u64 << self.cfg.pagesize.trailing_zeros();
            for i in 0..self.cfg.scratch as u64 {
                let e = self.rd64(arr + 8 * i);
                if e == 0 || e % psz != 0 || self.translate(e, psz as usize).is_none() {
                    self.fault(format!("scratchpad buffer {i} of {} is not a mapped page: {e:#x}", self.cfg.scratch));
                    return;
                }
            }
        }
        // Ports with something connected raise their change.
        for i in 0..self.ports.len() {
            if self.ports[i].ccs {
                self.post_psc(i);
            }
        }
        self.slots.resize_with(self.cfg.max_slots as usize + 1, Slot::default);
    }

    fn write_portsc(&mut self, i: usize, v: u32) {
        let now = 0;
        let _ = now;
        let p = &mut self.ports[i];
        p.changes &= !(v & 0x00fe_0000);
        if v & 2 != 0 {
            p.ped = false;
        }
        if self.cfg.ppc && v & (1 << 9) != 0 {
            p.pp = true;
        }
        if v & (1 << 4) != 0 && p.ccs && p.reset_done_at.is_none() {
            p.reset_done_at = Some(u64::MAX); // armed; the clock fills in the time
        }
    }

    fn doorbell(&mut self, n: usize, value: u32) {
        if self.fault.is_some() {
            return;
        }
        if n == 0 {
            self.commands();
        } else {
            self.process_ring(n, value as usize);
        }
    }
}

impl Hw {
    pub fn new(cfg: Config) -> Rc<Hw> {
        let ports = cfg.ports as usize;
        let pp = !cfg.ppc;
        let bios_owned = cfg.bios_owned;
        Rc::new(Hw {
            st: RefCell::new(St {
                regions: Vec::new(),
                next_low: 0x0010_0000,
                next_high: 0x20_0000_0000,
                usbcmd: 0,
                usbsts: 1,
                crcr: 0,
                cmd_ptr: 0,
                cmd_ccs: true,
                dcbaap: 0,
                config: 0,
                iman: 0,
                erstsz: 0,
                erstba: 0,
                erdp: 0,
                ev_base: 0,
                ev_size: 0,
                ev_enq: 0,
                ev_cycle: true,
                ehb: false,
                slots: Vec::new(),
                ports: (0..ports).map(|_| RootPort { pp, ..RootPort::default() }).collect(),
                legsup: 1 | if bios_owned { 1 << 16 } else { 0 },
                legctl: if bios_owned { 1 | 1 << 4 | 1 << 13 } else { 0 },
                inject: Vec::new(),
                lose_commands: 0,
                hcrst_stuck: false,
                hc_resets: 0,
                commands: Vec::new(),
                interrupts_raised: 0,
                fault: None,
                xfer_events: Vec::new(),
                td_first: Vec::new(),
                cfg,
            }),
            now: Cell::new(0),
        })
    }

    pub fn regs(self: &Rc<Hw>) -> MockRegs {
        MockRegs(self.clone())
    }
    pub fn clock(self: &Rc<Hw>) -> MockClock {
        MockClock(self.clone())
    }
    pub fn mem(self: &Rc<Hw>) -> MockMem {
        MockMem(self.clone())
    }

    // ---- Test-side controls ----

    /// Plug `dev` into root port `port` (1-based).
    pub fn attach_root(&self, port: usize, dev: DevRef) {
        let mut st = self.st.borrow_mut();
        let p = &mut st.ports[port - 1];
        p.dev = Some(dev);
        p.ccs = true;
        p.changes |= 1 << 17;
        st.post_psc(port - 1);
    }

    pub fn detach_root(&self, port: usize) {
        let mut st = self.st.borrow_mut();
        let p = &mut st.ports[port - 1];
        p.dev = None;
        p.ccs = false;
        p.ped = false;
        p.changes |= 1 << 17;
        st.post_psc(port - 1);
    }

    /// Plug `child` into port `port` of the hub `hub`.
    pub fn hub_attach(&self, hub: &DevRef, port: usize, child: DevRef) {
        {
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
        self.kick_dev(hub);
    }

    pub fn hub_detach(&self, hub: &DevRef, port: usize) {
        {
            let mut h = hub.borrow_mut();
            let hm = h.hub.as_mut().unwrap();
            hm.children[port - 1] = None;
            let p = &mut hm.ports[port - 1];
            p.connected = false;
            p.enabled = false;
            p.change |= 1;
        }
        self.kick_dev(hub);
    }

    /// Raise change bits on root port `port` (a link state change, say) and
    /// post the event, with nothing connecting or disconnecting.
    pub fn poke_port(&self, port: usize, changes: u32) {
        let mut st = self.st.borrow_mut();
        st.ports[port - 1].changes |= changes;
        st.post_psc(port - 1);
    }

    pub fn slot_of(&self, dev: &DevRef) -> Option<usize> {
        let st = self.st.borrow();
        (1..st.slots.len()).find(|&i| st.slots[i].dev.as_ref().is_some_and(|d| Rc::ptr_eq(d, dev)))
    }

    /// Re-run every ring of a device (new data on an IN endpoint, a hub
    /// change).
    pub fn kick_dev(&self, dev: &DevRef) {
        if let Some(s) = self.slot_of(dev) {
            let mut st = self.st.borrow_mut();
            for dci in 2..32 {
                st.process_ring(s, dci);
            }
        }
    }

    /// Queue `data` on IN endpoint `ep` of `dev` and let the controller
    /// complete a waiting transfer with it.
    pub fn inject_in(&self, dev: &DevRef, ep: usize, data: &[u8]) {
        dev.borrow_mut().in_queue[ep].push_back(data.to_vec());
        self.kick_dev(dev);
    }

    /// The next transfer on (`slot`, `dci`) fails with completion code `code`
    /// (the endpoint halts).
    pub fn inject_error(&self, slot: usize, dci: usize, code: u8) {
        self.st.borrow_mut().inject.push((slot, dci, code));
    }

    /// The next `n` commands are taken off the ring and never answered (a
    /// controller that stopped answering).
    pub fn lose_commands(&self, n: u32) {
        self.st.borrow_mut().lose_commands = n;
    }

    /// From now on a host controller reset never completes.
    pub fn stick_hcrst(&self) {
        self.st.borrow_mut().hcrst_stuck = true;
    }

    /// Host controller resets done, the bring-up's included.
    pub fn hc_resets(&self) -> u32 {
        self.st.borrow().hc_resets
    }

    pub fn fault(&self) -> Option<String> {
        self.st.borrow().fault.clone()
    }
    pub fn commands(&self) -> Vec<u8> {
        self.st.borrow().commands.clone()
    }
    pub fn interrupts(&self) -> u32 {
        self.st.borrow().interrupts_raised
    }
    pub fn xfer_events(&self) -> Vec<(u8, u8, u8)> {
        self.st.borrow().xfer_events.clone()
    }
    /// The slot context the driver last gave the controller.
    pub fn slot_ctx(&self, slot: usize) -> [u32; 8] {
        self.st.borrow().slots[slot].slot_ctx
    }
    pub fn slot_enabled(&self, slot: usize) -> bool {
        self.st.borrow().slots.get(slot).is_some_and(|s| s.enabled)
    }
    pub fn enabled_slots(&self) -> usize {
        self.st.borrow().slots.iter().filter(|s| s.enabled).count()
    }
    /// (type, max packet, interval, state) of an endpoint the controller holds.
    pub fn ep_info(&self, slot: usize, dci: usize) -> (u8, u16, u8, u8) {
        let e = self.st.borrow().slots[slot].eps[dci];
        (e.ep_type, e.mps, e.interval, e.state)
    }
    /// The endpoint context words the driver configured an endpoint with.
    pub fn ep_ctx(&self, slot: usize, dci: usize) -> [u32; 8] {
        self.st.borrow().slots[slot].eps[dci].ctx
    }
    /// The first TRB of every data descriptor run on (`slot`, `dci`).
    pub fn first_trbs(&self, slot: usize, dci: usize) -> Vec<[u32; 4]> {
        let st = self.st.borrow();
        st.td_first.iter().filter(|(s, d, _)| *s as usize == slot && *d as usize == dci).map(|x| x.2).collect()
    }
    pub fn dcbaa_entry(&self, slot: usize) -> u64 {
        let mut st = self.st.borrow_mut();
        let a = st.dcbaap + 8 * slot as u64;
        st.rd64(a)
    }
    /// (USBLEGSUP, USBLEGCTLSTS) as the controller holds them.
    pub fn legacy_support(&self) -> (u32, u32) {
        let st = self.st.borrow();
        (st.legsup, st.legctl)
    }
}

// ---- The three traits ----

pub struct MockRegs(Rc<Hw>);
pub struct MockClock(Rc<Hw>);
pub struct MockMem(Rc<Hw>);

impl Regs for MockRegs {
    fn read32(&self, off: usize) -> u32 {
        self.0.st.borrow_mut().read(off)
    }
    fn write32(&self, off: usize, val: u32) {
        let mut st = self.0.st.borrow_mut();
        if off >= DBOFF {
            st.doorbell((off - DBOFF) / 4, val);
            return;
        }
        // A port reset armed by this write completes `reset_us` from now.
        let armed_before: Vec<bool> = st.ports.iter().map(|p| p.reset_done_at.is_some()).collect();
        st.write(off, val);
        let now = self.0.now.get();
        let reset_us = st.cfg.reset_us;
        for (p, was) in st.ports.iter_mut().zip(armed_before) {
            if !was && p.reset_done_at == Some(u64::MAX) {
                p.reset_done_at = Some(now + reset_us);
            }
        }
    }
}

impl Clock for MockClock {
    fn now_us(&self) -> u64 {
        self.0.now.get()
    }
    fn delay_us(&self, us: u32) {
        let now = self.0.now.get() + us as u64;
        self.0.now.set(now);
        let mut st = self.0.st.borrow_mut();
        for i in 0..st.ports.len() {
            if st.ports[i].reset_done_at.is_some_and(|t| t <= now) {
                let p = &mut st.ports[i];
                p.reset_done_at = None;
                if p.ccs {
                    p.ped = true;
                    p.changes |= 1 << 21 | 1 << 18;
                }
                st.post_psc(i);
            }
        }
    }
}

impl Memory for MockMem {
    fn alloc_region(&self, len: usize, align: usize, mask: u64) -> Option<DmaBuf> {
        let mut st = self.0.st.borrow_mut();
        let align = align.max(4096);
        let layout = Layout::from_size_align(len, align).ok()?;
        // SAFETY: the layout has a non-zero size; the memory is leaked, which
        // is what a test wants.
        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            return None;
        }
        // A request with a 32-bit limit gets low bus addresses; one without,
        // addresses above 4 GiB, so an addressing bug cannot hide.
        let bus = if mask <= 0xffff_ffff {
            let b = st.next_low.next_multiple_of(align as u64);
            st.next_low = b + len as u64;
            b
        } else {
            let b = st.next_high.next_multiple_of(align as u64);
            st.next_high = b + len as u64;
            b
        };
        if bus + len as u64 - 1 > mask {
            return None;
        }
        st.regions.push(Region { bus, ptr, len });
        // SAFETY: `ptr` is `len` bytes of live, leaked memory.
        Some(unsafe { DmaBuf::new(ptr, bus, len) })
    }

    fn free_region(&self, b: DmaBuf) {
        let mut st = self.0.st.borrow_mut();
        st.regions.retain(|r| r.bus != b.bus());
    }

    fn enable(&self) -> bool {
        true
    }

    fn to_device(&self, _cpu: *const u8, _len: usize) {}
    fn from_device(&self, _cpu: *const u8, _len: usize) {}
}
