// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The CRB interface against a scripted CRB modelled on QEMU's `tpm-crb`
//! (hw/tpm/tpm_crb.c: register page at 0xFED40000, control area at +0x40, one
//! buffer for command and response at +0x80) and on what Linux `tpm_crb`
//! does around it. Every access the driver makes is checked; a violation is
//! logged, not panicked, so a test asserts on the log.

use crate::fake::{h, FakeClock};
use azos_tpm::crb::{head_for, read_buffers, Buffers, Crb, StartMethod};
use azos_tpm::mmio::MmioAccess;
use azos_tpm::tis::Duration;
use azos_tpm::tpm::{StartupType, Tpm};
use azos_tpm::{Error, Transport, Wait};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

pub const BASE: u64 = 0xFED4_0000;
/// Where the control area of a TPM without the locality registers (start
/// method 8 on an older PTT) sits: not at offset 0x40 of its page.
const CTRL_NO_HEAD: u64 = BASE + 0x100;

pub struct CrbDev {
    pub script: VecDeque<(Vec<u8>, Vec<u8>)>,
    pub violations: Vec<String>,
    pub start_method: StartMethod,
    pub ctrl: u64,
    pub present: bool,
    pub intf_type: u32,
    pub sts_error: bool,
    /// START reads that still read 1 after a START.
    pub exec_polls: u32,
    pub never_completes: bool,
    pub cmd_buf: u64,
    pub cmd_size: u32,
    pub rsp_buf: u64,
    pub rsp_size: u32,
    pub assigned: bool,
    pub idle: bool,
    pub start: bool,
    pub cancels: u32,
    pub cmd_ready_writes: u32,
    pub go_idle_writes: u32,
    pub starts: u32,
    pub releases: u32,
    polls_left: u32,
    mem: Vec<u8>,
}

impl CrbDev {
    fn new(start_method: StartMethod) -> CrbDev {
        let ctrl = match start_method {
            StartMethod::Crb => BASE + 0x40,
            StartMethod::Acpi => CTRL_NO_HEAD,
        };
        CrbDev {
            script: VecDeque::new(),
            violations: Vec::new(),
            start_method,
            ctrl,
            present: true,
            intf_type: 1,
            sts_error: false,
            exec_polls: 2,
            never_completes: false,
            cmd_buf: BASE + 0x200,
            cmd_size: 0xE00,
            rsp_buf: BASE + 0x200,
            rsp_size: 0xE00,
            assigned: false,
            idle: true,
            start: false,
            cancels: 0,
            cmd_ready_writes: 0,
            go_idle_writes: 0,
            starts: 0,
            releases: 0,
            polls_left: 0,
            mem: vec![0; 0x1000],
        }
    }

    pub fn expect(&mut self, cmd: &str, rsp: &str) {
        self.script.push_back((h(cmd), h(rsp)));
    }

    fn v(&mut self, s: String) {
        self.violations.push(s);
    }

    fn head(&self) -> Option<u64> {
        head_for(self.ctrl, self.start_method)
    }

    fn in_buf(&self, a: u64, base: u64, size: u32) -> bool {
        a >= base && a < base + size as u64
    }

    /// The command the driver wrote, run against the script.
    fn run(&mut self) {
        let off = (self.cmd_buf - BASE) as usize;
        let n = u32::from_be_bytes(self.mem[off + 2..off + 6].try_into().unwrap()) as usize;
        let got = self.mem[off..off + n.min(self.cmd_size as usize)].to_vec();
        let rsp = match self.script.pop_front() {
            Some((cmd, rsp)) if cmd == got => rsp,
            Some((cmd, _)) => {
                self.v(format!("command mismatch: want {cmd:02x?} got {got:02x?}"));
                h("80 01 00 00 00 0A 00 00 01 01")
            }
            None => {
                self.v(format!("unscripted command {got:02x?}"));
                h("80 01 00 00 00 0A 00 00 01 01")
            }
        };
        let r = (self.rsp_buf - BASE) as usize;
        self.mem[r..r + rsp.len()].copy_from_slice(&rsp);
        self.polls_left = self.exec_polls;
    }

    fn read32(&mut self, a: u64) -> u32 {
        if !self.present {
            return u32::MAX;
        }
        if let Some(hd) = self.head() {
            match a - hd {
                0x00 => return 0x80 | if self.assigned { 0x02 } else { 0 },
                0x30 => return self.intf_type | 1 << 14,
                0x34 => return 0x0001 << 16 | 0x1014,
                _ => {}
            }
        } else if a < self.ctrl && a < BASE + 0x40 {
            self.v(format!("locality register read at {a:#x} on a TPM without them"));
        }
        let c = self.ctrl;
        match a.wrapping_sub(c) {
            0x00 => 0,
            0x04 => (self.sts_error as u32) | (self.idle as u32) << 1,
            0x0C => {
                if self.start && !self.never_completes {
                    if self.polls_left == 0 {
                        self.start = false;
                    } else {
                        self.polls_left -= 1;
                    }
                }
                self.start as u32
            }
            0x18 => self.cmd_size,
            0x1C => self.cmd_buf as u32,
            0x20 => (self.cmd_buf >> 32) as u32,
            0x24 => self.rsp_size,
            0x28 => self.rsp_buf as u32,
            0x2C => (self.rsp_buf >> 32) as u32,
            _ => {
                self.v(format!("read32 of an unmodelled register {a:#x}"));
                0
            }
        }
    }

    fn write32(&mut self, a: u64, v: u32) {
        if !self.present {
            return;
        }
        if let Some(hd) = self.head() {
            if a == hd + 0x08 {
                // QEMU acts on the exact value.
                match v {
                    1 => self.assigned = true,
                    2 => {
                        self.assigned = false;
                        self.releases += 1;
                    }
                    _ => self.v(format!("LOC_CTRL {v:#x}")),
                }
                return;
            }
        } else if a < BASE + 0x40 {
            self.v(format!("locality register write at {a:#x} on a TPM without them"));
            return;
        }
        let c = self.ctrl;
        match a.wrapping_sub(c) {
            0x00 => {
                if self.start_method == StartMethod::Acpi {
                    self.v(format!("REQ {v:#x} on an ACPI-start TPM"));
                }
                match v {
                    1 => {
                        self.cmd_ready_writes += 1;
                        self.idle = false;
                    }
                    2 => {
                        self.go_idle_writes += 1;
                        self.idle = true;
                    }
                    _ => self.v(format!("REQ {v:#x}")),
                }
            }
            0x08 => {
                if v == 1 && self.start {
                    self.start = false;
                    self.cancels += 1;
                }
            }
            0x0C => {
                if v != 1 {
                    return;
                }
                if self.start {
                    self.v("START while a command runs".into());
                } else if self.head().is_some() && !self.assigned {
                    // QEMU ignores it: the start comes from no locality.
                    self.v("START without the locality".into());
                } else if self.start_method == StartMethod::Crb && self.idle {
                    self.v("START while idle (no cmdReady)".into());
                } else {
                    self.starts += 1;
                    self.start = true;
                    self.run();
                }
            }
            _ => self.v(format!("write32 of an unmodelled register {a:#x} = {v:#x}")),
        }
    }

    fn read8(&mut self, a: u64) -> u8 {
        if !self.in_buf(a, self.rsp_buf, self.rsp_size) {
            self.v(format!("read8 outside the response buffer: {a:#x}"));
            return 0xFF;
        }
        if self.start {
            self.v("response read while START is set".into());
        }
        self.mem[(a - BASE) as usize]
    }

    fn write8(&mut self, a: u64, v: u8) {
        if !self.in_buf(a, self.cmd_buf, self.cmd_size) {
            self.v(format!("write8 outside the command buffer: {a:#x}"));
            return;
        }
        if self.start {
            self.v("command written while START is set".into());
        }
        self.mem[(a - BASE) as usize] = v;
    }
}

pub type SharedCrb = Rc<RefCell<CrbDev>>;

pub struct CrbMmio(pub SharedCrb);

impl MmioAccess for CrbMmio {
    fn read8(&mut self, a: u64) -> u8 {
        self.0.borrow_mut().read8(a)
    }
    fn read32(&mut self, a: u64) -> u32 {
        assert_eq!(a % 4, 0, "unaligned dword {a:#x}");
        self.0.borrow_mut().read32(a)
    }
    fn write8(&mut self, a: u64, v: u8) {
        self.0.borrow_mut().write8(a, v)
    }
    fn write32(&mut self, a: u64, v: u32) {
        assert_eq!(a % 4, 0, "unaligned dword {a:#x}");
        self.0.borrow_mut().write32(a, v)
    }
}

pub type CrbTpm = Tpm<Crb<CrbMmio, FakeClock>>;

/// A device configured by `cfg`, its buffers read the way the kernel reads
/// them, and the driver on top.
pub fn crb_rig_with(start: StartMethod, cfg: impl FnOnce(&mut CrbDev)) -> (CrbTpm, SharedCrb, FakeClock) {
    let dev = Rc::new(RefCell::new(CrbDev::new(start)));
    cfg(&mut dev.borrow_mut());
    let ctrl = dev.borrow().ctrl;
    let clock = FakeClock::new();
    let buf = read_buffers(&mut CrbMmio(dev.clone()), ctrl).expect("the control area names usable buffers");
    let t = Tpm::new(Crb::new(CrbMmio(dev.clone()), clock.clone(), ctrl, start, buf));
    (t, dev, clock)
}

pub fn crb_rig(start: StartMethod) -> (CrbTpm, SharedCrb, FakeClock) {
    crb_rig_with(start, |_| {})
}

pub fn assert_clean(d: &SharedCrb) {
    let d = d.borrow();
    assert!(d.violations.is_empty(), "device violations: {:?}", d.violations);
    assert!(!d.assigned, "locality left held");
    assert!(!d.start, "a command left running");
    assert!(d.script.is_empty(), "script not consumed: {} left", d.script.len());
}

const STARTUP: &str = "80 01 00 00 00 0C 00 00 01 44 00 00";
const STARTUP_OK: &str = "80 01 00 00 00 0A 00 00 00 00";

/// The QEMU layout: locality registers at the page, identity from INTF_ID
/// (IBM 0x1014, device 1), the locality given back.
#[test]
fn probe_reads_intf_id_and_gives_the_locality_back() {
    let (mut t, d, _) = crb_rig(StartMethod::Crb);
    let i = t.probe().unwrap();
    assert_eq!((i.vid, i.did, i.rid), (0x1014, 0x0001, 0));
    assert_clean(&d);
    assert_eq!(d.borrow().releases, 1);
}

/// Nothing at the window, a window whose interface is not a CRB (a FIFO),
/// a TPM in its fatal state: no TPM.
#[test]
fn probe_refuses_absent_fifo_and_fatal() {
    let d = Rc::new(RefCell::new(CrbDev::new(StartMethod::Crb)));
    d.borrow_mut().present = false;
    assert_eq!(read_buffers(&mut CrbMmio(d), BASE + 0x40), Err(Error::NoDevice), "all ones");
    let (mut t, d, _) = crb_rig_with(StartMethod::Crb, |d| d.intf_type = 0);
    assert_eq!(t.probe(), Err(Error::NoDevice), "a FIFO interface");
    assert!(!d.borrow().assigned, "locality given back");
    let (mut t, _, _) = crb_rig_with(StartMethod::Crb, |d| d.sts_error = true);
    assert_eq!(t.probe(), Err(Error::Fatal));
}

/// **One command, start method 7**: locality, cmdReady, the bytes, START,
/// START falls, the response, goIdle, locality back.
/// **Canary** `canary-crb-start`: START is never written, the command times
/// out on `Wait::Start`.
#[test]
fn a_command_over_crb_method_7() {
    let (mut t, d, _) = crb_rig(StartMethod::Crb);
    d.borrow_mut().expect(STARTUP, STARTUP_OK);
    t.startup(StartupType::Clear).unwrap();
    assert_clean(&d);
    let d = d.borrow();
    assert_eq!((d.starts, d.cmd_ready_writes, d.go_idle_writes, d.releases), (1, 1, 1, 1));
    assert!(d.idle, "idle after the command");
}

/// The commands the kernel sends, back to back, over CRB.
#[test]
fn the_kernels_commands_over_crb() {
    let (mut t, d, _) = crb_rig(StartMethod::Crb);
    let digest: Vec<String> = (0..32).map(|i| format!("{i:02X}")).collect();
    let digest = digest.join(" ");
    d.borrow_mut().expect(STARTUP, STARTUP_OK);
    d.borrow_mut().expect(
        "80 01 00 00 00 0C 00 00 01 7B 00 08",
        "80 01 00 00 00 14 00 00 00 00 00 08 01 02 03 04 05 06 07 08",
    );
    d.borrow_mut().expect(
        &format!("80 02 00 00 00 41 00 00 01 82 00 00 00 08 00 00 00 09 40 00 00 09 00 00 01 00 00 00 00 00 01 00 0B {digest}"),
        "80 02 00 00 00 13 00 00 00 00 00 00 00 00 00 00 01 00 00",
    );
    t.startup(StartupType::Clear).unwrap();
    let mut r = [0u8; 8];
    t.get_random(&mut r).unwrap();
    assert_eq!(r, [1, 2, 3, 4, 5, 6, 7, 8]);
    let mut dg = [0u8; 32];
    dg.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);
    t.pcr_extend(8, &dg).unwrap();
    assert_clean(&d);
    assert_eq!(d.borrow().starts, 3);
}

/// **Start method 8 without the locality registers** (the control area is not
/// at offset 0x40 of its page): no locality register is touched, no
/// cmdReady/goIdle, START alone.
#[test]
fn method_8_without_locality_registers() {
    let (mut t, d, _) = crb_rig(StartMethod::Acpi);
    let i = t.probe().unwrap();
    assert_eq!((i.vid, i.did), (0, 0), "no identity registers");
    d.borrow_mut().expect(STARTUP, STARTUP_OK);
    t.startup(StartupType::Clear).unwrap();
    assert_clean(&d);
    let d = d.borrow();
    assert_eq!((d.starts, d.cmd_ready_writes, d.go_idle_writes), (1, 0, 0));
}

/// A TPM that never lowers START (one waiting for the ACPI `_DSM`, a dead
/// one): bounded by the duration class, CANCEL written, locality given back,
/// and the next command still goes (CANCEL cleared first).
#[test]
fn a_start_that_never_falls_times_out_and_cancels() {
    let (mut t, d, clock) = crb_rig(StartMethod::Crb);
    d.borrow_mut().never_completes = true;
    d.borrow_mut().expect(STARTUP, STARTUP_OK);
    assert_eq!(t.startup(StartupType::Clear), Err(Error::Timeout(Wait::Start)));
    assert!(clock.0.get() >= Duration::Medium.us() as u64, "waited the class out");
    assert!(clock.0.get() < 2 * Duration::Medium.us() as u64 + 1_000_000, "and not much longer");
    assert_eq!(d.borrow().cancels, 1);
    assert!(!d.borrow().assigned);
    d.borrow_mut().never_completes = false;
    d.borrow_mut().expect(STARTUP, STARTUP_OK);
    t.startup(StartupType::Clear).unwrap();
    assert_clean(&d);
}

/// **The response is bounded by the response buffer**, not only by the
/// caller's: a header that declares more than the buffer holds is refused
/// before a byte past the header is read.
/// **Canary** `canary-rspsize`: the driver reads past the buffer.
#[test]
fn a_response_larger_than_its_buffer_is_refused() {
    let (mut t, d, _) = crb_rig_with(StartMethod::Crb, |d| {
        d.cmd_size = 0x40;
        d.rsp_size = 0x40;
    });
    let mut big = String::from("80 01 00 00 00 50 00 00 00 00");
    big.push_str(&" 00".repeat(0x50 - 10));
    d.borrow_mut().expect(STARTUP, &big);
    assert_eq!(t.startup(StartupType::Clear), Err(Error::BadResponseSize));
    let d = d.borrow();
    assert!(d.violations.is_empty(), "{:?}", d.violations);
    assert!(!d.assigned);
}

/// A command larger than the command buffer is refused before a byte goes.
#[test]
fn a_command_larger_than_its_buffer_is_refused() {
    let (mut t, d, _) = crb_rig_with(StartMethod::Crb, |d| {
        d.cmd_size = 0x10;
        d.rsp_size = 0x10;
    });
    let mut c = vec![0x80, 1, 0, 0, 0, 0x20, 0, 0, 1, 0x7B];
    c.resize(0x20, 0);
    let mut rsp = [0u8; 64];
    assert_eq!(t.transport().transmit(&c, &mut rsp, Duration::Short), Err(Error::BadCommand));
    assert_eq!(d.borrow().starts, 0);
    assert_clean(&d);
}

/// The buffers the control area names are checked before anything maps them.
#[test]
fn read_buffers_checks_what_the_control_area_says() {
    let read = |f: &dyn Fn(&mut CrbDev)| {
        let d = Rc::new(RefCell::new(CrbDev::new(StartMethod::Crb)));
        f(&mut d.borrow_mut());
        read_buffers(&mut CrbMmio(d), BASE + 0x40)
    };
    assert_eq!(
        read(&|_| {}),
        Ok(Buffers { cmd: BASE + 0x200, cmd_size: 0xE00, rsp: BASE + 0x200, rsp_size: 0xE00 })
    );
    assert_eq!(read(&|d| d.cmd_buf = 0), Err(Error::Malformed), "a buffer at 0");
    assert_eq!(read(&|d| d.rsp_size = 9), Err(Error::Malformed), "smaller than a header");
    assert_eq!(read(&|d| d.rsp_size = 0x400), Err(Error::Malformed), "one buffer, two sizes");
    assert_eq!(read(&|d| { d.rsp_buf = BASE + 0x300; d.rsp_size = 0x100 }), Err(Error::Malformed), "overlap");
    let apart = read(&|d| { d.cmd_size = 0x100; d.rsp_buf = BASE + 0x300; d.rsp_size = 0x100 }).unwrap();
    assert_eq!((apart.cmd_span(), apart.rsp_span()), (0x100, 0x100), "two buffers side by side");
    assert_eq!(read(&|_| {}).unwrap().cmd_span(), azos_tpm::tis::CMD_MAX as u64, "the span is what the driver uses");
    assert_eq!(read(&|d| { d.cmd_buf = u64::MAX - 0x10; d.rsp_buf = u64::MAX - 0x10 }), Err(Error::Malformed), "wraps");
}

#[test]
fn head_is_0x40_below_a_method_7_control_area_at_page_offset_0x40() {
    assert_eq!(head_for(0xFED4_0040, StartMethod::Crb), Some(0xFED4_0000));
    assert_eq!(head_for(0xFED4_0080, StartMethod::Crb), None, "not the PTP layout");
    assert_eq!(head_for(0xFED4_0040, StartMethod::Acpi), None, "methods 2 and 8 go without");
}

/// The transport trait the kernel's x86 enum forwards: the same answers
/// through `dyn`-free generic code as through the inherent methods.
#[test]
fn crb_is_a_transport() {
    fn via<T: Transport>(t: &mut T) -> Result<azos_tpm::tis::DeviceInfo, Error> {
        t.probe()
    }
    let (mut t, d, _) = crb_rig(StartMethod::Crb);
    assert!(via(t.transport()).is_ok());
    assert_clean(&d);
}
