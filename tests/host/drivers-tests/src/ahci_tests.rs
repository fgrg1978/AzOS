// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `ahci.rs` (the AHCI 1.3 SATA host driver) run on the host over a
//! register-level model of an HBA and an ATA disk.
//!
//! The model is written from the AHCI 1.3.1 and ATA specifications, not from
//! the driver: its own register offsets, its own walk of the command list,
//! command table and PRDT out of the "physical" pages the driver gave it, and
//! a disk that answers the four ATA commands the driver uses. It refuses what
//! an HBA refuses (a port register touched with `GHC.AE` clear, a command
//! issued with the engine stopped or the FIS receiver off, a second command
//! while one is in flight, a misaligned list or table, a reset while the
//! firmware owns the HBA, a port that was never spun up showing a link) and
//! records what it saw as `violations`, so a test asserts on the driver's
//! behaviour and not on its own bookkeeping.
//!
//! Time: while the HBA's interrupt is off, every poll of a port register
//! makes the model's device progress (`latency` reads of `PxCI` per command);
//! once the driver has turned the interrupt on (`GHC.IE` and `PxIE`), reads
//! no longer advance it and the only thing that does is the driver sleeping
//! (`Hooks::block_until` -> `step`), after which the model raises its line
//! and the "interrupt controller" calls the handler (`Ahci::irq`), which wakes
//! the sleeper. A driver that polled in interrupt mode would never see its
//! command complete.
//!
//! Each test names its canary: the one-line change to `ahci.rs` that must
//! turn it red.

use super::ahci::*;
use super::queue::{Claim, HwCmd, HwDone, HwOp, HwQueue, HwStatus, ReqQueue, HW_TAGS_MAX};
use std::cell::{Cell, RefCell};
use std::sync::{Arc, Mutex};

// AHCI 1.3.1 register offsets (the model's own copy).
const R_CAP: usize = 0x00;
const R_GHC: usize = 0x04;
const R_IS: usize = 0x08;
const R_PI: usize = 0x0C;
const R_CAP2: usize = 0x24;
const R_BOHC: usize = 0x28;
const P_BASE: usize = 0x100;
const P_STRIDE: usize = 0x80;
const P_CLB: usize = 0x00;
const P_CLBU: usize = 0x04;
const P_FB: usize = 0x08;
const P_FBU: usize = 0x0C;
const P_IS: usize = 0x10;
const P_IE: usize = 0x14;
const P_CMD: usize = 0x18;
const P_TFD: usize = 0x20;
const P_SIG: usize = 0x24;
const P_SSTS: usize = 0x28;
const P_SERR: usize = 0x30;
const P_CI: usize = 0x38;

const CAP_SSS: u32 = 1 << 27;
const CAP_S64A: u32 = 1 << 31;
const GHC_HR: u32 = 1;
const GHC_IE: u32 = 2;
const GHC_AE: u32 = 1 << 31;
const CMD_ST: u32 = 1;
const CMD_SUD: u32 = 2;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;
const IS_DHRS: u32 = 1;
const IS_TFES: u32 = 1 << 30;
const TFD_OK: u32 = 0x50;

const SECTOR: usize = 512;

/// Budgets the model's time fits in: every wait that succeeds does so in a
/// handful of polls; the ones that must expire do so in tens of milliseconds.
const BUDGETS: Budgets = Budgets {
    handoff_us: 200_000,
    reset_us: 200_000,
    stop_us: 100_000,
    link_us: 200_000,
    absent_us: 5_000,
    ready_us: 200_000,
    identify_us: 200_000,
    io_us: 40_000,
    flush_us: 40_000,
};

#[derive(Clone, Copy, PartialEq, Debug)]
enum Fault {
    None,
    /// The next data command ends with a task file error (UNC) and the port stops.
    TaskFile,
    /// The next command never completes.
    Hang,
    /// The next data command completes having moved 512 bytes too few.
    ShortCount,
}

/// One command the HBA was told to run, as the model decoded it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Logged {
    cmd: u8,
    lba: u64,
    count: u32,
    /// The PRDT: (bus address, byte count) per entry.
    prds: Vec<(u64, usize)>,
    write: bool,
}

struct Pending {
    log: Logged,
    countdown: u32,
}

struct PortM {
    present: bool,
    atapi: bool,
    /// Polls of `PxSSTS` that read "device detected, no link" after spin-up.
    link_polls: u32,
    /// Polls of `PxTFD` that read BSY after reset or spin-up.
    busy_polls: u32,
    spun: bool,
    link_left: u32,
    busy_left: u32,
    clb: u32,
    clbu: u32,
    fb: u32,
    fbu: u32,
    is: u32,
    ie: u32,
    cmd: u32,
    tfd: u32,
    serr: u32,
    ci: u32,
    running: bool,
    /// A fatal error stopped the engine: commands are ignored until `ST` is
    /// cleared.
    halted: bool,
    pending: Option<Pending>,
}

impl PortM {
    /// The device's FISes (its signature, the task file after reset) reach the
    /// port only while the FIS receiver runs and has an area to write to.
    fn fis_ready(&self) -> bool {
        self.cmd & CMD_FRE != 0 && (self.fb | self.fbu) != 0
    }

    fn new(present: bool) -> Self {
        PortM {
            present,
            atapi: false,
            link_polls: 2,
            busy_polls: 3,
            spun: false,
            link_left: 0,
            busy_left: 0,
            clb: 0,
            clbu: 0,
            fb: 0,
            fbu: 0,
            is: 0,
            ie: 0,
            cmd: 0,
            tfd: TFD_OK,
            serr: 0,
            ci: 0,
            running: false,
            halted: false,
            pending: None,
        }
    }
}

struct Inner {
    cap: u32,
    cap2: u32,
    ghc: u32,
    his: u32,
    bohc: u32,
    /// Polls of `BOHC` before the firmware lets go after the OS asks.
    handoff_polls: u32,
    handoff_left: u32,
    /// Polls of `GHC` that still read HR after a reset.
    reset_polls: u32,
    reset_left: u32,
    ports: Vec<PortM>,
    // the disk
    disk: Vec<u8>,
    flush_ext: bool,
    /// FLUSH CACHE EXT is advertised and then aborted.
    flush_aborts: bool,
    logical_4k: bool,
    lba48: bool,
    /// Reads of `PxCI` a command takes while the HBA's interrupt is off.
    latency: u32,
    fault: Fault,
    // evidence
    log: Vec<Logged>,
    resets: u32,
    flushes: u32,
    /// `ST` 1 -> 0 transitions per port.
    stops: Vec<u32>,
    violations: Vec<String>,
}

#[derive(Clone)]
struct Mock(Arc<Mutex<Inner>>);

fn virt(pa: u64) -> usize {
    azos_mm::addr::phys_to_virt(pa as usize)
}

fn rd_dword(pa: u64) -> u32 {
    // SAFETY: a dword of a page the driver gave the HBA.
    unsafe { std::ptr::read_volatile(virt(pa) as *const u32) }
}

impl Inner {
    fn violation(&mut self, what: impl Into<String>) {
        self.violations.push(what.into());
    }

    fn irq_mode(&self) -> bool {
        self.ghc & GHC_IE != 0 && self.ports.iter().any(|p| p.ie != 0)
    }

    /// Does the interrupt line read asserted?
    fn line(&self) -> bool {
        self.ghc & GHC_IE != 0
            && self.ports.iter().enumerate().any(|(n, p)| p.is & p.ie != 0 && self.his >> n & 1 != 0)
    }

    fn port_index(off: usize) -> Option<(usize, usize)> {
        (off >= P_BASE).then(|| ((off - P_BASE) / P_STRIDE, (off - P_BASE) % P_STRIDE))
    }

    fn reset(&mut self) {
        self.resets += 1;
        if self.bohc & 1 != 0 && self.bohc & 2 == 0 {
            self.violation("HBA reset while the firmware owns it (BOHC.BOS set, OOS clear)");
        }
        self.ghc = 0;
        self.his = 0;
        self.reset_left = self.reset_polls;
        let sss = self.cap & CAP_SSS != 0;
        for p in self.ports.iter_mut() {
            let (present, atapi, link_polls, busy_polls) = (p.present, p.atapi, p.link_polls, p.busy_polls);
            *p = PortM::new(present);
            p.atapi = atapi;
            p.link_polls = link_polls;
            p.busy_polls = busy_polls;
            // Without staggered spin-up the device is up at reset.
            p.spun = !sss;
            p.link_left = link_polls;
            p.busy_left = busy_polls;
        }
    }

    fn rd(&mut self, off: usize) -> u32 {
        match off {
            R_CAP => return self.cap,
            R_GHC => {
                if self.reset_left > 0 {
                    self.reset_left -= 1;
                    return self.ghc | GHC_HR;
                }
                return self.ghc;
            }
            R_IS => return self.his,
            R_PI => return (0..self.ports.len()).fold(0, |m, n| m | 1 << n),
            R_CAP2 => return self.cap2,
            R_BOHC => {
                if self.bohc & 2 != 0 && self.bohc & 1 != 0 {
                    if self.handoff_left == 0 {
                        self.bohc &= !1;
                    } else {
                        self.handoff_left -= 1;
                    }
                }
                return self.bohc;
            }
            _ => {}
        }
        let Some((n, o)) = Self::port_index(off) else { return 0 };
        if n >= self.ports.len() {
            return 0;
        }
        if self.ghc & GHC_AE == 0 {
            self.violation(format!("port {n} register {o:#x} read with GHC.AE clear"));
        }
        let irq = self.irq_mode();
        let p = &mut self.ports[n];
        match o {
            P_CLB => p.clb,
            P_CLBU => p.clbu,
            P_FB => p.fb,
            P_FBU => p.fbu,
            P_IS => p.is,
            P_IE => p.ie,
            P_CMD => p.cmd,
            P_SERR => p.serr,
            P_SSTS => {
                if !p.present || !p.spun {
                    0
                } else if p.link_left > 0 {
                    p.link_left -= 1;
                    1
                } else {
                    0x103
                }
            }
            P_TFD => {
                if p.present && !p.fis_ready() {
                    // Reset value: BSY, DRQ and ERR, until the first FIS lands.
                    0x7F
                } else if p.present && p.busy_left > 0 && p.spun && p.link_left == 0 {
                    p.busy_left -= 1;
                    0x80
                } else {
                    p.tfd
                }
            }
            P_SIG => {
                if !p.present || !p.fis_ready() || p.busy_left > 0 {
                    0xFFFF_FFFF
                } else if p.atapi {
                    0xEB14_0101
                } else {
                    0x101
                }
            }
            P_CI => {
                if !irq {
                    if let Some(pd) = p.pending.as_mut() {
                        if pd.countdown > 0 {
                            pd.countdown -= 1;
                        }
                    }
                    self.advance(n, false);
                }
                self.ports[n].ci
            }
            _ => 0,
        }
    }

    fn wr(&mut self, off: usize, v: u32) {
        match off {
            R_GHC => {
                if v & GHC_HR != 0 {
                    self.reset();
                    return;
                }
                self.ghc = v;
                return;
            }
            R_IS => {
                self.his &= !v;
                return;
            }
            R_BOHC => {
                // OS ownership request: the firmware answers after some polls.
                if v & 2 != 0 && self.bohc & 2 == 0 {
                    self.bohc |= 2;
                    self.handoff_left = self.handoff_polls;
                }
                return;
            }
            _ => {}
        }
        let Some((n, o)) = Self::port_index(off) else { return };
        if n >= self.ports.len() {
            return;
        }
        if self.ghc & GHC_AE == 0 {
            self.violation(format!("port {n} register {o:#x} written with GHC.AE clear"));
        }
        match o {
            P_CLB => self.ports[n].clb = v,
            P_CLBU => self.ports[n].clbu = v,
            P_FB => self.ports[n].fb = v,
            P_FBU => self.ports[n].fbu = v,
            P_IS => self.ports[n].is &= !v,
            P_IE => self.ports[n].ie = v,
            P_SERR => self.ports[n].serr &= !v,
            P_CMD => self.write_cmd(n, v),
            P_CI => {
                self.ports[n].ci |= v;
                self.issue(n);
            }
            _ => {}
        }
    }

    fn write_cmd(&mut self, n: usize, v: u32) {
        let p = &mut self.ports[n];
        if v & CMD_SUD != 0 {
            if !p.spun {
                p.spun = true;
                p.link_left = p.link_polls;
            }
        }
        let was_running = p.running;
        let st = v & CMD_ST != 0;
        if st && !was_running {
            p.running = true;
        } else if !st && was_running {
            // Stopping clears PxCI and ends whatever the engine held.
            p.running = false;
            p.halted = false;
            p.ci = 0;
            p.pending = None;
            p.tfd = TFD_OK;
            self.stops[n] += 1;
        }
        let p = &mut self.ports[n];
        let fre = v & CMD_FRE != 0;
        p.cmd = (v & !(CMD_CR | CMD_FR)) | if p.running { CMD_CR } else { 0 } | if fre { CMD_FR } else { 0 };
    }

    /// `PxCI` written: decode the slot 0 command out of the driver's memory.
    fn issue(&mut self, n: usize) {
        let (clb, fb, running, fre, halted, already) = {
            let p = &self.ports[n];
            (
                p.clb as u64 | (p.clbu as u64) << 32,
                p.fb as u64 | (p.fbu as u64) << 32,
                p.running,
                p.cmd & CMD_FRE != 0,
                p.halted,
                p.pending.is_some(),
            )
        };
        if !running || !fre {
            self.violation(format!("port {n}: command issued with the engine or the FIS receiver off"));
            return;
        }
        if halted {
            return;
        }
        if already {
            self.violation(format!("port {n}: a second command while one is in flight"));
            return;
        }
        if clb % 1024 != 0 || fb % 256 != 0 {
            self.violation(format!("port {n}: command list {clb:#x} / FIS area {fb:#x} misaligned"));
        }
        let dw0 = rd_dword(clb);
        let ctba = rd_dword(clb + 8) as u64 | (rd_dword(clb + 12) as u64) << 32;
        if ctba % 128 != 0 {
            self.violation(format!("port {n}: command table {ctba:#x} not 128-byte aligned"));
        }
        if dw0 & 0x1F != 5 {
            self.violation(format!("port {n}: command FIS length {} dwords, not 5", dw0 & 0x1F));
        }
        let write = dw0 & (1 << 6) != 0;
        let prdtl = (dw0 >> 16) as usize;
        let mut fis = [0u8; 20];
        for i in 0..5 {
            fis[4 * i..4 * i + 4].copy_from_slice(&rd_dword(ctba + 4 * i as u64).to_le_bytes());
        }
        if fis[0] != 0x27 || fis[1] != 0x80 {
            self.violation(format!("port {n}: FIS {:#04x}/{:#04x} is not a command H2D register FIS", fis[0], fis[1]));
        }
        let cmd = fis[2];
        let lba = fis[4] as u64
            | (fis[5] as u64) << 8
            | (fis[6] as u64) << 16
            | (fis[8] as u64) << 24
            | (fis[9] as u64) << 32
            | (fis[10] as u64) << 40;
        let count = fis[12] as u32 | (fis[13] as u32) << 8;
        if cmd != 0xEC && fis[7] & 0x40 == 0 {
            self.violation(format!("command {cmd:#04x} without the LBA bit in the device register"));
        }
        let mut prds = Vec::new();
        for i in 0..prdtl {
            let e = ctba + 0x80 + 16 * i as u64;
            let dba = rd_dword(e) as u64 | (rd_dword(e + 4) as u64) << 32;
            let dbc = rd_dword(e + 12);
            if dba % 2 != 0 || dbc & 1 == 0 {
                self.violation(format!("PRD {i}: address {dba:#x} or count {dbc:#x} odd-ness wrong"));
            }
            prds.push((dba, (dbc & 0x3F_FFFF) as usize + 1));
        }
        // A data command's bytes are those its PRDT names.
        let log = Logged { cmd, lba, count, prds, write };
        self.log.push(log.clone());
        let countdown = self.latency;
        self.ports[n].pending = Some(Pending { log, countdown });
        self.advance(n, false);
    }

    /// Finish port `n`'s command if its time has come (`force`: it has, the
    /// driver slept).
    fn advance(&mut self, n: usize, force: bool) {
        let ready = match self.ports[n].pending.as_ref() {
            Some(pd) => force || pd.countdown == 0,
            None => false,
        };
        if !ready {
            return;
        }
        let fault = std::mem::replace(&mut self.fault, Fault::None);
        if fault == Fault::Hang {
            // Never completes; the fault stays armed for no one.
            self.ports[n].pending.as_mut().unwrap().countdown = u32::MAX;
            return;
        }
        let log = self.ports[n].pending.take().unwrap().log;
        let bytes: usize = log.prds.iter().map(|p| p.1).sum();
        let clb = self.ports[n].clb as u64 | (self.ports[n].clbu as u64) << 32;
        let (mut abort, mut moved) = (false, bytes);
        match log.cmd {
            0xEC => self.identify_into(&log.prds),
            0x25 | 0x35 => {
                let want = if log.count == 0 { 65536 } else { log.count as usize } * SECTOR;
                if want != bytes {
                    self.violation(format!("PRDT names {bytes} bytes for a {want}-byte command"));
                }
                if (log.lba as usize + want / SECTOR) * SECTOR > self.disk.len() {
                    self.violation(format!("command beyond the disk: lba {} count {}", log.lba, log.count));
                } else if fault == Fault::TaskFile {
                    abort = true;
                } else {
                    self.dma(&log);
                }
            }
            0xEA => {
                self.flushes += 1;
                if self.flush_aborts || !self.flush_ext {
                    abort = true;
                }
            }
            c => self.violation(format!("unknown ATA command {c:#04x}")),
        }
        if fault == Fault::ShortCount {
            moved -= SECTOR;
        }
        let p = &mut self.ports[n];
        if abort {
            // Task file error: ERR, and the error register's UNC (data) or
            // ABRT (a command the disk refuses).
            let errreg = if log.cmd == 0xEA { 0x04 } else { 0x40 };
            p.tfd = TFD_OK | 1 | errreg << 8;
            p.is |= IS_TFES | IS_DHRS;
            p.halted = true;
            p.running = true;
            // CI stays set: the engine stopped on it.
            p.pending = None;
        } else {
            p.ci &= !1;
            p.is |= IS_DHRS;
        }
        self.his |= 1 << n;
        // PRDBC, in the command header.
        // SAFETY: slot 0's header, in the driver's command list page.
        unsafe { std::ptr::write_volatile((virt(clb) + 4) as *mut u32, moved as u32) };
    }

    fn identify_into(&mut self, prds: &[(u64, usize)]) {
        let mut w = [0u16; 256];
        w[0] = 0x0040;
        let name = b"AZOS MODEL DISK                         ";
        for i in 0..20 {
            w[27 + i] = (name[2 * i] as u16) << 8 | name[2 * i + 1] as u16;
        }
        w[49] = 1 << 9;
        w[83] = 0x4000 | if self.lba48 { 1 << 10 } else { 0 } | if self.flush_ext { 1 << 13 } else { 0 };
        let sectors = (self.disk.len() / SECTOR) as u64;
        w[60] = 0xFFFF; // 28-bit capacity: wrong on purpose, 100-103 are the truth
        w[61] = 0x0FFF;
        for i in 0..4 {
            w[100 + i] = (sectors >> (16 * i)) as u16;
        }
        w[106] = 0x4000;
        if self.logical_4k {
            w[106] |= 1 << 12;
            w[117] = 2048;
        }
        let mut bytes = Vec::new();
        for x in w {
            bytes.extend_from_slice(&x.to_le_bytes());
        }
        let mut off = 0;
        for &(pa, len) in prds {
            let n = len.min(bytes.len() - off);
            // SAFETY: a PRD the driver named: staging memory it owns.
            unsafe { std::ptr::copy_nonoverlapping(bytes[off..].as_ptr(), virt(pa) as *mut u8, n) };
            off += n;
        }
    }

    fn dma(&mut self, log: &Logged) {
        let mut disk_off = log.lba as usize * SECTOR;
        for &(pa, len) in &log.prds {
            // SAFETY: a PRD the driver named: staging memory it owns.
            unsafe {
                if log.write {
                    std::ptr::copy_nonoverlapping(virt(pa) as *const u8, self.disk[disk_off..].as_mut_ptr(), len);
                } else {
                    std::ptr::copy_nonoverlapping(self.disk[disk_off..].as_ptr(), virt(pa) as *mut u8, len);
                }
            }
            disk_off += len;
        }
    }
}

impl Regs for Mock {
    fn rd32(&self, off: usize) -> u32 {
        self.0.lock().unwrap().rd(off)
    }
    fn wr32(&self, off: usize, val: u32) {
        self.0.lock().unwrap().wr(off, val)
    }
}

impl Mock {
    /// An HBA with `ports` ports, the disk on `disk_port`, `sectors` sectors
    /// holding `pattern(sector)` bytes.
    fn new(ports: usize, disk_port: usize, sectors: usize) -> Mock {
        let mut disk = vec![0u8; sectors * SECTOR];
        for s in 0..sectors {
            disk[s * SECTOR..(s + 1) * SECTOR].fill(pattern(s as u64));
        }
        let mut ps: Vec<PortM> = (0..ports).map(|n| PortM::new(n == disk_port)).collect();
        for p in ps.iter_mut() {
            p.spun = false;
        }
        let m = Mock(Arc::new(Mutex::new(Inner {
            cap: CAP_SSS | CAP_S64A | (ports as u32 - 1),
            cap2: 0,
            ghc: 0,
            his: 0,
            bohc: 0,
            handoff_polls: 3,
            handoff_left: 0,
            reset_polls: 2,
            reset_left: 0,
            ports: ps,
            disk,
            flush_ext: true,
            flush_aborts: false,
            logical_4k: false,
            lba48: true,
            latency: 2,
            fault: Fault::None,
            log: Vec::new(),
            resets: 0,
            flushes: 0,
            stops: vec![0; ports],
            violations: Vec::new(),
        })));
        m
    }

    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        f(&mut self.0.lock().unwrap())
    }

    fn violations(&self) -> Vec<String> {
        self.with(|m| m.violations.clone())
    }

    /// Commands the model ran, IDENTIFY first.
    fn log(&self) -> Vec<Logged> {
        self.with(|m| m.log.clone())
    }

    fn disk(&self, sector: usize, count: usize) -> Vec<u8> {
        self.with(|m| m.disk[sector * SECTOR..(sector + count) * SECTOR].to_vec())
    }

    /// The device makes progress (the driver slept); the line is asserted.
    fn step(&self) -> bool {
        self.with(|m| {
            for n in 0..m.ports.len() {
                m.advance(n, true);
            }
            m.line()
        })
    }
}

fn pattern(sector: u64) -> u8 {
    (sector as u8).wrapping_mul(7).wrapping_add(3)
}

fn new_ahci(m: &Mock, irq: bool) -> Ahci<Mock> {
    Ahci::attach(m.clone(), u64::MAX, irq, BUDGETS).expect("attach")
}

fn data_cmd(op: HwOp, lba: u64, sectors: u32, segs: &[&[u8]]) -> HwCmd<'static> {
    // SAFETY-free trick: the test keeps the slices alive for the call by
    // leaking them; a few KiB per test.
    let segs: Vec<&'static [u8]> = segs.iter().map(|s| &*Box::leak(s.to_vec().into_boxed_slice())).collect();
    HwCmd { op, lba, sectors, fua: false, segs: Box::leak(segs.into_boxed_slice()) }
}

/// What the request layer does with one command: claim, start, reap until it
/// is done (sleeping in `wait` when the driver is in interrupt mode), copy a
/// read's data out, release.
fn run(hw: &Ahci<Mock>, cmd: &HwCmd<'_>) -> (HwStatus, Vec<u8>) {
    let tag = match hw.claim() {
        Claim::Tag(t) => t,
        c => panic!("claim answered {c:?}"),
    };
    hw.start(tag, cmd).expect("start");
    let mut out = [HwDone { tag: 0, status: HwStatus::Ok }; HW_TAGS_MAX];
    let t0 = std::time::Instant::now();
    loop {
        if hw.reap(&mut out) > 0 {
            break;
        }
        assert!(t0.elapsed().as_secs() < 5, "the command never ended");
        if !hw.wait(t0.elapsed().as_nanos() as u64 + 10_000_000) {
            std::hint::spin_loop();
        }
    }
    let status = out[0].status;
    let mut data = vec![0u8; cmd.sectors as usize * SECTOR];
    if status == HwStatus::Ok && cmd.op == HwOp::Read {
        hw.copy_out(0, 0, &mut data);
    }
    hw.release(tag);
    (status, data)
}

fn read(hw: &Ahci<Mock>, lba: u64, sectors: u32) -> (HwStatus, Vec<u8>) {
    run(hw, &data_cmd(HwOp::Read, lba, sectors, &[]))
}

fn flush(hw: &Ahci<Mock>) -> HwStatus {
    run(hw, &HwCmd { op: HwOp::Flush, lba: 0, sectors: 0, fua: false, segs: &[] }).0
}

fn expect(m: &Mock, expected_violations: usize) {
    let v = m.violations();
    assert_eq!(v.len(), expected_violations, "model violations: {v:?}");
}

// ── The wire ────────────────────────────────────────────────────────────

/// **Discriminates.** The FIS lays the 48-bit LBA out as three low bytes,
/// the device register, three high bytes; the count as low, high. Swap the
/// `lba >> 24` and `lba` bytes, or drop the Command bit, and the expected
/// bytes differ. Canary: `f[8] = (lba >> 24) as u8` -> `f[8] = (lba >> 16) as u8`.
#[test]
fn the_command_fis_is_laid_out_as_the_spec_has_it() {
    let f = h2d_fis(0x25, 0x0000_0123_4567_89AB, 0x0102);
    assert_eq!(
        f,
        [0x27, 0x80, 0x25, 0, 0xAB, 0x89, 0x67, 0x40, 0x45, 0x23, 0x01, 0, 0x02, 0x01, 0, 0, 0, 0, 0, 0]
    );
    // 65536 sectors is a count of 0.
    assert_eq!(&h2d_fis(0x35, 0, 65536)[12..14], &[0, 0]);
}

/// **Discriminates.** The header's first dword is the FIS length in dwords
/// (5), the write bit (6) and the PRDT length in 31:16; the table address
/// follows in dwords 2 and 3. Canary: `<< 6` -> `<< 7`.
#[test]
fn the_command_header_and_the_prd_entry_are_encoded_as_the_spec_has_them() {
    let h = cmd_header(true, 3, 0x1_2345_6800);
    assert_eq!(h[0], 5 | 1 << 6 | 3 << 16);
    assert_eq!((h[1], h[2], h[3]), (0, 0x2345_6800, 1));
    assert_eq!(cmd_header(false, 1, 0)[0], 5 | 1 << 16);
    // A byte count of 4096 is 4095 in the entry.
    assert_eq!(prd_entry(0x2_0000_1000, 4096), [0x1000, 2, 0, 4095]);
    assert_eq!(prd_entry(0x1000, 512)[3], 511);
}

fn ident_words() -> [u16; 256] {
    let mut w = [0u16; 256];
    w[83] = 0x4000 | 1 << 10 | 1 << 13;
    w[100] = 0x3456;
    w[101] = 0x0012;
    w[106] = 0x4000;
    w
}

/// **Discriminates.** The capacity is words 100-103, not the 28-bit words
/// 60-61 (set to nonsense here), and the checks refuse an ATAPI device, a
/// disk without 48-bit LBA and one with 4 KiB logical sectors. Canary:
/// `w[100]` -> `w[60]` in `decode_identify`; or drop the `w[83]` check.
#[test]
fn identify_is_decoded_and_the_disks_the_driver_cannot_drive_are_refused() {
    let mut w = ident_words();
    w[60] = 0xFFFF;
    w[61] = 0x0FFF;
    assert_eq!(decode_identify(&w), Ok(Ident { sectors: 0x12_3456, flush_ext: true }));
    w[83] &= !(1 << 13);
    assert!(!decode_identify(&w).unwrap().flush_ext);
    let mut a = ident_words();
    a[0] = 0x8500;
    assert!(matches!(decode_identify(&a), Err(AhciError::Format(_))));
    let mut b = ident_words();
    b[83] &= !(1 << 10);
    assert!(matches!(decode_identify(&b), Err(AhciError::Format(_))));
    let mut c = ident_words();
    c[106] |= 1 << 12;
    c[117] = 2048;
    assert!(matches!(decode_identify(&c), Err(AhciError::Format(_))));
    // A logical sector of 256 words is 512 bytes: fine.
    c[117] = 256;
    assert!(decode_identify(&c).is_ok());
    let mut d = ident_words();
    d[100] = 0;
    d[101] = 0;
    assert!(matches!(decode_identify(&d), Err(AhciError::Format(_))));
}

// ── Bring-up ────────────────────────────────────────────────────────────

/// **Discriminates.** The HBA is taken (AE, reset, AE), the port is spun up
/// (the model shows no link until SUD), pointed at 1 KiB / 256-byte aligned
/// memory, started with the FIS receiver on, and IDENTIFY DEVICE runs first:
/// one PRDT entry of 512 bytes. Interrupts stay off (not asked for).
/// Canaries: drop the `CMD_SUD` write in `probe_port` (the model shows no
/// link: NoDisk); drop the AE write after the reset (the model records
/// register accesses with AE clear); probe without the FIS receiver or
/// without `PxFB` (the model's task file stays at its reset value, no
/// signature: NoDisk).
#[test]
fn attach_resets_the_hba_spins_the_port_up_and_identifies_the_disk() {
    let m = Mock::new(4, 0, 256);
    let hw = new_ahci(&m, false);
    assert_eq!(hw.sectors(), 256);
    let caps = hw.caps();
    assert_eq!(caps.sectors, 256);
    assert_eq!(caps.max_sectors as usize, XFER_SECTORS);
    assert!(!caps.fua, "SATA has no FUA outside NCQ");
    assert_eq!(caps.max_discard_sectors, 0);
    let log = m.log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].cmd, 0xEC);
    assert_eq!(log[0].prds.len(), 1);
    assert_eq!(log[0].prds[0].1, 512);
    m.with(|m| {
        assert_eq!(m.resets, 1);
        let p = &m.ports[0];
        assert!(p.running && p.cmd & CMD_FRE != 0 && p.cmd & CMD_SUD != 0);
        assert_eq!(p.ie, 0, "no interrupt was asked for");
        assert_eq!(m.ghc & GHC_IE, 0);
    });
    expect(&m, 0);
}

/// **Discriminates.** The disk is the first port with an ATA signature and a
/// link: port 0 is empty, port 1 an ATAPI drive, port 2 the disk, port 3 a
/// second disk that must be left alone. Canary: drop the `SIG_ATA` compare
/// in `probe_port` (port 1 is taken, and its IDENTIFY is not a disk's).
#[test]
fn the_first_ata_port_is_the_disk() {
    let m = Mock::new(4, 2, 128);
    m.with(|m| {
        m.ports[1].present = true;
        m.ports[1].atapi = true;
        m.ports[3].present = true;
    });
    let hw = new_ahci(&m, false);
    assert_eq!(hw.sectors(), 128);
    m.with(|m| {
        assert!(m.ports[2].running);
        assert!(!m.ports[1].running && !m.ports[3].running && !m.ports[0].running);
    });
    expect(&m, 0);
}

/// **Discriminates.** No ATA device on any port is `NoDisk`, and does not
/// leave a port running or receiving FISes into pages that went back.
/// Canary: drop the `let _ = p.stop(b)` of a failed `probe_port`; or the
/// `found` check.
#[test]
fn a_controller_with_no_disk_is_not_used() {
    let m = Mock::new(3, 0, 16);
    m.with(|m| {
        m.ports[0].present = false;
        m.ports[1].present = true;
        m.ports[1].atapi = true;
    });
    assert!(matches!(Ahci::attach(m.clone(), u64::MAX, false, BUDGETS), Err(AhciError::NoDisk)));
    m.with(|m| assert!(m.ports.iter().all(|p| !p.running && p.cmd & CMD_FRE == 0)));
    expect(&m, 0);
}

/// **Discriminates.** A disk that is not driveable fails the attach and the
/// port is stopped again. Canary: drop `teardown()` in `attach`.
#[test]
fn a_disk_the_driver_cannot_drive_stops_the_port_again() {
    let m = Mock::new(1, 0, 16);
    m.with(|m| m.lba48 = false);
    assert!(matches!(Ahci::attach(m.clone(), u64::MAX, false, BUDGETS), Err(AhciError::Format(_))));
    m.with(|m| {
        assert!(!m.ports[0].running, "the port was left running");
        assert_eq!(m.resets, 2, "bring-up reset, then teardown reset");
    });
}

/// **Discriminates.** The firmware owns the HBA until it lets go: the OS
/// asks (OOS), waits for BOS to clear, and only then resets (the model
/// records a reset while the firmware owns it). Canary: drop `bios_handoff`.
#[test]
fn the_hba_is_taken_from_the_firmware_before_it_is_reset() {
    let m = Mock::new(1, 0, 16);
    m.with(|m| {
        m.cap2 = 1;
        m.bohc = 1;
    });
    let _hw = new_ahci(&m, false);
    m.with(|m| assert_eq!(m.bohc & 1, 0, "the firmware still owns the HBA"));
    expect(&m, 0);

    // A firmware that never lets go: refused, and still not reset.
    let m = Mock::new(1, 0, 16);
    m.with(|m| {
        m.cap2 = 1;
        m.bohc = 1;
        m.handoff_polls = u32::MAX;
    });
    assert!(matches!(Ahci::attach(m.clone(), u64::MAX, false, BUDGETS), Err(AhciError::Handoff)));
    m.with(|m| assert_eq!(m.resets, 0));
}

/// **Discriminates.** An HBA without 64-bit addressing is given only memory
/// below 4 GiB. The host's heap is above that, so with no low memory the
/// attach finds none; with low memory every address the HBA was given has a
/// zero high half. An HBA with 64-bit addressing takes the high pages.
/// Canary: `dma_mask.min(0xFFFF_FFFF)` -> `dma_mask` in `attach` (the first
/// attach then succeeds with high pages).
#[test]
fn an_hba_without_64bit_addressing_is_given_memory_below_4gib() {
    #[cfg(target_pointer_width = "64")]
    {
        let m = Mock::new(1, 0, 16);
        m.with(|m| m.cap &= !CAP_S64A);
        azos_mm::pmm::use_low_phys(false);
        let r = Ahci::attach(m.clone(), u64::MAX, false, BUDGETS);
        assert!(matches!(r, Err(AhciError::NoMemory)), "a 32-bit HBA was given pages above 4 GiB");

        azos_mm::pmm::use_low_phys(true);
        let m = Mock::new(1, 0, 16);
        m.with(|m| m.cap &= !CAP_S64A);
        let hw = Ahci::attach(m.clone(), u64::MAX, false, BUDGETS).expect("low pages");
        azos_mm::pmm::use_low_phys(false);
        m.with(|m| {
            let p = &m.ports[0];
            assert_eq!((p.clbu, p.fbu), (0, 0));
        });
        let log = m.log();
        assert!(log[0].prds.iter().all(|&(pa, _)| pa < 1 << 32));
        drop(hw);

        // 64-bit capable: the high pages are fine.
        let m = Mock::new(1, 0, 16);
        let _hw = new_ahci(&m, false);
        expect(&m, 0);
    }
}

// ── The data path ───────────────────────────────────────────────────────

/// **Discriminates.** A read returns the sectors the disk holds, across the
/// bounce pages (13 sectors is 6656 B: a 4096 + 2560 PRDT), as READ DMA EXT
/// with the right LBA and count. Canary: `ATA_READ_DMA_EXT` -> `0x24`; or
/// `copy_out` ignoring `off`.
#[test]
fn a_read_returns_the_disk_through_a_prdt_over_the_staging_pages() {
    let m = Mock::new(1, 0, 256);
    let hw = new_ahci(&m, false);
    let (st, data) = read(&hw, 40, 13);
    assert_eq!(st, HwStatus::Ok);
    assert_eq!(data, m.disk(40, 13));
    let l = &m.log()[1];
    assert_eq!((l.cmd, l.lba, l.count, l.write), (0x25, 40, 13, false));
    assert_eq!(l.prds.iter().map(|p| p.1).collect::<Vec<_>>(), vec![4096, 2560]);
    // One sector: one entry of 512.
    let (st, data) = read(&hw, 255, 1);
    assert_eq!((st, data), (HwStatus::Ok, m.disk(255, 1)));
    assert_eq!(m.log()[2].prds, vec![(m.log()[2].prds[0].0, 512)]);
    expect(&m, 0);
}

/// **Discriminates.** A write reaches the disk byte for byte from segments
/// that do not fall on sector or page boundaries, as WRITE DMA EXT with the
/// write bit set; a read right after returns it. Canary: `stage_in` advancing
/// `off` by one segment too few; or `write` false in `build_command`.
#[test]
fn a_write_copies_its_segments_in_order_and_reaches_the_disk() {
    let m = Mock::new(1, 0, 256);
    let hw = new_ahci(&m, false);
    let bytes: Vec<u8> = (0..10 * SECTOR).map(|i| (i * 31 % 251) as u8).collect();
    let (a, rest) = bytes.split_at(700);
    let (b, c) = rest.split_at(3000);
    let (st, _) = run(&hw, &data_cmd(HwOp::Write, 100, 10, &[a, b, c]));
    assert_eq!(st, HwStatus::Ok);
    assert_eq!(m.disk(100, 10), bytes);
    let l = &m.log()[1];
    assert_eq!((l.cmd, l.lba, l.count, l.write), (0x35, 100, 10, true));
    assert_eq!(l.prds.iter().map(|p| p.1).collect::<Vec<_>>(), vec![4096, 1024]);
    let (st, back) = read(&hw, 100, 10);
    assert_eq!((st, back), (HwStatus::Ok, bytes));
    expect(&m, 0);
}

/// **Discriminates.** Only one command is ever in the HBA: the slot is
/// `Busy` while held, free again after `release`, and the model records no
/// second command. Canary: `claim` always `Tag(0)` (the layer then starts a
/// second command and the model records it).
#[test]
fn one_command_is_in_the_device_at_a_time() {
    let m = Mock::new(1, 0, 1024);
    let hw = new_ahci(&m, false);
    assert!(matches!(hw.claim(), Claim::Tag(0)));
    assert!(matches!(hw.claim(), Claim::Busy));
    hw.release(0);
    assert!(matches!(hw.claim(), Claim::Tag(0)));
    hw.release(0);
    // The driver refuses what the device cannot do, without touching it.
    let big = data_cmd(HwOp::Read, 0, XFER_SECTORS as u32 + 1, &[]);
    assert!(hw.start(0, &big).is_err());
    let past = data_cmd(HwOp::Read, 1020, 8, &[]);
    assert!(hw.start(0, &past).is_err());
    assert!(hw.start(0, &HwCmd { op: HwOp::Discard, lba: 0, sectors: 8, fua: false, segs: &[] }).is_err());
    assert_eq!(m.log().len(), 1, "only IDENTIFY ran");
    expect(&m, 0);
}

/// **Discriminates.** The real request layer drives the disk: a transfer of
/// more than one command's sectors is cut into commands and reassembled; a
/// write and a read back match. Canary: `max_sectors` larger than
/// `XFER_SECTORS` in `caps` (the driver refuses the command and the transfer
/// fails).
#[test]
fn the_request_layer_cuts_a_big_transfer_into_commands() {
    let m = Mock::new(1, 0, 1024);
    let hw: &'static Ahci<Mock> = Box::leak(Box::new(new_ahci(&m, false)));
    let q: &'static ReqQueue = Box::leak(Box::new(ReqQueue::new()));
    let count = XFER_SECTORS as u32 * 2 + 5;
    let mut buf = vec![0u8; count as usize * SECTOR];
    q.transfer(hw, 10, false, 7, count, 0, buf.as_mut_ptr(), buf.len()).expect("read");
    assert_eq!(buf, m.disk(7, count as usize));
    let mut w: Vec<u8> = (0..buf.len()).map(|i| (i % 253) as u8).collect();
    q.transfer(hw, 10, true, 500, count, 0, w.as_mut_ptr(), w.len()).expect("write");
    assert_eq!(m.disk(500, count as usize), w);
    assert!(m.log().len() >= 1 + 3 + 3, "{} commands", m.log().len());
    expect(&m, 0);
}

// ── Flush ───────────────────────────────────────────────────────────────

/// **Discriminates.** A disk with FLUSH CACHE EXT is sent it (0xEA, no data,
/// no PRDT); a disk without it is `Unsupported` and the HBA is not touched.
/// Canary: `HwOp::Flush if self.flush_ext` -> `HwOp::Flush if true` (the
/// second half then sends the command and the model aborts it: Unsupported
/// still, but a command was logged, which the assertion refuses).
#[test]
fn flush_is_sent_where_the_disk_has_it_and_unsupported_where_it_does_not() {
    let m = Mock::new(1, 0, 16);
    let hw = new_ahci(&m, false);
    assert_eq!(flush(&hw), HwStatus::Ok);
    let l = m.log().last().unwrap().clone();
    assert_eq!((l.cmd, l.prds.len()), (0xEA, 0));
    assert_eq!(m.with(|m| m.flushes), 1);
    expect(&m, 0);

    let m = Mock::new(1, 0, 16);
    m.with(|m| m.flush_ext = false);
    let hw = new_ahci(&m, false);
    assert_eq!(flush(&hw), HwStatus::Unsupported);
    assert_eq!(m.log().len(), 1, "no command was sent for a flush the disk does not have");
    // Still usable.
    assert_eq!(read(&hw, 0, 1).0, HwStatus::Ok);
    expect(&m, 0);
}

/// **Discriminates.** A disk that advertises the flush and aborts it (task
/// file error, ABRT) is `Unsupported`, not an I/O error, and the port is
/// restarted so the next command works. Canary: drop the `aborted` test in
/// `outcome` (the status is then `Io`).
#[test]
fn an_aborted_flush_is_unsupported_and_the_port_carries_on() {
    let m = Mock::new(1, 0, 16);
    m.with(|m| m.flush_aborts = true);
    let hw = new_ahci(&m, false);
    assert_eq!(flush(&hw), HwStatus::Unsupported);
    assert_eq!(m.with(|m| m.stops[0]), 1, "the port was not restarted");
    assert_eq!(read(&hw, 3, 2).0, HwStatus::Ok);
    expect(&m, 0);
}

// ── Failure ─────────────────────────────────────────────────────────────

/// **Discriminates.** A task file error fails that command (`Io`), the driver
/// restarts the port (the engine stopped, errors cleared, started again: the
/// model ignores commands until `ST` toggles), and the next read works. The
/// disk is not dead. Canary: `restart_port` returning `true` at entry (the
/// model keeps ignoring commands and the next read times out and kills the
/// driver).
#[test]
fn a_port_error_fails_the_command_and_the_port_is_restarted() {
    let m = Mock::new(1, 0, 64);
    let hw = new_ahci(&m, false);
    m.with(|m| m.fault = Fault::TaskFile);
    let (st, _) = read(&hw, 8, 4);
    assert_eq!(st, HwStatus::Io);
    assert!(!hw.is_dead());
    m.with(|m| {
        assert_eq!(m.stops[0], 1);
        assert!(m.ports[0].running && !m.ports[0].halted);
        assert_eq!(m.ports[0].is, 0, "PxIS was left set");
        assert_eq!(m.ports[0].serr, 0, "PxSERR was left set");
    });
    let (st, data) = read(&hw, 8, 4);
    assert_eq!((st, data), (HwStatus::Ok, m.disk(8, 4)));
    expect(&m, 0);
}

/// **Discriminates.** A command that does not complete within its budget is
/// `Timeout`, the driver resets the HBA (which stops its DMA), latches dead,
/// refuses every later claim. Canary: drop the `expired` check in `outcome`
/// (the command never ends: the test's own 5-second bound fires); or drop
/// the `failed` check in `claim` (the claim then answers a tag).
#[test]
fn a_command_past_its_budget_resets_the_hba_and_the_driver_stays_dead() {
    let m = Mock::new(1, 0, 64);
    let hw = new_ahci(&m, false);
    m.with(|m| m.fault = Fault::Hang);
    let (st, _) = read(&hw, 0, 1);
    assert_eq!(st, HwStatus::Timeout);
    assert!(hw.is_dead());
    m.with(|m| {
        assert_eq!(m.resets, 2, "bring-up reset, then the dead-device reset");
        assert!(!m.ports[0].running, "the HBA still runs its engine");
    });
    assert!(matches!(hw.claim(), Claim::Dead));
    assert!(hw.start(0, &data_cmd(HwOp::Read, 0, 1, &[])).is_err());
    expect(&m, 0);
}

/// **Discriminates.** A transfer that moved fewer bytes than the PRDT named
/// (PRDBC short) is an error, though the HBA reported success. Canary: drop
/// the `moved != bytes` check in `outcome`.
#[test]
fn a_short_transfer_is_an_error() {
    let m = Mock::new(1, 0, 64);
    let hw = new_ahci(&m, false);
    m.with(|m| m.fault = Fault::ShortCount);
    assert_eq!(read(&hw, 0, 4).0, HwStatus::Io);
    assert_eq!(read(&hw, 0, 4).0, HwStatus::Ok);
    expect(&m, 0);
}

// ── Completion by interrupt ─────────────────────────────────────────────

thread_local! {
    static HARNESS: RefCell<Option<(Mock, usize)>> = const { RefCell::new(None) };
    static WOKEN: Cell<u32> = const { Cell::new(0) };
    static BLOCKED: Cell<u32> = const { Cell::new(0) };
}

fn h_tid() -> u32 {
    7
}

fn h_wake(tid: u32) {
    assert_eq!(tid, 7);
    WOKEN.with(|w| w.set(w.get() + 1));
}

/// The driver sleeps: the device makes progress, and if its line is then
/// asserted the interrupt controller runs the handler.
fn h_block(_deadline: u64) -> bool {
    BLOCKED.with(|b| b.set(b.get() + 1));
    HARNESS.with(|h| {
        let h = h.borrow();
        let (m, ahci) = h.as_ref().unwrap();
        if m.step() {
            // SAFETY: the pointer of the `Ahci` the running test owns.
            unsafe { &*(*ahci as *const Ahci<Mock>) }.irq();
        }
    });
    true
}

static HOOKS: Hooks = Hooks { tid: h_tid, block_until: h_block, wake: h_wake };

/// **Discriminates.** With the interrupt on, a command's completion is only
/// seen after the driver slept and the handler ran: the model does not
/// advance on reads, so a driver that polled would never finish. The waiter
/// is woken by the handler (`wake` called with its TID), the interrupt
/// counters move, and IE is enabled only after IDENTIFY. Canary:
/// `wait()` returning `false` at entry (the command never completes in the
/// model's interrupt time; the test's bound fires); or `irq()` not calling
/// `wake` (WOKEN stays 0).
#[test]
fn with_the_interrupt_on_the_driver_sleeps_and_the_handler_wakes_it() {
    let m = Mock::new(1, 0, 64);
    let hw = new_ahci(&m, true);
    m.with(|m| {
        assert_eq!(m.ports[0].ie & IS_TFES, IS_TFES);
        assert_ne!(m.ghc & GHC_IE, 0);
    });
    assert!(!hw.irq_mode(), "no hooks yet: the waiter spins");
    hw.set_hooks(&HOOKS);
    assert!(hw.irq_mode());
    HARNESS.with(|h| *h.borrow_mut() = Some((m.clone(), &hw as *const Ahci<Mock> as usize)));
    WOKEN.with(|w| w.set(0));
    BLOCKED.with(|b| b.set(0));

    for lba in [0u64, 16, 33] {
        let (st, data) = read(&hw, lba, 3);
        assert_eq!((st, data), (HwStatus::Ok, m.disk(lba as usize, 3)));
    }
    let (taken, slept) = hw.irq_counts();
    assert!(taken >= 3, "interrupts taken: {taken}");
    assert!(slept >= 3, "waits that slept: {slept}");
    assert!(WOKEN.with(|w| w.get()) >= 3, "the handler did not wake the sleeper");
    expect(&m, 0);
    HARNESS.with(|h| *h.borrow_mut() = None);
}

/// **Discriminates.** A fatal error arriving by interrupt is handled like a
/// polled one: the sleeping reaper sees the harvested cause, fails the
/// command and restarts the port. Canary: `harvest` not OR-ing into
/// `events` (the cause is cleared at the device and lost: the command then
/// hangs until its budget and the driver dies).
#[test]
fn a_port_error_raised_by_interrupt_is_not_lost() {
    let m = Mock::new(1, 0, 64);
    let hw = new_ahci(&m, true);
    hw.set_hooks(&HOOKS);
    HARNESS.with(|h| *h.borrow_mut() = Some((m.clone(), &hw as *const Ahci<Mock> as usize)));
    m.with(|m| m.fault = Fault::TaskFile);
    assert_eq!(read(&hw, 0, 2).0, HwStatus::Io);
    assert!(!hw.is_dead());
    assert_eq!(read(&hw, 0, 2).0, HwStatus::Ok);
    expect(&m, 0);
    HARNESS.with(|h| *h.borrow_mut() = None);
}
