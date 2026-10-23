// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `mmc.rs` (SDHCI host driver: ADMA2 data path, interrupt completion) run on
//! the host over a register-level model of an SDHCI v3 controller and an SD
//! card.
//!
//! The model is written from the SDHCI v3.00 specification, not from the
//! driver: its own register offsets, its own ADMA2 engine that walks the
//! descriptor table the driver built, out of the "physical" pages the driver
//! gave it, and a card that answers the SD command set the driver uses. It
//! refuses what a controller would refuse (a data command with the wrong DMA
//! select, a table whose last descriptor is not End, a status bit that was not
//! enabled never shows) and records what it saw, so a test can assert on the
//! driver's behaviour, not on its own bookkeeping.
//!
//! Time: a polled waiter makes the model's device progress with every read of
//! INT_STATUS (`latency` reads per event); once the driver has switched the
//! controller to interrupt completion (SIGNAL_ENABLE != 0), reads no longer
//! advance it and the only thing that does is the driver sleeping
//! (`IrqHooks::block_until` -> `step`), after which the model raises its line
//! and the "interrupt controller" calls `mmc::irq_on` -- the handler -- which
//! wakes the sleeper. A driver that polled in interrupt mode would therefore
//! never see its command complete.

use super::mmc::{self, IrqHooks, MmcSlot, Regs};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

const SLOT: MmcSlot = MmcSlot::Sd;
const IDX: usize = 1;
const LINE: u32 = 0x21;

// SDHCI v3.00 register offsets (the model's own copy).
const R_BLKSIZE: usize = 0x04;
const R_BLKCNT: usize = 0x06;
const R_ARG: usize = 0x08;
const R_TRNMOD: usize = 0x0C;
const R_CMD: usize = 0x0E;
const R_RESP: usize = 0x10;
const R_BUFFER: usize = 0x20;
const R_PRESENT: usize = 0x24;
const R_HOSTCTL: usize = 0x28;
const R_CLOCK: usize = 0x2C;
const R_TIMEOUT: usize = 0x2E;
const R_RESET: usize = 0x2F;
const R_INT_STATUS: usize = 0x30;
const R_INT_ENABLE: usize = 0x34;
const R_SIGNAL: usize = 0x38;
const R_ADMA_ERR: usize = 0x54;
const R_ADMA_ADDR: usize = 0x58;
const R_CAPS: usize = 0x40;

const INT_CMD: u32 = 1 << 0;
const INT_XFER: u32 = 1 << 1;
const ERR_CMD_TIMEOUT: u32 = 1 << 16;
const ERR_DATA_CRC: u32 = 1 << 21;
const ERR_ADMA: u32 = 1 << 25;

const CARD_SECTORS: usize = 8192;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Fault {
    None,
    /// The next data command ends with an ADMA error.
    Adma,
    /// The next data command ends with a data CRC error.
    DataCrc,
    /// The next command never answers: the model only raises a command timeout.
    CmdTimeout,
}

#[derive(Clone, Debug)]
struct DataCmd {
    cmd: u16,
    arg: u32,
    trnmod: u16,
    blkcnt: u16,
}

struct Inner {
    regs: [u8; 0x100],
    visible: u32,
    stages: VecDeque<u32>,
    poll_reads: u32,
    // card
    card: Vec<u8>,
    sdhc: bool,
    state: u32,
    rca: u32,
    app: bool,
    acmd41_polls: u32,
    prg_left: u32,
    // knobs
    adma2: bool,
    latency: u32,
    prg_polls: u32,
    fault: Fault,
    // evidence
    status_reads: u32,
    buffer_port: u32,
    line_resets: u32,
    cmds: Vec<u16>,
    data_cmds: Vec<DataCmd>,
    descs: Vec<(u16, u16, u32)>,
    violations: Vec<String>,
}

pub struct Mock {
    inner: Mutex<Inner>,
}

const ST_IDLE: u32 = 0;
const ST_READY: u32 = 1;
const ST_IDENT: u32 = 2;
const ST_STBY: u32 = 3;
const ST_TRAN: u32 = 4;
const ST_PRG: u32 = 7;

fn le16(b: &[u8]) -> u16 { u16::from_le_bytes([b[0], b[1]]) }
fn le32(b: &[u8]) -> u32 { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) }

impl Inner {
    fn put(&mut self, off: usize, bytes: &[u8]) {
        self.regs[off..off + bytes.len()].copy_from_slice(bytes);
    }
    fn get16(&self, off: usize) -> u16 { le16(&self.regs[off..]) }
    fn get32(&self, off: usize) -> u32 { le32(&self.regs[off..]) }

    fn violation(&mut self, what: impl Into<String>) {
        self.violations.push(what.into());
    }

    /// One event becomes visible -- only if the driver enabled its status bit.
    fn release_one(&mut self) -> bool {
        self.poll_reads = 0;
        match self.stages.pop_front() {
            Some(s) => {
                self.visible |= s & self.get32(R_INT_ENABLE);
                true
            }
            None => false,
        }
    }

    fn r1(&self, errors: u32) -> u32 {
        let ready = if self.state == ST_PRG { 0 } else { 1 << 8 };
        (self.state << 9) | ready | errors
    }

    fn respond(&mut self, r: [u32; 4]) {
        for (i, w) in r.iter().enumerate() {
            self.put(R_RESP + 4 * i, &w.to_le_bytes());
        }
    }

    fn exec(&mut self, cmdreg: u16) {
        let cmd = (cmdreg >> 8) & 0x3F;
        let flags = cmdreg & 0x3F;
        let arg = self.get32(R_ARG);
        let trnmod = self.get16(R_TRNMOD);
        let blkcnt = self.get16(R_BLKCNT);
        self.cmds.push(cmd);

        if self.fault == Fault::CmdTimeout {
            self.fault = Fault::None;
            self.stages.push_back(ERR_CMD_TIMEOUT);
            return;
        }

        let app = std::mem::replace(&mut self.app, false);
        let busy = flags & 3 == 3;
        let data = flags & 0x20 != 0;
        let mut errors = 0u32;
        let mut resp = [0u32; 4];
        let mut dir_read = false;
        let mut start = 0usize;
        let mut nblk = 0usize;

        match (app, cmd) {
            (_, 0) => { self.state = ST_IDLE; }
            (_, 8) => { resp[0] = arg & 0x1FF; self.state = ST_IDLE; }
            (_, 55) => { self.app = true; resp[0] = self.r1(1 << 5); }
            (true, 41) => {
                // Powered up after a few polls, like a real card.
                self.acmd41_polls += 1;
                let up = if self.acmd41_polls >= 3 { 1u32 << 31 } else { 0 };
                resp[0] = up | 0x00FF_8000 | if self.sdhc { 1 << 30 } else { 0 };
                if up != 0 { self.state = ST_READY; }
            }
            (_, 2) => { resp = [0x0123_4567, 0x89AB_CDEF, 0x1357_9BDF, 0x0246_8ACE]; self.state = ST_IDENT; }
            (_, 3) => { self.rca = 0x1234; resp[0] = self.rca << 16; self.state = ST_STBY; }
            (_, 7) => { self.state = ST_TRAN; resp[0] = self.r1(0); }
            (_, 16) => { resp[0] = self.r1(0); }
            (true, 6) => { resp[0] = self.r1(0); }
            (_, 13) => {
                resp[0] = self.r1(0);
                if self.state == ST_PRG {
                    self.prg_left = self.prg_left.saturating_sub(1);
                    if self.prg_left == 0 { self.state = ST_TRAN; }
                }
            }
            (_, 17) | (_, 18) | (_, 24) | (_, 25) => {
                dir_read = cmd == 17 || cmd == 18;
                let multi = cmd == 18 || cmd == 25;
                nblk = if trnmod & 2 != 0 { blkcnt as usize } else { 1 };
                let sector = if self.sdhc { arg as usize } else { arg as usize / 512 };
                if !self.sdhc && arg % 512 != 0 {
                    self.violation(format!("SDSC byte address {arg:#x} is not sector aligned"));
                }
                if self.state != ST_TRAN {
                    self.violation(format!("data command in card state {}", self.state));
                }
                if sector + nblk > CARD_SECTORS {
                    errors |= 1 << 30; // ADDRESS_ERROR
                } else {
                    start = sector * 512;
                }
                // What the driver must have programmed.
                if self.get16(R_BLKSIZE) & 0xFFF != 512 { self.violation("block size is not 512"); }
                if self.regs[R_HOSTCTL] & 0x18 != 0x10 {
                    self.violation(format!("data command without ADMA2-32 selected (host control {:#x})", self.regs[R_HOSTCTL]));
                }
                if trnmod & 1 == 0 { self.violation("data command without DMA enable"); }
                if trnmod & 2 == 0 { self.violation("data command without block count enable"); }
                if (trnmod & 0x10 != 0) != dir_read { self.violation("transfer mode direction disagrees with the command"); }
                if (trnmod & 0x20 != 0) != multi { self.violation("multi-block bit disagrees with the command"); }
                if multi && trnmod & 4 == 0 { self.violation("multi-block transfer without Auto CMD12"); }
                if !multi && trnmod & 4 != 0 { self.violation("single-block transfer with Auto CMD12"); }
                if nblk != 1 && !multi { self.violation("single-block command with a block count"); }
                if !data { self.violation("data command without Data Present"); }
                resp[0] = self.r1(errors);
                self.data_cmds.push(DataCmd { cmd, arg, trnmod, blkcnt });
            }
            _ => self.violation(format!("unexpected command {cmd} (app {app})")),
        }
        if (flags & 3 == 0) && cmd != 0 {
            self.violation(format!("command {cmd} issued without a response type"));
        }
        self.respond(resp);

        let mut stages = vec![INT_CMD];
        if data {
            let fault = std::mem::replace(&mut self.fault, Fault::None);
            let ok = errors == 0;
            let adma = self.run_adma(nblk * 512, dir_read, start, ok);
            match (fault, adma) {
                (Fault::Adma, _) | (_, Err(())) => {
                    self.put(R_ADMA_ERR, &1u32.to_le_bytes());
                    stages.push(ERR_ADMA);
                }
                (Fault::DataCrc, _) => stages.push(ERR_DATA_CRC),
                _ => {
                    stages.push(INT_XFER);
                    if !dir_read && ok {
                        if self.prg_polls > 0 {
                            self.state = ST_PRG;
                            self.prg_left = self.prg_polls;
                        }
                    }
                }
            }
        } else if busy {
            stages.push(INT_XFER);
        }
        self.stages.extend(stages);
    }

    /// The controller's ADMA2 engine: walk the table at ADMA_ADDR, moving
    /// `bytes` between the pages it names and the card at byte offset
    /// `start` (when `apply`, i.e. the card accepted the command).
    fn run_adma(&mut self, bytes: usize, dir_read: bool, start: usize, apply: bool) -> Result<(), ()> {
        let table = le32(&self.regs[R_ADMA_ADDR..]) as usize;
        let hi = le32(&self.regs[R_ADMA_ADDR + 4..]);
        if hi != 0 { self.violation("ADMA address high word is not zero for a 32-bit table"); }
        let mut p = azos_mm::addr::phys_to_virt(table);
        let mut done = 0usize;
        loop {
            let mut d = [0u8; 8];
            // SAFETY: the table is a page the driver got from the allocator.
            unsafe { std::ptr::copy_nonoverlapping(p as *const u8, d.as_mut_ptr(), 8) };
            let (attr, len, addr) = (le16(&d[0..]), le16(&d[2..]), le32(&d[4..]));
            self.descs.push((attr, len, addr));
            if attr & 1 == 0 {
                self.violation("descriptor not valid");
                return Err(());
            }
            if (attr >> 4) & 3 != 2 {
                self.violation(format!("descriptor action {} is not tran", (attr >> 4) & 3));
                return Err(());
            }
            let l = if len == 0 { 65536 } else { len as usize };
            let n = l.min(bytes - done);
            let mem = azos_mm::addr::phys_to_virt(addr as usize) as *mut u8;
            if apply {
                let card = &mut self.card[start + done..start + done + n];
                // SAFETY: `mem` is a bounce page the driver allocated, `n <= len`.
                unsafe {
                    if dir_read {
                        std::ptr::copy_nonoverlapping(card.as_ptr(), mem, n);
                    } else {
                        std::ptr::copy_nonoverlapping(mem, card.as_mut_ptr(), n);
                    }
                }
            }
            done += n;
            if attr & 2 != 0 {
                if done != bytes {
                    self.violation(format!("table ended (End) after {done} of {bytes} bytes"));
                    return Err(());
                }
                return Ok(());
            }
            if done == bytes {
                self.violation("all data moved but the last descriptor is not End");
                return Err(());
            }
            p += 8;
        }
    }
}

impl Mock {
    pub fn new(sdhc: bool) -> Self {
        let mut i = Inner {
            regs: [0; 0x100],
            visible: 0,
            stages: VecDeque::new(),
            poll_reads: 0,
            card: vec![0; CARD_SECTORS * 512],
            sdhc,
            state: ST_IDLE,
            rca: 0,
            app: false,
            acmd41_polls: 0,
            prg_left: 0,
            adma2: true,
            latency: 2,
            prg_polls: 0,
            fault: Fault::None,
            status_reads: 0,
            buffer_port: 0,
            line_resets: 0,
            cmds: Vec::new(),
            data_cmds: Vec::new(),
            descs: Vec::new(),
            violations: Vec::new(),
        };
        i.put(R_CLOCK, &2u16.to_le_bytes());
        Mock { inner: Mutex::new(i) }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        f(&mut self.inner.lock().unwrap())
    }

    /// Let one pending event happen (the device ran while the driver slept).
    fn step(&self) -> bool {
        self.with(|i| i.release_one())
    }

    /// Is the interrupt line asserted?
    fn irq_asserted(&self) -> bool {
        self.with(|i| i.visible & i.get32(R_SIGNAL) != 0)
    }

    fn card_read(&self, byte_off: usize, len: usize) -> Vec<u8> {
        self.with(|i| i.card[byte_off..byte_off + len].to_vec())
    }
}

impl Regs for Mock {
    fn base(&self) -> usize { 0xBEEF_0000 }

    fn rd8(&self, off: usize) -> u8 {
        self.with(|i| if off == R_RESET { 0 } else { i.regs[off] })
    }
    fn rd16(&self, off: usize) -> u16 {
        self.with(|i| le16(&i.regs[off..]))
    }
    fn rd32(&self, off: usize) -> u32 {
        self.with(|i| match off {
            R_INT_STATUS => {
                i.status_reads += 1;
                if i.get32(R_SIGNAL) == 0 {
                    i.poll_reads += 1;
                    if i.poll_reads >= i.latency { i.release_one(); }
                }
                i.visible | if i.visible & 0xFFFF_0000 != 0 { 1 << 15 } else { 0 }
            }
            R_PRESENT => 1 << 16,
            R_CAPS => if i.adma2 { 0x0578_34B4 } else { 0x0578_34B4 & !(1 << 19) },
            R_BUFFER => { i.buffer_port += 1; 0 }
            _ => le32(&i.regs[off..]),
        })
    }
    fn wr8(&self, off: usize, val: u8) {
        self.with(|i| {
            if off == R_RESET {
                if val & 1 != 0 {
                    i.visible = 0;
                    i.stages.clear();
                    for b in i.regs.iter_mut() { *b = 0; }
                    i.regs[R_CLOCK] = 2;
                }
                if val & 6 != 0 {
                    i.line_resets += 1;
                    i.stages.clear();
                    i.visible = 0;
                }
                return;
            }
            i.regs[off] = val;
        })
    }
    fn wr16(&self, off: usize, val: u16) {
        self.with(|i| match off {
            R_CLOCK => i.put(off, &(val | if val & 1 != 0 { 2 } else { 0 }).to_le_bytes()),
            R_CMD => {
                i.put(off, &val.to_le_bytes());
                i.exec(val);
            }
            _ => i.put(off, &val.to_le_bytes()),
        })
    }
    fn wr32(&self, off: usize, val: u32) {
        self.with(|i| match off {
            R_INT_STATUS => i.visible &= !val,
            _ => i.put(off, &val.to_le_bytes()),
        })
    }
}

// ---- Harness ----

/// The model the hooks act on, and what they counted.
static CUR: Mutex<Option<Arc<Mock>>> = Mutex::new(None);
static BLOCKS: AtomicU32 = AtomicU32::new(0);
static WAKES: AtomicU32 = AtomicU32::new(0);
static WOKEN_TID: AtomicU32 = AtomicU32::new(0);

const TEST_TID: u32 = 7;

/// While set, the device finishes (and its interrupt is taken) at the moment
/// the driver asks who is sleeping: after its last look at the status, before
/// the waiter is published, so the handler finds nobody to wake.
static EVENT_IN_THE_WINDOW: AtomicBool = AtomicBool::new(false);

fn t_tid() -> u32 {
    if EVENT_IN_THE_WINDOW.load(Ordering::SeqCst) {
        let m = CUR.lock().unwrap().clone().expect("a model is installed");
        if m.step() && m.irq_asserted() {
            mmc::irq_on(&*m, IDX);
        }
    }
    TEST_TID
}

/// The driver sleeps: time passes, the device finishes something, and if it
/// raised its line the interrupt handler runs.
fn t_block(_deadline: u64) -> bool {
    BLOCKS.fetch_add(1, Ordering::SeqCst);
    let m = CUR.lock().unwrap().clone().expect("a model is installed");
    if m.step() && m.irq_asserted() {
        mmc::irq_on(&*m, IDX);
    }
    true
}

fn t_wake(tid: u32) {
    WAKES.fetch_add(1, Ordering::SeqCst);
    WOKEN_TID.store(tid, Ordering::SeqCst);
}

static HOOKS: IrqHooks = IrqHooks { tid: t_tid, block_until: t_block, wake: t_wake };

static SERIAL: Mutex<()> = Mutex::new(());

/// A fresh model with the card initialised through the driver, polled. The
/// driver's state is process-wide, so the tests run one at a time.
fn setup(sdhc: bool) -> (MutexGuard<'static, ()>, Arc<Mock>) {
    let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    azos_mm::pmm::use_low_phys(true);
    let m = Arc::new(Mock::new(sdhc));
    mmc::irq_off_on(&*m, SLOT);
    *CUR.lock().unwrap() = Some(m.clone());
    assert!(mmc::init_on(&*m, SLOT), "card initialisation");
    (guard, m)
}

fn pattern(sectors: usize, seed: u8) -> Vec<u8> {
    (0..sectors * 512).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed).wrapping_add((i >> 9) as u8)).collect()
}

fn counts() -> (u32, u32, u32, u32) {
    let (taken, slept) = mmc::mmc_irq_counts(SLOT);
    (BLOCKS.load(Ordering::SeqCst), WAKES.load(Ordering::SeqCst), taken, slept)
}

fn clean(m: &Mock) {
    m.with(|i| assert!(i.violations.is_empty(), "the model saw: {:?}", i.violations));
}

// ---- Tests ----

#[test]
fn adma2_descriptor_is_the_spec_layout() {
    // Valid | Act=tran, length 4096 (0x1000), address 0x8000_1000, little-endian.
    assert_eq!(mmc::adma2_descriptor(0x8000_1000, 4096, false), [0x21, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x80]);
    // The last one adds End (bit 1).
    assert_eq!(mmc::adma2_descriptor(0x8000_2000, 2560, true), [0x23, 0x00, 0x00, 0x0A, 0x00, 0x20, 0x00, 0x80]);
}

#[test]
fn init_selects_adma2_and_reports_through_the_status_bits() {
    let (_g, m) = setup(false);
    m.with(|i| {
        assert_eq!(i.regs[R_HOSTCTL], 0x02 | 0x10, "4-bit bus and ADMA2-32");
        assert_eq!(i.regs[R_TIMEOUT], 0x0E, "data timeout counter at its maximum");
        assert_eq!(i.get32(R_INT_ENABLE), 0x03FF_0003, "command/transfer complete and every error bit");
        assert_eq!(i.get32(R_SIGNAL), 0, "no interrupt line before the kernel routes it");
    });
    assert!(mmc::mmc_capacity(SLOT) > 0);
    clean(&m);
}

#[test]
fn a_host_without_adma2_is_refused() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    azos_mm::pmm::use_low_phys(true);
    let m = Mock::new(false);
    m.with(|i| i.adma2 = false);
    assert!(!mmc::init_on(&m, SLOT));
}

#[test]
fn multi_block_write_and_read_go_through_one_adma2_table() {
    for sdhc in [false, true] {
        let (_g, m) = setup(sdhc);
        // 37 sectors: four full pages and a 2560-byte tail.
        let data = pattern(37, 0x11);
        let lba = 100u64;
        m.with(|i| { i.data_cmds.clear(); i.descs.clear(); });
        mmc::write_on(&*m, SLOT, lba, 37, &data).expect("write");
        let (cmd, trnmod, blkcnt, arg) = m.with(|i| {
            assert_eq!(i.data_cmds.len(), 1, "one command for the whole request");
            let c = &i.data_cmds[0];
            (c.cmd, c.trnmod, c.blkcnt, c.arg)
        });
        assert_eq!((cmd, blkcnt), (25, 37), "CMD25 over 37 blocks");
        assert_eq!(trnmod, 0b10_0111, "DMA | block count | Auto CMD12 | multi, host to card");
        assert_eq!(arg as u64, if sdhc { lba } else { lba * 512 });
        m.with(|i| {
            assert_eq!(i.descs.len(), 5);
            for (n, d) in i.descs.iter().enumerate() {
                let last = n == 4;
                assert_eq!(d.0, if last { 0x23 } else { 0x21 }, "End on the last descriptor only");
                assert_eq!(d.1 as usize, if last { 2560 } else { 4096 });
                assert_eq!(d.2 % 4096, 0);
            }
            let mut pages: Vec<u32> = i.descs.iter().map(|d| d.2).collect();
            pages.sort();
            pages.dedup();
            assert_eq!(pages.len(), 5, "five distinct bounce pages");
        });
        assert_eq!(m.card_read(lba as usize * 512, 37 * 512), data, "the card holds what was written");

        let mut back = vec![0u8; 37 * 512];
        m.with(|i| i.data_cmds.clear());
        mmc::read_on(&*m, SLOT, lba, 37, &mut back).expect("read");
        assert_eq!(back, data);
        m.with(|i| {
            assert_eq!(i.data_cmds.len(), 1);
            assert_eq!(i.data_cmds[0].cmd, 18);
            assert_eq!(i.data_cmds[0].trnmod, 0b11_0111, "DMA | block count | Auto CMD12 | read | multi");
            assert_eq!(i.buffer_port, 0, "the Buffer Data Port is never used");
        });
        clean(&m);
    }
}

#[test]
fn one_sector_is_a_single_block_command() {
    let (_g, m) = setup(true);
    let data = pattern(1, 0x42);
    m.with(|i| i.data_cmds.clear());
    mmc::write_on(&*m, SLOT, 5, 1, &data).unwrap();
    let mut back = vec![0u8; 512];
    mmc::read_on(&*m, SLOT, 5, 1, &mut back).unwrap();
    assert_eq!(back, data);
    m.with(|i| {
        let c: Vec<u16> = i.data_cmds.iter().map(|d| d.cmd).collect();
        assert_eq!(c, vec![24, 17]);
        assert_eq!(i.data_cmds[0].trnmod, 0b11, "no multi, no Auto CMD12");
        assert_eq!(i.data_cmds[1].trnmod, 0b1_0011);
        assert_eq!(i.descs.len(), 2);
        assert_eq!(i.descs[0].0, 0x23, "a one-descriptor table is its own End");
    });
    clean(&m);
}

#[test]
fn a_request_longer_than_one_table_is_split_into_commands() {
    let (_g, m) = setup(true);
    let n = 300usize; // 128 + 128 + 44
    let data = pattern(n, 0x77);
    m.with(|i| i.data_cmds.clear());
    mmc::write_on(&*m, SLOT, 1000, n as u32, &data).unwrap();
    m.with(|i| {
        let v: Vec<(u16, u32, u16)> = i.data_cmds.iter().map(|d| (d.cmd, d.arg, d.blkcnt)).collect();
        assert_eq!(v, vec![(25, 1000, 128), (25, 1128, 128), (25, 1256, 44)]);
    });
    let mut back = vec![0u8; n * 512];
    mmc::read_on(&*m, SLOT, 1000, n as u32, &mut back).unwrap();
    assert_eq!(back, data);
    clean(&m);
}

#[test]
fn interrupt_mode_sleeps_instead_of_polling_and_the_handler_wakes_the_waiter() {
    let (_g, m) = setup(true);
    let (b0, w0, t0, s0) = counts();
    // Polled first: no sleep.
    let data = pattern(20, 0x31);
    mmc::write_on(&*m, SLOT, 40, 20, &data).unwrap();
    let (b1, _, t1, s1) = counts();
    assert_eq!((b1, t1, s1), (b0, t0, s0), "a polled request never sleeps and takes no interrupt");

    assert!(mmc::set_irq_mode_on(&*m, SLOT, LINE, &HOOKS));
    m.with(|i| assert_eq!(i.get32(R_SIGNAL), 0x03FF_0003, "the line is armed for completion and errors"));
    m.with(|i| i.status_reads = 0);
    let mut back = vec![0u8; 20 * 512];
    mmc::read_on(&*m, SLOT, 40, 20, &mut back).expect("a read completes only through the interrupt");
    assert_eq!(back, data);
    let (b2, w2, t2, s2) = counts();
    // Command Complete and Transfer Complete: two events, two sleeps.
    assert!(b2 - b1 >= 2, "the waiter slept for each event ({} blocks)", b2 - b1);
    assert!(t2 - t1 >= 2, "the handler ran for each event");
    assert!(s2 - s1 >= 2, "the sleeps are counted");
    assert!(w2 > w0, "the handler woke the sleeper");
    assert_eq!(WOKEN_TID.load(Ordering::SeqCst), TEST_TID, "by TID");
    m.with(|i| assert!(i.status_reads < 16, "{} INT_STATUS reads: that is polling", i.status_reads));
    clean(&m);

    // And back.
    mmc::irq_off_on(&*m, SLOT);
    m.with(|i| assert_eq!(i.get32(R_SIGNAL), 0));
    let (b3, ..) = counts();
    mmc::read_on(&*m, SLOT, 40, 20, &mut back).unwrap();
    assert_eq!(counts().0, b3, "polled again: no sleep");
}

#[test]
fn interrupt_mode_is_taken_for_a_flush_and_for_commands_without_data_too() {
    let (_g, m) = setup(false);
    assert!(mmc::set_irq_mode_on(&*m, SLOT, LINE, &HOOKS));
    let data = pattern(3, 0x09);
    mmc::write_on(&*m, SLOT, 7, 3, &data).unwrap();
    m.with(|i| { i.prg_polls = 0; i.cmds.clear(); });
    let (b0, ..) = counts();
    mmc::flush_on(&*m, SLOT).expect("flush");
    assert!(counts().0 > b0, "CMD13 completed by interrupt");
    m.with(|i| assert_eq!(i.cmds, vec![13]));
    clean(&m);
}

#[test]
fn an_event_raised_while_the_waiter_publishes_itself_is_not_slept_through() {
    let (_g, m) = setup(true);
    assert!(mmc::set_irq_mode_on(&*m, SLOT, LINE, &HOOKS));
    EVENT_IN_THE_WINDOW.store(true, Ordering::SeqCst);
    let (b0, w0, ..) = counts();
    let r = mmc::flush_on(&*m, SLOT);
    EVENT_IN_THE_WINDOW.store(false, Ordering::SeqCst);
    r.expect("flush");
    let (b1, w1, ..) = counts();
    // The handler ran with nobody published (no wake), and the waiter, looking
    // once more after publishing itself, found the event instead of sleeping.
    assert_eq!(w1, w0, "nobody was published when the handler ran");
    assert_eq!(b1, b0, "the waiter slept although its event had already happened");
    clean(&m);
}

#[test]
fn an_adma_error_fails_the_request_resets_the_lines_and_the_next_request_works() {
    let (_g, m) = setup(true);
    let data = pattern(8, 0x55);
    m.with(|i| { i.fault = Fault::Adma; i.line_resets = 0; });
    let r = mmc::write_on(&*m, SLOT, 9, 8, &data);
    assert!(r.is_err());
    m.with(|i| {
        assert!(i.line_resets >= 1, "CMD and DAT lines reset after the error");
        i.violations.clear();
    });
    // A write that failed latches the fault: the flush reports it once.
    assert!(mmc::flush_on(&*m, SLOT).is_err());
    mmc::write_on(&*m, SLOT, 9, 8, &data).expect("the controller is usable again");
    mmc::flush_on(&*m, SLOT).expect("and the flush is clean");
    assert_eq!(m.card_read(9 * 512, 8 * 512), data);
    clean(&m);
}

#[test]
fn a_data_error_fails_a_read_and_a_dead_command_times_out() {
    let (_g, m) = setup(true);
    let mut buf = vec![0u8; 512];
    m.with(|i| i.fault = Fault::DataCrc);
    assert!(mmc::read_on(&*m, SLOT, 3, 1, &mut buf).is_err());
    m.with(|i| i.fault = Fault::CmdTimeout);
    assert!(mmc::read_on(&*m, SLOT, 3, 1, &mut buf).is_err(), "a command timeout error is an error");
    mmc::read_on(&*m, SLOT, 3, 1, &mut buf).expect("recovered");
    clean(&m);
}

#[test]
fn a_command_that_never_completes_gives_up_at_its_deadline() {
    let (_g, m) = setup(true);
    m.with(|i| { i.latency = u32::MAX; i.line_resets = 0; });
    let mut buf = vec![0u8; 512];
    let t = std::time::Instant::now();
    assert!(mmc::read_on(&*m, SLOT, 3, 1, &mut buf).is_err());
    assert!(t.elapsed() < std::time::Duration::from_secs(2), "the command deadline (100 ms), not the transfer's");
    m.with(|i| assert!(i.line_resets >= 1));
}

#[test]
fn a_write_the_card_refuses_is_an_error_and_the_flush_reports_it_once() {
    let (_g, m) = setup(false);
    let data = pattern(1, 0x66);
    // Past the end of the 4 MiB card: ADDRESS_ERROR in the CMD24 response.
    let r = mmc::write_on(&*m, SLOT, (CARD_SECTORS as u64) + 50, 1, &data);
    assert!(r.is_err(), "the card's verdict decides the request");
    assert!(mmc::flush_on(&*m, SLOT).is_err(), "the fault is reported by the next flush");
    assert!(mmc::flush_on(&*m, SLOT).is_ok(), "and only once");
    clean(&m);
}

#[test]
fn flush_polls_the_card_status_until_it_leaves_programming() {
    let (_g, m) = setup(true);
    mmc::write_on(&*m, SLOT, 2, 4, &pattern(4, 0x01)).unwrap();
    m.with(|i| { i.prg_polls = 3; i.cmds.clear(); });
    // Programming starts with the next write.
    mmc::write_on(&*m, SLOT, 2, 4, &pattern(4, 0x02)).unwrap();
    let (reads0, _) = mmc::mmc_flush_evidence();
    m.with(|i| i.cmds.clear());
    mmc::flush_on(&*m, SLOT).expect("flush");
    let (reads1, status) = mmc::mmc_flush_evidence();
    assert_eq!(m.with(|i| i.cmds.clone()), vec![13, 13, 13, 13], "three CMD13 in prg, one in tran");
    assert_eq!(reads1 - reads0, 4);
    assert_eq!((status >> 9) & 0xF, 4, "tran");
    assert_ne!(status & (1 << 8), 0, "ready for data");
    clean(&m);
}

#[test]
fn requests_before_init_are_refused() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // Slot 0 is never initialised by these tests.
    let m = Mock::new(false);
    let mut buf = vec![0u8; 512];
    assert!(mmc::read_on(&m, MmcSlot::Emmc, 0, 1, &mut buf).is_err());
    assert!(mmc::write_on(&m, MmcSlot::Emmc, 0, 1, &buf).is_err());
    assert!(mmc::flush_on(&m, MmcSlot::Emmc).is_err());
    assert_eq!(mmc::mmc_capacity(MmcSlot::Emmc), 0);
}

// ---- Cache maintenance for a controller that is not coherent ----

mod noncoherent {
    use super::*;
    use std::sync::Mutex;

    static CALLS: Mutex<Vec<(&'static str, usize, usize)>> = Mutex::new(Vec::new());

    unsafe fn clean_fn(va: usize, len: usize) { CALLS.lock().unwrap().push(("clean", va, len)); }
    unsafe fn flush_fn(va: usize, len: usize) { CALLS.lock().unwrap().push(("flush", va, len)); }

    #[test]
    fn a_non_coherent_controller_gets_cache_maintenance_around_each_transfer() {
        // The hooks are process-wide: shared with `dwmshc_tests.rs`.
        let _h = crate::dwmshc_tests::CACHE_HOOKS.lock().unwrap_or_else(|e| e.into_inner());
        let (_g, m) = setup(true);
        azos_dma::cache::install(clean_fn, flush_fn);
        azos_dma::registry::declare_mmio(m.base() as u64, m.base() as u64, azos_dma::registry::MmioView::coherent(false)).expect("declare once");
        CALLS.lock().unwrap().clear();

        let data = pattern(16, 0x3C); // two pages
        mmc::write_on(&*m, SLOT, 0, 16, &data).unwrap();
        let w: Vec<_> = CALLS.lock().unwrap().drain(..).collect();
        // Table and two data pages cleaned (written back) before the device reads them.
        assert_eq!(w.iter().filter(|c| c.0 == "clean").count(), 3, "{w:?}");
        assert_eq!(w.iter().filter(|c| c.0 == "flush").count(), 0, "{w:?}");

        let mut back = vec![0u8; 16 * 512];
        mmc::read_on(&*m, SLOT, 0, 16, &mut back).unwrap();
        let r: Vec<_> = CALLS.lock().unwrap().drain(..).collect();
        // Table cleaned, data pages flushed before the device writes them and again after.
        assert_eq!(r.iter().filter(|c| c.0 == "clean").count(), 1, "{r:?}");
        assert_eq!(r.iter().filter(|c| c.0 == "flush").count(), 4, "{r:?}");
        assert_eq!(back, data);
        assert_eq!(r.last().unwrap().0, "flush", "the last thing before the CPU reads is a flush");
    }
}
