// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `i2c_k1.rs` (the SpacemiT K1 I2C master step machine) run on the host over
//! a register-level model of the controller and its slaves.
//!
//! The model is written from `drivers/i2c/busses/i2c-k1.c` (Linux v7.2.9), not
//! from the driver: its own copy of the register offsets and bit positions,
//! and the behaviour that file relies on. A byte starts when `ICR.TB` is
//! written with the unit enabled; the START bit says the byte in `IDBR` is an
//! address, and the model answers like the controller does: `ISR.ITE` once a
//! transmitted byte is out, `ISR.IRF` with a received byte in `IDBR`,
//! `ISR.MSD` once a STOP went out, `ISR.BED` (with `ISR.ACKNAK` level) for a
//! byte nobody acknowledged, `ISR.ALD` on a lost arbitration. Events are
//! cleared by writing ones to `ISR`, so a driver that does not clear them
//! sees them again. It records every byte the driver started, with the
//! START/STOP/ACKNAK bits it was started with, and every `ICR` write, so a
//! test asserts on the sequence on the wire, not only on the result.
//!
//! What it does NOT know, and the board must confirm (listed in the front's
//! report): whether a real slave NACK shows as `BED` with `ACKNAK`, `BED`
//! alone or `ACKNAK` alone; whether `MSD` is raised in polling mode with no
//! interrupt enabled; the exact moment `ITE` rises relative to the ACK.

use super::i2c_k1::*;
use super::i2c_txn::{Completion, I2cBus, SubmitError};
use std::cell::{Cell, RefCell};

// The model's own copy of the reference's offsets and bits (i2c-k1.c:16-89).
const M_ICR: usize = 0x00;
const M_ISR: usize = 0x04;
const M_IDBR: usize = 0x0c;
const M_IRCR: usize = 0x18;
const M_IBMR: usize = 0x1c;

const M_START: u32 = 1 << 0;
const M_STOP: u32 = 1 << 1;
const M_ACKNAK: u32 = 1 << 2;
const M_TB: u32 = 1 << 3;
const M_FAST: u32 = 1 << 8;
const M_UR: u32 = 1 << 10;
const M_RSTREQ: u32 = 1 << 11;
const M_SCLE: u32 = 1 << 13;
const M_IUE: u32 = 1 << 14;
const M_GCD: u32 = 1 << 21;
const M_MSDE: u32 = 1 << 26;

const M_ACKNAK_LVL: u32 = 1 << 14;
const M_UB: u32 = 1 << 15;
const M_IBB: u32 = 1 << 16;
const M_ALD: u32 = 1 << 18;
const M_ITE: u32 = 1 << 19;
const M_IRF: u32 = 1 << 20;
const M_BED: u32 = 1 << 22;
const M_MSD: u32 = 1 << 26;
/// The write-one-to-clear event bits (i2c-k1.c:62-75): ALD, ITE, IRF, GCAD,
/// BED, SAD, SSD, MSD, TXDONE, TXE, RXHF, RXF, RXOV.
const M_EVENTS: u32 = (1 << 18) | (1 << 19) | (1 << 20) | (1 << 21) | (1 << 22) | (1 << 23)
    | (1 << 24) | (1 << 26) | (1 << 27) | (1 << 28) | (1 << 29) | (1 << 30) | (1 << 31);

const M_NOFIX: u32 = 1 << 7;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Nak {
    /// The controller raises BED and shows ACKNAK.
    BedAndAcknak,
    /// BED alone.
    BedOnly,
}

/// A byte the driver started: the `IDBR` value (for a transmit) and the bits
/// of the `ICR` write that started it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Started {
    idbr: u8,
    start: bool,
    stop: bool,
    acknak: bool,
}

struct Slave {
    addr: u8,
    regs: [u8; 256],
    ptr: usize,
    /// Write phase: the first byte is the pointer.
    got_ptr: bool,
    /// Refuse the Nth write byte of a transaction (0 is the pointer byte).
    nak_write: Option<usize>,
    wr_count: usize,
    /// Every byte this slave accepted, in order.
    received: Vec<u8>,
}

impl Slave {
    fn new(addr: u8) -> Slave {
        let mut regs = [0u8; 256];
        for (i, r) in regs.iter_mut().enumerate() {
            *r = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        Slave { addr, regs, ptr: 0, got_ptr: false, nak_write: None, wr_count: 0, received: vec![] }
    }
}

struct Model {
    slaves: RefCell<Vec<Slave>>,
    nak_mode: Cell<Nak>,
    // The registers.
    icr: Cell<u32>,
    isr: Cell<u32>,
    idbr: Cell<u32>,
    ircr: Cell<u32>,
    // The wire.
    bus_busy: Cell<bool>,
    cur: Cell<Option<usize>>,
    reading: Cell<bool>,
    nak_level: Cell<bool>,
    // Knobs.
    /// `UB`/`IBB` read set for this many more reads of `ISR`.
    busy_reads: Cell<u32>,
    busy_forever: Cell<bool>,
    /// No event ever rises (a slave that holds SCL, a gated clock).
    deaf: Cell<bool>,
    /// Refuse the address byte of a READ (the write part was acknowledged).
    nak_read_addr: Cell<bool>,
    /// Lose the arbitration when the Nth byte (0-based, per run) is started.
    ald_at: Cell<Option<usize>>,
    /// `MSD` rises this many reads of `ISR` after the STOP byte.
    msd_delay: Cell<u32>,
    msd_pending: Cell<Option<u32>>,
    /// A byte's event rises this many reads of `ISR` after `TB` (the byte
    /// takes wire time).
    latency: Cell<u32>,
    /// Events not risen yet, and the reads left before they do.
    pending: Cell<(u32, u32)>,
    /// `TB` written while the previous byte's event had not risen: the driver
    /// started a byte on a busy shifter.
    collisions: Cell<u32>,
    /// `MSD` rises on the first read after the STOP byte, ahead of the data
    /// event of that byte.
    msd_first: Cell<bool>,
    /// SDA reads low until this many `RSTREQ` clocks went out.
    sda_low_clocks: Cell<u32>,
    // Observations.
    bytes: RefCell<Vec<Started>>,
    icr_writes: RefCell<Vec<u32>>,
    isr_clears: RefCell<Vec<u32>>,
    ircr_writes: RefCell<Vec<u32>>,
    resets: Cell<u32>,
    rstreq: Cell<u32>,
    accesses: Cell<u32>,
    /// A read's last byte was started without ACKNAK (a protocol error).
    acked_last: Cell<bool>,
}

impl Model {
    fn new() -> Model {
        Model {
            slaves: RefCell::new(vec![]),
            nak_mode: Cell::new(Nak::BedAndAcknak),
            icr: Cell::new(0),
            isr: Cell::new(0),
            idbr: Cell::new(0),
            ircr: Cell::new(0),
            bus_busy: Cell::new(false),
            cur: Cell::new(None),
            reading: Cell::new(false),
            nak_level: Cell::new(false),
            busy_reads: Cell::new(0),
            busy_forever: Cell::new(false),
            deaf: Cell::new(false),
            nak_read_addr: Cell::new(false),
            ald_at: Cell::new(None),
            msd_delay: Cell::new(0),
            msd_pending: Cell::new(None),
            latency: Cell::new(2),
            pending: Cell::new((0, 0)),
            collisions: Cell::new(0),
            msd_first: Cell::new(false),
            sda_low_clocks: Cell::new(0),
            bytes: RefCell::new(vec![]),
            icr_writes: RefCell::new(vec![]),
            isr_clears: RefCell::new(vec![]),
            ircr_writes: RefCell::new(vec![]),
            resets: Cell::new(0),
            rstreq: Cell::new(0),
            accesses: Cell::new(0),
            acked_last: Cell::new(false),
        }
    }

    fn with_slave(addr: u8) -> Model {
        let m = Model::new();
        m.slaves.borrow_mut().push(Slave::new(addr));
        m
    }

    /// Schedule event bits: they rise `latency` reads of `ISR` from now.
    fn raise(&self, bits: u32) {
        let (b, d) = self.pending.get();
        self.pending.set((b | bits, if b == 0 { self.latency.get() } else { d }));
    }

    fn nak(&self) {
        self.nak_level.set(true);
        self.raise(M_BED);
        self.bus_busy.set(false);
    }

    fn raise_stop(&self) {
        self.bus_busy.set(false);
        let d = self.msd_delay.get();
        if self.msd_first.get() {
            self.isr.set(self.isr.get() | M_MSD);
        } else if d == 0 {
            self.raise(M_MSD);
        } else {
            self.msd_pending.set(Some(d));
        }
    }

    /// The controller's reaction to `ICR.TB` with the unit enabled.
    fn byte(&self, icr: u32) {
        if self.deaf.get() {
            return;
        }
        if self.pending.get().0 != 0 {
            self.collisions.set(self.collisions.get() + 1);
        }
        let n = self.bytes.borrow().len();
        self.bytes.borrow_mut().push(Started {
            idbr: self.idbr.get() as u8,
            start: icr & M_START != 0,
            stop: icr & M_STOP != 0,
            acknak: icr & M_ACKNAK != 0,
        });
        if self.ald_at.get() == Some(n) {
            self.raise(M_ALD);
            self.bus_busy.set(false);
            return;
        }
        let stop = icr & M_STOP != 0;
        if icr & M_START != 0 {
            let a = (self.idbr.get() >> 1) as u8;
            self.reading.set(self.idbr.get() & 1 != 0);
            self.nak_level.set(false);
            let found = self.slaves.borrow().iter().position(|s| s.addr == a);
            let found = if self.reading.get() && self.nak_read_addr.get() { None } else { found };
            match found {
                None => {
                    self.cur.set(None);
                    self.nak();
                }
                Some(i) => {
                    self.cur.set(Some(i));
                    self.bus_busy.set(true);
                    let mut sl = self.slaves.borrow_mut();
                    if !self.reading.get() {
                        sl[i].got_ptr = false;
                        sl[i].wr_count = 0;
                    }
                    self.raise(M_ITE);
                }
            }
            return;
        }
        let Some(i) = self.cur.get() else { return };
        let mut sl = self.slaves.borrow_mut();
        if self.reading.get() {
            let p = sl[i].ptr;
            self.idbr.set(sl[i].regs[p % 256] as u32);
            sl[i].ptr = p + 1;
            self.raise(M_IRF);
            if stop {
                // A read ends with the master's NAK on its last byte.
                if icr & M_ACKNAK == 0 {
                    self.acked_last.set(true);
                }
                self.nak_level.set(true);
                drop(sl);
                self.raise_stop();
            }
        } else {
            let b = self.idbr.get() as u8;
            let k = sl[i].wr_count;
            sl[i].wr_count += 1;
            if sl[i].nak_write == Some(k) {
                drop(sl);
                self.nak();
                return;
            }
            sl[i].received.push(b);
            if !sl[i].got_ptr {
                sl[i].ptr = b as usize;
                sl[i].got_ptr = true;
            } else {
                let p = sl[i].ptr;
                sl[i].regs[p % 256] = b;
                sl[i].ptr = p + 1;
            }
            self.raise(M_ITE);
            if stop {
                drop(sl);
                self.raise_stop();
            }
        }
    }
}

impl K1Regs for Model {
    fn rd(&self, off: usize) -> u32 {
        self.accesses.set(self.accesses.get() + 1);
        match off {
            M_ICR => self.icr.get(),
            M_ISR => {
                let (bits, left) = self.pending.get();
                if bits != 0 {
                    if left == 0 {
                        self.isr.set(self.isr.get() | bits);
                        self.pending.set((0, 0));
                    } else {
                        self.pending.set((bits, left - 1));
                    }
                }
                if let Some(d) = self.msd_pending.get() {
                    if d == 0 {
                        self.isr.set(self.isr.get() | M_MSD);
                        self.msd_pending.set(None);
                    } else {
                        self.msd_pending.set(Some(d - 1));
                    }
                }
                let mut v = self.isr.get();
                if self.busy_forever.get() || self.bus_busy.get() {
                    v |= M_UB | M_IBB;
                } else if self.busy_reads.get() > 0 {
                    self.busy_reads.set(self.busy_reads.get() - 1);
                    v |= M_UB | M_IBB;
                }
                if self.nak_level.get() {
                    v |= M_ACKNAK_LVL;
                }
                // BED-only mode: the level bit stays clear.
                if self.nak_mode.get() == Nak::BedOnly {
                    v &= !M_ACKNAK_LVL;
                }
                v
            }
            M_IDBR => self.idbr.get(),
            M_IRCR => self.ircr.get(),
            M_IBMR => 0b10 | if self.sda_low_clocks.get() == 0 { 0b01 } else { 0 },
            _ => 0,
        }
    }

    fn wr(&self, off: usize, val: u32) {
        self.accesses.set(self.accesses.get() + 1);
        match off {
            M_ICR => {
                self.icr_writes.borrow_mut().push(val);
                self.icr.set(val & !(M_START | M_STOP | M_ACKNAK | M_TB));
                if val & M_UR != 0 {
                    self.resets.set(self.resets.get() + 1);
                    self.isr.set(0);
                    self.bus_busy.set(false);
                    self.cur.set(None);
                    self.msd_pending.set(None);
                    self.pending.set((0, 0));
                    return;
                }
                if val & M_RSTREQ != 0 {
                    self.rstreq.set(self.rstreq.get() + 1);
                    assert_eq!(self.ircr.get() & 0xF, 1, "a bus-reset request clocks one cycle (IRCR.RST_CYC = 1)");
                    self.sda_low_clocks.set(self.sda_low_clocks.get().saturating_sub(1));
                }
                if val & M_IUE != 0 && val & M_TB != 0 {
                    self.byte(val);
                }
            }
            M_ISR => {
                self.isr_clears.borrow_mut().push(val);
                self.isr.set(self.isr.get() & !(val & M_EVENTS));
            }
            M_IDBR => self.idbr.set(val),
            M_IRCR => {
                self.ircr_writes.borrow_mut().push(val);
                self.ircr.set(val);
            }
            _ => {}
        }
    }
}

const TIMEOUT: u64 = 2_000;
const D: usize = 4;

fn bus() -> I2cBus<D> {
    I2cBus::new(8)
}

/// Step until `ticket` has a completion; the clock advances one per step.
fn run(master: &mut K1Master, q: &mut I2cBus<D>, m: &Model, ticket: u32) -> Completion {
    for now in 0..TIMEOUT * 4 {
        master.service(q, m, now, TIMEOUT);
        if let Some(c) = q.take(ticket) {
            assert_eq!(m.collisions.get(), 0, "the driver started a byte while the previous one was on the wire");
            return c;
        }
    }
    panic!("transaction {ticket} never finished");
}

/// Step `n` times from `from`.
fn steps(master: &mut K1Master, q: &mut I2cBus<D>, m: &Model, from: u64, n: u64) {
    for now in from..from + n {
        master.service(q, m, now, TIMEOUT);
    }
}

fn st(idbr: u8, start: bool, stop: bool, acknak: bool) -> Started {
    Started { idbr, start, stop, acknak }
}

const PMIC: u8 = 0x41;

#[test]
fn unit_is_configured_while_disabled_then_enabled() {
    for fast in [true, false] {
        let m = Model::with_slave(PMIC);
        let mut q = bus();
        let mut master = K1Master::new(fast, 0);
        let t = q.submit(PMIC, &[0x10, 0xAB], 0).unwrap();
        let c = run(&mut master, &mut q, &m, t);
        assert!(c.ok);
        let icr = m.icr_writes.borrow();
        let cfg = M_GCD | M_SCLE | M_MSDE | if fast { M_FAST } else { 0 };
        assert_eq!(icr[0], cfg, "configured with the unit still disabled: GCD, SCLE, MSDE and the speed bit");
        assert_eq!(icr[0] & M_IUE, 0);
        assert_eq!(m.ircr_writes.borrow()[0] & M_NOFIX, M_NOFIX, "the SDA glitch fix is bypassed");
        assert_eq!(*m.isr_clears.borrow().first().unwrap() & M_EVENTS, M_EVENTS, "stale events cleared before the unit is enabled");
        assert_eq!(icr[1], cfg | M_IUE, "then the unit is enabled");
        assert_eq!(*icr.last().unwrap() & M_IUE, 0, "and disabled again at the end");
    }
}

#[test]
fn write_sends_stop_with_the_last_byte_only() {
    let m = Model::with_slave(PMIC);
    let mut q = bus();
    let mut master = K1Master::new(true, 0);
    let t = q.submit(PMIC, &[0x10, 0xAB, 0xCD], 0).unwrap();
    let c = run(&mut master, &mut q, &m, t);
    assert!(c.ok);
    assert_eq!(
        *m.bytes.borrow(),
        vec![
            st(PMIC << 1, true, false, false),
            st(0x10, false, false, false),
            st(0xAB, false, false, false),
            st(0xCD, false, true, false),
        ]
    );
    let s = m.slaves.borrow();
    assert_eq!(s[0].received, vec![0x10, 0xAB, 0xCD]);
    assert_eq!((s[0].regs[0x10], s[0].regs[0x11]), (0xAB, 0xCD));
    assert!(master.is_idle() && q.is_idle());
    assert_eq!((q.aborts, q.timeouts, q.completed), (0, 0, 1));
}

#[test]
fn register_read_is_a_repeated_start_with_nak_and_stop_on_the_last_byte() {
    let m = Model::with_slave(0x68);
    let mut q = bus();
    let mut master = K1Master::new(true, 0);
    let t = q.submit(0x68, &[0x3B], 14).unwrap();
    let c = run(&mut master, &mut q, &m, t);
    assert!(c.ok);
    let b = m.bytes.borrow();
    assert_eq!(b.len(), 1 + 1 + 1 + 14, "address, register, address again, 14 reads");
    assert_eq!(b[0], st(0x68 << 1, true, false, false));
    assert_eq!(b[1], st(0x3B, false, false, false), "no STOP between the write and the read part");
    assert_eq!(b[2], st(0x68 << 1 | 1, true, false, false), "repeated START, read direction");
    for (i, x) in b[3..16].iter().enumerate() {
        assert!(!x.start && !x.stop && !x.acknak, "read byte {i} is a plain receive");
    }
    assert!(b[16].stop && b[16].acknak && !b[16].start, "the last byte is started with STOP and the master's NAK");
    assert!(!m.acked_last.get());
    let s = m.slaves.borrow();
    let want: Vec<u8> = (0..14).map(|i| s[0].regs[0x3B + i]).collect();
    assert_eq!(&c.rd[..14], &want[..]);
    assert_eq!(c.rd_len, 14);
}

#[test]
fn read_only_transaction_starts_in_read_direction() {
    let m = Model::with_slave(0x50);
    let mut q = bus();
    let mut master = K1Master::new(false, 0);
    let t = q.submit(0x50, &[], 3).unwrap();
    let c = run(&mut master, &mut q, &m, t);
    assert!(c.ok);
    let b = m.bytes.borrow();
    assert_eq!(b[0], st(0x50 << 1 | 1, true, false, false));
    assert_eq!(b.len(), 4);
    assert!(b[3].stop && b[3].acknak);
    assert_eq!(&c.rd[..3], &[3, 10, 17]);
}

#[test]
fn single_byte_read_carries_stop_and_nak_at_once() {
    let m = Model::with_slave(0x68);
    let mut q = bus();
    let mut master = K1Master::new(true, 0);
    let t = q.submit(0x68, &[0x75], 1).unwrap();
    let c = run(&mut master, &mut q, &m, t);
    assert!(c.ok);
    let b = m.bytes.borrow();
    assert_eq!(b.len(), 4);
    assert!(b[3].stop && b[3].acknak);
}

#[test]
fn caller_buffers_are_used_without_copy() {
    let m = Model::with_slave(0x68);
    let mut q = bus();
    let mut master = K1Master::new(true, 0);
    let wr = [0x20u8];
    let mut rd = [0u8; 70];
    // SAFETY: both buffers outlive `run`, which returns with the completion.
    let t = unsafe { q.submit_ext(0x68, wr.as_ptr(), 1, rd.as_mut_ptr(), rd.len()) }.unwrap();
    let c = run(&mut master, &mut q, &m, t);
    assert!(c.ok);
    let s = m.slaves.borrow();
    for i in 0..70 {
        assert_eq!(rd[i], s[0].regs[0x20 + i], "byte {i}");
    }
    assert_eq!(c.rd_len, 0, "an ext transaction wrote into the caller's buffer");
    assert_eq!(q.submit(0x68, &[], 0), Err(SubmitError::BadLength));
}

#[test]
fn nack_on_the_address_fails_resets_the_unit_and_the_next_transaction_runs() {
    for mode in [Nak::BedAndAcknak, Nak::BedOnly] {
        let m = Model::with_slave(PMIC);
        m.nak_mode.set(mode);
        let mut q = bus();
        let mut master = K1Master::new(true, 0);
        let gone = q.submit(0x33, &[0x00], 0).unwrap();
        let good = q.submit(PMIC, &[0x10, 0x55], 0).unwrap();
        let c = run(&mut master, &mut q, &m, gone);
        assert!(!c.ok, "{mode:?}");
        assert_eq!(q.aborts, 1);
        assert_eq!(master.nacks, if mode == Nak::BedAndAcknak { 1 } else { 0 });
        assert_eq!(master.nacks + master.bus_errors, 1);
        assert_eq!(master.arb_lost, 0);
        assert_eq!(*m.icr_writes.borrow().last().unwrap(), M_UR, "the unit is reset, UR held until the next step");
        assert_eq!(m.resets.get(), 1);
        // The queued transaction must not start while UR is held.
        let n = m.icr_writes.borrow().len();
        steps(&mut master, &mut q, &m, 10, 1);
        assert_eq!(m.icr_writes.borrow()[n], 0, "UR released one step later");
        let c = run(&mut master, &mut q, &m, good);
        assert!(c.ok, "{mode:?}");
        assert_eq!(m.slaves.borrow()[0].regs[0x10], 0x55);
        assert_eq!(m.rstreq.get(), 0, "a NACK does not clock the bus");
    }
}

#[test]
fn nack_on_a_data_byte_fails() {
    let m = Model::with_slave(PMIC);
    m.slaves.borrow_mut()[0].nak_write = Some(1);
    let mut q = bus();
    let mut master = K1Master::new(true, 0);
    let t = q.submit(PMIC, &[0x10, 0xAA, 0xBB], 0).unwrap();
    let c = run(&mut master, &mut q, &m, t);
    assert!(!c.ok);
    assert_eq!(q.aborts, 1);
    assert_eq!(m.bytes.borrow().len(), 3, "address, register, the refused byte; nothing after");
    assert_ne!(m.slaves.borrow()[0].regs[0x10], 0xAA);
    assert_eq!(*m.icr_writes.borrow().last().unwrap() & M_UR, M_UR);
}

#[test]
fn nack_on_the_last_byte_fails_as_an_abort_and_not_a_timeout() {
    // The byte started with STOP is refused: BED rises instead of MSD.
    let m = Model::with_slave(PMIC);
    m.slaves.borrow_mut()[0].nak_write = Some(2);
    let mut q = bus();
    let mut master = K1Master::new(true, 0);
    let t = q.submit(PMIC, &[0x10, 0xAA, 0xBB], 0).unwrap();
    let c = run(&mut master, &mut q, &m, t);
    assert!(!c.ok);
    assert_eq!((q.aborts, q.timeouts), (1, 0));
    assert_eq!(m.rstreq.get(), 0);
}

#[test]
fn nack_on_the_restart_address_fails_a_read() {
    // The slave takes the register byte, then refuses its read address.
    let m = Model::with_slave(0x68);
    m.nak_read_addr.set(true);
    let mut q = bus();
    let mut master = K1Master::new(true, 0);
    let t = q.submit(0x68, &[0x00], 2).unwrap();
    let c = run(&mut master, &mut q, &m, t);
    assert!(!c.ok);
    assert_eq!(m.bytes.borrow().len(), 3, "address, register, the refused read address");
    assert_eq!(q.aborts, 1);
    assert_eq!(c.rd_len, 0, "no byte was read");
}

#[test]
fn arbitration_loss_resets_and_does_not_clock_the_bus() {
    let m = Model::with_slave(0x68);
    m.ald_at.set(Some(2));
    m.sda_low_clocks.set(5); // the other master holds SDA low: clocking it would be wrong
    let mut q = bus();
    let mut master = K1Master::new(true, 0);
    let t = q.submit(0x68, &[0x3B], 4).unwrap();
    let c = run(&mut master, &mut q, &m, t);
    assert!(!c.ok);
    assert_eq!(master.arb_lost, 1);
    assert_eq!((master.nacks, master.bus_errors), (0, 0));
    assert_eq!(q.aborts, 1);
    assert_eq!(*m.icr_writes.borrow().last().unwrap(), M_UR);
    steps(&mut master, &mut q, &m, 10, 5);
    assert_eq!(m.rstreq.get(), 0, "another master owns the bus: no recovery clocks");
    assert!(master.is_idle());
}

#[test]
fn a_dead_controller_times_out_and_the_bus_is_clocked_free() {
    let m = Model::with_slave(0x68);
    m.deaf.set(true);
    m.sda_low_clocks.set(3);
    let mut q = bus();
    let mut master = K1Master::new(true, 0);
    let t = q.submit(0x68, &[0x3B], 2).unwrap();
    let c = run(&mut master, &mut q, &m, t);
    assert!(!c.ok);
    assert_eq!(q.timeouts, 1);
    assert_eq!(q.aborts, 0, "a timeout is not an abort");
    assert!(!master.is_idle(), "recovery is under way");
    steps(&mut master, &mut q, &m, TIMEOUT * 5, 20);
    assert_eq!(m.rstreq.get(), 3, "one request per step until SDA is released");
    assert!(master.is_idle());
    assert_eq!(master.stuck, 0);
    assert_eq!(*m.icr_writes.borrow().last().unwrap(), M_RSTREQ);
}

#[test]
fn a_bus_that_stays_low_is_given_up_after_nine_clocks() {
    let m = Model::with_slave(0x68);
    m.deaf.set(true);
    m.sda_low_clocks.set(1000);
    let mut q = bus();
    let mut master = K1Master::new(true, 0);
    let t = q.submit(0x68, &[0x3B], 2).unwrap();
    run(&mut master, &mut q, &m, t);
    steps(&mut master, &mut q, &m, TIMEOUT * 5, 40);
    assert_eq!(m.rstreq.get(), 9);
    assert_eq!(master.stuck, 1);
    assert!(master.is_idle(), "it does not clock forever");
}

#[test]
fn a_busy_bus_delays_the_start_until_it_is_idle() {
    let m = Model::with_slave(PMIC);
    m.busy_reads.set(6);
    let mut q = bus();
    let mut master = K1Master::new(true, 0);
    let t = q.submit(PMIC, &[0x10, 0x01], 0).unwrap();
    for now in 0..3 {
        master.service(&mut q, &m, now, TIMEOUT);
    }
    assert!(m.bytes.borrow().is_empty(), "no START while UB or IBB is set");
    let c = run(&mut master, &mut q, &m, t);
    assert!(c.ok);
    assert_eq!(m.slaves.borrow()[0].regs[0x10], 0x01);
}

#[test]
fn a_bus_busy_for_good_times_out_without_a_start() {
    let m = Model::with_slave(PMIC);
    m.busy_forever.set(true);
    let mut q = bus();
    let mut master = K1Master::new(true, 0);
    let t = q.submit(PMIC, &[0x10, 0x01], 0).unwrap();
    let c = run(&mut master, &mut q, &m, t);
    assert!(!c.ok);
    assert!(m.bytes.borrow().is_empty());
    assert_eq!(q.timeouts, 1);
}

#[test]
fn a_late_master_stop_still_completes_and_an_early_one_is_not_lost() {
    // `first`: MSD rises before the last byte's own event, so the step that
    // sees it is not the one that enters the Stop phase (it must be remembered).
    for (delay, first) in [(0, false), (1, false), (7, false), (0, true)] {
        for (wr, rd) in [(&[0x3Bu8][..], 3usize), (&[0x10, 0x01][..], 0)] {
            let m = Model::with_slave(0x68);
            m.msd_delay.set(delay);
            m.msd_first.set(first);
            let mut q = bus();
            let mut master = K1Master::new(true, 0);
            let t = q.submit(0x68, wr, rd).unwrap();
            let c = run(&mut master, &mut q, &m, t);
            assert!(c.ok, "MSD after {delay} reads (ahead of the data: {first}), read part {rd}");
            assert_eq!(q.timeouts, 0);
        }
    }
}

#[test]
fn a_step_does_a_bounded_amount_of_register_work() {
    let m = Model::with_slave(0x68);
    let mut q = bus();
    let mut master = K1Master::new(true, 0);
    let t = q.submit(0x68, &[0x3B], 14).unwrap();
    let mut worst = 0;
    for now in 0..TIMEOUT {
        let before = m.accesses.get();
        master.service(&mut q, &m, now, TIMEOUT);
        worst = worst.max(m.accesses.get() - before);
        if q.take(t).is_some() {
            break;
        }
    }
    assert!(q.take(t).unwrap().ok);
    assert!(worst <= 8, "a step touched {worst} registers: it must stay one byte's work");
}

#[test]
fn queued_transactions_run_in_order_and_complete_by_ticket() {
    let m = Model::with_slave(0x68);
    let mut q = bus();
    let mut master = K1Master::new(true, 0);
    let a = q.submit(0x68, &[0x00], 2).unwrap();
    let b = q.submit(0x68, &[0x10], 2).unwrap();
    let c = q.submit(0x68, &[0x20, 0x77], 0).unwrap();
    run(&mut master, &mut q, &m, c);
    assert!(q.take(a).unwrap().ok && q.take(b).unwrap().ok && q.take(c).unwrap().ok);
    let (ra, rb) = (q.take(a).unwrap().rd, q.take(b).unwrap().rd);
    let s = m.slaves.borrow();
    assert_eq!(&ra[..2], &[s[0].regs[0], s[0].regs[1]]);
    assert_eq!(&rb[..2], &[s[0].regs[0x10], s[0].regs[0x11]]);
    assert_eq!(s[0].regs[0x20], 0x77);
    assert_eq!(q.completed, 3);
}

#[test]
fn bring_up_reset_is_released_by_the_first_step() {
    let m = Model::with_slave(PMIC);
    let mut q = bus();
    let mut master = K1Master::new(true, 0);
    master.reset_unit(&m, 0);
    assert_eq!(*m.icr_writes.borrow(), vec![M_UR]);
    assert!(!master.is_idle());
    master.service(&mut q, &m, 0, TIMEOUT);
    assert_eq!(*m.icr_writes.borrow(), vec![M_UR, 0]);
    assert!(master.is_idle());
    assert_eq!(m.rstreq.get(), 0);
}

#[test]
fn the_unit_reset_is_held_for_the_configured_ticks_even_when_stepped_back_to_back() {
    // A caller that may not sleep steps again at once: the hold is the clock's.
    let hold = 5;
    for failing in [false, true] {
        let m = Model::with_slave(PMIC);
        let mut q = bus();
        let mut master = K1Master::new(true, hold);
        let at;
        if failing {
            q.submit(0x33, &[0x00], 0).unwrap();
            let mut now = 0;
            loop {
                if master.service(&mut q, &m, now, TIMEOUT).is_some() { break; }
                now += 1;
            }
            at = now;
        } else {
            master.reset_unit(&m, 100);
            at = 100;
        }
        assert_eq!(*m.icr_writes.borrow().last().unwrap(), M_UR);
        for now in at..at + hold {
            master.service(&mut q, &m, now, TIMEOUT);
            assert_eq!(*m.icr_writes.borrow().last().unwrap(), M_UR, "still held at +{}", now - at);
        }
        master.service(&mut q, &m, at + hold, TIMEOUT);
        assert_eq!(*m.icr_writes.borrow().last().unwrap(), 0, "released after {hold} ticks");
        assert!(master.is_idle());
    }
}
