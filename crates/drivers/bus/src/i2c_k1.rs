// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The SpacemiT K1 I2C master (`spacemit,k1-i2c`) as a step machine over the
//! bus's transaction queue (`crate::i2c_txn::I2cBus`).
//!
//! The register map, the bit meanings and the order of the transfer come from
//! the mainline driver, `drivers/i2c/busses/i2c-k1.c` of Linux v7.2.9 (read
//! for facts; nothing copied). Its line numbers are cited as `i2c-k1.c:NNN`
//! where a register or a bit is named.
//!
//! # What this controller is
//!
//! A PXA-family byte engine, not the DesignWare FIFO engine of
//! `crate::i2c_txn`: the CPU moves ONE byte at a time through `IDBR`. A byte
//! is started by setting `ICR.TB` (with `START`, `STOP` and `ACKNAK` where the
//! bus protocol wants them) and the controller raises `ISR.ITE` (a byte went
//! out, `IDBR` is free) or `ISR.IRF` (a byte came in) when it is done. Between
//! bytes the controller holds SCL low until the next `TB`, so a late step
//! slows the wire; it never corrupts it. Mainline uses no FIFO mode and no
//! `ILCR` load count: the SCL rate follows the TWSI functional clock and
//! `ICR.MODE_FAST` (`i2c-k1.c:28`, `:289-290`).
//!
//! # The step
//!
//! [`K1Master::service`] is one bounded step: it reads `ISR` once, clears the
//! events it saw (write-one-to-clear, as `i2c-k1.c:253`), and does at most
//! one byte's work. No wait on the wire and no delay inside it, so it runs
//! under the bus lock exactly like the DesignWare step, from the `i2c-svc`
//! task or, once the controller's line is wired, from its interrupt (the
//! interrupt-enable bits stay clear: this is mainline's PIO mode,
//! `i2c-k1.c:262-286`, `:492-547`). A transaction is the queue's [`BusTxn`]: a write part
//! (register address, bytes) and then a read part after a REPEATED start:
//!
//! ```text
//! WaitIdle -> Addr(write) -> Write ... Write -> Addr(read) -> Read ... Read -> Stop
//!             START+TB       IDBR+TB            START+TB      TB   ... TB+STOP+ACKNAK
//! ```
//!
//! # Failure and recovery
//!
//! `ISR.BED` (a bus error: also how a NACK shows), `RXOV` and `ALD`
//! (arbitration lost) end the transaction failed (`i2c-k1.c:97`, `:163-178`,
//! `:439-441`); a NACK is `BED` with `ACKNAK` set (`:177`). The unit is then
//! reset: `ICR.UR`, held for `ur_hold` clock ticks and released by the first
//! step after that (mainline spins 5 us between the two writes,
//! `i2c-k1.c:156-161`; here the hold is measured against the step's clock, so a
//! caller that steps back to back without sleeping still holds it, and nothing
//! spins). A timeout, and a bus still busy at the start, also run the
//! bus-recovery clocks of
//! `i2c-k1.c:188-218`, one per step: `IRCR.RST_CYC = 1` and `ICR.RSTREQ` until
//! SDA is released, nine times at most.
//!
//! ISA-neutral and free of MMIO: the registers come through [`K1Regs`], so
//! `tests/host/drivers-tests` runs this file against a modelled controller.
//! Board validation (SpacemiT K1) is pending.

use crate::i2c_txn::{BusTxn, I2cBus, TXN_RD_MAX};

/// The controller's registers, by byte offset. The kernel's implementation
/// is MMIO; the host tests' is a model.
pub trait K1Regs {
    fn rd(&self, off: usize) -> u32;
    fn wr(&self, off: usize, val: u32);
}

// Registers (i2c-k1.c:16-20).
pub const ICR: usize = 0x00;
pub const ISR: usize = 0x04;
pub const IDBR: usize = 0x0c;
pub const IRCR: usize = 0x18;
pub const IBMR: usize = 0x1c;

// ICR bits (i2c-k1.c:22-43).
pub const CR_START: u32 = 1 << 0;
pub const CR_STOP: u32 = 1 << 1;
pub const CR_ACKNAK: u32 = 1 << 2;
pub const CR_TB: u32 = 1 << 3;
pub const CR_MODE_FAST: u32 = 1 << 8;
pub const CR_UR: u32 = 1 << 10;
pub const CR_RSTREQ: u32 = 1 << 11;
pub const CR_SCLE: u32 = 1 << 13;
pub const CR_IUE: u32 = 1 << 14;
pub const CR_GCD: u32 = 1 << 21;
pub const CR_MSDE: u32 = 1 << 26;

// ISR bits (i2c-k1.c:57-75). `ACKNAK`, `UB`, `IBB` and `EBB` are levels; the
// others are events cleared by writing a one (`:254-257`).
pub const SR_ACKNAK: u32 = 1 << 14;
pub const SR_UB: u32 = 1 << 15;
pub const SR_IBB: u32 = 1 << 16;
pub const SR_ALD: u32 = 1 << 18;
pub const SR_ITE: u32 = 1 << 19;
pub const SR_IRF: u32 = 1 << 20;
pub const SR_GCAD: u32 = 1 << 21;
pub const SR_BED: u32 = 1 << 22;
pub const SR_SAD: u32 = 1 << 23;
pub const SR_SSD: u32 = 1 << 24;
pub const SR_MSD: u32 = 1 << 26;
pub const SR_TXDONE: u32 = 1 << 27;
pub const SR_TXE: u32 = 1 << 28;
pub const SR_RXHF: u32 = 1 << 29;
pub const SR_RXF: u32 = 1 << 30;
pub const SR_RXOV: u32 = 1 << 31;

/// The ISR bits a write of ones clears (`SPACEMIT_I2C_INT_STATUS_MASK`, i2c-k1.c:77-81).
pub const SR_EVENTS: u32 = SR_RXOV | SR_RXF | SR_RXHF | SR_TXE | SR_TXDONE | SR_MSD | SR_SSD
    | SR_SAD | SR_BED | SR_GCAD | SR_IRF | SR_ITE | SR_ALD;

/// A transaction fails on any of these (`SPACEMIT_SR_ERR`, i2c-k1.c:107).
pub const SR_ERR: u32 = SR_BED | SR_RXOV | SR_ALD;

// IRCR (i2c-k1.c:83-85).
/// Bypass the SDA glitch fix: it delays the repeated start.
pub const RCR_SDA_GLITCH_NOFIX: u32 = 1 << 7;
/// The cycles of SCL one bus-reset request clocks (bits 3:0).
pub const RCR_RST_CYC_MASK: u32 = 0xF;

// IBMR (i2c-k1.c:87-89).
pub const BMR_SDA: u32 = 1 << 0;
pub const BMR_SCL: u32 = 1 << 1;

/// Recovery clocks tried before the bus is given up as stuck
/// (`SPACEMIT_BUS_RESET_CLK_CNT_MAX`, i2c-k1.c:99).
pub const RESET_CLOCKS_MAX: u8 = 9;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    /// Unit enabled; waiting for `ISR.UB` and `ISR.IBB` to clear.
    WaitIdle,
    /// START and the address byte are on the wire (`read`: the part's
    /// direction); waiting for `ITE`.
    Addr { read: bool },
    /// Write bytes: each `ITE` frees `IDBR` for the next.
    Write,
    /// Read bytes: each `IRF` has one in `IDBR`.
    Read,
    /// The last byte and STOP are issued; waiting for `MSD`.
    Stop,
}

/// The transaction on the wire.
struct Active {
    txn: BusTxn,
    phase: Phase,
    /// Write bytes put in `IDBR`.
    sent: usize,
    /// Read bytes collected from `IDBR`.
    got: usize,
    /// `MSD` seen (it can arrive in the same read of `ISR` as the last
    /// byte's `ITE`/`IRF`, which clears it before `Stop` looks).
    msd: bool,
    rx: [u8; TXN_RD_MAX],
    started: u64,
}

/// What the unit is doing after a failure, one register write per step.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Recover {
    /// `UR` was set at `at`; the first step `ur_hold` ticks later clears it.
    /// `clock`: then free a stuck SDA.
    Release { clock: bool, at: u64 },
    /// Clock the bus with `RSTREQ` until SDA is released; `cycles` tried.
    Clock { cycles: u8 },
}

/// One bus's controller engine. The queue and the completions are the bus's
/// [`I2cBus`], passed to every step.
pub struct K1Master {
    /// `ICR` with the unit enabled: what every byte's `ICR` write starts from.
    icr_on: u32,
    /// Clock ticks `ICR.UR` is held before it is released (mainline: 5 us).
    ur_hold: u64,
    active: Option<Active>,
    recover: Option<Recover>,
    /// Transactions a slave refused (`BED` with `ACKNAK`).
    pub nacks: u32,
    /// Transactions that lost the arbitration (`ALD`).
    pub arb_lost: u32,
    /// Transactions ended by a bus error that was no NACK, or an overrun.
    pub bus_errors: u32,
    /// Recoveries that ended with SDA still held low.
    pub stuck: u32,
}

impl K1Master {
    /// `fast`: the 400 kHz mode (Kconfig `I2C_K1_FAST_MODE`), else 100 kHz.
    /// `ur_hold`: how many ticks of the step clock a unit reset is held.
    pub const fn new(fast: bool, ur_hold: u64) -> Self {
        K1Master {
            icr_on: CR_GCD | CR_SCLE | CR_MSDE | CR_IUE | if fast { CR_MODE_FAST } else { 0 },
            ur_hold,
            active: None,
            recover: None,
            nacks: 0,
            arb_lost: 0,
            bus_errors: 0,
            stuck: 0,
        }
    }

    /// Reset the unit (bring-up, from `i2c_attach`): `UR` now, released by
    /// the first step `ur_hold` ticks after `now`.
    pub fn reset_unit<R: K1Regs + ?Sized>(&mut self, r: &R, now: u64) {
        r.wr(ICR, CR_UR);
        self.recover = Some(Recover::Release { clock: false, at: now });
    }

    /// No transaction on the wire and no recovery under way.
    pub fn is_idle(&self) -> bool {
        self.active.is_none() && self.recover.is_none()
    }

    /// One step (see the module doc). `now` is the clock; `timeout` in the
    /// same units bounds a transaction from its start. Returns the ticket
    /// of a transaction this step finished, if any.
    pub fn service<R: K1Regs + ?Sized, const D: usize>(
        &mut self,
        q: &mut I2cBus<D>,
        r: &R,
        now: u64,
        timeout: u64,
    ) -> Option<u32> {
        if let Some(rec) = self.recover {
            self.recover_step(r, rec, now);
            return None;
        }
        if self.active.is_none() {
            let txn = q.pop_next()?;
            self.begin(r, txn, now);
        }
        let mut a = self.active.take()?;
        let isr = r.rd(ISR);
        if isr & SR_EVENTS != 0 {
            r.wr(ISR, isr & SR_EVENTS);
        }
        if isr & SR_MSD != 0 {
            a.msd = true;
        }
        if isr & SR_ERR != 0 {
            return Some(self.fail(q, r, a, isr, false, now));
        }
        match a.phase {
            Phase::WaitIdle => {
                if isr & (SR_UB | SR_IBB) == 0 {
                    let read = a.txn.wr_len == 0;
                    self.start_part(r, &mut a, read);
                }
            }
            Phase::Addr { read } => {
                if isr & SR_ITE != 0 {
                    if read {
                        a.phase = Phase::Read;
                        self.trigger_read(r, &a);
                    } else {
                        a.phase = Phase::Write;
                        self.put_byte(r, &mut a);
                    }
                }
            }
            Phase::Write => {
                if isr & SR_ITE != 0 {
                    if a.sent < a.txn.wr_len as usize {
                        self.put_byte(r, &mut a);
                    } else {
                        // The last write byte is out, with no STOP: the read
                        // part starts with a repeated START (the PIO path polls `ITE` after the last write
                        // byte before it rewrites `IDBR`, i2c-k1.c:516-526).
                        self.start_part(r, &mut a, true);
                    }
                }
            }
            Phase::Read => {
                if isr & SR_IRF != 0 {
                    let b = (r.rd(IDBR) & 0xFF) as u8;
                    a.txn.put_rd(&mut a.rx, a.got, b);
                    a.got += 1;
                    if a.got == a.txn.rd_len as usize {
                        a.phase = Phase::Stop;
                    } else {
                        self.trigger_read(r, &a);
                    }
                }
            }
            Phase::Stop => {}
        }
        if a.phase == Phase::Stop && a.msd {
            return Some(self.complete(q, r, a, true, now));
        }
        if now.saturating_sub(a.started) >= timeout {
            q.timeouts = q.timeouts.wrapping_add(1);
            return Some(self.fail(q, r, a, 0, true, now));
        }
        self.active = Some(a);
        None
    }

    /// Program the unit for `txn` and make it the transaction on the wire
    /// (i2c-k1.c:259-312, :138-145, :645-647): configuration while disabled, the SDA
    /// glitch fix off, the stale events cleared, then the unit enabled.
    fn begin<R: K1Regs + ?Sized>(&mut self, r: &R, txn: BusTxn, now: u64) {
        r.wr(ICR, self.icr_on & !CR_IUE);
        r.wr(IRCR, r.rd(IRCR) | RCR_SDA_GLITCH_NOFIX);
        r.wr(ISR, SR_EVENTS);
        r.wr(ICR, self.icr_on);
        self.active = Some(Active {
            txn,
            phase: Phase::WaitIdle,
            sent: 0,
            got: 0,
            msd: false,
            rx: [0; TXN_RD_MAX],
            started: now,
        });
    }

    /// Send START and the address byte of the write part, or of the read
    /// part (`read`).
    fn start_part<R: K1Regs + ?Sized>(&self, r: &R, a: &mut Active, read: bool) {
        r.wr(IDBR, (a.txn.addr as u32) << 1 | read as u32);
        r.wr(ICR, self.icr_on | CR_START | CR_TB);
        a.phase = Phase::Addr { read };
    }

    /// Put the next write byte in `IDBR` and start it; the last byte of a
    /// write-only transaction carries STOP, and then only `MSD` is left.
    fn put_byte<R: K1Regs + ?Sized>(&self, r: &R, a: &mut Active) {
        r.wr(IDBR, a.txn.wr_byte(a.sent) as u32);
        a.sent += 1;
        let last = a.sent == a.txn.wr_len as usize && a.txn.rd_len == 0;
        r.wr(ICR, self.icr_on | CR_TB | if last { CR_STOP } else { 0 });
        if last {
            a.phase = Phase::Stop;
        }
    }

    /// Start the receive of the next read byte. The LAST one is started with
    /// ACKNAK (the master's NACK) and STOP (i2c-k1.c:341-348, :466-474).
    fn trigger_read<R: K1Regs + ?Sized>(&self, r: &R, a: &Active) {
        let last = a.got + 1 == a.txn.rd_len as usize;
        r.wr(ICR, self.icr_on | CR_TB | if last { CR_STOP | CR_ACKNAK } else { 0 });
    }

    /// The unit is disabled and the result stored.
    fn complete<R: K1Regs + ?Sized, const D: usize>(
        &mut self,
        q: &mut I2cBus<D>,
        r: &R,
        a: Active,
        ok: bool,
        now: u64,
    ) -> u32 {
        r.wr(ICR, self.icr_on & !CR_IUE);
        let ticket = a.txn.ticket;
        // An `ext` transaction read into the caller's buffer: nothing to hand over.
        let got = if a.txn.ext.is_some() { 0 } else { a.got };
        q.complete_now(ticket, ok, &a.rx[..got], now);
        ticket
    }

    /// End `a` as failed and start the unit's recovery: a reset always, the
    /// bus-clocking too after a timeout. `isr` classifies an error.
    fn fail<R: K1Regs + ?Sized, const D: usize>(
        &mut self,
        q: &mut I2cBus<D>,
        r: &R,
        a: Active,
        isr: u32,
        timed_out: bool,
        now: u64,
    ) -> u32 {
        if !timed_out {
            q.aborts = q.aborts.wrapping_add(1);
            if isr & SR_ALD != 0 {
                self.arb_lost = self.arb_lost.wrapping_add(1);
            } else if isr & SR_ACKNAK != 0 {
                self.nacks = self.nacks.wrapping_add(1);
            } else {
                self.bus_errors = self.bus_errors.wrapping_add(1);
            }
        }
        let ticket = self.complete(q, r, a, false, now);
        r.wr(ICR, CR_UR);
        self.recover = Some(Recover::Release { clock: timed_out, at: now });
        ticket
    }

    fn recover_step<R: K1Regs + ?Sized>(&mut self, r: &R, rec: Recover, now: u64) {
        match rec {
            Recover::Release { clock, at } => {
                if now.saturating_sub(at) < self.ur_hold {
                    return;
                }
                r.wr(ICR, 0);
                self.recover = clock.then_some(Recover::Clock { cycles: 0 });
            }
            Recover::Clock { cycles } => {
                if r.rd(IBMR) & BMR_SDA != 0 {
                    self.recover = None;
                } else if cycles >= RESET_CLOCKS_MAX {
                    self.stuck = self.stuck.wrapping_add(1);
                    self.recover = None;
                } else {
                    r.wr(IRCR, 1);
                    r.wr(ICR, CR_RSTREQ);
                    self.recover = Some(Recover::Clock { cycles: cycles + 1 });
                }
            }
        }
    }
}
