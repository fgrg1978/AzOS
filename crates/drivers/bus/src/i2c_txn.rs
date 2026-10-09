// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Queued I2C bus transactions and the DesignWare controller state machine
//! that runs them (wave 15, IO-QUEUES-AUDIT row S1).
//!
//! # Why
//!
//! The synchronous DesignWare path (`i2c.rs`, `dw_i2c`) polls `IC_STATUS`
//! for the whole transfer with the bus `SpinLock` held, so preemption is off
//! for it: ~1.35 ms for the IMU's 14-byte read at 100 kHz, from `imu_task`,
//! a real-time task, 100 times a second. The owner rule is that a real-time
//! task only enqueues.
//!
//! # The shape
//!
//! * A caller [`I2cBus::submit`]s a [`BusTxn`] (address, up to
//!   [`TXN_WR_MAX`] bytes to write, up to [`TXN_RD_MAX`] to read) and gets a
//!   ticket back, or a refusal (queue full, counted). It never waits.
//! * [`I2cBus::service`] is one step of the controller: it starts the next
//!   queued transaction when the bus is idle, moves what the RX FIFO holds
//!   into the transaction, refills the TX FIFO with as many commands as the
//!   FIFOs have room for, and finishes the transaction on its last byte, on
//!   an abort (`TX_ABRT`: a NACK) or on the timeout. It reads the RAW
//!   interrupt status, so the same step serves the controller's interrupt
//!   (interrupt mask: `TX_EMPTY` while commands remain, `RX_FULL` at the
//!   read's threshold, `TX_ABRT`, `STOP_DET`) and a poll from a task when no
//!   interrupt line is wired. Each step is a handful of register accesses,
//!   bounded by the FIFO depth: no wait on the wire inside it.
//! * The result lands in a completion slot, stamped with the clock value of
//!   the step that finished it (the acquisition time); [`I2cBus::take`]
//!   returns it by ticket.
//!
//! Read commands are pushed only while the RX FIFO has room for their bytes,
//! so the receive FIFO cannot overflow, and no `IC_DATA_CMD` write is made
//! without `IC_STATUS.TFNF` (a DesignWare controller silently drops a write
//! to a full TX FIFO, U05-6).
//!
//! ISA-neutral and free of MMIO: the registers come through [`DwRegs`], so
//! `tests/host/drivers-tests` runs this file against a modelled controller.
//! Board validation (VisionFive 2) is pending: QEMU has no DesignWare I2C.

/// Largest write part of one transaction (a register address and a few
/// bytes).
pub const TXN_WR_MAX: usize = 4;
/// Largest read part of one transaction (the IMU's burst is 14).
pub const TXN_RD_MAX: usize = 32;

// DesignWare APB I2C registers (DW_apb_i2c databook).
pub const IC_TAR: usize = 0x04;
pub const IC_DATA_CMD: usize = 0x10;
pub const IC_INTR_MASK: usize = 0x30;
pub const IC_RAW_INTR_STAT: usize = 0x34;
pub const IC_RX_TL: usize = 0x38;
pub const IC_TX_TL: usize = 0x3C;
pub const IC_CLR_INTR: usize = 0x40;
pub const IC_CLR_TX_ABRT: usize = 0x54;
pub const IC_CLR_STOP_DET: usize = 0x60;
pub const IC_ENABLE: usize = 0x6C;
pub const IC_STATUS: usize = 0x70;
pub const IC_RXFLR: usize = 0x78;

// Interrupt bits (IC_RAW_INTR_STAT / IC_INTR_MASK).
pub const INTR_RX_FULL: u32 = 1 << 2;
pub const INTR_TX_EMPTY: u32 = 1 << 4;
pub const INTR_TX_ABRT: u32 = 1 << 6;
pub const INTR_STOP_DET: u32 = 1 << 9;

// IC_STATUS bits.
pub const STATUS_TFNF: u32 = 1 << 1;
pub const STATUS_RFNE: u32 = 1 << 3;

// IC_DATA_CMD bits.
pub const CMD_READ: u32 = 1 << 8;
pub const CMD_STOP: u32 = 1 << 9;

/// The controller's registers, by byte offset. The kernel's implementation
/// is MMIO; the host tests' is a model.
pub trait DwRegs {
    fn rd(&self, off: usize) -> u32;
    fn wr(&self, off: usize, val: u32);
}

/// The caller's own buffers for a transaction it waits for
/// ([`I2cBus::submit_ext`]): any length, no copy. Valid until the
/// transaction's completion, which the submitter waits for.
#[derive(Clone, Copy, Debug)]
pub struct ExtBuf {
    pub wr: *const u8,
    pub rd: *mut u8,
}

// SAFETY: the buffers are touched only by the service step, under the bus's
// lock, while the submitter waits for the completion (`submit_ext`'s
// contract); nothing else holds them meanwhile.
unsafe impl Send for ExtBuf {}

/// One queued transaction.
#[derive(Clone, Copy, Debug)]
pub struct BusTxn {
    pub addr: u8,
    /// The write part, when it is held inline (`ext` is `None`).
    pub wr: [u8; TXN_WR_MAX],
    pub wr_len: u16,
    pub rd_len: u16,
    pub ticket: u32,
    /// The caller's buffers instead of `wr` and the completion's `rd`.
    pub ext: Option<ExtBuf>,
}

impl BusTxn {
    const EMPTY: BusTxn = BusTxn { addr: 0, wr: [0; TXN_WR_MAX], wr_len: 0, rd_len: 0, ticket: 0, ext: None };

    fn cmds(&self) -> usize {
        self.wr_len as usize + self.rd_len as usize
    }

    fn wr_byte(&self, i: usize) -> u8 {
        match self.ext {
            // SAFETY: `i < wr_len`, inside the caller's buffer (`submit_ext`).
            Some(e) => unsafe { *e.wr.add(i) },
            None => self.wr[i],
        }
    }
}

/// A finished transaction.
#[derive(Clone, Copy, Debug)]
pub struct Completion {
    pub ticket: u32,
    /// Every byte transferred, no abort, no timeout.
    pub ok: bool,
    /// The bytes read, for an inline transaction (an `ext` one wrote them
    /// into the caller's buffer).
    pub rd: [u8; TXN_RD_MAX],
    pub rd_len: u16,
    /// Clock value of the step that finished it: the acquisition time.
    pub at: u64,
}

impl Completion {
    const NONE: Completion = Completion { ticket: 0, ok: false, rd: [0; TXN_RD_MAX], rd_len: 0, at: 0 };
}

/// Why [`I2cBus::submit`] refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitError {
    /// The queue holds its depth already.
    Full,
    /// Write part above [`TXN_WR_MAX`] or read part above [`TXN_RD_MAX`]
    /// (inline), a part above `u16::MAX` (`submit_ext`), or nothing to
    /// transfer.
    BadLength,
}

/// The transaction on the wire.
struct Active {
    txn: BusTxn,
    /// Commands (write bytes, then read commands) pushed to the TX FIFO.
    sent: usize,
    /// Read bytes collected from the RX FIFO.
    got: usize,
    rx: [u8; TXN_RD_MAX],
    started: u64,
}

/// One bus: the transaction queue, the transaction on the wire and the
/// completion slots. `D` is the queue depth (Kconfig `I2C_TXN_QUEUE_DEPTH`);
/// completions are kept in `D` slots by ticket, so a result stays readable
/// until `D` later transactions finish.
pub struct I2cBus<const D: usize> {
    queue: [BusTxn; D],
    head: usize,
    len: usize,
    active: Option<Active>,
    done: [Completion; D],
    next_ticket: u32,
    /// RX FIFO depth of the controller, in entries: reads in flight never
    /// exceed it. (The TX side needs no depth: every push checks TFNF.)
    fifo_depth: usize,
    /// Submissions refused because the queue was full.
    pub refused: u32,
    /// Transactions ended by `TX_ABRT` (a NACK, arbitration lost).
    pub aborts: u32,
    /// Transactions ended by the timeout.
    pub timeouts: u32,
    /// Transactions finished.
    pub completed: u32,
}

impl<const D: usize> I2cBus<D> {
    /// `fifo_depth`: the controller's RX FIFO depth in entries (at least 2;
    /// Kconfig `I2C_DW_RX_FIFO_DEPTH`).
    pub const fn new(fifo_depth: usize) -> Self {
        I2cBus {
            queue: [BusTxn::EMPTY; D],
            head: 0,
            len: 0,
            active: None,
            done: [Completion::NONE; D],
            next_ticket: 1,
            fifo_depth: if fifo_depth < 2 { 2 } else { fifo_depth },
            refused: 0,
            aborts: 0,
            timeouts: 0,
            completed: 0,
        }
    }

    /// A transaction is on the wire (the bus's `IC_TAR` is taken).
    pub fn is_active(&self) -> bool {
        self.active.is_some()
    }

    /// Nothing queued and nothing on the wire.
    pub fn is_idle(&self) -> bool {
        self.active.is_none() && self.len == 0
    }

    /// Queue a transaction: write `wr` to `addr`, then read `rd_len` bytes
    /// (a repeated start between the two). Never waits. Returns the ticket.
    pub fn submit(&mut self, addr: u8, wr: &[u8], rd_len: usize) -> Result<u32, SubmitError> {
        if wr.len() > TXN_WR_MAX || rd_len > TXN_RD_MAX || wr.len() + rd_len == 0 {
            return Err(SubmitError::BadLength);
        }
        if self.len == D {
            self.refused = self.refused.wrapping_add(1);
            return Err(SubmitError::Full);
        }
        let ticket = self.alloc_ticket();
        let mut t = BusTxn { addr, wr: [0; TXN_WR_MAX], wr_len: wr.len() as u16, rd_len: rd_len as u16, ticket, ext: None };
        t.wr[..wr.len()].copy_from_slice(wr);
        self.queue[(self.head + self.len) % D] = t;
        self.len += 1;
        Ok(ticket)
    }

    /// Queue a transaction on the caller's own buffers: write `wr_len` bytes
    /// from `wr`, then read `rd_len` into `rd`. For a synchronous caller
    /// that waits (sleeping) for the ticket's completion.
    ///
    /// # Safety
    ///
    /// `wr` must be readable for `wr_len` bytes and `rd` writable for
    /// `rd_len` bytes, and neither may be used otherwise, until
    /// [`take`](Self::take) returns this ticket's completion (a timeout
    /// finishes it too, so that point always comes).
    pub unsafe fn submit_ext(&mut self, addr: u8, wr: *const u8, wr_len: usize, rd: *mut u8, rd_len: usize) -> Result<u32, SubmitError> {
        if wr_len > u16::MAX as usize || rd_len > u16::MAX as usize || wr_len + rd_len == 0 {
            return Err(SubmitError::BadLength);
        }
        if self.len == D {
            self.refused = self.refused.wrapping_add(1);
            return Err(SubmitError::Full);
        }
        let ticket = self.alloc_ticket();
        let t = BusTxn { addr, wr: [0; TXN_WR_MAX], wr_len: wr_len as u16, rd_len: rd_len as u16, ticket, ext: Some(ExtBuf { wr, rd }) };
        self.queue[(self.head + self.len) % D] = t;
        self.len += 1;
        Ok(ticket)
    }

    /// The result of `ticket`, if it has finished (and was not overwritten
    /// by `D` later completions). Taking it leaves it in place.
    pub fn take(&self, ticket: u32) -> Option<Completion> {
        let c = &self.done[ticket as usize % D];
        if c.ticket == ticket && ticket != 0 { Some(*c) } else { None }
    }

    /// One step of the controller (see the module doc). `now` is the clock;
    /// `timeout` in the same units bounds a transaction from its start.
    /// Returns the ticket of a transaction this step finished, if any.
    pub fn service<R: DwRegs + ?Sized>(&mut self, r: &R, now: u64, timeout: u64) -> Option<u32> {
        if self.active.is_none() {
            if self.len == 0 {
                return None;
            }
            let txn = self.queue[self.head];
            self.head = (self.head + 1) % D;
            self.len -= 1;
            self.start(r, txn, now);
        }
        let raw = r.rd(IC_RAW_INTR_STAT);
        if raw & INTR_TX_ABRT != 0 {
            let _ = r.rd(IC_CLR_TX_ABRT);
            self.aborts = self.aborts.wrapping_add(1);
            return Some(self.finish(r, false, now));
        }
        self.collect(r);
        self.refill(r);
        let a = self.active.as_ref()?;
        let total = a.txn.cmds();
        let complete = if a.txn.rd_len > 0 {
            a.got == a.txn.rd_len as usize
        } else {
            a.sent == total && raw & INTR_STOP_DET != 0
        };
        if complete {
            if raw & INTR_STOP_DET != 0 {
                let _ = r.rd(IC_CLR_STOP_DET);
            }
            return Some(self.finish(r, true, now));
        }
        if now.saturating_sub(a.started) >= timeout {
            self.timeouts = self.timeouts.wrapping_add(1);
            return Some(self.finish(r, false, now));
        }
        None
    }

    fn start<R: DwRegs + ?Sized>(&mut self, r: &R, txn: BusTxn, now: u64) {
        r.wr(IC_TAR, txn.addr as u32);
        r.wr(IC_ENABLE, 1);
        let _ = r.rd(IC_CLR_INTR);
        // RX_FULL fires once the whole read (or a FIFO's worth) is in;
        // TX_EMPTY at half the FIFO, so the refill overlaps the wire.
        let rd = (txn.rd_len as usize).clamp(1, self.fifo_depth);
        r.wr(IC_RX_TL, (rd - 1) as u32);
        r.wr(IC_TX_TL, (self.fifo_depth / 2) as u32);
        self.active = Some(Active { txn, sent: 0, got: 0, rx: [0; TXN_RD_MAX], started: now });
        r.wr(IC_INTR_MASK, INTR_TX_EMPTY | INTR_RX_FULL | INTR_TX_ABRT | INTR_STOP_DET);
    }

    /// Move what the RX FIFO holds into the transaction.
    fn collect<R: DwRegs + ?Sized>(&mut self, r: &R) {
        let Some(a) = self.active.as_mut() else { return };
        while a.got < a.txn.rd_len as usize && r.rd(IC_STATUS) & STATUS_RFNE != 0 {
            let b = (r.rd(IC_DATA_CMD) & 0xFF) as u8;
            match a.txn.ext {
                // SAFETY: `got < rd_len`, inside the caller's buffer (`submit_ext`).
                Some(e) => unsafe { *e.rd.add(a.got) = b },
                None => a.rx[a.got] = b,
            }
            a.got += 1;
        }
    }

    /// Push commands while the TX FIFO has room and, for reads, while the RX
    /// FIFO has room for every read in flight. Masks `TX_EMPTY` once the
    /// last command is in.
    fn refill<R: DwRegs + ?Sized>(&mut self, r: &R) {
        let depth = self.fifo_depth;
        let Some(a) = self.active.as_mut() else { return };
        let wr_len = a.txn.wr_len as usize;
        let total = a.txn.cmds();
        while a.sent < total {
            if a.sent >= wr_len {
                // Reads in flight: pushed, not yet collected (RX FIFO + wire).
                let in_flight = a.sent - wr_len - a.got;
                if in_flight >= depth {
                    break;
                }
            }
            if r.rd(IC_STATUS) & STATUS_TFNF == 0 {
                break;
            }
            let last = a.sent + 1 == total;
            let stop = if last { CMD_STOP } else { 0 };
            let cmd = if a.sent < wr_len { a.txn.wr_byte(a.sent) as u32 } else { CMD_READ };
            r.wr(IC_DATA_CMD, cmd | stop);
            a.sent += 1;
        }
        if a.sent == total {
            r.wr(IC_INTR_MASK, INTR_RX_FULL | INTR_TX_ABRT | INTR_STOP_DET);
        }
    }

    fn finish<R: DwRegs + ?Sized>(&mut self, r: &R, ok: bool, now: u64) -> u32 {
        r.wr(IC_INTR_MASK, 0);
        let _ = r.rd(IC_CLR_INTR);
        let a = self.active.take().expect("finish with no active transaction");
        let ticket = a.txn.ticket;
        self.done[ticket as usize % D] = Completion { ticket, ok, rd: a.rx, rd_len: a.txn.rd_len, at: now };
        self.completed = self.completed.wrapping_add(1);
        ticket
    }

    /// A completion for a transaction run without the controller (the QEMU
    /// simulation, which transfers at submit): stored like one `service`
    /// finished.
    pub fn complete_now(&mut self, ticket: u32, ok: bool, rd: &[u8], now: u64) {
        let mut c = Completion { ticket, ok, rd: [0; TXN_RD_MAX], rd_len: rd.len().min(TXN_RD_MAX) as u16, at: now };
        c.rd[..c.rd_len as usize].copy_from_slice(&rd[..c.rd_len as usize]);
        self.done[ticket as usize % D] = c;
        self.completed = self.completed.wrapping_add(1);
    }

    /// A ticket for a transaction run without the controller (the QEMU
    /// simulation), finished later with [`complete_now`](Self::complete_now).
    pub fn alloc_ticket(&mut self) -> u32 {
        let ticket = self.next_ticket;
        self.next_ticket = self.next_ticket.wrapping_add(1).max(1);
        ticket
    }
}

/// A synchronous caller's wait for its own transaction: `step` runs one
/// service step (under the bus lock, the only preemption-off window) and
/// returns the transaction's completion once it exists; between steps the
/// caller `sleep`s, which returns `false` when this context may not sleep
/// (then it only spins a hint before the next step). Ends because every
/// transaction finishes: on its last byte, an abort or the timeout.
pub fn wait_completion(mut step: impl FnMut() -> Option<Completion>, mut sleep: impl FnMut() -> bool) -> Completion {
    loop {
        if let Some(c) = step() {
            return c;
        }
        if !sleep() {
            core::hint::spin_loop();
        }
    }
}
