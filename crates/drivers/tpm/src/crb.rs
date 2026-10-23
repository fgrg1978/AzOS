// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Command Response Buffer interface (TCG PC Client Platform TPM Profile,
//! CRB): the interface of the firmware TPMs of PCs (Intel PTT, AMD fTPM) and
//! of QEMU's `tpm-crb`.
//!
//! Two register blocks and the buffers they name:
//!
//! * the **locality registers** (`LOC_STATE`, `LOC_CTRL`, `INTF_ID`), the
//!   0x40 bytes right below the control area in the PTP layout;
//! * the **control area** at the ACPI TPM2 table's `ControlAreaAddress`:
//!   `REQ` (`cmdReady`, `goIdle`), `STS` (`tpmSts`, `tpmIdle`), `CANCEL`,
//!   `START`, and the address and size of the command buffer and of the
//!   response buffer (often one buffer for both).
//!
//! One command is: request the locality, `cmdReady` (start method 7), the
//! command into the command buffer, `START` = 1, wait for `START` to fall
//! (bounded by the command's duration class; `CANCEL` when it does not), the
//! response header, then the size it declares (bounded by the response
//! buffer and by the caller's), `goIdle` (method 7), release the locality.
//! The sequence of Linux `tpm_crb` (`crb_send`, `crb_recv`, `__crb_cmd_ready`,
//! `__crb_go_idle`, `__crb_request_locality`).
//!
//! **Start methods 2 and 8** ([`StartMethod::Acpi`]) want the TPM device's
//! ACPI `_DSM` (function 1 of `6bbf6cab-5463-4714-b7cd-f0203c0368d4`) after
//! `START`, and no `cmdReady`/`goIdle`. Evaluating `_DSM` takes an AML
//! interpreter this kernel does not have. The driver writes `START` (Linux
//! writes it too for every `MSFT0101` device, for the PTT that announces an
//! ACPI start and needs the register); a TPM that still waits for the `_DSM`
//! never lowers `START`, the command times out, bounded, and the TPM is not
//! used.
//!
//! **Where the locality registers are.** The table names only the control
//! area. Linux uses the locality registers for start method 7 when the
//! control area is its `_CRS` window's start + 0x40; without `_CRS` (AML
//! again), [`head_for`] takes them for method 7 when the control area sits at
//! offset 0x40 of its page (QEMU: control area 0xFED40040, registers
//! 0xFED40000), and goes without them (no locality, no identity registers)
//! otherwise.

use crate::mmio::MmioAccess;
use crate::tis::{self, check_command, Clock, DeviceInfo, Duration, Timeouts, CMD_MAX, HEADER_BYTES, RESP_MAX};
use crate::{Error, Transport, Wait};

/// Bytes from the locality registers to the control area (PTP layout).
pub const HEAD_BYTES: u64 = 0x40;
/// Bytes of the control area the driver reads and writes, from its start.
pub const CTRL_BYTES: u64 = 0x30;

// Locality registers, from the head.
const LOC_STATE: u64 = 0x00;
const LOC_CTRL: u64 = 0x08;
const INTF_ID: u64 = 0x30;
const INTF_ID_HI: u64 = 0x34;
// Control area, from `ControlAreaAddress`.
const REQ: u64 = 0x00;
const STS: u64 = 0x04;
const CANCEL: u64 = 0x08;
const START: u64 = 0x0C;
const CMD_SIZE: u64 = 0x18;
const CMD_LADDR: u64 = 0x1C;
const CMD_HADDR: u64 = 0x20;
const RSP_SIZE: u64 = 0x24;
const RSP_ADDR: u64 = 0x28;

const LOC_STATE_ASSIGNED: u32 = 1 << 1;
const LOC_STATE_VALID: u32 = 1 << 7;
/// `LOC_STATE.activeLocality`, bits 4:2.
const fn active_locality(v: u32) -> u32 {
    (v >> 2) & 7
}
const LOC_CTRL_REQUEST: u32 = 1 << 0;
const LOC_CTRL_RELINQUISH: u32 = 1 << 1;
const REQ_CMD_READY: u32 = 1 << 0;
const REQ_GO_IDLE: u32 = 1 << 1;
const STS_ERROR: u32 = 1 << 0;
const START_INVOKE: u32 = 1 << 0;
const CANCEL_INVOKE: u32 = 1 << 0;
/// `INTF_ID.InterfaceType` (bits 3:0) of an active CRB.
const INTF_TYPE_CRB: u32 = 1;

/// How the TPM2 table says a command is started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartMethod {
    /// 7: `CTRL_START`, with `cmdReady` and `goIdle` around the command.
    Crb,
    /// 2, 8: `CTRL_START` and the ACPI `_DSM` (not evaluated, see the module
    /// doc), no `cmdReady` or `goIdle`.
    Acpi,
}

/// The locality registers of a control area at `ctrl`: 0x40 below it for
/// start method 7 when it sits at offset 0x40 of its page, none otherwise
/// (see the module doc).
pub const fn head_for(ctrl: u64, start: StartMethod) -> Option<u64> {
    match start {
        StartMethod::Crb if ctrl & 0xFFF == HEAD_BYTES => Some(ctrl - HEAD_BYTES),
        _ => None,
    }
}

/// The buffers as the control area names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Buffers {
    pub cmd: u64,
    pub cmd_size: u32,
    pub rsp: u64,
    pub rsp_size: u32,
}

impl Buffers {
    /// Bytes of the command buffer the driver touches, from `cmd`: the
    /// window the caller maps.
    pub fn cmd_span(&self) -> u64 {
        (self.cmd_size as u64).min(CMD_MAX as u64)
    }

    /// Bytes of the response buffer the driver touches, from `rsp`.
    pub fn rsp_span(&self) -> u64 {
        (self.rsp_size as u64).min(RESP_MAX as u64)
    }
}

/// The buffers the control area at `ctrl` (mapped) names, checked: an
/// all-ones area is no device; a buffer at 0, smaller than a header or
/// wrapping the address space is `Malformed`, as are two buffers that
/// overlap without being the same one, and one buffer for both with two
/// sizes (the PTP requires them equal; Linux refuses that too).
pub fn read_buffers<A: MmioAccess>(mmio: &mut A, ctrl: u64) -> Result<Buffers, Error> {
    let cmd_size = mmio.read32(ctrl + CMD_SIZE);
    let rsp_size = mmio.read32(ctrl + RSP_SIZE);
    if cmd_size == u32::MAX && rsp_size == u32::MAX {
        return Err(Error::NoDevice);
    }
    let b = Buffers {
        cmd: (mmio.read32(ctrl + CMD_HADDR) as u64) << 32 | mmio.read32(ctrl + CMD_LADDR) as u64,
        cmd_size,
        rsp: (mmio.read32(ctrl + RSP_ADDR + 4) as u64) << 32 | mmio.read32(ctrl + RSP_ADDR) as u64,
        rsp_size,
    };
    let span = |a: u64, n: u32| if a == 0 || (n as usize) < HEADER_BYTES { None } else { a.checked_add(n as u64) };
    let (Some(cmd_end), Some(rsp_end)) = (span(b.cmd, b.cmd_size), span(b.rsp, b.rsp_size)) else {
        return Err(Error::Malformed);
    };
    let ok = if b.cmd == b.rsp { b.cmd_size == b.rsp_size } else { cmd_end <= b.rsp || rsp_end <= b.cmd };
    if ok { Ok(b) } else { Err(Error::Malformed) }
}

pub struct Crb<A: MmioAccess, C: Clock> {
    mmio: A,
    clock: C,
    ctrl: u64,
    head: Option<u64>,
    start: StartMethod,
    buf: Buffers,
    timeouts: Timeouts,
}

impl<A: MmioAccess, C: Clock> Crb<A, C> {
    /// The CRB whose control area is at `ctrl`, started as `start`, with the
    /// buffers [`read_buffers`] read. The control area, the locality
    /// registers ([`head_for`]) and the buffers' spans must be mapped.
    pub fn new(mmio: A, clock: C, ctrl: u64, start: StartMethod, buf: Buffers) -> Self {
        Crb { mmio, clock, ctrl, head: head_for(ctrl, start), start, buf, timeouts: Timeouts::TPM2 }
    }

    fn rd(&mut self, a: u64) -> u32 {
        self.mmio.read32(a)
    }

    fn wr(&mut self, a: u64, v: u32) {
        self.mmio.write32(a, v)
    }

    fn poll<F>(&mut self, what: Wait, timeout_us: u32, f: F) -> Result<u32, Error>
    where
        F: FnMut(&mut Self) -> Result<Option<u32>, Error>,
    {
        tis::poll(self, |c| &mut c.clock, what, timeout_us, f)
    }

    /// Wait for the control-area bits `mask` at `reg` to read 0.
    fn wait_clear(&mut self, reg: u64, mask: u32, what: Wait, timeout_us: u32) -> Result<(), Error> {
        let a = self.ctrl + reg;
        self.poll(what, timeout_us, |c| Ok(if c.rd(a) & mask == 0 { Some(0) } else { None })).map(|_| ())
    }

    const BOTH: u32 = LOC_STATE_ASSIGNED | LOC_STATE_VALID;

    fn request_locality(&mut self, h: u64) -> Result<(), Error> {
        let mine = |v: u32| v != u32::MAX && v & Self::BOTH == Self::BOTH && active_locality(v) == 0;
        if mine(self.rd(h + LOC_STATE)) {
            return Ok(());
        }
        self.wr(h + LOC_CTRL, LOC_CTRL_REQUEST);
        let c = self.timeouts.c_us;
        self.poll(Wait::Locality, c, |x| Ok(if mine(x.rd(h + LOC_STATE)) { Some(0) } else { None })).map(|_| ())
    }

    fn release_locality(&mut self, h: u64) -> Result<(), Error> {
        if cfg!(feature = "canary-release") {
            return Ok(());
        }
        self.wr(h + LOC_CTRL, LOC_CTRL_RELINQUISH);
        let c = self.timeouts.c_us;
        self.poll(Wait::Locality, c, |x| {
            Ok(if x.rd(h + LOC_STATE) & Self::BOTH == LOC_STATE_VALID { Some(0) } else { None })
        })
        .map(|_| ())
    }

    /// The identity registers (none without the locality registers) and the
    /// state: an all-ones window is no device, `tpmSts` set is [`Error::Fatal`].
    pub fn probe(&mut self) -> Result<DeviceInfo, Error> {
        let info = match self.head {
            Some(h) => {
                let a = self.timeouts.a_us;
                self.poll(Wait::StsValid, a, |x| {
                    let v = x.rd(h + LOC_STATE);
                    Ok(if v != u32::MAX && v & LOC_STATE_VALID != 0 { Some(v) } else { None })
                })
                .map_err(|e| if matches!(e, Error::Timeout(_)) { Error::NoDevice } else { e })?;
                self.request_locality(h)?;
                let id = self.rd(h + INTF_ID);
                let id_hi = self.rd(h + INTF_ID_HI);
                self.release_locality(h)?;
                if id & 0xF != INTF_TYPE_CRB {
                    return Err(Error::NoDevice);
                }
                DeviceInfo { vid: id_hi as u16, did: (id_hi >> 16) as u16, rid: (id >> 24) as u8 }
            }
            None => DeviceInfo { vid: 0, did: 0, rid: 0 },
        };
        match self.rd(self.ctrl + STS) {
            u32::MAX => Err(Error::NoDevice),
            s if s & STS_ERROR != 0 => Err(Error::Fatal),
            _ => Ok(info),
        }
    }

    /// One command; see the module doc for the sequence.
    pub fn transmit(&mut self, cmd: &[u8], rsp: &mut [u8], dur: Duration) -> Result<usize, Error> {
        check_command(cmd)?;
        if cmd.len() > self.buf.cmd_size as usize {
            return Err(Error::BadCommand);
        }
        if let Some(h) = self.head {
            self.request_locality(h)?;
        }
        let r = self.exchange(cmd, rsp, dur);
        if self.start == StartMethod::Crb {
            // As Linux's tpm_chip_stop: a goIdle that does not complete costs
            // this command nothing (its response is read); the next cmdReady
            // says so.
            let c = self.timeouts.c_us;
            self.wr(self.ctrl + REQ, REQ_GO_IDLE);
            let _ = self.wait_clear(REQ, REQ_GO_IDLE, Wait::Idle, c);
        }
        let rel = match self.head {
            Some(h) => self.release_locality(h),
            None => Ok(()),
        };
        let n = r?;
        rel?;
        Ok(n)
    }

    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8], dur: Duration) -> Result<usize, Error> {
        let t = self.timeouts;
        if self.rd(self.ctrl + STS) & STS_ERROR != 0 {
            return Err(Error::Fatal);
        }
        if self.start == StartMethod::Crb {
            self.wr(self.ctrl + REQ, REQ_CMD_READY);
            self.wait_clear(REQ, REQ_CMD_READY, Wait::CommandReady, t.c_us)?;
        }
        self.wr(self.ctrl + CANCEL, 0);
        let base = self.buf.cmd;
        for (i, b) in cmd.iter().enumerate() {
            self.mmio.write8(base + i as u64, *b);
        }
        if !cfg!(feature = "canary-crb-start") {
            self.wr(self.ctrl + START, START_INVOKE);
        }
        if let Err(e) = self.wait_clear(START, START_INVOKE, Wait::Start, dur.us()) {
            // Ask the TPM to drop the command; the next one clears CANCEL.
            self.wr(self.ctrl + CANCEL, CANCEL_INVOKE);
            let _ = self.wait_clear(START, START_INVOKE, Wait::Start, t.c_us);
            return Err(e);
        }
        if self.rd(self.ctrl + STS) & STS_ERROR != 0 {
            return Err(Error::Fatal);
        }
        // The header, then the size it declares, bounded by the response
        // buffer and the caller's before any byte past the header is read.
        let rb = self.buf.rsp;
        let mut hdr = [0u8; HEADER_BYTES];
        for (i, b) in hdr.iter_mut().enumerate() {
            *b = self.mmio.read8(rb + i as u64);
        }
        let total = u32::from_be_bytes([hdr[2], hdr[3], hdr[4], hdr[5]]) as usize;
        if total < HEADER_BYTES
            || (!cfg!(feature = "canary-rspsize") && (total > rsp.len() || total > self.buf.rsp_span() as usize))
        {
            return Err(Error::BadResponseSize);
        }
        rsp[..HEADER_BYTES].copy_from_slice(&hdr);
        for (i, b) in rsp[HEADER_BYTES..total].iter_mut().enumerate() {
            *b = self.mmio.read8(rb + (HEADER_BYTES + i) as u64);
        }
        Ok(total)
    }
}

impl<A: MmioAccess, C: Clock> Transport for Crb<A, C> {
    fn probe(&mut self) -> Result<DeviceInfo, Error> {
        Crb::probe(self)
    }

    fn transmit(&mut self, cmd: &[u8], rsp: &mut [u8], dur: Duration) -> Result<usize, Error> {
        Crb::transmit(self, cmd, rsp, dur)
    }

    fn pause_us(&mut self, us: u32) {
        self.clock.pause_us(us)
    }
}
