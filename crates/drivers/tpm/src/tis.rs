// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The TIS/FIFO interface (TCG PC Client Platform TPM Profile, FIFO).
//!
//! One command is: request the locality, make the TPM `commandReady`, push
//! the command in `burstCount`-sized pieces holding the last byte back until
//! `expect` has been seen set, `tpmGo`, wait for `dataAvail`, read the
//! response in pieces, check `dataAvail` fell, go idle, release the locality.
//! Every wait is bounded by the A/B/C timeouts or by the command's duration
//! class; none spins forever.

use crate::{BusError, Error, Wait};

// Register offsets inside one locality's 4 KiB page (PTP, FIFO register map).
pub const REG_ACCESS: u16 = 0x00;
/// `TPM_STS`: status in bits 7:0, `burstCount` in bits 23:8, family in 27:26.
pub const REG_STS: u16 = 0x18;
pub const REG_DATA_FIFO: u16 = 0x24;
/// `TPM_DID_VID`: vendor in bits 15:0, device in bits 31:16.
pub const REG_DID_VID: u16 = 0xF00;
pub const REG_RID: u16 = 0xF04;

/// `TPM_ACCESS` bits.
pub mod access {
    pub const VALID: u8 = 0x80;
    pub const ACTIVE: u8 = 0x20;
    pub const REQUEST_USE: u8 = 0x02;
}

/// `TPM_STS` status-byte bits.
pub mod sts {
    pub const VALID: u8 = 0x80;
    pub const CMD_READY: u8 = 0x40;
    pub const GO: u8 = 0x20;
    pub const DATA_AVAIL: u8 = 0x10;
    pub const EXPECT: u8 = 0x08;
}

/// `burstCount` of a 32-bit `TPM_STS` value.
pub const fn sts_burst(v: u32) -> u16 {
    (v >> 8) as u16
}

/// Family of a 32-bit `TPM_STS` value: 0 = TPM 1.2, 1 = TPM 2.0.
pub const fn sts_family(v: u32) -> u8 {
    ((v >> 26) & 3) as u8
}

/// Highest locality the interface defines.
pub const MAX_LOCALITY: u8 = 4;
/// Bytes of a TPM 2.0 command or response header.
pub const HEADER_BYTES: usize = 10;
/// Largest command the driver builds and sends.
pub const CMD_MAX: usize = 256;
/// Largest response the driver accepts.
pub const RESP_MAX: usize = 256;

/// The register file of one TPM, one locality at a time. `reg` is the offset
/// inside the locality page. A multi-byte read or write at [`REG_DATA_FIFO`]
/// moves successive FIFO bytes; at any other register it moves successive
/// bytes from `reg` upward (little-endian for the 32-bit registers).
pub trait TisRegs {
    fn read(&mut self, locality: u8, reg: u16, buf: &mut [u8]) -> Result<(), BusError>;
    fn write(&mut self, locality: u8, reg: u16, data: &[u8]) -> Result<(), BusError>;
}

/// Time for the bounded waits. The driver polls; `pause_us` is where a task
/// sleeps or a bare-metal caller spins.
pub trait Clock {
    fn now_us(&mut self) -> u64;
    fn pause_us(&mut self, us: u32);
}

/// The interface timeouts of a TPM 2.0 (PTP defaults), in microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// `stsValid`, locality changes, `burstCount` becoming non-zero.
    pub a_us: u32,
    /// `commandReady`.
    pub b_us: u32,
    /// `stsValid` after bytes moved.
    pub c_us: u32,
}

impl Timeouts {
    pub const TPM2: Timeouts = Timeouts { a_us: 750_000, b_us: 2_000_000, c_us: 200_000 };
}

/// How long a command may take before `dataAvail`. Generous: a flash write on
/// a cheap part is slow, and the bound only has to catch a dead TPM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Duration {
    Short,
    Medium,
    Long,
}

impl Duration {
    pub const fn us(self) -> u32 {
        match self {
            Duration::Short => 750_000,
            Duration::Medium => 2_000_000,
            Duration::Long => 30_000_000,
        }
    }
}

/// Identity registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    pub vid: u16,
    pub did: u16,
    pub rid: u8,
}

const POLL_US: u32 = 50;

pub struct Tis<R: TisRegs, C: Clock> {
    regs: R,
    clock: C,
    locality: u8,
    timeouts: Timeouts,
}

impl<R: TisRegs, C: Clock> Tis<R, C> {
    pub fn new(regs: R, clock: C, locality: u8) -> Self {
        Tis { regs, clock, locality, timeouts: Timeouts::TPM2 }
    }

    fn rd(&mut self, reg: u16, buf: &mut [u8]) -> Result<(), Error> {
        self.regs.read(self.locality, reg, buf).map_err(|_| Error::Bus)
    }

    fn wr(&mut self, reg: u16, data: &[u8]) -> Result<(), Error> {
        self.regs.write(self.locality, reg, data).map_err(|_| Error::Bus)
    }

    fn rd8(&mut self, reg: u16) -> Result<u8, Error> {
        let mut b = [0u8; 1];
        self.rd(reg, &mut b)?;
        Ok(b[0])
    }

    fn rd32(&mut self, reg: u16) -> Result<u32, Error> {
        let mut b = [0u8; 4];
        self.rd(reg, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn status(&mut self) -> Result<u32, Error> {
        self.rd32(REG_STS)
    }

    /// Poll `f` until it yields a value or `timeout_us` has passed. `f` runs
    /// at least once, so a zero timeout still looks.
    fn poll<F>(&mut self, what: Wait, timeout_us: u32, mut f: F) -> Result<u32, Error>
    where
        F: FnMut(&mut Self) -> Result<Option<u32>, Error>,
    {
        let start = self.clock.now_us();
        loop {
            if let Some(v) = f(self)? {
                return Ok(v);
            }
            if self.clock.now_us().saturating_sub(start) >= timeout_us as u64 {
                return Err(Error::Timeout(what));
            }
            self.clock.pause_us(POLL_US);
        }
    }

    /// `STS` once `stsValid` is set.
    fn wait_valid(&mut self, timeout_us: u32) -> Result<u32, Error> {
        self.poll(Wait::StsValid, timeout_us, |t| {
            let s = t.status()?;
            Ok(if s as u8 & sts::VALID != 0 { Some(s) } else { None })
        })
    }

    /// `STS` once it is valid and `burstCount` is non-zero.
    fn wait_burst(&mut self) -> Result<u32, Error> {
        let a = self.timeouts.a_us;
        self.poll(Wait::Burst, a, |t| {
            let s = t.status()?;
            Ok(if s as u8 & sts::VALID != 0 && sts_burst(s) != 0 { Some(s) } else { None })
        })
    }

    /// Read the identity registers and check there is a TPM 2.0 behind them.
    pub fn probe(&mut self) -> Result<DeviceInfo, Error> {
        if self.locality > MAX_LOCALITY {
            return Err(Error::BadLocality);
        }
        let a = self.timeouts.a_us;
        self.poll(Wait::StsValid, a, |t| {
            let v = t.rd8(REG_ACCESS)?;
            Ok(if v != 0xFF && v & access::VALID != 0 { Some(v as u32) } else { None })
        })
        .map_err(|e| if matches!(e, Error::Timeout(_)) { Error::NoDevice } else { e })?;
        self.request_locality()?;
        let r = self.probe_active();
        let rel = self.release_locality();
        let info = r?;
        rel?;
        Ok(info)
    }

    fn probe_active(&mut self) -> Result<DeviceInfo, Error> {
        let s = self.status()?;
        if sts_family(s) != 1 {
            return Err(Error::NotTpm2);
        }
        let didvid = self.rd32(REG_DID_VID)?;
        let rid = self.rd8(REG_RID)?;
        Ok(DeviceInfo { vid: didvid as u16, did: (didvid >> 16) as u16, rid })
    }

    fn request_locality(&mut self) -> Result<(), Error> {
        if self.locality > MAX_LOCALITY {
            return Err(Error::BadLocality);
        }
        let acc = self.rd8(REG_ACCESS)?;
        if acc == 0xFF {
            return Err(Error::NoDevice);
        }
        const BOTH: u8 = access::VALID | access::ACTIVE;
        if acc & BOTH == BOTH {
            return Ok(());
        }
        self.wr(REG_ACCESS, &[access::REQUEST_USE])?;
        let a = self.timeouts.a_us;
        self.poll(Wait::Locality, a, |t| {
            let v = t.rd8(REG_ACCESS)?;
            Ok(if v & BOTH == BOTH { Some(v as u32) } else { None })
        })
        .map(|_| ())
    }

    fn release_locality(&mut self) -> Result<(), Error> {
        if cfg!(feature = "canary-release") {
            return Ok(());
        }
        const BOTH: u8 = access::VALID | access::ACTIVE;
        let acc = self.rd8(REG_ACCESS)?;
        if acc != 0xFF && acc & BOTH == BOTH {
            self.wr(REG_ACCESS, &[access::ACTIVE])?;
        }
        Ok(())
    }

    /// Send `cmd`, put the response in `rsp`, return its length. The command's
    /// size field must equal `cmd.len()`; the response's size field is checked
    /// against 10 and `rsp.len()` before any byte past the header is read.
    pub fn transmit(&mut self, cmd: &[u8], rsp: &mut [u8], dur: Duration) -> Result<usize, Error> {
        if cmd.len() < HEADER_BYTES
            || cmd.len() > CMD_MAX
            || u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]) as usize != cmd.len()
        {
            return Err(Error::BadCommand);
        }
        self.request_locality()?;
        let r = self.exchange(cmd, rsp, dur);
        if r.is_err() {
            // Abort whatever state the TPM is in; the next command starts clean.
            let _ = self.wr(REG_STS, &[sts::CMD_READY]);
        }
        let rel = self.release_locality();
        let n = r?;
        rel?;
        Ok(n)
    }

    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8], dur: Duration) -> Result<usize, Error> {
        let t = self.timeouts;
        // Idle -> Ready.
        let s = self.status()?;
        if s as u8 & sts::CMD_READY == 0 {
            self.wr(REG_STS, &[sts::CMD_READY])?;
            self.poll(Wait::CommandReady, t.b_us, |x| {
                let s = x.status()?;
                Ok(if s as u8 & sts::CMD_READY != 0 { Some(s) } else { None })
            })?;
        }
        // The command, the last byte held back until `expect` says more is due.
        let last = cmd.len() - 1;
        let mut sent = 0;
        while sent < last {
            let s = self.wait_burst()?;
            let mut n = (sts_burst(s) as usize).min(last - sent);
            if cfg!(feature = "canary-burst") {
                n = last - sent;
            }
            self.wr(REG_DATA_FIFO, &cmd[sent..sent + n])?;
            sent += n;
            let s = self.wait_valid(t.c_us)?;
            if !cfg!(feature = "canary-expect") && s as u8 & sts::EXPECT == 0 {
                return Err(Error::ExpectMismatch);
            }
        }
        self.wait_burst()?;
        self.wr(REG_DATA_FIFO, &cmd[last..])?;
        let s = self.wait_valid(t.c_us)?;
        if s as u8 & sts::EXPECT != 0 {
            return Err(Error::ExpectMismatch);
        }
        self.wr(REG_STS, &[sts::GO])?;
        // Execution.
        self.poll(Wait::DataAvail, dur.us(), |x| {
            let s = x.status()?;
            let want = sts::VALID | sts::DATA_AVAIL;
            Ok(if s as u8 & want == want { Some(s) } else { None })
        })?;
        // The response: header first, then the size it declares.
        let mut hdr = [0u8; HEADER_BYTES];
        self.recv(&mut hdr)?;
        let total = u32::from_be_bytes([hdr[2], hdr[3], hdr[4], hdr[5]]) as usize;
        if total < HEADER_BYTES || (!cfg!(feature = "canary-rspsize") && total > rsp.len()) {
            return Err(Error::BadResponseSize);
        }
        rsp[..HEADER_BYTES].copy_from_slice(&hdr);
        self.recv(&mut rsp[HEADER_BYTES..total])?;
        let s = self.wait_valid(t.c_us)?;
        if s as u8 & sts::DATA_AVAIL != 0 {
            return Err(Error::TrailingData);
        }
        // Back to idle for the next command.
        self.wr(REG_STS, &[sts::CMD_READY])?;
        Ok(total)
    }

    /// Fill `buf` from the FIFO, a burst at a time, `dataAvail` required
    /// before every burst.
    fn recv(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        let mut got = 0;
        while got < buf.len() {
            let s = self.wait_burst()?;
            if s as u8 & sts::DATA_AVAIL == 0 {
                return Err(Error::Truncated);
            }
            let n = (sts_burst(s) as usize).min(buf.len() - got);
            self.rd(REG_DATA_FIFO, &mut buf[got..got + n])?;
            got += n;
        }
        Ok(())
    }
}
