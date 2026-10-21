// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! EtherCAT frame and datagram codec (ETG.1000.4 section 5).
//!
//! ```text
//! Ethernet II   dst[6] src[6] ethertype 0x88A4 (big endian)
//! EtherCAT hdr  u16 LE: bits 0..10 length of the datagrams, bit 11 reserved,
//!               bits 12..15 type (1 = datagrams)
//! datagram      cmd u8, idx u8, address u32 LE, len/flags u16 LE
//!               (bits 0..10 len, 14 circulating, 15 more), irq u16 LE,
//!               data[len], wkc u16 LE
//! ```
//!
//! The frame is padded with zeros to the 60-byte Ethernet minimum (FCS is the
//! NIC's); the EtherCAT length field does not count the padding.

use crate::Error;

/// EtherType carried in the Ethernet II header.
pub const ETHERTYPE: u16 = 0x88A4;
/// Ethernet II header: dst, src, type.
pub const ETH_HDR_LEN: usize = 14;
/// The u16 EtherCAT frame header.
pub const ECAT_HDR_LEN: usize = 2;
/// Datagram header: cmd, idx, address, len/flags, irq.
pub const DG_HDR_LEN: usize = 10;
/// Working counter, after the data.
pub const WKC_LEN: usize = 2;
/// Fixed bytes a datagram costs on top of its data.
pub const DG_OVERHEAD: usize = DG_HDR_LEN + WKC_LEN;
/// Most datagram bytes one frame carries (1500 minus the EtherCAT header).
pub const MAX_PAYLOAD: usize = 1498;
/// Largest frame this codec produces, without FCS.
pub const MAX_FRAME: usize = ETH_HDR_LEN + ECAT_HDR_LEN + MAX_PAYLOAD;
/// Ethernet minimum frame without FCS; shorter frames are zero padded.
pub const MIN_FRAME: usize = 60;
/// Offset of the first datagram in a frame.
pub const FIRST_DG_OFFSET: usize = ETH_HDR_LEN + ECAT_HDR_LEN;
/// The destination MAC masters use: every slave forwards it.
pub const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

const FRAME_TYPE_DATAGRAMS: u8 = 1;
const LEN_MASK: u16 = 0x07FF;
const FLAG_CIRCULATING: u16 = 1 << 14;
const FLAG_MORE: u16 = 1 << 15;

/// How a command picks the slaves it acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addressing {
    /// No slave (NOP).
    None,
    /// Auto-increment position: `ADP` counts down from 0 at each slave, the
    /// slave that sees 0 acts. A master addresses position `n` with `-n`.
    Position,
    /// Configured station address set in register 0x0010.
    Node,
    /// Every slave.
    Broadcast,
    /// 32-bit logical address, resolved by each slave's FMMUs.
    Logical,
}

/// The EtherCAT command set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cmd {
    Nop = 0,
    Aprd = 1,
    Apwr = 2,
    Aprw = 3,
    Fprd = 4,
    Fpwr = 5,
    Fprw = 6,
    Brd = 7,
    Bwr = 8,
    Brw = 9,
    Lrd = 10,
    Lwr = 11,
    Lrw = 12,
    /// Auto-increment read the reference clock, write everyone else.
    Armw = 13,
    /// Configured-address variant of [`Cmd::Armw`].
    Frmw = 14,
}

impl Cmd {
    /// Decode a command byte.
    pub fn from_u8(v: u8) -> Result<Cmd, Error> {
        Ok(match v {
            0 => Cmd::Nop,
            1 => Cmd::Aprd,
            2 => Cmd::Apwr,
            3 => Cmd::Aprw,
            4 => Cmd::Fprd,
            5 => Cmd::Fpwr,
            6 => Cmd::Fprw,
            7 => Cmd::Brd,
            8 => Cmd::Bwr,
            9 => Cmd::Brw,
            10 => Cmd::Lrd,
            11 => Cmd::Lwr,
            12 => Cmd::Lrw,
            13 => Cmd::Armw,
            14 => Cmd::Frmw,
            other => return Err(Error::UnknownCmd(other)),
        })
    }

    /// Which slaves the address field selects.
    pub fn addressing(self) -> Addressing {
        match self {
            Cmd::Nop => Addressing::None,
            Cmd::Aprd | Cmd::Apwr | Cmd::Aprw | Cmd::Armw => Addressing::Position,
            Cmd::Fprd | Cmd::Fpwr | Cmd::Fprw | Cmd::Frmw => Addressing::Node,
            Cmd::Brd | Cmd::Bwr | Cmd::Brw => Addressing::Broadcast,
            Cmd::Lrd | Cmd::Lwr | Cmd::Lrw => Addressing::Logical,
        }
    }

    /// The command copies slave memory into the datagram.
    pub fn reads(self) -> bool {
        matches!(
            self,
            Cmd::Aprd | Cmd::Aprw | Cmd::Fprd | Cmd::Fprw | Cmd::Brd | Cmd::Brw
                | Cmd::Lrd | Cmd::Lrw | Cmd::Armw | Cmd::Frmw
        )
    }

    /// The command copies the datagram into slave memory.
    pub fn writes(self) -> bool {
        matches!(
            self,
            Cmd::Apwr | Cmd::Aprw | Cmd::Fpwr | Cmd::Fprw | Cmd::Bwr | Cmd::Brw
                | Cmd::Lwr | Cmd::Lrw | Cmd::Armw | Cmd::Frmw
        )
    }
}

/// The 4-byte address field of a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Addr(pub u32);

impl Addr {
    /// Auto-increment address of the slave at `position` (0 is the first one on
    /// the wire), register offset `ado`.
    pub fn position(position: u16, ado: u16) -> Addr {
        Addr(u32::from(0u16.wrapping_sub(position)) | (u32::from(ado) << 16))
    }

    /// Configured station address `station`, register offset `ado`.
    pub fn node(station: u16, ado: u16) -> Addr {
        Addr(u32::from(station) | (u32::from(ado) << 16))
    }

    /// Broadcast: `ado` is the register offset, the position part is 0.
    pub fn broadcast(ado: u16) -> Addr {
        Addr(u32::from(ado) << 16)
    }

    /// 32-bit logical address.
    pub fn logical(addr: u32) -> Addr {
        Addr(addr)
    }

    /// The `ADP` half: position or station address.
    pub fn adp(self) -> u16 {
        self.0 as u16
    }

    /// The `ADO` half: register offset.
    pub fn ado(self) -> u16 {
        (self.0 >> 16) as u16
    }
}

/// One datagram as parsed out of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Datagram<'a> {
    pub cmd: Cmd,
    /// Master-chosen index, echoed back unchanged: how a reply finds its request.
    pub idx: u8,
    pub addr: Addr,
    /// Set by a slave that saw the datagram twice (a broken ring).
    pub circulating: bool,
    pub more: bool,
    pub irq: u16,
    pub data: &'a [u8],
    /// Working counter: how many slaves acted.
    pub wkc: u16,
    /// Offset of `data[0]` inside the frame buffer, so a cyclic master can
    /// rewrite process data in place and read replies without a copy.
    pub data_offset: usize,
}

/// A parsed frame: the MACs and the datagram area.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Iterate the datagram chain, checking it against the frame length.
    pub fn datagrams(&self) -> Datagrams<'a> {
        Datagrams { buf: self.payload, pos: 0, done: self.payload.is_empty() }
    }
}

/// Parse the Ethernet and EtherCAT headers. The datagrams are checked lazily by
/// [`Frame::datagrams`].
pub fn parse(buf: &[u8]) -> Result<Frame<'_>, Error> {
    if buf.len() < FIRST_DG_OFFSET {
        return Err(Error::Truncated);
    }
    if u16::from_be_bytes([buf[12], buf[13]]) != ETHERTYPE {
        return Err(Error::NotEthercat);
    }
    let hdr = u16::from_le_bytes([buf[ETH_HDR_LEN], buf[ETH_HDR_LEN + 1]]);
    let ty = (hdr >> 12) as u8;
    if ty != FRAME_TYPE_DATAGRAMS {
        return Err(Error::UnsupportedType(ty));
    }
    let len = usize::from(hdr & LEN_MASK);
    let end = FIRST_DG_OFFSET + len;
    if end > buf.len() {
        return Err(Error::Truncated);
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&buf[0..6]);
    src.copy_from_slice(&buf[6..12]);
    Ok(Frame { dst, src, payload: &buf[FIRST_DG_OFFSET..end] })
}

/// Iterator over the datagrams of a [`Frame`]. After the first error it ends.
pub struct Datagrams<'a> {
    buf: &'a [u8],
    pos: usize,
    done: bool,
}

impl<'a> Iterator for Datagrams<'a> {
    type Item = Result<Datagram<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let r = self.step();
        if r.is_err() {
            self.done = true;
        }
        Some(r)
    }
}

impl<'a> Datagrams<'a> {
    fn step(&mut self) -> Result<Datagram<'a>, Error> {
        let b = &self.buf[self.pos..];
        if b.len() < DG_OVERHEAD {
            return Err(Error::Truncated);
        }
        let cmd = Cmd::from_u8(b[0])?;
        let lf = u16::from_le_bytes([b[6], b[7]]);
        let len = usize::from(lf & LEN_MASK);
        if b.len() < DG_OVERHEAD + len {
            return Err(Error::Truncated);
        }
        let more = lf & FLAG_MORE != 0;
        let dg = Datagram {
            cmd,
            idx: b[1],
            addr: Addr(u32::from_le_bytes([b[2], b[3], b[4], b[5]])),
            circulating: lf & FLAG_CIRCULATING != 0,
            more,
            irq: u16::from_le_bytes([b[8], b[9]]),
            data: &b[DG_HDR_LEN..DG_HDR_LEN + len],
            wkc: u16::from_le_bytes([b[DG_HDR_LEN + len], b[DG_HDR_LEN + len + 1]]),
            data_offset: FIRST_DG_OFFSET + self.pos + DG_HDR_LEN,
        };
        self.pos += DG_OVERHEAD + len;
        let at_end = self.pos == self.buf.len();
        match (more, at_end) {
            (false, true) => self.done = true,
            (true, false) => {}
            _ => return Err(Error::BadChain),
        }
        Ok(dg)
    }
}

/// Builds one frame in a caller buffer. Every byte the frame covers is written,
/// so the buffer need not be clean.
pub struct FrameBuilder<'a> {
    buf: &'a mut [u8],
    /// Datagram bytes so far (the value of the EtherCAT length field).
    dg_len: usize,
    /// Offset of the last datagram's header, to set its "more" bit.
    last_hdr: Option<usize>,
}

impl<'a> FrameBuilder<'a> {
    /// Start a frame from `src` to `dst` (masters use [`BROADCAST_MAC`]).
    pub fn new(buf: &'a mut [u8], dst: [u8; 6], src: [u8; 6]) -> Result<Self, Error> {
        if buf.len() < MIN_FRAME {
            return Err(Error::BufferTooSmall);
        }
        buf[0..6].copy_from_slice(&dst);
        buf[6..12].copy_from_slice(&src);
        buf[12..14].copy_from_slice(&ETHERTYPE.to_be_bytes());
        Ok(FrameBuilder { buf, dg_len: 0, last_hdr: None })
    }

    /// Append a datagram with `data` (for a pure read the content is ignored
    /// by slaves; pass zeros). Returns the offset of its data in the frame.
    pub fn push(&mut self, cmd: Cmd, idx: u8, addr: Addr, data: &[u8]) -> Result<usize, Error> {
        let off = self.reserve(cmd, idx, addr, data.len())?;
        self.buf[off..off + data.len()].copy_from_slice(data);
        Ok(off)
    }

    /// Append a datagram whose `len` data bytes are zero: a read, or a write of
    /// zeros. Returns the offset of its data in the frame.
    pub fn push_zeroed(&mut self, cmd: Cmd, idx: u8, addr: Addr, len: usize) -> Result<usize, Error> {
        let off = self.reserve(cmd, idx, addr, len)?;
        self.buf[off..off + len].fill(0);
        Ok(off)
    }

    fn reserve(&mut self, cmd: Cmd, idx: u8, addr: Addr, len: usize) -> Result<usize, Error> {
        if len > usize::from(LEN_MASK) || self.dg_len + DG_OVERHEAD + len > MAX_PAYLOAD {
            return Err(Error::TooLong);
        }
        let hdr = FIRST_DG_OFFSET + self.dg_len;
        let end = hdr + DG_OVERHEAD + len;
        if end > self.buf.len() {
            return Err(Error::BufferTooSmall);
        }
        if let Some(prev) = self.last_hdr {
            self.buf[prev + 7] |= (FLAG_MORE >> 8) as u8;
        }
        self.buf[hdr] = cmd as u8;
        self.buf[hdr + 1] = idx;
        self.buf[hdr + 2..hdr + 6].copy_from_slice(&addr.0.to_le_bytes());
        self.buf[hdr + 6..hdr + 8].copy_from_slice(&(len as u16).to_le_bytes());
        self.buf[hdr + 8..hdr + 10].fill(0);
        self.buf[end - WKC_LEN..end].fill(0);
        self.last_hdr = Some(hdr);
        self.dg_len += DG_OVERHEAD + len;
        Ok(hdr + DG_HDR_LEN)
    }

    /// Seal the frame: write the EtherCAT header, zero-pad to the Ethernet
    /// minimum, return the frame length.
    pub fn finish(self) -> Result<usize, Error> {
        if self.last_hdr.is_none() {
            return Err(Error::Empty);
        }
        let hdr = (self.dg_len as u16) | (u16::from(FRAME_TYPE_DATAGRAMS) << 12);
        self.buf[ETH_HDR_LEN..FIRST_DG_OFFSET].copy_from_slice(&hdr.to_le_bytes());
        let used = FIRST_DG_OFFSET + self.dg_len;
        if used >= MIN_FRAME {
            return Ok(used);
        }
        self.buf[used..MIN_FRAME].fill(0);
        Ok(MIN_FRAME)
    }
}
