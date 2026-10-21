// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The primitives of the Zenoh wire format: variable-length integers, length
//! prefixed byte arrays and strings, the ZenohID, and the extension chain.
//!
//! [`Reader`] hands out slices of the input (nothing is copied, nothing is
//! allocated while decoding); [`Writer`] appends to a `Vec<u8>`.

use alloc::vec::Vec;

/// Why a byte string is not a message we understand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The input ends inside a field.
    Truncated,
    /// An integer does not fit the field it is read into (or written from).
    Overflow,
    /// A byte array is longer than its length prefix can express.
    TooLong,
    /// A string field is not UTF-8.
    BadUtf8,
    /// A ZenohID has a length outside 1..=16.
    BadZidLen,
    /// A field holds a value the protocol does not define.
    BadValue(&'static str),
    /// A message id we do not decode (OAM, JOIN, ...); the id is the header's low bits.
    Unsupported(u8),
    /// An extension header with the reserved encoding `0b11`.
    BadExtEnc,
    /// A mandatory extension (M bit) we do not know: the message must be refused.
    MandatoryExt(u8),
}

pub type Result<T> = core::result::Result<T, Error>;

/// The input side: a cursor over a byte string, consuming from the front.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Everything not consumed yet; the reader is empty afterwards.
    pub fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.buf)
    }

    pub fn peek(&self) -> Option<u8> {
        self.buf.first().copied()
    }

    pub fn u8(&mut self) -> Result<u8> {
        let (&b, rest) = self.buf.split_first().ok_or(Error::Truncated)?;
        self.buf = rest;
        Ok(b)
    }

    pub fn u16_le(&mut self) -> Result<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(Error::Truncated);
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(head)
    }

    /// A VLE integer: seven bits per byte, least significant group first, bit 7
    /// set while more bytes follow; a `u64` takes at most nine bytes, because
    /// the ninth carries all eight of its bits (7 x 8 + 8 = 64) and has no
    /// continuation flag. (zenoh-rust and zenoh-pico read and write it so; an
    /// NTP64 timestamp, whose bit 63 is set, is always nine bytes.)
    pub fn vle(&mut self) -> Result<u64> {
        let mut v: u64 = 0;
        for i in 0..8u32 {
            let b = self.u8()?;
            v |= ((b & 0x7F) as u64) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Ok(v | (self.u8()? as u64) << 56)
    }

    pub fn vle32(&mut self) -> Result<u32> {
        u32::try_from(self.vle()?).map_err(|_| Error::Overflow)
    }

    pub fn vle16(&mut self) -> Result<u16> {
        u16::try_from(self.vle()?).map_err(|_| Error::Overflow)
    }

    /// `<u8;z16>`: a VLE length (at most 65535) and that many bytes.
    pub fn z16(&mut self) -> Result<&'a [u8]> {
        let n = self.vle16()? as usize;
        self.bytes(n)
    }

    /// `<u8;z32>`: a VLE length (at most 2^32 - 1) and that many bytes.
    pub fn z32(&mut self) -> Result<&'a [u8]> {
        let n = self.vle32()? as usize;
        self.bytes(n)
    }

    /// `<u8;z8>`: a VLE length (at most 255) and that many bytes.
    pub fn z8(&mut self) -> Result<&'a [u8]> {
        let n = self.vle()?;
        if n > 0xFF {
            return Err(Error::Overflow);
        }
        self.bytes(n as usize)
    }

    pub fn str16(&mut self) -> Result<&'a str> {
        core::str::from_utf8(self.z16()?).map_err(|_| Error::BadUtf8)
    }

    pub fn zid(&mut self, len: usize) -> Result<Zid> {
        Zid::new(self.bytes(len)?)
    }
}

/// The output side: bytes appended to a `Vec<u8>`.
#[derive(Clone, Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn u8(&mut self, b: u8) {
        self.buf.push(b);
    }

    pub fn u16_le(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    pub fn vle(&mut self, mut v: u64) {
        // After eight groups what is left (at most 8 bits) is the ninth byte, whole.
        let mut groups = 0;
        while v > 0x7F && groups < 8 {
            self.buf.push((v as u8 & 0x7F) | 0x80);
            v >>= 7;
            groups += 1;
        }
        self.buf.push(v as u8);
    }

    pub fn z16(&mut self, b: &[u8]) -> Result<()> {
        if b.len() > u16::MAX as usize {
            return Err(Error::TooLong);
        }
        self.vle(b.len() as u64);
        self.bytes(b);
        Ok(())
    }

    pub fn z32(&mut self, b: &[u8]) -> Result<()> {
        if b.len() as u64 > u32::MAX as u64 {
            return Err(Error::TooLong);
        }
        self.vle(b.len() as u64);
        self.bytes(b);
        Ok(())
    }

    pub fn z8(&mut self, b: &[u8]) -> Result<()> {
        if b.len() > 0xFF {
            return Err(Error::TooLong);
        }
        self.vle(b.len() as u64);
        self.bytes(b);
        Ok(())
    }

    /// Position of the next byte; a header written at `pos()` can be patched
    /// later with [`Writer::set_flags`].
    pub fn pos(&self) -> usize {
        self.buf.len()
    }

    /// OR `mask` into the byte at `pos` (a header written earlier).
    pub fn set_flags(&mut self, pos: usize, mask: u8) {
        self.buf[pos] |= mask;
    }
}

/// A ZenohID: 1 to 16 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Zid {
    len: u8,
    bytes: [u8; 16],
}

impl Zid {
    pub fn new(b: &[u8]) -> Result<Zid> {
        if b.is_empty() || b.len() > 16 {
            return Err(Error::BadZidLen);
        }
        let mut bytes = [0u8; 16];
        bytes[..b.len()].copy_from_slice(b);
        Ok(Zid { len: b.len() as u8, bytes })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// The length minus one, which is what the four bits of a header carry.
    pub(crate) fn nibble(&self) -> u8 {
        self.len - 1
    }
}

// ---- extensions -----------------------------------------------------------

/// The Z flag of every header: an extension chain follows.
pub(crate) const Z: u8 = 0x80;

pub(crate) enum ExtBody<'a> {
    Unit,
    Z64(u64),
    ZBuf(&'a [u8]),
}

/// One extension of a chain: `|Z|ENC|M|ID|`, then the body ENC selects.
pub(crate) struct Ext<'a> {
    pub id: u8,
    pub mandatory: bool,
    pub body: ExtBody<'a>,
}

/// Walk an extension chain. `f` returns `Ok(true)` for an extension it took,
/// `Ok(false)` for one it does not know: unknown extensions are skipped, unless
/// mandatory, which refuses the message.
pub(crate) fn read_exts<'a>(
    r: &mut Reader<'a>,
    mut f: impl FnMut(&Ext<'a>) -> Result<bool>,
) -> Result<()> {
    loop {
        let h = r.u8()?;
        let body = match (h >> 5) & 3 {
            0 => ExtBody::Unit,
            1 => ExtBody::Z64(r.vle()?),
            2 => ExtBody::ZBuf(r.z32()?),
            _ => return Err(Error::BadExtEnc),
        };
        let ext = Ext { id: h & 0x0F, mandatory: h & 0x10 != 0, body };
        if !f(&ext)? && ext.mandatory {
            return Err(Error::MandatoryExt(ext.id));
        }
        if h & Z == 0 {
            return Ok(());
        }
    }
}

/// Writes a chain: each extension's header has its Z bit set when another
/// follows. The message header's own Z bit is set by [`ExtWriter::finish`].
pub(crate) struct ExtWriter {
    header_pos: usize,
    last: Option<usize>,
}

impl ExtWriter {
    /// `header_pos`: where the message header (whose Z flag this chain owns) was written.
    pub fn new(header_pos: usize) -> Self {
        ExtWriter { header_pos, last: None }
    }

    fn head(&mut self, w: &mut Writer, enc: u8, mandatory: bool, id: u8) {
        if let Some(p) = self.last {
            w.set_flags(p, Z);
        }
        self.last = Some(w.pos());
        w.u8((enc << 5) | ((mandatory as u8) << 4) | (id & 0x0F));
    }

    pub fn unit(&mut self, w: &mut Writer, id: u8, mandatory: bool) {
        self.head(w, 0, mandatory, id);
    }

    pub fn z64(&mut self, w: &mut Writer, id: u8, mandatory: bool, v: u64) {
        self.head(w, 1, mandatory, id);
        w.vle(v);
    }

    pub fn zbuf(&mut self, w: &mut Writer, id: u8, mandatory: bool, b: &[u8]) -> Result<()> {
        self.head(w, 2, mandatory, id);
        w.z32(b)
    }

    /// Set the message header's Z flag when the chain is not empty.
    pub fn finish(self, w: &mut Writer) {
        if self.last.is_some() {
            w.set_flags(self.header_pos, Z);
        }
    }
}
