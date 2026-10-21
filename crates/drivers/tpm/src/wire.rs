// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! TPM 2.0 wire structures: big-endian everywhere.
//!
//! [`Cmd`] builds a command in a fixed buffer and patches the size field when
//! finished; [`Reader`] takes a response apart and never slices by a number it
//! read from the wire without checking it against what is left.

use crate::tis::{CMD_MAX, HEADER_BYTES};
use crate::Error;

pub const ST_NO_SESSIONS: u16 = 0x8001;
pub const ST_SESSIONS: u16 = 0x8002;

pub const CC_NV_DEFINE_SPACE: u32 = 0x0000_012A;
pub const CC_NV_WRITE: u32 = 0x0000_0137;
pub const CC_STARTUP: u32 = 0x0000_0144;
pub const CC_NV_READ: u32 = 0x0000_014E;
pub const CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
pub const CC_GET_RANDOM: u32 = 0x0000_017B;
pub const CC_PCR_READ: u32 = 0x0000_017E;
pub const CC_PCR_EXTEND: u32 = 0x0000_0182;

pub const RC_SUCCESS: u32 = 0;
/// `TPM_RC_INITIALIZE`: Startup was already done since reset.
pub const RC_INITIALIZE: u32 = 0x0000_0100;
/// `TPM_RC_NV_UNINITIALIZED`: the index is defined, never written.
pub const RC_NV_UNINITIALIZED: u32 = 0x0000_014A;
/// `TPM_RC_NV_DEFINED`: the index already exists.
pub const RC_NV_DEFINED: u32 = 0x0000_014C;

pub const ALG_SHA256: u16 = 0x000B;
pub const RH_OWNER: u32 = 0x4000_0001;
pub const RS_PW: u32 = 0x4000_0009;

/// A command under construction. Overflow is remembered and reported by
/// [`Cmd::finish`], so the builders stay straight-line.
pub struct Cmd {
    buf: [u8; CMD_MAX],
    len: usize,
    over: bool,
}

impl Cmd {
    pub fn new(tag: u16, cc: u32) -> Cmd {
        let mut c = Cmd { buf: [0; CMD_MAX], len: 0, over: false };
        c.u16(tag);
        c.u32(0);
        c.u32(cc);
        c
    }

    pub fn u8(&mut self, v: u8) {
        self.bytes(&[v]);
    }

    pub fn u16(&mut self, v: u16) {
        self.bytes(&v.to_be_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.bytes(&v.to_be_bytes());
    }

    pub fn bytes(&mut self, b: &[u8]) {
        if self.len + b.len() > CMD_MAX {
            self.over = true;
            return;
        }
        self.buf[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
    }

    /// A `TPM2B_*`: u16 length, then the bytes.
    pub fn tpm2b(&mut self, b: &[u8]) {
        if b.len() > u16::MAX as usize {
            self.over = true;
            return;
        }
        self.u16(b.len() as u16);
        self.bytes(b);
    }

    /// The authorization area of one password session (`TPM_RS_PW`, empty
    /// nonce, `continueSession`, `auth` as the HMAC field).
    pub fn pw_auth(&mut self, auth: &[u8]) {
        self.u32((4 + 2 + 1 + 2 + auth.len()) as u32);
        self.u32(RS_PW);
        self.u16(0);
        self.u8(1);
        self.tpm2b(auth);
    }

    pub fn finish(mut self) -> Result<Cmd, Error> {
        if self.over || self.len < HEADER_BYTES {
            return Err(Error::BadCommand);
        }
        let n = self.len as u32;
        self.buf[2..6].copy_from_slice(&n.to_be_bytes());
        Ok(self)
    }

    pub fn bytes_out(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Bounds-checked big-endian reader.
pub struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Reader { b }
    }

    pub fn remaining(&self) -> usize {
        self.b.len()
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.b.len() {
            return Err(Error::Malformed);
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }

    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, Error> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, Error> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A `TPM2B_*`: its bytes, the length checked against what is left.
    pub fn tpm2b(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()? as usize;
        self.bytes(n)
    }
}

/// Check a whole response against the tag the request implies and return the
/// bytes after the header. A non-zero response code is `Err(Tpm(rc))`
/// whatever the tag; a success must carry `want_tag`.
pub fn parse_response(rsp: &[u8], want_tag: u16) -> Result<&[u8], Error> {
    let mut r = Reader::new(rsp);
    let tag = r.u16().map_err(|_| Error::BadResponseSize)?;
    let size = r.u32().map_err(|_| Error::BadResponseSize)? as usize;
    let rc = r.u32().map_err(|_| Error::BadResponseSize)?;
    if size != rsp.len() {
        return Err(Error::Malformed);
    }
    if rc != RC_SUCCESS {
        return Err(Error::Tpm(rc));
    }
    if tag != want_tag {
        return Err(Error::Malformed);
    }
    Ok(&rsp[HEADER_BYTES..])
}

/// A successful session response: `parameterSize`, the parameters, then the
/// response auth area. Returns the parameters; the auth area is bounded and
/// otherwise ignored (password sessions carry nothing to verify).
pub fn session_params(body: &[u8]) -> Result<&[u8], Error> {
    let mut r = Reader::new(body);
    let n = r.u32()? as usize;
    let params = r.bytes(n)?;
    Ok(params)
}
