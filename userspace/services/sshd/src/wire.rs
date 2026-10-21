// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The data types of the SSH wire format (RFC 4251 section 5) and the message
//! numbers this server speaks (RFC 4253, 4252, 4254).
//!
//! `Reader` never panics and never reads past its slice: every accessor
//! returns `None` at the end, so a truncated packet is a refusal, not a fault.

use alloc::vec::Vec;

// ── Message numbers ─────────────────────────────────────────────────────────
pub const MSG_DISCONNECT: u8 = 1;
pub const MSG_IGNORE: u8 = 2;
pub const MSG_UNIMPLEMENTED: u8 = 3;
pub const MSG_DEBUG: u8 = 4;
pub const MSG_SERVICE_REQUEST: u8 = 5;
pub const MSG_SERVICE_ACCEPT: u8 = 6;
pub const MSG_KEXINIT: u8 = 20;
pub const MSG_NEWKEYS: u8 = 21;
pub const MSG_KEX_ECDH_INIT: u8 = 30;
pub const MSG_KEX_ECDH_REPLY: u8 = 31;
pub const MSG_USERAUTH_REQUEST: u8 = 50;
pub const MSG_USERAUTH_FAILURE: u8 = 51;
pub const MSG_USERAUTH_SUCCESS: u8 = 52;
pub const MSG_USERAUTH_PK_OK: u8 = 60;
pub const MSG_GLOBAL_REQUEST: u8 = 80;
pub const MSG_REQUEST_FAILURE: u8 = 82;
pub const MSG_CHANNEL_OPEN: u8 = 90;
pub const MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
pub const MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const MSG_CHANNEL_DATA: u8 = 94;
pub const MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
pub const MSG_CHANNEL_EOF: u8 = 96;
pub const MSG_CHANNEL_CLOSE: u8 = 97;
pub const MSG_CHANNEL_REQUEST: u8 = 98;
pub const MSG_CHANNEL_SUCCESS: u8 = 99;
pub const MSG_CHANNEL_FAILURE: u8 = 100;

// ── Disconnect reason codes (RFC 4253 section 11.1) ────────────────────────
pub const DISCONNECT_PROTOCOL_ERROR: u32 = 2;
pub const DISCONNECT_KEY_EXCHANGE_FAILED: u32 = 3;
pub const DISCONNECT_SERVICE_NOT_AVAILABLE: u32 = 7;
pub const DISCONNECT_NO_MORE_AUTH_METHODS: u32 = 14;
pub const DISCONNECT_BY_APPLICATION: u32 = 11;

/// A cursor over a received payload.
pub struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, at: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.b.len() - self.at
    }

    pub fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.at)?;
        self.at += 1;
        Some(v)
    }

    pub fn boolean(&mut self) -> Option<bool> {
        self.u8().map(|v| v != 0)
    }

    pub fn u32(&mut self) -> Option<u32> {
        let s = self.b.get(self.at..self.at.checked_add(4)?)?;
        self.at += 4;
        Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// `string`: a length and that many bytes.
    pub fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        let end = self.at.checked_add(n)?;
        let s = self.b.get(self.at..end)?;
        self.at = end;
        Some(s)
    }

    /// Skip `n` bytes.
    pub fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.at.checked_add(n)?;
        (end <= self.b.len()).then(|| self.at = end)
    }

}

/// A payload being built.
#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn new(msg: u8) -> Self {
        Self { buf: alloc::vec![msg] }
    }

    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn boolean(&mut self, v: bool) -> &mut Self {
        self.u8(v as u8)
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn string(&mut self, b: &[u8]) -> &mut Self {
        self.u32(b.len() as u32);
        self.raw(b)
    }

    /// `mpint` of the unsigned big-endian integer `be`: leading zeros dropped,
    /// a zero byte put in front when the top bit is set (RFC 4251 section 5).
    pub fn mpint(&mut self, be: &[u8]) -> &mut Self {
        let mut s = be;
        while let [0, rest @ ..] = s {
            s = rest;
        }
        let pad = matches!(s.first(), Some(b) if b & 0x80 != 0);
        self.u32(s.len() as u32 + pad as u32);
        if pad {
            self.u8(0);
        }
        self.raw(s)
    }

    /// `name-list`: names joined by commas.
    pub fn name_list(&mut self, names: &[&str]) -> &mut Self {
        let n: usize = names.iter().map(|s| s.len()).sum::<usize>() + names.len().saturating_sub(1);
        self.u32(n as u32);
        for (i, s) in names.iter().enumerate() {
            if i > 0 {
                self.u8(b',');
            }
            self.raw(s.as_bytes());
        }
        self
    }
}

/// Is `name` one of the comma-separated entries of `list`?
pub fn list_has(list: &[u8], name: &str) -> bool {
    list.split(|&c| c == b',').any(|e| e == name.as_bytes())
}

/// The first entry of `list`.
pub fn list_first(list: &[u8]) -> &[u8] {
    list.split(|&c| c == b',').next().unwrap_or(&[])
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64, no padding (the form of a `SHA256:` fingerprint).
pub fn base64_nopad(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(B64[(n >> 18) as usize & 63]);
        out.push(B64[(n >> 12) as usize & 63]);
        if c.len() > 1 {
            out.push(B64[(n >> 6) as usize & 63]);
        }
        if c.len() > 2 {
            out.push(B64[n as usize & 63]);
        }
    }
    out
}
