// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The binary packet protocol (RFC 4253 section 6) and the one cipher this
//! server offers, `chacha20-poly1305@openssh.com` (PROTOCOL.chacha20poly1305).
//!
//! Before the first NEWKEYS a packet is `uint32 length | byte padding | payload
//! | padding`, in the clear. After it, with the AEAD cipher:
//!
//! ```text
//! enc_len(4) | enc(padding_length | payload | padding) | tag(16)
//! ```
//!
//! The 64 key bytes are two ChaCha20 keys: `K_2` (the first 32) protects the
//! payload and, at block counter 0, derives the Poly1305 key; `K_1` (the last
//! 32) protects the length field. The nonce is the packet's sequence number as
//! eight big-endian bytes (the 12-byte IETF nonce with four zero bytes in
//! front). The tag is Poly1305 over `enc_len || enc(...)`, with no padding of
//! the message. The length is not part of the block alignment: the bytes after
//! it add up to a multiple of 8.
//!
//! Sequence numbers are 32 bits and count every packet of the connection, key
//! changes included (strict key exchange resets them: [`Rx::reset_seq`]).
//! They are never reused under one key: an endpoint that reaches `u32::MAX`
//! refuses to send or receive another packet.

use alloc::vec::Vec;
use azos_crypto::chachapoly::{chacha20_block, chacha20_xor, poly1305, TAG_LEN};
use azos_crypto::ct::{ct_eq, secure_zero};

/// The largest `packet_length` accepted. RFC 4253 section 6.1 requires 35000.
pub const MAX_PACKET: usize = 35000;
/// The largest payload accepted (RFC 4253: at least 32768).
pub const MAX_PAYLOAD: usize = 32768 + 1024;
const BLOCK: usize = 8;
const MIN_PAD: usize = 4;

/// The 64 key bytes of `chacha20-poly1305@openssh.com`.
#[derive(Clone)]
pub struct Key {
    k_main: [u8; 32],
    k_header: [u8; 32],
}

impl Key {
    pub fn new(material: &[u8; 64]) -> Self {
        let mut k_main = [0u8; 32];
        let mut k_header = [0u8; 32];
        k_main.copy_from_slice(&material[..32]);
        k_header.copy_from_slice(&material[32..]);
        Self { k_main, k_header }
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        secure_zero(&mut self.k_main);
        secure_zero(&mut self.k_header);
    }
}

/// The IETF nonce of packet number `seq`.
fn nonce(seq: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[8..].copy_from_slice(&seq.to_be_bytes());
    n
}

/// The Poly1305 key of packet `seq`: the first 32 bytes of block 0 under `K_2`.
fn poly_key(key: &Key, seq: u32) -> [u8; 32] {
    let mut blk = chacha20_block(&key.k_main, 0, &nonce(seq));
    let mut k = [0u8; 32];
    k.copy_from_slice(&blk[..32]);
    secure_zero(&mut blk);
    k
}

/// Seal one packet: `payload` in, the bytes for the wire appended to `out`.
/// `seq` is the packet's sequence number. `None` for a payload over
/// [`MAX_PAYLOAD`].
pub fn seal(key: &Key, seq: u32, payload: &[u8], out: &mut Vec<u8>) -> Option<()> {
    if payload.len() > MAX_PAYLOAD {
        return None;
    }
    let pad = padding(payload.len(), 1);
    let len = 1 + payload.len() + pad;
    let start = out.len();
    out.extend_from_slice(&(len as u32).to_be_bytes());
    out.push(pad as u8);
    out.extend_from_slice(payload);
    out.resize(out.len() + pad, 0);
    let n = nonce(seq);
    chacha20_xor(&key.k_header, 0, &n, &mut out[start..start + 4]);
    chacha20_xor(&key.k_main, 1, &n, &mut out[start + 4..]);
    let mut pk = poly_key(key, seq);
    let tag = poly1305(&pk, &out[start..]);
    secure_zero(&mut pk);
    out.extend_from_slice(&tag);
    Some(())
}

/// Padding bytes for a payload of `n`, so that `head + n + padding` is a
/// multiple of 8 and padding is at least 4. `head` is 1 for the AEAD form
/// (the length field is outside the alignment) and 5 for the clear one.
fn padding(n: usize, head: usize) -> usize {
    let mut p = BLOCK - (head + n) % BLOCK;
    if p < MIN_PAD {
        p += BLOCK;
    }
    p
}

/// Frame `payload` in the clear (before the first NEWKEYS).
pub fn seal_plain(payload: &[u8], out: &mut Vec<u8>) -> Option<()> {
    if payload.len() > MAX_PAYLOAD {
        return None;
    }
    let pad = padding(payload.len(), 5);
    let len = 1 + payload.len() + pad;
    out.extend_from_slice(&(len as u32).to_be_bytes());
    out.push(pad as u8);
    out.extend_from_slice(payload);
    out.resize(out.len() + pad, 0);
    Some(())
}

/// Why a packet was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    /// The length or padding field is out of range.
    Malformed,
    /// The tag does not verify.
    Mac,
    /// The sequence number would wrap.
    SeqExhausted,
}

/// The receiving half: bytes in, payloads out.
pub struct Rx {
    key: Option<Key>,
    seq: u32,
    buf: Vec<u8>,
}

impl Default for Rx {
    fn default() -> Self {
        Self::new()
    }
}

impl Rx {
    pub const fn new() -> Self {
        Self { key: None, seq: 0, buf: Vec::new() }
    }

    /// Bytes of the connection that follow the packets already taken.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub fn set_key(&mut self, key: Key) {
        self.key = Some(key);
    }

    pub fn seq(&self) -> u32 {
        self.seq
    }

    pub fn reset_seq(&mut self) {
        self.seq = 0;
    }

    /// The next whole packet's payload, or `Ok(None)` if more bytes are
    /// needed. An `Err` ends the connection: nothing after it is read.
    pub fn next(&mut self) -> Result<Option<Vec<u8>>, PacketError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let seq = self.seq;
        let (len, total) = match &self.key {
            None => {
                let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
                (len, 4 + len)
            }
            Some(k) => {
                let mut l = [self.buf[0], self.buf[1], self.buf[2], self.buf[3]];
                chacha20_xor(&k.k_header, 0, &nonce(seq), &mut l);
                let len = u32::from_be_bytes(l) as usize;
                (len, 4 + len + TAG_LEN)
            }
        };
        // The length is checked before it is believed: a bound, and the
        // alignment the sender must have used.
        let aligned = if self.key.is_some() { len % BLOCK == 0 } else { (len + 4) % BLOCK == 0 };
        if !(MIN_PAD + 2..=MAX_PACKET).contains(&len) || !aligned {
            return Err(PacketError::Malformed);
        }
        if self.buf.len() < total {
            return Ok(None);
        }
        if seq == u32::MAX {
            return Err(PacketError::SeqExhausted);
        }
        let mut body: Vec<u8> = match &self.key {
            None => self.buf[4..total].to_vec(),
            Some(k) => {
                let mut pk = poly_key(k, seq);
                let want = poly1305(&pk, &self.buf[..4 + len]);
                secure_zero(&mut pk);
                if !ct_eq(&want, &self.buf[4 + len..total]) {
                    return Err(PacketError::Mac);
                }
                let mut b = self.buf[4..4 + len].to_vec();
                chacha20_xor(&k.k_main, 1, &nonce(seq), &mut b);
                b
            }
        };
        self.buf.drain(..total);
        self.seq = seq + 1;
        let pad = body[0] as usize;
        if pad < MIN_PAD || 1 + pad > body.len() {
            return Err(PacketError::Malformed);
        }
        let payload_len = body.len() - 1 - pad;
        if payload_len == 0 {
            return Err(PacketError::Malformed);
        }
        body.drain(..1);
        body.truncate(payload_len);
        Ok(Some(body))
    }
}

/// The sending half: payloads in, wire bytes out.
pub struct Tx {
    key: Option<Key>,
    seq: u32,
}

impl Default for Tx {
    fn default() -> Self {
        Self::new()
    }
}

impl Tx {
    pub const fn new() -> Self {
        Self { key: None, seq: 0 }
    }

    pub fn set_key(&mut self, key: Key) {
        self.key = Some(key);
    }

    pub fn reset_seq(&mut self) {
        self.seq = 0;
    }

    /// Frame `payload` and append it to `out`. `None` if it is too long or
    /// the sequence numbers are used up.
    pub fn send(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Option<()> {
        if self.seq == u32::MAX {
            return None;
        }
        match &self.key {
            None => seal_plain(payload, out)?,
            Some(k) => seal(k, self.seq, payload, out)?,
        }
        self.seq += 1;
        Some(())
    }
}
