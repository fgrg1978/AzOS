// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The message of a security record's line in `logd`'s files: every field of
//! the canonical bytes, so a reader recomputes the chain from the text alone.
//!
//! ```text
//! v1 <seq> <ts> <clock> <kind> <cpu> <flags> <payload hex> [<what>]
//! v1 seam
//! ```
//!
//! Numbers are decimal, the payload is lowercase hex (its length is the
//! envelope's `len`), and what follows the payload is for a reader's eyes
//! only: the kind's name and an event's class and verdict. `seam` is the line
//! `logd` writes when it starts reading the ring from its oldest record (a new
//! boot, or files that no longer match the ring): the next record may begin
//! a boot.

use crate::{kind, Envelope, Event, PAYLOAD, VERSION};

/// Bytes of the longest message.
pub const MSG_MAX: usize = 3 + 6 * 21 + 2 * PAYLOAD + 1 + 40;

const SEAM: &[u8] = b"v1 seam";

struct Put<'a> {
    out: &'a mut [u8],
    n: usize,
}

impl Put<'_> {
    fn bytes(&mut self, b: &[u8]) {
        let k = b.len().min(self.out.len() - self.n);
        self.out[self.n..self.n + k].copy_from_slice(&b[..k]);
        self.n += k;
    }

    fn dec(&mut self, mut v: u64) {
        let mut d = [0u8; 20];
        let mut i = d.len();
        loop {
            i -= 1;
            d[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.bytes(&d[i..]);
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// The message of record `env`, `payload` into `out`; its length.
pub fn render(env: &Envelope, payload: &[u8], out: &mut [u8]) -> usize {
    let len = (env.len as usize).min(PAYLOAD).min(payload.len());
    let mut p = Put { out, n: 0 };
    p.bytes(&[b'v', b'0' + VERSION]);
    for v in [env.seq, env.ts, env.clock as u64, env.kind as u64, env.cpu as u64, env.flags as u64] {
        p.bytes(b" ");
        p.dec(v);
    }
    p.bytes(b" ");
    if len == 0 {
        p.bytes(b"-");
    }
    for &b in &payload[..len] {
        p.bytes(&[HEX[(b >> 4) as usize], HEX[(b & 15) as usize]]);
    }
    let what: &str = match env.kind {
        kind::EVENT => "event",
        kind::ANCHOR => "anchor",
        kind::SEAL => "seal",
        kind::LOSS => "loss",
        _ => "",
    };
    if !what.is_empty() {
        p.bytes(b" ");
        p.bytes(what.as_bytes());
    }
    if let Some(e) = (env.kind == kind::EVENT).then(|| Event::decode(&payload[..len])).flatten() {
        p.bytes(b" ");
        p.bytes(e.class.name().as_bytes());
        p.bytes(b" rule=");
        p.dec(e.rule as u64);
        p.bytes(b" verdict=");
        p.dec(e.verdict as u64);
    }
    p.n
}

/// The seam message into `out`; its length.
pub fn render_seam(out: &mut [u8]) -> usize {
    let mut p = Put { out, n: 0 };
    p.bytes(SEAM);
    p.n
}

/// What a message holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parsed {
    Record { env: Envelope, payload: [u8; PAYLOAD] },
    Seam,
}

fn num(t: &[u8]) -> Option<u64> {
    if t.is_empty() || t.len() > 20 {
        return None;
    }
    let mut v: u64 = 0;
    for &c in t {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(v)
}

fn nib(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// The record or seam a message names; `None` for anything else (another
/// version, a field out of range, a payload of odd or too many digits).
pub fn parse(msg: &[u8]) -> Option<Parsed> {
    if msg == SEAM {
        return Some(Parsed::Seam);
    }
    let mut it = msg.split(|&b| b == b' ');
    if it.next()? != [b'v', b'0' + VERSION] {
        return None;
    }
    let mut f = [0u64; 6];
    for v in f.iter_mut() {
        *v = num(it.next()?)?;
    }
    let hex = it.next()?;
    let hex: &[u8] = if hex == b"-" { &[] } else { hex };
    if hex.len() % 2 != 0 || hex.len() / 2 > PAYLOAD || f[2] > 0xff || f[3] > 0xffff || f[4] > 0xff || f[5] > 0xff {
        return None;
    }
    let mut payload = [0u8; PAYLOAD];
    for (i, pair) in hex.chunks(2).enumerate() {
        payload[i] = nib(pair[0])? << 4 | nib(pair[1])?;
    }
    let env = Envelope {
        seq: f[0],
        ts: f[1],
        clock: f[2] as u8,
        source: 0,
        kind: f[3] as u16,
        len: (hex.len() / 2) as u16,
        cpu: f[4] as u8,
        flags: f[5] as u8,
    };
    Some(Parsed::Record { env, payload })
}
