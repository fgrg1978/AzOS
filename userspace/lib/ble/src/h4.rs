// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! H4: the HCI packet indicator and framing over a byte stream.
//!
//! One indicator byte, then the packet: a command (`0x01`), ACL data (`0x02`)
//! or an event (`0x04`). The stream has no delimiter, so the [`Deframer`] is
//! incremental (a packet may end in a later chunk than it began) and refuses to
//! trust what it reads:
//!
//! * a byte that is no indicator where one is due is dropped and counted
//!   ([`Stats::bad_indicator`]); SCO and ISO packets (`0x03`, `0x05`) are not
//!   something this host negotiates, so they are garbage too;
//! * a length that does not fit the buffer, or an ACL payload past
//!   [`ACL_DATA_MAX`], is skipped as a whole, counted ([`Stats::oversize`]),
//!   and the stream stays in step;
//! * a half packet is dropped by [`Deframer::reset`], which the host calls when
//!   the line went quiet in the middle of one or the ring said it lost bytes.

/// Indicator of a command packet (host to controller).
pub const IND_CMD: u8 = 0x01;
/// Indicator of an ACL data packet.
pub const IND_ACL: u8 = 0x02;
/// Indicator of an event packet (controller to host).
pub const IND_EVT: u8 = 0x04;

/// Most data bytes of one ACL packet (the LE data length extension's limit).
pub const ACL_DATA_MAX: usize = 251;
/// Largest parameter block of an event.
pub const EVT_PARAM_MAX: usize = 255;
/// Bytes the deframer keeps of a packet (without the indicator): an event
/// header and the largest parameter block, or an ACL header and the largest
/// payload, whichever is more.
pub const BODY_MAX: usize = 2 + EVT_PARAM_MAX;

/// What a finished packet is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `code, length, parameters`.
    Event,
    /// `handle+flags (2), length (2), data`.
    Acl,
}

/// What the deframer counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Packets delivered.
    pub frames: u32,
    /// Bytes dropped where an indicator was due.
    pub bad_indicator: u32,
    /// Packets skipped for a length past the buffer.
    pub oversize: u32,
    /// Half packets dropped by [`Deframer::reset`].
    pub resets: u32,
}

/// The incremental H4 parser.
pub struct Deframer {
    kind: Option<Kind>,
    buf: [u8; BODY_MAX],
    have: usize,
    need: usize,
    skip: usize,
    done: usize,
    pub stats: Stats,
}

impl Default for Deframer {
    fn default() -> Self {
        Self::new()
    }
}

impl Deframer {
    pub const fn new() -> Deframer {
        Deframer {
            kind: None,
            buf: [0; BODY_MAX],
            have: 0,
            need: 0,
            skip: 0,
            done: 0,
            stats: Stats { frames: 0, bad_indicator: 0, oversize: 0, resets: 0 },
        }
    }

    /// Whether a packet is half read (or being skipped).
    pub fn partial(&self) -> bool {
        self.kind.is_some() || self.skip > 0
    }

    /// Drop a half packet; the next byte is taken for an indicator.
    pub fn reset(&mut self) {
        if self.partial() {
            self.stats.resets += 1;
        }
        self.kind = None;
        self.have = 0;
        self.skip = 0;
    }

    /// Take one byte. `Some(kind)` when it completed a packet, whose bytes
    /// (without the indicator) [`body`](Self::body) answers until the next push.
    pub fn push(&mut self, b: u8) -> Option<Kind> {
        if self.skip > 0 {
            self.skip -= 1;
            return None;
        }
        let kind = match self.kind {
            Some(k) => k,
            None => {
                self.kind = match b {
                    IND_EVT => Some(Kind::Event),
                    IND_ACL => Some(Kind::Acl),
                    _ => {
                        self.stats.bad_indicator += 1;
                        None
                    }
                };
                self.have = 0;
                self.need = 0;
                return None;
            }
        };
        self.buf[self.have] = b;
        self.have += 1;
        let hdr = match kind {
            Kind::Event => 2,
            Kind::Acl => 4,
        };
        if self.have == hdr {
            let len = match kind {
                Kind::Event => self.buf[1] as usize,
                Kind::Acl => u16::from_le_bytes([self.buf[2], self.buf[3]]) as usize,
            };
            if len > BODY_MAX - hdr || (kind == Kind::Acl && len > ACL_DATA_MAX) {
                self.stats.oversize += 1;
                self.kind = None;
                self.skip = len;
                return None;
            }
            self.need = hdr + len;
        }
        if self.have >= hdr && self.have == self.need {
            self.kind = None;
            self.done = self.have;
            self.stats.frames += 1;
            return Some(kind);
        }
        None
    }

    /// The bytes of the packet the last [`push`](Self::push) completed.
    pub fn body(&self) -> &[u8] {
        &self.buf[..self.done]
    }
}

/// A command packet into `out`: indicator, opcode, length, parameters. The
/// bytes written, or `None` when `out` is too small or `params` too long.
pub fn command(opcode: u16, params: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = 4 + params.len();
    if params.len() > 255 || out.len() < n {
        return None;
    }
    out[0] = IND_CMD;
    out[1..3].copy_from_slice(&opcode.to_le_bytes());
    out[3] = params.len() as u8;
    out[4..n].copy_from_slice(params);
    Some(n)
}

/// An ACL packet into `out`: indicator, handle with the packet-boundary flags
/// (`pb`: `0b00` first non-flushable, `0b01` continuation), length, data.
pub fn acl(handle: u16, pb: u8, data: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = 5 + data.len();
    if data.len() > ACL_DATA_MAX || out.len() < n {
        return None;
    }
    out[0] = IND_ACL;
    let hf = (handle & 0x0FFF) | ((pb as u16 & 3) << 12);
    out[1..3].copy_from_slice(&hf.to_le_bytes());
    out[3..5].copy_from_slice(&(data.len() as u16).to_le_bytes());
    out[5..n].copy_from_slice(data);
    Some(n)
}
