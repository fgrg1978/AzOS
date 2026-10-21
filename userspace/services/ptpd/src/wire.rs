// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The IEEE 1588-2019 (PTP version 2) message codec, the subset an end-to-end
//! slave speaks: Announce, Sync, Follow_Up, Delay_Req and Delay_Resp, carried by
//! UDP (ports 319 and 320, `transportSpecific` 0).
//!
//! No allocation, no clock: [`parse`] reads a datagram or a frame's payload,
//! the `encode_*` functions write into a caller's buffer and return the
//! length. Timestamps are signed nanoseconds on the sender's scale (`i128`: a
//! 48-bit second count times 10^9 does not fit 64 bits), the correction field
//! keeps its wire unit (nanoseconds times 2^16) in [`Header::correction`].

/// Longest message this codec writes or reads (an Announce).
pub const MSG_MAX: usize = 64;

/// The header every message starts with.
pub const HEADER_LEN: usize = 34;

/// `messageType`s (the low nibble of the first byte).
pub mod mt {
    pub const SYNC: u8 = 0x0;
    pub const DELAY_REQ: u8 = 0x1;
    pub const FOLLOW_UP: u8 = 0x8;
    pub const DELAY_RESP: u8 = 0x9;
    pub const ANNOUNCE: u8 = 0xB;
}

/// `flagField` bits (octet 0 is the high byte).
pub mod flag {
    /// A Sync is followed by a Follow_Up with the timestamp.
    pub const TWO_STEP: u16 = 0x0200;
    /// Announce: `currentUtcOffset` is valid.
    pub const UTC_OFFSET_VALID: u16 = 0x0004;
    /// Announce: the grandmaster's time is on the PTP (TAI) timescale.
    pub const PTP_TIMESCALE: u16 = 0x0008;
    /// Announce: an alternate master's: not to be used.
    pub const ALTERNATE_MASTER: u16 = 0x0100;
}

/// The `transportSpecific` nibble of a UDP (IEEE 1588) message.
pub const TS_1588: u8 = 0;

/// `controlField` (the legacy field of version 1; version 2 still fills it).
const fn control(t: u8) -> u8 {
    match t {
        mt::SYNC => 0,
        mt::DELAY_REQ => 1,
        mt::FOLLOW_UP => 2,
        mt::DELAY_RESP => 3,
        _ => 5,
    }
}

/// A port: the clock's EUI-64-shaped identity and a port number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct PortId {
    pub clock: [u8; 8],
    pub port: u16,
}

/// The common header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub transport_specific: u8,
    pub msg_type: u8,
    pub len: u16,
    pub domain: u8,
    pub flags: u16,
    /// Nanoseconds times 2^16 (what bridges add as residence time).
    pub correction: i64,
    pub source: PortId,
    pub seq: u16,
    pub log_interval: i8,
}

impl Header {
    /// A header for a message this port sends.
    pub fn new(transport_specific: u8, msg_type: u8, domain: u8, source: PortId, seq: u16) -> Header {
        Header { transport_specific, msg_type, len: 0, domain, flags: 0, correction: 0, source, seq, log_interval: 0x7F }
    }

    /// The correction field in whole nanoseconds, rounded toward minus infinity.
    pub fn correction_ns(&self) -> i128 {
        (self.correction >> 16) as i128
    }
}

/// What a message after the header says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body {
    Announce(Announce),
    Sync { origin: i128 },
    FollowUp { precise_origin: i128 },
    DelayReq,
    DelayResp { receive: i128, requesting: PortId },
}

/// The announced grandmaster and the path to it (IEEE 1588 §13.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Announce {
    /// Seconds TAI minus UTC.
    pub utc_offset: i16,
    pub priority1: u8,
    pub class: u8,
    pub accuracy: u8,
    pub variance: u16,
    pub priority2: u8,
    pub identity: [u8; 8],
    pub steps_removed: u16,
    pub time_source: u8,
}

/// Why a message was not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Shorter than its header or its type's body, or `messageLength` is.
    Short,
    /// `versionPTP` is not 2.
    Version,
    /// A message type this codec does not read (Signaling, Management).
    Type,
}

#[cfg(test)]
fn put_ts(out: &mut [u8], ns: i128) {
    let ns = ns.max(0);
    let (s, n) = ((ns / 1_000_000_000) as u64, (ns % 1_000_000_000) as u32);
    out[0..6].copy_from_slice(&s.to_be_bytes()[2..8]);
    out[6..10].copy_from_slice(&n.to_be_bytes());
}

fn get_ts(b: &[u8]) -> i128 {
    let mut s = [0u8; 8];
    s[2..8].copy_from_slice(&b[0..6]);
    let n = u32::from_be_bytes([b[6], b[7], b[8], b[9]]);
    u64::from_be_bytes(s) as i128 * 1_000_000_000 + n as i128
}

fn put_port(out: &mut [u8], p: PortId) {
    out[0..8].copy_from_slice(&p.clock);
    out[8..10].copy_from_slice(&p.port.to_be_bytes());
}

fn get_port(b: &[u8]) -> PortId {
    let mut clock = [0u8; 8];
    clock.copy_from_slice(&b[0..8]);
    PortId { clock, port: u16::from_be_bytes([b[8], b[9]]) }
}

fn put_header(out: &mut [u8], h: &Header, len: usize) {
    out[..len].fill(0);
    out[0] = h.transport_specific << 4 | h.msg_type;
    out[1] = 2;
    out[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    out[4] = h.domain;
    out[6..8].copy_from_slice(&h.flags.to_be_bytes());
    out[8..16].copy_from_slice(&h.correction.to_be_bytes());
    put_port(&mut out[20..30], h.source);
    out[30..32].copy_from_slice(&h.seq.to_be_bytes());
    out[32] = control(h.msg_type);
    out[33] = h.log_interval as u8;
}

/// A Delay_Req: header plus the (zero) origin timestamp. Returns the length.
pub fn encode_request(out: &mut [u8; MSG_MAX], h: &Header) -> usize {
    put_header(out, h, 44);
    44
}

/// A Sync or a Follow_Up carrying `ts` (the origin or precise origin timestamp).
/// Only a master writes one: the host tests' scripted master.
#[cfg(test)]
pub fn encode_time(out: &mut [u8; MSG_MAX], h: &Header, ts: i128) -> usize {
    put_header(out, h, 44);
    put_ts(&mut out[34..44], ts);
    44
}

/// A Delay_Resp: a timestamp and the port that asked. Only a master sends it:
/// the host tests' scripted master.
#[cfg(test)]
pub fn encode_response(out: &mut [u8; MSG_MAX], h: &Header, ts: i128, requesting: PortId) -> usize {
    put_header(out, h, 54);
    put_ts(&mut out[34..44], ts);
    put_port(&mut out[44..54], requesting);
    54
}

/// An Announce. Only a master sends it: the host tests' scripted master.
#[cfg(test)]
pub fn encode_announce(out: &mut [u8; MSG_MAX], h: &Header, a: &Announce) -> usize {
    put_header(out, h, 64);
    out[44..46].copy_from_slice(&a.utc_offset.to_be_bytes());
    out[47] = a.priority1;
    out[48] = a.class;
    out[49] = a.accuracy;
    out[50..52].copy_from_slice(&a.variance.to_be_bytes());
    out[52] = a.priority2;
    out[53..61].copy_from_slice(&a.identity);
    out[61..63].copy_from_slice(&a.steps_removed.to_be_bytes());
    out[63] = a.time_source;
    64
}

/// Read one message.
pub fn parse(b: &[u8]) -> Result<(Header, Body), ParseError> {
    if b.len() < HEADER_LEN {
        return Err(ParseError::Short);
    }
    if b[1] & 0x0F != 2 {
        return Err(ParseError::Version);
    }
    let h = Header {
        transport_specific: b[0] >> 4,
        msg_type: b[0] & 0x0F,
        len: u16::from_be_bytes([b[2], b[3]]),
        domain: b[4],
        flags: u16::from_be_bytes([b[6], b[7]]),
        correction: i64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
        source: get_port(&b[20..30]),
        seq: u16::from_be_bytes([b[30], b[31]]),
        log_interval: b[33] as i8,
    };
    // The length the sender states must be there; trailing bytes (a TLV) are ignored.
    let need = |n: usize| if b.len() >= n && h.len as usize >= n { Ok(()) } else { Err(ParseError::Short) };
    let body = match h.msg_type {
        mt::SYNC => {
            need(44)?;
            Body::Sync { origin: get_ts(&b[34..44]) }
        }
        mt::FOLLOW_UP => {
            need(44)?;
            Body::FollowUp { precise_origin: get_ts(&b[34..44]) }
        }
        mt::DELAY_REQ => {
            need(44)?;
            Body::DelayReq
        }
        mt::DELAY_RESP => {
            need(54)?;
            Body::DelayResp { receive: get_ts(&b[34..44]), requesting: get_port(&b[44..54]) }
        }
        mt::ANNOUNCE => {
            need(64)?;
            let mut identity = [0u8; 8];
            identity.copy_from_slice(&b[53..61]);
            Body::Announce(Announce {
                utc_offset: i16::from_be_bytes([b[44], b[45]]),
                priority1: b[47],
                class: b[48],
                accuracy: b[49],
                variance: u16::from_be_bytes([b[50], b[51]]),
                priority2: b[52],
                identity,
                steps_removed: u16::from_be_bytes([b[61], b[62]]),
                time_source: b[63],
            })
        }
        _ => return Err(ParseError::Type),
    };
    Ok((h, body))
}
