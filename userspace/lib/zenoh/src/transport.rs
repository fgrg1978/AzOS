// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The transport messages of a unicast session: INIT and OPEN (the handshake),
//! CLOSE, KEEP_ALIVE, and FRAME / FRAGMENT, which carry the network messages.
//!
//! Every message starts with one header byte: the message id in bits 4..0 and
//! three flags in bits 7..5 (Z, the last one, always says "an extension chain
//! follows"). OAM and JOIN (multicast) are not decoded: [`Error::Unsupported`].
//!
//! A *batch* is what one link write carries: one or more transport messages
//! back to back. FRAME and FRAGMENT run to the end of their batch, so they are
//! always the last message of it. On a stream link (TCP) a batch is preceded by
//! its length as two little-endian bytes ([`stream_prefix`], [`split_stream`]);
//! on a datagram link the datagram is the batch.

use crate::codec::{read_exts, Error, ExtBody, ExtWriter, Reader, Result, Writer, Zid, Z};
use crate::network::NetworkMsg;

const ID_INIT: u8 = 0x01;
const ID_OPEN: u8 = 0x02;
const ID_CLOSE: u8 = 0x03;
const ID_KEEP_ALIVE: u8 = 0x04;
const ID_FRAME: u8 = 0x05;
const ID_FRAGMENT: u8 = 0x06;

/// The protocol version zenoh 1.0 (and zenoh-pico 1.x) speak.
pub const VERSION: u8 = 0x09;
/// The batch size when INIT carries none: the most a two-byte prefix can say.
pub const DEFAULT_BATCH_SIZE: u16 = 65535;

/// The role a node announces in INIT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WhatAmI {
    Router = 0,
    Peer = 1,
    Client = 2,
}

impl WhatAmI {
    fn from_bits(b: u8) -> Result<WhatAmI> {
        match b & 3 {
            0 => Ok(WhatAmI::Router),
            1 => Ok(WhatAmI::Peer),
            2 => Ok(WhatAmI::Client),
            _ => Err(Error::BadValue("whatami 0b11")),
        }
    }
}

/// The width of a sequence number or request id on this session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bits {
    B8 = 0,
    B16 = 1,
    B32 = 2,
    B64 = 3,
}

impl Bits {
    fn from_bits(b: u8) -> Bits {
        match b & 3 {
            0 => Bits::B8,
            1 => Bits::B16,
            2 => Bits::B32,
            _ => Bits::B64,
        }
    }

    /// The largest value of this width: sequence numbers wrap at it plus one.
    pub fn mask(self) -> u64 {
        match self {
            Bits::B8 => 0xFF,
            Bits::B16 => 0xFFFF,
            Bits::B32 => 0xFFFF_FFFF,
            Bits::B64 => u64::MAX,
        }
    }
}

/// The resolution byte of INIT: the width of frame sequence numbers (bits 1..0)
/// and of request ids (bits 3..2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolution {
    pub fsn: Bits,
    pub rid: Bits,
}

impl Resolution {
    /// 32 bits both: the byte `0x0A`.
    pub const DEFAULT: Resolution = Resolution { fsn: Bits::B32, rid: Bits::B32 };

    pub fn to_byte(self) -> u8 {
        (self.fsn as u8) | ((self.rid as u8) << 2)
    }

    pub fn from_byte(b: u8) -> Resolution {
        Resolution { fsn: Bits::from_bits(b), rid: Bits::from_bits(b >> 2) }
    }

    /// The narrower of each field: what a responder may answer (it may lower
    /// the resolution, never raise it).
    pub fn narrowest(self, other: Resolution) -> Resolution {
        Resolution {
            fsn: if (self.fsn as u8) < (other.fsn as u8) { self.fsn } else { other.fsn },
            rid: if (self.rid as u8) < (other.rid as u8) { self.rid } else { other.rid },
        }
    }
}

/// The optional size block of INIT (flag S).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SizeParams {
    pub resolution: Resolution,
    pub batch_size: u16,
}

impl SizeParams {
    pub const DEFAULT: SizeParams =
        SizeParams { resolution: Resolution::DEFAULT, batch_size: DEFAULT_BATCH_SIZE };
}

/// INIT (0x01). Flag A makes it the answer (InitAck), which carries the cookie
/// the initiator must return in OPEN.
///
/// Extensions: QoS (id 1, unit) and Patch (id 7, z64) are decoded; any other
/// optional extension is skipped (so a feature the peer offers and we do not
/// answer stays off), a mandatory unknown one is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Init<'a> {
    pub version: u8,
    pub whatami: WhatAmI,
    pub zid: Zid,
    /// `None`: flag S absent, the defaults of [`SizeParams::DEFAULT`] apply.
    pub size: Option<SizeParams>,
    /// `Some` exactly when this is the answer (flag A).
    pub cookie: Option<&'a [u8]>,
    pub qos: bool,
    /// The protocol patch level (0 = the base 1.0.0 protocol).
    pub patch: u8,
}

impl<'a> Init<'a> {
    pub fn is_ack(&self) -> bool {
        self.cookie.is_some()
    }

    pub fn size_or_default(&self) -> SizeParams {
        self.size.unwrap_or(SizeParams::DEFAULT)
    }
}

/// A lease: how long the peer may stay silent before the session is dead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub value: u64,
    /// Flag T: the value is in seconds, otherwise milliseconds.
    pub seconds: bool,
}

impl Lease {
    pub fn millis(self) -> u64 {
        if self.seconds {
            self.value.saturating_mul(1000)
        } else {
            self.value
        }
    }
}

/// OPEN (0x02). Flag A makes it the answer (OpenAck); the request (OpenSyn)
/// returns the cookie of InitAck.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Open<'a> {
    pub lease: Lease,
    pub initial_sn: u64,
    /// `Some` exactly when this is the request (flag A absent).
    pub cookie: Option<&'a [u8]>,
    pub qos: bool,
}

impl<'a> Open<'a> {
    pub fn is_ack(&self) -> bool {
        self.cookie.is_none()
    }
}

/// CLOSE reasons (the byte of CLOSE).
pub mod reason {
    pub const GENERIC: u8 = 0x00;
    pub const UNSUPPORTED: u8 = 0x01;
    pub const INVALID: u8 = 0x02;
    pub const MAX_SESSIONS: u8 = 0x03;
    pub const MAX_LINKS: u8 = 0x04;
    pub const EXPIRED: u8 = 0x05;
    pub const UNRESPONSIVE: u8 = 0x06;
    pub const CONNECTION_TO_SELF: u8 = 0x07;
}

/// CLOSE (0x03): `session` (flag S) ends the whole session, otherwise only the link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Close {
    pub session: bool,
    pub reason: u8,
}

/// FRAME (0x05): a sequence number and the network messages that fill the rest
/// of the batch, left undecoded in `body` ([`Frame::messages`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Flag R: the reliable channel (otherwise best effort).
    pub reliable: bool,
    pub sn: u64,
    /// The QoS extension (id 1, mandatory): the priority 0..=7 of every
    /// message in the frame.
    pub priority: Option<u8>,
    pub body: &'a [u8],
}

impl<'a> Frame<'a> {
    /// The network messages of the body, decoded one at a time.
    pub fn messages(&self) -> Messages<'a> {
        Messages { r: Reader::new(self.body) }
    }
}

/// The network messages of a frame body. An error ends the iteration (the
/// messages have no length of their own, so nothing after a bad one can be found).
pub struct Messages<'a> {
    r: Reader<'a>,
}

impl<'a> Iterator for Messages<'a> {
    type Item = Result<NetworkMsg<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.r.is_empty() {
            return None;
        }
        let m = NetworkMsg::decode(&mut self.r);
        if m.is_err() {
            self.r.rest();
        }
        Some(m)
    }
}

/// FRAGMENT (0x06): one piece of a network message too large for a batch.
/// The pieces share the sequence-number space of FRAME on the channel; they are
/// joined in order until one has `more == false`, and the result is one network
/// message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment<'a> {
    pub reliable: bool,
    /// Flag M: more fragments follow.
    pub more: bool,
    pub sn: u64,
    pub priority: Option<u8>,
    /// Extension id 2 (patch level 1): this is the first fragment.
    pub first: bool,
    /// Extension id 3 (patch level 1): drop what was reassembled so far.
    pub drop: bool,
    pub data: &'a [u8],
}

/// One transport message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transport<'a> {
    Init(Init<'a>),
    Open(Open<'a>),
    Close(Close),
    KeepAlive,
    Frame(Frame<'a>),
    Fragment(Fragment<'a>),
}

fn skip_exts(r: &mut Reader<'_>) -> Result<()> {
    read_exts(r, |_| Ok(false))
}

fn read_priority(e: &crate::codec::Ext<'_>) -> Option<u8> {
    match e.body {
        ExtBody::Z64(v) => Some((v & 7) as u8),
        _ => None,
    }
}

impl<'a> Transport<'a> {
    /// Decode one message from the front of `r`.
    pub fn decode(r: &mut Reader<'a>) -> Result<Transport<'a>> {
        let h = r.u8()?;
        let z = h & Z != 0;
        match h & 0x1F {
            ID_INIT => {
                let (s, a) = (h & 0x40 != 0, h & 0x20 != 0);
                let version = r.u8()?;
                let b = r.u8()?;
                let whatami = WhatAmI::from_bits(b)?;
                let zid = r.zid((b >> 4) as usize + 1)?;
                let size = if s {
                    let resolution = Resolution::from_byte(r.u8()?);
                    Some(SizeParams { resolution, batch_size: r.u16_le()? })
                } else {
                    None
                };
                let cookie = if a { Some(r.z16()?) } else { None };
                let (mut qos, mut patch) = (false, 0u8);
                if z {
                    read_exts(r, |e| match (e.id, &e.body) {
                        (1, ExtBody::Unit) => {
                            qos = true;
                            Ok(true)
                        }
                        (7, ExtBody::Z64(v)) => {
                            patch = u8::try_from(*v).map_err(|_| Error::Overflow)?;
                            Ok(true)
                        }
                        _ => Ok(false),
                    })?;
                }
                Ok(Transport::Init(Init { version, whatami, zid, size, cookie, qos, patch }))
            }
            ID_OPEN => {
                let (t, a) = (h & 0x40 != 0, h & 0x20 != 0);
                let lease = Lease { value: r.vle()?, seconds: t };
                let initial_sn = r.vle()?;
                let cookie = if a { None } else { Some(r.z16()?) };
                let mut qos = false;
                if z {
                    read_exts(r, |e| match (e.id, &e.body) {
                        (1, ExtBody::Unit) => {
                            qos = true;
                            Ok(true)
                        }
                        _ => Ok(false),
                    })?;
                }
                Ok(Transport::Open(Open { lease, initial_sn, cookie, qos }))
            }
            ID_CLOSE => {
                let session = h & 0x20 != 0;
                let reason = r.u8()?;
                if z {
                    skip_exts(r)?;
                }
                Ok(Transport::Close(Close { session, reason }))
            }
            ID_KEEP_ALIVE => {
                if z {
                    skip_exts(r)?;
                }
                Ok(Transport::KeepAlive)
            }
            ID_FRAME => {
                let reliable = h & 0x20 != 0;
                let sn = r.vle()?;
                let mut priority = None;
                if z {
                    read_exts(r, |e| {
                        if e.id == 1 {
                            if let Some(p) = read_priority(e) {
                                priority = Some(p);
                                return Ok(true);
                            }
                        }
                        Ok(false)
                    })?;
                }
                Ok(Transport::Frame(Frame { reliable, sn, priority, body: r.rest() }))
            }
            ID_FRAGMENT => {
                let (reliable, more) = (h & 0x20 != 0, h & 0x40 != 0);
                let sn = r.vle()?;
                let (mut priority, mut first, mut drop) = (None, false, false);
                if z {
                    read_exts(r, |e| match e.id {
                        1 => {
                            if let Some(p) = read_priority(e) {
                                priority = Some(p);
                                return Ok(true);
                            }
                            Ok(false)
                        }
                        2 => {
                            first = true;
                            Ok(true)
                        }
                        3 => {
                            drop = true;
                            Ok(true)
                        }
                        _ => Ok(false),
                    })?;
                }
                Ok(Transport::Fragment(Fragment {
                    reliable,
                    more,
                    sn,
                    priority,
                    first,
                    drop,
                    data: r.rest(),
                }))
            }
            id => Err(Error::Unsupported(id)),
        }
    }

    /// Append the message to `w`. FRAME and FRAGMENT must be last in their batch.
    pub fn encode(&self, w: &mut Writer) -> Result<()> {
        match self {
            Transport::Init(m) => {
                let hp = w.pos();
                let ack = m.cookie.is_some();
                w.u8(ID_INIT | ((m.size.is_some() as u8) << 6) | ((ack as u8) << 5));
                w.u8(m.version);
                w.u8((m.zid.nibble() << 4) | m.whatami as u8);
                w.bytes(m.zid.as_slice());
                if let Some(s) = m.size {
                    w.u8(s.resolution.to_byte());
                    w.u16_le(s.batch_size);
                }
                if let Some(c) = m.cookie {
                    w.z16(c)?;
                }
                let mut x = ExtWriter::new(hp);
                if m.qos {
                    x.unit(w, 1, false);
                }
                if m.patch != 0 {
                    x.z64(w, 7, false, m.patch as u64);
                }
                x.finish(w);
            }
            Transport::Open(m) => {
                let hp = w.pos();
                w.u8(ID_OPEN | ((m.lease.seconds as u8) << 6) | ((m.cookie.is_none() as u8) << 5));
                w.vle(m.lease.value);
                w.vle(m.initial_sn);
                if let Some(c) = m.cookie {
                    w.z16(c)?;
                }
                let mut x = ExtWriter::new(hp);
                if m.qos {
                    x.unit(w, 1, false);
                }
                x.finish(w);
            }
            Transport::Close(m) => {
                w.u8(ID_CLOSE | ((m.session as u8) << 5));
                w.u8(m.reason);
            }
            Transport::KeepAlive => w.u8(ID_KEEP_ALIVE),
            Transport::Frame(m) => {
                let hp = w.pos();
                w.u8(ID_FRAME | ((m.reliable as u8) << 5));
                w.vle(m.sn);
                let mut x = ExtWriter::new(hp);
                if let Some(p) = m.priority {
                    x.z64(w, 1, true, (p & 7) as u64);
                }
                x.finish(w);
                w.bytes(m.body);
            }
            Transport::Fragment(m) => {
                let hp = w.pos();
                w.u8(ID_FRAGMENT | ((m.more as u8) << 6) | ((m.reliable as u8) << 5));
                w.vle(m.sn);
                let mut x = ExtWriter::new(hp);
                if let Some(p) = m.priority {
                    x.z64(w, 1, true, (p & 7) as u64);
                }
                if m.first {
                    x.unit(w, 2, false);
                }
                if m.drop {
                    x.unit(w, 3, false);
                }
                x.finish(w);
                w.bytes(m.data);
            }
        }
        Ok(())
    }
}

/// Encode a FRAME that carries `msgs`.
pub fn encode_frame(
    w: &mut Writer,
    reliable: bool,
    sn: u64,
    priority: Option<u8>,
    msgs: &[NetworkMsg<'_>],
) -> Result<()> {
    let mut body = Writer::new();
    for m in msgs {
        m.encode(&mut body)?;
    }
    Transport::Frame(Frame { reliable, sn, priority, body: body.as_slice() }).encode(w)
}

/// The transport messages of one batch, decoded in order. An error ends the iteration.
pub struct Batch<'a> {
    r: Reader<'a>,
}

/// Decode a batch.
pub fn decode_batch(batch: &[u8]) -> Batch<'_> {
    Batch { r: Reader::new(batch) }
}

impl<'a> Iterator for Batch<'a> {
    type Item = Result<Transport<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.r.is_empty() {
            return None;
        }
        let m = Transport::decode(&mut self.r);
        if m.is_err() {
            self.r.rest();
        }
        Some(m)
    }
}

/// The two-byte little-endian length that precedes a batch on a stream link.
/// `Err(TooLong)` when the batch is longer than the prefix can say.
pub fn stream_prefix(batch_len: usize) -> Result<[u8; 2]> {
    u16::try_from(batch_len).map(u16::to_le_bytes).map_err(|_| Error::TooLong)
}

/// Cut the first batch off the bytes read from a stream link: `Some((batch,
/// rest))`, or `None` when more bytes are needed.
pub fn split_stream(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.len() < 2 {
        return None;
    }
    let n = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + n {
        return None;
    }
    Some((&buf[2..2 + n], &buf[2 + n..]))
}
