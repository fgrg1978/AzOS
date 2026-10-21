// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ATT: the attribute protocol's PDUs (Core Vol 3 Part F).
//!
//! The codec, the error codes and the rules of the bearer that do not depend on
//! an attribute database: the default MTU, the MTU exchange, the one request in
//! flight and the one indication in flight ([`Bearer`]). The database, the
//! discovery procedures and the permissions are GATT's (the later front); a PDU
//! the host does not answer itself reaches the upper layer as the raw bytes
//! that [`Pdu::parse`] decodes.

use crate::{le16, put16, Error, L2CAP_MTU};

/// Fixed L2CAP channel of ATT.
pub const CID_ATT: u16 = 0x0004;
/// The MTU before any exchange.
pub const DEFAULT_MTU: u16 = 23;
/// The MTU this host offers (the L2CAP payload it can reassemble).
pub const LOCAL_MTU: u16 = L2CAP_MTU as u16;
/// Seconds the bearer waits for the answer to a request or indication.
pub const TRANSACTION_TIMEOUT_MS: u64 = 30_000;

/// Opcodes.
pub mod op {
    pub const ERROR_RSP: u8 = 0x01;
    pub const EXCHANGE_MTU_REQ: u8 = 0x02;
    pub const EXCHANGE_MTU_RSP: u8 = 0x03;
    pub const FIND_INFO_REQ: u8 = 0x04;
    pub const FIND_INFO_RSP: u8 = 0x05;
    pub const FIND_BY_TYPE_VALUE_REQ: u8 = 0x06;
    pub const FIND_BY_TYPE_VALUE_RSP: u8 = 0x07;
    pub const READ_BY_TYPE_REQ: u8 = 0x08;
    pub const READ_BY_TYPE_RSP: u8 = 0x09;
    pub const READ_REQ: u8 = 0x0A;
    pub const READ_RSP: u8 = 0x0B;
    pub const READ_BLOB_REQ: u8 = 0x0C;
    pub const READ_BLOB_RSP: u8 = 0x0D;
    pub const READ_BY_GROUP_TYPE_REQ: u8 = 0x10;
    pub const READ_BY_GROUP_TYPE_RSP: u8 = 0x11;
    pub const WRITE_REQ: u8 = 0x12;
    pub const WRITE_RSP: u8 = 0x13;
    pub const PREPARE_WRITE_REQ: u8 = 0x16;
    pub const PREPARE_WRITE_RSP: u8 = 0x17;
    pub const EXECUTE_WRITE_REQ: u8 = 0x18;
    pub const EXECUTE_WRITE_RSP: u8 = 0x19;
    pub const NOTIFICATION: u8 = 0x1B;
    pub const INDICATION: u8 = 0x1D;
    pub const CONFIRMATION: u8 = 0x1E;
    pub const WRITE_CMD: u8 = 0x52;
}

/// Error codes of an Error Response.
pub mod err {
    pub const INVALID_HANDLE: u8 = 0x01;
    pub const READ_NOT_PERMITTED: u8 = 0x02;
    pub const WRITE_NOT_PERMITTED: u8 = 0x03;
    pub const INVALID_PDU: u8 = 0x04;
    pub const INSUFFICIENT_AUTHENTICATION: u8 = 0x05;
    pub const REQUEST_NOT_SUPPORTED: u8 = 0x06;
    pub const INVALID_OFFSET: u8 = 0x07;
    pub const INSUFFICIENT_AUTHORIZATION: u8 = 0x08;
    pub const PREPARE_QUEUE_FULL: u8 = 0x09;
    pub const ATTRIBUTE_NOT_FOUND: u8 = 0x0A;
    pub const ATTRIBUTE_NOT_LONG: u8 = 0x0B;
    pub const INVALID_ATTRIBUTE_VALUE_LENGTH: u8 = 0x0D;
    pub const UNLIKELY_ERROR: u8 = 0x0E;
    pub const INSUFFICIENT_ENCRYPTION: u8 = 0x0F;
    pub const UNSUPPORTED_GROUP_TYPE: u8 = 0x10;
    pub const INSUFFICIENT_RESOURCES: u8 = 0x11;
}

/// What a PDU is to the bearer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Client to server, answered by one response or error.
    Request,
    /// The answer to a request (an Error Response included).
    Response,
    /// Client to server, never answered.
    Command,
    /// Server to client, never answered.
    Notification,
    /// Server to client, answered by a confirmation.
    Indication,
    Confirmation,
}

/// The class of an opcode; `None` for one this host does not know.
pub fn class_of(opcode: u8) -> Option<Class> {
    use op::*;
    Some(match opcode {
        EXCHANGE_MTU_REQ | FIND_INFO_REQ | FIND_BY_TYPE_VALUE_REQ | READ_BY_TYPE_REQ | READ_REQ | READ_BLOB_REQ
        | READ_BY_GROUP_TYPE_REQ | WRITE_REQ | PREPARE_WRITE_REQ | EXECUTE_WRITE_REQ => Class::Request,
        ERROR_RSP | EXCHANGE_MTU_RSP | FIND_INFO_RSP | FIND_BY_TYPE_VALUE_RSP | READ_BY_TYPE_RSP | READ_RSP
        | READ_BLOB_RSP | READ_BY_GROUP_TYPE_RSP | WRITE_RSP | PREPARE_WRITE_RSP | EXECUTE_WRITE_RSP => {
            Class::Response
        }
        WRITE_CMD => Class::Command,
        NOTIFICATION => Class::Notification,
        INDICATION => Class::Indication,
        CONFIRMATION => Class::Confirmation,
        _ => return None,
    })
}

/// An attribute type: 16-bit or 128-bit UUID, little-endian on the air.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Uuid {
    U16(u16),
    U128([u8; 16]),
}

impl Uuid {
    fn parse(b: &[u8]) -> Result<Uuid, Error> {
        match b.len() {
            2 => Ok(Uuid::U16(le16(b, 0))),
            16 => {
                let mut u = [0u8; 16];
                u.copy_from_slice(b);
                Ok(Uuid::U128(u))
            }
            _ => Err(Error::Invalid),
        }
    }

    fn len(&self) -> usize {
        match self {
            Uuid::U16(_) => 2,
            Uuid::U128(_) => 16,
        }
    }

    fn put(&self, out: &mut [u8]) {
        match self {
            Uuid::U16(v) => out[..2].copy_from_slice(&v.to_le_bytes()),
            Uuid::U128(u) => out[..16].copy_from_slice(u),
        }
    }
}

/// A decoded ATT PDU; byte slices borrow the packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pdu<'a> {
    ErrorRsp { request: u8, handle: u16, code: u8 },
    ExchangeMtuReq { mtu: u16 },
    ExchangeMtuRsp { mtu: u16 },
    FindInfoReq { start: u16, end: u16 },
    /// `format`: 1 for 16-bit UUIDs, 2 for 128-bit; `data` the pairs.
    FindInfoRsp { format: u8, data: &'a [u8] },
    FindByTypeValueReq { start: u16, end: u16, attr_type: u16, value: &'a [u8] },
    FindByTypeValueRsp { data: &'a [u8] },
    ReadByTypeReq { start: u16, end: u16, uuid: Uuid },
    ReadByTypeRsp { item_len: u8, data: &'a [u8] },
    ReadReq { handle: u16 },
    ReadRsp { value: &'a [u8] },
    ReadBlobReq { handle: u16, offset: u16 },
    ReadBlobRsp { value: &'a [u8] },
    ReadByGroupTypeReq { start: u16, end: u16, uuid: Uuid },
    ReadByGroupTypeRsp { item_len: u8, data: &'a [u8] },
    WriteReq { handle: u16, value: &'a [u8] },
    WriteRsp,
    WriteCmd { handle: u16, value: &'a [u8] },
    PrepareWriteReq { handle: u16, offset: u16, value: &'a [u8] },
    PrepareWriteRsp { handle: u16, offset: u16, value: &'a [u8] },
    ExecuteWriteReq { flags: u8 },
    ExecuteWriteRsp,
    Notification { handle: u16, value: &'a [u8] },
    Indication { handle: u16, value: &'a [u8] },
    Confirmation,
}

impl<'a> Pdu<'a> {
    /// Decode a PDU. `Error::Unknown` for an opcode this host does not decode
    /// (the caller answers a request with `REQUEST_NOT_SUPPORTED` and ignores
    /// anything else), `Error::Short` or `Invalid` for a malformed one
    /// (`INVALID_PDU`).
    pub fn parse(b: &'a [u8]) -> Result<Pdu<'a>, Error> {
        let opc = *b.first().ok_or(Error::Short)?;
        let p = &b[1..];
        let need = |n: usize| if p.len() >= n { Ok(()) } else { Err(Error::Short) };
        let exact = |n: usize| match p.len() {
            l if l < n => Err(Error::Short),
            l if l > n => Err(Error::Invalid),
            _ => Ok(()),
        };
        Ok(match opc {
            op::ERROR_RSP => {
                exact(4)?;
                Pdu::ErrorRsp { request: p[0], handle: le16(p, 1), code: p[3] }
            }
            op::EXCHANGE_MTU_REQ => {
                exact(2)?;
                Pdu::ExchangeMtuReq { mtu: le16(p, 0) }
            }
            op::EXCHANGE_MTU_RSP => {
                exact(2)?;
                Pdu::ExchangeMtuRsp { mtu: le16(p, 0) }
            }
            op::FIND_INFO_REQ => {
                exact(4)?;
                Pdu::FindInfoReq { start: le16(p, 0), end: le16(p, 2) }
            }
            op::FIND_INFO_RSP => {
                need(1)?;
                if p[0] != 1 && p[0] != 2 {
                    return Err(Error::Invalid);
                }
                Pdu::FindInfoRsp { format: p[0], data: &p[1..] }
            }
            op::FIND_BY_TYPE_VALUE_REQ => {
                need(6)?;
                Pdu::FindByTypeValueReq { start: le16(p, 0), end: le16(p, 2), attr_type: le16(p, 4), value: &p[6..] }
            }
            op::FIND_BY_TYPE_VALUE_RSP => Pdu::FindByTypeValueRsp { data: p },
            op::READ_BY_TYPE_REQ => {
                need(6)?;
                Pdu::ReadByTypeReq { start: le16(p, 0), end: le16(p, 2), uuid: Uuid::parse(&p[4..])? }
            }
            op::READ_BY_TYPE_RSP => {
                need(1)?;
                Pdu::ReadByTypeRsp { item_len: p[0], data: &p[1..] }
            }
            op::READ_REQ => {
                exact(2)?;
                Pdu::ReadReq { handle: le16(p, 0) }
            }
            op::READ_RSP => Pdu::ReadRsp { value: p },
            op::READ_BLOB_REQ => {
                exact(4)?;
                Pdu::ReadBlobReq { handle: le16(p, 0), offset: le16(p, 2) }
            }
            op::READ_BLOB_RSP => Pdu::ReadBlobRsp { value: p },
            op::READ_BY_GROUP_TYPE_REQ => {
                need(6)?;
                Pdu::ReadByGroupTypeReq { start: le16(p, 0), end: le16(p, 2), uuid: Uuid::parse(&p[4..])? }
            }
            op::READ_BY_GROUP_TYPE_RSP => {
                need(1)?;
                Pdu::ReadByGroupTypeRsp { item_len: p[0], data: &p[1..] }
            }
            op::WRITE_REQ => {
                need(2)?;
                Pdu::WriteReq { handle: le16(p, 0), value: &p[2..] }
            }
            op::WRITE_RSP => {
                exact(0)?;
                Pdu::WriteRsp
            }
            op::WRITE_CMD => {
                need(2)?;
                Pdu::WriteCmd { handle: le16(p, 0), value: &p[2..] }
            }
            op::PREPARE_WRITE_REQ => {
                need(4)?;
                Pdu::PrepareWriteReq { handle: le16(p, 0), offset: le16(p, 2), value: &p[4..] }
            }
            op::PREPARE_WRITE_RSP => {
                need(4)?;
                Pdu::PrepareWriteRsp { handle: le16(p, 0), offset: le16(p, 2), value: &p[4..] }
            }
            op::EXECUTE_WRITE_REQ => {
                exact(1)?;
                Pdu::ExecuteWriteReq { flags: p[0] }
            }
            op::EXECUTE_WRITE_RSP => {
                exact(0)?;
                Pdu::ExecuteWriteRsp
            }
            op::NOTIFICATION => {
                need(2)?;
                Pdu::Notification { handle: le16(p, 0), value: &p[2..] }
            }
            op::INDICATION => {
                need(2)?;
                Pdu::Indication { handle: le16(p, 0), value: &p[2..] }
            }
            op::CONFIRMATION => {
                exact(0)?;
                Pdu::Confirmation
            }
            _ => return Err(Error::Unknown),
        })
    }

    /// The opcode.
    pub fn opcode(&self) -> u8 {
        match self {
            Pdu::ErrorRsp { .. } => op::ERROR_RSP,
            Pdu::ExchangeMtuReq { .. } => op::EXCHANGE_MTU_REQ,
            Pdu::ExchangeMtuRsp { .. } => op::EXCHANGE_MTU_RSP,
            Pdu::FindInfoReq { .. } => op::FIND_INFO_REQ,
            Pdu::FindInfoRsp { .. } => op::FIND_INFO_RSP,
            Pdu::FindByTypeValueReq { .. } => op::FIND_BY_TYPE_VALUE_REQ,
            Pdu::FindByTypeValueRsp { .. } => op::FIND_BY_TYPE_VALUE_RSP,
            Pdu::ReadByTypeReq { .. } => op::READ_BY_TYPE_REQ,
            Pdu::ReadByTypeRsp { .. } => op::READ_BY_TYPE_RSP,
            Pdu::ReadReq { .. } => op::READ_REQ,
            Pdu::ReadRsp { .. } => op::READ_RSP,
            Pdu::ReadBlobReq { .. } => op::READ_BLOB_REQ,
            Pdu::ReadBlobRsp { .. } => op::READ_BLOB_RSP,
            Pdu::ReadByGroupTypeReq { .. } => op::READ_BY_GROUP_TYPE_REQ,
            Pdu::ReadByGroupTypeRsp { .. } => op::READ_BY_GROUP_TYPE_RSP,
            Pdu::WriteReq { .. } => op::WRITE_REQ,
            Pdu::WriteRsp => op::WRITE_RSP,
            Pdu::WriteCmd { .. } => op::WRITE_CMD,
            Pdu::PrepareWriteReq { .. } => op::PREPARE_WRITE_REQ,
            Pdu::PrepareWriteRsp { .. } => op::PREPARE_WRITE_RSP,
            Pdu::ExecuteWriteReq { .. } => op::EXECUTE_WRITE_REQ,
            Pdu::ExecuteWriteRsp => op::EXECUTE_WRITE_RSP,
            Pdu::Notification { .. } => op::NOTIFICATION,
            Pdu::Indication { .. } => op::INDICATION,
            Pdu::Confirmation => op::CONFIRMATION,
        }
    }

    /// Encode into `out`; the bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut n = 1usize;
        let olen = out.len();
        let room = |n: usize, add: usize| if olen >= n + add { Ok(()) } else { Err(Error::NoRoom) };
        room(0, 1)?;
        out[0] = self.opcode();
        macro_rules! w16 {
            ($v:expr) => {{
                room(n, 2)?;
                put16(out, n, $v);
                n += 2;
            }};
        }
        macro_rules! bytes {
            ($v:expr) => {{
                let v: &[u8] = $v;
                room(n, v.len())?;
                out[n..n + v.len()].copy_from_slice(v);
                n += v.len();
            }};
        }
        match *self {
            Pdu::ErrorRsp { request, handle, code } => {
                room(n, 1)?;
                out[n] = request;
                n += 1;
                w16!(handle);
                room(n, 1)?;
                out[n] = code;
                n += 1;
            }
            Pdu::ExchangeMtuReq { mtu } | Pdu::ExchangeMtuRsp { mtu } => w16!(mtu),
            Pdu::FindInfoReq { start, end } => {
                w16!(start);
                w16!(end);
            }
            Pdu::FindInfoRsp { format, data } => {
                room(n, 1)?;
                out[n] = format;
                n += 1;
                bytes!(data);
            }
            Pdu::FindByTypeValueReq { start, end, attr_type, value } => {
                w16!(start);
                w16!(end);
                w16!(attr_type);
                bytes!(value);
            }
            Pdu::FindByTypeValueRsp { data } => bytes!(data),
            Pdu::ReadByTypeReq { start, end, uuid } | Pdu::ReadByGroupTypeReq { start, end, uuid } => {
                w16!(start);
                w16!(end);
                room(n, uuid.len())?;
                uuid.put(&mut out[n..]);
                n += uuid.len();
            }
            Pdu::ReadByTypeRsp { item_len, data } | Pdu::ReadByGroupTypeRsp { item_len, data } => {
                room(n, 1)?;
                out[n] = item_len;
                n += 1;
                bytes!(data);
            }
            Pdu::ReadReq { handle } => w16!(handle),
            Pdu::ReadRsp { value } | Pdu::ReadBlobRsp { value } => bytes!(value),
            Pdu::ReadBlobReq { handle, offset } => {
                w16!(handle);
                w16!(offset);
            }
            Pdu::WriteReq { handle, value }
            | Pdu::WriteCmd { handle, value }
            | Pdu::Notification { handle, value }
            | Pdu::Indication { handle, value } => {
                w16!(handle);
                bytes!(value);
            }
            Pdu::PrepareWriteReq { handle, offset, value } | Pdu::PrepareWriteRsp { handle, offset, value } => {
                w16!(handle);
                w16!(offset);
                bytes!(value);
            }
            Pdu::ExecuteWriteReq { flags } => {
                room(n, 1)?;
                out[n] = flags;
                n += 1;
            }
            Pdu::WriteRsp | Pdu::ExecuteWriteRsp | Pdu::Confirmation => {}
        }
        Ok(n)
    }
}

/// What the bearer of one connection tracks: the MTU, and the transactions in
/// flight in each direction.
#[derive(Clone, Copy, Debug, Default)]
pub struct Bearer {
    /// Effective MTU, once exchanged; `0` before (the default applies).
    mtu: u16,
    /// Opcode of our request awaiting its response, and when it expires.
    req: Option<(u8, u64)>,
    /// Our MTU request is the one in flight.
    exchanging: bool,
    /// Our indication awaits its confirmation, and when it expires.
    ind: Option<u64>,
    /// The peer's request awaits our response (the upper layer owes it).
    owed: bool,
    /// The MTU exchange happens once per connection, in either direction.
    exchanged: bool,
}

/// Why the bearer refused to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A request (or an indication) is still in flight.
    Busy,
    /// The PDU does not fit the MTU.
    TooBig,
    /// Not a PDU this side may send in this state (a response with no request owed).
    NotAllowed,
}

impl Bearer {
    pub const fn new() -> Bearer {
        Bearer { mtu: 0, req: None, exchanging: false, ind: None, owed: false, exchanged: false }
    }

    /// The MTU in force.
    pub fn mtu(&self) -> u16 {
        if self.mtu == 0 {
            DEFAULT_MTU
        } else {
            self.mtu
        }
    }

    /// Account for a PDU we are about to send; `Err` leaves the state alone.
    pub fn sending(&mut self, p: &Pdu, len: usize, now_ms: u64) -> Result<(), Refusal> {
        if len > self.mtu() as usize {
            return Err(Refusal::TooBig);
        }
        let opc = p.opcode();
        match class_of(opc) {
            Some(Class::Request) => {
                if self.req.is_some() {
                    return Err(Refusal::Busy);
                }
                if opc == op::EXCHANGE_MTU_REQ {
                    if self.exchanged {
                        return Err(Refusal::NotAllowed);
                    }
                    self.exchanging = true;
                }
                self.req = Some((opc, now_ms + TRANSACTION_TIMEOUT_MS));
            }
            Some(Class::Indication) => {
                if self.ind.is_some() {
                    return Err(Refusal::Busy);
                }
                self.ind = Some(now_ms + TRANSACTION_TIMEOUT_MS);
            }
            Some(Class::Response) => {
                if !self.owed {
                    return Err(Refusal::NotAllowed);
                }
                self.owed = false;
            }
            Some(Class::Confirmation) | Some(Class::Command) | Some(Class::Notification) | None => {}
        }
        Ok(())
    }

    /// Account for a received PDU. `Ok(true)` when it is for the upper layer;
    /// `Ok(false)` when the bearer consumed it; `Err(())` when the peer broke a
    /// rule (a second request while one is owed): the PDU is dropped.
    pub fn received(&mut self, p: &Pdu) -> Result<bool, ()> {
        match class_of(p.opcode()) {
            Some(Class::Request) => {
                if self.owed {
                    return Err(());
                }
                self.owed = true;
                Ok(true)
            }
            Some(Class::Response) => match self.req {
                Some((opc, _)) if response_matches(opc, p) => {
                    self.req = None;
                    if let Pdu::ExchangeMtuRsp { mtu } = *p {
                        self.exchanging = false;
                        self.exchanged = true;
                        self.mtu = mtu.clamp(DEFAULT_MTU, LOCAL_MTU);
                    }
                    if matches!(p, Pdu::ErrorRsp { .. }) {
                        self.exchanging = false;
                    }
                    Ok(true)
                }
                _ => Ok(false),
            },
            Some(Class::Confirmation) => {
                if self.ind.take().is_some() {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Some(Class::Command) | Some(Class::Notification) | Some(Class::Indication) | None => Ok(true),
        }
    }

    /// The MTU request from the peer: the effective MTU is the smaller of the
    /// two; it is applied when our response goes out. `None` when an exchange
    /// already happened (the peer's second request is answered with an error).
    pub fn peer_mtu(&mut self, peer: u16) -> Option<u16> {
        if self.exchanged || self.exchanging {
            return None;
        }
        self.exchanged = true;
        self.mtu = peer.clamp(DEFAULT_MTU, LOCAL_MTU);
        Some(LOCAL_MTU)
    }

    /// Whether a transaction we started timed out (the bearer is then dead:
    /// the specification has the link dropped).
    pub fn expired(&self, now_ms: u64) -> bool {
        matches!(self.req, Some((_, t)) if now_ms >= t) || matches!(self.ind, Some(t) if now_ms >= t)
    }
}

fn response_matches(req: u8, p: &Pdu) -> bool {
    use op::*;
    match *p {
        Pdu::ErrorRsp { request, .. } => request == req,
        Pdu::ExchangeMtuRsp { .. } => req == EXCHANGE_MTU_REQ,
        Pdu::FindInfoRsp { .. } => req == FIND_INFO_REQ,
        Pdu::FindByTypeValueRsp { .. } => req == FIND_BY_TYPE_VALUE_REQ,
        Pdu::ReadByTypeRsp { .. } => req == READ_BY_TYPE_REQ,
        Pdu::ReadRsp { .. } => req == READ_REQ,
        Pdu::ReadBlobRsp { .. } => req == READ_BLOB_REQ,
        Pdu::ReadByGroupTypeRsp { .. } => req == READ_BY_GROUP_TYPE_REQ,
        Pdu::WriteRsp => req == WRITE_REQ,
        Pdu::PrepareWriteRsp { .. } => req == PREPARE_WRITE_REQ,
        Pdu::ExecuteWriteRsp => req == EXECUTE_WRITE_REQ,
        _ => false,
    }
}
