// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The network messages: what a FRAME carries.
//!
//! * [`Declare`]: a node tells its neighbour what it subscribes to, what it can
//!   answer (queryables), which key-expression ids it defined, which liveliness
//!   tokens it holds.
//! * [`Push`]: a PUT or a DEL on a key.
//! * [`Request`] / [`Response`] / [`ResponseFinal`]: a query, its replies (or
//!   errors), and the end of the replies.
//! * [`Interest`]: ask the neighbour to send (and keep sending) declarations.
//!
//! Network messages have no length of their own: the decoder of one needs the
//! whole message to know where the next starts. OAM (0x1F) is not decoded.
//!
//! Every decoded string and byte array borrows from the input. A key is a
//! [`WireExpr`]: a scope (an id the sender declared, 0 for none) and a suffix.
//!
//! Extensions: those named in the specification are decoded into fields; an
//! unknown optional one is skipped, an unknown mandatory one (and the shared
//! memory extensions, which this codec does not implement) refuse the message.

use crate::codec::{read_exts, Error, Ext, ExtBody, ExtWriter, Reader, Result, Writer, Zid, Z};

const ID_INTEREST: u8 = 0x19;
const ID_RESPONSE_FINAL: u8 = 0x1A;
const ID_RESPONSE: u8 = 0x1B;
const ID_REQUEST: u8 = 0x1C;
const ID_PUSH: u8 = 0x1D;
const ID_DECLARE: u8 = 0x1E;

// Data sub-messages (their own id space, inside PUSH / REQUEST / RESPONSE).
const ID_PUT: u8 = 0x01;
const ID_DEL: u8 = 0x02;
const ID_QUERY: u8 = 0x03;
const ID_REPLY: u8 = 0x04;
const ID_ERR: u8 = 0x05;

// Declarations (their own id space, inside DECLARE).
const D_KEXPR: u8 = 0x00;
const U_KEXPR: u8 = 0x01;
const D_SUBSCRIBER: u8 = 0x02;
const U_SUBSCRIBER: u8 = 0x03;
const D_QUERYABLE: u8 = 0x04;
const U_QUERYABLE: u8 = 0x05;
const D_TOKEN: u8 = 0x06;
const U_TOKEN: u8 = 0x07;
const D_FINAL: u8 = 0x1A;

const FLAG_N: u8 = 0x20;
const FLAG_M: u8 = 0x40;

// ---- shared pieces ---------------------------------------------------------

/// A key on the wire: `scope` is an id the sender defined with a key-expression
/// declaration (0: none, the key is the suffix alone) and `suffix` is appended
/// to what the scope stands for. `sender` (flag M) says the scope is from the
/// sender's table, otherwise from the receiver's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireExpr<'a> {
    pub scope: u16,
    pub suffix: &'a str,
    pub sender: bool,
}

impl<'a> WireExpr<'a> {
    /// A key with no scope: the suffix is the whole expression.
    pub fn plain(suffix: &'a str) -> Self {
        WireExpr { scope: 0, suffix, sender: true }
    }
}

fn read_key<'a>(r: &mut Reader<'a>, h: u8) -> Result<WireExpr<'a>> {
    let scope = r.vle16()?;
    let suffix = if h & FLAG_N != 0 { r.str16()? } else { "" };
    Ok(WireExpr { scope, suffix, sender: h & FLAG_M != 0 })
}

/// The N and M flag bits for a key.
fn key_flags(k: &WireExpr<'_>) -> u8 {
    (if k.suffix.is_empty() { 0 } else { FLAG_N }) | (if k.sender { FLAG_M } else { 0 })
}

fn write_key(w: &mut Writer, k: &WireExpr<'_>) -> Result<()> {
    w.vle(k.scope as u64);
    if !k.suffix.is_empty() {
        w.z16(k.suffix.as_bytes())?;
    }
    Ok(())
}

/// The QoS extension byte: priority in bits 2..0 (5 is the default, Data), D
/// (bit 3) block instead of drop on congestion, E (bit 4) express: do not batch,
/// F (bit 5) block-first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Qos(pub u8);

impl Qos {
    pub const DEFAULT: Qos = Qos(5);

    pub fn priority(self) -> u8 {
        self.0 & 7
    }

    pub fn block(self) -> bool {
        self.0 & 0x08 != 0
    }

    pub fn express(self) -> bool {
        self.0 & 0x10 != 0
    }
}

/// A hybrid-logical-clock timestamp: NTP64 time and the ZenohID of the clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timestamp {
    pub time: u64,
    pub zid: Zid,
}

fn read_ts(r: &mut Reader<'_>) -> Result<Timestamp> {
    let time = r.vle()?;
    let id = r.z8()?;
    Ok(Timestamp { time, zid: Zid::new(id)? })
}

fn write_ts(w: &mut Writer, t: &Timestamp) -> Result<()> {
    w.vle(t.time);
    w.z8(t.zid.as_slice())
}

/// The data encoding of a payload: an id (0 raw bytes, 1 UTF-8 text, ...) and
/// an optional schema. On the wire: `id << 1 | has_schema` as a VLE, then the
/// schema as `<u8;z8>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Encoding<'a> {
    pub id: u32,
    pub schema: Option<&'a [u8]>,
}

fn read_encoding<'a>(r: &mut Reader<'a>) -> Result<Encoding<'a>> {
    let v = r.vle32()?;
    let schema = if v & 1 != 0 { Some(r.z8()?) } else { None };
    Ok(Encoding { id: v >> 1, schema })
}

fn write_encoding(w: &mut Writer, e: &Encoding<'_>) -> Result<()> {
    if e.id > u32::MAX >> 1 {
        return Err(Error::Overflow);
    }
    w.vle(((e.id << 1) | e.schema.is_some() as u32) as u64);
    if let Some(s) = e.schema {
        w.z8(s)?;
    }
    Ok(())
}

/// Who produced a datum and its number there (extension SourceInfo).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceInfo {
    pub zid: Zid,
    pub eid: u32,
    pub sn: u32,
}

fn read_zid_nibble(r: &mut Reader<'_>) -> Result<Zid> {
    let h = r.u8()?;
    r.zid((h >> 4) as usize + 1)
}

fn exact<'a, T>(mut r: Reader<'a>, f: impl FnOnce(&mut Reader<'a>) -> Result<T>) -> Result<T> {
    let v = f(&mut r)?;
    if r.is_empty() {
        Ok(v)
    } else {
        Err(Error::BadValue("extension has trailing bytes"))
    }
}

fn read_source_info(b: &[u8]) -> Result<SourceInfo> {
    exact(Reader::new(b), |r| {
        let zid = read_zid_nibble(r)?;
        Ok(SourceInfo { zid, eid: r.vle32()?, sn: r.vle32()? })
    })
}

fn write_zid_nibble(w: &mut Writer, z: &Zid) {
    w.u8(z.nibble() << 4);
    w.bytes(z.as_slice());
}

fn source_info_bytes(s: &SourceInfo) -> Writer {
    let mut b = Writer::new();
    write_zid_nibble(&mut b, &s.zid);
    b.vle(s.eid as u64);
    b.vle(s.sn as u64);
    b
}

/// What a REPLY (or ERR) answering a query says about the responder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponderId {
    pub zid: Zid,
    pub eid: u32,
}

/// How a query's replies are consolidated (the byte of QUERY and REPLY).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consolidation {
    Auto = 0,
    None = 1,
    Monotonic = 2,
    Latest = 3,
}

impl Consolidation {
    fn from_byte(b: u8) -> Result<Consolidation> {
        match b {
            0 => Ok(Consolidation::Auto),
            1 => Ok(Consolidation::None),
            2 => Ok(Consolidation::Monotonic),
            3 => Ok(Consolidation::Latest),
            _ => Err(Error::BadValue("consolidation")),
        }
    }
}

/// Which queryables a query is for (extension QueryTarget).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryTarget {
    BestMatching = 0,
    All = 1,
    AllComplete = 2,
}

impl QueryTarget {
    fn from_u64(v: u64) -> Result<QueryTarget> {
        match v {
            0 => Ok(QueryTarget::BestMatching),
            1 => Ok(QueryTarget::All),
            2 => Ok(QueryTarget::AllComplete),
            _ => Err(Error::BadValue("query target")),
        }
    }
}

/// The extensions every network message may carry (QoS, Timestamp), and NodeId
/// (id 3, Z64, mandatory) on those that are forwarded. One handler for the three.
fn common_ext(e: &Ext<'_>, qos: &mut Option<Qos>, ts: &mut Option<Timestamp>) -> Result<bool> {
    match (e.id, &e.body) {
        (1, ExtBody::Z64(v)) => {
            *qos = Some(Qos(*v as u8));
            Ok(true)
        }
        (2, ExtBody::ZBuf(b)) => {
            *ts = Some(exact(Reader::new(b), read_ts)?);
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn node_ext(e: &Ext<'_>, node: &mut Option<u16>) -> Result<bool> {
    match (e.id, &e.body) {
        (3, ExtBody::Z64(v)) => {
            *node = Some(u16::try_from(*v).map_err(|_| Error::Overflow)?);
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn put_common(
    x: &mut ExtWriter,
    w: &mut Writer,
    qos: Option<Qos>,
    ts: Option<&Timestamp>,
) -> Result<()> {
    if let Some(q) = qos {
        x.z64(w, 1, false, q.0 as u64);
    }
    if let Some(t) = ts {
        let mut b = Writer::new();
        write_ts(&mut b, t)?;
        x.zbuf(w, 2, false, b.as_slice())?;
    }
    Ok(())
}

fn put_node(x: &mut ExtWriter, w: &mut Writer, node: Option<u16>) {
    if let Some(n) = node {
        x.z64(w, 3, true, n as u64);
    }
}

// ---- data sub-messages ---------------------------------------------------------

/// PUT: a value on a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Put<'a> {
    pub timestamp: Option<Timestamp>,
    pub encoding: Option<Encoding<'a>>,
    pub source_info: Option<SourceInfo>,
    pub attachment: Option<&'a [u8]>,
    pub payload: &'a [u8],
}

/// DEL: the value on a key is gone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Del<'a> {
    pub timestamp: Option<Timestamp>,
    pub source_info: Option<SourceInfo>,
    pub attachment: Option<&'a [u8]>,
}

/// What a PUSH, or a REPLY, carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushBody<'a> {
    Put(Put<'a>),
    Del(Del<'a>),
}

impl<'a> PushBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<PushBody<'a>> {
        let h = r.u8()?;
        let z = h & Z != 0;
        match h & 0x1F {
            ID_PUT => {
                let timestamp = if h & 0x20 != 0 { Some(read_ts(r)?) } else { None };
                let encoding = if h & 0x40 != 0 { Some(read_encoding(r)?) } else { None };
                let (mut source_info, mut attachment) = (None, None);
                if z {
                    read_exts(r, |e| match (e.id, &e.body) {
                        (1, ExtBody::ZBuf(b)) => {
                            source_info = Some(read_source_info(b)?);
                            Ok(true)
                        }
                        (3, ExtBody::ZBuf(b)) => {
                            attachment = Some(*b);
                            Ok(true)
                        }
                        _ => Ok(false),
                    })?;
                }
                let payload = r.z32()?;
                Ok(PushBody::Put(Put { timestamp, encoding, source_info, attachment, payload }))
            }
            ID_DEL => {
                let timestamp = if h & 0x20 != 0 { Some(read_ts(r)?) } else { None };
                let (mut source_info, mut attachment) = (None, None);
                if z {
                    read_exts(r, |e| match (e.id, &e.body) {
                        (1, ExtBody::ZBuf(b)) => {
                            source_info = Some(read_source_info(b)?);
                            Ok(true)
                        }
                        (2, ExtBody::ZBuf(b)) => {
                            attachment = Some(*b);
                            Ok(true)
                        }
                        _ => Ok(false),
                    })?;
                }
                Ok(PushBody::Del(Del { timestamp, source_info, attachment }))
            }
            id => Err(Error::Unsupported(id)),
        }
    }

    fn encode(&self, w: &mut Writer) -> Result<()> {
        let hp = w.pos();
        let mut x = ExtWriter::new(hp);
        match self {
            PushBody::Put(p) => {
                w.u8(ID_PUT
                    | ((p.timestamp.is_some() as u8) << 5)
                    | ((p.encoding.is_some() as u8) << 6));
                if let Some(t) = &p.timestamp {
                    write_ts(w, t)?;
                }
                if let Some(e) = &p.encoding {
                    write_encoding(w, e)?;
                }
                if let Some(s) = &p.source_info {
                    x.zbuf(w, 1, false, source_info_bytes(s).as_slice())?;
                }
                if let Some(a) = p.attachment {
                    x.zbuf(w, 3, false, a)?;
                }
                x.finish(w);
                w.z32(p.payload)
            }
            PushBody::Del(d) => {
                w.u8(ID_DEL | ((d.timestamp.is_some() as u8) << 5));
                if let Some(t) = &d.timestamp {
                    write_ts(w, t)?;
                }
                if let Some(s) = &d.source_info {
                    x.zbuf(w, 1, false, source_info_bytes(s).as_slice())?;
                }
                if let Some(a) = d.attachment {
                    x.zbuf(w, 2, false, a)?;
                }
                x.finish(w);
                Ok(())
            }
        }
    }
}

/// QUERY: what a REQUEST asks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query<'a> {
    pub consolidation: Option<Consolidation>,
    /// Empty: none.
    pub parameters: &'a str,
    pub source_info: Option<SourceInfo>,
    /// A value sent with the query (extension QueryBody): encoding, then payload.
    pub body: Option<(Encoding<'a>, &'a [u8])>,
    pub attachment: Option<&'a [u8]>,
}

impl<'a> Query<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Query<'a>> {
        let h = r.u8()?;
        if h & 0x1F != ID_QUERY {
            return Err(Error::Unsupported(h & 0x1F));
        }
        let consolidation =
            if h & 0x20 != 0 { Some(Consolidation::from_byte(r.u8()?)?) } else { None };
        let parameters = if h & 0x40 != 0 { r.str16()? } else { "" };
        let (mut source_info, mut body, mut attachment) = (None, None, None);
        if h & Z != 0 {
            read_exts(r, |e| match (e.id, &e.body) {
                (1, ExtBody::ZBuf(b)) => {
                    source_info = Some(read_source_info(b)?);
                    Ok(true)
                }
                (3, ExtBody::ZBuf(b)) => {
                    body = Some(exact(Reader::new(b), |s| {
                        let enc = read_encoding(s)?;
                        Ok((enc, s.z32()?))
                    })?);
                    Ok(true)
                }
                (5, ExtBody::ZBuf(b)) => {
                    attachment = Some(*b);
                    Ok(true)
                }
                _ => Ok(false),
            })?;
        }
        Ok(Query { consolidation, parameters, source_info, body, attachment })
    }

    fn encode(&self, w: &mut Writer) -> Result<()> {
        let hp = w.pos();
        w.u8(ID_QUERY
            | ((self.consolidation.is_some() as u8) << 5)
            | (((!self.parameters.is_empty()) as u8) << 6));
        if let Some(c) = self.consolidation {
            w.u8(c as u8);
        }
        if !self.parameters.is_empty() {
            w.z16(self.parameters.as_bytes())?;
        }
        let mut x = ExtWriter::new(hp);
        if let Some(s) = &self.source_info {
            x.zbuf(w, 1, false, source_info_bytes(s).as_slice())?;
        }
        if let Some((enc, payload)) = &self.body {
            let mut b = Writer::new();
            write_encoding(&mut b, enc)?;
            b.z32(payload)?;
            x.zbuf(w, 3, false, b.as_slice())?;
        }
        if let Some(a) = self.attachment {
            x.zbuf(w, 5, false, a)?;
        }
        x.finish(w);
        Ok(())
    }
}

/// REPLY: one answer to a query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply<'a> {
    pub consolidation: Option<Consolidation>,
    pub body: PushBody<'a>,
}

/// ERR: an error answer to a query; the payload is the application's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrBody<'a> {
    pub encoding: Option<Encoding<'a>>,
    pub source_info: Option<SourceInfo>,
    pub payload: &'a [u8],
}

/// What a RESPONSE carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseBody<'a> {
    Reply(Reply<'a>),
    Err(ErrBody<'a>),
}

impl<'a> ResponseBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<ResponseBody<'a>> {
        let h = r.u8()?;
        let z = h & Z != 0;
        match h & 0x1F {
            ID_REPLY => {
                let consolidation =
                    if h & 0x20 != 0 { Some(Consolidation::from_byte(r.u8()?)?) } else { None };
                if z {
                    read_exts(r, |_| Ok(false))?;
                }
                Ok(ResponseBody::Reply(Reply { consolidation, body: PushBody::decode(r)? }))
            }
            ID_ERR => {
                let encoding = if h & 0x40 != 0 { Some(read_encoding(r)?) } else { None };
                let mut source_info = None;
                if z {
                    read_exts(r, |e| match (e.id, &e.body) {
                        (1, ExtBody::ZBuf(b)) => {
                            source_info = Some(read_source_info(b)?);
                            Ok(true)
                        }
                        _ => Ok(false),
                    })?;
                }
                Ok(ResponseBody::Err(ErrBody { encoding, source_info, payload: r.z32()? }))
            }
            id => Err(Error::Unsupported(id)),
        }
    }

    fn encode(&self, w: &mut Writer) -> Result<()> {
        match self {
            ResponseBody::Reply(p) => {
                w.u8(ID_REPLY | ((p.consolidation.is_some() as u8) << 5));
                if let Some(c) = p.consolidation {
                    w.u8(c as u8);
                }
                p.body.encode(w)
            }
            ResponseBody::Err(e) => {
                let hp = w.pos();
                w.u8(ID_ERR | ((e.encoding.is_some() as u8) << 6));
                if let Some(enc) = &e.encoding {
                    write_encoding(w, enc)?;
                }
                let mut x = ExtWriter::new(hp);
                if let Some(s) = &e.source_info {
                    x.zbuf(w, 1, false, source_info_bytes(s).as_slice())?;
                }
                x.finish(w);
                w.z32(e.payload)
            }
        }
    }
}

// ---- network messages ----------------------------------------------------------

/// PUSH (0x1D): a PUT or DEL on a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Push<'a> {
    pub key: WireExpr<'a>,
    pub qos: Option<Qos>,
    pub timestamp: Option<Timestamp>,
    pub node_id: Option<u16>,
    pub body: PushBody<'a>,
}

/// REQUEST (0x1C): a query. `id` is chosen by the sender and returned in every
/// RESPONSE and in the RESPONSE_FINAL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub id: u32,
    pub key: WireExpr<'a>,
    pub qos: Option<Qos>,
    pub timestamp: Option<Timestamp>,
    pub node_id: Option<u16>,
    pub target: Option<QueryTarget>,
    /// The most RESPONSEs wanted (extension Budget, non-zero).
    pub budget: Option<u32>,
    /// Milliseconds (extension Timeout).
    pub timeout_ms: Option<u64>,
    pub query: Query<'a>,
}

/// RESPONSE (0x1B): a REPLY or ERR for the request `id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response<'a> {
    pub id: u32,
    pub key: WireExpr<'a>,
    pub qos: Option<Qos>,
    pub timestamp: Option<Timestamp>,
    pub responder: Option<ResponderId>,
    pub body: ResponseBody<'a>,
}

/// RESPONSE_FINAL (0x1A): no more responses for the request `id` from this source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseFinal {
    pub id: u32,
    pub qos: Option<Qos>,
    pub timestamp: Option<Timestamp>,
}

/// What a DECLARE declares (or undeclares).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Declaration<'a> {
    /// Define `id` (u16) as shorthand for a key; later keys name it as their scope.
    KeyExpr { id: u16, key: WireExpr<'a> },
    UndeclareKeyExpr { id: u16 },
    Subscriber { id: u32, key: WireExpr<'a> },
    /// `key`: the extension WireExpr, which tells the receiver what the id stood for.
    UndeclareSubscriber { id: u32, key: Option<WireExpr<'a>> },
    /// `complete`: answers every key it declares, not a part of them; `distance`:
    /// hops away.
    Queryable { id: u32, key: WireExpr<'a>, complete: bool, distance: u16 },
    UndeclareQueryable { id: u32, key: Option<WireExpr<'a>> },
    /// A liveliness token.
    Token { id: u32, key: WireExpr<'a> },
    UndeclareToken { id: u32, key: Option<WireExpr<'a>> },
    /// The end of the current declarations an INTEREST asked for.
    Final,
}

/// DECLARE (0x1E).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declare<'a> {
    /// The INTEREST this answers (flag I).
    pub interest_id: Option<u32>,
    pub qos: Option<Qos>,
    pub timestamp: Option<Timestamp>,
    pub node_id: Option<u16>,
    pub body: Declaration<'a>,
}

/// What an INTEREST asks for (bits 6..5 of its header).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterestMode {
    /// End a previous Future or CurrentFuture interest with the same id.
    Final = 0,
    /// The declarations that exist now, then a D_FINAL.
    Current = 1,
    /// The declarations from now on.
    Future = 2,
    /// Both.
    CurrentFuture = 3,
}

/// The options byte of an INTEREST that is not Final.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterestOptions<'a> {
    pub keyexprs: bool,
    pub subscribers: bool,
    pub queryables: bool,
    pub tokens: bool,
    /// Flag A: the receiver should aggregate matching replies.
    pub aggregate: bool,
    /// Flag R (with N and M): only declarations that intersect this key.
    pub key: Option<WireExpr<'a>>,
}

/// INTEREST (0x19).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interest<'a> {
    pub id: u32,
    pub mode: InterestMode,
    /// `Some` exactly when `mode` is not `Final`.
    pub options: Option<InterestOptions<'a>>,
    pub qos: Option<Qos>,
    pub timestamp: Option<Timestamp>,
    pub node_id: Option<u16>,
}

/// One network message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkMsg<'a> {
    Push(Push<'a>),
    Request(Request<'a>),
    Response(Response<'a>),
    ResponseFinal(ResponseFinal),
    Declare(Declare<'a>),
    Interest(Interest<'a>),
}

fn read_wire_expr_ext<'a>(b: &'a [u8]) -> Result<WireExpr<'a>> {
    exact(Reader::new(b), |r| {
        let f = r.u8()?;
        let scope = r.vle16()?;
        let suffix = if f & 1 != 0 { r.str16()? } else { "" };
        Ok(WireExpr { scope, suffix, sender: f & 2 != 0 })
    })
}

fn wire_expr_ext_bytes(k: &WireExpr<'_>) -> Result<Writer> {
    let mut b = Writer::new();
    b.u8((k.sender as u8) << 1 | (!k.suffix.is_empty()) as u8);
    write_key(&mut b, k)?;
    Ok(b)
}

impl<'a> Declaration<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Declaration<'a>> {
        let h = r.u8()?;
        let z = h & Z != 0;
        let skip = |r: &mut Reader<'a>| -> Result<()> {
            if z {
                read_exts(r, |_| Ok(false))
            } else {
                Ok(())
            }
        };
        // Undeclarations: an id, and the extension that says what it stood for.
        let undeclare = |r: &mut Reader<'a>| -> Result<Option<WireExpr<'a>>> {
            let mut key = None;
            if z {
                read_exts(r, |e| match (e.id, &e.body) {
                    (0x0F, ExtBody::ZBuf(b)) => {
                        key = Some(read_wire_expr_ext(b)?);
                        Ok(true)
                    }
                    _ => Ok(false),
                })?;
            }
            Ok(key)
        };
        match h & 0x1F {
            D_KEXPR => {
                let id = r.vle16()?;
                // No M flag here: the scope is from the declarer's own table.
                let key = read_key(r, h | FLAG_M)?;
                skip(r)?;
                Ok(Declaration::KeyExpr { id, key })
            }
            U_KEXPR => {
                let id = r.vle16()?;
                skip(r)?;
                Ok(Declaration::UndeclareKeyExpr { id })
            }
            D_SUBSCRIBER => {
                let id = r.vle32()?;
                let key = read_key(r, h)?;
                skip(r)?;
                Ok(Declaration::Subscriber { id, key })
            }
            U_SUBSCRIBER => {
                let id = r.vle32()?;
                Ok(Declaration::UndeclareSubscriber { id, key: undeclare(r)? })
            }
            D_QUERYABLE => {
                let id = r.vle32()?;
                let key = read_key(r, h)?;
                let (mut complete, mut distance) = (false, 0u16);
                if z {
                    read_exts(r, |e| match (e.id, &e.body) {
                        (1, ExtBody::Z64(v)) => {
                            // Bit 0 complete, bits 1..8 reserved, bits 8..24 distance.
                            complete = v & 1 != 0;
                            distance = u16::try_from(v >> 8).map_err(|_| Error::Overflow)?;
                            Ok(true)
                        }
                        _ => Ok(false),
                    })?;
                }
                Ok(Declaration::Queryable { id, key, complete, distance })
            }
            U_QUERYABLE => {
                let id = r.vle32()?;
                Ok(Declaration::UndeclareQueryable { id, key: undeclare(r)? })
            }
            D_TOKEN => {
                let id = r.vle32()?;
                let key = read_key(r, h)?;
                skip(r)?;
                Ok(Declaration::Token { id, key })
            }
            U_TOKEN => {
                let id = r.vle32()?;
                Ok(Declaration::UndeclareToken { id, key: undeclare(r)? })
            }
            D_FINAL => {
                skip(r)?;
                Ok(Declaration::Final)
            }
            id => Err(Error::Unsupported(id)),
        }
    }

    fn encode(&self, w: &mut Writer) -> Result<()> {
        let hp = w.pos();
        let mut x = ExtWriter::new(hp);
        match self {
            Declaration::KeyExpr { id, key } => {
                w.u8(D_KEXPR | (key_flags(key) & FLAG_N));
                w.vle(*id as u64);
                write_key(w, key)?;
            }
            Declaration::UndeclareKeyExpr { id } => {
                w.u8(U_KEXPR);
                w.vle(*id as u64);
            }
            Declaration::Subscriber { id, key } => {
                w.u8(D_SUBSCRIBER | key_flags(key));
                w.vle(*id as u64);
                write_key(w, key)?;
            }
            Declaration::UndeclareSubscriber { id, key } => {
                w.u8(U_SUBSCRIBER);
                w.vle(*id as u64);
                if let Some(k) = key {
                    x.zbuf(w, 0x0F, true, wire_expr_ext_bytes(k)?.as_slice())?;
                }
            }
            Declaration::Queryable { id, key, complete, distance } => {
                w.u8(D_QUERYABLE | key_flags(key));
                w.vle(*id as u64);
                write_key(w, key)?;
                if *complete || *distance != 0 {
                    x.z64(w, 1, false, ((*distance as u64) << 8) | *complete as u64);
                }
            }
            Declaration::UndeclareQueryable { id, key } => {
                w.u8(U_QUERYABLE);
                w.vle(*id as u64);
                if let Some(k) = key {
                    x.zbuf(w, 0x0F, true, wire_expr_ext_bytes(k)?.as_slice())?;
                }
            }
            Declaration::Token { id, key } => {
                w.u8(D_TOKEN | key_flags(key));
                w.vle(*id as u64);
                write_key(w, key)?;
            }
            Declaration::UndeclareToken { id, key } => {
                w.u8(U_TOKEN);
                w.vle(*id as u64);
                if let Some(k) = key {
                    x.zbuf(w, 0x0F, true, wire_expr_ext_bytes(k)?.as_slice())?;
                }
            }
            Declaration::Final => w.u8(D_FINAL),
        }
        x.finish(w);
        Ok(())
    }
}

impl<'a> NetworkMsg<'a> {
    /// Decode one message from the front of `r`.
    pub fn decode(r: &mut Reader<'a>) -> Result<NetworkMsg<'a>> {
        let h = r.u8()?;
        let z = h & Z != 0;
        match h & 0x1F {
            ID_PUSH => {
                let key = read_key(r, h)?;
                let (mut qos, mut timestamp, mut node_id) = (None, None, None);
                if z {
                    read_exts(r, |e| {
                        Ok(common_ext(e, &mut qos, &mut timestamp)? || node_ext(e, &mut node_id)?)
                    })?;
                }
                let body = PushBody::decode(r)?;
                Ok(NetworkMsg::Push(Push { key, qos, timestamp, node_id, body }))
            }
            ID_REQUEST => {
                let id = r.vle32()?;
                let key = read_key(r, h)?;
                let (mut qos, mut timestamp, mut node_id) = (None, None, None);
                let (mut target, mut budget, mut timeout_ms) = (None, None, None);
                if z {
                    read_exts(r, |e| {
                        if common_ext(e, &mut qos, &mut timestamp)? || node_ext(e, &mut node_id)? {
                            return Ok(true);
                        }
                        match (e.id, &e.body) {
                            (4, ExtBody::Z64(v)) => {
                                target = Some(QueryTarget::from_u64(*v)?);
                                Ok(true)
                            }
                            (5, ExtBody::Z64(v)) => {
                                budget = Some(u32::try_from(*v).map_err(|_| Error::Overflow)?);
                                Ok(true)
                            }
                            (6, ExtBody::Z64(v)) => {
                                timeout_ms = Some(*v);
                                Ok(true)
                            }
                            _ => Ok(false),
                        }
                    })?;
                }
                let query = Query::decode(r)?;
                Ok(NetworkMsg::Request(Request {
                    id,
                    key,
                    qos,
                    timestamp,
                    node_id,
                    target,
                    budget,
                    timeout_ms,
                    query,
                }))
            }
            ID_RESPONSE => {
                let id = r.vle32()?;
                let key = read_key(r, h)?;
                let (mut qos, mut timestamp, mut responder) = (None, None, None);
                if z {
                    read_exts(r, |e| {
                        if common_ext(e, &mut qos, &mut timestamp)? {
                            return Ok(true);
                        }
                        match (e.id, &e.body) {
                            (3, ExtBody::ZBuf(b)) => {
                                responder = Some(exact(Reader::new(b), |s| {
                                    let zid = read_zid_nibble(s)?;
                                    Ok(ResponderId { zid, eid: s.vle32()? })
                                })?);
                                Ok(true)
                            }
                            _ => Ok(false),
                        }
                    })?;
                }
                let body = ResponseBody::decode(r)?;
                Ok(NetworkMsg::Response(Response { id, key, qos, timestamp, responder, body }))
            }
            ID_RESPONSE_FINAL => {
                let id = r.vle32()?;
                let (mut qos, mut timestamp) = (None, None);
                if z {
                    read_exts(r, |e| common_ext(e, &mut qos, &mut timestamp))?;
                }
                Ok(NetworkMsg::ResponseFinal(ResponseFinal { id, qos, timestamp }))
            }
            ID_DECLARE => {
                let interest_id = if h & 0x20 != 0 { Some(r.vle32()?) } else { None };
                let (mut qos, mut timestamp, mut node_id) = (None, None, None);
                if z {
                    read_exts(r, |e| {
                        Ok(common_ext(e, &mut qos, &mut timestamp)? || node_ext(e, &mut node_id)?)
                    })?;
                }
                let body = Declaration::decode(r)?;
                Ok(NetworkMsg::Declare(Declare { interest_id, qos, timestamp, node_id, body }))
            }
            ID_INTEREST => {
                let mode = match (h >> 5) & 3 {
                    0 => InterestMode::Final,
                    1 => InterestMode::Current,
                    2 => InterestMode::Future,
                    _ => InterestMode::CurrentFuture,
                };
                let id = r.vle32()?;
                let options = if mode == InterestMode::Final {
                    None
                } else {
                    let o = r.u8()?;
                    let key = if o & 0x10 != 0 {
                        Some(read_key(r, (o & FLAG_N) | (o & FLAG_M))?)
                    } else if o & (FLAG_N | FLAG_M) != 0 {
                        return Err(Error::BadValue("interest N or M without R"));
                    } else {
                        None
                    };
                    Some(InterestOptions {
                        keyexprs: o & 0x01 != 0,
                        subscribers: o & 0x02 != 0,
                        queryables: o & 0x04 != 0,
                        tokens: o & 0x08 != 0,
                        aggregate: o & 0x80 != 0,
                        key,
                    })
                };
                let (mut qos, mut timestamp, mut node_id) = (None, None, None);
                if z {
                    read_exts(r, |e| {
                        Ok(common_ext(e, &mut qos, &mut timestamp)? || node_ext(e, &mut node_id)?)
                    })?;
                }
                Ok(NetworkMsg::Interest(Interest { id, mode, options, qos, timestamp, node_id }))
            }
            id => Err(Error::Unsupported(id)),
        }
    }

    /// Append the message to `w`.
    pub fn encode(&self, w: &mut Writer) -> Result<()> {
        let hp = w.pos();
        let mut x = ExtWriter::new(hp);
        match self {
            NetworkMsg::Push(m) => {
                w.u8(ID_PUSH | key_flags(&m.key));
                write_key(w, &m.key)?;
                put_common(&mut x, w, m.qos, m.timestamp.as_ref())?;
                put_node(&mut x, w, m.node_id);
                x.finish(w);
                m.body.encode(w)
            }
            NetworkMsg::Request(m) => {
                w.u8(ID_REQUEST | key_flags(&m.key));
                w.vle(m.id as u64);
                write_key(w, &m.key)?;
                put_common(&mut x, w, m.qos, m.timestamp.as_ref())?;
                put_node(&mut x, w, m.node_id);
                if let Some(t) = m.target {
                    x.z64(w, 4, true, t as u64);
                }
                if let Some(b) = m.budget {
                    x.z64(w, 5, false, b as u64);
                }
                if let Some(t) = m.timeout_ms {
                    x.z64(w, 6, false, t);
                }
                x.finish(w);
                m.query.encode(w)
            }
            NetworkMsg::Response(m) => {
                w.u8(ID_RESPONSE | key_flags(&m.key));
                w.vle(m.id as u64);
                write_key(w, &m.key)?;
                put_common(&mut x, w, m.qos, m.timestamp.as_ref())?;
                if let Some(rid) = &m.responder {
                    let mut b = Writer::new();
                    write_zid_nibble(&mut b, &rid.zid);
                    b.vle(rid.eid as u64);
                    x.zbuf(w, 3, false, b.as_slice())?;
                }
                x.finish(w);
                m.body.encode(w)
            }
            NetworkMsg::ResponseFinal(m) => {
                w.u8(ID_RESPONSE_FINAL);
                w.vle(m.id as u64);
                put_common(&mut x, w, m.qos, m.timestamp.as_ref())?;
                x.finish(w);
                Ok(())
            }
            NetworkMsg::Declare(m) => {
                w.u8(ID_DECLARE | ((m.interest_id.is_some() as u8) << 5));
                if let Some(i) = m.interest_id {
                    w.vle(i as u64);
                }
                put_common(&mut x, w, m.qos, m.timestamp.as_ref())?;
                put_node(&mut x, w, m.node_id);
                x.finish(w);
                m.body.encode(w)
            }
            NetworkMsg::Interest(m) => {
                w.u8(ID_INTEREST | ((m.mode as u8) << 5));
                w.vle(m.id as u64);
                match (m.mode, &m.options) {
                    (InterestMode::Final, None) => {}
                    (InterestMode::Final, Some(_)) | (_, None) => {
                        return Err(Error::BadValue("interest options do not match its mode"));
                    }
                    (_, Some(o)) => {
                        w.u8(o.keyexprs as u8
                            | (o.subscribers as u8) << 1
                            | (o.queryables as u8) << 2
                            | (o.tokens as u8) << 3
                            | (o.key.is_some() as u8) << 4
                            | o.key.as_ref().map_or(0, key_flags)
                            | (o.aggregate as u8) << 7);
                        if let Some(k) = &o.key {
                            write_key(w, k)?;
                        }
                    }
                }
                put_common(&mut x, w, m.qos, m.timestamp.as_ref())?;
                put_node(&mut x, w, m.node_id);
                x.finish(w);
                Ok(())
            }
        }
    }
}
