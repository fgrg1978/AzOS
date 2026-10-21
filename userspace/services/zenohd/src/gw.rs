// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The gateway engine: one Zenoh client session over a stream link, the
//! queryables it declares from the topology's exports, the op each query turns
//! into, and the decision records it publishes.
//!
//! Pure: no socket, no clock, no capability of its own. The kernel host
//! (`main.rs`) and the host tests (`tests/host/zenohd-tests`, a scripted
//! router) implement [`Host`] (time, the two kinds of call) and [`Link`]
//! (bytes out); the engine is fed the bytes that come in.
//!
//! # A query is one op
//!
//! A `REQUEST` whose key names an op of an export ([`crate::route`]) is turned
//! into one IDL call. **The gateway holds the authority of its row and no more:**
//! for each query it asks the kernel for a warrant (`Host::invoke`: an
//! attenuated copy of the export's endpoint, call right only, badged with the
//! gateway's own id of the query, lapsing with the query), calls the op
//! through it and drops it.
//! What the kernel admits or refuses is the kernel's: the gateway checks no
//! right of its own, so it cannot grant one. It never lends and never forwards
//! a warrant (the warrant transport between nodes is `rpcsrv`).
//!
//! The query's body is the op's arguments, one little-endian `u64` per request
//! word after the header (the interface's own wire form, no schema: the op
//! table says how many). The answer is a `REPLY` when the op ran and an `ERR`
//! when it did not, with the same payload, little-endian `u64` words:
//!
//! | word | meaning |
//! |------|---------|
//! | 0 | [`code`]: `SERVED`, `REFUSED` (the kernel refused the warrant or the call), `BAD_REQUEST` (arguments do not fit the op), `FAILED` (the server answered with an IDL error status), `BUSY` (over the query rate) |
//! | 1 | **the receipt**: the id of the newest decision record the kernel wrote for this gateway while the op ran (`why <id>`), 0 when it wrote none |
//! | 2 | the receipt's rule (bits 0..8) and verdict (bits 8..16) |
//! | 3 | the IDL reply status (`SERVED`/`FAILED`), or the kernel's negative code as a two's-complement word (`REFUSED`) |
//! | 4.. | the op's reply words after the status (`SERVED`) |
//!
//! The receipt of a refusal is the kernel's own record of it (a capability
//! denial, a refused effect), written under the gateway's task id. The receipt
//! of an admitted op is the derive record of its warrant when the kernel keeps
//! admissions (Kconfig `DECISION_RECORDS_DEV`), otherwise 0; that record is
//! written under the gateway's Domain, not its task id, so it is told by the
//! expiry the gateway gave the warrant (a nanosecond clock reading, no other
//! task's derive carries it). Both are found through the `Decisions` object,
//! among the records after the decision total read before the call; the newest
//! is the receipt. The gateway handles one query at a time, so a refusal under
//! its task id is the query's own.
//!
//! # Decisions as topics
//!
//! With a topic prefix configured, every decision record the `Decisions` object
//! holds is published, as it appears, under `<prefix>/<rule>/<verdict>`
//! (`azos/decisions/cap-denial/deny`), the payload the record's fixed-size
//! binary form (`ProvenanceRecord::to_bytes`, the one the admin
//! introspection region publishes). At most [`PUBLISH_BURST`] per [`PUBLISH_PERIOD_NS`]; records that were
//! overwritten before they could be read are counted, not hidden.
//!
//! # What is not done
//!
//! Fragmented messages (a query or a declaration over one batch), scouting,
//! multicast, authentication extensions and liveliness are not handled; the
//! codec (`userspace/lib/zenoh`) does not decode them either.

use crate::route::{route, Export, NoRoute};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use azos_decision::{Rule, Verdict};
use azos_decisions::{DecisionsCall, DecisionsClient, Filter, ProvenanceRecord, QUERY_IDS, RULES, VERDICTS};
use azos_idl::{header, IdlError, MsgDesc, Transport, MSG_VERSION};
use azos_zenoh::codec::Writer;
use azos_zenoh::network::{
    Declaration, Declare, ErrBody, Interest, InterestMode, NetworkMsg, Push, PushBody, Put, Reply, Request, Response,
    ResponderId, ResponseBody, ResponseFinal, WireExpr,
};
use azos_zenoh::transport::{
    decode_batch, encode_frame, reason, split_stream, stream_prefix, Close, Init, Lease, Open, Resolution,
    SizeParams, Transport as Msg, WhatAmI, VERSION,
};
use azos_zenoh::{Zid, keyexpr};

/// The word 0 of an answer.
pub mod code {
    pub const SERVED: u64 = 0;
    pub const REFUSED: u64 = 1;
    pub const BAD_REQUEST: u64 = 2;
    pub const FAILED: u64 = 3;
    pub const BUSY: u64 = 4;
}

/// The batch size the gateway offers: the most it will read or write in one
/// link message. A query over it never reaches the engine.
pub const BATCH: u16 = 2048;
/// Decision records published per period, at most.
pub const PUBLISH_BURST: usize = 8;
/// The period of publishing.
pub const PUBLISH_PERIOD_NS: u64 = 100_000_000;
/// Key-expression ids the router may define for itself.
const KEYS_MAX: usize = 64;
/// Pages of one receipt search (each holds [`QUERY_IDS`] ids).
const RECEIPT_PAGES: usize = 8;

/// The settings, from Kconfig and the entropy pool.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub zid: Zid,
    /// The first frame sequence number (random: a replayed frame is not valid).
    pub initial_sn: u64,
    /// How long this side tolerates silence from the router, ms.
    pub lease_ms: u64,
    /// The longest a warrant lives, ms: a query's own timeout counts when it is shorter.
    pub timeout_max_ms: u64,
    /// Queries served per second, at most.
    pub query_rate: u32,
    /// The prefix decision records are published under; empty: none.
    pub topic: &'static str,
    /// The subject the kernel writes this task's refusals under: its task id.
    pub me: u32,
}

/// The authority of one op, relative to the moment the host mints it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Warrant {
    /// The gateway's id of this query: a counter it assigns, never 0. The
    /// server sees it as the badge of the call, so a call is told from the
    /// next and a receipt is matched to it. **It does not name the requester**:
    /// the ZenohID a query carries (`source_info`) is written by the querier,
    /// the link authenticates nobody, and so the gateway vouches for none.
    pub badge: u32,
    /// The warrant lapses this long after it is minted.
    pub life_ns: u64,
    /// The call's deadline, from the call.
    pub deadline_ns: u64,
}

/// What the engine needs from its surroundings.
pub trait Host {
    fn now_ns(&mut self) -> u64;
    fn log(&mut self, line: &str);
    /// Call `req` on the export endpoint `endpoint` through a warrant minted for
    /// the call and dropped after it; the reply replaces `req`.
    fn invoke(&mut self, endpoint: u32, req: &mut MsgDesc, w: &Warrant) -> Invoked;
    /// One call on the `Decisions` endpoint.
    fn decisions(&mut self, req: &mut MsgDesc) -> Result<(), i64>;
}

/// What [`Host::invoke`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invoked {
    /// `Err` is the kernel's negative code: the warrant or the call was refused.
    pub result: Result<(), i64>,
    /// The expiry the warrant was minted with, absolute nanoseconds; 0 when
    /// none was minted.
    pub expiry_ns: u64,
}

/// Where bytes go: one write is one stream-framed batch (prefix included).
pub trait Link {
    fn send(&mut self, bytes: &[u8]) -> bool;
}

/// Where a session is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Nothing sent: [`Gw::start`] has not run.
    Idle,
    /// InitSyn sent.
    InitSent,
    /// OpenSyn sent.
    OpenSent,
    /// The queryables are declared.
    Up,
    /// Closed, by either side.
    Dead,
}

/// What the engine counted: the tests read it, the host logs it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub queries: u32,
    pub served: u32,
    pub refused: u32,
    pub bad: u32,
    pub busy: u32,
    pub unrouted: u32,
    pub published: u32,
    /// Decision records overwritten before they could be published.
    pub lost: u64,
    /// Messages of a kind the engine does not handle (fragments, ...).
    pub ignored: u32,
}

/// The session.
pub struct Gw {
    cfg: Config,
    exports: Vec<Export>,
    state: State,
    rx: Vec<u8>,
    tx_sn: u64,
    sn_mask: u64,
    batch: usize,
    cookie: Vec<u8>,
    /// The id the next query's warrant carries (never 0).
    next_badge: u32,
    peer_lease_ms: u64,
    last_rx: u64,
    last_tx: u64,
    keys: Vec<(u16, String)>,
    cursor: u64,
    last_publish: u64,
    window_start: u64,
    window_count: u32,
    pub stats: Stats,
}

/// The decisions endpoint as a transport for the generated client.
struct Dec<'a, H: Host>(core::cell::RefCell<&'a mut H>);

impl<H: Host> Transport for Dec<'_, H> {
    fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
        self.0.borrow_mut().decisions(msg).map_err(|rc| IdlError::Transport(rc as isize))
    }
}

/// The decision total now (the newest id held when nothing newer is asked for).
fn total<C: DecisionsCall>(c: &C) -> Option<u64> {
    let r = c.query(Filter { after: u64::MAX, ..Filter::ANY }.pack()).ok()?;
    Some(azos_decisions::unpack_count(r[0]).1)
}

/// The newest decision of `subject` after `mark`.
fn newest_of<C: DecisionsCall>(c: &C, subject: u32, mark: u64) -> Option<ProvenanceRecord> {
    let mut f = Filter { subject: Some(subject), after: mark, ..Filter::ANY };
    let mut newest = 0;
    for _ in 0..RECEIPT_PAGES {
        let r = c.query(f.pack()).ok()?;
        let n = azos_decisions::unpack_count(r[0]).0.min(QUERY_IDS);
        if n == 0 {
            break;
        }
        newest = r[n];
        f.after = newest;
        if n < QUERY_IDS {
            break;
        }
    }
    if newest == 0 {
        return None;
    }
    azos_decisions::fetch(c, newest).ok().flatten()
}

/// The derive record of the warrant minted with `expiry_ns`, after `mark`.
fn derive_of<C: DecisionsCall>(c: &C, mark: u64, expiry_ns: u64) -> Option<ProvenanceRecord> {
    let mut f = Filter {
        rule: Some(Rule::CapDerive as u8),
        verdict: Some(Verdict::Admit as u8),
        after: mark,
        ..Filter::ANY
    };
    for _ in 0..RECEIPT_PAGES {
        let r = c.query(f.pack()).ok()?;
        let n = azos_decisions::unpack_count(r[0]).0.min(QUERY_IDS);
        for &id in &r[1..1 + n] {
            if let Some(p) = azos_decisions::fetch(c, id).ok().flatten() {
                if p.n[2] == expiry_ns {
                    return Some(p);
                }
            }
        }
        if n < QUERY_IDS {
            break;
        }
        f.after = r[n];
    }
    None
}

/// The receipt of an op: the newest of the gateway's own decisions and its
/// warrant's derive record.
fn receipt<C: DecisionsCall>(c: &C, me: u32, mark: u64, expiry_ns: u64) -> Option<ProvenanceRecord> {
    let own = newest_of(c, me, mark);
    let derive = if expiry_ns != 0 { derive_of(c, mark, expiry_ns) } else { None };
    match (own, derive) {
        (Some(a), Some(b)) => Some(if a.seq > b.seq { a } else { b }),
        (a, b) => a.or(b),
    }
}

fn words_le(w: &[u64]) -> Vec<u8> {
    let mut v = Vec::with_capacity(w.len() * 8);
    for x in w {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v
}

impl Gw {
    pub fn new(cfg: Config, exports: Vec<Export>) -> Gw {
        Gw {
            cfg,
            exports,
            state: State::Idle,
            rx: Vec::new(),
            tx_sn: cfg.initial_sn,
            sn_mask: u32::MAX as u64,
            batch: BATCH as usize,
            cookie: Vec::new(),
            next_badge: 1,
            peer_lease_ms: 0,
            last_rx: 0,
            last_tx: 0,
            keys: Vec::new(),
            cursor: 0,
            last_publish: 0,
            window_start: 0,
            window_count: 0,
            stats: Stats::default(),
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Forget the session (a new link): the exports and the counters stay.
    pub fn reset(&mut self) {
        let (cfg, exports, stats) = (self.cfg, core::mem::take(&mut self.exports), self.stats);
        *self = Gw::new(cfg, exports);
        self.stats = stats;
    }

    // ── sending ─────────────────────────────────────────────────────────────

    fn send_batch<H: Host, L: Link>(&mut self, host: &mut H, link: &mut L, batch: &[u8]) -> bool {
        let Ok(prefix) = stream_prefix(batch.len()) else { return false };
        if batch.len() > self.batch {
            return false;
        }
        let mut out = Vec::with_capacity(2 + batch.len());
        out.extend_from_slice(&prefix);
        out.extend_from_slice(batch);
        self.last_tx = host.now_ns();
        if link.send(&out) {
            true
        } else {
            self.state = State::Dead;
            false
        }
    }

    fn send_msg<H: Host, L: Link>(&mut self, host: &mut H, link: &mut L, m: &Msg<'_>) -> bool {
        let mut w = Writer::new();
        m.encode(&mut w).is_ok() && self.send_batch(host, link, w.as_slice())
    }

    fn send_net<H: Host, L: Link>(&mut self, host: &mut H, link: &mut L, msgs: &[NetworkMsg<'_>]) -> bool {
        let mut w = Writer::new();
        let sn = self.tx_sn;
        if encode_frame(&mut w, true, sn, None, msgs).is_err() {
            return false;
        }
        self.tx_sn = (sn + 1) & self.sn_mask;
        self.send_batch(host, link, w.as_slice())
    }

    fn die<H: Host, L: Link>(&mut self, host: &mut H, link: &mut L, why: u8, what: &str) {
        if self.state != State::Dead {
            if self.state != State::Idle {
                let _ = self.send_msg(host, link, &Msg::Close(Close { session: true, reason: why }));
            }
            host.log(&format!("[zenohd] session closed: {what}\n"));
        }
        self.state = State::Dead;
    }

    // ── the session ─────────────────────────────────────────────────────────

    /// Send InitSyn: the first message of a new link.
    pub fn start<H: Host, L: Link>(&mut self, host: &mut H, link: &mut L) {
        self.last_rx = host.now_ns();
        let init = Init {
            version: VERSION,
            whatami: WhatAmI::Client,
            zid: self.cfg.zid,
            size: Some(SizeParams { resolution: Resolution::DEFAULT, batch_size: BATCH }),
            cookie: None,
            qos: false,
            patch: 0,
        };
        if self.send_msg(host, link, &Msg::Init(init)) {
            self.state = State::InitSent;
        }
    }

    /// Bytes read from the link.
    pub fn on_bytes<H: Host, L: Link>(&mut self, host: &mut H, link: &mut L, bytes: &[u8]) {
        if self.state == State::Dead {
            return;
        }
        self.rx.extend_from_slice(bytes);
        while self.state != State::Dead {
            let Some((batch, rest)) = split_stream(&self.rx) else { break };
            let (batch, consumed) = (batch.to_vec(), self.rx.len() - rest.len());
            self.rx.drain(..consumed);
            self.last_rx = host.now_ns();
            self.on_batch(host, link, &batch);
        }
        if self.rx.len() > 2 + self.batch {
            self.die(host, link, reason::INVALID, "a batch over the size offered");
        }
    }

    fn on_batch<H: Host, L: Link>(&mut self, host: &mut H, link: &mut L, batch: &[u8]) {
        for m in decode_batch(batch) {
            let Ok(m) = m else {
                self.die(host, link, reason::INVALID, "a message that does not decode");
                return;
            };
            match m {
                Msg::Init(i) if self.state == State::InitSent && i.is_ack() => {
                    if i.version != VERSION {
                        self.die(host, link, reason::UNSUPPORTED, "the router speaks another protocol version");
                        return;
                    }
                    let theirs = i.size_or_default();
                    let res = Resolution::DEFAULT.narrowest(theirs.resolution);
                    self.sn_mask = res.fsn.mask();
                    self.tx_sn &= self.sn_mask;
                    self.batch = (theirs.batch_size).min(BATCH) as usize;
                    self.cookie = i.cookie.map(<[u8]>::to_vec).unwrap_or_default();
                    let cookie = self.cookie.clone();
                    let open = Open {
                        lease: Lease { value: self.cfg.lease_ms, seconds: false },
                        initial_sn: self.cfg.initial_sn & self.sn_mask,
                        cookie: Some(&cookie),
                        qos: false,
                    };
                    if self.send_msg(host, link, &Msg::Open(open)) {
                        self.state = State::OpenSent;
                    }
                }
                Msg::Open(o) if self.state == State::OpenSent && o.is_ack() => {
                    self.peer_lease_ms = o.lease.millis().max(1);
                    self.state = State::Up;
                    self.declare_all(host, link, None);
                    self.start_topics(host);
                    host.log(&format!(
                        "[zenohd] session up, {} queryable(s), lease {} ms\n",
                        self.exports.len(),
                        self.peer_lease_ms
                    ));
                }
                Msg::Close(_) => {
                    self.die(host, link, reason::GENERIC, "the router closed it");
                    return;
                }
                Msg::KeepAlive => {}
                Msg::Frame(f) if self.state == State::Up => {
                    for n in f.messages() {
                        match n {
                            Ok(n) => self.on_net(host, link, n),
                            Err(_) => {
                                self.die(host, link, reason::INVALID, "a network message that does not decode");
                                return;
                            }
                        }
                    }
                }
                Msg::Fragment(_) => self.stats.ignored += 1,
                _ => {}
            }
            if self.state == State::Dead {
                return;
            }
        }
    }

    /// Declare the queryables, for the whole session or for one interest.
    fn declare_all<H: Host, L: Link>(&mut self, host: &mut H, link: &mut L, interest: Option<u32>) {
        let keys: Vec<String> = self.exports.iter().map(|e| e.key.clone()).collect();
        for (i, key) in keys.iter().enumerate() {
            let d = Declare {
                interest_id: interest,
                qos: None,
                timestamp: None,
                node_id: None,
                body: Declaration::Queryable {
                    id: i as u32 + 1,
                    key: WireExpr::plain(key),
                    complete: false,
                    distance: 0,
                },
            };
            self.send_net(host, link, &[NetworkMsg::Declare(d)]);
        }
        if let Some(id) = interest {
            let d = Declare { interest_id: Some(id), qos: None, timestamp: None, node_id: None, body: Declaration::Final };
            self.send_net(host, link, &[NetworkMsg::Declare(d)]);
        }
    }

    fn resolve(&self, k: &WireExpr<'_>) -> Option<String> {
        if k.scope == 0 {
            return Some(String::from(k.suffix));
        }
        // The router's own ids only: this side declares none.
        if !k.sender {
            return None;
        }
        let (_, base) = self.keys.iter().find(|(id, _)| *id == k.scope)?;
        Some(format!("{base}{}", k.suffix))
    }

    fn on_net<H: Host, L: Link>(&mut self, host: &mut H, link: &mut L, m: NetworkMsg<'_>) {
        match m {
            NetworkMsg::Request(r) => self.on_request(host, link, &r),
            NetworkMsg::Declare(Declare { body: Declaration::KeyExpr { id, key }, .. }) => {
                if let Some(full) = self.resolve(&key) {
                    self.keys.retain(|(i, _)| *i != id);
                    if self.keys.len() < KEYS_MAX && keyexpr::is_valid(&full) {
                        self.keys.push((id, full));
                    }
                }
            }
            NetworkMsg::Declare(Declare { body: Declaration::UndeclareKeyExpr { id }, .. }) => {
                self.keys.retain(|(i, _)| *i != id);
            }
            // The router asks what this side has declared. Queryables are all it
            // has; any other kind is answered with the end of the (empty) list.
            NetworkMsg::Interest(Interest { id, mode: InterestMode::Current | InterestMode::CurrentFuture, options, .. }) => {
                if options.is_some_and(|o| o.queryables) {
                    self.declare_all(host, link, Some(id));
                } else {
                    let d = Declare {
                        interest_id: Some(id),
                        qos: None,
                        timestamp: None,
                        node_id: None,
                        body: Declaration::Final,
                    };
                    self.send_net(host, link, &[NetworkMsg::Declare(d)]);
                }
            }
            _ => {}
        }
    }

    // ── queries ─────────────────────────────────────────────────────────────

    /// May another query be served in this second?
    fn admit_rate(&mut self, now: u64) -> bool {
        if now.wrapping_sub(self.window_start) >= 1_000_000_000 {
            self.window_start = now;
            self.window_count = 0;
        }
        self.window_count += 1;
        self.window_count <= self.cfg.query_rate
    }

    /// The id of the next query, counting from 1 and skipping 0 on wrap.
    fn take_badge(&mut self) -> u32 {
        let b = self.next_badge;
        self.next_badge = b.checked_add(1).unwrap_or(1);
        b
    }

    fn on_request<H: Host, L: Link>(&mut self, host: &mut H, link: &mut L, r: &Request<'_>) {
        let Some(key) = self.resolve(&r.key) else {
            self.stats.unrouted += 1;
            return self.finish(host, link, r.id);
        };
        let (iface, endpoint, op) = match route(&self.exports, &key) {
            Ok((e, op)) => (e.iface, e.endpoint, op),
            Err(NoRoute::NotConcrete | NoRoute::NoOp) => {
                self.stats.unrouted += 1;
                return self.finish(host, link, r.id);
            }
        };
        self.stats.queries += 1;
        let now = host.now_ns();
        if !self.admit_rate(now) {
            self.stats.busy += 1;
            return self.reply(host, link, r, &key, code::BUSY, None, &[0]);
        }
        // The arguments: the request words after the header, one per word.
        let args: &[u8] = r.query.body.map_or(&[], |(_, b)| b);
        let want = op.req_words as usize - 1;
        if args.len() != want * 8 || op.req_caps != 0 || op.req_words as usize > azos_idl::MSG_WORDS_MAX {
            self.stats.bad += 1;
            return self.reply(host, link, r, &key, code::BAD_REQUEST, None, &[0]);
        }
        let mut msg = MsgDesc { version: MSG_VERSION, n_words: op.req_words, ..MsgDesc::default() };
        msg.words[0] = header(iface.id, iface.level, op.op);
        for (i, c) in args.chunks_exact(8).enumerate() {
            msg.words[1 + i] = u64::from_le_bytes(c.try_into().unwrap_or([0; 8]));
        }
        let life_ms = r.timeout_ms.filter(|&t| t != 0).unwrap_or(self.cfg.timeout_max_ms).min(self.cfg.timeout_max_ms);
        let life_ns = life_ms * 1_000_000;
        let warrant = Warrant {
            badge: self.take_badge(),
            life_ns,
            deadline_ns: if op.deadline_ns != 0 { op.deadline_ns.min(life_ns) } else { life_ns },
        };
        // The decision total before the op: whatever the kernel writes for this
        // subject after it is this query's.
        let mark = total(&DecisionsClient::new(Dec(core::cell::RefCell::new(&mut *host)))).unwrap_or(0);
        let inv = host.invoke(endpoint, &mut msg, &warrant);
        let receipt = receipt(&DecisionsClient::new(Dec(core::cell::RefCell::new(&mut *host))), self.cfg.me, mark, inv.expiry_ns);
        let (code, words) = match inv.result {
            Err(e) => {
                self.stats.refused += 1;
                (code::REFUSED, alloc::vec![e as u64])
            }
            Ok(()) => {
                let n = (msg.n_words as usize).clamp(1, azos_idl::MSG_WORDS_MAX);
                let status = msg.words[0];
                if status != azos_idl::STATUS_OK {
                    self.stats.refused += 1;
                    (code::FAILED, alloc::vec![status])
                } else {
                    self.stats.served += 1;
                    (code::SERVED, msg.words[..n].to_vec())
                }
            }
        };
        self.reply(host, link, r, &key, code, receipt.as_ref(), &words);
    }

    /// Answer `r`: the payload of the module's table, then the end of the replies.
    fn reply<H: Host, L: Link>(
        &mut self,
        host: &mut H,
        link: &mut L,
        r: &Request<'_>,
        key: &str,
        code: u64,
        receipt: Option<&ProvenanceRecord>,
        words: &[u64],
    ) {
        let mut all = Vec::with_capacity(4 + words.len());
        all.push(code);
        all.push(receipt.map_or(0, |p| p.seq));
        all.push(receipt.map_or(0, |p| p.rule as u64 | (p.verdict as u64) << 8));
        all.push(words.first().copied().unwrap_or(0));
        all.extend_from_slice(words.get(1..).unwrap_or(&[]));
        let payload = words_le(&all);
        let body = if code == code::SERVED {
            ResponseBody::Reply(Reply {
                consolidation: None,
                body: PushBody::Put(Put { timestamp: None, encoding: None, source_info: None, attachment: None, payload: &payload }),
            })
        } else {
            ResponseBody::Err(ErrBody { encoding: None, source_info: None, payload: &payload })
        };
        let resp = Response {
            id: r.id,
            key: WireExpr::plain(key),
            qos: None,
            timestamp: None,
            responder: Some(ResponderId { zid: self.cfg.zid, eid: 0 }),
            body,
        };
        let fin = ResponseFinal { id: r.id, qos: None, timestamp: None };
        if !self.send_net(host, link, &[NetworkMsg::Response(resp), NetworkMsg::ResponseFinal(fin)]) {
            self.finish(host, link, r.id);
        }
    }

    /// The end of the replies to `id`, with none.
    fn finish<H: Host, L: Link>(&mut self, host: &mut H, link: &mut L, id: u32) {
        self.send_net(host, link, &[NetworkMsg::ResponseFinal(ResponseFinal { id, qos: None, timestamp: None })]);
    }

    // ── time ────────────────────────────────────────────────────────────────

    fn start_topics<H: Host>(&mut self, host: &mut H) {
        if self.cfg.topic.is_empty() {
            return;
        }
        // Records from now on, not the history.
        self.cursor = total(&DecisionsClient::new(Dec(core::cell::RefCell::new(&mut *host)))).unwrap_or(0);
        self.last_publish = host.now_ns();
    }

    fn publish<H: Host, L: Link>(&mut self, host: &mut H, link: &mut L) {
        let mut ids = [0u64; PUBLISH_BURST];
        let c = DecisionsClient::new(Dec(core::cell::RefCell::new(&mut *host)));
        let f = Filter { after: self.cursor, ..Filter::ANY };
        let Ok((n, tot)) = azos_decisions::list(&c, &f, &mut ids) else { return };
        let mut recs: Vec<ProvenanceRecord> = Vec::new();
        for &id in &ids[..n] {
            match azos_decisions::fetch(&c, id) {
                Ok(Some(p)) => recs.push(p),
                _ => self.stats.lost += 1,
            }
        }
        drop(c);
        if n == 0 {
            self.cursor = self.cursor.max(tot);
            return;
        }
        if ids[0] > self.cursor + 1 {
            self.stats.lost += ids[0] - self.cursor - 1;
        }
        self.cursor = ids[n - 1];
        for p in &recs {
            let rule = RULES.get(p.rule as usize).map_or("unknown", |r| r.name);
            let verdict = VERDICTS.get(p.verdict as usize).copied().unwrap_or("unknown");
            let key = format!("{}/{}/{}", self.cfg.topic, rule, verdict);
            let bytes = p.to_bytes();
            let push = Push {
                key: WireExpr::plain(&key),
                qos: None,
                timestamp: None,
                node_id: None,
                body: PushBody::Put(Put { timestamp: None, encoding: None, source_info: None, attachment: None, payload: &bytes }),
            };
            if self.send_net(host, link, &[NetworkMsg::Push(push)]) {
                self.stats.published += 1;
            }
        }
    }

    /// Housekeeping: the keep-alive, the lease, the topics. Call it at least
    /// every few milliseconds.
    pub fn tick<H: Host, L: Link>(&mut self, host: &mut H, link: &mut L) {
        let now = host.now_ns();
        match self.state {
            State::Idle | State::Dead => {}
            State::InitSent | State::OpenSent | State::Up => {
                if now.saturating_sub(self.last_rx) > self.cfg.lease_ms * 1_000_000 {
                    return self.die(host, link, reason::EXPIRED, "the router went silent");
                }
                if self.state == State::Up {
                    if now.saturating_sub(self.last_tx) >= self.peer_lease_ms * 1_000_000 / 4 {
                        self.send_msg(host, link, &Msg::KeepAlive);
                    }
                    if !self.cfg.topic.is_empty() && now.saturating_sub(self.last_publish) >= PUBLISH_PERIOD_NS {
                        self.last_publish = now;
                        self.publish(host, link);
                    }
                }
            }
        }
    }
}
