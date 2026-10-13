// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The engine of the RPC server: both roles of a node in one state machine.
//!
//! **Importing** (a local caller called a proxy endpoint): [`Rpc::begin`] turns
//! the accepted request into a frame message and sends it; [`Rpc::poll`] is
//! called until it answers with the reply descriptor the local caller gets,
//! which is also where resends, the deadline and a broken session are
//! decided. **Exporting** (a peer sent a request): [`Rpc::on_frame`] checks it
//! against the topology's exports, runs it against the real endpoint through
//! the peer's warrant and sends the answer. The only call that blocks in here is
//! that one (`Host::call` on the real endpoint), and it carries a deadline of at
//! most `rto * (retries + 1)`, which is as long as the caller would wait: the
//! server binary reads frames and calls `on_frame` on one thread, and accepts
//! local calls and calls `begin` and `poll` on the other, behind one lock; the
//! host tests drive both engines from one.
//!
//! A call that fails for a reason of the link or of the far node is always an
//! ordinary IDL reply, a status word ([`IdlError`]), so the caller's stub
//! sees `NoConnection`, `PeerDied`, `DeadlineExpired` or `Refused` and needs
//! to know nothing of the transport.

use azos_abi::cap::CapPerms;
use azos_abi::error::Errno;
use azos_abi::ipc_msg::{CapDesc, MsgDesc, CAP_MODE_DUP, CAP_MODE_MOVE, MSG_VERSION};
use azos_idl::{header_id, header_op, Delivery, IdlError};

use crate::journal::Journal;
use crate::policy::{self, Name, Policy, Service};
use crate::session::{Minted, Seen, Session, State, Warrant};
use crate::wire::{
    frags_for, get_data, get_desc, get_header, put_desc, put_header, Asm, Header, Kind, FRAGS_MAX, FRAG_BODY,
    FRAME_MAX, HEADER_BYTES, MSG_CAP,
};
use crate::{Config, Handshake, Host, Link, NodeId, IFACES_MAX, MAX_SESSIONS, MINTED_CAP, PROOF_MAX};

const RW: u16 = CapPerms::RW.bits() as u16;
const WRITE: u16 = CapPerms::WRITE.bits() as u16;

/// An outstanding call, held by the local caller's thread between
/// [`Rpc::begin`] and the [`Rpc::poll`] that finishes it.
#[derive(Clone, Copy)]
pub struct Call {
    session: u32,
    peer: NodeId,
    seq: u64,
    delivery: Delivery,
    attempts: u8,
    next_ns: u64,
    /// Absolute ns on this clock, 0 for none.
    deadline_ns: u64,
}

/// What [`Rpc::begin`] made of a request.
pub enum Started {
    /// Answered at once (a refusal, no session, a deadline already passed):
    /// the reply for the local caller.
    Done(MsgDesc),
    /// Sent; poll it.
    Pending(Call),
}

/// The outstanding call's slot for its answer.
struct Pend {
    active: bool,
    have: bool,
    session: u32,
    seq: u64,
    len: usize,
}

/// A node's RPC server.
pub struct Rpc<H: Host, L: Link, A: Handshake> {
    pub host: H,
    pub link: L,
    pub auth: A,
    cfg: Config,
    policy: Policy,
    catalog: &'static [Service],
    sessions: [Session; MAX_SESSIONS],
    journal: Journal,
    tx: [u8; FRAME_MAX],
    /// The request being sent, kept for resends.
    enc: [u8; MSG_CAP],
    enc_len: usize,
    /// The answer received for the outstanding call.
    rep: [u8; MSG_CAP],
    /// Scratch: the answer being built, a Hello's body.
    rsp: [u8; MSG_CAP],
    pend: Pend,
    next_session: u32,
}

fn status_desc(e: IdlError) -> MsgDesc {
    let mut d = MsgDesc { version: MSG_VERSION, n_words: 1, ..MsgDesc::default() };
    d.words[0] = e.status();
    d
}

fn put_status(e: IdlError, out: &mut [u8]) -> usize {
    let mut at = 0;
    // A status always fits.
    let _ = put_desc(&status_desc(e), out, &mut at);
    at
}

/// Send `body` as the message `h`, one frame per fragment.
fn send_msg<L: Link>(link: &mut L, tx: &mut [u8; FRAME_MAX], peer: NodeId, h: &Header, body: &[u8]) -> bool {
    let cnt = frags_for(body.len());
    debug_assert!(cnt <= FRAGS_MAX);
    let mut ok = true;
    for i in 0..cnt {
        let lo = i * FRAG_BODY;
        let hi = (lo + FRAG_BODY).min(body.len());
        let mut hh = *h;
        hh.frag_idx = i as u16;
        hh.frag_cnt = cnt as u16;
        put_header(&hh, tx);
        tx[HEADER_BYTES..HEADER_BYTES + (hi - lo)].copy_from_slice(&body[lo..hi]);
        ok &= link.send(peer, &tx[..HEADER_BYTES + (hi - lo)]);
    }
    ok
}

impl<H: Host, L: Link, A: Handshake> Rpc<H, L, A> {
    /// A server over `link`, carrying the interfaces of `catalog`. **Nothing is
    /// set**: [`Rpc::configure`] gives it its node id and timings, and
    /// [`Rpc::set_policy`] its peers and exports (until then it exports
    /// nothing and knows no peer). Every field starts as zeros, so a `static`
    /// server costs no bytes in the image.
    pub const fn new(host: H, link: L, auth: A, catalog: &'static [Service]) -> Self {
        Rpc {
            host,
            link,
            auth,
            cfg: Config {
                node: 0,
                epoch: 0,
                warrant_ttl_ns: 0,
                dedupe_window: 0,
                retries: 0,
                rto_ns: 0,
                ping_ns: 0,
                miss_limit: 0,
            },
            policy: Policy::NONE,
            catalog,
            sessions: [Session::free(), Session::free(), Session::free(), Session::free()],
            journal: Journal::new(),
            tx: [0; FRAME_MAX],
            enc: [0; MSG_CAP],
            enc_len: 0,
            rep: [0; MSG_CAP],
            rsp: [0; MSG_CAP],
            pend: Pend { active: false, have: false, session: 0, seq: 0, len: 0 },
            next_session: 0,
        }
    }

    /// The node's id and timings (see [`Config`]); once, before the first frame.
    pub fn configure(&mut self, cfg: Config) {
        self.cfg = cfg;
    }

    /// Replace the policy (the parsed `/proc/rpc`).
    pub fn set_policy(&mut self, p: Policy) {
        self.policy = p;
    }

    /// The provenance this node has recorded.
    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    /// The session with `peer`, if one is not free.
    pub fn session_with(&self, peer: NodeId) -> Option<&Session> {
        self.sessions.iter().find(|s| s.state != State::Free && s.peer == peer)
    }

    fn header(&self, kind: Kind, session: u32, seq: u64) -> Header {
        Header::new(kind, session, seq, self.cfg.node, self.cfg.epoch)
    }

    fn si_by_peer(&self, peer: NodeId) -> Option<usize> {
        self.sessions.iter().position(|s| s.state != State::Free && s.peer == peer)
    }

    fn si_up(&self, peer: NodeId, id: u32) -> Option<usize> {
        self.sessions.iter().position(|s| s.state == State::Up && s.peer == peer && s.id == id)
    }

    fn si_up_by_id(&self, id: u32) -> Option<usize> {
        self.sessions.iter().position(|s| s.state == State::Up && s.id == id)
    }

    // ── sessions ────────────────────────────────────────────────────────

    /// The interface ids this node will serve to `class`: those it exports to
    /// it and holds the endpoint of.
    fn grants_for(&mut self, class: &Name) -> ([u32; IFACES_MAX], u8) {
        let mut ids = [0u32; IFACES_MAX];
        let mut n = 0;
        for s in self.catalog {
            if n == IFACES_MAX {
                break;
            }
            if let Some(e) = self.policy.export(s.name, class) {
                if self.host.endpoint(e.index).is_some() {
                    ids[n] = s.id;
                    n += 1;
                }
            }
        }
        (ids, n as u8)
    }

    /// Fill `self.rsp` with a Hello body for `peer`: proof, then the ids; its length.
    fn hello_body(&mut self, peer: NodeId, ids: &[u32]) -> usize {
        let mut proof = [0u8; PROOF_MAX];
        let n = self.auth.prove(peer, &mut proof).min(PROOF_MAX);
        let b = &mut self.rsp;
        b[0] = n as u8;
        b[1..1 + n].copy_from_slice(&proof[..n]);
        let mut at = 1 + n;
        b[at] = ids.len() as u8;
        at += 1;
        for id in ids {
            b[at..at + 4].copy_from_slice(&id.to_le_bytes());
            at += 4;
        }
        at
    }

    fn parse_hello<'a>(&mut self, body: &'a [u8]) -> Option<(&'a [u8], [u32; IFACES_MAX], u8)> {
        let pl = *body.first()? as usize;
        let proof = body.get(1..1 + pl)?;
        let n = *body.get(1 + pl)? as usize;
        if n > IFACES_MAX {
            return None;
        }
        let mut ids = [0u32; IFACES_MAX];
        let mut at = 2 + pl;
        for id in ids.iter_mut().take(n) {
            let b = body.get(at..at + 4)?;
            *id = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            at += 4;
        }
        Some((proof, ids, n as u8))
    }

    /// Dial `peer`, if this node has the lower id (the lower id dials, the
    /// higher answers, so two nodes never make two sessions) and nothing is
    /// open yet.
    pub fn connect(&mut self, peer: NodeId) {
        if self.cfg.node >= peer || self.si_by_peer(peer).is_some() {
            return;
        }
        let Some(class) = self.policy.class_of(peer) else { return };
        let Some(si) = self.sessions.iter().position(|s| s.state == State::Free) else { return };
        let now = self.host.now_ns();
        let (granted, ng) = self.grants_for(&class);
        let nonce = now | 1;
        let s = &mut self.sessions[si];
        s.state = State::Dialing;
        s.peer = peer;
        s.class = class;
        s.id = 0;
        s.nonce = nonce;
        s.hellos = 1;
        s.probed_ns = now;
        s.granted = granted;
        s.n_granted = ng;
        s.n_offered = 0;
        self.send_hello(si, Kind::Hello);
    }

    fn send_hello(&mut self, si: usize, kind: Kind) {
        let (peer, nonce, id, ng, granted) = {
            let s = &self.sessions[si];
            (s.peer, s.nonce, s.id, s.n_granted as usize, s.granted)
        };
        let n = self.hello_body(peer, &granted[..ng]);
        let h = self.header(kind, id, nonce);
        send_msg(&mut self.link, &mut self.tx, peer, &h, &self.rsp[..n]);
    }

    fn on_hello(&mut self, h: &Header, body: &[u8]) {
        // The higher node answers; a Hello from a higher node is not for us.
        if self.cfg.node <= h.node {
            return;
        }
        let Some(class) = self.policy.class_of(h.node) else {
            self.host.log(b"[rpcsrv] hello from a node no peer class lists: ignored\n");
            return;
        };
        let Some((proof, ids, n)) = self.parse_hello(body) else { return };
        if !self.auth.verify(h.node, proof) {
            self.host.log(b"[rpcsrv] hello: identity proof refused\n");
            return;
        }
        let now = self.host.now_ns();
        let si = match self.si_by_peer(h.node) {
            Some(si) => {
                let s = &self.sessions[si];
                if s.state == State::Up && s.peer_epoch == h.epoch && s.nonce == h.seq {
                    // A resent Hello: the answer was lost. Answer again.
                    self.sessions[si].heard_ns = now;
                    self.send_hello(si, Kind::HelloAck);
                    return;
                }
                // A new epoch or a new dial: the old session is gone.
                self.break_session(si, false);
                si
            }
            None => match self.sessions.iter().position(|s| s.state == State::Free) {
                Some(si) => si,
                None => return,
            },
        };
        let (granted, ng) = self.grants_for(&class);
        self.next_session = self.next_session.wrapping_add(1).max(1);
        let id = self.next_session;
        let window = self.cfg.dedupe_window;
        let s = &mut self.sessions[si];
        s.state = State::Up;
        s.peer = h.node;
        s.class = class;
        s.id = id;
        s.peer_epoch = h.epoch;
        s.nonce = h.seq;
        s.next_seq = 1;
        s.heard_ns = now;
        s.probed_ns = now;
        s.misses = 0;
        s.offered = ids;
        s.n_offered = n;
        s.granted = granted;
        s.n_granted = ng;
        s.dedupe.reset(window);
        s.warrants.iter_mut().for_each(|w| w.live = false);
        s.minted.iter_mut().for_each(|m| m.live = false);
        self.send_hello(si, Kind::HelloAck);
    }

    fn on_ack(&mut self, h: &Header, body: &[u8]) {
        let Some(si) = self.sessions.iter().position(|s| s.state == State::Dialing && s.peer == h.node && s.nonce == h.seq)
        else {
            return;
        };
        let Some((proof, ids, n)) = self.parse_hello(body) else { return };
        if h.session == 0 || !self.auth.verify(h.node, proof) {
            self.host.log(b"[rpcsrv] hello answer: refused\n");
            self.sessions[si].state = State::Free;
            return;
        }
        let now = self.host.now_ns();
        let window = self.cfg.dedupe_window;
        let s = &mut self.sessions[si];
        s.state = State::Up;
        s.id = h.session;
        s.peer_epoch = h.epoch;
        s.next_seq = 1;
        s.heard_ns = now;
        s.probed_ns = now;
        s.misses = 0;
        s.offered = ids;
        s.n_offered = n;
        s.dedupe.reset(window);
        s.warrants.iter_mut().for_each(|w| w.live = false);
        s.minted.iter_mut().for_each(|m| m.live = false);
    }

    /// End the session in slot `si` and **revoke everything minted over it**:
    /// every warrant and every re-minted object is closed, with the copies
    /// derived from them. `notify` sends the peer a Bye so it does the same.
    /// A call waiting on the session finds it gone and is told `NoConnection`.
    pub fn break_session(&mut self, si: usize, notify: bool) {
        let now = self.host.now_ns();
        let (peer, id, was_up) = {
            let s = &self.sessions[si];
            (s.peer, s.id, s.state != State::Free)
        };
        if !was_up {
            return;
        }
        let mut closed = 0u64;
        for k in 0..IFACES_MAX {
            let w = self.sessions[si].warrants[k];
            if w.live {
                self.host.close(w.handle);
                self.sessions[si].warrants[k].live = false;
                closed += 1;
            }
        }
        for k in 0..MINTED_CAP {
            let m = self.sessions[si].minted[k];
            if m.live {
                self.host.close(m.handle);
                self.sessions[si].minted[k].live = false;
                closed += 1;
            }
        }
        let abandoned = u64::from(self.pend.active && self.pend.session == id);
        self.journal.revoke(now, peer, id, closed, abandoned);
        if notify && self.sessions[si].state == State::Up {
            let h = self.header(Kind::Bye, id, 0);
            send_msg(&mut self.link, &mut self.tx, peer, &h, &[]);
        }
        self.sessions[si].state = State::Free;
    }

    // ── minted objects and warrants ─────────────────────────────────────

    fn track_minted(&mut self, si: usize, handle: u32, expiry_ns: u64) {
        let slot = match self.sessions[si].minted.iter().position(|m| !m.live) {
            Some(k) => k,
            None => {
                // Make room: the one that lapses first is closed (its lent copy
                // with it). An expiry of 0 is "never", which lapses last.
                let k = (0..MINTED_CAP)
                    .min_by_key(|&k| match self.sessions[si].minted[k].expiry_ns {
                        0 => u64::MAX,
                        e => e,
                    })
                    .unwrap_or(0);
                self.host.close(self.sessions[si].minted[k].handle);
                k
            }
        };
        self.sessions[si].minted[slot] = Minted { live: true, handle, expiry_ns };
    }

    /// Close an object [`Rpc::track_minted`] recorded, **and drop the record**:
    /// a later sweep or break closes only what is still recorded, so a handle
    /// number the kernel has since given to another object (a warrant, a newer
    /// re-minted object) is never closed in its place. An object the table
    /// already evicted (and closed) is not closed again.
    fn release_minted(&mut self, si: usize, handle: u32) {
        if let Some(k) = self.sessions[si].minted.iter().position(|m| m.live && m.handle == handle) {
            self.sessions[si].minted[k].live = false;
            self.host.close(handle);
        }
    }

    /// The warrant for interface `iface` over session `si`: the live one, or a
    /// fresh child of `ep` (renewed when a quarter of its life is left).
    fn warrant(&mut self, si: usize, iface: u32, ep: u32, now: u64) -> Option<u32> {
        let ttl = self.cfg.warrant_ttl_ns;
        if let Some(k) = self.sessions[si].warrants.iter().position(|w| w.live && w.iface == iface) {
            let w = self.sessions[si].warrants[k];
            if ttl == 0 || w.expiry_ns > now + ttl / 4 {
                return Some(w.handle);
            }
            self.host.close(w.handle);
            self.sessions[si].warrants[k].live = false;
        }
        let k = self.sessions[si].warrants.iter().position(|w| !w.live)?;
        let (peer, id) = (self.sessions[si].peer, self.sessions[si].id);
        let expiry = if ttl == 0 { 0 } else { now + ttl };
        let h = self.host.derive(ep, WRITE, id, expiry).ok()?;
        self.sessions[si].warrants[k] = Warrant { live: true, iface, handle: h, expiry_ns: expiry };
        self.journal.derive(now, peer, id, 0, id, h, ep, [iface as u64, 0, expiry]);
        Some(h)
    }

    // ── importing ───────────────────────────────────────────────────────

    fn consume(&mut self, req: &MsgDesc) {
        for c in req.caps.iter().take(req.n_caps as usize) {
            self.host.close(c.handle);
        }
    }

    /// A local caller called a proxy endpoint with `req` (the accepted
    /// descriptor); `subject` identifies it in the provenance (its badge).
    /// Every capability the request carried is consumed.
    pub fn begin(&mut self, req: &MsgDesc, subject: u32) -> Started {
        let now = self.host.now_ns();
        let refuse = |this: &mut Self, e: IdlError| {
            this.consume(req);
            Started::Done(status_desc(e))
        };
        if req.n_words < 1 || req.clock_id != 0 {
            return refuse(self, IdlError::Malformed);
        }
        let (id, op) = (header_id(req.words[0]), header_op(req.words[0]));
        let Some(svc) = policy::find(self.catalog, id) else { return refuse(self, IdlError::BadInterface) };
        let Some(info) = svc.op(op) else { return refuse(self, IdlError::BadOp) };
        let Some(delivery) = info.delivery() else {
            // An op that says nothing about being resent crosses no link.
            self.journal.refuse(now, 0, 0, 0, subject, [id as u64, op as u64, IdlError::Refused.status()]);
            return refuse(self, IdlError::Refused);
        };
        if self.pend.active {
            return refuse(self, IdlError::Refused);
        }
        let Some(si) = self.sessions.iter().position(|s| s.state == State::Up && s.offers(id)) else {
            // Nobody offers it. If every peer is connected, the service is not
            // exported to this node; if one is not, it may be the one that
            // would have.
            let all_up = self.policy.nodes().all(|n| self.sessions.iter().any(|s| s.state == State::Up && s.peer == n));
            return refuse(self, if all_up { IdlError::Refused } else { IdlError::NoConnection });
        };
        if req.deadline != 0 && req.deadline <= now {
            return refuse(self, IdlError::DeadlineExpired);
        }
        // The message: the descriptor as it is, expiries as time remaining, then the
        // pages of each MemObj. Only a MOVE of a MemObj crosses.
        let mut wire = *req;
        let mut at = 0;
        for c in wire.caps.iter_mut().take(req.n_caps as usize) {
            if c.mode != CAP_MODE_MOVE {
                return refuse(self, IdlError::Refused);
            }
            c.expiry_ns = match c.expiry_ns {
                0 => 0,
                e if e > now => e - now,
                _ => return refuse(self, IdlError::DeadlineExpired),
            };
        }
        if put_desc(&wire, &mut self.enc, &mut at).is_none() {
            return refuse(self, IdlError::Malformed);
        }
        for c in req.caps.iter().take(req.n_caps as usize) {
            let Some(size) = self.host.mo_size(c.handle) else { return refuse(self, IdlError::Refused) };
            if at + 4 + size > MSG_CAP {
                return refuse(self, IdlError::Refused);
            }
            let Some(n) = self.host.mo_read(c.handle, &mut self.enc[at + 4..at + 4 + size]) else {
                return refuse(self, IdlError::Refused);
            };
            self.enc[at..at + 4].copy_from_slice(&(n as u32).to_le_bytes());
            at += 4 + n;
        }
        self.enc_len = at;
        // The pages are in the message: the objects are consumed (a MOVE).
        self.consume(req);

        let s = &mut self.sessions[si];
        let (peer, session, seq) = (s.peer, s.id, s.next_seq);
        s.next_seq += 1;
        self.pend = Pend { active: true, have: false, session, seq, len: 0 };
        let call = Call {
            session,
            peer,
            seq,
            delivery,
            attempts: 1,
            next_ns: now + self.cfg.rto_ns,
            deadline_ns: req.deadline,
        };
        self.journal.derive(now, peer, session, seq, subject, 0, 0, [id as u64, op as u64, req.deadline]);
        self.transmit(&call, now);
        Started::Pending(call)
    }

    fn transmit(&mut self, call: &Call, now: u64) {
        let mut h = self.header(Kind::Req, call.session, call.seq);
        if call.deadline_ns != 0 {
            h.remaining_ns = call.deadline_ns.saturating_sub(now).max(1);
        }
        send_msg(&mut self.link, &mut self.tx, call.peer, &h, &self.enc[..self.enc_len]);
    }

    /// Advance an outstanding call. `Some(reply)` when it has finished (the
    /// answer, or a status that says why not); `None` while it waits.
    pub fn poll(&mut self, call: &mut Call) -> Option<MsgDesc> {
        let now = self.host.now_ns();
        let live = self.si_up_by_id(call.session);
        if self.pend.active && self.pend.have && self.pend.session == call.session && self.pend.seq == call.seq {
            self.pend.active = false;
            return Some(match live {
                Some(si) => self.reply_to_local(si, call, now),
                None => status_desc(IdlError::NoConnection),
            });
        }
        let Some(si) = live else {
            self.pend.active = false;
            return Some(status_desc(IdlError::NoConnection));
        };
        if call.deadline_ns != 0 && now >= call.deadline_ns {
            self.pend.active = false;
            return Some(status_desc(IdlError::DeadlineExpired));
        }
        if now < call.next_ns {
            return None;
        }
        let may_resend = !matches!(call.delivery, Delivery::OnceOnly) && call.attempts <= self.cfg.retries;
        if may_resend {
            call.attempts += 1;
            call.next_ns = now + self.cfg.rto_ns;
            let c = *call;
            self.transmit(&c, now);
            return None;
        }
        // No answer and nothing more to try: the outcome is unknown. A once-only
        // op is never asked again; the others have used their retries.
        self.pend.active = false;
        let s = &mut self.sessions[si];
        s.misses += 1;
        if s.misses >= self.cfg.miss_limit {
            self.break_session(si, true);
        }
        Some(status_desc(IdlError::NoConnection))
    }

    /// The local reply for the answer in `self.rep`: its words, and each
    /// MemObj re-minted from its pages, lent to the local caller as a copy that
    /// lapses with the warrant TTL, the parent kept in the session so a break
    /// revokes it.
    fn reply_to_local(&mut self, si: usize, call: &Call, now: u64) -> MsgDesc {
        let body_len = self.pend.len;
        let mut at = 0;
        let Some(mut d) = get_desc(&self.rep[..body_len], &mut at) else { return status_desc(IdlError::Malformed) };
        let ttl = self.cfg.warrant_ttl_ns;
        let expiry = if ttl == 0 { 0 } else { now + ttl };
        for k in 0..d.n_caps as usize {
            let wire = d.caps[k];
            let made = get_data(&self.rep[..body_len], &mut at)
                .ok_or(IdlError::Malformed)
                .and_then(|data| self.host.mo_create(data).map_err(|_| IdlError::Refused));
            let h = match made {
                Ok(h) => h,
                Err(e) => {
                    // Close what this reply already made.
                    for c in d.caps.iter().take(k) {
                        self.release_minted(si, c.handle);
                    }
                    return status_desc(e);
                }
            };
            self.track_minted(si, h, expiry);
            let rights = if wire.rights & RW != 0 { wire.rights & RW } else { RW };
            d.caps[k] = CapDesc { handle: h, mode: CAP_MODE_DUP, _pad: 0, rights, expiry_ns: expiry };
            self.journal.derive(now, call.peer, call.session, call.seq, 0, h, 0, [0, 0, expiry]);
        }
        d
    }

    // ── frames in ───────────────────────────────────────────────────────

    /// A datagram arrived. `asm` is the reassembly state of the thread that
    /// reads the link.
    pub fn on_frame(&mut self, asm: &mut Asm, frame: &[u8]) {
        let Some((h, frag)) = get_header(frame) else { return };
        if h.node == 0 || h.node == self.cfg.node {
            return;
        }
        let Some(slot) = asm.push(&h, frag) else { return };
        let (head, body) = asm.message(slot);
        self.dispatch(&head, body);
        asm.done(slot);
    }

    fn dispatch(&mut self, h: &Header, body: &[u8]) {
        match h.kind {
            Kind::Hello => return self.on_hello(h, body),
            Kind::HelloAck => return self.on_ack(h, body),
            _ => {}
        }
        let Some(si) = self.si_up(h.node, h.session) else {
            // A session this node does not have (it restarted, or broke it):
            // tell the sender, so it breaks its side and says NoConnection.
            if h.kind != Kind::Bye {
                let b = self.header(Kind::Bye, h.session, 0);
                send_msg(&mut self.link, &mut self.tx, h.node, &b, &[]);
            }
            return;
        };
        let now = self.host.now_ns();
        self.sessions[si].heard_ns = now;
        self.sessions[si].misses = 0;
        match h.kind {
            Kind::Req => self.serve_req(si, h, body, now),
            Kind::Rep => {
                if self.pend.active && !self.pend.have && self.pend.session == h.session && self.pend.seq == h.seq {
                    self.rep[..body.len()].copy_from_slice(body);
                    self.pend.len = body.len();
                    self.pend.have = true;
                }
            }
            Kind::Ping => {
                let p = self.header(Kind::Pong, h.session, h.seq);
                send_msg(&mut self.link, &mut self.tx, h.node, &p, &[]);
            }
            Kind::Pong => {}
            Kind::Bye => self.break_session(si, false),
            Kind::Hello | Kind::HelloAck => {}
        }
    }

    // ── exporting ───────────────────────────────────────────────────────

    fn reply_status(&mut self, si: usize, h: &Header, e: IdlError, record: bool) {
        let n = put_status(e, &mut self.rsp);
        self.finish_rep(si, h, n, record);
    }

    /// Send `self.rsp[..n]` as the answer to `h`; keep it for a repeat of the
    /// call when `record`.
    fn finish_rep(&mut self, si: usize, h: &Header, n: usize, record: bool) {
        if record {
            self.sessions[si].dedupe.record(h.seq, Some(&self.rsp[..n]));
        }
        let peer = self.sessions[si].peer;
        let r = self.header(Kind::Rep, h.session, h.seq);
        send_msg(&mut self.link, &mut self.tx, peer, &r, &self.rsp[..n]);
    }

    fn serve_req(&mut self, si: usize, h: &Header, body: &[u8], now: u64) {
        let (peer, session) = (self.sessions[si].peer, self.sessions[si].id);
        let mut at = 0;
        let Some(mut desc) = get_desc(body, &mut at) else { return self.reply_status(si, h, IdlError::Malformed, false) };
        if desc.n_words < 1 {
            return self.reply_status(si, h, IdlError::Malformed, false);
        }
        let (id, op) = (header_id(desc.words[0]), header_op(desc.words[0]));
        let refuse_n = [id as u64, op as u64, IdlError::Refused.status()];
        // Exported to this peer's class, and an op that says how it is delivered.
        let svc = policy::find(self.catalog, id).filter(|_| self.sessions[si].grants(id));
        let Some(svc) = svc else {
            self.journal.refuse(now, peer, session, h.seq, session, refuse_n);
            return self.reply_status(si, h, IdlError::Refused, false);
        };
        let Some(delivery) = svc.op(op).and_then(|o| o.delivery()) else {
            self.journal.refuse(now, peer, session, h.seq, session, refuse_n);
            return self.reply_status(si, h, IdlError::Refused, false);
        };
        if h.clock != 0 {
            return self.reply_status(si, h, IdlError::Refused, false);
        }
        // A call that must not run twice: a repeat gets the answer kept, or
        // the admission that it cannot be told.
        let dedupe = !matches!(delivery, Delivery::Idempotent);
        if dedupe {
            match self.sessions[si].dedupe.lookup(h.seq) {
                Seen::Cached(b) => {
                    let r = self.header(Kind::Rep, h.session, h.seq);
                    send_msg(&mut self.link, &mut self.tx, peer, &r, b);
                    return;
                }
                Seen::Unknown => return self.reply_status(si, h, IdlError::NoConnection, false),
                Seen::Fresh => {}
            }
        }
        // The call below blocks this thread, and the engine's lock with it: it
        // never waits longer than the caller would (the caller gives up after
        // its resends, `rto * (retries + 1)`), whatever deadline it sent.
        let abs_deadline = {
            let patience = self.cfg.rto_ns.saturating_mul(u64::from(self.cfg.retries) + 1);
            let cap = if patience == 0 { 0 } else { now.saturating_add(patience) };
            match (h.remaining_ns, cap) {
                (0, c) => c,
                (r, 0) => now.saturating_add(r),
                (r, c) => now.saturating_add(r).min(c),
            }
        };
        let class = self.sessions[si].class;
        let Some(ep) = self.policy.export(svc.name, &class).and_then(|e| self.host.endpoint(e.index)) else {
            return self.reply_status(si, h, IdlError::Refused, false);
        };
        let ttl = self.cfg.warrant_ttl_ns;
        let lend_until = if ttl == 0 { 0 } else { now + ttl };

        // The pages that crossed become new objects here, lent to the server as
        // copies that lapse; the parents are the session's.
        let mut made = 0usize;
        let mut failed = None;
        for k in 0..desc.n_caps as usize {
            let wire = desc.caps[k];
            let Some(data) = get_data(body, &mut at) else {
                failed = Some(IdlError::Malformed);
                break;
            };
            if wire.mode != CAP_MODE_MOVE {
                failed = Some(IdlError::Refused);
                break;
            }
            let Ok(m) = self.host.mo_create(data) else {
                failed = Some(IdlError::Refused);
                break;
            };
            let mut until = lend_until;
            if wire.expiry_ns != 0 {
                let e = now + wire.expiry_ns;
                until = if until == 0 { e } else { until.min(e) };
            }
            self.track_minted(si, m, until);
            let rights = if wire.rights & RW != 0 { wire.rights & RW } else { RW };
            desc.caps[k] = CapDesc { handle: m, mode: CAP_MODE_DUP, _pad: 0, rights, expiry_ns: until };
            self.journal.derive(now, peer, session, h.seq, session, m, 0, [id as u64, op as u64, until]);
            made = k + 1;
        }
        if let Some(e) = failed {
            for c in desc.caps.iter().take(made) {
                self.release_minted(si, c.handle);
            }
            return self.reply_status(si, h, e, false);
        }

        // The call, through the peer's warrant, with the deadline the caller has left.
        desc.version = MSG_VERSION;
        desc.flags = 0;
        desc.badge = 0;
        desc.deadline = abs_deadline;
        desc.clock_id = 0;
        desc._pad = 0;
        let saved = desc;
        let mut rc = match self.warrant(si, id, ep, now) {
            Some(w) => self.host.call(w, &mut desc),
            None => Errno::EPERM.to_syscall_ret(),
        };
        if rc == Errno::EPERM.to_syscall_ret() || rc == Errno::ECAPSTALE.to_syscall_ret() {
            // The warrant lapsed under the call: derive a fresh one, once.
            if let Some(k) = self.sessions[si].warrants.iter().position(|w| w.live && w.iface == id) {
                self.host.close(self.sessions[si].warrants[k].handle);
                self.sessions[si].warrants[k].live = false;
            }
            if let Some(w) = self.warrant(si, id, ep, now) {
                desc = saved;
                rc = self.host.call(w, &mut desc);
            }
        }

        let n = if rc == 0 {
            self.encode_reply(&desc)
        } else {
            let e = if rc == Errno::EPEERDIED.to_syscall_ret() || rc == Errno::EREVOKED.to_syscall_ret() {
                IdlError::PeerDied
            } else if rc == Errno::EDEADLINE.to_syscall_ret() {
                IdlError::DeadlineExpired
            } else {
                IdlError::Refused
            };
            put_status(e, &mut self.rsp)
        };
        self.finish_rep(si, h, n, dedupe);
    }

    /// The answer of the real server as the message for the caller: its words,
    /// and the pages of each MemObj it lent (a capability of any other kind
    /// cannot cross, and makes the answer `Refused`). The server's copies are
    /// closed: the pages are in the message.
    fn encode_reply(&mut self, d: &MsgDesc) -> usize {
        let mut wire = *d;
        let mut at = 0;
        let fits = (0..d.n_caps as usize).all(|k| {
            let c = d.caps[k];
            c.mode == CAP_MODE_DUP || c.mode == CAP_MODE_MOVE
        });
        let mut ok = fits;
        for c in wire.caps.iter_mut().take(d.n_caps as usize) {
            // The far side re-mints; what it lends it lends for its own TTL.
            c.mode = CAP_MODE_MOVE;
            c.expiry_ns = 0;
            ok &= self.host.mo_size(c.handle).is_some();
        }
        if ok && put_desc(&wire, &mut self.rsp, &mut at).is_some() {
            for c in d.caps.iter().take(d.n_caps as usize) {
                let Some(size) = self.host.mo_size(c.handle) else { ok = false; break };
                if at + 4 + size > MSG_CAP {
                    ok = false;
                    break;
                }
                let Some(n) = self.host.mo_read(c.handle, &mut self.rsp[at + 4..at + 4 + size]) else {
                    ok = false;
                    break;
                };
                self.rsp[at..at + 4].copy_from_slice(&(n as u32).to_le_bytes());
                at += 4 + n;
            }
        } else {
            ok = false;
        }
        for c in d.caps.iter().take(d.n_caps as usize) {
            self.host.close(c.handle);
        }
        if ok { at } else { put_status(IdlError::Refused, &mut self.rsp) }
    }

    // ── time ────────────────────────────────────────────────────────────

    /// Housekeeping, called now and then (about every `rto`): resend Hellos,
    /// probe silent sessions and break the dead ones, close what lapsed, and
    /// dial the peers this node should dial.
    pub fn tick(&mut self) {
        let now = self.host.now_ns();
        for si in 0..MAX_SESSIONS {
            match self.sessions[si].state {
                State::Free => {}
                State::Dialing => {
                    if now.saturating_sub(self.sessions[si].probed_ns) >= self.cfg.rto_ns {
                        if self.sessions[si].hellos > self.cfg.retries {
                            self.sessions[si].state = State::Free;
                        } else {
                            self.sessions[si].hellos += 1;
                            self.sessions[si].probed_ns = now;
                            self.send_hello(si, Kind::Hello);
                        }
                    }
                }
                State::Up => {
                    self.sweep(si, now);
                    let s = &self.sessions[si];
                    if now.saturating_sub(s.heard_ns.max(s.probed_ns)) >= self.cfg.ping_ns {
                        if s.probed_ns > s.heard_ns {
                            // The last probe went unanswered.
                            self.sessions[si].misses += 1;
                            if self.sessions[si].misses >= self.cfg.miss_limit {
                                self.break_session(si, true);
                                continue;
                            }
                        }
                        let (peer, id) = (self.sessions[si].peer, self.sessions[si].id);
                        self.sessions[si].probed_ns = now;
                        let seq = now;
                        let p = self.header(Kind::Ping, id, seq);
                        send_msg(&mut self.link, &mut self.tx, peer, &p, &[]);
                    }
                }
            }
        }
        let nodes: [NodeId; crate::policy::PEERS_MAX] = {
            let mut a = [0; crate::policy::PEERS_MAX];
            for (i, n) in self.policy.nodes().enumerate() {
                a[i] = n;
            }
            a
        };
        for n in nodes.into_iter().filter(|&n| n != 0) {
            self.connect(n);
        }
    }

    /// Close the warrants and minted objects of session `si` that have lapsed.
    fn sweep(&mut self, si: usize, now: u64) {
        for k in 0..IFACES_MAX {
            let w = self.sessions[si].warrants[k];
            if w.live && w.expiry_ns != 0 && w.expiry_ns <= now {
                self.host.close(w.handle);
                self.sessions[si].warrants[k].live = false;
            }
        }
        for k in 0..MINTED_CAP {
            let m = self.sessions[si].minted[k];
            if m.live && m.expiry_ns != 0 && m.expiry_ns <= now {
                self.host.close(m.handle);
                self.sessions[si].minted[k].live = false;
            }
        }
    }
}
