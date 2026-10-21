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

use crate::chan::{self, Channel};
use crate::journal::Journal;
use crate::policy::{self, Name, Policy, Service};
use crate::session::{Minted, Pending, Remint, Seen, Session, State, Warrant};
use crate::wire::{
    cav, frags_for, get_data, get_desc, get_header, get_token, is_hello, put_desc, put_header, put_token, Asm, Caveat,
    Header, Kind, FRAGS_MAX, FRAG_BODY, FRAME_MAX, HEADER_BYTES, HELLO_MAX, MSG_CAP,
};
use crate::{Config, Host, Link, NodeId, IFACES_MAX, MAX_SESSIONS, MINTED_CAP, WARRANTS_MAX};

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
    /// The interface called (what the objects of its reply are tagged with).
    iface: u32,
}

/// A revocation notice sent to a peer and not yet acknowledged.
#[derive(Clone, Copy)]
struct Notice {
    used: bool,
    /// The interface whose authority was withdrawn.
    iface: u32,
    /// The notice's number (the frame's `seq`, echoed by the ack).
    nonce: u64,
    /// When it was first sent (this clock): the bound counts from here.
    sent_ns: u64,
    /// When it was last sent: it is resent every `rto`.
    tx_ns: u64,
    /// Handles this node closed on its own side when it withdrew.
    closed: u32,
}

const NO_NOTICE: Notice = Notice { used: false, iface: 0, nonce: 0, sent_ns: 0, tx_ns: 0, closed: 0 };

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
pub struct Rpc<H: Host, L: Link> {
    pub host: H,
    pub link: L,
    cfg: Config,
    policy: Policy,
    catalog: &'static [Service],
    sessions: [Session; MAX_SESSIONS],
    /// Handshakes answered and not yet confirmed (see [`Pending`]).
    pending: [Pending; MAX_SESSIONS],
    journal: Journal,
    tx: [u8; FRAME_MAX],
    /// The fragment just opened.
    plain: [u8; FRAG_BODY],
    /// The request being sent, kept for resends.
    enc: [u8; MSG_CAP],
    enc_len: usize,
    /// The answer received for the outstanding call.
    rep: [u8; MSG_CAP],
    /// Scratch: the answer being built, a Hello's body.
    rsp: [u8; MSG_CAP],
    pend: Pend,
    next_session: u32,
    /// Revocation notices in flight, per session slot (one per interface at
    /// most: a withdrawn interface is no longer granted).
    notices: [[Notice; IFACES_MAX]; MAX_SESSIONS],
    next_notice: u64,
    /// How long a notice may go unanswered before the session is broken
    /// (0: `rto * (retries + 1)`, the patience of a call).
    revoke_bound_ns: u64,
    /// The interface each live [`Session::minted`] object came in over.
    minted_iface: [[u32; MINTED_CAP]; MAX_SESSIONS],
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

/// Send `body` as the message `h`, one sealed frame per fragment (each with its
/// own packet counter, so a resend is a new packet).
fn send_msg<L: Link>(link: &mut L, tx: &mut [u8; FRAME_MAX], chan: &mut Channel, peer: NodeId, h: &Header, body: &[u8]) -> bool {
    let cnt = frags_for(body.len());
    debug_assert!(cnt <= FRAGS_MAX);
    let mut ok = true;
    for i in 0..cnt {
        let lo = i * FRAG_BODY;
        let hi = (lo + FRAG_BODY).min(body.len());
        let mut hh = *h;
        hh.frag_idx = i as u16;
        hh.frag_cnt = cnt as u16;
        ok &= match chan.seal(&mut hh, &body[lo..hi], tx) {
            Some(n) => link.send(peer, &tx[..n]),
            None => false,
        };
    }
    ok
}

/// Send a handshake message (one frame, not sealed: it is the Noise message).
fn send_hello_frame<L: Link>(link: &mut L, tx: &mut [u8; FRAME_MAX], peer: NodeId, h: &Header, msg: &[u8]) -> bool {
    put_header(h, tx);
    tx[HEADER_BYTES..HEADER_BYTES + msg.len()].copy_from_slice(msg);
    link.send(peer, &tx[..HEADER_BYTES + msg.len()])
}

/// The ids a Hello's payload lists: a count, then the ids.
fn put_ids(ids: &[u32], out: &mut [u8]) -> usize {
    out[0] = ids.len() as u8;
    let mut at = 1;
    for id in ids {
        out[at..at + 4].copy_from_slice(&id.to_le_bytes());
        at += 4;
    }
    at
}

fn get_ids(b: &[u8]) -> Option<([u32; IFACES_MAX], u8)> {
    let n = *b.first()? as usize;
    if n > IFACES_MAX {
        return None;
    }
    let mut ids = [0u32; IFACES_MAX];
    for (k, id) in ids.iter_mut().take(n).enumerate() {
        let w = b.get(1 + k * 4..5 + k * 4)?;
        *id = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
    }
    Some((ids, n as u8))
}

fn u32_le(b: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))
}

impl<H: Host, L: Link> Rpc<H, L> {
    /// A server over `link`, carrying the interfaces of `catalog`. **Nothing is
    /// set**: [`Rpc::configure`] gives it its node id and timings, and
    /// [`Rpc::set_policy`] its peers and exports (until then it exports
    /// nothing and knows no peer). Every field starts as zeros, so a `static`
    /// server costs no bytes in the image.
    pub const fn new(host: H, link: L, catalog: &'static [Service]) -> Self {
        Rpc {
            host,
            link,
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
            pending: [Pending::free(), Pending::free(), Pending::free(), Pending::free()],
            journal: Journal::new(),
            tx: [0; FRAME_MAX],
            plain: [0; FRAG_BODY],
            enc: [0; MSG_CAP],
            enc_len: 0,
            rep: [0; MSG_CAP],
            rsp: [0; MSG_CAP],
            pend: Pend { active: false, have: false, session: 0, seq: 0, len: 0 },
            next_session: 0,
            notices: [[NO_NOTICE; IFACES_MAX]; MAX_SESSIONS],
            next_notice: 0,
            revoke_bound_ns: 0,
            minted_iface: [[0; MINTED_CAP]; MAX_SESSIONS],
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

    /// How long a revocation notice may go unanswered before the session with
    /// the peer is broken (Kconfig `RPC_REVOKE_BOUND_MS`). Unset (0), the
    /// patience of a call: `rto * (retries + 1)`.
    pub fn set_revoke_bound(&mut self, ns: u64) {
        self.revoke_bound_ns = ns;
    }

    fn revoke_bound(&self) -> u64 {
        match self.revoke_bound_ns {
            0 => self.cfg.rto_ns.saturating_mul(u64::from(self.cfg.retries) + 1),
            b => b,
        }
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

    /// Dial `peer`, if this node has the lower id (the lower id dials, the
    /// higher answers, so two nodes never make two sessions), nothing is open
    /// yet and the topology pins the peer's static key. The Hello is the first
    /// message of the Noise IK handshake.
    pub fn connect(&mut self, peer: NodeId) {
        if self.cfg.node >= peer || self.si_by_peer(peer).is_some() {
            return;
        }
        let Some(class) = self.policy.class_of(peer) else { return };
        let Some(pk) = self.policy.noise_pk(peer).copied() else { return };
        let Some(si) = self.sessions.iter().position(|s| s.state == State::Free) else { return };
        let Some(mut sk) = self.host.static_key() else { return };
        let mut eph = [0u8; 32];
        if !self.host.entropy(&mut eph) {
            chan::wipe(&mut sk);
            return;
        }
        let now = self.host.now_ns();
        let (granted, ng) = self.grants_for(&class);
        let nonce = now | 1;
        let mut payload = [0u8; 1 + 4 * IFACES_MAX];
        let pn = put_ids(&granted[..ng as usize], &mut payload);
        let pro = chan::prologue(self.cfg.node, peer, self.cfg.epoch, nonce);
        let mut hello = [0u8; HELLO_MAX];
        let dialed = chan::dial(&sk, &pk, &pro, &eph, &payload[..pn], &mut hello);
        chan::wipe(&mut sk);
        let Some((_, n)) = dialed else {
            chan::wipe(&mut eph);
            return;
        };
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
        s.eph = eph;
        s.hello = hello;
        s.hello_len = n as u8;
        chan::wipe(&mut eph);
        self.send_hello(si);
    }

    /// Send (or resend) the Hello of the dialing session in slot `si`.
    fn send_hello(&mut self, si: usize) {
        let s = &self.sessions[si];
        let h = Header::new(Kind::Hello, 0, s.nonce, self.cfg.node, self.cfg.epoch);
        send_hello_frame(&mut self.link, &mut self.tx, s.peer, &h, &s.hello[..s.hello_len as usize]);
    }

    /// A Hello arrived: answer it if the sender is the node the topology
    /// pins this key to. The session it makes is **pending** until the dialer
    /// shows it holds the keys; a session already up is left alone.
    fn on_hello(&mut self, h: &Header, body: &[u8]) {
        // The higher node answers; a Hello from a higher node is not for us.
        if self.cfg.node <= h.node {
            return;
        }
        let Some(class) = self.policy.class_of(h.node) else {
            self.host.log(b"[rpcsrv] hello from a node no peer class lists: ignored\n");
            return;
        };
        let Some(pk) = self.policy.noise_pk(h.node).copied() else { return };
        // A Hello this node already answered (the answer was lost) is answered
        // again with the same bytes, which runs no handshake; one the session
        // up now came from, or an older one, is a repeat and is ignored.
        if let Some(p) = self.pending.iter().find(|p| p.used && p.peer == h.node && p.peer_epoch == h.epoch && p.nonce == h.seq) {
            let rh = Header::new(Kind::HelloAck, p.id, p.nonce, self.cfg.node, self.cfg.epoch);
            send_hello_frame(&mut self.link, &mut self.tx, h.node, &rh, &p.ack[..p.ack_len as usize]);
            return;
        }
        if let Some(si) = self.si_by_peer(h.node) {
            let s = &self.sessions[si];
            if s.peer_epoch == h.epoch && h.seq <= s.nonce {
                return;
            }
        }
        let Some(mut sk) = self.host.static_key() else { return };
        let mut eph = [0u8; 32];
        if !self.host.entropy(&mut eph) {
            chan::wipe(&mut sk);
            return;
        }
        let (granted, ng) = self.grants_for(&class);
        self.next_session = self.next_session.wrapping_add(1).max(1);
        let id = self.next_session;
        // The answer's payload: the session id, this node's epoch, the ids.
        let mut reply = [0u8; 8 + 1 + 4 * IFACES_MAX];
        reply[..4].copy_from_slice(&id.to_le_bytes());
        reply[4..8].copy_from_slice(&self.cfg.epoch.to_le_bytes());
        let rn = 8 + put_ids(&granted[..ng as usize], &mut reply[8..]);
        let pro = chan::prologue(h.node, self.cfg.node, h.epoch, h.seq);
        let mut ack = [0u8; HELLO_MAX];
        let mut payload = [0u8; 64];
        let r = chan::answer(&sk, &pk, &pro, body, &eph, &reply[..rn], &mut ack, &mut payload);
        chan::wipe(&mut sk);
        chan::wipe(&mut eph);
        let Some((channel, an, pn)) = r else {
            self.host.log(b"[rpcsrv] hello refused: not the key the topology pins for that node\n");
            return;
        };
        let Some((offered, no)) = get_ids(&payload[..pn]) else { return };
        let now = self.host.now_ns();
        // One slot per peer; else a free one; else the oldest is replaced.
        let pi = self
            .pending
            .iter()
            .position(|p| p.used && p.peer == h.node)
            .or_else(|| self.pending.iter().position(|p| !p.used))
            .unwrap_or_else(|| (0..MAX_SESSIONS).min_by_key(|&k| self.pending[k].born_ns).unwrap_or(0));
        let p = &mut self.pending[pi];
        p.used = true;
        p.peer = h.node;
        p.class = class;
        p.id = id;
        p.peer_epoch = h.epoch;
        p.nonce = h.seq;
        p.born_ns = now;
        p.offered = offered;
        p.n_offered = no;
        p.granted = granted;
        p.n_granted = ng;
        p.chan = channel;
        p.ack = ack;
        p.ack_len = an as u8;
        let rh = Header::new(Kind::HelloAck, id, h.seq, self.cfg.node, self.cfg.epoch);
        send_hello_frame(&mut self.link, &mut self.tx, h.node, &rh, &ack[..an]);
    }

    /// The answer to this node's Hello arrived: finish the handshake, and if
    /// the answerer holds the key the topology pins for it, the session is up.
    /// An answer that does not verify is ignored (anyone can send one; the
    /// dial goes on until its resends run out).
    fn on_ack(&mut self, h: &Header, body: &[u8]) {
        let Some(si) = self.sessions.iter().position(|s| s.state == State::Dialing && s.peer == h.node && s.nonce == h.seq)
        else {
            return;
        };
        let Some(pk) = self.policy.noise_pk(h.node).copied() else { return };
        let Some(mut sk) = self.host.static_key() else { return };
        // The handshake is a pure function of its inputs: the same ephemeral
        // key and payload rebuild the state the Hello left.
        let (nonce, eph, granted, ng) = {
            let s = &self.sessions[si];
            (s.nonce, s.eph, s.granted, s.n_granted)
        };
        let mut payload = [0u8; 1 + 4 * IFACES_MAX];
        let pn = put_ids(&granted[..ng as usize], &mut payload);
        let pro = chan::prologue(self.cfg.node, h.node, self.cfg.epoch, nonce);
        let mut scratch = [0u8; HELLO_MAX];
        let dialed = chan::dial(&sk, &pk, &pro, &eph, &payload[..pn], &mut scratch);
        chan::wipe(&mut sk);
        let Some((hs, _)) = dialed else { return };
        let mut reply = [0u8; 64];
        let Some((channel, rn)) = chan::finish_dial(hs, &pk, body, &mut reply) else {
            self.host.log(b"[rpcsrv] hello answer refused: not the key the topology pins for that node\n");
            return;
        };
        let (Some(id), Some(epoch)) = (u32_le(&reply[..rn]), reply[..rn].get(4..).and_then(u32_le)) else { return };
        let Some((ids, n)) = reply[..rn].get(8..).and_then(get_ids) else { return };
        // The header says nothing the keys did not already say: it must agree.
        if id == 0 || id != h.session || epoch != h.epoch {
            return;
        }
        let now = self.host.now_ns();
        let window = self.cfg.dedupe_window;
        let s = &mut self.sessions[si];
        s.state = State::Up;
        s.id = id;
        s.peer_epoch = epoch;
        s.next_seq = 1;
        s.heard_ns = now;
        s.probed_ns = now;
        s.misses = 0;
        s.offered = ids;
        s.n_offered = n;
        s.dedupe.reset(window);
        s.warrants.iter_mut().for_each(|w| w.live = false);
        s.reset_quotas();
        s.minted.iter_mut().for_each(|m| m.live = false);
        s.chan = channel;
        s.confirmed = false;
        chan::wipe(&mut s.eph);
        // The dialer's first sealed frame is what lets the answerer replace
        // the session it had: send it now, not at the next probe.
        self.ping(si, now);
    }

    /// The first sealed frame under new keys opened: the pending handshake in
    /// slot `pi` is confirmed, and replaces the session the peer had (all it
    /// minted is revoked). The slot of the session now up.
    fn promote(&mut self, pi: usize) -> Option<usize> {
        let peer = self.pending[pi].peer;
        let si = match self.si_by_peer(peer) {
            Some(si) => {
                self.break_session(si, false);
                si
            }
            None => match self.sessions.iter().position(|s| s.state == State::Free) {
                Some(si) => si,
                None => {
                    self.pending[pi].used = false;
                    self.pending[pi].chan.clear();
                    return None;
                }
            },
        };
        let now = self.host.now_ns();
        let window = self.cfg.dedupe_window;
        let p = &mut self.pending[pi];
        let s = &mut self.sessions[si];
        s.state = State::Up;
        s.peer = p.peer;
        s.class = p.class;
        s.id = p.id;
        s.peer_epoch = p.peer_epoch;
        s.nonce = p.nonce;
        s.next_seq = 1;
        s.heard_ns = now;
        s.probed_ns = now;
        s.misses = 0;
        s.offered = p.offered;
        s.n_offered = p.n_offered;
        s.granted = p.granted;
        s.n_granted = p.n_granted;
        s.dedupe.reset(window);
        s.warrants.iter_mut().for_each(|w| w.live = false);
        s.reset_quotas();
        s.minted.iter_mut().for_each(|m| m.live = false);
        s.confirmed = true;
        core::mem::swap(&mut s.chan, &mut p.chan);
        p.chan.clear();
        p.used = false;
        Some(si)
    }

    /// Probe session `si`: a sealed Ping.
    fn ping(&mut self, si: usize, now: u64) {
        let (peer, id) = (self.sessions[si].peer, self.sessions[si].id);
        self.sessions[si].probed_ns = now;
        let p = self.header(Kind::Ping, id, now);
        send_msg(&mut self.link, &mut self.tx, &mut self.sessions[si].chan, peer, &p, &[]);
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
        for k in 0..WARRANTS_MAX {
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
        self.notices[si] = [NO_NOTICE; IFACES_MAX];
        if notify && self.sessions[si].state == State::Up {
            let h = self.header(Kind::Bye, id, 0);
            send_msg(&mut self.link, &mut self.tx, &mut self.sessions[si].chan, peer, &h, &[]);
        }
        self.sessions[si].clear();
    }

    // ── minted objects and warrants ─────────────────────────────────────

    fn track_minted(&mut self, si: usize, handle: u32, expiry_ns: u64, iface: u32) {
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
        self.minted_iface[si][slot] = iface;
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

    /// The slot of the live warrant of session `si` that can serve a call of
    /// `iface` whose token re-minted to `g`: for the interface, with exactly
    /// the caveats of `g`, and **lapsing no later than the token does** (a
    /// warrant that outlives the token would run the call under an expiry the
    /// token never had; it is a miss, and the token gets a warrant of its own).
    fn warrant_slot(&self, si: usize, iface: u32, g: &Remint) -> Option<usize> {
        self.sessions[si].warrants.iter().position(|w| {
            let outlives = g.expiry_ns != 0 && (w.expiry_ns == 0 || w.expiry_ns > g.expiry_ns);
            w.live && w.iface == iface && !outlives && w.caveats[..w.n_caveats as usize] == *g.caveat_list()
        })
    }

    /// The warrant for interface `iface` over session `si` under the caveats of
    /// `g`: the live one, or a fresh child of `ep` (renewed when a quarter of
    /// its life is left) lapsing at `g.expiry_ns` (what the call's token
    /// re-minted to, 0 never). With every slot taken the one that lapses first
    /// is closed. The token's `QUOTA`s are not the warrant's: they are counted
    /// by the session ([`Session::spend`]), so a warrant evicted, renewed or
    /// derived again never renews a count.
    fn warrant(&mut self, si: usize, iface: u32, ep: u32, now: u64, g: &Remint) -> Option<u32> {
        let ttl = self.cfg.warrant_ttl_ns;
        if let Some(k) = self.warrant_slot(si, iface, g) {
            let w = self.sessions[si].warrants[k];
            if ttl == 0 || w.expiry_ns > now + ttl / 4 {
                return Some(w.handle);
            }
            self.host.close(w.handle);
            self.sessions[si].warrants[k].live = false;
        }
        let k = match self.sessions[si].warrants.iter().position(|w| !w.live) {
            Some(k) => k,
            None => {
                let k = (0..WARRANTS_MAX)
                    .min_by_key(|&k| match self.sessions[si].warrants[k].expiry_ns {
                        0 => u64::MAX,
                        e => e,
                    })
                    .unwrap_or(0);
                self.host.close(self.sessions[si].warrants[k].handle);
                k
            }
        };
        let (peer, id) = (self.sessions[si].peer, self.sessions[si].id);
        let h = match self.host.derive(ep, WRITE, id, g.expiry_ns, g.caveat_list()) {
            Ok(h) => h,
            Err(e) => {
                self.sessions[si].warrants[k].live = false;
                // The endpoint capability itself is gone (closed, or revoked
                // from above): the export is withdrawn, not just this derive.
                if e == Errno::ECAPSTALE.to_syscall_ret() || e == Errno::EREVOKED.to_syscall_ret() {
                    self.revoke_export(iface);
                }
                return None;
            }
        };
        self.sessions[si].warrants[k] =
            Warrant { live: true, iface, caveats: g.caveats, n_caveats: g.n_caveats, handle: h, expiry_ns: g.expiry_ns };
        self.journal.derive(now, peer, id, 0, id, h, ep, [iface as u64, g.n_caveats as u64, g.expiry_ns]);
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
        // The warrant for the call: started by this node under the session's key
        // and narrowed to the node it is sent to (a token captured and replayed
        // at a third node is refused there). No `EXPIRY`: a resend repeats these
        // bytes, and a time-left caveat would be anchored again at each arrival.
        let peer_node = self.sessions[si].peer;
        let Some(mut tok) = self.sessions[si].issue(self.cfg.node, id) else { return refuse(self, IdlError::NoConnection) };
        if tok.attenuate(Caveat::new(cav::NODE, u64::from(peer_node))).is_err()
            || put_token(&tok, &mut self.enc, &mut at).is_none()
        {
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
            iface: id,
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
        if let Some(si) = self.si_up_by_id(call.session) {
            send_msg(&mut self.link, &mut self.tx, &mut self.sessions[si].chan, call.peer, &h, &self.enc[..self.enc_len]);
        }
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
            self.track_minted(si, h, expiry, call.iface);
            let rights = if wire.rights & RW != 0 { wire.rights & RW } else { RW };
            d.caps[k] = CapDesc { handle: h, mode: CAP_MODE_DUP, _pad: 0, rights, expiry_ns: expiry };
            self.journal.derive(now, call.peer, call.session, call.seq, 0, h, 0, [0, 0, expiry]);
        }
        d
    }

    // ── frames in ───────────────────────────────────────────────────────

    /// A datagram arrived. `asm` is the reassembly state of the thread that
    /// reads the link. A Hello and its answer are the handshake; every other
    /// frame must open under the keys of the session it names (or of a
    /// pending handshake, which it then confirms): a frame that does not, a
    /// repeat of one that did, or one for a session this node does not have is
    /// dropped without a word.
    pub fn on_frame(&mut self, asm: &mut Asm, frame: &[u8]) {
        let Some((h, rest)) = get_header(frame) else { return };
        if h.node == 0 || h.node == self.cfg.node {
            return;
        }
        if is_hello(h.kind) {
            return if h.kind == Kind::Hello { self.on_hello(&h, rest) } else { self.on_ack(&h, rest) };
        }
        let opened = if let Some(si) = self.si_up(h.node, h.session) {
            self.sessions[si].chan.open(&h, frame, &mut self.plain)
        } else if let Some(pi) = self.pending.iter().position(|p| p.used && p.peer == h.node && p.id == h.session) {
            let n = self.pending[pi].chan.open(&h, frame, &mut self.plain);
            if n.is_some() && self.promote(pi).is_none() {
                return;
            }
            n
        } else {
            None
        };
        let Some(n) = opened else { return };
        let Some(slot) = asm.push(&h, &self.plain[..n]) else { return };
        let (head, body) = asm.message(slot);
        self.dispatch(&head, body);
        asm.done(slot);
    }

    fn dispatch(&mut self, h: &Header, body: &[u8]) {
        let Some(si) = self.si_up(h.node, h.session) else { return };
        let now = self.host.now_ns();
        self.sessions[si].heard_ns = now;
        self.sessions[si].misses = 0;
        self.sessions[si].confirmed = true;
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
                send_msg(&mut self.link, &mut self.tx, &mut self.sessions[si].chan, h.node, &p, &[]);
            }
            Kind::Pong => {}
            Kind::Bye => self.break_session(si, false),
            Kind::Revoke => self.on_revoke(si, h, body),
            Kind::RevokeAck => self.on_revoke_ack(si, h, body, now),
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
        send_msg(&mut self.link, &mut self.tx, &mut self.sessions[si].chan, peer, &r, &self.rsp[..n]);
    }

    fn serve_req(&mut self, si: usize, h: &Header, body: &[u8], now: u64) {
        let (peer, session) = (self.sessions[si].peer, self.sessions[si].id);
        let mut at = 0;
        let Some(mut desc) = get_desc(body, &mut at) else { return self.reply_status(si, h, IdlError::Malformed, false) };
        if desc.n_words < 1 {
            return self.reply_status(si, h, IdlError::Malformed, false);
        }
        let Some(tok) = get_token(body, &mut at) else { return self.reply_status(si, h, IdlError::Malformed, false) };
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
        // The token the call came with: verified under the session's key, for
        // this very interface, and re-minted as the warrant this node lends the
        // peer. Anything it does not hold up to refuses the call.
        let ttl = self.cfg.warrant_ttl_ns;
        let grant = match self.sessions[si].remint(&tok, self.cfg.node, now, ttl) {
            Ok(r) if r.iface == id && r.usable() => Some(r),
            _ => None,
        };
        let Some(grant) = grant else {
            self.journal.refuse(now, peer, session, h.seq, session, refuse_n);
            return self.reply_status(si, h, IdlError::Refused, false);
        };
        // A call that must not run twice: a repeat gets the answer kept, or
        // the admission that it cannot be told.
        let dedupe = !matches!(delivery, Delivery::Idempotent);
        if dedupe {
            let r = self.header(Kind::Rep, h.session, h.seq);
            let s = &mut self.sessions[si];
            match s.dedupe.lookup(h.seq) {
                Seen::Cached(b) => {
                    send_msg(&mut self.link, &mut self.tx, &mut s.chan, peer, &r, b);
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
            // Granted at the handshake and held no longer: the authority this
            // node lent for the interface is gone.
            self.revoke_export(id);
            return self.reply_status(si, h, IdlError::Refused, false);
        };
        let lend_until = grant.expiry_ns;

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
            self.track_minted(si, m, until, id);
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

        // A use of every `QUOTA` the token carries, counted here and per
        // lineage: all of them or none, and the call refused when one is spent.
        if !self.sessions[si].spend(grant.budget_list()) {
            for c in desc.caps.iter().take(made) {
                self.release_minted(si, c.handle);
            }
            self.journal.refuse(now, peer, session, h.seq, session, refuse_n);
            return self.reply_status(si, h, IdlError::Refused, false);
        }

        // The call, through the peer's warrant, with the deadline the caller has left.
        desc.version = MSG_VERSION;
        desc.flags = 0;
        desc.badge = 0;
        desc.deadline = abs_deadline;
        desc.clock_id = 0;
        // Data from another node carries no local label; the kernel adds this
        // server's principal to the call.
        desc.label = 0;
        let saved = desc;
        let mut rc = match self.warrant(si, id, ep, now, &grant) {
            Some(w) => self.host.call(w, &mut desc),
            None => Errno::EPERM.to_syscall_ret(),
        };
        // The warrant lapsed under the call: derive a fresh one, once (the
        // quota was counted above and is not counted again).
        if rc == Errno::EPERM.to_syscall_ret() || rc == Errno::ECAPSTALE.to_syscall_ret() {
            if let Some(k) = self.warrant_slot(si, id, &grant) {
                self.host.close(self.sessions[si].warrants[k].handle);
                self.sessions[si].warrants[k].live = false;
            }
            if let Some(w) = self.warrant(si, id, ep, now, &grant) {
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

    // ── revocation across nodes ─────────────────────────────────────────

    /// **This node's authority over `iface` is gone** (its export endpoint was
    /// closed or revoked): what it lent the peers over the interface is closed
    /// here (the warrants it derived, the objects it re-minted from their
    /// pages), the interface is no longer granted, and every peer that holds
    /// authority descending from it is sent a signed notice (a sealed
    /// [`Kind::Revoke`]). The peer revokes what it holds (the interface is no
    /// longer offered to its callers, the objects it re-minted from this
    /// node's replies are revoked) and answers [`Kind::RevokeAck`]; from the
    /// instant the ack arrives no effect of the authority remains over that
    /// link. A peer that does not answer within the bound ([`Rpc::set_revoke_bound`])
    /// has its session broken, which revokes everything minted over it. Both
    /// sides record `Rule::RemoteRevoke`. Called when the engine finds the
    /// endpoint gone (a request it cannot serve, a derive the kernel refuses
    /// as stale, the housekeeping tick) and by whoever withdraws an export.
    pub fn revoke_export(&mut self, iface: u32) {
        let now = self.host.now_ns();
        for si in 0..MAX_SESSIONS {
            // A session still dialing grants what its Hello said; it is
            // checked once it is up.
            if self.sessions[si].state != State::Up || !self.sessions[si].grants(iface) {
                continue;
            }
            let closed = self.close_iface(si, iface);
            let s = &mut self.sessions[si];
            if let Some(k) = s.granted[..s.n_granted as usize].iter().position(|&g| g == iface) {
                s.n_granted -= 1;
                s.granted[k] = s.granted[s.n_granted as usize];
            }
            let Some(slot) = self.notices[si].iter().position(|n| !n.used) else {
                // A notice that cannot be tracked cannot be bounded: the
                // session goes (and with it everything minted over it).
                self.break_session(si, true);
                continue;
            };
            self.next_notice += 1;
            let nonce = self.next_notice;
            self.notices[si][slot] = Notice { used: true, iface, nonce, sent_ns: now, tx_ns: now, closed };
            self.send_notice(si, nonce, iface);
        }
    }

    /// Close the warrants and re-minted objects of session `si` that belong to
    /// `iface`; how many handles.
    fn close_iface(&mut self, si: usize, iface: u32) -> u32 {
        let mut closed = 0;
        for k in 0..WARRANTS_MAX {
            let w = self.sessions[si].warrants[k];
            if w.live && w.iface == iface {
                self.host.close(w.handle);
                self.sessions[si].warrants[k].live = false;
                closed += 1;
            }
        }
        for k in 0..MINTED_CAP {
            let m = self.sessions[si].minted[k];
            if m.live && self.minted_iface[si][k] == iface {
                self.host.close(m.handle);
                self.sessions[si].minted[k].live = false;
                closed += 1;
            }
        }
        closed
    }

    fn send_notice(&mut self, si: usize, nonce: u64, iface: u32) {
        let (peer, id) = (self.sessions[si].peer, self.sessions[si].id);
        let h = self.header(Kind::Revoke, id, nonce);
        send_msg(&mut self.link, &mut self.tx, &mut self.sessions[si].chan, peer, &h, &iface.to_le_bytes());
    }

    /// The peer of session `si` withdrew its authority over the interface in
    /// `body`: stop offering it, revoke the objects re-minted from its replies
    /// (closing each takes the copies lent to the local callers with it),
    /// record it, and answer. A repeated notice finds nothing left to
    /// revoke and is answered the same.
    fn on_revoke(&mut self, si: usize, h: &Header, body: &[u8]) {
        let Some(iface) = u32_le(body).filter(|&i| i != 0 && body.len() == 4) else { return };
        let (peer, id, epoch) = (self.sessions[si].peer, self.sessions[si].id, self.sessions[si].peer_epoch);
        let s = &mut self.sessions[si];
        let held = s.offers(iface);
        if let Some(k) = s.offered[..s.n_offered as usize].iter().position(|&o| o == iface) {
            s.n_offered -= 1;
            s.offered[k] = s.offered[s.n_offered as usize];
        }
        let mut closed = 0u64;
        for k in 0..MINTED_CAP {
            let m = self.sessions[si].minted[k];
            if m.live && self.minted_iface[si][k] == iface {
                self.host.close(m.handle);
                self.sessions[si].minted[k].live = false;
                closed += 1;
            }
        }
        if held || closed > 0 {
            let now = self.host.now_ns();
            self.journal.remote_revoke(now, peer, id, h.seq, [iface as u64, closed, epoch as u64]);
        }
        let r = self.header(Kind::RevokeAck, id, h.seq);
        send_msg(&mut self.link, &mut self.tx, &mut self.sessions[si].chan, peer, &r, &iface.to_le_bytes());
    }

    /// The peer ran notice `h.seq`: the revocation has taken effect over the
    /// link as of now.
    fn on_revoke_ack(&mut self, si: usize, h: &Header, body: &[u8], now: u64) {
        let Some(iface) = u32_le(body).filter(|_| body.len() == 4) else { return };
        let Some(k) = self.notices[si].iter().position(|n| n.used && n.nonce == h.seq && n.iface == iface) else { return };
        let n = self.notices[si][k];
        self.notices[si][k] = NO_NOTICE;
        let (peer, id, epoch) = (self.sessions[si].peer, self.sessions[si].id, self.sessions[si].peer_epoch);
        self.journal.remote_revoke(now, peer, id, n.nonce, [iface as u64, n.closed as u64, epoch as u64]);
    }

    /// Resend the notices of session `si` that are due and enforce the bound.
    /// `false` when the bound ran out and the session was broken.
    fn chase_notices(&mut self, si: usize, now: u64) -> bool {
        if self.sessions[si].state != State::Up {
            return false;
        }
        let bound = self.revoke_bound();
        for k in 0..IFACES_MAX {
            let n = self.notices[si][k];
            if !n.used {
                continue;
            }
            if now.saturating_sub(n.sent_ns) >= bound {
                let (peer, id, epoch) = (self.sessions[si].peer, self.sessions[si].id, self.sessions[si].peer_epoch);
                self.journal.remote_revoke_unconfirmed(now, peer, id, n.nonce, [n.iface as u64, n.closed as u64, epoch as u64]);
                self.break_session(si, true);
                return false;
            }
            if now.saturating_sub(n.tx_ns) >= self.cfg.rto_ns {
                self.notices[si][k].tx_ns = now;
                self.send_notice(si, n.nonce, n.iface);
            }
        }
        true
    }

    /// Is the endpoint this node exports `id` over still held? The interfaces
    /// granted on session `si` are checked, and one that is not is withdrawn.
    /// The held endpoint capability is the authority behind the grant, so its
    /// absence (even for the moment a local server restarts) is a withdrawal:
    /// the peer is told, answers, and is granted the new endpoint only by a new
    /// handshake. The cost is one notice and one ack, not a session break,
    /// unless the peer stays silent past the bound.
    fn check_exports(&mut self, si: usize) {
        let (ids, n, class) = {
            let s = &self.sessions[si];
            (s.granted, s.n_granted as usize, s.class)
        };
        for &id in &ids[..n] {
            let held = policy::find(self.catalog, id)
                .and_then(|svc| self.policy.export(svc.name, &class))
                .is_some_and(|e| self.host.endpoint(e.index).is_some());
            if !held {
                self.revoke_export(id);
            }
        }
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
                            self.sessions[si].clear();
                        } else {
                            self.sessions[si].hellos += 1;
                            self.sessions[si].probed_ns = now;
                            self.send_hello(si);
                        }
                    }
                }
                State::Up => {
                    self.sweep(si, now);
                    self.check_exports(si);
                    if !self.chase_notices(si, now) {
                        continue;
                    }
                    let s = &self.sessions[si];
                    // The answerer has not been heard from since the keys were
                    // agreed: the confirming Ping may have been lost, so it is
                    // resent every `rto`, not every `ping`.
                    let every = if s.confirmed { self.cfg.ping_ns } else { self.cfg.rto_ns };
                    if now.saturating_sub(s.heard_ns.max(s.probed_ns)) >= every {
                        if s.probed_ns > s.heard_ns {
                            // The last probe went unanswered.
                            self.sessions[si].misses += 1;
                            if self.sessions[si].misses >= self.cfg.miss_limit {
                                self.break_session(si, true);
                                continue;
                            }
                        }
                        self.ping(si, now);
                    }
                }
            }
        }
        // A handshake whose dialer never confirmed it (a lost Ping is resent,
        // a replayed Hello never is) is forgotten.
        let lapse = self.cfg.ping_ns.max(self.cfg.rto_ns.saturating_mul(u64::from(self.cfg.retries) + 2));
        for p in self.pending.iter_mut().filter(|p| p.used) {
            if now.saturating_sub(p.born_ns) >= lapse {
                p.used = false;
                p.chan.clear();
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
        for k in 0..WARRANTS_MAX {
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
