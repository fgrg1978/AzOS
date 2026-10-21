// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The server side of one SSH connection, as a state machine with no I/O.
//!
//! The host loop feeds it the bytes the socket delivered ([`Server::feed`]),
//! sends the bytes it queued ([`Server::pending`], [`Server::advance`]) and
//! acts on the [`Event`]s it raised (a login, a pty, a command, typed bytes).
//! Time, randomness and the record of refusals come through [`Env`]. Nothing
//! here reads a clock or a socket, so `tests/host/sshd-tests` drives it with a
//! client written there.
//!
//! The layers, in the order a connection goes through them:
//!
//!  1. the version lines (RFC 4253 section 4.2);
//!  2. key exchange (`kex.rs`), then packets sealed by `packet.rs`; strict key
//!     exchange when the client offers it, and a client-started re-exchange
//!     at any time after the first;
//!  3. the `ssh-userauth` service: a signature by an authorized key
//!     (`auth.rs`), at most [`MAX_FAILURES`] failed attempts;
//!  4. the connection layer: one `session` channel at a time, whose requests
//!     (`pty-req`, `shell`, `exec`, `window-change`) become events. Everything
//!     else a client may ask (forwarding, subsystems, agent and X11) is
//!     refused, and each refusal is a [`Decision`].
//!
//! Before authentication the only messages accepted are the transport's and
//! the authentication service's; a connection-layer message from a client that
//! has not logged in ends the connection.

use crate::auth::{self, AuthKey, Method};
use crate::kex::{self, Exchange, KexError, Proposal};
use crate::packet::{Key, PacketError, Rx, Tx};
use crate::wire::*;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use azos_crypto::x25519::{x25519_checked, BASEPOINT};

/// Failed login attempts allowed before the connection is ended.
pub const MAX_FAILURES: u32 = 6;
/// Authentication requests allowed in all (queries for keys included).
pub const MAX_REQUESTS: u32 = 24;
/// The bytes of channel data the server lets the client have in flight.
pub const LOCAL_WINDOW: u32 = 65536;
/// The largest data packet the server accepts on the channel.
pub const LOCAL_MAX_PACKET: u32 = 16384;
/// The most channel data one packet carries: with the packet's own bytes it is
/// about one TCP segment, and the packet is a small allocation (the ring-3
/// allocator maps anything over 2 KiB afresh, with guard pages, and a long
/// stream of those runs the program out of address space).
pub const MAX_DATA: usize = 1400;
/// The longest version line (RFC 4253 section 4.2).
const MAX_VERSION_LINE: usize = 255;

/// What the server needs from its host.
pub trait Env {
    /// Fill `out` from the entropy pool.
    fn random(&mut self, out: &mut [u8]);
    /// Sign `msg` (the exchange hash) with the host key. The key is the
    /// host's: the server holds its public part ([`Config::host_public`]) and
    /// never the secret. `None`: the keystore refused or is gone, and the key
    /// exchange fails.
    fn sign_host(&mut self, msg: &[u8]) -> Option<[u8; 64]>;
    /// A decision the server took (a login or a session refused, or let in).
    fn decision(&mut self, d: Decision);
}

/// What was decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// Key exchange: the client's algorithms against the server's.
    Kex,
    /// Authentication: who may log in.
    Login,
    /// The connection layer: what a logged-in client may ask.
    Session,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Admit,
    Refuse,
}

/// A decision record of the server: the rule, the verdict, the subject, the
/// reason, and the alternative the verdict rejected (as the kernel's records
/// carry it, `azos_decision::RULES`). The kernel's journal cannot be written
/// from ring 3, so these go to the console and to the volume's log
/// (`main.rs`), the way the RPC server keeps its own provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub rule: Rule,
    pub verdict: Verdict,
    /// The user name the client gave, or what the request named.
    pub subject: Vec<u8>,
    /// The key it used, if any.
    pub key: Option<[u8; 32]>,
    pub why: &'static str,
}

impl Decision {
    /// The alternative this verdict rejected.
    pub fn rejected(&self) -> &'static str {
        match (self.rule, self.verdict) {
            (Rule::Kex, Verdict::Refuse) => "negotiate down to an algorithm the server does not offer",
            (Rule::Kex, Verdict::Admit) => "-",
            (Rule::Login, Verdict::Refuse) => "log in: the request names an authorized key and a signature that verifies",
            (Rule::Login, Verdict::Admit) => "refuse: the key is not authorized, or its signature does not verify",
            (Rule::Session, Verdict::Refuse) => "serve the request: only an interactive session or a command is offered",
            (Rule::Session, Verdict::Admit) => "-",
        }
    }

    /// One log line, no newline.
    pub fn line(&self) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(match self.rule {
            Rule::Kex => b"kex ",
            Rule::Login => b"login ",
            Rule::Session => b"session ",
        });
        s.extend_from_slice(match self.verdict {
            Verdict::Admit => b"admit",
            Verdict::Refuse => b"refuse",
        });
        s.extend_from_slice(b" user=");
        for &c in self.subject.iter().take(64) {
            s.push(if (0x20..0x7f).contains(&c) && c != b'=' { c } else { b'?' });
        }
        if let Some(k) = &self.key {
            s.extend_from_slice(b" key=");
            s.extend_from_slice(&kex::fingerprint(k));
        }
        s.extend_from_slice(b" why=");
        s.extend_from_slice(self.why.as_bytes());
        s.extend_from_slice(b" rejected=");
        s.extend_from_slice(self.rejected().as_bytes());
        s
    }
}

/// What the host does after the server has seen something.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client logged in with this key.
    Authenticated { user: Vec<u8>, key: [u8; 32] },
    /// `pty-req`: a terminal of this size.
    Pty { term: Vec<u8>, cols: u32, rows: u32 },
    /// `window-change`.
    Resize { cols: u32, rows: u32 },
    /// `shell`.
    Shell,
    /// `exec`: the command line.
    Exec(Vec<u8>),
    /// Bytes the client typed or piped.
    Data(Vec<u8>),
    /// The client sent EOF on the channel.
    Eof,
    /// The channel is gone (closed by either side).
    Closed,
}

/// The server's long-lived settings.
pub struct Config {
    /// The public part of the host key, which the host signs with ([`Env::sign_host`]).
    pub host_public: [u8; 32],
    pub authorized: Vec<AuthKey>,
}

impl Config {
    pub fn new(host_public: [u8; 32], authorized: Vec<AuthKey>) -> Self {
        Self { host_public, authorized }
    }
}

/// Where the key exchange stands.
enum Step {
    /// Our KEXINIT is out; the client's is not in.
    WaitKexInit,
    /// Both are in; the client's ECDH_INIT is next.
    WaitEcdhInit,
    /// We sent our NEWKEYS; the client's is next. The key it brings is held.
    WaitNewKeys(Key),
}

struct Kex {
    step: Step,
    ours: Vec<u8>,
    theirs: Vec<u8>,
    /// The next packet is a wrong guess of the client's: drop it.
    skip: bool,
}

struct Chan {
    peer: u32,
    /// How much the client still lets us send.
    peer_window: u64,
    peer_max_packet: u32,
    /// How much we still let the client send.
    local_window: u32,
    /// Window to give back once the host has taken the data.
    returned: u32,
    sent_close: bool,
    sent_eof: bool,
}

/// One connection.
pub struct Server<'c> {
    cfg: &'c Config,
    closed: bool,
    /// The version lines are read; packets follow.
    versioned: bool,
    ver_buf: Vec<u8>,
    client_version: Vec<u8>,
    rx: Rx,
    tx: Tx,
    out: Vec<u8>,
    /// Packets raised while a key exchange is running, sent after it.
    held: Vec<Vec<u8>>,
    kex: Option<Kex>,
    strict: bool,
    /// The first key exchange is over (both NEWKEYS are through).
    established: bool,
    session_id: Option<[u8; 32]>,
    service_ok: bool,
    user: Vec<u8>,
    authed: bool,
    failures: u32,
    requests: u32,
    chan: Option<Chan>,
    events: VecDeque<Event>,
}

type Fail = (u32, &'static str);

impl<'c> Server<'c> {
    /// A new connection: the version line and our KEXINIT are queued.
    pub fn new<E: Env>(cfg: &'c Config, env: &mut E) -> Self {
        let mut s = Self {
            cfg,
            closed: false,
            versioned: false,
            ver_buf: Vec::new(),
            client_version: Vec::new(),
            rx: Rx::new(),
            tx: Tx::new(),
            out: Vec::new(),
            held: Vec::new(),
            kex: None,
            strict: false,
            established: false,
            session_id: None,
            service_ok: false,
            user: Vec::new(),
            authed: false,
            failures: 0,
            requests: 0,
            chan: None,
            events: VecDeque::new(),
        };
        s.out.extend_from_slice(kex::VERSION);
        s.out.extend_from_slice(b"\r\n");
        let mut cookie = [0u8; 16];
        env.random(&mut cookie);
        let ours = kex::server_kexinit(&cookie);
        s.send_now(&ours);
        s.kex = Some(Kex { step: Step::WaitKexInit, ours, theirs: Vec::new(), skip: false });
        s
    }

    // ── Host-facing ─────────────────────────────────────────────────────────

    /// Bytes to send to the peer.
    pub fn pending(&self) -> &[u8] {
        &self.out
    }

    /// `n` bytes of [`Server::pending`] were sent.
    pub fn advance(&mut self, n: usize) {
        self.out.drain(..n.min(self.out.len()));
    }

    /// The connection is over (a DISCONNECT was queued, or the peer's came):
    /// send what is pending, then close the socket.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn is_authenticated(&self) -> bool {
        self.authed
    }

    pub fn pop_event(&mut self) -> Option<Event> {
        let ev = self.events.pop_front()?;
        if let Event::Data(d) = &ev {
            // The host has the bytes: give the window back (in batches).
            if let Some(c) = &mut self.chan {
                c.returned += d.len() as u32;
                if c.returned >= LOCAL_WINDOW / 4 && self.kex.is_none() {
                    let n = core::mem::take(&mut c.returned);
                    let peer = c.peer;
                    c.local_window += n;
                    let mut w = Writer::new(MSG_CHANNEL_WINDOW_ADJUST);
                    w.u32(peer).u32(n);
                    self.send(&w.buf);
                }
            }
        }
        Some(ev)
    }

    /// End the connection with a DISCONNECT.
    pub fn disconnect(&mut self, code: u32, why: &str) {
        if self.closed {
            return;
        }
        let mut w = Writer::new(MSG_DISCONNECT);
        w.u32(code).string(why.as_bytes()).string(b"");
        self.send_now(&w.buf);
        self.closed = true;
    }

    /// Can the host write channel data now? (Not during a key exchange, not
    /// with the peer's window shut, not without a channel.)
    pub fn can_write(&self) -> bool {
        self.kex.is_none()
            && !self.closed
            && self.chan.as_ref().is_some_and(|c| !c.sent_eof && c.peer_window > 0)
    }

    /// Send channel data; the number of bytes taken (0 if [`Server::can_write`]
    /// is false). Never more than one packet.
    pub fn write(&mut self, data: &[u8]) -> usize {
        if !self.can_write() {
            return 0;
        }
        let c = self.chan.as_mut().unwrap();
        let n = data.len().min(c.peer_window.min(u32::MAX as u64) as usize).min(c.peer_max_packet as usize).min(MAX_DATA);
        if n == 0 {
            return 0;
        }
        c.peer_window -= n as u64;
        let mut w = Writer::new(MSG_CHANNEL_DATA);
        w.u32(c.peer).string(&data[..n]);
        self.send(&w.buf);
        n
    }

    /// Report how the command ended, then end the channel's output: the
    /// `exit-status` request, EOF and CLOSE.
    pub fn finish(&mut self, status: u32) {
        let Some(c) = &mut self.chan else { return };
        if c.sent_close {
            return;
        }
        let peer = c.peer;
        c.sent_eof = true;
        c.sent_close = true;
        let mut w = Writer::new(MSG_CHANNEL_REQUEST);
        w.u32(peer).string(b"exit-status").boolean(false).u32(status);
        self.send(&w.buf);
        let mut w = Writer::new(MSG_CHANNEL_EOF);
        w.u32(peer);
        self.send(&w.buf);
        let mut w = Writer::new(MSG_CHANNEL_CLOSE);
        w.u32(peer);
        self.send(&w.buf);
    }

    // ── Input ───────────────────────────────────────────────────────────────

    /// Bytes from the socket.
    pub fn feed<E: Env>(&mut self, env: &mut E, bytes: &[u8]) {
        if self.closed {
            return;
        }
        let mut rest = bytes;
        if !self.versioned {
            self.ver_buf.extend_from_slice(rest);
            let Some(nl) = self.ver_buf.iter().position(|&c| c == b'\n') else {
                if self.ver_buf.len() > MAX_VERSION_LINE {
                    self.closed = true;
                }
                return;
            };
            if nl >= MAX_VERSION_LINE {
                self.closed = true;
                return;
            }
            let line = &self.ver_buf[..nl];
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if !(line.starts_with(b"SSH-2.0-") || line.starts_with(b"SSH-1.99-")) {
                // Not SSH-2: nothing to say to it in the SSH way.
                self.closed = true;
                return;
            }
            self.client_version = line.to_vec();
            let tail = self.ver_buf[nl + 1..].to_vec();
            self.ver_buf = Vec::new();
            self.versioned = true;
            self.rx.push(&tail);
            rest = &[];
        }
        self.rx.push(rest);
        loop {
            if self.closed {
                return;
            }
            match self.rx.next() {
                Ok(None) => return,
                Ok(Some(p)) => {
                    if let Err((code, why)) = self.dispatch(env, &p) {
                        self.disconnect(code, why);
                        return;
                    }
                }
                Err(e) => {
                    let why = match e {
                        PacketError::Mac => "bad packet authentication",
                        PacketError::Malformed => "malformed packet",
                        PacketError::SeqExhausted => "sequence numbers used up",
                    };
                    // A forged or damaged packet gets no answer under the
                    // keys it failed: the connection is simply dropped.
                    let _ = why;
                    self.closed = true;
                    return;
                }
            }
        }
    }

    // ── Sending ─────────────────────────────────────────────────────────────

    /// Queue a packet at once (the transport's own messages).
    fn send_now(&mut self, payload: &[u8]) {
        if self.tx.send(payload, &mut self.out).is_none() {
            self.closed = true;
        }
    }

    /// Queue a packet of the upper layers: held back while keys are changing.
    fn send(&mut self, payload: &[u8]) {
        if self.kex.is_some() {
            self.held.push(payload.to_vec());
        } else {
            self.send_now(payload);
        }
    }

    // ── Dispatch ────────────────────────────────────────────────────────────

    fn dispatch<E: Env>(&mut self, env: &mut E, p: &[u8]) -> Result<(), Fail> {
        let msg = p[0];
        let index = self.rx.seq().wrapping_sub(1);
        if self.kex.as_ref().is_some_and(|k| k.skip) {
            // The client's wrong guess of a key-exchange packet.
            self.kex.as_mut().unwrap().skip = false;
            return Ok(());
        }
        // Strict key exchange: while the first exchange runs, nothing but its
        // own messages (RFC-draft strict-kex): an IGNORE or DEBUG slipped in
        // is how the Terrapin attack shifts the sequence numbers.
        let initial = !self.established;
        if initial && self.strict && !matches!(msg, MSG_KEXINIT | MSG_KEX_ECDH_INIT | MSG_NEWKEYS | MSG_DISCONNECT) {
            return Err((DISCONNECT_PROTOCOL_ERROR, "unexpected message during strict key exchange"));
        }
        match msg {
            MSG_DISCONNECT => {
                self.closed = true;
                if self.chan.take().is_some() {
                    self.events.push_back(Event::Closed);
                }
                Ok(())
            }
            MSG_IGNORE | MSG_DEBUG => Ok(()),
            MSG_UNIMPLEMENTED => Ok(()),
            MSG_KEXINIT => self.on_kexinit(env, p, index),
            MSG_KEX_ECDH_INIT => self.on_ecdh_init(env, p),
            MSG_NEWKEYS => self.on_newkeys(),
            _ if self.kex.is_some() => Err((DISCONNECT_PROTOCOL_ERROR, "unexpected message during key exchange")),
            _ if self.session_id.is_none() => Err((DISCONNECT_PROTOCOL_ERROR, "message before key exchange")),
            MSG_SERVICE_REQUEST => self.on_service_request(p),
            MSG_USERAUTH_REQUEST => self.on_userauth(env, p),
            _ if !self.authed => Err((DISCONNECT_PROTOCOL_ERROR, "message before authentication")),
            MSG_GLOBAL_REQUEST => self.on_global_request(p),
            MSG_CHANNEL_OPEN => self.on_channel_open(env, p),
            MSG_CHANNEL_WINDOW_ADJUST => self.on_window_adjust(p),
            MSG_CHANNEL_DATA => self.on_channel_data(p, false),
            MSG_CHANNEL_EXTENDED_DATA => self.on_channel_data(p, true),
            MSG_CHANNEL_EOF => self.on_channel_eof(p),
            MSG_CHANNEL_CLOSE => self.on_channel_close(p),
            MSG_CHANNEL_REQUEST => self.on_channel_request(env, p),
            MSG_CHANNEL_SUCCESS | MSG_CHANNEL_FAILURE => Ok(()),
            _ => {
                // RFC 4253 section 11.4: answer an unknown message number with
                // UNIMPLEMENTED and the sequence number of the one we did not
                // understand.
                let mut w = Writer::new(MSG_UNIMPLEMENTED);
                w.u32(index);
                self.send(&w.buf);
                Ok(())
            }
        }
    }

    // ── Transport: key exchange ─────────────────────────────────────────────

    fn on_kexinit<E: Env>(&mut self, env: &mut E, p: &[u8], index: u32) -> Result<(), Fail> {
        let initial = !self.established;
        let proposal: Proposal = match kex::negotiate(p) {
            Ok(x) => x,
            Err(e) => {
                env.decision(Decision {
                    rule: Rule::Kex,
                    verdict: Verdict::Refuse,
                    subject: self.client_version.clone(),
                    key: None,
                    why: e.why(),
                });
                return Err((
                    DISCONNECT_KEY_EXCHANGE_FAILED,
                    if e == KexError::Malformed { "malformed key exchange init" } else { "no common algorithms" },
                ));
            }
        };
        if initial {
            self.strict = proposal.strict;
            if self.strict && index != 0 {
                return Err((DISCONNECT_PROTOCOL_ERROR, "strict key exchange: KEXINIT was not the first packet"));
            }
            let k = self.kex.as_mut().ok_or((DISCONNECT_PROTOCOL_ERROR, "unexpected KEXINIT"))?;
            if !matches!(k.step, Step::WaitKexInit) {
                return Err((DISCONNECT_PROTOCOL_ERROR, "unexpected KEXINIT"));
            }
            k.theirs = p.to_vec();
            k.skip = proposal.skip_next;
            k.step = Step::WaitEcdhInit;
        } else {
            // The client started a new exchange.
            if self.kex.is_some() {
                return Err((DISCONNECT_PROTOCOL_ERROR, "unexpected KEXINIT"));
            }
            let mut cookie = [0u8; 16];
            env.random(&mut cookie);
            let ours = kex::server_kexinit(&cookie);
            self.send_now(&ours);
            self.kex = Some(Kex { step: Step::WaitEcdhInit, ours, theirs: p.to_vec(), skip: proposal.skip_next });
        }
        Ok(())
    }

    fn on_ecdh_init<E: Env>(&mut self, env: &mut E, p: &[u8]) -> Result<(), Fail> {
        let fail = (DISCONNECT_KEY_EXCHANGE_FAILED, "key exchange failed");
        let Some(k) = &self.kex else { return Err((DISCONNECT_PROTOCOL_ERROR, "unexpected ECDH_INIT")) };
        if !matches!(k.step, Step::WaitEcdhInit) {
            return Err((DISCONNECT_PROTOCOL_ERROR, "unexpected ECDH_INIT"));
        }
        let mut r = Reader::new(p);
        r.u8();
        let qc: [u8; 32] = r.string().and_then(|q| q.try_into().ok()).ok_or(fail)?;
        if r.remaining() != 0 {
            return Err(fail);
        }
        let mut secret = [0u8; 32];
        env.random(&mut secret);
        let qs = azos_crypto::x25519::x25519(&secret, &BASEPOINT);
        // A small-order public key gives an all-zero secret: refuse it.
        let shared = x25519_checked(&secret, &qc).ok_or(fail)?;
        azos_crypto::ct::secure_zero(&mut secret);

        let blob = kex::host_key_blob(&self.cfg.host_public);
        let h = kex::exchange_hash(
            &Exchange {
                client_version: &self.client_version,
                server_version: kex::VERSION,
                client_kexinit: &k.theirs,
                server_kexinit: &k.ours,
                host_key: &blob,
                client_public: &qc,
                server_public: &qs,
            },
            &shared,
        );
        let session_id = *self.session_id.get_or_insert(h);
        // The host key signs in the keystore. A host that cannot sign has no
        // identity to offer: the exchange ends here, before the keys are used.
        let Some(sig) = env.sign_host(&h) else { return Err((DISCONNECT_KEY_EXCHANGE_FAILED, "host key unavailable")) };
        let (c2s, s2c) = kex::derive_keys(&shared, &h, &session_id);

        let mut w = Writer::new(MSG_KEX_ECDH_REPLY);
        w.string(&blob).string(&qs).string(&kex::signature_blob(&sig));
        self.send_now(&w.buf);
        self.send_now(&[MSG_NEWKEYS]);
        // From the next packet on, we send under the new key.
        self.tx.set_key(s2c);
        if self.strict {
            self.tx.reset_seq();
        }
        self.kex.as_mut().unwrap().step = Step::WaitNewKeys(c2s);
        Ok(())
    }

    fn on_newkeys(&mut self) -> Result<(), Fail> {
        let Some(k) = self.kex.take() else { return Err((DISCONNECT_PROTOCOL_ERROR, "unexpected NEWKEYS")) };
        let Step::WaitNewKeys(c2s) = k.step else {
            return Err((DISCONNECT_PROTOCOL_ERROR, "unexpected NEWKEYS"));
        };
        self.rx.set_key(c2s);
        if self.strict {
            self.rx.reset_seq();
        }
        self.established = true;
        // The exchange is over: what was raised during it goes out now.
        for p in core::mem::take(&mut self.held) {
            self.send_now(&p);
        }
        Ok(())
    }

    // ── The authentication service ──────────────────────────────────────────

    fn on_service_request(&mut self, p: &[u8]) -> Result<(), Fail> {
        let mut r = Reader::new(p);
        r.u8();
        let name = r.string().ok_or((DISCONNECT_PROTOCOL_ERROR, "malformed service request"))?;
        if name != b"ssh-userauth" {
            return Err((DISCONNECT_SERVICE_NOT_AVAILABLE, "service not available"));
        }
        self.service_ok = true;
        let mut w = Writer::new(MSG_SERVICE_ACCEPT);
        w.string(name);
        self.send(&w.buf);
        Ok(())
    }

    fn auth_failure(&mut self, partial: bool) {
        let mut w = Writer::new(MSG_USERAUTH_FAILURE);
        w.name_list(&["publickey"]).boolean(partial);
        self.send(&w.buf);
    }

    fn on_userauth<E: Env>(&mut self, env: &mut E, p: &[u8]) -> Result<(), Fail> {
        if !self.service_ok {
            return Err((DISCONNECT_PROTOCOL_ERROR, "authentication before service request"));
        }
        if self.authed {
            // RFC 4252 section 5.1: once logged in, further requests are ignored.
            return Ok(());
        }
        self.requests += 1;
        if self.requests > MAX_REQUESTS {
            return Err((DISCONNECT_NO_MORE_AUTH_METHODS, "too many authentication requests"));
        }
        let Some((user, service, method)) = auth::parse_request(p) else {
            return Err((DISCONNECT_PROTOCOL_ERROR, "malformed authentication request"));
        };
        let user = user.to_vec();
        let refuse = |s: &mut Self, env: &mut E, key: Option<[u8; 32]>, why: &'static str, counts: bool| -> Result<(), Fail> {
            env.decision(Decision { rule: Rule::Login, verdict: Verdict::Refuse, subject: user.clone(), key, why });
            if counts {
                s.failures += 1;
            }
            if s.failures >= MAX_FAILURES {
                return Err((DISCONNECT_NO_MORE_AUTH_METHODS, "too many authentication failures"));
            }
            s.auth_failure(false);
            Ok(())
        };
        if service != b"ssh-connection" {
            return refuse(self, env, None, "service is not ssh-connection", true);
        }
        match method {
            // The probe every client starts with: say which method works.
            Method::None => {
                self.auth_failure(false);
                Ok(())
            }
            Method::Other => refuse(self, env, None, "method not offered (public keys only)", true),
            Method::PublicKey(req) => {
                if req.alg != kex::HOSTKEY_ALG.as_bytes() {
                    return refuse(self, env, None, "key type not accepted (ssh-ed25519 only)", true);
                }
                let Some(key) = auth::key_of_blob(req.blob) else {
                    return refuse(self, env, None, "malformed public key", true);
                };
                let listed = self.cfg.authorized.iter().any(|a| a.key == key && a.user == user);
                if !listed {
                    // A query for a key not listed is not a failed signature:
                    // the client may have another key. A signed attempt is.
                    return refuse(self, env, Some(key), "key is not authorized", req.signed);
                }
                if !req.signed {
                    let mut w = Writer::new(MSG_USERAUTH_PK_OK);
                    w.string(req.alg).string(req.blob);
                    self.send(&w.buf);
                    return Ok(());
                }
                let sid = self.session_id.ok_or((DISCONNECT_PROTOCOL_ERROR, "no session id"))?;
                if !auth::signature_ok(&sid, &req, &key) {
                    return refuse(self, env, Some(key), "signature does not verify", true);
                }
                self.authed = true;
                self.user = user.clone();
                env.decision(Decision {
                    rule: Rule::Login,
                    verdict: Verdict::Admit,
                    subject: user.clone(),
                    key: Some(key),
                    why: "authorized key, signature verifies",
                });
                self.send(&[MSG_USERAUTH_SUCCESS]);
                self.events.push_back(Event::Authenticated { user, key });
                Ok(())
            }
        }
    }

    // ── The connection layer ────────────────────────────────────────────────

    fn on_global_request(&mut self, p: &[u8]) -> Result<(), Fail> {
        let mut r = Reader::new(p);
        r.u8();
        let bad = (DISCONNECT_PROTOCOL_ERROR, "malformed global request");
        r.string().ok_or(bad)?;
        let want_reply = r.boolean().ok_or(bad)?;
        // Port forwarding and keepalive pings alike: none is served.
        if want_reply {
            self.send(&[MSG_REQUEST_FAILURE]);
        }
        Ok(())
    }

    fn open_failure(&mut self, sender: u32, reason: u32, text: &str) {
        let mut w = Writer::new(MSG_CHANNEL_OPEN_FAILURE);
        w.u32(sender).u32(reason).string(text.as_bytes()).string(b"");
        self.send(&w.buf);
    }

    fn on_channel_open<E: Env>(&mut self, env: &mut E, p: &[u8]) -> Result<(), Fail> {
        let bad = (DISCONNECT_PROTOCOL_ERROR, "malformed channel open");
        let mut r = Reader::new(p);
        r.u8();
        let kind = r.string().ok_or(bad)?;
        let sender = r.u32().ok_or(bad)?;
        let window = r.u32().ok_or(bad)?;
        let max_packet = r.u32().ok_or(bad)?;
        let refuse = |s: &mut Self, env: &mut E, why: &'static str, reason: u32| {
            env.decision(Decision { rule: Rule::Session, verdict: Verdict::Refuse, subject: kind.to_vec(), key: None, why });
            s.open_failure(sender, reason, why);
        };
        if kind != b"session" {
            refuse(self, env, "channel type not offered (session only: no forwarding)", 3);
            return Ok(());
        }
        if self.chan.is_some() {
            refuse(self, env, "one session at a time", 4);
            return Ok(());
        }
        if max_packet == 0 {
            refuse(self, env, "peer's maximum packet size is zero", 2);
            return Ok(());
        }
        self.chan = Some(Chan {
            peer: sender,
            peer_window: window as u64,
            peer_max_packet: max_packet,
            local_window: LOCAL_WINDOW,
            returned: 0,
            sent_close: false,
            sent_eof: false,
        });
        let mut w = Writer::new(MSG_CHANNEL_OPEN_CONFIRMATION);
        w.u32(sender).u32(0).u32(LOCAL_WINDOW).u32(LOCAL_MAX_PACKET);
        self.send(&w.buf);
        Ok(())
    }

    /// The channel a message names (ours is always 0).
    fn chan_of(&mut self, r: &mut Reader) -> Result<&mut Chan, Fail> {
        let id = r.u32().ok_or((DISCONNECT_PROTOCOL_ERROR, "malformed channel message"))?;
        match &mut self.chan {
            Some(c) if id == 0 => Ok(c),
            _ => Err((DISCONNECT_PROTOCOL_ERROR, "message for a channel that is not open")),
        }
    }

    fn on_window_adjust(&mut self, p: &[u8]) -> Result<(), Fail> {
        let mut r = Reader::new(p);
        r.u8();
        let c = self.chan_of(&mut r)?;
        let n = r.u32().ok_or((DISCONNECT_PROTOCOL_ERROR, "malformed window adjust"))?;
        // RFC 4254 section 5.2: the window never exceeds 2^32 - 1.
        c.peer_window = (c.peer_window + n as u64).min(u32::MAX as u64);
        Ok(())
    }

    fn on_channel_data(&mut self, p: &[u8], extended: bool) -> Result<(), Fail> {
        let mut r = Reader::new(p);
        r.u8();
        let c = self.chan_of(&mut r)?;
        if extended {
            r.u32().ok_or((DISCONNECT_PROTOCOL_ERROR, "malformed extended data"))?;
        }
        let data = r.string().ok_or((DISCONNECT_PROTOCOL_ERROR, "malformed channel data"))?;
        if data.len() > LOCAL_MAX_PACKET as usize || data.len() as u32 > c.local_window {
            return Err((DISCONNECT_PROTOCOL_ERROR, "channel data over the window"));
        }
        c.local_window -= data.len() as u32;
        if extended {
            // A client has no stderr to send: drop the bytes, return the window.
            c.returned += data.len() as u32;
        } else if !data.is_empty() {
            self.events.push_back(Event::Data(data.to_vec()));
        }
        Ok(())
    }

    fn on_channel_eof(&mut self, p: &[u8]) -> Result<(), Fail> {
        let mut r = Reader::new(p);
        r.u8();
        self.chan_of(&mut r)?;
        self.events.push_back(Event::Eof);
        Ok(())
    }

    fn on_channel_close(&mut self, p: &[u8]) -> Result<(), Fail> {
        let mut r = Reader::new(p);
        r.u8();
        let c = self.chan_of(&mut r)?;
        let (peer, sent) = (c.peer, c.sent_close);
        if !sent {
            let mut w = Writer::new(MSG_CHANNEL_CLOSE);
            w.u32(peer);
            self.send(&w.buf);
        }
        self.chan = None;
        self.events.push_back(Event::Closed);
        Ok(())
    }

    fn on_channel_request<E: Env>(&mut self, env: &mut E, p: &[u8]) -> Result<(), Fail> {
        let bad = (DISCONNECT_PROTOCOL_ERROR, "malformed channel request");
        let mut r = Reader::new(p);
        r.u8();
        let peer = self.chan_of(&mut r)?.peer;
        let kind = r.string().ok_or(bad)?;
        let want_reply = r.boolean().ok_or(bad)?;
        let mut ok = true;
        match kind {
            b"pty-req" => {
                let term = r.string().ok_or(bad)?.to_vec();
                let cols = r.u32().ok_or(bad)?;
                let rows = r.u32().ok_or(bad)?;
                self.events.push_back(Event::Pty { term, cols, rows });
            }
            b"window-change" => {
                let cols = r.u32().ok_or(bad)?;
                let rows = r.u32().ok_or(bad)?;
                self.events.push_back(Event::Resize { cols, rows });
            }
            b"shell" => self.events.push_back(Event::Shell),
            b"exec" => {
                let cmd = r.string().ok_or(bad)?.to_vec();
                self.events.push_back(Event::Exec(cmd));
            }
            // Signals and the like have nothing to act on here; they are no
            // refusal and want no answer.
            b"signal" | b"eow@openssh.com" => {}
            // Environment variables are not passed on.
            b"env" => ok = false,
            _ => {
                ok = false;
                env.decision(Decision {
                    rule: Rule::Session,
                    verdict: Verdict::Refuse,
                    subject: kind.to_vec(),
                    key: None,
                    why: "channel request not offered (pty, shell, exec and window-change only)",
                });
            }
        }
        if want_reply {
            let mut w = Writer::new(if ok { MSG_CHANNEL_SUCCESS } else { MSG_CHANNEL_FAILURE });
            w.u32(peer);
            self.send(&w.buf);
        }
        Ok(())
    }
}
