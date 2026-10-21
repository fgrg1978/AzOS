// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The test client and the world around the server.
//!
//! The client is written from the RFCs: the exchange hash and the key
//! derivation below are built with `Vec` and `sha2`, not with the server's
//! `Writer` and `Sha256`, so an error that the server's code shares with
//! itself still shows.

use crate::auth::AuthKey;
use crate::packet::{Key, Rx, Tx};
use crate::server::{Config, Decision, Env, Server};
use crate::wire::*;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

pub fn host_seed() -> [u8; 32] {
    // RFC 8032 section 7.1, test 1.
    hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
}

pub fn user_seed() -> [u8; 32] {
    hex32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
}

pub fn other_seed() -> [u8; 32] {
    [7u8; 32]
}

pub fn hex32(s: &str) -> [u8; 32] {
    let v = hex(s);
    v.try_into().unwrap()
}

pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

pub fn pubkey(seed: &[u8; 32]) -> [u8; 32] {
    azos_crypto::ed25519::public_from_seed(seed)
}

/// A config that lets `user_seed()` in as `root`.
pub fn config() -> Config {
    Config::new(pubkey(&host_seed()), vec![AuthKey { user: b"root".to_vec(), key: pubkey(&user_seed()) }])
}

/// Standard base64, padding optional (an OpenSSH `.pub` file's key blob).
/// `None` for a character outside the alphabet or a length no encoder makes.
pub fn base64_decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut s = s;
    while let [rest @ .., b'='] = s {
        s = rest;
    }
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in s {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = acc << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Randomness from a counter, and the decisions kept for the test to read.
/// The host key signs here as the keystore does in the kernel: the Ed25519
/// signature of `host_seed()`, unless `no_host_key` says the keystore is gone.
#[derive(Default)]
pub struct TestEnv {
    pub ctr: u64,
    pub decisions: Vec<Decision>,
    pub no_host_key: bool,
}

impl Env for TestEnv {
    fn random(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(32) {
            self.ctr += 1;
            let h = Sha256::digest(self.ctr.to_be_bytes());
            chunk.copy_from_slice(&h[..chunk.len()]);
        }
    }

    fn decision(&mut self, d: Decision) {
        self.decisions.push(d);
    }

    fn sign_host(&mut self, msg: &[u8]) -> Option<[u8; 64]> {
        (!self.no_host_key).then(|| azos_crypto::ed25519::sign_message(&host_seed(), msg))
    }
}

// ── The independent hash and derivation ─────────────────────────────────────

fn put_string(v: &mut Vec<u8>, b: &[u8]) {
    v.extend_from_slice(&(b.len() as u32).to_be_bytes());
    v.extend_from_slice(b);
}

fn put_mpint(v: &mut Vec<u8>, k: &[u8; 32]) {
    let first = k.iter().position(|&b| b != 0).unwrap_or(32);
    let k = &k[first..];
    if k.first().is_some_and(|b| b & 0x80 != 0) {
        v.extend_from_slice(&(k.len() as u32 + 1).to_be_bytes());
        v.push(0);
    } else {
        v.extend_from_slice(&(k.len() as u32).to_be_bytes());
    }
    v.extend_from_slice(k);
}

pub struct HashInputs<'a> {
    pub v_c: &'a [u8],
    pub v_s: &'a [u8],
    pub i_c: &'a [u8],
    pub i_s: &'a [u8],
    pub k_s: &'a [u8],
    pub q_c: &'a [u8],
    pub q_s: &'a [u8],
    pub k: &'a [u8; 32],
}

/// RFC 8731 section 3.1 / RFC 5656 section 4: H = HASH(V_C || V_S || I_C || I_S
/// || K_S || Q_C || Q_S || K), each a `string`, K an `mpint`.
pub fn exchange_hash(x: &HashInputs) -> [u8; 32] {
    let mut v = Vec::new();
    for s in [x.v_c, x.v_s, x.i_c, x.i_s, x.k_s, x.q_c, x.q_s] {
        put_string(&mut v, s);
    }
    put_mpint(&mut v, x.k);
    Sha256::digest(&v).into()
}

/// RFC 4253 section 7.2: the `len` key bytes of `letter`.
pub fn derive(k: &[u8; 32], h: &[u8; 32], letter: u8, sid: &[u8; 32], len: usize) -> Vec<u8> {
    let mut km = Vec::new();
    put_mpint(&mut km, k);
    let mut d = km.clone();
    d.extend_from_slice(h);
    d.push(letter);
    d.extend_from_slice(sid);
    let mut key: Vec<u8> = Sha256::digest(&d).to_vec();
    while key.len() < len {
        let mut d = km.clone();
        d.extend_from_slice(h);
        d.extend_from_slice(&key);
        key.extend_from_slice(&Sha256::digest(&d));
    }
    key.truncate(len);
    key
}

// ── The client ──────────────────────────────────────────────────────────────

pub const CLIENT_VERSION: &[u8] = b"SSH-2.0-testclient_1";

pub struct Kex {
    pub ours: Vec<u8>,
    pub theirs: Option<Vec<u8>>,
    pub eph: [u8; 32],
    pub q_c: [u8; 32],
    pub keys: Option<(Key, Key)>,
}

pub struct Client {
    pub tx: Tx,
    pub rx: Rx,
    /// Bytes for the server.
    pub out: Vec<u8>,
    ver_buf: Vec<u8>,
    pub server_version: Option<Vec<u8>>,
    pub session_id: Option<[u8; 32]>,
    pub kex: Option<Kex>,
    pub strict: bool,
    pub host_key_seen: Option<[u8; 32]>,
    /// What came in, after the key exchange's own messages.
    pub got: VecDeque<Vec<u8>>,
    pub disconnected: Option<u32>,
    eph_ctr: u8,
    /// The sequence number of the next packet the client sends.
    pub seq_out: u32,
}

pub fn client_kexinit(cookie: u8, strict: bool, kex: &[&str], host: &[&str], enc: &[&str], comp: &[&str]) -> Vec<u8> {
    let mut w = Writer::new(MSG_KEXINIT);
    w.raw(&[cookie; 16]);
    let mut k: Vec<&str> = kex.to_vec();
    k.push("ext-info-c");
    if strict {
        k.push("kex-strict-c-v00@openssh.com");
    }
    w.name_list(&k);
    w.name_list(host);
    w.name_list(enc);
    w.name_list(enc);
    w.name_list(&["hmac-sha2-256"]);
    w.name_list(&["hmac-sha2-256"]);
    w.name_list(comp);
    w.name_list(comp);
    w.name_list(&[]);
    w.name_list(&[]);
    w.boolean(false);
    w.u32(0);
    w.buf
}

pub fn good_kexinit(strict: bool) -> Vec<u8> {
    client_kexinit(
        0xc1,
        strict,
        &["curve25519-sha256"],
        &["ssh-ed25519"],
        &["chacha20-poly1305@openssh.com"],
        &["none"],
    )
}

impl Client {
    /// A client that has sent its version line and its KEXINIT.
    pub fn new(strict: bool) -> Self {
        let mut c = Self::silent(strict);
        c.out.extend_from_slice(CLIENT_VERSION);
        c.out.extend_from_slice(b"\r\n");
        let ours = good_kexinit(strict);
        c.send(&ours);
        c.kex = Some(Kex { ours, theirs: None, eph: c.next_eph(), q_c: [0; 32], keys: None });
        c.kex.as_mut().unwrap().q_c = azos_crypto::x25519::x25519(&c.kex.as_ref().unwrap().eph, &azos_crypto::x25519::BASEPOINT);
        c
    }

    /// A client that has sent nothing.
    pub fn silent(strict: bool) -> Self {
        Self {
            tx: Tx::new(),
            rx: Rx::new(),
            out: Vec::new(),
            ver_buf: Vec::new(),
            server_version: None,
            session_id: None,
            kex: None,
            strict,
            host_key_seen: None,
            got: VecDeque::new(),
            disconnected: None,
            eph_ctr: 0,
            seq_out: 0,
        }
    }

    fn next_eph(&mut self) -> [u8; 32] {
        self.eph_ctr += 1;
        [0x40 + self.eph_ctr; 32]
    }

    pub fn send(&mut self, payload: &[u8]) {
        self.tx.send(payload, &mut self.out).unwrap();
        self.seq_out += 1;
    }

    /// Start a new key exchange (RFC 4253 section 9).
    pub fn rekey(&mut self) {
        let ours = good_kexinit(self.strict);
        self.send(&ours);
        let eph = self.next_eph();
        let q_c = azos_crypto::x25519::x25519(&eph, &azos_crypto::x25519::BASEPOINT);
        self.kex = Some(Kex { ours, theirs: None, eph, q_c, keys: None });
    }

    /// Bytes from the server.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.server_version.is_none() {
            self.ver_buf.extend_from_slice(bytes);
            let Some(nl) = self.ver_buf.iter().position(|&c| c == b'\n') else { return };
            let line = self.ver_buf[..nl].strip_suffix(b"\r").unwrap_or(&self.ver_buf[..nl]).to_vec();
            let rest = self.ver_buf[nl + 1..].to_vec();
            self.server_version = Some(line);
            self.rx.push(&rest);
        } else {
            self.rx.push(bytes);
        }
        loop {
            let p = match self.rx.next() {
                Ok(Some(p)) => p,
                Ok(None) => return,
                Err(e) => panic!("client: bad packet from the server: {e:?}"),
            };
            self.on_packet(p);
        }
    }

    fn on_packet(&mut self, p: Vec<u8>) {
        match p[0] {
            MSG_KEXINIT => {
                // A client that never sent a KEXINIT (a test of the server's
                // refusals) has nothing to answer with.
                let Some(k) = self.kex.as_mut() else { return };
                k.theirs = Some(p);
                let mut w = Writer::new(MSG_KEX_ECDH_INIT);
                w.string(&k.q_c);
                let init = w.buf;
                self.send(&init);
            }
            MSG_KEX_ECDH_REPLY => {
                let mut r = Reader::new(&p);
                r.u8();
                let k_s = r.string().unwrap().to_vec();
                let q_s: [u8; 32] = r.string().unwrap().try_into().unwrap();
                let sig_blob = r.string().unwrap().to_vec();
                let kx = self.kex.as_mut().unwrap();
                let k = azos_crypto::x25519::x25519(&kx.eph, &q_s);
                let h = exchange_hash(&HashInputs {
                    v_c: CLIENT_VERSION,
                    v_s: self.server_version.as_ref().unwrap(),
                    i_c: &kx.ours,
                    i_s: kx.theirs.as_ref().unwrap(),
                    k_s: &k_s,
                    q_c: &kx.q_c,
                    q_s: &q_s,
                    k: &k,
                });
                // The host key blob: string "ssh-ed25519", string key.
                let mut kr = Reader::new(&k_s);
                assert_eq!(kr.string().unwrap(), b"ssh-ed25519");
                let pk: [u8; 32] = kr.string().unwrap().try_into().unwrap();
                let mut sr = Reader::new(&sig_blob);
                assert_eq!(sr.string().unwrap(), b"ssh-ed25519");
                let sig: [u8; 64] = sr.string().unwrap().try_into().unwrap();
                assert!(
                    azos_crypto::ed25519::sig_verify_message(&pk, &sig, &h),
                    "the server's signature over the exchange hash does not verify"
                );
                self.host_key_seen = Some(pk);
                let sid = *self.session_id.get_or_insert(h);
                let c2s: [u8; 64] = derive(&k, &h, b'C', &sid, 64).try_into().unwrap();
                let s2c: [u8; 64] = derive(&k, &h, b'D', &sid, 64).try_into().unwrap();
                self.kex.as_mut().unwrap().keys = Some((Key::new(&c2s), Key::new(&s2c)));
            }
            MSG_NEWKEYS => {
                let kx = self.kex.take().expect("NEWKEYS with no exchange");
                let (c2s, s2c) = kx.keys.expect("NEWKEYS before the reply");
                // Our NEWKEYS goes out under the old keys, then the new ones.
                self.send(&[MSG_NEWKEYS]);
                self.tx.set_key(c2s);
                self.rx.set_key(s2c);
                if self.strict {
                    self.tx.reset_seq();
                    self.rx.reset_seq();
                    self.seq_out = 0;
                }
            }
            MSG_DISCONNECT => {
                let mut r = Reader::new(&p);
                r.u8();
                self.disconnected = Some(r.u32().unwrap());
            }
            MSG_IGNORE | MSG_DEBUG => {}
            _ => self.got.push_back(p),
        }
    }

    /// The next payload that is not the key exchange's.
    pub fn take(&mut self) -> Vec<u8> {
        self.got.pop_front().expect("the server sent nothing")
    }

    pub fn take_type(&mut self, t: u8) -> Vec<u8> {
        let p = self.take();
        assert_eq!(p[0], t, "wanted message {t}, got {} ({:02x?})", p[0], p);
        p
    }

    // ── Upper-layer requests ────────────────────────────────────────────────

    pub fn service_request(&mut self) {
        let mut w = Writer::new(MSG_SERVICE_REQUEST);
        w.string(b"ssh-userauth");
        self.send(&w.buf);
    }

    pub fn auth_none(&mut self, user: &[u8]) {
        let mut w = Writer::new(MSG_USERAUTH_REQUEST);
        w.string(user).string(b"ssh-connection").string(b"none");
        self.send(&w.buf);
    }

    pub fn auth_password(&mut self, user: &[u8]) {
        let mut w = Writer::new(MSG_USERAUTH_REQUEST);
        w.string(user).string(b"ssh-connection").string(b"password").boolean(false).string(b"hunter2");
        self.send(&w.buf);
    }

    /// A public-key request; signed with `seed` when `sign`.
    pub fn auth_publickey(&mut self, user: &[u8], seed: &[u8; 32], sign: bool) {
        self.auth_publickey_for(user, b"ssh-connection", seed, sign, &self.session_id.unwrap())
    }

    pub fn auth_publickey_for(&mut self, user: &[u8], service: &[u8], seed: &[u8; 32], sign: bool, sid: &[u8; 32]) {
        let pk = pubkey(seed);
        let mut blob = Writer::default();
        blob.string(b"ssh-ed25519").string(&pk);
        let mut w = Writer::new(MSG_USERAUTH_REQUEST);
        w.string(user).string(service).string(b"publickey").boolean(sign).string(b"ssh-ed25519").string(&blob.buf);
        if sign {
            // RFC 4252 section 7.
            let mut m = Writer::default();
            m.string(sid).u8(MSG_USERAUTH_REQUEST).string(user).string(service).string(b"publickey").boolean(true);
            m.string(b"ssh-ed25519").string(&blob.buf);
            let sig = azos_crypto::ed25519::sign_message(seed, &m.buf);
            let mut sb = Writer::default();
            sb.string(b"ssh-ed25519").string(&sig);
            w.string(&sb.buf);
        }
        self.send(&w.buf);
    }

    pub fn open_session(&mut self, id: u32, window: u32, max_packet: u32) {
        let mut w = Writer::new(MSG_CHANNEL_OPEN);
        w.string(b"session").u32(id).u32(window).u32(max_packet);
        self.send(&w.buf);
    }

    pub fn channel_request(&mut self, chan: u32, kind: &[u8], want_reply: bool, rest: &[u8]) {
        let mut w = Writer::new(MSG_CHANNEL_REQUEST);
        w.u32(chan).string(kind).boolean(want_reply).raw(rest);
        self.send(&w.buf);
    }

    pub fn pty_req(&mut self, chan: u32, cols: u32, rows: u32) {
        let mut r = Writer::default();
        r.string(b"xterm").u32(cols).u32(rows).u32(0).u32(0).string(b"");
        self.channel_request(chan, b"pty-req", true, &r.buf);
    }

    pub fn exec(&mut self, chan: u32, cmd: &[u8]) {
        let mut r = Writer::default();
        r.string(cmd);
        self.channel_request(chan, b"exec", true, &r.buf);
    }

    pub fn shell(&mut self, chan: u32) {
        self.channel_request(chan, b"shell", true, &[]);
    }

    pub fn data(&mut self, chan: u32, d: &[u8]) {
        let mut w = Writer::new(MSG_CHANNEL_DATA);
        w.u32(chan).string(d);
        self.send(&w.buf);
    }
}

/// Move bytes both ways until neither side has any.
pub fn exchange(cl: &mut Client, srv: &mut Server, env: &mut TestEnv) {
    for _ in 0..64 {
        let mut moved = false;
        if !cl.out.is_empty() {
            let b = std::mem::take(&mut cl.out);
            srv.feed(env, &b);
            moved = true;
        }
        if !srv.pending().is_empty() {
            let b = srv.pending().to_vec();
            srv.advance(b.len());
            cl.feed(&b);
            moved = true;
        }
        if !moved {
            return;
        }
    }
    panic!("the exchange did not settle");
}

/// A server and a client, through the key exchange.
pub fn connected<'c>(cfg: &'c Config, env: &mut TestEnv, strict: bool) -> (Server<'c>, Client) {
    let mut srv = Server::new(cfg, env);
    let mut cl = Client::new(strict);
    exchange(&mut cl, &mut srv, env);
    assert!(cl.session_id.is_some(), "no session id after the exchange");
    assert!(cl.kex.is_none(), "the exchange did not finish");
    (srv, cl)
}

/// ... and logged in with the authorized key.
pub fn logged_in<'c>(cfg: &'c Config, env: &mut TestEnv, strict: bool) -> (Server<'c>, Client) {
    let (mut srv, mut cl) = connected(cfg, env, strict);
    cl.service_request();
    exchange(&mut cl, &mut srv, env);
    cl.take_type(MSG_SERVICE_ACCEPT);
    cl.auth_none(b"root");
    exchange(&mut cl, &mut srv, env);
    cl.take_type(MSG_USERAUTH_FAILURE);
    cl.auth_publickey(b"root", &user_seed(), true);
    exchange(&mut cl, &mut srv, env);
    cl.take_type(MSG_USERAUTH_SUCCESS);
    (srv, cl)
}

/// ... with a session channel open (the server's channel is 0).
pub fn with_channel<'c>(cfg: &'c Config, env: &mut TestEnv, strict: bool) -> (Server<'c>, Client) {
    let (mut srv, mut cl) = logged_in(cfg, env, strict);
    cl.open_session(5, 1 << 20, 32768);
    exchange(&mut cl, &mut srv, env);
    let p = cl.take_type(MSG_CHANNEL_OPEN_CONFIRMATION);
    let mut r = Reader::new(&p);
    r.u8();
    assert_eq!(r.u32(), Some(5));
    assert_eq!(r.u32(), Some(0));
    (srv, cl)
}
