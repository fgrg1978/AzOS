// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Noise Protocol Framework (revision 34) handshakes over the in-tree
//! X25519, ChaCha20-Poly1305 and SHA-256:
//!
//! * `Noise_IK_25519_ChaChaPoly_SHA256` -- the initiator already knows the
//!   responder's static key (a paired peer reconnecting: 1 round trip, the
//!   initiator's identity is hidden from passive observers).
//! * `Noise_XX_25519_ChaChaPoly_SHA256` -- neither side knows the other
//!   (first contact: 1.5 round trips, both statics are sent encrypted).
//!
//! No allocation and no RNG: the caller hands in the ephemeral private key
//! with every `write_message` (from `entropy::fill`, or a fixed value in
//! tests), so a handshake is a pure function of its inputs. Messages are
//! written to and read from caller buffers. After the last message
//! [`HandshakeState::finish`] returns the two transport [`CipherState`]s and
//! the handshake hash (the channel-binding value both sides can sign).
//!
//! Every Diffie-Hellman result goes through `x25519_checked`, so a low-order
//! peer key aborts the handshake instead of pinning the key to a known
//! value. Any error poisons the handshake state; a failed handshake is
//! restarted from scratch, never resumed.

use crate::chachapoly::{self, KEY_LEN, TAG_LEN};
use crate::ct::secure_zero;
use crate::hkdf::hmac_sha256;
use crate::sha256::Sha256;
use crate::x25519::{x25519_checked, x25519_pubkey};

pub const DH_LEN: usize = 32;
pub const HASH_LEN: usize = 32;
/// Noise §3: no message, handshake or transport, exceeds 65535 bytes.
pub const MAX_MESSAGE: usize = 65535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The output buffer cannot hold the message / plaintext.
    BufferTooSmall,
    /// The message would exceed 65535 bytes.
    MessageTooLong,
    /// The received message is shorter than its pattern requires.
    Truncated,
    /// A DH produced the all-zero output (low-order peer key).
    BadDh,
    /// AEAD authentication failed.
    Decrypt,
    /// Not this side's turn, handshake finished, poisoned, or bad setup.
    WrongState,
    /// The 2^64 - 1 message limit of a CipherState was reached.
    NonceExhausted,
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pattern {
    Ik,
    Xx,
}

impl Pattern {
    pub const fn protocol_name(self) -> &'static [u8] {
        match self {
            Pattern::Ik => b"Noise_IK_25519_ChaChaPoly_SHA256",
            Pattern::Xx => b"Noise_XX_25519_ChaChaPoly_SHA256",
        }
    }
    fn messages(self) -> &'static [&'static [Tok]] {
        match self {
            Pattern::Ik => &IK,
            Pattern::Xx => &XX,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

#[derive(Clone, Copy)]
enum Tok {
    E,
    S,
    Ee,
    Es,
    Se,
    Ss,
}

// IK:  <- s ... -> e, es, s, ss   <- e, ee, se
const IK: [&[Tok]; 2] = [&[Tok::E, Tok::Es, Tok::S, Tok::Ss], &[Tok::E, Tok::Ee, Tok::Se]];
// XX:  -> e   <- e, ee, s, es   -> s, se
const XX: [&[Tok]; 3] =
    [&[Tok::E], &[Tok::E, Tok::Ee, Tok::S, Tok::Es], &[Tok::S, Tok::Se]];

/// Noise CipherState: a key and a 64-bit message counter.
pub struct CipherState {
    k: [u8; KEY_LEN],
    n: u64,
    keyed: bool,
}

impl CipherState {
    /// A state with no key (all zero bytes): what a slot holds before a
    /// handshake fills it, so a `static` of them costs no image bytes.
    pub const fn empty() -> Self {
        Self { k: [0; KEY_LEN], n: 0, keyed: false }
    }

    fn with_key(k: [u8; KEY_LEN]) -> Self {
        Self { k, n: 0, keyed: true }
    }

    pub fn has_key(&self) -> bool {
        self.keyed
    }

    /// Messages processed so far under this key.
    pub fn nonce(&self) -> u64 {
        self.n
    }

    /// Noise `SetNonce`: the next message uses counter `n`. For a transport
    /// whose datagrams arrive out of order or not at all, the receiver takes
    /// the counter from the packet (and refuses a repeat itself, with a replay
    /// window): the in-order stream of `decrypt` alone does not survive a loss.
    pub fn set_nonce(&mut self, n: u64) {
        self.n = n;
    }

    fn nonce_bytes(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[4..].copy_from_slice(&self.n.to_le_bytes());
        b
    }

    /// Encrypt `buf` in place under (`ad`, next nonce); returns the tag.
    pub fn encrypt(&mut self, ad: &[u8], buf: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        if !self.keyed {
            return Err(Error::WrongState);
        }
        if self.n == u64::MAX {
            return Err(Error::NonceExhausted);
        }
        if buf.len() > MAX_MESSAGE - TAG_LEN {
            return Err(Error::MessageTooLong);
        }
        let tag = chachapoly::seal(&self.k, &self.nonce_bytes(), ad, buf)
            .ok_or(Error::MessageTooLong)?;
        self.n += 1;
        Ok(tag)
    }

    /// Verify and decrypt `buf` in place. The counter advances only on
    /// success, so a forged or replayed packet does not desynchronise the
    /// stream; `buf` is left as received on failure.
    pub fn decrypt(&mut self, ad: &[u8], buf: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<()> {
        if !self.keyed {
            return Err(Error::WrongState);
        }
        if self.n == u64::MAX {
            return Err(Error::NonceExhausted);
        }
        if buf.len() > MAX_MESSAGE - TAG_LEN {
            return Err(Error::MessageTooLong);
        }
        if !chachapoly::open(&self.k, &self.nonce_bytes(), ad, buf, tag) {
            return Err(Error::Decrypt);
        }
        self.n += 1;
        Ok(())
    }

    /// Noise REKEY: `k = first 32 bytes of ENCRYPT(k, 2^64 - 1, "", zeros)`.
    pub fn rekey(&mut self) {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&u64::MAX.to_le_bytes());
        let mut block = [0u8; KEY_LEN];
        chachapoly::chacha20_xor(&self.k, 1, &nonce, &mut block);
        secure_zero(&mut self.k);
        self.k = block;
        secure_zero(&mut block);
    }
}

impl Drop for CipherState {
    fn drop(&mut self) {
        secure_zero(&mut self.k);
    }
}

/// Noise HKDF with two outputs (§4.3): HMAC extract then 0x01 / 0x02 steps.
fn hkdf2(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut temp = hmac_sha256(ck, &[ikm]);
    let o1 = hmac_sha256(&temp, &[&[1u8]]);
    let o2 = hmac_sha256(&temp, &[&o1, &[2u8]]);
    secure_zero(&mut temp);
    (o1, o2)
}

struct Symmetric {
    cs: CipherState,
    ck: [u8; 32],
    h: [u8; 32],
}

impl Symmetric {
    fn new(name: &[u8]) -> Self {
        let mut h = [0u8; 32];
        if name.len() <= HASH_LEN {
            h[..name.len()].copy_from_slice(name);
        } else {
            let mut s = Sha256::new();
            s.update(name);
            h = s.finalize();
        }
        Self { cs: CipherState::empty(), ck: h, h }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut s = Sha256::new();
        s.update(&self.h);
        s.update(data);
        self.h = s.finalize();
    }

    fn mix_key(&mut self, ikm: &[u8; 32]) {
        let (ck, mut tk) = hkdf2(&self.ck, ikm);
        self.ck = ck;
        self.cs = CipherState::with_key(tk);
        secure_zero(&mut tk);
    }

    /// Append the (encrypted when keyed) `plain` to `out`, hash the result.
    fn encrypt_and_hash(&mut self, plain: &[u8], out: &mut [u8]) -> Result<usize> {
        let tag_len = if self.cs.has_key() { TAG_LEN } else { 0 };
        let n = plain.len();
        if out.len() < n + tag_len {
            return Err(Error::BufferTooSmall);
        }
        out[..n].copy_from_slice(plain);
        if tag_len != 0 {
            let tag = self.cs.encrypt(&self.h, &mut out[..n])?;
            out[n..n + TAG_LEN].copy_from_slice(&tag);
        }
        let total = n + tag_len;
        self.mix_hash(&out[..total]);
        Ok(total)
    }

    /// Inverse of `encrypt_and_hash`; returns the plaintext length.
    fn decrypt_and_hash(&mut self, input: &[u8], out: &mut [u8]) -> Result<usize> {
        let n;
        if self.cs.has_key() {
            if input.len() < TAG_LEN {
                return Err(Error::Truncated);
            }
            n = input.len() - TAG_LEN;
            if out.len() < n {
                return Err(Error::BufferTooSmall);
            }
            out[..n].copy_from_slice(&input[..n]);
            let mut tag = [0u8; TAG_LEN];
            tag.copy_from_slice(&input[n..]);
            self.cs.decrypt(&self.h, &mut out[..n], &tag)?;
        } else {
            n = input.len();
            if out.len() < n {
                return Err(Error::BufferTooSmall);
            }
            out[..n].copy_from_slice(input);
        }
        self.mix_hash(input);
        Ok(n)
    }
}

impl Drop for Symmetric {
    fn drop(&mut self) {
        secure_zero(&mut self.ck);
    }
}

/// The two transport directions and the values the handshake produced.
pub struct Transport {
    /// Encrypts what we send.
    pub send: CipherState,
    /// Decrypts what the peer sends.
    pub recv: CipherState,
    /// Handshake hash `h`: identical on both sides, unique to this session.
    pub hash: [u8; HASH_LEN],
    /// The peer's authenticated static public key.
    pub remote_static: [u8; DH_LEN],
    /// A secret both sides derive from the final chaining key (`ck`) under a
    /// label of its own, independent of the two transport keys: key material a
    /// protocol above the channel may use for its own MACs. Unlike `hash` it is
    /// not derivable from the wire. Private: [`Transport::take_exporter`] hands
    /// it over once, and a `Transport` dropped without that wipes it.
    exporter: [u8; HASH_LEN],
}

impl Transport {
    /// The exporter secret, moved out: the copy kept here is zeroed, so a second
    /// call returns all zeros.
    pub fn take_exporter(&mut self) -> [u8; HASH_LEN] {
        let e = self.exporter;
        secure_zero(&mut self.exporter);
        e
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        secure_zero(&mut self.exporter);
    }
}

pub struct HandshakeState {
    sym: Symmetric,
    pattern: Pattern,
    role: Role,
    s: [u8; DH_LEN],
    s_pub: [u8; DH_LEN],
    e: [u8; DH_LEN],
    rs: Option<[u8; DH_LEN]>,
    re: Option<[u8; DH_LEN]>,
    idx: usize,
    poisoned: bool,
}

impl HandshakeState {
    fn new(
        pattern: Pattern,
        role: Role,
        s: &[u8; DH_LEN],
        rs: Option<&[u8; DH_LEN]>,
        prologue: &[u8],
    ) -> Result<Self> {
        // IK needs the responder's static up front; XX must not have one.
        let rs_ok = match (pattern, role) {
            (Pattern::Ik, Role::Initiator) => rs.is_some(),
            _ => rs.is_none(),
        };
        if !rs_ok {
            return Err(Error::WrongState);
        }
        let s_pub = x25519_pubkey(s);
        let mut sym = Symmetric::new(pattern.protocol_name());
        sym.mix_hash(prologue);
        if pattern == Pattern::Ik {
            // Pre-message `<- s`: the responder's static, known to both.
            match role {
                Role::Initiator => sym.mix_hash(rs.ok_or(Error::WrongState)?),
                Role::Responder => sym.mix_hash(&s_pub),
            }
        }
        Ok(Self {
            sym,
            pattern,
            role,
            s: *s,
            s_pub,
            e: [0; DH_LEN],
            rs: rs.copied(),
            re: None,
            idx: 0,
            poisoned: false,
        })
    }

    /// Start as initiator. `rs` is the responder's static key for IK, `None`
    /// for XX.
    pub fn initiator(
        pattern: Pattern,
        s: &[u8; DH_LEN],
        rs: Option<&[u8; DH_LEN]>,
        prologue: &[u8],
    ) -> Result<Self> {
        Self::new(pattern, Role::Initiator, s, rs, prologue)
    }

    pub fn responder(pattern: Pattern, s: &[u8; DH_LEN], prologue: &[u8]) -> Result<Self> {
        Self::new(pattern, Role::Responder, s, None, prologue)
    }

    /// Our static public key.
    pub fn local_static(&self) -> &[u8; DH_LEN] {
        &self.s_pub
    }

    /// The peer's static key once the pattern has delivered it.
    pub fn remote_static(&self) -> Option<&[u8; DH_LEN]> {
        self.rs.as_ref()
    }

    /// Running transcript hash (both sides agree after every message).
    pub fn handshake_hash(&self) -> &[u8; HASH_LEN] {
        &self.sym.h
    }

    pub fn is_finished(&self) -> bool {
        !self.poisoned && self.idx == self.pattern.messages().len()
    }

    /// Whether the next message is ours to write.
    pub fn is_my_turn(&self) -> bool {
        !self.poisoned
            && self.idx < self.pattern.messages().len()
            && ((self.idx % 2 == 0) == (self.role == Role::Initiator))
    }

    fn dh(&self, tok: Tok) -> Result<[u8; 32]> {
        let init = self.role == Role::Initiator;
        // (our key, their key) per Noise §5.3: `es` is DH(initiator e,
        // responder s), `se` is DH(initiator s, responder e).
        let (k, p) = match (tok, init) {
            (Tok::Ee, _) => (&self.e, self.re),
            (Tok::Ss, _) => (&self.s, self.rs),
            (Tok::Es, true) => (&self.e, self.rs),
            (Tok::Es, false) => (&self.s, self.re),
            (Tok::Se, true) => (&self.s, self.re),
            (Tok::Se, false) => (&self.e, self.rs),
            _ => return Err(Error::WrongState),
        };
        let p = p.ok_or(Error::WrongState)?;
        x25519_checked(k, &p).ok_or(Error::BadDh)
    }

    fn mix_dh(&mut self, tok: Tok) -> Result<()> {
        let mut shared = self.dh(tok)?;
        self.sym.mix_key(&shared);
        secure_zero(&mut shared);
        Ok(())
    }

    /// Write the next handshake message into `out` and return its length.
    /// `eph` is a fresh ephemeral private key (every message of both
    /// patterns starts with `e`); never reuse one across handshakes.
    pub fn write_message(&mut self, eph: &[u8; DH_LEN], payload: &[u8], out: &mut [u8]) -> Result<usize> {
        if !self.is_my_turn() {
            return Err(Error::WrongState);
        }
        let r = self.write_inner(eph, payload, out);
        match r {
            Ok(n) => {
                self.idx += 1;
                Ok(n)
            }
            Err(e) => {
                self.poisoned = true;
                Err(e)
            }
        }
    }

    fn write_inner(&mut self, eph: &[u8; DH_LEN], payload: &[u8], out: &mut [u8]) -> Result<usize> {
        let out = if out.len() > MAX_MESSAGE { &mut out[..MAX_MESSAGE] } else { out };
        let mut off = 0usize;
        for &tok in self.pattern.messages()[self.idx] {
            match tok {
                Tok::E => {
                    if out.len() < off + DH_LEN {
                        return Err(Error::BufferTooSmall);
                    }
                    self.e = *eph;
                    let e_pub = x25519_pubkey(eph);
                    out[off..off + DH_LEN].copy_from_slice(&e_pub);
                    self.sym.mix_hash(&e_pub);
                    off += DH_LEN;
                }
                Tok::S => {
                    let s_pub = self.s_pub;
                    off += self.sym.encrypt_and_hash(&s_pub, &mut out[off..])?;
                }
                dh => self.mix_dh(dh)?,
            }
        }
        off += self.sym.encrypt_and_hash(payload, &mut out[off..])?;
        Ok(off)
    }

    /// Process the peer's next handshake message; the decrypted payload is
    /// written to `payload_out` and its length returned.
    pub fn read_message(&mut self, msg: &[u8], payload_out: &mut [u8]) -> Result<usize> {
        // Reading is the peer's turn: not ours, not finished, not poisoned.
        if self.poisoned || self.idx >= self.pattern.messages().len() || self.is_my_turn() {
            return Err(Error::WrongState);
        }
        if msg.len() > MAX_MESSAGE {
            self.poisoned = true;
            return Err(Error::MessageTooLong);
        }
        let r = self.read_inner(msg, payload_out);
        match r {
            Ok(n) => {
                self.idx += 1;
                Ok(n)
            }
            Err(e) => {
                self.poisoned = true;
                Err(e)
            }
        }
    }

    fn read_inner(&mut self, msg: &[u8], payload_out: &mut [u8]) -> Result<usize> {
        let mut off = 0usize;
        for &tok in self.pattern.messages()[self.idx] {
            match tok {
                Tok::E => {
                    if msg.len() < off + DH_LEN {
                        return Err(Error::Truncated);
                    }
                    let mut re = [0u8; DH_LEN];
                    re.copy_from_slice(&msg[off..off + DH_LEN]);
                    self.sym.mix_hash(&re);
                    self.re = Some(re);
                    off += DH_LEN;
                }
                Tok::S => {
                    let len = DH_LEN + if self.sym.cs.has_key() { TAG_LEN } else { 0 };
                    if msg.len() < off + len {
                        return Err(Error::Truncated);
                    }
                    let mut rs = [0u8; DH_LEN];
                    self.sym.decrypt_and_hash(&msg[off..off + len], &mut rs)?;
                    self.rs = Some(rs);
                    off += len;
                }
                dh => self.mix_dh(dh)?,
            }
        }
        self.sym.decrypt_and_hash(&msg[off..], payload_out)
    }

    /// Split into the two transport ciphers once the pattern is complete.
    pub fn finish(self) -> Result<Transport> {
        if !self.is_finished() {
            return Err(Error::WrongState);
        }
        let rs = self.rs.ok_or(Error::WrongState)?;
        let (mut k1, mut k2) = hkdf2(&self.sym.ck, &[]);
        let (c1, c2) = (CipherState::with_key(k1), CipherState::with_key(k2));
        secure_zero(&mut k1);
        secure_zero(&mut k2);
        let (exporter, mut spare) = hkdf2(&self.sym.ck, b"azos noise exporter v1");
        secure_zero(&mut spare);
        let (send, recv) = match self.role {
            Role::Initiator => (c1, c2),
            Role::Responder => (c2, c1),
        };
        Ok(Transport { send, recv, hash: self.sym.h, remote_static: rs, exporter })
    }
}

impl Drop for HandshakeState {
    fn drop(&mut self) {
        secure_zero(&mut self.s);
        secure_zero(&mut self.e);
    }
}
