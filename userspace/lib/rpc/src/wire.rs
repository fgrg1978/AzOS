// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The transport format: the IDL wire format in frames.
//!
//! A message is the [`MsgDesc`] an IDL stub would send, **as it is**: word 0 is
//! the header (`id << 32 | level << 16 | op`), then the arguments; each
//! capability entry is the `CapDesc` of the descriptor. Nothing is translated
//! on the way across except what a clock or a table forces:
//!
//! * a **deadline** is not an absolute time (the nodes' clocks differ): the
//!   frame carries the **time remaining** and the **clock class**
//!   ([`Header::clock`], a `ClockId`; only MONO is served), and the receiver
//!   anchors it on its own clock;
//! * a capability entry's **`expiry_ns`** crosses the same way (remaining
//!   nanoseconds, 0 = none), and its **`handle`** is the sender's, kept as it
//!   is: it names the entry, it opens nothing on the far side;
//! * a **MemObj** entry is followed, in the message, by the bytes of the
//!   object: its pages cross and are re-minted as a new object on the other
//!   side, and the sender's object is consumed. Nothing else crosses: the
//!   engine refuses an entry that is not a MemObj.
//!
//! Every frame but the two that open a session is **sealed**: the header is
//! sent as it is and authenticated (it is the associated data), the fragment
//! of the body after it is encrypted with the session's Noise `CipherState`
//! and ends in the 16-byte tag. The header's `ctr` is the packet counter (the
//! Noise nonce): datagrams are lost, repeated and reordered, so the receiver
//! takes the counter from the packet and refuses a repeat with a replay
//! window ([`crate::chan`]). A [`Kind::Hello`] and a [`Kind::HelloAck`] carry the
//! two messages of the Noise IK handshake instead, in one frame each.
//!
//! ```text
//! frame  = header (48 bytes) + a fragment of the message body + tag (16)
//! body   = n_words u8, n_caps u8, reserved u16 (0)
//!          words      n_words * u64
//!          caps       n_caps  * 16 bytes (CapDesc: handle u32, mode u8, pad u8, rights u16, expiry u64)
//!          data       for each cap, in order: len u32, len bytes
//! ```
//!
//! All integers are little-endian. A message larger than a frame is cut into
//! fragments of [`FRAG_BODY`] bytes (every one but the last full), each sealed
//! on its own, and put together by [`Asm`] after they are opened; one lost
//! fragment loses the message, and the sender's retransmission policy (by the
//! op's delivery attribute) decides what that means.

use azos_abi::ipc_msg::{CapDesc, MsgDesc, MSG_CAPS_MAX, MSG_VERSION, MSG_WORDS_MAX};
use azos_crypto::ct::ct_eq;
use azos_crypto::hkdf::hmac_sha256;

/// The first two bytes of a frame ("RZ").
pub const MAGIC: u16 = 0x5A52;
/// The format version.
pub const VERSION: u8 = 2;
/// The largest frame, header included: what a UDP datagram carries in one
/// Ethernet frame with room to spare.
pub const FRAME_MAX: usize = 1200;
/// Bytes of the frame header.
pub const HEADER_BYTES: usize = 48;
/// Bytes of the tag that ends a sealed fragment (the ChaCha20-Poly1305 tag).
pub const TAG_BYTES: usize = 16;
/// Bytes of message body in a full fragment.
pub const FRAG_BODY: usize = FRAME_MAX - HEADER_BYTES - TAG_BYTES;
/// The largest body of a Hello or a HelloAck (one Noise IK message).
pub const HELLO_MAX: usize = 160;
/// The largest message body the engine puts together or sends: a descriptor
/// and 16 KiB of MemObj.
pub const MSG_CAP: usize = 16 * 1024 + 1024;
/// Fragments of the largest message.
pub const FRAGS_MAX: usize = MSG_CAP.div_ceil(FRAG_BODY);
const _: () = assert!(FRAGS_MAX <= 32, "Asm tracks fragments in a u32");

/// What a frame is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Opens a session: the first message of the Noise IK handshake (the
    /// dialing node's static key, encrypted, in it) and, as its payload, the
    /// interface ids the node will serve the peer's class.
    Hello = 1,
    /// Accepts it: the second message, whose payload is the session id and
    /// the interface ids the answering node will serve.
    HelloAck = 2,
    /// A call.
    Req = 3,
    /// Its answer.
    Rep = 4,
    /// Liveness probe.
    Ping = 5,
    /// Its answer.
    Pong = 6,
    /// The sender ends the session: the receiver breaks it.
    Bye = 7,
    /// The sender withdrew its authority over one interface (its export
    /// endpoint is gone or revoked): the receiver revokes what it holds that
    /// descends from it and answers [`Kind::RevokeAck`]. `seq` is the notice's
    /// number; the body is the interface id (u32).
    Revoke = 8,
    /// The receiver ran the revocation of notice `seq`: the body is the
    /// interface id (u32). From the instant the sender hears this, no effect
    /// of the withdrawn authority happens on the receiver.
    RevokeAck = 9,
}

impl Kind {
    fn from_u8(b: u8) -> Option<Kind> {
        Some(match b {
            1 => Kind::Hello,
            2 => Kind::HelloAck,
            3 => Kind::Req,
            4 => Kind::Rep,
            5 => Kind::Ping,
            6 => Kind::Pong,
            7 => Kind::Bye,
            8 => Kind::Revoke,
            9 => Kind::RevokeAck,
            _ => return None,
        })
    }
}

/// A frame header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    /// The session (0 in a [`Kind::Hello`]).
    pub session: u32,
    /// A call's number (a [`Kind::Rep`] repeats its request's); in a Hello,
    /// the dialer's nonce; in a Ping, the probe's number.
    pub seq: u64,
    /// Nanoseconds the caller has left for a request (0 = no deadline).
    pub remaining_ns: u64,
    /// The sender's node id.
    pub node: u32,
    /// The sender's boot epoch: a new one under the same node id is a
    /// restart, and the sessions it had are gone.
    pub epoch: u32,
    /// The clock class `remaining_ns` is on (`ClockId` raw value; 0 = MONO).
    pub clock: u32,
    /// This fragment's index.
    pub frag_idx: u16,
    /// Fragments of the message (at least 1).
    pub frag_cnt: u16,
    /// The packet counter of a sealed frame: the Noise nonce, one per frame
    /// and direction, never repeated under a session's keys. 0 in a Hello.
    pub ctr: u64,
}

impl Header {
    /// A single-fragment header of `kind` for `session` from `node`.
    pub const fn new(kind: Kind, session: u32, seq: u64, node: u32, epoch: u32) -> Header {
        Header { kind, session, seq, remaining_ns: 0, node, epoch, clock: 0, frag_idx: 0, frag_cnt: 1, ctr: 0 }
    }
}

/// Write `h` at the start of `out`.
pub fn put_header(h: &Header, out: &mut [u8]) {
    out[0..2].copy_from_slice(&MAGIC.to_le_bytes());
    out[2] = VERSION;
    out[3] = h.kind as u8;
    out[4..8].copy_from_slice(&h.session.to_le_bytes());
    out[8..16].copy_from_slice(&h.seq.to_le_bytes());
    out[16..24].copy_from_slice(&h.remaining_ns.to_le_bytes());
    out[24..28].copy_from_slice(&h.node.to_le_bytes());
    out[28..32].copy_from_slice(&h.epoch.to_le_bytes());
    out[32..36].copy_from_slice(&h.clock.to_le_bytes());
    out[36..38].copy_from_slice(&h.frag_idx.to_le_bytes());
    out[38..40].copy_from_slice(&h.frag_cnt.to_le_bytes());
    out[40..48].copy_from_slice(&h.ctr.to_le_bytes());
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

/// Does a frame of `kind` carry a handshake message (not sealed)?
pub const fn is_hello(kind: Kind) -> bool {
    matches!(kind, Kind::Hello | Kind::HelloAck)
}

/// Read a frame: its header and what follows it, the sealed fragment (or, for
/// a Hello and a HelloAck, the Noise message). `None` for anything that is
/// not a frame of this format (magic, version, kind, a handshake frame that
/// is fragmented or longer than [`HELLO_MAX`], a sealed fragment without room
/// for its tag, a fragment index outside its count, a fragment longer than
/// [`FRAG_BODY`], a non-final fragment shorter than it, a fragment that would
/// end past [`MSG_CAP`]): dropped, never guessed at.
pub fn get_header(frame: &[u8]) -> Option<(Header, &[u8])> {
    if frame.len() < HEADER_BYTES || frame.len() > FRAME_MAX {
        return None;
    }
    if u16_at(frame, 0) != MAGIC || frame[2] != VERSION {
        return None;
    }
    let h = Header {
        kind: Kind::from_u8(frame[3])?,
        session: u32_at(frame, 4),
        seq: u64_at(frame, 8),
        remaining_ns: u64_at(frame, 16),
        node: u32_at(frame, 24),
        epoch: u32_at(frame, 28),
        clock: u32_at(frame, 32),
        frag_idx: u16_at(frame, 36),
        frag_cnt: u16_at(frame, 38),
        ctr: u64_at(frame, 40),
    };
    let rest = &frame[HEADER_BYTES..];
    if h.frag_cnt == 0 || h.frag_cnt as usize > FRAGS_MAX || h.frag_idx >= h.frag_cnt {
        return None;
    }
    if is_hello(h.kind) {
        return (h.frag_cnt == 1 && rest.len() <= HELLO_MAX).then_some((h, rest));
    }
    let Some(plain) = rest.len().checked_sub(TAG_BYTES) else { return None };
    if h.frag_idx + 1 < h.frag_cnt && plain != FRAG_BODY {
        return None;
    }
    // The fragment lands inside a message of at most MSG_CAP bytes: the last
    // fragment of FRAGS_MAX can carry fewer bytes than a full one, and a frame
    // that says otherwise is not from a sender that follows the format.
    if h.frag_idx as usize * FRAG_BODY + plain > MSG_CAP {
        return None;
    }
    Some((h, rest))
}

/// Fragments a body of `len` bytes takes (an empty body is one empty fragment).
pub const fn frags_for(len: usize) -> usize {
    if len == 0 { 1 } else { len.div_ceil(FRAG_BODY) }
}

// ── the message body ────────────────────────────────────────────────────

/// Append the descriptor part of `d` (counts, words, capability entries, in
/// the form on the wire) to `out` at `*at`. `None` when it does not fit.
pub fn put_desc(d: &MsgDesc, out: &mut [u8], at: &mut usize) -> Option<()> {
    let (nw, nc) = (d.n_words as usize, d.n_caps as usize);
    if nw > MSG_WORDS_MAX || nc > MSG_CAPS_MAX {
        return None;
    }
    let need = 4 + nw * 8 + nc * 16;
    let o = out.get_mut(*at..*at + need)?;
    o[0] = d.n_words;
    o[1] = d.n_caps;
    o[2] = 0;
    o[3] = 0;
    let mut p = 4;
    for w in &d.words[..nw] {
        o[p..p + 8].copy_from_slice(&w.to_le_bytes());
        p += 8;
    }
    for c in &d.caps[..nc] {
        o[p..p + 4].copy_from_slice(&c.handle.to_le_bytes());
        o[p + 4] = c.mode;
        o[p + 5] = c._pad;
        o[p + 6..p + 8].copy_from_slice(&c.rights.to_le_bytes());
        o[p + 8..p + 16].copy_from_slice(&c.expiry_ns.to_le_bytes());
        p += 16;
    }
    *at += need;
    Some(())
}

/// Read the descriptor part at `*at`: the version is the current one, the
/// counts are within the ABI ceilings, the reserved half-word is 0, every
/// entry has a pad of 0. `None` otherwise.
pub fn get_desc(body: &[u8], at: &mut usize) -> Option<MsgDesc> {
    let b = body.get(*at..)?;
    if b.len() < 4 || b[2] != 0 || b[3] != 0 {
        return None;
    }
    let (nw, nc) = (b[0] as usize, b[1] as usize);
    if nw > MSG_WORDS_MAX || nc > MSG_CAPS_MAX || b.len() < 4 + nw * 8 + nc * 16 {
        return None;
    }
    let mut d = MsgDesc { version: MSG_VERSION, n_words: nw as u8, n_caps: nc as u8, ..MsgDesc::default() };
    let mut p = 4;
    for w in d.words.iter_mut().take(nw) {
        *w = u64_at(b, p);
        p += 8;
    }
    for c in d.caps.iter_mut().take(nc) {
        if b[p + 5] != 0 {
            return None;
        }
        *c = CapDesc {
            handle: u32_at(b, p),
            mode: b[p + 4],
            _pad: 0,
            rights: u16_at(b, p + 6),
            expiry_ns: u64_at(b, p + 8),
        };
        p += 16;
    }
    *at += p;
    Some(d)
}

/// Read one capability's data at `*at`.
pub fn get_data<'a>(body: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let b = body.get(*at..)?;
    if b.len() < 4 {
        return None;
    }
    let len = u32_at(b, 0) as usize;
    let d = b.get(4..4usize.checked_add(len)?)?;
    *at += 4 + len;
    Some(d)
}

// ── warrant tokens ──────────────────────────────────────────────────────

/// The caveat kinds a token may carry: the kernel's own (`caveat` in
/// `crates/core/ipc/src/cap.rs`, whose numbers these are; a host test reads
/// that file and fails when they differ). 0 is no caveat; a kind not listed is
/// refused wherever a token is built or read.
pub mod cav {
    /// `arg`: nanoseconds the warrant has left **at the moment the frame is
    /// sent** (clocks differ between nodes, so a token never carries an
    /// absolute time, like a frame's deadline). The receiver anchors it on its
    /// own clock.
    pub const EXPIRY: u8 = 1;
    /// `arg`: uses left.
    pub const QUOTA: u8 = 2;
    /// `arg`: the node the warrant is valid on. Checked by the receiving
    /// server against its own id.
    pub const NODE: u8 = 3;
    /// `arg`: a mask of the op classes the warrant may be invoked with.
    pub const OP_MASK: u8 = 4;
    /// `arg`: a receipt the use must leave. Reserved by the kernel.
    pub const RECEIPT: u8 = 5;
    /// `arg`: the label bits a one-shot warrant takes off a message. Local
    /// only: the kernel mints it for a user session, and a server refuses a
    /// token that carries one (`session::Refusal::Declassify`).
    pub const DECLASSIFY: u8 = 6;

    /// Is `kind` one the kernel knows?
    pub const fn known(kind: u8) -> bool {
        matches!(kind, EXPIRY | QUOTA | NODE | OP_MASK | RECEIPT | DECLASSIFY)
    }
}

/// The most caveats a token carries (the kernel's `CAVEATS_MAX`: the list a
/// re-minted warrant can hold).
pub const CAVEATS_MAX: usize = 4;
/// Bytes of the HMAC at the end of a token.
pub const SIG_BYTES: usize = 32;
/// The longest token on the wire: issuer, interface, count, a full list, the
/// signature.
pub const TOKEN_MAX: usize = 10 + CAVEATS_MAX * 9 + SIG_BYTES;

/// One condition on the use of a warrant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Caveat {
    pub kind: u8,
    pub arg: u64,
}

impl Caveat {
    pub const fn new(kind: u8, arg: u64) -> Caveat {
        Caveat { kind, arg }
    }
}

/// Why a caveat cannot be added to a token.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TokenError {
    /// The list already holds [`CAVEATS_MAX`].
    Full,
    /// A kind the kernel does not know.
    UnknownKind,
}

/// A warrant as it crosses a session: which interface it is for, who issued it
/// and the caveats on it, chained by HMAC-SHA256 in the manner of a macaroon.
///
/// ```text
/// sig0 = HMAC(session key, "azos-rpc warrant/1" || session u32 || issuer u32 || iface u32)
/// sigN = HMAC(sig(N-1),    kind u8 || arg u64)
/// token  = issuer u32, iface u32, n u8, reserved u8 (0), n * (kind u8, arg u64), sigN (32)
/// ```
///
/// **Only a holder of the session key can start a chain; anyone holding a
/// token can extend it, and no one can shorten or edit it.** Appending is one
/// more HMAC keyed by the signature the token already carries, so the key is
/// not needed; removing or changing a caveat would need the signature before
/// it, which the token does not keep and HMAC does not give back. Binding the
/// session and the issuer into `sig0` keeps a token from one session (or from
/// the other end of this one, reflected) from verifying in another. The
/// session key never leaves the two nodes ([`crate::chan::Channel::mac_key`]);
/// the sealed frame that carries a token authenticates the hop, the chain
/// authenticates the caveats against anyone who can hold the token but not
/// the key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Token {
    /// The node that started the chain.
    pub issuer: u32,
    /// The interface id the warrant is for.
    pub iface: u32,
    n: u8,
    list: [Caveat; CAVEATS_MAX],
    sig: [u8; SIG_BYTES],
}

const CAV_NONE: Caveat = Caveat { kind: 0, arg: 0 };

fn chain_root(key: &[u8; 32], session: u32, issuer: u32, iface: u32) -> [u8; SIG_BYTES] {
    hmac_sha256(key, &[b"azos-rpc warrant/1", &session.to_le_bytes(), &issuer.to_le_bytes(), &iface.to_le_bytes()])
}

fn chain_step(sig: &[u8; SIG_BYTES], c: &Caveat) -> [u8; SIG_BYTES] {
    hmac_sha256(sig, &[&[c.kind], &c.arg.to_le_bytes()])
}

impl Token {
    /// A token with no caveat, started by `issuer` under `key` for `session`.
    pub fn mint(key: &[u8; 32], session: u32, issuer: u32, iface: u32) -> Token {
        Token { issuer, iface, n: 0, list: [CAV_NONE; CAVEATS_MAX], sig: chain_root(key, session, issuer, iface) }
    }

    /// The caveats, in the order they were added.
    pub fn caveats(&self) -> &[Caveat] {
        &self.list[..self.n as usize]
    }

    /// Add `c`. Needs no key: this is the one operation a holder has.
    pub fn attenuate(&mut self, c: Caveat) -> Result<(), TokenError> {
        if !cav::known(c.kind) {
            return Err(TokenError::UnknownKind);
        }
        if self.n as usize >= CAVEATS_MAX {
            return Err(TokenError::Full);
        }
        self.sig = chain_step(&self.sig, &c);
        self.list[self.n as usize] = c;
        self.n += 1;
        Ok(())
    }

    /// The signature after each of the caveats, in order (`[i]` is the chain
    /// as it stood once caveat `i` was added), valid up to the caveat count.
    /// Attenuation only appends, so every token derived from this one carries
    /// these same prefixes: the signature after a caveat names that caveat and
    /// everything before it, for the holder and for every copy it narrows.
    pub fn prefix_sigs(&self, key: &[u8; 32], session: u32) -> [[u8; SIG_BYTES]; CAVEATS_MAX] {
        let mut out = [[0u8; SIG_BYTES]; CAVEATS_MAX];
        let mut sig = chain_root(key, session, self.issuer, self.iface);
        for (o, c) in out.iter_mut().zip(self.caveats()) {
            sig = chain_step(&sig, c);
            *o = sig;
        }
        out
    }

    /// Does the chain hold under `key` for `session`: is `sig` what the issuer
    /// and the caveats, in order, chain to? Constant time in the signature.
    pub fn verify(&self, key: &[u8; 32], session: u32) -> bool {
        let mut sig = chain_root(key, session, self.issuer, self.iface);
        for c in self.caveats() {
            sig = chain_step(&sig, c);
        }
        ct_eq(&sig, &self.sig)
    }
}

/// Append `t` to `out` at `*at`. `None` when it does not fit.
pub fn put_token(t: &Token, out: &mut [u8], at: &mut usize) -> Option<()> {
    let n = t.n as usize;
    let need = 10 + n * 9 + SIG_BYTES;
    let o = out.get_mut(*at..*at + need)?;
    o[0..4].copy_from_slice(&t.issuer.to_le_bytes());
    o[4..8].copy_from_slice(&t.iface.to_le_bytes());
    o[8] = t.n;
    o[9] = 0;
    let mut p = 10;
    for c in t.caveats() {
        o[p] = c.kind;
        o[p + 1..p + 9].copy_from_slice(&c.arg.to_le_bytes());
        p += 9;
    }
    o[p..p + SIG_BYTES].copy_from_slice(&t.sig);
    *at += need;
    Some(())
}

/// Read a token at `*at`: the count is within [`CAVEATS_MAX`], the reserved
/// byte is 0, every kind is one the kernel knows. `None` otherwise. **This is
/// not verification**: the chain is checked by [`Token::verify`].
pub fn get_token(body: &[u8], at: &mut usize) -> Option<Token> {
    let b = body.get(*at..)?;
    if b.len() < 10 || b[9] != 0 {
        return None;
    }
    let n = b[8] as usize;
    let need = 10 + n * 9 + SIG_BYTES;
    if n > CAVEATS_MAX || b.len() < need {
        return None;
    }
    let mut t = Token {
        issuer: u32_at(b, 0),
        iface: u32_at(b, 4),
        n: n as u8,
        list: [CAV_NONE; CAVEATS_MAX],
        sig: [0; SIG_BYTES],
    };
    let mut p = 10;
    for slot in t.list.iter_mut().take(n) {
        if !cav::known(b[p]) {
            return None;
        }
        *slot = Caveat { kind: b[p], arg: u64_at(b, p + 1) };
        p += 9;
    }
    t.sig.copy_from_slice(&b[p..p + SIG_BYTES]);
    *at += need;
    Some(t)
}

// ── reassembly ──────────────────────────────────────────────────────────

/// Messages being put together at once: a request and a reply can be in
/// flight in opposite directions between two nodes.
pub const ASM_SLOTS: usize = 2;

struct Slot {
    used: bool,
    kind: Kind,
    node: u32,
    session: u32,
    seq: u64,
    cnt: u16,
    mask: u32,
    last_len: usize,
    head: Header,
    buf: [u8; MSG_CAP],
}

/// Puts the fragments of a message together. A message is named by
/// (kind, sender node, session, seq); a fragment of a message that fits no
/// slot replaces the oldest, so a lost fragment costs its message and nothing
/// else.
pub struct Asm {
    slots: [Slot; ASM_SLOTS],
    next: usize,
}

const EMPTY_HEADER: Header = Header::new(Kind::Ping, 0, 0, 0, 0);

impl Asm {
    /// Nothing in progress.
    pub const fn new() -> Asm {
        const S: Slot = Slot {
            used: false,
            kind: Kind::Ping,
            node: 0,
            session: 0,
            seq: 0,
            cnt: 0,
            mask: 0,
            last_len: 0,
            head: EMPTY_HEADER,
            buf: [0; MSG_CAP],
        };
        Asm { slots: [S, S], next: 0 }
    }

    /// Take one fragment. `Some(slot)` when it completes a message (read it
    /// with [`Asm::message`], release it with [`Asm::done`]).
    pub fn push(&mut self, h: &Header, frag: &[u8]) -> Option<usize> {
        let (cnt, idx) = (h.frag_cnt as usize, h.frag_idx as usize);
        let i = self.pick(h);
        let s = &mut self.slots[i];
        if !s.used {
            s.used = true;
            s.kind = h.kind;
            s.node = h.node;
            s.session = h.session;
            s.seq = h.seq;
            s.cnt = h.frag_cnt;
            s.mask = 0;
            s.last_len = 0;
            s.head = *h;
        }
        if s.cnt != h.frag_cnt {
            // The same message named with another count: not this message.
            s.used = false;
            return None;
        }
        // `get_header` keeps a fragment inside `MSG_CAP`; a caller that did not
        // go through it gets a refusal, not a panic.
        let Some(dst) = s.buf.get_mut(idx * FRAG_BODY..idx * FRAG_BODY + frag.len()) else {
            s.used = false;
            return None;
        };
        dst.copy_from_slice(frag);
        s.mask |= 1 << idx;
        if idx + 1 == cnt {
            s.last_len = frag.len();
        }
        let full = if cnt == 32 { u32::MAX } else { (1u32 << cnt) - 1 };
        (s.mask == full).then_some(i)
    }

    /// The slot for the message `h` belongs to: the one already assembling it,
    /// else a free one, else the oldest in use (replaced).
    fn pick(&mut self, h: &Header) -> usize {
        if let Some(i) = self.slots.iter().position(|s| {
            s.used && s.kind == h.kind && s.node == h.node && s.session == h.session && s.seq == h.seq
        }) {
            return i;
        }
        if let Some(i) = self.slots.iter().position(|s| !s.used) {
            return i;
        }
        let i = self.next;
        self.next = (self.next + 1) % ASM_SLOTS;
        self.slots[i].used = false;
        i
    }

    /// The completed message in `slot`: its first header and its body.
    pub fn message(&self, slot: usize) -> (Header, &[u8]) {
        let s = &self.slots[slot];
        let len = (s.cnt as usize - 1) * FRAG_BODY + s.last_len;
        (s.head, &s.buf[..len])
    }

    /// Release `slot`.
    pub fn done(&mut self, slot: usize) {
        self.slots[slot].used = false;
    }
}
