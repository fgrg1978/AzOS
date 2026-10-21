// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sealed channel of one session, and the Noise IK handshake that makes it.
//!
//! **Every session is authenticated.** A node dials with `Noise_IK_25519_
//! ChaChaPoly_SHA256`: the dialer knows the answerer's static key (it is the
//! `noise_pk` of the answerer in the topology's `[peer.NAME]` row), sends its
//! own, encrypted, in the first message, and the answerer accepts only if that
//! key is the one its topology pins for the node id the Hello states. Both
//! static keys are therefore the topology's, which is signed; nothing a
//! datagram states is believed.
//!
//! What binds the rest of a Hello to the keys is the Noise **prologue**: the
//! two node ids, the dialer's boot epoch and its nonce are mixed into the
//! transcript hash, so a header edited on the way makes the handshake fail.
//! The answer's session id and epoch travel in its (encrypted) payload.
//!
//! The transport is the pair of Noise `CipherState`s the handshake splits into,
//! used with an **explicit counter** (the header's `ctr`): the receiver takes
//! the nonce from the packet, because datagrams are lost, repeated and
//! reordered, and refuses a counter it has seen (or that fell out of a
//! 64-packet window) before it decrypts anything.

use azos_crypto::chachapoly::TAG_LEN;
use azos_crypto::ct::{ct_eq, secure_zero};
use azos_crypto::hkdf::hmac_sha256;
use azos_crypto::noise::{CipherState, HandshakeState, Pattern, Transport, DH_LEN};
use azos_crypto::x25519::x25519_pubkey;

use crate::wire::{put_header, Header, HEADER_BYTES, TAG_BYTES};
use crate::NodeId;

const _: () = assert!(TAG_LEN == TAG_BYTES);

/// The public half of a static key: what the topology's `noise_pk` of the node
/// lists.
pub fn static_public_key(sk: &[u8; DH_LEN]) -> [u8; DH_LEN] {
    x25519_pubkey(sk)
}

/// The prologue of a handshake: the protocol, both node ids, the dialer's
/// epoch and nonce. The answerer builds it from the Hello's header, so a
/// header changed after the dialer wrote it fails the handshake.
pub fn prologue(dialer: NodeId, answerer: NodeId, epoch: u32, nonce: u64) -> [u8; 30] {
    let mut p = [0u8; 30];
    p[..10].copy_from_slice(b"azos-rpc/2");
    p[10..14].copy_from_slice(&dialer.to_le_bytes());
    p[14..18].copy_from_slice(&answerer.to_le_bytes());
    p[18..22].copy_from_slice(&epoch.to_le_bytes());
    p[22..30].copy_from_slice(&nonce.to_le_bytes());
    p
}

/// The dialer's side of the handshake, up to its first message. It is a pure
/// function of its inputs, so the same call rebuilds the state when the answer
/// arrives: nothing but the ephemeral key has to be kept in between.
pub fn dial(
    sk: &[u8; DH_LEN],
    answerer_pk: &[u8; DH_LEN],
    prologue: &[u8],
    eph: &[u8; DH_LEN],
    payload: &[u8],
    out: &mut [u8],
) -> Option<(HandshakeState, usize)> {
    let mut hs = HandshakeState::initiator(Pattern::Ik, sk, Some(answerer_pk), prologue).ok()?;
    let n = hs.write_message(eph, payload, out).ok()?;
    Some((hs, n))
}

/// The answerer's side: read the first message, check the static key it
/// carries is `dialer_pk`, write the answer (whose payload is `reply`) and
/// split. Returns the channel and the lengths of the answer (in `ack`) and of
/// the dialer's payload (in `payload`); `None` for anything wrong with the
/// message or the key.
pub fn answer(
    sk: &[u8; DH_LEN],
    dialer_pk: &[u8; DH_LEN],
    prologue: &[u8],
    hello: &[u8],
    eph: &[u8; DH_LEN],
    reply: &[u8],
    ack: &mut [u8],
    payload: &mut [u8; 64],
) -> Option<(Channel, usize, usize)> {
    let mut hs = HandshakeState::responder(Pattern::Ik, sk, prologue).ok()?;
    let n = hs.read_message(hello, payload).ok()?;
    // IK proves the dialer holds *a* key; the topology says which one it must be.
    if !hs.remote_static().is_some_and(|rs| ct_eq(rs, dialer_pk)) {
        return None;
    }
    let len = hs.write_message(eph, reply, ack).ok()?;
    let t = hs.finish().ok()?;
    ct_eq(&t.remote_static, dialer_pk).then(|| (Channel::from_transport(t), len, n))
}

/// What the answer carried, once opened: read by the dialer.
pub fn finish_dial(
    mut hs: HandshakeState,
    answerer_pk: &[u8; DH_LEN],
    ack: &[u8],
    payload: &mut [u8; 64],
) -> Option<(Channel, usize)> {
    let n = hs.read_message(ack, payload).ok()?;
    let t = hs.finish().ok()?;
    ct_eq(&t.remote_static, answerer_pk).then(|| (Channel::from_transport(t), n))
}

/// Which packet counters have been seen: the highest, and the 64 below it.
#[derive(Clone, Copy)]
pub struct Window {
    /// Whether any packet has been accepted (counter 0 is valid).
    any: bool,
    high: u64,
    /// Bit `i` set: counter `high - i` was seen.
    seen: u64,
}

impl Window {
    const fn new() -> Window {
        Window { any: false, high: 0, seen: 0 }
    }

    /// Is `ctr` new: above everything seen, or inside the window and not in it?
    fn fresh(&self, ctr: u64) -> bool {
        if !self.any || ctr > self.high {
            return true;
        }
        let d = self.high - ctr;
        d < 64 && self.seen & (1 << d) == 0
    }

    /// `ctr` authenticated: record it.
    fn accept(&mut self, ctr: u64) {
        if !self.any {
            *self = Window { any: true, high: ctr, seen: 1 };
        } else if ctr > self.high {
            let shift = ctr - self.high;
            self.seen = if shift >= 64 { 0 } else { self.seen << shift };
            self.seen |= 1;
            self.high = ctr;
        } else {
            self.seen |= 1 << (self.high - ctr);
        }
    }
}

/// The two directions of a session. All zeros until a handshake fills it, so a
/// `static` of sessions costs no image bytes.
pub struct Channel {
    send: CipherState,
    recv: CipherState,
    win: Window,
    /// The session's MAC key for what rides inside the sealed frames (the
    /// warrant chains of `wire::Token`): derived from the handshake's secrets,
    /// the same on both sides, never on the wire. It lives exactly as long as
    /// the keys do ([`Channel::mac_key`] is `None` while they are not set).
    /// **There is no rekey in this channel** (nothing here calls
    /// `CipherState::rekey`; a session whose counter runs out is broken and a
    /// new handshake derives a new exporter): a rekey added later must derive
    /// a new `mac` from the new chaining material in the same step.
    mac: [u8; 32],
}

impl Channel {
    /// No keys: [`Channel::seal`] and [`Channel::open`] refuse.
    pub const fn idle() -> Channel {
        Channel { send: CipherState::empty(), recv: CipherState::empty(), win: Window::new(), mac: [0; 32] }
    }

    fn from_transport(mut t: Transport) -> Channel {
        let mut exporter = t.take_exporter();
        let mac = hmac_sha256(&exporter, &[b"azos-rpc session mac key v1"]);
        secure_zero(&mut exporter);
        // `Transport` wipes its exporter when dropped, so its fields cannot be
        // moved out by pattern; the cipher states are swapped for empty ones.
        let send = core::mem::replace(&mut t.send, CipherState::empty());
        let recv = core::mem::replace(&mut t.recv, CipherState::empty());
        Channel { send, recv, win: Window::new(), mac }
    }

    /// Seal `plain` as the frame with header `h` (its `ctr` is set here) into
    /// `out`: the header, the encrypted body, the tag. Returns the frame's
    /// length; `None` when `out` is too small or the keys are spent.
    pub fn seal(&mut self, h: &mut Header, plain: &[u8], out: &mut [u8]) -> Option<usize> {
        let n = HEADER_BYTES + plain.len();
        if out.len() < n + TAG_BYTES {
            return None;
        }
        h.ctr = self.send.nonce();
        put_header(h, out);
        let (head, body) = out.split_at_mut(HEADER_BYTES);
        body[..plain.len()].copy_from_slice(plain);
        let tag = self.send.encrypt(head, &mut body[..plain.len()]).ok()?;
        body[plain.len()..plain.len() + TAG_BYTES].copy_from_slice(&tag);
        Some(n + TAG_BYTES)
    }

    /// Open a sealed `frame` (whose header is `h`) into `out`: the length of
    /// the body, or `None` for a counter already seen, a tag that does not
    /// verify (a forged or altered frame) or a buffer too small. The counter
    /// is recorded only when the frame authenticates.
    pub fn open(&mut self, h: &Header, frame: &[u8], out: &mut [u8]) -> Option<usize> {
        let sealed = frame.get(HEADER_BYTES..)?;
        let n = sealed.len().checked_sub(TAG_BYTES)?;
        if out.len() < n || !self.win.fresh(h.ctr) {
            return None;
        }
        out[..n].copy_from_slice(&sealed[..n]);
        let mut tag = [0u8; TAG_BYTES];
        tag.copy_from_slice(&sealed[n..]);
        self.recv.set_nonce(h.ctr);
        self.recv.decrypt(&frame[..HEADER_BYTES], &mut out[..n], &tag).ok()?;
        self.win.accept(h.ctr);
        Some(n)
    }

    /// The session's MAC key; `None` while the channel has no keys.
    pub fn mac_key(&self) -> Option<&[u8; 32]> {
        self.send.has_key().then_some(&self.mac)
    }

    /// Forget the keys.
    pub fn clear(&mut self) {
        *self = Channel::idle();
    }
}

impl Drop for Channel {
    /// The cipher states wipe themselves; the MAC key is wiped here, so a
    /// channel replaced, cleared or dropped leaves none behind.
    fn drop(&mut self) {
        secure_zero(&mut self.mac);
    }
}

/// Zero a copy of a secret.
pub fn wipe(k: &mut [u8; 32]) {
    secure_zero(k);
}
