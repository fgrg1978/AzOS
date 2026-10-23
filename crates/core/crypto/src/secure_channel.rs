// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The brain link's secure channel: a Noise handshake (`noise.rs`) and the
//! Noise transport it yields, framed for a TCP byte stream.
//!
//! Pure `no_std`, no allocation, no RNG, no clock: the caller hands in every
//! ephemeral private key and every buffer, so a session is a function of its
//! inputs and the host tests can pin every wire byte against the brain's
//! Python implementation (`AzOSRobotBrain/secure_channel.py`).
//!
//! ## Roles
//!
//! The robot is the TCP client (it dials the brain) and the Noise
//! **initiator**; the brain is the TCP server and the Noise responder. One
//! inversion fewer than the previous design, and the one `IK` needs: its
//! initiator already knows the responder's static key, which is the brain's,
//! pinned in the signed topology (`[peer.brain]`, `noise_pk`).
//!
//! ## Keys, from the one provisioned secret
//!
//! The 32-byte link key (reserved sector / `LinkKey` endpoint) is never used as
//! an X25519 scalar. Static keys derive from it, one per side and per purpose:
//!
//! ```text
//! static_sk(side) = HKDF-SHA256(salt = "azos-brain-link-v1 static",
//!                               ikm  = link key, info = "azos brain-link <side> static v1")
//! ```
//!
//! * pinned brain key: **`Noise_IK`**. The robot is given the brain's static
//!   public key (it need not be derivable from the link key: the operator's
//!   own key makes it a second factor). The brain proves it holds the private
//!   half in message 2; the brain checks that the robot's static (sent in
//!   message 1) is the one the link key derives.
//! * no pinned key: **`Noise_XX`**, both statics the derived ones. After
//!   message 2 the robot compares the brain's static with the key the link
//!   key derives for the brain and aborts before sending its own static in
//!   message 3; the brain makes the mirrored check after message 3. A peer
//!   without the link key cannot present either static, so XX is
//!   authenticated by the same secret as before, not trust-on-first-use.
//!
//! Both patterns keep the forward secrecy of the ephemerals: a later leak of
//! the link key does not open a recorded session.
//!
//! ## Wire
//!
//! ```text
//! robot -> brain   [pattern 'I' | 'X']                     once, before frame 1
//! frame            [length u16 BE][body]                   length = body bytes
//! IK    1 robot -> brain  e, es, s, ss      2 brain -> robot  e, ee, se
//! XX    1 robot -> brain  e                 2 brain -> robot  e, ee, s, es
//!       3 robot -> brain  s, se
//! transport frame  [length u16 BE][ChaCha20-Poly1305 ciphertext || tag]
//! ```
//!
//! Handshake payloads are empty. The prologue is `"azos-brain-link-v1"` and
//! the pattern byte, so the byte the responder had to read before it could
//! pick a pattern is bound into the transcript.
//!
//! A transport frame's associated data is its own two length bytes, and its
//! nonce is the CipherState's counter, which the wire does not carry: TCP is
//! in order, so a dropped, repeated or reordered frame fails the AEAD and ends
//! the session. There is no in-session recovery and no authenticated REJECT:
//! **any violation closes the connection**, and the reconnect is a fresh
//! handshake with fresh ephemerals, which is also what keeps a frame recorded
//! in an earlier session from decrypting in this one.
//!
//! An empty plaintext (a bare 16-byte tag) is the rekey signal: after it the
//! sender, and the receiver on reading it, replace that direction's key by
//! Noise `REKEY` (the counter keeps running). [`Link::seal_message`] sends one
//! whenever the generation would pass [`REKEY_MAX_RECORDS`] messages or
//! [`REKEY_MAX_BYTES`] bytes, or when the caller asked with
//! [`Link::request_rekey`] (the wall-clock trigger, [`REKEY_INTERVAL_SECS`],
//! is the caller's: this module has no clock). The receiver enforces the same
//! limits. A message is therefore never empty.
//!
//! ## No session survives a restore
//!
//! A `Link` has no export and no import, and no path in the tree carries one
//! across a restart: a service swap (`Documentation/update.md`, "Service
//! update by endpoint handover") starts the successor from its image, and a
//! crash restart does the same, so the next session is always a fresh
//! handshake with fresh ephemerals and its counters start at 0 under a key no
//! earlier session had. The (key, nonce) pair therefore cannot repeat through
//! anything the OS does. The one way it could is a rewind of the whole
//! machine's memory below the OS (a hypervisor snapshot restored while the
//! live image runs on); the OS cannot see that, and no `Link` step can cure
//! it from inside the image, so this module carries none. If a freeze/thaw of
//! a running session is ever built, it needs its own design (an epoch agreed
//! with the peer, a real caller on both ends) and lands with that caller.
//!
//! ## There is no other mode
//!
//! The brain link is always this session: no plaintext mode, no MAC-only mode,
//! and no runtime switch (a key in `/fat/CONFIG.INI` would live on the FAT
//! volume of a removable card, so it would be an attacker-writable
//! downgrade). A frame travels only inside a message of an
//! established session, so a peer without the link key has nothing to send.
//!
//! In-session replay is the transport's counter, so a captured frame replays
//! nowhere; across sessions it fails the AEAD under the new keys. There is no
//! second replay floor and no second MAC: one authenticated channel.
//!
//! `link-provisioning-enforced` (Kconfig `LINK_PROVISIONING_ENFORCED`) hardens the
//! provisioning around that fact, fixed at COMPILE time like
//! `secure-boot-enforced`: a boot without a link key halts, a handshake
//! without seeded entropy is refused, and the UART bridge, which carries
//! brain-protocol frames outside any session, is down. See
//! [`link_provisioning_enforced`].

use crate::chachapoly::TAG_LEN;
use crate::ct::{ct_eq, secure_zero};
use crate::hkdf;
use crate::noise::{self, CipherState, HandshakeState, Pattern, DH_LEN, HASH_LEN};
use crate::sha256::Sha256;
use crate::x25519::x25519_pubkey;

// ── Constants (mirrored by `AzOSRobotBrain/secure_channel.py`) ──────────

/// Length of the link key (a pre-shared secret, never a curve scalar).
pub const PSK_BYTES: usize = 32;
/// The pattern byte for `Noise_IK` (the brain's static key is pinned).
pub const PATTERN_IK: u8 = b'I';
/// The pattern byte for `Noise_XX`.
pub const PATTERN_XX: u8 = b'X';
/// The prologue's fixed part; the pattern byte follows it.
pub const PROLOGUE_LABEL: &[u8] = b"azos-brain-link-v1";
/// HKDF salt of the derived static keys.
pub const STATIC_SALT: &[u8] = b"azos-brain-link-v1 static";
/// HKDF info of the robot's derived static key.
pub const KERNEL_STATIC_INFO: &[u8] = b"azos brain-link kernel static v1";
/// HKDF info of the brain's derived static key (the XX identity).
pub const BRAIN_STATIC_INFO: &[u8] = b"azos brain-link brain static v1";

/// Bytes of a frame's length prefix.
pub const FRAME_HEAD: usize = 2;
/// Per-frame overhead of a transport message: the length prefix and the tag.
pub const FRAME_OVERHEAD: usize = FRAME_HEAD + TAG_LEN;
/// Largest handshake message body (a message with an empty payload is at most
/// 96 bytes; the slack is for diagnostics, not for payloads).
pub const HANDSHAKE_MSG_MAX: usize = 128;
/// Largest handshake output: the pattern byte, the prefix and the message.
pub const HANDSHAKE_OUT_MAX: usize = 1 + FRAME_HEAD + HANDSHAKE_MSG_MAX;
/// Size of a session id.
pub const SESSION_ID_BYTES: usize = 16;
/// Largest message [`Link::seal_message`] accepts.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;

/// Worst-case sealed size of a `msg_len`-byte message: its frame plus one
/// rekey frame. Size `out` for [`Link::seal_message`] with this.
pub const fn sealed_len_max(msg_len: usize) -> usize {
    2 * FRAME_OVERHEAD + msg_len
}

/// Messages per key generation, per direction, including the rekey message
/// that closes it.
pub const REKEY_MAX_RECORDS: u32 = 1 << 20;
/// Plaintext bytes per key generation, per direction (1 GiB).
pub const REKEY_MAX_BYTES: u64 = 1 << 30;
/// Wall-clock rekey interval (1 hour). The caller measures it and
/// calls [`Link::request_rekey`].
pub const REKEY_INTERVAL_SECS: u64 = 3600;
/// Smallest message limit [`Link::set_rekey_limits`] accepts: a message and
/// the rekey message in front of it.
pub const REKEY_MIN_RECORDS: u32 = 2;
/// Smallest byte limit [`Link::set_rekey_limits`] accepts: the largest message.
pub const REKEY_MIN_BYTES: u64 = MAX_MESSAGE_BYTES as u64;
/// Shortest wall-clock rekey interval a configuration may ask for, in seconds.
pub const REKEY_INTERVAL_MIN_SECS: u64 = 5;

/// The wall-clock rekey interval for a configured request, in seconds.
///
/// A request may only SHORTEN [`REKEY_INTERVAL_SECS`]: a shorter interval
/// ratchets more often and weakens nothing, while a longer one would let a
/// file on a USB-exported volume stretch the key's life past the default hour.
/// So `None` (no request) and anything above the default give the default,
/// and anything below [`REKEY_INTERVAL_MIN_SECS`] gives that floor. One
/// function for every binary: the test image and a board read the same key
/// through the same clamp.
pub const fn rekey_interval_secs(requested: Option<u64>) -> u64 {
    match requested {
        None => REKEY_INTERVAL_SECS,
        Some(v) if v < REKEY_INTERVAL_MIN_SECS => REKEY_INTERVAL_MIN_SECS,
        Some(v) if v > REKEY_INTERVAL_SECS => REKEY_INTERVAL_SECS,
        Some(v) => v,
    }
}

// ── Link policy: provisioning hardening, fixed at compile time ────────

/// Was this binary built with `link-provisioning-enforced`?
///
/// `const fn` so callers can bind it to a `const` and have the policy branches
/// const-folded away rather than evaluated per use. No file, no config key and
/// no disk state decides it, deliberately: a gate whose enabling condition
/// came off disk once failed open and looked fine (the secure-boot scenario).
/// `tests/host/aead-link-tests` asserts the value in BOTH feature states.
pub const fn link_provisioning_enforced() -> bool {
    cfg!(feature = "link-provisioning-enforced")
}

// ── Keys ───────────────────────────────────────────────────────────────

/// A static X25519 private key derived from the link key for `info`.
fn derive_static(psk: &[u8; PSK_BYTES], info: &[u8]) -> [u8; DH_LEN] {
    let mut sk = [0u8; DH_LEN];
    // Cannot fail: 32 bytes is far below HKDF's 255 * 32 limit.
    let _ = hkdf::hkdf(STATIC_SALT, psk, info, &mut sk);
    sk
}

/// The robot's static private key for the brain link.
pub fn kernel_static_key(psk: &[u8; PSK_BYTES]) -> [u8; DH_LEN] {
    derive_static(psk, KERNEL_STATIC_INFO)
}

/// The brain's derived static private key (the XX identity; an IK brain uses
/// the key the operator pinned instead).
pub fn brain_static_key(psk: &[u8; PSK_BYTES]) -> [u8; DH_LEN] {
    derive_static(psk, BRAIN_STATIC_INFO)
}

// ── The link key's reserved-sector record ──────────────────────────────
//
// The key is provisioned into reserved tail sector `LINK_KEY`
// (`kernel/src/reserved_tail.rs`) as a record, never as raw bytes: one
// 512-byte sector, `LINK_KEY_RECORD_BYTES` (41) meaningful:
//   offset  size  field
//   0       4     magic "KLNK"
//   4       1     version (1)
//   5       32    key
//   37      4     integrity tag (first 4 bytes of SHA-256(bytes 0..37))
// Written from the host only (`tools/link_key_provision.py`); the kernel
// never writes it. A raw key, a torn write or filesystem data in that sector
// is not a key.

pub const LINK_KEY_MAGIC: [u8; 4] = *b"KLNK";
pub const LINK_KEY_VERSION: u8 = 1;
pub const LINK_KEY_RECORD_BYTES: usize = 4 + 1 + PSK_BYTES + 4;

/// Why a reserved sector yields no link key.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum LinkKeyFault {
    /// Every byte of the record's span is zero: nothing was provisioned.
    Absent,
    /// Anything else that is not a valid record: a short buffer, a wrong
    /// magic or version, a tag that does not match, or an all-zero key.
    Malformed,
}

/// Decode the link-key record at the start of `data` (a reserved sector).
pub fn link_key_record_decode(data: &[u8]) -> Result<[u8; PSK_BYTES], LinkKeyFault> {
    if data.len() < LINK_KEY_RECORD_BYTES {
        return Err(LinkKeyFault::Malformed);
    }
    let rec = &data[..LINK_KEY_RECORD_BYTES];
    if rec.iter().all(|&b| b == 0) {
        return Err(LinkKeyFault::Absent);
    }
    if rec[0..4] != LINK_KEY_MAGIC || rec[4] != LINK_KEY_VERSION {
        return Err(LinkKeyFault::Malformed);
    }
    let body = &rec[..LINK_KEY_RECORD_BYTES - 4];
    let mut h = Sha256::new();
    h.update(body);
    let d = h.finalize();
    if !ct_eq(&rec[LINK_KEY_RECORD_BYTES - 4..], &d[..4]) {
        return Err(LinkKeyFault::Malformed);
    }
    let mut key = [0u8; PSK_BYTES];
    key.copy_from_slice(&body[5..]);
    if key.iter().all(|&b| b == 0) {
        return Err(LinkKeyFault::Malformed);
    }
    Ok(key)
}

// ── Framing ────────────────────────────────────────────────────────────

/// Why a transport frame did not open.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordError {
    /// Not a failure: the buffer does not hold a whole frame yet. Nothing
    /// consumed, no state changed.
    Incomplete,
    /// The link is not established (never was, or already terminal).
    NotEstablished,
    /// Terminal: a length below the tag, or above what the reader accepts.
    BadHeader,
    /// Terminal: the AEAD failed (forged, replayed, reordered or dropped
    /// frame, or keys that do not match).
    BadMac,
    /// Terminal: the peer's generation passed the message or byte limit
    /// without a rekey.
    RekeyOverdue,
}

impl RecordError {
    /// Does this error end the session? Everything except `Incomplete` and
    /// `NotEstablished` does.
    pub fn is_terminal(self) -> bool {
        !matches!(self, RecordError::Incomplete | RecordError::NotEstablished)
    }
}

/// Wire size (prefix included) of the frame whose first bytes are `head`, for
/// a reader that accepts bodies up to `max_body` bytes (tag included).
///
/// `Err(Incomplete)` while fewer than [`FRAME_HEAD`] bytes are available;
/// `Err(BadHeader)` for a length below the tag or above `max_body`.
/// Unauthenticated: a reader uses it only to learn how many bytes to wait for.
pub fn frame_len(head: &[u8], max_body: usize) -> Result<usize, RecordError> {
    if head.len() < FRAME_HEAD {
        return Err(RecordError::Incomplete);
    }
    let body = u16::from_be_bytes([head[0], head[1]]) as usize;
    if body < TAG_LEN || body > max_body {
        return Err(RecordError::BadHeader);
    }
    Ok(FRAME_HEAD + body)
}

/// The body limit of a reader whose peer sends messages of at most
/// `max_message` bytes.
pub const fn max_body_for(max_message: usize) -> usize {
    max_message + TAG_LEN
}

// ── Handshake ──────────────────────────────────────────────────────────

/// Why a handshake step failed. Every variant ends the handshake: the caller
/// closes the connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandshakeError {
    /// Called in the wrong state (finished, failed, or not our turn).
    BadState,
    /// The input is not one whole frame, or its length is wrong.
    BadFrame,
    /// The output buffer is smaller than [`HANDSHAKE_OUT_MAX`].
    BufferTooSmall,
    /// The Noise state machine refused (bad key, bad tag, wrong prologue).
    Noise(noise::Error),
    /// The peer's static key is not the one this side expects.
    PeerKeyMismatch,
    /// The peer sent a handshake payload; there are none.
    UnexpectedPayload,
}

impl From<noise::Error> for HandshakeError {
    fn from(e: noise::Error) -> Self {
        HandshakeError::Noise(e)
    }
}

fn prologue(pattern_byte: u8) -> [u8; PROLOGUE_LABEL.len() + 1] {
    let mut p = [0u8; PROLOGUE_LABEL.len() + 1];
    p[..PROLOGUE_LABEL.len()].copy_from_slice(PROLOGUE_LABEL);
    p[PROLOGUE_LABEL.len()] = pattern_byte;
    p
}

/// The robot's half of the handshake (the Noise initiator).
///
/// Drive it with [`Initiator::step`] until [`Initiator::is_done`], then
/// [`Initiator::finish`]. The first output starts with the pattern byte.
pub struct Initiator {
    hs: HandshakeState,
    pattern: Pattern,
    /// The brain's static public key the XX handshake must show; `None` for
    /// IK, where the pinned key is the one the handshake authenticates.
    expect: Option<[u8; DH_LEN]>,
    sent_pattern: bool,
    failed: bool,
}

impl Initiator {
    /// A handshake keyed by `psk`: `Noise_IK` toward `brain_pinned` when the
    /// brain's static public key is pinned, `Noise_XX` otherwise.
    pub fn new(psk: &[u8; PSK_BYTES], brain_pinned: Option<&[u8; DH_LEN]>) -> Result<Self, HandshakeError> {
        let mut sk = kernel_static_key(psk);
        let (pattern, pb, expect) = match brain_pinned {
            Some(_) => (Pattern::Ik, PATTERN_IK, None),
            None => {
                let mut bsk = brain_static_key(psk);
                let pk = x25519_pubkey(&bsk);
                secure_zero(&mut bsk);
                (Pattern::Xx, PATTERN_XX, Some(pk))
            }
        };
        let hs = HandshakeState::initiator(pattern, &sk, brain_pinned, &prologue(pb));
        secure_zero(&mut sk);
        Ok(Initiator { hs: hs?, pattern, expect, sent_pattern: false, failed: false })
    }

    /// The pattern byte this handshake announces.
    pub fn pattern_byte(&self) -> u8 {
        match self.pattern {
            Pattern::Ik => PATTERN_IK,
            Pattern::Xx => PATTERN_XX,
        }
    }

    /// Our static public key (what the brain checks against the key the link
    /// key derives).
    pub fn local_static(&self) -> &[u8; DH_LEN] {
        self.hs.local_static()
    }

    /// Has the pattern completed?
    pub fn is_done(&self) -> bool {
        !self.failed && self.hs.is_finished()
    }

    /// One step: read the peer's frame `input` (None for the first call),
    /// then write our next frame into `out` if it is our turn. Returns the
    /// bytes written to `out` (0 when the handshake finished without us
    /// writing). `eph` is a fresh ephemeral private key; it is only used by a
    /// message that has an `e` token. On `Err` the handshake is over.
    pub fn step(&mut self, input: Option<&[u8]>, eph: &[u8; DH_LEN], out: &mut [u8]) -> Result<usize, HandshakeError> {
        if self.failed {
            return Err(HandshakeError::BadState);
        }
        let r = self.step_inner(input, eph, out);
        if r.is_err() {
            self.failed = true;
        }
        r
    }

    fn step_inner(&mut self, input: Option<&[u8]>, eph: &[u8; DH_LEN], out: &mut [u8]) -> Result<usize, HandshakeError> {
        if out.len() < HANDSHAKE_OUT_MAX {
            return Err(HandshakeError::BufferTooSmall);
        }
        if let Some(frame) = input {
            if frame.len() < FRAME_HEAD
                || u16::from_be_bytes([frame[0], frame[1]]) as usize != frame.len() - FRAME_HEAD
                || frame.len() - FRAME_HEAD > HANDSHAKE_MSG_MAX
            {
                return Err(HandshakeError::BadFrame);
            }
            let mut payload = [0u8; 0];
            match self.hs.read_message(&frame[FRAME_HEAD..], &mut payload) {
                Ok(0) => {}
                Ok(_) | Err(noise::Error::BufferTooSmall) => return Err(HandshakeError::UnexpectedPayload),
                Err(e) => return Err(e.into()),
            }
            // XX: the brain's static is known now, before ours goes out.
            if let (Some(want), Some(got)) = (self.expect.as_ref(), self.hs.remote_static()) {
                if !ct_eq(want, got) {
                    return Err(HandshakeError::PeerKeyMismatch);
                }
            }
        }
        if !self.hs.is_my_turn() {
            return Ok(0);
        }
        let mut off = 0usize;
        if !self.sent_pattern {
            out[0] = self.pattern_byte();
            self.sent_pattern = true;
            off = 1;
        }
        let body = &mut out[off + FRAME_HEAD..off + FRAME_HEAD + HANDSHAKE_MSG_MAX];
        let n = self.hs.write_message(eph, &[], body)?;
        out[off..off + FRAME_HEAD].copy_from_slice(&(n as u16).to_be_bytes());
        Ok(off + FRAME_HEAD + n)
    }

    /// The handshake hash: identical on both sides, unique to this session.
    pub fn handshake_hash(&self) -> &[u8; HASH_LEN] {
        self.hs.handshake_hash()
    }

    /// Split into the established [`Link`] once the pattern is complete.
    pub fn finish(self) -> Result<Link, HandshakeError> {
        if !self.is_done() {
            return Err(HandshakeError::BadState);
        }
        let mut t = self.hs.finish()?;
        let send = core::mem::replace(&mut t.send, CipherState::empty());
        let recv = core::mem::replace(&mut t.recv, CipherState::empty());
        Ok(Link::established(send, recv, t.hash, t.remote_static))
    }
}

// ── Session ids ────────────────────────────────────────────────────────

/// Recently seen session ids, for refusing a repeated session (a repeat means
/// both ephemerals repeated).
///
/// Fixed capacity, no allocation; the oldest id is overwritten when full.
/// Lookups compare every stored id without an early exit.
pub struct SessionIdCache<const N: usize> {
    ids: [[u8; SESSION_ID_BYTES]; N],
    filled: usize,
    next: usize,
}

impl<const N: usize> SessionIdCache<N> {
    pub const fn new() -> Self {
        SessionIdCache { ids: [[0u8; SESSION_ID_BYTES]; N], filled: 0, next: 0 }
    }

    /// Record `id`. Returns `false`, recording nothing, if `id` is already
    /// present: the caller refuses that session.
    pub fn insert_if_new(&mut self, id: &[u8; SESSION_ID_BYTES]) -> bool {
        let mut seen = false;
        for stored in self.ids[..self.filled].iter() {
            seen |= ct_eq(stored, id);
        }
        if seen {
            return false;
        }
        if N != 0 {
            self.ids[self.next] = *id;
            self.next = (self.next + 1) % N;
            if self.filled < N {
                self.filled += 1;
            }
        }
        true
    }
}

// ── Transport ──────────────────────────────────────────────────────────

/// What [`Link::open_frame`] found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordKind {
    /// `len` plaintext bytes now sit at `frame[FRAME_HEAD..FRAME_HEAD + len]`.
    Data { len: usize },
    /// The peer advanced its transmit generation; no data.
    Rekey,
}

/// One opened frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Opened {
    pub kind: RecordKind,
    /// Wire bytes the frame occupied.
    pub consumed: usize,
}

/// Why [`Link::seal_message`] refused. No state changes on refusal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SealError {
    NotEstablished,
    /// Longer than [`MAX_MESSAGE_BYTES`].
    MessageTooLarge,
    /// An empty message is the rekey signal, never data.
    EmptyMessage,
    /// `out` is shorter than the frames this call must write.
    BufferTooSmall,
    /// The CipherState's 2^64 - 1 message limit; reconnect.
    CounterExhausted,
}

/// An established session: the two Noise transport CipherStates and the
/// per-generation accounting.
pub struct Link {
    send: CipherState,
    recv: CipherState,
    hash: [u8; HASH_LEN],
    remote: [u8; DH_LEN],
    /// False once the session ended (a terminal event) or was closed.
    established: bool,
    tx_gen: u64,
    rx_gen: u64,
    tx_msgs: u32,
    tx_bytes: u64,
    rx_msgs: u32,
    rx_bytes: u64,
    limit_msgs: u32,
    limit_bytes: u64,
    rekey_requested: bool,
}

impl Link {
    fn established(send: CipherState, recv: CipherState, hash: [u8; HASH_LEN], remote: [u8; DH_LEN]) -> Self {
        Link {
            send,
            recv,
            hash,
            remote,
            established: true,
            tx_gen: 0,
            rx_gen: 0,
            tx_msgs: 0,
            tx_bytes: 0,
            rx_msgs: 0,
            rx_bytes: 0,
            limit_msgs: REKEY_MAX_RECORDS,
            limit_bytes: REKEY_MAX_BYTES,
            rekey_requested: false,
        }
    }

    /// Leave `Established`, and wipe the keys.
    fn close(&mut self) {
        self.established = false;
        self.send = CipherState::empty();
        self.recv = CipherState::empty();
        secure_zero(&mut self.hash);
    }

    fn fail(&mut self, e: RecordError) -> RecordError {
        self.close();
        e
    }

    pub fn is_established(&self) -> bool {
        self.established
    }

    /// Session id: the first 16 bytes of the handshake hash.
    pub fn session_id(&self) -> [u8; SESSION_ID_BYTES] {
        let mut id = [0u8; SESSION_ID_BYTES];
        id.copy_from_slice(&self.hash[..SESSION_ID_BYTES]);
        id
    }

    /// The peer's authenticated static public key.
    pub fn remote_static(&self) -> &[u8; DH_LEN] {
        &self.remote
    }

    /// Key generation the transmit side has reached.
    pub fn tx_generation(&self) -> u64 {
        self.tx_gen
    }

    /// Key generation the receive side has reached.
    pub fn rx_generation(&self) -> u64 {
        self.rx_gen
    }

    /// Ask for a rekey: the next [`Link::seal_message`] puts a rekey frame in
    /// front of its message.
    pub fn request_rekey(&mut self) {
        self.rekey_requested = true;
    }

    /// Lower the per-generation limits, clamped to
    /// `[REKEY_MIN_*, REKEY_MAX_*]`. They apply to both directions: the
    /// transmit side rekeys at them and the receive side refuses a peer that
    /// passes them, so both ends of a link must use the same values.
    pub fn set_rekey_limits(&mut self, messages: u32, bytes: u64) {
        self.limit_msgs = messages.clamp(REKEY_MIN_RECORDS, REKEY_MAX_RECORDS);
        self.limit_bytes = bytes.clamp(REKEY_MIN_BYTES, REKEY_MAX_BYTES);
    }

    /// Seal one frame of `plain` (empty: the rekey signal) into `out`, which
    /// holds `plain.len() + FRAME_OVERHEAD` bytes (the caller checked).
    /// Returns the frame's wire size.
    fn seal_frame(cs: &mut CipherState, plain: &[u8], out: &mut [u8]) -> Result<usize, noise::Error> {
        let body = plain.len() + TAG_LEN;
        let head = (body as u16).to_be_bytes();
        out[..FRAME_HEAD].copy_from_slice(&head);
        out[FRAME_HEAD..FRAME_HEAD + plain.len()].copy_from_slice(plain);
        let tag = cs.encrypt(&head, &mut out[FRAME_HEAD..FRAME_HEAD + plain.len()])?;
        out[FRAME_HEAD + plain.len()..FRAME_HEAD + body].copy_from_slice(&tag);
        Ok(FRAME_HEAD + body)
    }

    /// Seal `msg` as one frame, with a rekey frame in front when the
    /// generation limits or [`Link::request_rekey`] call for one. Returns the
    /// bytes written. Size `out` with [`sealed_len_max`].
    ///
    /// On `Err` nothing was written that the caller should send and no state
    /// changed.
    pub fn seal_message(&mut self, msg: &[u8], out: &mut [u8]) -> Result<usize, SealError> {
        if !self.established {
            return Err(SealError::NotEstablished);
        }
        if msg.is_empty() {
            return Err(SealError::EmptyMessage);
        }
        if msg.len() > MAX_MESSAGE_BYTES {
            return Err(SealError::MessageTooLarge);
        }
        let rekey = self.rekey_requested
            || self.tx_msgs as u64 + 2 > self.limit_msgs as u64
            || self.tx_bytes + msg.len() as u64 > self.limit_bytes;
        let need = msg.len() + FRAME_OVERHEAD + if rekey { FRAME_OVERHEAD } else { 0 };
        if out.len() < need {
            return Err(SealError::BufferTooSmall);
        }
        if self.send.nonce() > u64::MAX - 3 {
            return Err(SealError::CounterExhausted);
        }
        let mut off = 0usize;
        if rekey {
            off += Self::seal_frame(&mut self.send, &[], out).map_err(|_| SealError::CounterExhausted)?;
            self.send.rekey();
            self.tx_gen += 1;
            self.tx_msgs = 0;
            self.tx_bytes = 0;
            self.rekey_requested = false;
        }
        off += Self::seal_frame(&mut self.send, msg, &mut out[off..]).map_err(|_| SealError::CounterExhausted)?;
        self.tx_msgs += 1;
        self.tx_bytes += msg.len() as u64;
        Ok(off)
    }

    /// Open the frame at the front of `frame` **in place**. Size it with
    /// [`frame_len`]; the plaintext of a data frame is left at
    /// `frame[FRAME_HEAD..FRAME_HEAD + len]`.
    ///
    /// Loop over a TCP byte stream with this, advancing by `consumed`; on
    /// `Err(Incomplete)` keep the unconsumed tail and wait for more bytes. Any
    /// error with [`RecordError::is_terminal`] ends the session: the keys are
    /// wiped, stop reading and close the connection.
    ///
    /// `max_body` bounds a body as in [`frame_len`]: a peer that claims more
    /// is a violation, before any byte of it is read.
// REQ-012
    pub fn open_frame(&mut self, frame: &mut [u8], max_body: usize) -> Result<Opened, RecordError> {
        if !self.established {
            return Err(RecordError::NotEstablished);
        }
        let total = match frame_len(frame, max_body) {
            Ok(t) => t,
            Err(RecordError::Incomplete) => return Err(RecordError::Incomplete),
            Err(e) => return Err(self.fail(e)),
        };
        if frame.len() < total {
            return Err(RecordError::Incomplete);
        }
        let plen = total - FRAME_OVERHEAD;
        let head = [frame[0], frame[1]];
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&frame[FRAME_HEAD + plen..total]);
        if self.recv.decrypt(&head, &mut frame[FRAME_HEAD..FRAME_HEAD + plen], &tag).is_err() {
            return Err(self.fail(RecordError::BadMac));
        }
        if plen == 0 {
            self.recv.rekey();
            self.rx_gen += 1;
            self.rx_msgs = 0;
            self.rx_bytes = 0;
            return Ok(Opened { kind: RecordKind::Rekey, consumed: total });
        }
        // The sender rekeys before its `limit_msgs`-th message of a
        // generation (see `seal_message`), so a data frame that would be that
        // message is a peer that skipped the rekey.
        if self.rx_msgs as u64 + 1 >= self.limit_msgs as u64 || self.rx_bytes + plen as u64 > self.limit_bytes {
            return Err(self.fail(RecordError::RekeyOverdue));
        }
        self.rx_msgs += 1;
        self.rx_bytes += plen as u64;
        Ok(Opened { kind: RecordKind::Data { len: plen }, consumed: total })
    }
}

/// Wipe every secret the link holds and leave the registration.
impl Drop for Link {
    fn drop(&mut self) {
        self.close();
        secure_zero(&mut self.remote);
    }
}
