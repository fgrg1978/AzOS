// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! RFC-0019 encrypted brain link — handshake state machine and record layer.
//!
//! Pure `no_std`, host-buildable.  Cross-side compat with the brain
//! Python `secure_channel.SecureChannel` is verified by
//! `tests/host/encrypt-link-tests/` using deterministic ephemeral keys.
//!
//! ## Role split — the TCP role and the crypto role are INVERTED
//!
//! In the AZOS topology the kernel dials the brain, so the kernel is the
//! TCP *client*.  The crypto handshake runs the other way round: the brain
//! speaks first.  `AzOSRobotBrain/protocol.py` calls `start_handshake()` and
//! `kernel/src/tasks/brain_link.rs` calls `brain_responder_handshake()`, which drives
//! `handle_initiator_hello` / `handle_initiator_confirm`.  So:
//!
//! ```text
//!   crypto initiator = brain   (TCP server)
//!   crypto responder = kernel  (TCP client)
//! ```
//!
//! The distinction is load-bearing — it selects the direction-bound key
//! pair below — so getting it wrong produces a link where nothing decrypts.
//!
//! ```text
//! initiator → responder: [0x02][HELLO=0x48][initiator_e_pub 32B]
//! responder → initiator: [0x02][HELLO=0x48][responder_e_pub 32B][proof_r 32B]
//! initiator → responder: [0x02][CONFIRM=0x43][proof_i 32B]
//! either    → other:     [0x02][REJECT=0x52]              (then close)
//! ```
//!
//! `proof_r = HMAC-SHA256(PSK, "RESP" || initiator_e_pub || responder_e_pub)`
//! `proof_i = HMAC-SHA256(PSK, "INIT" || responder_e_pub || initiator_e_pub)`
//!
//! Every peer-driven handshake failure is terminal (`Rejected`), and the
//! refusing side sends [`REJECT_FRAME`] before closing — one frame for every
//! cause, so the peer learns nothing about which check failed.  A side that
//! reads [`REJECT_FRAME`] where it expected the next handshake message gets
//! [`HandshakeError::PeerRejected`] and must close.  Callers read the first
//! [`REJECT_BYTES`] of each handshake message before the rest, so a REJECT
//! is recognised as such rather than surfacing as a short read.
//!
//! `session_id = SHA-256("SID" || initiator_e_pub || responder_e_pub)[0..16]`
//! names the session.  [`SessionIdCache`] lets a side refuse a handshake
//! whose session id it has already seen.  The cache lives in RAM: it covers
//! the lifetime of one boot or one brain process, not a reboot.
//!
//! ## Record layer
//!
//! ```text
//! Offset  Size  Field
//! 0x00    8     nonce prefix (caller-supplied randomness)
//! 0x08    4     record counter, u32 LE
//! 0x0C    2     length field, u16 LE: bits 0..11 payload length N (<= 2048),
//!               bits 12..15 flags
//! 0x0E    N     AES-128-CTR ciphertext, counter block = nonce12 || be32(1..)
//! 0x0E+N  32    HMAC-SHA-256(mac key, bytes 0x00..0x0E+N)
//! ```
//!
//! Flags (authenticated: the MAC covers the length field):
//!
//! ```text
//!   0x0000  DATA    final (or only) record of a message
//!   0x1000  MORE    message continues in the next record; N must be 2048
//!   0x2000  REKEY   N = 0; the sender's NEXT record uses the next generation
//!   0x4000  REJECT  N = 0; the sender refuses the session; terminal
//!   0x8000  reserved, must be zero
//! ```
//!
//! A flags-zero record is byte-identical to the frame
//! `azos_crypto::secure_channel::SecureChannel` produces for the same
//! keys, nonce and counter, which is what keeps the Python-generated
//! generation-0 vectors in `encrypt-link-tests` valid.  A receiver built
//! before the flags existed reads a flagged record as a length above 2048
//! and refuses it, so an old peer fails closed rather than misparsing.
//!
//! Keys, per direction `d` (`C2S` = brain → kernel, `S2C` = the reverse):
//!
//! ```text
//!   generation 0:  enc = SHA-256(shared || "ENC" || d)[0..16]
//!                  mac = SHA-256(shared || "MAC" || d)[0..16]
//!                  chain_0 = SHA-256(shared || "RKY" || d)
//!   generation g:  chain_g = SHA-256(chain_{g-1} || "RKY" || d || be64(g))
//!                  enc = SHA-256(chain_g || "ENC" || d)[0..16]
//!                  mac = SHA-256(chain_g || "MAC" || d)[0..16]
//! ```
//!
//! The shared secret and the ephemeral private key are wiped as soon as the
//! generation-0 keys and chains exist; each ratchet step wipes the previous
//! chain and keys.  Keys of an earlier generation are therefore not
//! recoverable from the state of a later one.
//!
//! The record counter runs across generations and never resets inside a
//! session; the receiver accepts only the exact next counter.  A record
//! replayed from before a rekey fails twice over: its MAC is under a key the
//! receiver no longer holds, and its counter is behind.  The counter caps a
//! session at `u32::MAX` records, after which sealing refuses and the peers
//! must reconnect.
//!
//! Rekey is per direction and sender-driven: [`EncryptLink::seal_message`]
//! emits a REKEY record first whenever the current generation would pass
//! [`REKEY_MAX_RECORDS`] records or [`REKEY_MAX_BYTES`] payload bytes, or
//! when the caller asked for it with [`EncryptLink::request_rekey`] (the
//! wall-clock trigger, [`REKEY_INTERVAL_SECS`], is the caller's: this crate
//! has no clock).  The receiver enforces the same limits and treats a
//! generation that overruns them as a violation.
//!
//! Messages longer than one record (up to [`MAX_MESSAGE_BYTES`]) are split
//! into 2048-byte MORE records followed by one DATA record.  REKEY is only
//! valid between messages.
//!
//! Any record-layer violation — bad header, MAC, counter, overdue rekey,
//! oversize message — is terminal: the link leaves `Established`, the
//! receive keys are wiped, and the caller may send one authenticated REJECT
//! record with [`EncryptLink::seal_reject`] before closing.  A received
//! REJECT record ends the session with nothing to answer.
//!
//! ## Forward secrecy: none, today
//!
//! The ephemeral keys are only as good as the entropy behind them, and
//! there is no TRNG driver in this tree.  See the note on
//! `azos_behavior::encrypt_link::derive_ephemeral_priv`.
//!
//! ## K-C5: this mode can be made MANDATORY
//!
//! Built with the `link-encrypt-enforced` feature, the brain link refuses to
//! produce or accept a frame that is not inside an established session here:
//! no plaintext mode, no HMAC-only mode, no runtime override. See the "Link
//! policy" section below for the mechanism and
//! `behavior::auth_envelope`'s `LINK_ENCRYPT_ENFORCED` for the gate itself.
//!
//! ## Entropy
//!
//! This crate is **pure**: it does NOT collect entropy.  Callers
//! generate the 32-byte ephemeral private key themselves (kernel uses
//! a mix of CLINT time + cycle counter + PSK + salt via SHA-256;
//! tests pass fixed keys) and pass it to [`EncryptLink::new`].  Same
//! for the 8-byte nonce prefix of every record.

use core::sync::atomic::{AtomicUsize, Ordering};

use azos_crypto::aes::{Aes128, AES_KEY_SIZE};
use azos_crypto::ct::{ct_eq, secure_zero};
use azos_crypto::sha256::Sha256;
use azos_crypto::x25519;

// ── Wire constants (must match brain `secure_channel.py`) ──────────────

/// Mode byte for the encrypted (RFC-0019) link.
pub const MODE_ENCRYPTED: u8 = 0x02;
/// Frame label: HELLO carries an ephemeral public key.
pub const LABEL_HELLO: u8 = 0x48;
/// Frame label: CONFIRM carries the initiator's PSK proof.
pub const LABEL_CONFIRM: u8 = 0x43;
/// Frame label: REJECT signals handshake failure (no detail leaked).
pub const LABEL_REJECT: u8 = 0x52;

/// Size of the handshake REJECT frame.
pub const REJECT_BYTES: usize = 2;
/// The handshake REJECT frame, sent by the refusing side before it closes.
pub const REJECT_FRAME: [u8; REJECT_BYTES] = [MODE_ENCRYPTED, LABEL_REJECT];

/// Size of an ephemeral X25519 public key.
pub const EPH_PUB_BYTES: usize = 32;
/// Size of a handshake proof (HMAC-SHA-256, full 32 B — NOT truncated).
pub const PROOF_BYTES: usize = 32;
/// Size of a session id.
pub const SESSION_ID_BYTES: usize = 16;

/// Wire size of the responder's HELLO+proof reply.
pub const HELLO_REPLY_BYTES: usize = 2 + EPH_PUB_BYTES + PROOF_BYTES;
/// Wire size of the initiator's HELLO.
pub const HELLO_INIT_BYTES: usize = 2 + EPH_PUB_BYTES;
/// Wire size of the initiator's CONFIRM.
pub const CONFIRM_BYTES: usize = 2 + PROOF_BYTES;

/// Pre-shared key length (32 raw bytes), matches `auth_envelope::KEY_BYTES`.
pub const PSK_BYTES: usize = 32;

// Record sizes are the crypto crate's; re-exported so callers don't import
// from it directly.
pub use azos_crypto::secure_channel::{
    NONCE_SIZE as ENC_NONCE_SIZE,
    HMAC_SIZE as ENC_HMAC_SIZE,
    PACKET_OVERHEAD as ENC_OVERHEAD,
    MAX_PAYLOAD_SIZE as ENC_MAX_PAYLOAD,
};

/// Bytes a reader needs before it knows a record's length: nonce + length
/// field.  See [`parse_record_header`].
pub const RECORD_HEADER_BYTES: usize = ENC_NONCE_SIZE + 2;

/// Payload-length bits of the record length field.
pub const RECORD_LEN_MASK: u16 = 0x0FFF;
/// The message continues in the next record.
pub const RECORD_FLAG_MORE: u16 = 0x1000;
/// Control: the sender's next record uses the next key generation.
pub const RECORD_FLAG_REKEY: u16 = 0x2000;
/// Control: the sender refuses the session.
pub const RECORD_FLAG_REJECT: u16 = 0x4000;
/// Reserved; a record with this bit set is a violation.
pub const RECORD_FLAG_RESERVED: u16 = 0x8000;

const _: () = assert!(ENC_MAX_PAYLOAD <= RECORD_LEN_MASK as usize);

/// Largest message [`EncryptLink::seal_message`] accepts and a receiver
/// reassembles.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;

/// Records one message of `msg_len` bytes occupies (an empty message still
/// takes one record).
pub const fn records_for(msg_len: usize) -> usize {
    if msg_len == 0 { 1 } else { (msg_len + ENC_MAX_PAYLOAD - 1) / ENC_MAX_PAYLOAD }
}

/// Worst-case sealed size of a `msg_len`-byte message: its records plus one
/// REKEY record.  Size `out` for [`EncryptLink::seal_message`] with this.
pub const fn sealed_len_max(msg_len: usize) -> usize {
    (records_for(msg_len) + 1) * ENC_OVERHEAD + msg_len
}

/// Records per key generation, per direction, including the REKEY record
/// that closes it.
pub const REKEY_MAX_RECORDS: u32 = 1 << 20;
/// Payload bytes per key generation, per direction (RFC-0019: 1 GiB).
pub const REKEY_MAX_BYTES: u64 = 1 << 30;
/// Wall-clock rekey interval (RFC-0019: 1 hour).  The caller measures it and
/// calls [`EncryptLink::request_rekey`].
pub const REKEY_INTERVAL_SECS: u64 = 3600;
/// Smallest record limit [`EncryptLink::set_rekey_limits`] accepts: the
/// largest message plus its REKEY record must fit one generation.
pub const REKEY_MIN_RECORDS: u32 = records_for(MAX_MESSAGE_BYTES) as u32 + 1;
/// Smallest byte limit [`EncryptLink::set_rekey_limits`] accepts.
pub const REKEY_MIN_BYTES: u64 = MAX_MESSAGE_BYTES as u64;
/// Shortest wall-clock rekey interval a configuration may ask for, in
/// seconds: the floor of [`rekey_interval_secs`].
pub const REKEY_INTERVAL_MIN_SECS: u64 = 5;

/// The wall-clock rekey interval for a configured request, in seconds.
///
/// A request may only SHORTEN [`REKEY_INTERVAL_SECS`]: a shorter interval
/// ratchets more often and weakens nothing, while a longer one would let a
/// file on a USB-exported volume stretch the key's life past RFC-0019's
/// hour. So `None` (no request) and anything above the default give the
/// default, and anything below [`REKEY_INTERVAL_MIN_SECS`] gives that floor.
/// One function for every binary: the test image and a board read the same
/// key through the same clamp.
pub const fn rekey_interval_secs(requested: Option<u64>) -> u64 {
    match requested {
        None => REKEY_INTERVAL_SECS,
        Some(v) if v < REKEY_INTERVAL_MIN_SECS => REKEY_INTERVAL_MIN_SECS,
        Some(v) if v > REKEY_INTERVAL_SECS => REKEY_INTERVAL_SECS,
        Some(v) => v,
    }
}

// ── KDF labels ─────────────────────────────────────────────────────────

const KDF_LABEL_RESP: &[u8] = b"RESP";
const KDF_LABEL_INIT: &[u8] = b"INIT";
const KDF_LABEL_ENC: &[u8] = b"ENC";
const KDF_LABEL_MAC: &[u8] = b"MAC";
const KDF_LABEL_RKY: &[u8] = b"RKY";
const KDF_LABEL_SID: &[u8] = b"SID";
const DIR_C2S: &[u8; 3] = b"C2S";
const DIR_S2C: &[u8; 3] = b"S2C";

// ── Link policy (K-C5): encrypted mode may be MANDATORY ────────────────
//
// The brain link has three historical modes:
//
//   1. plaintext   — no `/fat/LINK.KEY`; `auth_envelope::wrap`/`unwrap`
//                    degrade to the identity function.
//   2. HMAC-only   — key present, `CFG_LINK_ENCRYPT=0` (today's default).
//   3. encrypted   — key present, `CFG_LINK_ENCRYPT=1`; this crate's AEAD
//                    session wraps the HMAC envelope.
//
// Mode 2 carries a real hole: `auth_envelope::HIGHEST_RX_NONCE`, the only
// replay high-water mark in the stack, lives in RAM. A reboot zeroes it, and
// the brain derives its send nonces from `time_ns()`, so *any* recorded frame
// beats a zeroed mark. Between reboot and the first legitimate brain frame,
// a captured `PKT_ESTOP` — or a captured "FORWARD 100" — replays.
//
// Mode 3 closes that for free: each connection derives fresh session keys
// from fresh ephemeral X25519 keys, so a frame recorded before the reboot
// fails the AEAD MAC under the new `rx_mac_key` and never reaches the
// envelope layer at all. (Proven by
// `aead-link-tests::frame_from_a_previous_session_does_not_decrypt_in_a_new_one`.)
// The owner chose this over persisting the watermark: no flash wear, no
// rollback policy, and a keyless boot leaves the robot with no link —
// fail-closed, which is the correct side to be wrong on.
//
// `link-encrypt-enforced` makes modes 1 and 2 unreachable. Like
// `secure-boot-enforced` and `link-auth-enforced` it is fixed at COMPILE
// time and consults no runtime variable — `CFG_LINK_ENCRYPT` lives in
// `/fat/CONFIG.INI` on the FAT volume `msc_gadget.rs` also exports over USB
// mass storage, so a runtime knob here would be an attacker-writable
// downgrade switch, not a policy.

/// Number of `EncryptLink`s currently in [`HandshakeState::Established`].
///
/// Maintained as an invariant of the state machine: bumped at the two (and
/// only two) points that assign `Established`, dropped by `deregister` on
/// every transition out of it (a terminal record-layer event, or `Drop`).
/// There is deliberately **no setter** — the only way to make this non-zero
/// is to complete a PSK-authenticated X25519 handshake, which is what makes
/// the gate in `auth_envelope` something other than a flag someone can flip.
static AEAD_SESSIONS: AtomicUsize = AtomicUsize::new(0);

/// Was this binary built with `link-encrypt-enforced`?
///
/// `const fn` so callers can bind it to a `const` and have the policy
/// branches const-folded away rather than evaluated per packet — see
/// `LINK_ENCRYPT_ENFORCED` in `behavior/src/auth_envelope.rs`.
pub const fn link_encrypt_enforced() -> bool {
    cfg!(feature = "link-encrypt-enforced")
}

/// How many AEAD sessions are established right now.
pub fn aead_session_count() -> usize {
    AEAD_SESSIONS.load(Ordering::Acquire)
}

/// Is at least one RFC-0019 AEAD session established?
pub fn aead_session_established() -> bool {
    aead_session_count() != 0
}

/// **The gate.** May an `auth_envelope` frame be produced or accepted right
/// now?
///
/// With the policy off this is unconditionally `true` and the whole thing
/// const-folds to nothing. With it on, an envelope frame is only legitimate
/// when it is travelling inside an AEAD session — i.e. when the caller will
/// seal what `wrap` returns, and when the bytes handed to `unwrap` came out
/// of this crate's record layer.
///
/// Cost when enforced: one acquire load + one compare + one branch. The
/// envelope HMAC it guards is three SHA-256 compressions minimum (ikey
/// block, data, okey||inner) ≈ 192 rounds ≈ 1500 RV64 ops for the smallest
/// frame, before the AEAD layer's own AES-CTR and 32-byte HMAC. The gate is
/// under 0.2% of the packet it gates, which is why it sits on the hot path
/// per packet instead of once at establishment.
pub fn envelope_frame_permitted() -> bool {
    // Short-circuit on the const first: with the feature off, LLVM deletes
    // the atomic load entirely.
    !link_encrypt_enforced() || aead_session_established()
}

// ── Handshake state ────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandshakeState {
    /// No bytes exchanged yet.
    Init,
    /// Initiator: sent HELLO, waiting for peer's HELLO+proof.
    AwaitPeerHello,
    /// Responder: sent HELLO+proof, waiting for peer's CONFIRM.
    AwaitConfirm,
    /// Keys derived, records may be sealed and opened.
    Established,
    /// Refused by either side, or a record-layer violation.  Terminal.
    Rejected,
}

/// Compile-time bound for [`hmac_sha256`]: RFC 2104 hashes keys longer than
/// the block, which no caller here needs, so such a key does not compile.
struct KeyFitsBlock<const N: usize>;
impl<const N: usize> KeyFitsBlock<N> {
    const OK: () = assert!(N <= 64);
}

/// HMAC-SHA-256 over the concatenation of `data`.  RFC 2104 zero-pads the
/// key to the hash's block size (64 B for SHA-256).
fn hmac_sha256<const N: usize>(key: &[u8; N], data: &[&[u8]]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5C;
    let () = KeyFitsBlock::<N>::OK;

    let mut k_pad = [0u8; BLOCK_SIZE];
    k_pad[..N].copy_from_slice(key);

    let mut inner_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE { inner_key[i] = k_pad[i] ^ IPAD; }
    let mut h = Sha256::new();
    h.update(&inner_key);
    for d in data { h.update(d); }
    let mut inner_hash = h.finalize();

    let mut outer_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE { outer_key[i] = k_pad[i] ^ OPAD; }
    let mut h = Sha256::new();
    h.update(&outer_key);
    h.update(&inner_hash);
    let out = h.finalize();

    // `k_pad` is the key zero-padded; `inner_key`/`outer_key` are the key
    // XOR'd with a public constant, i.e. trivially reversible to it. For the
    // proofs that key is the long-lived PSK, for records a session MAC key;
    // neither belongs in a released stack frame.
    secure_zero(&mut k_pad);
    secure_zero(&mut inner_key);
    secure_zero(&mut outer_key);
    secure_zero(&mut inner_hash);

    out
}

/// SHA-256 over the concatenation of `parts`.
fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts { h.update(p); }
    h.finalize()
}

/// First 16 bytes of SHA-256 over `parts`; the rest of the digest is wiped.
fn kdf16(parts: &[&[u8]]) -> [u8; AES_KEY_SIZE] {
    let mut d = sha256_parts(parts);
    let mut out = [0u8; AES_KEY_SIZE];
    out.copy_from_slice(&d[..AES_KEY_SIZE]);
    secure_zero(&mut d);
    out
}

/// `proof_r = HMAC-SHA256(PSK, "RESP" || initiator_pub || responder_pub)`.
pub fn proof_responder(psk: &[u8; PSK_BYTES],
                       initiator_pub: &[u8; EPH_PUB_BYTES],
                       responder_pub: &[u8; EPH_PUB_BYTES])
    -> [u8; PROOF_BYTES]
{
    hmac_sha256(psk, &[KDF_LABEL_RESP, initiator_pub, responder_pub])
}

/// `proof_i = HMAC-SHA256(PSK, "INIT" || responder_pub || initiator_pub)`.
pub fn proof_initiator(psk: &[u8; PSK_BYTES],
                       responder_pub: &[u8; EPH_PUB_BYTES],
                       initiator_pub: &[u8; EPH_PUB_BYTES])
    -> [u8; PROOF_BYTES]
{
    hmac_sha256(psk, &[KDF_LABEL_INIT, responder_pub, initiator_pub])
}

/// `session_id = SHA-256("SID" || initiator_pub || responder_pub)[0..16]`.
pub fn session_id(initiator_pub: &[u8; EPH_PUB_BYTES],
                  responder_pub: &[u8; EPH_PUB_BYTES])
    -> [u8; SESSION_ID_BYTES]
{
    let d = sha256_parts(&[KDF_LABEL_SID, initiator_pub, responder_pub]);
    let mut out = [0u8; SESSION_ID_BYTES];
    out.copy_from_slice(&d[..SESSION_ID_BYTES]);
    out
}

/// Is `frame` exactly the handshake REJECT frame?
pub fn is_reject_frame(frame: &[u8]) -> bool {
    frame.len() == REJECT_BYTES && frame[0] == MODE_ENCRYPTED && frame[1] == LABEL_REJECT
}

/// Recently seen session ids, for refusing a repeated session.
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

    /// Record `id`.  Returns `false`, recording nothing, if `id` is already
    /// present — the caller refuses that handshake.
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
            if self.filled < N { self.filled += 1; }
        }
        true
    }
}

// ── Record layer: per-direction key state ──────────────────────────────

/// One direction's keys and counters.
struct Direction {
    label: &'static [u8; 3],
    /// Ratchet secret of the current generation.
    chain: [u8; 32],
    enc: [u8; AES_KEY_SIZE],
    mac: [u8; AES_KEY_SIZE],
    generation: u64,
    /// Next record counter to send / to accept.  Never reset in a session.
    counter: u32,
    /// Records in the current generation.
    gen_records: u32,
    /// Payload bytes in the current generation.
    gen_bytes: u64,
}

impl Direction {
    const fn empty() -> Self {
        Direction {
            label: DIR_C2S,
            chain: [0u8; 32],
            enc: [0u8; AES_KEY_SIZE],
            mac: [0u8; AES_KEY_SIZE],
            generation: 0,
            counter: 0,
            gen_records: 0,
            gen_bytes: 0,
        }
    }

    /// Generation 0 from the X25519 shared secret.
    fn install(&mut self, shared: &[u8; 32], label: &'static [u8; 3]) {
        self.label = label;
        self.enc = kdf16(&[shared, KDF_LABEL_ENC, label]);
        self.mac = kdf16(&[shared, KDF_LABEL_MAC, label]);
        self.chain = sha256_parts(&[shared, KDF_LABEL_RKY, label]);
        self.generation = 0;
        self.counter = 0;
        self.gen_records = 0;
        self.gen_bytes = 0;
    }

    /// Advance to the next generation, wiping the current chain and keys.
    fn ratchet(&mut self) {
        let next_gen = self.generation.saturating_add(1);
        let mut next = sha256_parts(&[
            &self.chain, KDF_LABEL_RKY, self.label, &next_gen.to_be_bytes(),
        ]);
        self.wipe();
        self.enc = kdf16(&[&next, KDF_LABEL_ENC, self.label]);
        self.mac = kdf16(&[&next, KDF_LABEL_MAC, self.label]);
        self.chain = next;
        secure_zero(&mut next);
        self.generation = next_gen;
        self.gen_records = 0;
        self.gen_bytes = 0;
    }

    fn wipe(&mut self) {
        secure_zero(&mut self.chain);
        secure_zero(&mut self.enc);
        secure_zero(&mut self.mac);
    }

    /// Seal one record.  Returns 0, changing nothing, if the payload is too
    /// long, `out` too short, or the counter exhausted; callers that pre-check
    /// those never see 0.
    fn seal_record(&mut self, flags: u16, payload: &[u8], nonce_rand: &[u8; 8],
                   out: &mut [u8]) -> usize {
        let len = payload.len();
        let total = ENC_OVERHEAD + len;
        if len > ENC_MAX_PAYLOAD || out.len() < total || self.counter == u32::MAX {
            return 0;
        }
        let mut nonce = [0u8; ENC_NONCE_SIZE];
        nonce[..8].copy_from_slice(nonce_rand);
        nonce[8..].copy_from_slice(&self.counter.to_le_bytes());
        out[..ENC_NONCE_SIZE].copy_from_slice(&nonce);
        let field = (len as u16) | flags;
        out[ENC_NONCE_SIZE..RECORD_HEADER_BYTES].copy_from_slice(&field.to_le_bytes());
        let ct_end = RECORD_HEADER_BYTES + len;
        out[RECORD_HEADER_BYTES..ct_end].copy_from_slice(payload);
        Aes128::new(&self.enc).ctr_encrypt(&nonce, &mut out[RECORD_HEADER_BYTES..ct_end]);
        let tag = hmac_sha256(&self.mac, &[&out[..ct_end]]);
        out[ct_end..total].copy_from_slice(&tag);
        self.counter += 1;
        self.gen_records = self.gen_records.saturating_add(1);
        self.gen_bytes = self.gen_bytes.saturating_add(len as u64);
        total
    }
}

/// Parse and validate a record header (nonce + length field).
///
/// Returns `(flags, payload_len)`.  `Err(Incomplete)` when fewer than
/// [`RECORD_HEADER_BYTES`] are available; `Err(BadHeader)` for a reserved
/// bit, a length above 2048, a MORE record that is not full, a control
/// record with a payload, or more than one flag.  Unauthenticated: a reader
/// uses it only to learn how many bytes to wait for.
pub fn parse_record_header(head: &[u8]) -> Result<(u16, usize), RecordError> {
    if head.len() < RECORD_HEADER_BYTES {
        return Err(RecordError::Incomplete);
    }
    let field = u16::from_le_bytes([head[ENC_NONCE_SIZE], head[ENC_NONCE_SIZE + 1]]);
    let flags = field & !RECORD_LEN_MASK;
    let len = (field & RECORD_LEN_MASK) as usize;
    if len > ENC_MAX_PAYLOAD {
        return Err(RecordError::BadHeader);
    }
    let ok = match flags {
        0 => true,
        RECORD_FLAG_MORE => len == ENC_MAX_PAYLOAD,
        RECORD_FLAG_REKEY | RECORD_FLAG_REJECT => len == 0,
        _ => false,
    };
    if ok { Ok((flags, len)) } else { Err(RecordError::BadHeader) }
}

/// What [`EncryptLink::open_record`] found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordKind {
    /// `len` payload bytes were written to the front of `out`.  `more`:
    /// the message continues in the next record.
    Data { len: usize, more: bool },
    /// The peer advanced its transmit generation; nothing written.
    Rekey,
}

/// One opened record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Opened {
    pub kind: RecordKind,
    /// Wire bytes the record occupied.
    pub consumed: usize,
}

/// Why [`EncryptLink::open_record`] did not return a record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordError {
    /// Not a failure: the buffer does not hold a whole record yet.  Nothing
    /// consumed, no state changed.
    Incomplete,
    /// The link is not established (never was, or already terminal).
    NotEstablished,
    /// Terminal: reserved bit, bad length, or inconsistent flags.
    BadHeader,
    /// Terminal: MAC mismatch.
    BadMac,
    /// Terminal: the record counter is not the next one (replay, reorder,
    /// or a dropped record).
    BadCounter,
    /// Terminal: the peer's generation passed the record or byte limit
    /// without a REKEY.
    RekeyOverdue,
    /// Terminal: REKEY in the middle of a message.
    UnexpectedRekey,
    /// Terminal: the message being reassembled passed [`MAX_MESSAGE_BYTES`].
    MessageTooLarge,
    /// Terminal: `out` cannot hold the record's payload.
    BufferTooSmall,
    /// Terminal: the peer sent a REJECT record.
    PeerRejected,
}

impl RecordError {
    /// Does this error end the session?  Everything except `Incomplete` and
    /// `NotEstablished` does.
    pub fn is_terminal(self) -> bool {
        !matches!(self, RecordError::Incomplete | RecordError::NotEstablished)
    }
}

/// Why [`EncryptLink::seal_message`] refused.  No state changes on refusal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SealError {
    NotEstablished,
    /// Longer than [`MAX_MESSAGE_BYTES`].
    MessageTooLarge,
    /// `out` is shorter than the records this call must write.
    BufferTooSmall,
    /// The session's record counter would reach `u32::MAX`; reconnect.
    CounterExhausted,
}

// ── Public channel struct ──────────────────────────────────────────────

/// One handshake + AEAD session.
pub struct EncryptLink {
    state: HandshakeState,
    psk: [u8; PSK_BYTES],
    eph_priv: [u8; 32],
    eph_pub: [u8; EPH_PUB_BYTES],
    peer_pub: [u8; EPH_PUB_BYTES],
    session_id: [u8; SESSION_ID_BYTES],
    /// Session keys have been derived (from `AwaitConfirm`/`Established` on).
    keyed: bool,
    tx: Direction,
    rx: Direction,
    /// The transmit keys may still seal one REJECT record.
    tx_open: bool,
    rekey_records: u32,
    rekey_bytes: u64,
    rekey_requested: bool,
    /// Bytes of the message being reassembled; non-zero only between a MORE
    /// record and the DATA record that ends the message.
    rx_message_len: usize,
    rx_in_message: bool,
}

/// Errors a peer-driven handshake step can produce.  Every variant except
/// `BadState` leaves the link `Rejected`; the caller sends [`REJECT_FRAME`]
/// unless the variant is `PeerRejected`, then closes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandshakeError {
    /// Called in the wrong state; nothing changed.
    BadState,
    BadFrameLength,
    BadHeader,
    ProofMismatch,
    /// The peer's ephemeral public key produced a degenerate (all-zero)
    /// X25519 shared secret — a small-order point, see
    /// `azos_crypto::x25519::x25519_checked` — or equals our own.
    BadPeerKey,
    /// The peer sent [`REJECT_FRAME`].
    PeerRejected,
}

impl EncryptLink {
    /// Build a fresh channel.  `eph_priv` is the X25519 private key
    /// caller-derived from a TRNG (production) or pinned (tests).
    pub fn new(psk: [u8; PSK_BYTES], eph_priv: [u8; 32]) -> Self {
        let eph_pub = x25519::x25519_pubkey(&eph_priv);
        EncryptLink {
            state: HandshakeState::Init,
            psk,
            eph_priv,
            eph_pub,
            peer_pub: [0u8; EPH_PUB_BYTES],
            session_id: [0u8; SESSION_ID_BYTES],
            keyed: false,
            tx: Direction::empty(),
            rx: Direction::empty(),
            tx_open: false,
            rekey_records: REKEY_MAX_RECORDS,
            rekey_bytes: REKEY_MAX_BYTES,
            rekey_requested: false,
            rx_message_len: 0,
            rx_in_message: false,
        }
    }

    pub fn state(&self) -> HandshakeState { self.state }
    pub fn is_established(&self) -> bool {
        self.state == HandshakeState::Established
    }
    pub fn is_rejected(&self) -> bool {
        self.state == HandshakeState::Rejected
    }

    /// Local ephemeral public key (exposed for handshake bookkeeping +
    /// test pinning).
    pub fn eph_pub(&self) -> &[u8; EPH_PUB_BYTES] { &self.eph_pub }

    /// This session's id, once the session keys exist.
    pub fn session_id(&self) -> Option<[u8; SESSION_ID_BYTES]> {
        if self.keyed { Some(self.session_id) } else { None }
    }

    /// Transmit key generation (0 until the first rekey).
    pub fn tx_generation(&self) -> u64 { self.tx.generation }
    /// Receive key generation (0 until the peer's first rekey).
    pub fn rx_generation(&self) -> u64 { self.rx.generation }

    /// Make the next [`EncryptLink::seal_message`] start with a REKEY
    /// record.  This is how the wall-clock trigger reaches the crate.
    pub fn request_rekey(&mut self) { self.rekey_requested = true; }

    /// Lower the per-generation limits, clamped to
    /// `[REKEY_MIN_*, REKEY_MAX_*]`.  They apply to both directions: the
    /// transmit side rekeys at them and the receive side refuses a peer that
    /// passes them, so both ends of a link must use the same values.
    pub fn set_rekey_limits(&mut self, records: u32, bytes: u64) {
        self.rekey_records = records.clamp(REKEY_MIN_RECORDS, REKEY_MAX_RECORDS);
        self.rekey_bytes = bytes.clamp(REKEY_MIN_BYTES, REKEY_MAX_BYTES);
    }

    /// The **only** way to reach `Established`, so `AEAD_SESSIONS` cannot
    /// drift from the number of live established links.
    ///
    /// Both callers below have already checked they are in a pre-`Established`
    /// state (`AwaitPeerHello` / `AwaitConfirm`), and every transition out of
    /// `Established` goes through `deregister` — so increments and decrements
    /// pair exactly one-to-one.
    fn mark_established(&mut self) {
        // Guard rather than `debug_assert!`: an assert here would be a
        // reachable panic in a non-release build, and `panic = "abort"` on a
        // robot means a board reset. More to the point, a double increment is
        // the mirror of the underflow guarded in `deregister` — one decrement
        // would then leave the count permanently non-zero and the gate
        // permanently OPEN. Refusing to double-count is the fail-closed
        // choice, and it costs a compare on a path that runs once per
        // connection.
        if self.state == HandshakeState::Established {
            return;
        }
        self.state = HandshakeState::Established;
        AEAD_SESSIONS.fetch_add(1, Ordering::AcqRel);
    }

    /// Drop this link's registration if it holds one.  Must run BEFORE
    /// `state` is overwritten, or the check reads the new state and the
    /// count never comes down — which under `link-encrypt-enforced` would
    /// leave `envelope_frame_permitted()` stuck at `true` after the session
    /// ended. That is fail-OPEN.
    fn deregister(&mut self) {
        if self.state == HandshakeState::Established {
            // `saturating_sub`, not `fetch_sub`: an unbalanced decrement on a
            // `usize` wraps to `usize::MAX` silently (no panic even with
            // `overflow-checks = true`, because atomics don't get the checked
            // lowering), and a saturated-high counter reads as "a session is
            // active" forever. The pairing is provable from the state guards,
            // so this should be unreachable — but of the two ways to be
            // wrong, only one leaves the gate wedged open.
            let _ = AEAD_SESSIONS.fetch_update(
                Ordering::AcqRel, Ordering::Acquire,
                |n| Some(n.saturating_sub(1)));
        }
    }

    /// Terminal handshake failure: nothing to seal, everything wiped.
    fn reject_handshake(&mut self) {
        self.deregister();
        self.state = HandshakeState::Rejected;
        secure_zero(&mut self.eph_priv);
        self.tx.wipe();
        self.rx.wipe();
        self.keyed = false;
        self.tx_open = false;
    }

    /// Terminal receive-side violation.  The receive keys go; the transmit
    /// keys stay so [`EncryptLink::seal_reject`] can answer once.
    fn fail_rx(&mut self, e: RecordError) -> RecordError {
        self.deregister();
        self.state = HandshakeState::Rejected;
        self.rx.wipe();
        self.rx_in_message = false;
        self.rx_message_len = 0;
        e
    }

    /// X25519 + generation-0 keys + session id.  Wipes the private key and
    /// the shared secret.  `false` for a small-order peer point.
    fn derive_session(&mut self, peer: &[u8; EPH_PUB_BYTES], initiator: bool) -> bool {
        let mut shared = match x25519::x25519_checked(&self.eph_priv, peer) {
            Some(s) => s,
            None => return false,
        };
        self.peer_pub = *peer;
        let (tx_label, rx_label) = if initiator {
            // We spoke first → transmit C2S, receive S2C.
            (DIR_C2S, DIR_S2C)
        } else {
            (DIR_S2C, DIR_C2S)
        };
        self.tx.install(&shared, tx_label);
        self.rx.install(&shared, rx_label);
        self.session_id = if initiator {
            session_id(&self.eph_pub, peer)
        } else {
            session_id(peer, &self.eph_pub)
        };
        secure_zero(&mut shared);
        secure_zero(&mut self.eph_priv);
        self.keyed = true;
        self.tx_open = true;
        true
    }

    // ── Initiator path ────────────────────────────────────────────

    /// Initiator step 1.  Write HELLO into `out`, advance to
    /// `AwaitPeerHello`.
    pub fn start_initiator(&mut self, out: &mut [u8; HELLO_INIT_BYTES])
        -> Result<usize, HandshakeError>
    {
        if self.state != HandshakeState::Init { return Err(HandshakeError::BadState); }
        out[0] = MODE_ENCRYPTED;
        out[1] = LABEL_HELLO;
        out[2..2 + EPH_PUB_BYTES].copy_from_slice(&self.eph_pub);
        self.state = HandshakeState::AwaitPeerHello;
        Ok(HELLO_INIT_BYTES)
    }

    /// Initiator step 2.  Parse the responder's HELLO+proof (or its REJECT),
    /// verify, write CONFIRM into `out`.
    pub fn handle_peer_hello(&mut self, frame: &[u8],
                             out: &mut [u8; CONFIRM_BYTES])
        -> Result<usize, HandshakeError>
    {
        if self.state != HandshakeState::AwaitPeerHello {
            return Err(HandshakeError::BadState);
        }
        if let Err(e) = check_handshake_frame(frame, HELLO_REPLY_BYTES, LABEL_HELLO) {
            self.reject_handshake();
            return Err(e);
        }
        let mut peer = [0u8; EPH_PUB_BYTES];
        peer.copy_from_slice(&frame[2..2 + EPH_PUB_BYTES]);
        let proof_r = &frame[2 + EPH_PUB_BYTES..];
        let expected = proof_responder(&self.psk, &self.eph_pub, &peer);
        if !ct_eq(&expected, proof_r) {
            self.reject_handshake();
            return Err(HandshakeError::ProofMismatch);
        }
        if ct_eq(&peer, &self.eph_pub) || !self.derive_session(&peer, true) {
            self.reject_handshake();
            return Err(HandshakeError::BadPeerKey);
        }
        let proof_i = proof_initiator(&self.psk, &peer, &self.eph_pub);
        out[0] = MODE_ENCRYPTED;
        out[1] = LABEL_CONFIRM;
        out[2..2 + PROOF_BYTES].copy_from_slice(&proof_i);
        self.mark_established();
        Ok(CONFIRM_BYTES)
    }

    // ── Responder path ────────────────────────────────────────────

    /// Responder step 1.  Process initiator's HELLO, write HELLO+proof
    /// reply.
    pub fn handle_initiator_hello(&mut self, frame: &[u8],
                                  out: &mut [u8; HELLO_REPLY_BYTES])
        -> Result<usize, HandshakeError>
    {
        if self.state != HandshakeState::Init {
            return Err(HandshakeError::BadState);
        }
        if let Err(e) = check_handshake_frame(frame, HELLO_INIT_BYTES, LABEL_HELLO) {
            self.reject_handshake();
            return Err(e);
        }
        let mut peer = [0u8; EPH_PUB_BYTES];
        peer.copy_from_slice(&frame[2..2 + EPH_PUB_BYTES]);
        // We answered → we are the crypto responder → we transmit on S2C
        // and receive on C2S. This is the kernel's path.
        //
        // NOTE: `peer` is UNAUTHENTICATED here — the PSK proof exchange has
        // not happened yet — so this is where a small-order point, or our
        // own key reflected back, would be injected. Both are terminal
        // `Rejected`; falling through would send a proof and sit in
        // `AwaitConfirm` holding all-zero session keys.
        if ct_eq(&peer, &self.eph_pub) || !self.derive_session(&peer, false) {
            self.reject_handshake();
            return Err(HandshakeError::BadPeerKey);
        }
        let proof_r = proof_responder(&self.psk, &peer, &self.eph_pub);
        out[0] = MODE_ENCRYPTED;
        out[1] = LABEL_HELLO;
        out[2..2 + EPH_PUB_BYTES].copy_from_slice(&self.eph_pub);
        out[2 + EPH_PUB_BYTES..].copy_from_slice(&proof_r);
        self.state = HandshakeState::AwaitConfirm;
        Ok(HELLO_REPLY_BYTES)
    }

    /// Responder step 2.  Verify the initiator's CONFIRM proof (or take its
    /// REJECT).
    pub fn handle_initiator_confirm(&mut self, frame: &[u8])
        -> Result<(), HandshakeError>
    {
        if self.state != HandshakeState::AwaitConfirm {
            return Err(HandshakeError::BadState);
        }
        if let Err(e) = check_handshake_frame(frame, CONFIRM_BYTES, LABEL_CONFIRM) {
            self.reject_handshake();
            return Err(e);
        }
        let proof_i = &frame[2..2 + PROOF_BYTES];
        let expected = proof_initiator(&self.psk, &self.eph_pub, &self.peer_pub);
        if !ct_eq(&expected, proof_i) {
            self.reject_handshake();
            return Err(HandshakeError::ProofMismatch);
        }
        self.mark_established();
        Ok(())
    }

    // ── Record layer ──────────────────────────────────────────────

    /// Seal `msg` as one message: an optional REKEY record, then
    /// `records_for(msg.len())` data records.  `nonce_rand` is called once
    /// per record for its 8-byte nonce prefix.  Returns the bytes written.
    ///
    /// Size `out` with [`sealed_len_max`].  On `Err` nothing was written
    /// that the caller should send and no state changed.
    pub fn seal_message<F: FnMut() -> [u8; 8]>(&mut self, msg: &[u8], mut nonce_rand: F,
                                               out: &mut [u8])
        -> Result<usize, SealError>
    {
        if self.state != HandshakeState::Established {
            return Err(SealError::NotEstablished);
        }
        if msg.len() > MAX_MESSAGE_BYTES {
            return Err(SealError::MessageTooLarge);
        }
        let k = records_for(msg.len());
        let rekey = self.rekey_requested
            || self.tx.gen_records as u64 + k as u64 + 1 > self.rekey_records as u64
            || self.tx.gen_bytes + msg.len() as u64 > self.rekey_bytes;
        let n = k + rekey as usize;
        if out.len() < n * ENC_OVERHEAD + msg.len() {
            return Err(SealError::BufferTooSmall);
        }
        // Counters used: counter .. counter+n-1, each below u32::MAX (the
        // receiver never accepts u32::MAX).
        if self.tx.counter as u64 + n as u64 > u32::MAX as u64 {
            return Err(SealError::CounterExhausted);
        }
        let mut off = 0usize;
        if rekey {
            off += self.tx.seal_record(RECORD_FLAG_REKEY, &[], &nonce_rand(), &mut out[off..]);
            self.tx.ratchet();
            self.rekey_requested = false;
        }
        for i in 0..k {
            let start = i * ENC_MAX_PAYLOAD;
            let end = if start + ENC_MAX_PAYLOAD < msg.len() { start + ENC_MAX_PAYLOAD } else { msg.len() };
            let flags = if i + 1 < k { RECORD_FLAG_MORE } else { 0 };
            off += self.tx.seal_record(flags, &msg[start..end], &nonce_rand(), &mut out[off..]);
        }
        Ok(off)
    }

    /// Seal one authenticated REJECT record and end the session.  Valid while
    /// established, or once after a receive-side violation.  Returns the
    /// bytes written (0 if there is nothing left to seal with or `out` is
    /// shorter than [`ENC_OVERHEAD`]).  The caller sends them and closes.
    pub fn seal_reject(&mut self, nonce_rand: &[u8; 8], out: &mut [u8]) -> usize {
        if !self.keyed || !self.tx_open {
            return 0;
        }
        if self.state != HandshakeState::Established && self.state != HandshakeState::Rejected {
            return 0;
        }
        let n = self.tx.seal_record(RECORD_FLAG_REJECT, &[], nonce_rand, out);
        self.deregister();
        self.state = HandshakeState::Rejected;
        self.tx.wipe();
        self.rx.wipe();
        self.tx_open = false;
        n
    }

    /// Open the first record in `buf`, writing any payload to the front of
    /// `out`.
    ///
    /// Loop over a TCP byte stream with this, advancing by `consumed`; on
    /// `Err(Incomplete)` keep the unconsumed tail and wait for more bytes.
    /// Payloads of `Data { more: true }` records concatenate with the next
    /// records' up to the `more: false` one, which completes the message.
    /// Any error with [`RecordError::is_terminal`] ends the session: stop
    /// reading, optionally [`EncryptLink::seal_reject`], close.
    pub fn open_record(&mut self, buf: &[u8], out: &mut [u8]) -> Result<Opened, RecordError> {
        if self.state != HandshakeState::Established {
            return Err(RecordError::NotEstablished);
        }
        let (flags, len) = match parse_record_header(buf) {
            Ok(v) => v,
            Err(RecordError::Incomplete) => return Err(RecordError::Incomplete),
            Err(e) => return Err(self.fail_rx(e)),
        };
        let ct_end = RECORD_HEADER_BYTES + len;
        let total = ct_end + ENC_HMAC_SIZE;
        if buf.len() < total {
            return Err(RecordError::Incomplete);
        }
        let tag = hmac_sha256(&self.rx.mac, &[&buf[..ct_end]]);
        if !ct_eq(&tag, &buf[ct_end..total]) {
            return Err(self.fail_rx(RecordError::BadMac));
        }
        let counter = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if counter != self.rx.counter || counter == u32::MAX {
            return Err(self.fail_rx(RecordError::BadCounter));
        }
        if self.rx.gen_records >= self.rekey_records {
            return Err(self.fail_rx(RecordError::RekeyOverdue));
        }
        match flags {
            RECORD_FLAG_REJECT => {
                self.deregister();
                self.state = HandshakeState::Rejected;
                self.tx.wipe();
                self.rx.wipe();
                self.tx_open = false;
                Err(RecordError::PeerRejected)
            }
            RECORD_FLAG_REKEY => {
                if self.rx_in_message {
                    return Err(self.fail_rx(RecordError::UnexpectedRekey));
                }
                self.rx.counter += 1;
                self.rx.ratchet();
                Ok(Opened { kind: RecordKind::Rekey, consumed: total })
            }
            _ => {
                if self.rx.gen_bytes + len as u64 > self.rekey_bytes {
                    return Err(self.fail_rx(RecordError::RekeyOverdue));
                }
                let msg_len = self.rx_message_len + len;
                if msg_len > MAX_MESSAGE_BYTES {
                    return Err(self.fail_rx(RecordError::MessageTooLarge));
                }
                if out.len() < len {
                    return Err(self.fail_rx(RecordError::BufferTooSmall));
                }
                let mut nonce = [0u8; ENC_NONCE_SIZE];
                nonce.copy_from_slice(&buf[..ENC_NONCE_SIZE]);
                out[..len].copy_from_slice(&buf[RECORD_HEADER_BYTES..ct_end]);
                Aes128::new(&self.rx.enc).ctr_decrypt(&nonce, &mut out[..len]);
                self.rx.counter += 1;
                self.rx.gen_records += 1;
                self.rx.gen_bytes += len as u64;
                let more = flags == RECORD_FLAG_MORE;
                self.rx_in_message = more;
                self.rx_message_len = if more { msg_len } else { 0 };
                Ok(Opened { kind: RecordKind::Data { len, more }, consumed: total })
            }
        }
    }

    // ── Single-record calls (no rekey, no counter check) ──────────

    /// Seal `plaintext` as one flags-zero record under the current transmit
    /// generation.  Returns the wire byte count, 0 on failure.
    ///
    /// Does not rekey: a peer that enforces the generation limits closes the
    /// session once this has sealed [`REKEY_MAX_RECORDS`] records.  Use
    /// [`EncryptLink::seal_message`] on a live link.
    pub fn encrypt(&mut self, plaintext: &[u8],
                   nonce_rand: &[u8; 8],
                   out: &mut [u8]) -> usize
    {
        if !self.is_established() { return 0; }
        self.tx.seal_record(0, plaintext, nonce_rand, out)
    }

    /// Verify and decrypt the first flags-zero record in `buf` under the
    /// current receive generation, returning `(plaintext_len, consumed)`;
    /// `(0, 0)` on failure, a torn record, or any flagged record.
    ///
    /// Keeps no state: no counter check (a replayed record decrypts again),
    /// no REKEY, no reassembly.  A stream reader on a live link uses
    /// [`EncryptLink::open_record`].
    ///
    /// TCP hands you a byte stream, so two records sent separately routinely
    /// arrive in one `recv()`; loop on `consumed` rather than decrypting only
    /// the first — the brain sends `PKT_ESTOP` (0x88) once, unacknowledged.
    pub fn decrypt_consuming(&self, buf: &[u8], plaintext_out: &mut [u8])
        -> (usize, usize)
    {
        if !self.is_established() { return (0, 0); }
        let len = match parse_record_header(buf) {
            Ok((0, len)) => len,
            _ => return (0, 0),
        };
        let ct_end = RECORD_HEADER_BYTES + len;
        let total = ct_end + ENC_HMAC_SIZE;
        if buf.len() < total || plaintext_out.len() < len { return (0, 0); }
        let tag = hmac_sha256(&self.rx.mac, &[&buf[..ct_end]]);
        if !ct_eq(&tag, &buf[ct_end..total]) { return (0, 0); }
        let mut nonce = [0u8; ENC_NONCE_SIZE];
        nonce.copy_from_slice(&buf[..ENC_NONCE_SIZE]);
        plaintext_out[..len].copy_from_slice(&buf[RECORD_HEADER_BYTES..ct_end]);
        Aes128::new(&self.rx.enc).ctr_decrypt(&nonce, &mut plaintext_out[..len]);
        (len, total)
    }

    /// Decrypt `frame` into `plaintext_out`.  Returns plaintext length
    /// or 0 on failure.  Lossy on a coalesced buffer — see
    /// [`EncryptLink::decrypt_consuming`].
    pub fn decrypt(&self, frame: &[u8], plaintext_out: &mut [u8]) -> usize {
        self.decrypt_consuming(frame, plaintext_out).0
    }

    /// Every secret byte the link holds, for tests that check what a rekey
    /// or a terminal event leaves behind: ephemeral private key, then
    /// transmit chain/enc/mac, then receive chain/enc/mac.
    #[cfg(feature = "key-introspection")]
    pub fn key_material(&self) -> [u8; KEY_MATERIAL_BYTES] {
        let mut out = [0u8; KEY_MATERIAL_BYTES];
        let mut off = 0;
        for part in [&self.eph_priv[..], &self.tx.chain[..], &self.tx.enc[..], &self.tx.mac[..],
                     &self.rx.chain[..], &self.rx.enc[..], &self.rx.mac[..]] {
            out[off..off + part.len()].copy_from_slice(part);
            off += part.len();
        }
        out
    }
}

/// Size of [`EncryptLink::key_material`].
#[cfg(feature = "key-introspection")]
pub const KEY_MATERIAL_BYTES: usize = 32 + 2 * (32 + AES_KEY_SIZE + AES_KEY_SIZE);

/// Common handshake-frame checks: a REJECT frame, then length, then header.
fn check_handshake_frame(frame: &[u8], len: usize, label: u8) -> Result<(), HandshakeError> {
    if is_reject_frame(frame) {
        return Err(HandshakeError::PeerRejected);
    }
    if frame.len() != len {
        return Err(HandshakeError::BadFrameLength);
    }
    if frame[0] != MODE_ENCRYPTED || frame[1] != label {
        return Err(HandshakeError::BadHeader);
    }
    Ok(())
}

/// Wipe every secret this channel holds.
///
/// `EncryptLink` is constructed per TCP connection and dropped on every
/// disconnect (`link = None` in the kernel's brain loop), so without this
/// each reconnect leaves another copy of the *pre-shared* key — the one
/// secret in the system that never rotates — and the session keys in
/// released memory.
impl Drop for EncryptLink {
    fn drop(&mut self) {
        self.deregister();
        secure_zero(&mut self.psk);
        secure_zero(&mut self.eph_priv);
        secure_zero(&mut self.peer_pub);
        self.tx.wipe();
        self.rx.wipe();
        self.state = HandshakeState::Rejected;
    }
}

// Re-export the X25519 pubkey helper so callers / tests don't need to
// pull the crypto crate.
pub use x25519::x25519_pubkey;
