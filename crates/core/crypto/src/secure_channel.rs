// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Secure channel — encrypted brain↔robot protocol (F07.4/F07.5).
//!
//! Wraps the binary brain protocol in AES-128-CTR encryption with
//! SHA-256 HMAC for integrity. Key agreement via X25519.
//!
//! ## Handshake (simplified PSK + ECDH)
//!
//! 1. Robot → Brain: `HELLO` + robot_public_key (32 bytes)
//! 2. Brain → Robot: `HELLO` + brain_public_key (32 bytes)
//! 3. Both compute: shared_secret = X25519(my_private, their_public)
//! 4. Derive four keys — one (enc, mac) pair **per direction**:
//!      enc_c2s = SHA-256(shared_secret || "ENC" || "C2S")[0..16]
//!      mac_c2s = SHA-256(shared_secret || "MAC" || "C2S")[0..16]
//!      enc_s2c = SHA-256(shared_secret || "ENC" || "S2C")[0..16]
//!      mac_s2c = SHA-256(shared_secret || "MAC" || "S2C")[0..16]
//! 5. All subsequent packets: AES-CTR(tx enc_key, nonce) + HMAC(tx mac_key)
//!
//! ## Direction labels — read this before touching the KDF
//!
//! `C` and `S` name **crypto handshake roles**, not TCP roles, and in this
//! system the two are swapped. The kernel is the TCP *client* (it dials the
//! brain) but the crypto *responder*; the brain is the TCP server but the
//! crypto initiator (`AzOSRobotBrain/protocol.py` calls `start_handshake`,
//! `kernel/src/tasks/brain_link.rs` calls `brain_responder_handshake`). So:
//!
//! ```text
//!   C2S  =  initiator → responder  =  brain → kernel
//!   S2C  =  responder → initiator  =  kernel → brain
//! ```
//!
//! Getting this backwards produces a channel that fails closed (nothing
//! decrypts), not one that is subtly weak — but it will look like a network
//! bug, so the mapping is spelled out here rather than left to inference.
//!
//! ## Encrypted packet format
//!
//! ```text
//! Offset  Size  Field
//! 0x00    12    Nonce (random 8 bytes + 4-byte counter)
//! 0x0C    2     Encrypted payload length (LE)
//! 0x0E    N     Encrypted payload (AES-128-CTR)
//! 0x0E+N  32    HMAC-SHA-256 over [nonce || length || ciphertext]
//! ```

use crate::sha256::{Sha256, Digest};
use crate::aes::{Aes128, AES_KEY_SIZE};
use crate::ct::{ct_eq, secure_zero};
use crate::x25519;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Nonce size for AES-CTR (12 bytes: 8 random + 4 counter).
pub const NONCE_SIZE: usize = 12;

/// HMAC tag size (SHA-256 output).
pub const HMAC_SIZE: usize = 32;

/// Overhead per encrypted packet: nonce + length + HMAC.
pub const PACKET_OVERHEAD: usize = NONCE_SIZE + 2 + HMAC_SIZE;

/// Maximum plaintext payload size.
pub const MAX_PAYLOAD_SIZE: usize = 2048;

/// Handshake magic byte.
pub const HANDSHAKE_HELLO: u8 = 0x48; // 'H'

/// Key derivation label for encryption key.
const KDF_LABEL_ENC: &[u8] = b"ENC";
/// Key derivation label for MAC key.
const KDF_LABEL_MAC: &[u8] = b"MAC";

/// Direction label: initiator → responder (brain → kernel).
const KDF_DIR_C2S: &[u8] = b"C2S";
/// Direction label: responder → initiator (kernel → brain).
const KDF_DIR_S2C: &[u8] = b"S2C";

// ---------------------------------------------------------------------------
// Secure Channel State
// ---------------------------------------------------------------------------

/// State of the secure channel.
#[derive(Clone, Copy, PartialEq)]
pub enum ChannelState {
    /// No handshake performed yet.
    Init,
    /// Handshake complete, keys derived.
    Established,
}

/// Which half of the handshake this channel is playing.
///
/// See the module-level "Direction labels" note: this is the **crypto**
/// role, which is the inverse of the TCP role in this system. The kernel
/// is `Responder`; the Python brain is `Initiator`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Sends the first HELLO. Transmits on C2S, receives on S2C.
    Initiator,
    /// Answers the first HELLO. Transmits on S2C, receives on C2S.
    Responder,
}

/// Secure channel context.
pub struct SecureChannel {
    /// Channel state.
    pub state: ChannelState,
    /// Our private key (32 bytes).
    private_key: [u8; 32],
    /// Our public key (32 bytes).
    pub public_key: [u8; 32],
    /// Peer's public key (32 bytes).
    peer_public_key: [u8; 32],
    /// Encryption key for frames **we send** (16 bytes for AES-128).
    tx_enc_key: [u8; AES_KEY_SIZE],
    /// MAC key for frames **we send** (16 bytes).
    tx_mac_key: [u8; AES_KEY_SIZE],
    /// Encryption key for frames **we receive** (16 bytes).
    rx_enc_key: [u8; AES_KEY_SIZE],
    /// MAC key for frames **we receive** (16 bytes).
    rx_mac_key: [u8; AES_KEY_SIZE],
    /// Send nonce counter (incremented per packet).
    tx_counter: u32,
}

impl SecureChannel {
    /// Create a new secure channel with the given private key.
    pub fn new(private_key: [u8; 32]) -> Self {
        let public_key = x25519::x25519_pubkey(&private_key);
        Self {
            state: ChannelState::Init,
            private_key,
            public_key,
            peer_public_key: [0u8; 32],
            tx_enc_key: [0u8; AES_KEY_SIZE],
            tx_mac_key: [0u8; AES_KEY_SIZE],
            rx_enc_key: [0u8; AES_KEY_SIZE],
            rx_mac_key: [0u8; AES_KEY_SIZE],
            tx_counter: 0,
        }
    }

    /// Complete the handshake with the peer's public key, deriving a
    /// **separate** (enc, mac) key pair for each direction of travel.
    ///
    /// Returns `false` — leaving `state` at whatever it was, keys untouched
    /// and all-zero — when the X25519 shared secret degenerates to zero
    /// (see [`x25519::x25519_checked`]). Callers **must** check the return
    /// and move to a terminal rejected state; a channel left in an
    /// intermediate state after a `false` here would be one whose keys are
    /// all zeros.
    ///
    /// ## Why direction separation is not optional
    ///
    /// Previously both peers derived one `enc_key`/`mac_key` pair and used
    /// it in both directions. A frame the kernel *sent* was therefore a
    /// cryptographically valid frame *inbound* at the kernel: the MAC only
    /// proved "someone holding the session key produced these bytes", never
    /// "the brain produced these bytes". An attacker who can echo TCP
    /// segments — no key required — could reflect the kernel's own traffic
    /// back at it and have it verify.
    ///
    /// That was not exploitable in practice only because the brain→kernel
    /// packet types (`0x80`/`0x83`/`0x88`) and the kernel→brain types
    /// (`0x01`/`0x02`/`0x03`) happen to be disjoint, so the dispatcher
    /// dropped a reflected frame after authenticating it. A naming
    /// convention in a different crate was holding a cryptographic flaw
    /// closed. Binding the direction into the KDF closes it here, where it
    /// belongs: a reflected frame now fails the MAC check, because the
    /// kernel verifies inbound frames with `mac_c2s` and only ever produces
    /// `mac_s2c`.
    ///
    /// **Wire-format change.** `AzOSRobotBrain/secure_channel.py::_derive_keys`
    /// must derive the same four keys and pick the mirrored pair.
    #[must_use]
    pub fn handshake_directional(&mut self, peer_public_key: &[u8; 32],
                                 role: Role) -> bool {
        // Compute shared secret via X25519, rejecting small-order peer
        // points (all-zero product) — the peer key is unauthenticated at
        // this point on the responder path.
        let shared_secret = match x25519::x25519_checked(&self.private_key,
                                                        peer_public_key) {
            Some(s) => s,
            None => return false,
        };

        self.peer_public_key = *peer_public_key;

        // Derive all four keys, then bind them to tx/rx by role. Deriving
        // both directions unconditionally (rather than only the two we
        // need) keeps the KDF a pure function of (shared_secret) and makes
        // the role affect only which pair lands in tx vs rx — so an
        // initiator and a responder that agree on the shared secret cannot
        // disagree about key *values*, only about which is which.
        let mut enc_c2s = [0u8; AES_KEY_SIZE];
        let mut mac_c2s = [0u8; AES_KEY_SIZE];
        let mut enc_s2c = [0u8; AES_KEY_SIZE];
        let mut mac_s2c = [0u8; AES_KEY_SIZE];
        kdf(&shared_secret, KDF_LABEL_ENC, KDF_DIR_C2S, &mut enc_c2s);
        kdf(&shared_secret, KDF_LABEL_MAC, KDF_DIR_C2S, &mut mac_c2s);
        kdf(&shared_secret, KDF_LABEL_ENC, KDF_DIR_S2C, &mut enc_s2c);
        kdf(&shared_secret, KDF_LABEL_MAC, KDF_DIR_S2C, &mut mac_s2c);

        match role {
            Role::Initiator => {
                self.tx_enc_key = enc_c2s;
                self.tx_mac_key = mac_c2s;
                self.rx_enc_key = enc_s2c;
                self.rx_mac_key = mac_s2c;
            }
            Role::Responder => {
                self.tx_enc_key = enc_s2c;
                self.tx_mac_key = mac_s2c;
                self.rx_enc_key = enc_c2s;
                self.rx_mac_key = mac_c2s;
            }
        }

        // Wipe the scratch copies and the shared secret: they are as
        // sensitive as the session keys and would otherwise sit in this
        // (deep, boot-time) stack frame indefinitely.
        secure_zero(&mut enc_c2s);
        secure_zero(&mut mac_c2s);
        secure_zero(&mut enc_s2c);
        secure_zero(&mut mac_s2c);
        let mut shared_secret = shared_secret;
        secure_zero(&mut shared_secret);

        self.state = ChannelState::Established;
        self.tx_counter = 0;
        true
    }

    /// Legacy single-argument handshake — **hardcodes [`Role::Initiator`]**.
    ///
    /// Kept so out-of-lane callers (`domains/robot/bench/src/crypto.rs`) keep
    /// compiling. It is deliberately *not* a restoration of the old
    /// non-directional KDF: if two peers both end up here they both claim
    /// the initiator direction, so neither can decrypt the other and the
    /// channel fails **closed**. The old behaviour would have failed open,
    /// silently reinstating the reflection flaw described on
    /// [`SecureChannel::handshake_directional`].
    ///
    /// New code must call `handshake_directional` with an explicit role.
    /// `domains/robot/bench` should pass `Role::Initiator` / `Role::Responder` to
    /// its two halves so its per-packet benches measure the success path
    /// again rather than the MAC-reject path.
    pub fn handshake(&mut self, peer_public_key: &[u8; 32]) -> bool {
        self.handshake_directional(peer_public_key, Role::Initiator)
    }

    /// Encrypt a plaintext payload into the output buffer.
    ///
    /// Returns the total encrypted packet size, or 0 on error.
    /// `nonce_rand`: 8 bytes of randomness for the nonce.
    pub fn encrypt(&mut self, plaintext: &[u8], nonce_rand: &[u8; 8],
                   out: &mut [u8]) -> usize {
        if self.state != ChannelState::Established { return 0; }
        if plaintext.len() > MAX_PAYLOAD_SIZE { return 0; }

        let total = NONCE_SIZE + 2 + plaintext.len() + HMAC_SIZE;
        if out.len() < total { return 0; }

        // Build nonce: 8 random bytes + 4-byte counter.
        // The counter MUST NOT wrap — AES-CTR reuses the keystream block at
        // (key, nonce), so a repeated (nonce_rand, tx_counter) pair leaks
        // plaintext via XOR. At u32::MAX we refuse to encrypt further; the
        // peer must establish a new session (which resets `tx_counter` to 0
        // with fresh keys per `establish`).
        if self.tx_counter == u32::MAX {
            return 0;
        }
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..8].copy_from_slice(nonce_rand);
        nonce[8..12].copy_from_slice(&self.tx_counter.to_le_bytes());
        self.tx_counter += 1;

        // Write nonce
        out[..NONCE_SIZE].copy_from_slice(&nonce);

        // Write length (LE)
        let len_bytes = (plaintext.len() as u16).to_le_bytes();
        out[NONCE_SIZE..NONCE_SIZE + 2].copy_from_slice(&len_bytes);

        // Encrypt payload with AES-128-CTR
        let ct_start = NONCE_SIZE + 2;
        let ct_end = ct_start + plaintext.len();
        out[ct_start..ct_end].copy_from_slice(plaintext);
        let aes = Aes128::new(&self.tx_enc_key);
        // Use first 12 bytes of nonce for CTR
        aes.ctr_encrypt(&nonce, &mut out[ct_start..ct_end]);

        // Compute HMAC over [nonce || length || ciphertext]
        let hmac = hmac_sha256(&self.tx_mac_key, &out[..ct_end]);
        out[ct_end..ct_end + HMAC_SIZE].copy_from_slice(&hmac);

        total
    }

    /// Decrypt the **first** AEAD frame in `packet`, reporting how many
    /// bytes that frame occupied so the caller can loop over a buffer that
    /// holds more than one.
    ///
    /// Returns `(plaintext_len, consumed)`; `(0, 0)` on any failure —
    /// not established, truncated frame, oversized length field, undersized
    /// output buffer, or MAC mismatch. `consumed` is always the exact wire
    /// size of the frame just verified, never `packet.len()`.
    ///
    /// ## Why this exists (safety-critical)
    ///
    /// TCP is a byte stream: `send()` boundaries are not `recv()`
    /// boundaries. Two AEAD frames written by two separate brain sends
    /// routinely arrive in one `recv()`. The old length check was
    /// `packet.len() < expected_total`, i.e. "at least one frame's worth" —
    /// so `decrypt` HMAC'd `packet[..ct_end]` (exactly frame 1), verified,
    /// returned frame 1's payload, and **discarded every remaining byte
    /// with no error, no return-value signal and no log**.
    ///
    /// The kernel already has a coalescing loop, but it sits one layer
    /// further in — it re-parses `recv_buf` for multiple *brain-protocol*
    /// packets after the envelope is stripped. Bytes dropped here never
    /// reach it. A `PKT_ESTOP` (0x88, emergency stop) coalesced behind any
    /// other command was therefore silently lost, and the brain sends ESTOP
    /// exactly once with no ack and no retransmit
    /// (`AzOSRobotBrain/server.py`, `AzOSRobotBrain/api.py`). This is the K-C3/C4
    /// dropped-coalesced-frame bug reappearing one layer out, on the
    /// emergency-stop path.
    ///
    /// Note that returning `(len, consumed)` only *enables* the fix; the
    /// gap is not closed until the caller actually loops on `consumed`.
    ///
    /// ## There is NO anti-replay here, on purpose (K-C5)
    ///
    /// This function keeps no receive-side counter and no nonce window. A
    /// captured frame replayed inside the *same* live session decrypts and
    /// verifies every time. The replay defence for the brain link lives one
    /// layer in, at `behavior::auth_envelope`'s `HIGHEST_RX_NONCE`
    /// high-water mark — do not delete that on the assumption that "the AEAD
    /// handles replay".
    ///
    /// What the AEAD *does* give is **cross-session** replay rejection, for
    /// free and without any state: each connection derives fresh session keys
    /// from fresh ephemeral X25519 keys, so a frame from a previous session
    /// fails the `rx_mac_key` check below. That is what makes requiring
    /// encrypted mode a real answer to the reboot-resets-the-watermark hole,
    /// rather than a restatement of it.
    ///
    /// Adding a strict-monotonic counter check here was considered and
    /// rejected twice over: it needs interior mutability (this takes `&self`,
    /// and `kernel/src/tasks/brain_link.rs` holds the link behind `Option::as_ref`), and
    /// the brain resets `_tx_counter` to 0 on rekey
    /// (`AzOSRobotBrain/secure_channel.py`), so it would reject every frame
    /// after the first rekey. Rekey is dormant today, which makes that a
    /// landmine rather than a bug.
    pub fn decrypt_consuming(&self, packet: &[u8], plaintext_out: &mut [u8])
        -> (usize, usize)
    {
        if self.state != ChannelState::Established { return (0, 0); }
        if packet.len() < PACKET_OVERHEAD { return (0, 0); }

        // Parse nonce
        let nonce: [u8; NONCE_SIZE] = {
            let mut n = [0u8; NONCE_SIZE];
            n.copy_from_slice(&packet[..NONCE_SIZE]);
            n
        };

        // Parse length
        let payload_len = u16::from_le_bytes([
            packet[NONCE_SIZE], packet[NONCE_SIZE + 1]
        ]) as usize;

        // Bound the attacker-controlled length field BEFORE it is used in
        // any arithmetic, so `ct_end`/`expected_total` cannot be pushed
        // anywhere near overflow. `payload_len` is at most 0xFFFF from a
        // u16 anyway; this narrows it to MAX_PAYLOAD_SIZE.
        if payload_len > MAX_PAYLOAD_SIZE { return (0, 0); }

        let ct_start = NONCE_SIZE + 2;
        let ct_end = ct_start + payload_len;
        let expected_total = ct_end + HMAC_SIZE;

        // A short buffer is a torn frame, not a bad frame: the caller has
        // not received the whole thing yet. We still report failure (we
        // cannot verify what we do not have), but the caller can tell the
        // two apart by comparing `packet.len()` to nothing being consumed.
        if packet.len() < expected_total { return (0, 0); }
        if plaintext_out.len() < payload_len { return (0, 0); }

        // Verify HMAC with the RECEIVE mac key. Using a direction-specific
        // key here is what makes a reflected copy of one of our own frames
        // fail: we sign with tx_mac_key and verify with rx_mac_key.
        let expected_hmac = hmac_sha256(&self.rx_mac_key, &packet[..ct_end]);
        let packet_hmac = &packet[ct_end..ct_end + HMAC_SIZE];
        if !ct_eq(&expected_hmac, packet_hmac) {
            return (0, 0); // integrity check failed
        }

        // Decrypt
        plaintext_out[..payload_len].copy_from_slice(&packet[ct_start..ct_end]);
        let aes = Aes128::new(&self.rx_enc_key);
        aes.ctr_decrypt(&nonce, &mut plaintext_out[..payload_len]);

        (payload_len, expected_total)
    }

    /// Decrypt one AEAD frame. Returns plaintext length, or 0 on error.
    ///
    /// Thin wrapper over [`SecureChannel::decrypt_consuming`] that throws
    /// the consumed-byte count away. It is therefore **still lossy on a
    /// coalesced buffer** — deliberately so: making this function reject
    /// `packet.len() != expected_total` would turn today's "frame 1
    /// delivered, frame 2 lost" into "both lost", a regression on the
    /// ESTOP path for as long as any caller has not migrated. Callers
    /// reading from a TCP stream must use `decrypt_consuming` in a loop.
    pub fn decrypt(&self, packet: &[u8], plaintext_out: &mut [u8]) -> usize {
        self.decrypt_consuming(packet, plaintext_out).0
    }
}

/// Zero every byte of key material this channel holds.
///
/// `private_key` and the four session keys are the whole security of the
/// link; leaving them in a freed stack slot or heap block after the channel
/// is torn down (which happens on *every* TCP reconnect — see
/// `link = None` in the kernel's brain loop) hands them to whatever reads
/// that memory next. `secure_zero` uses volatile writes so the optimiser
/// may not treat these as dead stores, which it otherwise would: nothing
/// reads these fields again.
///
/// `peer_public_key` and `public_key` are public values and are wiped only
/// for uniformity, not secrecy.
impl Drop for SecureChannel {
    fn drop(&mut self) {
        secure_zero(&mut self.private_key);
        secure_zero(&mut self.tx_enc_key);
        secure_zero(&mut self.tx_mac_key);
        secure_zero(&mut self.rx_enc_key);
        secure_zero(&mut self.rx_mac_key);
        secure_zero(&mut self.peer_public_key);
        self.state = ChannelState::Init;
        self.tx_counter = 0;
    }
}

/// One KDF slot: `SHA-256(shared_secret || label || direction)[0..16]`.
///
/// Direction is appended *after* the ENC/MAC label so that the four outputs
/// are pairwise independent: no two (label, direction) pairs are prefixes
/// of each other, and all four labels are fixed-length 3-byte ASCII, so the
/// concatenation is unambiguous without an explicit length field.
fn kdf(shared_secret: &[u8; 32], label: &[u8], direction: &[u8],
       out: &mut [u8; AES_KEY_SIZE]) {
    let mut h = Sha256::new();
    h.update(shared_secret);
    h.update(label);
    h.update(direction);
    let digest = h.finalize();
    out.copy_from_slice(&digest[..AES_KEY_SIZE]);
}

// ---------------------------------------------------------------------------
// HMAC-SHA-256 (RFC 2104)
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA-256(key, data).
fn hmac_sha256(key: &[u8; AES_KEY_SIZE], data: &[u8]) -> Digest {
    /// SHA-256 block size.
    const BLOCK_SIZE: usize = 64;
    /// Inner padding byte.
    const IPAD: u8 = 0x36;
    /// Outer padding byte.
    const OPAD: u8 = 0x5C;

    // Key is 16 bytes, pad to 64 bytes with zeros
    let mut k_padded = [0u8; BLOCK_SIZE];
    k_padded[..key.len()].copy_from_slice(key);

    // Inner hash: SHA-256((K ⊕ ipad) || data)
    let mut inner_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_key[i] = k_padded[i] ^ IPAD;
    }
    let mut h = Sha256::new();
    h.update(&inner_key);
    h.update(data);
    let inner_hash = h.finalize();

    // Outer hash: SHA-256((K ⊕ opad) || inner_hash)
    let mut outer_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer_key[i] = k_padded[i] ^ OPAD;
    }
    let mut h = Sha256::new();
    h.update(&outer_key);
    h.update(&inner_hash);
    let out = h.finalize();

    // The three 64-byte blocks below are all trivially reversible to the
    // MAC key (`K ⊕ 0x36…`, `K ⊕ 0x5C…`, and K itself zero-padded). They
    // live on the stack of a function called once per packet, so without an
    // explicit wipe a snapshot of the stack region contains the session MAC
    // key in three forms. Cost is 192 volatile byte stores against a
    // two-block SHA-256 — under 2% of this function.
    secure_zero(&mut k_padded);
    secure_zero(&mut inner_key);
    secure_zero(&mut outer_key);

    out
}

// `constant_time_eq` was one of five near-identical copies in the tree, and
// one of the three that lacked the `black_box` barrier — on the AEAD tag
// comparison, of all places. It now lives in `crate::ct::ct_eq`; see that
// module for why the barrier is load-bearing.
