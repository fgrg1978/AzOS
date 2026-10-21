// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Key exchange: the algorithm lists, `curve25519-sha256` (RFC 8731), the
//! exchange hash and the key derivation of RFC 4253 section 7.2.
//!
//! One choice per list, and no fallback: the key exchange is
//! `curve25519-sha256` (also under its `@libssh.org` name), the host key
//! `ssh-ed25519`, the cipher `chacha20-poly1305@openssh.com` (an AEAD: the MAC
//! lists carry a name and are ignored), compression `none`. A client that
//! offers none of them is refused; there is nothing older to fall back to.
//!
//! Strict key exchange (`kex-strict-s-v00@openssh.com`, the Terrapin
//! countermeasure) is offered, and enforced when the client offers
//! `kex-strict-c-v00@openssh.com`: see `server.rs`.

use crate::packet::Key;
use crate::wire::{list_first, list_has, Reader, Writer, MSG_KEXINIT};
use alloc::vec::Vec;
use azos_crypto::sha256::Sha256;

/// The version line the server sends (without the CR LF).
pub const VERSION: &[u8] = b"SSH-2.0-AzOS_1";

pub const KEX_ALG: &str = "curve25519-sha256";
pub const KEX_ALG_LIBSSH: &str = "curve25519-sha256@libssh.org";
pub const KEX_STRICT_SERVER: &str = "kex-strict-s-v00@openssh.com";
pub const KEX_STRICT_CLIENT: &str = "kex-strict-c-v00@openssh.com";
pub const HOSTKEY_ALG: &str = "ssh-ed25519";
pub const CIPHER_ALG: &str = "chacha20-poly1305@openssh.com";
/// Named in the MAC lists only because the lists may not be empty; the AEAD
/// cipher carries its own tag and no MAC is ever computed.
pub const MAC_ALG: &str = "hmac-sha2-256";

/// The server's SSH_MSG_KEXINIT payload.
pub fn server_kexinit(cookie: &[u8; 16]) -> Vec<u8> {
    let mut w = Writer::new(MSG_KEXINIT);
    w.raw(cookie);
    w.name_list(&[KEX_ALG, KEX_ALG_LIBSSH, KEX_STRICT_SERVER]);
    w.name_list(&[HOSTKEY_ALG]);
    w.name_list(&[CIPHER_ALG]);
    w.name_list(&[CIPHER_ALG]);
    w.name_list(&[MAC_ALG]);
    w.name_list(&[MAC_ALG]);
    w.name_list(&["none"]);
    w.name_list(&["none"]);
    w.name_list(&[]);
    w.name_list(&[]);
    w.boolean(false);
    w.u32(0);
    w.buf
}

/// What a client's KEXINIT came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proposal {
    /// The client offered `kex-strict-c-v00@openssh.com`: both sides enforce
    /// strict key exchange.
    pub strict: bool,
    /// The client sent a guessed key-exchange packet right behind its KEXINIT
    /// and the guess is wrong: that packet is dropped, unread.
    pub skip_next: bool,
}

/// Why a client's KEXINIT was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KexError {
    Malformed,
    NoKex,
    NoHostKey,
    NoCipher,
    NoCompression,
}

impl KexError {
    pub fn why(self) -> &'static str {
        match self {
            KexError::Malformed => "malformed key exchange init",
            KexError::NoKex => "no common key exchange (curve25519-sha256 only)",
            KexError::NoHostKey => "no common host key algorithm (ssh-ed25519 only)",
            KexError::NoCipher => "no common cipher (chacha20-poly1305@openssh.com only)",
            KexError::NoCompression => "compression none is not offered",
        }
    }
}

/// Read the client's KEXINIT payload against the server's lists.
pub fn negotiate(payload: &[u8]) -> Result<Proposal, KexError> {
    let mut r = Reader::new(payload);
    if r.u8() != Some(MSG_KEXINIT) {
        return Err(KexError::Malformed);
    }
    let bad = KexError::Malformed;
    r.skip(16).ok_or(bad)?;
    let kex = r.string().ok_or(bad)?;
    let host = r.string().ok_or(bad)?;
    let enc_c2s = r.string().ok_or(bad)?;
    let enc_s2c = r.string().ok_or(bad)?;
    let _mac_c2s = r.string().ok_or(bad)?;
    let _mac_s2c = r.string().ok_or(bad)?;
    let comp_c2s = r.string().ok_or(bad)?;
    let comp_s2c = r.string().ok_or(bad)?;
    let _lang_c2s = r.string().ok_or(bad)?;
    let _lang_s2c = r.string().ok_or(bad)?;
    let follows = r.boolean().ok_or(bad)?;
    r.u32().ok_or(bad)?;

    if !list_has(kex, KEX_ALG) && !list_has(kex, KEX_ALG_LIBSSH) {
        return Err(KexError::NoKex);
    }
    if !list_has(host, HOSTKEY_ALG) {
        return Err(KexError::NoHostKey);
    }
    if !list_has(enc_c2s, CIPHER_ALG) || !list_has(enc_s2c, CIPHER_ALG) {
        return Err(KexError::NoCipher);
    }
    if !list_has(comp_c2s, "none") || !list_has(comp_s2c, "none") {
        return Err(KexError::NoCompression);
    }
    // RFC 4253 section 7: the guess is right when the client's first kex name
    // and first host key name are the ones the server chose (the server's
    // choice is the client's first name the server also has).
    let first_kex = list_first(kex);
    let kex_right = first_kex == KEX_ALG.as_bytes() || first_kex == KEX_ALG_LIBSSH.as_bytes();
    let host_right = list_first(host) == HOSTKEY_ALG.as_bytes();
    Ok(Proposal { strict: list_has(kex, KEX_STRICT_CLIENT), skip_next: follows && !(kex_right && host_right) })
}

/// The host key as it travels: `string "ssh-ed25519" | string key`.
pub fn host_key_blob(pk: &[u8; 32]) -> Vec<u8> {
    let mut w = Writer::default();
    w.string(HOSTKEY_ALG.as_bytes());
    w.string(pk);
    w.buf
}

/// A signature as it travels: `string "ssh-ed25519" | string signature`.
pub fn signature_blob(sig: &[u8; 64]) -> Vec<u8> {
    let mut w = Writer::default();
    w.string(HOSTKEY_ALG.as_bytes());
    w.string(sig);
    w.buf
}

/// The OpenSSH fingerprint of a host key, `SHA256:` and the unpadded base64
/// of the hash of its blob: what `ssh` shows the user to compare.
pub fn fingerprint(pk: &[u8; 32]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(&host_key_blob(pk));
    let mut out = b"SHA256:".to_vec();
    out.extend_from_slice(&crate::wire::base64_nopad(&h.finalize()));
    out
}

/// The inputs of the exchange hash (RFC 8731 section 3.1).
pub struct Exchange<'a> {
    pub client_version: &'a [u8],
    pub server_version: &'a [u8],
    pub client_kexinit: &'a [u8],
    pub server_kexinit: &'a [u8],
    pub host_key: &'a [u8],
    pub client_public: &'a [u8; 32],
    pub server_public: &'a [u8; 32],
}

/// `H`, and the shared secret `K` as an mpint, hashed in the order of the RFC.
pub fn exchange_hash(x: &Exchange, shared: &[u8; 32]) -> [u8; 32] {
    let mut w = Writer::default();
    w.string(x.client_version);
    w.string(x.server_version);
    w.string(x.client_kexinit);
    w.string(x.server_kexinit);
    w.string(x.host_key);
    w.string(x.client_public);
    w.string(x.server_public);
    // OpenSSH (and so every client) puts the 32 output bytes of X25519 into
    // the mpint as they are, most significant first.
    w.mpint(shared);
    let mut h = Sha256::new();
    h.update(&w.buf);
    h.finalize()
}

/// One derived key of RFC 4253 section 7.2: `HASH(K || H || letter || id)`,
/// extended by `HASH(K || H || key so far)` until `out` is full.
fn derive(shared: &[u8; 32], h: &[u8; 32], letter: u8, session_id: &[u8; 32], out: &mut [u8]) {
    let mut kw = Writer::default();
    kw.mpint(shared);
    let mut first = Sha256::new();
    first.update(&kw.buf);
    first.update(h);
    first.update(&[letter]);
    first.update(session_id);
    let mut have = 0;
    let mut block = first.finalize();
    loop {
        let n = (out.len() - have).min(32);
        out[have..have + n].copy_from_slice(&block[..n]);
        have += n;
        if have == out.len() {
            break;
        }
        let mut next = Sha256::new();
        next.update(&kw.buf);
        next.update(h);
        next.update(&out[..have]);
        block = next.finalize();
    }
    azos_crypto::ct::secure_zero(&mut block);
    azos_crypto::ct::secure_zero(&mut kw.buf);
}

/// The two directions' keys: (client to server, server to client).
pub fn derive_keys(shared: &[u8; 32], h: &[u8; 32], session_id: &[u8; 32]) -> (Key, Key) {
    let mut c2s = [0u8; 64];
    let mut s2c = [0u8; 64];
    // "C" is the client-to-server encryption key, "D" the other direction
    // (the letters A and B are the IVs, which this cipher does not use).
    derive(shared, h, b'C', session_id, &mut c2s);
    derive(shared, h, b'D', session_id, &mut s2c);
    let keys = (Key::new(&c2s), Key::new(&s2c));
    azos_crypto::ct::secure_zero(&mut c2s);
    azos_crypto::ct::secure_zero(&mut s2c);
    keys
}
