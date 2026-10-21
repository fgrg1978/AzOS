// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! User authentication (RFC 4252): public keys only, `ssh-ed25519`.
//!
//! There is no password method and no keyboard-interactive one: nothing in
//! this server can be guessed. A login is a signature, by a key the signed
//! topology lists for the user name, over the session id and the request.
//!
//! The accounts are the kernel's `/proc/ssh`, which shows the topology's
//! `[login.NAME]` rows: one line per public key, `<user name> <64 hex digits>`.
//! There is no file on the volume to edit, so nothing an attacker who can write
//! the volume does adds a key.

use crate::kex::HOSTKEY_ALG;
use crate::wire::{Reader, Writer, MSG_USERAUTH_REQUEST};
use alloc::vec::Vec;
use azos_crypto::ed25519::sig_verify_message;

/// One authorized key, and the user name it logs in as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthKey {
    pub user: Vec<u8>,
    pub key: [u8; 32],
}

/// What reading `/proc/ssh` came to.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Parsed {
    pub keys: Vec<AuthKey>,
    /// Lines that were not `<name> <64 hex digits>`.
    pub skipped: usize,
}

/// Read `/proc/ssh`.
pub fn parse_logins(text: &[u8]) -> Parsed {
    let mut out = Parsed::default();
    for line in text.split(|&c| c == b'\n') {
        if line.is_empty() {
            continue;
        }
        let mut f = line.split(|&c| c == b' ');
        let (Some(user), Some(hex), None) = (f.next(), f.next(), f.next()) else {
            out.skipped += 1;
            continue;
        };
        match (user.is_empty(), hex_key(hex)) {
            (false, Some(key)) => out.keys.push(AuthKey { user: user.to_vec(), key }),
            _ => out.skipped += 1,
        }
    }
    out
}

/// 64 hex digits as 32 bytes.
fn hex_key(hex: &[u8]) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut key = [0u8; 32];
    for (b, pair) in key.iter_mut().zip(hex.chunks_exact(2)) {
        *b = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(key)
}

/// The 32 key bytes of an `ssh-ed25519` public key blob, if it is one.
pub fn key_of_blob(blob: &[u8]) -> Option<[u8; 32]> {
    let mut r = Reader::new(blob);
    if r.string()? != HOSTKEY_ALG.as_bytes() {
        return None;
    }
    let k = r.string()?;
    if r.remaining() != 0 {
        return None;
    }
    k.try_into().ok()
}

/// A parsed `publickey` request.
pub struct PublicKeyRequest<'a> {
    pub user: &'a [u8],
    pub service: &'a [u8],
    pub signed: bool,
    pub alg: &'a [u8],
    pub blob: &'a [u8],
    pub signature: &'a [u8],
}

/// What the method of a USERAUTH_REQUEST was.
pub enum Method<'a> {
    None,
    PublicKey(PublicKeyRequest<'a>),
    /// Any other method (password, keyboard-interactive, hostbased): not offered.
    Other,
}

/// The user, the service and the method of a USERAUTH_REQUEST payload.
pub fn parse_request(payload: &[u8]) -> Option<(&[u8], &[u8], Method<'_>)> {
    let mut r = Reader::new(payload);
    if r.u8()? != MSG_USERAUTH_REQUEST {
        return None;
    }
    let user = r.string()?;
    let service = r.string()?;
    let method = r.string()?;
    let m = match method {
        b"none" => Method::None,
        b"publickey" => {
            let signed = r.boolean()?;
            let alg = r.string()?;
            let blob = r.string()?;
            let signature = if signed { r.string()? } else { &[] };
            Method::PublicKey(PublicKeyRequest { user, service, signed, alg, blob, signature })
        }
        _ => Method::Other,
    };
    Some((user, service, m))
}

/// Does the signature in `req` verify, under `key`, over the session id and
/// the request (RFC 4252 section 7)?
pub fn signature_ok(session_id: &[u8; 32], req: &PublicKeyRequest, key: &[u8; 32]) -> bool {
    let mut r = Reader::new(req.signature);
    let (Some(alg), Some(sig), 0) = (r.string(), r.string(), r.remaining()) else { return false };
    if alg != HOSTKEY_ALG.as_bytes() {
        return false;
    }
    let Ok(sig) = <[u8; 64]>::try_from(sig) else { return false };
    let mut w = Writer::default();
    w.string(session_id);
    w.u8(MSG_USERAUTH_REQUEST);
    w.string(req.user);
    w.string(req.service);
    w.string(b"publickey");
    w.boolean(true);
    w.string(req.alg);
    w.string(req.blob);
    sig_verify_message(key, &sig, &w.buf)
}
