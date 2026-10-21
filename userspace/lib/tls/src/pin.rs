// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pins: the SHA-256 of a server's SubjectPublicKeyInfo.
//!
//! A pin names a **key**, not a certificate: the server can renew its
//! certificate under the same key, and a configuration lists the next key as a
//! second pin before the old one retires. There is no system CA store and no
//! way to ask for one; a client with no pin has nobody it trusts.

use rustls::pki_types::CertificateDer;
use rustls::server::ParsedCertificate;
use sha2::{Digest, Sha256};

/// A pin: SHA-256 of the DER SubjectPublicKeyInfo.
pub type Pin = [u8; 32];

/// The pin of a certificate webpki has parsed: the one SubjectPublicKeyInfo
/// that the handshake signature is then verified against.
pub fn of_parsed(cert: &ParsedCertificate<'_>) -> Pin {
    Sha256::digest(cert.subject_public_key_info().as_ref()).into()
}

/// The pin of the certificate in `der`; `None` when it is not a certificate.
pub fn of_certificate(cert_der: &[u8]) -> Option<Pin> {
    ParsedCertificate::try_from(&CertificateDer::from(cert_der)).ok().map(|c| of_parsed(&c))
}

/// 64 hex digits (either case) as a pin.
pub fn from_hex(s: &str) -> Option<Pin> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let nibble = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut pin = [0u8; 32];
    for (i, o) in pin.iter_mut().enumerate() {
        *o = nibble(b[2 * i])? << 4 | nibble(b[2 * i + 1])?;
    }
    Some(pin)
}

/// A pin as 64 lower-case hex digits: the form a row holds.
pub fn to_hex(pin: &Pin) -> String {
    pin.iter().map(|b| format!("{b:02x}")).collect()
}
