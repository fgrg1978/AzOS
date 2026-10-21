// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! TLS in ring 3, over the sockets of the std port (`std::net`).
//!
//! rustls with the rustls-rustcrypto provider (third_party/vendor: no aws-lc-rs,
//! no ring), wrapped small:
//!
//! * [`client`]: a client whose only trust is a list of **pins**, the SHA-256 of
//!   the server's SubjectPublicKeyInfo ([`pin`], [`verify`]). There is no
//!   system CA store and no switch that adds one. The configuration is
//!   [`rows::Source`], `key=value` rows.
//! * [`server`]: the other side of the same handshake.
//! * [`http`]: a minimal HTTP/1.0 GET over any byte stream, strict about
//!   truncation (a body that ends without `close_notify` or short of its
//!   `Content-Length` is an error).
//! * [`time`]: the clock a handshake reads; unset means no time, and no time
//!   means no handshake.
//! * `remote` (feature `packages`): the package source of the installer, which
//!   is where a package comes from and nothing else: the package's own
//!   signature still decides whether it is installed. Its user is `pkgd`
//!   (`userspace/services/pkgd`, a std program), which runs it for
//!   `Packages::fetch` (`pkg fetch`); `tests/host/tls-tests` drives the
//!   installer's fetch over it against a pinned server on loopback.
//!
//! **Entropy.** rustls' provider draws through getrandom 0.2, which has no
//! backend for `target_os = "azos"`. The program that links this crate
//! registers one (the std port's random source behind the `entropy`
//! capability); `userspace/services/pkgd/src/main.rs` and
//! `userspace/lib/tls-probe/src/main.rs` show the hook. Only one
//! registration is allowed per binary, so a library cannot make it.
//!
//! Host tests: `tests/host/tls-tests`.
#![forbid(unsafe_code)]

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;
use rustls_rustcrypto::sign;

mod der;
pub mod client;
pub mod http;
pub mod pin;
#[cfg(feature = "packages")]
pub mod remote;
pub mod rows;
pub mod server;
pub mod time;
pub mod verify;

/// The rustcrypto provider, the one every configuration uses, with a key provider that cannot hold an RSA
/// private key: `deny.toml` ignores RUSTSEC-2023-0071 (Marvin) on the ground that the `rsa` crate only verifies
/// signatures here, and this is what keeps that true for the server side (`with_single_cert` loads its key
/// through the provider, which would otherwise try RSA first).
fn provider() -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider { key_provider: &NoRsaKeys, ..rustls_rustcrypto::provider() })
}

/// Signing keys are ECDSA (P-256, P-384) or Ed25519, never RSA. Public because `userspace/lib/quic` builds its
/// provider with it too: the `deny.toml` claim about RUSTSEC-2023-0071 covers every crate that links the
/// provider, and there is one key loader for them all.
#[derive(Debug)]
pub struct NoRsaKeys;

impl rustls::crypto::KeyProvider for NoRsaKeys {
    fn load_private_key(&self, der: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, rustls::Error> {
        #[cfg(feature = "canary-rsa-keys")]
        return rustls_rustcrypto::provider().key_provider.load_private_key(der);
        #[cfg(not(feature = "canary-rsa-keys"))]
        sign::any_ecdsa_type(&der).or_else(|_| sign::any_eddsa_type(&der))
    }
}
