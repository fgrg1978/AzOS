// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! No RSA private-key operation is reachable from the TLS code.
//!
//! `deny.toml` ignores RUSTSEC-2023-0071 (Marvin: RSA private-key operations leak through timing) and
//! RUSTSEC-2024-0436 (`paste`, unmaintained). The first is sound only while the `rsa` crate, which the
//! rustls-rustcrypto provider links, is used to *verify* signatures with the server's public key. The
//! provider can also *sign* with an RSA key, and `ServerConfig::with_single_cert` loads its key through
//! the provider's key provider, so the test is the behaviour: the server configuration refuses an RSA key,
//! and takes an ECDSA one in the same setup. The source scan is a tripwire for the names that would
//! bypass the key provider.

mod common;

use common::*;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const RSA_KEY: &[u8] = include_bytes!("../pki/rsa_key.der");

fn config_with(key: &[u8]) -> Result<(), rustls::Error> {
    azos_tls::server::config(
        vec![CertificateDer::from(GOOD.to_vec())],
        PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.to_vec())),
        at(NOW),
    )
    .map(|_| ())
}

/// **Canary `canary-rsa-keys`:** the provider's own loader (RSA first) accepts the RSA key and fails this test.
#[test]
fn the_server_refuses_an_rsa_private_key() {
    assert!(RSA_KEY.len() > 1000, "the fixture is a 2048-bit RSA key");
    // The same setup with the ECDSA key succeeds, so the refusal is the key type.
    config_with(GOOD_KEY).expect("an ECDSA P-256 key is accepted");
    config_with(RSA_KEY).expect_err("an RSA key must be refused");
}

#[test]
fn the_tls_sources_name_no_rsa_key_path() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../userspace/lib/tls");
    let mut files = vec![src.join("Cargo.toml")];
    for e in std::fs::read_dir(src.join("src")).expect("userspace/lib/tls/src") {
        files.push(e.unwrap().path());
    }
    assert!(files.len() > 5, "the scan found the crate");
    // The provider's RSA-first loader, its RSA signer, the RSA crate itself, and client certificates (the
    // only other place a private key enters a configuration).
    let banned = ["any_supported_type", "RsaSigningKey", "RsaPrivateKey", "sign::rsa", "with_client_auth_cert", "rsa ="];
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        let code: String = text.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
        for b in banned {
            assert!(!code.contains(b), "{} names `{b}`", f.display());
        }
    }
}
