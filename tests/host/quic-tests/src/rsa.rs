// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! No RSA private-key operation is reachable from the QUIC code.
//!
//! `deny.toml` ignores RUSTSEC-2023-0071 (Marvin: RSA private-key operations leak through timing) on the
//! ground that the `rsa` crate, linked by the rustls-rustcrypto provider, only verifies signatures here. The
//! provider's own key loader tries RSA first, and the QUIC identity loads its key through the provider's
//! key provider, so the test is the behaviour: every provider this crate hands out refuses an RSA key and
//! still takes the Ed25519 identity. The source scan is a tripwire for the names that would bypass the key
//! provider. The fixture is the one `tests/host/tls-tests` refuses too.

use azos_quic::identity::Identity;
use azos_quic::suite;
use rustls::pki_types::{PrivatePkcs8KeyDer, PrivateKeyDer};
use rustls::CipherSuite;

const RSA_KEY: &[u8] = include_bytes!("../../tls-tests/pki/rsa_key.der");

fn load(p: &rustls::crypto::CryptoProvider, key: &[u8]) -> Result<(), rustls::Error> {
    p.key_provider.load_private_key(PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.to_vec()))).map(|_| ())
}

/// **Canary `canary-rsa-keys`:** the provider's own loader (RSA first) accepts the RSA key and fails this test.
#[test]
fn the_quic_providers_refuse_an_rsa_private_key() {
    assert!(RSA_KEY.len() > 1000, "the fixture is a 2048-bit RSA key");
    // The identity of every endpoint is an Ed25519 key and still loads, so the refusal is the key type.
    Identity::from_seed(&[7; 32]).expect("the Ed25519 identity loads");
    let providers = [
        suite::provider(),
        suite::provider_only(CipherSuite::TLS13_AES_128_GCM_SHA256),
        suite::provider_only(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
    ];
    for p in providers {
        load(&p, RSA_KEY).expect_err("an RSA key must be refused");
    }
}

#[test]
fn the_quic_sources_name_no_rsa_key_path() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../userspace/lib/quic");
    let mut files = vec![src.join("Cargo.toml")];
    for e in std::fs::read_dir(src.join("src")).expect("userspace/lib/quic/src") {
        files.push(e.unwrap().path());
    }
    assert!(files.len() > 5, "the scan found the crate");
    // The provider's RSA-first loader, its RSA signer, the RSA crate itself, and the places where a private
    // key enters a rustls configuration other than the provider's key provider.
    let banned = ["any_supported_type", "RsaSigningKey", "RsaPrivateKey", "sign::rsa", "with_client_auth_cert", "with_single_cert", "rsa ="];
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        let code: String = text.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
        for b in banned {
            assert!(!code.contains(b), "{} names `{b}`", f.display());
        }
    }
}
