// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What QUIC's TLS handshake runs on: RFC 7250 raw public keys.
//!
//! **Authentication of the peer is not done here.** The RPC session inside the
//! QUIC connection is Noise IK with the static keys the signed topology pins
//! (`azos_rpc::chan`); a peer that is not the pinned node never gets a session
//! whatever it presents to QUIC. TLS is therefore asked for what Noise does not
//! give the *datagrams*: a handshake that proves the other end can receive at the
//! address it claims (no spoofed source feeds the anti-amplification limit),
//! loss recovery, congestion control and flow control on the path. Reasons not to
//! put the topology's key into TLS:
//!
//! * the topology pins X25519 keys (key agreement: they cannot sign a TLS
//!   `CertificateVerify`), and the session's warrant MAC key, its ids, epochs
//!   and Bye all come from the Noise handshake; replacing it would re-plumb the
//!   whole engine instead of choosing a transport;
//! * a certificate has a validity window, and a device whose clock has not been
//!   set reads 1970 plus the uptime (tls-probe documents it): the handshake would
//!   fail exactly when the link is first needed. A raw public key has no dates.
//!
//! So the server holds an Ed25519 key it generates at start, and the client
//! accepts whatever key it is shown *after verifying the handshake signature with
//! it* (so the peer holds the private half: the connection is with whoever answers
//! at that address, not with a replay of someone's recorded handshake). The cost of
//! the choice, stated: the TLS layer alone authenticates nobody, and every frame is
//! sealed twice (QUIC's AEAD around Noise's). A MITM that terminates both QUIC
//! connections can relay and drop frames, as it can on the plain UDP link, and
//! cannot read or forge them. A key to pin would need a TLS key per node that the
//! topology also lists (it pins only the Noise key today); the verifier is the one
//! place a pin would go.

use std::sync::Arc;

use quinn_proto::crypto;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature_with_raw_key, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

use crate::crypto::{NoInitialCipherSuite, QuicClientConfig, QuicServerConfig};
use crate::suite;

/// PKCS#8 v1 DER of an Ed25519 key up to the 32-byte seed (RFC 8410).
const PKCS8_PREFIX: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
/// SubjectPublicKeyInfo DER of an Ed25519 key up to the 32-byte public key (RFC 8410).
const SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// The QUIC name the client states; raw public keys carry no name to check.
pub const SERVER_NAME: &str = "azos-rpc";

/// The TLS key of one QUIC endpoint: an Ed25519 key made for this run.
#[derive(Clone)]
pub struct Identity {
    key: Arc<dyn SigningKey>,
    spki: Vec<u8>,
}

impl Identity {
    /// A key from `seed`; [`Identity::generate`] draws the seed from the entropy pool.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Identity, Error> {
        let public = ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes();
        let mut pkcs8 = PKCS8_PREFIX.to_vec();
        pkcs8.extend_from_slice(seed);
        let key = suite::provider().key_provider.load_private_key(PrivatePkcs8KeyDer::from(pkcs8).into())?;
        let mut spki = SPKI_PREFIX.to_vec();
        spki.extend_from_slice(&public);
        Ok(Identity { key, spki })
    }

    /// A key from the system's entropy (on a device, the kernel's pool).
    pub fn generate() -> Result<Identity, Error> {
        let mut seed = [0u8; 32];
        getrandom04::fill(&mut seed).map_err(|e| Error::General(format!("entropy: {e}")))?;
        let id = Identity::from_seed(&seed);
        seed.fill(0);
        id
    }

    /// The public key as the peer sees it: SubjectPublicKeyInfo DER.
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }
}

/// Accepts the server's raw public key after checking the handshake signature
/// with it.
#[derive(Debug)]
struct RawKeyVerifier {
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for RawKeyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // The key is judged by the signature that follows ([`Self::verify_tls13_signature`]), not here.
        if !intermediates.is_empty() {
            return Err(Error::General("a raw public key has no chain".into()));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("QUIC is TLS 1.3 only".into()))
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature_with_raw_key(message, &SubjectPublicKeyInfoDer::from(cert.as_ref()), dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// The client's TLS configuration: TLS 1.3, raw public keys, no resumption.
pub fn client_crypto() -> Result<Arc<dyn crypto::ClientConfig>, Error> {
    client_crypto_with(suite::provider())
}

/// [`client_crypto`] over `provider` (QUIC-capable suites: [`suite::provider`]).
pub fn client_crypto_with(provider: Arc<CryptoProvider>) -> Result<Arc<dyn crypto::ClientConfig>, Error> {
    let verifier = Arc::new(RawKeyVerifier { algs: provider.signature_verification_algorithms });
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    let q = QuicClientConfig::new(Arc::new(config)).map_err(|NoInitialCipherSuite| Error::General("no QUIC initial suite".into()))?;
    Ok(Arc::new(q))
}

/// The server's TLS configuration: TLS 1.3, `identity`'s raw public key, no tickets.
pub fn server_crypto(identity: &Identity) -> Result<Arc<dyn crypto::ServerConfig>, Error> {
    server_crypto_with(suite::provider(), identity)
}

/// [`server_crypto`] over `provider` (QUIC-capable suites: [`suite::provider`]).
pub fn server_crypto_with(provider: Arc<CryptoProvider>, identity: &Identity) -> Result<Arc<dyn crypto::ServerConfig>, Error> {
    let certified = CertifiedKey::new(vec![CertificateDer::from(identity.spki.clone())], identity.key.clone());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(certified))));
    config.send_tls13_tickets = 0;
    let q = QuicServerConfig::new(Arc::new(config)).map_err(|NoInitialCipherSuite| Error::General("no QUIC initial suite".into()))?;
    Ok(Arc::new(q))
}
