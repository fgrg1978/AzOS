// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The pinned server verifier.
//!
//! What a handshake must show for the client to go on:
//!
//! 1. the end-entity certificate parses (webpki, the same parser that checks
//!    the handshake signature, and whose SubjectPublicKeyInfo is what is
//!    pinned) and is valid for the server name;
//! 2. it is inside its validity window **at the instant rustls hands in**,
//!    which is the configured [`TimeProvider`](rustls::time_provider::TimeProvider)'s
//!    and never the verifier's own clock;
//! 3. the SHA-256 of its SubjectPublicKeyInfo is one of the pins;
//! 4. the server proves it holds that key: the handshake signature is verified
//!    by the provider against the certificate's key (TLS 1.2 and 1.3).
//!
//! No chain is built and no issuer is consulted: the pin is the trust anchor,
//! so intermediates are ignored and a certificate renewed under the same key
//! keeps working. A mismatch is [`PinMismatch`], carried as the certificate
//! error `Other`.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{CertificateError, DigitallySignedStruct, Error, OtherError, SignatureScheme};

use crate::pin::{self, Pin};
use crate::der;

/// The certificate's key is none of the pins.
#[derive(Debug)]
pub struct PinMismatch {
    /// The pin the server presented.
    pub presented: Pin,
}

impl fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "server key {} is not pinned", pin::to_hex(&self.presented))
    }
}

impl StdError for PinMismatch {}

/// The verifier a client with `pins` and no other trust uses.
#[derive(Debug)]
pub struct PinnedVerifier {
    pins: Vec<Pin>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedVerifier {
    /// A verifier for `pins`, checking handshake signatures with `algorithms`.
    pub fn new(pins: &[Pin], algorithms: WebPkiSupportedAlgorithms) -> Arc<Self> {
        Arc::new(Self { pins: pins.to_vec(), algorithms })
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let bad = |e: CertificateError| Error::InvalidCertificate(e);
        let parsed = ParsedCertificate::try_from(end_entity)?;
        let (not_before, not_after) = der::validity(end_entity).ok_or_else(|| bad(CertificateError::BadEncoding))?;
        let at = now.as_secs();
        if !cfg!(feature = "canary-no-validity") {
            if at < not_before {
                return Err(bad(CertificateError::NotValidYet));
            }
            if at > not_after {
                return Err(bad(CertificateError::Expired));
            }
        }
        rustls::client::verify_server_name(&parsed, server_name)?;
        let presented = pin::of_parsed(&parsed);
        if !cfg!(feature = "canary-no-pin") && !self.pins.contains(&presented) {
            return Err(bad(CertificateError::Other(OtherError(Arc::new(PinMismatch { presented })))));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
