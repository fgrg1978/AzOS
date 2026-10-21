// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The pinned client.

use std::io::{self, Read, Write};
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::time_provider::TimeProvider;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::pin::Pin;
use crate::verify::PinnedVerifier;

/// A client that trusts exactly the keys in `pins`, reading the clock from
/// `time`. No pins is an error: such a client would trust nobody, and the way
/// to say so is not to build it.
pub fn config(pins: &[Pin], time: Arc<dyn TimeProvider>) -> Result<Arc<ClientConfig>, rustls::Error> {
    if pins.is_empty() {
        return Err(rustls::Error::General("no pin: there is nobody to trust".into()));
    }
    let provider = crate::provider();
    let verifier = PinnedVerifier::new(pins, provider.signature_verification_algorithms);
    Ok(Arc::new(
        ClientConfig::builder_with_details(provider, time)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
    ))
}

/// Handshake with `host` over `stream`; the stream returned reads and writes
/// application data. A refused certificate is an `InvalidData` error that
/// carries the [`rustls::Error`] ([`tls_error`]).
pub fn connect<S: Read + Write>(
    config: Arc<ClientConfig>,
    host: &str,
    mut stream: S,
) -> io::Result<StreamOwned<ClientConnection, S>> {
    let name = ServerName::try_from(host.to_owned()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut conn = ClientConnection::new(config, name).map_err(io::Error::other)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut stream)?;
    }
    Ok(StreamOwned::new(conn, stream))
}

/// The TLS error inside an I/O error, when it is one: the difference between a
/// peer that was refused and a connection that broke.
pub fn tls_error(e: &io::Error) -> Option<&rustls::Error> {
    e.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>())
}
