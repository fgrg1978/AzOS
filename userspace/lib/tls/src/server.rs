// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The server side of the same handshake: one certificate chain and its key, no
//! client authentication.

use std::io::{self, Read, Write};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::time_provider::TimeProvider;
use rustls::{ServerConfig, ServerConnection, StreamOwned};

/// A server presenting `chain` (leaf first) with `key`.
pub fn config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    time: Arc<dyn TimeProvider>,
) -> Result<Arc<ServerConfig>, rustls::Error> {
    Ok(Arc::new(
        ServerConfig::builder_with_details(crate::provider(), time)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, key)?,
    ))
}

/// Accept one connection on `stream`: the handshake is complete when this returns.
pub fn accept<S: Read + Write>(config: Arc<ServerConfig>, mut stream: S) -> io::Result<StreamOwned<ServerConnection, S>> {
    let mut conn = ServerConnection::new(config).map_err(io::Error::other)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut stream)?;
    }
    Ok(StreamOwned::new(conn, stream))
}
