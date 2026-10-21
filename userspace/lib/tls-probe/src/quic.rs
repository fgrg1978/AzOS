// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! quinn-proto, linked without a crypto feature: its transport types are
//! built here. A QUIC handshake needs `quinn_proto::crypto::{ClientConfig,
//! ServerConfig, Session}` and `HmacKey` implementations over a TLS provider;
//! quinn-proto ships them only behind its `ring` and `aws-lc-rs` features, which
//! this tree does not build, so that adaptor over rustls' `quic` module and the
//! rustcrypto provider is the work of the QUIC front, not of this probe.

/// A transport configuration with a stream limit and a connection id: the types
/// compile and link, and the arithmetic below is what the probe prints.
pub fn config_summary() -> u64 {
    let mut t = quinn_proto::TransportConfig::default();
    t.max_concurrent_bidi_streams(quinn_proto::VarInt::from_u32(8));
    let cid = quinn_proto::ConnectionId::new(&[0xA2; 8]);
    u64::from(quinn_proto::VarInt::from_u32(8)) + cid.len() as u64
}
