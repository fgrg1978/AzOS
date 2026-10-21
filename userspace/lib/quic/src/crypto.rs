// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only) AND MIT
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// SPDX-FileCopyrightText: 2018 The quinn Developers
//
// The TLS session adaptor in this file (TlsSession, the header and packet key
// wrappers, the version and Initial-key handling, the client and server
// configuration types) follows quinn-proto 0.11's src/crypto/rustls.rs, which
// is MIT OR Apache-2.0 and is used here under the MIT license:
//
//   Copyright (c) 2018 The quinn Developers
//
//   Permission is hereby granted, free of charge, to any person obtaining a copy
//   of this software and associated documentation files (the "Software"), to deal
//   in the Software without restriction, including without limitation the rights
//   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//   copies of the Software, and to permit persons to whom the Software is
//   furnished to do so, subject to the following conditions:
//
//   The above copyright notice and this permission notice shall be included in all
//   copies or substantial portions of the Software.
//
//   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//   SOFTWARE.
//! The adaptor quinn-proto needs between its `crypto` traits and rustls' `quic`
//! module.
//!
//! quinn-proto ships this adaptor only behind its `ring` and `aws-lc-rs`
//! features, which this tree does not build. This is the same adaptor with
//! the primitives it takes from ring replaced by the RustCrypto crates: the
//! retry-packet integrity tag (AES-128-GCM with the fixed key of RFC 9001
//! section 5.8), the HMAC-SHA256 key of stateless resets, and the AEAD key
//! retry tokens are sealed under (HKDF-SHA256 into AES-256-GCM).

use std::{any::Any, io, sync::Arc};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::KeyInit;
use bytes::BytesMut;
use hmac::{Hmac, Mac};
use quinn_proto::crypto::{
    self, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, UnsupportedVersion,
};
use quinn_proto::{ConnectError, ConnectionId, Side, TransportError, TransportErrorCode};
use rustls::pki_types::ServerName;
use rustls::quic::{Connection, HeaderProtectionKey, KeyChange, PacketKey, Secrets, Suite, Version};
use sha2::Sha256;

use quinn_proto::transport_parameters::TransportParameters;

fn side(s: Side) -> rustls::Side {
    match s {
        Side::Client => rustls::Side::Client,
        Side::Server => rustls::Side::Server,
    }
}

/// What `Connection::handshake_data` downcasts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeData {
    /// The TLS 1.3 cipher suite the connection runs on (`None` until it is chosen).
    pub suite: Option<rustls::CipherSuite>,
}

/// A rustls QUIC session.
pub struct TlsSession {
    version: Version,
    got_handshake_data: bool,
    next_secrets: Option<Secrets>,
    inner: Connection,
    suite: Suite,
}

impl TlsSession {
    fn side(&self) -> Side {
        match self.inner {
            Connection::Client(_) => Side::Client,
            Connection::Server(_) => Side::Server,
        }
    }
}

impl crypto::Session for TlsSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, s: Side) -> Keys {
        initial_keys(self.version, *dst_cid, s, &self.suite)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.got_handshake_data.then(|| Box::new(HandshakeData { suite: self.inner.negotiated_cipher_suite().map(|s| s.suite()) }) as Box<dyn Any>)
    }

    /// The peer's raw public key (SubjectPublicKeyInfo DER) as a `Vec<u8>`; the
    /// rustls session keeps it as the one "certificate" of the peer.
    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_certificates().and_then(|v| v.first()).map(|spki| Box::new(spki.as_ref().to_vec()) as Box<dyn Any>)
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn crypto::PacketKey>)> {
        let keys = self.inner.zero_rtt_keys()?;
        Some((header_key(keys.header), packet_key(keys.packet)))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        match self.inner {
            Connection::Client(ref session) => Some(session.is_early_data_accepted()),
            _ => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.inner.read_hs(buf).map_err(|e| {
            if let Some(alert) = self.inner.alert() {
                TransportError { code: TransportErrorCode::crypto(alert.into()), frame: None, reason: e.to_string() }
            } else {
                TransportError { code: TransportErrorCode::PROTOCOL_VIOLATION, frame: None, reason: format!("TLS error: {e}") }
            }
        })?;
        if !self.got_handshake_data {
            // rustls has no explicit signal that the ClientHello (server) or the ALPN
            // choice (client) is ready: the first read that leaves either known, or
            // the handshake over, is it.
            let have_server_name = match self.inner {
                Connection::Client(_) => false,
                Connection::Server(ref session) => session.server_name().is_some(),
            };
            if self.inner.alpn_protocol().is_some() || have_server_name || !self.is_handshaking() {
                self.got_handshake_data = true;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        match self.inner.quic_transport_parameters() {
            None => Ok(None),
            Some(buf) => match TransportParameters::read(self.side(), &mut io::Cursor::new(buf)) {
                Ok(params) => Ok(Some(params)),
                Err(e) => Err(e.into()),
            },
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        let keys = match self.inner.write_hs(buf)? {
            KeyChange::Handshake { keys } => keys,
            KeyChange::OneRtt { keys, next } => {
                self.next_secrets = Some(next);
                keys
            }
        };
        Some(Keys {
            header: KeyPair { local: header_key(keys.local.header), remote: header_key(keys.remote.header) },
            packet: KeyPair { local: packet_key(keys.local.packet), remote: packet_key(keys.remote.packet) },
        })
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn crypto::PacketKey>>> {
        let secrets = self.next_secrets.as_mut()?;
        let keys = secrets.next_packet_keys();
        Some(KeyPair { local: packet_key(keys.local), remote: packet_key(keys.remote) })
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let Some(tag_start) = payload.len().checked_sub(16) else { return false };
        let mut pseudo = Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
        pseudo.push(orig_dst_cid.len() as u8);
        pseudo.extend_from_slice(orig_dst_cid);
        pseudo.extend_from_slice(header);
        let tag_start = tag_start + pseudo.len();
        pseudo.extend_from_slice(payload);
        let (nonce, key) = retry_secrets(self.version);
        let (aad, tag) = pseudo.split_at(tag_start);
        aes_gcm::Aes128Gcm::new(GenericArray::from_slice(&key))
            .decrypt_in_place_detached(GenericArray::from_slice(&nonce), aad, &mut [], GenericArray::from_slice(tag))
            .is_ok()
    }

    fn export_keying_material(&self, output: &mut [u8], label: &[u8], context: &[u8]) -> Result<(), ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, Some(context)).map_err(|_| ExportKeyingMaterialError)?;
        Ok(())
    }
}

const RETRY_KEY_DRAFT: [u8; 16] = [0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1];
const RETRY_NONCE_DRAFT: [u8; 12] = [0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c];
const RETRY_KEY_V1: [u8; 16] = [0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e];
const RETRY_NONCE_V1: [u8; 12] = [0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb];

/// The fixed nonce and key of the retry integrity tag.
fn retry_secrets(v: Version) -> ([u8; 12], [u8; 16]) {
    match v {
        Version::V1 => (RETRY_NONCE_V1, RETRY_KEY_V1),
        Version::V1Draft => (RETRY_NONCE_DRAFT, RETRY_KEY_DRAFT),
        _ => unreachable!("interpret_version admits V1 and V1Draft only"),
    }
}

/// Header protection for quinn-proto: a rustls key applied to a whole packet.
struct HeaderAdapter(Box<dyn HeaderProtectionKey>);

impl HeaderKey for HeaderAdapter {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.0
            .decrypt_in_place(&sample[..self.0.sample_len()], &mut first[0], &mut rest[pn_offset - 1..pn_end])
            .expect("a sample of the key's length");
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.0
            .encrypt_in_place(&sample[..self.0.sample_len()], &mut first[0], &mut rest[pn_offset - 1..pn_end])
            .expect("a sample of the key's length");
    }

    fn sample_size(&self) -> usize {
        self.0.sample_len()
    }
}

/// Packet protection for quinn-proto: a rustls key applied to a whole packet.
struct PacketAdapter(Box<dyn PacketKey>);

impl crypto::PacketKey for PacketAdapter {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - self.0.tag_len());
        let tag = self.0.encrypt_in_place(packet, &*header, payload).expect("a payload the AEAD can seal");
        tag_storage.copy_from_slice(tag.as_ref());
    }

    fn decrypt(&self, packet: u64, header: &[u8], payload: &mut BytesMut) -> Result<(), CryptoError> {
        let plain_len = self.0.decrypt_in_place(packet, header, payload.as_mut()).map_err(|_| CryptoError)?.len();
        payload.truncate(plain_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.0.tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        self.0.confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.0.integrity_limit()
    }
}

fn header_key(k: Box<dyn HeaderProtectionKey>) -> Box<dyn HeaderKey> {
    Box::new(HeaderAdapter(k))
}

fn packet_key(k: Box<dyn PacketKey>) -> Box<dyn crypto::PacketKey> {
    Box::new(PacketAdapter(k))
}

fn initial_keys(version: Version, dst_cid: ConnectionId, s: Side, suite: &Suite) -> Keys {
    let keys = suite.keys(&dst_cid, side(s), version);
    Keys {
        header: KeyPair { local: header_key(keys.local.header), remote: header_key(keys.remote.header) },
        packet: KeyPair { local: packet_key(keys.local.packet), remote: packet_key(keys.remote.packet) },
    }
}

fn interpret_version(version: u32) -> Result<Version, UnsupportedVersion> {
    match version {
        0xff00_001d..=0xff00_0020 => Ok(Version::V1Draft),
        0x0000_0001 | 0xff00_0021..=0xff00_0022 => Ok(Version::V1),
        _ => Err(UnsupportedVersion),
    }
}

fn to_vec(params: &TransportParameters) -> Vec<u8> {
    let mut bytes = Vec::new();
    params.write(&mut bytes);
    bytes
}

/// The initial cipher suite (TLS_AES_128_GCM_SHA256 with QUIC protection) is not in the provider.
#[derive(Debug)]
pub struct NoInitialCipherSuite;

impl std::fmt::Display for NoInitialCipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("no QUIC-capable TLS13_AES_128_GCM_SHA256 in the provider")
    }
}

impl std::error::Error for NoInitialCipherSuite {}

/// A QUIC-compatible TLS client configuration.
pub struct QuicClientConfig {
    inner: Arc<rustls::ClientConfig>,
    initial: Suite,
}

impl QuicClientConfig {
    /// Wrap a rustls client configuration (TLS 1.3 enabled, a provider with QUIC suites).
    pub fn new(inner: Arc<rustls::ClientConfig>) -> Result<Self, NoInitialCipherSuite> {
        let initial = crate::suite::initial_suite(inner.crypto_provider()).ok_or(NoInitialCipherSuite)?;
        Ok(Self { inner, initial })
    }
}

impl crypto::ClientConfig for QuicClientConfig {
    fn start_session(self: Arc<Self>, version: u32, server_name: &str, params: &TransportParameters) -> Result<Box<dyn crypto::Session>, ConnectError> {
        let version = interpret_version(version)?;
        let name = ServerName::try_from(server_name).map_err(|_| ConnectError::InvalidServerName(server_name.into()))?.to_owned();
        let conn = rustls::quic::ClientConnection::new(self.inner.clone(), version, name, to_vec(params))
            .map_err(|_| ConnectError::NoDefaultClientConfig)?;
        Ok(Box::new(TlsSession {
            version,
            got_handshake_data: false,
            next_secrets: None,
            inner: Connection::Client(conn),
            suite: self.initial,
        }))
    }
}

/// A QUIC-compatible TLS server configuration.
pub struct QuicServerConfig {
    inner: Arc<rustls::ServerConfig>,
    initial: Suite,
}

impl QuicServerConfig {
    /// Wrap a rustls server configuration (TLS 1.3 enabled, a provider with QUIC suites).
    pub fn new(inner: Arc<rustls::ServerConfig>) -> Result<Self, NoInitialCipherSuite> {
        let initial = crate::suite::initial_suite(inner.crypto_provider()).ok_or(NoInitialCipherSuite)?;
        Ok(Self { inner, initial })
    }
}

impl crypto::ServerConfig for QuicServerConfig {
    fn start_session(self: Arc<Self>, version: u32, params: &TransportParameters) -> Box<dyn crypto::Session> {
        // `initial_keys` rejected any version this does not accept before a session starts.
        let version = interpret_version(version).expect("a version initial_keys accepted");
        let conn = rustls::quic::ServerConnection::new(self.inner.clone(), version, to_vec(params)).expect("a TLS 1.3 server configuration");
        Box::new(TlsSession { version, got_handshake_data: false, next_secrets: None, inner: Connection::Server(conn), suite: self.initial })
    }

    fn initial_keys(&self, version: u32, dst_cid: &ConnectionId) -> Result<Keys, UnsupportedVersion> {
        let version = interpret_version(version)?;
        Ok(initial_keys(version, *dst_cid, Side::Server, &self.initial))
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        let version = interpret_version(version).expect("a version initial_keys accepted");
        let (nonce, key) = retry_secrets(version);
        let mut pseudo = Vec::with_capacity(packet.len() + orig_dst_cid.len() + 1);
        pseudo.push(orig_dst_cid.len() as u8);
        pseudo.extend_from_slice(orig_dst_cid);
        pseudo.extend_from_slice(packet);
        let tag = aes_gcm::Aes128Gcm::new(GenericArray::from_slice(&key))
            .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &pseudo, &mut [])
            .expect("an empty plaintext");
        let mut out = [0u8; 16];
        out.copy_from_slice(&tag);
        out
    }
}

/// The key stateless resets are signed with: HMAC-SHA256.
pub struct ResetKey([u8; 64]);

impl ResetKey {
    /// A fresh random key.
    pub fn random() -> Result<Self, getrandom04::Error> {
        let mut k = [0u8; 64];
        getrandom04::fill(&mut k)?;
        Ok(ResetKey(k))
    }

    fn mac(&self) -> Hmac<Sha256> {
        <Hmac<Sha256> as Mac>::new_from_slice(&self.0).expect("HMAC takes any key length")
    }
}

impl crypto::HmacKey for ResetKey {
    fn sign(&self, data: &[u8], out: &mut [u8]) {
        let mut m = self.mac();
        m.update(data);
        out.copy_from_slice(&m.finalize().into_bytes());
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let mut m = self.mac();
        m.update(data);
        m.verify_slice(signature).map_err(|_| CryptoError)
    }
}

/// The master key retry tokens are sealed under: an HKDF-SHA256 pseudo-random
/// key, from which each token derives its own AES-256-GCM key.
pub struct TokenKey(hkdf::Hkdf<Sha256>);

impl TokenKey {
    /// A fresh random key.
    pub fn random() -> Result<Self, getrandom04::Error> {
        let mut master = [0u8; 64];
        getrandom04::fill(&mut master)?;
        Ok(TokenKey(hkdf::Hkdf::<Sha256>::new(None, &master)))
    }
}

impl crypto::HandshakeTokenKey for TokenKey {
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn crypto::AeadKey> {
        let mut key = [0u8; 32];
        self.0.expand(random_bytes, &mut key).expect("32 bytes is a valid HKDF-SHA256 output length");
        Box::new(TokenAead(aes_gcm::Aes256Gcm::new(GenericArray::from_slice(&key))))
    }
}

struct TokenAead(aes_gcm::Aes256Gcm);

impl crypto::AeadKey for TokenAead {
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError> {
        self.0.encrypt_in_place(GenericArray::from_slice(&[0u8; 12]), additional_data, data).map_err(|_| CryptoError)
    }

    fn open<'a>(&self, data: &'a mut [u8], additional_data: &[u8]) -> Result<&'a mut [u8], CryptoError> {
        let plain = data.len().checked_sub(16).ok_or(CryptoError)?;
        let (body, tag) = data.split_at_mut(plain);
        self.0
            .decrypt_in_place_detached(GenericArray::from_slice(&[0u8; 12]), additional_data, body, GenericArray::from_slice(tag))
            .map_err(|_| CryptoError)?;
        Ok(body)
    }
}
