// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! rustls over the rustcrypto provider: configurations, an in-memory handshake
//! between a client and a server, and the client side over any byte stream.
//!
//! **Time.** rustls reads the wall clock to check a certificate's validity, and
//! on `*-unknown-azos` that clock (`SystemTime::now`) is the real-time clock
//! the vDSO publishes, which reads 1970 plus the uptime until a time source
//! (NTP) has set it. The loopback handshake therefore takes its time from a
//! [`FixedTime`], so it does not depend on the device's clock; the stream path
//! takes [`DeviceTime`], the clock as it is, and a device that has not synced
//! fails the handshake with a "certificate not valid yet" error, which is the
//! right answer.

use std::fmt;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::time_provider::TimeProvider;
use rustls::{ClientConfig, ClientConnection, Connection, RootCertStore, ServerConfig, ServerConnection};

/// The server name the fixtures' leaf certificate is issued for.
pub const SERVER_NAME: &str = "probe.azos";

/// 2026-10-17 00:00:00 UTC, inside the fixtures' validity (they are made on
/// 2026-10-16 and last a hundred years).
pub const FIXED_UNIX_SECS: u64 = 1_792_195_200;

/// The test CA, the only trust anchor (`pki/gen.sh`).
const CA_DER: &[u8] = include_bytes!("../pki/ca.der");
/// The leaf certificate for [`SERVER_NAME`], signed by the CA.
const LEAF_DER: &[u8] = include_bytes!("../pki/leaf.der");
/// The leaf's ECDSA P-256 key, PKCS#8.
const LEAF_KEY_DER: &[u8] = include_bytes!("../pki/leaf_key.der");

/// A clock that always reads [`FIXED_UNIX_SECS`].
#[derive(Debug)]
pub struct FixedTime;

impl TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(std::time::Duration::from_secs(FIXED_UNIX_SECS)))
    }
}

/// The system clock (on azos, the real-time clock of the vDSO).
#[derive(Debug)]
pub struct DeviceTime;

impl TimeProvider for DeviceTime {
    fn current_time(&self) -> Option<UnixTime> {
        SystemTime::now().duration_since(UNIX_EPOCH).ok().map(UnixTime::since_unix_epoch)
    }
}

/// Whether the system clock has been set: it reads after 2026-01-01. Unset, it
/// reads 1970 plus the uptime.
pub fn clock_is_set() -> bool {
    SystemTime::now().duration_since(UNIX_EPOCH).is_ok_and(|d| d.as_secs() >= 1_767_225_600)
}

/// The rustcrypto provider, shared by every configuration.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls_rustcrypto::provider())
}

/// A client that trusts the test CA only.
pub fn client_config(time: Arc<dyn TimeProvider>) -> Result<Arc<ClientConfig>, rustls::Error> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(CA_DER)).map_err(|e| rustls::Error::General(format!("trust anchor: {e}")))?;
    Ok(Arc::new(
        ClientConfig::builder_with_details(provider(), time)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

/// A server with the fixtures' leaf certificate and key.
pub fn server_config(time: Arc<dyn TimeProvider>) -> Result<Arc<ServerConfig>, rustls::Error> {
    let chain = vec![CertificateDer::from(LEAF_DER)];
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(LEAF_KEY_DER));
    Ok(Arc::new(
        ServerConfig::builder_with_details(provider(), time)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, key)?,
    ))
}

/// What a loopback handshake negotiated and moved.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub version: String,
    pub suite: String,
    /// Bytes the client wrote to the wire and the server wrote back, in total.
    pub client_wire: usize,
    pub server_wire: usize,
    /// The payload as the server read it, and the reply as the client read it.
    pub request: Vec<u8>,
    pub reply: Vec<u8>,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} ({} B up, {} B down, {} B echoed)",
            self.version,
            self.suite,
            self.client_wire,
            self.server_wire,
            self.reply.len()
        )
    }
}

/// Move everything `from` has to say into `to`: the number of bytes moved.
fn flow(from: &mut Connection, to: &mut Connection) -> Result<usize, String> {
    let mut wire = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut wire).map_err(|e| format!("write_tls: {e}"))?;
    }
    let mut rest = wire.as_slice();
    while !rest.is_empty() {
        let n = to.read_tls(&mut rest).map_err(|e| format!("read_tls: {e}"))?;
        to.process_new_packets().map_err(|e| format!("process_new_packets: {e}"))?;
        if n == 0 {
            return Err("the receiver took no bytes".into());
        }
    }
    Ok(wire.len())
}

/// Handshake `client` against `server` over memory, then send `request` up and
/// have the server send it back.
pub fn loopback(
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
    name: &str,
    request: &[u8],
) -> Result<Outcome, String> {
    let server_name = ServerName::try_from(name.to_owned()).map_err(|e| format!("server name: {e}"))?;
    let mut c: Connection = ClientConnection::new(client, server_name).map_err(|e| format!("client: {e}"))?.into();
    let mut s: Connection = ServerConnection::new(server).map_err(|e| format!("server: {e}"))?.into();
    let (mut up, mut down) = (0, 0);
    for _ in 0..16 {
        if !c.is_handshaking() && !s.is_handshaking() {
            break;
        }
        up += flow(&mut c, &mut s)?;
        down += flow(&mut s, &mut c)?;
    }
    if c.is_handshaking() || s.is_handshaking() {
        return Err("the handshake did not finish in 16 flights".into());
    }
    let version = format!("{:?}", c.protocol_version().ok_or("no protocol version")?);
    let suite = format!("{:?}", c.negotiated_cipher_suite().ok_or("no cipher suite")?.suite());

    c.writer().write_all(request).map_err(|e| format!("client write: {e}"))?;
    up += flow(&mut c, &mut s)?;
    let mut got = vec![0u8; request.len()];
    s.reader().read_exact(&mut got).map_err(|e| format!("server read: {e}"))?;
    s.writer().write_all(&got).map_err(|e| format!("server write: {e}"))?;
    down += flow(&mut s, &mut c)?;
    let mut reply = vec![0u8; request.len()];
    c.reader().read_exact(&mut reply).map_err(|e| format!("client read: {e}"))?;
    Ok(Outcome { version, suite, client_wire: up, server_wire: down, request: got, reply })
}

/// The loopback handshake of the fixtures at the fixed time: what the probe
/// prints and the host test checks.
pub fn self_test(request: &[u8]) -> Result<Outcome, String> {
    let time: Arc<dyn TimeProvider> = Arc::new(FixedTime);
    let client = client_config(time.clone()).map_err(|e| e.to_string())?;
    let server = server_config(time).map_err(|e| e.to_string())?;
    loopback(client, server, SERVER_NAME, request)
}

/// The client side over a byte stream (a `TcpStream`): handshake, write
/// `request`, read until the server closes or `limit` bytes. The trust anchor is
/// the test CA, so the peer is a server holding the fixtures (`openssl s_server
/// -certform DER -cert pki/leaf.der -keyform DER -key pki/leaf_key.der`), and
/// the clock is `time` ([`DeviceTime`] on a device).
pub fn fetch<S: Read + Write>(
    stream: &mut S,
    name: &str,
    request: &[u8],
    limit: usize,
    time: Arc<dyn TimeProvider>,
) -> io::Result<Vec<u8>> {
    let config = client_config(time).map_err(|e| io::Error::other(e.to_string()))?;
    let server_name = ServerName::try_from(name.to_owned()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let mut conn = ClientConnection::new(config, server_name).map_err(|e| io::Error::other(e.to_string()))?;
    let mut tls = rustls::Stream::new(&mut conn, stream);
    tls.write_all(request)?;
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    while out.len() < limit {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            // A close without close_notify ends the reply as well.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}
