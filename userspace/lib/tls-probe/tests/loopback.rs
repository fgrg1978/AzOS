// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The probe's TLS exchange on the host, which is the only place a handshake can
//! run before a device has a network: client and server (rustls over the
//! rustcrypto provider) over memory and over a loopback TCP connection, the
//! certificate chain checked against the test CA, application data both ways,
//! and the refusals a device will meet (a wrong name, an unknown CA, a clock
//! that has not been set). Run with
//! `python3 userspace/lib/tls-probe/vendor.py test`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::pki_types::UnixTime;
use rustls::time_provider::TimeProvider;
use rustls::{RootCertStore, ServerConnection};
use tls_probe::tls::{self, FixedTime, SERVER_NAME};

fn fixed() -> Arc<dyn TimeProvider> {
    Arc::new(FixedTime)
}

/// A clock stuck at the epoch: a device whose time source has not run.
#[derive(Debug)]
struct Unset;

impl TimeProvider for Unset {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(1000)))
    }
}

#[test]
fn a_client_and_a_server_handshake_and_echo() {
    let o = tls::self_test(b"hello from the probe").expect("loopback handshake");
    assert_eq!(o.request, b"hello from the probe");
    assert_eq!(o.reply, b"hello from the probe");
    assert!(o.version.contains("1_3"), "TLS 1.3 expected, got {}", o.version);
    assert!(o.client_wire > 0 && o.server_wire > o.client_wire, "the server sends the certificate chain: {o}");
}

/// **Canary:** a client that did not check the name would pass this.
#[test]
fn a_certificate_for_another_name_is_refused() {
    let err = tls::loopback(tls::client_config(fixed()).unwrap(), tls::server_config(fixed()).unwrap(), "other.azos", b"x")
        .expect_err("the leaf is for probe.azos");
    assert!(err.contains("NotValidForName") || err.contains("not valid for name"), "{err}");
}

/// **Canary:** a client that trusted whatever it was shown would pass this.
#[test]
fn a_chain_to_an_unknown_ca_is_refused() {
    let client = Arc::new(
        rustls::ClientConfig::builder_with_details(tls::provider(), fixed())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth(),
    );
    let err = tls::loopback(client, tls::server_config(fixed()).unwrap(), SERVER_NAME, b"x").expect_err("no trust anchor");
    assert!(err.contains("UnknownIssuer") || err.contains("unknown"), "{err}");
}

/// A device whose clock reads 1970 plus the uptime finds the certificate not
/// valid yet: the handshake fails rather than trusting a wrong time.
#[test]
fn an_unset_clock_fails_the_validity_check() {
    let err = tls::loopback(tls::client_config(Arc::new(Unset)).unwrap(), tls::server_config(fixed()).unwrap(), SERVER_NAME, b"x")
        .expect_err("the certificate is not valid in 1970");
    assert!(err.contains("NotValidYet") || err.contains("not valid yet"), "{err}");
}

/// The same exchange over a real TCP connection and `tls::fetch`, the path the
/// device runs over a `TcpStream`.
#[test]
fn fetch_over_a_loopback_tcp_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut conn = ServerConnection::new(tls::server_config(fixed()).unwrap()).unwrap();
        let mut stream = rustls::Stream::new(&mut conn, &mut sock);
        let mut req = [0u8; 18];
        stream.read_exact(&mut req).unwrap();
        assert_eq!(&req, b"GET / HTTP/1.0\r\n\r\n");
        stream.write_all(b"HTTP/1.0 200 OK\r\n\r\nfrom the server").unwrap();
        stream.conn.send_close_notify();
        stream.flush().unwrap();
    });
    let mut sock = TcpStream::connect(addr).unwrap();
    let reply = tls::fetch(&mut sock, SERVER_NAME, b"GET / HTTP/1.0\r\n\r\n", 4096, fixed()).expect("fetch");
    server.join().unwrap();
    assert_eq!(reply, b"HTTP/1.0 200 OK\r\n\r\nfrom the server");
}
