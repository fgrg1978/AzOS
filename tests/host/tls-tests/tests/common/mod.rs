// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Shared by the suites: the fixtures, a clock, and a TLS server on loopback.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use azos_tls::pin::{self, Pin};
use azos_tls::server;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::time_provider::TimeProvider;

pub const GOOD: &[u8] = include_bytes!("../../pki/good.der");
pub const GOOD_KEY: &[u8] = include_bytes!("../../pki/good_key.der");
pub const OTHER: &[u8] = include_bytes!("../../pki/other.der");
pub const OTHER_KEY: &[u8] = include_bytes!("../../pki/other_key.der");
pub const EXPIRED: &[u8] = include_bytes!("../../pki/expired.der");
pub const EXPIRED_KEY: &[u8] = include_bytes!("../../pki/expired_key.der");

/// The pins as `pki/gen.sh` prints them, from OpenSSL (`x509 -pubkey | pkey
/// -pubin -outform DER | dgst -sha256`): an oracle that is not this code.
pub const GOOD_PIN: &str = "82d7b7beae24051a8c8e1eff0f77c816547f45e1908c912eb82418f5a19531a2";
pub const OTHER_PIN: &str = "e80a35476a947c49e8cb116a9d18d59e555458aa6147703a1e1ba9c5db945e24";
pub const EXPIRED_PIN: &str = "59f282e437f47f18ea01280cbb789438bc32866b4614a9a7bcf07957e845d746";

pub const NAME: &str = "probe.azos";
/// 2026-10-17 00:00:00 UTC: inside `good` and `other`, long after `expired`.
pub const NOW: u64 = 1_792_195_200;
/// 2020-01-01 12:00:00 UTC: inside `expired`'s one day.
pub const WHEN_EXPIRED_WAS_VALID: u64 = 1_577_880_000;

pub fn pin_of(hex: &str) -> Pin {
    pin::from_hex(hex).expect("a pin")
}

/// A clock stuck at one instant.
#[derive(Debug)]
pub struct At(pub u64);

impl TimeProvider for At {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
    }
}

pub fn at(secs: u64) -> Arc<dyn TimeProvider> {
    Arc::new(At(secs))
}

/// What the loopback server does once the handshake is done.
pub enum Reply {
    /// Read the request, answer 200 with this body (and a Content-Length), then close_notify.
    Ok(Vec<u8>),
    /// Answer with this status line and no body.
    Status(u16),
    /// Promise `claimed` bytes, send `sent` of them, and drop the TCP connection with no close_notify.
    Cut { claimed: usize, sent: usize },
}

/// A TLS server presenting `cert` with `key` on a loopback port, serving one connection with `reply`.
/// The thread returns the request it read, or the error the handshake ended in.
pub fn serve(cert: &[u8], key: &[u8], time: Arc<dyn TimeProvider>, reply: Reply) -> (SocketAddr, JoinHandle<std::io::Result<String>>) {
    let config = server::config(
        vec![CertificateDer::from(cert.to_vec())],
        PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.to_vec())),
        time,
    )
    .expect("server config");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (tcp, _) = listener.accept()?;
        tcp.set_read_timeout(Some(Duration::from_secs(20)))?;
        let mut tls = server::accept(config, tcp)?;
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            if tls.read(&mut byte)? == 0 {
                break;
            }
            request.push(byte[0]);
        }
        match reply {
            Reply::Ok(body) => {
                tls.write_all(format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes())?;
                tls.write_all(&body)?;
                tls.conn.send_close_notify();
                tls.flush()?;
            }
            Reply::Status(code) => {
                tls.write_all(format!("HTTP/1.0 {code} Nope\r\nContent-Length: 0\r\n\r\n").as_bytes())?;
                tls.conn.send_close_notify();
                tls.flush()?;
            }
            Reply::Cut { claimed, sent } => {
                tls.write_all(format!("HTTP/1.0 200 OK\r\nContent-Length: {claimed}\r\n\r\n").as_bytes())?;
                tls.write_all(&vec![0xAB; sent])?;
                tls.flush()?;
                // The connection ends here, with no close_notify: an attacker's truncation.
            }
        }
        Ok(String::from_utf8_lossy(&request).into_owned())
    });
    (addr, handle)
}

/// The rows of a source at `addr` pinned to `pins`.
pub fn rows(addr: SocketAddr, host: &str, pins: &[&str]) -> String {
    let mut text = format!("host={host}\naddr={addr}\npath=/azos/acme.pkg\n");
    for (i, p) in pins.iter().enumerate() {
        text.push_str(&format!("pin_{}={p}\n", i + 1));
    }
    text
}

/// A body of `n` bytes that cannot be mistaken for another of the same length.
pub fn body(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 + i / 251) as u8).collect()
}
