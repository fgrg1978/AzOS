// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The pinned client against a TLS server over loopback TCP: the handshake and
//! the refusals. Every refusal has the same setup with the fault removed that
//! succeeds, so a refusal cannot come from anything else; the `canary-*`
//! features turn one check off and the guarding test must fail.

mod common;

use std::net::TcpStream;

use azos_tls::client;
use azos_tls::http;
use azos_tls::verify::PinMismatch;
use common::*;
use rustls::{CertificateError, Error};

/// Handshake and GET `path` from a server presenting `cert`, pinned to `pins`,
/// asking for the name `host`, the client's clock at `now`.
fn get(
    cert: (&[u8], &[u8]),
    server_clock: u64,
    pins: &[&str],
    host: &str,
    now: u64,
) -> (Result<Vec<u8>, std::io::Error>, std::io::Result<String>) {
    let (addr, server) = serve(cert.0, cert.1, at(server_clock), Reply::Ok(body(3000)));
    let pins: Vec<_> = pins.iter().map(|p| pin_of(p)).collect();
    let result = (|| {
        let config = client::config(&pins, at(now)).map_err(std::io::Error::other)?;
        let mut tls = client::connect(config, host, TcpStream::connect(addr)?)?;
        let mut buf = vec![0u8; 4096];
        let n = http::get(&mut tls, host, "/azos/acme.pkg", &mut buf).map_err(std::io::Error::other)?;
        buf.truncate(n);
        Ok(buf)
    })();
    (result, server.join().unwrap())
}

fn refusal(r: &Result<Vec<u8>, std::io::Error>) -> &Error {
    let e = r.as_ref().expect_err("the handshake must be refused");
    client::tls_error(e).unwrap_or_else(|| panic!("a TLS error, not {e}"))
}

#[test]
fn a_pinned_server_is_fetched_from_over_loopback() {
    let (got, served) = get((GOOD, GOOD_KEY), NOW, &[GOOD_PIN], NAME, NOW);
    assert_eq!(got.expect("fetch"), body(3000));
    let request = served.expect("server");
    assert!(request.starts_with("GET /azos/acme.pkg HTTP/1.0\r\nHost: probe.azos\r\n"), "{request:?}");
}

/// **Canary `canary-no-pin`:** a client that took any certificate it was shown passes this.
#[test]
fn a_pin_mismatch_is_refused() {
    let (got, _) = get((OTHER, OTHER_KEY), NOW, &[GOOD_PIN], NAME, NOW);
    let Error::InvalidCertificate(CertificateError::Other(other)) = refusal(&got) else { panic!("{:?}", refusal(&got)) };
    let mismatch = other.0.downcast_ref::<PinMismatch>().expect("a PinMismatch");
    assert_eq!(azos_tls::pin::to_hex(&mismatch.presented), OTHER_PIN);
}

/// The same server, once its key is pinned (the next key listed while the first retires).
#[test]
fn any_one_of_the_pins_accepts() {
    let (got, _) = get((OTHER, OTHER_KEY), NOW, &[GOOD_PIN, OTHER_PIN], NAME, NOW);
    assert_eq!(got.expect("rotated key"), body(3000));
}

/// **Canary `canary-no-validity`:** a client that did not look at the dates passes this.
#[test]
fn an_expired_certificate_is_refused() {
    let (got, _) = get((EXPIRED, EXPIRED_KEY), WHEN_EXPIRED_WAS_VALID, &[EXPIRED_PIN], NAME, NOW);
    assert!(matches!(refusal(&got), Error::InvalidCertificate(CertificateError::Expired)), "{:?}", refusal(&got));
}

/// The expired certificate, on a day it was valid: the refusal above is the date and nothing else.
#[test]
fn the_same_certificate_is_accepted_inside_its_day() {
    let (got, _) = get((EXPIRED, EXPIRED_KEY), WHEN_EXPIRED_WAS_VALID, &[EXPIRED_PIN], NAME, WHEN_EXPIRED_WAS_VALID);
    assert_eq!(got.expect("inside the window"), body(3000));
}

/// A device whose clock has not been set reads 1970 plus the uptime: before every certificate.
#[test]
fn a_certificate_not_yet_valid_is_refused() {
    let (got, _) = get((GOOD, GOOD_KEY), NOW, &[GOOD_PIN], NAME, 5_000);
    assert!(matches!(refusal(&got), Error::InvalidCertificate(CertificateError::NotValidYet)), "{:?}", refusal(&got));
}

#[test]
fn a_certificate_for_another_name_is_refused() {
    let (got, _) = get((GOOD, GOOD_KEY), NOW, &[GOOD_PIN], "other.azos", NOW);
    assert!(
        matches!(refusal(&got), Error::InvalidCertificate(CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. })),
        "{:?}",
        refusal(&got)
    );
}

#[test]
fn a_client_with_no_pin_cannot_be_built() {
    assert!(client::config(&[], at(NOW)).is_err());
}

/// A server that cuts the connection short of its Content-Length, with no
/// close_notify, is a truncated package and not a short one.
#[test]
fn a_cut_connection_is_a_truncated_body() {
    let (addr, _server) = serve(GOOD, GOOD_KEY, at(NOW), Reply::Cut { claimed: 1000, sent: 400 });
    let config = client::config(&[pin_of(GOOD_PIN)], at(NOW)).unwrap();
    let mut tls = client::connect(config, NAME, TcpStream::connect(addr).unwrap()).unwrap();
    let mut buf = vec![0u8; 2000];
    let err = http::get(&mut tls, NAME, "/x", &mut buf).expect_err("truncated");
    assert!(matches!(err, http::HttpError::Truncated), "{err}");
}

/// The window is read to the second: `expired.der` is valid from 2020-01-01
/// 00:00:00 to 2020-01-01 23:59:59 UTC, both ends included.
#[test]
fn the_validity_window_is_exact_to_the_second() {
    let try_at = |t: u64| get((EXPIRED, EXPIRED_KEY), t, &[EXPIRED_PIN], NAME, t).0;
    let (first, last) = (1_577_836_800, 1_577_923_199);
    assert!(try_at(first).is_ok() && try_at(last).is_ok());
    assert!(matches!(refusal(&try_at(first - 1)), Error::InvalidCertificate(CertificateError::NotValidYet)));
    assert!(matches!(refusal(&try_at(last + 1)), Error::InvalidCertificate(CertificateError::Expired)));
}
