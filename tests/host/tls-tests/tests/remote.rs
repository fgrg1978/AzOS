// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The installer's HTTPS package source (`azos_tls::remote::HttpsRemote`) against
//! a pinned server over loopback: what comes back as bytes, and each way it
//! fails as the `FetchErr` the installer reports.

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use azos_packages::{FetchErr, Remote};
use azos_tls::remote::HttpsRemote;
use common::*;

fn fetch(reply: Reply, cert: (&[u8], &[u8]), pins: &[&str], cap: usize) -> (Result<Vec<u8>, FetchErr>, std::io::Result<String>) {
    let (addr, server) = serve(cert.0, cert.1, at(NOW), reply);
    let rows = rows(addr, NAME, pins);
    let mut buf = vec![0u8; cap];
    let got = HttpsRemote::new(at(NOW)).get(rows.as_bytes(), &mut buf).map(|n| buf[..n].to_vec());
    (got, server.join().unwrap())
}

#[test]
fn the_package_arrives_whole() {
    let pkg = body(70_000);
    let (got, served) = fetch(Reply::Ok(pkg.clone()), (GOOD, GOOD_KEY), &[GOOD_PIN], 80_000);
    assert_eq!(got.unwrap(), pkg);
    assert!(served.unwrap().starts_with("GET /azos/acme.pkg HTTP/1.0\r\n"));
}

/// The index and the packages an index names are the files beside the one the
/// source rows name: same server, same directory.
#[test]
fn a_sibling_is_asked_for_in_the_directory_of_the_named_file() {
    let index = body(3000);
    let (addr, server) = serve(GOOD, GOOD_KEY, at(NOW), Reply::Ok(index.clone()));
    let rows = rows(addr, NAME, &[GOOD_PIN]);
    let mut buf = vec![0u8; 4096];
    let n = HttpsRemote::new(at(NOW)).get_sibling(rows.as_bytes(), "INDEX.AZX", &mut buf).unwrap();
    assert_eq!(&buf[..n], &index[..]);
    assert!(server.join().unwrap().unwrap().starts_with("GET /azos/INDEX.AZX HTTP/1.0\r\n"));
}

#[test]
fn a_sibling_that_is_not_one_path_segment_is_not_asked_for() {
    let rows = rows("127.0.0.1:9".parse().unwrap(), NAME, &[GOOD_PIN]);
    for bad in ["", ".", "..", "a/b", "../x", "a b"] {
        assert_eq!(HttpsRemote::new(at(NOW)).get_sibling(rows.as_bytes(), bad, &mut [0u8; 8]), Err(FetchErr::Rows), "{bad:?}");
    }
}

#[test]
fn a_server_that_is_not_pinned_gives_nothing() {
    let (got, _) = fetch(Reply::Ok(body(100)), (OTHER, OTHER_KEY), &[GOOD_PIN], 1000);
    assert_eq!(got, Err(FetchErr::Tls));
}

#[test]
fn an_expired_server_gives_nothing() {
    let (got, _) = fetch(Reply::Ok(body(100)), (EXPIRED, EXPIRED_KEY), &[EXPIRED_PIN], 1000);
    assert_eq!(got, Err(FetchErr::Tls));
}

#[test]
fn an_answer_that_is_not_the_package_is_a_status() {
    let (got, _) = fetch(Reply::Status(404), (GOOD, GOOD_KEY), &[GOOD_PIN], 1000);
    assert_eq!(got, Err(FetchErr::Status));
}

#[test]
fn a_package_larger_than_the_buffer_is_too_large() {
    let (got, _) = fetch(Reply::Ok(body(1001)), (GOOD, GOOD_KEY), &[GOOD_PIN], 1000);
    assert_eq!(got, Err(FetchErr::TooLarge));
}

#[test]
fn a_cut_transfer_is_an_io_error() {
    let (got, _) = fetch(Reply::Cut { claimed: 1000, sent: 10 }, (GOOD, GOOD_KEY), &[GOOD_PIN], 2000);
    assert_eq!(got, Err(FetchErr::Io));
}

#[test]
fn nobody_listening_is_connect() {
    let addr = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let rows = rows(addr, NAME, &[GOOD_PIN]);
    assert_eq!(HttpsRemote::new(at(NOW)).get(rows.as_bytes(), &mut [0u8; 8]), Err(FetchErr::Connect));
}

#[test]
fn rows_that_are_not_a_source_are_rows() {
    assert_eq!(HttpsRemote::new(at(NOW)).get(b"host=x\n", &mut [0u8; 8]), Err(FetchErr::Rows));
}

#[test]
fn a_server_that_never_handshakes_is_cut_off_at_the_deadline() {
    // Accepts and says nothing: the handshake read waits for it.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let rows = rows(listener.local_addr().unwrap(), NAME, &[GOOD_PIN]);
    let hold = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_secs(3));
        drop(tcp);
    });
    let t = Instant::now();
    let got = HttpsRemote::new(at(NOW)).with_deadline(Duration::from_millis(400)).get(rows.as_bytes(), &mut [0u8; 8]);
    assert_eq!(got, Err(FetchErr::Io));
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    hold.join().unwrap();
}

#[test]
fn a_server_that_drips_the_package_is_cut_off_at_the_deadline() {
    // Every read is answered well inside the per-read timeout; only the total can stop it.
    let config = azos_tls::server::config(
        vec![rustls::pki_types::CertificateDer::from(GOOD.to_vec())],
        rustls::pki_types::PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(GOOD_KEY.to_vec())),
        at(NOW),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let rows = rows(listener.local_addr().unwrap(), NAME, &[GOOD_PIN]);
    let drip = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut tls = azos_tls::server::accept(config, tcp).unwrap();
        let mut byte = [0u8; 1];
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            tls.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        let _ = tls.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 1000\r\n\r\n");
        for _ in 0..100 {
            if tls.write_all(&[0xAB]).and_then(|()| tls.flush()).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    let t = Instant::now();
    let got = HttpsRemote::new(at(NOW)).with_deadline(Duration::from_millis(600)).get(rows.as_bytes(), &mut [0u8; 2000]);
    assert_eq!(got, Err(FetchErr::Io));
    assert!(t.elapsed() < Duration::from_millis(2500), "{:?}", t.elapsed());
    drip.join().unwrap();
}
