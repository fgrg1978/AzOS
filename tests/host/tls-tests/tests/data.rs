// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the pinned client reads and writes without a network: pins out of
//! certificates, the source rows, and the HTTP GET over a scripted stream.

mod common;

use std::io::{self, Read, Write};

use azos_tls::http::{self, HttpError};
use azos_tls::pin;
use azos_tls::rows::{RowError, Source, MAX_PINS};
use common::*;

#[test]
fn pins_of_the_fixtures_are_openssls() {
    for (der, want) in [(GOOD, GOOD_PIN), (OTHER, OTHER_PIN), (EXPIRED, EXPIRED_PIN)] {
        assert_eq!(pin::to_hex(&pin::of_certificate(der).unwrap()), want);
    }
}

#[test]
fn a_certificate_that_is_not_one_has_no_pin() {
    assert!(pin::of_certificate(b"").is_none());
    assert!(pin::of_certificate(&[0x30, 0x80, 0, 0]).is_none(), "indefinite length");
    for cut in [1, 5, 40, GOOD.len() / 2, GOOD.len() - 1] {
        assert!(pin::of_certificate(&GOOD[..cut]).is_none(), "cut at {cut}");
    }
}

#[test]
fn pin_hex_round_trips_and_refuses_the_wrong_length() {
    assert_eq!(pin::to_hex(&pin_of(GOOD_PIN)), GOOD_PIN);
    assert_eq!(pin::from_hex(&GOOD_PIN.to_uppercase()), Some(pin_of(GOOD_PIN)));
    assert!(pin::from_hex(&GOOD_PIN[1..]).is_none());
    assert!(pin::from_hex(&format!("{}g", &GOOD_PIN[1..])).is_none());
}

const ROWS: &str = "\
# the package source
host=packages.example.org
addr=203.0.113.7:443   # no DNS
path=/azos/acme.pkg

pin_1=82d7b7beae24051a8c8e1eff0f77c816547f45e1908c912eb82418f5a19531a2
pin_2=e80a35476a947c49e8cb116a9d18d59e555458aa6147703a1e1ba9c5db945e24
";

#[test]
fn rows_describe_a_source() {
    let s = Source::parse(ROWS.as_bytes()).unwrap();
    assert_eq!(s.host, "packages.example.org");
    assert_eq!(s.addr.to_string(), "203.0.113.7:443");
    assert_eq!(s.path, "/azos/acme.pkg");
    assert_eq!(s.pins, vec![pin_of(GOOD_PIN), pin_of(OTHER_PIN)]);
}

#[test]
fn rows_that_are_not_a_source_are_refused() {
    let without = |key: &str| ROWS.lines().filter(|l| !l.starts_with(key)).collect::<Vec<_>>().join("\n");
    let parse = |t: &str| Source::parse(t.as_bytes());
    assert_eq!(parse(&without("pin_")), Err(RowError::Missing("pin_1")), "a source with no pin trusts nobody");
    assert_eq!(parse(&without("host")), Err(RowError::Missing("host")));
    assert_eq!(parse(&without("addr")), Err(RowError::Missing("addr")));
    assert_eq!(parse(&without("path")), Err(RowError::Missing("path")));
    assert_eq!(parse(&format!("{ROWS}host=again\n")), Err(RowError::Duplicate(8)));
    assert_eq!(parse(&format!("{ROWS}ca=system\n")), Err(RowError::Line(8)), "there is no system CA store to ask for");
    assert_eq!(parse(&format!("{ROWS}nonsense\n")), Err(RowError::Line(8)));
    assert_eq!(parse(&ROWS.replace("/azos/acme.pkg", "azos")), Err(RowError::Value("path")));
    assert_eq!(parse(&ROWS.replace("203.0.113.7:443", "example.org:443")), Err(RowError::Value("addr")));
    assert_eq!(parse(&ROWS.replace(GOOD_PIN, "abcd")), Err(RowError::Value("pin")));
    assert_eq!(Source::parse(&[0xFF, 0xFE]), Err(RowError::Encoding));
    // A value that would end the request line or add a header.
    assert_eq!(parse(&ROWS.replace("/azos/acme.pkg", "/a HTTP/1.0\\r\\nX: y")), Err(RowError::Value("path")));
    assert_eq!(parse(&ROWS.replace("packages.example.org", "a b")), Err(RowError::Value("host")));
    let many: String = (1..=MAX_PINS + 1).map(|i| format!("pin_{i}={GOOD_PIN}\n")).collect();
    assert_eq!(parse(&format!("host=h\naddr=1.2.3.4:5\npath=/p\n{many}")), Err(RowError::TooManyPins));
}

/// A stream that answers a request with a script and then ends.
struct Script {
    reply: io::Cursor<Vec<u8>>,
    sent: Vec<u8>,
    /// Fail the read after the script with this error instead of ending.
    then: Option<io::ErrorKind>,
}

fn script(reply: &[u8]) -> Script {
    Script { reply: io::Cursor::new(reply.to_vec()), sent: Vec::new(), then: None }
}

impl Read for Script {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Small pieces, so that a header and a body arrive split anywhere.
        let n = buf.len().min(7);
        match self.reply.read(&mut buf[..n])? {
            0 => self.then.map_or(Ok(0), |k| Err(k.into())),
            n => Ok(n),
        }
    }
}

impl Write for Script {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.sent.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn run(reply: &[u8], cap: usize) -> (Result<usize, HttpError>, Vec<u8>) {
    let mut s = script(reply);
    let mut buf = vec![0u8; cap];
    let r = http::get(&mut s, "h", "/p", &mut buf);
    let n = *r.as_ref().unwrap_or(&0);
    buf.truncate(n);
    (r, buf)
}

#[test]
fn a_get_reads_the_body_by_content_length_or_to_the_end() {
    let (r, b) = run(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-A: b\r\n\r\nhello", 100);
    assert_eq!((r.unwrap(), b.as_slice()), (5, &b"hello"[..]));
    let (r, b) = run(b"HTTP/1.0 200 OK\r\n\r\nuntil the end", 100);
    assert_eq!((r.unwrap(), b.as_slice()), (13, &b"until the end"[..]));
    let (r, b) = run(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", 100);
    assert_eq!((r.unwrap(), b.len()), (0, 0));
    let mut s = script(b"HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\nx");
    http::get(&mut s, "pkg.example", "/azos/a.pkg", &mut [0u8; 4]).unwrap();
    assert_eq!(s.sent, b"GET /azos/a.pkg HTTP/1.0\r\nHost: pkg.example\r\nAccept: application/octet-stream\r\nConnection: close\r\n\r\n");
}

#[test]
fn a_get_that_cannot_prove_the_body_whole_fails() {
    let truncated = |r: Result<usize, HttpError>| matches!(r, Err(HttpError::Truncated));
    assert!(truncated(run(b"HTTP/1.0 200 OK\r\nContent-Length: 10\r\n\r\nshort", 100).0));
    assert!(truncated(run(b"HTTP/1.0 200 OK\r\nContent-Le", 100).0), "the header itself is cut");
    let mut s = script(b"HTTP/1.0 200 OK\r\n\r\ncut by an attacker");
    s.then = Some(io::ErrorKind::UnexpectedEof);
    assert!(truncated(http::get(&mut s, "h", "/p", &mut [0u8; 100])), "no Content-Length and no close_notify");
}

#[test]
fn a_get_refuses_what_it_does_not_understand() {
    assert!(matches!(run(b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n", 10).0, Err(HttpError::Status(404))));
    assert!(matches!(run(b"HTTP/1.1 301 Moved\r\nLocation: http://elsewhere/\r\n\r\n", 10).0, Err(HttpError::Status(301))));
    assert!(matches!(run(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", 100).0, Err(HttpError::Malformed)));
    assert!(matches!(run(b"SMTP/1.0 200 OK\r\n\r\n", 10).0, Err(HttpError::Malformed)));
    assert!(matches!(run(b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd", 10).0, Err(HttpError::Malformed)));
    assert!(matches!(run(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nabcd", 10).0, Err(HttpError::Malformed)), "more than it said");
    let long = format!("HTTP/1.0 200 OK\r\nX: {}\r\n\r\n", "y".repeat(http::HEAD_MAX));
    assert!(matches!(run(long.as_bytes(), 10).0, Err(HttpError::Malformed)));
}

#[test]
fn a_get_never_overruns_its_buffer() {
    assert!(matches!(run(b"HTTP/1.0 200 OK\r\nContent-Length: 11\r\n\r\nhello world", 10).0, Err(HttpError::TooLarge)));
    assert!(matches!(run(b"HTTP/1.0 200 OK\r\n\r\nhello world", 10).0, Err(HttpError::TooLarge)));
    assert!(matches!(run(b"HTTP/1.0 200 OK\r\n\r\nhello worl", 10).0, Ok(10)), "exactly full");
}
