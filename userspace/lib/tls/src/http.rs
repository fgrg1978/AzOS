// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A GET over a byte stream, into a caller's buffer.
//!
//! HTTP/1.0, so that the body is never chunked: it ends at `Content-Length`
//! or, without one, at the close of the stream. Redirects are not followed (a
//! pinned source answers for itself), and a body that cannot be shown to be
//! whole is an error: a stream that ends early, with or without a
//! `Content-Length`, is [`HttpError::Truncated`]. Over TLS a close without
//! `close_notify` surfaces as `UnexpectedEof`, which is the same thing.

use std::fmt;
use std::io::{self, Read, Write};

/// The most response header this reads.
pub const HEAD_MAX: usize = 8 * 1024;

/// Why a GET failed.
#[derive(Debug)]
pub enum HttpError {
    /// The stream failed.
    Io(io::Error),
    /// The status line or a header is not HTTP/1.x as this reads it.
    Malformed,
    /// A status other than 200.
    Status(u16),
    /// The body is longer than the buffer.
    TooLarge,
    /// The body ends before it should.
    Truncated,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "stream: {e}"),
            Self::Malformed => write!(f, "malformed response"),
            Self::Status(s) => write!(f, "status {s}"),
            Self::TooLarge => write!(f, "body larger than the buffer"),
            Self::Truncated => write!(f, "body truncated"),
        }
    }
}

impl std::error::Error for HttpError {}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// `(status, Content-Length)` of the header block in `head` (no final blank line).
fn parse_head(head: &[u8]) -> Result<(u16, Option<usize>), HttpError> {
    let text = std::str::from_utf8(head).map_err(|_| HttpError::Malformed)?;
    let mut lines = text.split("\r\n");
    let mut status = lines.next().ok_or(HttpError::Malformed)?.split(' ');
    if !status.next().is_some_and(|v| v == "HTTP/1.0" || v == "HTTP/1.1") {
        return Err(HttpError::Malformed);
    }
    let code: u16 = status.next().and_then(|c| c.parse().ok()).ok_or(HttpError::Malformed)?;
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(HttpError::Malformed)?;
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                let n: usize = value.trim().parse().map_err(|_| HttpError::Malformed)?;
                if length.replace(n).is_some_and(|prev| prev != n) {
                    return Err(HttpError::Malformed);
                }
            }
            // Asked for HTTP/1.0; a server that chunks anyway is not understood.
            "transfer-encoding" => return Err(HttpError::Malformed),
            _ => {}
        }
    }
    Ok((code, length))
}

fn read_error(e: io::Error) -> HttpError {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        HttpError::Truncated
    } else {
        HttpError::Io(e)
    }
}

/// GET `path` from `host` over `stream` into `buf`: the body's length.
pub fn get<S: Read + Write>(stream: &mut S, host: &str, path: &str, buf: &mut [u8]) -> Result<usize, HttpError> {
    let request = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nAccept: application/octet-stream\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).and_then(|()| stream.flush()).map_err(HttpError::Io)?;

    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let end = loop {
        if let Some(at) = find(&head, b"\r\n\r\n") {
            break at;
        }
        if head.len() > HEAD_MAX {
            return Err(HttpError::Malformed);
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err(HttpError::Truncated),
            Ok(n) => head.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(read_error(e)),
        }
    };
    let (code, length) = parse_head(&head[..end])?;
    if code != 200 {
        return Err(HttpError::Status(code));
    }
    // The body bytes that arrived with the header, then the rest of it.
    let first = &head[end + 4..];
    let cap = length.unwrap_or(buf.len());
    if cap > buf.len() || first.len() > cap {
        return Err(if cap > buf.len() || length.is_none() { HttpError::TooLarge } else { HttpError::Malformed });
    }
    buf[..first.len()].copy_from_slice(first);
    let mut n = first.len();
    loop {
        if length == Some(n) {
            return Ok(n);
        }
        if n == cap {
            // No Content-Length and the buffer is full: more body is too much.
            return match stream.read(&mut chunk[..1]) {
                Ok(0) => Ok(n),
                Ok(_) => Err(HttpError::TooLarge),
                Err(e) => Err(read_error(e)),
            };
        }
        match stream.read(&mut buf[n..cap]) {
            Ok(0) if length.is_none() => return Ok(n),
            Ok(0) => return Err(HttpError::Truncated),
            Ok(k) => n += k,
            Err(e) => return Err(read_error(e)),
        }
    }
}
