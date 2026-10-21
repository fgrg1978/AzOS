// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The configuration rows of a pinned HTTPS source.
//!
//! Plain `key=value` lines (`#` starts a comment, blanks are skipped), the
//! shape of the device's other configuration files; a key may appear once.
//!
//! ```text
//! host=packages.example.org     # server name: SNI, certificate name, Host header
//! addr=203.0.113.7:443          # where to connect; no DNS is involved
//! path=/azos/acme-vision.pkg    # what to GET
//! pin_1=<64 hex digits>         # SHA-256 of the server's SubjectPublicKeyInfo
//! pin_2=<64 hex digits>         # the next key, while the first retires
//! ```
//!
//! At least one pin is required, and at most [`MAX_PINS`]: a source with no pin
//! is not a source (the client has no system CA store to fall back on).

use std::fmt;
use std::net::SocketAddr;

use crate::pin::{self, Pin};

/// Pins one source can list: the key in use, its successor, and room for a recovery key.
pub const MAX_PINS: usize = 4;

/// A pinned HTTPS source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The server name the certificate must be valid for.
    pub host: String,
    /// The socket to connect to.
    pub addr: SocketAddr,
    /// The request path, starting with `/`.
    pub path: String,
    /// The accepted keys.
    pub pins: Vec<Pin>,
}

/// Why rows are not a [`Source`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowError {
    /// Not UTF-8.
    Encoding,
    /// A line without `=` or with an unknown key (the line number, from 1).
    Line(usize),
    /// A key given twice (the line number of the second).
    Duplicate(usize),
    /// A required row is missing.
    Missing(&'static str),
    /// A value that does not parse or that could be used to smuggle a header.
    Value(&'static str),
    /// More than [`MAX_PINS`] pins.
    TooManyPins,
}

impl fmt::Display for RowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding => write!(f, "rows are not UTF-8"),
            Self::Line(n) => write!(f, "line {n}: not a known key=value row"),
            Self::Duplicate(n) => write!(f, "line {n}: key given twice"),
            Self::Missing(k) => write!(f, "missing row `{k}`"),
            Self::Value(k) => write!(f, "bad value for `{k}`"),
            Self::TooManyPins => write!(f, "more than {MAX_PINS} pins"),
        }
    }
}

impl std::error::Error for RowError {}

/// A value that can sit in a request line or a header: printable ASCII, no space.
fn token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic())
}

impl Source {
    /// The source the rows in `text` describe.
    pub fn parse(text: &[u8]) -> Result<Self, RowError> {
        let text = std::str::from_utf8(text).map_err(|_| RowError::Encoding)?;
        let (mut host, mut addr, mut path) = (None, None, None);
        let mut pins: Vec<Pin> = Vec::new();
        let mut seen: Vec<&str> = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let n = i + 1;
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or(RowError::Line(n))?;
            let (key, value) = (key.trim(), value.trim());
            if seen.contains(&key) {
                return Err(RowError::Duplicate(n));
            }
            seen.push(key);
            match key {
                "host" => host = Some(token(value).then(|| value.to_owned()).ok_or(RowError::Value("host"))?),
                "addr" => addr = Some(value.parse::<SocketAddr>().map_err(|_| RowError::Value("addr"))?),
                "path" => {
                    path = Some((token(value) && value.starts_with('/')).then(|| value.to_owned()).ok_or(RowError::Value("path"))?)
                }
                k if k.starts_with("pin_") => {
                    if pins.len() == MAX_PINS {
                        return Err(RowError::TooManyPins);
                    }
                    pins.push(pin::from_hex(value).ok_or(RowError::Value("pin"))?);
                }
                _ => return Err(RowError::Line(n)),
            }
        }
        if pins.is_empty() {
            return Err(RowError::Missing("pin_1"));
        }
        Ok(Self {
            host: host.ok_or(RowError::Missing("host"))?,
            addr: addr.ok_or(RowError::Missing("addr"))?,
            path: path.ok_or(RowError::Missing("path"))?,
            pins,
        })
    }
}
