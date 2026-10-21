// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The package source of the installer: HTTPS to a pinned server.
//!
//! `Service::fetch` (userspace/lib/packages) reads the source rows off its
//! volume and hands them to a [`Remote`]; this is the one that dials
//! `std::net`, handshakes against the pins in the rows and GETs the path.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use azos_packages::{FetchErr, Remote};
use rustls::time_provider::TimeProvider;

use crate::http::{self, HttpError};
use crate::rows::Source;
use crate::time::DeviceTime;
use crate::client;

/// How long one read or write on the connection may wait.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the whole fetch may take, from the first SYN to the last byte:
/// connect, handshake and transfer together. A server that answers every
/// 29 seconds never trips [`IO_TIMEOUT`]; this is what stops it.
const TOTAL: Duration = Duration::from_secs(300);

/// The connection with one end instant for everything done on it: each read
/// and write may wait as long as is left, and no longer than [`IO_TIMEOUT`].
struct Deadline {
    tcp: TcpStream,
    end: Instant,
}

impl Deadline {
    /// The wait one operation gets, or the error that says the time is up.
    fn left(&self) -> io::Result<Duration> {
        match self.end.checked_duration_since(Instant::now()) {
            Some(left) if !left.is_zero() => Ok(left.min(IO_TIMEOUT)),
            _ => Err(io::Error::from(io::ErrorKind::TimedOut)),
        }
    }
}

impl Read for Deadline {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tcp.set_read_timeout(Some(self.left()?))?;
        self.tcp.read(buf)
    }
}

impl Write for Deadline {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tcp.set_write_timeout(Some(self.left()?))?;
        self.tcp.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

/// A [`Remote`] over TLS, with the clock it reads certificates' validity from
/// and the time a whole fetch may take.
pub struct HttpsRemote {
    time: Arc<dyn TimeProvider>,
    total: Duration,
}

impl HttpsRemote {
    /// Reading `time`; a fetch is cut off after five minutes.
    pub fn new(time: Arc<dyn TimeProvider>) -> Self {
        Self { time, total: TOTAL }
    }

    /// The same, cutting a fetch off after `total` instead.
    pub fn with_deadline(mut self, total: Duration) -> Self {
        self.total = total;
        self
    }

    /// Reading the system clock, which counts only once it has been set.
    pub fn device() -> Self {
        Self::new(Arc::new(DeviceTime))
    }
}

impl Remote for HttpsRemote {
    fn get(&mut self, rows: &[u8], buf: &mut [u8]) -> Result<usize, FetchErr> {
        let source = Source::parse(rows).map_err(|_| FetchErr::Rows)?;
        let config = client::config(&source.pins, self.time.clone()).map_err(|_| FetchErr::Tls)?;
        // A server that stops answering, or that answers just often enough,
        // must not hold the installer for ever: one deadline covers the
        // connect, the handshake and the transfer.
        let end = Instant::now() + self.total;
        let tcp = TcpStream::connect_timeout(&source.addr, self.total).map_err(|_| FetchErr::Connect)?;
        let tls_or_io = |e: &std::io::Error| if client::tls_error(e).is_some() { FetchErr::Tls } else { FetchErr::Io };
        let mut stream = client::connect(config, &source.host, Deadline { tcp, end }).map_err(|e| tls_or_io(&e))?;
        let got = http::get(&mut stream, &source.host, &source.path, buf).map_err(|e| match e {
            HttpError::Status(_) | HttpError::Malformed => FetchErr::Status,
            HttpError::TooLarge => FetchErr::TooLarge,
            HttpError::Truncated => FetchErr::Io,
            HttpError::Io(e) => tls_or_io(&e),
        })?;
        // Best effort: the package is in hand either way.
        stream.conn.send_close_notify();
        let _ = std::io::Write::flush(&mut stream);
        Ok(got)
    }
}
