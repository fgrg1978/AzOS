// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The development package source of the installer: a signed package fetched
//! over TFTP from the development host.
//!
//! `Packages::fetch` reads `/fat/PKG/SOURCE.CFG` and hands the rows to a
//! [`Remote`]. In a production build that is HTTPS to a pinned server
//! (`azos_tls::remote`). In a development build (Kconfig `PKG_FETCH_TFTP`, which
//! needs `BUILD_TYPE_DEV`) the same file may instead name a TFTP server, which
//! is what a developer has running on the host (`tools/dev/tftp_serve.py`, QEMU's
//! `-netdev user,tftp=DIR` at 10.0.2.2):
//!
//! ```text
//! tftp=10.0.2.2         # the server's IPv4 address, optionally :port (default 69)
//! file=acme-vision.pkg  # what to read
//! ```
//!
//! TFTP authenticates nothing, and does not need to: this source only
//! delivers bytes. What the installer does with them does not depend on how
//! they came -- the package is installed because its own signature verifies
//! against the signers of the device's signed topology, so a package fetched
//! this way has no more authority than one placed on the disk, and a forged one
//! is refused and journalled like any other (`tests/host/pkg-tests`,
//! `tftp_source`).
//!
//! The socket is `std::net::UdpSocket`, the warrant `PKGD.ELF`'s seccomp
//! profile already grants for its HTTPS dial (the UDP ops of the socket
//! layer); this module adds no authority. The protocol is `azos_tftp`'s.

use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use azos_packages::{FetchErr, Remote};
use azos_tftp::client::{tftp_fetch, Pacing, TftpFetchError, UdpTransport};
use azos_tftp::{TFTP_BLOCK_SIZE, TFTP_MAX_FILENAME_BYTES, TFTP_PORT};

/// How long one wait for a datagram lasts: the unit [`Pacing`] counts in.
const WAIT: Duration = Duration::from_millis(250);
/// Silent waits before the last datagram is sent again (one second).
const RESEND_AFTER: u32 = 4;
/// Resends in a row, without a block arriving, before the fetch gives up.
const MAX_RESENDS: u32 = 8;
/// Waits beyond one per block (and a few repeats of each) that a whole fetch
/// may spend on the silences of a lossy path.
const SLACK_POLLS: u32 = 2_000;
/// How long the whole fetch may take, from the request to the last block.
const TOTAL: Duration = Duration::from_secs(120);

/// Why rows are not a TFTP source.
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
    /// A value that does not parse.
    Value(&'static str),
}

/// A TFTP source: the server to ask and the file to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub server: SocketAddrV4,
    pub file: String,
}

fn rows_of(text: &[u8]) -> Option<impl Iterator<Item = (usize, &str)>> {
    let text = std::str::from_utf8(text).ok()?;
    Some(text.lines().enumerate().map(|(i, l)| (i + 1, l.split('#').next().unwrap_or("").trim())).filter(|(_, l)| !l.is_empty()))
}

/// Do the rows of `SOURCE.CFG` name a TFTP source? Only the presence of the
/// `tftp` key decides it: a mistake in the rest is [`Source::parse`]'s to
/// report, not a reason to try another transport.
pub fn is_tftp(text: &[u8]) -> bool {
    rows_of(text).is_some_and(|mut rows| rows.any(|(_, l)| l.split_once('=').is_some_and(|(k, _)| k.trim() == "tftp")))
}

impl Source {
    /// The source the rows in `text` describe.
    pub fn parse(text: &[u8]) -> Result<Self, RowError> {
        let rows = rows_of(text).ok_or(RowError::Encoding)?;
        let (mut server, mut file) = (None, None);
        let mut seen: Vec<&str> = Vec::new();
        for (n, line) in rows {
            let (key, value) = line.split_once('=').ok_or(RowError::Line(n))?;
            let (key, value) = (key.trim(), value.trim());
            if seen.contains(&key) {
                return Err(RowError::Duplicate(n));
            }
            seen.push(key);
            match key {
                "tftp" => {
                    // An address alone is the well-known port.
                    server = Some(
                        value
                            .parse::<SocketAddrV4>()
                            .or_else(|_| value.parse::<Ipv4Addr>().map(|ip| SocketAddrV4::new(ip, TFTP_PORT)))
                            .map_err(|_| RowError::Value("tftp"))?,
                    )
                }
                "file" => {
                    // One word of printable ASCII that fits the request packet:
                    // no space, no NUL, nothing that is not a name.
                    let ok = !value.is_empty() && value.len() <= TFTP_MAX_FILENAME_BYTES && value.bytes().all(|b| b.is_ascii_graphic());
                    file = Some(ok.then(|| value.to_owned()).ok_or(RowError::Value("file"))?)
                }
                _ => return Err(RowError::Line(n)),
            }
        }
        Ok(Self { server: server.ok_or(RowError::Missing("tftp"))?, file: file.ok_or(RowError::Missing("file"))? })
    }
}

/// The fetch loop's datagram socket: a `std::net::UdpSocket`, bound to an
/// ephemeral port and NOT connected (the server replies from a port of its own
/// choosing), whose every wait for a datagram is [`WAIT`] and which gives up
/// altogether at `end`.
struct StdUdp {
    sock: RefCell<Option<UdpSocket>>,
    end: Instant,
}

impl UdpTransport for StdUdp {
    fn bind(&self) -> i32 {
        match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
            Ok(s) if s.set_read_timeout(Some(WAIT)).is_ok() => {
                *self.sock.borrow_mut() = Some(s);
                0
            }
            _ => -1,
        }
    }

    fn unbind(&self, _sock: usize) {
        *self.sock.borrow_mut() = None;
    }

    fn sendto(&self, _sock: i32, dst_ip: &[u8; 4], dst_port: u16, data: &[u8]) -> i32 {
        match self.sock.borrow().as_ref() {
            Some(s) if s.send_to(data, SocketAddr::from((*dst_ip, dst_port))).is_ok() => 0,
            _ => -1,
        }
    }

    fn recvfrom(&self, _sock: i32, buf: &mut [u8], src_ip: &mut [u8; 4], src_port: &mut u16) -> i32 {
        // Past the deadline nothing is waited for: the loop sees silence and
        // gives up after its resends, at once.
        if Instant::now() >= self.end {
            return -1;
        }
        match self.sock.borrow().as_ref().map(|s| s.recv_from(buf)) {
            Some(Ok((n, SocketAddr::V4(from)))) => {
                *src_ip = from.ip().octets();
                *src_port = from.port();
                n as i32
            }
            // A timeout is the ordinary silence; any other error reads the same.
            _ => 0,
        }
    }

    fn poll(&self) {}
}

/// A [`Remote`] over TFTP, with the time a whole fetch may take.
pub struct TftpRemote {
    /// From the request to the last block (the host suite shortens it).
    pub total: Duration,
}

impl TftpRemote {
    /// A fetch is cut off after two minutes.
    pub const fn new() -> Self {
        Self { total: TOTAL }
    }
}

impl Remote for TftpRemote {
    fn get(&mut self, rows: &[u8], buf: &mut [u8]) -> Result<usize, FetchErr> {
        let source = Source::parse(rows).map_err(|_| FetchErr::Rows)?;
        let blocks = (buf.len() / TFTP_BLOCK_SIZE + 1) as u32;
        let pacing = Pacing {
            // A wait per block, with room for a few repeats, and the silences.
            max_polls: blocks.saturating_mul(3).saturating_add(SLACK_POLLS),
            resend_after: RESEND_AFTER,
            max_resends: MAX_RESENDS,
        };
        let net = StdUdp { sock: RefCell::new(None), end: Instant::now() + self.total };
        tftp_fetch(&net, source.server.ip().octets(), source.server.port(), &source.file, buf, pacing).map_err(|e| match e {
            TftpFetchError::Encode(_) => FetchErr::Rows,
            TftpFetchError::BufferOverflow => FetchErr::TooLarge,
            TftpFetchError::SocketBindFailed | TftpFetchError::SendFailed | TftpFetchError::NoReply => FetchErr::Connect,
            // The server refused (no such file, access violation): an answer
            // that is not the package.
            TftpFetchError::ServerError(_) => FetchErr::Status,
            TftpFetchError::OutOfOrderBlock { .. } | TftpFetchError::PollBudgetExhausted => FetchErr::Io,
        })
    }
}

/// The installer's package source: HTTPS to a pinned server, and, when `TFTP`
/// (Kconfig `PKG_FETCH_TFTP`, a development build), TFTP when the rows name a
/// `tftp` server. A production build compiles the TFTP branch out: a `tftp=`
/// row is then an HTTPS source with an unknown key, which is refused as a
/// source that is not one.
pub struct Sources<H: Remote, const TFTP: bool> {
    pub https: H,
    pub tftp: TftpRemote,
}

impl<H: Remote, const TFTP: bool> Sources<H, TFTP> {
    pub fn new(https: H) -> Self {
        Self { https, tftp: TftpRemote::new() }
    }
}

impl<H: Remote, const TFTP: bool> Remote for Sources<H, TFTP> {
    fn get(&mut self, rows: &[u8], buf: &mut [u8]) -> Result<usize, FetchErr> {
        if TFTP && is_tftp(rows) {
            self.tftp.get(rows, buf)
        } else {
            self.https.get(rows, buf)
        }
    }
}
