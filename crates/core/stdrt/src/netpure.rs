// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The parts of `std::net` that need no trap, so a host test can pin them: the
//! socket address wire layout, the native result code to error kind mapping and
//! the blocking wait's back-off. `crate::net` (the calls) and
//! `sdk/std/sys/net/connection/azos.rs` (the `std` types) are thin around them.
//!
//! **Wire layout.** `NODE_BIND`, `NODE_CONNECT` and `NODE_SENDTO` take a
//! `sockaddr` in a user buffer, `NODE_RECVFROM` writes one. The IPv4 form is
//! the 16 bytes the kernel's `read_sockaddr` reads today: the family (`u16`
//! little endian), the port (big endian), the address, 8 bytes of padding. The
//! IPv6 form is Linux's `sockaddr_in6` so the same text means the same thing to
//! a ported program: family, port (big endian), flow info (big endian), the 16
//! address bytes, the scope id (little endian, the ISAs' byte order), 28 bytes.
//! The kernel reads only the first 16 bytes of either, whatever length the call
//! passes (`handlers.rs::read_sockaddr`), so an IPv6 socket address does not
//! reach a socket yet; the length argument of `NODE_BIND` and `NODE_CONNECT` is
//! already part of the call.

/// `AF_INET`, the family of a 16-byte `sockaddr_in`.
pub const AF_INET: u16 = 2;
/// `AF_INET6`, the family of a 28-byte `sockaddr_in6`.
pub const AF_INET6: u16 = 10;
/// `SOCK_STREAM` (TCP).
pub const SOCK_STREAM: u64 = 1;
/// `SOCK_DGRAM` (UDP).
pub const SOCK_DGRAM: u64 = 2;
/// Bytes of a `sockaddr_in`.
pub const SOCKADDR_V4_LEN: usize = 16;
/// Bytes of a `sockaddr_in6`.
pub const SOCKADDR_V6_LEN: usize = 28;

/// A socket address, in host byte order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Addr {
    V4 { ip: [u8; 4], port: u16 },
    V6 { ip: [u8; 16], port: u16, flowinfo: u32, scope_id: u32 },
}

impl Addr {
    /// The port.
    pub const fn port(&self) -> u16 {
        match *self {
            Addr::V4 { port, .. } | Addr::V6 { port, .. } => port,
        }
    }

    /// The same address with another port.
    pub const fn with_port(self, port: u16) -> Addr {
        match self {
            Addr::V4 { ip, .. } => Addr::V4 { ip, port },
            Addr::V6 { ip, flowinfo, scope_id, .. } => Addr::V6 { ip, port, flowinfo, scope_id },
        }
    }

    /// `AF_INET` or `AF_INET6`.
    pub const fn family(&self) -> u16 {
        match self {
            Addr::V4 { .. } => AF_INET,
            Addr::V6 { .. } => AF_INET6,
        }
    }

    /// Write the `sockaddr` form into `out` and return its length (16 or 28);
    /// the bytes past it are zero.
    pub fn encode(&self, out: &mut [u8; SOCKADDR_V6_LEN]) -> usize {
        *out = [0; SOCKADDR_V6_LEN];
        out[0..2].copy_from_slice(&self.family().to_le_bytes());
        out[2..4].copy_from_slice(&self.port().to_be_bytes());
        match *self {
            Addr::V4 { ip, .. } => {
                out[4..8].copy_from_slice(&ip);
                SOCKADDR_V4_LEN
            }
            Addr::V6 { ip, flowinfo, scope_id, .. } => {
                out[4..8].copy_from_slice(&flowinfo.to_be_bytes());
                out[8..24].copy_from_slice(&ip);
                out[24..28].copy_from_slice(&scope_id.to_le_bytes());
                SOCKADDR_V6_LEN
            }
        }
    }

    /// Read a `sockaddr` the kernel wrote. `None` for a family this layer does
    /// not speak or a buffer shorter than the family's form (an all-zero
    /// buffer, which a kernel that had nothing to say leaves, is `None` too).
    pub fn decode(raw: &[u8]) -> Option<Addr> {
        if raw.len() < 4 {
            return None;
        }
        let family = u16::from_le_bytes([raw[0], raw[1]]);
        let port = u16::from_be_bytes([raw[2], raw[3]]);
        match family {
            AF_INET if raw.len() >= SOCKADDR_V4_LEN => Some(Addr::V4 { ip: [raw[4], raw[5], raw[6], raw[7]], port }),
            AF_INET6 if raw.len() >= SOCKADDR_V6_LEN => {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&raw[8..24]);
                Some(Addr::V6 {
                    ip,
                    port,
                    flowinfo: u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
                    scope_id: u32::from_le_bytes([raw[24], raw[25], raw[26], raw[27]]),
                })
            }
            _ => None,
        }
    }
}

/// The call a result code came back from: the kernel's plain `-1` means a
/// different thing for each.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    /// `DOMAIN_SOCKET`: `-1` is "no socket could be created" (the per-task quota
    /// or the table).
    Socket,
    /// `NODE_BIND`: `-1` is a socket the stack cannot bind (no UDP slot, a
    /// family the socket does not have).
    Bind,
    /// `NODE_CONNECT`: `-1` is a handshake that did not finish within the
    /// kernel's budget, or a refused address.
    Connect,
    /// `NODE_SEND` / `NODE_SENDTO` on a stream: `-1` is a connection that is
    /// closed.
    SendStream,
    /// `NODE_SEND` / `NODE_SENDTO` on a datagram socket: `-1` is no route (an
    /// ARP miss) or an unconnected socket.
    SendDgram,
    /// `NODE_RECV` / `NODE_RECVFROM` on a datagram socket: `-1` is an unbound
    /// socket.
    RecvDgram,
    /// `NODE_RECV` on a stream: the end of the stream is its own code
    /// ([`is_eof`]), so `-1` is a refusal: a socket that holds no connection or
    /// a buffer the kernel cannot write.
    RecvStream,
}

/// Whether `code`, the result of `NODE_RECV` on a stream, is the end of the
/// stream: the connection has ended and nothing is left to read. That is not
/// an error; every other negative result is.
pub fn is_eof(code: isize) -> bool {
    code as i64 == azos_abi::error::Errno::EEOF.to_syscall_ret()
}

/// What a failed call means, in terms `std::io::ErrorKind` names. This crate is
/// `no_std` and cannot name that type; the port maps one to the other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    WouldBlock,
    TimedOut,
    Interrupted,
    ConnectionRefused,
    BrokenPipe,
    NotConnected,
    InvalidInput,
    PermissionDenied,
    AddrNotAvailable,
    HostUnreachable,
    OutOfMemory,
    QuotaExceeded,
    Unsupported,
    Other,
}

/// The kind of the negative result `code` of `op`.
///
/// The native results are `-errno` (`azos_abi::error::Errno`) and, from the
/// socket calls, a bare `-1` the kernel answers for every refusal that has no
/// code of its own; the `-1` is read per `op`. A socket call refused for a
/// capability reason carries `ECAPSTALE`, `ECAPKIND` or `ECAPPERMS`: the handle
/// is not (or no longer) a socket this task may use, which the caller sees as
/// an invalid argument or a missing permission, never as a network failure.
pub fn kind_of(code: isize, op: Op) -> Kind {
    match code {
        -1 => match op {
            Op::Socket => Kind::QuotaExceeded,
            Op::Bind => Kind::AddrNotAvailable,
            Op::Connect => Kind::ConnectionRefused,
            Op::SendStream => Kind::BrokenPipe,
            Op::SendDgram => Kind::HostUnreachable,
            Op::RecvDgram => Kind::InvalidInput,
            Op::RecvStream => Kind::NotConnected,
        },
        -4 => Kind::Interrupted,
        -9 | -22 | -200 | -202 => Kind::InvalidInput,
        -11 => Kind::WouldBlock,
        -12 => Kind::OutOfMemory,
        -13 | -99 | -201 => Kind::PermissionDenied,
        -24 | -28 | -209 => Kind::QuotaExceeded,
        -32 => Kind::BrokenPipe,
        -38 => Kind::Unsupported,
        -110 => Kind::TimedOut,
        _ => Kind::Other,
    }
}

/// A blocking wait's back-off: the receive and the send of a socket are polls
/// (`NODE_RECV` does not block, and the only way to sleep is the absolute
/// sleep), so the wait sleeps a short time that doubles up to a cap, and never
/// past the caller's deadline.
#[derive(Clone, Copy, Debug)]
pub struct Backoff {
    next_ns: u64,
}

impl Backoff {
    /// First sleep, ns: short enough that a reply already on its way is not
    /// held back for a scheduler tick.
    pub const FIRST_NS: u64 = 100_000;
    /// Longest single sleep, ns: how late a datagram or a segment that arrives
    /// during it can be noticed, and the wake-ups an idle socket costs.
    pub const CAP_NS: u64 = 2_000_000;

    pub const fn new() -> Backoff {
        Backoff { next_ns: Self::FIRST_NS }
    }

    /// The absolute time (monotonic ns) to sleep until after a poll that found
    /// nothing at `now_ns`, given the call's `deadline_ns` (`None`: no
    /// limit). `None` when the deadline has passed: the wait is over. The step
    /// doubles for the next call.
    pub fn next_wake(&mut self, now_ns: u64, deadline_ns: Option<u64>) -> Option<u64> {
        if let Some(d) = deadline_ns {
            if now_ns >= d {
                return None;
            }
        }
        let step = self.next_ns;
        self.next_ns = (step * 2).min(Self::CAP_NS);
        let wake = now_ns.saturating_add(step);
        Some(match deadline_ns {
            Some(d) => wake.min(d),
            None => wake,
        })
    }
}

/// The deadline of a call that started at `now_ns` under timeout `timeout_ns`
/// (0: none).
pub const fn deadline(now_ns: u64, timeout_ns: u64) -> Option<u64> {
    if timeout_ns == 0 {
        None
    } else {
        Some(now_ns.saturating_add(timeout_ns))
    }
}

/// `std` refuses a zero timeout (`set_read_timeout(Some(0))` is an error), and
/// this layer keeps "none" as 0, so a duration becomes nanoseconds here:
/// `None` for zero (to be refused), at least 1 otherwise, saturating.
pub const fn timeout_ns(secs: u64, subsec_nanos: u32) -> Option<u64> {
    let ns = secs.saturating_mul(1_000_000_000).saturating_add(subsec_nanos as u64);
    if ns == 0 {
        None
    } else {
        Some(ns)
    }
}

/// First port of the range `crate::net` draws a bind-to-port-0 from. The
/// stack's UDP bind takes the port it is given and has no ephemeral choice of
/// its own, so a socket bound to port 0 gets one here (IANA's dynamic range,
/// the one the TCP side of the stack uses by default).
pub const EPHEMERAL_FIRST: u16 = 49152;

/// A port in the ephemeral range from 16 random bits.
pub const fn ephemeral_port(random: u16) -> u16 {
    EPHEMERAL_FIRST + random % (u16::MAX - EPHEMERAL_FIRST + 1)
}

/// A datagram or segment the native calls move in one piece: the longest
/// buffer one `NODE_SEND` takes (longer is clamped, not refused) and one
/// `NODE_RECV` returns (`libsys::SOCK_SEND_MAX` and `SOCK_RECV_MAX`).
pub const SEND_MAX: usize = 1460;
pub const RECV_MAX: usize = 4096;
