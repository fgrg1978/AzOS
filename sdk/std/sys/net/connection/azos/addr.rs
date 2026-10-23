// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The conversions between `std`'s socket types and the native ones. They name
//! `std` only through `crate::net` and `crate::io`, so `tests/host/stdrt-tests`
//! builds this very file against the host's `std` (which has the same types)
//! and pins the layout and the error kinds.

use crate::io;
use crate::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use azos_stdrt::netpure::{Addr, Kind};

pub fn to_addr(a: &SocketAddr) -> Addr {
    match a {
        SocketAddr::V4(v4) => Addr::V4 { ip: v4.ip().octets(), port: v4.port() },
        SocketAddr::V6(v6) => Addr::V6 {
            ip: v6.ip().octets(),
            port: v6.port(),
            flowinfo: v6.flowinfo(),
            scope_id: v6.scope_id(),
        },
    }
}

pub fn from_addr(a: Addr) -> SocketAddr {
    match a {
        Addr::V4 { ip, port } => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)),
        Addr::V6 { ip, port, flowinfo, scope_id } => {
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, flowinfo, scope_id))
        }
    }
}

pub fn io_err(k: Kind) -> io::Error {
    use io::ErrorKind as E;
    io::Error::from(match k {
        Kind::WouldBlock => E::WouldBlock,
        Kind::TimedOut => E::TimedOut,
        Kind::Interrupted => E::Interrupted,
        Kind::ConnectionRefused => E::ConnectionRefused,
        Kind::BrokenPipe => E::BrokenPipe,
        Kind::NotConnected => E::NotConnected,
        Kind::InvalidInput => E::InvalidInput,
        Kind::PermissionDenied => E::PermissionDenied,
        Kind::AddrNotAvailable => E::AddrNotAvailable,
        Kind::AddrInUse => E::AddrInUse,
        Kind::HostUnreachable => E::HostUnreachable,
        Kind::OutOfMemory => E::OutOfMemory,
        Kind::QuotaExceeded => E::QuotaExceeded,
        Kind::Unsupported => E::Unsupported,
        Kind::Other => E::Other,
    })
}
