// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `std::net` on `*-unknown-azos`, the parts that issue no trap: the socket
//! address wire layout, the conversions between `std`'s address types and it,
//! the native result code to error kind mapping, and the blocking wait's
//! back-off. The calls themselves (`azos_stdrt::net`) are covered from ring 3
//! (`tests/sdk/sdktest`).
//!
//! The conversions are `sdk/std/sys/net/connection/azos/addr.rs` itself, built
//! here against the host's `std` (it names `std` only through `crate::net` and
//! `crate::io`, which the two modules below stand in for).

#[allow(unused_imports)]
mod net {
    pub use std::net::*;
}
#[allow(unused_imports)]
mod io {
    pub use std::io::*;
}
#[path = "../../../../sdk/std/sys/net/connection/azos/addr.rs"]
mod addr;

use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use azos_abi::error::Errno;
use azos_stdrt::netpure::{
    deadline, ephemeral_port, is_eof, kind_of, timeout_ns, Addr, Backoff, Kind, Op, AF_INET, AF_INET6, EPHEMERAL_FIRST, RECV_MAX,
    SEND_MAX, SOCKADDR_V4_LEN, SOCKADDR_V6_LEN,
};

const KERNEL_HANDLERS: &str = include_str!("../../../../crates/core/syscall/src/handlers.rs");
const KERNEL_SOCKET: &str = include_str!("../../../../crates/net/net/src/socket.rs");
const LIBSYS: &str = include_str!("../../../../crates/core/libsys/src/lib.rs");
const STDRT_NET: &str = include_str!("../../../../crates/core/stdrt/src/net.rs");
const STD_NET: &str = include_str!("../../../../sdk/std/sys/net/connection/azos.rs");

fn encoded(a: &Addr) -> Vec<u8> {
    let mut raw = [0u8; SOCKADDR_V6_LEN];
    let n = a.encode(&mut raw);
    raw[..n].to_vec()
}

/// The kernel's `read_sockaddr`, restated: family little endian, port big
/// endian, four address bytes. **Canary:** an encoder that wrote the port little
/// endian fails the byte check below.
fn kernel_reads(raw: &[u8; 16]) -> (u16, u16, [u8; 4]) {
    (u16::from_le_bytes([raw[0], raw[1]]), u16::from_be_bytes([raw[2], raw[3]]), [raw[4], raw[5], raw[6], raw[7]])
}

/// The restatement above is the kernel's, not an invention: the handler's text
/// holds the same three reads and the same 16-byte copy, and the socket layer's
/// family numbers are this layer's.
#[test]
fn the_v4_layout_is_the_one_the_kernel_reads() {
    for needle in [
        "let mut raw = [0u8; 16];",
        "let family = u16::from_le_bytes([raw[0], raw[1]]);",
        "let port   = u16::from_be_bytes([raw[2], raw[3]]);",
        "let addr   = [raw[4], raw[5], raw[6], raw[7]];",
    ] {
        assert!(KERNEL_HANDLERS.contains(needle), "read_sockaddr changed: {needle}");
    }
    assert!(KERNEL_SOCKET.contains(&format!("pub const AF_INET: u32  = {AF_INET};")));
    assert!(KERNEL_SOCKET.contains(&format!("pub const AF_INET6: u32 = {AF_INET6};")));
    assert!(KERNEL_SOCKET.contains("pub const SOCK_STREAM: u32 = 1;"));
    assert!(KERNEL_SOCKET.contains("pub const SOCK_DGRAM:  u32 = 2;"));
}

#[test]
fn v4_encodes_as_the_16_bytes_the_kernel_parses() {
    let a = Addr::V4 { ip: [10, 0, 2, 15], port: 0x1F90 };
    let raw = encoded(&a);
    assert_eq!(raw.len(), SOCKADDR_V4_LEN);
    assert_eq!(raw, [2, 0, 0x1F, 0x90, 10, 0, 2, 15, 0, 0, 0, 0, 0, 0, 0, 0]);
    let fixed: [u8; 16] = raw.as_slice().try_into().unwrap();
    assert_eq!(kernel_reads(&fixed), (AF_INET, 0x1F90, [10, 0, 2, 15]));
}

/// Linux's `sockaddr_in6` for `[fe80::1]:443`, flow 7, scope 3: the family and
/// scope little endian, the port and flow info big endian.
#[test]
fn v6_encodes_as_sockaddr_in6() {
    let mut ip = [0u8; 16];
    ip[0] = 0xfe;
    ip[1] = 0x80;
    ip[15] = 1;
    let a = Addr::V6 { ip, port: 443, flowinfo: 7, scope_id: 3 };
    let raw = encoded(&a);
    assert_eq!(raw.len(), SOCKADDR_V6_LEN);
    assert_eq!(&raw[0..2], &[10, 0]);
    assert_eq!(&raw[2..4], &[0x01, 0xBB]);
    assert_eq!(&raw[4..8], &[0, 0, 0, 7]);
    assert_eq!(&raw[8..24], &ip);
    assert_eq!(&raw[24..28], &[3, 0, 0, 0]);
}

#[test]
fn addresses_survive_the_wire() {
    let v4 = Addr::V4 { ip: [192, 168, 1, 77], port: 65535 };
    let v6 = Addr::V6 { ip: [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xAB, 0xCD], port: 1, flowinfo: 0xABCDEF, scope_id: 9 };
    for a in [v4, v6] {
        assert_eq!(Addr::decode(&encoded(&a)), Some(a));
    }
    // The kernel's reply buffer is 28 bytes whatever the family: the extra
    // bytes after a 16-byte v4 form are ignored.
    let mut buf = [0u8; SOCKADDR_V6_LEN];
    v4.encode(&mut buf);
    assert_eq!(Addr::decode(&buf), Some(v4));
}

#[test]
fn what_is_not_an_address_does_not_decode() {
    // Nothing written: the zero family.
    assert_eq!(Addr::decode(&[0u8; SOCKADDR_V6_LEN]), None);
    // A family this layer does not speak (AF_PACKET).
    let mut other = [0u8; SOCKADDR_V6_LEN];
    other[0] = 17;
    assert_eq!(Addr::decode(&other), None);
    // Shorter than the family's form.
    let v6 = encoded(&Addr::V6 { ip: [1; 16], port: 2, flowinfo: 0, scope_id: 0 });
    assert_eq!(Addr::decode(&v6[..SOCKADDR_V6_LEN - 1]), None);
    let v4 = encoded(&Addr::V4 { ip: [1; 4], port: 2 });
    assert_eq!(Addr::decode(&v4[..SOCKADDR_V4_LEN - 1]), None);
    assert_eq!(Addr::decode(&[]), None);
}

#[test]
fn std_addresses_convert_both_ways() {
    let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 5));
    let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1234), 443, 0x55, 6));
    assert_eq!(addr::to_addr(&v4), Addr::V4 { ip: [1, 2, 3, 4], port: 5 });
    match addr::to_addr(&v6) {
        Addr::V6 { ip, port, flowinfo, scope_id } => {
            assert_eq!(ip, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1234).octets());
            assert_eq!((port, flowinfo, scope_id), (443, 0x55, 6));
        }
        other => panic!("{other:?}"),
    }
    for a in [v4, v6] {
        assert_eq!(addr::from_addr(addr::to_addr(&a)), a);
        assert_eq!(addr::from_addr(Addr::decode(&encoded(&addr::to_addr(&a))).unwrap()), a);
    }
    assert_eq!(Addr::V4 { ip: [1; 4], port: 80 }.with_port(8080), Addr::V4 { ip: [1; 4], port: 8080 });
    assert_eq!(Addr::V4 { ip: [1; 4], port: 80 }.port(), 80);
}

/// Every kind has an `io::ErrorKind`, and the three that mean "try again later"
/// are not confused with a failure. **Canary:** mapping `WouldBlock` to
/// `TimedOut` fails the first assertion.
#[test]
fn kinds_map_to_io_error_kinds() {
    let k = |k: Kind| addr::io_err(k).kind();
    assert_eq!(k(Kind::WouldBlock), ErrorKind::WouldBlock);
    assert_eq!(k(Kind::TimedOut), ErrorKind::TimedOut);
    assert_eq!(k(Kind::Interrupted), ErrorKind::Interrupted);
    assert_eq!(k(Kind::ConnectionRefused), ErrorKind::ConnectionRefused);
    assert_eq!(k(Kind::BrokenPipe), ErrorKind::BrokenPipe);
    assert_eq!(k(Kind::NotConnected), ErrorKind::NotConnected);
    assert_eq!(k(Kind::InvalidInput), ErrorKind::InvalidInput);
    assert_eq!(k(Kind::PermissionDenied), ErrorKind::PermissionDenied);
    assert_eq!(k(Kind::AddrNotAvailable), ErrorKind::AddrNotAvailable);
    assert_eq!(k(Kind::AddrInUse), ErrorKind::AddrInUse);
    assert_eq!(k(Kind::HostUnreachable), ErrorKind::HostUnreachable);
    assert_eq!(k(Kind::OutOfMemory), ErrorKind::OutOfMemory);
    assert_eq!(k(Kind::QuotaExceeded), ErrorKind::QuotaExceeded);
    assert_eq!(k(Kind::Unsupported), ErrorKind::Unsupported);
    assert_eq!(k(Kind::Other), ErrorKind::Other);
}

/// The native results, as the ABI's errno table has them. The kernel's bare
/// `-1` is read per call: a refused connect is `ConnectionRefused`, a send on a
/// closed stream `BrokenPipe`, and so on. **Canary:** reading `-1` the way the
/// pal's generic mapping does (permission denied) fails the connect row.
#[test]
fn native_results_map_per_call() {
    let ret = |e: Errno| e.to_syscall_ret() as isize;
    assert_eq!(kind_of(-1, Op::Connect), Kind::ConnectionRefused);
    assert_eq!(kind_of(-1, Op::Socket), Kind::QuotaExceeded);
    assert_eq!(kind_of(-1, Op::Bind), Kind::AddrNotAvailable);
    assert_eq!(kind_of(-1, Op::SendStream), Kind::BrokenPipe);
    assert_eq!(kind_of(-1, Op::SendDgram), Kind::HostUnreachable);
    assert_eq!(kind_of(-1, Op::RecvDgram), Kind::InvalidInput);
    assert_eq!(kind_of(-1, Op::RecvStream), Kind::NotConnected);
    assert_eq!(kind_of(-1, Op::Listen), Kind::AddrInUse);
    assert_eq!(kind_of(-1, Op::Accept), Kind::InvalidInput);
    // The coded results are the same whichever call answered.
    for op in [Op::Socket, Op::Bind, Op::Connect, Op::SendStream, Op::SendDgram, Op::RecvDgram, Op::RecvStream, Op::Listen, Op::Accept] {
        assert_eq!(kind_of(ret(Errno::EAGAIN), op), Kind::WouldBlock);
        assert_eq!(kind_of(ret(Errno::EINTR), op), Kind::Interrupted);
        assert_eq!(kind_of(ret(Errno::EINVAL), op), Kind::InvalidInput);
        assert_eq!(kind_of(ret(Errno::EBADF), op), Kind::InvalidInput);
        assert_eq!(kind_of(ret(Errno::ECAPSTALE), op), Kind::InvalidInput);
        assert_eq!(kind_of(ret(Errno::ECAPKIND), op), Kind::InvalidInput);
        assert_eq!(kind_of(ret(Errno::ECAPPERMS), op), Kind::PermissionDenied);
        assert_eq!(kind_of(ret(Errno::ENOTOWNER), op), Kind::PermissionDenied);
        assert_eq!(kind_of(ret(Errno::EACCES), op), Kind::PermissionDenied);
        assert_eq!(kind_of(ret(Errno::EMFILE), op), Kind::QuotaExceeded);
        assert_eq!(kind_of(ret(Errno::EQUOTA), op), Kind::QuotaExceeded);
        assert_eq!(kind_of(ret(Errno::ENOSPC), op), Kind::QuotaExceeded);
        assert_eq!(kind_of(ret(Errno::ENOMEM), op), Kind::OutOfMemory);
        assert_eq!(kind_of(ret(Errno::EPIPE), op), Kind::BrokenPipe);
        assert_eq!(kind_of(ret(Errno::ENOSYS), op), Kind::Unsupported);
        assert_eq!(kind_of(-110, op), Kind::TimedOut);
        assert_eq!(kind_of(-4242, op), Kind::Other);
    }
}

/// The end of a stream is `-EEOF` and nothing else: a bare `-1` (a socket with
/// no connection, a buffer the kernel could not write) and a coded refusal are
/// errors, so a reset or revoked handle never reads as a clean end of file.
/// The kernel side is pinned by source: both receive handlers turn the
/// socket layer's `-1` into `-EEOF` only for a connection that has ended.
/// **Canary:** `is_eof(-1)` (the old reading) fails the first row.
#[test]
fn only_the_eof_code_ends_a_stream() {
    assert!(!is_eof(-1));
    assert!(!is_eof(Errno::ECAPSTALE.to_syscall_ret() as isize));
    assert!(!is_eof(Errno::EPIPE.to_syscall_ret() as isize));
    assert!(!is_eof(0));
    assert!(!is_eof(1));
    assert!(is_eof(Errno::EEOF.to_syscall_ret() as isize));
    assert_eq!(kind_of(-1, Op::RecvStream), Kind::NotConnected);
    assert_eq!(KERNEL_HANDLERS.matches("socket_stream_ended(fd as i32)").count(), 2);
    assert!(KERNEL_HANDLERS.contains("Errno::EEOF.to_syscall_ret()"));
    assert!(KERNEL_SOCKET.contains("pub fn socket_stream_ended(fd: i32) -> bool"));
}

/// `std::net::TcpListener` is the native listener, as sshd's is through
/// libsys: `bind` makes a stream socket and listens (`NODE_BIND`, then
/// `NODE_LISTEN`), `accept` polls `NODE_ACCEPT`, whose "nobody waiting" is
/// `-EAGAIN` (`WouldBlock`, so the poll waits or a nonblocking listener
/// returns), and a taken port is `AddrInUse`. The kernel side is pinned by
/// source. **Canary:** the old `TcpListener(!)`, whose `bind` answered
/// `Unsupported`, fails the first two rows.
#[test]
fn the_std_listener_listens_and_accepts_through_the_native_ops() {
    assert!(STD_NET.contains("let port = sock.listen(&to_addr(a)).map_err(io_err)?;"));
    assert!(STD_NET.contains("let sock = self.sock.accept().map_err(io_err)?;"));
    assert!(!STD_NET.contains("TcpListener(!)"));
    assert!(STDRT_NET.contains("invoke(held.h(), inv::NODE_LISTEN, [0; 4])"));
    assert!(STDRT_NET.contains("invoke(held.h(), inv::NODE_ACCEPT, [0; 4])"));
    assert_eq!(kind_of(Errno::EAGAIN.to_syscall_ret() as isize, Op::Accept), Kind::WouldBlock);
    assert_eq!(kind_of(-1, Op::Listen), Kind::AddrInUse);
    // NODE_ACCEPT with nothing waiting answers -EAGAIN; NODE_LISTEN is the
    // socket layer's 0 or -1; sshd uses the same two ops through libsys.
    assert!(KERNEL_HANDLERS.contains("    if conn < 0 {\n        return Errno::EAGAIN.to_syscall_ret();"));
    assert!(KERNEL_HANDLERS.contains("azos_net::socket_listen_bound(fd as i32) as i64"));
    assert!(LIBSYS.contains("invoke(cap, invoke_abi::NODE_LISTEN, [0; 4]).0"));
    assert!(LIBSYS.contains("invoke(cap, invoke_abi::NODE_ACCEPT, [0; 4]).0"));
}

#[test]
fn the_backoff_doubles_to_its_cap() {
    let mut b = Backoff::new();
    let mut now = 1_000_000u64;
    let mut steps = Vec::new();
    for _ in 0..8 {
        let wake = b.next_wake(now, None).unwrap();
        steps.push(wake - now);
        now = wake;
    }
    assert_eq!(steps[0], Backoff::FIRST_NS);
    assert_eq!(steps[1], 2 * Backoff::FIRST_NS);
    assert_eq!(steps[2], 4 * Backoff::FIRST_NS);
    assert!(steps.windows(2).all(|w| w[1] >= w[0]));
    assert_eq!(*steps.last().unwrap(), Backoff::CAP_NS);
}

/// A wait never sleeps past its deadline, and a deadline that has come ends it.
/// **Canary:** a back-off that ignored the deadline sleeps the full step.
#[test]
fn the_backoff_stops_at_the_deadline() {
    let mut b = Backoff::new();
    assert_eq!(b.next_wake(1_000, Some(1_050)), Some(1_050));
    assert_eq!(b.next_wake(1_050, Some(1_050)), None);
    assert_eq!(b.next_wake(2_000, Some(1_050)), None);
    // Saturating at the end of time.
    assert_eq!(Backoff::new().next_wake(u64::MAX - 1, None), Some(u64::MAX));
}

#[test]
fn timeouts_are_zero_for_none_and_refused_at_zero() {
    assert_eq!(deadline(100, 0), None);
    assert_eq!(deadline(100, 50), Some(150));
    assert_eq!(deadline(u64::MAX - 1, 50), Some(u64::MAX));
    assert_eq!(timeout_ns(0, 0), None);
    assert_eq!(timeout_ns(0, 1), Some(1));
    assert_eq!(timeout_ns(2, 500), Some(2_000_000_500));
    assert_eq!(timeout_ns(u64::MAX, 999_999_999), Some(u64::MAX));
}

/// Every random draw lands in the range the stack's TCP side uses by default.
#[test]
fn ephemeral_ports_stay_in_the_dynamic_range() {
    for r in 0..=u16::MAX {
        let p = ephemeral_port(r);
        assert!(p >= EPHEMERAL_FIRST, "{r} -> {p}");
    }
    assert_eq!(ephemeral_port(0), EPHEMERAL_FIRST);
    assert_eq!(ephemeral_port(u16::MAX - EPHEMERAL_FIRST), u16::MAX);
}

/// The datagram size limits are libsys's (the kernel clamps a send to the first
/// and a receive to the second); a drift would cut datagrams silently.
#[test]
fn the_buffer_limits_are_the_kernels() {
    assert!(LIBSYS.contains(&format!("pub const SOCK_SEND_MAX: usize = {SEND_MAX};")));
    assert!(LIBSYS.contains(&format!("pub const SOCK_RECV_MAX: usize = {RECV_MAX};")));
    assert!(KERNEL_HANDLERS.contains("let count = (len as usize).min(1460);"));
    assert!(KERNEL_HANDLERS.contains("(len as usize).min(4096)"));
}
