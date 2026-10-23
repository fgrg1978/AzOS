// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `std::net` over the native socket ops (`azos_stdrt::net`): a socket is a
//! `Cap<Socket>` handle, a call is one `invoke` op, a failure is a negative
//! native result (no descriptor, no `errno`).
//!
//! What is served: `TcpStream` (IPv4; blocking, read and write timeouts,
//! nonblocking, `shutdown` of the read side and of both), `TcpListener`
//! (IPv4: bind, a blocking or nonblocking `accept`), `UdpSocket` (IPv4:
//! bind, connect, send/recv, send_to/recv_from, multicast, the same flags).
//! Reads and writes that wait are polls with an absolute sleep between looks
//! (the kernel has no blocking receive), so a timeout is exact to a few ms.
//!
//! What is not, and the op the kernel lacks (each answers `Unsupported` naming
//! it): the peer of an accepted stream (`accept` answers `0.0.0.0:0`; the
//! accept op returns only the handle), `shutdown(Write)` (no half-close), a
//! TCP socket's own address (the stack picks the source port and does not say
//! which), name resolution (no resolver op), IPv6 addresses (the stack has TCP
//! over IPv6, but the socket ops read a 16-byte `sockaddr_in`; the 28-byte form
//! is already encoded and the connect call is made, so it works the day the
//! kernel reads it), UDP over IPv6 (the stack has none), peek (receive dequeues),
//! TTL, linger and broadcast.

use super::each_addr;
use crate::fmt;
use crate::io::{self, BorrowedCursor, IoSlice, IoSliceMut};
use crate::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, ToSocketAddrs};
use crate::sync::Mutex;
use crate::sys::unsupported;
use crate::time::{Duration, Instant};
use azos_stdrt::net as rt;
use azos_stdrt::netpure;

mod addr;
use self::addr::{from_addr, io_err, to_addr};

fn timeout_ns(d: Option<Duration>) -> io::Result<Option<u64>> {
    match d {
        None => Ok(None),
        Some(d) => match netpure::timeout_ns(d.as_secs(), d.subsec_nanos()) {
            Some(ns) => Ok(Some(ns)),
            None => Err(io::const_error!(io::ErrorKind::InvalidInput, "cannot set a 0 duration timeout")),
        },
    }
}

fn timeout_dur(ns: Option<u64>) -> Option<Duration> {
    ns.map(Duration::from_nanos)
}

pub struct TcpStream {
    sock: rt::Socket,
    /// `None` for a stream a listener accepted (the op does not report it).
    peer: Option<SocketAddr>,
}

impl TcpStream {
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<TcpStream> {
        each_addr(addr, |a| {
            let sock = rt::Socket::new(a.is_ipv6(), true).map_err(io_err)?;
            sock.connect(&to_addr(a)).map_err(io_err)?;
            Ok(TcpStream { sock, peer: Some(*a) })
        })
    }

    /// The stack's own handshake budget is the bound (the connect op blocks in
    /// the kernel); a shorter `timeout` cannot cut it. A connect that fails
    /// after `timeout` is `TimedOut`, not a refusal.
    pub fn connect_timeout(addr: &SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        timeout_ns(Some(timeout))?;
        let start = Instant::now();
        let sock = rt::Socket::new(addr.is_ipv6(), true).map_err(io_err)?;
        match sock.connect(&to_addr(addr)) {
            Ok(()) => Ok(TcpStream { sock, peer: Some(*addr) }),
            Err(_) if start.elapsed() >= timeout => Err(io::Error::from(io::ErrorKind::TimedOut)),
            Err(k) => Err(io_err(k)),
        }
    }

    pub fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout_ns(timeout_ns(d)?);
        Ok(())
    }

    pub fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.sock.set_write_timeout_ns(timeout_ns(d)?);
        Ok(())
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(timeout_dur(self.sock.read_timeout_ns()))
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(timeout_dur(self.sock.write_timeout_ns()))
    }

    pub fn peek(&self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::const_error!(io::ErrorKind::Unsupported, "peek: the receive op dequeues"))
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.sock.recv(buf).map_err(io_err)
    }

    pub fn read_buf(&self, cursor: BorrowedCursor<'_>) -> io::Result<()> {
        io::default_read_buf(|buf| self.read(buf), cursor)
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        io::default_read_vectored(|b| self.read(b), bufs)
    }

    pub fn is_read_vectored(&self) -> bool {
        false
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.sock.send(buf).map_err(io_err)
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        io::default_write_vectored(|b| self.write(b), bufs)
    }

    pub fn is_write_vectored(&self) -> bool {
        false
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.peer.ok_or(io::const_error!(io::ErrorKind::Unsupported, "an accepted stream's peer is not reported"))
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        Err(io::const_error!(
            io::ErrorKind::Unsupported,
            "the stack picks a stream's source port and has no op to report it"
        ))
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match how {
            Shutdown::Read => self.sock.shutdown_read(),
            Shutdown::Both => self.sock.close(),
            Shutdown::Write => {
                return Err(io::const_error!(
                    io::ErrorKind::Unsupported,
                    "shutdown(Write): the native socket ops have no half-close"
                ));
            }
        }
        Ok(())
    }

    pub fn duplicate(&self) -> io::Result<TcpStream> {
        unsupported()
    }

    pub fn set_linger(&self, _: Option<Duration>) -> io::Result<()> {
        unsupported()
    }

    pub fn linger(&self) -> io::Result<Option<Duration>> {
        unsupported()
    }

    /// The stack sends every segment as written (it has no Nagle delay), so
    /// `nodelay` is always on; turning it off is refused.
    pub fn set_nodelay(&self, on: bool) -> io::Result<()> {
        if on {
            Ok(())
        } else {
            Err(io::const_error!(io::ErrorKind::Unsupported, "the stack never delays a segment"))
        }
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        Ok(true)
    }

    pub fn set_ttl(&self, _: u32) -> io::Result<()> {
        unsupported()
    }

    pub fn ttl(&self) -> io::Result<u32> {
        unsupported()
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        Ok(None)
    }

    pub fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        self.sock.set_nonblocking(on);
        Ok(())
    }
}

impl fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpStream").field("peer", &self.peer).finish_non_exhaustive()
    }
}

/// A TCP listener (IPv4): `NODE_BIND` and `NODE_LISTEN` on a stream socket,
/// `NODE_ACCEPT` for each connection. `accept` waits for one unless the
/// listener is nonblocking (`WouldBlock`).
pub struct TcpListener {
    sock: rt::Socket,
    local: SocketAddr,
}

/// The address `accept` answers for the peer: the op hands back only the new
/// handle, and the stack has no op that reports a connection's peer.
const PEER_UNKNOWN: SocketAddr = SocketAddr::new(crate::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

impl TcpListener {
    /// Listen on `addr`'s port (the stack's listener takes every local
    /// address); port 0 draws one from the ephemeral range.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<TcpListener> {
        each_addr(addr, |a| {
            if a.is_ipv6() {
                return Err(io::const_error!(
                    io::ErrorKind::Unsupported,
                    "TcpListener: the socket ops read a 16-byte sockaddr_in"
                ));
            }
            let sock = rt::Socket::new(false, true).map_err(io_err)?;
            let port = sock.listen(&to_addr(a)).map_err(io_err)?;
            let mut local = *a;
            local.set_port(port);
            Ok(TcpListener { sock, local })
        })
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    /// The stream, and `0.0.0.0:0` for its peer (the accept op does not report
    /// it; the stream's `peer_addr` says `Unsupported`).
    pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let sock = self.sock.accept().map_err(io_err)?;
        Ok((TcpStream { sock, peer: None }, PEER_UNKNOWN))
    }

    pub fn duplicate(&self) -> io::Result<TcpListener> {
        unsupported()
    }

    pub fn set_ttl(&self, _: u32) -> io::Result<()> {
        unsupported()
    }

    pub fn ttl(&self) -> io::Result<u32> {
        unsupported()
    }

    pub fn set_only_v6(&self, _: bool) -> io::Result<()> {
        unsupported()
    }

    pub fn only_v6(&self) -> io::Result<bool> {
        Ok(false)
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        Ok(None)
    }

    pub fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        self.sock.set_nonblocking(on);
        Ok(())
    }
}

impl fmt::Debug for TcpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpListener").field("addr", &self.local).finish_non_exhaustive()
    }
}

pub struct UdpSocket {
    sock: rt::Socket,
    local: SocketAddr,
    peer: Mutex<Option<SocketAddr>>,
}

fn udp_v4(a: &SocketAddr) -> io::Result<()> {
    if a.is_ipv6() {
        Err(io::const_error!(io::ErrorKind::Unsupported, "UdpSocket: the stack has no UDP over IPv6"))
    } else {
        Ok(())
    }
}

impl UdpSocket {
    /// Bind to `addr`. The stack's UDP bind takes the port and ignores the
    /// address (a datagram for the port arrives whichever local address it was
    /// sent to); port 0 draws one from the ephemeral range.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<UdpSocket> {
        each_addr(addr, |a| {
            udp_v4(a)?;
            let sock = rt::Socket::new(false, false).map_err(io_err)?;
            let port = sock.bind(&to_addr(a)).map_err(io_err)?;
            let mut local = *a;
            local.set_port(port);
            Ok(UdpSocket { sock, local, peer: Mutex::new(None) })
        })
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        (*self.peer.lock().unwrap_or_else(|e| e.into_inner())).ok_or(io::Error::from(io::ErrorKind::NotConnected))
    }

    /// The address bound; once connected, with the interface's address in place
    /// of an unspecified one.
    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        let mut a = self.local;
        let connected = self.peer.lock().unwrap_or_else(|e| e.into_inner()).is_some();
        if connected && a.ip().is_unspecified() {
            a.set_ip(Ipv4Addr::from(rt::local_ip_v4()).into());
        }
        Ok(a)
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (n, from) = self.sock.recv_from(buf).map_err(io_err)?;
        Ok((n, from_addr(from)))
    }

    pub fn peek_from(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Err(io::const_error!(io::ErrorKind::Unsupported, "peek_from: the receive op dequeues"))
    }

    pub fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> io::Result<usize> {
        udp_v4(addr)?;
        self.sock.send_to(buf, &to_addr(addr)).map_err(io_err)
    }

    pub fn duplicate(&self) -> io::Result<UdpSocket> {
        unsupported()
    }

    pub fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout_ns(timeout_ns(d)?);
        Ok(())
    }

    pub fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.sock.set_write_timeout_ns(timeout_ns(d)?);
        Ok(())
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(timeout_dur(self.sock.read_timeout_ns()))
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(timeout_dur(self.sock.write_timeout_ns()))
    }

    pub fn set_broadcast(&self, _: bool) -> io::Result<()> {
        unsupported()
    }

    pub fn broadcast(&self) -> io::Result<bool> {
        unsupported()
    }

    pub fn set_multicast_loop_v4(&self, _: bool) -> io::Result<()> {
        unsupported()
    }

    pub fn multicast_loop_v4(&self) -> io::Result<bool> {
        unsupported()
    }

    pub fn set_multicast_ttl_v4(&self, _: u32) -> io::Result<()> {
        unsupported()
    }

    pub fn multicast_ttl_v4(&self) -> io::Result<u32> {
        unsupported()
    }

    pub fn set_multicast_loop_v6(&self, _: bool) -> io::Result<()> {
        unsupported()
    }

    pub fn multicast_loop_v6(&self) -> io::Result<bool> {
        unsupported()
    }

    /// The stack has one interface, so `interface` is not consulted.
    pub fn join_multicast_v4(&self, group: &Ipv4Addr, _interface: &Ipv4Addr) -> io::Result<()> {
        self.sock.multicast_v4(group.octets(), true).map_err(io_err)
    }

    pub fn join_multicast_v6(&self, _: &Ipv6Addr, _: u32) -> io::Result<()> {
        unsupported()
    }

    pub fn leave_multicast_v4(&self, group: &Ipv4Addr, _interface: &Ipv4Addr) -> io::Result<()> {
        self.sock.multicast_v4(group.octets(), false).map_err(io_err)
    }

    pub fn leave_multicast_v6(&self, _: &Ipv6Addr, _: u32) -> io::Result<()> {
        unsupported()
    }

    pub fn set_ttl(&self, _: u32) -> io::Result<()> {
        unsupported()
    }

    pub fn ttl(&self) -> io::Result<u32> {
        unsupported()
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        Ok(None)
    }

    pub fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        self.sock.set_nonblocking(on);
        Ok(())
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.sock.recv(buf).map_err(io_err)
    }

    pub fn peek(&self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::const_error!(io::ErrorKind::Unsupported, "peek: the receive op dequeues"))
    }

    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.sock.send(buf).map_err(io_err)
    }

    pub fn connect<A: ToSocketAddrs>(&self, addr: A) -> io::Result<()> {
        each_addr(addr, |a| {
            udp_v4(a)?;
            self.sock.connect(&to_addr(a)).map_err(io_err)?;
            *self.peer.lock().unwrap_or_else(|e| e.into_inner()) = Some(*a);
            Ok(())
        })
    }
}

impl fmt::Debug for UdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpSocket").field("local", &self.local).finish_non_exhaustive()
    }
}

/// No name resolution: the kernel has a resolver (A and AAAA), but no op
/// carries a query from ring 3, and the DNS server address (from DHCP) is not
/// published to it. A literal address never gets here (`std` parses it first).
pub struct LookupHost(!);

impl Iterator for LookupHost {
    type Item = SocketAddr;
    fn next(&mut self) -> Option<SocketAddr> {
        self.0
    }
}

pub fn lookup_host(_host: &str, _port: u16) -> io::Result<LookupHost> {
    Err(io::const_error!(io::ErrorKind::Unsupported, "name lookup: the native ABI has no resolver op"))
}
