// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Sockets: what `std::net` stands on (`sdk/std/sys/net/connection/azos.rs`).
//!
//! A socket is a `Cap<Socket>` handle (`DOMAIN_SOCKET` makes it, `SYS_CAP_CLOSE`
//! ends it) and every call on it is one `invoke` op of the `Node` kind. There is
//! no descriptor number and no `errno`; a failure is a negative native result,
//! read into a [`Kind`] by [`netpure::kind_of`].
//!
//! **Blocking is a sleep, not a trap.** `NODE_RECV` and `NODE_RECVFROM` do not
//! block (0 is "nothing yet") and a full send window answers 0, so a blocking
//! call polls, sleeping on the absolute sleep (`SYS_SLEEP_UNTIL`, the one way to
//! wait) for the [`Backoff`] step between looks, never past its deadline. The
//! timeouts and the nonblocking flag are this layer's: the kernel has none.
//! Only `NODE_CONNECT` blocks inside the kernel (the handshake, bounded by the
//! stack's own budget).
//!
//! **A handle is closed with no call in flight.** Every call holds the socket
//! ([`Socket::hold`]) for the length of one `invoke` (never across a sleep) and
//! [`Socket::close`] raises a flag that stops new holds, waits for the ones
//! taken, and only then gives the handle back. A thread inside `recv` while
//! another shuts the socket down therefore never sends or receives on a handle
//! the table has handed to something else.
//!
//! **A listener** is a stream socket given a port by `NODE_BIND` and opened by
//! `NODE_LISTEN` ([`Socket::listen`], one call for both: the stack's TCP bind
//! only records the port, and a taken port shows at the listen). `NODE_ACCEPT`
//! does not block (`-EAGAIN` is "nobody waiting"), so [`Socket::accept`] polls
//! as a receive does. The accepted socket's peer is not reported: the op
//! answers only the new handle.
//!
//! **What the kernel does not offer** (each is named where a caller would
//! reach it): a half-close, a socket's own address, the peer of an accepted
//! connection, IPv6 `sockaddr` (the kernel reads 16 bytes), UDP over IPv6, and
//! a resolver.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::netpure::{self, Addr, Backoff, Kind, Op, AF_INET, AF_INET6, SOCK_DGRAM, SOCK_STREAM};
use crate::sys::{invoke, syscall6};
use crate::time;
use azos_abi::invoke as inv;
use azos_abi::syscall_nr::SYS_CAP_CLOSE;

pub use crate::netpure::{Addr as SockAddr, Kind as ErrKind};

/// Set in [`Socket::busy`] once the socket is being closed: no call takes the
/// handle any more.
const CLOSING: u32 = 1 << 31;
/// Tries at a free ephemeral port before a bind gives up.
const BIND_TRIES: usize = 16;

/// One socket: a TCP stream or a UDP datagram socket.
pub struct Socket {
    /// The `Cap<Socket>` handle; given back by [`Socket::close`] only.
    h: u32,
    /// The calls holding the handle (low bits) and [`CLOSING`].
    busy: AtomicU32,
    stream: bool,
    connected: AtomicBool,
    nonblocking: AtomicBool,
    /// `0`: no timeout (the nanoseconds of `std::time::Duration` otherwise).
    read_timeout_ns: AtomicU64,
    write_timeout_ns: AtomicU64,
    /// `shutdown(Read)` or `shutdown(Both)` happened: reads are at the end.
    read_shut: AtomicBool,
}

impl Socket {
    /// A new, unconnected socket. `v6` makes an `AF_INET6` one; the stack has
    /// no UDP over IPv6, so a datagram socket there is `Unsupported` without
    /// asking the kernel.
    pub fn new(v6: bool, stream: bool) -> Result<Socket, Kind> {
        if v6 && !stream {
            return Err(Kind::Unsupported);
        }
        let domain = if v6 { AF_INET6 } else { AF_INET } as u64;
        let ty = if stream { SOCK_STREAM } else { SOCK_DGRAM };
        let (h, _) = invoke(inv::DOMAIN_SELF.as_raw(), inv::DOMAIN_SOCKET, [domain, ty, 0, 0]);
        if h < 0 {
            return Err(netpure::kind_of(h, Op::Socket));
        }
        Ok(Socket::from_handle(h as u32, stream, false))
    }

    /// The socket a handle names: a new one (`connected` false), or one
    /// `NODE_ACCEPT` gave (a stream, connected).
    fn from_handle(h: u32, stream: bool, connected: bool) -> Socket {
        Socket {
            h,
            busy: AtomicU32::new(0),
            stream,
            connected: AtomicBool::new(connected),
            nonblocking: AtomicBool::new(false),
            read_timeout_ns: AtomicU64::new(0),
            write_timeout_ns: AtomicU64::new(0),
            read_shut: AtomicBool::new(false),
        }
    }

    /// Take the handle for one call, or `None` once the socket is closing.
    fn hold(&self) -> Option<Held<'_>> {
        let mut s = self.busy.load(Ordering::Acquire);
        loop {
            if s & CLOSING != 0 {
                return None;
            }
            match self.busy.compare_exchange_weak(s, s + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(Held { sock: self }),
                Err(now) => s = now,
            }
        }
    }

    /// `true` for a TCP socket.
    pub fn is_stream(&self) -> bool {
        self.stream
    }

    /// Connect to `addr`. A stream socket returns when the handshake has
    /// finished (or the stack's budget for it ran out: `ConnectionRefused`); a
    /// datagram socket only fixes the peer, and the stack gives it a local port.
    pub fn connect(&self, addr: &Addr) -> Result<(), Kind> {
        let held = self.hold().ok_or(Kind::InvalidInput)?;
        let mut raw = [0u8; netpure::SOCKADDR_V6_LEN];
        let len = addr.encode(&mut raw);
        let (r, _) = invoke(held.h(), inv::NODE_CONNECT, [raw.as_ptr() as u64, len as u64, 0, 0]);
        if r < 0 {
            return Err(netpure::kind_of(r, Op::Connect));
        }
        self.connected.store(true, Ordering::Release);
        Ok(())
    }

    /// Bind to `addr`. Port 0 on a datagram socket draws one from the
    /// ephemeral range (the stack's UDP bind keeps the port it is given); the
    /// port bound is returned. A stream socket binds in [`listen`](Self::listen)
    /// (`InvalidInput` here): binding one only serves a listener.
    pub fn bind(&self, addr: &Addr) -> Result<u16, Kind> {
        if self.stream {
            return Err(Kind::InvalidInput);
        }
        let held = self.hold().ok_or(Kind::InvalidInput)?;
        let mut raw = [0u8; netpure::SOCKADDR_V6_LEN];
        let fixed = addr.port() != 0;
        for _ in 0..if fixed { 1 } else { BIND_TRIES } {
            let port = if fixed { addr.port() } else { random_ephemeral_port() };
            let len = addr.with_port(port).encode(&mut raw);
            let (r, _) = invoke(held.h(), inv::NODE_BIND, [raw.as_ptr() as u64, len as u64, 0, 0]);
            if r >= 0 {
                return Ok(port);
            }
            if fixed {
                return Err(netpure::kind_of(r, Op::Bind));
            }
        }
        Err(Kind::AddrNotAvailable)
    }

    /// Listen on `addr`'s port with a stream socket (`NODE_BIND`, then
    /// `NODE_LISTEN`); the port listened on is returned. Port 0 draws one from
    /// the ephemeral range, and a draw another listener holds is drawn again.
    /// A fixed port that is taken is `AddrInUse`.
    pub fn listen(&self, addr: &Addr) -> Result<u16, Kind> {
        if !self.stream {
            return Err(Kind::InvalidInput);
        }
        let held = self.hold().ok_or(Kind::InvalidInput)?;
        let mut raw = [0u8; netpure::SOCKADDR_V6_LEN];
        let fixed = addr.port() != 0;
        for _ in 0..if fixed { 1 } else { BIND_TRIES } {
            let port = if fixed { addr.port() } else { random_ephemeral_port() };
            let len = addr.with_port(port).encode(&mut raw);
            let (r, _) = invoke(held.h(), inv::NODE_BIND, [raw.as_ptr() as u64, len as u64, 0, 0]);
            if r < 0 {
                return Err(netpure::kind_of(r, Op::Bind));
            }
            let (r, _) = invoke(held.h(), inv::NODE_LISTEN, [0; 4]);
            if r >= 0 {
                return Ok(port);
            }
            if fixed || netpure::kind_of(r, Op::Listen) != Kind::AddrInUse {
                return Err(netpure::kind_of(r, Op::Listen));
            }
        }
        Err(Kind::AddrInUse)
    }

    /// Take one connection from a listening socket: a connected stream socket
    /// the caller owns. Waits for one unless the socket is nonblocking
    /// (`WouldBlock`); a listener has no timeout.
    pub fn accept(&self) -> Result<Socket, Kind> {
        let mut backoff = Backoff::new();
        loop {
            let r = {
                let held = self.hold().ok_or(Kind::InvalidInput)?;
                invoke(held.h(), inv::NODE_ACCEPT, [0; 4]).0
            };
            if r >= 0 {
                return Ok(Socket::from_handle(r as u32, true, true));
            }
            if netpure::kind_of(r, Op::Accept) != Kind::WouldBlock {
                return Err(netpure::kind_of(r, Op::Accept));
            }
            self.wait(&mut backoff, None)?;
        }
    }

    /// Join (`join`) or leave the IPv4 multicast `group` on a datagram socket.
    pub fn multicast_v4(&self, group: [u8; 4], join: bool) -> Result<(), Kind> {
        if self.stream {
            return Err(Kind::InvalidInput);
        }
        let held = self.hold().ok_or(Kind::InvalidInput)?;
        let op = if join { inv::NODE_MCAST_JOIN } else { inv::NODE_MCAST_LEAVE };
        let (r, _) = invoke(held.h(), op, [u32::from_be_bytes(group) as u64, 0, 0, 0]);
        if r < 0 {
            return Err(netpure::kind_of(r, Op::Bind));
        }
        Ok(())
    }

    pub fn set_nonblocking(&self, on: bool) {
        self.nonblocking.store(on, Ordering::Release);
    }

    pub fn nonblocking(&self) -> bool {
        self.nonblocking.load(Ordering::Acquire)
    }

    /// Set the read timeout (`None`: wait for ever). `Some(0)` is refused by
    /// the caller (`std` makes it an error), not here.
    pub fn set_read_timeout_ns(&self, ns: Option<u64>) {
        self.read_timeout_ns.store(ns.unwrap_or(0), Ordering::Release);
    }

    pub fn set_write_timeout_ns(&self, ns: Option<u64>) {
        self.write_timeout_ns.store(ns.unwrap_or(0), Ordering::Release);
    }

    pub fn read_timeout_ns(&self) -> Option<u64> {
        Some(self.read_timeout_ns.load(Ordering::Acquire)).filter(|&n| n != 0)
    }

    pub fn write_timeout_ns(&self) -> Option<u64> {
        Some(self.write_timeout_ns.load(Ordering::Acquire)).filter(|&n| n != 0)
    }

    /// Read into `buf`: bytes received, `Ok(0)` at the end of a stream (the
    /// peer closed and nothing is left, or the read side was shut down).
    ///
    /// Nonblocking, or a read timeout that ran out, is `WouldBlock` (the
    /// convention of the Unix `std`).
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, Kind> {
        self.recv_inner(buf, None)
    }

    /// [`recv`](Self::recv) on a datagram socket, with the sender's address.
    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Addr), Kind> {
        let mut from = None;
        let n = self.recv_inner(buf, Some(&mut from))?;
        Ok((n, from.ok_or(Kind::Other)?))
    }

    fn recv_inner(&self, buf: &mut [u8], mut from: Option<&mut Option<Addr>>) -> Result<usize, Kind> {
        if buf.is_empty() {
            return Ok(0);
        }
        let deadline = netpure::deadline(time::now_ns(), self.read_timeout_ns.load(Ordering::Acquire));
        let mut backoff = Backoff::new();
        loop {
            if self.read_shut.load(Ordering::Acquire) {
                return Ok(0);
            }
            let len = buf.len().min(netpure::RECV_MAX) as u64;
            let mut raw = [0u8; netpure::SOCKADDR_V6_LEN];
            let r = {
                let held = self.hold().ok_or(Kind::InvalidInput)?;
                if from.is_some() {
                    invoke(held.h(), inv::NODE_RECVFROM, [buf.as_mut_ptr() as u64, len, raw.as_mut_ptr() as u64, 0]).0
                } else {
                    invoke(held.h(), inv::NODE_RECV, [buf.as_mut_ptr() as u64, len, 0, 0]).0
                }
            };
            if r > 0 {
                if let Some(f) = from.as_mut() {
                    **f = Addr::decode(&raw);
                }
                return Ok(r as usize);
            }
            if r < 0 {
                // The end of a stream has a code of its own; a bare -1 is a
                // refusal and must not read as a clean end of file.
                if self.stream && netpure::is_eof(r) {
                    return Ok(0);
                }
                let op = if self.stream { Op::RecvStream } else { Op::RecvDgram };
                return Err(netpure::kind_of(r, op));
            }
            self.wait(&mut backoff, deadline)?;
        }
    }

    /// Write `buf` to the connected peer: bytes accepted (a stream takes at most
    /// one segment's worth per call, as a short `write` does anywhere; a
    /// datagram is sent whole or refused).
    pub fn send(&self, buf: &[u8]) -> Result<usize, Kind> {
        if !self.stream && !self.connected.load(Ordering::Acquire) {
            return Err(Kind::NotConnected);
        }
        self.send_inner(buf, None)
    }

    /// Send a datagram to `to` (IPv4; a datagram socket has no other family).
    pub fn send_to(&self, buf: &[u8], to: &Addr) -> Result<usize, Kind> {
        if self.stream {
            return Err(Kind::InvalidInput);
        }
        if !matches!(to, Addr::V4 { .. }) {
            return Err(Kind::Unsupported);
        }
        self.send_inner(buf, Some(to))
    }

    fn send_inner(&self, buf: &[u8], to: Option<&Addr>) -> Result<usize, Kind> {
        if buf.is_empty() {
            return Ok(0);
        }
        // The call clamps a longer buffer instead of refusing it: right for a
        // stream (a short write), wrong for a datagram, which would be sent cut.
        if !self.stream && buf.len() > netpure::SEND_MAX {
            return Err(Kind::InvalidInput);
        }
        let deadline = netpure::deadline(time::now_ns(), self.write_timeout_ns.load(Ordering::Acquire));
        let mut backoff = Backoff::new();
        let op = if self.stream { Op::SendStream } else { Op::SendDgram };
        loop {
            let len = buf.len().min(netpure::SEND_MAX) as u64;
            let mut raw = [0u8; netpure::SOCKADDR_V6_LEN];
            let r = {
                let held = self.hold().ok_or(Kind::BrokenPipe)?;
                match to {
                    Some(a) => {
                        a.encode(&mut raw);
                        invoke(held.h(), inv::NODE_SENDTO, [buf.as_ptr() as u64, len, raw.as_ptr() as u64, 0]).0
                    }
                    None => invoke(held.h(), inv::NODE_SEND, [buf.as_ptr() as u64, len, 0, 0]).0,
                }
            };
            if r > 0 {
                return Ok(r as usize);
            }
            // 0 is a full send window; -EAGAIN is degraded mode refusing a
            // write while it is contained. Both end when the condition does.
            if r == 0 || (r < 0 && netpure::kind_of(r, op) == Kind::WouldBlock) {
                self.wait(&mut backoff, deadline)?;
                continue;
            }
            return Err(netpure::kind_of(r, op));
        }
    }

    /// One look found nothing: sleep a step, or end the wait (`WouldBlock`)
    /// when the socket is nonblocking or the deadline has passed.
    fn wait(&self, backoff: &mut Backoff, deadline: Option<u64>) -> Result<(), Kind> {
        if self.nonblocking.load(Ordering::Acquire) {
            return Err(Kind::WouldBlock);
        }
        match backoff.next_wake(time::now_ns(), deadline) {
            Some(wake) => {
                time::sleep_until(wake);
                Ok(())
            }
            None => Err(Kind::WouldBlock),
        }
    }

    /// `shutdown(Read)`: later reads see the end of the stream. The kernel has
    /// no half-close op, so the sending side cannot be shut alone
    /// (`Unsupported`); [`close`](Self::close) shuts both.
    pub fn shutdown_read(&self) {
        self.read_shut.store(true, Ordering::Release);
    }

    /// `shutdown(Both)`: reads see the end of the stream, writes fail, and the
    /// handle is closed (the stack sends its FIN as it frees the socket) once
    /// the calls that hold it have returned. A call blocked in the kernel (a
    /// connect waiting for its handshake) delays the close until it returns;
    /// the waits of `recv` and `send` hold nothing, so they do not. The second
    /// close of a socket, from any thread, does nothing.
    pub fn close(&self) {
        self.read_shut.store(true, Ordering::Release);
        if self.busy.fetch_or(CLOSING, Ordering::AcqRel) & CLOSING != 0 {
            return;
        }
        while self.busy.load(Ordering::Acquire) != CLOSING {
            time::sleep_until(time::now_ns().saturating_add(Backoff::FIRST_NS));
        }
        // SAFETY: a plain call on a handle this socket owns and nothing
        // holds; a stale one answers an error, which changes nothing the
        // caller can do.
        unsafe { syscall6(SYS_CAP_CLOSE, self.h as u64, 0, 0, 0, 0, 0) };
    }
}

/// One call's hold on a socket's handle (see [`Socket::hold`]); released on drop.
struct Held<'a> {
    sock: &'a Socket,
}

impl Held<'_> {
    fn h(&self) -> u32 {
        self.sock.h
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.sock.busy.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.close();
    }
}

/// The interface's IPv4 address (`DOMAIN_NET_GETIP`), `0.0.0.0` before a lease.
pub fn local_ip_v4() -> [u8; 4] {
    let (r, _) = invoke(inv::DOMAIN_SELF.as_raw(), inv::DOMAIN_NET_GETIP, [0; 4]);
    (r as u32).to_be_bytes()
}

fn random_ephemeral_port() -> u16 {
    let mut b = [0u8; 2];
    if crate::alloc::fill_entropy(&mut b) {
        netpure::ephemeral_port(u16::from_le_bytes(b))
    } else {
        // No pool (a row without the entropy capability): the clock still
        // differs between two tries.
        netpure::ephemeral_port(time::now_ns() as u16)
    }
}
