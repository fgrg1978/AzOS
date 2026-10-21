// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The egress gate (`net_egress` of the effect gate): a socket owned by a task
//! asks it at its first packet to a destination that is not this node, by
//! `connect`, or by an unconnected `sendto` once per destination. The hook
//! here records what it was asked and answers as told; the effect gate behind
//! it (the Domain's `egress` row, the receipt) is tested in `actuation-tests`.
//!
//! **Canary.** `--features envelope-egress-canary` (the gate is never asked):
//! the `*_is_refused` rows go red, and the datagram they assert never left is
//! on the wire.

#![cfg(test)]

use crate::socket::{self, SockAddr, AF_INET, AF_INET6, EGRESS_REFUSED, SOCK_DGRAM, SOCK_STREAM};
use crate::{arp, igmp, tcp, udp, wire, NET_SERIAL};
use azos_common::envelope::DestClass;
use std::sync::Mutex;

const TASK: u32 = 61;
const PUBLIC: [u8; 4] = [93, 184, 216, 34];
const PRIVATE: [u8; 4] = [10, 0, 0, 9];
const LINK: [u8; 4] = [169, 254, 7, 7];
const MAC: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

/// (owner, class, dest word, port) of every question.
static ASKED: Mutex<Vec<(u32, u8, u32, u16)>> = Mutex::new(Vec::new());
/// The classes the model Domain's row lets out (`DestClass::permitted(level)`).
static LEVEL: Mutex<u8> = Mutex::new(0);

fn gate(owner: u32, class: DestClass, dest: u32, port: u16) -> bool {
    ASKED.lock().unwrap().push((owner, class as u8, dest, port));
    class.permitted(*LEVEL.lock().unwrap())
}

struct Session {
    _g: std::sync::MutexGuard<'static, ()>,
}

impl Drop for Session {
    fn drop(&mut self) {
        socket::clear_egress_gate_for_test();
    }
}

fn begin(level: u8) -> Session {
    let g = NET_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for fd in 0..socket::MAX_SOCKETS {
        socket::socket_close(fd as i32);
    }
    for i in 0..udp::UDP_MAX_SOCKETS {
        udp::unbind(i);
    }
    for idx in 0..azos_limits::TCP_MAX_CONNS {
        tcp::close(idx);
        tcp::close(idx);
    }
    igmp::clear();
    wire::reset();
    azos_drv_irqchip::clint::set_test_time(520_000);
    for ip in [PUBLIC, PRIVATE, LINK] {
        arp::insert(ip, MAC);
    }
    ASKED.lock().unwrap().clear();
    *LEVEL.lock().unwrap() = level;
    socket::set_egress_gate(gate);
    Session { _g: g }
}

fn asked() -> usize {
    ASKED.lock().unwrap().len()
}

fn to(addr: [u8; 4], port: u16) -> SockAddr {
    SockAddr { family: AF_INET as u16, port, addr }
}

/// A bound UDP socket (an unbound one cannot send).
fn bound(fd: i32) -> i32 {
    static PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(41_000);
    assert!(fd >= 0);
    let port = PORT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(socket::socket_bind(fd, &SockAddr { family: AF_INET as u16, port, addr: [0; 4] }), 0);
    fd
}

fn udp_sock(owner: u32) -> i32 {
    bound(socket::socket_create_owned(AF_INET, SOCK_DGRAM, 0, owner))
}

fn datagrams_to(dst: [u8; 4]) -> usize {
    wire::sent().iter().filter(|s| s.dst_ip == dst && s.proto == crate::ip::IP_PROTO_UDP).count()
}

/// An unconnected `sendto` to a destination the row does not reach answers
/// `-EACCES` and puts nothing on the wire; one it reaches goes out.
/// **Canary.** `envelope-egress-canary`: the datagram goes out, red.
#[test]
fn a_sendto_past_the_rows_reach_is_refused_and_nothing_leaves() {
    let _s = begin(1); // cautious: private networks, not the public internet
    let fd = udp_sock(TASK);
    assert_eq!(socket::socket_sendto(fd, b"x", &to(PUBLIC, 53)), EGRESS_REFUSED, "sendto_is_refused");
    assert_eq!(datagrams_to(PUBLIC), 0, "a refused datagram reached the wire");
    assert_eq!(socket::socket_sendto(fd, b"x", &to(PRIVATE, 53)), 1);
    assert_eq!(datagrams_to(PRIVATE), 1);
    let log = ASKED.lock().unwrap().clone();
    assert_eq!(log[0], (TASK, DestClass::Public as u8, u32::from_be_bytes(PUBLIC), 53));
    assert_eq!(log[1], (TASK, DestClass::Private as u8, u32::from_be_bytes(PRIVATE), 53));
}

/// The gate is asked at the first packet to a destination and not again: a
/// new destination asks, the old one does not, and a refused one asks every
/// time (nothing was cleared).
#[test]
fn the_first_packet_to_a_destination_asks_and_the_next_do_not() {
    // What the stack does with a datagram after the gate (an ARP rate limit
    // can refuse a repeat) is not this test's: it counts the questions.
    let _s = begin(0);
    let fd = udp_sock(TASK);
    for i in 0..3 {
        assert_ne!(socket::socket_sendto(fd, b"x", &to(PRIVATE, 53)), EGRESS_REFUSED, "send {i}");
    }
    assert_eq!(asked(), 1);
    for i in 0..2 {
        assert_ne!(socket::socket_sendto(fd, b"x", &to(LINK, 53)), EGRESS_REFUSED, "send {i}");
    }
    assert_eq!(asked(), 2);
    assert_ne!(socket::socket_sendto(fd, b"x", &to(PRIVATE, 53)), EGRESS_REFUSED);
    assert_eq!(asked(), 3, "back to the first destination: the cache holds the last cleared one");
    // A closed socket's slot, reused, has cleared nothing.
    socket::socket_close(fd);
    let again = udp_sock(TASK);
    assert_ne!(socket::socket_sendto(again, b"x", &to(PRIVATE, 53)), EGRESS_REFUSED);
    assert_eq!(asked(), 4);
    // A refusal clears nothing: it asks again.
    *LEVEL.lock().unwrap() = 3;
    let c = udp_sock(TASK);
    assert_eq!(socket::socket_sendto(c, b"x", &to(LINK, 5353)), EGRESS_REFUSED);
    assert_eq!(socket::socket_sendto(c, b"x", &to(LINK, 5353)), EGRESS_REFUSED);
    assert_eq!(asked(), 6);
}

/// A connected UDP socket was cleared at the connect: its sends ask nothing.
/// A refused connect connects nothing.
#[test]
fn a_connect_asks_once_for_the_peer_and_a_refused_one_connects_nothing() {
    let _s = begin(1);
    let fd = udp_sock(TASK);
    assert_eq!(socket::socket_connect(fd, &to(PUBLIC, 9), 0), EGRESS_REFUSED, "connect_is_refused");
    assert_eq!(socket::socket_send(fd, b"x"), -1, "no peer was fixed");
    assert_eq!(datagrams_to(PUBLIC), 0);
    assert_eq!(socket::socket_connect(fd, &to(PRIVATE, 9), 0), 0);
    let before = asked();
    for _ in 0..4 {
        assert_eq!(socket::socket_send(fd, b"x"), 1);
    }
    assert_eq!(asked(), before, "the sends of a cleared peer ask nothing");
    assert_eq!(datagrams_to(PRIVATE), 4);
}

/// A TCP connect past the reach sends no SYN; inside it does. Through the
/// yielding connect the syscall layer uses, which would otherwise wait out the
/// handshake.
#[test]
fn a_tcp_connect_past_the_reach_sends_no_syn() {
    let _s = begin(1);
    let fd = socket::socket_create_owned(AF_INET, SOCK_STREAM, 0, TASK);
    assert!(fd >= 0);
    let rc = socket::socket_connect_with_yield(fd, &to(PUBLIC, 443), 0, || {});
    assert_eq!(rc, EGRESS_REFUSED, "tcp_connect_is_refused");
    assert!(wire::sent().iter().all(|s| s.dst_ip != PUBLIC), "a SYN left");
    let rc = socket::socket_connect(fd, &to(PRIVATE, 443), 0);
    assert_eq!(rc, 0);
    assert!(wire::sent().iter().any(|s| s.dst_ip == PRIVATE && s.proto == wire::IP_PROTO_TCP), "no SYN to the private peer");
}

/// An IPv6 stream connect is classed by its address; the word the gate records
/// is the address's last four bytes. (`::1` is classed as the node itself in
/// `azos_common::envelope`'s tests.)
#[test]
fn an_ipv6_connect_is_classed_by_its_address() {
    let _s = begin(1);
    let fd = socket::socket_create_owned(AF_INET6, SOCK_STREAM, 0, TASK);
    assert!(fd >= 0);
    let mut a = [0u8; 16];
    a[0] = 0x20;
    a[1] = 0x01;
    a[2] = 0x0d;
    a[3] = 0xb8;
    a[15] = 1;
    let dst = socket::SockAddr6 { port: 443, addr: a };
    assert_eq!(socket::socket_connect6_with_yield(fd, &dst, 0, || {}), EGRESS_REFUSED, "ipv6_connect_is_refused");
    assert_eq!(ASKED.lock().unwrap()[0], (TASK, DestClass::Public as u8, 1, 443));
}

/// What is not gated: loopback, a kernel-owned socket (the brain link, OTA,
/// TFTP belong to no Domain), and a build with no gate installed.
#[test]
fn loopback_the_kernels_own_sockets_and_a_missing_gate_are_not_held() {
    let _s = begin(3); // contained: nothing off the node
    let fd = udp_sock(TASK);
    assert_eq!(socket::socket_connect(fd, &to([127, 0, 0, 1], 9), 0), 0);
    assert_eq!(asked(), 0, "loopback never leaves the node");
    let k = bound(socket::socket_create(AF_INET, SOCK_DGRAM, 0));
    assert_eq!(socket::socket_sendto(k, b"x", &to(PUBLIC, 123)), 1);
    assert_eq!(asked(), 0, "a kernel socket belongs to no Domain");
    socket::clear_egress_gate_for_test();
    let o = udp_sock(TASK);
    assert_eq!(socket::socket_sendto(o, b"x", &to(PUBLIC, 123)), 1, "no gate, today's behaviour");
}

