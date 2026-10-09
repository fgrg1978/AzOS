// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Generation-checked TCP handles and the ephemeral port allocator.
//!
//! **The ABA.** Kernel tasks and the socket table held a bare slot index and
//! closed it after a wait. A peer's RST frees the slot under its holder, the
//! next connect takes the same slot, and the old holder's `close` then closes
//! the NEW connection: vsbench's TCP lane was cut 3/3 that way when the brain
//! link's connect was refused. A [`tcp::TcpHandle`] carries the generation its
//! slot had when it was issued, and every operation through a stale handle is
//! a no-op.
//!
//! **The port.** `SYS_CONNECT` chose `0xC000 + fd` as the local port, so a
//! second connect on the same fd named the previous connection's 4-tuple,
//! which the peer may still hold in TIME-WAIT and refuse. Local port 0 now
//! asks the stack for a free port from the ephemeral range.
//!
//! Canaries (three buckets): `--cfg 'feature="tcp-handle-gen-canary"'` turns
//! the stale-handle tests red, `--cfg 'feature="tcp-ephemeral-port-canary"'`
//! the port tests; a bare slot index passed to `TcpHandle`'s API, or a raw
//! `azos_net::tcp::close(usize)` from outside the net crate, does not compile.

use super::tcp;
use super::tcp_rx::*;

const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;
const FIN: u8 = 0x01;

/// The last SYN we sent: `(local port, ISN)`.
fn last_syn() -> (u16, u32) {
    let s = super::wire::sent();
    let p = &s.last().expect("connect must put a SYN on the wire").payload;
    assert_eq!(p[13] & SYN, SYN, "the last segment out must be our SYN");
    (u16::from_be_bytes([p[0], p[1]]), u32::from_be_bytes([p[4], p[5], p[6], p[7]]))
}

/// Refuse our SYN the way a closed peer port does: RST|ACK acknowledging it.
fn refuse(peer_port: u16, our_port: u16, our_isn: u32) {
    deliver(&segment(peer_port, our_port, 0, our_isn.wrapping_add(1), RST | ACK, 0, &[]));
}

#[test]
fn a_stale_handle_closes_nothing_after_its_slot_is_reissued() {
    let _g = begin();
    let a = tcp::TcpHandle::connect(PEER_IP, 9000, 0).expect("connect A");
    let (a_port, a_isn) = last_syn();
    refuse(9000, a_port, a_isn);
    assert!(a.state() == tcp::TcpState::Closed,
        "precondition: the RST frees A's slot, got {}", st(a.state()));

    let b = tcp::TcpHandle::connect(PEER_IP, 9001, 0).expect("connect B");
    assert_eq!(b.slot(), a.slot(), "precondition: B must reuse A's slot");
    assert!(b.state() == tcp::TcpState::SynSent, "precondition: B in SynSent");

    super::wire::clear_sent();
    a.close();
    a.abort();
    a.shutdown_write();
    assert!(b.state() == tcp::TcpState::SynSent,
        "A's stale handle closed B's connection (now {}): the ABA the generation exists \
         to close", st(b.state()));
    assert!(super::wire::sent().is_empty(),
        "a stale handle put {} segment(s) on B's 4-tuple", super::wire::sent_count());
    assert!(a.state() == tcp::TcpState::Closed, "a stale handle reads as Closed");
    assert_eq!(a.send_data(b"x"), -1, "and sends nothing");
    let mut buf = [0u8; 4];
    assert_eq!(a.recv(&mut buf), -1, "and reads nothing");
    assert_eq!(a.local_port(), 0, "and has no port");
    b.close();
}

/// The same hole one layer up: the socket table held the slot, so closing
/// the old fd closed whatever connection held the slot by then.
#[test]
fn closing_an_fd_whose_slot_was_reissued_leaves_the_new_owner_alone() {
    let _g = begin();
    use crate::socket::{socket_close, socket_connect, socket_create, SockAddr, AF_INET, SOCK_STREAM};
    let peer = |port| SockAddr { family: 2, port, addr: PEER_IP };

    let fd1 = socket_create(AF_INET, SOCK_STREAM, 0);
    assert!(fd1 >= 0);
    assert_eq!(socket_connect(fd1, &peer(9010), 0), 0, "connect fd1");
    let (p1, isn1) = last_syn();
    refuse(9010, p1, isn1);

    let fd2 = socket_create(AF_INET, SOCK_STREAM, 0);
    assert!(fd2 >= 0 && fd2 != fd1);
    assert_eq!(socket_connect(fd2, &peer(9011), 0), 0, "connect fd2");
    let h1 = crate::socket::socket_tcp_conn(fd1).expect("fd1 has a connection");
    let h2 = crate::socket::socket_tcp_conn(fd2).expect("fd2 has a connection");
    assert_eq!(h1.slot(), h2.slot(), "precondition: fd2's connection reuses fd1's slot");

    socket_close(fd1);
    assert!(h2.state() == tcp::TcpState::SynSent,
        "closing fd1 closed fd2's connection (now {})", st(h2.state()));
    socket_close(fd2);
    assert!(h2.state() == tcp::TcpState::Closed, "control: fd2's own close does close it");
}

#[test]
fn two_consecutive_connects_get_different_ephemeral_ports() {
    let _g = begin();
    let a = tcp::TcpHandle::connect(PEER_IP, 9020, 0).expect("connect A");
    let (pa, _) = last_syn();
    assert_eq!(a.local_port(), pa, "the handle reports the port on the wire");
    a.close();
    assert!(a.state() == tcp::TcpState::Closed, "precondition: A gone");
    let b = tcp::TcpHandle::connect(PEER_IP, 9020, 0).expect("connect B");
    let (pb, _) = last_syn();
    b.close();
    for p in [pa, pb] {
        assert!((tcp::EPHEMERAL_MIN..=tcp::EPHEMERAL_MAX).contains(&p),
            "port {p} outside the ephemeral range");
    }
    assert_ne!(pa, pb,
        "a redial to the same peer reused local port {pa}: the 4-tuple the peer may still \
         hold (the old 0xC000 + fd behaviour)");
}

/// The same through the socket layer, on one fd reused for a second connect.
#[test]
fn a_reused_fd_connects_from_a_new_port() {
    let _g = begin();
    use crate::socket::{socket_close, socket_connect, socket_create, SockAddr, AF_INET, SOCK_STREAM};
    let peer = SockAddr { family: 2, port: 9030, addr: PEER_IP };
    let fd = socket_create(AF_INET, SOCK_STREAM, 0);
    assert_eq!(socket_connect(fd, &peer, 0), 0);
    let (p1, _) = last_syn();
    socket_close(fd);
    let fd2 = socket_create(AF_INET, SOCK_STREAM, 0);
    assert_eq!(fd2, fd, "precondition: the fd is reused");
    assert_eq!(socket_connect(fd2, &peer, 0), 0);
    let (p2, _) = last_syn();
    socket_close(fd2);
    assert_ne!(p1, p2, "the reused fd dialled from its previous local port {p1}");
}

/// A port whose connection sits in TIME-WAIT, to the same peer, is never
/// handed out again until that connection is gone -- across a whole lap of
/// the range, so the cursor certainly passes it.
#[test]
fn a_port_held_in_time_wait_is_skipped() {
    let _g = begin();
    const PEER_PORT: u16 = 9040;
    let a = tcp::TcpHandle::connect(PEER_IP, PEER_PORT, 0).expect("connect A");
    let (p, isn) = last_syn();
    let peer_isn = 0x7000_0000u32;
    deliver(&segment(PEER_PORT, p, peer_isn, isn.wrapping_add(1), SYN | ACK, 4096, &[]));
    assert!(a.state() == tcp::TcpState::Established, "precondition: established");
    a.close(); // our FIN: FinWait1
    // The peer acknowledges our FIN and sends its own: TimeWait.
    deliver(&segment(PEER_PORT, p, peer_isn.wrapping_add(1), isn.wrapping_add(2),
                     FIN | ACK, 4096, &[]));
    assert!(a.state() == tcp::TcpState::TimeWait,
        "precondition: TimeWait, got {}", st(a.state()));

    let span = (tcp::EPHEMERAL_MAX - tcp::EPHEMERAL_MIN) as u32 + 1;
    for i in 0..span {
        super::wire::clear_sent();
        let h = tcp::TcpHandle::connect(PEER_IP, PEER_PORT, 0)
            .unwrap_or_else(|| panic!("connect #{i} failed with one port in TIME-WAIT"));
        let (q, _) = last_syn();
        assert_ne!(q, p, "connect #{i} was handed port {p}, held in TIME-WAIT for the same peer");
        h.close();
    }
    assert!(a.state() == tcp::TcpState::TimeWait, "the TIME-WAIT connection was left alone");
}
