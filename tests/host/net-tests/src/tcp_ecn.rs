// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Explicit Congestion Notification (RFC 3168, Kconfig `TCP_ECN`): the
//! handshake, ECT(0) on new data only, the receiver's echo until CWR, and the
//! sender's once-per-window reaction. Marks come in through the real
//! `ip::handle`, so the IPv4 ECN field is read where the kernel reads it.
//!
//! **Canary**: built with `CONFIG_TCP_ECN=n`, every test here but the one for
//! a SYN that does not ask fails.

use super::tcp_options::{last, mss, seg, Seg};
use super::tcp_rx::*;
use super::{ip, raw, tcp, wire};

const SYN: u8 = 0x02;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;
const ECE: u8 = 0x40;
const CWR: u8 = 0x80;
const TICKS_PER_MS: u64 = 10_000;
const SEG: usize = 1000;
const WIN: u16 = u16::MAX;

/// The ECN field of every IPv4 TCP datagram on the wire, with the segment,
/// oldest first.
fn out() -> Vec<(u8, Seg)> {
    let segs = super::tcp_options::sent();
    let ecn: Vec<u8> = raw::all()
        .iter()
        .filter(|f| f.len() >= 34 && f[12..14] == [0x08, 0x00] && f[23] == wire::IP_PROTO_TCP)
        .map(|f| f[15] & 0b11)
        .collect();
    assert_eq!(ecn.len(), segs.len());
    ecn.into_iter().zip(segs).collect()
}

/// A segment from the peer in an IPv4 datagram whose ECN field is `ecn`,
/// through `ip::handle`; the held ACKs leave as at the end of a poll pass.
fn deliver_ecn(segment: &[u8], ecn: u8) {
    let mut d = vec![0u8; 20];
    let mut h = [0u8; 20];
    ip::build_header(&mut h, ip::IP_PROTO_TCP, &PEER_IP, &OUR_IP, segment.len() as u16);
    h[1] = ecn;
    h[10..12].copy_from_slice(&[0, 0]);
    let ck = ip::checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    d.copy_from_slice(&h);
    d.extend_from_slice(segment);
    ip::handle(&d, &OUR_MAC, &OUR_IP);
    if tcp::TCP_DELACK_PASS_FLUSH {
        tcp::flush_held_acks(false);
    }
}

/// A passive open whose SYN carries `syn_flags` (and MSS 1000). Returns (idx,
/// our SND.NXT, the peer's next sequence, the SYN-ACK).
fn open(port: u16, peer_port: u16, peer_isn: u32, syn_flags: u8) -> (usize, u32, u32, Seg) {
    assert!(tcp::listen(port) >= 0);
    wire::clear_sent();
    deliver(&seg(peer_port, port, peer_isn, 0, syn_flags, WIN, &mss(SEG as u16), &[]));
    let synack = last();
    let idx = slot_in(tcp::TcpState::SynRcvd).expect("a half-open slot");
    let ours = synack.seq.wrapping_add(1);
    let theirs = peer_isn.wrapping_add(1);
    deliver(&seg(peer_port, port, theirs, ours, ACK, WIN, &[], &[]));
    assert!(tcp::conn_state(idx) == tcp::TcpState::Established);
    wire::clear_sent();
    (idx, ours, theirs, synack)
}

/// Offer 1000-byte segments until one is refused; how many were taken.
fn fill(idx: usize) -> usize {
    let mut k = 0;
    while tcp::send_data(idx, &[0x5A; SEG]) == SEG as i32 {
        k += 1;
        assert!(k < 100);
    }
    k
}

/// Our SYN asks for ECN (ECE and CWR, RFC 3168 §6.1.1) and leaves Not-ECT
/// (§6.1.1: a SYN is never ECN-capable).
#[test]
fn an_active_open_asks_for_ecn() {
    let _g = begin();
    wire::clear_sent();
    assert!(tcp::connect(PEER_IP, 47900, 47901) >= 0);
    let (ecn, syn) = out().pop().unwrap();
    assert_eq!(syn.flags & (SYN | ACK | ECE | CWR), SYN | ECE | CWR, "an ECN-setup SYN");
    assert_eq!(ecn, 0, "a SYN is Not-ECT");
}

/// A SYN that asks is answered ECE without CWR, and the connection's new data
/// leaves ECT(0) while its pure ACKs stay Not-ECT (§6.1.4).
#[test]
fn a_syn_that_asks_is_agreed_to_and_new_data_is_ect() {
    let _g = begin();
    let (idx, ours, theirs, synack) = open(7901, 47902, 0x5000_0000, SYN | ECE | CWR);
    assert_eq!(synack.flags & (ECE | CWR), ECE, "an ECN-setup SYN-ACK");
    assert!(tcp::TcpHandle::find(7901, tcp::TcpState::Established).unwrap().negotiated().ecn);

    assert_eq!(tcp::send_data(idx, &[1; SEG]), SEG as i32);
    deliver(&seg(47902, 7901, theirs, ours.wrapping_add(SEG as u32), PSH | ACK, WIN, &[], b"x"));
    let o = out();
    assert_eq!(o[0].1.payload_len, SEG);
    assert_eq!(o[0].0, ip::ECN_ECT0, "new data is ECT(0)");
    let ack = o.last().unwrap();
    assert_eq!((ack.1.payload_len, ack.0), (0, 0), "a pure ACK is Not-ECT");
}

/// A SYN that does not ask gets no ECN: no ECE on the SYN-ACK, Not-ECT data.
#[test]
fn a_syn_that_does_not_ask_gets_no_ecn() {
    let _g = begin();
    let (idx, _ours, _theirs, synack) = open(7902, 47903, 0x5100_0000, SYN);
    assert_eq!(synack.flags & (ECE | CWR), 0);
    assert_eq!(tcp::send_data(idx, &[1; SEG]), SEG as i32);
    assert_eq!(out()[0].0, 0, "Not-ECT on a connection without ECN");
}

/// A retransmission is never ECN-capable (§6.1.5).
#[test]
fn a_retransmission_is_not_ect() {
    let _g = begin();
    let t0 = azos_drv_sys::timebase::now();
    let (idx, _ours, _theirs, _) = open(7903, 47904, 0x5200_0000, SYN | ECE | CWR);
    assert_eq!(tcp::send_data(idx, &[1; SEG]), SEG as i32);
    assert_eq!(out()[0].0, ip::ECN_ECT0, "precondition: the first transmission is ECT(0)");
    wire::clear_sent();
    azos_drv_irqchip::clint::set_test_time(t0 + 1_000 * TICKS_PER_MS);
    tcp::tcp_tick();
    let (ecn, s) = out().pop().unwrap();
    assert_eq!(s.payload_len, SEG, "precondition: the timer resent it");
    assert_eq!(ecn, 0, "the resend is Not-ECT");
}

/// The receiver (§6.1.3): a CE mark is answered at once with ECE, every
/// segment after it carries ECE, and a segment with CWR ends the echo.
#[test]
fn a_mark_is_echoed_until_the_sender_says_it_reacted() {
    let _g = begin();
    let (_idx, ours, theirs, _) = open(7904, 47905, 0x5300_0000, SYN | ECE | CWR);
    deliver_ecn(&seg(47905, 7904, theirs, ours, ACK, WIN, &[], &[2; 1000]), ip::ECN_CE);
    let a = last();
    assert_eq!(a.ack, theirs.wrapping_add(1000), "the marked segment is taken");
    assert_ne!(a.flags & ECE, 0, "and echoed at once");

    let theirs = theirs.wrapping_add(1000);
    deliver_ecn(&seg(47905, 7904, theirs, ours, PSH | ACK, WIN, &[], b"y"), ip::ECN_ECT0);
    assert_ne!(last().flags & ECE, 0, "the echo goes on until CWR");

    let theirs = theirs.wrapping_add(1);
    deliver_ecn(&seg(47905, 7904, theirs, ours, PSH | ACK | CWR, WIN, &[], b"z"), ip::ECN_ECT0);
    assert_eq!(last().flags & ECE, 0, "CWR ends the echo");
}

/// The sender (§6.1.2): an echo halves the window once; further echoes for
/// data sent before the reaction change nothing, and the first new segment
/// after it carries CWR. An echo for data sent after the reaction is a new
/// signal.
///
/// Ten segments in flight (RFC 6928's window at an MSS of 1000). The ACK of
/// S0 with ECE: ssthresh = max(9000 / 2, 2000) = 4500, cwnd 4500 against 9000
/// in flight, nothing new leaves. The ACK of S1..S6 with ECE is the same
/// window: 3000 in flight under a cwnd past 4500 lets one segment go, with
/// CWR; halving again would have left 2000 against 3000 and sent nothing.
#[test]
fn an_echo_halves_the_window_once_per_window_and_the_next_data_carries_cwr() {
    let _g = begin();
    let (idx, ours, theirs, _) = open(7905, 47906, 0x5400_0000, SYN | ECE | CWR);
    assert_eq!(fill(idx), 10, "precondition: the initial window");
    let at = |k: u32| ours.wrapping_add(k * SEG as u32);

    deliver(&seg(47906, 7905, theirs, at(1), ACK | ECE, WIN, &[], &[]));
    wire::clear_sent();
    assert_eq!(fill(idx), 0, "the echo halved the window below what is in flight");

    deliver(&seg(47906, 7905, theirs, at(7), ACK | ECE, WIN, &[], &[]));
    wire::clear_sent();
    assert!(fill(idx) >= 1, "a second echo in the same window halved it again");
    let o = out();
    assert_ne!(o[0].1.flags & CWR, 0, "the first new segment after the reaction carries CWR");
    assert!(o[1..].iter().all(|(_, s)| s.flags & CWR == 0), "and only the first");

    // An echo acknowledging data sent after the reaction is a new signal.
    let sent_after = o.len() as u32;
    deliver(&seg(47906, 7905, theirs, at(10 + sent_after), ACK | ECE, WIN, &[], &[]));
    wire::clear_sent();
    let k = fill(idx);
    assert!(k >= 1, "the new reaction leaves a window: nothing is in flight");
    assert_ne!(out()[0].1.flags & CWR, 0, "a new reaction, a new CWR");
}
