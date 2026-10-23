// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SYN cookies (RFC 4987 §3.6, Kconfig `TCP_SYNCOOKIES`): a listener whose
//! half-open slots are all taken answers with a stateless SYN-ACK, and the
//! third leg that carries the cookie back becomes the connection.
//!
//! **Canary**: built with `CONFIG_TCP_SYNCOOKIES=n`, the listener reaps its
//! oldest half-open connection instead (U06-7), and every test here fails:
//! the flood's oldest handshake no longer completes, and the third leg of a
//! handshake nobody holds draws a reset.

use super::tcp_options::{last, mss, option, seg, sent, Seg, SACK_PERM, WSCALE};
use super::tcp_rx::*;
use super::{tcp, wire};
use azos_limits::TCP_MAX_CONNS;

const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;
const WIN: u16 = u16::MAX;
const TICKS_PER_S: u64 = 10_000_000;

/// The half-open cap: half the table.
const CAP: usize = TCP_MAX_CONNS / 2;

/// Fill the half-open cap of listener `port` with SYNs from `CAP` distinct
/// ports. Returns each one's (peer port, peer ISN, our SYN-ACK), oldest first.
fn flood(port: u16, base: u16) -> Vec<(u16, u32, Seg)> {
    assert!(tcp::listen(port) >= 0);
    (0..CAP as u16)
        .map(|i| {
            wire::clear_sent();
            let isn = 0x6000_0000 + i as u32 * 0x1000;
            deliver(&seg(base + i, port, isn, 0, SYN, WIN, &mss(1460), &[]));
            (base + i, isn, last())
        })
        .collect()
}

/// The SYN-ACK a SYN from `peer_port` with `opts` draws.
fn syn(port: u16, peer_port: u16, isn: u32, opts: &[u8]) -> Seg {
    wire::clear_sent();
    deliver(&seg(peer_port, port, isn, 0, SYN, WIN, opts, &[]));
    let synack = last();
    assert_eq!(synack.flags & (SYN | ACK | RST), SYN | ACK, "a SYN-ACK");
    assert_eq!(count_in(tcp::TcpState::SynRcvd), CAP, "the cap still holds");
    synack
}

/// Every handshake of the flood still completes: the cookie reaped none of
/// them (the fallback without cookies reaps the oldest).
fn flood_intact(port: u16, f: &[(u16, u32, Seg)]) {
    let before = count_in(tcp::TcpState::Established);
    for (pp, isn, sa) in f {
        deliver(&seg(*pp, port, isn.wrapping_add(1), sa.seq.wrapping_add(1), ACK, WIN, &[], &[]));
    }
    assert_eq!(count_in(tcp::TcpState::Established), before + f.len(),
        "a half-open connection of the flood was reaped");
}

/// A listener at its half-open cap answers with a cookie: no slot is taken and
/// no half-open connection is reaped; the third leg, data and all, becomes a
/// connection `accept` returns, at the MSS the SYN offered. A SYN without
/// Timestamps gets a SYN-ACK with the MSS only: nothing else would be
/// remembered.
#[test]
fn at_the_half_open_cap_a_syn_gets_a_cookie_and_its_third_leg_a_connection() {
    let _g = begin();
    let f = flood(7701, 41700);
    assert_eq!(count_in(tcp::TcpState::SynRcvd), CAP, "precondition: the cap is full");

    let opts = [mss(1460).to_vec(), WSCALE.to_vec(), SACK_PERM.to_vec()].concat();
    let synack = syn(7701, 42701, 0x7000_0000, &opts);
    assert_eq!(synack.opts, mss(1460).to_vec(), "without Timestamps, the MSS alone");

    deliver(&seg(42701, 7701, 0x7000_0001, synack.seq.wrapping_add(1), PSH | ACK, WIN, &[], b"hello"));
    let h = tcp::TcpHandle::accept(7701).expect("the third leg must be a connection");
    let mut buf = [0u8; 8];
    assert_eq!(h.recv(&mut buf), 5, "the third leg's data is delivered");
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(h.remote_mss(), 1460, "the MSS the cookie carried");
    let n = h.negotiated();
    assert!(n.wscale.is_none() && !n.sack && !n.ts, "nothing a cookie without Timestamps can say");
    flood_intact(7701, &f);
}

/// With Timestamps the cookie keeps what the SYN offered in our TSval's low
/// bits, echoed back: the connection scales windows, SACKs and stamps its
/// segments as a stateful one would.
#[test]
fn with_timestamps_a_cookie_keeps_window_scale_and_sack() {
    let _g = begin();
    let f = flood(7702, 41710);
    let mut opts = [mss(1460).to_vec(), WSCALE.to_vec(), SACK_PERM.to_vec()].concat();
    opts.extend_from_slice(&[1, 1, 8, 10, 0, 0, 0, 33, 0, 0, 0, 0]);
    let synack = syn(7702, 42702, 0x7100_0000, &opts);
    assert!(option(&synack.opts, 3).is_some() && option(&synack.opts, 4).is_some(),
        "the SYN-ACK offers Window Scale and SACK back");
    let ts = option(&synack.opts, 8).expect("and Timestamps");
    let tsval = u32::from_be_bytes([ts[0], ts[1], ts[2], ts[3]]);

    let mut echo = vec![1, 1, 8, 10, 0, 0, 0, 34];
    echo.extend_from_slice(&tsval.to_be_bytes());
    deliver(&seg(42702, 7702, 0x7100_0001, synack.seq.wrapping_add(1), ACK, WIN, &echo, &[]));
    let h = tcp::TcpHandle::accept(7702).expect("the third leg must be a connection");
    let n = h.negotiated();
    assert_eq!(n.wscale.map(|w| w.0), Some(WSCALE[3]), "the peer's shift came back");
    assert!(n.sack && n.ts);
    wire::clear_sent();
    assert_eq!(h.send_data(&[9; 1460]), 1448, "a stamped connection: the MSS less 12");
    flood_intact(7702, &f);
}

/// A third leg whose cookie is not one we made — a wrong value, or the right
/// one with another peer ISN — is answered with a reset and opens nothing.
#[test]
fn a_forged_cookie_is_reset_and_opens_nothing() {
    let _g = begin();
    flood(7703, 41720);
    let synack = syn(7703, 42703, 0x7200_0000, &mss(1460));
    for (s, a) in [(0x7200_0001u32, synack.seq.wrapping_add(2)), (0x7200_0002, synack.seq.wrapping_add(1))] {
        wire::clear_sent();
        deliver(&seg(42703, 7703, s, a, ACK, WIN, &[], &[]));
        assert!(sent().iter().any(|o| o.flags & RST != 0), "a forged cookie draws a reset");
        assert!(tcp::TcpHandle::accept(7703).is_none(), "and opens no connection");
    }
    // The genuine one still works.
    deliver(&seg(42703, 7703, 0x7200_0001, synack.seq.wrapping_add(1), ACK, WIN, &[], &[]));
    assert!(tcp::TcpHandle::accept(7703).is_some());
}

/// A cookie is good for the period it was made in and the next (64 s each):
/// 100 s later it still works, 200 s later it does not.
#[test]
fn a_cookie_expires_after_two_periods() {
    let _g = begin();
    let t0 = azos_drv_sys::timebase::now();
    flood(7704, 41730);
    let first = syn(7704, 42704, 0x7300_0000, &mss(1460));
    let second = syn(7704, 42705, 0x7400_0000, &mss(1460));

    azos_drv_irqchip::clint::set_test_time(t0 + 100 * TICKS_PER_S);
    deliver(&seg(42704, 7704, 0x7300_0001, first.seq.wrapping_add(1), ACK, WIN, &[], &[]));
    assert!(tcp::TcpHandle::accept(7704).is_some(), "100 s: still valid");

    azos_drv_irqchip::clint::set_test_time(t0 + 200 * TICKS_PER_S);
    wire::clear_sent();
    deliver(&seg(42705, 7704, 0x7400_0001, second.seq.wrapping_add(1), ACK, WIN, &[], &[]));
    assert!(tcp::TcpHandle::accept(7704).is_none(), "200 s: expired");
    assert!(sent().iter().any(|o| o.flags & RST != 0));
}
