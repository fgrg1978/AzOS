// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! TCP Timestamps (RFC 7323, Kconfig `TCP_TIMESTAMPS`): the negotiation, the
//! option on every segment after it, RTT measurement from the echo, PAWS, and
//! the room the option leaves SACK.
//!
//! **Canary**: built with `CONFIG_TCP_TIMESTAMPS=n` (a copy of the `.config`
//! named by `KCONFIG_CONFIG`), every test here but the one for a peer that
//! offers nothing fails: no SYN offers the option, none answers it, and the
//! rest follows.

use super::tcp_options::{
    establish_with, last, mss, open_active, option, sack_blocks, seg, sent, SACK_PERM, WSCALE,
};
use super::tcp_rx::*;
use super::{tcp, wire};

const SYN: u8 = 0x02;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;
const OPT_TS: u8 = 8;
const TICKS_PER_MS: u64 = 10_000;

/// NOP NOP + Timestamps, as Linux pads it.
fn ts(val: u32, ecr: u32) -> Vec<u8> {
    let mut o = vec![1, 1, OPT_TS, 10];
    o.extend_from_slice(&val.to_be_bytes());
    o.extend_from_slice(&ecr.to_be_bytes());
    o
}

/// (TSval, TSecr) of a segment's Timestamps option.
fn ts_of(opts: &[u8]) -> Option<(u32, u32)> {
    let v = option(opts, OPT_TS)?;
    assert_eq!(v.len(), 8, "a Timestamps option is 10 octets");
    Some((u32::from_be_bytes([v[0], v[1], v[2], v[3]]), u32::from_be_bytes([v[4], v[5], v[6], v[7]])))
}

/// A passive open from a peer whose SYN offers MSS 1460, Window Scale, SACK
/// and Timestamps with TSval `peer_ts`. Returns (idx, our SND.NXT, the peer's
/// next sequence, the TSval of our SYN-ACK).
fn open_ts(port: u16, peer_port: u16, peer_isn: u32, peer_ts: u32) -> (usize, u32, u32, u32) {
    let opts = [mss(1460).to_vec(), WSCALE.to_vec(), SACK_PERM.to_vec(), ts(peer_ts, 0)].concat();
    let (idx, ours, theirs, synack) = establish_with(port, peer_port, peer_isn, &opts, u16::MAX);
    let (val, ecr) = ts_of(&synack.opts).expect("a SYN offering Timestamps is answered with them");
    assert_eq!(ecr, peer_ts, "the SYN-ACK echoes the SYN's clock");
    (idx, ours, theirs, val)
}

/// Our SYN offers Timestamps, echo 0 (RFC 7323 §3.2), in Linux's 20-octet
/// layout: MSS, SACK-Permitted + Timestamps, NOP + Window Scale.
#[test]
fn an_active_open_offers_timestamps() {
    let _g = begin();
    wire::clear_sent();
    assert!(tcp::connect(PEER_IP, 47800, 47801) >= 0);
    let syn = last();
    assert_eq!(syn.flags & (SYN | ACK), SYN);
    let (_val, ecr) = ts_of(&syn.opts).expect("the SYN must offer Timestamps");
    assert_eq!(ecr, 0, "nothing to echo yet");
    assert_eq!(syn.opts.len(), 20, "MSS, SACK-Permitted + Timestamps, Window Scale: {:?}", syn.opts);
    assert!(option(&syn.opts, 4).is_some() && option(&syn.opts, 3).is_some());
}

/// Both SYNs carried the option, so every segment after them does (§3.2):
/// our data echoes the peer's newest clock, and its payload is the MSS less
/// the option's 12 octets (RFC 6691).
#[test]
fn a_negotiated_connection_stamps_every_segment_and_cuts_the_payload_by_the_option() {
    let _g = begin();
    let (idx, ours, theirs, synack_val) = open_ts(7801, 47802, 0x4000_0000, 1_000);
    deliver(&seg(47802, 7801, theirs, ours, PSH | ACK, u16::MAX, &ts(1_001, synack_val), b"hi"));
    let ack = last();
    assert_eq!(ts_of(&ack.opts).map(|t| t.1), Some(1_001), "the ACK echoes the newest clock");

    wire::clear_sent();
    assert_eq!(tcp::send_data(idx, &[0x33; 1460]), 1448, "1460 less the Timestamps option");
    let data = last();
    assert_eq!(data.payload_len, 1448);
    assert_eq!(ts_of(&data.opts).map(|t| t.1), Some(1_001));
    assert!(tcp::TcpHandle::find(7801, tcp::TcpState::Established).unwrap().negotiated().ts);
}

/// A peer that offers no Timestamps gets none, and the connection carries no
/// options at all: the full MSS of payload.
#[test]
fn a_syn_without_timestamps_is_answered_without_them() {
    let _g = begin();
    let opts = [mss(1460).to_vec(), SACK_PERM.to_vec()].concat();
    let (idx, _ours, _theirs, synack) = establish_with(7802, 47803, 0x4100_0000, &opts, u16::MAX);
    assert!(ts_of(&synack.opts).is_none(), "the SYN did not offer them");
    assert_eq!(tcp::send_data(idx, &[0x33; 1460]), 1460);
    assert!(last().opts.is_empty(), "no options on the data of a connection that negotiated none");
}

/// An active open whose SYN-ACK carries Timestamps uses them; our ACK echoes it.
#[test]
fn an_active_open_uses_timestamps_when_the_syn_ack_carries_them() {
    let _g = begin();
    wire::clear_sent();
    let idx = tcp::connect(PEER_IP, 47804, 47805);
    assert!(idx >= 0);
    let syn = last();
    let (syn_val, _) = ts_of(&syn.opts).unwrap();
    let opts = [mss(1460).to_vec(), ts(77, syn_val)].concat();
    deliver(&seg(47804, 47805, 0x4200_0000, syn.seq.wrapping_add(1), SYN | ACK, u16::MAX, &opts, &[]));
    assert!(tcp::conn_state(idx as usize) == tcp::TcpState::Established);
    assert_eq!(ts_of(&last().opts).map(|t| t.1), Some(77), "the third leg echoes the SYN-ACK's clock");
    // And a SYN-ACK without them leaves the connection without them.
    let (idx, _, _) = open_active(47806, 47807, 0x4300_0000, &mss(1460), u16::MAX);
    assert_eq!(tcp::send_data(idx, &[1; 1460]), 1460);
    assert!(last().opts.is_empty());
}

/// PAWS (§5): a segment inside the window whose clock is behind TS.Recent is
/// an old duplicate. It is not delivered, and it is answered with an ACK of
/// where we are; the same bytes with a current clock are taken.
#[test]
fn paws_refuses_a_segment_whose_clock_is_behind_and_takes_it_when_current() {
    let _g = begin();
    let (idx, ours, theirs, v) = open_ts(7803, 47808, 0x4400_0000, 5_000);
    deliver(&seg(47808, 7803, theirs, ours, PSH | ACK, u16::MAX, &ts(6_000, v), b"one"));
    let next = theirs.wrapping_add(3);

    wire::clear_sent();
    deliver(&seg(47808, 7803, next, ours, PSH | ACK, u16::MAX, &ts(5_999, v), b"two"));
    let mut buf = [0u8; 16];
    assert_eq!(tcp::recv(idx, &mut buf), 3, "only the first segment may be delivered");
    assert_eq!(&buf[..3], b"one");
    let out = sent();
    assert_eq!(out.len(), 1, "the refused segment is answered once: {out:?}");
    assert_eq!((out[0].ack, out[0].payload_len), (next, 0), "an ACK of what we have");

    deliver(&seg(47808, 7803, next, ours, PSH | ACK, u16::MAX, &ts(6_000, v), b"two"));
    assert_eq!(tcp::recv(idx, &mut buf), 3, "an equal clock is not behind");
    assert_eq!(&buf[..3], b"two");
}

/// TS.Recent follows §4.3: an out-of-order arrival does not move it (its
/// clock is not the one a sender times the hole with), the segment that fills
/// the hole does.
#[test]
fn the_echo_follows_the_segment_at_the_left_edge() {
    let _g = begin();
    let (_idx, ours, theirs, v) = open_ts(7804, 47809, 0x4500_0000, 100);
    deliver(&seg(47809, 7804, theirs, ours, PSH | ACK, u16::MAX, &ts(110, v), &[1; 100]));
    assert_eq!(ts_of(&last().opts).map(|t| t.1), Some(110));
    // 100 bytes lost, the next 100 arrive with a later clock: the duplicate
    // ACK still echoes 110.
    deliver(&seg(47809, 7804, theirs.wrapping_add(200), ours, PSH | ACK, u16::MAX,
                 &ts(130, v), &[3; 100]));
    assert_eq!(ts_of(&last().opts).map(|t| t.1), Some(110), "an out-of-order clock is not taken");
    deliver(&seg(47809, 7804, theirs.wrapping_add(100), ours, PSH | ACK, u16::MAX,
                 &ts(140, v), &[2; 100]));
    let ack = last();
    assert_eq!(ack.ack, theirs.wrapping_add(300), "the hole filled");
    assert_eq!(ts_of(&ack.opts).map(|t| t.1), Some(140), "the segment at the left edge sets the echo");
}

/// RTTM (§4): the ACK of a retransmitted segment is a sample, measured from
/// the transmission it echoes — no Karn rule, and no segment timed.
///
/// Sent at T0, resent by the timer at T0 + 1 s; the peer's ACK at T0 + 1010
/// ms echoes the FIRST transmission's clock: R = 1010 ms, the first sample, so
/// SRTT = 1010 ms and RTTVAR = 505 ms.
#[test]
fn the_ack_of_a_retransmission_is_timed_from_the_transmission_it_echoes() {
    let _g = begin();
    let t0 = azos_drv_sys::timebase::now();
    let (idx, ours, theirs, _v) = open_ts(7805, 47810, 0x4600_0000, 9);
    assert_eq!(tcp::send_data(idx, &[7; 500]), 500);
    let first = ts_of(&last().opts).unwrap().0;
    assert_eq!(tcp::conn_rtt(idx).unwrap().timed_seq, None, "with Timestamps nothing is timed");

    wire::clear_sent();
    azos_drv_irqchip::clint::set_test_time(t0 + 1_000 * TICKS_PER_MS);
    tcp::tcp_tick();
    let resent = last();
    assert_eq!(resent.payload_len, 500, "precondition: the timer resent it");
    assert_eq!(ts_of(&resent.opts).unwrap().0, first.wrapping_add(1_000), "the clock counts milliseconds");

    azos_drv_irqchip::clint::set_test_time(t0 + 1_010 * TICKS_PER_MS);
    deliver(&seg(47810, 7805, theirs, ours.wrapping_add(500), ACK, u16::MAX, &ts(10, first), &[]));
    let e = tcp::conn_rtt(idx).unwrap();
    assert!(e.measured, "the ACK of a resent segment must be a sample with Timestamps");
    assert_eq!(e.srtt, 1_010 * TICKS_PER_MS * 1_000, "R measured from the transmission echoed");
    assert_eq!(e.rttvar, 505 * TICKS_PER_MS * 1_000);
}

/// Beside Timestamps a SACK option has room for three blocks (40 = 12 + 4 +
/// 3 x 8), so the out-of-order queue holds three: every held range is
/// reported, and a fourth arrival is left for the peer to resend.
#[test]
fn beside_timestamps_three_held_ranges_are_held_and_all_reported() {
    let _g = begin();
    let (_idx, ours, theirs, v) = open_ts(7806, 47811, 0x4700_0000, 50);
    for k in 0..4u32 {
        deliver(&seg(47811, 7806, theirs.wrapping_add(200 * k + 100), ours, PSH | ACK, u16::MAX,
                     &ts(60 + k, v), &[k as u8; 100]));
    }
    let ack = last();
    assert!(ack.opts.len() <= 40);
    assert!(ts_of(&ack.opts).is_some(), "an ACK still carries Timestamps");
    let mut blocks = sack_blocks(&ack);
    blocks.sort();
    let at = |k: u32| theirs.wrapping_add(200 * k + 100);
    assert_eq!(blocks, vec![(at(0), at(0) + 100), (at(1), at(1) + 100), (at(2), at(2) + 100)],
        "three held ranges, all reported; the fourth arrival is not held");
}
