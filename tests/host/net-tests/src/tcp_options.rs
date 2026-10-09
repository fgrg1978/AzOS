// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Window scaling (RFC 7323), SACK (RFC 2018) and the MSS option, read off
//! the wire.
//!
//! **The rest of this suite negotiates nothing.** `tcp_rx::establish` sends a
//! bare 20-byte SYN, so every other TCP module runs the unscaled, SACK-less
//! path — which is also exactly what a peer that ignores both options gets.
//! Every test here opens with a SYN that carries options, and checks one of
//! the things a peer depends on:
//!
//! * an option is on only when BOTH SYNs carried it — a window we scale and
//!   the peer reads raw is wrong by a factor of `2^shift`;
//! * after the SYN exchange every window is shifted, the ones we write and the
//!   ones we read, and the window of a SYN itself never is;
//! * a SACK block names bytes we actually hold: never a range at or below the
//!   cumulative ACK, never the tail of a segment we truncated, never a segment
//!   left behind by a previous connection in the same slot.
//!
//! The RFC 5961 reset rule gets its own case at the edge of the scaled window,
//! because "in window" is the one phrase scaling changes.

use super::tcp_rx::*;
use super::{tcp, wire};
use azos_limits::TCP_BUF_SIZE;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

const OPT_MSS: u8 = 2;
const OPT_WSCALE: u8 = 3;
const OPT_SACK_PERM: u8 = 4;
const OPT_SACK: u8 = 5;

/// Restated from `tcp.rs` (`TCP_MSS`), as `tcp_reassembly` does.
const OOO_SEGMENT_MAX_LEN: u32 = 1460;

/// `RCV_WSCALE` is private to `tcp.rs`. Its definition is "the smallest shift
/// that fits `TCP_BUF_SIZE - 1` in the 16-bit field", so that is what is
/// written here, and the SYN-ACK test pins the value on the wire against it.
const OUR_WSCALE: u8 = {
    let mut s = 0u8;
    while ((TCP_BUF_SIZE - 1) >> s) > u16::MAX as usize {
        s += 1;
    }
    s
};

/// The largest window a scaled connection can advertise: 65535 shifted, and
/// never more than the ring.
const SCALED_WND: u32 = {
    let w = (u16::MAX as u32) << OUR_WSCALE;
    if w > TCP_BUF_SIZE as u32 { TCP_BUF_SIZE as u32 } else { w }
};

/// Linux's default shift, and large enough that a forgotten shift is not a
/// near miss.
const PEER_WSCALE: u8 = 7;

fn mss(v: u16) -> [u8; 4] {
    let b = v.to_be_bytes();
    [OPT_MSS, 4, b[0], b[1]]
}

/// NOP + Window Scale, padded to a word the way Linux sends it.
const WSCALE: [u8; 4] = [1, OPT_WSCALE, 3, PEER_WSCALE];

/// NOP NOP + SACK-Permitted.
const SACK_PERM: [u8; 4] = [1, 1, OPT_SACK_PERM, 2];

/// What a Linux SYN offers, less timestamps.
fn all_options() -> Vec<u8> {
    [mss(1460), WSCALE, SACK_PERM].concat()
}

/// `tcp_rx::segment`, with TCP options. That builder hardcodes a 20-byte
/// header, which is why nothing else in the suite can negotiate.
fn seg(
    src_port: u16, dst_port: u16, seq: u32, ack: u32,
    flags: u8, window: u16, opts: &[u8], payload: &[u8],
) -> Vec<u8> {
    assert_eq!(opts.len() % 4, 0, "options must be padded to whole words");
    let mut s = Vec::with_capacity(20 + opts.len() + payload.len());
    s.extend_from_slice(&src_port.to_be_bytes());
    s.extend_from_slice(&dst_port.to_be_bytes());
    s.extend_from_slice(&seq.to_be_bytes());
    s.extend_from_slice(&ack.to_be_bytes());
    s.push((((20 + opts.len()) / 4) as u8) << 4);
    s.push(flags);
    s.extend_from_slice(&window.to_be_bytes());
    s.extend_from_slice(&[0, 0]); // checksum placeholder
    s.extend_from_slice(&[0, 0]); // urgent
    s.extend_from_slice(opts);
    s.extend_from_slice(payload);
    let pseudo = wire::pseudo_checksum(&PEER_IP, &OUR_IP, wire::IP_PROTO_TCP, s.len() as u16);
    let ck = tcp::tcp_checksum(pseudo, &s);
    s[16..18].copy_from_slice(&ck.to_be_bytes());
    s
}

/// A segment the stack put on the wire, options included.
#[derive(Debug, Clone)]
struct Seg {
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    opts: Vec<u8>,
    payload_len: usize,
}

fn sent() -> Vec<Seg> {
    wire::sent()
        .iter()
        .filter(|s| s.proto == wire::IP_PROTO_TCP)
        .map(|s| {
            let p = &s.payload;
            let off = ((p[12] >> 4) as usize) * 4;
            Seg {
                seq: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
                ack: u32::from_be_bytes([p[8], p[9], p[10], p[11]]),
                flags: p[13],
                window: u16::from_be_bytes([p[14], p[15]]),
                opts: p[20..off].to_vec(),
                payload_len: p.len() - off,
            }
        })
        .collect()
}

fn last() -> Seg {
    sent().pop().expect("a segment should have been sent")
}

/// The value bytes of the first option of `kind`, walking NOPs and lengths.
fn option(opts: &[u8], kind: u8) -> Option<Vec<u8>> {
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => return None,
            1 => i += 1,
            k => {
                let len = *opts.get(i + 1)? as usize;
                if len < 2 || i + len > opts.len() {
                    return None;
                }
                if k == kind {
                    return Some(opts[i + 2..i + len].to_vec());
                }
                i += len;
            }
        }
    }
    None
}

/// The SACK blocks a segment carries, in the order it carries them.
fn sack_blocks(s: &Seg) -> Vec<(u32, u32)> {
    option(&s.opts, OPT_SACK)
        .map(|v| {
            v.chunks(8)
                .map(|c| {
                    (u32::from_be_bytes([c[0], c[1], c[2], c[3]]),
                     u32::from_be_bytes([c[4], c[5], c[6], c[7]]))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Complete a passive open on a port that is already listening: a SYN carrying
/// `syn_opts`, then a third leg advertising `ack_window`.
/// Returns (idx, our snd.nxt, the peer's next sequence, the SYN-ACK).
fn handshake(
    port: u16, peer_port: u16, peer_isn: u32, syn_opts: &[u8], ack_window: u16,
) -> (usize, u32, u32, Seg) {
    wire::clear_sent();
    deliver(&seg(peer_port, port, peer_isn, 0, SYN, 4096, syn_opts, &[]));
    let synack = last();
    assert_eq!(synack.flags & (SYN | ACK), SYN | ACK, "expected SYN-ACK");
    let idx = slot_in(tcp::TcpState::SynRcvd)
        .expect("the SYN must have opened a half-open connection");
    let ours = synack.seq.wrapping_add(1);
    let theirs = peer_isn.wrapping_add(1);
    deliver(&seg(peer_port, port, theirs, ours, ACK, ack_window, &[], &[]));
    assert!(
        tcp::conn_state(idx) == tcp::TcpState::Established,
        "the third leg must establish it, got {}", st(tcp::conn_state(idx)),
    );
    wire::clear_sent();
    (idx, ours, theirs, synack)
}

fn establish_with(
    port: u16, peer_port: u16, peer_isn: u32, syn_opts: &[u8], ack_window: u16,
) -> (usize, u32, u32, Seg) {
    assert!(tcp::listen(port) >= 0, "no free connection slot for the listener");
    handshake(port, peer_port, peer_isn, syn_opts, ack_window)
}

/// Dial out, and answer our SYN with a SYN-ACK carrying `opts` and `window`.
/// Returns (idx, our snd.nxt, the peer's next sequence).
fn open_active(
    local_port: u16, peer_port: u16, peer_isn: u32, opts: &[u8], window: u16,
) -> (usize, u32, u32) {
    wire::clear_sent();
    let idx = tcp::connect(PEER_IP, peer_port, local_port);
    assert!(idx >= 0, "no free connection slot to dial out");
    let idx = idx as usize;
    let iss = last().seq;
    deliver(&seg(peer_port, local_port, peer_isn, iss.wrapping_add(1),
                 SYN | ACK, window, opts, &[]));
    assert!(
        tcp::conn_state(idx) == tcp::TcpState::Established,
        "the SYN-ACK must establish it, got {}", st(tcp::conn_state(idx)),
    );
    wire::clear_sent();
    (idx, iss.wrapping_add(1), peer_isn.wrapping_add(1))
}

/// Deliver `n` in-order bytes starting at `theirs`, in 1 KiB segments, and
/// return the next sequence. Carries `ours` as the ACK (U06-1/U13-1: an
/// unacceptable ACK now drops the whole segment, so `ack = 0` stopped being
/// a convenience and became wrong).
fn fill(port: u16, peer_port: u16, ours: u32, mut theirs: u32, n: usize) -> u32 {
    let chunk = [0x5Au8; 1024];
    let mut left = n;
    while left > 0 {
        let k = left.min(chunk.len());
        deliver(&seg(peer_port, port, theirs, ours, PSH | ACK, 4096, &[], &chunk[..k]));
        theirs = theirs.wrapping_add(k as u32);
        left -= k;
    }
    theirs
}

/// `fill`, reading connection `idx` empty after each segment, so the receive
/// ring never holds more than one and every arrival sees the whole window.
fn fill_draining(idx: usize, port: u16, peer_port: u16, ours: u32, mut theirs: u32, n: usize) -> u32 {
    let chunk = [0x5Au8; 1024];
    let mut buf = [0u8; 4096];
    let mut left = n;
    while left > 0 {
        let k = left.min(chunk.len());
        deliver(&seg(peer_port, port, theirs, ours, PSH | ACK, 4096, &[], &chunk[..k]));
        theirs = theirs.wrapping_add(k as u32);
        left -= k;
        while tcp::recv(idx, &mut buf) > 0 {}
    }
    theirs
}

/// The window field for `buffered` unread bytes on a scaled connection.
fn scaled_window(buffered: usize) -> u16 {
    ((TCP_BUF_SIZE - buffered - 1) >> OUR_WSCALE).min(u16::MAX as usize) as u16
}

/// The window field for `buffered` unread bytes on an unscaled connection: the
/// free space, saturated. 65535 at the 128 KiB ring, where a shift would show.
fn raw_window(buffered: usize) -> u16 {
    (TCP_BUF_SIZE - buffered - 1).min(u16::MAX as usize) as u16
}

/// 10 KiB unread: enough to pull a scaled window below the 65535 an unscaled
/// one still shows, which an empty buffer does not (both read 65535).
const BUFFERED: usize = 10 * 1024;

// ── Negotiation ──────────────────────────────────────────────────────────────

/// A SYN-ACK may carry Window Scale only if the SYN did (RFC 7323 §2.2), and
/// SACK-Permitted likewise: an option one end never offered is one it will
/// never honour. Every SYN-ACK carries our MSS, and its window is not scaled.
#[test]
fn a_syn_ack_carries_window_scale_and_sack_permitted_only_if_the_syn_did() {
    let _g = begin();
    assert!(tcp::listen(7800) >= 0);
    let cases: [(&str, Vec<u8>, bool, bool); 4] = [
        ("no option but MSS", mss(1460).to_vec(), false, false),
        ("Window Scale", [mss(1460), WSCALE].concat(), true, false),
        ("SACK-Permitted", [mss(1460), SACK_PERM].concat(), false, true),
        ("both", all_options(), true, true),
    ];
    for (i, (what, opts, ws, sack)) in cases.iter().enumerate() {
        wire::clear_sent();
        deliver(&seg(44000 + i as u16, 7800, 0x1000 + i as u32, 0, SYN, 4096, opts, &[]));
        let synack = last();
        assert_eq!(synack.flags & (SYN | ACK), SYN | ACK, "{what}: expected a SYN-ACK");
        assert_eq!(synack.payload_len, 0, "{what}: a SYN-ACK carries no data");
        assert_eq!(
            option(&synack.opts, OPT_MSS), Some(1460u16.to_be_bytes().to_vec()),
            "{what}: our MSS is the 1500-byte MTU less 20 of IP and 20 of TCP",
        );
        assert_eq!(
            option(&synack.opts, OPT_WSCALE), if *ws { Some(vec![OUR_WSCALE]) } else { None },
            "{what}: Window Scale must be echoed exactly when the SYN offered it",
        );
        assert_eq!(
            option(&synack.opts, OPT_SACK_PERM).is_some(), *sack,
            "{what}: SACK-Permitted must be echoed exactly when the SYN offered it",
        );
        assert_eq!(synack.window, EMPTY_WINDOW, "{what}: the window of a SYN-ACK is never scaled");
    }
}

/// An active open offers both options, and its SYN's window is not scaled —
/// the shift it offers is not in force until the SYN-ACK agrees to it.
#[test]
fn an_active_open_offers_both_options_in_a_syn_whose_window_is_not_scaled() {
    let _g = begin();
    wire::clear_sent();
    assert!(tcp::connect(PEER_IP, 7810, 45010) >= 0);
    let syn = last();
    assert_eq!(syn.flags, SYN, "expected a bare SYN");
    assert_eq!(option(&syn.opts, OPT_MSS), Some(1460u16.to_be_bytes().to_vec()));
    assert_eq!(option(&syn.opts, OPT_WSCALE), Some(vec![OUR_WSCALE]),
        "the SYN must offer the shift that covers the {TCP_BUF_SIZE}-byte ring");
    assert!(option(&syn.opts, OPT_SACK_PERM).is_some(), "the SYN must offer SACK");
    assert_eq!(syn.window, EMPTY_WINDOW, "RFC 7323 §2.2: a SYN's window is never scaled");
}

// ── The configured ring size ─────────────────────────────────────────────────

/// A connection is its two rings, each `TCP_BUF_SIZE` bytes from `.config`, and
/// a fixed amount of state, so the static table follows the configured size
/// byte for byte. `STATE` was measured on 2026-09-14 (6,088 B) and grew by 24 B in wave 15 (delayed-ACK state, N6): 268,256 B per connection
/// at 131072 (edge, embedded) and 38,880 B at 16384 (fleet), the figures
/// `config/Kconfig.limits` quotes. `STATE` is exact on purpose:
/// whoever adds or resizes a `TcpConn` field updates it here, together with
/// those figures in `config/Kconfig.limits` (also quoted in
/// `config/Kconfig.network` and `config/defconfigs/fleet.config`).
#[test]
fn a_connection_is_two_rings_of_the_configured_size_plus_fixed_state() {
    const STATE: usize = 6_112;
    let one = core::mem::size_of::<tcp::TcpConn>();
    println!(
        "[tcp-size] TCP_BUF_SIZE {TCP_BUF_SIZE} B: size_of::<TcpConn>() = {one} B, \
         TCP_MAX_CONNS {} x {one} B = {} B",
        tcp::TCP_MAX_CONNS, tcp::TCP_MAX_CONNS * one,
    );
    assert_eq!(
        one, 2 * TCP_BUF_SIZE + STATE,
        "a connection must be a receive ring and a send ring of TCP_BUF_SIZE = {TCP_BUF_SIZE} \
         bytes plus {STATE} B of state",
    );
}

/// The shift a SYN offers and the window it carries follow the configured ring.
/// Stated independently of `OUR_WSCALE` and `EMPTY_WINDOW`, which restate the
/// code's own expressions: for a power-of-two ring (`crates/core/limits/build.rs`)
/// the smallest shift that fits `TCP_BUF_SIZE - 1` in 16 bits is
/// `log2(TCP_BUF_SIZE) - 16`, never below 0 (1 at 131072, 0 at 16384), and a
/// SYN's window is the empty ring's free space, `TCP_BUF_SIZE - 1`, saturated.
#[test]
fn the_offered_shift_and_the_syn_window_follow_the_configured_ring() {
    let _g = begin();
    let shift = TCP_BUF_SIZE.trailing_zeros().saturating_sub(16) as u8;
    let window = if TCP_BUF_SIZE > 65536 { u16::MAX } else { (TCP_BUF_SIZE - 1) as u16 };
    wire::clear_sent();
    assert!(tcp::connect(PEER_IP, 7990, 45190) >= 0, "no free connection slot to dial out");
    let syn = last();
    assert_eq!(syn.flags, SYN, "expected a bare SYN");
    assert_eq!(option(&syn.opts, OPT_WSCALE), Some(vec![shift]),
        "a {TCP_BUF_SIZE}-byte ring: the SYN must offer shift {shift}");
    assert_eq!(syn.window, window,
        "a {TCP_BUF_SIZE}-byte ring holds {} bytes: that is the most a SYN may offer",
        TCP_BUF_SIZE - 1);
}

/// Slow start lasts until the send ring is the bound. The initial ssthresh is
/// `TCP_BUF_SIZE` and `cwnd` never exceeds the send ring of the same size, so
/// every ACK of one full segment releases two until the next pair no longer
/// fits in the ring. A threshold below the ring would end slow start early, and
/// from there an ACK of one segment releases one. The peer's window,
/// 65535 << 7, is larger than any ring `config/Kconfig.network` allows.
///
/// A threshold at or above the ring cannot be told apart from `TCP_BUF_SIZE`
/// this way: `grow_cwnd` stops at the ring either way.
#[test]
fn slow_start_lasts_until_the_send_ring_is_full() {
    const SEG: usize = 1460;
    let _g = begin();
    let (idx, ours, theirs, _) =
        establish_with(7991, 45191, 0x1A00_0000, &all_options(), u16::MAX);
    let ring = TCP_BUF_SIZE / SEG;
    let data = [0x5Cu8; SEG];
    let offer = |flight: &mut usize| -> usize {
        let mut k = 0;
        loop {
            let n = tcp::send_data(idx, &data);
            assert!(n >= 0, "send_data failed on an established connection: {n}");
            if n == 0 {
                return k;
            }
            assert_eq!(n as usize, SEG, "a whole segment, or nothing");
            *flight += 1;
            k += 1;
            assert!(*flight <= ring,
                "{flight} segments in flight do not fit the {TCP_BUF_SIZE}-byte send ring");
        }
    };
    let mut flight = 0usize;
    let mut una = ours;
    assert_eq!(offer(&mut flight), 2, "precondition: the initial window is two segments");
    loop {
        una = una.wrapping_add(SEG as u32);
        flight -= 1;
        deliver(&seg(45191, 7991, theirs, una, ACK, u16::MAX, &[], &[]));
        if offer(&mut flight) != 2 {
            break;
        }
    }
    println!("[tcp-size] slow start ended with {flight} x {SEG} B in flight, send ring {TCP_BUF_SIZE} B");
    assert!(
        (flight + 1) * SEG > TCP_BUF_SIZE,
        "slow start ended with {flight} segments ({} B) in flight, below the {TCP_BUF_SIZE}-byte \
         send ring: the initial ssthresh is not the configured ring size",
        flight * SEG,
    );
}

/// The options walk keeps the MSS answers the boot conformance block asserts
/// (kernel/src/main.rs), and does not stop at the MSS: options after it must
/// still be read, and a truncated Window Scale must not switch scaling on.
#[test]
fn the_option_walk_keeps_its_mss_answers_and_reads_past_the_mss() {
    let _g = begin();
    assert!(tcp::listen(7896) >= 0);
    // (options, MSS we must record, Window Scale echoed, SACK-Permitted echoed)
    let cases: [(&[u8], u16, bool, bool); 6] = [
        (&[1, 250, 4, 0, 0, 2, 4, 0x04, 0xB0, 1, 1, 1], 1200, false, false),
        (&[1, 1, 1, 1], 536, false, false),
        (&[2, 4, 0, 0, 1, 1, 1, 1], 64, false, false),
        (&[2, 4, 0x04, 0xB0, 1, 3, 3, 7, 1, 1, 4, 2], 1200, true, true),
        (&[2, 4, 0x04, 0xB0, 1, 1, 3, 3], 1200, false, false),
        (&[1, 3, 3, 15, 2, 4, 0x05, 0xB4], 1460, true, false),
    ];
    for (i, &(opts, want_mss, ws, sack)) in cases.iter().enumerate() {
        wire::clear_sent();
        deliver(&seg(45200 + i as u16, 7896, 0x2000 + i as u32, 0, SYN, 4096, opts, &[]));
        let slot = slot_in(tcp::TcpState::SynRcvd).expect("the SYN must be accepted");
        let synack = last();
        assert_eq!(tcp::conn_remote_mss(slot), want_mss, "case {i}: {opts:?}");
        assert_eq!(option(&synack.opts, OPT_WSCALE).is_some(), ws, "case {i}: {opts:?}");
        assert_eq!(option(&synack.opts, OPT_SACK_PERM).is_some(), sack, "case {i}: {opts:?}");
        tcp::close(slot);
    }
}

/// A SYN-ACK retransmission repeats exactly the options of the first one. One
/// that dropped Window Scale would leave the peer scaling windows we read raw.
#[test]
fn a_syn_ack_retransmission_repeats_exactly_the_options_first_sent() {
    let _g = begin();
    assert!(tcp::listen(7895) >= 0);
    deliver(&seg(45095, 7895, 0x1300_0000, 0, SYN, 4096, &all_options(), &[]));
    deliver(&seg(45096, 7895, 0x1400_0000, 0, SYN, 4096, &mss(1460), &[]));
    wire::clear_sent();

    azos_drv_irqchip::clint::set_test_time(10_000 + 2 * azos_drv_sys::timebase::TIMER_FREQ);
    tcp::tcp_tick();

    let retries = sent();
    assert_eq!(retries.len(), 2, "both half-open slots must retransmit, got {retries:?}");
    let offered = retries.iter().find(|s| s.ack == 0x1300_0001).expect("SYN-ACK to 45095");
    let bare = retries.iter().find(|s| s.ack == 0x1400_0001).expect("SYN-ACK to 45096");
    assert_eq!(option(&offered.opts, OPT_WSCALE), Some(vec![OUR_WSCALE]),
        "the retransmission to the peer that offered Window Scale must still echo it");
    assert!(option(&offered.opts, OPT_SACK_PERM).is_some(),
        "and SACK-Permitted");
    assert_eq!(option(&bare.opts, OPT_WSCALE), None,
        "the retransmission to the peer that offered nothing must still offer nothing");
    assert_eq!(option(&bare.opts, OPT_SACK_PERM), None);
}

// ── Windows we read ──────────────────────────────────────────────────────────

/// The third leg of a passive open is the first segment without SYN, so its
/// window is scaled: window 10 at shift 7 is 1280 bytes.
#[test]
fn the_window_on_the_third_leg_is_scaled() {
    let _g = begin();
    let (idx, _ours, _theirs, _) = establish_with(7830, 45030, 0x0300_0000, &all_options(), 10);
    assert_eq!(
        tcp::send_data(idx, &[0x42; 100]), 100,
        "window 10 << {PEER_WSCALE} is 1280 bytes; reading it raw allows only 10",
    );
}

/// Every ACK after the handshake is scaled the same way.
#[test]
fn every_window_read_after_the_handshake_is_scaled() {
    let _g = begin();
    let (idx, ours, theirs, _) = establish_with(7831, 45031, 0x0310_0000, &all_options(), 4096);
    deliver(&seg(45031, 7831, theirs, ours, ACK, 1, &[], &[]));
    assert_eq!(
        tcp::send_data(idx, &[0x42; 1000]), 1 << PEER_WSCALE,
        "window 1 << {PEER_WSCALE} bounds the segment at {} bytes", 1u32 << PEER_WSCALE,
    );
}

/// The window of a SYN-ACK is read raw even though the same segment agrees to
/// a shift (RFC 7323 §2.2): 100 means 100.
#[test]
fn a_syn_ack_window_is_read_unscaled_even_when_it_agrees_to_a_shift() {
    let _g = begin();
    let (idx, _ours, _theirs) = open_active(45020, 7820, 0x0500_0000, &all_options(), 100);
    assert_eq!(
        tcp::send_data(idx, &[0x42; 1000]), 100,
        "the SYN-ACK advertised 100 bytes; scaling it would overrun the peer",
    );
}

// ── Windows we write ─────────────────────────────────────────────────────────

/// With scaling on, the field is the free space shifted and rounded DOWN:
/// 120831 free is 60415, and rounding up to 60416 would promise a byte the
/// ring does not have.
#[test]
fn the_advertised_window_is_the_free_space_shifted_and_rounded_down() {
    let _g = begin();
    let (_idx, ours, theirs, _) = establish_with(7840, 45040, 0x0400_0000, &all_options(), 4096);
    fill(7840, 45040, ours, theirs, BUFFERED);
    assert_eq!(
        last().window, scaled_window(BUFFERED),
        "{BUFFERED} bytes unread must advertise (free >> {OUR_WSCALE})",
    );
}

/// A passive open whose SYN did not offer Window Scale scales nothing, in
/// either direction, even though we could have.
#[test]
fn a_passive_open_without_window_scale_in_the_syn_scales_nothing() {
    let _g = begin();
    let (idx, ours, theirs, _) =
        establish_with(7841, 45041, 0x0410_0000, &[mss(1460), SACK_PERM].concat(), 10);
    assert_eq!(tcp::send_data(idx, &[0x42; 100]), 10, "the peer's window is read raw");
    fill(7841, 45041, ours, theirs, BUFFERED);
    assert_eq!(
        last().window, raw_window(BUFFERED),
        "our window must be written raw: the peer will not shift it, so \
         (free >> {OUR_WSCALE}) would under-report by half",
    );
}

/// An active open whose SYN-ACK does not carry Window Scale scales nothing,
/// though our SYN offered it; one whose SYN-ACK does, scales.
#[test]
fn an_active_open_scales_only_if_the_syn_ack_carries_window_scale() {
    let _g = begin();
    let (_idx, ours, theirs) = open_active(45021, 7821, 0x0510_0000, &mss(1460), 4096);
    fill(45021, 7821, ours, theirs, BUFFERED);
    assert_eq!(last().window, raw_window(BUFFERED),
        "our SYN offering a shift is not an agreement; the SYN-ACK did not carry one");

    let (_idx, ours, theirs) = open_active(45022, 7822, 0x0520_0000, &all_options(), 4096);
    fill(45022, 7822, ours, theirs, BUFFERED);
    assert_eq!(last().window, scaled_window(BUFFERED),
        "a SYN-ACK carrying Window Scale turns scaling on for the active side too");
}

/// Every control segment a connection sends carries the scaled live window,
/// not the 65535 constant: unshifted by the peer, the constant promises the
/// whole ring on every duplicate ACK, keep-alive and FIN acknowledgement.
#[test]
fn control_segments_after_the_handshake_carry_the_scaled_window() {
    let _g = begin();
    let (idx, ours, theirs, _) = establish_with(7850, 45050, 0x0800_0000, &all_options(), 4096);
    let theirs = fill(7850, 45050, ours, theirs, BUFFERED);
    let want = scaled_window(BUFFERED);

    wire::clear_sent();
    deliver(&seg(45050, 7850, theirs.wrapping_add(100), ours, PSH | ACK, 4096, &[], b"gap!"));
    assert_eq!(last().window, want, "the duplicate ACK for an out-of-order segment");

    wire::clear_sent();
    azos_drv_irqchip::clint::set_test_time(10_000 + 31 * azos_drv_sys::timebase::TIMER_FREQ);
    tcp::tcp_tick();
    let probe = last();
    assert_eq!(probe.seq, ours.wrapping_sub(1), "precondition: that was the keep-alive probe");
    assert_eq!(probe.window, want, "the keep-alive probe");

    wire::clear_sent();
    deliver(&seg(45050, 7850, theirs, ours, FIN | ACK, 4096, &[], &[]));
    assert!(tcp::conn_state(idx) == tcp::TcpState::CloseWait,
        "precondition: the FIN was consumed, got {}", st(tcp::conn_state(idx)));
    assert_eq!(last().window, want, "the ACK of the peer's FIN");
}

// ── "In window" under scaling ────────────────────────────────────────────────

/// A scaled connection offers the whole ring, so a segment 70 000 bytes ahead,
/// past any unscaled window, is in its window and must be held.
///
/// Needs a scaled window above 70 004 B, which only a ring of 128 KiB or more
/// has: at 64 KiB or less the shift is 0 and the scaled window is the unscaled
/// one. Below that the test prints why it did not run (`cargo test --
/// --nocapture` shows the line) and returns. The unscaled half of the property
/// holds at every size and is the next test.
#[test]
fn data_past_the_unscaled_window_is_held_on_a_scaled_connection() {
    const FAR: u32 = 70_000;
    const WINDOW: u32 = SCALED_WND;
    if !(FAR > u16::MAX as u32 && FAR + 4 < WINDOW) {
        println!(
            "[skip] tcp_options::data_past_the_unscaled_window_is_held_on_a_scaled_connection: \
             needs a scaled window above {} B; this build's is {WINDOW} B \
             (TCP_BUF_SIZE {TCP_BUF_SIZE} B, shift {OUR_WSCALE})",
            FAR + 4,
        );
        return;
    }
    let _g = begin();

    let (_idx, ours, theirs, _) = establish_with(7860, 45060, 0x0900_0000, &all_options(), 4096);
    deliver(&seg(45060, 7860, theirs.wrapping_add(FAR), ours, PSH | ACK, 4096, &[], b"FAR!"));
    fill(7860, 45060, ours, theirs, FAR as usize);
    assert_eq!(
        last().ack, theirs.wrapping_add(FAR + 4),
        "the segment at +{FAR} was inside the scaled window and must have been held",
    );
}

/// An unscaled connection offers `EMPTY_WINDOW` bytes, 65535 at the 128 KiB
/// ring and 16383 at 16 KiB, whatever its ring holds: a segment whose first
/// byte is one past that window is dropped, and one whose last byte is the
/// window's last is held. The blind-injection cost of a peer that negotiated
/// nothing does not move.
///
/// Both segments arrive on an empty ring, and the bytes before them are read
/// as they arrive (`fill_draining`), so the ring never holds more than one
/// segment: when the held one is delivered and RCV.NXT reaches the window's
/// edge, the dropped one would have been delivered right after it had it been
/// held. The final ACK tells the two apart at every ring size.
#[test]
fn data_past_the_unscaled_window_is_dropped_on_an_unscaled_connection() {
    let _g = begin();
    let edge = EMPTY_WINDOW as u32;
    let (idx, ours, theirs) = establish(7861, 45061, 0x0A00_0000);

    deliver(&segment(45061, 7861, theirs.wrapping_add(edge - 4), ours, PSH | ACK, 4096, b"LAST"));
    let held = last();
    assert_eq!(
        (held.ack, held.window), (theirs, EMPTY_WINDOW),
        "precondition: a duplicate ACK for the held segment, with the ring empty",
    );
    deliver(&segment(45061, 7861, theirs.wrapping_add(edge), ours, PSH | ACK, 4096, b"FAR!"));

    fill_draining(idx, 7861, 45061, ours, theirs, (edge - 4) as usize);
    assert_eq!(
        last().ack, theirs.wrapping_add(edge),
        "RCV.NXT must stop at the edge of the {edge}-byte unscaled window: the segment \
         ending there was held, the one starting there must have been dropped",
    );
}

/// RFC 5961 §3.2 under scaling: a reset must hit RCV.NXT exactly, however
/// large the window. Resets just past the unscaled window, at the scaled edge
/// and just beyond it change nothing; the exact one still closes.
#[test]
fn a_reset_at_the_edge_of_a_scaled_window_does_not_close_the_connection() {
    let _g = begin();
    let (idx, _ours, theirs, _) = establish_with(7870, 45070, 0x0B00_0000, &all_options(), 4096);
    for off in [u16::MAX as u32, u16::MAX as u32 + 1, SCALED_WND - 1, SCALED_WND, SCALED_WND + 1] {
        deliver(&seg(45070, 7870, theirs.wrapping_add(off), 0, RST, 0, &[], &[]));
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::Established,
            "a RST at RCV.NXT+{off} (scaled window {SCALED_WND}) tore the connection down, got {}",
            st(tcp::conn_state(idx)),
        );
    }
    deliver(&seg(45070, 7870, theirs, 0, RST, 0, &[], &[]));
    assert!(tcp::conn_state(idx) == tcp::TcpState::Closed,
        "a RST at exactly RCV.NXT must still close, got {}", st(tcp::conn_state(idx)));
}

// ── SACK ─────────────────────────────────────────────────────────────────────

/// Each held segment is reported, the newest block first (RFC 2018 §4), and
/// the ACK that fills one hole still reports what lies past the next.
#[test]
fn sack_blocks_name_what_is_held_with_the_newest_first() {
    let _g = begin();
    let (_idx, ours, t, _) = establish_with(7880, 45080, 0x0C00_0000, &all_options(), 4096);
    let at = |o: u32| t.wrapping_add(o);

    deliver(&seg(45080, 7880, at(10), ours, PSH | ACK, 4096, &[], b"AAAA"));
    let first = last();
    assert_eq!(first.ack, t, "the hole is not acknowledged");
    assert_eq!(sack_blocks(&first), vec![(at(10), at(14))]);

    deliver(&seg(45080, 7880, at(30), ours, PSH | ACK, 4096, &[], b"CCCC"));
    assert_eq!(
        sack_blocks(&last()), vec![(at(30), at(34)), (at(10), at(14))],
        "the block holding the newest arrival goes first",
    );

    deliver(&seg(45080, 7880, at(0), ours, PSH | ACK, 4096, &[], &[b'.'; 10]));
    let filled = last();
    assert_eq!(filled.ack, at(14), "filling the first hole releases the segment behind it");
    assert_eq!(sack_blocks(&filled), vec![(at(30), at(34))],
        "the in-order ACK still reports the segment past the remaining hole");
}

/// Adjacent held segments are one block, not two.
#[test]
fn adjacent_held_segments_are_reported_as_one_block() {
    let _g = begin();
    let (_idx, ours, t, _) = establish_with(7881, 45081, 0x0D00_0000, &all_options(), 4096);
    deliver(&seg(45081, 7881, t.wrapping_add(10), ours, PSH | ACK, 4096, &[], b"AAAA"));
    deliver(&seg(45081, 7881, t.wrapping_add(14), ours, PSH | ACK, 4096, &[], b"BBBB"));
    assert_eq!(sack_blocks(&last()), vec![(t.wrapping_add(10), t.wrapping_add(18))]);
}

/// A held segment is truncated to one slot, and its block must say so: SACKing
/// the truncated tail tells the sender bytes we dropped are safe with us.
#[test]
fn a_sack_block_covers_the_bytes_stored_not_the_bytes_received() {
    let _g = begin();
    let (_idx, ours, t, _) = establish_with(7882, 45082, 0x0E00_0000, &all_options(), 4096);
    // More than one slot, or nothing is truncated and the block proves nothing.
    deliver(&seg(45082, 7882, t.wrapping_add(4), ours, PSH | ACK, 4096, &[], &[0x77; 2000]));
    assert_eq!(
        sack_blocks(&last()), vec![(t.wrapping_add(4), t.wrapping_add(4 + OOO_SEGMENT_MAX_LEN))],
        "2000 bytes arrived, {OOO_SEGMENT_MAX_LEN} were kept",
    );
}

/// A block once sent is never withdrawn while its bytes are above the
/// cumulative ACK (no reneging, RFC 2018 §8). With four segments held, arrivals
/// that do not fit (beyond every held segment, before them, across one) are
/// dropped, and the ACK answering each still names exactly the four held
/// segments. Asserted on the wire, where the sender reads it.
#[test]
fn a_full_queue_never_withdraws_a_reported_sack_block() {
    let _g = begin();
    let (_idx, ours, t, _) = establish_with(7884, 45084, 0x1000_0000, &all_options(), 4096);
    let at = |o: u32| t.wrapping_add(o);
    for off in [100u32, 400, 800, 1200] {
        deliver(&seg(45084, 7884, at(off), ours, PSH | ACK, 4096, &[], b"HELD"));
    }
    let mut held = sack_blocks(&last());
    held.sort();
    assert_eq!(
        held, vec![(at(100), at(104)), (at(400), at(404)), (at(800), at(804)), (at(1200), at(1204))],
        "precondition: the four held segments are all reported",
    );
    for (off, body) in [(5000u32, &b"late"[..]), (10, &b"near"[..]), (398, &b"overlaps"[..])] {
        deliver(&seg(45084, 7884, at(off), ours, PSH | ACK, 4096, &[], body));
        let dup = last();
        assert_eq!(dup.ack, t, "precondition: that was the duplicate ACK");
        let mut blocks = sack_blocks(&dup);
        blocks.sort();
        assert_eq!(
            blocks, held,
            "after an arrival at +{off} that did not fit, the SACK blocks no longer name the four held segments",
        );
    }
}

/// No SACK-Permitted in the SYN, no SACK option on any ACK.
#[test]
fn no_sack_option_without_sack_permitted_in_the_syn() {
    let _g = begin();
    let (_idx, ours, t, _) =
        establish_with(7883, 45083, 0x0F00_0000, &[mss(1460), WSCALE].concat(), 4096);
    deliver(&seg(45083, 7883, t.wrapping_add(10), ours, PSH | ACK, 4096, &[], b"AAAA"));
    let dup = last();
    assert_eq!(dup.ack, t, "precondition: that was the duplicate ACK");
    assert!(dup.opts.is_empty(), "an ACK carried options {:?} the peer never permitted", dup.opts);
}

/// A held segment the ring could only partly absorb is left AT RCV.NXT, and a
/// block there would sit on the cumulative ACK — never reported. After a drain
/// its remainder is taken up in order and nothing is lost.
#[test]
fn a_held_remainder_at_rcv_nxt_is_never_reported_as_sacked() {
    let _g = begin();
    let (idx, ours, t, _) = establish_with(7884, 45084, 0x1000_0000, &all_options(), 4096);
    // The ring holds TCP_BUF_SIZE - 1 bytes; leave six free.
    let base = fill(7884, 45084, ours, t, TCP_BUF_SIZE - 1 - 6);

    deliver(&seg(45084, 7884, base.wrapping_add(4), ours, PSH | ACK, 4096, &[], b"WXYZ"));
    assert_eq!(sack_blocks(&last()), vec![(base.wrapping_add(4), base.wrapping_add(8))],
        "precondition: the segment is held and reported");

    deliver(&seg(45084, 7884, base, ours, PSH | ACK, 4096, &[], b"abcd"));
    let full = last();
    assert_eq!(full.ack, base.wrapping_add(6), "four in order plus the two held bytes that fit");
    assert_eq!(full.window, 0, "precondition: the ring is full");
    assert!(sack_blocks(&full).is_empty(),
        "the unabsorbed 'YZ' sits at RCV.NXT; reported {:?}", sack_blocks(&full));

    let mut buf = [0u8; 4096];
    let mut tail = Vec::new();
    loop {
        let n = tcp::recv(idx, &mut buf);
        if n <= 0 { break; }
        tail.extend_from_slice(&buf[..n as usize]);
    }
    assert_eq!(&tail[tail.len() - 6..], b"abcdWX");

    deliver(&seg(45084, 7884, base.wrapping_add(6), ours, PSH | ACK, 4096, &[], b"YZ"));
    let after = last();
    assert_eq!(after.ack, base.wrapping_add(8));
    assert!(sack_blocks(&after).is_empty(), "nothing is held any more");
    let n = tcp::recv(idx, &mut buf);
    assert_eq!(&buf[..n.max(0) as usize], b"YZ");
}

/// A retransmission routinely covers the front of a segment already held. The
/// held tail must still be delivered — matching only a segment that starts
/// exactly at RCV.NXT stranded it below RCV.NXT for good.
#[test]
fn a_retransmission_overlapping_a_held_segment_releases_its_tail() {
    let _g = begin();
    let (idx, ours, t) = establish(7885, 45085, 0x1100_0000);
    deliver(&segment(45085, 7885, t.wrapping_add(4), ours, PSH | ACK, 4096, b"456789AB"));
    deliver(&segment(45085, 7885, t, ours, PSH | ACK, 4096, b"01234567"));
    assert_eq!(outbound().last().unwrap().ack, t.wrapping_add(12),
        "the held tail 89AB is contiguous once 0..8 arrived");
    let mut buf = [0u8; 32];
    let n = tcp::recv(idx, &mut buf);
    assert_eq!(&buf[..n.max(0) as usize], b"0123456789AB");
}

/// A slot freed by a reset and reused must not carry the old connection's held
/// segments: a flush would splice one peer's bytes into another's stream, and
/// a SACK block would report them as received.
#[test]
fn a_reused_slot_does_not_inherit_the_previous_connections_held_segments() {
    let _g = begin();
    let (idx, ours, t, _) = establish_with(7897, 45097, 0x1500_0000, &all_options(), 4096);
    deliver(&seg(45097, 7897, t.wrapping_add(10), ours, PSH | ACK, 4096, &[], b"OLD!"));
    assert_eq!(sack_blocks(&last()).len(), 1, "precondition: the segment is held");
    deliver(&seg(45097, 7897, t, 0, RST, 0, &[], &[]));
    assert!(tcp::conn_state(idx) == tcp::TcpState::Closed, "precondition: reset");

    // Same listener, another peer port, the same ISN: RCV.NXT lands exactly
    // where the old connection's was.
    let (idx2, ours2, t2, _) = handshake(7897, 45098, 0x1500_0000, &all_options(), 4096);
    assert_eq!(idx2, idx, "precondition: the freed slot is the one reused");
    assert_eq!(t2, t);

    deliver(&seg(45098, 7897, t, ours2, PSH | ACK, 4096, &[], b"0123456789"));
    let a = last();
    assert_eq!(a.ack, t.wrapping_add(10), "the old connection's bytes at +10 were spliced in");
    assert!(sack_blocks(&a).is_empty(), "reported {:?} from the previous connection", sack_blocks(&a));
    let mut buf = [0u8; 32];
    assert_eq!(tcp::recv(idx2, &mut buf), 10);
}

// ── MSS ──────────────────────────────────────────────────────────────────────

/// The peer's MSS bounds every segment we send.
#[test]
fn the_peers_mss_bounds_the_segments_we_send() {
    let _g = begin();
    let (idx, _ours, _theirs, _) = establish_with(7890, 45090, 0x1200_0000, &mss(1200), 4096);
    assert_eq!(tcp::send_data(idx, &[0x33; 2000]), 1200, "the peer asked for 1200-byte segments");
    assert_eq!(last().payload_len, 1200);
}
