// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The send side: several segments in flight under a congestion window that
//! governs them, loss recovery that decides what is resent, and the RFC 793
//! replies around a connection — resets for acknowledgements of nothing we
//! sent, ACKs for segments outside the window, TIME-WAIT reuse, simultaneous
//! open.
//!
//! **The peer is a script.** It decides what to acknowledge, what was lost and
//! what to SACK; every segment still goes in through `handle_checked` and out
//! through the real `ip.rs`, as in `tcp_rx`.
//!
//! **The arithmetic.** Each SYN here advertises an MSS (1000 unless a test
//! says otherwise) and the peer's window is 65535 unscaled, so `cwnd` is the
//! only bound on what is in flight and a window is a count of 1000-byte
//! segments. The constants restated below are private to `tcp.rs`; restating
//! them is deliberate — if one moves, a count here fails and someone looks at
//! the congestion control rather than at the test.

use super::tcp_rx::{begin, deliver, slot_in, st, OUR_IP, PEER_IP};
use super::{tcp, wire};
use azos_limits::TCP_BUF_SIZE;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

const TICKS_PER_MS: u64 = 10_000;
/// `RTO_INITIAL_MS`: nothing has been timed on a fresh connection.
const RTO_INITIAL: u64 = 1_000 * TICKS_PER_MS;
/// `RTO_VAR_FLOOR_MS`: the least the variance term adds to SRTT.
const VAR_FLOOR: u64 = 200 * TICKS_PER_MS;
/// `INVALID_ACK_INTERVAL_MS`.
const INVALID_ACK_INTERVAL: u64 = 500 * TICKS_PER_MS;
/// The clock `begin()` sets.
const T0: u64 = 10_000;

/// Segment size in these tests, advertised as the peer's MSS.
const SEG: usize = 1000;
const WIN: u16 = 65535;

/// This build's send ring, `TCP_SND_BUF_SIZE` = `TCP_BUF_SIZE` in `tcp.rs`. It
/// bounds what is in flight twice: `send_data` never lets the flight pass it,
/// and `grow_cwnd` never lets `cwnd` pass it.
const SEND_RING: usize = TCP_BUF_SIZE;

/// Whether the send ring holds `needed` bytes: the flight a test builds and the
/// segment it then offers. The arithmetic above takes `cwnd` as the only bound
/// on what is in flight, which holds only while the ring is larger. Below that,
/// a refusal the test reads as `cwnd`'s or a recovery rule's is the ring's, and
/// the test has nothing to say at this size: it prints why it did not run
/// (`cargo test -- --nocapture` shows the line) and returns.
fn send_ring_holds(test: &str, needed: usize, flight: &str) -> bool {
    if SEND_RING >= needed {
        return true;
    }
    println!(
        "[skip] tcp_sender::{test}: needs a send ring of at least {needed} B ({flight}), \
         so that cwnd and not the ring bounds the flight; this build's is {SEND_RING} B",
    );
    false
}

/// `tcp_rx::segment`, with options.
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
    s.extend_from_slice(&[0, 0, 0, 0]);
    s.extend_from_slice(opts);
    s.extend_from_slice(payload);
    let pseudo = wire::pseudo_checksum(&PEER_IP, &OUR_IP, wire::IP_PROTO_TCP, s.len() as u16);
    let ck = tcp::tcp_checksum(pseudo, &s);
    s[16..18].copy_from_slice(&ck.to_be_bytes());
    s
}

/// A segment the stack put on the wire, payload bytes included.
#[derive(Debug, Clone)]
struct Out {
    seq: u32,
    ack: u32,
    flags: u8,
    payload: Vec<u8>,
}

fn sent() -> Vec<Out> {
    wire::sent()
        .iter()
        .filter(|s| s.proto == wire::IP_PROTO_TCP)
        .map(|s| {
            let p = &s.payload;
            let off = ((p[12] >> 4) as usize) * 4;
            Out {
                seq: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
                ack: u32::from_be_bytes([p[8], p[9], p[10], p[11]]),
                flags: p[13],
                payload: p[off..].to_vec(),
            }
        })
        .collect()
}

/// Only the segments that carried data.
fn data_sent() -> Vec<Out> {
    sent().into_iter().filter(|o| !o.payload.is_empty()).collect()
}

fn mss(v: u16) -> [u8; 4] {
    let b = v.to_be_bytes();
    [2, 4, b[0], b[1]]
}

const SACK_PERM: [u8; 4] = [1, 1, 4, 2];

/// The stream every test sends: byte `i` is `i % 251`, so a byte resent from
/// the wrong place in the ring cannot pass for the right one.
fn pattern(off: usize, n: usize) -> Vec<u8> {
    (off..off + n).map(|i| (i % 251) as u8).collect()
}

/// Passive open on `port` whose SYN advertises `mss_v` and, with `sack`,
/// SACK-Permitted. Returns (idx, our SND.NXT, the peer's next sequence).
fn open(port: u16, peer_port: u16, peer_isn: u32, mss_v: u16, sack: bool) -> (usize, u32, u32) {
    assert!(tcp::listen(port) >= 0, "no free connection slot for the listener");
    let mut opts = mss(mss_v).to_vec();
    if sack {
        opts.extend_from_slice(&SACK_PERM);
    }
    wire::clear_sent();
    deliver(&seg(peer_port, port, peer_isn, 0, SYN, WIN, &opts, &[]));
    let synack = sent().pop().expect("a SYN to a listening port must be answered");
    assert_eq!(synack.flags, SYN | ACK, "expected a SYN-ACK");
    let idx = slot_in(tcp::TcpState::SynRcvd).expect("the SYN must open a half-open slot");
    let ours = synack.seq.wrapping_add(1);
    let theirs = peer_isn.wrapping_add(1);
    deliver(&seg(peer_port, port, theirs, ours, ACK, WIN, &[], &[]));
    assert!(
        tcp::conn_state(idx) == tcp::TcpState::Established,
        "the third leg must establish it, got {}", st(tcp::conn_state(idx)),
    );
    wire::clear_sent();
    (idx, ours, theirs)
}

/// The application side of a bulk sender: offers whole segments of
/// `pattern` until `send_data` refuses one.
struct Stream {
    idx: usize,
    next: usize,
}

impl Stream {
    fn new(idx: usize) -> Self {
        Stream { idx, next: 0 }
    }

    /// Segments `send_data` took before it answered 0.
    fn fill(&mut self) -> usize {
        let mut k = 0;
        loop {
            let n = tcp::send_data(self.idx, &pattern(self.next, SEG));
            assert!(n >= 0, "send_data failed on an established connection: {n}");
            if n == 0 {
                return k;
            }
            assert_eq!(n as usize, SEG, "a whole segment, or nothing");
            self.next += SEG;
            k += 1;
            assert!(k <= 200, "the window never closed");
        }
    }
}

/// The peer's bare ACK: cumulative `ack`, `window`, and SACK `blocks` in the
/// order given.
fn peer_ack(port: u16, peer_port: u16, theirs: u32, ack: u32, window: u16, blocks: &[(u32, u32)]) {
    let mut opts = Vec::new();
    if !blocks.is_empty() {
        opts.extend_from_slice(&[1, 1, 5, 2 + 8 * blocks.len() as u8]);
        for &(l, r) in blocks {
            opts.extend_from_slice(&l.to_be_bytes());
            opts.extend_from_slice(&r.to_be_bytes());
        }
    }
    deliver(&seg(peer_port, port, theirs, ack, ACK, window, &opts, &[]));
}

/// Passive open, then slow start one acknowledged segment at a time until `n`
/// 1000-byte segments are in flight: each ACK of one segment opens the window
/// by one and releases two. Returns (the stream, SND.UNA, the peer's next
/// sequence); the stream offset at SND.UNA is `stream.next - n * SEG`.
fn in_flight(
    port: u16, peer_port: u16, peer_isn: u32, mss_v: u16, sack: bool, n: usize,
) -> (Stream, u32, u32) {
    assert!(n >= 2);
    let (idx, ours, theirs) = open(port, peer_port, peer_isn, mss_v, sack);
    let mut s = Stream::new(idx);
    assert_eq!(s.fill(), 2, "precondition: the initial window");
    let mut una = ours;
    for _ in 2..n {
        una = una.wrapping_add(SEG as u32);
        peer_ack(port, peer_port, theirs, una, WIN, &[]);
        assert_eq!(s.fill(), 2, "precondition: slow start");
    }
    assert_eq!(tcp::send_data(idx, &pattern(s.next, SEG)), 0, "precondition: {n} in flight");
    wire::clear_sent();
    (s, una, theirs)
}

/// Three segments in flight, the first one acknowledged before them: the
/// state every duplicate-ACK test starts from. Returns (idx, SND.UNA, peer's
/// next sequence). SND.UNA sits at stream offset 1000.
fn three_in_flight(port: u16, peer_port: u16, peer_isn: u32) -> (usize, u32, u32) {
    let (idx, ours, theirs) = open(port, peer_port, peer_isn, SEG as u16, false);
    let mut s = Stream::new(idx);
    assert_eq!(s.fill(), 2, "precondition: the initial window");
    let una = ours.wrapping_add(SEG as u32);
    peer_ack(port, peer_port, theirs, una, WIN, &[]);
    assert_eq!(s.fill(), 2, "precondition: slow start");
    wire::clear_sent();
    (idx, una, theirs)
}

// ── The send window ─────────────────────────────────────────────────────────

/// A second segment leaves while the first is unacknowledged. The window
/// starts at two of our 1460-byte segments, 2920 bytes: two 1000-byte
/// segments fit and a third does not.
#[test]
fn several_segments_are_in_flight_before_the_first_is_acknowledged() {
    let _g = begin();
    let (idx, ours, _theirs) = open(7900, 46000, 0x2000_0000, SEG as u16, false);
    let mut s = Stream::new(idx);

    assert_eq!(s.fill(), 2, "cwnd 2920 admits two 1000-byte segments before any ACK");
    let out = data_sent();
    assert_eq!(out.len(), 2, "both must be on the wire, not only counted");
    assert_eq!(out[0].seq, ours);
    assert_eq!(out[1].seq, ours.wrapping_add(SEG as u32), "the second follows the first");
    assert_eq!(out[1].payload, pattern(SEG, SEG));
    assert!(tcp::is_unacked(idx));
}

/// Slow start: every segment acknowledged opens the window by one, so each
/// ACK of one segment releases two.
#[test]
fn slow_start_releases_two_segments_for_each_one_acknowledged() {
    let _g = begin();
    let (idx, ours, theirs) = open(7901, 46001, 0x2100_0000, SEG as u16, false);
    let mut s = Stream::new(idx);
    assert_eq!(s.fill(), 2);
    for round in 1..=4u32 {
        peer_ack(7901, 46001, theirs, ours.wrapping_add(round * SEG as u32), WIN, &[]);
        assert_eq!(s.fill(), 2, "round {round}: one segment acknowledged, cwnd += 1000");
    }
}

/// Congestion avoidance: above ssthresh the window grows by SMSS*SMSS/cwnd
/// per ACK (RFC 5681 eq. 3), about one segment per window.
///
/// A timeout with 2000 bytes in flight sets ssthresh to max(2000/2, 2*1000) =
/// 2000 and cwnd to 1000; the ACK of both segments brings cwnd back to 2000,
/// which is ssthresh. From there, one segment acknowledged per round:
///
/// | round | cwnd                     | in flight | fits |
/// |-------|--------------------------|-----------|------|
/// | 0     | 2000 + 1e6/2000 = 2500   | 1000      | 1    |
/// | 1     | 2500 + 1e6/2500 = 2900   | 1000      | 1    |
/// | 2     | 2900 + 1e6/2900 = 3244   | 1000      | 2    |
/// | 3     | 3244 + 1e6/3244 = 3552   | 2000      | 1    |
///
/// Slow start would release two every round.
#[test]
fn congestion_avoidance_grows_by_about_one_segment_per_window() {
    let _g = begin();
    let (idx, ours, theirs) = open(7902, 46002, 0x2200_0000, SEG as u16, false);
    let mut s = Stream::new(idx);
    assert_eq!(s.fill(), 2);

    azos_drv_irqchip::clint::set_test_time(T0 + RTO_INITIAL);
    tcp::tcp_tick();
    peer_ack(7902, 46002, theirs, ours.wrapping_add(2 * SEG as u32), WIN, &[]);
    assert_eq!(s.fill(), 2, "precondition: cwnd is back at ssthresh, 2000");

    let mut counts = Vec::new();
    for round in 3..=6u32 {
        peer_ack(7902, 46002, theirs, ours.wrapping_add(round * SEG as u32), WIN, &[]);
        counts.push(s.fill());
    }
    assert_eq!(counts, vec![1, 1, 2, 1], "above ssthresh the window must grow by SMSS*SMSS/cwnd");
}

/// A timeout resends one segment from SND.UNA and collapses the window to
/// one segment (RFC 5681 §3.1): nothing new goes out until the loss is
/// repaired, and the window then regrows from one.
#[test]
fn a_timeout_resends_one_segment_and_collapses_the_window() {
    let _g = begin();
    let (idx, ours, theirs) = open(7903, 46003, 0x2300_0000, SEG as u16, false);
    let mut s = Stream::new(idx);
    assert_eq!(s.fill(), 2);
    wire::clear_sent();

    azos_drv_irqchip::clint::set_test_time(T0 + RTO_INITIAL);
    tcp::tcp_tick();
    let out = data_sent();
    assert_eq!(out.len(), 1, "a timeout resends one segment, got {}", out.len());
    assert_eq!(out[0].seq, ours, "from SND.UNA");
    assert_eq!(out[0].payload, pattern(0, SEG));
    assert_eq!(tcp::send_data(idx, &pattern(2 * SEG, SEG)), 0,
        "2000 bytes in flight against a one-segment window");

    // The peer had the second segment: one ACK covers both. In slow start
    // from 1000 that makes 2000, room for two.
    peer_ack(7903, 46003, theirs, ours.wrapping_add(2 * SEG as u32), WIN, &[]);
    assert_eq!(s.fill(), 2, "the window must regrow from one segment, not resume at 2920");
}

// ── Duplicate ACKs and fast retransmit ──────────────────────────────────────

/// The third duplicate ACK resends the first unacknowledged segment, once.
#[test]
fn the_third_duplicate_ack_resends_the_first_unacknowledged_segment() {
    let _g = begin();
    let (_idx, una, theirs) = three_in_flight(7904, 46004, 0x2400_0000);

    peer_ack(7904, 46004, theirs, una, WIN, &[]);
    peer_ack(7904, 46004, theirs, una, WIN, &[]);
    assert!(data_sent().is_empty(), "two duplicates are not a loss");

    peer_ack(7904, 46004, theirs, una, WIN, &[]);
    let out = data_sent();
    assert_eq!(out.len(), 1, "the third duplicate must resend exactly one segment");
    assert_eq!(out[0].seq, una);
    assert_eq!(out[0].payload, pattern(SEG, SEG), "the bytes at SND.UNA, from the ring");
}

/// An ACK that repeats SND.UNA with a different window is a window update, not
/// a duplicate (RFC 5681 §2). A peer draining its buffer sends exactly these.
#[test]
fn window_updates_are_not_duplicate_acks() {
    let _g = begin();
    let (_idx, una, theirs) = three_in_flight(7905, 46005, 0x2500_0000);

    for w in [60_000u16, 50_000, 40_000, 30_000] {
        peer_ack(7905, 46005, theirs, una, w, &[]);
    }
    assert!(data_sent().is_empty(),
        "four window updates were counted as duplicates and resent a segment nobody lost");

    // Positive control: the same ACK three times with an unchanged window is a loss.
    for _ in 0..3 {
        peer_ack(7905, 46005, theirs, una, 30_000, &[]);
    }
    assert_eq!(data_sent().len(), 1, "three true duplicates must still resend");
}

/// An ACK that carries data is not a duplicate either: on a link that talks
/// both ways, a peer with nothing new to acknowledge still sends.
#[test]
fn acks_carrying_data_are_not_duplicate_acks() {
    let _g = begin();
    let (_idx, una, mut theirs) = three_in_flight(7906, 46006, 0x2600_0000);

    for _ in 0..4 {
        deliver(&seg(46006, 7906, theirs, una, PSH | ACK, WIN, &[], b"telemetry"));
        theirs = theirs.wrapping_add(9);
    }
    assert!(data_sent().is_empty(),
        "four data segments acknowledging nothing new were counted as duplicates");

    for _ in 0..3 {
        peer_ack(7906, 46006, theirs, una, WIN, &[]);
    }
    assert_eq!(data_sent().len(), 1, "three bare duplicates must still resend");
}

/// SACK (RFC 2018): a resend skips what the peer reported holding.
///
/// Six 1000-byte segments A..F are in flight; the peer lost A and C and SACKs
/// B, D, E and F, one ACK per arrival, as a receiver does. The MSS is 1460
/// here, so a resend that ignored the blocks would cut 1460 bytes from SND.UNA
/// and carry 460 of B.
///
/// Each ACK carries SACK information the previous one did not, which is what
/// makes it a duplicate under RFC 6675 §2. (This test used to repeat identical
/// blocks: duplicates under RFC 5681, not under RFC 6675, and with 2000 SACKed
/// bytes against 2 * 1460 `IsLost` never fires either — that sequence now
/// recovers by the timer, as RFC 6675 specifies.)
#[test]
fn a_resend_skips_the_ranges_the_peer_has_sacked() {
    let _g = begin();
    let (s, una, theirs) = in_flight(7907, 46007, 0x2700_0000, 1460, true, 6);
    let idx = s.idx;
    let off = s.next - 6 * SEG;
    let at = |k: u32| una.wrapping_add(k * 1000);
    let b = (at(1), at(2));
    peer_ack(7907, 46007, theirs, una, WIN, &[b]);
    peer_ack(7907, 46007, theirs, una, WIN, &[(at(3), at(4)), b]);
    assert!(data_sent().is_empty(), "two duplicates are not a loss");

    peer_ack(7907, 46007, theirs, una, WIN, &[(at(3), at(5)), b]);
    let out = data_sent();
    assert_eq!(out.len(), 1, "the third duplicate resends");
    assert_eq!((out[0].seq, out[0].payload.len()), (at(0), 1000),
        "A only: the resend must stop where the SACKed B begins");
    assert_eq!(out[0].payload, pattern(off, 1000));

    // D..F held: 3000 SACKed bytes above C prove it lost.
    peer_ack(7907, 46007, theirs, una, WIN, &[(at(3), at(6)), b]);
    let out = data_sent();
    assert_eq!(out.len(), 2, "C is lost and the window has room for it");
    assert_eq!((out[1].seq, out[1].payload.len()), (at(2), 1000), "C, stepping over B");
    assert_eq!(out[1].payload, pattern(off + 2000, 1000));

    peer_ack(7907, 46007, theirs, una, WIN, &[(at(3), at(6)), b]);
    assert_eq!(data_sent().len(), 2, "no hole is left below the highest SACKed byte");

    peer_ack(7907, 46007, theirs, at(6), WIN, &[]);
    assert!(!tcp::is_unacked(idx), "the whole flight is acknowledged");
}

// ── The retransmission timer (RFC 6298) ─────────────────────────────────────

/// An ACK of new data restarts the timer for what is still in flight (§5.3):
/// the second segment's clock starts when the first is acknowledged, not
/// when the first was sent.
///
/// Both leave at T0; the first is acknowledged 900 ms later. That ACK is also
/// the connection's first RTT sample, so RTO becomes SRTT + 4 * RTTVAR =
/// 900 + 4 * 450 = 2700 ms (§2.2). A timer still running from T0 expires at
/// T0 + 2700 ms; one restarted by the ACK, at T0 + 3600 ms.
#[test]
fn an_ack_of_new_data_restarts_the_retransmission_timer() {
    let _g = begin();
    let (idx, ours, theirs) = open(7909, 46009, 0x2900_0000, SEG as u16, false);
    let mut s = Stream::new(idx);
    assert_eq!(s.fill(), 2);

    let acked_at = T0 + 900 * TICKS_PER_MS;
    let rto = 2_700 * TICKS_PER_MS;
    azos_drv_irqchip::clint::set_test_time(acked_at);
    peer_ack(7909, 46009, theirs, ours.wrapping_add(SEG as u32), WIN, &[]);
    wire::clear_sent();

    azos_drv_irqchip::clint::set_test_time(T0 + rto);
    tcp::tcp_tick();
    assert!(data_sent().is_empty(), "the timer ran from the first send, not from the ACK");

    azos_drv_irqchip::clint::set_test_time(acked_at + rto);
    tcp::tcp_tick();
    let out = data_sent();
    assert_eq!(out.len(), 1, "one RTO after the ACK, the second segment must time out");
    assert_eq!(out[0].seq, ours.wrapping_add(SEG as u32));
}

/// Karn's algorithm: an ACK that follows a retransmission cannot say which
/// transmission it answers, so it gives no RTT sample, and the backed-off RTO
/// stays until a segment sent once is acknowledged.
///
/// Sent at T0, resent at T0 + 1 s (RTO doubles to 2 s), acknowledged 10 ms
/// later. Measuring from the first send would give 1010 ms and an RTO of
/// 1010 + 4 * 505 = 3030 ms. The next segment must time out at 2 s.
#[test]
fn an_ack_after_a_retransmission_gives_no_rtt_sample() {
    let _g = begin();
    let (idx, ours, theirs) = open(7910, 46010, 0x2A00_0000, SEG as u16, false);
    assert_eq!(tcp::send_data(idx, &pattern(0, SEG)), SEG as i32);
    azos_drv_irqchip::clint::set_test_time(T0 + RTO_INITIAL);
    tcp::tcp_tick();
    let t1 = T0 + RTO_INITIAL + 10 * TICKS_PER_MS;
    azos_drv_irqchip::clint::set_test_time(t1);
    peer_ack(7910, 46010, theirs, ours.wrapping_add(SEG as u32), WIN, &[]);
    assert!(!tcp::is_unacked(idx), "precondition: acknowledged");

    assert_eq!(tcp::send_data(idx, &pattern(SEG, SEG)), SEG as i32);
    wire::clear_sent();
    azos_drv_irqchip::clint::set_test_time(t1 + 2 * RTO_INITIAL);
    tcp::tcp_tick();
    assert_eq!(data_sent().len(), 1,
        "the RTO must still be the backed-off 2 s; a sample was taken from the retransmitted segment");
}

/// What a sample would change: whether one was taken, SRTT, RTTVAR and RTO.
fn estimate(idx: usize) -> (bool, u64, u64, u64) {
    let e = tcp::conn_rtt(idx).expect("a valid slot");
    (e.measured, e.srtt, e.rttvar, e.rto_ticks)
}

/// The sequence number just past the segment being timed, if one is.
fn timed(idx: usize) -> Option<u32> {
    tcp::conn_rtt(idx).expect("a valid slot").timed_seq
}

/// A sample of 0 ticks — the ACK arrives in the tick its segment left — is a
/// measurement: the next sample is averaged into it (RFC 6298 §2.3), not taken
/// as the first (§2.2).
///
/// S0 and its ACK at T0: SRTT 0, RTTVAR 0, RTO = 0 + max(4 * 0, 200 ms) =
/// 200 ms, the variance term's floor. S1 at T0, its ACK at T0 + 100 ms,
/// R = 100 ms: RTTVAR = 3/4 * 0 + 1/4 * 100 = 25 ms, SRTT = 7/8 * 0 + 1/8 *
/// 100 = 12.5 ms, RTO = 12.5 + max(4 * 25, 200) = 212.5 ms. Taken as a first
/// sample, R would make SRTT 100 ms, RTTVAR 50 ms and RTO 300 ms. The next
/// segment must time out at 212.5 ms.
#[test]
fn a_sample_of_zero_ticks_counts_and_the_next_one_is_averaged_in() {
    let _g = begin();
    let (idx, ours, theirs) = open(7976, 46516, 0x7600_0000, SEG as u16, false);
    let ms100 = 100 * TICKS_PER_MS;
    assert_eq!(estimate(idx), (false, 0, 0, RTO_INITIAL), "precondition: nothing measured");

    assert_eq!(tcp::send_data(idx, &pattern(0, SEG)), SEG as i32);
    peer_ack(7976, 46516, theirs, ours.wrapping_add(SEG as u32), WIN, &[]);
    assert_eq!(estimate(idx), (true, 0, 0, VAR_FLOOR), "a 0-tick sample is a measurement");

    assert_eq!(tcp::send_data(idx, &pattern(SEG, SEG)), SEG as i32);
    let t1 = T0 + ms100;
    azos_drv_irqchip::clint::set_test_time(t1);
    peer_ack(7976, 46516, theirs, ours.wrapping_add(2 * SEG as u32), WIN, &[]);
    let rto = ms100 / 8 + VAR_FLOOR;
    assert_eq!(estimate(idx), (true, ms100 * 1000 / 8, ms100 * 1000 / 4, rto),
        "the second sample must be averaged into the first, not replace it");

    assert_eq!(tcp::send_data(idx, &pattern(2 * SEG, SEG)), SEG as i32);
    wire::clear_sent();
    azos_drv_irqchip::clint::set_test_time(t1 + rto - TICKS_PER_MS);
    tcp::tcp_tick();
    assert!(data_sent().is_empty(), "a timeout before the RTO");
    azos_drv_irqchip::clint::set_test_time(t1 + rto);
    tcp::tcp_tick();
    assert_eq!(data_sent().len(), 1, "the RTO is 212.5 ms; a second sample taken as the first makes it 300 ms");
}

// ── The RTO's floors and when the timer restarts ────────────────────────────

/// The variance term of the RTO never falls below 200 ms
/// (`RTO_VAR_FLOOR_MS`). On a path whose round trip does not vary, RTTVAR
/// decays towards 0, and RFC 6298 §2.3's max(G, 4 * RTTVAR) with G = 1 ms
/// would leave the RTO a millisecond above SRTT, shorter than any resend's
/// round trip.
///
/// Thirty segments, each acknowledged 300 ms after it left: SRTT 300 ms, and
/// RTTVAR 150 ms after the first sample, three quarters of that after each
/// further one — well under a millisecond by the thirtieth. The RTO is
/// 300 + 200 = 500 ms, where G alone gives 301 ms: the next segment times out
/// at 500 ms and not before.
#[test]
fn on_a_steady_path_the_rto_stays_200_ms_above_srtt() {
    let _g = begin();
    let (idx, ours, theirs) = open(7980, 46520, 0x8000_0000, SEG as u16, false);
    let rtt = 300 * TICKS_PER_MS;
    let mut t = T0;
    for k in 0..30u32 {
        assert_eq!(tcp::send_data(idx, &pattern(k as usize * SEG, SEG)), SEG as i32);
        t += rtt;
        azos_drv_irqchip::clint::set_test_time(t);
        peer_ack(7980, 46520, theirs, ours.wrapping_add((k + 1) * SEG as u32), WIN, &[]);
    }
    let (measured, srtt, rttvar, rto) = estimate(idx);
    assert!(measured && srtt == rtt * 1000, "precondition: SRTT settled on 300 ms, got {srtt}");
    assert!(rttvar * 4 / 1000 < TICKS_PER_MS, "precondition: 4 * RTTVAR decayed under G, got {rttvar}");
    assert_eq!(rto, rtt + VAR_FLOOR, "the RTO must be SRTT + 200 ms");

    assert_eq!(tcp::send_data(idx, &pattern(30 * SEG, SEG)), SEG as i32);
    wire::clear_sent();
    azos_drv_irqchip::clint::set_test_time(t + rtt + VAR_FLOOR - TICKS_PER_MS);
    tcp::tcp_tick();
    assert!(data_sent().is_empty(), "a timeout before SRTT + 200 ms");
    azos_drv_irqchip::clint::set_test_time(t + rtt + VAR_FLOOR);
    tcp::tcp_tick();
    assert_eq!(data_sent().len(), 1, "one timeout at SRTT + 200 ms");
}

/// During SACK recovery an ACK reporting bytes the peer had not SACKed before
/// restarts the retransmission timer, as an ACK of new data does (RFC 6298
/// §5.3): the recovery is making progress, and its resend may still be on its
/// way.
///
/// Ten segments at T0, every sample 0 ticks, so the RTO is 200 ms. SACKs of
/// S1..S3 start recovery and resend S0, all at T0. At +150 ms the SACK grows to
/// S1..S4, with no room to resend anything. No timeout at +200 ms; one at
/// +350 ms, from SND.UNA.
#[test]
fn new_sack_information_during_recovery_restarts_the_retransmission_timer() {
    let _g = begin();
    let (s, una, theirs) = in_flight(7981, 46521, 0x8100_0000, SEG as u16, true, 10);
    let at = |k: u32| una.wrapping_add(k * 1000);
    let ack = |blocks: &[(u32, u32)]| peer_ack(7981, 46521, theirs, una, WIN, blocks);
    let seqs = || data_sent().iter().map(|o| o.seq).collect::<Vec<_>>();
    for end in 2..=4 {
        ack(&[(at(1), at(end))]);
    }
    assert_eq!(seqs(), vec![at(0)], "precondition: recovery resends S0");
    assert_eq!(estimate(s.idx).3, VAR_FLOOR, "precondition: RTO 200 ms");
    wire::clear_sent();

    let sacked_at = T0 + 150 * TICKS_PER_MS;
    azos_drv_irqchip::clint::set_test_time(sacked_at);
    ack(&[(at(1), at(5))]);
    assert!(seqs().is_empty(), "precondition: no room to resend anything");

    azos_drv_irqchip::clint::set_test_time(T0 + VAR_FLOOR);
    tcp::tcp_tick();
    assert!(seqs().is_empty(), "the timer ran from the last cumulative ACK, not from the SACK at +150 ms");
    azos_drv_irqchip::clint::set_test_time(sacked_at + VAR_FLOOR - TICKS_PER_MS);
    tcp::tcp_tick();
    assert!(seqs().is_empty(), "a timeout before one RTO after the SACK");
    azos_drv_irqchip::clint::set_test_time(sacked_at + VAR_FLOOR);
    tcp::tcp_tick();
    assert_eq!(seqs(), vec![una], "one RTO after the SACK, the timeout resends from SND.UNA");
}

/// A SACK that repeats what the peer already reported is no progress, and
/// restarts nothing: the same recovery as above, but the ACK at +150 ms
/// repeats S1..S3, and the timer fires at +200 ms.
#[test]
fn a_repeated_sack_report_during_recovery_does_not_restart_the_timer() {
    let _g = begin();
    let (_s, una, theirs) = in_flight(7982, 46522, 0x8200_0000, SEG as u16, true, 10);
    let at = |k: u32| una.wrapping_add(k * 1000);
    let ack = |blocks: &[(u32, u32)]| peer_ack(7982, 46522, theirs, una, WIN, blocks);
    let seqs = || data_sent().iter().map(|o| o.seq).collect::<Vec<_>>();
    for end in 2..=4 {
        ack(&[(at(1), at(end))]);
    }
    assert_eq!(seqs(), vec![at(0)], "precondition: recovery resends S0");
    wire::clear_sent();

    azos_drv_irqchip::clint::set_test_time(T0 + 150 * TICKS_PER_MS);
    ack(&[(at(1), at(4))]);
    assert!(seqs().is_empty(), "precondition: nothing resent");
    azos_drv_irqchip::clint::set_test_time(T0 + VAR_FLOOR);
    tcp::tcp_tick();
    assert_eq!(seqs(), vec![una], "a repeated report restarted the timer");
}

/// Before recovery a new SACK restarts nothing either: one or two duplicates
/// are all a tail loss may draw, and its timeout must still run from the last
/// cumulative ACK. The first SACK, of S1 alone, arrives at +150 ms; the timer
/// fires at +200 ms.
#[test]
fn a_new_sack_before_recovery_does_not_restart_the_timer() {
    let _g = begin();
    let (_s, una, theirs) = in_flight(7983, 46523, 0x8300_0000, SEG as u16, true, 10);
    let at = |k: u32| una.wrapping_add(k * 1000);
    let seqs = || data_sent().iter().map(|o| o.seq).collect::<Vec<_>>();

    azos_drv_irqchip::clint::set_test_time(T0 + 150 * TICKS_PER_MS);
    peer_ack(7983, 46523, theirs, una, WIN, &[(at(1), at(2))]);
    assert!(seqs().is_empty(), "precondition: one duplicate starts no recovery");
    azos_drv_irqchip::clint::set_test_time(T0 + VAR_FLOOR);
    tcp::tcp_tick();
    assert_eq!(seqs(), vec![una], "a SACK before recovery restarted the timer");
}

/// RTO_MAX, 60 s (RFC 6298 §2.5), caps what a sample makes of the RTO. S0
/// acknowledged 70 s after it left gives SRTT 70 s, RTTVAR 35 s and
/// SRTT + 4 * RTTVAR = 210 s, which becomes 60 s: the next segment times out at
/// 60 s and not before.
#[test]
fn a_seventy_second_sample_gives_an_rto_of_sixty_seconds() {
    let _g = begin();
    let (idx, ours, theirs) = open(7984, 46524, 0x8400_0000, SEG as u16, false);
    let s = 1_000 * TICKS_PER_MS;
    assert_eq!(tcp::send_data(idx, &pattern(0, SEG)), SEG as i32);
    let t = T0 + 70 * s;
    azos_drv_irqchip::clint::set_test_time(t);
    peer_ack(7984, 46524, theirs, ours.wrapping_add(SEG as u32), WIN, &[]);
    assert_eq!(estimate(idx), (true, 70 * s * 1000, 35 * s * 1000, 60 * s), "the RTO must stop at 60 s");

    assert_eq!(tcp::send_data(idx, &pattern(SEG, SEG)), SEG as i32);
    wire::clear_sent();
    azos_drv_irqchip::clint::set_test_time(t + 60 * s - TICKS_PER_MS);
    tcp::tcp_tick();
    assert!(data_sent().is_empty(), "a timeout before 60 s");
    azos_drv_irqchip::clint::set_test_time(t + 60 * s);
    tcp::tcp_tick();
    assert_eq!(data_sent().len(), 1, "one timeout at 60 s");
}

/// Backoff doubles the RTO at each timeout (RFC 6298 §5.5) and stops at
/// RTO_MAX. From the initial 1 s, nothing measured: timeouts at +1, +3, +7,
/// +15, +31 and +63 s leave the RTO at 2, 4, 8, 16, 32 and min(64, 60) = 60 s,
/// so the seventh fires at +123 s, not +127 s. Seven attempts stay under
/// `RETX_MAX_ATTEMPTS` (8); data in flight keeps keepalive out.
#[test]
fn backoff_stops_doubling_at_sixty_seconds() {
    let _g = begin();
    let (idx, ours, _theirs) = open(7985, 46525, 0x8500_0000, SEG as u16, false);
    let s = 1_000 * TICKS_PER_MS;
    assert_eq!(tcp::send_data(idx, &pattern(0, SEG)), SEG as i32);
    wire::clear_sent();
    for at in [1u64, 3, 7, 15, 31, 63, 123] {
        azos_drv_irqchip::clint::set_test_time(T0 + at * s - TICKS_PER_MS);
        tcp::tcp_tick();
        assert!(data_sent().is_empty(), "a timeout before +{at} s");
        azos_drv_irqchip::clint::set_test_time(T0 + at * s);
        tcp::tcp_tick();
        assert_eq!(data_sent().iter().map(|o| o.seq).collect::<Vec<_>>(), vec![ours],
            "the timeout due at +{at} s");
        wire::clear_sent();
    }
    assert_eq!(estimate(idx).3, 60 * s, "the RTO after seven timeouts");
}

// ── Karn on the resends an ACK, a send or a report triggers ─────────────────
//
// `retransmit` ends the measurement in progress for every segment it resends,
// whichever caller asked. Each test makes the timed segment one of the bytes a
// different caller resends, and asserts that the ACK covering it leaves the
// estimate exactly as it was. The resend after a timeout is not among them:
// the timeout ends the measurement itself, and what is timed after it is new
// data above `recover`, which that resend never reaches. The report of a
// smaller path is in `tcp_pmtu`.

/// NewReno's fast retransmit (RFC 5681 §3.2) resends the timed segment.
///
/// S0 and S1 leave at T0, S0 timed. Three duplicates resend S0; the ACK of
/// both, 300 ms later, must take no sample — from the first send it would read
/// 300 ms.
#[test]
fn a_fast_retransmission_of_the_timed_segment_ends_its_measurement() {
    let _g = begin();
    let (idx, ours, theirs) = open(7970, 46510, 0x7000_0000, SEG as u16, false);
    assert_eq!(tcp::send_data(idx, &pattern(0, SEG)), SEG as i32);
    assert_eq!(tcp::send_data(idx, &pattern(SEG, SEG)), SEG as i32);
    assert_eq!(timed(idx), Some(ours.wrapping_add(SEG as u32)), "precondition: S0 is timed");
    let before = estimate(idx);
    wire::clear_sent();

    for _ in 0..3 {
        peer_ack(7970, 46510, theirs, ours, WIN, &[]);
    }
    assert_eq!(data_sent().iter().map(|o| o.seq).collect::<Vec<_>>(), vec![ours], "precondition: S0 resent");

    azos_drv_irqchip::clint::set_test_time(T0 + 300 * TICKS_PER_MS);
    peer_ack(7970, 46510, theirs, ours.wrapping_add(2 * SEG as u32), WIN, &[]);
    assert!(!tcp::is_unacked(idx), "precondition: both acknowledged");
    assert_eq!(estimate(idx), before, "an ACK of a resent segment gave an RTT sample");
}

/// NewReno's partial-ACK resend (RFC 6582 §3.2 step 5) resends the timed
/// segment when the fast retransmit resent nothing: the peer's window was
/// closed.
///
/// S0 and S1 leave at T0; S0's ACK at +100 ms is a sample and S2 leaves,
/// timed. The peer closes its window with SND.UNA at S1, and three duplicates
/// start recovery with nothing resent. Its ACK of S1, the window open again, is
/// partial: S2 is resent at once, and the ACK of S2 at +400 ms must take no
/// sample.
#[test]
fn a_partial_ack_resend_of_the_timed_segment_ends_its_measurement() {
    let _g = begin();
    let (idx, ours, theirs) = open(7971, 46511, 0x7100_0000, SEG as u16, false);
    let at = |k: u32| ours.wrapping_add(k * SEG as u32);
    let ack = |a: u32, w: u16| peer_ack(7971, 46511, theirs, a, w, &[]);
    assert_eq!(tcp::send_data(idx, &pattern(0, SEG)), SEG as i32);
    assert_eq!(tcp::send_data(idx, &pattern(SEG, SEG)), SEG as i32);
    azos_drv_irqchip::clint::set_test_time(T0 + 100 * TICKS_PER_MS);
    ack(at(1), WIN);
    assert_eq!(tcp::send_data(idx, &pattern(2 * SEG, SEG)), SEG as i32);
    assert_eq!(timed(idx), Some(at(3)), "precondition: S2 is timed");
    wire::clear_sent();

    ack(at(1), 0);
    for _ in 0..3 {
        ack(at(1), 0);
    }
    assert!(data_sent().is_empty(), "precondition: the closed window holds the fast retransmit");
    assert_eq!(timed(idx), Some(at(3)), "precondition: nothing resent, S2 still timed");
    let before = estimate(idx);

    ack(at(2), WIN);
    let out = data_sent();
    assert_eq!(out.iter().map(|o| (o.seq, o.payload.len())).collect::<Vec<_>>(), vec![(at(2), SEG)],
        "precondition: the partial ACK resends S2");
    assert_eq!(out[0].payload, pattern(2 * SEG, SEG));

    azos_drv_irqchip::clint::set_test_time(T0 + 400 * TICKS_PER_MS);
    ack(at(3), WIN);
    assert!(!tcp::is_unacked(idx), "precondition: all acknowledged");
    assert_eq!(estimate(idx), before, "an ACK of a resent segment gave an RTT sample");
}

/// The retransmission that starts SACK recovery (RFC 6675 §5 step 4.3)
/// resends the timed segment at SND.UNA.
///
/// Eight 250-byte segments leave at T0, S0 timed; S1, S3 and S5 are SACKed,
/// three ranges that prove S0 lost, as in
/// `the_scoreboard_alone_proves_snd_una_lost_before_three_duplicates`. The ACK
/// of S0 and S1, 300 ms later, must take no sample.
#[test]
fn the_retransmission_that_starts_sack_recovery_ends_the_measurement() {
    let _g = begin();
    let (idx, ours, theirs) = open(7972, 46512, 0x7200_0000, SEG as u16, true);
    send_small(idx, 250, 8);
    let at = |k: u32| ours.wrapping_add(k * 250);
    assert_eq!(timed(idx), Some(at(1)), "precondition: S0 is timed");
    let before = estimate(idx);

    peer_ack(7972, 46512, theirs, ours, WIN, &[(at(1), at(2))]);
    peer_ack(7972, 46512, theirs, ours, WIN, &[(at(3), at(4)), (at(1), at(2))]);
    peer_ack(7972, 46512, theirs, ours, WIN, &[(at(5), at(6)), (at(3), at(4)), (at(1), at(2))]);
    assert_eq!(data_sent().iter().map(|o| (o.seq, o.payload.len())).collect::<Vec<_>>(),
        vec![(at(0), 250)], "precondition: recovery resends S0");

    azos_drv_irqchip::clint::set_test_time(T0 + 300 * TICKS_PER_MS);
    peer_ack(7972, 46512, theirs, at(2), WIN, &[(at(5), at(6)), (at(3), at(4))]);
    assert_eq!(estimate(idx), before, "an ACK of a resent segment gave an RTT sample");
}

/// SACK recovery's rule (1), from an ACK (RFC 6675 §5 (C)), resends a new
/// segment timed during recovery once SACKs above it prove it lost.
///
/// Ten segments S0..S9, S0 lost: recovery (cwnd 5000) resends S0, which ends
/// the measurement then in progress. As S6..S9 are SACKed, new N0..N3 go out
/// one per ACK, N0 timed (pipe 4000 each time, as in
/// `during_sack_recovery_new_data_waits_for_the_pipe_not_the_flight`). N0 is
/// lost: the SACK of N1..N3, 3000 bytes above it, proves it, and that ACK
/// resends it (pipe 1000, room 4000). The ACK of everything, 500 ms later,
/// must take no sample.
#[test]
fn a_sack_recovery_resend_from_an_ack_ends_the_measurement_of_new_data() {
    let _g = begin();
    let (s, una, theirs) = in_flight(7973, 46513, 0x7300_0000, SEG as u16, true, 10);
    let idx = s.idx;
    let at = |k: u32| una.wrapping_add(k * 1000);
    let ack = |a: u32, blocks: &[(u32, u32)]| peer_ack(7973, 46513, theirs, a, WIN, blocks);
    let seqs = || data_sent().iter().map(|o| (o.seq, o.payload.len())).collect::<Vec<_>>();

    for end in 2..=4 {
        ack(una, &[(at(1), at(end))]);
    }
    assert_eq!(seqs(), vec![(at(0), SEG)], "precondition: recovery resends S0");
    wire::clear_sent();
    for end in 5..=6 {
        ack(una, &[(at(1), at(end))]);
    }
    for k in 0..4u32 {
        ack(una, &[(at(1), at(7 + k))]);
        assert_eq!(tcp::send_data(idx, &pattern(s.next + k as usize * SEG, SEG)), SEG as i32,
            "precondition: room for N{k}");
    }
    assert_eq!(seqs(), (10u32..14).map(|k| (at(k), SEG)).collect::<Vec<_>>(),
        "precondition: N0..N3 and nothing else");
    assert_eq!(timed(idx), Some(at(11)), "precondition: N0 is timed");
    wire::clear_sent();
    let before = estimate(idx);

    ack(una, &[(at(11), at(14)), (at(1), at(10))]);
    assert_eq!(seqs(), vec![(at(10), SEG)], "precondition: the ACK resends N0");

    azos_drv_irqchip::clint::set_test_time(T0 + 500 * TICKS_PER_MS);
    ack(at(14), &[]);
    assert!(!tcp::is_unacked(idx), "precondition: all acknowledged");
    assert_eq!(estimate(idx), before, "an ACK of a resent segment gave an RTT sample");
}

// ── The receiving end of a re-cut retransmission ────────────────────────────

/// A sender that cuts retransmissions from SND.UNA may resend a held segment
/// as a longer one at the same sequence. The longer copy is kept, so its tail
/// is delivered with the rest rather than having to come round again.
#[test]
fn a_longer_resend_of_a_held_segment_replaces_the_shorter_copy() {
    let _g = begin();
    let (idx, ours, theirs) = open(7911, 46011, 0x2B00_0000, SEG as u16, false);
    let at = |o: u32| theirs.wrapping_add(o);
    deliver(&seg(46011, 7911, at(4), ours, PSH | ACK, WIN, &[], b"4567"));
    deliver(&seg(46011, 7911, at(4), ours, PSH | ACK, WIN, &[], b"456789AB"));
    deliver(&seg(46011, 7911, at(0), ours, PSH | ACK, WIN, &[], b"0123"));
    assert_eq!(sent().last().unwrap().ack, at(12), "the longer copy's tail is contiguous too");
    let mut buf = [0u8; 32];
    let n = tcp::recv(idx, &mut buf);
    assert_eq!(&buf[..n.max(0) as usize], b"0123456789AB");
}

// ── Data in flight at close ─────────────────────────────────────────────────

/// `close()` puts the FIN behind whatever is still in flight. If a data
/// segment before it is lost, that segment must be resent — the peer cannot
/// acknowledge the FIN until it has the bytes ahead of it.
#[test]
fn data_in_flight_when_close_runs_is_resent_before_the_fin() {
    let _g = begin();
    let (idx, ours, theirs) = open(7908, 46008, 0x2800_0000, SEG as u16, false);
    assert_eq!(tcp::send_data(idx, &pattern(0, SEG)), SEG as i32);
    tcp::close(idx);
    assert!(tcp::conn_state(idx) == tcp::TcpState::FinWait1, "precondition");
    wire::clear_sent();

    azos_drv_irqchip::clint::set_test_time(T0 + RTO_INITIAL);
    tcp::tcp_tick();
    let out = data_sent();
    assert_eq!(out.len(), 1, "the lost data must be resent, got {:?}", sent());
    assert_eq!(out[0].seq, ours);
    assert_eq!(out[0].payload, pattern(0, SEG));

    peer_ack(7908, 46008, theirs, ours.wrapping_add(SEG as u32), WIN, &[]);
    assert!(!tcp::is_unacked(idx), "an ACK of the data must be processed in FinWait1");
    assert!(tcp::conn_state(idx) == tcp::TcpState::FinWait1, "the FIN is not yet acknowledged");

    peer_ack(7908, 46008, theirs, ours.wrapping_add(SEG as u32 + 1), WIN, &[]);
    assert!(tcp::conn_state(idx) == tcp::TcpState::FinWait2,
        "and the FIN's ACK still moves on, got {}", st(tcp::conn_state(idx)));
}

/// `close()` does not restart the timer of data already in flight: a segment
/// sent at T0 and closed on at T0 + 900 ms is still resent one RTO after T0.
/// Restarting it at the close would also hand a peer that stopped answering a
/// fresh budget of backed-off retries.
#[test]
fn close_does_not_restart_the_timer_of_data_in_flight() {
    let _g = begin();
    let (idx, ours, _theirs) = open(7912, 46012, 0x2C00_0000, SEG as u16, false);
    assert_eq!(tcp::send_data(idx, &pattern(0, SEG)), SEG as i32);

    azos_drv_irqchip::clint::set_test_time(T0 + 900 * TICKS_PER_MS);
    tcp::close(idx);
    assert!(tcp::conn_state(idx) == tcp::TcpState::FinWait1, "precondition");
    wire::clear_sent();

    azos_drv_irqchip::clint::set_test_time(T0 + RTO_INITIAL);
    tcp::tcp_tick();
    let out = data_sent();
    assert_eq!(out.len(), 1,
        "one RTO after the data left it must be resent; the close restarted its timer");
    assert_eq!(out[0].seq, ours);
}

// ── Resets (RFC 793 §3.9) ───────────────────────────────────────────────────
//
// Each test runs at its own clock so the global reset budget (10 per 100 ms)
// starts fresh and no other test's resets are counted against it.

/// SYN-SENT: an ACK that does not acknowledge our SYN draws a reset at
/// SEG.ACK, and the connection attempt is left alone.
#[test]
fn syn_sent_answers_an_ack_of_something_else_with_a_reset() {
    let _g = begin();
    azos_drv_irqchip::clint::set_test_time(3_000_000_000);
    wire::clear_sent();
    let idx = tcp::connect(PEER_IP, 7920, 46100);
    assert!(idx >= 0);
    let idx = idx as usize;
    let iss = sent().pop().expect("SYN").seq;
    wire::clear_sent();

    deliver(&seg(7920, 46100, 0x5000_0000, iss.wrapping_add(100), SYN | ACK, WIN, &mss(1000), &[]));
    let out = sent();
    assert_eq!(out.len(), 1, "exactly one reply, got {out:?}");
    assert_eq!(out[0].flags, RST, "a reset without ACK");
    assert_eq!(out[0].seq, iss.wrapping_add(100), "at the sender's SEG.ACK");
    assert!(tcp::conn_state(idx) == tcp::TcpState::SynSent,
        "the reset must not close our own attempt, got {}", st(tcp::conn_state(idx)));

    deliver(&seg(7920, 46100, 0x5000_0000, iss.wrapping_add(1), SYN | ACK, WIN, &mss(1000), &[]));
    assert!(tcp::conn_state(idx) == tcp::TcpState::Established,
        "the genuine SYN-ACK still establishes it");
}

/// SYN-RECEIVED: the third leg must acknowledge our SYN-ACK; any other ACK
/// draws a reset and leaves the half-open slot waiting for the real one.
#[test]
fn syn_received_answers_an_ack_of_something_else_with_a_reset() {
    let _g = begin();
    azos_drv_irqchip::clint::set_test_time(3_100_000_000);
    assert!(tcp::listen(7921) >= 0);
    wire::clear_sent();
    deliver(&seg(46101, 7921, 0x5100_0000, 0, SYN, WIN, &mss(1000), &[]));
    let iss = sent().pop().expect("SYN-ACK").seq;
    let idx = slot_in(tcp::TcpState::SynRcvd).expect("half-open slot");
    wire::clear_sent();

    deliver(&seg(46101, 7921, 0x5100_0001, iss.wrapping_add(7), ACK, WIN, &[], &[]));
    let out = sent();
    assert_eq!(out.len(), 1, "exactly one reply, got {out:?}");
    assert_eq!((out[0].flags, out[0].seq), (RST, iss.wrapping_add(7)));
    assert!(tcp::conn_state(idx) == tcp::TcpState::SynRcvd);

    deliver(&seg(46101, 7921, 0x5100_0001, iss.wrapping_add(1), ACK, WIN, &[], &[]));
    assert!(tcp::conn_state(idx) == tcp::TcpState::Established);
}

/// LISTEN: a segment carrying an ACK acknowledges nothing this port sent. It
/// draws a reset — a SYN-ACK too, which must not open a connection — and the
/// resets share the closed-port budget.
#[test]
fn a_listening_port_answers_an_ack_with_a_reset_within_the_budget() {
    let _g = begin();
    let t = 3_200_000_000u64;
    azos_drv_irqchip::clint::set_test_time(t);
    assert!(tcp::listen(7922) >= 0);
    wire::clear_sent();

    deliver(&seg(46102, 7922, 5, 0x1234_5678, ACK, WIN, &[], &[]));
    let out = sent();
    assert_eq!(out.len(), 1, "exactly one reply, got {out:?}");
    assert_eq!((out[0].flags, out[0].seq), (RST, 0x1234_5678));

    azos_drv_irqchip::clint::set_test_time(t + 200 * TICKS_PER_MS);
    wire::clear_sent();
    deliver(&seg(46103, 7922, 6, 0x1111_0000, SYN | ACK, WIN, &mss(1000), &[]));
    assert_eq!(sent().iter().filter(|o| o.flags == RST).count(), 1, "a SYN-ACK is answered by a reset");
    assert!(slot_in(tcp::TcpState::SynRcvd).is_none(), "and opens nothing");
    assert!(slot_in(tcp::TcpState::Listen).is_some(), "the listener is untouched");

    azos_drv_irqchip::clint::set_test_time(t + 400 * TICKS_PER_MS);
    wire::clear_sent();
    for i in 0..1000u32 {
        deliver(&seg(46104, 7922, i, 0x2000_0000 + i, ACK, WIN, &[], &[]));
    }
    let rsts = sent().iter().filter(|o| o.flags & RST != 0).count();
    assert!((1..=10).contains(&rsts), "1000 ACKs in one instant drew {rsts} resets");
}

// ── ACKs to unacceptable segments (RFC 793 §3.9) ────────────────────────────

/// A retransmission of data we already hold is answered: the peer's copy of
/// our ACK was lost, and without another it retransmits until it gives up.
/// The answers are bounded per connection.
#[test]
fn a_segment_already_received_is_acknowledged_again_at_a_bounded_rate() {
    let _g = begin();
    let (idx, ours, theirs) = open(7930, 46200, 0x3000_0000, SEG as u16, false);
    let hello = seg(46200, 7930, theirs, ours, PSH | ACK, WIN, &[], b"hello");
    deliver(&hello);
    let mut buf = [0u8; 16];
    assert_eq!(tcp::recv(idx, &mut buf), 5);
    wire::clear_sent();

    deliver(&hello);
    let out = sent();
    assert_eq!(out.len(), 1, "the duplicate must be answered once, got {out:?}");
    assert_eq!((out[0].flags, out[0].ack, out[0].payload.len()), (ACK, theirs.wrapping_add(5), 0));

    wire::clear_sent();
    for _ in 0..20 {
        deliver(&hello);
    }
    assert_eq!(sent().len(), 0, "twenty more in the same instant must draw nothing");

    azos_drv_irqchip::clint::set_test_time(T0 + INVALID_ACK_INTERVAL);
    deliver(&hello);
    assert_eq!(sent().len(), 1, "after the interval, one more answer");
}

/// A retransmission that overlaps what arrived and carries new bytes past it
/// is acceptable (RFC 793 §3.3, last case) and delivers only the new bytes.
#[test]
fn an_overlapping_retransmission_delivers_only_its_new_bytes() {
    let _g = begin();
    let (idx, ours, theirs) = open(7931, 46201, 0x3100_0000, SEG as u16, false);
    deliver(&seg(46201, 7931, theirs, ours, PSH | ACK, WIN, &[], b"hello"));
    deliver(&seg(46201, 7931, theirs.wrapping_add(2), ours, PSH | ACK, WIN, &[], b"lloworld"));
    assert_eq!(sent().last().unwrap().ack, theirs.wrapping_add(10));
    let mut buf = [0u8; 32];
    let n = tcp::recv(idx, &mut buf);
    assert_eq!(&buf[..n.max(0) as usize], b"helloworld");
}

/// A keep-alive probe — no data, one byte behind RCV.NXT — asks for an ACK,
/// and gets one. Accepting it in silence did not keep anyone alive.
#[test]
fn a_keep_alive_probe_is_answered() {
    let _g = begin();
    let (_idx, ours, theirs) = open(7932, 46202, 0x3200_0000, SEG as u16, false);
    deliver(&seg(46202, 7932, theirs.wrapping_sub(1), ours, ACK, WIN, &[], &[]));
    let out = sent();
    assert_eq!(out.len(), 1, "the probe must be answered, got {out:?}");
    assert_eq!((out[0].flags, out[0].seq, out[0].ack), (ACK, ours, theirs));
}

// ── TIME-WAIT and port reuse ────────────────────────────────────────────────

/// Reconnecting from the port of a connection still in TIME-WAIT — what the
/// brain link does after closing from Established — reclaims the old slot,
/// starts past every sequence number it used, and establishes.
#[test]
fn a_connect_from_a_4_tuple_in_time_wait_establishes() {
    let _g = begin();
    let idx = tcp::connect(PEER_IP, 7940, 46300);
    assert!(idx >= 0);
    let idx = idx as usize;
    let iss = sent().pop().expect("SYN").seq;
    let ours = iss.wrapping_add(1);
    let theirs = 0x6000_0001u32;
    deliver(&seg(7940, 46300, theirs.wrapping_sub(1), ours, SYN | ACK, WIN, &mss(1000), &[]));
    tcp::close(idx);
    deliver(&seg(7940, 46300, theirs, ours.wrapping_add(1), ACK, WIN, &[], &[]));
    deliver(&seg(7940, 46300, theirs, ours.wrapping_add(1), FIN | ACK, WIN, &[], &[]));
    assert!(tcp::conn_state(idx) == tcp::TcpState::TimeWait,
        "precondition: TIME-WAIT, got {}", st(tcp::conn_state(idx)));

    wire::clear_sent();
    let again = tcp::connect(PEER_IP, 7940, 46300);
    assert!(again >= 0);
    let again = again as usize;
    let iss2 = sent().pop().expect("SYN").seq;

    deliver(&seg(7940, 46300, 0x7000_0000, iss2.wrapping_add(1), SYN | ACK, WIN, &mss(1000), &[]));
    assert!(tcp::conn_state(again) == tcp::TcpState::Established,
        "the SYN-ACK went to the old TIME-WAIT slot instead, got {}", st(tcp::conn_state(again)));
    assert!(slot_in(tcp::TcpState::TimeWait).is_none(), "the old slot is reclaimed");

    // Same 4-tuple and the same clock, so the ISN generator gives the same
    // number as before: only the floor puts the new ISS past the old FIN.
    let past = iss2.wrapping_sub(ours.wrapping_add(1));
    assert!(past != 0 && past < 1 << 31,
        "the new ISS {iss2} must lie past the old FIN at {ours}");
}

/// Active open from `port` to the peer's `peer_port`, through to Established.
/// Returns (idx, our SND.NXT, the peer's next sequence).
fn dial(port: u16, peer_port: u16, peer_isn: u32) -> (usize, u32, u32) {
    wire::clear_sent();
    let idx = tcp::connect(PEER_IP, peer_port, port);
    assert!(idx >= 0, "no free connection slot");
    let idx = idx as usize;
    let ours = sent().pop().expect("SYN").seq.wrapping_add(1);
    deliver(&seg(peer_port, port, peer_isn, ours, SYN | ACK, WIN, &mss(1000), &[]));
    assert!(tcp::conn_state(idx) == tcp::TcpState::Established,
        "precondition: Established, got {}", st(tcp::conn_state(idx)));
    wire::clear_sent();
    (idx, ours, peer_isn.wrapping_add(1))
}

/// Dials the 4-tuple slot `old` still holds and expects a refusal with nothing
/// on the wire. If a second slot is handed out instead, the peer answers its
/// SYN the way a new incarnation would, and the failure reports where that
/// answer went.
fn expect_refused(old: usize, port: u16, peer_port: u16) {
    wire::clear_sent();
    let again = tcp::connect(PEER_IP, peer_port, port);
    if again < 0 {
        assert!(sent().iter().all(|o| o.flags & SYN == 0), "a refused connect sent a SYN");
        return;
    }
    let again = again as usize;
    let old_was = st(tcp::conn_state(old));
    let syn = sent().pop().expect("SYN");
    wire::clear_sent();
    deliver(&seg(peer_port, port, 0x7700_0000, syn.seq.wrapping_add(1), SYN | ACK, WIN, &mss(1000), &[]));
    panic!(
        "connect opened slot {again} beside slot {old} ({old_was}) for the same 4-tuple; \
         after the SYN-ACK for its SYN, slot {again} is {} and slot {old} is {}, and the stack sent {:?}",
        st(tcp::conn_state(again)), st(tcp::conn_state(old)), sent(),
    );
}

/// A 4-tuple is one connection (RFC 793 §2.7). While the old one is still
/// closing, dialling it again is refused, as Linux refuses it; the refusal
/// lasts only until TIME-WAIT, which a connect reclaims.
#[test]
fn a_connect_on_a_4_tuple_still_closing_is_refused_until_time_wait() {
    let _g = begin();
    let (idx, ours, theirs) = dial(46310, 7942, 0x6400_0000);
    tcp::close(idx);
    assert!(tcp::conn_state(idx) == tcp::TcpState::FinWait1, "precondition");
    expect_refused(idx, 46310, 7942);

    deliver(&seg(7942, 46310, theirs, ours.wrapping_add(1), ACK, WIN, &[], &[]));
    assert!(tcp::conn_state(idx) == tcp::TcpState::FinWait2,
        "the old connection keeps closing, got {}", st(tcp::conn_state(idx)));
    expect_refused(idx, 46310, 7942);

    deliver(&seg(7942, 46310, theirs, ours.wrapping_add(1), FIN | ACK, WIN, &[], &[]));
    assert!(tcp::conn_state(idx) == tcp::TcpState::TimeWait,
        "got {}", st(tcp::conn_state(idx)));
    wire::clear_sent();
    let again = tcp::connect(PEER_IP, 7942, 46310);
    assert!(again >= 0, "TIME-WAIT must not refuse the same connect");
    let again = again as usize;
    let syn = sent().pop().expect("SYN");
    deliver(&seg(7942, 46310, 0x6480_0000, syn.seq.wrapping_add(1), SYN | ACK, WIN, &mss(1000), &[]));
    assert!(tcp::conn_state(again) == tcp::TcpState::Established,
        "got {}", st(tcp::conn_state(again)));
}

/// The same rule from the other side of a close: an established connection,
/// one the peer has closed (CLOSE-WAIT) and one waiting for the ACK of our FIN
/// (LAST-ACK) each keep their 4-tuple until they are gone.
#[test]
fn a_connect_on_a_4_tuple_that_is_open_or_in_last_ack_is_refused() {
    let _g = begin();
    let (idx, ours, theirs) = dial(46311, 7943, 0x6500_0000);
    expect_refused(idx, 46311, 7943);

    deliver(&seg(7943, 46311, theirs, ours, FIN | ACK, WIN, &[], &[]));
    assert!(tcp::conn_state(idx) == tcp::TcpState::CloseWait,
        "precondition: CloseWait, got {}", st(tcp::conn_state(idx)));
    expect_refused(idx, 46311, 7943);

    tcp::close(idx);
    assert!(tcp::conn_state(idx) == tcp::TcpState::LastAck, "precondition");
    expect_refused(idx, 46311, 7943);

    deliver(&seg(7943, 46311, theirs.wrapping_add(1), ours.wrapping_add(1), ACK, WIN, &[], &[]));
    assert!(tcp::conn_state(idx) == tcp::TcpState::Closed,
        "got {}", st(tcp::conn_state(idx)));
    wire::clear_sent();
    let again = tcp::connect(PEER_IP, 7943, 46311);
    assert!(again >= 0, "a closed 4-tuple must be free again");
    let again = again as usize;
    let syn = sent().pop().expect("SYN");
    deliver(&seg(7943, 46311, 0x6580_0000, syn.seq.wrapping_add(1), SYN | ACK, WIN, &mss(1000), &[]));
    assert!(tcp::conn_state(again) == tcp::TcpState::Established,
        "got {}", st(tcp::conn_state(again)));
}

/// A peer reconnecting to our listener from the port of a connection we hold
/// in TIME-WAIT gets in when its SYN is past the old RCV.NXT (RFC 1122
/// §4.2.2.13); an old duplicate SYN does not.
#[test]
fn a_new_syn_for_a_4_tuple_in_time_wait_opens_a_connection() {
    let _g = begin();
    let (idx, ours, theirs) = open(7941, 46301, 0x6100_0000, SEG as u16, false);
    tcp::close(idx);
    deliver(&seg(46301, 7941, theirs, ours.wrapping_add(1), ACK, WIN, &[], &[]));
    deliver(&seg(46301, 7941, theirs, ours.wrapping_add(1), FIN | ACK, WIN, &[], &[]));
    assert!(tcp::conn_state(idx) == tcp::TcpState::TimeWait, "precondition");
    wire::clear_sent();

    deliver(&seg(46301, 7941, 0x6100_0000, 0, SYN, WIN, &mss(1000), &[]));
    assert!(sent().iter().all(|o| o.flags & SYN == 0), "an old duplicate SYN reopened the connection");
    assert!(tcp::conn_state(idx) == tcp::TcpState::TimeWait);

    let fresh = theirs.wrapping_add(100_000);
    deliver(&seg(46301, 7941, fresh, 0, SYN, WIN, &mss(1000), &[]));
    let synack = sent().pop().expect("the new SYN must be answered");
    assert_eq!((synack.flags, synack.ack), (SYN | ACK, fresh.wrapping_add(1)));
    assert!(slot_in(tcp::TcpState::SynRcvd).is_some());
    assert!(slot_in(tcp::TcpState::TimeWait).is_none());
}

// ── Simultaneous open (RFC 793 §3.4) ────────────────────────────────────────

/// Both ends dial at once: each SYN is answered with a SYN-ACK from the ISS
/// already sent, and the peer's SYN-ACK completes the connection.
#[test]
fn a_simultaneous_open_reaches_established() {
    let _g = begin();
    wire::clear_sent();
    let idx = tcp::connect(PEER_IP, 7950, 46400);
    assert!(idx >= 0);
    let idx = idx as usize;
    let iss = sent().pop().expect("SYN").seq;
    wire::clear_sent();

    deliver(&seg(7950, 46400, 0x6300_0000, 0, SYN, WIN, &mss(1000), &[]));
    let out = sent();
    assert_eq!(out.len(), 1, "our SYN crossed theirs; it must be answered, got {out:?}");
    assert_eq!((out[0].flags, out[0].seq, out[0].ack), (SYN | ACK, iss, 0x6300_0001));
    assert!(tcp::conn_state(idx) == tcp::TcpState::SynRcvd,
        "got {}", st(tcp::conn_state(idx)));

    wire::clear_sent();
    deliver(&seg(7950, 46400, 0x6300_0000, iss.wrapping_add(1), SYN | ACK, WIN, &mss(1000), &[]));
    assert!(tcp::conn_state(idx) == tcp::TcpState::Established,
        "got {}", st(tcp::conn_state(idx)));
    let ack = sent().pop().expect("the peer's SYN-ACK must be acknowledged");
    assert_eq!((ack.flags, ack.seq, ack.ack), (ACK, iss.wrapping_add(1), 0x6300_0001));

    wire::clear_sent();
    assert_eq!(tcp::send_data(idx, b"crossed"), 7);
    assert_eq!(data_sent()[0].seq, iss.wrapping_add(1));
}

// ── SACK loss recovery (RFC 6675) ───────────────────────────────────────────
//
// Every connection below negotiated SACK (except the NewReno control) and
// advertised an MSS of 1000, so SMSS is 1000 and `IsLost` needs DupThresh (3)
// SACKed ranges, or more than 2 * SMSS = 2000 SACKed bytes, above a sequence
// number. Recovery starts with cwnd = max(FlightSize / 2, 2 * SMSS), and
// pipe = bytes not SACKed - lost bytes not SACKed + bytes resent in this
// recovery; each test works its figures out in its comment.

/// `n` segments of `len` bytes on `idx`, the stream starting at offset 0.
fn send_small(idx: usize, len: usize, n: usize) {
    for k in 0..n {
        assert_eq!(tcp::send_data(idx, &pattern(k * len, len)), len as i32, "precondition: segment {k}");
    }
    wire::clear_sent();
}

/// DupThresh duplicate ACKs start recovery on their own (RFC 6675 §5 step 1),
/// even when the SACKed bytes are too few for `IsLost`: eight 250-byte
/// segments, the first lost, the next three SACKed one ACK at a time — one
/// range of 750 bytes. An ACK repeating a block already reported is not a
/// duplicate under RFC 6675 §2, however many times it comes.
#[test]
fn three_acks_with_new_sack_information_start_recovery_and_repeats_do_not_count() {
    let _g = begin();
    let (idx, ours, theirs) = open(7960, 46500, 0x6600_0000, SEG as u16, true);
    send_small(idx, 250, 8);
    let at = |k: u32| ours.wrapping_add(k * 250);

    peer_ack(7960, 46500, theirs, ours, WIN, &[(at(1), at(2))]);
    for _ in 0..3 {
        peer_ack(7960, 46500, theirs, ours, WIN, &[(at(1), at(2))]);
    }
    peer_ack(7960, 46500, theirs, ours, WIN, &[(at(1), at(3))]);
    assert!(data_sent().is_empty(),
        "two ACKs carried new SACK information; the three repeats must not count as duplicates");

    peer_ack(7960, 46500, theirs, ours, WIN, &[(at(1), at(4))]);
    let out = data_sent();
    assert_eq!(out.len(), 1, "the third duplicate must start recovery with one resend, got {out:?}");
    assert_eq!((out[0].seq, out[0].payload.len()), (at(0), 250),
        "the segment at SND.UNA, stopping at the SACKed range");
    assert_eq!(out[0].payload, pattern(0, 250));
}

/// The scoreboard alone can prove SND.UNA lost before three duplicates arrive
/// (RFC 6675 §5 step 2, `IsLost(HighACK + 1)`), by either count:
///
/// * bytes: 1000-byte segments, the first lost, the next three SACKed in two
///   ACKs. 2000 SACKed bytes are not more than 2 * SMSS; 3000 are.
/// * ranges: 250-byte segments, the even ones lost, the odd ones SACKed. Two
///   ranges are not DupThresh; three are, with only 750 bytes SACKed.
///
/// Either way recovery starts on the second duplicate, with one resend: cwnd
/// 2500 against pipe 2000 in the first case, 2000 against 1250 in the second.
#[test]
fn the_scoreboard_alone_proves_snd_una_lost_before_three_duplicates() {
    let _g = begin();
    let (s, una, theirs) = in_flight(7961, 46501, 0x6700_0000, SEG as u16, true, 5);
    let off = s.next - 5 * SEG;
    let at = |k: u32| una.wrapping_add(k * 1000);
    peer_ack(7961, 46501, theirs, una, WIN, &[(at(1), at(3))]);
    assert!(data_sent().is_empty(), "2000 SACKed bytes are not more than 2 * SMSS");
    peer_ack(7961, 46501, theirs, una, WIN, &[(at(1), at(4))]);
    let out = data_sent();
    assert_eq!(out.len(), 1, "3000 SACKed bytes prove SND.UNA lost on the second duplicate, got {out:?}");
    assert_eq!((out[0].seq, out[0].payload.len()), (at(0), 1000));
    assert_eq!(out[0].payload, pattern(off, SEG));

    let (idx, ours, theirs) = open(7962, 46502, 0x6800_0000, SEG as u16, true);
    send_small(idx, 250, 8);
    let at = |k: u32| ours.wrapping_add(k * 250);
    peer_ack(7962, 46502, theirs, ours, WIN, &[(at(3), at(4)), (at(1), at(2))]);
    assert!(data_sent().is_empty(), "two SACKed ranges are not DupThresh");
    peer_ack(7962, 46502, theirs, ours, WIN, &[(at(5), at(6)), (at(3), at(4)), (at(1), at(2))]);
    let out = data_sent();
    assert_eq!(out.len(), 1, "three SACKed ranges prove SND.UNA lost on the second duplicate, got {out:?}");
    assert_eq!((out[0].seq, out[0].payload.len()), (at(0), 250));
    assert_eq!(out[0].payload, pattern(0, 250));
}

/// During recovery new data waits for `cwnd - pipe`, not `cwnd - flight`
/// (RFC 6675 §5 (C)): SACKed and lost bytes have left the network.
///
/// Ten segments S0..S9 in flight, S0 lost, S1.. SACKed one ACK at a time.
/// FlightSize is 10000, so recovery starts with cwnd 5000 and resends S0.
/// pipe = not SACKed - S0 (lost) + S0 (resent):
///
/// | SACKed | pipe | cwnd - pipe | new segments |
/// |--------|------|-------------|--------------|
/// | S1..S3 | 7000 | < 0         | 0            |
/// | S1..S4 | 6000 | < 0         | 0            |
/// | S1..S5 | 5000 | 0           | 0            |
/// | S1..S6 | 4000 | 1000        | 1            |
///
/// The flight never falls below 10000, so a sender still counting it sends
/// nothing new; one that did not count S0's resend sends at S1..S5 already.
#[test]
fn during_sack_recovery_new_data_waits_for_the_pipe_not_the_flight() {
    let _g = begin();
    let (s, una, theirs) = in_flight(7963, 46503, 0x6900_0000, SEG as u16, true, 10);
    let idx = s.idx;
    let at = |k: u32| una.wrapping_add(k * 1000);
    let fresh = pattern(s.next, SEG);

    peer_ack(7963, 46503, theirs, una, WIN, &[(at(1), at(2))]);
    peer_ack(7963, 46503, theirs, una, WIN, &[(at(1), at(3))]);
    peer_ack(7963, 46503, theirs, una, WIN, &[(at(1), at(4))]);
    let out = data_sent();
    assert_eq!(out.iter().map(|o| o.seq).collect::<Vec<_>>(), vec![at(0)], "precondition: recovery resends S0");
    wire::clear_sent();
    assert_eq!(tcp::send_data(idx, &fresh), 0, "S1..S3 SACKed: pipe 7000");

    for (end, pipe, want) in [(5u32, 6000, 0), (6, 5000, 0), (7, 4000, SEG as i32)] {
        peer_ack(7963, 46503, theirs, una, WIN, &[(at(1), at(end))]);
        assert!(data_sent().is_empty(), "nothing is lost but S0, which went already");
        assert_eq!(tcp::send_data(idx, &fresh), want,
            "S1..S{} SACKed: pipe {pipe} against cwnd 5000", end - 1);
    }
    let out = data_sent();
    assert_eq!((out.len(), out[0].seq), (1, at(10)), "the new segment is on the wire");
    assert_eq!(out[0].payload, fresh);
    assert_eq!(tcp::send_data(idx, &pattern(s.next + SEG, SEG)), 0, "and it filled the room");
}

/// NextSeg rule (1) before rule (2) (RFC 6675 §4): lost ranges are resent
/// before any new data, and never a byte the peer SACKed.
///
/// Ten segments S0..S9; S0, S2 and S4 lost. SACKs arrive for S1, S3, S5, then
/// for S6, S7 and S8, extending S5's range. Three ranges above S0 prove S0
/// lost and start recovery (cwnd 5000); S2 is lost once more than 2000 SACKed
/// bytes lie above it, S4 once 3000 do.
///
/// | SACKed        | lost     | pipe                    | sent       |
/// |---------------|----------|-------------------------|------------|
/// | S1 S3 S5      | S0       | 7000 - 1000 + 1000 = 7000 | S0       |
/// | S1 S3 S5..S6  | S0 S2    | 6000 - 2000 + 1000 = 5000 | nothing  |
/// | S1 S3 S5..S7  | S0 S2 S4 | 5000 - 3000 + 1000 = 3000 | S2, S4   |
/// | S1 S3 S5..S8  | S0 S2 S4 | 4000 - 3000 + 3000 = 4000 | new data |
#[test]
fn lost_ranges_are_resent_before_new_data_and_sacked_bytes_never_are() {
    let _g = begin();
    let (s, una, theirs) = in_flight(7964, 46504, 0x6A00_0000, SEG as u16, true, 10);
    let idx = s.idx;
    let off = s.next - 10 * SEG;
    let at = |k: u32| una.wrapping_add(k * 1000);
    let r = |a: u32, b: u32| (at(a), at(b));
    let ack = |blocks: &[(u32, u32)]| peer_ack(7964, 46504, theirs, una, WIN, blocks);
    let fresh = pattern(s.next, SEG);
    let mut resent = Vec::new();

    ack(&[r(1, 2)]);
    ack(&[r(3, 4), r(1, 2)]);
    ack(&[r(5, 6), r(3, 4), r(1, 2)]);
    let out = data_sent();
    assert_eq!(out.iter().map(|o| o.seq).collect::<Vec<_>>(), vec![at(0)], "recovery starts by resending S0");
    resent.extend(out);
    wire::clear_sent();
    assert_eq!(tcp::send_data(idx, &fresh), 0);

    ack(&[r(5, 7), r(3, 4), r(1, 2)]);
    assert!(data_sent().is_empty(), "pipe 5000 fills cwnd 5000");
    assert_eq!(tcp::send_data(idx, &fresh), 0);

    ack(&[r(5, 8), r(3, 4), r(1, 2)]);
    let out = data_sent();
    assert_eq!(out.iter().map(|o| (o.seq, o.payload.len())).collect::<Vec<_>>(),
        vec![(at(2), 1000), (at(4), 1000)], "S2 then S4, each stopping at the next SACKed range");
    resent.extend(out);
    wire::clear_sent();
    assert_eq!(tcp::send_data(idx, &fresh), 0, "S2 and S4 took the room; nothing new yet");

    ack(&[r(5, 9), r(3, 4), r(1, 2)]);
    assert!(data_sent().is_empty(), "no lost range is left, and no rescue is due");
    assert_eq!(tcp::send_data(idx, &fresh), SEG as i32, "now the room goes to new data");
    let out = data_sent();
    assert_eq!((out.len(), out[0].seq), (1, at(10)));

    for o in &resent {
        let k = o.seq.wrapping_sub(una) / 1000;
        assert!([0, 2, 4].contains(&k), "resent S{k}, which the peer SACKed");
        assert_eq!(o.payload, pattern(off + k as usize * SEG, SEG));
    }
}

/// Rule (1) before rule (2) holds for the application's send too. One ACK
/// releases at most `RECOVERY_RETX_BURST` (four) segments; when more lost
/// bytes fit in `cwnd - pipe`, `send_data` resends them and takes no new data
/// until none is left.
///
/// Twenty segments S0..S19, S0..S15 lost, S16..S19 SACKed in one ACK: 4000
/// SACKed bytes prove all sixteen lost, and cwnd is 10000. The ACK resends
/// S0..S3 (pipe 4000); the next send resends S4..S7 (pipe 8000), the one
/// after S8 and S9 (pipe 10000), each answering 0; the last finds no room.
///
/// Needs a send ring of 21 segments: below it the new segment is refused by
/// the ring, not by rule (1).
#[test]
fn a_send_during_sack_recovery_resends_lost_ranges_before_taking_new_data() {
    if !send_ring_holds(
        "a_send_during_sack_recovery_resends_lost_ranges_before_taking_new_data",
        21 * SEG,
        "twenty segments in flight and one new one offered",
    ) {
        return;
    }
    let _g = begin();
    let (s, una, theirs) = in_flight(7965, 46505, 0x6B00_0000, SEG as u16, true, 20);
    let idx = s.idx;
    let at = |k: u32| una.wrapping_add(k * 1000);
    let fresh = pattern(s.next, SEG);
    let seqs = || data_sent().iter().map(|o| o.seq).collect::<Vec<_>>();
    let span = |a: u32, b: u32| (a..b).map(|k| at(k)).collect::<Vec<_>>();

    peer_ack(7965, 46505, theirs, una, WIN, &[(at(16), at(20))]);
    assert_eq!(seqs(), span(0, 4), "the ACK releases four segments");
    wire::clear_sent();

    assert_eq!(tcp::send_data(idx, &fresh), 0, "lost bytes still fit: no new data");
    assert_eq!(seqs(), span(4, 8));
    wire::clear_sent();
    assert_eq!(tcp::send_data(idx, &fresh), 0);
    assert_eq!(seqs(), span(8, 10), "S8 and S9 fill cwnd");
    wire::clear_sent();
    assert_eq!(tcp::send_data(idx, &fresh), 0, "no room left");
    assert!(seqs().is_empty());
}

/// Recovery ends at the first cumulative ACK at or past RecoveryPoint, SND.NXT
/// when it began (RFC 6675 §5 (A)), and not at a partial ACK below it.
///
/// Eight segments S0..S7; S0 and S4 lost. S1..S3 SACKed prove S0 lost:
/// recovery, cwnd 4000, RecoveryPoint the end of S7. S0's resend draws a
/// partial ACK to S4. There, still in recovery, an ACK SACKing S5 frees a
/// segment of room (pipe 3000) and S4 goes by rule (3). The ACK of everything
/// through S7 ends recovery: new data N0..N3 fills cwnd 4000, and one SACK of
/// N1 above a lost N0 is one duplicate, not a resend. Two more duplicates
/// start the next recovery.
#[test]
fn sack_recovery_ends_at_the_recovery_point_and_not_before() {
    let _g = begin();
    let (mut s, una, theirs) = in_flight(7966, 46506, 0x6C00_0000, SEG as u16, true, 8);
    let at = |k: u32| una.wrapping_add(k * 1000);
    let ack = |a: u32, blocks: &[(u32, u32)]| peer_ack(7966, 46506, theirs, a, WIN, blocks);
    let seqs = || data_sent().iter().map(|o| (o.seq, o.payload.len())).collect::<Vec<_>>();

    ack(una, &[(at(1), at(4))]);
    assert_eq!(seqs(), vec![(at(0), 1000)], "precondition: recovery");
    wire::clear_sent();

    ack(at(4), &[]);
    assert!(seqs().is_empty(), "a partial ACK: pipe 4000 fills cwnd 4000");
    ack(at(4), &[(at(5), at(6))]);
    assert_eq!(seqs(), vec![(at(4), 1000)],
        "still in recovery after the partial ACK: S4 must go by rule (3)");
    wire::clear_sent();

    ack(at(8), &[]);
    assert_eq!(s.fill(), 4, "recovery over: cwnd is ssthresh, 4000, and nothing is in flight");
    wire::clear_sent();
    ack(at(8), &[(at(9), at(10))]);
    assert!(seqs().is_empty(), "out of recovery, one SACK of N1 is one duplicate and resends nothing");
    ack(at(8), &[(at(9), at(11))]);
    assert!(seqs().is_empty());
    ack(at(8), &[(at(9), at(12))]);
    assert_eq!(seqs(), vec![(at(8), 1000)], "the third duplicate starts the next recovery");
}

/// A peer that did not negotiate SACK keeps NewReno (RFC 6582): three RFC 5681
/// duplicates resend SND.UNA with cwnd = ssthresh + 3 segments, every further
/// duplicate inflates cwnd by a segment, and a partial ACK resends the next
/// hole at once.
///
/// Eight segments in flight: ssthresh 4000, cwnd 7000 against a flight of
/// 8000. The fourth duplicate makes cwnd 8000, still no room; the fifth 9000,
/// room for one.
#[test]
fn a_peer_without_sack_still_recovers_by_newreno() {
    let _g = begin();
    let (s, una, theirs) = in_flight(7967, 46507, 0x6D00_0000, SEG as u16, false, 8);
    let idx = s.idx;
    let at = |k: u32| una.wrapping_add(k * 1000);
    let dup = || peer_ack(7967, 46507, theirs, una, WIN, &[]);
    let fresh = pattern(s.next, SEG);

    dup();
    dup();
    dup();
    assert_eq!(data_sent().iter().map(|o| o.seq).collect::<Vec<_>>(), vec![at(0)],
        "the third duplicate resends S0");
    wire::clear_sent();
    assert_eq!(tcp::send_data(idx, &fresh), 0, "cwnd 7000 against 8000 in flight");
    dup();
    assert_eq!(tcp::send_data(idx, &fresh), 0, "cwnd 8000 against 8000 in flight");
    dup();
    assert_eq!(tcp::send_data(idx, &fresh), SEG as i32, "cwnd 9000: the inflation admits one new segment");
    wire::clear_sent();

    peer_ack(7967, 46507, theirs, at(2), WIN, &[]);
    assert_eq!(data_sent().iter().map(|o| o.seq).collect::<Vec<_>>(), vec![at(2)],
        "a partial ACK resends the next hole at once");
}

/// SACK recovery's rule (1), from `send_data`, resends a new segment timed
/// during recovery: the ACK that proves it lost spent its burst of
/// `RECOVERY_RETX_BURST` (four) on older lost segments below it.
///
/// Eighteen segments S0..S17, S0 lost: recovery (cwnd 9000) resends S0. With
/// S1..S13 SACKed, pipe is 5000 — S0's resend and S14..S17, not yet lost — and
/// new N0..N3 fill cwnd, N0 timed. The SACK of N1..N3 proves S14..S17 and N0
/// lost (pipe 1000): the ACK resends S14..S17, and the next `send_data`
/// resends N0 instead of taking new data. The ACK of everything, 500 ms later,
/// must take no sample.
///
/// The ACK's resends end N0's measurement before the send resends it, as any
/// resend does; this fails only if neither path ends it. A send's resend comes
/// first only when an ACK has already decided what to resend and another hart
/// sends before it does — nothing a single-threaded test can arrange, because
/// the send finds exactly the room, window and lost range the ACK found.
///
/// Needs a send ring of 23 segments: below it "cwnd is full" at N4 is the
/// ring's refusal, not `cwnd`'s.
#[test]
fn a_sack_recovery_resend_from_a_send_ends_the_measurement_of_new_data() {
    if !send_ring_holds(
        "a_sack_recovery_resend_from_a_send_ends_the_measurement_of_new_data",
        23 * SEG,
        "eighteen segments in flight, N0..N3 sent during recovery and N4 offered",
    ) {
        return;
    }
    let _g = begin();
    let (s, una, theirs) = in_flight(7974, 46514, 0x7400_0000, SEG as u16, true, 18);
    let idx = s.idx;
    let at = |k: u32| una.wrapping_add(k * 1000);
    let ack = |a: u32, blocks: &[(u32, u32)]| peer_ack(7974, 46514, theirs, a, WIN, blocks);
    let seqs = || data_sent().iter().map(|o| (o.seq, o.payload.len())).collect::<Vec<_>>();
    let span = |a: u32, b: u32| (a..b).map(|k| (at(k), SEG)).collect::<Vec<_>>();

    for end in 2..=4 {
        ack(una, &[(at(1), at(end))]);
    }
    assert_eq!(seqs(), span(0, 1), "precondition: recovery resends S0");
    wire::clear_sent();
    ack(una, &[(at(1), at(14))]);
    for k in 0..4 {
        assert_eq!(tcp::send_data(idx, &pattern(s.next + k * SEG, SEG)), SEG as i32,
            "precondition: room for N{k}");
    }
    assert_eq!(tcp::send_data(idx, &pattern(s.next + 4 * SEG, SEG)), 0, "precondition: cwnd is full");
    assert_eq!(seqs(), span(18, 22), "precondition: N0..N3 and nothing else");
    assert_eq!(timed(idx), Some(at(19)), "precondition: N0 is timed");
    wire::clear_sent();
    let before = estimate(idx);

    ack(una, &[(at(19), at(22)), (at(1), at(14))]);
    assert_eq!(seqs(), span(14, 18), "precondition: the ACK's burst resends S14..S17");
    wire::clear_sent();
    assert_eq!(tcp::send_data(idx, &pattern(s.next + 4 * SEG, SEG)), 0, "a lost range goes before new data");
    assert_eq!(seqs(), span(18, 19), "precondition: the send resends N0");

    azos_drv_irqchip::clint::set_test_time(T0 + 500 * TICKS_PER_MS);
    ack(at(22), &[]);
    assert!(!tcp::is_unacked(idx), "precondition: all acknowledged");
    assert_eq!(estimate(idx), before, "an ACK of a resent segment gave an RTT sample");
}

/// RFC 6582 §3.2 step 1: after a NewReno recovery ends at `recover`,
/// duplicates still at that SND.UNA may answer the recovery's own resends and
/// start nothing; once an ACK passes it, three duplicates do.
///
/// S0..S3 in flight; three duplicates resend S0 with `recover` at the end of S3
/// and cwnd 2000 + 3000, which admits N0. The ACK of S0..S3 ends recovery
/// exactly at `recover`, N0 in flight: three duplicates there resend nothing.
/// N1 leaves; the ACK of N0 passes `recover`, and three duplicates resend N1.
#[test]
fn duplicates_at_the_recovery_point_start_nothing_until_an_ack_passes_it() {
    let _g = begin();
    let (s, una, theirs) = in_flight(7977, 46517, 0x7700_0000, SEG as u16, false, 4);
    let idx = s.idx;
    let at = |k: u32| una.wrapping_add(k * 1000);
    let ack = |a: u32| peer_ack(7977, 46517, theirs, a, WIN, &[]);

    for _ in 0..3 {
        ack(una);
    }
    assert_eq!(data_sent().iter().map(|o| o.seq).collect::<Vec<_>>(), vec![at(0)], "precondition: S0 resent");
    assert_eq!(tcp::send_data(idx, &pattern(s.next, SEG)), SEG as i32, "precondition: cwnd 5000 admits N0");
    ack(at(4));
    wire::clear_sent();

    for _ in 0..3 {
        ack(at(4));
    }
    assert!(data_sent().is_empty(), "duplicates at the recovery point started another recovery");

    assert_eq!(tcp::send_data(idx, &pattern(s.next + SEG, SEG)), SEG as i32, "precondition: room for N1");
    ack(at(5));
    wire::clear_sent();
    for _ in 0..3 {
        ack(at(5));
    }
    assert_eq!(data_sent().iter().map(|o| (o.seq, o.payload.len())).collect::<Vec<_>>(), vec![(at(5), SEG)],
        "past the recovery point, three duplicates must resend");
}

/// RFC 6582's guard compares `recover` with SND.UNA in sequence space, which
/// is circular. Left where it was last set — here the initial sequence number,
/// as no recovery ever ran — `recover` reads as ahead of SND.UNA once SND.UNA
/// is 2^31 bytes past it, and three duplicates would then resend nothing for
/// the next 2^31 bytes.
///
/// A little more than 2^31 bytes (2^31 + 2^20, rounded up to a window) go
/// through the real send and ACK paths in 1460-byte segments, 44 to the
/// peer's unscaled 65535-byte window, with no loss; then a full flight is out
/// and three duplicates must resend SND.UNA.
#[test]
fn fast_retransmit_still_works_after_2_31_bytes_without_a_recovery() {
    let _g = begin();
    let (idx, ours, theirs) = open(7978, 46518, 0x7800_0000, 1460, false);
    let chunk = [0x5Au8; 1460];
    let target = (1u64 << 31) + (1u64 << 20);
    let mut acked = 0u64;
    let mut una = ours;
    while acked < target {
        let mut n = 0u64;
        loop {
            let r = tcp::send_data(idx, &chunk);
            if r <= 0 {
                break;
            }
            n += r as u64;
        }
        assert!(n > 0, "the window never reopened after {acked} bytes");
        una = una.wrapping_add(n as u32);
        acked += n;
        peer_ack(7978, 46518, theirs, una, WIN, &[]);
        wire::clear_sent();
    }
    assert!(acked > 1u64 << 31 && acked < 1u64 << 32, "precondition: between 2^31 and 2^32 bytes, got {acked}");
    assert!(!tcp::is_unacked(idx), "precondition: everything acknowledged");

    let mut k = 0;
    while tcp::send_data(idx, &chunk) > 0 {
        k += 1;
    }
    assert!(k >= 3, "precondition: a flight to lose from, got {k} segments");
    wire::clear_sent();
    for _ in 0..3 {
        peer_ack(7978, 46518, theirs, una, WIN, &[]);
    }
    assert_eq!(data_sent().iter().map(|o| (o.seq, o.payload.len())).collect::<Vec<_>>(), vec![(una, 1460)],
        "three duplicates after 2^31 bytes without a recovery must resend SND.UNA");
}

/// A timeout during SACK recovery ends it (RFC 6675 §5.1): RecoveryPoint moves
/// to HighData, the scoreboard is forgotten (RFC 2018 §8), the resend starts
/// at SND.UNA, and no new recovery begins until SND.UNA reaches the new
/// RecoveryPoint, however much the peer SACKs meanwhile.
///
/// Eight segments S0..S7, S0 and S1 lost. SACKs of S2..S4 start recovery;
/// S2..S6 prove S1 lost too, resend it, and leave room for one new segment N0,
/// so HighData becomes N0's end. The timer fires: S0 once, cwnd one segment.
/// Then:
/// * S5..S7 are SACKed afresh in three ACKs — three duplicates, 3000 bytes
///   above SND.UNA — and nothing goes: a timeout's recovery is not left for a
///   SACK one.
/// * The ACK of S0 lets the collapsed window (2000) resend S1 and S2. S2 was
///   SACKed before the timeout only, so it is resent: that report was
///   forgotten.
/// * An ACK through S7 reaches the old RecoveryPoint, not the new one: the
///   timeout's recovery goes on and resends N0.
#[test]
fn a_timeout_ends_sack_recovery_and_none_restarts_before_the_new_recovery_point() {
    let _g = begin();
    let (s, una, theirs) = in_flight(7968, 46508, 0x6E00_0000, SEG as u16, true, 8);
    let idx = s.idx;
    let off = s.next - 8 * SEG;
    let at = |k: u32| una.wrapping_add(k * 1000);
    let ack = |a: u32, blocks: &[(u32, u32)]| peer_ack(7968, 46508, theirs, a, WIN, blocks);
    let seqs = || data_sent().iter().map(|o| (o.seq, o.payload.len())).collect::<Vec<_>>();

    ack(una, &[(at(2), at(5))]);
    ack(una, &[(at(2), at(7))]);
    assert_eq!(seqs(), vec![(at(0), 1000), (at(1), 1000)], "precondition: S0 and S1 resent");
    assert_eq!(tcp::send_data(idx, &pattern(s.next, SEG)), SEG as i32, "precondition: room for N0");
    wire::clear_sent();

    azos_drv_irqchip::clint::set_test_time(T0 + RTO_INITIAL);
    tcp::tcp_tick();
    assert_eq!(seqs(), vec![(at(0), 1000)], "the timeout resends S0");
    wire::clear_sent();

    ack(una, &[(at(5), at(6))]);
    ack(una, &[(at(5), at(7))]);
    ack(una, &[(at(5), at(8))]);
    assert!(seqs().is_empty(), "SACKs after a timeout started a SACK recovery: {:?}", seqs());

    ack(at(1), &[(at(5), at(8))]);
    let out = data_sent();
    assert_eq!(out.iter().map(|o| (o.seq, o.payload.len())).collect::<Vec<_>>(),
        vec![(at(1), 1000), (at(2), 1000)],
        "S2, SACKed only before the timeout, must be resent after S1");
    assert_eq!(out[1].payload, pattern(off + 2 * SEG, SEG));
    wire::clear_sent();

    ack(at(8), &[]);
    assert_eq!(seqs(), vec![(at(8), 1000)],
        "an ACK through S7 is not past HighData at the timeout; N0 must still be resent");
}

/// NextSeg rule (4), the rescue retransmission: a loss at the tail of the
/// flight, with nothing SACKed above it, is resent before the timer, once per
/// recovery.
///
/// Six segments S0..S5; S0 and S5 lost. S1..S3 SACKed start recovery (cwnd
/// 3000) and resend S0. S4's SACK leaves room (pipe 2000) but no rule
/// applies: nothing is lost above HighRxt, nothing unSACKed lies below the
/// highest SACK, and SND.UNA has not passed S0's resend. The ACK of S0..S4
/// does pass it: S5, the highest byte not SACKed, goes as the rescue — once,
/// although `cwnd - pipe` (2000) would admit two.
#[test]
fn the_tail_of_a_flight_is_rescued_once_before_the_timer() {
    let _g = begin();
    let (s, una, theirs) = in_flight(7969, 46509, 0x6F00_0000, SEG as u16, true, 6);
    let off = s.next - 6 * SEG;
    let at = |k: u32| una.wrapping_add(k * 1000);
    let ack = |a: u32, blocks: &[(u32, u32)]| peer_ack(7969, 46509, theirs, a, WIN, blocks);

    ack(una, &[(at(1), at(4))]);
    assert_eq!(data_sent().iter().map(|o| o.seq).collect::<Vec<_>>(), vec![at(0)], "precondition: recovery");
    wire::clear_sent();
    ack(una, &[(at(1), at(5))]);
    assert!(data_sent().is_empty(), "no NextSeg rule applies yet");

    ack(at(5), &[]);
    let out = data_sent();
    assert_eq!(out.iter().map(|o| (o.seq, o.payload.len())).collect::<Vec<_>>(), vec![(at(5), 1000)],
        "S5 must be rescued exactly once");
    assert_eq!(out[0].payload, pattern(off + 5 * SEG, SEG));
}
