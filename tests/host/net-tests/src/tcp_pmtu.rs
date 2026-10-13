// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Path MTU discovery (RFC 1191) as this TCP does it: every segment leaves with
//! Don't Fragment, an ICMP Fragmentation Needed lowers the MSS of the one
//! connection it provably names (RFC 5927), and a path that drops full-sized
//! segments without saying so is found by its timeouts.
//!
//! **The path is a script.** A router with a smaller MTU sits between the
//! stack and a receiver that acknowledges cumulatively; both are played here.
//! ICMP comes in through the real `ip::handle`, and every segment goes out
//! through the real `ip.rs`, so the DF bit and the lengths asserted are the
//! ones on the wire.

use super::tcp_rx::{begin, deliver, slot_in, st, OUR_IP, OUR_MAC, PEER_IP};
use super::{ip, tcp, wire};

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const WIN: u16 = 65535;

const TICKS_PER_MS: u64 = 10_000;
/// The clock `begin()` sets.
const T0: u64 = 10_000;

/// A router on the path.
const ROUTER_IP: [u8; 4] = [10, 0, 0, 1];

// `tcp::pmtu_stats`, as an array so a whole outcome can be compared at once.
const ACCEPTED: usize = 0;
const OVER_BUDGET: usize = 1;
const MALFORMED: usize = 2;
const FOREIGN: usize = 3;
const OUT_OF_WINDOW: usize = 4;
const NOT_LOWER: usize = 5;
const BELOW_FLOOR: usize = 6;
const BLACKHOLE: usize = 7;

fn stats() -> [u32; 8] {
    let s = tcp::pmtu_stats();
    [s.accepted, s.over_budget, s.malformed, s.foreign, s.out_of_window, s.not_lower,
     s.below_floor, s.blackhole]
}

fn since(before: [u32; 8]) -> [u32; 8] {
    let now = stats();
    core::array::from_fn(|i| now[i] - before[i])
}

fn pattern(off: usize, n: usize) -> Vec<u8> {
    (off..off + n).map(|i| (i % 251) as u8).collect()
}

/// A segment from the peer, with options, and a valid checksum.
fn seg(
    src_port: u16, dst_port: u16, seq: u32, ack: u32,
    flags: u8, window: u16, opts: &[u8], payload: &[u8],
) -> Vec<u8> {
    assert_eq!(opts.len() % 4, 0);
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

/// SACK option bytes for `blocks`, or nothing.
fn sack(blocks: &[(u32, u32)]) -> Vec<u8> {
    let mut o = Vec::new();
    if !blocks.is_empty() {
        o.extend_from_slice(&[1, 1, 5, 2 + 8 * blocks.len() as u8]);
        for &(l, r) in blocks {
            o.extend_from_slice(&l.to_be_bytes());
            o.extend_from_slice(&r.to_be_bytes());
        }
    }
    o
}

/// Every IPv4 datagram put on the wire since the last call; the record is
/// emptied.
fn take_datagrams() -> Vec<Vec<u8>> {
    let frames = std::mem::take(&mut *crate::raw::FRAMES.lock().unwrap());
    frames
        .into_iter()
        .filter(|f| f.len() >= 34 && f[12] == 0x08 && f[13] == 0x00)
        .map(|f| {
            let total = u16::from_be_bytes([f[16], f[17]]) as usize;
            f[14..(14 + total).min(f.len())].to_vec()
        })
        .collect()
}

/// A TCP segment the stack sent, with the datagram it went in.
struct Tx {
    datagram: Vec<u8>,
    seq: u32,
    flags: u8,
    payload: Vec<u8>,
}

impl Tx {
    fn df(&self) -> bool {
        self.datagram[6] & 0x40 != 0
    }
}

fn take_tcp() -> Vec<Tx> {
    take_datagrams()
        .into_iter()
        .filter(|d| d[9] == ip::IP_PROTO_TCP)
        .map(|d| {
            let ihl = ((d[0] & 0x0F) as usize) * 4;
            let t = &d[ihl..];
            let off = ((t[12] >> 4) as usize) * 4;
            let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
            let flags = t[13];
            let payload = t[off..].to_vec();
            Tx { datagram: d, seq, flags, payload }
        })
        .collect()
}

/// Passive open on `port` from a peer advertising `mss` (and SACK-Permitted
/// with `sack`). Returns (idx, our SND.NXT, the peer's next sequence).
fn open(port: u16, peer_port: u16, peer_isn: u32, mss: u16, sack_ok: bool) -> (usize, u32, u32) {
    assert!(tcp::listen(port) >= 0, "no free slot for the listener");
    handshake(port, peer_port, peer_isn, mss, sack_ok)
}

/// `open`, on a port already listening.
fn handshake(port: u16, peer_port: u16, peer_isn: u32, mss: u16, sack_ok: bool) -> (usize, u32, u32) {
    let mut opts = vec![2, 4, (mss >> 8) as u8, mss as u8];
    if sack_ok {
        opts.extend_from_slice(&[1, 1, 4, 2]);
    }
    deliver(&seg(peer_port, port, peer_isn, 0, SYN, WIN, &opts, &[]));
    let synack = take_tcp().pop().expect("a SYN to a listening port must be answered");
    assert_eq!(synack.flags, SYN | ACK);
    let idx = slot_in(tcp::TcpState::SynRcvd).expect("half-open slot");
    let ours = synack.seq.wrapping_add(1);
    let theirs = peer_isn.wrapping_add(1);
    deliver(&seg(peer_port, port, theirs, ours, ACK, WIN, &[], &[]));
    assert!(tcp::conn_state(idx) == tcp::TcpState::Established,
        "precondition: Established, got {}", st(tcp::conn_state(idx)));
    let _ = take_datagrams();
    (idx, ours, theirs)
}

/// An IPv4 datagram from `src` to us, through the real `ip::handle`.
fn inbound(src: [u8; 4], proto: u8, body: &[u8]) {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&((20 + body.len()) as u16).to_be_bytes());
    p[8] = 64;
    p[9] = proto;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&OUR_IP);
    let ck = ip::checksum(&p);
    p[10..12].copy_from_slice(&ck.to_be_bytes());
    p.extend_from_slice(body);
    ip::handle(&p, &OUR_MAC, &OUR_IP);
}

/// ICMP Destination Unreachable, Fragmentation Needed (RFC 792, RFC 1191 §4),
/// reporting `mtu` and quoting `quote`.
fn frag_needed(mtu: u16, quote: &[u8]) -> Vec<u8> {
    let mut m = vec![3, 4, 0, 0, 0, 0];
    m.extend_from_slice(&mtu.to_be_bytes());
    m.extend_from_slice(quote);
    let ck = ip::checksum(&m);
    m[2..4].copy_from_slice(&ck.to_be_bytes());
    m
}

/// What a router quotes of a datagram it could not forward: the IPv4 header and
/// what follows it, here the whole TCP header.
fn quote(datagram: &[u8]) -> Vec<u8> {
    datagram[..datagram.len().min(40)].to_vec()
}

fn from_router(msg: &[u8]) {
    inbound(ROUTER_IP, ip::IP_PROTO_ICMP, msg);
}

// ── Don't Fragment ──────────────────────────────────────────────────────────

/// TCP asks the path to refuse rather than fragment (RFC 1191 §3); nothing
/// else this host sends changes.
#[test]
fn tcp_segments_leave_with_dont_fragment_and_other_datagrams_without() {
    let _g = begin();
    let (idx, ours, _theirs) = open(8100, 47100, 0x7100_0000, 1460, false);
    assert_eq!(tcp::send_data(idx, &pattern(0, 100)), 100);
    let out = take_tcp();
    assert_eq!(out.len(), 1, "one data segment");
    assert_eq!((out[0].seq, out[0].payload.len()), (ours, 100));
    assert_eq!(&out[0].datagram[6..8], &[0x40, 0x00], "DF set, MF clear, offset 0");

    let mut echo = vec![8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
    echo.extend_from_slice(b"ping");
    let ck = ip::checksum(&echo);
    echo[2..4].copy_from_slice(&ck.to_be_bytes());
    inbound(PEER_IP, ip::IP_PROTO_ICMP, &echo);
    let d = take_datagrams();
    assert_eq!(d.len(), 1, "the echo request is answered");
    assert_eq!(d[0][9], ip::IP_PROTO_ICMP);
    assert_eq!(&d[0][6..8], &[0, 0], "an echo reply must not carry DF: only TCP sets it");
}

// ── What a Fragmentation Needed must prove ──────────────────────────────────

/// Every way a Fragmentation Needed can fail to name a segment of ours in
/// flight, or fail to lower anything, is counted and changes nothing: no
/// resend, and the next segment is still a full 1460 bytes. Past ten messages
/// in 100 ms the rest are not even examined.
#[test]
fn forged_or_useless_frag_needed_messages_change_nothing() {
    let _g = begin();
    let (idx, ours, theirs) = open(8101, 47101, 0x7200_0000, 1460, false);
    assert_eq!(tcp::send_data(idx, &pattern(0, 1460)), 1460);
    assert_eq!(tcp::send_data(idx, &pattern(1460, 1460)), 1460);
    let sent = take_tcp();
    assert_eq!(sent.len(), 2, "precondition: two full segments in flight");
    let d0 = sent[0].datagram.clone();
    assert_eq!(d0.len(), 1500, "precondition: a full-sized datagram");
    let nxt = ours.wrapping_add(2920);

    let with = |at: usize, bytes: &[u8]| {
        let mut q = quote(&d0);
        q[at..at + bytes.len()].copy_from_slice(bytes);
        q
    };
    let mut bad_checksum = frag_needed(1280, &quote(&d0));
    bad_checksum[2] ^= 0xFF;
    let cases: Vec<(&str, Vec<u8>, usize)> = vec![
        ("a sequence number before SND.UNA", frag_needed(1280, &with(24, &ours.wrapping_sub(1).to_be_bytes())), OUT_OF_WINDOW),
        ("a sequence number at SND.NXT", frag_needed(1280, &with(24, &nxt.to_be_bytes())), OUT_OF_WINDOW),
        ("another remote port", frag_needed(1280, &with(22, &47109u16.to_be_bytes())), FOREIGN),
        ("another local port", frag_needed(1280, &with(20, &8109u16.to_be_bytes())), FOREIGN),
        ("another remote address", frag_needed(1280, &with(16, &[10, 0, 0, 77])), FOREIGN),
        ("a source that is not our address", frag_needed(1280, &with(12, &[10, 0, 0, 66])), FOREIGN),
        ("an MTU the quoted datagram fitted", frag_needed(1500, &quote(&d0)), NOT_LOWER),
        ("an MTU above the link's", frag_needed(9000, &quote(&d0)), NOT_LOWER),
        ("a quoted length forged below the MTU", frag_needed(1280, &with(2, &200u16.to_be_bytes())), NOT_LOWER),
        ("an MTU one below the 576 floor", frag_needed(575, &quote(&d0)), BELOW_FLOOR),
        ("an MTU of 68", frag_needed(68, &quote(&d0)), BELOW_FLOOR),
        ("a bad ICMP checksum", bad_checksum, MALFORMED),
        ("a quote too short to hold the sequence number", frag_needed(1280, &d0[..24]), MALFORMED),
        ("a quote of a UDP datagram", frag_needed(1280, &with(9, &[17])), MALFORMED),
    ];
    let mut t = T0;
    for (what, msg, reason) in &cases {
        // A fresh budget window for each, so only the message is judged.
        t += 100 * TICKS_PER_MS;
        azos_drv_irqchip::clint::set_test_time(t);
        let before = stats();
        from_router(msg);
        let mut want = [0u32; 8];
        want[*reason] = 1;
        assert_eq!(since(before), want, "{what}: counted wrongly");
        assert!(take_tcp().is_empty(), "{what}: the stack resent something");
    }

    t += 100 * TICKS_PER_MS;
    azos_drv_irqchip::clint::set_test_time(t);
    let before = stats();
    for _ in 0..11 {
        from_router(&frag_needed(1280, &with(24, &nxt.to_be_bytes())));
    }
    let d = since(before);
    assert_eq!((d[OUT_OF_WINDOW], d[OVER_BUDGET]), (10, 1),
        "ten messages a window are examined and the eleventh is dropped unexamined");

    assert!(take_tcp().is_empty());
    deliver(&seg(47101, 8101, theirs, nxt, ACK, WIN, &[], &[]));
    assert_eq!(tcp::send_data(idx, &pattern(2920, 1460)), 1460, "the MSS must still be 1460");
    assert_eq!(take_tcp().last().map(|o| o.datagram.len()), Some(1500));
}

// ── Karn ────────────────────────────────────────────────────────────────────

/// The resend of a flight at a lowered MSS carries the timed segment again, so
/// the ACK that follows cannot time it (RFC 6298 §3). No resend before this
/// one ended the measurement.
///
/// Two 1460-byte segments leave, the first timed; a valid report of a
/// 1280-byte path resends both at the new size. Their ACK, 300 ms later, must
/// take no sample. The clock is moved a minute on first, so the report falls
/// in a budget window of its own.
#[test]
fn the_resend_at_a_lowered_mss_ends_the_measurement() {
    let _g = begin();
    let (idx, ours, theirs) = open(8110, 47110, 0x7A00_0000, 1460, false);
    let t = T0 + 60_000 * TICKS_PER_MS;
    azos_drv_irqchip::clint::set_test_time(t);
    let rtt = || tcp::conn_rtt(idx).expect("a valid slot");
    let estimate = || {
        let e = rtt();
        (e.measured, e.srtt, e.rttvar, e.rto_ticks)
    };
    assert_eq!(tcp::send_data(idx, &pattern(0, 1460)), 1460);
    assert_eq!(tcp::send_data(idx, &pattern(1460, 1460)), 1460);
    let sent = take_tcp();
    assert_eq!(sent.len(), 2, "precondition");
    assert_eq!(rtt().timed_seq, Some(ours.wrapping_add(1460)), "precondition: the first segment is timed");
    let before = estimate();

    from_router(&frag_needed(1280, &quote(&sent[0].datagram)));
    assert_eq!(take_tcp().len(), 3, "precondition: the flight is resent at the new size");

    azos_drv_irqchip::clint::set_test_time(t + 300 * TICKS_PER_MS);
    deliver(&seg(47110, 8110, theirs, ours.wrapping_add(2920), ACK, WIN, &[], &[]));
    assert!(!tcp::is_unacked(idx), "precondition: acknowledged");
    assert_eq!(estimate(), before, "an ACK of a resent segment gave an RTT sample");
}

// ── A genuine smaller path ──────────────────────────────────────────────────

/// A router with a 1280-byte MTU refuses the first 1500-byte datagram. The
/// flight — two 1460-byte segments, 2920 bytes — is resent at once as 1240 +
/// 1240 + 440, the bytes unchanged, and the report for the second datagram,
/// or one claiming 1400, raises nothing.
///
/// No congestion response: cwnd is still 2920, and the ACK of the flight grows
/// it by one SMSS to 4160 in slow start — room for three 1240-byte segments. A
/// sender that treated the report as a loss would have cut cwnd to one
/// segment, and could resend only the first 1240 bytes.
#[test]
fn a_valid_frag_needed_resends_the_flight_at_the_new_size_without_a_congestion_response() {
    let _g = begin();
    let (idx, ours, theirs) = open(8102, 47102, 0x7300_0000, 1460, false);
    assert_eq!(tcp::send_data(idx, &pattern(0, 1460)), 1460);
    assert_eq!(tcp::send_data(idx, &pattern(1460, 1460)), 1460);
    let sent = take_tcp();
    assert_eq!(sent.len(), 2, "precondition");

    let before = stats();
    from_router(&frag_needed(1280, &quote(&sent[0].datagram)));
    assert_eq!(since(before)[ACCEPTED], 1, "the report names a segment in flight");
    let out = take_tcp();
    assert_eq!(
        out.iter().map(|o| (o.seq.wrapping_sub(ours), o.payload.len())).collect::<Vec<_>>(),
        vec![(0, 1240), (1240, 1240), (2480, 440)],
        "the whole flight must be resent from SND.UNA at the new size",
    );
    for o in &out {
        assert!(o.df() && o.datagram.len() <= 1280);
        assert_eq!(o.payload, pattern(o.seq.wrapping_sub(ours) as usize, o.payload.len()));
    }

    let before = stats();
    from_router(&frag_needed(1280, &quote(&sent[1].datagram)));
    from_router(&frag_needed(1400, &quote(&sent[0].datagram)));
    let d = since(before);
    assert_eq!((d[ACCEPTED], d[NOT_LOWER]), (0, 2), "neither may raise the MSS or resend again");
    assert!(take_tcp().is_empty());

    deliver(&seg(47102, 8102, theirs, ours.wrapping_add(2920), ACK, WIN, &[], &[]));
    let mut off = 2920;
    let mut k = 0;
    loop {
        let n = tcp::send_data(idx, &pattern(off, 1460));
        if n <= 0 {
            break;
        }
        assert_eq!(n, 1240, "new data is cut at the new MSS");
        off += 1240;
        k += 1;
        assert!(k < 20);
    }
    // Slow start counts bytes (RFC 3465, L = 2 SMSS): the ACK of 2920 bytes
    // grows 2920 by 2 x 1240, to 5400 -- four segments of the new MSS.
    assert_eq!(k, 4, "cwnd must be 5400 after the flight's ACK, not one segment");
}

/// The lowered MSS is one connection's (the owner's rule: per connection, no
/// destination cache): another connection keeps 1460, and a connection that
/// later takes the same slot starts again from 1460.
#[test]
fn a_lowered_mss_belongs_to_one_connection() {
    let _g = begin();
    let (a, _, _) = open(8107, 47107, 0x7800_0000, 1460, false);
    let (b, _, _) = open(8108, 47108, 0x7900_0000, 1460, false);
    assert_eq!(tcp::send_data(a, &pattern(0, 1460)), 1460);
    let d = take_tcp().pop().expect("the segment").datagram;
    let before = stats();
    from_router(&frag_needed(1280, &quote(&d)));
    assert_eq!(since(before)[ACCEPTED], 1, "precondition: A's MSS is lowered");
    let _ = take_tcp();

    assert_eq!(tcp::send_data(b, &pattern(0, 1460)), 1460, "B must keep its MSS");
    tcp::abort(a);
    let _ = take_datagrams();
    let (c, _, _) = handshake(8107, 47110, 0x7A00_0000, 1460, false);
    assert_eq!(c, a, "precondition: the new connection takes A's slot");
    assert_eq!(tcp::send_data(c, &pattern(0, 1460)), 1460, "a new connection must start from the full MSS");
}

/// Delivered in order through the scripted path.
struct Path {
    delivered: usize,
    largest: usize,
    corrupt: bool,
    elapsed_ms: u64,
}

/// Send `total` bytes over a connection whose path has an `mtu`-byte hop. The
/// router drops every larger datagram and, with `report`, answers each with a
/// Fragmentation Needed quoting it. The receiver keeps only in-order bytes and
/// acknowledges what it has after every burst. The clock moves 1 ms per round
/// and `tcp_tick` runs every round, until everything is delivered or
/// `limit_ms` pass.
fn transfer(port: u16, peer_port: u16, peer_isn: u32, mtu: usize, report: bool,
            total: usize, limit_ms: u64) -> Path {
    let (idx, ours, theirs) = open(port, peer_port, peer_isn, 1460, false);
    let start = azos_drv_sys::timebase::now();
    let mut now = start;
    let mut offered = 0usize;
    let mut p = Path { delivered: 0, largest: 0, corrupt: false, elapsed_ms: 0 };
    while p.delivered < total && now - start < limit_ms * TICKS_PER_MS {
        while offered < total {
            let n = (total - offered).min(1460);
            let r = tcp::send_data(idx, &pattern(offered, n));
            if r <= 0 {
                break;
            }
            offered += r as usize;
        }
        let mut arrived = false;
        for tx in take_tcp() {
            if tx.payload.is_empty() {
                continue;
            }
            assert!(tx.df(), "a TCP segment left without DF");
            if tx.datagram.len() > mtu {
                if report {
                    from_router(&frag_needed(mtu as u16, &quote(&tx.datagram)));
                }
                continue;
            }
            arrived = true;
            let off = tx.seq.wrapping_sub(ours) as usize;
            if off <= p.delivered && off + tx.payload.len() > p.delivered {
                let fresh = &tx.payload[p.delivered - off..];
                if fresh != pattern(p.delivered, fresh.len()).as_slice() {
                    p.corrupt = true;
                }
                p.delivered += fresh.len();
                p.largest = p.largest.max(tx.payload.len());
            }
        }
        if arrived {
            deliver(&seg(peer_port, port, theirs, ours.wrapping_add(p.delivered as u32),
                         ACK, WIN, &[], &[]));
        }
        now += TICKS_PER_MS;
        azos_drv_irqchip::clint::set_test_time(now);
        tcp::tcp_tick();
    }
    p.elapsed_ms = (now - start) / TICKS_PER_MS;
    p
}

/// End to end through a 1280-byte hop that reports: every byte arrives in
/// order, every segment delivered is the largest that fits, and the repair
/// takes milliseconds — the first timeout on a fresh connection is a second
/// away, so a stream that waited for one could not finish in 200 ms.
#[test]
fn a_stream_through_a_smaller_mtu_arrives_intact() {
    let _g = begin();
    let before = stats();
    let p = transfer(8103, 47103, 0x7400_0000, 1280, true, 20_000, 10_000);
    assert!(!p.corrupt, "a byte arrived at the wrong offset");
    assert_eq!(p.delivered, 20_000, "the stream stopped after {} ms", p.elapsed_ms);
    assert_eq!(p.largest, 1240, "segments must use all of the 1280-byte path and no more");
    let d = since(before);
    assert_eq!((d[ACCEPTED], d[BLACKHOLE]), (1, 0));
    assert!(p.elapsed_ms < 200, "repaired by a timeout, not by the report: {} ms", p.elapsed_ms);
}

// ── A path that says nothing ────────────────────────────────────────────────

/// A 1280-byte hop that drops larger datagrams in silence. The first flight
/// times out at 1 s, 2 s more and 4 s more; the third timeout of a full
/// segment halves the MSS to 730, which fits, and the stream completes.
#[test]
fn a_path_that_silently_drops_full_segments_is_survived_by_halving_the_mss() {
    let _g = begin();
    let before = stats();
    let p = transfer(8104, 47104, 0x7500_0000, 1280, false, 20_000, 60_000);
    assert!(!p.corrupt, "a byte arrived at the wrong offset");
    assert_eq!(p.delivered, 20_000, "the stream died in the black hole after {} ms", p.elapsed_ms);
    assert_eq!(p.largest, 730, "1460 halved once is 730");
    let d = since(before);
    assert_eq!((d[BLACKHOLE], d[ACCEPTED]), (1, 0));
    assert!((7_000..8_000).contains(&p.elapsed_ms),
        "the fallback belongs at the third timeout, 7 s in; finished at {} ms", p.elapsed_ms);
}

/// The fallback needs a full-sized segment to time out: a 100-byte segment
/// lost four times says nothing about what a 1460-byte one would do.
#[test]
fn timeouts_of_a_segment_shorter_than_the_mss_do_not_lower_it() {
    let _g = begin();
    let (idx, ours, _theirs) = open(8105, 47105, 0x7600_0000, 1460, false);
    assert_eq!(tcp::send_data(idx, &pattern(0, 100)), 100);
    let before = stats();
    for ms in [1_000u64, 3_000, 7_000, 15_000] {
        azos_drv_irqchip::clint::set_test_time(T0 + ms * TICKS_PER_MS);
        tcp::tcp_tick();
    }
    let out: Vec<Tx> = take_tcp().into_iter().filter(|o| !o.payload.is_empty()).collect();
    assert_eq!(out.len(), 5, "the segment and four timeouts' resends");
    assert!(out.iter().all(|o| o.seq == ours && o.payload.len() == 100));
    assert_eq!(since(before)[BLACKHOLE], 0, "a short segment must not lower the MSS");
}

// ── With SACK recovery in progress ──────────────────────────────────────────

/// A Fragmentation Needed during SACK recovery (RFC 6675) ends that recovery
/// and resends from SND.UNA at the new size, skipping what the peer SACKed:
/// the scoreboard is byte ranges, so nothing in it was cut for the old size.
///
/// Four 1000-byte segments S0..S3 in flight; S1..S3 SACKed start recovery,
/// which resends S0 whole. A 576-byte hop reports: MSS 536. S0 goes again as
/// 536 + 464, and nothing from S1..S3.
#[test]
fn frag_needed_during_sack_recovery_resends_at_the_new_size_and_skips_sacked_bytes() {
    let _g = begin();
    let (idx, ours, theirs) = open(8106, 47106, 0x7700_0000, 1000, true);
    let ack = |a: u32, blocks: &[(u32, u32)]| {
        deliver(&seg(47106, 8106, theirs, a, ACK, WIN, &sack(blocks), &[]));
    };
    let mut off = 0usize;
    let mut sent: Vec<Tx> = Vec::new();
    for round in 0..3u32 {
        if round > 0 {
            ack(ours.wrapping_add(round * 1000), &[]);
        }
        for _ in 0..2 {
            assert_eq!(tcp::send_data(idx, &pattern(off, 1000)), 1000, "precondition: slow start");
            off += 1000;
        }
        sent.extend(take_tcp());
    }
    let una = ours.wrapping_add(2000);
    let at = |k: u32| una.wrapping_add(k * 1000);
    let s0 = sent.iter().find(|o| o.seq == una).expect("S0 was sent").datagram.clone();

    ack(una, &[(at(1), at(4))]);
    let out = take_tcp();
    assert_eq!(out.iter().map(|o| (o.seq, o.payload.len())).collect::<Vec<_>>(), vec![(una, 1000)],
        "precondition: SACK recovery resends S0");

    let before = stats();
    from_router(&frag_needed(576, &quote(&s0)));
    assert_eq!(since(before)[ACCEPTED], 1);
    let out = take_tcp();
    assert_eq!(out.iter().map(|o| (o.seq, o.payload.len())).collect::<Vec<_>>(),
        vec![(una, 536), (una.wrapping_add(536), 464)],
        "S0 at the new size, stopping where the SACKed bytes begin");
    for o in &out {
        assert_eq!(o.payload, pattern(2000 + o.seq.wrapping_sub(una) as usize, o.payload.len()));
    }

    ack(at(4), &[]);
    assert!(!tcp::is_unacked(idx));
    assert_eq!(tcp::send_data(idx, &pattern(off, 1000)), 536, "new data at the new MSS");
}
