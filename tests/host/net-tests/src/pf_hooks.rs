// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The packet-filter seam (`crates/net/net/src/filter.rs`) on the IPv4 path:
//! the three hooks, what each verdict does, the null filter, and the rate limit
//! on refusal records. The IPv6 path's hooks are in `ipv6_tcp.rs`.
//!
//! **The real `ip.rs` is in the loop.** Packets come in through `ip::handle`
//! and go out through `ip::send`; what a test reads is the wire the stack wrote
//! (ICMP echo reply, ICMP "administratively prohibited"), not a counter the
//! code under test keeps about itself. The one exception is the forward hook:
//! `ip::forward` calls it, but that path needs a second interface, so its
//! tests call `filter::forward` directly with the view and connection state
//! they choose.
//!
//! **Canary discipline.** Each verdict test has its mirror: the same packet with
//! an accepting filter produces the observable the refusal removes (the echo
//! reply, the datagram on the wire), so a drop that "passes" because the
//! observable never existed would fail the mirror.

use crate::NET_SERIAL as SERIAL;
use crate::filter::{self, ConnPhase, ConnState, Hook, PacketFilter, PacketView, Verdict};
use crate::{arp, ip, raw, wire};
use std::sync::Mutex;

const OUR_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const OUR_IP: [u8; 4] = [10, 0, 0, 2];
const PEER_MAC: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
const PEER_IP: [u8; 4] = [10, 0, 0, 9];
const T0: u64 = 50_000;
const SEC: u64 = azos_drv_sys::timebase::TIMER_FREQ;

/// What the filter was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Call {
    hook: Hook,
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    len: usize,
    sport: Option<u16>,
    dport: Option<u16>,
    flags: Option<u8>,
    conn: Option<ConnState>,
}

/// A filter that logs every question and answers per hook.
struct Probe {
    calls: Mutex<Vec<Call>>,
    answers: Mutex<[Verdict; 3]>,
}

impl PacketFilter for Probe {
    fn check(&self, hook: Hook, pkt: &PacketView, conn: Option<&ConnState>) -> Verdict {
        self.calls.lock().unwrap().push(Call {
            hook,
            src: pkt.src[..4].try_into().unwrap(),
            dst: pkt.dst[..4].try_into().unwrap(),
            proto: pkt.proto,
            len: pkt.packet.len(),
            sport: pkt.src_port(),
            dport: pkt.dst_port(),
            flags: pkt.tcp_flags(),
            conn: conn.copied(),
        });
        self.answers.lock().unwrap()[hook as usize]
    }
}

static PROBE: Probe = Probe {
    calls: Mutex::new(Vec::new()),
    answers: Mutex::new([Verdict::Accept; 3]),
};

fn answer(hook: Hook, v: Verdict) {
    PROBE.answers.lock().unwrap()[hook as usize] = v;
}

fn calls(hook: Hook) -> Vec<Call> {
    PROBE.calls.lock().unwrap().iter().filter(|c| c.hook == hook).cloned().collect()
}

/// Holds the suite's lock and, on the way out, takes the filter off the stack:
/// a filter left installed would judge the next module's packets, a leftover
/// `Drop` answer would make them vanish.
struct Session(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

impl Drop for Session {
    fn drop(&mut self) {
        filter::reset_for_test();
    }
}

fn begin() -> Session {
    let g = Session(SERIAL.lock().unwrap_or_else(|e| e.into_inner()));
    assert!(azos_decision::ON, "the decision ring is off: the record assertions would be vacuous");
    filter::reset_for_test();
    *PROBE.calls.lock().unwrap() = Vec::new();
    *PROBE.answers.lock().unwrap() = [Verdict::Accept; 3];
    azos_drv_irqchip::clint::set_test_time(T0);
    crate::inbound::reset();
    wire::reset();
    arp::cache_reset_for_test();
    arp::insert(PEER_IP, PEER_MAC);
    ip::arp_txq_reset_for_test();
    g
}

fn install() {
    filter::set_filter(&PROBE);
}

/// RFC 1071, independent of the kernel's `ip::checksum`.
fn rfc1071(bytes: &[u8]) -> u16 {
    let mut acc: u64 = 0;
    for pair in bytes.chunks(2) {
        acc += (u64::from(pair[0]) << 8) | if pair.len() == 2 { u64::from(pair[1]) } else { 0 };
    }
    while acc > 0xFFFF {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    !(acc as u16)
}

fn ip_packet(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
    let mut hdr = [0u8; 20];
    ip::build_header(&mut hdr, proto, &src, &dst, l4.len() as u16);
    let mut p = hdr.to_vec();
    p.extend_from_slice(l4);
    p
}

fn udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
    let mut l4 = Vec::new();
    l4.extend_from_slice(&sport.to_be_bytes());
    l4.extend_from_slice(&dport.to_be_bytes());
    l4.extend_from_slice(&(8 + data.len() as u16).to_be_bytes());
    l4.extend_from_slice(&[0, 0]); // checksum 0: none (RFC 768)
    l4.extend_from_slice(data);
    ip_packet(src, dst, ip::IP_PROTO_UDP, &l4)
}

fn tcp_syn(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    let mut l4 = vec![0u8; 20];
    l4[0..2].copy_from_slice(&sport.to_be_bytes());
    l4[2..4].copy_from_slice(&dport.to_be_bytes());
    l4[12] = 5 << 4;
    l4[13] = 0x02; // SYN
    ip_packet(src, dst, ip::IP_PROTO_TCP, &l4)
}

fn echo_request(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut l4 = vec![8u8, 0, 0, 0, 0x12, 0x34, 0, 1, b'p', b'f'];
    let cs = rfc1071(&l4).to_be_bytes();
    l4[2] = cs[0];
    l4[3] = cs[1];
    ip_packet(src, dst, ip::IP_PROTO_ICMP, &l4)
}

fn deliver(packet: &[u8]) {
    ip::handle(packet, &OUR_MAC, &OUR_IP);
}

/// ICMP datagrams the stack put on the wire, as (type, code, whole ICMP message).
fn icmp_sent() -> Vec<(u8, u8, Vec<u8>)> {
    wire::sent()
        .into_iter()
        .filter(|s| s.proto == ip::IP_PROTO_ICMP)
        .map(|s| (s.payload[0], s.payload[1], s.payload))
        .collect()
}

// ── The null filter ─────────────────────────────────────────────────────────

#[test]
fn null_filter_passes_everything_and_asks_nobody() {
    let _g = begin();
    assert!(!filter::active());

    // In: an echo request is answered. Out: a datagram reaches the wire.
    deliver(&echo_request(PEER_IP, OUR_IP));
    let replies = icmp_sent();
    assert_eq!(replies.len(), 1);
    assert_eq!((replies[0].0, replies[0].1), (0, 0), "echo reply");
    assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &PEER_IP, ip::IP_PROTO_UDP, &[0u8; 8]), 0);
    assert_eq!(wire::sent_count(), 2);

    assert!(PROBE.calls.lock().unwrap().is_empty());
    assert_eq!(filter::stats().refused, 0);
    assert_eq!(filter::stats().recorded, 0);
}

#[test]
fn clearing_the_filter_returns_to_the_null_filter() {
    let _g = begin();
    install();
    answer(Hook::Ingress, Verdict::Drop);
    deliver(&echo_request(PEER_IP, OUR_IP));
    assert!(icmp_sent().is_empty(), "dropped while installed");

    filter::clear_filter();
    assert!(!filter::active());
    deliver(&echo_request(PEER_IP, OUR_IP));
    assert_eq!(icmp_sent().len(), 1, "answered again once cleared");
}

// ── Ingress ─────────────────────────────────────────────────────────────────

#[test]
fn ingress_hook_is_called_with_the_view_of_the_datagram() {
    let _g = begin();
    install();
    deliver(&udp(PEER_IP, OUR_IP, 5353, 9000, b"hello"));
    deliver(&tcp_syn(PEER_IP, OUR_IP, 40000, 22));

    let c = calls(Hook::Ingress);
    assert_eq!(c.len(), 2);
    assert_eq!(c[0], Call {
        hook: Hook::Ingress, src: PEER_IP, dst: OUR_IP, proto: ip::IP_PROTO_UDP,
        len: 20 + 8 + 5, sport: Some(5353), dport: Some(9000), flags: None, conn: None,
    });
    assert_eq!(c[1], Call {
        hook: Hook::Ingress, src: PEER_IP, dst: OUR_IP, proto: ip::IP_PROTO_TCP,
        len: 40, sport: Some(40000), dport: Some(22), flags: Some(0x02), conn: None,
    });
}

#[test]
fn ingress_is_asked_only_about_datagrams_the_stack_would_have_taken() {
    let _g = begin();
    install();
    // Not for us (unicast to another host), a bad header checksum, a fragment.
    deliver(&udp(PEER_IP, [10, 0, 0, 77], 1, 2, b"x"));
    let mut bad = udp(PEER_IP, OUR_IP, 1, 2, b"x");
    bad[10] ^= 0xFF;
    deliver(&bad);
    let mut frag = udp(PEER_IP, OUR_IP, 1, 2, b"x");
    frag[6] |= 0x20; // MF
    deliver(&frag);
    assert!(calls(Hook::Ingress).is_empty());
}

#[test]
fn ingress_drop_discards_silently_and_its_mirror_is_answered() {
    let _g = begin();
    // Mirror: accepting filter, the echo is answered.
    install();
    deliver(&echo_request(PEER_IP, OUR_IP));
    assert_eq!(icmp_sent().len(), 1);

    wire::reset();
    answer(Hook::Ingress, Verdict::Drop);
    deliver(&echo_request(PEER_IP, OUR_IP));
    assert_eq!(wire::sent_count(), 0, "nothing at all goes back for a Drop");
    assert_eq!(filter::stats().refused, 1);
    assert_eq!(filter::stats().replied, 0);
}

#[test]
fn ingress_reject_answers_with_icmp_administratively_prohibited() {
    let _g = begin();
    install();
    answer(Hook::Ingress, Verdict::Reject);
    let pkt = udp(PEER_IP, OUR_IP, 5353, 9000, b"0123456789");
    deliver(&pkt);

    let sent = icmp_sent();
    assert_eq!(sent.len(), 1);
    let (ty, code, msg) = &sent[0];
    assert_eq!((*ty, *code), (3, 13), "destination unreachable, administratively prohibited");
    assert_eq!(rfc1071(msg), 0, "ICMP checksum");
    assert_eq!(&msg[4..8], &[0, 0, 0, 0], "unused field");
    assert_eq!(&msg[8..], &pkt[..28], "the offending header and its first eight bytes");
    // It went to the sender.
    assert_eq!(wire::sent()[0].dst_ip, PEER_IP);
    assert_eq!((filter::stats().refused, filter::stats().replied), (1, 1));
}

#[test]
fn reject_never_answers_icmp_broadcast_multicast_or_a_non_host_source() {
    let _g = begin();
    install();
    answer(Hook::Ingress, Verdict::Reject);

    deliver(&echo_request(PEER_IP, OUR_IP)); // about ICMP
    deliver(&udp(PEER_IP, [255, 255, 255, 255], 1, 2, b"x")); // limited broadcast
    deliver(&udp(PEER_IP, [10, 0, 0, 255], 1, 2, b"x")); // directed broadcast
    deliver(&udp([0, 0, 0, 0], OUR_IP, 1, 2, b"x")); // source unspecified
    deliver(&udp([224, 0, 0, 5], OUR_IP, 1, 2, b"x")); // source multicast
    deliver(&udp([255, 255, 255, 255], OUR_IP, 1, 2, b"x")); // source broadcast

    assert_eq!(wire::sent_count(), 0);
    let s = filter::stats();
    // The broadcast datagrams are not for a unicast filter decision here: the
    // stack's own destination filter admits the two broadcasts, so all six
    // reach the hook that refuses them, and none is answered.
    assert_eq!(s.replied, 0);
    assert_eq!(s.reply_held, s.refused);
}

#[test]
fn ingress_reject_replies_are_rate_limited() {
    let _g = begin();
    install();
    answer(Hook::Ingress, Verdict::Reject);
    let n = filter::REPLY_BURST as usize + 7;
    for i in 0..n {
        deliver(&udp(PEER_IP, OUR_IP, 1000 + i as u16, 9000, b"x"));
    }
    let s = filter::stats();
    assert_eq!(s.refused as usize, n);
    assert_eq!(s.replied as u64, filter::REPLY_BURST);
    assert_eq!(s.reply_held, 7);
    assert_eq!(icmp_sent().len() as u64, filter::REPLY_BURST);

    // A second later the bucket has credit again.
    azos_drv_irqchip::clint::set_test_time(T0 + SEC);
    deliver(&udp(PEER_IP, OUR_IP, 1, 9000, b"x"));
    assert_eq!(filter::stats().replied as u64, filter::REPLY_BURST + 1);
}

// ── Egress ──────────────────────────────────────────────────────────────────

#[test]
fn egress_hook_is_called_with_the_view_of_the_datagram_that_leaves() {
    let _g = begin();
    install();
    let mut l4 = vec![0u8; 20];
    l4[0..2].copy_from_slice(&1234u16.to_be_bytes());
    l4[2..4].copy_from_slice(&80u16.to_be_bytes());
    l4[13] = 0x12; // SYN|ACK
    assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &PEER_IP, ip::IP_PROTO_TCP, &l4), 0);

    let c = calls(Hook::Egress);
    assert_eq!(c, vec![Call {
        hook: Hook::Egress, src: OUR_IP, dst: PEER_IP, proto: ip::IP_PROTO_TCP,
        len: 40, sport: Some(1234), dport: Some(80), flags: Some(0x12), conn: None,
    }]);
    assert_eq!(wire::sent_count(), 1, "accepted: on the wire");
}

#[test]
fn egress_drop_reads_as_sent_but_nothing_leaves() {
    let _g = begin();
    install();
    answer(Hook::Egress, Verdict::Drop);
    assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &PEER_IP, ip::IP_PROTO_UDP, &[0u8; 12]), 0);
    assert_eq!(wire::sent_count(), 0);
    assert_eq!(raw::count(), 0);
    assert_eq!(filter::stats().refused, 1);
}

#[test]
fn egress_reject_is_the_callers_error_and_nothing_leaves() {
    let _g = begin();
    install();
    answer(Hook::Egress, Verdict::Reject);
    assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &PEER_IP, ip::IP_PROTO_UDP, &[0u8; 12]), -1);
    assert_eq!(wire::sent_count(), 0);
    // No ICMP is sent for our own datagram.
    assert_eq!(filter::stats().replied, 0);
}

#[test]
fn egress_covers_the_loopback_and_arp_queued_paths() {
    let _g = begin();
    install();
    answer(Hook::Egress, Verdict::Drop);

    // To ourselves: dropped before it is looped back (no ingress call follows).
    assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &OUR_IP, ip::IP_PROTO_UDP, &[0u8; 8]), 0);
    assert!(calls(Hook::Ingress).is_empty());
    // To a host with no MAC yet: dropped before it is queued for ARP, so no ARP
    // request goes out and nothing waits.
    let stranger = [10, 0, 0, 42];
    assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &stranger, ip::IP_PROTO_UDP, &[0u8; 8]), 0);
    assert_eq!(raw::count(), 0, "no ARP request for a datagram that was refused");
    assert_eq!(ip::arp_txq_stats().0, 0, "nothing queued");

    // Mirror: the same two sends with an accepting egress hook do queue and loop.
    answer(Hook::Egress, Verdict::Accept);
    assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &stranger, ip::IP_PROTO_UDP, &[0u8; 8]), 0);
    assert_eq!(ip::arp_txq_stats().0, 1, "queued behind the ARP request");
    assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &OUR_IP, ip::IP_PROTO_UDP, &[0u8; 8]), 0);
    assert_eq!(calls(Hook::Ingress).len(), 1, "the looped-back datagram met the ingress hook");
}

// ── Forward ─────────────────────────────────────────────────────────────────

#[test]
fn forward_hook_gets_the_view_and_the_connection_state() {
    let _g = begin();
    install();
    let other = [192, 168, 7, 7];
    let pkt = udp(PEER_IP, other, 4000, 53, b"q");
    let st = ConnState { phase: ConnPhase::Established, reply: true };

    assert!(filter::forward(&pkt, Some(&st), &OUR_MAC, &OUR_IP));
    assert!(filter::forward(&pkt, None, &OUR_MAC, &OUR_IP));

    let c = calls(Hook::Forward);
    assert_eq!(c.len(), 2);
    assert_eq!((c[0].src, c[0].dst, c[0].proto, c[0].sport, c[0].dport), (PEER_IP, other, ip::IP_PROTO_UDP, Some(4000), Some(53)));
    assert_eq!(c[0].conn, Some(st));
    assert_eq!(c[1].conn, None);
    assert!(calls(Hook::Ingress).is_empty() && calls(Hook::Egress).is_empty());
}

#[test]
fn forward_drop_and_reject_stop_the_packet_and_reject_answers_the_sender() {
    let _g = begin();
    install();
    let pkt = udp(PEER_IP, [192, 168, 7, 7], 4000, 53, b"q");

    answer(Hook::Forward, Verdict::Drop);
    assert!(!filter::forward(&pkt, None, &OUR_MAC, &OUR_IP));
    assert_eq!(wire::sent_count(), 0);

    answer(Hook::Forward, Verdict::Reject);
    assert!(!filter::forward(&pkt, None, &OUR_MAC, &OUR_IP));
    let sent = icmp_sent();
    assert_eq!(sent.len(), 1);
    assert_eq!((sent[0].0, sent[0].1), (3, 13));
    assert_eq!(wire::sent()[0].dst_ip, PEER_IP);
}

#[test]
fn forward_with_no_filter_accepts_without_looking() {
    let _g = begin();
    let pkt = udp(PEER_IP, [192, 168, 7, 7], 4000, 53, b"q");
    assert!(filter::forward(&pkt, None, &OUR_MAC, &OUR_IP));
    assert!(PROBE.calls.lock().unwrap().is_empty());
}

// ── The view ────────────────────────────────────────────────────────────────

#[test]
fn view_refuses_what_is_not_an_ip_header_and_has_no_ports_for_other_protocols() {
    assert!(PacketView::parse(&[]).is_none());
    assert!(PacketView::parse(&[0x45; 19]).is_none(), "shorter than a header");
    for version in [0x55, 0x75] {
        let mut other = udp(PEER_IP, OUR_IP, 1, 2, b"");
        other[0] = version;
        assert!(PacketView::parse(&other).is_none(), "neither version 4 nor 6");
    }
    let v4 = udp(PEER_IP, OUR_IP, 1, 2, b"");
    let v = PacketView::parse(&v4).unwrap();
    assert_eq!((v.v6, &v.src[..4], &v.src[4..], v.hdr_len), (false, &PEER_IP[..], &[0u8; 12][..], 20));
    // An IPv6 header: version 6, the next header is the protocol, ports after 40 bytes.
    let mut v6 = vec![0x60, 0, 0, 0, 0, 8, ip::IP_PROTO_UDP, 64];
    v6.extend_from_slice(&[0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
    v6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    v6.extend_from_slice(&[0x13, 0x88, 0x00, 0x35, 0, 8, 0, 0]);
    let v = PacketView::parse(&v6).unwrap();
    assert_eq!((v.v6, v.src[15], v.dst[0], v.proto, v.hdr_len), (true, 9, 0x20, ip::IP_PROTO_UDP, 40));
    assert_eq!((v.src_port(), v.dst_port()), (Some(5000), Some(53)));
    assert!(PacketView::parse(&v6[..39]).is_none(), "an IPv6 header cut short");
    let mut short_ihl = udp(PEER_IP, OUR_IP, 1, 2, b"");
    short_ihl[0] = 0x43;
    assert!(PacketView::parse(&short_ihl).is_none(), "IHL under 5");
    let mut long_ihl = udp(PEER_IP, OUR_IP, 1, 2, b"");
    long_ihl[0] = 0x4F;
    assert!(PacketView::parse(&long_ihl[..28]).is_none(), "IHL past the end");

    let icmp = echo_request(PEER_IP, OUR_IP);
    let v = PacketView::parse(&icmp).unwrap();
    assert_eq!((v.src_port(), v.dst_port(), v.tcp_flags()), (None, None, None));

    // A TCP/UDP header cut short has no port rather than a panic.
    let cut = ip_packet(PEER_IP, OUR_IP, ip::IP_PROTO_UDP, &[0x12, 0x34, 0x00]);
    let v = PacketView::parse(&cut).unwrap();
    assert_eq!((v.src_port(), v.dst_port()), (Some(0x1234), None));
}

// ── Refusal records ─────────────────────────────────────────────────────────

/// Packet-refused records written since `first_seq`, oldest first.
fn refusal_records(first_seq: u64) -> Vec<azos_decision::Record> {
    let mut v = Vec::new();
    azos_decision::for_each(|r| {
        if r.seq >= first_seq && r.rule == azos_decision::Rule::PacketRefused as u8 {
            v.push(*r);
        }
    });
    v
}

#[test]
fn a_refusal_is_recorded_with_its_hook_verdict_addresses_and_ports() {
    let _g = begin();
    install();
    let before = azos_decision::total() + 1;
    answer(Hook::Ingress, Verdict::Drop);
    deliver(&udp(PEER_IP, OUR_IP, 5353, 9000, b"x"));
    answer(Hook::Egress, Verdict::Reject);
    assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &PEER_IP, ip::IP_PROTO_TCP, &{
        let mut l4 = vec![0u8; 20];
        l4[0..2].copy_from_slice(&1234u16.to_be_bytes());
        l4[2..4].copy_from_slice(&80u16.to_be_bytes());
        l4
    }), -1);

    let r = refusal_records(before);
    assert_eq!(r.len(), 2);
    for rec in &r {
        assert_eq!(rec.verdict, azos_decision::Verdict::Refuse as u8);
    }
    let addrs = |s: [u8; 4], d: [u8; 4]| (u32::from_be_bytes(s) as u64) << 32 | u32::from_be_bytes(d) as u64;
    let meta = |h: Hook, v: Verdict, p: u8, sp: u64, dp: u64| {
        (h as u64) << 56 | (v as u64) << 48 | (p as u64) << 40 | sp << 16 | dp
    };
    assert_eq!(r[0].subject, u32::from_be_bytes(PEER_IP));
    assert_eq!(r[0].n, [addrs(PEER_IP, OUR_IP), meta(Hook::Ingress, Verdict::Drop, ip::IP_PROTO_UDP, 5353, 9000), 0]);
    assert_eq!(r[1].subject, u32::from_be_bytes(OUR_IP));
    assert_eq!(r[1].n, [addrs(OUR_IP, PEER_IP), meta(Hook::Egress, Verdict::Reject, ip::IP_PROTO_TCP, 1234, 80), 0]);
}

#[test]
fn an_accepted_packet_leaves_no_record() {
    let _g = begin();
    install();
    let before = azos_decision::total() + 1;
    for i in 0..20 {
        deliver(&udp(PEER_IP, OUR_IP, 1000 + i, 9000, b"x"));
    }
    assert!(refusal_records(before).is_empty());
    assert_eq!(filter::stats().refused, 0);
}

#[test]
fn refusal_records_are_rate_limited_and_the_held_count_rides_the_next_record() {
    let _g = begin();
    install();
    answer(Hook::Ingress, Verdict::Drop);
    let before = azos_decision::total() + 1;
    let burst = filter::RECORD_BURST as usize;

    // A flood at one instant: the burst is recorded, the rest only counted.
    for i in 0..burst + 5 {
        deliver(&udp(PEER_IP, OUR_IP, 2000 + i as u16, 9000, b"x"));
    }
    let s = filter::stats();
    assert_eq!(s.refused as usize, burst + 5, "every refusal is counted");
    assert_eq!(s.recorded as usize, burst);
    assert_eq!(s.record_held, 5);
    let r = refusal_records(before);
    assert_eq!(r.len(), burst, "the ring holds the burst and no more");
    assert!(r.iter().all(|x| x.n[2] == 0), "nothing was held back before the burst ended");

    // One second at RECORDS_PER_SEC refills that many tokens.
    azos_drv_irqchip::clint::set_test_time(T0 + SEC);
    for i in 0..filter::RECORDS_PER_SEC as usize + 3 {
        deliver(&udp(PEER_IP, OUR_IP, 3000 + i as u16, 9000, b"x"));
    }
    let r = refusal_records(before);
    assert_eq!(r.len(), burst + filter::RECORDS_PER_SEC as usize);
    assert_eq!(r[burst].n[2], 5, "the first record after the pause says how many were held back");
    assert!(r[burst + 1..].iter().all(|x| x.n[2] == 0));
    assert_eq!(filter::stats().record_held, 5 + 3);
}

#[test]
fn a_clock_that_goes_backwards_does_not_refill_the_bucket() {
    let _g = begin();
    install();
    answer(Hook::Ingress, Verdict::Drop);
    azos_drv_irqchip::clint::set_test_time(T0 + 10 * SEC);
    let burst = filter::RECORD_BURST as usize;
    for i in 0..burst {
        deliver(&udp(PEER_IP, OUR_IP, 100 + i as u16, 9000, b"x"));
    }
    assert_eq!(filter::stats().recorded as usize, burst);
    azos_drv_irqchip::clint::set_test_time(T0);
    deliver(&udp(PEER_IP, OUR_IP, 1, 9000, b"x"));
    assert_eq!(filter::stats().recorded as usize, burst, "no credit from a negative interval");
    assert_eq!(filter::stats().record_held, 1);
}
