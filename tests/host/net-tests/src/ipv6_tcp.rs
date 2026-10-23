// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! TCP over IPv6, SLAAC and AAAA, through the real stack.
//!
//! **The loopback model.** The stack has one connection table and one set of
//! addresses, so a listener and a client of the same stack can talk to each
//! other: `connect` to our own link-local address, and every frame the stack
//! puts on the wire (`raw::FRAMES`) is fed back in through `inbound` and the
//! harness' `net_poll`, which runs `ipv6::ipv6_rx` and `tcp::handle_checked_v6`.
//! Both ends run the real state machine, no segment is crafted by hand, and
//! the frames are read off the wire with real IPv6 headers.
//!
//! The 4-tuples do not collide: the client is (ephemeral, 7000) and the
//! accepted side (7000, ephemeral).
//!
//! **The checksum oracle.** `ref_checksum` below sums the pseudo-header and the
//! segment byte by byte from RFC 8200 §8.1. It does not call the stack's own
//! `ipv6::pseudo_checksum`, so a wrong pseudo-header cannot make the sender
//! and the checker agree.

use super::tcp_rx::{self, begin as v4_begin, OUR_MAC};
use super::{inbound, ipv6, raw, tcp};
use std::sync::Mutex;

const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;
const PEER_MAC: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
const ROUTER_MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
const FE80_ROUTER: [u8; 16] = addr(0xFE80, 0, 0, 0, 0, 0, 0, 1);
const FE80_PEER: [u8; 16] = addr(0xFE80, 0, 0, 0, 0, 0, 0, 9);
const GLOBAL_PREFIX: [u8; 8] = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2];
const TICKS_PER_S: u64 = azos_drv_sys::timebase::TIMER_FREQ;

const fn addr(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> [u8; 16] {
    let w = [a, b, c, d, e, f, g, h];
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 8 {
        out[2 * i] = (w[i] >> 8) as u8;
        out[2 * i + 1] = w[i] as u8;
        i += 1;
    }
    out
}

// ── Oracle and frame builders ────────────────────────────────────────────────

/// RFC 8200 §8.1, byte by byte: 0 for a packet whose checksum verifies.
fn ref_checksum(src: &[u8; 16], dst: &[u8; 16], proto: u8, body: &[u8]) -> u16 {
    let mut b = Vec::new();
    b.extend_from_slice(src);
    b.extend_from_slice(dst);
    b.extend_from_slice(&(body.len() as u32).to_be_bytes());
    b.extend_from_slice(&[0, 0, 0, proto]);
    b.extend_from_slice(body);
    if b.len() % 2 == 1 {
        b.push(0);
    }
    let mut sum: u32 = 0;
    for w in b.chunks(2) {
        sum += u16::from_be_bytes([w[0], w[1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Ethernet + IPv6 around `body`, whose checksum field is at `csum_at` and is
/// filled in here.
fn frame6(
    dst_mac: [u8; 6], src: [u8; 16], dst: [u8; 16], proto: u8, hop: u8,
    mut body: Vec<u8>, csum_at: usize,
) -> Vec<u8> {
    body[csum_at] = 0;
    body[csum_at + 1] = 0;
    let c = ref_checksum(&src, &dst, proto, &body);
    body[csum_at..csum_at + 2].copy_from_slice(&c.to_be_bytes());
    let mut f = Vec::new();
    f.extend_from_slice(&dst_mac);
    f.extend_from_slice(&PEER_MAC);
    f.extend_from_slice(&0x86DDu16.to_be_bytes());
    f.extend_from_slice(&[0x60, 0, 0, 0]);
    f.extend_from_slice(&(body.len() as u16).to_be_bytes());
    f.push(proto);
    f.push(hop);
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);
    f.extend_from_slice(&body);
    f
}

/// A TCP segment with `opts` (whole words) and `payload`, in a frame to us.
fn seg6(
    src: [u8; 16], dst: [u8; 16], sp: u16, dp: u16, seq: u32, ack: u32,
    flags: u8, opts: &[u8], payload: &[u8],
) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&sp.to_be_bytes());
    s.extend_from_slice(&dp.to_be_bytes());
    s.extend_from_slice(&seq.to_be_bytes());
    s.extend_from_slice(&ack.to_be_bytes());
    s.push((((20 + opts.len()) / 4) as u8) << 4);
    s.push(flags);
    s.extend_from_slice(&60_000u16.to_be_bytes());
    s.extend_from_slice(&[0, 0, 0, 0]);
    s.extend_from_slice(opts);
    s.extend_from_slice(payload);
    frame6(OUR_MAC, src, dst, 6, 64, s, 16)
}

/// A Router Advertisement from `src` (hop limit `hop`) carrying `opts`.
fn ra_frame(src: [u8; 16], hop: u8, router_lifetime: u16, opts: &[u8]) -> Vec<u8> {
    let mut b = vec![134, 0, 0, 0, 64, 0];
    b.extend_from_slice(&router_lifetime.to_be_bytes());
    b.extend_from_slice(&[0; 8]);
    b.extend_from_slice(opts);
    frame6([0x33, 0x33, 0, 0, 0, 1], src, ipv6::MCAST_ALL_NODES, 58, hop, b, 2)
}

fn slla(mac: [u8; 6]) -> Vec<u8> {
    let mut o = vec![1, 1];
    o.extend_from_slice(&mac);
    o
}

fn pio(prefix_len: u8, flags: u8, valid: u32, preferred: u32, prefix: [u8; 8]) -> Vec<u8> {
    let mut o = vec![3, 4, prefix_len, flags];
    o.extend_from_slice(&valid.to_be_bytes());
    o.extend_from_slice(&preferred.to_be_bytes());
    o.extend_from_slice(&[0; 4]);
    o.extend_from_slice(&prefix);
    o.extend_from_slice(&[0; 8]);
    o
}

fn our_global() -> [u8; 16] {
    let mut g = [0u8; 16];
    g[..8].copy_from_slice(&GLOBAL_PREFIX);
    g[8..].copy_from_slice(&ipv6::eui64_link_local(&OUR_MAC)[8..]);
    g
}

/// One frame off the wire, parsed.
#[derive(Clone)]
struct Sent {
    dst_mac: [u8; 6],
    src: [u8; 16],
    dst: [u8; 16],
    next: u8,
    hop: u8,
    payload: Vec<u8>,
    total: usize,
}

impl Sent {
    fn parse(f: &[u8]) -> Option<Sent> {
        if f.len() < 54 || u16::from_be_bytes([f[12], f[13]]) != 0x86DD {
            return None;
        }
        let len = u16::from_be_bytes([f[18], f[19]]) as usize;
        Some(Sent {
            dst_mac: f[0..6].try_into().unwrap(),
            src: f[22..38].try_into().unwrap(),
            dst: f[38..54].try_into().unwrap(),
            next: f[20],
            hop: f[21],
            payload: f[54..54 + len].to_vec(),
            total: f.len(),
        })
    }
    fn tcp_flags(&self) -> u8 { self.payload[13] }
    fn tcp_payload_len(&self) -> usize {
        self.payload.len() - ((self.payload[12] >> 4) as usize) * 4
    }
    fn tcp_options(&self) -> &[u8] {
        &self.payload[20..((self.payload[12] >> 4) as usize) * 4]
    }
    /// The MSS option, if the segment has one.
    fn mss(&self) -> Option<u16> {
        let o = self.tcp_options();
        let mut i = 0;
        while i + 1 < o.len() {
            match o[i] {
                0 => break,
                1 => i += 1,
                k => {
                    let l = o[i + 1] as usize;
                    if l < 2 || i + l > o.len() { break; }
                    if k == 2 && l == 4 { return Some(u16::from_be_bytes([o[i + 2], o[i + 3]])); }
                    i += l;
                }
            }
        }
        None
    }
}

/// Every frame the stack sent since `begin`, kept across the loopback.
static LOG: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

fn log_frames(frames: &[Vec<u8>]) {
    LOG.lock().unwrap().extend(frames.iter().cloned());
}

fn logged() -> Vec<Sent> {
    LOG.lock().unwrap().iter().filter_map(|f| Sent::parse(f)).collect()
}

/// Take the serial lock, clear the TCP table, the wire and the log, and bring
/// the IPv6 stack up from nothing (which sends the Router Solicitation).
fn begin() -> std::sync::MutexGuard<'static, ()> {
    let g = v4_begin();
    inbound::reset();
    ipv6::ipv6_init(&OUR_MAC);
    raw::reset();
    LOG.lock().unwrap().clear();
    g
}

/// Feed every IPv6 frame the stack sent back to it, until none is left.
/// Each pass is a poll pass: the ACKs it held leave when it ends, and the TCP
/// timers run, as the kernel's poller does.
fn pump() {
    for _ in 0..200 {
        let frames: Vec<Vec<u8>> = std::mem::take(&mut *raw::FRAMES.lock().unwrap());
        let v6: Vec<Vec<u8>> = frames.into_iter()
            .filter(|f| f.len() > 14 && f[12] == 0x86 && f[13] == 0xDD)
            .collect();
        if v6.is_empty() {
            return;
        }
        log_frames(&v6);
        for f in v6 {
            inbound::push_frame(f);
        }
        while !inbound::QUEUE.lock().unwrap().is_empty() {
            super::net_poll();
        }
        tcp::flush_held_acks(false);
        tcp::tcp_tick();
    }
    panic!("the loopback did not settle in 200 passes");
}

/// Deliver `frame` as one poll pass and return what the stack sent in answer.
fn inject(frame: Vec<u8>) -> Vec<Sent> {
    raw::reset();
    inbound::push_frame(frame);
    super::net_poll();
    tcp::flush_held_acks(false);
    let out = std::mem::take(&mut *raw::FRAMES.lock().unwrap());
    log_frames(&out);
    out.iter().filter_map(|f| Sent::parse(f)).collect()
}

// ── Handshake, data and close ────────────────────────────────────────────────

#[test]
fn a_v6_connection_opens_carries_data_both_ways_and_closes() {
    let _g = begin();
    let me = ipv6::ipv6_link_local();
    assert!(tcp::TcpHandle::listen6(7000).is_some(), "no slot for the listener");
    let c = tcp::TcpHandle::connect(me, 7000, 0).expect("connect");
    pump();
    assert!(c.state() == tcp::TcpState::Established, "the handshake did not finish");
    let s = tcp::TcpHandle::accept6(7000).expect("the accepted side");
    assert!(s.state() == tcp::TcpState::Established);
    assert!(tcp::TcpHandle::accept6(7000).is_none(), "one connection, accepted once");

    // 10 000 bytes one way: several full segments, so the MSS matters.
    let out: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    let mut sent = 0usize;
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    for _ in 0..2000 {
        if sent < out.len() {
            let n = c.send_data(&out[sent..]);
            assert!(n >= 0, "send failed at {sent}");
            sent += n as usize;
        }
        pump();
        loop {
            let n = s.recv(&mut buf);
            if n <= 0 { break; }
            got.extend_from_slice(&buf[..n as usize]);
        }
        if got.len() == out.len() { break; }
    }
    assert_eq!(got.len(), out.len(), "the stream did not arrive whole");
    assert!(got == out, "the stream arrived altered");

    // And 3 000 back.
    let back: Vec<u8> = (0..3_000u32).map(|i| (i % 241) as u8 ^ 0x5A).collect();
    let mut sent = 0usize;
    let mut got = Vec::new();
    for _ in 0..1000 {
        if sent < back.len() {
            let n = s.send_data(&back[sent..]);
            assert!(n >= 0);
            sent += n as usize;
        }
        pump();
        loop {
            let n = c.recv(&mut buf);
            if n <= 0 { break; }
            got.extend_from_slice(&buf[..n as usize]);
        }
        if got.len() == back.len() { break; }
    }
    assert!(got == back, "the reply stream did not arrive whole");

    // Close: the client's FIN, then the server's.
    c.close();
    pump();
    assert!(s.state() == tcp::TcpState::CloseWait);
    s.close();
    pump();
    assert!(s.state() == tcp::TcpState::Closed, "the passive side must be gone");
    assert!(
        matches!(c.state(), tcp::TcpState::TimeWait | tcp::TcpState::Closed),
        "the active side must have finished",
    );

    // What went on the wire: IPv6 only, to and from us, every checksum good,
    // inside the MTU, with segments no larger than the IPv6 MSS.
    assert_eq!(super::wire::sent_count(), 0, "no IPv4 frame for an IPv6 connection");
    let frames = logged();
    assert!(frames.len() > 20, "expected a real exchange, saw {} frames", frames.len());
    let mut biggest = 0;
    for f in &frames {
        assert_eq!(f.next, 6, "only TCP in this exchange");
        assert_eq!(f.src, me);
        assert_eq!(f.dst, me);
        assert_eq!(f.hop, 64);
        assert!(f.total <= 1514, "a {} byte frame does not fit the MTU", f.total);
        assert_eq!(
            ref_checksum(&f.src, &f.dst, 6, &f.payload), 0,
            "a segment left with a wrong IPv6 pseudo-header checksum",
        );
        biggest = biggest.max(f.tcp_payload_len());
    }
    // Both ends are this stack, so Timestamps are on when the build has them,
    // and their 12 octets come out of every segment's payload.
    let full = if azos_limits::TCP_TIMESTAMPS { 1440 - 12 } else { 1440 };
    assert_eq!(biggest, full, "full segments carry the IPv6 MSS, 1440, less the options");
    let syns: Vec<_> = frames.iter().filter(|f| f.tcp_flags() & SYN != 0).collect();
    assert_eq!(syns.len(), 2, "a SYN and a SYN-ACK");
    for f in syns {
        assert_eq!(f.mss(), Some(1440), "a SYN over IPv6 offers MSS 1440, not 1460");
    }
}

#[test]
fn a_v6_peer_with_a_small_mss_is_sent_segments_that_fit_it() {
    let _g = begin();
    let me = ipv6::ipv6_link_local();
    assert!(tcp::TcpHandle::listen6(7003).is_some());
    // SYN with MSS 1220 (Linux's value on a 1280 path).
    let syn = seg6(FE80_PEER, me, 40000, 7003, 1000, 0, SYN, &[2, 4, 0x04, 0xC4], &[]);
    let out = inject(syn);
    assert_eq!(out.len(), 1, "one SYN-ACK");
    let synack = &out[0];
    assert_eq!(synack.dst, FE80_PEER);
    assert_eq!(synack.src, me);
    assert_eq!(synack.tcp_flags(), SYN | ACK);
    assert_eq!(synack.mss(), Some(1440));
    assert_eq!(ref_checksum(&synack.src, &synack.dst, 6, &synack.payload), 0);
    let our_seq = u32::from_be_bytes(synack.payload[4..8].try_into().unwrap());

    let _ = inject(seg6(FE80_PEER, me, 40000, 7003, 1001, our_seq + 1, ACK, &[], &[]));
    let h = tcp::TcpHandle::accept6(7003).expect("accepted");
    assert!(h.state() == tcp::TcpState::Established);

    let data = vec![0xA5u8; 3000];
    raw::reset();
    let mut sent = 0;
    for _ in 0..8 {
        let n = h.send_data(&data[sent..]);
        assert!(n >= 0);
        sent += n as usize;
    }
    let frames: Vec<Sent> = raw::all().iter().filter_map(|f| Sent::parse(f)).collect();
    assert!(frames.len() >= 2);
    for f in &frames {
        assert!(f.tcp_payload_len() <= 1220, "a segment over the peer's MSS");
        assert_eq!(f.dst, FE80_PEER);
    }
    assert_eq!(frames[0].tcp_payload_len(), 1220);
}

#[test]
fn a_listener_takes_connections_of_its_own_family_only() {
    let _g = begin();
    let me = ipv6::ipv6_link_local();

    // An IPv6 listener: an IPv4 SYN to its port is refused with a reset.
    assert!(tcp::TcpHandle::listen6(7001).is_some());
    let syn4 = tcp_rx::segment(40001, 7001, 500, 0, SYN, 8192, &[]);
    tcp_rx::deliver(&syn4);
    let out = tcp_rx::outbound();
    assert_eq!(out.len(), 1);
    assert!(out[0].flags & RST != 0, "an IPv4 SYN to an IPv6 listener must be reset");
    assert_eq!(tcp_rx::count_in(tcp::TcpState::SynRcvd), 0);

    // An IPv4 listener: an IPv6 SYN to its port is refused the same way.
    assert!(tcp::listen(7002) >= 0);
    let out = inject(seg6(FE80_PEER, me, 40002, 7002, 700, 0, SYN, &[], &[]));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].tcp_flags() & RST, RST, "an IPv6 SYN to an IPv4 listener must be reset");
    assert_eq!(out[0].dst, FE80_PEER);
    assert_eq!(ref_checksum(&out[0].src, &out[0].dst, 6, &out[0].payload), 0);
    assert_eq!(tcp_rx::count_in(tcp::TcpState::SynRcvd), 0);
}

#[test]
fn accept_hands_each_family_its_own_connections_when_both_listen_on_one_port() {
    let _g = begin();
    let me = ipv6::ipv6_link_local();
    assert!(tcp::TcpHandle::listen6(7005).is_some());
    // An IPv4 peer completes a handshake on the same port number.
    let (_idx, _our, _peer) = tcp_rx::establish(7005, 41000, 9000);
    assert!(tcp::TcpHandle::accept6(7005).is_none(), "an IPv4 connection is not for an IPv6 socket");
    // An IPv6 peer does too.
    let out = inject(seg6(FE80_PEER, me, 41001, 7005, 100, 0, SYN, &[], &[]));
    let our_seq = u32::from_be_bytes(out[0].payload[4..8].try_into().unwrap());
    let _ = inject(seg6(FE80_PEER, me, 41001, 7005, 101, our_seq + 1, ACK, &[], &[]));
    let h = tcp::TcpHandle::accept6(7005).expect("the IPv6 connection");
    assert!(h.state() == tcp::TcpState::Established);
    assert!(tcp::TcpHandle::accept(7005).is_some(), "the IPv4 connection is still there for IPv4");
}

#[test]
fn a_v6_segment_that_is_not_for_us_or_does_not_verify_opens_nothing() {
    let _g = begin();
    let me = ipv6::ipv6_link_local();
    assert!(tcp::TcpHandle::listen6(7004).is_some());

    // A bad checksum is dropped without a word.
    let mut bad = seg6(FE80_PEER, me, 40004, 7004, 1, 0, SYN, &[], &[]);
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    bad[14 + 40 + 16] ^= 0xFF;
    assert!(inject(bad).is_empty(), "a segment with a wrong checksum draws no answer");
    assert_eq!(tcp_rx::count_in(tcp::TcpState::SynRcvd), 0);

    // To a multicast group: TCP is for unicast addresses only.
    let group = ipv6::MCAST_ALL_NODES;
    let to_group = seg6(FE80_PEER, group, 40005, 7004, 1, 0, SYN, &[], &[]);
    assert!(inject(to_group).is_empty());
    assert_eq!(tcp_rx::count_in(tcp::TcpState::SynRcvd), 0);

    // To an address that is not ours.
    let other = addr(0xFE80, 0, 0, 0, 0, 0, 0, 0x77);
    assert!(inject(seg6(FE80_PEER, other, 40006, 7004, 1, 0, SYN, &[], &[])).is_empty());
    assert_eq!(tcp_rx::count_in(tcp::TcpState::SynRcvd), 0);

    // The same SYN, well formed and to us, is taken.
    let out = inject(seg6(FE80_PEER, me, 40007, 7004, 1, 0, SYN, &[], &[]));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].tcp_flags(), SYN | ACK);
}

// ── SLAAC ────────────────────────────────────────────────────────────────────

fn ra_with_prefix(valid: u32, preferred: u32) -> Vec<u8> {
    let mut o = slla(ROUTER_MAC);
    o.extend(pio(64, 0xC0, valid, preferred, GLOBAL_PREFIX));
    ra_frame(FE80_ROUTER, 255, 1800, &o)
}

#[test]
fn init_solicits_routers_and_an_advertisement_configures_a_global_address() {
    let _g = v4_begin();
    inbound::reset();
    raw::reset();
    ipv6::ipv6_init(&OUR_MAC);
    // The Router Solicitation, byte by byte.
    let rs = raw::all();
    assert_eq!(rs.len(), 1, "ipv6_init sends exactly one Router Solicitation");
    let f = Sent::parse(&rs[0]).expect("an IPv6 frame");
    assert_eq!(f.dst_mac, [0x33, 0x33, 0, 0, 0, 0x02], "FF02::2's multicast MAC");
    assert_eq!(f.dst, ipv6::MCAST_ALL_ROUTERS);
    assert_eq!(f.src, ipv6::eui64_link_local(&OUR_MAC));
    assert_eq!(f.next, 58);
    assert_eq!(f.hop, 255, "RFC 4861: neighbour discovery is sent with hop limit 255");
    assert_eq!(f.payload[0], 133);
    assert_eq!(&f.payload[8..16], &slla(OUR_MAC)[..], "our MAC as the source link-layer option");
    assert_eq!(ref_checksum(&f.src, &f.dst, 58, &f.payload), 0);

    assert_eq!(ipv6::ipv6_global(), None, "no address before an advertisement");
    // And so no way to reach a global destination: a packet from fe80:: to a
    // global address is one no router forwards.
    let far = addr(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 9);
    assert_eq!(ipv6::ipv6_source_for(&far), None);
    assert!(tcp::TcpHandle::connect(far, 80, 0).is_none(), "no global address, no connection");
    assert!(!ipv6::udpv6_send(&far, 1000, 2000, b"x"));
    assert_eq!(raw::count(), 1, "only the Router Solicitation is on the wire");
    let before = ipv6::eui64_link_local(&OUR_MAC);
    assert!(!ipv6::is_our_addr(&our_global()));

    inbound::push_frame(ra_with_prefix(3600, 1800));
    super::net_poll();
    assert_eq!(ipv6::ipv6_global(), Some(our_global()), "prefix + our interface id");
    assert_eq!(&our_global()[..8], &GLOBAL_PREFIX);
    assert_eq!(&our_global()[8..], &before[8..]);
    assert!(ipv6::is_our_addr(&our_global()));
    assert!(ipv6::is_our_addr(&before), "the link-local address stays");
    assert_eq!(
        ipv6::ipv6_source_for(&addr(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 9)), Some(our_global()),
        "a global destination is reached from the global address",
    );
    assert_eq!(ipv6::ipv6_source_for(&FE80_PEER), Some(before), "a link-local one from the link-local");
}

#[test]
fn an_advertisement_that_could_not_come_from_this_link_changes_nothing() {
    let _g = v4_begin();
    inbound::reset();
    ipv6::ipv6_init(&OUR_MAC);
    raw::reset();
    let mut o = slla(ROUTER_MAC);
    o.extend(pio(64, 0xC0, 3600, 1800, GLOBAL_PREFIX));

    // Hop limit 64: it crossed a router.
    inbound::push_frame(ra_frame(FE80_ROUTER, 64, 1800, &o));
    // Not from a link-local address.
    inbound::push_frame(ra_frame(addr(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 255, 1800, &o));
    // A /48 prefix is not for SLAAC.
    let mut o48 = slla(ROUTER_MAC);
    o48.extend(pio(48, 0xC0, 3600, 1800, GLOBAL_PREFIX));
    inbound::push_frame(ra_frame(FE80_ROUTER, 255, 1800, &o48));
    // No autonomous flag.
    let mut onoa = slla(ROUTER_MAC);
    onoa.extend(pio(64, 0x80, 3600, 1800, GLOBAL_PREFIX));
    inbound::push_frame(ra_frame(FE80_ROUTER, 255, 1800, &onoa));
    // A link-local prefix.
    let mut oll = slla(ROUTER_MAC);
    oll.extend(pio(64, 0xC0, 3600, 1800, [0xFE, 0x80, 0, 0, 0, 0, 0, 0]));
    inbound::push_frame(ra_frame(FE80_ROUTER, 255, 1800, &oll));
    // Preferred beyond valid.
    let mut opv = slla(ROUTER_MAC);
    opv.extend(pio(64, 0xC0, 100, 200, GLOBAL_PREFIX));
    inbound::push_frame(ra_frame(FE80_ROUTER, 255, 1800, &opv));
    // An option of length 0 discards the whole advertisement.
    let mut ozero = slla(ROUTER_MAC);
    ozero.extend_from_slice(&[7, 0, 0, 0, 0, 0, 0, 0]);
    ozero.extend(pio(64, 0xC0, 3600, 1800, GLOBAL_PREFIX));
    inbound::push_frame(ra_frame(FE80_ROUTER, 255, 1800, &ozero));
    // A wrong ICMPv6 checksum.
    let mut badsum = ra_with_prefix(3600, 1800);
    badsum[14 + 40 + 2] ^= 0xFF;
    inbound::push_frame(badsum);

    super::net_poll();
    assert_eq!(ipv6::ipv6_global(), None, "none of these may configure an address");

    // And the canary: the well-formed one does.
    inbound::push_frame(ra_with_prefix(3600, 1800));
    super::net_poll();
    assert_eq!(ipv6::ipv6_global(), Some(our_global()));
}

#[test]
fn the_global_address_answers_ping_and_neighbour_solicitation_from_itself() {
    let _g = v4_begin();
    inbound::reset();
    ipv6::ipv6_init(&OUR_MAC);
    inbound::push_frame(ra_with_prefix(3600, 1800));
    super::net_poll();
    let g = our_global();

    // Echo request to the global address: the reply comes from it.
    raw::reset();
    let mut echo = vec![128, 0, 0, 0, 0x12, 0x34, 0, 1];
    echo.extend_from_slice(b"ping6");
    let out = inject(frame6(OUR_MAC, FE80_PEER, g, 58, 64, echo, 2));
    assert_eq!(out.len(), 1, "one echo reply");
    assert_eq!(out[0].payload[0], 129);
    assert_eq!(out[0].src, g, "answered from the address that was pinged");
    assert_eq!(ref_checksum(&out[0].src, &out[0].dst, 58, &out[0].payload), 0);

    // Neighbour solicitation for the global address: advertised as itself.
    let mut ns = vec![135, 0, 0, 0, 0, 0, 0, 0];
    ns.extend_from_slice(&g);
    ns.extend(slla(PEER_MAC));
    let out = inject(frame6(OUR_MAC, FE80_PEER, g, 58, 255, ns, 2));
    assert_eq!(out.len(), 1, "one neighbour advertisement");
    assert_eq!(out[0].payload[0], 136);
    assert_eq!(&out[0].payload[8..24], &g, "the target is the address solicited");
    assert_eq!(out[0].src, g);
    assert_eq!(out[0].dst_mac, PEER_MAC, "unicast to the solicitor's link-layer address");
}

#[test]
fn a_refresh_cannot_shorten_a_long_lifetime_below_two_hours() {
    let _g = v4_begin();
    inbound::reset();
    ipv6::ipv6_init(&OUR_MAC);
    azos_drv_irqchip::clint::set_test_time(10_000);
    inbound::push_frame(ra_with_prefix(100_000, 50_000));
    let t0 = azos_drv_sys::timebase::now();
    super::net_poll();
    assert_eq!(ipv6::ipv6_global(), Some(our_global()));
    // A forged refresh of the same prefix with a valid lifetime of 10 s.
    inbound::push_frame(ra_with_prefix(10, 5));
    super::net_poll();
    azos_drv_irqchip::clint::set_test_time(t0 + 3600 * TICKS_PER_S);
    assert_eq!(ipv6::ipv6_global(), Some(our_global()), "still valid an hour later");
    azos_drv_irqchip::clint::set_test_time(t0 + 3 * 3600 * TICKS_PER_S);
    assert_eq!(ipv6::ipv6_global(), None, "capped at two hours, not kept for 27");
    azos_drv_irqchip::clint::set_test_time(t0 + 1000);
}

#[test]
fn off_link_traffic_goes_to_the_router_and_local_traffic_does_not() {
    let _g = begin();
    // Router known, prefix on-link.
    inbound::push_frame(ra_with_prefix(3600, 1800));
    super::net_poll();
    raw::reset();

    // Off-link destination, from the global address, to the router's MAC.
    let far = addr(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 9);
    let h = tcp::TcpHandle::connect(far, 80, 0).expect("connect");
    let _ = h;
    let out: Vec<Sent> = raw::all().iter().filter_map(|f| Sent::parse(f)).collect();
    assert_eq!(out.len(), 1, "the SYN");
    assert_eq!(out[0].dst_mac, ROUTER_MAC, "off-link: to the default router");
    assert_eq!(out[0].src, our_global());
    assert_eq!(out[0].dst, far);
    assert_eq!(out[0].tcp_flags() & !(0x40 | 0x80), SYN, "a SYN, ECN-setup or not");
    assert_eq!(out[0].mss(), Some(1440));
    assert_eq!(ref_checksum(&out[0].src, &out[0].dst, 6, &out[0].payload), 0);

    // Link-local destination: the link itself, not the router.
    raw::reset();
    let _ = tcp::TcpHandle::connect(FE80_PEER, 81, 0).expect("connect");
    let out: Vec<Sent> = raw::all().iter().filter_map(|f| Sent::parse(f)).collect();
    assert_eq!(out.len(), 1);
    assert_ne!(out[0].dst_mac, ROUTER_MAC);
    assert_eq!(out[0].src, ipv6::eui64_link_local(&OUR_MAC), "scoped destination, scoped source");

    // An on-link global neighbour: no neighbour cache, so the link broadcast.
    raw::reset();
    let mut near = GLOBAL_PREFIX.to_vec();
    near.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 5]);
    let near: [u8; 16] = near.try_into().unwrap();
    let _ = tcp::TcpHandle::connect(near, 82, 0).expect("connect");
    let out: Vec<Sent> = raw::all().iter().filter_map(|f| Sent::parse(f)).collect();
    assert_eq!(out.len(), 1);
    assert_ne!(out[0].dst_mac, ROUTER_MAC, "an on-link host is not reached through the router");

    // Router lifetime 0: the router is gone.
    inbound::push_frame(ra_frame(FE80_ROUTER, 255, 0, &[]));
    super::net_poll();
    raw::reset();
    let _ = tcp::TcpHandle::connect(addr(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 10), 83, 0)
        .expect("connect");
    let out: Vec<Sent> = raw::all().iter().filter_map(|f| Sent::parse(f)).collect();
    assert_eq!(out.len(), 1);
    assert_ne!(out[0].dst_mac, ROUTER_MAC, "a router with lifetime 0 is not a router");
}

// ── AAAA ─────────────────────────────────────────────────────────────────────

/// A response to a query for `www.example.com` AAAA (id 0xBEEF), RFC 3596:
/// the question echoed, then `www.example.com. 3600 IN AAAA 2001:db8::1`
/// with the name as a pointer to the question.
///
/// ```text
/// header  BE EF 81 80 | 00 01 | 00 01 | 00 00 | 00 00
/// off 12  03 www 07 example 03 com 00 | 00 1C (AAAA) | 00 01 (IN)      to 33
/// off 33  C0 0C | 00 1C | 00 01 | 00 00 0E 10 | 00 10 | 16 octets      to 61
/// ```
const RESPONSE_AAAA: [u8; 61] = [
    0xBE, 0xEF, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
    0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x1C, 0x00, 0x01,
    0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x10,
    0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
];
const AAAA_2001_DB8_1: [u8; 16] = addr(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

#[test]
fn an_aaaa_response_yields_the_ipv6_address_and_only_for_an_aaaa_question() {
    assert_eq!(super::dns::parse_response_aaaa(&RESPONSE_AAAA, 0xBEEF), Some(AAAA_2001_DB8_1));
    assert_eq!(super::dns::parse_response_aaaa(&RESPONSE_AAAA, 0xBEEE), None, "another id");
    // The A parser does not take an AAAA record as an address: the type
    // decides, not the rdata's shape.
    assert_eq!(super::dns::parse_response(&RESPONSE_AAAA, 0xBEEF), None);
    // Nor the AAAA parser an A record.
    let mut a = RESPONSE_AAAA;
    a[29..31].copy_from_slice(&1u16.to_be_bytes());
    a[35..37].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(super::dns::parse_response_aaaa(&a, 0xBEEF), None);
}

#[test]
fn a_truncated_or_misshapen_aaaa_record_is_refused() {
    for n in 0..RESPONSE_AAAA.len() {
        assert_eq!(
            super::dns::parse_response_aaaa(&RESPONSE_AAAA[..n], 0xBEEF), None,
            "{n} octets cannot hold all 16 of the rdata",
        );
    }
    // RDLENGTH 4 on an AAAA record: not an IPv6 address.
    let mut short = RESPONSE_AAAA;
    short[43..45].copy_from_slice(&4u16.to_be_bytes());
    assert_eq!(super::dns::parse_response_aaaa(&short, 0xBEEF), None);
    // RDLENGTH 20: not either.
    let mut long = RESPONSE_AAAA;
    long[43..45].copy_from_slice(&20u16.to_be_bytes());
    assert_eq!(super::dns::parse_response_aaaa(&long, 0xBEEF), None);
    // RCODE 3 (NXDOMAIN) decides, with the record still attached.
    let mut nx = RESPONSE_AAAA;
    nx[3] = 0x83;
    assert_eq!(super::dns::parse_response_aaaa(&nx, 0xBEEF), None);
}

#[test]
fn a_cname_before_the_aaaa_record_is_stepped_over() {
    let resp: [u8; 75] = [
        0xBE, 0xEF, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
        0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x1C, 0x00, 0x01,
        0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x02,
        0xC0, 0x10,
        0xC0, 0x10, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x10,
        0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    assert_eq!(super::dns::parse_response_aaaa(&resp, 0xBEEF), Some(AAAA_2001_DB8_1));
}

const DNS_SERVER_IP: [u8; 4] = [10, 0, 0, 53];

/// The far end: answer the newest query for port 53 with an AAAA record.
fn answer_aaaa() {
    let q = super::wire::sent().into_iter().rev().find(|s| {
        s.proto == 17 && s.dst_ip == DNS_SERVER_IP && s.payload.len() > 8 + 12
            && s.payload[2..4] == [0x00, 0x35]
    });
    let Some(q) = q else { return };
    let (sport, dns) = (u16::from_be_bytes([q.payload[0], q.payload[1]]), &q.payload[8..]);
    let qtype = u16::from_be_bytes([dns[dns.len() - 4], dns[dns.len() - 3]]);
    let mut d = Vec::new();
    d.extend_from_slice(&dns[0..2]);
    d.extend_from_slice(&0x8180u16.to_be_bytes());
    d.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
    d.extend_from_slice(&dns[12..]);
    d.extend_from_slice(&[0xC0, 0x0C]);
    d.extend_from_slice(&qtype.to_be_bytes());
    d.extend_from_slice(&1u16.to_be_bytes());
    d.extend_from_slice(&60u32.to_be_bytes());
    if qtype == 28 {
        d.extend_from_slice(&16u16.to_be_bytes());
        d.extend_from_slice(&AAAA_2001_DB8_1);
    } else {
        d.extend_from_slice(&4u16.to_be_bytes());
        d.extend_from_slice(&[93, 184, 216, 34]);
    }
    let mut u = Vec::new();
    u.extend_from_slice(&53u16.to_be_bytes());
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&((8 + d.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(&d);
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&((20 + u.len()) as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&DNS_SERVER_IP);
    p[16..20].copy_from_slice(&super::net_get_ip());
    let ck = super::ip::checksum(&p[..20]);
    p[10..12].copy_from_slice(&ck.to_be_bytes());
    p.extend_from_slice(&u);
    inbound::push_ipv4(&p);
}

#[test]
fn resolve_aaaa_asks_for_type_28_and_caches_apart_from_the_a_record() {
    let _g = super::NET_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    inbound::reset();
    raw::reset();
    azos_drv_irqchip::clint::set_test_time(900_000);
    super::arp::insert(DNS_SERVER_IP, [0x02, 0x35, 0x35, 0x35, 0x35, 0x35]);
    super::dns::set_dns_server(DNS_SERVER_IP);
    inbound::on_poll(answer_aaaa);

    let host = "aaaa.example.test";
    assert_eq!(super::dns::resolve_aaaa_with_yield(host, core::hint::spin_loop), Some(AAAA_2001_DB8_1));
    let queries = |t: u16| super::wire::sent().iter().filter(|s| {
        s.proto == 17 && s.dst_ip == DNS_SERVER_IP && s.payload.len() > 8 + 12
            && s.payload[2..4] == [0x00, 0x35]
            && s.payload[s.payload.len() - 4..s.payload.len() - 2] == t.to_be_bytes()
    }).count();
    assert_eq!(queries(28), 1, "one AAAA query on the wire");
    assert_eq!(queries(1), 0);

    // Cached: no second query.
    assert_eq!(super::dns::resolve_aaaa_with_yield(host, core::hint::spin_loop), Some(AAAA_2001_DB8_1));
    assert_eq!(queries(28), 1, "the answer is cached");

    // The A record of the same name is a separate question: it goes out, and
    // its answer is the A address, not the cached AAAA.
    assert_eq!(super::dns::resolve_with_yield(host, core::hint::spin_loop), Some([93, 184, 216, 34]));
    assert_eq!(queries(1), 1, "an A query for the same name still goes out");
    inbound::reset();
}

// ── Sockets ──────────────────────────────────────────────────────────────────

#[test]
fn an_af_inet6_stream_socket_listens_accepts_connects_sends_and_closes() {
    use super::socket::*;
    let _g = begin();
    let me = ipv6::ipv6_link_local();
    for fd in 0..MAX_SOCKETS { socket_close(fd as i32); }

    assert_eq!(socket_create(AF_INET6, SOCK_DGRAM, 0), -1, "no datagram sockets over IPv6");
    assert_eq!(socket_create(AF_INET6 + 100, SOCK_STREAM, 0), -1);

    let l = socket_create(AF_INET6, SOCK_STREAM, 0);
    assert!(l >= 0);
    // Bind refuses an address that is not ours, and a v4-only call on it.
    let mut a = SockAddr6 { port: 7100, addr: FE80_PEER };
    assert_eq!(socket_bind6(l, &a), -1, "bound to somebody else's address");
    a.addr = [0; 16];
    assert_eq!(socket_bind6(l, &a), 0);
    assert_eq!(socket_listen_bound(l), 0);

    let c = socket_create(AF_INET6, SOCK_STREAM, 0);
    // A v4 socket cannot dial v6, a v6 socket cannot dial v4.
    let v4 = socket_create(AF_INET, SOCK_STREAM, 0);
    let to = SockAddr6 { port: 7100, addr: me };
    assert_eq!(socket_connect6_with_yield(v4, &to, 0, || {}), -1,
        "an AF_INET socket does not connect over IPv6");
    let to4 = SockAddr { family: AF_INET as u16, port: 80, addr: [10, 0, 0, 9] };
    assert_eq!(socket_connect(c, &to4, 0), -1, "an AF_INET6 socket does not connect over IPv4");
    assert_eq!(socket_bind6(v4, &a), -1, "bind6 is for AF_INET6 sockets");
    socket_close(v4);

    assert_eq!(socket_accept(l), -1, "nobody has dialled yet");
    assert_eq!(socket_connect6_with_yield(c, &to, 0, pump), 0, "the handshake must complete");
    let s = socket_accept(l);
    assert!(s >= 0, "accept must hand out the connection");
    assert_eq!(socket_accept(l), -1, "only once");

    assert_eq!(socket_send(c, b"hello over v6"), 13);
    pump();
    let mut buf = [0u8; 64];
    assert_eq!(socket_recv(s, &mut buf), 13);
    assert_eq!(&buf[..13], b"hello over v6");
    assert_eq!(socket_send(s, b"and back"), 8);
    pump();
    assert_eq!(socket_recv(c, &mut buf), 8);
    assert_eq!(&buf[..8], b"and back");

    // The listener of the other family does not see this port.
    assert!(tcp::TcpHandle::accept(7100).is_none());

    socket_close(c);
    pump();
    socket_close(s);
    pump();
    socket_close(l);
    for fd in 0..MAX_SOCKETS { socket_close(fd as i32); }
    assert_eq!(super::wire::sent_count(), 0, "no IPv4 frame");
    assert!(logged().iter().all(|f| ref_checksum(&f.src, &f.dst, f.next, &f.payload) == 0));
}

#[test]
fn a_v6_connect_to_a_dead_peer_gives_up_and_frees_the_slot() {
    use super::socket::*;
    let _g = begin();
    for fd in 0..MAX_SOCKETS { socket_close(fd as i32); }
    // A RST from the peer ends the wait at once: the yield plays the peer.
    let c = socket_create(AF_INET6, SOCK_STREAM, 0);
    let to = SockAddr6 { port: 9, addr: FE80_PEER };
    fn reset_it() {
        let syn = raw::all().iter().filter_map(|f| Sent::parse(f)).find(|f| f.tcp_flags() == SYN);
        let Some(syn) = syn else { return };
        raw::reset();
        let seq = u32::from_be_bytes(syn.payload[4..8].try_into().unwrap());
        let sp = u16::from_be_bytes([syn.payload[0], syn.payload[1]]);
        let rst = seg6(FE80_PEER, syn.src, 9, sp, 0, seq + 1, RST | ACK, &[], &[]);
        inbound::push_frame(rst);
        super::net_poll();
    }
    assert_eq!(socket_connect6_with_yield(c, &to, 0, reset_it), -1);
    assert_eq!(tcp_rx::count_in(tcp::TcpState::SynSent), 0, "the slot is free again");
    socket_close(c);
}

// ── The packet filter on the IPv6 path ───────────────────────────────────────
//
// `filter.rs` judges IPv6 at the ingress hook (`ipv6_rx`) and the egress hook
// (`ipv6::emit_to`, the Router Solicitation), with the IPv4 path's rules, flow
// table and refusal records. Each refusal below has its mirror, the same
// packet with no filter or an admitting row drawing the answer the refusal
// removes; the canary `fw-ipv6-canary` (IPv6 skips the hooks, the code before
// the filter covered it) turns every refusal red.

use super::filter::{self, Firewall, FwRule, Hook, Verdict};

/// Takes the filter off the stack on the way out, whatever the test did.
struct Unfiltered;

impl Drop for Unfiltered {
    fn drop(&mut self) {
        filter::reset_for_test();
    }
}

/// Install a built-in firewall with `inbound` and `rules`, for the rest of the
/// test (leaked: the filter seam keeps a `'static`).
fn firewall(inbound: Verdict, rules: &[FwRule]) -> Unfiltered {
    filter::reset_for_test();
    let fw: &'static Firewall = Box::leak(Box::new(Firewall::new()));
    assert_eq!(fw.load(inbound, rules.iter().copied(), 0x5EED_0006), Some(rules.len()));
    filter::set_filter(fw);
    Unfiltered
}

/// A row for an IPv6 prefix (`len` 0: any address of either family).
fn rule6(hook: Hook, proto: u8, port: u16, net: [u8; 16], len: u8, action: Verdict) -> FwRule {
    FwRule { hook, proto, port_lo: port, port_hi: port, net, net_len: len, net_v6: len != 0, action }
}

fn echo_to(dst: [u8; 16]) -> Vec<u8> {
    let mut echo = vec![128, 0, 0, 0, 0x12, 0x34, 0, 1];
    echo.extend_from_slice(b"fw6");
    frame6(OUR_MAC, FE80_PEER, dst, 58, 64, echo, 2)
}

fn ns_for(target: [u8; 16]) -> Vec<u8> {
    let mut ns = vec![135, 0, 0, 0, 0, 0, 0, 0];
    ns.extend_from_slice(&target);
    ns.extend(slla(PEER_MAC));
    frame6(OUR_MAC, FE80_PEER, target, 58, 255, ns, 2)
}

/// Packet-refused records written since `first_seq`.
fn refusals_since(first_seq: u64) -> Vec<azos_decision::Record> {
    let mut v = Vec::new();
    azos_decision::for_each(|r| {
        if r.seq >= first_seq && r.rule == azos_decision::Rule::PacketRefused as u8 {
            v.push(*r);
        }
    });
    v
}

#[test]
fn a_gateway_drops_v6_echo_and_syn_while_slaac_and_neighbour_discovery_still_work() {
    let _g = begin();
    let me = ipv6::ipv6_link_local();

    // Mirror first, no filter: the echo is answered, a SYN to a closed port reset.
    assert_eq!(inject(echo_to(me)).iter().filter(|s| s.payload[0] == 129).count(), 1);
    let syn = seg6(FE80_PEER, me, 40100, 23, 1, 0, SYN, &[], &[]);
    assert!(inject(syn.clone()).iter().any(|s| s.next == 6 && s.tcp_flags() & RST != 0));

    let _fw = firewall(Verdict::Drop, &[]);
    let before = azos_decision::total() + 1;
    let refused = filter::stats().refused;

    // SLAAC under the inbound default: the advertisement is taken...
    assert!(inject(ra_with_prefix(3600, 1800)).is_empty());
    assert_eq!(ipv6::ipv6_global(), Some(our_global()), "the Router Advertisement passed");
    // ...and a solicitation for the new address is answered.
    let out = inject(ns_for(our_global()));
    assert_eq!(out.len(), 1, "the Neighbour Solicitation passed and the advertisement left");
    assert_eq!((out[0].payload[0], out[0].src), (136, our_global()));
    assert_eq!(filter::stats().refused, refused, "Neighbour Discovery is not refused");

    // The echo and the SYN are dropped without a word.
    assert!(inject(echo_to(me)).is_empty(), "echo_refused");
    assert!(inject(syn).is_empty(), "syn_refused");
    assert_eq!(filter::stats().refused, refused + 2);

    // Recorded as IPv6: the last four bytes of each address, bit 32 of n[1].
    let r = refusals_since(before);
    assert_eq!(r.len(), 2);
    let word = |a: &[u8; 16]| u32::from_be_bytes(a[12..16].try_into().unwrap());
    let meta = |p: u8, sp: u64, dp: u64| {
        (Hook::Ingress as u64) << 56 | (Verdict::Drop as u64) << 48 | (p as u64) << 40 | 1 << 32 | sp << 16 | dp
    };
    assert_eq!(r[0].subject, word(&FE80_PEER));
    assert_eq!(r[0].n, [(word(&FE80_PEER) as u64) << 32 | word(&me) as u64, meta(58, 0, 0), 0]);
    assert_eq!(r[1].n[1], meta(6, 40100, 23));
}

#[test]
fn neighbour_discovery_passes_the_default_only_with_hop_limit_255_and_a_row_still_decides() {
    let _g = begin();
    let me = ipv6::ipv6_link_local();
    let _fw = firewall(Verdict::Drop, &[]);
    // Hop limit 64: not from this link. `ipv6_rx` discards it before the
    // filter is asked, so it is not counted as a refusal either.
    let mut ns = vec![135, 0, 0, 0, 0, 0, 0, 0];
    ns.extend_from_slice(&me);
    ns.extend(slla(PEER_MAC));
    let refused = filter::stats().refused;
    assert!(inject(frame6(OUR_MAC, FE80_PEER, me, 58, 64, ns, 2)).is_empty());
    assert_eq!(filter::stats().refused, refused, "the filter was not asked about an off-link ND message");
    assert_eq!(inject(ns_for(me)).len(), 1, "the same solicitation at hop limit 255 is answered");

    // A row for ICMP (no prefix: both families, ICMPv6 here) is asked first.
    let _fw = firewall(Verdict::Drop, &[rule6(Hook::Ingress, super::ip::IP_PROTO_ICMP, 0, [0; 16], 0, Verdict::Drop)]);
    assert!(inject(ns_for(me)).is_empty(), "a row that drops ICMP drops Neighbour Discovery too");
    // And one that admits ICMP admits the echo the default drops.
    let _fw = firewall(Verdict::Drop, &[rule6(Hook::Ingress, super::ip::IP_PROTO_ICMP, 0, [0; 16], 0, Verdict::Accept)]);
    assert_eq!(inject(echo_to(me)).iter().filter(|s| s.payload[0] == 129).count(), 1);
}

#[test]
fn a_v6_row_admits_its_port_from_its_prefix_and_a_v4_row_does_not_match_v6() {
    let _g = begin();
    let me = ipv6::ipv6_link_local();
    assert!(tcp::TcpHandle::listen6(7010).is_some());
    let fe80 = addr(0xFE80, 0, 0, 0, 0, 0, 0, 0);
    // The IPv4 row names 254.128.0.0/16, the first bytes of fe80::: a family
    // confusion would let it admit the IPv6 SYN.
    let mut v4 = [0u8; 16];
    v4[..2].copy_from_slice(&[0xFE, 0x80]);
    let v4_row = FwRule { hook: Hook::Ingress, proto: 6, port_lo: 7010, port_hi: 7010, net: v4, net_len: 16, net_v6: false, action: Verdict::Accept };
    let _fw = firewall(Verdict::Drop, &[v4_row]);
    assert!(inject(seg6(FE80_PEER, me, 40110, 7010, 1, 0, SYN, &[], &[])).is_empty(), "v4_row_admitted_v6");

    let _fw = firewall(Verdict::Drop, &[rule6(Hook::Ingress, 6, 7010, fe80, 64, Verdict::Accept)]);
    let out = inject(seg6(FE80_PEER, me, 40111, 7010, 1, 0, SYN, &[], &[]));
    assert_eq!((out.len(), out[0].tcp_flags()), (1, SYN | ACK), "the row admits the SYN");
    // The prefix is matched: from another /64 the default applies.
    let far = addr(0x2001, 0xdb8, 0, 9, 0, 0, 0, 9);
    assert!(inject(seg6(far, me, 40112, 7010, 1, 0, SYN, &[], &[])).is_empty());
}

#[test]
fn a_v6_reject_answers_icmpv6_administratively_prohibited_quoting_the_packet() {
    let _g = begin();
    let me = ipv6::ipv6_link_local();
    let _fw = firewall(Verdict::Accept, &[rule6(Hook::Ingress, 6, 23, [0; 16], 0, Verdict::Reject)]);
    let syn = seg6(FE80_PEER, me, 40120, 23, 7, 0, SYN, &[], &[]);
    let out = inject(syn.clone());
    assert_eq!(out.len(), 1, "one answer, and no RST");
    let e = &out[0];
    assert_eq!((e.next, e.payload[0], e.payload[1]), (58, 1, 1), "Destination Unreachable, administratively prohibited");
    assert_eq!((e.src, e.dst), (me, FE80_PEER));
    assert_eq!(ref_checksum(&e.src, &e.dst, 58, &e.payload), 0);
    assert_eq!(&e.payload[8..], &syn[14..], "the whole offending packet is quoted");

    // Never about an ICMPv6 message.
    let _fw = firewall(Verdict::Accept, &[rule6(Hook::Ingress, 58, 0, [0; 16], 0, Verdict::Reject)]);
    assert!(inject(echo_to(me)).is_empty());
}

#[test]
fn an_outbound_v6_flow_is_answered_through_the_inbound_drop_and_a_stranger_is_not() {
    let _g = begin();
    let _fw = firewall(Verdict::Drop, &[]);
    let c = tcp::TcpHandle::connect(FE80_PEER, 80, 0).expect("connect");
    let syn = raw::all().iter().filter_map(|f| Sent::parse(f)).find(|f| f.next == 6 && f.tcp_flags() & (SYN | ACK) == SYN);
    let syn = syn.expect("the SYN left: outbound is accepted");
    let sp = u16::from_be_bytes([syn.payload[0], syn.payload[1]]);
    let seq = u32::from_be_bytes(syn.payload[4..8].try_into().unwrap());
    // A stranger on another port is not the flow.
    let stranger = seg6(FE80_PEER, syn.src, 81, sp, 500, seq + 1, SYN | ACK, &[], &[]);
    assert!(inject(stranger).is_empty(), "stranger_admitted");
    // The peer's answer passes, and the handshake ends.
    let out = inject(seg6(FE80_PEER, syn.src, 80, sp, 500, seq + 1, SYN | ACK, &[], &[]));
    assert!(out.iter().any(|s| s.tcp_flags() == ACK), "the answer passed and was acknowledged");
    assert!(c.state() == tcp::TcpState::Established);
}

#[test]
fn an_outbound_v6_row_drops_or_rejects_what_the_stack_sends() {
    let _g = begin();
    let fe80 = addr(0xFE80, 0, 0, 0, 0, 0, 0, 0);
    let sent = || raw::all().iter().filter_map(|f| Sent::parse(f)).filter(|s| s.next == 17).count();

    raw::reset();
    assert!(ipv6::udpv6_send(&FE80_PEER, 5000, 53, b"q"), "mirror: no filter");
    assert_eq!(sent(), 1);

    let _fw = firewall(Verdict::Accept, &[rule6(Hook::Egress, 17, 53, fe80, 10, Verdict::Drop)]);
    raw::reset();
    assert!(ipv6::udpv6_send(&FE80_PEER, 5000, 53, b"q"), "a drop reads as sent");
    assert_eq!(sent(), 0, "egress_dropped");

    let _fw = firewall(Verdict::Accept, &[rule6(Hook::Egress, 17, 53, fe80, 10, Verdict::Reject)]);
    raw::reset();
    assert!(!ipv6::udpv6_send(&FE80_PEER, 5000, 53, b"q"), "a reject is the caller's error");
    assert_eq!(sent(), 0, "egress_rejected");
    // Another port is not the row's.
    assert!(ipv6::udpv6_send(&FE80_PEER, 5000, 54, b"q"));
    assert_eq!(sent(), 1);
}
