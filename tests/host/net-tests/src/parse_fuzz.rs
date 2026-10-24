// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Hostile-input tests for the link and application parsers that read bytes a
//! stranger on the segment (or a compromised server) chooses: ARP, IGMP, DHCP,
//! DNS, NTP and the ICMPv6 Neighbour Discovery options.
//!
//! Each parser gets the same three kinds of input:
//!
//! * **hand-crafted** malformed packets, one per defect (truncated at every
//!   length, an oversized length field, a compression loop, a zero-length
//!   option, a wrong fixed field), each asserted REFUSED;
//! * a **positive control** next to them, so a rejection cannot pass on a
//!   parser that refuses everything;
//! * **seeded random** packets (bit flips, truncations, tails, `0xFFFF`
//!   fields over a valid packet, and pure noise) that must never panic and
//!   whose every accepted result must satisfy the parser's own invariant.
//!
//! Deterministic: the generator is a fixed-seed xorshift, so a failure names
//! its iteration and reproduces. With `panic = "abort"` in the kernel a
//! reachable panic in any of these is a board reset an attacker can trigger.
//!
//! Checksums here are computed by `ocsum` below, never by the kernel's own
//! functions: verifying the kernel's checksum with the kernel's checksum
//! proves only that it agrees with itself.

use crate::NET_SERIAL as SERIAL;
use crate::{arp, dhcp, dns, igmp, inbound, ip, ipv6, netcfg, ntp, raw, tcp, wire};

// ── Generator ────────────────────────────────────────────────────────────────

/// xorshift64*: small, fixed, reproducible.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self { Rng(seed | 1) }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize { (self.next() % n as u64) as usize }
    fn noise(&mut self, n: usize) -> Vec<u8> { (0..n).map(|_| self.next() as u8).collect() }
}

/// A damaged copy of `base`: one to four of {byte replaced, bit flipped, byte
/// set to 0xFF or 0x00, truncation, random tail, a 16-bit field set to 0xFFFF}.
fn mutate(r: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    for _ in 0..1 + r.below(4) {
        match r.below(7) {
            0 if !v.is_empty() => { let i = r.below(v.len()); v[i] = r.next() as u8; }
            1 if !v.is_empty() => { let i = r.below(v.len()); v[i] ^= 1 << r.below(8); }
            2 if !v.is_empty() => { let i = r.below(v.len()); v[i] = 0xFF; }
            3 if !v.is_empty() => { let i = r.below(v.len()); v[i] = 0x00; }
            4 => { let n = r.below(v.len() + 1); v.truncate(n); }
            5 => { let n = 1 + r.below(40); v.extend(r.noise(n)); }
            _ if v.len() >= 2 => { let i = r.below(v.len() - 1); v[i] = 0xFF; v[i + 1] = 0xFF; }
            _ => {}
        }
    }
    v
}

/// RFC 1071 one's-complement sum of `parts` taken as one byte string.
fn ocsum(parts: &[&[u8]]) -> u16 {
    let bytes: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    let mut acc: u64 = 0;
    for pair in bytes.chunks(2) {
        let hi = u64::from(pair[0]) << 8;
        let lo = if pair.len() == 2 { u64::from(pair[1]) } else { 0 };
        acc += hi | lo;
    }
    while acc > 0xFFFF { acc = (acc & 0xFFFF) + (acc >> 16); }
    !(acc as u16)
}

const OUR_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const OUR_IP: [u8; 4] = [10, 0, 0, 2];
const PEER_IP: [u8; 4] = [10, 0, 0, 9];
const PEER_MAC: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

/// Wrap a UDP payload in IPv4 (no checksum on the UDP, RFC 768) and queue it.
fn push_udp(src_ip: [u8; 4], src_port: u16, dst_port: u16, payload: &[u8]) {
    let mut u = Vec::new();
    u.extend_from_slice(&src_port.to_be_bytes());
    u.extend_from_slice(&dst_port.to_be_bytes());
    u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&((20 + u.len()) as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src_ip);
    p[16..20].copy_from_slice(&OUR_IP);
    let ck = ocsum(&[&p[..20]]);
    p[10..12].copy_from_slice(&ck.to_be_bytes());
    p.extend_from_slice(&u);
    inbound::push_ipv4(&p);
}

// ── ARP ──────────────────────────────────────────────────────────────────────

fn arp_begin() -> std::sync::MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    raw::reset();
    azos_drv_irqchip::clint::set_test_time(50_000);
    arp::cache_reset_for_test();
    ip::arp_txq_reset_for_test();
    g
}

#[allow(clippy::too_many_arguments)]
fn arp_pkt(
    htype: u16, ptype: u16, hlen: u8, plen: u8, oper: u16,
    sha: [u8; 6], spa: [u8; 4], tha: [u8; 6], tpa: [u8; 4],
) -> Vec<u8> {
    let mut p = Vec::with_capacity(28);
    p.extend_from_slice(&htype.to_be_bytes());
    p.extend_from_slice(&ptype.to_be_bytes());
    p.push(hlen);
    p.push(plen);
    p.extend_from_slice(&oper.to_be_bytes());
    p.extend_from_slice(&sha);
    p.extend_from_slice(&spa);
    p.extend_from_slice(&tha);
    p.extend_from_slice(&tpa);
    p
}

/// A well-formed request for our address from `sha`/`spa`.
fn arp_request(sha: [u8; 6], spa: [u8; 4]) -> Vec<u8> {
    arp_pkt(1, 0x0800, 6, 4, 1, sha, spa, [0; 6], OUR_IP)
}

fn arp_deliver(p: &[u8]) {
    arp::handle(p, &OUR_MAC, &OUR_IP);
}

/// A sender address the cache could represent as a neighbour.
fn arp_sender_ok(spa: &[u8; 4], sha: &[u8; 6]) -> bool {
    spa[0] != 0 && *spa != [255; 4] && *spa != OUR_IP && spa[0] != 127 && spa[0] < 224
        && sha[0] & 1 == 0 && *sha != [0; 6] && *sha != OUR_MAC
}

#[test]
fn arp_answers_a_well_formed_request_and_nothing_else_does() {
    let _g = arp_begin();
    arp_deliver(&arp_request(PEER_MAC, PEER_IP));
    assert_eq!(arp::lookup(&PEER_IP), Some(PEER_MAC), "control: the asker is learned");
    let frames = raw::all();
    assert_eq!(frames.len(), 1, "control: and answered");
    let f = &frames[0];
    assert_eq!(f.len(), 14 + 28);
    assert_eq!(&f[0..6], &PEER_MAC, "the reply goes to the asker's MAC");
    assert_eq!(u16::from_be_bytes([f[14 + 6], f[14 + 7]]), 2, "a reply");
    assert_eq!(&f[14 + 8..14 + 14], &OUR_MAC);
    assert_eq!(&f[14 + 14..14 + 18], &OUR_IP);
    assert_eq!(&f[14 + 18..14 + 24], &PEER_MAC);
    assert_eq!(&f[14 + 24..14 + 28], &PEER_IP);

    // Padding after the 28 octets (an Ethernet minimum frame) is not a defect.
    arp::cache_reset_for_test();
    raw::reset();
    let mut padded = arp_request(PEER_MAC, PEER_IP);
    padded.extend_from_slice(&[0u8; 18]);
    arp_deliver(&padded);
    assert_eq!(raw::count(), 1, "padding is ignored");
}

#[test]
fn arp_refuses_every_truncation_and_every_hostile_field() {
    let _g = arp_begin();
    let valid = arp_request(PEER_MAC, PEER_IP);

    // Every proper prefix of a request is too short to be one.
    for n in 0..valid.len() {
        arp_deliver(&valid[..n]);
        assert_eq!(raw::count(), 0, "a {n}-octet packet drew a reply");
        assert_eq!(arp::lookup(&PEER_IP), None, "a {n}-octet packet taught a binding");
    }

    let hostile: Vec<(&str, Vec<u8>)> = vec![
        ("hardware type is not Ethernet", arp_pkt(6, 0x0800, 6, 4, 1, PEER_MAC, PEER_IP, [0; 6], OUR_IP)),
        ("protocol type is IPv6", arp_pkt(1, 0x86DD, 6, 4, 1, PEER_MAC, PEER_IP, [0; 6], OUR_IP)),
        ("hardware length 8", arp_pkt(1, 0x0800, 8, 4, 1, PEER_MAC, PEER_IP, [0; 6], OUR_IP)),
        ("hardware length 0", arp_pkt(1, 0x0800, 0, 4, 1, PEER_MAC, PEER_IP, [0; 6], OUR_IP)),
        ("protocol length 16", arp_pkt(1, 0x0800, 6, 16, 1, PEER_MAC, PEER_IP, [0; 6], OUR_IP)),
        ("protocol length 255", arp_pkt(1, 0x0800, 6, 255, 1, PEER_MAC, PEER_IP, [0; 6], OUR_IP)),
        ("opcode 0", arp_pkt(1, 0x0800, 6, 4, 0, PEER_MAC, PEER_IP, [0; 6], OUR_IP)),
        ("opcode 3 (RARP request)", arp_pkt(1, 0x0800, 6, 4, 3, PEER_MAC, PEER_IP, [0; 6], OUR_IP)),
        ("opcode 0xFFFF", arp_pkt(1, 0x0800, 6, 4, 0xFFFF, PEER_MAC, PEER_IP, [0; 6], OUR_IP)),
        ("sender IP 0.0.0.0", arp_request(PEER_MAC, [0; 4])),
        ("sender IP in 0.0.0.0/8", arp_request(PEER_MAC, [0, 1, 2, 3])),
        ("sender IP broadcast", arp_request(PEER_MAC, [255; 4])),
        ("sender IP is OUR address", arp_request(PEER_MAC, OUR_IP)),
        ("sender IP loopback", arp_request(PEER_MAC, [127, 0, 0, 1])),
        ("sender IP multicast", arp_request(PEER_MAC, [224, 0, 0, 251])),
        ("sender IP reserved", arp_request(PEER_MAC, [240, 0, 0, 1])),
        ("sender MAC all zero", arp_request([0; 6], PEER_IP)),
        ("sender MAC is a group address", arp_request([0x01, 0, 0x5E, 0, 0, 1], PEER_IP)),
        ("sender MAC is broadcast", arp_request([0xFF; 6], PEER_IP)),
        ("sender MAC is OUR MAC", arp_request(OUR_MAC, PEER_IP)),
        ("request for someone else", arp_pkt(1, 0x0800, 6, 4, 1, PEER_MAC, PEER_IP, [0; 6], [10, 0, 0, 77])),
        ("unsolicited reply", arp_pkt(1, 0x0800, 6, 4, 2, PEER_MAC, PEER_IP, OUR_MAC, OUR_IP)),
    ];
    for (name, p) in &hostile {
        arp::cache_reset_for_test();
        raw::reset();
        arp_deliver(p);
        assert_eq!(raw::count(), 0, "{name}: drew a frame");
        assert_eq!(arp::lookup(&PEER_IP), None, "{name}: taught a binding");
        assert_eq!(arp::lookup(&OUR_IP), None, "{name}: taught a binding for OUR address");
    }

    // Our own address unconfigured: no question can be about it.
    arp::cache_reset_for_test();
    raw::reset();
    arp::handle(&arp_pkt(1, 0x0800, 6, 4, 1, PEER_MAC, PEER_IP, [0; 6], [0; 4]), &OUR_MAC, &[0; 4]);
    assert_eq!(raw::count(), 0, "an unconfigured host answers nothing");
}

#[test]
fn arp_random_input_never_panics_and_replies_only_to_a_valid_sender() {
    let _g = arp_begin();
    let mut r = Rng::new(0xA4B0_0001);
    let bases = [
        arp_request(PEER_MAC, PEER_IP),
        arp_pkt(1, 0x0800, 6, 4, 2, PEER_MAC, PEER_IP, OUR_MAC, OUR_IP),
    ];
    for it in 0..6000 {
        let p = if it % 4 == 3 {
            let n = r.below(90);
            r.noise(n)
        } else {
            mutate(&mut r, &bases[it % 2])
        };
        arp::cache_reset_for_test();
        raw::reset();
        arp_deliver(&p);

        let frames = raw::all();
        assert!(frames.len() <= 2, "iteration {it}: {} frames from one packet", frames.len());
        for f in &frames {
            // Whatever left is a canonical Ethernet/IPv4 ARP frame from us.
            assert_eq!(f.len(), 14 + 28, "iteration {it}");
            assert_eq!(u16::from_be_bytes([f[12], f[13]]), 0x0806, "iteration {it}");
            assert_eq!(&f[14..14 + 6], &[0, 1, 8, 0, 6, 4], "iteration {it}: header");
            let op = u16::from_be_bytes([f[14 + 6], f[14 + 7]]);
            assert!(op == 1 || op == 2, "iteration {it}: opcode {op}");
            assert_eq!(&f[14 + 8..14 + 14], &OUR_MAC, "iteration {it}: sender MAC");
            assert_eq!(&f[14 + 14..14 + 18], &OUR_IP, "iteration {it}: sender IP");
            if op == 2 {
                // A reply answers a request that passed every check.
                assert!(p.len() >= 28, "iteration {it}: replied to a short packet");
                let spa: [u8; 4] = p[14..18].try_into().unwrap();
                let sha: [u8; 6] = p[8..14].try_into().unwrap();
                assert!(arp_sender_ok(&spa, &sha), "iteration {it}: replied to {spa:?}/{sha:02x?}");
                assert_eq!(&f[0..6], &sha, "iteration {it}: not unicast to the asker");
            }
        }
    }
}

// ── IGMP ─────────────────────────────────────────────────────────────────────

const GROUP: [u8; 4] = [239, 1, 2, 3];

fn igmp_begin() -> std::sync::MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    igmp::clear();
    inbound::reset();
    raw::reset();
    azos_drv_irqchip::clint::set_test_time(700_000);
    g
}

/// An IGMP query of `len` octets (8, or 12 and more for v3) for `group`, with
/// a correct checksum over the whole message.
fn igmp_query(len: usize, max_resp: u8, group: [u8; 4]) -> Vec<u8> {
    let mut m = vec![0u8; len];
    m[0] = 0x11;
    m[1] = max_resp;
    m[4..8].copy_from_slice(&group);
    let ck = ocsum(&[&m]);
    m[2..4].copy_from_slice(&ck.to_be_bytes());
    m
}

fn igmp_reports() -> usize {
    raw::all().iter()
        .filter(|f| f.len() > 14 + 20 && f[12] == 0x08 && f[13] == 0x00 && f[14 + 9] == 2)
        .count()
}

#[test]
fn igmp_answers_only_a_query_of_a_length_the_rfc_defines() {
    let _g = igmp_begin();
    assert_eq!(igmp::join(&GROUP), 0);
    raw::reset();

    // Control: v2 (8 octets) and v3 (12, and longer) general queries are answered.
    for len in [8usize, 12, 16, 40] {
        raw::reset();
        igmp::handle(&igmp_query(len, 100, [0; 4]));
        assert_eq!(igmp_reports(), 1, "control: a {len}-octet general query must be answered");
    }
    // RFC 3376 §7.1: nine to eleven octets is neither a v2 nor a v3 query.
    for len in [9usize, 10, 11] {
        raw::reset();
        igmp::handle(&igmp_query(len, 100, [0; 4]));
        assert_eq!(igmp_reports(), 0, "a {len}-octet query is malformed and must be ignored");
    }
    // Shorter than a message: nothing, for every length.
    for len in 0..8usize {
        raw::reset();
        igmp::handle(&vec![0x11u8; len]);
        assert_eq!(igmp_reports(), 0, "{len} octets");
    }
    // A valid message with any one octet damaged fails its checksum.
    let q = igmp_query(12, 100, [0; 4]);
    for i in 0..q.len() {
        let mut bad = q.clone();
        bad[i] ^= 0x5A;
        raw::reset();
        igmp::handle(&bad);
        assert_eq!(igmp_reports(), 0, "octet {i} damaged, still answered");
    }
    // A group-specific query for a group we are not in, for a non-group
    // address, and for all-hosts (which may never be reported).
    for g in [[239u8, 9, 9, 9], [10, 0, 0, 1], [224, 0, 0, 1], [255; 4]] {
        raw::reset();
        igmp::handle(&igmp_query(8, 100, g));
        assert_eq!(igmp_reports(), 0, "query for {g:?}");
    }
    // And for the group we ARE in, it is answered.
    raw::reset();
    igmp::handle(&igmp_query(8, 100, GROUP));
    assert_eq!(igmp_reports(), 1);
}

#[test]
fn igmp_random_input_never_panics_and_acts_only_on_a_valid_query() {
    let _g = igmp_begin();
    assert_eq!(igmp::join(&GROUP), 0);
    let mut r = Rng::new(0x16_0001);
    let bases = [igmp_query(8, 100, [0; 4]), igmp_query(12, 0, GROUP), igmp_query(24, 7, [0; 4])];
    for it in 0..6000 {
        let p = if it % 3 == 2 {
            let n = r.below(48);
            r.noise(n)
        } else {
            mutate(&mut r, &bases[it % 3])
        };
        raw::reset();
        igmp::handle(&p);
        if igmp_reports() > 0 {
            // A report left only for a query: type 0x11, 8 or 12+ octets,
            // checksum over every octet verifying.
            assert!(p.len() == 8 || p.len() >= 12, "iteration {it}: length {}", p.len());
            assert_eq!(p[0], 0x11, "iteration {it}");
            assert_eq!(ocsum(&[&p]), 0, "iteration {it}: answered a bad checksum");
        }
    }
}

// ── DHCP ─────────────────────────────────────────────────────────────────────

const SERVER: [u8; 4] = [10, 0, 0, 1];
const OFFERED: [u8; 4] = [10, 0, 0, 42];

fn dhcp_begin() -> std::sync::MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for idx in 0..azos_limits::TCP_MAX_CONNS {
        tcp::close(idx);
        tcp::close(idx);
    }
    raw::reset();
    netcfg::reset();
    azos_drv_irqchip::clint::set_test_time(300_000);
    tcp::init([0x02, 0, 0, 0, 0, 0x02], [0, 0, 0, 0]);
    g
}

/// Start an exchange and read its transaction id off the DISCOVER, as a
/// server on the link would.
fn dhcp_xid() -> u32 {
    dhcp::dhcp_discover();
    let frames = raw::all();
    let f = frames.last().expect("a DISCOVER was transmitted");
    let b = &f[42..]; // Ethernet 14 + IPv4 20 + UDP 8
    u32::from_be_bytes([b[4], b[5], b[6], b[7]])
}

/// BOOTREPLY header (240 octets) with `yiaddr`, then `opts` verbatim.
fn dhcp_msg(xid: u32, yiaddr: [u8; 4], opts: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; 240];
    d[0] = 2;
    d[4..8].copy_from_slice(&xid.to_be_bytes());
    d[16..20].copy_from_slice(&yiaddr);
    d[236..240].copy_from_slice(&[99, 130, 83, 99]);
    d.extend_from_slice(opts);
    d
}

/// The options of an honest OFFER/ACK, with each field replaceable.
fn dhcp_opts(kind: u8, mask: [u8; 4], gw: [u8; 4], dns: [u8; 4], sid: [u8; 4]) -> Vec<u8> {
    let mut o = vec![53, 1, kind, 1, 4];
    o.extend_from_slice(&mask);
    o.extend_from_slice(&[3, 4]);
    o.extend_from_slice(&gw);
    o.extend_from_slice(&[6, 4]);
    o.extend_from_slice(&dns);
    o.extend_from_slice(&[54, 4]);
    o.extend_from_slice(&sid);
    o.push(255);
    o
}

fn good_opts(kind: u8) -> Vec<u8> {
    dhcp_opts(kind, [255, 255, 255, 0], SERVER, [10, 0, 0, 53], SERVER)
}

#[test]
fn dhcp_refuses_a_malformed_option_list_or_an_unusable_lease() {
    let _g = dhcp_begin();
    let xid = dhcp_xid();
    let offer = |opts: &[u8]| dhcp::dhcp_handle_offer(&dhcp_msg(xid, OFFERED, opts));

    assert_eq!(offer(&good_opts(2)), Some((OFFERED, SERVER)), "control: an honest OFFER");

    // Heavily padded options are legal (RFC 2132 §3.1) and not counted
    // against the option budget.
    let mut padded = vec![0u8; 900];
    padded.extend_from_slice(&good_opts(2));
    assert_eq!(offer(&padded), Some((OFFERED, SERVER)), "control: padding is ignored");

    // Every truncation that cuts an option, or the header, is refused. Option
    // 54 is the last before END, so it is whole exactly when only END is
    // missing (RFC 1542 §2.1: the UDP length is trusted).
    let full = dhcp_msg(xid, OFFERED, &good_opts(2));
    for n in 0..full.len() - 1 {
        assert_eq!(dhcp::dhcp_handle_offer(&full[..n]), None, "{n}-octet prefix accepted");
    }
    assert_eq!(dhcp::dhcp_handle_offer(&full[..full.len() - 1]), Some((OFFERED, SERVER)),
               "control: only the END octet missing");

    let mut tlv65: Vec<u8> = Vec::new();
    for _ in 0..65 { tlv65.extend_from_slice(&[100, 0]); }
    tlv65.extend_from_slice(&good_opts(2));
    let mut tlv64: Vec<u8> = Vec::new();
    for _ in 0..59 { tlv64.extend_from_slice(&[100, 0]); }
    tlv64.extend_from_slice(&good_opts(2));

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("length byte past the end (nothing usable before it)", vec![53, 1, 2, 54]),
        ("value past the end", vec![53, 1, 2, 54, 4, 10, 0]),
        ("length 255 with no data", vec![53, 1, 2, 54, 255, 1, 2, 3]),
        ("no options at all", vec![]),
        ("more than the option budget", tlv65),
        ("message type of length 0", vec![53, 0, 54, 4, 10, 0, 0, 1, 255]),
        ("message type of length 2", vec![53, 2, 2, 2, 54, 4, 10, 0, 0, 1, 255]),
        ("server id of length 0", vec![53, 1, 2, 54, 0, 255]),
        ("server id of length 3", vec![53, 1, 2, 54, 3, 10, 0, 0, 255]),
        ("server id of length 8", vec![53, 1, 2, 54, 8, 10, 0, 0, 1, 9, 9, 9, 9, 255]),
        ("mask of length 3", vec![53, 1, 2, 1, 3, 255, 255, 255, 54, 4, 10, 0, 0, 1, 255]),
        ("router of length 6", vec![53, 1, 2, 3, 6, 10, 0, 0, 1, 10, 0, 54, 4, 10, 0, 0, 1, 255]),
        ("router of length 0", vec![53, 1, 2, 3, 0, 54, 4, 10, 0, 0, 1, 255]),
        ("dns of length 5", vec![53, 1, 2, 6, 5, 1, 2, 3, 4, 5, 54, 4, 10, 0, 0, 1, 255]),
        ("message type twice", vec![53, 1, 2, 53, 1, 5, 54, 4, 10, 0, 0, 1, 255]),
        ("server id twice", vec![53, 1, 2, 54, 4, 10, 0, 0, 1, 54, 4, 10, 0, 0, 66, 255]),
        ("no server id", vec![53, 1, 2, 1, 4, 255, 255, 255, 0, 255]),
        ("no message type", vec![54, 4, 10, 0, 0, 1, 255]),
        ("mask 0.0.0.0", dhcp_opts(2, [0; 4], SERVER, [10, 0, 0, 53], SERVER)),
        ("mask not contiguous", dhcp_opts(2, [255, 0, 255, 0], SERVER, [10, 0, 0, 53], SERVER)),
        ("mask not contiguous (low bit)", dhcp_opts(2, [255, 255, 255, 1], SERVER, [10, 0, 0, 53], SERVER)),
        ("gateway is broadcast", dhcp_opts(2, [255, 255, 255, 0], [255; 4], [10, 0, 0, 53], SERVER)),
        ("gateway is multicast", dhcp_opts(2, [255, 255, 255, 0], [224, 0, 0, 1], [10, 0, 0, 53], SERVER)),
        ("gateway is loopback", dhcp_opts(2, [255, 255, 255, 0], [127, 0, 0, 1], [10, 0, 0, 53], SERVER)),
        ("dns is multicast", dhcp_opts(2, [255, 255, 255, 0], SERVER, [224, 0, 0, 251], SERVER)),
        ("server id 0.0.0.0", dhcp_opts(2, [255, 255, 255, 0], SERVER, [10, 0, 0, 53], [0; 4])),
        ("server id broadcast", dhcp_opts(2, [255, 255, 255, 0], SERVER, [10, 0, 0, 53], [255; 4])),
        ("server id multicast", dhcp_opts(2, [255, 255, 255, 0], SERVER, [10, 0, 0, 53], [224, 0, 0, 1])),
    ];
    for (name, opts) in &cases {
        assert_eq!(offer(opts), None, "{name}");
    }
    // Sixty-four options in all fit the budget: the bound is not tighter than
    // it says (59 unknown, plus the five real ones).
    assert_eq!(offer(&tlv64), Some((OFFERED, SERVER)), "control: 64 options are fine");

    // The address itself: nothing a host can take.
    for (name, y) in [
        ("yiaddr 0.0.0.0", [0u8; 4]),
        ("yiaddr in 0.0.0.0/8", [0, 0, 0, 42]),
        ("yiaddr broadcast", [255; 4]),
        ("yiaddr multicast", [224, 0, 0, 1]),
        ("yiaddr reserved", [240, 1, 2, 3]),
        ("yiaddr loopback", [127, 0, 0, 1]),
        ("yiaddr is the network address", [10, 0, 0, 0]),
        ("yiaddr is the subnet broadcast", [10, 0, 0, 255]),
    ] {
        assert_eq!(dhcp::dhcp_handle_offer(&dhcp_msg(xid, y, &good_opts(2))), None, "{name}");
    }

    // The fixed header.
    let mut wrong_op = dhcp_msg(xid, OFFERED, &good_opts(2));
    wrong_op[0] = 1;
    let mut wrong_cookie = dhcp_msg(xid, OFFERED, &good_opts(2));
    wrong_cookie[238] ^= 1;
    let wrong_xid = dhcp_msg(xid ^ 1, OFFERED, &good_opts(2));
    for (name, m) in [("BOOTREQUEST", wrong_op), ("bad cookie", wrong_cookie), ("wrong xid", wrong_xid)] {
        assert_eq!(dhcp::dhcp_handle_offer(&m), None, "{name}");
    }
}

#[test]
fn dhcp_random_input_never_panics_and_a_lease_is_always_usable() {
    let _g = dhcp_begin();
    let mut r = Rng::new(0xD4C9_0001);
    for it in 0..1500 {
        let xid = dhcp_xid();
        let offer = dhcp_msg(xid, OFFERED, &good_opts(2));
        let ack = dhcp_msg(xid, OFFERED, &good_opts(5));
        assert!(dhcp::dhcp_handle_offer(&offer).is_some(), "control, iteration {it}");

        let m = if it % 5 == 4 {
            // Noise behind a header that gets past the fixed-field checks.
            let n = r.below(300);
            dhcp_msg(xid, OFFERED, &r.noise(n))
        } else {
            mutate(&mut r, if it % 2 == 0 { &offer } else { &ack })
        };
        if let Some((ipa, sid)) = dhcp::dhcp_handle_offer(&m) {
            assert!(ipa[0] != 0 && ipa[0] != 127 && ipa[0] < 224, "iteration {it}: offered {ipa:?}");
            assert!(sid[0] != 0 && sid[0] != 127 && sid[0] < 224, "iteration {it}: server {sid:?}");
        }
        // Rebind to an honest server, then try the ACK path.
        let _ = dhcp::dhcp_handle_offer(&offer);
        netcfg::reset();
        if dhcp::dhcp_handle_ack(&m) {
            let (addr, mask, gw) = netcfg::last().expect("an accepted ACK configures the interface");
            assert!(addr[0] != 0 && addr[0] != 127 && addr[0] < 224, "iteration {it}: {addr:?}");
            let mk = u32::from_be_bytes(mask);
            assert!(mk != 0 && (!mk).wrapping_add(1) & !mk == 0, "iteration {it}: mask {mask:?}");
            assert!(gw == [0; 4] || (gw[0] != 127 && gw[0] < 224), "iteration {it}: gateway {gw:?}");
        }
    }
}

// ── DNS ──────────────────────────────────────────────────────────────────────

const QNAME: &[u8] = b"\x07example\x03com\x00";
const GOOD_A: [u8; 4] = [93, 184, 216, 34];

/// A response header for one question, `an` announced answers, then the
/// question (type `qtype`, class IN), then `records` verbatim.
fn dns_msg(id: u16, flags: u16, qd: u16, an: u16, qtype: u16, records: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&id.to_be_bytes());
    d.extend_from_slice(&flags.to_be_bytes());
    d.extend_from_slice(&qd.to_be_bytes());
    d.extend_from_slice(&an.to_be_bytes());
    d.extend_from_slice(&[0, 0, 0, 0]);
    d.extend_from_slice(QNAME);
    d.extend_from_slice(&qtype.to_be_bytes());
    d.extend_from_slice(&1u16.to_be_bytes());
    d.extend_from_slice(records);
    d
}

/// One resource record whose name is `name`.
fn rr(name: &[u8], rtype: u16, class: u16, rdlength: u16, rdata: &[u8]) -> Vec<u8> {
    let mut v = name.to_vec();
    v.extend_from_slice(&rtype.to_be_bytes());
    v.extend_from_slice(&class.to_be_bytes());
    v.extend_from_slice(&60u32.to_be_bytes());
    v.extend_from_slice(&rdlength.to_be_bytes());
    v.extend_from_slice(rdata);
    v
}

/// The usual owner name: a pointer to the question's name at offset 12.
const PTR_Q: &[u8] = &[0xC0, 0x0C];
const ID: u16 = 0xBEEF;
const OK: u16 = 0x8180;

fn a_rr(ip: [u8; 4]) -> Vec<u8> { rr(PTR_Q, 1, 1, 4, &ip) }
fn good_a() -> Vec<u8> { dns_msg(ID, OK, 1, 1, 1, &a_rr(GOOD_A)) }

#[test]
fn dns_parser_refuses_malformed_names_and_records() {
    assert_eq!(dns::parse_response(&good_a(), ID), Some(GOOD_A), "control");

    // Truncated at every length: the answer is cut somewhere, always refused.
    let full = good_a();
    for n in 0..full.len() {
        assert_eq!(dns::parse_response(&full[..n], ID), None, "{n}-octet prefix accepted");
    }

    // Compression pointers. The answer's owner name sits at offset
    // 12 + 13 + 4 = 29 in every message built by `dns_msg` with `QNAME`.
    let own = 12 + QNAME.len() + 4;
    let self_ptr = [0xC0, own as u8];
    let fwd_ptr = [0xC0, (own + 40) as u8];
    let into_header = [0xC0, 0x00];
    let into_header_2 = [0xC0, 0x0B];
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("pointer to itself", dns_msg(ID, OK, 1, 1, 1, &rr(&self_ptr, 1, 1, 4, &GOOD_A))),
        ("pointer forward", dns_msg(ID, OK, 1, 1, 1, &rr(&fwd_ptr, 1, 1, 4, &GOOD_A))),
        ("pointer to offset 0", dns_msg(ID, OK, 1, 1, 1, &rr(&into_header, 1, 1, 4, &GOOD_A))),
        ("pointer into the header", dns_msg(ID, OK, 1, 1, 1, &rr(&into_header_2, 1, 1, 4, &GOOD_A))),
        ("pointer past the message", dns_msg(ID, OK, 1, 1, 1, &rr(&[0xFF, 0xFF], 1, 1, 4, &GOOD_A))),
        ("pointer is the last octet", dns_msg(ID, OK, 1, 1, 1, &[0xC0])),
        ("reserved label type 01", dns_msg(ID, OK, 1, 1, 1, &rr(&[0x40, 1, 2, 0], 1, 1, 4, &GOOD_A))),
        ("reserved label type 10", dns_msg(ID, OK, 1, 1, 1, &rr(&[0x80, 1, 2, 0], 1, 1, 4, &GOOD_A))),
        ("label past the end", dns_msg(ID, OK, 1, 1, 1, &[63, b'a', b'b'])),
        ("name with no terminator", dns_msg(ID, OK, 1, 1, 1, &[3, b'a', b'b', b'c'])),
        ("name over 255 octets", {
            let mut n = Vec::new();
            for _ in 0..5 { n.push(63); n.extend_from_slice(&[b'x'; 63]); }
            n.push(0);
            dns_msg(ID, OK, 1, 1, 1, &rr(&n, 1, 1, 4, &GOOD_A))
        }),
        ("rdlength past the end", dns_msg(ID, OK, 1, 1, 1, &rr(PTR_Q, 1, 1, 0xFFFF, &GOOD_A))),
        ("rdlength 5, 4 present", dns_msg(ID, OK, 1, 1, 1, &rr(PTR_Q, 1, 1, 5, &GOOD_A))),
        ("record header cut", dns_msg(ID, OK, 1, 1, 1, &[0xC0, 0x0C, 0, 1, 0, 1, 0, 0])),
        ("ANCOUNT larger than the data", dns_msg(ID, OK, 1, 65535, 1, &a_rr(GOOD_A)[..0])),
        ("no records for ANCOUNT 1", dns_msg(ID, OK, 1, 1, 1, &[])),
        ("ANCOUNT 0", dns_msg(ID, OK, 1, 0, 1, &a_rr(GOOD_A))),
        ("QDCOUNT 0", dns_msg(ID, OK, 0, 1, 1, &a_rr(GOOD_A))),
        ("QDCOUNT 2", dns_msg(ID, OK, 2, 1, 1, &a_rr(GOOD_A))),
        ("QDCOUNT 65535", dns_msg(ID, OK, 65535, 1, 1, &a_rr(GOOD_A))),
        ("not a response", dns_msg(ID, 0x0100, 1, 1, 1, &a_rr(GOOD_A))),
        ("RCODE NXDOMAIN", dns_msg(ID, OK | 3, 1, 1, 1, &a_rr(GOOD_A))),
        ("wrong id", dns_msg(ID ^ 1, OK, 1, 1, 1, &a_rr(GOOD_A))),
        ("class CH", dns_msg(ID, OK, 1, 1, 1, &rr(PTR_Q, 1, 3, 4, &GOOD_A))),
        ("type AAAA for an A query", dns_msg(ID, OK, 1, 1, 1, &rr(PTR_Q, 28, 1, 16, &[1; 16]))),
        ("A with 3 octets of rdata", dns_msg(ID, OK, 1, 1, 1, &rr(PTR_Q, 1, 1, 3, &GOOD_A[..3]))),
        ("A with 16 octets of rdata", dns_msg(ID, OK, 1, 1, 1, &rr(PTR_Q, 1, 1, 16, &[1; 16]))),
        ("address 0.0.0.0", dns_msg(ID, OK, 1, 1, 1, &a_rr([0; 4]))),
        ("address in 0.0.0.0/8", dns_msg(ID, OK, 1, 1, 1, &a_rr([0, 0, 0, 42]))),
        ("address loopback", dns_msg(ID, OK, 1, 1, 1, &a_rr([127, 0, 0, 1]))),
        ("address multicast", dns_msg(ID, OK, 1, 1, 1, &a_rr([224, 0, 0, 1]))),
        ("address broadcast", dns_msg(ID, OK, 1, 1, 1, &a_rr([255; 4]))),
    ];
    for (name, m) in &cases {
        assert_eq!(dns::parse_response(m, ID), None, "{name}");
    }

    // A bad record is skipped, not fatal: a later good one is still taken.
    let mut two = rr(PTR_Q, 1, 1, 3, &GOOD_A[..3]); // wrong rdata length
    two.extend_from_slice(&rr(PTR_Q, 1, 1, 4, &[0; 4])); // unusable
    two.extend_from_slice(&rr(PTR_Q, 5, 1, 2, &[0xC0, 0x0C])); // CNAME
    two.extend_from_slice(&a_rr(GOOD_A));
    assert_eq!(dns::parse_response(&dns_msg(ID, OK, 1, 4, 1, &two), ID), Some(GOOD_A));

    // A name spelled out as a label and then a pointer to the rest of it is
    // that name; one with a label of its own in front is another name.
    let mut spelled = b"\x07example".to_vec();
    spelled.extend_from_slice(&[0xC0, 12 + 8]); // `com` in the question
    assert_eq!(
        dns::parse_response(&dns_msg(ID, OK, 1, 1, 1, &rr(&spelled, 1, 1, 4, &GOOD_A)), ID),
        Some(GOOD_A),
        "control: label then pointer",
    );
    let mut other = b"\x03www".to_vec();
    other.extend_from_slice(&[0xC0, 12]);
    assert_eq!(
        dns::parse_response(&dns_msg(ID, OK, 1, 1, 1, &rr(&other, 1, 1, 4, &GOOD_A)), ID),
        None,
        "www.example.com is not example.com",
    );

    // A 65535-record claim over a short message costs the message, not 65535.
    let mut many = Vec::new();
    for _ in 0..8 { many.extend_from_slice(&rr(PTR_Q, 5, 1, 2, &[0xC0, 0x0C])); }
    assert_eq!(dns::parse_response(&dns_msg(ID, OK, 1, 65535, 1, &many), ID), None);
}

#[test]
fn dns_aaaa_parser_checks_length_and_address() {
    let g6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let m = dns_msg(ID, OK, 1, 1, 28, &rr(PTR_Q, 28, 1, 16, &g6));
    assert_eq!(dns::parse_response_aaaa(&m, ID), Some(g6), "control");
    for n in 0..m.len() {
        assert_eq!(dns::parse_response_aaaa(&m[..n], ID), None, "{n}-octet prefix accepted");
    }
    let mut lo = [0u8; 16];
    lo[15] = 1;
    let mut mc = [0u8; 16];
    mc[0] = 0xFF;
    mc[1] = 0x02;
    mc[15] = 1;
    for (name, rec) in [
        ("rdlength 4", rr(PTR_Q, 28, 1, 4, &g6[..4])),
        ("rdlength 17", rr(PTR_Q, 28, 1, 17, &[g6.as_slice(), &[0]].concat())),
        ("unspecified ::", rr(PTR_Q, 28, 1, 16, &[0; 16])),
        ("IPv4-compatible ::a.b.c.d", { let mut v = [0u8; 16]; v[12..].copy_from_slice(&GOOD_A); rr(PTR_Q, 28, 1, 16, &v) }),
        ("loopback ::1", rr(PTR_Q, 28, 1, 16, &lo)),
        ("multicast ff02::1", rr(PTR_Q, 28, 1, 16, &mc)),
        ("class CH", rr(PTR_Q, 28, 3, 16, &g6)),
        ("an A record", rr(PTR_Q, 1, 1, 4, &GOOD_A)),
    ] {
        assert_eq!(dns::parse_response_aaaa(&dns_msg(ID, OK, 1, 1, 28, &rec), ID), None, "{name}");
    }
}

#[test]
fn dns_random_input_never_panics_and_an_answer_is_always_usable() {
    // Serialised: `handle_response` and `active_port` read the resolver's
    // process-wide query record, which the resolve tests arm and disarm.
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng::new(0xD115_0001);
    let g6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let a_base = good_a();
    let aaaa_base = dns_msg(ID, OK, 1, 1, 28, &rr(PTR_Q, 28, 1, 16, &g6));
    let mut two = a_rr([10, 0, 0, 1]);
    two.extend_from_slice(&rr(&[3, b'w', b'w', b'w', 0xC0, 0x0C], 5, 1, 2, &[0xC0, 0x0C]));
    let two_base = dns_msg(ID, OK, 1, 2, 1, &two);
    for it in 0..8000 {
        let m = match it % 4 {
            0 => mutate(&mut r, &a_base),
            1 => mutate(&mut r, &aaaa_base),
            2 => mutate(&mut r, &two_base),
            _ => {
                // Noise behind a header that matches the id and the QR bit, so
                // the record walk is what is being driven.
                let n = r.below(120);
                let mut m = vec![(ID >> 8) as u8, ID as u8, 0x81, 0x80, 0, 1, r.next() as u8, r.next() as u8, 0, 0, 0, 0];
                m.extend(r.noise(n));
                m
            }
        };
        if let Some(a) = dns::parse_response(&m, ID) {
            assert!(a[0] != 0 && a[0] != 127 && a[0] < 224, "iteration {it}: {a:?}");
        }
        if let Some(a) = dns::parse_response_aaaa(&m, ID) {
            assert!(a[0] != 0 && a[0] != 0xFF, "iteration {it}: {a:?}");
        }
        // The id is the first thing checked: any other draws nothing.
        if m.len() < 2 || u16::from_be_bytes([m[0], m[1]]) != ID ^ 0x8000 {
            assert_eq!(dns::parse_response(&m, ID ^ 0x8000), None, "iteration {it}");
        }
        // And a response nobody asked for is dropped before it is read.
        dns::handle_response(&[8, 8, 8, 8], 53, 4444, &m);
    }
    assert_eq!(dns::active_port(), 0, "no query is outstanding");
}

// ── DNS: the whole resolve path, with a hostile body ────────────────────────

mod resolve {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    const SERVER_IP: [u8; 4] = [10, 0, 0, 53];
    const SERVER_MAC: [u8; 6] = [0x02, 0x53, 0x53, 0x53, 0x53, 0x53];

    /// What the "server" sends after the echoed question, given the offset
    /// that question ends at (where the first record starts): (ANCOUNT, records).
    type Body = fn(usize) -> (u16, Vec<u8>);
    static BODY: Mutex<Option<Body>> = Mutex::new(None);
    static ANSWERED: AtomicBool = AtomicBool::new(false);

    /// Runs inside `net_poll`: read the query the resolver just sent and
    /// answer it, echoing its id, source port and question.
    fn answer() {
        if ANSWERED.load(Ordering::SeqCst) { return; }
        let q = wire::sent().iter().find_map(|s| {
            if s.proto != 17 || s.payload.len() < 8 + 12 { return None; }
            if u16::from_be_bytes([s.payload[2], s.payload[3]]) != 53 { return None; }
            Some((u16::from_be_bytes([s.payload[0], s.payload[1]]), s.payload[8..].to_vec()))
        });
        let Some((port, query)) = q else { return };
        ANSWERED.store(true, Ordering::SeqCst);
        let body = BODY.lock().unwrap().expect("a body is planned");
        let (an, records) = body(query.len());
        let mut d = Vec::new();
        d.extend_from_slice(&query[0..2]); // id
        d.extend_from_slice(&OK.to_be_bytes());
        d.extend_from_slice(&1u16.to_be_bytes());
        d.extend_from_slice(&an.to_be_bytes());
        d.extend_from_slice(&[0, 0, 0, 0]);
        d.extend_from_slice(&query[12..]); // the question, byte for byte
        d.extend_from_slice(&records);
        push_udp(SERVER_IP, 53, port, &d);
    }

    fn resolve_with(name: &str, body: Body) -> Option<[u8; 4]> {
        inbound::reset();
        raw::reset();
        azos_drv_irqchip::clint::set_test_time(200_000);
        arp::insert(SERVER_IP, SERVER_MAC);
        dns::set_dns_server(SERVER_IP);
        *BODY.lock().unwrap() = Some(body);
        ANSWERED.store(false, Ordering::SeqCst);
        inbound::on_poll(answer);
        let r = dns::resolve_with_yield(name, core::hint::spin_loop);
        inbound::reset();
        r
    }

    #[test]
    fn a_looping_or_oversized_answer_from_the_right_server_resolves_nothing() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            resolve_with("ok.fuzz.test", |_| (1, a_rr(GOOD_A))),
            Some(GOOD_A),
            "control: an honest answer through the whole path",
        );
        // Each of these passes every `handle_response` check (right server,
        // port, id and question) and is refused only by the record walk.
        assert_eq!(
            resolve_with("self.fuzz.test", |q| (1, rr(&[0xC0, q as u8], 1, 1, 4, &GOOD_A))),
            None, "an owner name that points at itself",
        );
        assert_eq!(
            resolve_with("fwd.fuzz.test", |q| (1, rr(&[0xC0, (q + 60) as u8], 1, 1, 4, &GOOD_A))),
            None, "an owner name that points forward",
        );
        assert_eq!(
            resolve_with("len.fuzz.test", |_| (1, rr(PTR_Q, 1, 1, 0xFFFF, &GOOD_A))),
            None, "an rdlength past the message",
        );
        assert_eq!(
            resolve_with("many.fuzz.test", |_| (65535, rr(PTR_Q, 5, 1, 2, &[0xC0, 0x0C]))),
            None, "an ANCOUNT far beyond the records present",
        );
        assert_eq!(
            resolve_with("lo.fuzz.test", |_| (1, a_rr([127, 0, 0, 1]))),
            None, "a name answered with the loopback address",
        );
        assert_eq!(dns::active_port(), 0, "the query is disarmed after every outcome");
    }
}

// ── NTP ──────────────────────────────────────────────────────────────────────

mod ntpfz {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    const SERVER_IP: [u8; 4] = [10, 0, 0, 123];
    const SERVER_MAC: [u8; 6] = [0x02, 0x12, 0x33, 0x44, 0x55, 0x66];
    /// 2020-01-01 in the NTP epoch: the plausibility floor.
    const FLOOR: u32 = 3_786_825_600;
    const UNIX_OFFSET: u32 = 2_208_988_800;

    static PKT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    static PATCH: AtomicBool = AtomicBool::new(true);
    static ANSWERED: AtomicBool = AtomicBool::new(false);

    /// Runs inside `net_poll`: answer the request once with `PKT`, carrying
    /// the request's nonce in the originate field when `PATCH` is set.
    fn answer() {
        if ANSWERED.load(Ordering::SeqCst) { return; }
        let nonce = wire::sent().iter().find_map(|s| {
            if s.proto != 17 || s.payload.len() < 8 + 48 { return None; }
            if u16::from_be_bytes([s.payload[2], s.payload[3]]) != 123 { return None; }
            Some(s.payload[8 + 40..8 + 48].to_vec())
        });
        let Some(nonce) = nonce else { return };
        ANSWERED.store(true, Ordering::SeqCst);
        let mut reply = PKT.lock().unwrap().clone();
        if PATCH.load(Ordering::SeqCst) && reply.len() >= 32 {
            reply[24..32].copy_from_slice(&nonce);
        }
        push_udp(SERVER_IP, 123, 1123, &reply);
    }

    /// A server reply: version 4, mode 4, stratum 2, transmit `sec`.
    fn reply(sec: u32) -> Vec<u8> {
        let mut p = vec![0u8; 48];
        p[0] = 0x24;
        p[1] = 2;
        p[40..44].copy_from_slice(&sec.to_be_bytes());
        p
    }

    /// One sync attempt against a server that sends `pkt`; the time it set,
    /// or 0.
    fn sync_with(pkt: Vec<u8>, patch: bool) -> u32 {
        inbound::reset();
        raw::reset();
        azos_drv_irqchip::clint::set_test_time(500_000);
        arp::insert(SERVER_IP, SERVER_MAC);
        ntp::set_ntp_server(SERVER_IP);
        *PKT.lock().unwrap() = pkt;
        PATCH.store(patch, Ordering::SeqCst);
        ANSWERED.store(false, Ordering::SeqCst);
        inbound::on_poll(answer);
        let t = ntp::ntp_sync_with_yield(core::hint::spin_loop);
        inbound::reset();
        t
    }

    #[test]
    fn ntp_refuses_every_reply_that_is_not_a_plausible_fresh_server_answer() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(sync_with(reply(FLOOR), true), FLOOR - UNIX_OFFSET, "control: an honest reply");
        let mut with_ext = reply(FLOOR);
        with_ext.extend_from_slice(&[0u8; 20]);
        assert_eq!(sync_with(with_ext, true), FLOOR - UNIX_OFFSET, "control: trailing octets are ignored");

        // Cut at every length short of a packet.
        for n in 0..48 {
            assert_eq!(sync_with(reply(FLOOR)[..n].to_vec(), true), 0, "{n}-octet reply accepted");
        }
        let mut bad: Vec<(&str, Vec<u8>)> = Vec::new();
        for mode in [0u8, 1, 2, 3, 5, 6, 7] {
            let mut p = reply(FLOOR);
            p[0] = 0x20 | mode;
            bad.push(("wrong mode", p));
        }
        for vn in [0u8, 5, 6, 7] {
            let mut p = reply(FLOOR);
            p[0] = (vn << 3) | 4;
            bad.push(("version outside 1-4", p));
        }
        let mut li3 = reply(FLOOR);
        li3[0] = 0xE4;
        bad.push(("LI 3, unsynchronised", li3));
        for st in [0u8, 16, 255] {
            let mut p = reply(FLOOR);
            p[1] = st;
            bad.push(("stratum 0 or above 15", p));
        }
        bad.push(("transmit timestamp zero", reply(0)));
        bad.push(("era 0 before the floor", reply(0x8000_0001)));
        bad.push(("era 0 at 1968-01-20, bit 0 set", reply(0x8000_0000)));
        for (name, p) in bad {
            assert_eq!(sync_with(p.clone(), true), 0, "{name}: {:02x?}", &p[..4]);
        }
        // Nonce: not echoed (originate zero) and echoed wrongly.
        assert_eq!(sync_with(reply(FLOOR), false), 0, "originate timestamp not echoed");
        let mut wrong = reply(FLOOR);
        wrong[24..32].copy_from_slice(&[0x55; 8]);
        assert_eq!(sync_with(wrong, false), 0, "originate timestamp forged");
    }

    #[test]
    fn ntp_random_replies_never_panic_and_an_accepted_one_is_well_formed() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let mut r = Rng::new(0x07_0001);
        let base = reply(FLOOR);
        for it in 0..250 {
            let p = mutate(&mut r, &base);
            let t = sync_with(p.clone(), true);
            if t != 0 {
                assert!(p.len() >= 48, "iteration {it}");
                assert!(ntp::header_acceptable(&p), "iteration {it}: {:02x?}", &p[..2]);
                let sec = u32::from_be_bytes([p[40], p[41], p[42], p[43]]);
                assert!(p[40..48] != [0u8; 8], "iteration {it}: zero transmit timestamp");
                assert!(sec & 0x8000_0000 == 0 || sec >= FLOOR, "iteration {it}: implausible {sec:#x}");
                assert_eq!(t, sec.wrapping_sub(UNIX_OFFSET), "iteration {it}");
            }
        }
    }

    #[test]
    fn ntp_header_filter_survives_noise() {
        // Serialised: `handle_response` reads the client's process-wide state.
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let mut r = Rng::new(0x07_0002);
        for it in 0..8000 {
            let n = r.below(80);
            let p = r.noise(n);
            if ntp::header_acceptable(&p) {
                assert!(p.len() >= 48, "iteration {it}");
                assert_eq!(p[0] & 7, 4, "iteration {it}: mode");
                assert!((1..=4).contains(&((p[0] >> 3) & 7)), "iteration {it}: version");
                assert!(p[0] >> 6 != 3, "iteration {it}: LI");
                assert!((1..=15).contains(&p[1]), "iteration {it}: stratum");
            }
            // And a datagram nobody asked for is dropped before it is read.
            ntp::handle_response(&[10, 0, 0, 123], 123, &p);
        }
    }
}

// ── ICMPv6 Neighbour Discovery ───────────────────────────────────────────────

mod nd {
    use super::*;

    const MAC6: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    const PEER6_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF];
    const PEER6: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];
    const PREFIX: [u8; 8] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1];

    fn begin() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        raw::reset();
        azos_drv_irqchip::clint::set_test_time(100_000);
        ipv6::ipv6_init(&MAC6);
        raw::reset();
        g
    }

    fn ll() -> [u8; 16] { ipv6::eui64_link_local(&MAC6) }

    /// Fill the ICMPv6 checksum (octets 2-3) over the pseudo-header.
    fn sign(src: [u8; 16], dst: [u8; 16], msg: &mut [u8]) {
        if msg.len() < 4 { return; }
        msg[2] = 0;
        msg[3] = 0;
        let len = (msg.len() as u32).to_be_bytes();
        let ck = ocsum(&[&src, &dst, &len, &[0, 0, 0, 58], msg]);
        msg[2..4].copy_from_slice(&ck.to_be_bytes());
    }

    /// An IPv6 datagram (no Ethernet header), as `ipv6_rx` takes it.
    fn ip6(next: u8, hop: u8, src: [u8; 16], dst: [u8; 16], payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 40];
        f[0] = 0x60;
        f[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        f[6] = next;
        f[7] = hop;
        f[8..24].copy_from_slice(&src);
        f[24..40].copy_from_slice(&dst);
        f.extend_from_slice(payload);
        f
    }

    fn rx(f: &[u8]) { ipv6::ipv6_rx(f, f.len()); }

    fn slla(mac: [u8; 6]) -> Vec<u8> {
        let mut o = vec![1, 1];
        o.extend_from_slice(&mac);
        o
    }

    /// A signed Neighbour Solicitation for `target` with `options`.
    fn ns(src: [u8; 16], dst: [u8; 16], target: [u8; 16], options: &[u8]) -> Vec<u8> {
        let mut m = vec![135, 0, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&target);
        m.extend_from_slice(options);
        sign(src, dst, &mut m);
        m
    }

    // ── nd_source_lla ────────────────────────────────────────────────────────

    #[test]
    fn the_source_option_walk_refuses_every_malformed_list() {
        let good = slla(PEER6_MAC);
        assert_eq!(ipv6::nd_source_lla(&good), Some(PEER6_MAC), "control");

        let zero_len = vec![14u8, 0, 0, 0, 0, 0, 0, 0];
        let unknown = vec![5u8, 1, 0, 0, 0, 0, 0, 0]; // an MTU-shaped option
        let mut pio = vec![3u8, 4, 64, 0xC0];
        pio.extend_from_slice(&[0u8; 28]);
        let join = |a: &[u8], b: &[u8]| [a, b].concat();

        let mut overrun = good.clone();
        overrun[1] = 2;
        let mut two_units = good.clone();
        two_units[1] = 2;
        two_units.extend_from_slice(&[0u8; 8]);
        let mut stub = good.clone();
        stub.push(1);
        let mut tail7 = good.clone();
        tail7.extend_from_slice(&[9u8; 7]);
        let mut huge = vec![5u8, 255];
        huge.extend_from_slice(&[0u8; 100]);

        let none: Vec<(&str, Vec<u8>)> = vec![
            ("empty", vec![]),
            ("one octet", vec![1]),
            ("length 0", zero_len.clone()),
            ("length 0 before a good one", join(&zero_len, &good)),
            ("length 0 after a good one", join(&good, &zero_len)),
            ("claims two units, carries one", overrun),
            ("a two-unit option is not an Ethernet address", two_units),
            ("a stub after a good option", stub),
            ("seven octets after a good option", tail7),
            ("length 255 over a short list", huge),
            ("only another kind of option", join(&unknown, &pio)),
            ("target option, not source", { let mut o = good.clone(); o[0] = 2; o }),
            ("broadcast MAC", slla([0xFF; 6])),
            ("multicast MAC", slla([0x33, 0x33, 0, 0, 0, 1])),
            ("zero MAC", slla([0; 6])),
        ];
        for (name, o) in &none {
            assert_eq!(ipv6::nd_source_lla(o), None, "{name}");
        }
        assert_eq!(ipv6::nd_source_lla(&join(&unknown, &good)), Some(PEER6_MAC), "after an unknown option");
        assert_eq!(ipv6::nd_source_lla(&join(&good, &pio)), Some(PEER6_MAC), "before a prefix option");
    }

    #[test]
    fn the_source_option_walk_survives_noise() {
        let mut r = Rng::new(0x6D_0001);
        let base = [slla(PEER6_MAC), vec![5, 1, 0, 0, 0, 0, 0, 0]].concat();
        for it in 0..8000 {
            let o = if it % 2 == 0 {
                mutate(&mut r, &base)
            } else {
                let n = r.below(80);
                r.noise(n)
            };
            if let Some(mac) = ipv6::nd_source_lla(&o) {
                assert!(mac[0] & 1 == 0 && mac != [0; 6], "iteration {it}: {mac:02x?}");
            }
        }
    }

    // ── Neighbour Solicitation, end to end ───────────────────────────────────

    /// The advertisement on the wire, checked from the octets: unicast to the
    /// solicitor, hop limit 255, a correct checksum, nothing but what it says.
    fn assert_advertisement(f: &[u8], from: [u8; 16], to: [u8; 16]) {
        assert_eq!(f.len(), 14 + 40 + 32);
        assert_eq!(&f[0..6], &PEER6_MAC, "unicast to the solicitor's MAC");
        assert_eq!(f[14 + 7], 255, "ND hop limit");
        assert_eq!(&f[22..38], &from);
        assert_eq!(&f[38..54], &to);
        let na = &f[54..];
        assert_eq!(na[0], 136);
        assert_eq!(&na[8..24], &from, "the target is the address solicited");
        assert_eq!(&na[24..26], &[2, 1], "a target link-layer option");
        assert_eq!(&na[26..32], &crate::net_get_mac(), "our MAC, not someone else's memory");
        let len = (na.len() as u32).to_be_bytes();
        assert_eq!(ocsum(&[&from, &to, &len, &[0, 0, 0, 58], na]), 0, "checksum");
    }

    #[test]
    fn a_solicitation_is_answered_only_when_it_is_what_rfc_4861_says_it_must_be() {
        let _g = begin();
        let me = ll();
        let group = ipv6::solicited_node(&me);
        let good = ns(PEER6, me, me, &slla(PEER6_MAC));

        rx(&ip6(58, 255, PEER6, me, &good));
        assert_eq!(raw::count(), 1, "control: a unicast solicitation");
        assert_advertisement(&raw::all()[0], me, PEER6);

        raw::reset();
        rx(&ip6(58, 255, PEER6, group, &ns(PEER6, group, me, &slla(PEER6_MAC))));
        assert_eq!(raw::count(), 1, "control: to the solicited-node group");

        let mut other = me;
        other[15] ^= 0x55; // a different address, same prefix
        let mut not_unicast_src = PEER6;
        not_unicast_src[0] = 0xFF;
        let big_hop = |hop: u8| ip6(58, hop, PEER6, me, &good);

        let mut bad_code = good.clone();
        bad_code[1] = 1;
        sign(PEER6, me, &mut bad_code);
        let mut bad_sum = good.clone();
        bad_sum[2] ^= 0xFF;
        let mut wrong_len = ip6(58, 255, PEER6, me, &good);
        wrong_len[4..6].copy_from_slice(&((good.len() + 100) as u16).to_be_bytes());

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("hop limit 254", big_hop(254)),
            ("hop limit 64 (crossed a router)", big_hop(64)),
            ("hop limit 1", big_hop(1)),
            ("hop limit 0", big_hop(0)),
            ("code 1", ip6(58, 255, PEER6, me, &bad_code)),
            ("bad checksum", ip6(58, 255, PEER6, me, &bad_sum)),
            ("payload length beyond the frame", wrong_len),
            ("unspecified source", ip6(58, 255, [0; 16], me, &ns([0; 16], me, me, &slla(PEER6_MAC)))),
            ("multicast source", ip6(58, 255, not_unicast_src, me, &ns(not_unicast_src, me, me, &slla(PEER6_MAC)))),
            ("destination all-nodes, target ours", ip6(58, 255, PEER6, ipv6::MCAST_ALL_NODES,
                &ns(PEER6, ipv6::MCAST_ALL_NODES, me, &slla(PEER6_MAC)))),
            ("target not ours", ip6(58, 255, PEER6, me, &ns(PEER6, me, other, &slla(PEER6_MAC)))),
            ("target a group", ip6(58, 255, PEER6, group, &ns(PEER6, group, group, &slla(PEER6_MAC)))),
            ("no source link-layer option", ip6(58, 255, PEER6, me, &ns(PEER6, me, me, &[]))),
            ("zero-length option", ip6(58, 255, PEER6, me, &ns(PEER6, me, me, &[14, 0, 0, 0, 0, 0, 0, 0]))),
            ("option past the message", ip6(58, 255, PEER6, me, &ns(PEER6, me, me, &[1, 9, 0, 0, 0, 0, 0, 0]))),
            ("broadcast MAC in the option", ip6(58, 255, PEER6, me, &ns(PEER6, me, me, &slla([0xFF; 6])))),
        ];
        for (name, d) in &cases {
            raw::reset();
            rx(d);
            assert_eq!(raw::count(), 0, "{name}: drew a frame");
        }

        // Every length of the message, signed afresh so the checksum is not
        // what refuses it: none short of the option-bearing whole is answered.
        for n in 0..good.len() {
            let mut m = good[..n].to_vec();
            sign(PEER6, me, &mut m);
            raw::reset();
            rx(&ip6(58, 255, PEER6, me, &m));
            assert_eq!(raw::count(), 0, "{n}-octet solicitation answered");
        }

        // `frame_len` is the caller's claim; it may not exceed the slice.
        let d = ip6(58, 255, PEER6, me, &good);
        for (len, claim) in [(0usize, 0usize), (10, 10), (39, 40), (45, 200), (d.len() - 1, d.len())] {
            raw::reset();
            ipv6::ipv6_rx(&d[..len], claim);
            assert_eq!(raw::count(), 0, "slice {len}, claimed {claim}");
        }
    }

    #[test]
    fn echo_from_a_group_or_unspecified_source_is_not_reflected() {
        let _g = begin();
        let me = ll();
        for src in [[0u8; 16], ipv6::MCAST_ALL_NODES, [0xFF, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]] {
            let mut m = vec![128, 0, 0, 0, 0x12, 0x34, 0, 1, 0xAB, 0xCD];
            sign(src, me, &mut m);
            raw::reset();
            rx(&ip6(58, 64, src, me, &m));
            assert_eq!(raw::count(), 0, "echo from {src:02x?} reflected");
        }
        // Control.
        let mut m = vec![128, 0, 0, 0, 0x12, 0x34, 0, 1, 0xAB, 0xCD];
        sign(PEER6, me, &mut m);
        raw::reset();
        rx(&ip6(58, 64, PEER6, me, &m));
        assert_eq!(raw::count(), 1, "control: a unicast echo is answered");
    }

    #[test]
    fn solicitation_noise_never_panics_and_an_answer_goes_to_a_unicast_mac() {
        let _g = begin();
        let me = ll();
        let mut r = Rng::new(0x6D_0002);
        let base = ns(PEER6, me, me, &[slla(PEER6_MAC), vec![5, 1, 0, 0, 0, 0, 0, 0]].concat());
        for it in 0..6000 {
            let mut m = mutate(&mut r, &base);
            if it % 2 == 0 { sign(PEER6, me, &mut m); }
            let hop = if it % 5 == 0 { r.next() as u8 } else { 255 };
            raw::reset();
            rx(&ip6(58, hop, PEER6, me, &m));
            let frames = raw::all();
            assert!(frames.len() <= 1, "iteration {it}: {} frames", frames.len());
            for f in frames {
                // The only thing a solicitation can draw is one advertisement.
                assert!(f.len() == 14 + 40 + 32 && f[54] == 136, "iteration {it}: odd frame of {}", f.len());
                assert!(f[0] & 1 == 0 && f[0..6] != [0; 6], "iteration {it}: sent to {:02x?}", &f[0..6]);
                assert_eq!(f[14 + 7], 255, "iteration {it}");
                let na = &f[54..];
                let len = (na.len() as u32).to_be_bytes();
                assert_eq!(ocsum(&[&f[22..38], &f[38..54], &len, &[0, 0, 0, 58], na]), 0, "iteration {it}");
            }
        }
    }

    // ── Router Advertisement ─────────────────────────────────────────────────

    fn pio(prefix_len: u8, flags: u8, valid: u32, preferred: u32, prefix: [u8; 8]) -> Vec<u8> {
        let mut o = vec![3, 4, prefix_len, flags];
        o.extend_from_slice(&valid.to_be_bytes());
        o.extend_from_slice(&preferred.to_be_bytes());
        o.extend_from_slice(&[0; 4]);
        o.extend_from_slice(&prefix);
        o.extend_from_slice(&[0; 8]);
        o
    }

    /// A signed Router Advertisement from `src` carrying `opts`.
    fn ra(src: [u8; 16], code: u8, opts: &[u8]) -> Vec<u8> {
        let mut m = vec![134, code, 0, 0, 64, 0, 0x07, 0x08];
        m.extend_from_slice(&[0; 8]);
        m.extend_from_slice(opts);
        sign(src, ipv6::MCAST_ALL_NODES, &mut m);
        m
    }

    fn deliver_ra(hop: u8, src: [u8; 16], m: &[u8]) {
        rx(&ip6(58, hop, src, ipv6::MCAST_ALL_NODES, m));
    }

    fn our_global() -> [u8; 16] {
        let mut g = [0u8; 16];
        g[..8].copy_from_slice(&PREFIX);
        g[8..].copy_from_slice(&ll()[8..]);
        g
    }

    /// The address an advertisement formed, read off the wire: the target of
    /// the Duplicate Address Detection probe it set off (a solicitation from
    /// `::`, RFC 4862 §5.4.2), which leaves while the address is tentative and
    /// so before `ipv6_global` names it.
    fn formed() -> Option<[u8; 16]> {
        raw::all().iter()
            .find(|f| f.len() >= 78 && f[12..14] == [0x86, 0xDD] && f[54] == 135 && f[22..38] == [0u8; 16])
            .map(|f| f[62..78].try_into().unwrap())
    }

    #[test]
    fn a_router_advertisement_configures_an_address_only_when_every_check_passes() {
        let _g = begin();
        let good_pio = pio(64, 0xC0, 100_000, 50_000, PREFIX);
        let try_ra = |hop: u8, src: [u8; 16], m: &[u8]| -> Option<[u8; 16]> {
            ipv6::ipv6_init(&MAC6); // SLAAC state back to nothing
            raw::reset();
            deliver_ra(hop, src, m);
            formed()
        };

        assert_eq!(try_ra(255, PEER6, &ra(PEER6, 0, &good_pio)), Some(our_global()), "control");
        assert_eq!(
            try_ra(255, PEER6, &ra(PEER6, 0, &[slla(PEER6_MAC), good_pio.clone()].concat())),
            Some(our_global()), "control: with a source option first",
        );

        let zero_len = vec![14u8, 0, 0, 0, 0, 0, 0, 0];
        let mut pio3 = good_pio.clone();
        pio3[1] = 3; // 24 octets claimed of 32 carried: not a prefix option
        let mut pio_over = good_pio.clone();
        pio_over[1] = 9; // 72 octets claimed, 32 carried
        let global_src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut fe80_prefix = PREFIX;
        fe80_prefix[0] = 0xFE;
        fe80_prefix[1] = 0x80;
        let mut mc_prefix = PREFIX;
        mc_prefix[0] = 0xFF;

        let cases: Vec<(&str, u8, [u8; 16], Vec<u8>)> = vec![
            ("hop limit 64", 64, PEER6, ra(PEER6, 0, &good_pio)),
            ("hop limit 254", 254, PEER6, ra(PEER6, 0, &good_pio)),
            ("hop limit 0", 0, PEER6, ra(PEER6, 0, &good_pio)),
            ("global source", 255, global_src, ra(global_src, 0, &good_pio)),
            ("multicast source", 255, ipv6::MCAST_ALL_NODES, ra(ipv6::MCAST_ALL_NODES, 0, &good_pio)),
            ("unspecified source", 255, [0; 16], ra([0; 16], 0, &good_pio)),
            ("code 1", 255, PEER6, ra(PEER6, 1, &good_pio)),
            ("zero-length option before the prefix", 255, PEER6,
                ra(PEER6, 0, &[zero_len.clone(), good_pio.clone()].concat())),
            ("zero-length option after the prefix", 255, PEER6,
                ra(PEER6, 0, &[good_pio.clone(), zero_len.clone()].concat())),
            ("prefix option of 24 octets", 255, PEER6, ra(PEER6, 0, &pio3)),
            ("prefix option running past the message", 255, PEER6, ra(PEER6, 0, &pio_over)),
            ("prefix option cut short", 255, PEER6, ra(PEER6, 0, &good_pio[..20])),
            ("a lone option header byte", 255, PEER6, ra(PEER6, 0, &[3])),
            ("prefix length 65", 255, PEER6, ra(PEER6, 0, &pio(65, 0xC0, 100_000, 50_000, PREFIX))),
            ("prefix length 0", 255, PEER6, ra(PEER6, 0, &pio(0, 0xC0, 100_000, 50_000, PREFIX))),
            ("autonomous flag clear", 255, PEER6, ra(PEER6, 0, &pio(64, 0x80, 100_000, 50_000, PREFIX))),
            ("link-local prefix", 255, PEER6, ra(PEER6, 0, &pio(64, 0xC0, 100_000, 50_000, fe80_prefix))),
            ("multicast prefix", 255, PEER6, ra(PEER6, 0, &pio(64, 0xC0, 100_000, 50_000, mc_prefix))),
            ("unspecified prefix", 255, PEER6, ra(PEER6, 0, &pio(64, 0xC0, 100_000, 50_000, [0; 8]))),
            ("valid lifetime 0", 255, PEER6, ra(PEER6, 0, &pio(64, 0xC0, 0, 0, PREFIX))),
            ("preferred beyond valid", 255, PEER6, ra(PEER6, 0, &pio(64, 0xC0, 1000, 2000, PREFIX))),
        ];
        for (name, hop, src, m) in &cases {
            assert_eq!(try_ra(*hop, *src, m), None, "{name}: configured an address");
        }

        // Truncated, and signed afresh so the length is what refuses it.
        let whole = ra(PEER6, 0, &good_pio);
        for n in 0..whole.len() {
            let mut m = whole[..n].to_vec();
            sign(PEER6, ipv6::MCAST_ALL_NODES, &mut m);
            assert_eq!(try_ra(255, PEER6, &m), None, "{n}-octet advertisement configured an address");
        }
    }

    #[test]
    fn router_advertisement_noise_never_panics_and_only_a_sane_prefix_is_taken() {
        let _g = begin();
        let mut r = Rng::new(0x6D_0003);
        let base = ra(PEER6, 0, &[slla(PEER6_MAC), pio(64, 0xC0, 100_000, 50_000, PREFIX)].concat());
        for it in 0..3000 {
            ipv6::ipv6_init(&MAC6);
            raw::reset();
            let mut m = mutate(&mut r, &base);
            if it % 2 == 0 { sign(PEER6, ipv6::MCAST_ALL_NODES, &mut m); }
            let hop = if it % 7 == 0 { r.next() as u8 } else { 255 };
            deliver_ra(hop, PEER6, &m);
            if let Some(g) = formed() {
                assert_eq!(&g[8..], &ll()[8..], "iteration {it}: interface id");
                assert!(g[0] != 0x00 && g[0] != 0xFF && !(g[0] == 0xFE && g[1] & 0xC0 == 0x80),
                        "iteration {it}: prefix {:02x?}", &g[..8]);
                assert!(g[..8] != [0u8; 8], "iteration {it}");
            }
        }
    }
}
