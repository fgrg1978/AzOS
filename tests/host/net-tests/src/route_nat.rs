// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Forwarding between interfaces and NAPT (`crates/net/net/src/ip.rs`
//! `forward`, `nat.rs`).
//!
//! **The real `ip.rs`, `arp.rs`, `filter.rs` and `nat.rs` are in the loop.** The
//! model is a gateway with two interfaces, eth0 on the LAN (`10.1.0.1/24`, a
//! host at `10.1.0.9`) and eth1 on the uplink (`192.0.2.2/24`, its lease gateway
//! at `192.0.2.1`, a remote host at `198.51.100.7`). A test hands a packet to
//! `ip::handle` as the interface it arrives on would and reads the frames the
//! stack put on the recorded wire: which link a frame left by is its source MAC,
//! where it goes next is its destination MAC, and every packet is parsed back
//! and its IP, UDP, TCP and ICMP checksums recomputed here (`rfc1071`, not the
//! kernel's), so a rewrite that leaves a stale checksum fails.
//!
//! **Canary discipline.** Every translation or refusal has its mirror: the same
//! packet from a different port, remote or interface, with the mapping expired,
//! or with forwarding off, which must produce the opposite observable.

use crate::NET_SERIAL as SERIAL;
use crate::filter::{self, ConnPhase, ConnState, Hook, PacketFilter, PacketView, Verdict};
use crate::ip::nat;
use crate::{arp, ip, raw};
use std::sync::Mutex;

const T0: u64 = 90_000;
const SEC: u64 = azos_drv_sys::timebase::TIMER_FREQ;

const MAC_L: [u8; 6] = [0x02, 0xAA, 0x00, 0x00, 0x00, 0x01];
const IP_L: [u8; 4] = [10, 1, 0, 1];
const HOST: [u8; 4] = [10, 1, 0, 9];
const HOST_MAC: [u8; 6] = [0x02, 0xA0, 0xA0, 0xA0, 0xA0, 0x09];
const HOST2: [u8; 4] = [10, 1, 0, 50];
const HOST2_MAC: [u8; 6] = [0x02, 0xA0, 0xA0, 0xA0, 0xA0, 0x50];
const MAC_W: [u8; 6] = [0x02, 0xBB, 0x00, 0x00, 0x00, 0x02];
const IP_W: [u8; 4] = [192, 0, 2, 2];
const GW: [u8; 4] = [192, 0, 2, 1];
const GW_MAC: [u8; 6] = [0x02, 0x47, 0x57, 0x00, 0x02, 0x01];
const REMOTE: [u8; 4] = [198, 51, 100, 7];
const REMOTE2: [u8; 4] = [198, 51, 100, 8];
const ROUTER: [u8; 4] = [203, 0, 113, 1];

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const FIN: u8 = 0x01;
const PORT_MIN: u16 = azos_limits::NAT_PORT_MIN as u16;
const PORT_MAX: u16 = azos_limits::NAT_PORT_MAX as u16;

/// Holds the suite's lock and, on the way out, puts the stack back to what the
/// other modules expect: one host interface, no filter, forwarding and NAT off.
struct Session(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

impl Drop for Session {
    fn drop(&mut self) {
        filter::reset_for_test();
        nat::reset_for_test(false);
        ip::set_forwarding_for_test(false);
        ip::ifaces_reset_for_test();
    }
}

/// The gateway: eth0 (1) on the LAN, eth1 (2) on the uplink with a lease
/// gateway, so eth1 is the uplink. Forwarding and the masquerade on.
fn begin() -> Session {
    begin_mtu(1500)
}

fn begin_mtu(wan_mtu: u16) -> Session {
    let g = Session(SERIAL.lock().unwrap_or_else(|e| e.into_inner()));
    assert!(azos_decision::ON, "the decision ring is off: the record assertions would be vacuous");
    filter::reset_for_test();
    azos_drv_irqchip::clint::set_test_time(T0);
    crate::inbound::reset();
    raw::reset();
    arp::cache_reset_for_test();
    ip::arp_txq_reset_for_test();
    ip::ifaces_reset_for_test();
    assert_eq!(ip::iface_attach(0, MAC_L, 1500, [0; 16]), Some(1));
    assert!(ip::iface_configure(1, IP_L, [255, 255, 255, 0], [0; 4]));
    assert_eq!(ip::iface_attach(1, MAC_W, wan_mtu, [0; 16]), Some(2));
    assert!(ip::iface_configure(2, IP_W, [255, 255, 255, 0], GW));
    arp::insert_on(1, HOST, HOST_MAC);
    arp::insert_on(1, HOST2, HOST2_MAC);
    arp::insert_on(2, GW, GW_MAC);
    ip::set_forwarding_for_test(true);
    nat::reset_for_test(true);
    g
}

fn at(secs: u64) {
    azos_drv_irqchip::clint::set_test_time(T0 + secs * SEC);
}

fn now() -> u64 {
    azos_drv_sys::timebase::now()
}

// ── Packets ─────────────────────────────────────────────────────────────────

/// RFC 1071, independent of the kernel's `ip::checksum`.
fn rfc1071(parts: &[&[u8]]) -> u16 {
    let bytes: Vec<u8> = parts.concat();
    let mut acc: u64 = 0;
    for pair in bytes.chunks(2) {
        acc += (u64::from(pair[0]) << 8) | if pair.len() == 2 { u64::from(pair[1]) } else { 0 };
    }
    while acc > 0xFFFF {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    !(acc as u16)
}

fn pseudo(src: [u8; 4], dst: [u8; 4], proto: u8, len: usize) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(&[0, proto]);
    p.extend_from_slice(&(len as u16).to_be_bytes());
    p
}

fn ip_packet(proto: u8, src: [u8; 4], dst: [u8; 4], ttl: u8, df: bool, l4: &[u8]) -> Vec<u8> {
    let mut h = vec![0x45, 0, 0, 0, 0x12, 0x34, if df { 0x40 } else { 0 }, 0, ttl, proto, 0, 0];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let total = (20 + l4.len()) as u16;
    h[2..4].copy_from_slice(&total.to_be_bytes());
    let c = rfc1071(&[&h]);
    h[10..12].copy_from_slice(&c.to_be_bytes());
    h.extend_from_slice(l4);
    h
}

/// Set the TTL of an IPv4 packet and fix its header checksum.
fn set_ttl(p: &mut [u8], ttl: u8) {
    p[8] = ttl;
    p[10] = 0;
    p[11] = 0;
    let c = rfc1071(&[&p[..20]]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
}

fn udp_l4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
    let mut l4 = Vec::new();
    l4.extend_from_slice(&sport.to_be_bytes());
    l4.extend_from_slice(&dport.to_be_bytes());
    l4.extend_from_slice(&(8 + data.len() as u16).to_be_bytes());
    l4.extend_from_slice(&[0, 0]);
    l4.extend_from_slice(data);
    let c = rfc1071(&[&pseudo(src, dst, 17, l4.len()), &l4]);
    l4[6..8].copy_from_slice(&(if c == 0 { 0xFFFF } else { c }).to_be_bytes());
    l4
}

fn udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
    ip_packet(17, src, dst, 64, false, &udp_l4(src, dst, sport, dport, data))
}

fn tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8, data: &[u8]) -> Vec<u8> {
    let mut l4 = Vec::new();
    l4.extend_from_slice(&sport.to_be_bytes());
    l4.extend_from_slice(&dport.to_be_bytes());
    l4.extend_from_slice(&0x1000_0000u32.to_be_bytes());
    l4.extend_from_slice(&0x2000_0000u32.to_be_bytes());
    l4.extend_from_slice(&[0x50, flags, 0x20, 0, 0, 0, 0, 0]);
    l4.extend_from_slice(data);
    let c = rfc1071(&[&pseudo(src, dst, 6, l4.len()), &l4]);
    l4[16..18].copy_from_slice(&c.to_be_bytes());
    ip_packet(6, src, dst, 64, true, &l4)
}

fn icmp_msg(typ: u8, code: u8, rest: [u8; 4], body: &[u8]) -> Vec<u8> {
    let mut m = vec![typ, code, 0, 0];
    m.extend_from_slice(&rest);
    m.extend_from_slice(body);
    let c = rfc1071(&[&m]);
    m[2..4].copy_from_slice(&c.to_be_bytes());
    m
}

fn echo(src: [u8; 4], dst: [u8; 4], typ: u8, id: u16, seq: u16) -> Vec<u8> {
    let mut rest = [0u8; 4];
    rest[..2].copy_from_slice(&id.to_be_bytes());
    rest[2..].copy_from_slice(&seq.to_be_bytes());
    ip_packet(1, src, dst, 64, false, &icmp_msg(typ, 0, rest, b"ping"))
}

/// An IP packet's header fields and a check that every checksum in it holds.
struct Pkt {
    raw: Vec<u8>,
}

impl Pkt {
    fn src(&self) -> [u8; 4] { self.raw[12..16].try_into().unwrap() }
    fn dst(&self) -> [u8; 4] { self.raw[16..20].try_into().unwrap() }
    fn ttl(&self) -> u8 { self.raw[8] }
    fn proto(&self) -> u8 { self.raw[9] }
    fn l4(&self) -> &[u8] { &self.raw[20..] }
    fn sport(&self) -> u16 { u16::from_be_bytes([self.l4()[0], self.l4()[1]]) }
    fn dport(&self) -> u16 { u16::from_be_bytes([self.l4()[2], self.l4()[3]]) }
    fn icmp_type(&self) -> u8 { self.l4()[0] }
    fn icmp_code(&self) -> u8 { self.l4()[1] }
    fn echo_id(&self) -> u16 { u16::from_be_bytes([self.l4()[4], self.l4()[5]]) }

    /// The IP header sums to zero, and so does the transport segment with its
    /// pseudo-header (a UDP checksum of 0 is "none").
    fn checksums_hold(&self) -> bool {
        if rfc1071(&[&self.raw[..20]]) != 0 {
            return false;
        }
        let l4 = self.l4();
        match self.proto() {
            6 => rfc1071(&[&pseudo(self.src(), self.dst(), 6, l4.len()), l4]) == 0,
            17 => (l4[6] == 0 && l4[7] == 0) || rfc1071(&[&pseudo(self.src(), self.dst(), 17, l4.len()), l4]) == 0,
            1 => rfc1071(&[l4]) == 0,
            _ => true,
        }
    }

    /// For an ICMP error: the packet it quotes.
    fn quoted(&self) -> Pkt {
        Pkt { raw: self.l4()[8..].to_vec() }
    }
}

/// One frame the stack put on the wire.
struct Frame {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    pkt: Pkt,
}

/// The IPv4 frames on the wire that left with source MAC `mac`, oldest first.
fn sent_by(mac: [u8; 6]) -> Vec<Frame> {
    raw::all()
        .into_iter()
        .filter(|f| f.len() >= 34 && u16::from_be_bytes([f[12], f[13]]) == 0x0800 && f[6..12] == mac)
        .map(|f| {
            let total = u16::from_be_bytes([f[16], f[17]]) as usize;
            Frame {
                dst_mac: f[0..6].try_into().unwrap(),
                src_mac: f[6..12].try_into().unwrap(),
                pkt: Pkt { raw: f[14..14 + total].to_vec() },
            }
        })
        .collect()
}

/// A packet arrives on the LAN interface.
fn from_lan(pkt: &[u8]) {
    ip::handle(pkt, &MAC_L, &IP_L);
}

/// A packet arrives on the uplink.
fn from_wan(pkt: &[u8]) {
    ip::handle(pkt, &MAC_W, &IP_W);
}

/// Send `pkt` from the LAN and return the one frame that left the uplink.
fn out_via_wan(pkt: &[u8]) -> Frame {
    raw::reset();
    from_lan(pkt);
    let mut f = sent_by(MAC_W);
    assert_eq!(f.len(), 1, "exactly one frame must leave the uplink");
    f.remove(0)
}

fn nothing_on_the_wire() -> bool {
    sent_by(MAC_L).is_empty() && sent_by(MAC_W).is_empty()
}

// ── Forwarding ──────────────────────────────────────────────────────────────

/// **Discriminates.** Without NAT a packet for another network leaves by the
/// route's interface, unchanged but for TTL and the header checksum, to the next
/// hop's MAC; one for the uplink's own subnet goes to the host on-link. A stack
/// that kept dropping packets not for it (the mirror: forwarding off) puts
/// nothing on the wire.
#[test]
fn a_packet_for_another_network_is_routed_between_interfaces() {
    let _g = begin();
    nat::reset_for_test(false);
    let p = udp(HOST, REMOTE, 5000, 53, b"query");
    let f = out_via_wan(&p);
    assert_eq!(f.src_mac, MAC_W, "it left by the uplink");
    assert_eq!(f.dst_mac, GW_MAC, "to the next hop, the lease gateway");
    assert_eq!((f.pkt.src(), f.pkt.dst()), (HOST, REMOTE), "no NAT: the addresses are kept");
    assert_eq!((f.pkt.sport(), f.pkt.dport()), (5000, 53));
    assert_eq!(f.pkt.ttl(), 63, "TTL decremented");
    assert!(f.pkt.checksums_hold(), "header checksum rewritten, UDP checksum untouched");
    assert!(sent_by(MAC_L).is_empty(), "and nothing went back out where it came from");

    // On-link host of the uplink: the destination's own MAC.
    arp::insert_on(2, [192, 0, 2, 50], [0x02, 0x50, 0x50, 0x50, 0x50, 0x50]);
    raw::reset();
    from_lan(&udp(HOST, [192, 0, 2, 50], 5000, 53, b"q"));
    let f = sent_by(MAC_W);
    assert_eq!(f[0].dst_mac, [0x02, 0x50, 0x50, 0x50, 0x50, 0x50]);

    // Mirror: forwarding off.
    ip::set_forwarding_for_test(false);
    raw::reset();
    from_lan(&p);
    assert!(nothing_on_the_wire(), "a host drops a packet that is not for it");
}

/// **Discriminates.** The reverse direction routes too: a packet from the
/// uplink for a LAN host (no NAT) leaves on eth0 to the host's MAC.
#[test]
fn a_packet_from_the_uplink_is_routed_to_the_lan() {
    let _g = begin();
    nat::reset_for_test(false);
    raw::reset();
    from_wan(&udp(REMOTE, HOST, 53, 5000, b"answer"));
    let f = sent_by(MAC_L);
    assert_eq!(f.len(), 1);
    assert_eq!((f[0].dst_mac, f[0].pkt.dst(), f[0].pkt.ttl()), (HOST_MAC, HOST, 63));
    assert!(f[0].pkt.checksums_hold());
    assert!(sent_by(MAC_W).is_empty());
    assert_eq!(filter::stats().refused, 0, "a router with no masquerade refuses nothing here");
}

/// **Discriminates.** Behind the masquerade a packet from the uplink that
/// answers no mapping is not routed to the LAN: it is refused, counted and
/// recorded (nothing from outside opens a flow). Mirrors: the answer to a
/// mapping still gets in; with the masquerade off the same packet is routed.
#[test]
fn an_unsolicited_packet_from_the_uplink_is_refused_behind_the_masquerade() {
    let _g = begin();
    raw::reset();
    from_wan(&udp(REMOTE, HOST, 53, 5000, b"unasked"));
    assert!(nothing_on_the_wire(), "not routed to the LAN, not translated");
    let s = filter::stats();
    assert_eq!((s.refused, s.recorded), (1, 1), "refused through the filter path");

    // Also with a mapping present: another port, and another remote, answer nothing.
    let sent = out_via_wan(&udp(HOST, REMOTE, 5000, 53, b"q"));
    let wan = sent.pkt.sport();
    raw::reset();
    from_wan(&udp(REMOTE, HOST, 53, wan, b"to the private address"));
    from_wan(&udp(REMOTE2, IP_W, 53, wan, b"another remote"));
    assert!(nothing_on_the_wire());
    assert_eq!(filter::stats().refused, 2, "the first is refused; the second is addressed to this host, a local delivery that matches no socket");

    // Mirror: the real answer is translated back and delivered.
    from_wan(&udp(REMOTE, IP_W, 53, wan, b"answer"));
    let f = sent_by(MAC_L);
    assert_eq!((f.len(), f[0].pkt.dst(), f[0].pkt.dport()), (1, HOST, 5000));
    assert_eq!(filter::stats().refused, 2, "an answer is not a refusal");

    // Mirror: masquerade off, the unsolicited packet is routed.
    nat::reset_for_test(false);
    raw::reset();
    from_wan(&udp(REMOTE, HOST, 53, 5000, b"unasked"));
    assert_eq!(sent_by(MAC_L).len(), 1);
    assert_eq!(filter::stats().refused, 2);
}

/// **Discriminates.** TTL 1 is not forwarded and draws ICMP "time exceeded" to
/// the sender from the interface it came in on, quoting the packet. Mirror: TTL
/// 2 is forwarded with TTL 1 and draws nothing.
#[test]
fn ttl_expiry_is_answered_not_forwarded() {
    let _g = begin();
    let mut p = udp(HOST, REMOTE, 5000, 53, b"q");
    set_ttl(&mut p, 1);
    raw::reset();
    from_lan(&p);
    assert!(sent_by(MAC_W).is_empty(), "not forwarded");
    let e = sent_by(MAC_L);
    assert_eq!(e.len(), 1);
    assert_eq!((e[0].pkt.proto(), e[0].pkt.icmp_type(), e[0].pkt.icmp_code()), (1, 11, 0));
    assert_eq!((e[0].pkt.src(), e[0].pkt.dst(), e[0].dst_mac), (IP_L, HOST, HOST_MAC));
    assert!(e[0].pkt.checksums_hold());
    assert_eq!(e[0].pkt.quoted().raw[..28], p[..28], "the header and 8 bytes are quoted");

    set_ttl(&mut p, 2);
    raw::reset();
    from_lan(&p);
    assert_eq!(sent_by(MAC_W).len(), 1);
    assert_eq!(sent_by(MAC_W)[0].pkt.ttl(), 1);
    assert!(sent_by(MAC_L).is_empty());
}

/// **Discriminates.** A destination no route covers draws ICMP "network
/// unreachable"; one the egress link cannot carry draws "fragmentation needed"
/// carrying that link's MTU. Mirrors: a covered destination and a packet that
/// fits go through.
#[test]
fn unroutable_and_oversize_packets_are_answered() {
    let _g = begin_mtu(600);
    // The lease gateway is the only default; take it away.
    assert!(ip::iface_configure(2, IP_W, [255, 255, 255, 0], [0; 4]));
    raw::reset();
    from_lan(&udp(HOST, REMOTE, 5000, 53, b"q"));
    let e = sent_by(MAC_L);
    assert_eq!(e.len(), 1, "a network-unreachable error goes back");
    assert_eq!((e[0].pkt.icmp_type(), e[0].pkt.icmp_code()), (3, 0));
    assert!(sent_by(MAC_W).is_empty());

    assert!(ip::iface_configure(2, IP_W, [255, 255, 255, 0], GW));
    raw::reset();
    from_lan(&udp(HOST, REMOTE, 5000, 53, &[7u8; 1000]));
    let e = sent_by(MAC_L);
    assert_eq!(e.len(), 1);
    assert_eq!((e[0].pkt.icmp_type(), e[0].pkt.icmp_code()), (3, 4));
    assert_eq!(u16::from_be_bytes([e[0].pkt.l4()[6], e[0].pkt.l4()[7]]), 600, "next-hop MTU");
    assert!(sent_by(MAC_W).is_empty());

    raw::reset();
    from_lan(&udp(HOST, REMOTE, 5000, 53, &[7u8; 400]));
    assert_eq!(sent_by(MAC_W).len(), 1, "a packet that fits goes");
    assert!(sent_by(MAC_L).is_empty());
}

/// **Discriminates.** A packet that would leave by the interface it arrived on
/// (hairpin) is refused, counted and recorded, and nothing is sent. Mirror: the
/// same host's packet for the uplink is forwarded.
#[test]
fn a_packet_that_would_leave_by_the_way_it_came_is_refused() {
    let _g = begin();
    raw::reset();
    from_lan(&udp(HOST, HOST2, 5000, 53, b"q"));
    assert!(nothing_on_the_wire(), "no hairpin, no redirect");
    let s = filter::stats();
    assert_eq!((s.refused, s.recorded), (1, 1), "refused through the filter path");

    from_lan(&udp(HOST, REMOTE, 5000, 53, b"q"));
    assert_eq!(sent_by(MAC_W).len(), 1);
    assert_eq!(filter::stats().refused, 1);
}

/// **Discriminates.** Broadcast, multicast, loopback and directed-broadcast
/// destinations are never forwarded; a packet for another address of the gateway
/// is not either (it is not delivered locally: weak host model is not used).
#[test]
fn only_unicast_for_other_hosts_is_forwarded() {
    let _g = begin();
    raw::reset();
    for dst in [[224, 0, 0, 251], [255, 255, 255, 255], [127, 0, 0, 1], [192, 0, 2, 255], IP_W, [240, 0, 0, 1]] {
        from_lan(&udp(HOST, dst, 5000, 53, b"q"));
    }
    assert!(nothing_on_the_wire());
    // Refused and recorded: loopback, the uplink's directed broadcast, the
    // gateway's own uplink address, class E. Not refused: multicast (routine on
    // a LAN, dropped quietly) and the limited broadcast (the stack's own).
    let s = filter::stats();
    assert_eq!((s.refused, s.recorded), (4, 4));
    // An unroutable source is refused too.
    for src in [[127, 0, 0, 1], [0, 0, 0, 0], [240, 0, 0, 1]] {
        from_lan(&udp(src, REMOTE, 5000, 53, b"q"));
    }
    assert!(nothing_on_the_wire());
    assert_eq!(filter::stats().refused, 7);
    // Mirror: a unicast destination goes.
    from_lan(&udp(HOST, REMOTE, 5000, 53, b"q"));
    assert_eq!(sent_by(MAC_W).len(), 1);
}

// ── NAT: translate and reverse ──────────────────────────────────────────────

/// **Discriminates.** A UDP flow out is masqueraded: the uplink's address, a
/// port of the NAT range, valid checksums; the same flow keeps its port, another
/// flow of the same host gets another. The answer from the remote to that port
/// is put back to the LAN host and its port, with valid checksums. Mirrors: the
/// answer from another remote port, another remote address or to another port
/// is not forwarded.
#[test]
fn udp_is_masqueraded_and_the_answer_is_translated_back() {
    let _g = begin();
    let f = out_via_wan(&udp(HOST, REMOTE, 5000, 53, b"query"));
    assert_eq!((f.pkt.src(), f.pkt.dst()), (IP_W, REMOTE), "source is the uplink's address");
    let wan_port = f.pkt.sport();
    assert!((PORT_MIN..=PORT_MAX).contains(&wan_port), "from the NAT range");
    assert_eq!(f.pkt.dport(), 53);
    assert!(f.pkt.checksums_hold(), "UDP checksum updated, not stale");
    assert_eq!(&f.pkt.l4()[8..], b"query");

    // Same flow, same port; another flow, another port.
    assert_eq!(out_via_wan(&udp(HOST, REMOTE, 5000, 53, b"again")).pkt.sport(), wan_port);
    let other = out_via_wan(&udp(HOST, REMOTE, 5001, 53, b"second")).pkt.sport();
    assert_ne!(other, wan_port);

    // Mirrors first: nothing that is not the remote's answer to that port.
    raw::reset();
    from_wan(&udp(REMOTE, IP_W, 54, wan_port, b"x"));
    from_wan(&udp(REMOTE2, IP_W, 53, wan_port, b"x"));
    from_wan(&udp(REMOTE, IP_W, 53, wan_port.wrapping_add(7), b"x"));
    assert!(nothing_on_the_wire(), "a wrong remote port, remote or local port is not NAT traffic");

    from_wan(&udp(REMOTE, IP_W, 53, wan_port, b"answer"));
    let back = sent_by(MAC_L);
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].dst_mac, HOST_MAC);
    assert_eq!((back[0].pkt.src(), back[0].pkt.dst()), (REMOTE, HOST));
    assert_eq!((back[0].pkt.sport(), back[0].pkt.dport()), (53, 5000));
    assert_eq!(back[0].pkt.ttl(), 63);
    assert!(back[0].pkt.checksums_hold());
    assert_eq!(&back[0].pkt.l4()[8..], b"answer");
}

/// **Discriminates.** A UDP datagram with no checksum keeps having none.
#[test]
fn a_udp_datagram_without_checksum_stays_without() {
    let _g = begin();
    let mut l4 = udp_l4(HOST, REMOTE, 5000, 53, b"query");
    l4[6] = 0;
    l4[7] = 0;
    let f = out_via_wan(&ip_packet(17, HOST, REMOTE, 64, false, &l4));
    assert_eq!(&f.pkt.l4()[6..8], &[0, 0]);
    assert_eq!(f.pkt.src(), IP_W);
    assert!(f.pkt.checksums_hold());
}

/// **Discriminates.** A TCP connection: only the SYN opens a mapping (an ACK
/// with nothing behind it is refused and recorded), the SYN-ACK is translated
/// back, data flows both ways with valid checksums, and the flow hook is told
/// its phase.
#[test]
fn tcp_is_masqueraded_and_only_a_syn_opens_a_mapping() {
    let _g = begin();
    raw::reset();
    from_lan(&tcp(HOST, REMOTE, 40000, 80, ACK, b"data"));
    assert!(nothing_on_the_wire(), "no mid-stream packet without a mapping");
    assert_eq!(filter::stats().refused, 1);

    let syn = out_via_wan(&tcp(HOST, REMOTE, 40000, 80, SYN, b""));
    assert_eq!((syn.pkt.src(), syn.pkt.dst()), (IP_W, REMOTE));
    let p = syn.pkt.sport();
    assert!((PORT_MIN..=PORT_MAX).contains(&p));
    assert!(syn.pkt.checksums_hold(), "TCP checksum updated");

    raw::reset();
    from_wan(&tcp(REMOTE, IP_W, 80, p, SYN | ACK, b""));
    let r = sent_by(MAC_L);
    assert_eq!(r.len(), 1);
    assert_eq!((r[0].pkt.dst(), r[0].pkt.dport(), r[0].pkt.sport()), (HOST, 40000, 80));
    assert!(r[0].pkt.checksums_hold());
    assert_eq!(r[0].pkt.l4()[13], SYN | ACK, "flags untouched");

    let d = out_via_wan(&tcp(HOST, REMOTE, 40000, 80, ACK, b"hello"));
    assert_eq!((d.pkt.sport(), &d.pkt.l4()[20..]), (p, &b"hello"[..]));
    assert!(d.pkt.checksums_hold());
}

/// **Discriminates.** Other protocols (here GRE) and an ICMP error from the LAN
/// with no flow behind it are refused and recorded, not forwarded in the clear.
/// Mirror: with the masquerade off the same GRE packet is routed.
#[test]
fn a_protocol_without_ports_is_refused() {
    let _g = begin();
    let gre = ip_packet(47, HOST, REMOTE, 64, false, &[0u8; 8]);
    raw::reset();
    from_lan(&gre);
    assert!(nothing_on_the_wire());
    assert_eq!(filter::stats().refused, 1);

    let unreach = ip_packet(1, HOST, REMOTE, 64, false, &icmp_msg(3, 3, [0; 4], &udp(REMOTE, HOST, 1, 2, b"")[..28]));
    from_lan(&unreach);
    assert!(nothing_on_the_wire());
    assert_eq!(filter::stats().refused, 2);

    nat::reset_for_test(false);
    raw::reset();
    from_lan(&gre);
    assert_eq!(sent_by(MAC_W).len(), 1, "no NAT: routed as is");
}

/// **Discriminates.** ICMP echo: the identifier is mapped, the reply's is put
/// back, checksums hold. Mirror: a reply with another identifier, or an echo
/// request from the remote, is not forwarded.
#[test]
fn icmp_echo_is_masqueraded_by_identifier() {
    let _g = begin();
    let f = out_via_wan(&echo(HOST, REMOTE, 8, 0x1234, 1));
    assert_eq!((f.pkt.src(), f.pkt.dst()), (IP_W, REMOTE));
    let id = f.pkt.echo_id();
    assert!((PORT_MIN..=PORT_MAX).contains(&id));
    assert!(f.pkt.checksums_hold());

    raw::reset();
    from_wan(&echo(REMOTE, IP_W, 0, id.wrapping_add(1), 1));
    from_wan(&echo(REMOTE2, IP_W, 0, id, 1));
    assert!(nothing_on_the_wire(), "another identifier or remote is not an answer");
    assert!(sent_by(MAC_L).is_empty());

    from_wan(&echo(REMOTE, IP_W, 0, id, 1));
    let r = sent_by(MAC_L);
    assert_eq!(r.len(), 1);
    assert_eq!((r[0].pkt.dst(), r[0].pkt.echo_id(), r[0].pkt.icmp_type()), (HOST, 0x1234, 0));
    assert!(r[0].pkt.checksums_hold());
}

// ── NAT: ICMP errors ────────────────────────────────────────────────────────

/// An ICMP error from `ROUTER` to the uplink quoting the first 28 bytes of `quoted`.
fn error_about(quoted: &[u8], typ: u8, code: u8) -> Vec<u8> {
    ip_packet(1, ROUTER, IP_W, 60, false, &icmp_msg(typ, code, [0; 4], &quoted[..28]))
}

/// **Discriminates.** An ICMP error about a translated UDP flow reaches the LAN
/// host with everything it quotes put back: outer destination, quoted source
/// address and port, quoted header checksum, quoted UDP checksum (it is in the
/// eight bytes) and its own checksum, so the host recognises the packet it sent.
/// Mirror: an error quoting a port nobody holds is not forwarded.
#[test]
fn an_icmp_error_about_a_udp_flow_is_translated_back() {
    let _g = begin();
    let original = udp(HOST, REMOTE, 5000, 33434, b"probe");
    let sent = out_via_wan(&original);
    let wan = sent.pkt.sport();

    raw::reset();
    let stranger = udp(IP_W, REMOTE, wan.wrapping_add(1), 33434, b"probe");
    from_wan(&error_about(&stranger, 3, 3));
    assert!(nothing_on_the_wire(), "an error about no mapping is not forwarded");

    for (typ, code) in [(3, 3), (11, 0)] {
        raw::reset();
        from_wan(&error_about(&sent.pkt.raw, typ, code));
        let e = sent_by(MAC_L);
        assert_eq!(e.len(), 1, "type {typ}");
        let e = &e[0];
        assert_eq!((e.pkt.src(), e.pkt.dst(), e.dst_mac), (ROUTER, HOST, HOST_MAC));
        assert_eq!((e.pkt.icmp_type(), e.pkt.icmp_code()), (typ, code));
        assert!(e.pkt.checksums_hold(), "the error's own checksum");
        let q = e.pkt.quoted();
        assert_eq!(rfc1071(&[&q.raw[..20]]), 0, "the quoted header's checksum");
        assert_eq!((q.src(), q.dst(), q.sport(), q.dport()), (HOST, REMOTE, 5000, 33434));
        assert_eq!(q.raw[20..28], original[20..28], "the quoted transport header is the one the host sent");
    }
}

/// **Discriminates.** The quoted header's length is the one `parse_in` checked
/// and `rewrite_error` indexes with (not a fixed 20): a quote that carries IP
/// options (IHL 6) is translated at its real offsets, header checksum over 24
/// bytes and UDP header behind them.
#[test]
fn an_icmp_error_quoting_a_header_with_options_is_translated_at_its_own_length() {
    let _g = begin();
    let original = udp(HOST, REMOTE, 5000, 33434, b"probe");
    let sent = out_via_wan(&original);
    // The packet the uplink saw, with four NOP options added to its header.
    let mut q = sent.pkt.raw[..20].to_vec();
    q[0] = 0x46;
    q.extend_from_slice(&[1, 1, 1, 1]);
    q[10] = 0;
    q[11] = 0;
    let c = rfc1071(&[&q]);
    q[10..12].copy_from_slice(&c.to_be_bytes());
    q.extend_from_slice(&sent.pkt.raw[20..28]);
    assert_eq!(q.len(), 32);

    raw::reset();
    from_wan(&ip_packet(1, ROUTER, IP_W, 60, false, &icmp_msg(3, 3, [0; 4], &q)));
    let e = sent_by(MAC_L);
    assert_eq!(e.len(), 1);
    assert!(e[0].pkt.checksums_hold(), "the error's own checksum");
    let r = e[0].pkt.quoted().raw;
    assert_eq!(r[0], 0x46);
    assert_eq!(r[12..16], HOST, "quoted source address");
    assert_eq!(rfc1071(&[&r[..24]]), 0, "the quoted header's checksum over its 24 bytes");
    assert_eq!(r[24..32], original[20..28], "the quoted UDP header behind the options is the one the host sent");
}

/// **Discriminates.** The same for a TCP flow (the quote holds ports and
/// sequence number only) and for an ICMP echo (the identifier is in the quote).
#[test]
fn an_icmp_error_about_a_tcp_or_echo_flow_is_translated_back() {
    let _g = begin();
    let original = tcp(HOST, REMOTE, 40000, 80, SYN, b"");
    let sent = out_via_wan(&original);
    raw::reset();
    from_wan(&error_about(&sent.pkt.raw, 3, 1));
    let e = sent_by(MAC_L);
    assert_eq!(e.len(), 1);
    assert!(e[0].pkt.checksums_hold());
    let q = e[0].pkt.quoted();
    assert_eq!((q.src(), q.sport(), q.dport()), (HOST, 40000, 80));
    assert_eq!(rfc1071(&[&q.raw[..20]]), 0);

    let req = echo(HOST, REMOTE, 8, 0x4321, 9);
    let sent = out_via_wan(&req);
    raw::reset();
    from_wan(&error_about(&sent.pkt.raw, 11, 0));
    let e = sent_by(MAC_L);
    assert_eq!(e.len(), 1);
    assert!(e[0].pkt.checksums_hold());
    let q = e[0].pkt.quoted();
    assert_eq!((q.src(), q.echo_id()), (HOST, 0x4321));
    assert_eq!(q.raw[20..28], req[20..28], "the quoted ICMP header, checksum included");
}

/// **Discriminates.** An error does not renew or answer the mapping it is
/// about: after the flow's idle time the same error is no longer forwarded.
#[test]
fn an_icmp_error_does_not_keep_a_mapping_alive() {
    let _g = begin();
    let sent = out_via_wan(&udp(HOST, REMOTE, 5000, 33434, b"probe"));
    let life = azos_limits::NAT_UDP_TIMEOUT_S as u64;
    at(life - 1);
    raw::reset();
    from_wan(&error_about(&sent.pkt.raw, 3, 3));
    assert_eq!(sent_by(MAC_L).len(), 1, "still mapped");
    at(life + 1);
    raw::reset();
    from_wan(&error_about(&sent.pkt.raw, 3, 3));
    assert!(nothing_on_the_wire(), "the error did not renew it");
}

// ── NAT: hairpin and the filter ─────────────────────────────────────────────

/// **Discriminates.** A LAN host aiming at the uplink's own address and a mapped
/// port is not translated back (hairpin refused): nothing goes out. Mirror: the
/// same datagram from the remote, on the uplink, is.
#[test]
fn a_lan_host_cannot_reach_a_mapping_through_the_uplink_address() {
    let _g = begin();
    let sent = out_via_wan(&udp(HOST, REMOTE, 5000, 53, b"q"));
    let wan = sent.pkt.sport();
    raw::reset();
    from_lan(&udp(HOST2, IP_W, 53, wan, b"hairpin"));
    assert!(nothing_on_the_wire());
    let s = filter::stats();
    assert_eq!((s.refused, s.recorded), (1, 1), "the hairpin is refused through the filter path");
    from_wan(&udp(REMOTE, IP_W, 53, wan, b"real"));
    assert_eq!(sent_by(MAC_L).len(), 1);
    assert_eq!(filter::stats().refused, 1, "the real answer is no refusal");
}

/// What the forward hook was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Call {
    hook: Hook,
    src: [u8; 4],
    dst: [u8; 4],
    sport: Option<u16>,
    dport: Option<u16>,
    conn: Option<ConnState>,
}

struct Probe {
    calls: Mutex<Vec<Call>>,
    verdict: Mutex<Verdict>,
}

static PROBE: Probe = Probe { calls: Mutex::new(Vec::new()), verdict: Mutex::new(Verdict::Accept) };

impl PacketFilter for Probe {
    fn check(&self, hook: Hook, pkt: &PacketView, conn: Option<&ConnState>) -> Verdict {
        self.calls.lock().unwrap().push(Call {
            hook,
            src: pkt.src[..4].try_into().unwrap(),
            dst: pkt.dst[..4].try_into().unwrap(),
            sport: pkt.src_port(),
            dport: pkt.dst_port(),
            conn: conn.copied(),
        });
        *self.verdict.lock().unwrap()
    }
}

/// **Discriminates.** The forward hook sees the LAN's addresses on both legs: an
/// outbound packet before the source is rewritten (flow phase New), the answer
/// after the destination is put back (Established, reply). Not the ingress or
/// egress hook. A `Drop` there stops the packet before a mapping is made: the
/// table is empty and the answer is not forwarded (the mirror, with an accepting
/// filter, makes the mapping).
#[test]
fn the_forward_hook_sees_lan_addresses_and_runs_before_the_mapping() {
    let _g = begin();
    *PROBE.calls.lock().unwrap() = Vec::new();
    *PROBE.verdict.lock().unwrap() = Verdict::Drop;
    filter::set_filter(&PROBE);
    raw::reset();
    from_lan(&udp(HOST, REMOTE, 5000, 53, b"q"));
    assert!(nothing_on_the_wire());
    assert_eq!(nat::tracked(now()), 0, "a dropped packet makes no mapping");
    assert_eq!(filter::stats().refused, 1);

    *PROBE.verdict.lock().unwrap() = Verdict::Accept;
    *PROBE.calls.lock().unwrap() = Vec::new();
    let sent = out_via_wan(&udp(HOST, REMOTE, 5000, 53, b"q"));
    let wan = sent.pkt.sport();
    assert_eq!(nat::tracked(now()), 1);
    from_wan(&udp(REMOTE, IP_W, 53, wan, b"a"));
    let calls = PROBE.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2, "one question per forwarded packet, no other hook");
    assert_eq!(calls[0], Call {
        hook: Hook::Forward, src: HOST, dst: REMOTE, sport: Some(5000), dport: Some(53),
        conn: Some(ConnState { phase: ConnPhase::New, reply: false }),
    });
    assert_eq!(calls[1], Call {
        hook: Hook::Forward, src: REMOTE, dst: HOST, sport: Some(53), dport: Some(5000),
        conn: Some(ConnState { phase: ConnPhase::Established, reply: true }),
    });
    assert_eq!(sent_by(MAC_L).len(), 1);
}

// ── NAT: table, timeouts ────────────────────────────────────────────────────

/// **Discriminates.** UDP mappings expire after `NAT_UDP_TIMEOUT_S` without a
/// packet in either direction, and every packet renews them. Mirror: the answer
/// just inside the timeout passes.
#[test]
fn a_udp_mapping_expires_when_idle_and_is_renewed_by_traffic() {
    let _g = begin();
    let life = azos_limits::NAT_UDP_TIMEOUT_S as u64;
    let wan = out_via_wan(&udp(HOST, REMOTE, 5000, 53, b"q")).pkt.sport();

    at(life - 1);
    raw::reset();
    from_wan(&udp(REMOTE, IP_W, 53, wan, b"a"));
    assert_eq!(sent_by(MAC_L).len(), 1, "inside the timeout");

    // That answer renewed it: a second one the same distance later still passes ...
    at(2 * life - 2);
    raw::reset();
    from_wan(&udp(REMOTE, IP_W, 53, wan, b"a"));
    assert_eq!(sent_by(MAC_L).len(), 1, "renewed by the previous packet");

    // ... and one a whole timeout after the last does not.
    at(3 * life - 1);
    raw::reset();
    from_wan(&udp(REMOTE, IP_W, 53, wan, b"a"));
    assert!(nothing_on_the_wire(), "expired");
    assert_eq!(nat::tracked(now()), 0);
}

/// **Discriminates.** TCP timeouts by state: a SYN nobody answered and a flow
/// that has carried a FIN are held `NAT_TCP_TRANSIENT_S`, an answered one
/// `NAT_TCP_TIMEOUT_S`. Mirror: just inside each passes.
#[test]
fn tcp_mappings_expire_by_state() {
    let _g = begin();
    let transient = azos_limits::NAT_TCP_TRANSIENT_S as u64;
    let established = azos_limits::NAT_TCP_TIMEOUT_S as u64;

    // An unanswered SYN, retransmitted once.
    let p1 = out_via_wan(&tcp(HOST, REMOTE, 40001, 80, SYN, b"")).pkt.sport();
    // An answered flow that then sees a FIN.
    let p2 = out_via_wan(&tcp(HOST, REMOTE, 40002, 80, SYN, b"")).pkt.sport();
    from_wan(&tcp(REMOTE, IP_W, 80, p2, SYN | ACK, b""));
    // An answered flow.
    let p3 = out_via_wan(&tcp(HOST, REMOTE, 40003, 80, SYN, b"")).pkt.sport();
    from_wan(&tcp(REMOTE, IP_W, 80, p3, SYN | ACK, b""));
    let _ = out_via_wan(&tcp(HOST, REMOTE, 40002, 80, FIN | ACK, b""));

    at(transient - 1);
    // The SYN is retransmitted: same mapping, still unanswered.
    assert_eq!(out_via_wan(&tcp(HOST, REMOTE, 40001, 80, SYN, b"")).pkt.sport(), p1);
    raw::reset();
    from_wan(&tcp(REMOTE, IP_W, 80, p2, FIN | ACK, b""));
    assert_eq!(sent_by(MAC_L).len(), 1, "a closing mapping is held inside the transient timeout");

    at(2 * transient + 1);
    raw::reset();
    from_wan(&tcp(REMOTE, IP_W, 80, p1, ACK, b""));
    from_wan(&tcp(REMOTE, IP_W, 80, p2, ACK, b""));
    // (The local TCP answers a segment for no connection with an RST to the
    // remote: what must be absent is the LAN-side frame.)
    assert!(sent_by(MAC_L).is_empty(), "unanswered and closing mappings are gone after a transient timeout");

    from_wan(&tcp(REMOTE, IP_W, 80, p3, ACK, b""));
    assert_eq!(sent_by(MAC_L).len(), 1, "the answered one is still there");

    at(2 * transient + 1 + established + 1);
    raw::reset();
    from_wan(&tcp(REMOTE, IP_W, 80, p3, ACK, b""));
    assert!(sent_by(MAC_L).is_empty(), "and expires after the established timeout");
}

/// **Discriminates.** The table is bounded: with every flow answered, the
/// mappings never exceed `NAT_SLOTS`, the flows that do not fit are refused
/// (nothing on the wire, a refusal recorded) and the ones already there keep
/// translating. Mirror: the same number of flows nobody answers all get through,
/// because an unanswered mapping is evicted before an answered one.
#[test]
fn the_table_is_bounded_and_answered_flows_are_not_evicted() {
    let _g = begin();
    let mut answered = Vec::new();
    let mut refused_flows = 0usize;
    for i in 0..4 * nat::NAT_SLOTS as u16 {
        raw::reset();
        from_lan(&udp(HOST, REMOTE, 1000 + i, 53, b"q"));
        match sent_by(MAC_W).first() {
            Some(f) => {
                let wan = f.pkt.sport();
                raw::reset();
                from_wan(&udp(REMOTE, IP_W, 53, wan, b"a"));
                assert_eq!(sent_by(MAC_L).len(), 1);
                answered.push((1000 + i, wan));
            }
            None => refused_flows += 1,
        }
        assert!(nat::tracked(now()) <= nat::NAT_SLOTS, "the table never grows");
    }
    assert!(refused_flows > 0, "4x the table's flows cannot all fit");
    assert!(answered.len() <= nat::NAT_SLOTS);
    assert_eq!(filter::stats().refused as usize, refused_flows, "each refusal went through the filter path");
    assert_eq!(nat::tracked(now()), answered.len());
    // The answered ones still translate.
    for &(sport, wan) in &answered {
        raw::reset();
        from_wan(&udp(REMOTE, IP_W, 53, wan, b"again"));
        let r = sent_by(MAC_L);
        assert_eq!((r.len(), r[0].pkt.dport()), (1, sport));
    }
}

#[test]
fn unanswered_flows_are_evicted_before_answered_ones() {
    let _g = begin();
    for i in 0..4 * nat::NAT_SLOTS as u16 {
        raw::reset();
        from_lan(&udp(HOST, REMOTE, 2000 + i, 53, b"q"));
        assert_eq!(sent_by(MAC_W).len(), 1, "flow {i}: an unanswered mapping makes room");
    }
    assert!(nat::tracked(now()) <= nat::NAT_SLOTS);
    assert_eq!(filter::stats().refused, 0);
}

/// **Discriminates.** The translated port is never one this node's own TCP
/// connections use, and two live mappings of one protocol never share one. (Every
/// flow is answered, so none is evicted and every port issued is still live.)
#[test]
fn translated_ports_stay_in_range_and_are_unique() {
    let _g = begin();
    let mut seen = std::collections::HashSet::new();
    for i in 0..2 * nat::NAT_SLOTS as u16 {
        raw::reset();
        from_lan(&udp(HOST, REMOTE, 3000 + i, 53, b"q"));
        let Some(f) = sent_by(MAC_W).into_iter().next() else { continue };
        let p = f.pkt.sport();
        assert!((PORT_MIN..=PORT_MAX).contains(&p));
        assert!(
            p < azos_limits::TCP_EPHEMERAL_PORT_MIN as u16 || p > azos_limits::TCP_EPHEMERAL_PORT_MAX as u16,
            "outside the TCP ephemeral range"
        );
        assert!(seen.insert(p), "port {p} given to two live mappings");
        from_wan(&udp(REMOTE, IP_W, 53, p, b"a"));
    }
    assert!(seen.len() > 1);
}

// ── The uplink comes from the route table ──────────────────────────────────

/// **Discriminates.** The uplink is the interface of the best default route, a
/// `[route.NAME]` row beating a lease; what is masqueraded follows it. With a
/// static default on eth0 the LAN side is the other one: a packet from eth1's
/// network leaves by eth0 with eth0's address, and one that arrives on eth0
/// (outside now) unasked is refused. Mirror: with the masquerade off the same
/// packet is routed as is.
#[test]
fn the_uplink_is_the_interface_of_the_default_route() {
    let _g = begin();
    assert_eq!(ip::uplink(), Some(2), "the lease gateway of eth1");
    // A static default on eth0, metric 0, beats the lease (metric 100).
    ip::route_add([0; 4], 0, [10, 1, 0, 254], 1, 0).unwrap();
    assert_eq!(ip::uplink(), Some(1));
    arp::insert_on(1, [10, 1, 0, 254], [0x02, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE]);
    arp::insert_on(2, [192, 0, 2, 50], [0x02, 0x50, 0x50, 0x50, 0x50, 0x50]);

    raw::reset();
    from_wan(&udp([192, 0, 2, 50], REMOTE, 6000, 53, b"q"));
    let f = sent_by(MAC_L);
    assert_eq!(f.len(), 1, "leaves by eth0, now the uplink");
    assert_eq!((f[0].pkt.src(), f[0].dst_mac), (IP_L, [0x02, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE]));
    assert!(f[0].pkt.checksums_hold());

    // The old LAN is outside now: what it sends unasked is refused, not
    // translated towards the new LAN.
    raw::reset();
    from_lan(&udp(HOST, [192, 0, 2, 50], 6000, 53, b"q"));
    assert!(nothing_on_the_wire());
    assert_eq!(filter::stats().refused, 1);

    // Mirror: no masquerade, the same packet is routed as is.
    nat::reset_for_test(false);
    raw::reset();
    from_lan(&udp(HOST, [192, 0, 2, 50], 6000, 53, b"q"));
    let f = sent_by(MAC_W);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].pkt.src(), HOST, "towards a non-uplink interface nothing is masqueraded");
    assert_eq!(filter::stats().refused, 1);
}

/// **Discriminates.** With no default route at all there is no uplink and
/// nothing is masqueraded (the mirror of the test above on the lease gateway).
#[test]
fn without_a_default_route_there_is_no_uplink() {
    let _g = begin();
    assert!(ip::iface_configure(2, IP_W, [255, 255, 255, 0], [0; 4]));
    assert_eq!(ip::uplink(), None);
    arp::insert_on(2, [192, 0, 2, 50], [0x02, 0x50, 0x50, 0x50, 0x50, 0x50]);
    raw::reset();
    from_lan(&udp(HOST, [192, 0, 2, 50], 6000, 53, b"q"));
    let f = sent_by(MAC_W);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].pkt.src(), HOST, "routed, not masqueraded");
}
