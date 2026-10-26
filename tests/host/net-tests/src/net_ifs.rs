// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Several interfaces in one stack: the registry, the routing table, ARP per
//! interface, and `AF_PACKET` sockets (`crates/net/stack/src/{ip,arp,socket}.rs`).
//!
//! **The real `ip.rs`, `arp.rs` and `socket.rs` are in the loop.** A test
//! attaches two interfaces to the real registry, then sends through `ip::send`
//! and reads the frames the stack put on the recorded wire: *which link* a
//! frame left by is its source MAC (the stack names a link by the MAC of its
//! frames), and what it asked ARP for is the request's `sha`/`spa`/`tpa`. No
//! assertion reads a counter the code under test keeps about itself.
//!
//! **Not covered here.** `lib.rs` is replaced by this suite's stand-ins, so the
//! receive pass that calls `socket::packet_rx` per frame, `net_raw_send`'s
//! choice of NIC from the frame's source MAC and the topology wiring are
//! boot-checked, not host-checked (see the commit notes).
//!
//! **Canary discipline.** Every selection test has a mirror that would pass if
//! the stack ignored the table: the frame for the second link carries the
//! *first* link's MAC in the caller's arguments, so a stack that trusted the
//! caller instead of the route fails.

use crate::NET_SERIAL as SERIAL;
use crate::socket::{self, AF_PACKET, ETH_P_ALL, SOCK_OWNER_KERNEL, SOCK_RAW, SockAddr};
use crate::{arp, ip, raw, wire};

const T0: u64 = 70_000;

const MAC_A: [u8; 6] = [0x02, 0xAA, 0x00, 0x00, 0x00, 0x01];
const IP_A: [u8; 4] = [10, 1, 0, 2];
const MAC_B: [u8; 6] = [0x02, 0xBB, 0x00, 0x00, 0x00, 0x02];
const IP_B: [u8; 4] = [192, 168, 7, 2];
const GW_B: [u8; 4] = [192, 168, 7, 1];
const GW_B_MAC: [u8; 6] = [0x02, 0x47, 0x57, 0x00, 0x07, 0x01];
const PEER_A: [u8; 4] = [10, 1, 0, 9];
const PEER_A_MAC: [u8; 6] = [0x02, 0xA0, 0xA0, 0xA0, 0xA0, 0x09];
const PEER_B: [u8; 4] = [192, 168, 7, 9];
const PEER_B_MAC: [u8; 6] = [0x02, 0xB0, 0xB0, 0xB0, 0xB0, 0x09];
const FAR: [u8; 4] = [8, 8, 8, 8];

const PTP: u16 = 0x88F7;

/// Holds the suite's lock and, on the way out, hands the host stand-in its
/// single interface back and closes what the test opened.
struct Session {
    _g: std::sync::MutexGuard<'static, ()>,
    fds: Vec<i32>,
}

impl Session {
    /// A kernel-owned packet socket for `ethertype` (or [`ETH_P_ALL`]).
    fn packet(&mut self, ethertype: u32) -> i32 {
        let fd = socket::socket_create_owned(AF_PACKET, SOCK_RAW, ethertype, SOCK_OWNER_KERNEL);
        assert!(fd >= 0, "a kernel packet socket must be creatable");
        self.fds.push(fd);
        fd
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        for fd in self.fds.drain(..) {
            socket::socket_close(fd);
        }
        ip::ifaces_reset_for_test();
    }
}

/// Two interfaces: eth0 `10.1.0.2/24` with no gateway, eth1 `192.168.7.2/24`
/// with a lease gateway. Attached in that order, so they are 1 and 2.
fn begin() -> Session {
    let g = Session { _g: SERIAL.lock().unwrap_or_else(|e| e.into_inner()), fds: Vec::new() };
    azos_drv_irqchip::clint::set_test_time(T0);
    crate::inbound::reset();
    wire::reset();
    arp::cache_reset_for_test();
    ip::arp_txq_reset_for_test();
    ip::ifaces_reset_for_test();
    assert_eq!(ip::iface_attach(0, MAC_A, 1500, [0; 16]), Some(1));
    assert!(ip::iface_configure(1, IP_A, [255, 255, 255, 0], [0; 4]));
    assert_eq!(ip::iface_attach(1, MAC_B, 1500, [0; 16]), Some(2));
    assert!(ip::iface_configure(2, IP_B, [255, 255, 255, 0], GW_B));
    g
}

/// The IPv4 frames on the wire, with the Ethernet header kept.
fn ipv4_frames() -> Vec<Vec<u8>> {
    raw::all().into_iter()
        .filter(|f| f.len() >= 34 && u16::from_be_bytes([f[12], f[13]]) == 0x0800)
        .collect()
}

fn arp_frames() -> Vec<Vec<u8>> {
    raw::all().into_iter()
        .filter(|f| f.len() >= 42 && u16::from_be_bytes([f[12], f[13]]) == 0x0806)
        .collect()
}

fn dst_mac(f: &[u8]) -> [u8; 6] { f[0..6].try_into().unwrap() }
fn src_mac(f: &[u8]) -> [u8; 6] { f[6..12].try_into().unwrap() }
fn ip_dst(f: &[u8]) -> [u8; 4] { f[30..34].try_into().unwrap() }

/// An Ethernet/IPv4 ARP packet (the part after the Ethernet header).
fn arp_pkt(op: u16, sha: [u8; 6], spa: [u8; 4], tha: [u8; 6], tpa: [u8; 4]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&0x0800u16.to_be_bytes());
    p.extend_from_slice(&[6, 4]);
    p.extend_from_slice(&op.to_be_bytes());
    p.extend_from_slice(&sha);
    p.extend_from_slice(&spa);
    p.extend_from_slice(&tha);
    p.extend_from_slice(&tpa);
    p
}

/// A frame of `ethertype` from `src` to `dst`, padded to 60 bytes.
fn frame(dst: [u8; 6], src: [u8; 6], ethertype: u16, body: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(body);
    while f.len() < 60 { f.push(0); }
    f
}

// ── The registry ────────────────────────────────────────────────────────────

/// **Discriminates.** Interfaces are numbered in attach order, found by MAC,
/// by the address they hold and by name, and each keeps its own fields. A
/// registry that kept one global config (the old `NET_CFG`) answers the same
/// for both and fails the per-interface assertions.
#[test]
fn interfaces_are_numbered_in_attach_order_and_keep_their_own_fields() {
    let _s = begin();
    assert_eq!(ip::iface_count(), 2);
    let a = ip::iface_get(1).unwrap();
    let b = ip::iface_get(2).unwrap();
    assert_eq!((a.mac, a.ip, a.gateway, a.nic), (MAC_A, IP_A, [0; 4], 0));
    assert_eq!((b.mac, b.ip, b.gateway, b.nic), (MAC_B, IP_B, GW_B, 1));
    assert_eq!(ip::iface_by_mac(&MAC_B), Some(2));
    assert_eq!(ip::iface_by_mac(&PEER_A_MAC), None);
    assert_eq!(ip::iface_owning(&IP_A), Some(1));
    assert_eq!(ip::iface_owning(&IP_B), Some(2));
    assert_eq!(ip::iface_owning(&[0, 0, 0, 0]), None, "an unset address is nobody's");
    assert_eq!(ip::iface_by_name(b"eth0"), Some(1));
    assert_eq!(ip::iface_by_name(b"eth1"), Some(2));
    assert_eq!(ip::iface_by_name(b"eth2"), None, "no third interface");
    assert_eq!(ip::iface_get(3), None);
    assert_eq!(ip::iface_get(0), None, "0 is 'none', never an interface");
}

/// **Discriminates.** The table is bounded by `NET_MAX_INTERFACES`: the
/// attach after the last free number is refused rather than overwriting one.
#[test]
fn the_table_is_bounded() {
    let _s = begin();
    for n in 2..ip::MAX_IFS {
        assert_eq!(ip::iface_attach(n as u8, [2, 0, 0, 0, 1, n as u8], 1500, [0; 16]), Some(n as u8 + 1));
    }
    assert_eq!(ip::iface_attach(9, [2, 0, 0, 0, 9, 9], 1500, [0; 16]), None);
    assert_eq!(ip::iface_get(1).unwrap().mac, MAC_A, "nothing was overwritten");
}

/// **Discriminates.** A NIC that went away and came back (a USB adapter
/// plugged in again) keeps its interface, address included, and takes the MAC
/// it states now; a new NIC still takes the next number. An `iface_attach`
/// that always takes a free slot fills the table with copies of one adapter
/// and leaves the address on a number nothing sends from.
#[test]
fn a_nic_that_comes_back_keeps_its_interface() {
    let _s = begin();
    let back = [0x02, 0xCC, 0x00, 0x00, 0x00, 0x09];
    let again = [0x02, 0xCC, 0x00, 0x00, 0x00, 0x0A];
    assert_eq!(ip::iface_attach(2, back, 1500, [1; 16]), Some(3));
    assert!(ip::iface_configure(3, [172, 16, 0, 2], [255, 255, 0, 0], [0; 4]));
    assert_eq!(ip::iface_attach(2, again, 1500, [2; 16]), Some(3), "the same NIC, the same interface");
    let i = ip::iface_get(3).unwrap();
    assert_eq!((i.mac, i.ip, i.ip6_link_local), (again, [172, 16, 0, 2], [2; 16]));
    assert_eq!(ip::iface_count(), 3);
    assert_eq!(ip::iface_by_mac(&back), None, "the old MAC names nothing");
    assert_eq!(ip::iface_by_mac(&again), Some(3));
    assert_eq!(ip::iface_attach(3, [0x02, 0xDD, 0, 0, 0, 1], 1500, [0; 16]), Some(4), "another NIC, the next number");
}

/// A mask with a hole is refused and changes nothing: `255.0.255.0` has no
/// prefix length for the connected route to be derived from.
#[test]
fn a_mask_with_a_hole_is_refused() {
    let _s = begin();
    assert!(!ip::iface_configure(1, [10, 9, 0, 2], [255, 0, 255, 0], [0; 4]));
    assert_eq!(ip::iface_get(1).unwrap().ip, IP_A);
    assert_eq!(ip::mask_prefix_len(&[255, 255, 254, 0]), Some(23));
    assert_eq!(ip::mask_prefix_len(&[0, 0, 0, 0]), Some(0));
    assert_eq!(ip::mask_prefix_len(&[255, 255, 255, 255]), Some(32));
    assert_eq!(ip::mask_prefix_len(&[255, 0, 255, 0]), None);
}

// ── The routing table ───────────────────────────────────────────────────────

/// **Discriminates.** A destination on a link's own subnet goes out that link,
/// directly; one on the other's, the other; a far one takes the lease default
/// of the interface that has a gateway. Each is a different row of the answer.
#[test]
fn connected_routes_pick_their_link_and_the_lease_default_takes_the_rest() {
    let _s = begin();
    let r = ip::route(&PEER_A).unwrap();
    assert_eq!((r.ifindex, r.next_hop), (1, PEER_A), "on-link: the destination itself");
    let r = ip::route(&PEER_B).unwrap();
    assert_eq!((r.ifindex, r.next_hop), (2, PEER_B));
    let r = ip::route(&FAR).unwrap();
    assert_eq!((r.ifindex, r.next_hop), (2, GW_B), "off-link: eth1's gateway");
    assert_eq!(r.iface.mac, MAC_B);
}

/// **Discriminates.** With no gateway anywhere an off-link destination has no
/// route: `None`, not a guess at the first link. (The stack used to ARP it
/// directly.)
#[test]
fn no_route_is_no_route() {
    let _s = begin();
    assert!(ip::iface_configure(2, IP_B, [255, 255, 255, 0], [0; 4]));
    assert_eq!(ip::route(&FAR), None);
    assert!(ip::route(&PEER_A).is_some(), "the connected routes are untouched");
}

/// **Discriminates.** The longest prefix wins over a shorter one whatever
/// order they were added in: `8.8.0.0/16` through eth0 beats the lease default
/// (`/0`) on eth1 for `8.8.8.8`, and the default still takes `9.9.9.9`.
#[test]
fn longest_prefix_wins() {
    let _s = begin();
    ip::route_add([8, 8, 0, 0], 16, [10, 1, 0, 1], 1, 0).unwrap();
    let r = ip::route(&FAR).unwrap();
    assert_eq!((r.ifindex, r.next_hop), (1, [10, 1, 0, 1]));
    let r = ip::route(&[9, 9, 9, 9]).unwrap();
    assert_eq!((r.ifindex, r.next_hop), (2, GW_B));
}

/// **Discriminates.** Equal prefixes break on the lower metric, and a static
/// default (metric 0 unless the row says otherwise) beats the lease's default
/// (metric 100). A table that took the first row it found picks wrong in both.
#[test]
fn metric_breaks_ties_and_a_static_default_beats_the_lease() {
    let _s = begin();
    ip::route_add([172, 16, 0, 0], 12, [10, 1, 0, 1], 1, 5).unwrap();
    ip::route_add([172, 16, 0, 0], 12, GW_B, 2, 3).unwrap();
    let r = ip::route(&[172, 20, 0, 1]).unwrap();
    assert_eq!((r.ifindex, r.next_hop), (2, GW_B), "metric 3 beats metric 5");

    assert_eq!(ip::route(&FAR).unwrap().ifindex, 2, "precondition: the lease default");
    ip::route_add([0, 0, 0, 0], 0, [10, 1, 0, 1], 1, 0).unwrap();
    let r = ip::route(&FAR).unwrap();
    assert_eq!((r.ifindex, r.next_hop), (1, [10, 1, 0, 1]), "static /0 metric 0 < lease /0 metric 100");
}

/// **Discriminates.** A connected route beats a static one of the same prefix
/// length and metric (kind order), so a topology row cannot silently redirect
/// the link's own subnet.
#[test]
fn a_connected_route_beats_an_equal_static_one() {
    let _s = begin();
    ip::route_add([10, 1, 0, 0], 24, [192, 168, 7, 1], 2, 0).unwrap();
    let r = ip::route(&PEER_A).unwrap();
    assert_eq!((r.ifindex, r.next_hop), (1, PEER_A));
}

/// A static route over a link that is not attached carries nothing.
#[test]
fn route_add_refuses_what_it_cannot_hold() {
    let _s = begin();
    use ip::RouteError::*;
    assert_eq!(ip::route_add([1, 0, 0, 0], 33, [0; 4], 1, 0), Err(BadPrefix));
    assert_eq!(ip::route_add([1, 0, 0, 0], 8, [0; 4], 7, 0), Err(NoSuchInterface));
    assert_eq!(ip::route_add([1, 0, 0, 0], 8, [0; 4], 0, 0), Err(NoSuchInterface));
    ip::route_add([1, 2, 3, 4], 8, [0; 4], 1, 0).unwrap();
    assert_eq!(ip::route_add([1, 9, 9, 9], 8, [0; 4], 2, 0), Err(Duplicate),
               "host bits are cleared: 1.2.3.4/8 and 1.9.9.9/8 are one destination");
    assert_eq!(ip::routes()[0].unwrap().dest, [1, 0, 0, 0]);
    // Fill the rest; the next one has nowhere to go.
    for n in 1..ip::MAX_STATIC_ROUTES {
        ip::route_add([20 + n as u8, 0, 0, 0], 8, [0; 4], 1, 0).unwrap();
    }
    assert_eq!(ip::route_add([99, 0, 0, 0], 8, [0; 4], 1, 0), Err(Full));
}

// ── Egress: one stack, two links ────────────────────────────────────────────

/// **Discriminates.** A datagram to each link's subnet leaves by that link:
/// the frame's source MAC is the link's, whatever MAC the *caller* passed (both
/// calls pass eth0's, as TCP and UDP do today). A stack that used the caller's
/// MAC, or sent everything out the first NIC, fails the second assertion.
#[test]
fn a_datagram_leaves_by_the_routed_interface_with_its_mac() {
    let _s = begin();
    arp::insert_on(1, PEER_A, PEER_A_MAC);
    arp::insert_on(2, PEER_B, PEER_B_MAC);

    assert_eq!(ip::send(&MAC_A, &IP_A, &PEER_A, ip::IP_PROTO_UDP, b"to-a"), 0);
    assert_eq!(ip::send(&MAC_A, &IP_A, &PEER_B, ip::IP_PROTO_UDP, b"to-b"), 0);

    let f = ipv4_frames();
    assert_eq!(f.len(), 2);
    assert_eq!((src_mac(&f[0]), dst_mac(&f[0])), (MAC_A, PEER_A_MAC));
    assert_eq!((src_mac(&f[1]), dst_mac(&f[1])), (MAC_B, PEER_B_MAC),
               "eth1's frame must carry eth1's MAC, not the caller's");
    assert!(f[0].ends_with(b"to-a") && f[1].ends_with(b"to-b"));
}

/// **Discriminates.** An off-link destination goes to the gateway's MAC on the
/// gateway's link, with the real destination still in the IP header.
#[test]
fn an_off_link_datagram_goes_to_the_gateway_on_its_link() {
    let _s = begin();
    arp::insert_on(2, GW_B, GW_B_MAC);
    assert_eq!(ip::send(&MAC_A, &IP_A, &FAR, ip::IP_PROTO_UDP, b"far"), 0);
    let f = ipv4_frames();
    assert_eq!(f.len(), 1);
    assert_eq!((src_mac(&f[0]), dst_mac(&f[0])), (MAC_B, GW_B_MAC));
    assert_eq!(ip_dst(&f[0]), FAR);
}

/// **Discriminates.** No route: the send fails and nothing, not even an ARP
/// request, reaches any wire.
#[test]
fn a_destination_with_no_route_is_refused_and_nothing_is_sent() {
    let _s = begin();
    assert!(ip::iface_configure(2, IP_B, [255, 255, 255, 0], [0; 4]));
    assert_eq!(ip::send(&MAC_A, &IP_A, &FAR, ip::IP_PROTO_UDP, b"x"), -1);
    assert!(raw::all().is_empty());
}

/// **Discriminates.** A subnet-directed broadcast leaves its own link to the
/// broadcast MAC, and the other link's broadcast address is not this one's.
#[test]
fn a_directed_broadcast_leaves_its_own_link() {
    let _s = begin();
    assert_eq!(ip::send(&MAC_A, &IP_A, &[192, 168, 7, 255], ip::IP_PROTO_UDP, b"b1"), 0);
    assert_eq!(ip::send(&MAC_A, &IP_A, &[10, 1, 0, 255], ip::IP_PROTO_UDP, b"b0"), 0);
    let f = ipv4_frames();
    assert_eq!(f.len(), 2);
    assert_eq!((src_mac(&f[0]), dst_mac(&f[0])), (MAC_B, [0xff; 6]));
    assert_eq!((src_mac(&f[1]), dst_mac(&f[1])), (MAC_A, [0xff; 6]));
    assert!(arp_frames().is_empty(), "nobody answers ARP for a broadcast");
}

/// **Discriminates.** A datagram to the address of ANY interface is ours and
/// never reaches a wire: eth0's socket talking to eth1's address used to ARP
/// for it, and nobody answers ARP for our own address.
#[test]
fn a_datagram_to_another_interfaces_address_stays_inside() {
    let _s = begin();
    assert_eq!(ip::send(&MAC_A, &IP_A, &IP_B, ip::IP_PROTO_UDP, b"self"), 0);
    assert!(raw::all().is_empty(), "delivered locally, nothing on any wire");
}

/// **Discriminates.** Each link's own MTU bounds a send: 900 bytes fit eth0's
/// 1500 and not eth1's 576. A stack that checked one global constant sends both.
#[test]
fn each_links_mtu_bounds_a_send() {
    let _s = begin();
    ip::ifaces_reset_for_test();
    ip::iface_attach(0, MAC_A, 1500, [0; 16]).unwrap();
    assert!(ip::iface_configure(1, IP_A, [255, 255, 255, 0], [0; 4]));
    ip::iface_attach(1, MAC_B, 576, [0; 16]).unwrap();
    assert!(ip::iface_configure(2, IP_B, [255, 255, 255, 0], GW_B));
    arp::insert_on(1, PEER_A, PEER_A_MAC);
    arp::insert_on(2, PEER_B, PEER_B_MAC);
    let big = vec![0u8; 900];
    assert_eq!(ip::send(&MAC_A, &IP_A, &PEER_A, ip::IP_PROTO_UDP, &big), 0);
    assert_eq!(ip::send(&MAC_B, &IP_B, &PEER_B, ip::IP_PROTO_UDP, &big), -1);
    assert_eq!(ipv4_frames().len(), 1);
}

// ── ARP per interface ───────────────────────────────────────────────────────

/// **Discriminates.** An unresolved next hop is asked about on the link the
/// route chose, as that link: the request's `sha` and `spa` are eth1's, not
/// the first link's or the caller's. The packet waits, and the reply that
/// arrives on eth1 releases it out of eth1.
#[test]
fn arp_asks_on_the_routed_link_and_the_reply_releases_the_frame_there() {
    let _s = begin();
    assert_eq!(ip::send(&MAC_A, &IP_A, &PEER_B, ip::IP_PROTO_UDP, b"hold"), 0, "accepted, queued");
    let q = arp_frames();
    assert_eq!(q.len(), 1);
    assert_eq!(src_mac(&q[0]), MAC_B, "the request leaves eth1");
    assert_eq!(&q[0][22..28], &MAC_B, "sha");
    assert_eq!(&q[0][28..32], &IP_B, "spa");
    assert_eq!(&q[0][38..42], &PEER_B, "tpa");
    assert!(ipv4_frames().is_empty(), "nothing is sent to a MAC we do not know");

    arp::handle(&arp_pkt(2, PEER_B_MAC, PEER_B, MAC_B, IP_B), &MAC_B, &IP_B);

    let f = ipv4_frames();
    assert_eq!(f.len(), 1, "the queued frame leaves exactly once");
    assert_eq!((src_mac(&f[0]), dst_mac(&f[0])), (MAC_B, PEER_B_MAC));
    assert_eq!(arp::lookup_on(2, &PEER_B), Some(PEER_B_MAC));
    assert_eq!(arp::lookup_on(1, &PEER_B), None, "learned on eth1 only");
}

/// **Discriminates.** One address, two links, two bindings: the same IP is a
/// different host on each. A single shared cache answers both lookups with the
/// last writer.
#[test]
fn the_same_address_is_two_bindings_on_two_links() {
    let _s = begin();
    let x = [10, 50, 0, 1];
    arp::insert_on(1, x, PEER_A_MAC);
    arp::insert_on(2, x, PEER_B_MAC);
    assert_eq!(arp::lookup_on(1, &x), Some(PEER_A_MAC));
    assert_eq!(arp::lookup_on(2, &x), Some(PEER_B_MAC));
    assert_eq!(arp::lookup_on(3, &x), None, "a link that does not exist has no cache");
    assert_eq!(arp::lookup_on(0, &x), None);
}

/// **Discriminates.** A question asked on eth1 is answered only by a reply that
/// arrives on eth1: the same reply delivered on eth0 teaches nothing (the
/// outstanding-request table is per link), so a host on one segment cannot
/// answer for another. The mirror: the same reply on eth1 is learned.
#[test]
fn a_reply_on_the_wrong_link_does_not_answer_the_question() {
    let _s = begin();
    arp::send_request(&MAC_B, &IP_B, &PEER_B);
    arp::handle(&arp_pkt(2, PEER_B_MAC, PEER_B, MAC_A, IP_A), &MAC_A, &IP_A);
    assert_eq!(arp::lookup_on(1, &PEER_B), None, "eth0 never asked");
    assert_eq!(arp::lookup_on(2, &PEER_B), None, "and eth1 did not hear it");

    arp::handle(&arp_pkt(2, PEER_B_MAC, PEER_B, MAC_B, IP_B), &MAC_B, &IP_B);
    assert_eq!(arp::lookup_on(2, &PEER_B), Some(PEER_B_MAC), "the mirror: on the right link it is learned");
}

/// **Discriminates.** A request for an interface's address is answered with
/// THAT interface's MAC; a request for the other's, heard on this link, is not
/// ours to answer.
#[test]
fn a_request_is_answered_by_the_link_that_owns_the_address() {
    let _s = begin();
    arp::handle(&arp_pkt(1, PEER_B_MAC, PEER_B, [0; 6], IP_B), &MAC_B, &IP_B);
    let r = arp_frames();
    assert_eq!(r.len(), 1);
    assert_eq!((src_mac(&r[0]), dst_mac(&r[0])), (MAC_B, PEER_B_MAC));
    assert_eq!(&r[0][22..28], &MAC_B, "sha of the reply is eth1's");
    assert_eq!(&r[0][28..32], &IP_B);

    wire::reset();
    // eth1's address asked on eth0's segment: eth0 holds IP_A, so it is silent.
    arp::handle(&arp_pkt(1, PEER_A_MAC, PEER_A, [0; 6], IP_B), &MAC_A, &IP_A);
    assert!(arp_frames().is_empty());
}

/// **Discriminates.** The dial shape: TCP asks with the PRIMARY's MAC and
/// address about a peer on the second link. The question goes out eth1 as
/// eth1, and the answer that arrives on eth1 resolves the same query; a stack
/// that took the link from the caller's MAC would ask on eth0, look in eth0's
/// cache, and never see the answer. The mirror: a peer on eth0, asked with
/// eth1's MAC, still goes out eth0.
#[test]
fn a_question_goes_out_the_link_that_reaches_the_peer_whatever_mac_the_caller_holds() {
    let _s = begin();
    arp::send_request(&MAC_A, &IP_A, &PEER_B);
    let q = arp_frames();
    assert_eq!(q.len(), 1);
    assert_eq!(src_mac(&q[0]), MAC_B);
    assert_eq!((&q[0][22..28], &q[0][28..32], &q[0][38..42]), (&MAC_B[..], &IP_B[..], &PEER_B[..]));
    assert_eq!(arp::lookup_solicited_verified(&MAC_A, &IP_A, &PEER_B), None, "not answered yet");

    arp::handle(&arp_pkt(2, PEER_B_MAC, PEER_B, MAC_B, IP_B), &MAC_B, &IP_B);
    assert_eq!(arp::lookup_solicited_verified(&MAC_A, &IP_A, &PEER_B), Some(PEER_B_MAC),
               "the dial finds the binding the answer on eth1 made");
    assert_eq!(arp::lookup_on(1, &PEER_B), None);

    wire::reset();
    arp::send_request(&MAC_B, &IP_B, &PEER_A);
    let q = arp_frames();
    assert_eq!(q.len(), 1);
    assert_eq!((src_mac(&q[0]), &q[0][28..32]), (MAC_A, &IP_A[..]), "mirror: eth0's peer, eth0's question");
}

/// With no route to the address the caller's own MAC names the link, and a MAC
/// that is no interface's asks nothing.
#[test]
fn with_no_route_the_callers_mac_names_the_link() {
    let _s = begin();
    assert!(ip::iface_configure(2, IP_B, [255, 255, 255, 0], [0; 4]));
    arp::send_request(&MAC_A, &IP_A, &FAR);
    let q = arp_frames();
    assert_eq!(q.len(), 1);
    assert_eq!(src_mac(&q[0]), MAC_A);
    wire::reset();
    arp::send_request(&[2, 9, 9, 9, 9, 9], &IP_A, &FAR);
    assert!(raw::all().is_empty());
}

/// A packet that names a MAC no interface holds is dropped, not attributed to
/// the first link.
#[test]
fn arp_on_an_unknown_link_is_dropped() {
    let _s = begin();
    arp::handle(&arp_pkt(1, PEER_A_MAC, PEER_A, [0; 6], IP_A), &[2, 9, 9, 9, 9, 9], &IP_A);
    assert!(raw::all().is_empty());
    assert_eq!(arp::lookup_on(1, &PEER_A), None);
}

// ── AF_PACKET ───────────────────────────────────────────────────────────────

/// **Discriminates.** Receive filters by EtherType: a socket for 0x88F7 gets
/// the gPTP frame and not the IPv4 one, and `ETH_P_ALL` gets both. A socket
/// that ignored the filter would see the IPv4 frame in the first assertion.
#[test]
fn a_packet_socket_receives_by_ethertype() {
    let mut s = begin();
    let ptp = s.packet(PTP as u32);
    let all = s.packet(ETH_P_ALL);
    let g = frame([0x01, 0x80, 0xC2, 0, 0, 0x0E], PEER_B_MAC, PTP, b"sync");
    let v4 = frame(MAC_B, PEER_B_MAC, 0x0800, b"not-ptp");

    socket::packet_rx(2, &g);
    socket::packet_rx(2, &v4);

    let mut buf = [0u8; 1600];
    let n = socket::socket_recv(ptp, &mut buf);
    assert_eq!(n as usize, g.len());
    assert_eq!(&buf[..n as usize], &g[..]);
    assert_eq!(socket::socket_recv(ptp, &mut buf), 0, "the IPv4 frame was not queued for it");

    assert_eq!(socket::socket_recv(all, &mut buf) as usize, g.len());
    assert_eq!(socket::socket_recv(all, &mut buf) as usize, v4.len());
    assert_eq!(socket::socket_recv(all, &mut buf), 0);
}

/// **Discriminates.** Bound to one interface, a socket sees only that
/// interface's frames, and `recvfrom` reports which one a frame came in on.
#[test]
fn a_bound_packet_socket_sees_one_interface_and_reports_it() {
    let mut s = begin();
    let fd = s.packet(PTP as u32);
    let mut a = SockAddr::new();
    a.family = AF_PACKET as u16;
    a.port = 2;
    assert_eq!(socket::socket_bind(fd, &a), 0);

    socket::packet_rx(1, &frame([0xff; 6], PEER_A_MAC, PTP, b"on-eth0"));
    socket::packet_rx(2, &frame([0xff; 6], PEER_B_MAC, PTP, b"on-eth1"));

    let mut buf = [0u8; 1600];
    let mut from = SockAddr::new();
    let n = socket::socket_recvfrom(fd, &mut buf, &mut from);
    assert!(n > 0);
    assert_eq!(&buf[14..21], b"on-eth1");
    assert_eq!((from.family, from.port), (AF_PACKET as u16, 2));
    assert_eq!(socket::socket_recv(fd, &mut buf), 0, "eth0's frame was filtered out");

    a.port = 9;
    assert_eq!(socket::socket_bind(fd, &a), -1, "no such interface");
    a.port = 0;
    assert_eq!(socket::socket_bind(fd, &a), 0, "0 is every interface");
}

/// **Discriminates.** The ring is bounded and keeps the OLDEST frames: a reader
/// that falls behind loses the newest, counted, instead of growing a queue.
#[test]
fn the_receive_ring_is_bounded_and_counts_what_it_drops() {
    let mut s = begin();
    let fd = s.packet(PTP as u32);
    let (d0, x0) = socket::packet_stats();
    let extra = 3;
    for i in 0..(socket::PACKET_RX_SLOTS + extra) {
        socket::packet_rx(1, &frame([0xff; 6], PEER_A_MAC, PTP, &[i as u8]));
    }
    let (d1, x1) = socket::packet_stats();
    assert_eq!(d1 - d0, socket::PACKET_RX_SLOTS as u64);
    assert_eq!(x1 - x0, extra as u64);

    let mut buf = [0u8; 64];
    for i in 0..socket::PACKET_RX_SLOTS {
        assert!(socket::socket_recv(fd, &mut buf) > 0);
        assert_eq!(buf[14], i as u8, "oldest first, and none of the newest displaced them");
    }
    assert_eq!(socket::socket_recv(fd, &mut buf), 0);
    // The ring is reusable after it drains (head wrapped).
    socket::packet_rx(1, &frame([0xff; 6], PEER_A_MAC, PTP, &[77]));
    assert!(socket::socket_recv(fd, &mut buf) > 0);
    assert_eq!(buf[14], 77);
}

/// A frame longer than the buffer is cut to fit, as a datagram socket does.
#[test]
fn a_short_buffer_truncates_the_frame() {
    let mut s = begin();
    let fd = s.packet(PTP as u32);
    socket::packet_rx(1, &frame([0xff; 6], PEER_A_MAC, PTP, &[1u8; 100]));
    let mut buf = [0u8; 20];
    assert_eq!(socket::socket_recv(fd, &mut buf), 20);
}

/// **Discriminates.** Only the kernel may open one: a task's TID, the wrong
/// type, and an EtherType that is not 16 bits are all refused; the table is
/// bounded and a closed socket gives its slot back.
#[test]
fn creation_is_kernel_only_typed_and_bounded() {
    let mut s = begin();
    assert_eq!(socket::socket_create_owned(AF_PACKET, SOCK_RAW, PTP as u32, 7), -1,
               "a ring-3 task has no authority over the wire");
    assert_eq!(socket::socket_create_owned(AF_PACKET, socket::SOCK_DGRAM, PTP as u32, SOCK_OWNER_KERNEL), -1);
    assert_eq!(socket::socket_create_owned(AF_PACKET, SOCK_RAW, 0x1_0000, SOCK_OWNER_KERNEL), -1);

    let mut open = Vec::new();
    for _ in 0..socket::PACKET_SOCKETS {
        open.push(s.packet(PTP as u32));
    }
    assert_eq!(socket::socket_create_owned(AF_PACKET, SOCK_RAW, PTP as u32, SOCK_OWNER_KERNEL), -1,
               "NET_PACKET_SOCKETS is a bound");
    socket::socket_close(open[0]);
    s.fds.retain(|&f| f != open[0]);
    let again = socket::socket_create_owned(AF_PACKET, SOCK_RAW, PTP as u32, SOCK_OWNER_KERNEL);
    assert!(again >= 0, "closing gave the slot back");
    s.fds.push(again);
}

/// **Discriminates.** A send goes out of the interface that owns the frame's
/// source MAC, and out of no other: a source MAC no interface holds (speaking
/// as a neighbour), another EtherType than the socket's, a socket bound to the
/// other link, and a frame over the link's MTU are all refused with nothing on
/// the wire.
#[test]
fn a_packet_send_is_pinned_to_the_links_own_mac_ethertype_and_mtu() {
    let mut s = begin();
    let fd = s.packet(PTP as u32);
    let good = frame([0x01, 0x80, 0xC2, 0, 0, 0x0E], MAC_B, PTP, b"announce");
    assert_eq!(socket::socket_send(fd, &good) as usize, good.len());
    assert_eq!(raw::all(), vec![good.clone()]);

    wire::reset();
    let spoof = frame([0xff; 6], PEER_A_MAC, PTP, b"x");
    assert_eq!(socket::socket_send(fd, &spoof), -1, "not a MAC of ours");
    let other = frame([0xff; 6], MAC_B, 0x0800, b"x");
    assert_eq!(socket::socket_send(fd, &other), -1, "not this socket's EtherType");
    let huge = frame([0xff; 6], MAC_B, PTP, &[0u8; 1600]);
    assert_eq!(socket::socket_send(fd, &huge), -1, "longer than the MTU");
    assert_eq!(socket::socket_send(fd, &good[..10]), -1, "shorter than an Ethernet header");

    let mut a = SockAddr::new();
    a.port = 1;
    assert_eq!(socket::socket_bind(fd, &a), 0);
    assert_eq!(socket::socket_send(fd, &good), -1, "bound to eth0, frame is eth1's");
    assert!(raw::all().is_empty(), "every refusal left the wire quiet");

    let own = frame([0xff; 6], MAC_A, PTP, b"y");
    assert_eq!(socket::socket_send(fd, &own) as usize, own.len(), "mirror: eth0's own frame passes");
}
