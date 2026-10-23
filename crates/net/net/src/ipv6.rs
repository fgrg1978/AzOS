// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! IPv6 stack (F22).
//!
//! Implements a minimal IPv6 layer: link-local and SLAAC addressing, ICMPv6
//! (Neighbor Discovery, Router Advertisement, Echo Request/Reply), UDP and
//! TCP over IPv6 (`tcp.rs` builds and parses the segments, this file frames
//! them and routes them to a link-layer address).
//!
//! ## Feature coverage
//!
//! | Feature                     | Status |
//! |-----------------------------|--------|
//! | Link-local address (EUI-64) | ✓      |
//! | Neighbor Solicitation/Adv.  | ✓      |
//! | ICMPv6 Echo (ping6)         | ✓      |
//! | UDP over IPv6               | ✓      |
//! | Header parsing (RX path)    | ✓      |
//! | Header building (TX path)   | ✓      |
//! | Pseudo-header checksum      | ✓      |
//! | Router Solicitation (TX)    | ✓ (once, at init) |
//! | Router Advertisement (RX)   | ✓ (SLAAC prefix, default router MAC) |
//! | SLAAC global address        | ✓ (one /64, EUI-64 interface id) |
//! | TCP over IPv6 (TX/RX frame) | ✓      |
//! | Packet filter (ingress, egress) | ✓ (`filter.rs`, the IPv4 path's) |
//! | DAD, neighbour cache        | ✗ (future)     |
//! | DHCPv6                      | ✗ (future)     |
//!
//! ## Address plan
//! The kernel auto-configures one link-local address from the MAC address
//! using the EUI-64 algorithm (RFC 4291 §2.5.1):
//!   FE80::/64 + EUI-64(MAC)
//!
//! ## Packet flow
//! ```text
//! RX: ethernet_rx → ipv6_rx → filter::ingress_v6 → [icmpv6_rx | udpv6_rx | tcp::handle_checked_v6]
//! TX: udpv6_send / tcp_send → ipv6_build_header → emit → filter::egress → ethernet_send
//! ```
//!
//! The packet filter (`filter.rs`) is asked about every packet `ipv6_rx` takes
//! and every packet this file sends, the Neighbour Discovery ones included;
//! the built-in firewall's inbound default lets Neighbour Discovery through
//! (`filter::ND_TYPES`).

use core::sync::atomic::{AtomicBool, Ordering};
use azos_sync::SpinLock;

// ── Constants ─────────────────────────────────────────────────────────────────

/// EtherType for IPv6 frames (IEEE 802.3).
pub const ETH_TYPE_IPV6:    u16 = 0x86DD;

/// IPv6 version nibble (always 6).
pub const IPV6_VERSION:     u8  = 6;
/// Minimum IPv6 header size (no extension headers).
pub const IPV6_HDR_SIZE:    usize = 40;

/// Ethernet II header length, ahead of the IPv6 header in a built frame.
pub const ETH_HDR_LEN:      usize = 14;
/// UDP header length.
pub const UDP_HDR_LEN:      usize = 8;
/// Largest UDP payload that still fits one 1500-byte-MTU IPv6 datagram:
/// `1500 - 40 (IPv6) - 8 (UDP)`.  This stack does no fragmentation, so it is
/// a hard bound, and `udpv6_send`'s frame buffer is sized from it.
pub const IPV6_UDP_MAX_PAYLOAD: usize = 1500 - IPV6_HDR_SIZE - UDP_HDR_LEN;
/// Default Hop Limit (analogous to IPv4 TTL).
pub const IPV6_HOP_LIMIT:   u8  = 64;

/// Next-header values (protocol numbers, same as IPv4 protocol field).
pub const NEXTHDR_ICMPV6:   u8  = 58;
pub const NEXTHDR_UDP:      u8  = 17;
pub const NEXTHDR_TCP:      u8  = 6;

/// Destination Unreachable (RFC 4443 §3.1), the answer to a refused packet.
pub const ICMPV6_DEST_UNREACHABLE: u8 = 1;
/// ICMPv6 type codes.
pub const ICMPV6_ECHO_REQ:  u8  = 128;
pub const ICMPV6_ECHO_REPLY:u8  = 129;
pub const ICMPV6_NS:        u8  = 135; // Neighbor Solicitation
pub const ICMPV6_NA:        u8  = 136; // Neighbor Advertisement
pub const ICMPV6_RA:        u8  = 134; // Router Advertisement
pub const ICMPV6_RS:        u8  = 133; // Router Solicitation
pub const ICMPV6_REDIRECT:  u8  = 137; // Redirect (last of the ND types, 133-137)

/// ICMPv6 header size (type + code + checksum = 4 bytes) + Echo fields (4 bytes).
pub const ICMPV6_ECHO_HDR:  usize = 8;
/// Neighbor Solicitation message size (type+code+checksum+reserved+target = 24 bytes).
pub const ICMPV6_NS_SIZE:   usize = 24;
/// Neighbor Advertisement message size, fixed part (no options).
pub const ICMPV6_NA_SIZE:   usize = 24;

/// Neighbor Discovery option: Source Link-Layer Address (RFC 4861 §4.6.1).
pub const ND_OPT_SOURCE_LLA: u8 = 1;
/// Neighbor Discovery option: Target Link-Layer Address (RFC 4861 §4.6.1).
pub const ND_OPT_TARGET_LLA: u8 = 2;
/// Prefix Information option (RFC 4861 §4.6.2).
pub const ND_OPT_PREFIX_INFO: u8 = 3;
/// A link-layer address option for a 6-byte MAC: type, length (1, in units of
/// 8 octets), address.
pub const ND_OPT_LLA_SIZE:   usize = 8;
/// ND hop limit (RFC 4861 §7.1): 255 on every message sent, so a receiver can
/// tell the message was not forwarded by a router.
pub const ND_HOP_LIMIT:      u8  = 255;

/// NA flag: Solicited (S bit).
pub const NA_FLAG_SOLICITED: u32 = 1 << 30;
/// NA flag: Override (O bit).
pub const NA_FLAG_OVERRIDE:  u32 = 1 << 29;

/// All-nodes multicast address (`FF02::1`).
pub const MCAST_ALL_NODES: [u8; 16] = [
    0xFF, 0x02, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x01,
];
/// The loopback address, `::1`: never the source a refusal is answered to.
pub const LOOPBACK: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// All-routers multicast address (`FF02::2`).
pub const MCAST_ALL_ROUTERS: [u8; 16] = [
    0xFF, 0x02, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x02,
];

// ── Global state ──────────────────────────────────────────────────────────────

/// Our link-local IPv6 address (FE80::/64 + EUI-64).
static mut LINK_LOCAL_ADDR: [u8; 16] = [0u8; 16];
/// True once `ipv6_init()` has been called.
static IPV6_READY: AtomicBool = AtomicBool::new(false);

/// What Router Advertisements told us (SLAAC, RFC 4862). One global address
/// from one /64 prefix: this host has one interface and one default router.
struct Slaac {
    /// Global address (prefix + our interface id); all-zero when none.
    global:        [u8; 16],
    /// Tick the global address stops being valid; `u64::MAX` is infinite.
    global_expiry: u64,
    /// The prefix is on-link (PIO `L` flag): its neighbours are reached
    /// directly, everything else goes through the router.
    onlink:        bool,
    /// The default router's link-layer address (the RA's Source Link-Layer
    /// Address option); `router_expiry == 0` when there is none.
    router_mac:    [u8; 6],
    router_expiry: u64,
}

impl Slaac {
    const fn new() -> Self {
        Slaac { global: [0; 16], global_expiry: 0, onlink: false,
                router_mac: [0; 6], router_expiry: 0 }
    }
}

static SLAAC: SpinLock<Slaac> = SpinLock::new(Slaac::new());

/// RFC 4862 §5.5.3 (e): a refresh may not shorten the remaining valid
/// lifetime below two hours, or an off-path forged RA could expire the
/// address.
const SLAAC_TWO_HOURS_S: u64 = 7200;
/// Valid lifetime meaning "forever" (RFC 4861 §4.6.2).
const LIFETIME_INFINITE: u32 = 0xFFFF_FFFF;

fn secs_to_expiry(now: u64, secs: u32) -> u64 {
    if secs == LIFETIME_INFINITE { return u64::MAX; }
    now.saturating_add((secs as u64).saturating_mul(azos_drv_sys::timebase::TIMER_FREQ))
}

// ── Header layout ─────────────────────────────────────────────────────────────

/// Fixed IPv6 header (40 bytes, no extension headers).
///
/// All multi-byte fields are big-endian (network byte order).
#[repr(C, packed)]
pub struct Ipv6Hdr {
    /// Version (4b) | Traffic Class (8b) | Flow Label (20b).
    pub vcf:        [u8; 4],
    /// Payload length (bytes after this header).
    pub payload_len: [u8; 2],
    /// Next header (protocol).
    pub next_hdr:   u8,
    /// Hop limit (decremented by each router).
    pub hop_limit:  u8,
    /// Source address (128-bit).
    pub src:        [u8; 16],
    /// Destination address (128-bit).
    pub dst:        [u8; 16],
}

impl Ipv6Hdr {
    pub fn version(&self) -> u8  { (self.vcf[0] >> 4) & 0xF }
    pub fn payload_length(&self) -> u16 { u16::from_be_bytes(self.payload_len) }
}

// ── Address helpers ───────────────────────────────────────────────────────────

/// Compute the EUI-64 link-local address from a 48-bit MAC address.
///
/// Algorithm (RFC 4291 §2.5.6):
/// 1. Insert `FF:FE` in the middle of the MAC.
/// 2. Flip the Universal/Local bit (bit 6 of the first octet).
/// 3. Prepend `FE80::/64`.
pub fn eui64_link_local(mac: &[u8; 6]) -> [u8; 16] {
    let mut addr = [0u8; 16];
    // FE80::/64 prefix
    addr[0] = 0xFE;
    addr[1] = 0x80;
    // Interface ID (EUI-64): bytes 8..15
    addr[8]  = mac[0] ^ 0x02; // flip U/L bit
    addr[9]  = mac[1];
    addr[10] = mac[2];
    addr[11] = 0xFF;
    addr[12] = 0xFE;
    addr[13] = mac[3];
    addr[14] = mac[4];
    addr[15] = mac[5];
    addr
}

/// Initialize the IPv6 stack with the given MAC address.
///
/// Computes the link-local address, marks the stack ready and solicits a
/// Router Advertisement for SLAAC.
pub fn ipv6_init(mac: &[u8; 6]) {
    let ll = eui64_link_local(mac);
    unsafe { LINK_LOCAL_ADDR = ll; }
    *SLAAC.lock() = Slaac::new();
    IPV6_READY.store(true, Ordering::Release);
    // Ask for a Router Advertisement now rather than wait for the router's
    // next unsolicited one (RFC 4861 §6.3.7). Once: a lost solicitation
    // costs one router interval, and the router repeats its advertisement.
    send_router_solicitation(mac);
}

/// Our link-local address.  Returns all-zero if not initialized.
#[inline]
pub fn ipv6_link_local() -> [u8; 16] {
    unsafe { LINK_LOCAL_ADDR }
}

/// Returns `true` if the IPv6 stack has been initialized.
#[inline]
pub fn ipv6_ready() -> bool { IPV6_READY.load(Ordering::Acquire) }

/// Our SLAAC global address, while it is valid.
pub fn ipv6_global() -> Option<[u8; 16]> {
    let s = SLAAC.lock();
    if s.global == [0u8; 16] { return None; }
    if azos_drv_sys::timebase::now() >= s.global_expiry { return None; }
    Some(s.global)
}

/// Check if `addr` is one of our unicast addresses: link-local or global.
#[inline]
pub fn is_our_addr(addr: &[u8; 16]) -> bool {
    let ll = unsafe { LINK_LOCAL_ADDR };
    *addr == ll || ipv6_global() == Some(*addr)
}

/// Link-local unicast, `FE80::/10` (RFC 4291 §2.5.6).
#[inline]
pub fn is_link_local(addr: &[u8; 16]) -> bool {
    addr[0] == 0xFE && addr[1] & 0xC0 == 0x80
}

/// The source address for a datagram to `dst`: link-local for a link-local
/// or multicast destination (a global source would not be valid on a
/// scoped one), our SLAAC global address for anything else. `None` for a
/// global destination before an advertisement gave us an address: a packet
/// from `fe80::` to a global address is one no router forwards.
pub fn ipv6_source_for(dst: &[u8; 16]) -> Option<[u8; 16]> {
    if is_link_local(dst) || is_multicast(dst) { return Some(ipv6_link_local()); }
    ipv6_global()
}

/// Check if `addr` is the all-nodes multicast address `FF02::1`.
#[inline]
pub fn is_all_nodes(addr: &[u8; 16]) -> bool { addr == &MCAST_ALL_NODES }

/// Check if `addr` is a multicast address (starts with `FF`).
///
/// This is a *format* test, not a membership test — it says the address is
/// some multicast group, not that we are in it.  Do not use it as a receive
/// filter; use [`is_joined_group`].
#[inline]
pub fn is_multicast(addr: &[u8; 16]) -> bool { addr[0] == 0xFF }

/// True for `::`, the unspecified address.
#[inline]
pub fn is_unspecified(addr: &[u8; 16]) -> bool { addr == &[0u8; 16] }

/// The solicited-node multicast group for `addr` (RFC 4291 §2.7.1):
/// `FF02::1:FFXX:XXXX`, where `XX:XXXX` are the low 24 bits of `addr`.
///
/// Neighbor Solicitations for one of our addresses are sent to this group
/// rather than to all-nodes, so an interface that does not accept it cannot be
/// resolved by its neighbours.
pub fn solicited_node(addr: &[u8; 16]) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[0]  = 0xFF;
    g[1]  = 0x02;
    // bytes 2..11 stay zero
    g[11] = 0x01;
    g[12] = 0xFF;
    g[13] = addr[13];
    g[14] = addr[14];
    g[15] = addr[15];
    g
}

/// True if `addr` is a multicast group this interface has actually joined.
///
/// The joined set for a host with one auto-configured link-local address is
/// exactly two groups (RFC 4291 §2.8): all-nodes `FF02::1`, and the
/// solicited-node group of that address. The SLAAC global address shares the
/// interface id, so it shares the group.  Accepting `addr[0] == 0xFF` instead
/// — i.e. every group that exists — meant any remote host could pick an
/// arbitrary destination and still have the datagram parsed and dispatched to
/// an upper layer, which is how a forged source reached the shared UDP socket
/// table.  Membership, not format, is the filter.
#[inline]
pub fn is_joined_group(addr: &[u8; 16]) -> bool {
    is_all_nodes(addr) || *addr == solicited_node(&ipv6_link_local())
}

// ── Pseudo-header checksum ────────────────────────────────────────────────────

/// The pseudo-header's running 32-bit sum (RFC 8200 §8.1): both addresses,
/// the upper-layer length and the next-header value. Unfolded, like
/// `ip::pseudo_checksum`, so `tcp::tcp_checksum` can add the segment to it.
pub fn pseudo_sum(src: &[u8; 16], dst: &[u8; 16], proto: u8, len: u32) -> u32 {
    let mut sum: u32 = 0;
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src[i], src[i+1]]) as u32;
        sum += u16::from_be_bytes([dst[i], dst[i+1]]) as u32;
    }
    // The pseudo-header length is 32 bits wide; a payload here is under 64 KiB.
    sum += len >> 16;
    sum += len & 0xFFFF;
    sum += proto as u32;
    sum
}

/// Compute the ICMPv6 / UDP-over-IPv6 pseudo-header checksum.
///
/// RFC 2460 §8.1: the pseudo-header contains src, dst, upper-layer length,
/// zeros, and the next-header value.
pub fn pseudo_checksum(
    src:      &[u8; 16],
    dst:      &[u8; 16],
    proto:    u8,
    data:     &[u8],
) -> u16 {
    let mut sum = pseudo_sum(src, dst, proto, data.len() as u32);
    // Payload.
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i+1]]) as u32;
        i += 2;
    }
    if i < data.len() { sum += (data[i] as u32) << 8; }
    // Fold carry.
    while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16); }
    !(sum as u16)
}

// ── Header builder ────────────────────────────────────────────────────────────

/// Fill a 40-byte IPv6 header into `buf`.
///
/// `buf` must be at least `IPV6_HDR_SIZE` bytes.  Payload starts at buf[40].
pub fn ipv6_build_header(
    buf:         &mut [u8],
    next_hdr:    u8,
    src:         &[u8; 16],
    dst:         &[u8; 16],
    payload_len: u16,
) {
    debug_assert!(buf.len() >= IPV6_HDR_SIZE);
    buf[0] = IPV6_VERSION << 4;  // Version=6, TC=0, FL=0
    buf[1] = 0; buf[2] = 0; buf[3] = 0;
    buf[4] = (payload_len >> 8) as u8;
    buf[5] = payload_len as u8;
    buf[6] = next_hdr;
    buf[7] = IPV6_HOP_LIMIT;
    buf[8..24].copy_from_slice(src);
    buf[24..40].copy_from_slice(dst);
}

// ── ICMPv6 receive handler ────────────────────────────────────────────────────

/// Process an incoming ICMPv6 message.
///
/// `hdr` is the parsed IPv6 header.  `payload` starts at the ICMPv6 type byte.
/// Returns `true` if the packet was handled (a reply was sent or no reply needed),
/// `false` if the packet should be passed to upper layers.
pub fn icmpv6_rx(src: &[u8; 16], dst: &[u8; 16], payload: &[u8]) -> bool {
    if payload.len() < 4 { return false; }
    // **The checksum is mandatory and was never checked.** RFC 4443 §2.3
    // makes it compulsory for every ICMPv6 message, and `udpv6_rx` next door
    // already drops a datagram whose pseudo-header sum does not verify. Here
    // an echo request was reflected, and a Neighbour Solicitation answered,
    // with the checksum bytes set to anything at all. Once, for every type,
    // before anything is dispatched.
    if pseudo_checksum(src, dst, NEXTHDR_ICMPV6, payload) != 0 { return false; }
    match payload[0] {
        ICMPV6_ECHO_REQ => {
            // **Our unicast address only — never all-nodes.** IPv4 refuses a
            // broadcast echo for exactly this reason (`ip::handle_icmp`): an
            // attacker spoofs the victim as source and every host on the
            // segment answers the victim. This arm answered `ff02::1`, and
            // `ethernet::send_ipv6` sends a unicast IPv6 destination to the
            // Ethernet BROADCAST address while there is no neighbour cache, so
            // the reflected reply — up to a full MTU — reached every host on
            // the link as well. RFC 4443 §4.1 makes answering a multicast echo
            // optional; a robot whose radio link is a safety resource declines.
            //
            // The reply to a unicast echo still leaves as an Ethernet
            // broadcast: an echo request carries no link-layer address to
            // answer, so it closes with the neighbour cache, not here.
            if is_our_addr(dst) && !is_unspecified(src) && !is_multicast(src) {
                icmpv6_echo_reply(dst, src, payload);
                return true;
            }
        }
        ICMPV6_NS => {
            // Not refusable, unlike echo: answering a solicitation for our
            // own address is what makes the address reachable at all.
            //
            // **Answered at the solicitor's own link-layer address, and only
            // then.** The advertisement used to go out through `send_ipv6`,
            // which sends every unicast IPv6 destination to the Ethernet
            // broadcast address, so each solicitation drew a frame to every
            // host on the link. The solicitation names its sender's MAC in the
            // Source Link-Layer Address option (RFC 4861 §4.3); a unicast
            // reply needs exactly that. A solicitation without one — or with
            // a group MAC in it — draws nothing, rather than a broadcast.
            //
            // RFC 4861 §7.1.1 validation before any option is read: code 0, a
            // target that is not a group, a destination that is the target or
            // its solicited-node group (anything else is not a solicitation
            // for it), and a source that is a unicast address — the
            // unspecified source is Duplicate Address Detection, which carries
            // no link-layer option and is never answered here.
            if payload.len() >= ICMPV6_NS_SIZE && payload[1] == 0
                && !is_unspecified(src) && !is_multicast(src)
            {
                let target: [u8; 16] = payload[8..24].try_into().unwrap_or([0u8; 16]);
                if is_our_addr(&target)
                    && (*dst == target || *dst == solicited_node(&target))
                {
                    if let Some(mac) = nd_source_lla(&payload[ICMPV6_NS_SIZE..]) {
                        icmpv6_neighbor_advertisement(src, &mac, &target);
                        return true;
                    }
                }
            }
        }
        ICMPV6_RA => {
            // The hop limit (255) was checked by `ipv6_rx`, which still has
            // the header; the source and the options are checked here.
            ra_process(src, payload);
            return true;
        }
        _ => {}
    }
    false
}

/// Send an ICMPv6 Echo Reply in response to an Echo Request.
///
/// `local` is the address the request was sent to and the reply comes from: a
/// ping of our global address is answered from it, not from the link-local.
fn icmpv6_echo_reply(local: &[u8; 16], dst: &[u8; 16], request: &[u8]) {
    if request.len() < ICMPV6_ECHO_HDR { return; }

    // Build reply: same identifier + sequence, type=129.
    let payload_len = request.len();
    let frame_len   = 14 + IPV6_HDR_SIZE + payload_len;

    let mut frame = [0u8; 1500];
    if frame_len > frame.len() { return; }

    let src = *local;
    ipv6_build_header(&mut frame[14..], NEXTHDR_ICMPV6, &src, dst,
        payload_len as u16);

    let icmp = &mut frame[14 + IPV6_HDR_SIZE..14 + IPV6_HDR_SIZE + payload_len];
    icmp.copy_from_slice(request);
    icmp[0] = ICMPV6_ECHO_REPLY;
    icmp[1] = 0;
    // Zero checksum before computing.
    icmp[2] = 0; icmp[3] = 0;
    let csum = pseudo_checksum(&src, dst, NEXTHDR_ICMPV6, icmp);
    icmp[2] = (csum >> 8) as u8;
    icmp[3] = csum as u8;

    emit(&mut frame, frame_len, dst);
}

/// The unicast MAC in a Neighbour Solicitation's Source Link-Layer Address
/// option, or `None` if the solicitation must draw no reply.
///
/// `options` is everything after the 24-byte fixed part. `None` when:
/// - an option has length 0, which RFC 4861 §4.6 says discards the whole
///   packet — and which would otherwise never advance the walk;
/// - an option runs past the end of the message;
/// - there is no Source Link-Layer Address option;
/// - the address in it is a group address (broadcast or multicast): replying
///   there is the broadcast this path exists to avoid.
///
/// Every option is walked, not just up to the first match, so a malformed
/// option after a good one still discards the packet.
pub fn nd_source_lla(options: &[u8]) -> Option<[u8; 6]> {
    let mut found: Option<[u8; 6]> = None;
    let mut i = 0usize;
    while i < options.len() {
        if options.len() - i < 2 { return None; }
        let kind = options[i];
        let octets = options[i + 1] as usize * 8;
        if octets == 0 { return None; }
        if octets > options.len() - i { return None; }
        // Exactly one unit: that is the option's length for a 6-octet MAC
        // (RFC 2464 §6); a longer one is not an Ethernet address.
        if kind == ND_OPT_SOURCE_LLA && found.is_none() && octets == ND_OPT_LLA_SIZE {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&options[i + 2..i + 8]);
            found = Some(mac);
        }
        i += octets;
    }
    let mac = found?;
    // Group bit set (broadcast, 33:33:… multicast) or all-zero: no reply.
    if mac[0] & 0x01 != 0 || mac == [0u8; 6] { return None; }
    Some(mac)
}

/// Send a Neighbor Advertisement in response to a Neighbor Solicitation.
///
/// `dst` is the solicitor's IPv6 source and `dst_mac` the link-layer address
/// its Source Link-Layer Address option named. The advertisement carries our
/// own MAC in a Target Link-Layer Address option: RFC 4861 §7.2.4 requires it
/// when the solicitation was sent to a multicast group, which is how a
/// solicitation for an unresolved neighbour arrives, and it is sent always.
fn icmpv6_neighbor_advertisement(dst: &[u8; 16], dst_mac: &[u8; 6], target: &[u8; 16]) {
    // Advertised from the address that was solicited: link-local or global.
    let src = *target;
    let payload_len = ICMPV6_NA_SIZE + ND_OPT_LLA_SIZE;
    let frame_len   = 14 + IPV6_HDR_SIZE + payload_len;

    let mut frame = [0u8; 1500];
    ipv6_build_header(&mut frame[14..], NEXTHDR_ICMPV6, &src, dst,
        payload_len as u16);
    // RFC 4861 §7.1.2: a receiver discards an advertisement whose hop limit
    // is not 255 — Linux among them — so the default 64 made it unusable.
    frame[14 + 7] = ND_HOP_LIMIT;

    let na = &mut frame[14 + IPV6_HDR_SIZE..14 + IPV6_HDR_SIZE + payload_len];
    na[0] = ICMPV6_NA;
    na[1] = 0;
    na[2] = 0; na[3] = 0; // checksum (computed below)
    // Flags: Solicited | Override
    let flags = NA_FLAG_SOLICITED | NA_FLAG_OVERRIDE;
    na[4] = (flags >> 24) as u8;
    na[5] = (flags >> 16) as u8;
    na[6] = (flags >> 8)  as u8;
    na[7] = flags as u8;
    // Target address = the address solicited
    na[8..24].copy_from_slice(&src);
    // Target Link-Layer Address option: type 2, length 1 (8 octets), our MAC.
    na[24] = ND_OPT_TARGET_LLA;
    na[25] = 1;
    na[26..32].copy_from_slice(&super::net_get_mac());

    let csum = pseudo_checksum(&src, dst, NEXTHDR_ICMPV6, na);
    na[2] = (csum >> 8) as u8;
    na[3] = csum as u8;

    emit_to(&mut frame, frame_len, dst, Some(dst_mac));
}

// ── IPv6 receive dispatcher ───────────────────────────────────────────────────

/// Parse and dispatch an incoming IPv6 frame (no extension headers: a packet
/// with one has a next-header value no arm below takes, and is dropped).
///
/// `frame` starts at the Ethernet payload (byte 14 of the raw Ethernet frame).
/// `frame_len` is the Ethernet payload length.
pub fn ipv6_rx(frame: &[u8], frame_len: usize) {
    // `frame_len` is the caller's claim about `frame`; the slices below trust
    // it, so it may not exceed what the slice actually holds.
    if frame_len < IPV6_HDR_SIZE || frame_len > frame.len() { return; }
    if (frame[0] >> 4) != IPV6_VERSION { return; }

    let payload_len = u16::from_be_bytes([frame[4], frame[5]]) as usize;
    if IPV6_HDR_SIZE + payload_len > frame_len { return; }

    let src: &[u8; 16] = frame[8..24].try_into().unwrap();
    let dst: &[u8; 16] = frame[24..40].try_into().unwrap();
    // RFC 4291 §2.7: a multicast address is never a source. Every reply this
    // stack builds is addressed to the packet's source, so one would be sent
    // to a group.
    if is_multicast(src) { return; }

    // Destination filter: our unicast address, or a group we have joined
    // (all-nodes + solicited-node).  The trailing `|| is_multicast(dst)` this
    // replaces admitted every multicast address in existence, which made the
    // whole filter a no-op for anyone who bothered to set the first byte to
    // 0xFF — including traffic aimed at the UDP dispatcher below.
    if !is_our_addr(dst) && !is_joined_group(dst) { return; }

    let next_hdr = frame[6];
    let payload  = &frame[IPV6_HDR_SIZE..IPV6_HDR_SIZE + payload_len];

    // RFC 4861 §6.1.2, §7.1.1: a Router Solicitation, Router or Neighbor
    // Solicitation or Advertisement, or Redirect (types 133 to 137) whose hop
    // limit is not 255 has crossed a router, so it did not come from this
    // link. Without this any host on the Internet could set our address (RA)
    // or have a frame sent to a MAC of its choosing (NS option).
    let off_link_nd = next_hdr == NEXTHDR_ICMPV6
        && payload.first().is_some_and(|t| (ICMPV6_RS..=ICMPV6_REDIRECT).contains(t))
        && frame[7] != ND_HOP_LIMIT;
    // Packet filter, ingress hook: after every check above and only for what
    // an arm below takes (a connection is to one of our unicast addresses,
    // never to a group), so a filter sees only datagrams this stack would
    // otherwise have delivered, as on the IPv4 path.
    let taken = match next_hdr {
        NEXTHDR_ICMPV6 => !off_link_nd,
        NEXTHDR_UDP => true,
        NEXTHDR_TCP => is_our_addr(dst),
        _ => false,
    };
    if !taken { return; }
    // Canary (host suite `net-tests`): IPv6 skips the filter, as it did
    // before the filter covered it.
    if !cfg!(feature = "fw-ipv6-canary")
        && !super::filter::ingress_v6(&frame[..IPV6_HDR_SIZE + payload_len])
    {
        return;
    }

    match next_hdr {
        NEXTHDR_ICMPV6 => { icmpv6_rx(src, dst, payload); }
        NEXTHDR_UDP    => { super::udp::udpv6_rx(src, dst, payload); }
        // The ECN field is the low two bits of the Traffic Class (RFC 3168 §5,
        // RFC 8200 §7): bits 4..5 of the header's second octet.
        NEXTHDR_TCP    => {
            let ce = (frame[1] >> 4) & super::ip::ECN_MASK == super::ip::ECN_CE;
            super::tcp::handle_checked_v6(src, dst, payload, ce);
        }
        _ => {}
    }
}

// ── UDP over IPv6 TX ──────────────────────────────────────────────────────────

/// Send a UDP datagram over IPv6.
///
/// `src_port` and `dst_port` are host-byte-order.
/// Returns `true` on success.
pub fn udpv6_send(
    dst_addr: &[u8; 16],
    src_port: u16,
    dst_port: u16,
    data:     &[u8],
) -> bool {
    // Admission bound and frame size must agree, or the copy below writes past
    // the frame and panics — a full board reset under `panic = "abort"`.  They
    // did not: the old bound allowed 1444 payload bytes, giving a 1506-byte
    // frame into a `[u8; 1500]`.  Both are now derived from the same MTU
    // arithmetic (1500 = 40 IPv6 + 8 UDP + payload), and the explicit length
    // check below keeps that an enforced invariant rather than a claim.
    if data.len() > IPV6_UDP_MAX_PAYLOAD { return false; }
    let Some(src_addr) = ipv6_source_for(dst_addr) else { return false };

    // Build UDP header + payload (8 + data.len() bytes).
    let udp_len = (8 + data.len()) as u16;
    let mut udp_buf = [0u8; UDP_HDR_LEN + IPV6_UDP_MAX_PAYLOAD];
    udp_buf[0] = (src_port >> 8) as u8;
    udp_buf[1] = src_port as u8;
    udp_buf[2] = (dst_port >> 8) as u8;
    udp_buf[3] = dst_port as u8;
    udp_buf[4] = (udp_len >> 8) as u8;
    udp_buf[5] = udp_len as u8;
    udp_buf[6] = 0; udp_buf[7] = 0; // checksum placeholder
    udp_buf[8..8 + data.len()].copy_from_slice(data);

    let csum = pseudo_checksum(&src_addr, dst_addr, NEXTHDR_UDP,
        &udp_buf[..udp_len as usize]);
    udp_buf[6] = (csum >> 8) as u8;
    udp_buf[7] = csum as u8;

    let frame_len = ETH_HDR_LEN + IPV6_HDR_SIZE + udp_len as usize;
    let mut frame = [0u8; super::ethernet::ETH_FRAME_MAX];
    // Belt and braces: the admission bound above already guarantees this, but
    // the guarantee is arithmetic in another place, and the cost of being
    // wrong is a reset rather than a dropped packet.
    if frame_len > frame.len() { return false; }
    ipv6_build_header(&mut frame[ETH_HDR_LEN..], NEXTHDR_UDP, &src_addr, dst_addr, udp_len);
    frame[ETH_HDR_LEN + IPV6_HDR_SIZE..frame_len]
        .copy_from_slice(&udp_buf[..udp_len as usize]);

    emit(&mut frame, frame_len, dst_addr)
}

// ── Router discovery and SLAAC (RFC 4861, RFC 4862) ──────────────────────────

/// Fixed part of a Router Advertisement: type, code, checksum, current hop
/// limit, flags, router lifetime, reachable time, retransmit timer.
const ICMPV6_RA_SIZE: usize = 16;
/// Prefix Information option length in octets (length field 4).
const ND_OPT_PIO_SIZE: usize = 32;
/// PIO flags: on-link (`L`) and autonomous address configuration (`A`).
const PIO_FLAG_ONLINK: u8 = 0x80;
const PIO_FLAG_AUTO: u8 = 0x40;
/// SLAAC forms an address from a 64-bit prefix and a 64-bit interface id.
const SLAAC_PREFIX_LEN: u8 = 64;

/// Send a Router Solicitation to `FF02::2` from the link-local address.
///
/// Builds and hands over the whole Ethernet frame itself, with the MAC it was
/// given: `ethernet::send_ipv6_to_mac` asks `net_get_mac()`, which takes the
/// lock `net_init` holds around `ipv6_init`.
fn send_router_solicitation(mac: &[u8; 6]) {
    const RS_LEN: usize = 8 + ND_OPT_LLA_SIZE;
    let src = ipv6_link_local();
    let frame_len = ETH_HDR_LEN + IPV6_HDR_SIZE + RS_LEN;
    let mut frame = [0u8; ETH_HDR_LEN + IPV6_HDR_SIZE + RS_LEN];
    // 33:33:00:00:00:02, the multicast MAC of FF02::2 (RFC 2464 §7).
    frame[0..6].copy_from_slice(&[0x33, 0x33, 0, 0, 0, 0x02]);
    frame[6..12].copy_from_slice(mac);
    frame[12..14].copy_from_slice(&ETH_TYPE_IPV6.to_be_bytes());
    ipv6_build_header(&mut frame[ETH_HDR_LEN..], NEXTHDR_ICMPV6, &src,
        &MCAST_ALL_ROUTERS, RS_LEN as u16);
    frame[ETH_HDR_LEN + 7] = ND_HOP_LIMIT;
    let rs = &mut frame[ETH_HDR_LEN + IPV6_HDR_SIZE..];
    rs[0] = ICMPV6_RS;
    // rs[1..8]: code, checksum (below), reserved.
    rs[8] = ND_OPT_SOURCE_LLA;
    rs[9] = 1;
    rs[10..16].copy_from_slice(mac);
    let csum = pseudo_checksum(&src, &MCAST_ALL_ROUTERS, NEXTHDR_ICMPV6, rs);
    rs[2..4].copy_from_slice(&csum.to_be_bytes());
    if egress_refused(&frame[..frame_len]).is_some() { return; }
    let _ = super::net_raw_send(&frame[..frame_len]);
}

/// Act on a Router Advertisement (RFC 4861 §6.1.2 validation, then §6.3.4 and
/// RFC 4862 §5.5.3). `src` is the IPv6 source; the hop limit was checked
/// by `ipv6_rx`.
///
/// Takes from it: the default router's link-layer address, and one SLAAC
/// address from a /64 Prefix Information option with the autonomous flag.
/// An advertisement with any option of length 0, or running past the message,
/// is discarded whole.
fn ra_process(src: &[u8; 16], ra: &[u8]) {
    if !ipv6_ready() || !is_link_local(src) { return; }
    if ra.len() < ICMPV6_RA_SIZE || ra[1] != 0 { return; }
    let router_lifetime = u16::from_be_bytes([ra[6], ra[7]]) as u32;
    let opts = &ra[ICMPV6_RA_SIZE..];

    // One walk validates every option and keeps what is wanted.
    let mut slla: Option<[u8; 6]> = None;
    let mut pio: Option<&[u8]> = None;
    let mut i = 0usize;
    while i < opts.len() {
        if opts.len() - i < 2 { return; }
        let octets = opts[i + 1] as usize * 8;
        if octets == 0 || octets > opts.len() - i { return; }
        if opts[i] == ND_OPT_SOURCE_LLA && slla.is_none() && octets == ND_OPT_LLA_SIZE {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&opts[i + 2..i + 8]);
            // A group or all-zero address cannot be a router's unicast MAC.
            if mac[0] & 0x01 == 0 && mac != [0u8; 6] { slla = Some(mac); }
        }
        if opts[i] == ND_OPT_PREFIX_INFO && pio.is_none()
            && octets == ND_OPT_PIO_SIZE
            && opts[i + 2] == SLAAC_PREFIX_LEN
            && opts[i + 3] & PIO_FLAG_AUTO != 0
        {
            pio = Some(&opts[i..i + octets]);
        }
        i += octets;
    }

    let now = azos_drv_sys::timebase::now();
    let mut st = SLAAC.lock();

    if router_lifetime == 0 {
        st.router_expiry = 0;
    } else if let Some(mac) = slla {
        st.router_mac = mac;
        st.router_expiry = secs_to_expiry(now, router_lifetime);
    }

    let Some(p) = pio else { return };
    let valid = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
    let preferred = u32::from_be_bytes([p[8], p[9], p[10], p[11]]);
    let mut prefix = [0u8; 16];
    prefix[..8].copy_from_slice(&p[16..24]);
    // A prefix in ::/8 (unspecified, loopback, IPv4-compatible), link-local or
    // multicast is not for SLAAC; a preferred lifetime beyond the valid one is
    // an error (§5.5.3 c); a zero valid lifetime offers nothing.
    if is_link_local(&prefix) || is_multicast(&prefix) || prefix[0] == 0x00
        || valid == 0 || preferred > valid
    {
        return;
    }
    let mut addr = prefix;
    addr[8..].copy_from_slice(&ipv6_link_local()[8..]);

    let held = st.global != [0u8; 16] && now < st.global_expiry;
    if !held {
        st.global = addr;
        st.global_expiry = secs_to_expiry(now, valid);
    } else if st.global == addr {
        // §5.5.3 (e): a refresh raises the lifetime freely, but may lower it
        // only to two hours or more, so a forged advertisement cannot expire
        // an address that is in use.
        let remaining_s = if st.global_expiry == u64::MAX { u64::MAX } else {
            (st.global_expiry - now) / azos_drv_sys::timebase::TIMER_FREQ
        };
        if valid == LIFETIME_INFINITE || valid as u64 > remaining_s {
            st.global_expiry = secs_to_expiry(now, valid);
        } else if remaining_s > SLAAC_TWO_HOURS_S {
            st.global_expiry = secs_to_expiry(now, SLAAC_TWO_HOURS_S as u32);
        }
    } else {
        // A second prefix while the first is valid: one address per host.
        return;
    }
    st.onlink = p[3] & PIO_FLAG_ONLINK != 0;
}

/// The link-layer address for a unicast `dst` when it is not on this link's
/// own segment: the default router's. `None` means send it the way
/// `ethernet::send_ipv6` does — multicast to its group MAC, unicast to
/// broadcast, because there is no neighbour cache to look the host up in.
fn next_hop_mac(dst: &[u8; 16]) -> Option<[u8; 6]> {
    if is_multicast(dst) || is_link_local(dst) { return None; }
    let st = SLAAC.lock();
    if st.router_expiry == 0 || azos_drv_sys::timebase::now() >= st.router_expiry {
        return None;
    }
    if st.onlink && dst[..8] == st.global[..8] { return None; }
    Some(st.router_mac)
}

/// Hand a finished IPv6 frame (`frame[14..]` holds header and payload) to the
/// link: to the router's MAC for an off-link destination, otherwise by
/// `ethernet::send_ipv6`.
fn emit(frame: &mut [u8], frame_len: usize, dst: &[u8; 16]) -> bool {
    emit_to(frame, frame_len, dst, None)
}

/// [`emit`] to `mac` when the caller knows the link-layer address. Every IPv6
/// packet this host sends leaves here, so the packet filter's egress hook is
/// asked once, before the link sees it; the Router Solicitation, built whole
/// (see [`send_router_solicitation`]), asks it itself. `true` when the frame was
/// handed to the driver or the filter dropped it (lost "on the wire"),
/// `false` when it could not leave or the filter rejected it: the caller's
/// error, as `ip::send` reports it.
fn emit_to(frame: &mut [u8], frame_len: usize, dst: &[u8; 16], mac: Option<&[u8; 6]>) -> bool {
    if frame_len > frame.len() || frame_len < ETH_HDR_LEN { return false; }
    if let Some(v) = egress_refused(&frame[..frame_len]) {
        return v == super::filter::Verdict::Drop;
    }
    match mac.copied().or_else(|| next_hop_mac(dst)) {
        Some(mac) => super::ethernet::send_ipv6_to_mac(frame, frame_len, &mac),
        None      => super::ethernet::send_ipv6(frame, frame_len, dst),
    }
}

/// The packet filter's egress verdict on a whole IPv6 frame, `None` when it
/// may leave.
fn egress_refused(frame: &[u8]) -> Option<super::filter::Verdict> {
    // Canary (host suite `net-tests`): see `ipv6_rx`.
    if cfg!(feature = "fw-ipv6-canary") { return None; }
    match super::filter::egress(&frame[ETH_HDR_LEN..]) {
        super::filter::Verdict::Accept => None,
        v => Some(v),
    }
}

/// Largest ICMPv6 error message: the whole packet within the minimum IPv6
/// MTU, 1280 (RFC 4443 §2.4 (c)).
const ICMPV6_ERROR_MAX: usize = 1280 - IPV6_HDR_SIZE;

/// Send an ICMPv6 error of `kind` and `code` from `src` to `dst` about
/// `invoking` (the whole offending packet, header first), quoting as much of
/// it as fits [`ICMPV6_ERROR_MAX`]. `true` when it left.
pub fn icmpv6_send_error(src: &[u8; 16], dst: &[u8; 16], kind: u8, code: u8, invoking: &[u8]) -> bool {
    let quoted = invoking.len().min(ICMPV6_ERROR_MAX - 8);
    let msg_len = 8 + quoted;
    let frame_len = ETH_HDR_LEN + IPV6_HDR_SIZE + msg_len;
    let mut frame = [0u8; ETH_HDR_LEN + 1280];
    ipv6_build_header(&mut frame[ETH_HDR_LEN..], NEXTHDR_ICMPV6, src, dst, msg_len as u16);
    let msg = &mut frame[ETH_HDR_LEN + IPV6_HDR_SIZE..frame_len];
    msg[0] = kind;
    msg[1] = code;
    // msg[2..4] checksum (below), msg[4..8] unused (zero).
    msg[8..].copy_from_slice(&invoking[..quoted]);
    let csum = pseudo_checksum(src, dst, NEXTHDR_ICMPV6, msg);
    msg[2..4].copy_from_slice(&csum.to_be_bytes());
    emit(&mut frame, frame_len, dst)
}

/// Send one TCP segment (`segment`: header, options, payload, checksum
/// already filled) from `src` to `dst`. `0` when the frame was handed to the
/// driver, `-1` otherwise — the convention `ip::send` has, which TCP's send
/// path relies on to know whether the bytes left.
pub fn tcp_send(src: &[u8; 16], dst: &[u8; 16], segment: &[u8], ecn: u8) -> i32 {
    let frame_len = ETH_HDR_LEN + IPV6_HDR_SIZE + segment.len();
    let mut frame = [0u8; super::ethernet::ETH_FRAME_MAX];
    if frame_len > frame.len() { return -1; }
    ipv6_build_header(&mut frame[ETH_HDR_LEN..], NEXTHDR_TCP, src, dst, segment.len() as u16);
    // ECN in the Traffic Class's low bits (RFC 3168 §5): `ip::ECN_ECT0` on the
    // data of a connection that negotiated it.
    frame[ETH_HDR_LEN + 1] |= (ecn & super::ip::ECN_MASK) << 4;
    frame[ETH_HDR_LEN + IPV6_HDR_SIZE..frame_len].copy_from_slice(segment);
    if emit(&mut frame, frame_len, dst) { 0 } else { -1 }
}
