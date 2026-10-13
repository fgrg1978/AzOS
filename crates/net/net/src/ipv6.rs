// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! IPv6 stack (F22).
//!
//! Implements a minimal IPv6 layer sufficient for link-local communication,
//! ICMPv6 (Neighbor Discovery, Echo Request/Reply), and UDP over IPv6.
//! TCP over IPv6 is structurally supported but not wired into the socket
//! layer in this phase.
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
//! | Router Advertisement (RX)   | ✓ (parse only) |
//! | DHCPv6 / SLAAC full         | ✗ (future)     |
//!
//! ## Address plan
//! The kernel auto-configures one link-local address from the MAC address
//! using the EUI-64 algorithm (RFC 4291 §2.5.1):
//!   FE80::/64 + EUI-64(MAC)
//!
//! ## Packet flow
//! ```text
//! RX: ethernet_rx → ipv6_rx → [icmpv6_rx | udpv6_rx]
//! TX: udpv6_send  → ipv6_build_header → ethernet_send
//! ```

use core::sync::atomic::{AtomicBool, Ordering};

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

/// ICMPv6 type codes.
pub const ICMPV6_ECHO_REQ:  u8  = 128;
pub const ICMPV6_ECHO_REPLY:u8  = 129;
pub const ICMPV6_NS:        u8  = 135; // Neighbor Solicitation
pub const ICMPV6_NA:        u8  = 136; // Neighbor Advertisement
pub const ICMPV6_RA:        u8  = 134; // Router Advertisement

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
/// Computes the link-local address and marks the stack ready.
pub fn ipv6_init(mac: &[u8; 6]) {
    let ll = eui64_link_local(mac);
    unsafe { LINK_LOCAL_ADDR = ll; }
    IPV6_READY.store(true, Ordering::Release);
}

/// Our link-local address.  Returns all-zero if not initialized.
#[inline]
pub fn ipv6_link_local() -> [u8; 16] {
    unsafe { LINK_LOCAL_ADDR }
}

/// Returns `true` if the IPv6 stack has been initialized.
#[inline]
pub fn ipv6_ready() -> bool { IPV6_READY.load(Ordering::Acquire) }

/// Check if `addr` matches our link-local address.
#[inline]
pub fn is_our_addr(addr: &[u8; 16]) -> bool {
    unsafe { *addr == LINK_LOCAL_ADDR }
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
/// solicited-node group of that address.  Accepting `addr[0] == 0xFF` instead
/// — i.e. every group that exists — meant any remote host could pick an
/// arbitrary destination and still have the datagram parsed and dispatched to
/// an upper layer, which is how a forged source reached the shared UDP socket
/// table.  Membership, not format, is the filter.
#[inline]
pub fn is_joined_group(addr: &[u8; 16]) -> bool {
    is_all_nodes(addr) || *addr == solicited_node(&ipv6_link_local())
}

// ── Pseudo-header checksum ────────────────────────────────────────────────────

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
    let mut sum: u32 = 0;

    // Accumulate src and dst addresses (16 bytes each, as u16 pairs).
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src[i], src[i+1]]) as u32;
        sum += u16::from_be_bytes([dst[i], dst[i+1]]) as u32;
    }
    // Upper-layer packet length (32-bit in pseudo-header, but payload fits in 16-bit).
    sum += data.len() as u32;
    // Next-header.
    sum += proto as u32;
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
            if is_our_addr(dst) {
                icmpv6_echo_reply(src, payload);
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
            if payload.len() >= ICMPV6_NS_SIZE {
                let target = &payload[8..24];
                if is_our_addr(target.try_into().unwrap_or(&[0u8; 16])) {
                    if let Some(mac) = nd_source_lla(&payload[ICMPV6_NS_SIZE..]) {
                        icmpv6_neighbor_advertisement(src, &mac);
                        return true;
                    }
                }
            }
        }
        ICMPV6_RA => {
            // Parse Router Advertisement — record default gateway (future: SLAAC).
            // For now, just acknowledge reception (no state update).
            return true;
        }
        _ => {}
    }
    false
}

/// Send an ICMPv6 Echo Reply in response to an Echo Request.
fn icmpv6_echo_reply(dst: &[u8; 16], request: &[u8]) {
    if request.len() < ICMPV6_ECHO_HDR { return; }

    // Build reply: same identifier + sequence, type=129.
    let payload_len = request.len();
    let frame_len   = 14 + IPV6_HDR_SIZE + payload_len;

    let mut frame = [0u8; 1500];
    if frame_len > frame.len() { return; }

    let src = ipv6_link_local();
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

    super::ethernet::send_ipv6(&mut frame, frame_len, dst);
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
        if kind == ND_OPT_SOURCE_LLA && found.is_none() && octets >= ND_OPT_LLA_SIZE {
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
fn icmpv6_neighbor_advertisement(dst: &[u8; 16], dst_mac: &[u8; 6]) {
    let src = ipv6_link_local();
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
    // Target address = our link-local
    na[8..24].copy_from_slice(&src);
    // Target Link-Layer Address option: type 2, length 1 (8 octets), our MAC.
    na[24] = ND_OPT_TARGET_LLA;
    na[25] = 1;
    na[26..32].copy_from_slice(&super::net_get_mac());

    let csum = pseudo_checksum(&src, dst, NEXTHDR_ICMPV6, na);
    na[2] = (csum >> 8) as u8;
    na[3] = csum as u8;

    super::ethernet::send_ipv6_to_mac(&mut frame, frame_len, dst_mac);
}

// ── IPv6 receive dispatcher ───────────────────────────────────────────────────

/// Parse and dispatch an incoming IPv6 frame.
///
/// `frame` starts at the Ethernet payload (byte 14 of the raw Ethernet frame).
/// `frame_len` is the Ethernet payload length.
pub fn ipv6_rx(frame: &[u8], frame_len: usize) {
    if frame_len < IPV6_HDR_SIZE { return; }
    if (frame[0] >> 4) != IPV6_VERSION { return; }

    let payload_len = u16::from_be_bytes([frame[4], frame[5]]) as usize;
    if IPV6_HDR_SIZE + payload_len > frame_len { return; }

    let src: &[u8; 16] = frame[8..24].try_into().unwrap();
    let dst: &[u8; 16] = frame[24..40].try_into().unwrap();

    // Destination filter: our unicast address, or a group we have joined
    // (all-nodes + solicited-node).  The trailing `|| is_multicast(dst)` this
    // replaces admitted every multicast address in existence, which made the
    // whole filter a no-op for anyone who bothered to set the first byte to
    // 0xFF — including traffic aimed at the UDP dispatcher below.
    if !is_our_addr(dst) && !is_joined_group(dst) { return; }

    let next_hdr = frame[6];
    let payload  = &frame[IPV6_HDR_SIZE..IPV6_HDR_SIZE + payload_len];

    match next_hdr {
        NEXTHDR_ICMPV6 => { icmpv6_rx(src, dst, payload); }
        NEXTHDR_UDP    => { super::udp::udpv6_rx(src, dst, payload); }
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
    let src_addr = ipv6_link_local();

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

    super::ethernet::send_ipv6(&mut frame, frame_len, dst_addr)
}
