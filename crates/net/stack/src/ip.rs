// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// IP layer — port of net/ip.c
///
/// IPv4 header parsing, checksum, and basic routing.

use super::ethernet::{self, ETH_TYPE_IP};
use super::arp;
use wcet_macro::wcet;
use core::sync::atomic::AtomicU32;
use azos_sync::SpinLock;

/// NAPT for the forwarding path ([`forward`]): the masquerade behind the uplink
/// and its connection table. A child of this module because it only exists to
/// serve it.
#[path = "nat.rs"]
pub mod nat;

pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP:  u8 = 6;
pub const IP_PROTO_UDP:  u8 = 17;

/// ICMP Destination Unreachable (RFC 792).
pub const ICMP_DEST_UNREACHABLE: u8 = 3;
/// Its code 4, Fragmentation Needed and DF Set (RFC 792, RFC 1191 §4).
pub const ICMP_FRAG_NEEDED: u8 = 4;
/// ICMP Time Exceeded (RFC 792): a packet's TTL ran out on the way.
pub const ICMP_TIME_EXCEEDED: u8 = 11;

/// Standard Ethernet Maximum Transmission Unit (bytes).
pub const ETH_MTU: usize = 1500;

/// Minimum IPv4 header size (no options).
pub const IP_HDR_MIN: usize = 20;

/// More-Fragments flag inside the 16-bit fragment field.
pub const IP_FLAG_MF: u16 = 0x2000;
/// Don't-Fragment flag — a hint to routers, *not* an indication of fragmentation.
pub const IP_FLAG_DF: u16 = 0x4000;
/// Low 13 bits of the fragment field hold the offset (in 8-byte units).
pub const IP_FRAG_OFF_MASK: u16 = 0x1FFF;

#[repr(C, packed)]
pub struct IpHdr {
    pub version_ihl: u8,    // version (4) | IHL (in 32-bit words)
    pub dscp_ecn:    u8,
    pub total_len:   [u8; 2],
    pub id:          [u8; 2],
    pub frag_off:    [u8; 2],
    pub ttl:         u8,
    pub protocol:    u8,
    pub checksum:    [u8; 2],
    pub src:         [u8; 4],
    pub dst:         [u8; 4],
}

impl IpHdr {
    pub const MIN_SIZE: usize = 20;

    pub fn ihl_bytes(&self) -> usize {
        ((self.version_ihl & 0x0F) as usize) * 4
    }

    pub fn total_length(&self) -> u16 {
        u16::from_be_bytes(self.total_len)
    }

    pub fn version(&self) -> u8 {
        (self.version_ihl >> 4) & 0xF
    }

    /// Raw fragmentation field (flags + offset) in host order.
    pub fn frag_field(&self) -> u16 {
        u16::from_be_bytes(self.frag_off)
    }

    /// True if this datagram is a fragment: MF set, or a non-zero offset.
    /// DF (`IP_FLAG_DF`) is deliberately excluded — it is a routing hint and
    /// says nothing about whether *this* packet is fragmented.
    pub fn is_fragment(&self) -> bool {
        let f = self.frag_field();
        (f & IP_FLAG_MF) != 0 || (f & IP_FRAG_OFF_MASK) != 0
    }
}

/// Internet checksum (RFC 1071).
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = crate::checksum::sum_be16(0, data);
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

use core::sync::atomic::{AtomicU16, Ordering};

static IP_COUNTER: AtomicU16 = AtomicU16::new(0);

/// IP Router Alert option (RFC 2113 §2.1): type 148 (copied flag set, class 0,
/// number 20), length 4, value 0 — "every router examines this packet".
/// RFC 2236 §2 requires it on every IGMP message.
pub const IP_OPT_ROUTER_ALERT: [u8; 4] = [0x94, 0x04, 0x00, 0x00];

/// Longest options field an IPv4 header can carry: IHL is four bits, so at
/// most 15 words — 60 octets, 20 of them the fixed part (RFC 791 §3.1).
pub const IP_OPTS_MAX: usize = 40;

/// Build an IPv4 header into `buf[0..IpHdr::MIN_SIZE]`.
/// Caller must fill the payload after the header.
pub fn build_header(
    buf:      &mut [u8; 20],
    proto:    u8,
    src:      &[u8; 4],
    dst:      &[u8; 4],
    data_len: u16,
) {
    // No options is always buildable into 20 octets, so the length it returns
    // carries no information here.
    let _ = build_header_with_options(buf, proto, src, dst, &[], data_len);
}

/// Build an IPv4 header carrying `options` into `buf[..20 + options.len()]`
/// and return that length, or 0 when no header was written.
///
/// `options` must already end on a 32-bit boundary: IHL counts words, and
/// RFC 791 §3.1 pads the option list to fill the last one. The caller pads,
/// so the octets it passed are exactly the octets on the wire; a length that
/// is not a multiple of four, longer than `IP_OPTS_MAX`, or a `buf` too short
/// for the header is refused rather than silently truncated.
pub fn build_header_with_options(
    buf:      &mut [u8],
    proto:    u8,
    src:      &[u8; 4],
    dst:      &[u8; 4],
    options:  &[u8],
    data_len: u16,
) -> usize {
    build_header_flags(buf, proto, src, dst, options, data_len, 0, 0)
}

/// [`build_header_with_options`] with Don't Fragment set when `flags` carries
/// `IP_FLAG_DF`, and `ecn` in the ECN field. Nothing else of `flags` is
/// written: this stack never sends a fragment, so MF and the offset stay 0.
fn build_header_flags(
    buf:      &mut [u8],
    proto:    u8,
    src:      &[u8; 4],
    dst:      &[u8; 4],
    options:  &[u8],
    data_len: u16,
    flags:    u16,
    ecn:      u8,
) -> usize {
    if options.len() % 4 != 0 || options.len() > IP_OPTS_MAX { return 0; }
    let hlen = IpHdr::MIN_SIZE + options.len();
    if buf.len() < hlen { return 0; }
    // `hlen <= 60`; checked anyway, since release builds keep overflow checks
    // and a panic on the transmit path is a board reset.
    let total = match (hlen as u16).checked_add(data_len) {
        Some(t) => t,
        None    => return 0,
    };
    let id    = IP_COUNTER.fetch_add(1, Ordering::Relaxed);

    buf[0]  = 0x40 | (hlen / 4) as u8;       // version=4, IHL in 32-bit words
    buf[1]  = ecn;                           // DSCP 0, ECN field (RFC 3168 §5)
    let tl  = total.to_be_bytes();
    buf[2]  = tl[0];
    buf[3]  = tl[1];
    let ib  = id.to_be_bytes();
    buf[4]  = ib[0];
    buf[5]  = ib[1];
    let fb  = (flags & IP_FLAG_DF).to_be_bytes();
    buf[6]  = fb[0];
    buf[7]  = fb[1];
    // TTL. Multicast defaults to 1 (RFC 1112 §6.1, the `IP_MULTICAST_TTL`
    // default): a group datagram is link-local unless someone deliberately
    // widens its scope. Sending it with the unicast 64 would push local group
    // traffic through every router that would forward it — the opposite of
    // the default the standard chose. IGMP itself is required to use 1
    // (RFC 2236 §2), and this is what gives it that for free.
    buf[8]  = if dst[0] & 0xF0 == 0xE0 { 1 } else { 64 };
    buf[9]  = proto;
    buf[10] = 0;    // checksum placeholder
    buf[11] = 0;
    buf[12..16].copy_from_slice(src);
    buf[16..20].copy_from_slice(dst);
    buf[IpHdr::MIN_SIZE..hlen].copy_from_slice(options);
    // RFC 791 §3.1: the header checksum covers the whole header, options
    // included — not the fixed 20 octets.
    let cs = checksum(&buf[..hlen]);
    let cb = cs.to_be_bytes();
    buf[10] = cb[0];
    buf[11] = cb[1];
    hlen
}

/// Closes the loopback recursion, one flag per hart. See [`loopback_deliver`].
static LOOPBACK_ACTIVE: [core::sync::atomic::AtomicBool; LOOPBACK_HARTS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; LOOPBACK_HARTS];

// Host seam: `tests/host/net-tests` and syscall-tests' net shim pull this file
// in with `#[path]`, and their `azos_sync` shim has no preemption counter, so
// the host build runs as one hart that is never preempted.
#[cfg(target_os = "none")]
const LOOPBACK_HARTS: usize = azos_sync::preempt::SLOTS;
#[cfg(target_os = "none")]
#[cfg_attr(feature = "loopback-guard-canary", allow(dead_code))]
#[inline(always)]
fn loopback_pin() -> azos_sync::PreemptGuard { azos_sync::critical_section() }
#[cfg(target_os = "none")]
#[cfg_attr(feature = "loopback-guard-canary", allow(dead_code))]
#[inline(always)]
fn loopback_hart() -> usize { azos_arch::Cpu::hart_id(&azos_arch::ARCH) }
#[cfg(not(target_os = "none"))]
const LOOPBACK_HARTS: usize = 1;
#[cfg(not(target_os = "none"))]
#[cfg_attr(feature = "loopback-guard-canary", allow(dead_code))]
#[inline(always)]
fn loopback_pin() {}
#[cfg(not(target_os = "none"))]
#[cfg_attr(feature = "loopback-guard-canary", allow(dead_code))]
#[inline(always)]
fn loopback_hart() -> usize { 0 }

/// Deliver one built IP packet up this host's own stack, at most one level
/// deep per call stack. `false`: refused, because this call stack is already
/// inside a loopback delivery (a TCP answer to a looped-back segment).
///
/// **The guard is a property of the call stack, not of the machine.** It was
/// one global flag, held across `handle` with preemption ON (syscalls run
/// with interrupts enabled). A task preempted inside its own delivery left
/// the flag up, and every other task's loopback send was refused with -1
/// until it ran again: the vsbench UDP echo lost its reply whenever a wake-up
/// preempted the client between delivering its request and dropping the
/// flag, and the client then waited out its whole poll budget (product
/// kernel, -icount: one refused send in 21, read from a QEMU exec trace). On SMP two harts sending to themselves refused each other the same
/// way. Now the flag is per hart and the delivery runs with preemption off, so
/// the task that raised it is the only one that can see it: a recursion on
/// the same stack is still refused, nothing else is. A tick that lands inside
/// is paid when the guard drops, after the flag is down.
///
/// Cost: preemption is off for one `handle` of one packet (a UDP ring push,
/// or one TCP input step, whose own answer is refused here and not sent).
/// `loopback-guard-canary` restores the old global flag without the guard;
/// `loopback-preempt-probe` asks for a reschedule inside the window on every
/// delivery, as a tick landing there would (gate rows).
fn loopback_deliver(packet: &[u8], our_mac: &[u8; 6], our_ip: &[u8; 4]) -> bool {
    #[cfg(not(feature = "loopback-guard-canary"))]
    let _pinned = loopback_pin();
    #[cfg(not(feature = "loopback-guard-canary"))]
    let Some(active) = LOOPBACK_ACTIVE.get(loopback_hart()) else { return false };
    #[cfg(feature = "loopback-guard-canary")]
    let active = &LOOPBACK_ACTIVE[0];
    if active.swap(true, Ordering::Acquire) {
        return false;
    }
    handle(packet, our_mac, our_ip);
    #[cfg(feature = "loopback-preempt-probe")]
    {
        azos_sync::preempt::set_need_resched();
        drop(azos_sync::critical_section());
    }
    active.store(false, Ordering::Release);
    true
}

/// Send an IP packet.
///
/// A destination equal to our own IP is delivered up the stack without
/// touching the wire; everything else resolves through the ARP cache and
/// returns -1 when there is no MAC.
///
/// A TCP datagram leaves with Don't Fragment set (RFC 1191 §3). Only TCP has a
/// size to adjust when the path is smaller than the link, so only TCP asks the
/// path to say so; every other datagram leaves without it.
#[wcet(150_us)]
pub fn send(
    our_mac:  &[u8; 6],
    our_ip:   &[u8; 4],
    dst_ip:   &[u8; 4],
    proto:    u8,
    payload:  &[u8],
) -> i32 {
    send_ecn(our_mac, our_ip, dst_ip, proto, payload, 0)
}

/// ECN field value ECT(0) (RFC 3168 §5): the sender's transport reacts to
/// congestion marks, so a router may mark this packet instead of dropping it.
pub const ECN_ECT0: u8 = 0b10;
/// ECN field value CE: a router marked the packet (RFC 3168 §5).
pub const ECN_CE: u8 = 0b11;
/// The ECN field, the low two bits of the old TOS octet.
pub const ECN_MASK: u8 = 0b11;

/// [`send`] with `ecn` in the header's ECN field (RFC 3168 §5): TCP's
/// [`ECN_ECT0`] on the data of a connection that negotiated ECN, 0 (Not-ECT)
/// otherwise. DSCP stays 0.
pub fn send_ecn(
    our_mac:  &[u8; 6],
    our_ip:   &[u8; 4],
    dst_ip:   &[u8; 4],
    proto:    u8,
    payload:  &[u8],
    ecn:      u8,
) -> i32 {
    let flags = if proto == IP_PROTO_TCP { IP_FLAG_DF } else { 0 };
    send_flags(our_mac, our_ip, dst_ip, proto, &[], payload, flags, ecn & ECN_MASK)
}

/// [`send`] with IPv4 header options, already padded to a 32-bit boundary
/// (see [`build_header_with_options`]). Loopback, multicast, broadcast and
/// the ARP queue behave exactly as for `send`, which is this with no options.
///
/// Its one in-tree caller is IGMP, which RFC 2236 §2 requires to carry
/// [`IP_OPT_ROUTER_ALERT`]. Returns -1 for options that cannot be encoded.
pub fn send_with_options(
    our_mac:  &[u8; 6],
    our_ip:   &[u8; 4],
    dst_ip:   &[u8; 4],
    proto:    u8,
    options:  &[u8],
    payload:  &[u8],
) -> i32 {
    send_flags(our_mac, our_ip, dst_ip, proto, options, payload, 0, 0)
}

fn send_flags(
    our_mac:  &[u8; 6],
    our_ip:   &[u8; 4],
    dst_ip:   &[u8; 4],
    proto:    u8,
    options:  &[u8],
    payload:  &[u8],
    flags:    u16,
    ecn:      u8,
) -> i32 {
    if options.len() % 4 != 0 || options.len() > IP_OPTS_MAX { return -1; }
    let hdr_len   = IpHdr::MIN_SIZE + options.len();
    let total_len = hdr_len + payload.len();
    // MTU limit — options count against it like any other header octet.
    if total_len > ETH_MTU { return -1; }

    // The IP packet is built BEFORE deciding how it leaves, because it does
    // not depend on the destination MAC. That lets loopback and wire share
    // this buffer instead of each carrying its own. The header is written
    // straight into it, so options cost no second buffer on the stack.
    //
    // Built in place, behind room for the Ethernet header: the frame is
    // finished by writing 14 bytes in front instead of copying the whole
    // packet into a second 1.5 KB stack buffer (IO-QUEUES N5: copies per
    // transmitted frame 3 -> 2; the last one is the driver's staging copy,
    // which the asynchronous TX ring needs).
    const ETH_HDR: usize = ethernet::EthHdr::SIZE;
    let mut frame = [0u8; ethernet::ETH_FRAME_MAX];
    if ETH_HDR + total_len > frame.len() { return -1; }
    let ip_payload = &mut frame[ETH_HDR..];
    if build_header_flags(&mut ip_payload[..hdr_len], proto, our_ip, dst_ip,
                          options, payload.len() as u16, flags, ecn) != hdr_len {
        return -1;
    }
    ip_payload[hdr_len..total_len].copy_from_slice(payload);

    // Packet filter, egress hook: before the packet is looped back, queued for
    // ARP or put on the wire, so every path out is covered once. A dropped
    // datagram reads as sent (it was lost "on the wire"); a rejected one is
    // the caller's error.
    match super::filter::egress(&ip_payload[..total_len]) {
        super::filter::Verdict::Accept => {}
        super::filter::Verdict::Drop => return 0,
        super::filter::Verdict::Reject => return -1,
    }

    // ── Loopback ───────────────────────────────────────────────────────
    //
    // **Local traffic used to go out to the wire.** There was no check for a
    // self-addressed destination: a datagram aimed at our own IP fell into the
    // `arp::lookup` below, found no MAC — nobody answers ARP for its own
    // address — emitted a pointless ARP request and returned -1. In practice,
    // **two local processes could not talk to each other over IP**.
    //
    // Only `dst_ip == our_ip`, not `127.0.0.0/8`: the destination filter in
    // `handle` exists so we do not ingest a neighbour's traffic on shared
    // media, and widening it deserves its own decision.
    //
    // **Reuses `ip_payload`.** The first version declared its own `ETH_MTU`
    // buffer, and with a 16 KB task stack this function already spent 2032
    // bytes of frame. Duplicating a 1500-byte buffer on the network path,
    // under `panic = "abort"`, is not waste: it is moving a board reset closer.
    //
    // With several interfaces "our own IP" is the address of any of them: a
    // datagram to eth1's address from eth0's socket never leaves either link.
    // It is delivered as arriving on the interface that holds the address.
    let owner = iface_owning(dst_ip).and_then(iface_get);
    if (dst_ip == our_ip && *our_ip != [0, 0, 0, 0]) || owner.is_some() {
        let (lo_mac, lo_ip) = owner.map_or((*our_mac, *our_ip), |i| (i.mac, i.ip));
        // **Recursion guard.** `handle` delivers to UDP and TCP, and TCP
        // **answers**: an ACK over loopback would re-enter here with no
        // bottom. Depth 1 — the packet is delivered and any reply it triggers
        // is dropped. TCP retries a lost ACK; nobody retries a blown stack.
        return if loopback_deliver(&ip_payload[..total_len], &lo_mac, &lo_ip) { 0 } else { -1 };
    }

    // ── Multicast local delivery ────────────────────────
    //
    // A sender that has joined the group receives its own datagram: that is
    // the `IP_MULTICAST_LOOP` default of 1, not a convenience. A process
    // subscribed to a group expects to see traffic on it regardless of which
    // process on this host produced it, and the alternative -- local senders
    // being invisible to local receivers -- is the exact bug that made two
    // processes unable to talk over IP before loopback existed here.
    //
    // Unlike the unicast case this does **not** return: the datagram still
    // goes to the wire, because other hosts are members too. The same depth
    // guard applies, for the same reason.
    if super::igmp::is_multicast(dst_ip) && super::igmp::is_joined(dst_ip) {
        let _ = loopback_deliver(&ip_payload[..total_len], our_mac, our_ip);
    }

    // ── Egress: which link, which next hop (RFC 1122 §3.3.1) ───────────────
    //
    // U06-4: **there was no route beyond the local segment.** Every
    // destination was ARPed directly regardless of subnet, and an off-link
    // host (`dns.rs`'s `8.8.8.8` default, a brain or OTA host on another
    // network) drew a broadcast ARP request nobody on the link could answer.
    // Then there was one gateway and no table. Now [`route`] picks the link
    // and the next hop, by longest prefix, across every interface; the IP
    // header above already carries the real `dst_ip`, only the link-layer
    // next hop changes. A destination no route covers is refused (-1) instead
    // of being ARPed on whatever link happens to exist.
    //
    // Broadcast and multicast are addressed to a link, not routed: they
    // leave by the interface that owns the source address, or the first one
    // up when the source is unset (a DHCP client has no address yet, and
    // brings its own raw path for it).
    let is_multicast = super::igmp::is_multicast(dst_ip);
    let eg = if is_multicast || *dst_ip == [0xff; 4] {
        let ifindex = match iface_owning(our_ip).or_else(first_attached) {
            Some(n) => n,
            None => return -1,
        };
        match iface_get(ifindex) {
            Some(iface) => Egress { ifindex, next_hop: *dst_ip, iface },
            None => return -1,
        }
    } else {
        match route(dst_ip) {
            Some(e) => e,
            None => return -1,
        }
    };
    emit(&mut frame, total_len, dst_ip, &eg, is_multicast)
}

/// Put the finished IP packet at `frame[ETH_HDR..ETH_HDR + total_len]` on the
/// link `eg`: the broadcast and multicast link addresses, the next hop's MAC
/// from ARP (the packet waits in the ARP queue when it is not known yet), the
/// Ethernet header written in front, the frame handed to the driver. Shared by
/// [`send`], which builds the packet, and [`forward`], which only rewrites one.
fn emit(
    frame:        &mut [u8; ethernet::ETH_FRAME_MAX],
    total_len:    usize,
    dst_ip:       &[u8; 4],
    eg:           &Egress,
    is_multicast: bool,
) -> i32 {
    // The link's own MTU (the early check above only bounds the buffer).
    if total_len > eg.iface.mtu as usize { return -1; }
    let (our_mac, our_ip) = (&eg.iface.mac, &eg.iface.ip);
    const ETH_HDR: usize = ethernet::EthHdr::SIZE;

    // ── Broadcast (RFC 919 / RFC 922) ──────────────────────────────────
    //
    // **Broadcasting from here was impossible.** A broadcast destination fell
    // into the `arp::lookup` below, and **nobody answers ARP for a broadcast
    // address**: a pointless request went out and -1 came back.
    //
    // DHCP working does not contradict this — it confirms it: `dhcp.rs`
    // carries its own raw path with the comment "bypass ARP — broadcast".
    // Every protocol needing broadcast had to duplicate that workaround, and
    // from ring 3 there was simply no way at all.
    //
    // The two forms the standard defines:
    //   * **limited** `255.255.255.255` (RFC 919) — never forwarded
    //   * **subnet** `network | ~mask` (RFC 922) — everyone on this link:
    //     the egress link's own subnet, so the route already put it there
    //
    // Both go to the broadcast MAC `ff:ff:ff:ff:ff:ff` without asking ARP.
    let is_broadcast = *dst_ip == [0xff; 4] || *dst_ip == eg.iface.broadcast();

    // ── Multicast (RFC 1112 §6.4) ──────────────────────────────────────
    //
    // A group address is mapped straight to `01:00:5E:xx:xx:xx`; asking ARP
    // for it is meaningless — no host owns a group — and would have failed
    // exactly the way broadcast did before RFC 919/922 was implemented here.
    let dst_mac = if is_multicast {
        super::igmp::multicast_mac(dst_ip)
    } else if is_broadcast {
        [0xffu8; 6]
    } else {
        match arp::lookup_on(eg.ifindex, &eg.next_hop) {
            Some(m) => m,
            None    => {
                // **The packet is QUEUED, not dropped.** This used to send an
                // ARP request and return -1, so the FIRST datagram to any
                // address whose MAC was not already cached was lost —
                // guaranteed, every time, on a cold cache. Callers were told
                // "retry after delay" by a comment; none of them did.
                //
                // Same shape as Linux's `neigh` queue: the request goes out,
                // the frame waits for the answer, and the caller is told the
                // packet was ACCEPTED. See `enqueue_for_arp` for what that
                // costs and what is dropped instead. Keyed on the link and
                // the next hop (the gateway when off-link), matching what
                // `arp::send_request_on` asked for — U06-4.
                arp::send_request_on(eg.ifindex, our_mac, our_ip, &eg.next_hop);
                return enqueue_for_arp(eg.ifindex, our_mac, &eg.next_hop, &frame[ETH_HDR..ETH_HDR + total_len]);
            }
        }
    };

    let frame_len = ETH_HDR + total_len;
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(our_mac);
    frame[12..14].copy_from_slice(&ETH_TYPE_IP.to_be_bytes());

    if super::net_raw_send(&frame[..frame_len]) > 0 { 0 } else { -1 }
}

// ── Interfaces and routes ───────────────────────────────────────────────
//
// **One host, several links.** The stack used to have one address, one mask,
// one gateway and one MAC (`NET_CFG` in `lib.rs`), and `send` ARPed whatever
// the mask and the gateway told it to. This is the table that replaces them:
// every NIC the driver layer reports ready is an *interface*, numbered from 1
// in the order it came up (`ifindex`, the way every other stack numbers them,
// with 0 meaning "none"), named `eth<ifindex - 1>`, with its own MAC, MTU,
// IPv4 address and mask, the default gateway its address configuration
// produced (a DHCP lease, or `CONFIG.INI`) and an IPv6 link-local address.
// Interface 1 is the *primary* one: the single-address consumers that have not
// been made per-interface yet (TCP's source address, DHCP, DNS, NTP, IGMP, the
// IPv6 stack) read it through `net_get_ip()` and friends.
//
// **Routes.** A destination leaves by the best of three kinds of route, chosen
// by longest prefix, then lowest metric, then kind (connected, static, lease),
// then lowest interface number:
//   * *connected* — each configured interface's own `ip/mask`, never stored:
//     it is derived from the interface, so it cannot go stale when DHCP moves
//     the address;
//   * *static* — the `[route.NAME]` rows of the topology ([`route_add`]);
//   * *lease* — `0.0.0.0/0` via the interface's configured gateway, at
//     [`LEASE_METRIC`], so a static default (metric 0 unless the row says
//     otherwise) beats it.
// No route is `-1`, as `ENETUNREACH`: the stack no longer ARPs an off-link
// destination directly when it has no gateway.
//
// **Locks.** `IFACES`, then `ROUTES`; neither is held across an ARP lookup or
// a send (the caller gets a copy), the rule `arp_resolved` already follows.

/// A network interface number: 1-based, 0 is "none".
pub type IfIndex = u8;

/// Interfaces the registry holds (Kconfig `NET_MAX_INTERFACES`).
pub const MAX_IFS: usize = azos_limits::NET_MAX_INTERFACES;

/// The primary interface: the first NIC, and the one the single-address
/// consumers read.
pub const PRIMARY_IF: IfIndex = 1;

/// `Iface::nic` of an interface no NIC is attached to yet: its address is
/// configured (CONFIG.INI is read before the NIC probe), nothing can leave it.
pub const NIC_NONE: u8 = u8::MAX;

/// Metric of the default route an address configuration installs. Above the
/// 0 a topology row has unless it says otherwise.
pub const LEASE_METRIC: u32 = 100;

/// Static routes the table holds (Kconfig `TOPOLOGY_MAX_ROUTES`, the rows a
/// topology may declare).
pub const MAX_STATIC_ROUTES: usize = azos_limits::TOPOLOGY_MAX_ROUTES;

/// One network interface.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Iface {
    pub mac:  [u8; 6],
    /// Largest IP packet the link carries.
    pub mtu:  u16,
    /// `0.0.0.0` until configured.
    pub ip:   [u8; 4],
    pub mask: [u8; 4],
    /// Default gateway from the address configuration; `0.0.0.0` for none.
    pub gateway: [u8; 4],
    /// EUI-64 link-local address (RFC 4291 §2.5.1), from the MAC.
    pub ip6_link_local: [u8; 16],
    /// The driver layer's NIC number (`net_device`), or [`NIC_NONE`].
    pub nic:  u8,
}

impl Iface {
    /// An interface with an address configured and no NIC behind it yet.
    pub const fn detached(ip: [u8; 4], mask: [u8; 4], gateway: [u8; 4]) -> Self {
        Iface {
            mac: [0; 6], mtu: ETH_MTU as u16, ip, mask, gateway,
            ip6_link_local: [0; 16], nic: NIC_NONE,
        }
    }

    /// Frames can leave and arrive.
    pub fn attached(&self) -> bool { self.nic != NIC_NONE }

    /// The subnet-directed broadcast address (`network | ~mask`, RFC 922).
    pub fn broadcast(&self) -> [u8; 4] {
        let mut b = [0u8; 4];
        for i in 0..4 { b[i] = (self.ip[i] & self.mask[i]) | !self.mask[i]; }
        b
    }

}

/// The conventional name of interface `ifindex`: `eth0` for 1, `eth1` for 2,
/// ... ([`MAX_IFS`] is at most 8).
pub fn iface_name(ifindex: IfIndex) -> [u8; 4] {
    [b'e', b't', b'h', b'0'.wrapping_add(ifindex.wrapping_sub(1) % 10)]
}

/// Prefix length of a netmask, `None` for one with a hole in it
/// (`255.0.255.0`): a mask is a run of ones then a run of zeros.
pub fn mask_prefix_len(mask: &[u8; 4]) -> Option<u8> {
    let m = u32::from_be_bytes(*mask);
    (m.leading_ones() + m.trailing_zeros() == 32).then_some(m.leading_ones() as u8)
}

/// Does `addr` lie in `net/plen`?
fn in_prefix(addr: &[u8; 4], net: &[u8; 4], plen: u8) -> bool {
    if plen == 0 { return true; }
    let m = u32::MAX << (32 - plen as u32);
    (u32::from_be_bytes(*addr) & m) == (u32::from_be_bytes(*net) & m)
}

static IFACES: SpinLock<[Option<Iface>; MAX_IFS]> = SpinLock::new([None; MAX_IFS]);

/// Run `f` over the registry.
///
/// **Host seam.** The host suites stand in for `lib.rs` and register no NIC;
/// they answer `net_get_mac/ip/mask/gateway` with a fixed address. On the
/// host a primary interface that has no NIC attached is therefore *that*
/// address, so the suites that predate the registry keep seeing the one
/// interface they were written against. A test that wants a real table
/// attaches interface 1 itself (`iface_attach`), and the seam steps aside.
fn with_ifaces<R>(f: impl FnOnce(&[Option<Iface>; MAX_IFS]) -> R) -> R {
    let t = IFACES.lock();
    #[cfg(not(target_os = "none"))]
    if !matches!(t[0], Some(i) if i.attached()) {
        let mut seamed = *t;
        seamed[0] = Some(Iface {
            mac: super::net_get_mac(),
            mtu: ETH_MTU as u16,
            ip: super::net_get_ip(),
            mask: super::net_get_mask(),
            gateway: super::net_get_gateway(),
            ip6_link_local: [0; 16],
            nic: 0,
        });
        return f(&seamed);
    }
    f(&t)
}

/// Configure interface `ifindex`: address, mask and the default gateway of
/// its address configuration (`0.0.0.0` for none). The primary interface is
/// created, with no NIC, if it does not exist yet — the address is set before
/// the NIC is probed. `false` for an interface that does not exist, or a mask
/// with a hole in it.
pub fn iface_configure(ifindex: IfIndex, ip: [u8; 4], mask: [u8; 4], gateway: [u8; 4]) -> bool {
    if mask_prefix_len(&mask).is_none() { return false; }
    let Some(slot) = (ifindex as usize).checked_sub(1).filter(|&s| s < MAX_IFS) else { return false };
    let mut t = IFACES.lock();
    match &mut t[slot] {
        Some(i) => { i.ip = ip; i.mask = mask; i.gateway = gateway; true }
        None if ifindex == PRIMARY_IF => {
            t[slot] = Some(Iface::detached(ip, mask, gateway));
            true
        }
        None => false,
    }
}

/// Attach NIC `nic` as an interface. The primary interface takes the first
/// one (keeping the address configured for it); later NICs take the next free
/// number, unconfigured. A NIC that has an interface already (a NIC that went
/// away and came back) keeps it, with the MAC and link-local address it states
/// now. `None` when the table is full.
pub fn iface_attach(nic: u8, mac: [u8; 6], mtu: u16, ip6_link_local: [u8; 16]) -> Option<IfIndex> {
    let mut t = IFACES.lock();
    let slot = match t.iter().position(|i| i.is_some_and(|i| i.nic == nic)) {
        Some(s) => s,
        None => match t[0] {
            None => 0,
            Some(i) if !i.attached() => 0,
            Some(_) => (1..MAX_IFS).find(|&s| t[s].is_none())?,
        },
    };
    let base = t[slot].unwrap_or(Iface::detached([0; 4], [0; 4], [0; 4]));
    t[slot] = Some(Iface { mac, mtu, ip6_link_local, nic, ..base });
    Some(slot as IfIndex + 1)
}

/// A copy of interface `ifindex`.
pub fn iface_get(ifindex: IfIndex) -> Option<Iface> {
    let slot = (ifindex as usize).checked_sub(1)?;
    with_ifaces(|t| t.get(slot).copied().flatten())
}

/// How many interfaces exist (attached or only configured).
pub fn iface_count() -> usize {
    with_ifaces(|t| t.iter().flatten().count())
}

/// The attached interface whose MAC is `mac`: how a frame names the link it
/// belongs to (its source MAC on the way out, the MAC the receive pass hands
/// the protocol handlers on the way in).
pub fn iface_by_mac(mac: &[u8; 6]) -> Option<IfIndex> {
    with_ifaces(|t| {
        t.iter().position(|i| matches!(i, Some(i) if i.attached() && i.mac == *mac))
            .map(|s| s as IfIndex + 1)
    })
}

/// The attached interface that holds the unicast address `ip`.
pub fn iface_owning(ip: &[u8; 4]) -> Option<IfIndex> {
    if *ip == [0; 4] { return None; }
    with_ifaces(|t| {
        t.iter().position(|i| matches!(i, Some(i) if i.attached() && i.ip == *ip))
            .map(|s| s as IfIndex + 1)
    })
}

/// The interface called `name` (`eth0`, ...), the way a `[route.NAME]` row's
/// `dev` names one.
pub fn iface_by_name(name: &[u8]) -> Option<IfIndex> {
    (1..=MAX_IFS as IfIndex).find(|&n| name == iface_name(n)).filter(|&n| iface_get(n).is_some())
}

/// The lowest-numbered attached interface.
fn first_attached() -> Option<IfIndex> {
    with_ifaces(|t| {
        t.iter().position(|i| matches!(i, Some(i) if i.attached())).map(|s| s as IfIndex + 1)
    })
}

/// A static route: `dest/plen` is reached on `ifindex`, through `via` (or, for
/// `0.0.0.0`, directly on the link).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Route {
    pub dest:    [u8; 4],
    pub plen:    u8,
    pub via:     [u8; 4],
    pub ifindex: IfIndex,
    pub metric:  u32,
}

/// Why [`route_add`] refused a route.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RouteError {
    /// A prefix length above 32.
    BadPrefix,
    /// The interface does not exist.
    NoSuchInterface,
    /// A route to this destination at this metric is already there.
    Duplicate,
    /// The table holds [`MAX_STATIC_ROUTES`] routes.
    Full,
}

static ROUTES: SpinLock<[Option<Route>; MAX_STATIC_ROUTES]> =
    SpinLock::new([None; MAX_STATIC_ROUTES]);

/// Add a static route. Host bits of `dest` beyond `plen` are cleared.
pub fn route_add(
    dest: [u8; 4], plen: u8, via: [u8; 4], ifindex: IfIndex, metric: u32,
) -> Result<(), RouteError> {
    if plen > 32 { return Err(RouteError::BadPrefix); }
    if iface_get(ifindex).is_none() { return Err(RouteError::NoSuchInterface); }
    let mut net = u32::from_be_bytes(dest);
    if plen < 32 { net &= if plen == 0 { 0 } else { u32::MAX << (32 - plen as u32) }; }
    let r = Route { dest: net.to_be_bytes(), plen, via, ifindex, metric };
    let mut t = ROUTES.lock();
    if t.iter().flatten().any(|x| x.dest == r.dest && x.plen == plen && x.metric == metric) {
        return Err(RouteError::Duplicate);
    }
    match t.iter_mut().find(|s| s.is_none()) {
        Some(s) => { *s = Some(r); Ok(()) }
        None => Err(RouteError::Full),
    }
}

/// The static routes, in the order they were added.
pub fn routes() -> [Option<Route>; MAX_STATIC_ROUTES] {
    *ROUTES.lock()
}

/// Where a packet for a destination leaves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Egress {
    pub ifindex:  IfIndex,
    /// The address to resolve on that link: the gateway, or the destination
    /// itself when it is on-link.
    pub next_hop: [u8; 4],
    pub iface:    Iface,
}

/// The best route to `dst`: longest prefix, then lowest metric, then kind
/// (connected, static, lease), then lowest interface. `None` when nothing
/// matches.
pub fn route(dst: &[u8; 4]) -> Option<Egress> {
    best_route(dst, false)
}

/// The uplink: the interface of the best default route (`0.0.0.0/0`, a
/// `[route.NAME]` row or a lease gateway). What the masquerade of [`nat`]
/// translates behind.
pub fn uplink() -> Option<IfIndex> {
    best_route(&[0; 4], true).map(|e| e.ifindex)
}

/// [`route`], restricted to the default routes (prefix length 0) when
/// `default_only`.
fn best_route(dst: &[u8; 4], default_only: bool) -> Option<Egress> {
    // (plen, metric, kind, ifindex, next hop); better = longer prefix, then
    // the lower of each of the rest.
    type Cand = (u8, u32, u8, IfIndex, [u8; 4]);
    fn better(a: &Cand, b: &Cand) -> bool {
        (a.0, b.1, b.2, b.3) > (b.0, a.1, a.2, a.3)
    }
    with_ifaces(|t| {
        let mut best: Option<Cand> = None;
        let mut offer = |c: Cand| {
            if default_only && c.0 != 0 { return; }
            if best.as_ref().map_or(true, |b| better(&c, b)) { best = Some(c); }
        };
        for (s, i) in t.iter().enumerate() {
            let Some(i) = i.filter(|i| i.attached()) else { continue };
            let ifx = s as IfIndex + 1;
            if i.ip != [0; 4] {
                if let Some(plen) = mask_prefix_len(&i.mask) {
                    if in_prefix(dst, &i.ip, plen) { offer((plen, 0, 0, ifx, *dst)); }
                }
                if i.gateway != [0; 4] { offer((0, LEASE_METRIC, 2, ifx, i.gateway)); }
            }
        }
        for r in ROUTES.lock().iter().flatten() {
            let attached = (r.ifindex as usize).checked_sub(1).and_then(|s| t[s]).map_or(false, |i| i.attached());
            if attached && in_prefix(dst, &r.dest, r.plen) {
                let via = if r.via == [0; 4] { *dst } else { r.via };
                offer((r.plen, r.metric, 1, r.ifindex, via));
            }
        }
        best.and_then(|(_, _, _, ifx, next_hop)| {
            t[ifx as usize - 1].map(|iface| Egress { ifindex: ifx, next_hop, iface })
        })
    })
}

/// Test-only: forget every interface and route, so the host seam answers
/// interface 1 again (see [`with_ifaces`]).
pub fn ifaces_reset_for_test() {
    *IFACES.lock() = [None; MAX_IFS];
    *ROUTES.lock() = [None; MAX_STATIC_ROUTES];
}

// ── Pending-ARP transmit queue ──────────────────────────────────────────
//
// Frames that could not leave because the destination MAC was unknown, held
// until the ARP reply arrives. Bounded in every direction on purpose: a queue
// on the transmit path of a robot is a place where memory and latency both go
// wrong quietly.

/// Frames held at once, across ALL destinations.
///
/// Four, matching the spirit of Linux's default `unres_qlen` (3) rather than
/// its letter: this is a whole-queue bound, not a per-neighbour one, because a
/// per-neighbour queue needs a neighbour table and `ARP_TABLE` is a flat cache
/// with no per-entry state to hang it on. Four × `ETH_FRAME_MAX` is ~6 KiB of
/// static, which is the real reason not to make it larger.
pub const ARP_TXQ_SIZE: usize = 4;

/// How long a frame waits before it is dropped rather than sent late.
///
/// Deliberately the same 5 s as `ARP_PENDING_TTL_TICKS`: a frame must not
/// outlive the question it is waiting on, or a reply that arrives after the
/// anti-spoof window closed would find a frame still queued for it and send a
/// datagram nobody is expecting any more.
pub const ARP_TXQ_TTL_TICKS: u64 = 5 * azos_drv_sys::timebase::TIMER_FREQ;

#[derive(Clone, Copy)]
struct QueuedFrame {
    /// The complete Ethernet frame with a ZERO destination MAC. Patched in
    /// place on resolution — the only field that was unknown when it was
    /// built, so nothing has to be re-derived at drain time.
    frame:    [u8; ethernet::ETH_FRAME_MAX],
    len:      u16,
    /// The link it leaves by: the same next hop can be asked about on two.
    ifindex:  IfIndex,
    dst_ip:   [u8; 4],
    deadline: u64,
    valid:    bool,
}

impl QueuedFrame {
    const fn new() -> Self {
        QueuedFrame {
            frame: [0u8; ethernet::ETH_FRAME_MAX],
            len: 0,
            ifindex: 0,
            dst_ip: [0; 4],
            deadline: 0,
            valid: false,
        }
    }
}

static ARP_TXQ: SpinLock<[QueuedFrame; ARP_TXQ_SIZE]> =
    SpinLock::new([QueuedFrame::new(); ARP_TXQ_SIZE]);

/// Frames accepted into the queue.
static TXQ_QUEUED:      AtomicU32 = AtomicU32::new(0);
/// Frames that left because the ARP reply arrived in time.
static TXQ_SENT:        AtomicU32 = AtomicU32::new(0);
/// Frames refused because every slot was taken.
static TXQ_DROPPED_FULL: AtomicU32 = AtomicU32::new(0);
/// Frames dropped because no reply came within the TTL.
static TXQ_EXPIRED:     AtomicU32 = AtomicU32::new(0);

/// `(queued, sent, dropped_full, expired)` — the four numbers that say whether
/// this queue is helping or hiding a problem. A rising `expired` means the
/// peer is not answering ARP; a rising `dropped_full` means the queue is too
/// small for the traffic and packets are being lost exactly as they were
/// before it existed.
pub fn arp_txq_stats() -> (u32, u32, u32, u32) {
    (
        TXQ_QUEUED.load(Ordering::Relaxed),
        TXQ_SENT.load(Ordering::Relaxed),
        TXQ_DROPPED_FULL.load(Ordering::Relaxed),
        TXQ_EXPIRED.load(Ordering::Relaxed),
    )
}

/// Test-only: forget every queued frame and zero the counters.
pub fn arp_txq_reset_for_test() {
    let mut q = ARP_TXQ.lock();
    for i in 0..ARP_TXQ_SIZE { q[i] = QueuedFrame::new(); }
    TXQ_QUEUED.store(0, Ordering::Relaxed);
    TXQ_SENT.store(0, Ordering::Relaxed);
    TXQ_DROPPED_FULL.store(0, Ordering::Relaxed);
    TXQ_EXPIRED.store(0, Ordering::Relaxed);
}

/// Build the frame with a placeholder destination and hold it.
///
/// Returns 0 — the packet was ACCEPTED for transmission, which is the whole
/// contract change. Returns -1 only when it genuinely will not be sent: the
/// frame does not fit, or every slot is taken.
fn enqueue_for_arp(ifindex: IfIndex, our_mac: &[u8; 6], dst_ip: &[u8; 4], ip_payload: &[u8]) -> i32 {
    let frame_len = ethernet::EthHdr::SIZE + ip_payload.len();
    if frame_len > ethernet::ETH_FRAME_MAX { return -1; }

    let now = azos_drv_sys::timebase::now();
    let mut q = ARP_TXQ.lock();

    // Sweep first, so a queue full of dead frames does not refuse a live one.
    for i in 0..ARP_TXQ_SIZE {
        if q[i].valid && now >= q[i].deadline {
            q[i].valid = false;
            TXQ_EXPIRED.fetch_add(1, Ordering::Relaxed);
        }
    }

    let slot = match (0..ARP_TXQ_SIZE).find(|&i| !q[i].valid) {
        Some(i) => i,
        None => { TXQ_DROPPED_FULL.fetch_add(1, Ordering::Relaxed); return -1; }
    };

    // Zero destination MAC: the one thing that was unknown. Everything else is
    // final, so resolution is a 6-byte patch and a send.
    ethernet::build(&mut q[slot].frame[..frame_len], &[0u8; 6], our_mac,
                    ETH_TYPE_IP, ip_payload);
    q[slot].len      = frame_len as u16;
    q[slot].ifindex  = ifindex;
    q[slot].dst_ip   = *dst_ip;
    q[slot].deadline = now + ARP_TXQ_TTL_TICKS;
    q[slot].valid    = true;
    TXQ_QUEUED.fetch_add(1, Ordering::Relaxed);
    0
}

/// An ARP reply landed on link `ifindex`: send everything that was waiting on
/// this address there.
///
/// Called from `arp::handle` AFTER it has released `ARP_TABLE` — the frames go
/// out through `net_raw_send` and nothing here may run under another net lock.
/// Same discipline as `channel_destroy` releasing the pool before orphaning.
pub fn arp_resolved(ifindex: IfIndex, ip: &[u8; 4], mac: &[u8; 6]) {
    let now = azos_drv_sys::timebase::now();
    loop {
        // One frame per pass, and the lock is DROPPED before the send: holding
        // the queue across `net_raw_send` would put the driver's lock under
        // this one for the whole transmit.
        let ready = {
            let mut q = ARP_TXQ.lock();
            let mut found: Option<([u8; ethernet::ETH_FRAME_MAX], usize)> = None;
            for i in 0..ARP_TXQ_SIZE {
                if !q[i].valid { continue; }
                if now >= q[i].deadline {
                    q[i].valid = false;
                    TXQ_EXPIRED.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if q[i].ifindex == ifindex && q[i].dst_ip == *ip {
                    let len = q[i].len as usize;
                    q[i].frame[..6].copy_from_slice(mac);
                    found = Some((q[i].frame, len));
                    q[i].valid = false;
                    break;
                }
            }
            found
        };
        match ready {
            Some((frame, len)) => {
                if super::net_raw_send(&frame[..len]) > 0 {
                    TXQ_SENT.fetch_add(1, Ordering::Relaxed);
                }
            }
            None => break,
        }
    }
}

// ── Forwarding ───────────────────────────────────────────────────────────
//
// **A router, when Kconfig `NET_IP_FORWARD` says so.** A unicast packet that
// arrives for an address no interface holds is sent on by the route table
// instead of being dropped as a host drops it. Forwarded packets skip the
// ingress and egress hooks of the packet filter (they are neither for this host
// nor from it) and meet the forward hook, in this order:
//
//   1. the checks: multicast is dropped silently (routine on a LAN); with the
//      masquerade on, a packet from the uplink that answers no mapping is
//      refused (nothing from outside opens a flow); so is one with a source or
//      destination that is not a unicast address (broadcast, loopback, class
//      E), a directed broadcast of an interface (RFC 2644) and one for an
//      address of this host (the hairpin). A refusal goes through
//      `filter::refuse`: counted and recorded. TTL above 1 (else ICMP "time
//      exceeded");
//   2. an answer to a masqueraded flow is translated back (`nat::inbound`), so
//      the rest sees the LAN host's address as destination;
//   3. the route (else ICMP "network unreachable"); a packet that would leave
//      by the interface it arrived on is refused, no hairpin and no redirect;
//      one longer than the egress MTU draws "fragmentation needed" with that
//      MTU (the stack does not fragment, DF or not);
//   4. TTL decremented, header checksum rewritten;
//   5. the filter's forward hook, with the NAT's view of the flow;
//   6. an outbound packet leaving by the uplink is masqueraded (`nat::outbound`),
//      a refusal there (no mapping room, a protocol without ports) goes through
//      `filter::refuse`;
//   7. the packet is put on the link ([`emit`]), queued for ARP if need be.
//
// The packet is copied once into a frame buffer (the received one is read-only
// and the translation rewrites it), with room in front for the Ethernet header,
// exactly the buffer `send` builds into: no second copy before the driver's.
// The ICMP errors a router owes are rate-limited like the filter's rejections.

/// Is forwarding on? Starts as Kconfig `NET_IP_FORWARD`.
static FORWARDING: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(azos_limits::NET_IP_FORWARD);

/// Does this host route packets between interfaces? One relaxed load.
#[inline(always)]
pub fn forwarding() -> bool {
    FORWARDING.load(Ordering::Relaxed)
}

/// Test-only: switch forwarding on or off.
pub fn set_forwarding_for_test(on: bool) {
    FORWARDING.store(on, Ordering::Relaxed);
}

/// ICMP errors a router sends per second (sustained). A packet it cannot
/// forward is the sender's doing, but the answers must not become a flood of
/// their own (RFC 1812 §4.3.2.8).
const ICMP_ERRORS_PER_SEC: u32 = 50;
static ICMP_ERR_WINDOW: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static ICMP_ERR_SENT: AtomicU32 = AtomicU32::new(0);

/// A source or destination a router may forward: not unspecified, broadcast,
/// loopback, multicast or class E.
fn routable_unicast(a: &[u8; 4]) -> bool {
    *a != [0; 4] && *a != [0xff; 4] && a[0] != 127 && a[0] < 240 && !super::igmp::is_multicast(a)
}

/// Is `a` the subnet-directed broadcast of an interface (RFC 2644: never
/// forwarded)?
fn is_directed_broadcast(a: &[u8; 4]) -> bool {
    with_ifaces(|t| t.iter().flatten().any(|i| i.attached() && i.ip != [0; 4] && i.broadcast() == *a))
}

/// Send ICMP error `typ`/`code` about `offender` (a whole IPv4 packet that came
/// in on `ing`) to its sender, from the address of the interface it came in on:
/// the header and the first eight bytes behind it are quoted (RFC 792). Never
/// about an ICMP error, never to a source that is not a single host, and not
/// beyond [`ICMP_ERRORS_PER_SEC`].
fn icmp_error(ing: &Iface, typ: u8, code: u8, rest: [u8; 4], offender: &[u8]) {
    let ihl = (offender[0] & 0x0F) as usize * 4;
    let src = [offender[12], offender[13], offender[14], offender[15]];
    if !routable_unicast(&src) {
        return;
    }
    if offender[9] == IP_PROTO_ICMP
        && matches!(offender.get(ihl), Some(3 | 4 | 5 | 11 | 12))
    {
        return;
    }
    let now = azos_drv_sys::timebase::now();
    if now.wrapping_sub(ICMP_ERR_WINDOW.load(Ordering::Relaxed)) >= azos_drv_sys::timebase::TIMER_FREQ {
        ICMP_ERR_WINDOW.store(now, Ordering::Relaxed);
        ICMP_ERR_SENT.store(0, Ordering::Relaxed);
    }
    if ICMP_ERR_SENT.fetch_add(1, Ordering::Relaxed) >= ICMP_ERRORS_PER_SEC {
        return;
    }
    let quoted = (ihl + 8).min(offender.len());
    let mut icmp = [0u8; 8 + IP_HDR_MIN + IP_OPTS_MAX + 8];
    icmp[0] = typ;
    icmp[1] = code;
    icmp[4..8].copy_from_slice(&rest);
    icmp[8..8 + quoted].copy_from_slice(&offender[..quoted]);
    let len = 8 + quoted;
    let cs = checksum(&icmp[..len]).to_be_bytes();
    icmp[2] = cs[0];
    icmp[3] = cs[1];
    let _ = send(&ing.mac, &ing.ip, &src, IP_PROTO_ICMP, &icmp[..len]);
}

/// Count and record a packet `forward` decided not to route.
fn refuse_forward(packet: &[u8], in_mac: &[u8; 6], ing: &Iface) {
    super::filter::refuse(super::filter::Hook::Forward, super::filter::Verdict::Drop, packet, in_mac, &ing.ip);
}

/// Route one packet that arrived on the interface whose MAC is `in_mac`.
/// `pkt` is a whole IPv4 packet that has passed the checks of [`handle`]
/// (length, version, header checksum, not a fragment). `answer`: it is the
/// reply to a masqueraded flow, to be translated back before it is routed.
fn forward(pkt: &[u8], in_mac: &[u8; 6], answer: bool) {
    const ETH_HDR: usize = ethernet::EthHdr::SIZE;
    let Some(in_if) = iface_by_mac(in_mac) else { return };
    let Some(ing) = iface_get(in_if) else { return };
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    let total = pkt.len();
    let src = [pkt[12], pkt[13], pkt[14], pkt[15]];
    let dst = [pkt[16], pkt[17], pkt[18], pkt[19]];
    // A router does not forward multicast; on a LAN that is routine traffic, not
    // a refusal worth a record.
    if !answer && super::igmp::is_multicast(&dst) {
        return;
    }
    // Behind the masquerade nothing that arrives from outside opens a flow: a
    // packet from the uplink that is not the answer to a mapping (the answers
    // were told apart in `handle`) is refused, not routed to the LAN.
    if !answer && nat::masquerading() && uplink() == Some(in_if) {
        refuse_forward(pkt, in_mac, &ing);
        return;
    }
    if !routable_unicast(&src) || is_directed_broadcast(&dst) {
        refuse_forward(pkt, in_mac, &ing);
        return;
    }
    // A packet for one of our other addresses is not ours to route (and is not
    // delivered locally either: the stack does not use the weak host model). A
    // LAN host aiming at the uplink's address is the hairpin case.
    if !answer && (!routable_unicast(&dst) || iface_owning(&dst).is_some()) {
        refuse_forward(pkt, in_mac, &ing);
        return;
    }
    if pkt[8] <= 1 {
        icmp_error(&ing, ICMP_TIME_EXCEEDED, 0, [0; 4], pkt);
        return;
    }
    let now = azos_drv_sys::timebase::now();
    let mut frame = [0u8; ethernet::ETH_FRAME_MAX];
    if ETH_HDR + total > frame.len() { return; }
    let ip = &mut frame[ETH_HDR..ETH_HDR + total];
    ip.copy_from_slice(pkt);
    let mut conn = None;
    if answer {
        conn = nat::inbound(ip, ihl, in_if, now);
        if conn.is_none() { return; }
    }
    // After the translation the destination is the LAN host.
    let dst = [ip[16], ip[17], ip[18], ip[19]];
    if !routable_unicast(&dst) || iface_owning(&dst).is_some() {
        refuse_forward(ip, in_mac, &ing);
        return;
    }
    let Some(eg) = route(&dst) else {
        icmp_error(&ing, ICMP_DEST_UNREACHABLE, 0, [0; 4], pkt);
        return;
    };
    if eg.ifindex == in_if {
        refuse_forward(ip, in_mac, &ing);
        return;
    }
    if total > eg.iface.mtu as usize {
        let mtu = eg.iface.mtu.to_be_bytes();
        icmp_error(&ing, ICMP_DEST_UNREACHABLE, ICMP_FRAG_NEEDED, [0, 0, mtu[0], mtu[1]], pkt);
        return;
    }
    ip[8] -= 1;
    ip[10] = 0;
    ip[11] = 0;
    let cs = checksum(&ip[..ihl]).to_be_bytes();
    ip[10] = cs[0];
    ip[11] = cs[1];

    let masquerade = !answer && nat::masquerading() && uplink() == Some(eg.ifindex);
    if masquerade {
        if eg.iface.ip == [0; 4] {
            refuse_forward(ip, in_mac, &ing);
            return;
        }
        conn = Some(super::filter::ConnState {
            phase: nat::phase_out(ip, ihl, eg.ifindex, now),
            reply: false,
        });
    }
    if !super::filter::forward(ip, conn.as_ref(), in_mac, &ing.ip) { return; }
    if masquerade && nat::outbound(ip, ihl, eg.ifindex, eg.iface.ip, now).is_err() {
        refuse_forward(ip, in_mac, &ing);
        return;
    }
    let _ = emit(&mut frame, total, &dst, &eg, false);
}

/// Process an incoming IP packet (payload after ETH header).
pub fn handle(payload: &[u8], our_mac: &[u8; 6], our_ip: &[u8; 4]) {
    if payload.len() < IpHdr::MIN_SIZE { return; }
    let hdr = unsafe { &*(payload.as_ptr() as *const IpHdr) };
    if hdr.version() != 4 { return; }

    let ihl = hdr.ihl_bytes();
    if ihl < IpHdr::MIN_SIZE || payload.len() < ihl { return; }

    let total = hdr.total_length() as usize;
    if total > payload.len() { return; }
    // Crafted packets can carry `total_length < ihl`. The slice below is
    // `&payload[ihl..total]`; without this guard that's a reversed range
    // which Rust panics on (kernel halt in release with `panic = "abort"`).
    if total < ihl { return; }

    // Reject fragments. This stack performs NO reassembly, so the only safe
    // action is to drop: handing fragment N>0 to udp/tcp::handle would parse
    // payload bytes as a fresh L4 header, and an attacker could smuggle data
    // past any L4-level check simply by fragmenting it. Real reassembly needs
    // buffer pools, per-datagram timers and an eviction policy — deliberately
    // out of scope here. Note DF alone is not fragmentation (see is_fragment).
    if hdr.is_fragment() { return; }

    // Verify the header checksum before acting on any field beyond the length
    // bounds above. A well-formed header sums to 0xFFFF including its own
    // checksum word, so RFC-1071 one's complement of that is 0. `ihl` is
    // already bounded by `payload.len()`, so this slice cannot panic.
    if checksum(&payload[..ihl]) != 0 { return; }

    // Destination filter. Without it the stack processed every IPv4 packet the
    // NIC delivered, regardless of addressee. Harmless on a point-to-point link
    // (SLIRP only hands us our own traffic), but on shared media — a real LAN,
    // or QEMU's `socket` backend where both guests see every frame — we would
    // ingest the peer's packets, feed them to TCP (whose connection lookup can
    // match on ports alone), and burn checksum work on traffic that was never
    // ours. Accept:
    //   * our unicast address,
    //   * the limited broadcast 255.255.255.255 (DHCP OFFER/ACK arrive here),
    //   * the subnet directed broadcast (e.g. 10.0.0.255 for a /24),
    //   * anything while we are unconfigured (0.0.0.0) — a DHCP client must be
    //     able to hear the server before it has an address (RFC 2131 §4.1).
    //   * a multicast group we have actually joined (RFC 1112) — including
    //     224.0.0.1, of which every host is a permanent member.
    //
    // Membership is checked at the IP level and not left to the NIC: the
    // RFC 1112 §6.4 MAC mapping drops the group's 24th bit, so 32 groups
    // share one Ethernet address and hardware filtering alone would admit
    // traffic for 31 groups nobody joined.
    let dst = hdr.dst;

    // The answer to a flow the masquerade translated arrives addressed to the
    // uplink, which is this host's own address: it must be told from a packet
    // for a local socket BEFORE the destination test below lets it through as
    // one. Only the uplink's mappings can match (the interface is part of the
    // key), so a LAN host aiming at the uplink's address is not translated back
    // (hairpin), and with the masquerade off this costs one load.
    if nat::masquerading() && dst == *our_ip && *our_ip != [0, 0, 0, 0] {
        if let Some(in_if) = iface_by_mac(our_mac) {
            let now = azos_drv_sys::timebase::now();
            if nat::matches_inbound(&payload[..total], ihl, in_if, now) {
                forward(&payload[..total], our_mac, true);
                return;
            }
        }
    }

    if *our_ip != [0, 0, 0, 0] && dst != *our_ip && dst != [0xff; 4] {
        let admitted = if super::igmp::is_multicast(&dst) {
            super::igmp::is_joined(&dst)
        } else {
            // This link's subnet broadcast: the receiving interface is the
            // one that owns `our_mac`. An unknown link admits none.
            let bcast = iface_by_mac(our_mac).and_then(iface_get).map(|i| i.broadcast());
            bcast == Some(dst)
        };
        if !admitted {
            // Not for this host: a router sends it on, a host drops it.
            if forwarding() { forward(&payload[..total], our_mac, false); }
            return;
        }
    }

    // Learn sender IP→MAC from ARP (we already added it when ARP was processed,
    // but also update here from IP source)
    let src_ip = hdr.src;
    let _ = (src_ip, our_mac); // suppress unused warning

    // Packet filter: one branch when none is installed (`filter` module doc).
    // After every check above, so a filter sees only datagrams this stack
    // would otherwise have delivered, and before any transport spends work.
    if !super::filter::ingress(&payload[..total], our_mac, our_ip) { return; }

    let data = &payload[ihl..total];
    let proto = hdr.protocol;

    // Both L4 handlers take the destination address too: the TCP/UDP checksum
    // covers the IPv4 pseudo-header (src, dst, proto, length), so it cannot be
    // verified without it. Passing `&hdr.dst` here is what makes RX checksum
    // validation possible at all — see `udp::handle_checked` / `tcp::handle_checked`.
    match proto {
        IP_PROTO_ICMP => handle_icmp(&hdr.src, &hdr.dst, data, our_mac, our_ip),
        super::igmp::IP_PROTO_IGMP => super::igmp::handle(data),
        IP_PROTO_UDP  => super::udp::handle_checked(&hdr.src, &hdr.dst, data),
        IP_PROTO_TCP  => super::tcp::handle_checked_ce(&hdr.src, &hdr.dst, data,
                                                       hdr.dscp_ecn & ECN_MASK == ECN_CE),
        _             => {}
    }
}

/// Handle ICMP echo request (ping) — send echo reply — and hand Fragmentation
/// Needed to TCP.
///
/// Replies ONLY to our unicast address.  The destination filter in `handle`
/// deliberately admits the limited and subnet broadcasts (DHCP needs to hear
/// them), which means broadcast echo requests reach this function — and
/// answering those makes the robot a smurf reflector: an attacker pings the
/// broadcast address with the victim's source, every host on the segment
/// replies to the victim, and the robot's link is spent on someone else's
/// attack.  RFC 1122 §3.2.2.6 makes replying to broadcast echo optional; for a
/// device whose radio link is a safety resource it is simply refused.
fn handle_icmp(src_ip: &[u8; 4], dst_ip: &[u8; 4], data: &[u8], our_mac: &[u8; 6], our_ip: &[u8; 4]) {
    if dst_ip != our_ip { return; }
    if data.len() < 8 { return; }
    // Destination Unreachable, Fragmentation Needed and DF Set (RFC 1191 §4):
    // the one ICMP error acted on. TCP meters it before spending a checksum on
    // it and believes it only for a segment of its own still in flight; no
    // reply is ever sent.
    if data[0] == ICMP_DEST_UNREACHABLE && data[1] == ICMP_FRAG_NEEDED {
        super::tcp::icmp_frag_needed(data, our_ip);
        return;
    }
    // Same RFC 1071 identity as the IP header: a valid ICMP message sums to
    // 0xFFFF including its own checksum field. Echoing a corrupt request would
    // vouch for payload bytes we never verified.
    if checksum(data) != 0 { return; }
    let icmp_type = data[0];
    if icmp_type != 8 { return; }  // Only echo request

    // Build echo reply (type=0, same code/id/seq, same data)
    let mut reply = [0u8; 1480];
    let rlen = data.len().min(reply.len());
    reply[..rlen].copy_from_slice(&data[..rlen]);
    reply[0] = 0;  // echo reply
    reply[2] = 0;  // zero checksum
    reply[3] = 0;
    let cs = checksum(&reply[..rlen]);
    let cb = cs.to_be_bytes();
    reply[2] = cb[0];
    reply[3] = cb[1];

    send(our_mac, our_ip, src_ip, IP_PROTO_ICMP, &reply[..rlen]);
}

// The pseudo-header sum lives in `checksum.rs` so host tests can use the
// kernel's own arithmetic rather than a copy that would agree with itself.
// Re-exported here because the whole tree calls it as `ip::pseudo_checksum`.
pub use crate::checksum::pseudo_checksum;
