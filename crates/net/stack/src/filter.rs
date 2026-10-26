// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The packet-filter seam of the IP paths, IPv4 and IPv6.
//!
//! One interface, [`PacketFilter`], and three places it is asked: [`Hook::Ingress`]
//! (a datagram for this host, after the header checks and the destination
//! filter, before any transport sees it), [`Hook::Egress`] (a datagram this host
//! built, before it is looped back, queued for ARP or put on the wire) and
//! [`Hook::Forward`] (a datagram this host routes for someone else, when
//! `NET_IP_FORWARD` is on: the NAT of `nat.rs` is its tracker). A simple
//! built-in firewall and a complex external one plug in the same way: install
//! an object, answer [`Verdict`] for each packet.
//!
//! **Both address families, one filter.** `ip.rs` asks it about IPv4 packets,
//! `ipv6.rs` about IPv6 ones, through the same hooks and the same
//! [`PacketView`] (its `v6` flag says which family the addresses are in). IPv6
//! has no forwarding path, so it meets the ingress and egress hooks only. The
//! Neighbour Discovery messages `ipv6.rs` sends itself (the Neighbour
//! Advertisement, the Router Solicitation) are asked about too: an installed
//! filter sees every IPv6 packet this host sends and every one it takes.
//!
//! **The default is no filter, and it costs one branch.** [`active`] is a single
//! relaxed load of a flag; the packet view is built, and the filter asked, only
//! behind it. With nothing installed the stack is byte-for-byte the stack
//! without this module.
//!
//! **What the verdicts do.**
//!
//! | verdict  | ingress / forward                              | egress                    |
//! |----------|------------------------------------------------|---------------------------|
//! | `Accept` | the packet goes on                             | the packet goes on        |
//! | `Drop`   | silently discarded                             | discarded, `send` says 0  |
//! | `Reject` | discarded, ICMP or ICMPv6 "administratively prohibited" to the sender | discarded, `send` says -1 |
//!
//! A sender does not need to be told it was dropped (`Drop`: the packet is lost
//! on the wire, TCP retransmits); a local caller whose own datagram is refused
//! is told (`Reject`): there is no peer to answer, so the error return is the
//! reply. ICMP is never sent about a broadcast or multicast datagram, about an
//! ICMP datagram, or to a source that is not a single host (RFC 1122 §3.2.2;
//! for IPv6, RFC 4443 §2.4 (e)), and the replies are themselves rate-limited so
//! a flood of refused packets cannot be turned into a flood of replies.
//!
//! **Refusals leave a record.** Every `Drop` and `Reject` bumps a counter and
//! is offered to [`azos_decision`] as [`Rule::PacketRefused`]. A refusal record
//! reaches the durable sink unconditionally, which for a packet flood is the
//! wrong thing, so the stack rate-limits before it records: a token bucket of
//! [`RECORDS_PER_SEC`] with a burst of [`RECORD_BURST`]; the refusals it holds
//! back are counted, and the count rides in the third number of the next record
//! written, the way the capability-denial bucket reports its drops. An IPv6
//! refusal is recorded by the last four bytes of each address (the word the
//! egress gate records for an IPv6 destination too) and bit 32 of the second
//! number set.
//!
//! **The connection state is the filter's business.** The hooks take an
//! `Option<&ConnState>` so a filter that is handed state can use it; the stack
//! passes `None` at the ingress and egress hooks and the NAT's view of the
//! flow at the forward hook (`None` when the packet is not translated). The
//! built-in [`Firewall`] below keeps its own flow table instead and ignores the
//! argument. A stateless filter ignores it too.
//!
//! **The built-in firewall.** [`Firewall`] is the simple filter every preset can
//! have: the `[firewall.NAME]` rows of the topology, compiled at boot into a
//! rule table ([`FwRule`]); the first rule that matches decides; a packet no rule
//! matches gets the default policy (inbound: `FIREWALL_INBOUND_DROP`, on under
//! `USE_GATEWAY`; outbound: accept). It is stateful for TCP and UDP only: a flow
//! one side opened with an accepted packet is tracked by its 5-tuple, and once
//! the peer has answered, packets of the flow pass in both directions whatever
//! the rules say. The table has [`CT_SLOTS`] entries and never grows.
//!
//! A rule with an address prefix matches its own family only; a rule without
//! one matches both, and its `icmp` means ICMP for an IPv4 packet and ICMPv6
//! for an IPv6 one. The inbound default never refuses the five Neighbour
//! Discovery messages ([`ND_TYPES`]: Router Solicitation 133, Router
//! Advertisement 134, Neighbour Solicitation 135, Neighbour Advertisement 136,
//! Redirect 137) when their hop limit is 255, the mark of a message that did
//! not cross a router (RFC 4861 §6.1, §7.1): they are to IPv6 what ARP is to
//! IPv4, which the filter never sees, and SLAAC needs the advertisement and
//! the solicitation. A row still decides about them first. Every other ICMPv6
//! type, echo request and reply among them, gets the policy, as ICMP does.
//!
use super::{ip, ipv6};
use azos_decision::{Rule, Verdict as Decided};
use azos_sync::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Where in the path a packet is being judged.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Hook {
    /// Addressed to this host, before any transport sees it.
    Ingress = 0,
    /// Built by this host, before it leaves (or is looped back).
    Egress = 1,
    /// Being routed through this host (`ip::forward`; the NAT's flow state rides along).
    Forward = 2,
}

/// What a filter says about one packet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Verdict {
    Accept = 0,
    /// Discard without a word to the sender.
    Drop = 1,
    /// Discard and tell the sender.
    Reject = 2,
}

/// Where a packet stands in a connection the filter or a tracker knows of.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnPhase {
    /// First packet of a flow.
    New,
    /// Part of a flow both sides have spoken in.
    Established,
    /// Related to a flow (an ICMP error about it, an FTP-style data flow).
    Related,
}

/// The connection a packet belongs to, as far as whoever holds the state knows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConnState {
    pub phase: ConnPhase,
    /// The packet travels in the direction opposite to the one that opened the flow.
    pub reply: bool,
}

/// A read-only view of one IPv4 or IPv6 packet: the header fields a rule
/// matches on and the bytes behind them. Built over a packet the stack has
/// already validated (length, header checksum) or built itself.
#[derive(Clone, Copy, Debug)]
pub struct PacketView<'a> {
    /// IPv6 when `true`, IPv4 when `false`.
    pub v6: bool,
    /// Source and destination in network order: all 16 bytes for IPv6, the
    /// first four for IPv4 (the rest zero), the layout of the topology's
    /// `IpAddr`.
    pub src: [u8; 16],
    pub dst: [u8; 16],
    /// The IPv4 protocol, or the IPv6 next header (this stack takes no
    /// extension header, so it is the transport's number).
    pub proto: u8,
    /// The whole IP packet, header first, exactly `total_length` bytes (IPv6:
    /// the 40-byte header and the payload length).
    pub packet: &'a [u8],
    /// Header length in bytes (IPv4 options included; 40 for IPv6).
    pub hdr_len: usize,
}

impl<'a> PacketView<'a> {
    /// A view over `packet`, or `None` when it is not a whole IPv4 or IPv6
    /// header.
    pub fn parse(packet: &'a [u8]) -> Option<Self> {
        match packet.first()? >> 4 {
            4 => Self::parse_v4(packet),
            6 => Self::parse_v6(packet),
            _ => None,
        }
    }

    fn parse_v4(packet: &'a [u8]) -> Option<Self> {
        if packet.len() < ip::IP_HDR_MIN {
            return None;
        }
        let hdr_len = (packet[0] & 0x0F) as usize * 4;
        if hdr_len < ip::IP_HDR_MIN || packet.len() < hdr_len {
            return None;
        }
        let (mut src, mut dst) = ([0u8; 16], [0u8; 16]);
        src[..4].copy_from_slice(&packet[12..16]);
        dst[..4].copy_from_slice(&packet[16..20]);
        Some(PacketView { v6: false, src, dst, proto: packet[9], packet, hdr_len })
    }

    fn parse_v6(packet: &'a [u8]) -> Option<Self> {
        if packet.len() < ipv6::IPV6_HDR_SIZE {
            return None;
        }
        let (mut src, mut dst) = ([0u8; 16], [0u8; 16]);
        src.copy_from_slice(&packet[8..24]);
        dst.copy_from_slice(&packet[24..40]);
        Some(PacketView { v6: true, src, dst, proto: packet[6], packet, hdr_len: ipv6::IPV6_HDR_SIZE })
    }

    /// The transport segment: everything after the IP header.
    pub fn payload(&self) -> &'a [u8] {
        &self.packet[self.hdr_len..]
    }

    /// Is this an ICMP message of its family (ICMP for IPv4, ICMPv6 for IPv6)?
    pub fn is_icmp(&self) -> bool {
        self.proto == if self.v6 { ipv6::NEXTHDR_ICMPV6 } else { ip::IP_PROTO_ICMP }
    }

    /// One of the Neighbour Discovery messages ([`ND_TYPES`]) with the hop
    /// limit, 255, that says it did not cross a router.
    pub fn is_neighbour_discovery(&self) -> bool {
        self.v6
            && self.proto == ipv6::NEXTHDR_ICMPV6
            && self.packet[7] == ipv6::ND_HOP_LIMIT
            && self.payload().first().is_some_and(|t| ND_TYPES.contains(t))
    }

    /// Source port of a TCP or UDP datagram.
    pub fn src_port(&self) -> Option<u16> {
        self.port(0)
    }

    /// Destination port of a TCP or UDP datagram.
    pub fn dst_port(&self) -> Option<u16> {
        self.port(2)
    }

    /// The TCP flag byte (FIN 0x01, SYN 0x02, RST 0x04, PSH 0x08, ACK 0x10, ...).
    pub fn tcp_flags(&self) -> Option<u8> {
        if self.proto != ip::IP_PROTO_TCP {
            return None;
        }
        self.payload().get(13).copied()
    }

    fn port(&self, at: usize) -> Option<u16> {
        if self.proto != ip::IP_PROTO_TCP && self.proto != ip::IP_PROTO_UDP {
            return None;
        }
        let p = self.payload();
        if p.len() < at + 2 {
            return None;
        }
        Some(u16::from_be_bytes([p[at], p[at + 1]]))
    }
}

/// The ICMPv6 types of Neighbour Discovery (RFC 4861 §4): Router
/// Solicitation, Router Advertisement, Neighbour Solicitation and
/// Advertisement, Redirect. The set `ipv6.rs` refuses unless its hop limit is
/// 255, and the set the built-in firewall's inbound default never refuses.
pub const ND_TYPES: core::ops::RangeInclusive<u8> = ipv6::ICMPV6_RS..=ipv6::ICMPV6_REDIRECT;

/// A packet filter. Installed with [`set_filter`]; asked once per packet per hook.
///
/// `check` runs on the receive and transmit paths, on any hart, possibly at
/// once: it must be quick, must not block, and must not call back into the
/// stack's send path (a refused packet is answered by the stack, not by the
/// filter).
pub trait PacketFilter: Sync {
    fn check(&self, hook: Hook, pkt: &PacketView, conn: Option<&ConnState>) -> Verdict;
}

/// Refusal records written per second (sustained).
pub const RECORDS_PER_SEC: u64 = 4;
/// Refusal records written in one burst before the sustained rate applies.
pub const RECORD_BURST: u64 = 8;
/// ICMP rejections sent per second (sustained).
pub const REPLIES_PER_SEC: u64 = 50;
/// ICMP rejections sent in one burst.
pub const REPLY_BURST: u64 = 50;

static ACTIVE: AtomicBool = AtomicBool::new(false);
static FILTER: SpinLock<Option<&'static dyn PacketFilter>> = SpinLock::new(None);

/// Install `f` as the packet filter, replacing any other.
pub fn set_filter(f: &'static dyn PacketFilter) {
    *FILTER.lock() = Some(f);
    ACTIVE.store(true, Ordering::Release);
}

/// Remove the filter: back to the null filter that accepts everything.
pub fn clear_filter() {
    ACTIVE.store(false, Ordering::Release);
    *FILTER.lock() = None;
}

/// Is a filter installed? The one branch the null filter costs.
#[inline(always)]
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

// ── Rate limit ───────────────────────────────────────────────────────────────

/// A token bucket kept as ticks of credit, so it needs no division on the
/// admit path and no fractional tokens.
struct Bucket {
    /// Credit held, in ticks; one admit costs `cost`.
    level: u64,
    last: u64,
    primed: bool,
    /// Admits refused since the last one granted.
    owed: u64,
}

impl Bucket {
    const fn new() -> Self {
        Bucket { level: 0, last: 0, primed: false, owed: 0 }
    }

    /// Admit one event at `now` under `per_sec` with `burst`: `Some(owed)` (the
    /// events held back since the last admit), or `None` when this one is.
    fn admit(&mut self, now: u64, per_sec: u64, burst: u64) -> Option<u64> {
        let cost = (azos_drv_sys::timebase::TIMER_FREQ / per_sec.max(1)).max(1);
        let cap = cost.saturating_mul(burst.max(1));
        if !self.primed {
            self.primed = true;
            self.level = cap;
        } else {
            self.level = self.level.saturating_add(now.saturating_sub(self.last)).min(cap);
        }
        self.last = now;
        if self.level >= cost {
            self.level -= cost;
            Some(core::mem::take(&mut self.owed))
        } else {
            self.owed += 1;
            None
        }
    }
}

static RECORD_BUCKET: SpinLock<Bucket> = SpinLock::new(Bucket::new());
static REPLY_BUCKET: SpinLock<Bucket> = SpinLock::new(Bucket::new());

static REFUSED: AtomicU32 = AtomicU32::new(0);
static RECORDED: AtomicU32 = AtomicU32::new(0);
static RECORD_HELD: AtomicU32 = AtomicU32::new(0);
static REPLIED: AtomicU32 = AtomicU32::new(0);
static REPLY_HELD: AtomicU32 = AtomicU32::new(0);

/// What the filter seam has done since boot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Stats {
    /// Packets a filter dropped or rejected.
    pub refused: u32,
    /// Refusal records written (offered to the decision recorder).
    pub recorded: u32,
    /// Refusals the record rate limit held back.
    pub record_held: u32,
    /// ICMP rejections sent.
    pub replied: u32,
    /// ICMP rejections the reply rate limit (or RFC 1122) held back.
    pub reply_held: u32,
}

pub fn stats() -> Stats {
    Stats {
        refused: REFUSED.load(Ordering::Relaxed),
        recorded: RECORDED.load(Ordering::Relaxed),
        record_held: RECORD_HELD.load(Ordering::Relaxed),
        replied: REPLIED.load(Ordering::Relaxed),
        reply_held: REPLY_HELD.load(Ordering::Relaxed),
    }
}

/// Put the seam back to its boot state: no filter, buckets full, counters zero.
pub fn reset_for_test() {
    clear_filter();
    *RECORD_BUCKET.lock() = Bucket::new();
    *REPLY_BUCKET.lock() = Bucket::new();
    for c in [&REFUSED, &RECORDED, &RECORD_HELD, &REPLIED, &REPLY_HELD] {
        c.store(0, Ordering::Relaxed);
    }
}

// ── Asking the filter ────────────────────────────────────────────────────────

#[inline(never)]
fn ask(hook: Hook, pkt: &PacketView, conn: Option<&ConnState>) -> Verdict {
    // Copied out so the filter runs without the install lock held.
    let f = *FILTER.lock();
    let v = match f {
        Some(f) => f.check(hook, pkt, conn),
        None => Verdict::Accept,
    };
    if v != Verdict::Accept {
        refused(hook, v, pkt);
    }
    v
}

/// Count a refusal and, within the rate limit, record it.
fn refused(hook: Hook, v: Verdict, pkt: &PacketView) {
    REFUSED.fetch_add(1, Ordering::Relaxed);
    let now = azos_drv_sys::timebase::now();
    let owed = RECORD_BUCKET.lock().admit(now, RECORDS_PER_SEC, RECORD_BURST);
    let Some(owed) = owed else {
        RECORD_HELD.fetch_add(1, Ordering::Relaxed);
        return;
    };
    RECORDED.fetch_add(1, Ordering::Relaxed);
    let (sport, dport) = (pkt.src_port().unwrap_or(0) as u64, pkt.dst_port().unwrap_or(0) as u64);
    let (src, dst) = (record_word(pkt, &pkt.src), record_word(pkt, &pkt.dst));
    // n[0]: src << 32 | dst. n[1]: hook, verdict, protocol, bit 32 for IPv6,
    // ports. n[2]: refusals held back by the rate limit since the previous
    // record.
    azos_decision::record(
        Rule::PacketRefused,
        Decided::Refuse,
        src,
        [
            (src as u64) << 32 | dst as u64,
            (hook as u64) << 56 | (v as u64) << 48 | (pkt.proto as u64) << 40 | (pkt.v6 as u64) << 32 | sport << 16 | dport,
            owed,
        ],
    );
}

/// The 32 bits of an address a refusal record carries: the IPv4 address, or
/// the last four bytes of an IPv6 one.
fn record_word(pkt: &PacketView, a: &[u8; 16]) -> u32 {
    let at = if pkt.v6 { 12 } else { 0 };
    u32::from_be_bytes([a[at], a[at + 1], a[at + 2], a[at + 3]])
}

/// Judge an IPv4 packet addressed to this host, which came in on the
/// interface with `our_mac` and `our_ip`. `true`: let it through. Otherwise it
/// has been discarded here (and answered, for `Reject`).
#[inline(always)]
pub fn ingress(packet: &[u8], our_mac: &[u8; 6], our_ip: &[u8; 4]) -> bool {
    if !active() {
        return true;
    }
    receive(Hook::Ingress, packet, None, Some((our_mac, our_ip)))
}

/// [`ingress`] for an IPv6 packet: the answer to a `Reject` needs no
/// interface, `ipv6.rs` has one.
#[inline(always)]
pub fn ingress_v6(packet: &[u8]) -> bool {
    if !active() {
        return true;
    }
    receive(Hook::Ingress, packet, None, None)
}

/// Judge a packet this host would route. Same contract as [`ingress`]; `conn`
/// is the tracker's view of the flow, if there is a tracker.
#[inline(always)]
pub fn forward(packet: &[u8], conn: Option<&ConnState>, our_mac: &[u8; 6], our_ip: &[u8; 4]) -> bool {
    if !active() {
        return true;
    }
    receive(Hook::Forward, packet, conn, Some((our_mac, our_ip)))
}

/// Refuse a packet the stack itself decided not to forward (the NAT table has
/// no room, the packet would leave by the way it came, it came from outside
/// the masquerade unasked, it is aimed at this host's own address): the same count, the
/// same rate-limited [`Rule::PacketRefused`] record and, for `Reject`, the same
/// ICMP answer to the sender as a verdict from an installed filter. Unlike the
/// hooks it does not look at [`active`]: nothing was asked of a filter.
pub fn refuse(hook: Hook, v: Verdict, packet: &[u8], our_mac: &[u8; 6], our_ip: &[u8; 4]) {
    let Some(view) = PacketView::parse(packet) else { return };
    refused(hook, v, &view);
    if v == Verdict::Reject {
        answer(&view, Some((our_mac, our_ip)));
    }
}

/// Judge a packet this host built, IPv4 or IPv6. The caller acts on the
/// verdict: nothing for `Accept`, a discard for the others (see the table in
/// the module doc).
#[inline(always)]
pub fn egress(packet: &[u8]) -> Verdict {
    if !active() {
        return Verdict::Accept;
    }
    match PacketView::parse(packet) {
        Some(view) => ask(Hook::Egress, &view, None),
        None => Verdict::Accept,
    }
}

/// The interface an IPv4 packet came in on (its MAC and address), which
/// answers a `Reject`; `None` for IPv6.
type Iface<'a> = Option<(&'a [u8; 6], &'a [u8; 4])>;

#[inline(never)]
fn receive(hook: Hook, packet: &[u8], conn: Option<&ConnState>, iface: Iface) -> bool {
    let Some(view) = PacketView::parse(packet) else { return true };
    match ask(hook, &view, conn) {
        Verdict::Accept => true,
        Verdict::Drop => false,
        Verdict::Reject => {
            answer(&view, iface);
            false
        }
    }
}

/// Tell the sender of `view` it was refused, in its own family.
fn answer(view: &PacketView, iface: Iface) {
    match iface {
        Some((our_mac, our_ip)) if !view.v6 => reject(view, our_mac, our_ip),
        None if view.v6 => reject_v6(view),
        _ => {}
    }
}

/// ICMP Destination Unreachable, code 13 "communication administratively
/// prohibited" (RFC 1812 §5.2.7.1), to the sender of `view`, carrying the
/// offending header and its first eight payload bytes (RFC 792).
fn reject(view: &PacketView, our_mac: &[u8; 6], our_ip: &[u8; 4]) {
    if !may_answer(view) {
        REPLY_HELD.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if !admit_reply() {
        return;
    }
    let quoted = (view.hdr_len + 8).min(view.packet.len());
    let mut icmp = [0u8; 8 + ip::IP_HDR_MIN + ip::IP_OPTS_MAX + 8];
    icmp[0] = ip::ICMP_DEST_UNREACHABLE;
    icmp[1] = ICMP_ADMIN_PROHIBITED;
    icmp[8..8 + quoted].copy_from_slice(&view.packet[..quoted]);
    let len = 8 + quoted;
    let cs = ip::checksum(&icmp[..len]).to_be_bytes();
    icmp[2] = cs[0];
    icmp[3] = cs[1];
    REPLIED.fetch_add(1, Ordering::Relaxed);
    let _ = ip::send(our_mac, our_ip, &v4(&view.src), ip::IP_PROTO_ICMP, &icmp[..len]);
}

/// Code 13 of Destination Unreachable.
const ICMP_ADMIN_PROHIBITED: u8 = 13;

/// The IPv4 address in a view's 16-byte field.
fn v4(a: &[u8; 16]) -> [u8; 4] {
    [a[0], a[1], a[2], a[3]]
}

/// ICMPv6 Destination Unreachable, code 1 "communication with destination
/// administratively prohibited" (RFC 4443 §3.1), to the sender of `view`, from
/// the address it was sent to, carrying as much of it as fits the minimum
/// IPv6 MTU.
fn reject_v6(view: &PacketView) {
    if !may_answer_v6(view) {
        REPLY_HELD.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if !admit_reply() {
        return;
    }
    REPLIED.fetch_add(1, Ordering::Relaxed);
    let _ = ipv6::icmpv6_send_error(&view.dst, &view.src, ipv6::ICMPV6_DEST_UNREACHABLE, ICMPV6_ADMIN_PROHIBITED, view.packet);
}

/// Code 1 of ICMPv6 Destination Unreachable.
const ICMPV6_ADMIN_PROHIBITED: u8 = 1;

/// RFC 4443 §2.4 (e): no ICMPv6 error about an ICMPv6 message (this stack
/// sends none about informational ones either, as for IPv4), a datagram to a
/// group, or one whose source is not a single host.
fn may_answer_v6(view: &PacketView) -> bool {
    let single_host = |a: &[u8; 16]| {
        !ipv6::is_unspecified(a) && !ipv6::is_multicast(a) && *a != ipv6::LOOPBACK
    };
    !view.is_icmp() && single_host(&view.src) && single_host(&view.dst)
}

/// Is there a token for one more rejection? Counts the one held back.
fn admit_reply() -> bool {
    let now = azos_drv_sys::timebase::now();
    if REPLY_BUCKET.lock().admit(now, REPLIES_PER_SEC, REPLY_BURST).is_none() {
        REPLY_HELD.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    true
}

/// RFC 1122 §3.2.2: no ICMP error about an ICMP datagram, a broadcast or
/// multicast datagram, or one whose source is not a single host.
fn may_answer(view: &PacketView) -> bool {
    if view.is_icmp() {
        return false;
    }
    let single_host = |a: &[u8; 4]| {
        *a != [0; 4] && *a != [0xff; 4] && a[0] != 127 && !super::igmp::is_multicast(a)
    };
    let (src, dst) = (v4(&view.src), v4(&view.dst));
    if !single_host(&src) || !single_host(&dst) {
        return false;
    }
    let (ip, mask) = (super::net_get_ip(), super::net_get_mask());
    let directed_broadcast = (0..4).all(|i| dst[i] == (ip[i] & mask[i]) | !mask[i]);
    !directed_broadcast
}

// ── The built-in firewall ────────────────────────────────────────────────────

/// Rules the table holds: one per topology row (Kconfig
/// `TOPOLOGY_MAX_FIREWALL_ROWS`, the most a topology may declare).
pub const MAX_RULES: usize = azos_limits::TOPOLOGY_MAX_FIREWALL_ROWS;
/// Entries of one set of the flow table.
const WAYS: usize = 4;
/// Flows the firewall tracks: Kconfig `FIREWALL_CONNTRACK_MAX` rounded down to a
/// whole number of sets.
pub const CT_SLOTS: usize = azos_limits::FIREWALL_CONNTRACK_MAX / WAYS * WAYS;
const SETS: usize = CT_SLOTS / WAYS;
const _: () = assert!(SETS > 0, "FIREWALL_CONNTRACK_MAX holds at least one set of 4");
/// How long a TCP flow nobody has answered, or one that has carried a FIN or an
/// RST, is held without a packet (seconds).
const HALF_OPEN_S: u64 = 20;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// One compiled `[firewall.NAME]` row. All-zero is a valid rule (any ingress
/// packet, accept), which keeps an empty table in `.bss`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FwRule {
    /// Which hook the rule looks at.
    pub hook: Hook,
    /// IP protocol number; 0 matches any (protocol 0 is IPv6 hop-by-hop, which
    /// this stack never takes). `ip::IP_PROTO_ICMP` matches ICMPv6 in an IPv6
    /// packet: a row's `icmp` names the ICMP of the packet's family.
    pub proto: u8,
    /// First and last destination port matched (TCP and UDP only); `port_lo`
    /// 0 matches any packet.
    pub port_lo: u16,
    pub port_hi: u16,
    /// The remote address prefix in network order, laid out as
    /// [`PacketView::src`]: the source of an ingress packet, the destination of
    /// an egress or forwarded one. `net_len` 0 matches any address of either
    /// family; otherwise the prefix is IPv6 when `net_v6`, IPv4 when not, and
    /// matches packets of that family only.
    pub net: [u8; 16],
    pub net_len: u8,
    pub net_v6: bool,
    pub action: Verdict,
}

impl FwRule {
    const EMPTY: FwRule = FwRule {
        hook: Hook::Ingress,
        proto: 0,
        port_lo: 0,
        port_hi: 0,
        net: [0; 16],
        net_len: 0,
        net_v6: false,
        action: Verdict::Accept,
    };

    fn matches(&self, hook: Hook, pkt: &PacketView) -> bool {
        let proto_ok = match self.proto {
            0 => true,
            ip::IP_PROTO_ICMP => pkt.is_icmp(),
            p => p == pkt.proto,
        };
        if self.hook != hook || !proto_ok {
            return false;
        }
        if self.port_lo != 0 && !pkt.dst_port().is_some_and(|p| (self.port_lo..=self.port_hi).contains(&p)) {
            return false;
        }
        if self.net_len == 0 {
            return true;
        }
        if self.net_v6 != pkt.v6 {
            return false;
        }
        let remote = if hook == Hook::Ingress { &pkt.src } else { &pkt.dst };
        let bits = self.net_len.min(if self.net_v6 { 128 } else { 32 }) as usize;
        let (whole, rest) = (bits / 8, bits % 8);
        if remote[..whole] != self.net[..whole] {
            return false;
        }
        let mask = !(0xFFu8 >> rest);
        rest == 0 || remote[whole] & mask == self.net[whole] & mask
    }
}

/// The 5-tuple of a TCP or UDP packet, its family and its TCP flags (0 for
/// UDP). Whole addresses: an IPv4 and an IPv6 flow never share an entry.
#[derive(Clone, Copy)]
struct Tuple {
    src: [u8; 16],
    dst: [u8; 16],
    sport: u16,
    dport: u16,
    proto: u8,
    v6: bool,
    flags: u8,
}

impl Tuple {
    /// `None` for anything that is not a TCP or UDP packet with a whole header
    /// prefix: those are judged by the rules alone.
    fn of(pkt: &PacketView) -> Option<Self> {
        let (sport, dport) = (pkt.src_port()?, pkt.dst_port()?);
        let flags = if pkt.proto == ip::IP_PROTO_TCP { pkt.tcp_flags()? } else { 0 };
        Some(Tuple { src: pkt.src, dst: pkt.dst, sport, dport, proto: pkt.proto, v6: pkt.v6, flags })
    }

    /// May this packet open a flow: any UDP datagram, a TCP SYN without ACK.
    fn starts_flow(&self) -> bool {
        self.proto != ip::IP_PROTO_TCP || self.flags & (TCP_SYN | TCP_ACK) == TCP_SYN
    }
}

/// The flow state bits.
const ST_REPLIED: u8 = 1; // the peer has answered
const ST_CLOSING: u8 = 2; // a FIN or an RST went by
const ST_LOCAL: u8 = 4; // this host talking to itself (loopback)

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dir {
    /// Same direction as the packet that opened the flow.
    Original,
    Reply,
}

/// One tracked flow, in the direction of the packet that opened it.
#[derive(Clone, Copy)]
struct Flow {
    src: [u8; 16],
    dst: [u8; 16],
    sport: u16,
    dport: u16,
    proto: u8,
    v6: bool,
    state: u8,
    /// Timebase tick at which the entry stops counting; 0 for a free slot.
    expires: u64,
}

// The per-entry cost Kconfig `FIREWALL_CONNTRACK_MAX` states.
const _: () = assert!(core::mem::size_of::<Flow>() == 48);

impl Flow {
    const EMPTY: Flow = Flow { src: [0; 16], dst: [0; 16], sport: 0, dport: 0, proto: 0, v6: false, state: 0, expires: 0 };

    fn live(&self, now: u64) -> bool {
        self.expires > now
    }

    /// Nobody has answered it, or it is ending: the first to go when a set is full.
    fn embryonic(&self) -> bool {
        self.state & ST_REPLIED == 0 || self.state & ST_CLOSING != 0
    }

    fn direction(&self, t: &Tuple) -> Option<Dir> {
        if self.proto != t.proto || self.v6 != t.v6 {
            None
        } else if (self.src, self.dst, self.sport, self.dport) == (t.src, t.dst, t.sport, t.dport) {
            Some(Dir::Original)
        } else if (self.src, self.dst, self.sport, self.dport) == (t.dst, t.src, t.dport, t.sport) {
            Some(Dir::Reply)
        } else {
            None
        }
    }

    /// How long the entry lasts after a packet at its current state.
    fn lifetime_ticks(&self) -> u64 {
        let secs = if self.proto != ip::IP_PROTO_TCP {
            azos_limits::FIREWALL_UDP_TIMEOUT_S as u64
        } else if self.embryonic() {
            HALF_OPEN_S
        } else {
            azos_limits::FIREWALL_TCP_TIMEOUT_S as u64
        };
        secs.saturating_mul(azos_drv_sys::timebase::TIMER_FREQ)
    }
}

struct Inner {
    rules: [FwRule; MAX_RULES],
    nrules: usize,
    /// What a packet no rule matches gets at the ingress and forward hooks.
    inbound: Verdict,
    /// Keeps the flow table's set index out of an attacker's hands.
    seed: u64,
    /// Is there a refusal a reply must be able to pass? Only then is the table
    /// kept.
    track: bool,
    flows: [Flow; CT_SLOTS],
}

impl Inner {
    const fn new() -> Self {
        Inner {
            rules: [FwRule::EMPTY; MAX_RULES],
            nrules: 0,
            inbound: Verdict::Accept,
            seed: 0,
            track: false,
            flows: [Flow::EMPTY; CT_SLOTS],
        }
    }

    /// First match wins; no match gets the default policy, under which the
    /// inbound Neighbour Discovery messages always pass (module doc).
    fn rule_verdict(&self, hook: Hook, pkt: &PacketView) -> Verdict {
        for r in &self.rules[..self.nrules] {
            if r.matches(hook, pkt) {
                return r.action;
            }
        }
        if hook == Hook::Egress || pkt.is_neighbour_discovery() { Verdict::Accept } else { self.inbound }
    }

    /// The first slot of the set both directions of the flow share.
    fn set_of(&self, t: &Tuple) -> usize {
        let (a, b) = ((t.src, t.sport), (t.dst, t.dport));
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let mut h = self.seed ^ t.proto as u64 ^ (t.v6 as u64) << 8;
        let mut mix = |w: u64| {
            h = (h ^ w).wrapping_mul(0x9E37_79B9_7F4A_7C15);
            h ^= h >> 29;
        };
        for (addr, port) in [lo, hi] {
            // An IPv4 address fills the first word, the rest are zero.
            mix(u64::from_be_bytes([addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7]]));
            if t.v6 {
                mix(u64::from_be_bytes([addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]]));
            }
            mix(port as u64);
        }
        (h >> 32) as usize % SETS * WAYS
    }

    fn find(&self, t: &Tuple, now: u64) -> Option<(usize, Dir)> {
        let base = self.set_of(t);
        (base..base + WAYS).find_map(|i| {
            let f = &self.flows[i];
            if f.live(now) { f.direction(t).map(|d| (i, d)) } else { None }
        })
    }

    /// A packet went by on flow `i`: renew it. FIN and RST start its end; the
    /// entry stays for [`HALF_OPEN_S`] so the closing exchange still passes (an
    /// RST nobody checked the sequence number of cannot kill a flow outright).
    fn renew(&mut self, i: usize, flags: u8, now: u64) {
        let f = &mut self.flows[i];
        if f.proto == ip::IP_PROTO_TCP && flags & (TCP_FIN | TCP_RST) != 0 {
            f.state |= ST_CLOSING;
        }
        f.expires = now.saturating_add(f.lifetime_ticks());
    }

    /// Track a new flow. `false`: the set holds only live answered flows.
    fn insert(&mut self, t: &Tuple, local: bool, now: u64) -> bool {
        let base = self.set_of(t);
        let mut victim: Option<usize> = None;
        for i in base..base + WAYS {
            let f = &self.flows[i];
            if !f.live(now) {
                victim = Some(i);
                break;
            }
            if f.embryonic() && victim.map_or(true, |v| f.expires < self.flows[v].expires) {
                victim = Some(i);
            }
        }
        let Some(i) = victim else { return false };
        self.flows[i] = Flow {
            src: t.src,
            dst: t.dst,
            sport: t.sport,
            dport: t.dport,
            proto: t.proto,
            v6: t.v6,
            // A host talking to itself is answered by construction: the copy of
            // the packet that comes back in at the ingress hook must pass.
            state: if local { ST_REPLIED | ST_LOCAL } else { 0 },
            expires: 0,
        };
        self.renew(i, 0, now);
        true
    }

    fn judge(&mut self, hook: Hook, pkt: &PacketView, now: u64) -> Verdict {
        let tuple = if self.track { Tuple::of(pkt) } else { None };
        let mut again = None;
        if let Some(t) = &tuple {
            if let Some((i, dir)) = self.find(t, now) {
                let f = &mut self.flows[i];
                // The peer's packets pass; ours pass once it has answered. A
                // SYN in the original direction is a retransmission or a new
                // connection on a reused tuple: the rules look at it again.
                let through = f.state & ST_LOCAL != 0
                    || dir == Dir::Reply
                    || (f.state & ST_REPLIED != 0 && t.flags & (TCP_SYN | TCP_ACK) != TCP_SYN);
                if through {
                    if dir == Dir::Reply {
                        f.state |= ST_REPLIED;
                    }
                    self.renew(i, t.flags, now);
                    return Verdict::Accept;
                }
                again = Some(i);
            }
        }
        let v = self.rule_verdict(hook, pkt);
        let Some(t) = tuple else { return v };
        if v != Verdict::Accept || !t.starts_flow() {
            return v;
        }
        if let Some(i) = again {
            self.flows[i].state = 0;
            self.renew(i, t.flags, now);
        } else if !self.insert(&t, hook == Hook::Egress && t.src == t.dst, now) {
            // Fail closed: a flow that cannot be tracked would have its answers
            // dropped, so it is not started.
            return Verdict::Drop;
        }
        v
    }
}

/// The built-in packet filter: a rule table and a bounded flow table behind one
/// lock. Compile it once with [`Firewall::load`], then install it with
/// [`set_filter`] if [`Firewall::needed`].
pub struct Firewall {
    inner: SpinLock<Inner>,
}

impl Firewall {
    pub const fn new() -> Self {
        Firewall { inner: SpinLock::new(Inner::new()) }
    }

    /// Compile `rules` (in order) and the inbound default into the table and
    /// forget every tracked flow. `Some(n)`: `n` rules stored; `None`: more
    /// than [`MAX_RULES`], nothing changed. `seed` is the flow table's hash key.
    pub fn load(&self, inbound: Verdict, rules: impl Iterator<Item = FwRule>, seed: u64) -> Option<usize> {
        let mut g = self.inner.lock();
        let mut staged = [FwRule::EMPTY; MAX_RULES];
        let mut n = 0;
        for r in rules {
            *staged.get_mut(n)? = r;
            n += 1;
        }
        g.rules = staged;
        g.nrules = n;
        g.inbound = inbound;
        g.seed = seed;
        g.flows.fill(Flow::EMPTY);
        let refuses = |r: &FwRule| r.action != Verdict::Accept;
        g.track = inbound != Verdict::Accept || g.rules[..n].iter().any(|r| refuses(r) && r.hook != Hook::Egress);
        Some(n)
    }

    /// Would this firewall ever refuse a packet? With no rule that refuses and
    /// an accepting default it would not, and installing it only costs time.
    pub fn needed(&self) -> bool {
        let g = self.inner.lock();
        g.inbound != Verdict::Accept || g.rules[..g.nrules].iter().any(|r| r.action != Verdict::Accept)
    }

    /// Flows the table holds at `now` (those not yet expired).
    pub fn tracked(&self, now: u64) -> usize {
        self.inner.lock().flows.iter().filter(|f| f.live(now)).count()
    }
}

impl PacketFilter for Firewall {
    fn check(&self, hook: Hook, pkt: &PacketView, _conn: Option<&ConnState>) -> Verdict {
        self.inner.lock().judge(hook, pkt, azos_drv_sys::timebase::now())
    }
}
