// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The packet-filter seam of the IPv4 path.
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
//! | `Reject` | discarded, ICMP "administratively prohibited" to the sender | discarded, `send` says -1 |
//!
//! A sender does not need to be told it was dropped (`Drop`: the packet is lost
//! on the wire, TCP retransmits); a local caller whose own datagram is refused
//! is told (`Reject`): there is no peer to answer, so the error return is the
//! reply. ICMP is never sent about a broadcast or multicast datagram, about an
//! ICMP datagram, or to a source that is not a single host (RFC 1122 §3.2.2),
//! and the replies are themselves rate-limited so a flood of refused packets
//! cannot be turned into a flood of replies.
//!
//! **Refusals leave a record.** Every `Drop` and `Reject` bumps a counter and
//! is offered to [`azos_decision`] as [`Rule::PacketRefused`]. A refusal record
//! reaches the durable sink unconditionally, which for a packet flood is the
//! wrong thing, so the stack rate-limits before it records: a token bucket of
//! [`RECORDS_PER_SEC`] with a burst of [`RECORD_BURST`]; the refusals it holds
//! back are counted, and the count rides in the third number of the next record
//! written, the way the capability-denial bucket reports its drops.
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
use super::ip;
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

/// A read-only view of one IPv4 packet: the header fields a rule matches on
/// and the bytes behind them. Built over a packet the stack has already
/// validated (length, header checksum) or built itself.
#[derive(Clone, Copy, Debug)]
pub struct PacketView<'a> {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub proto: u8,
    /// The whole IP packet, header first, exactly `total_length` bytes.
    pub packet: &'a [u8],
    /// Header length in bytes (options included).
    pub ihl: usize,
}

impl<'a> PacketView<'a> {
    /// A view over `packet`, or `None` when it is not a whole IPv4 header.
    pub fn parse(packet: &'a [u8]) -> Option<Self> {
        if packet.len() < ip::IP_HDR_MIN || packet[0] >> 4 != 4 {
            return None;
        }
        let ihl = (packet[0] & 0x0F) as usize * 4;
        if ihl < ip::IP_HDR_MIN || packet.len() < ihl {
            return None;
        }
        Some(PacketView {
            src: [packet[12], packet[13], packet[14], packet[15]],
            dst: [packet[16], packet[17], packet[18], packet[19]],
            proto: packet[9],
            packet,
            ihl,
        })
    }

    /// The transport segment: everything after the IP header.
    pub fn payload(&self) -> &'a [u8] {
        &self.packet[self.ihl..]
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
    // n[0]: src << 32 | dst. n[1]: hook, verdict, protocol, ports.
    // n[2]: refusals held back by the rate limit since the previous record.
    azos_decision::record(
        Rule::PacketRefused,
        Decided::Refuse,
        u32::from_be_bytes(pkt.src),
        [
            (u32::from_be_bytes(pkt.src) as u64) << 32 | u32::from_be_bytes(pkt.dst) as u64,
            (hook as u64) << 56 | (v as u64) << 48 | (pkt.proto as u64) << 40 | sport << 16 | dport,
            owed,
        ],
    );
}

/// Judge a packet addressed to this host. `true`: let it through. Otherwise it
/// has been discarded here (and answered, for `Reject`).
#[inline(always)]
pub fn ingress(packet: &[u8], our_mac: &[u8; 6], our_ip: &[u8; 4]) -> bool {
    if !active() {
        return true;
    }
    receive(Hook::Ingress, packet, None, our_mac, our_ip)
}

/// Judge a packet this host would route. Same contract as [`ingress`]; `conn`
/// is the tracker's view of the flow, if there is a tracker.
#[inline(always)]
pub fn forward(packet: &[u8], conn: Option<&ConnState>, our_mac: &[u8; 6], our_ip: &[u8; 4]) -> bool {
    if !active() {
        return true;
    }
    receive(Hook::Forward, packet, conn, our_mac, our_ip)
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
        reject(&view, our_mac, our_ip);
    }
}

/// Judge a packet this host built. The caller acts on the verdict: nothing for
/// `Accept`, a discard for the others (see the table in the module doc).
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

#[inline(never)]
fn receive(hook: Hook, packet: &[u8], conn: Option<&ConnState>, our_mac: &[u8; 6], our_ip: &[u8; 4]) -> bool {
    let Some(view) = PacketView::parse(packet) else { return true };
    match ask(hook, &view, conn) {
        Verdict::Accept => true,
        Verdict::Drop => false,
        Verdict::Reject => {
            reject(&view, our_mac, our_ip);
            false
        }
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
    let now = azos_drv_sys::timebase::now();
    if REPLY_BUCKET.lock().admit(now, REPLIES_PER_SEC, REPLY_BURST).is_none() {
        REPLY_HELD.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let quoted = (view.ihl + 8).min(view.packet.len());
    let mut icmp = [0u8; 8 + ip::IP_HDR_MIN + ip::IP_OPTS_MAX + 8];
    icmp[0] = ip::ICMP_DEST_UNREACHABLE;
    icmp[1] = ICMP_ADMIN_PROHIBITED;
    icmp[8..8 + quoted].copy_from_slice(&view.packet[..quoted]);
    let len = 8 + quoted;
    let cs = ip::checksum(&icmp[..len]).to_be_bytes();
    icmp[2] = cs[0];
    icmp[3] = cs[1];
    REPLIED.fetch_add(1, Ordering::Relaxed);
    let _ = ip::send(our_mac, our_ip, &view.src, ip::IP_PROTO_ICMP, &icmp[..len]);
}

/// Code 13 of Destination Unreachable.
const ICMP_ADMIN_PROHIBITED: u8 = 13;

/// RFC 1122 §3.2.2: no ICMP error about an ICMP datagram, a broadcast or
/// multicast datagram, or one whose source is not a single host.
fn may_answer(view: &PacketView) -> bool {
    if view.proto == ip::IP_PROTO_ICMP {
        return false;
    }
    let single_host = |a: &[u8; 4]| {
        *a != [0; 4] && *a != [0xff; 4] && a[0] != 127 && !super::igmp::is_multicast(a)
    };
    if !single_host(&view.src) || !single_host(&view.dst) {
        return false;
    }
    let (ip, mask) = (super::net_get_ip(), super::net_get_mask());
    let directed_broadcast = (0..4).all(|i| view.dst[i] == (ip[i] & mask[i]) | !mask[i]);
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
    /// an IPv4 packet never carries).
    pub proto: u8,
    /// First and last destination port matched (TCP and UDP only); `port_lo`
    /// 0 matches any packet.
    pub port_lo: u16,
    pub port_hi: u16,
    /// The remote address prefix, host order: the source of an ingress packet,
    /// the destination of an egress or forwarded one. `net_len` 0 matches any.
    pub net: u32,
    pub net_len: u8,
    pub action: Verdict,
}

impl FwRule {
    const EMPTY: FwRule = FwRule {
        hook: Hook::Ingress,
        proto: 0,
        port_lo: 0,
        port_hi: 0,
        net: 0,
        net_len: 0,
        action: Verdict::Accept,
    };

    fn matches(&self, hook: Hook, pkt: &PacketView) -> bool {
        if self.hook != hook || (self.proto != 0 && self.proto != pkt.proto) {
            return false;
        }
        if self.port_lo != 0 && !pkt.dst_port().is_some_and(|p| (self.port_lo..=self.port_hi).contains(&p)) {
            return false;
        }
        if self.net_len == 0 {
            return true;
        }
        let remote = u32::from_be_bytes(if hook == Hook::Ingress { pkt.src } else { pkt.dst });
        let mask = u32::MAX << (32 - self.net_len.min(32) as u32);
        remote & mask == self.net & mask
    }
}

/// The 5-tuple of a TCP or UDP packet, and its TCP flags (0 for UDP).
#[derive(Clone, Copy)]
struct Tuple {
    src: u32,
    dst: u32,
    sport: u16,
    dport: u16,
    proto: u8,
    flags: u8,
}

impl Tuple {
    /// `None` for anything that is not a TCP or UDP packet with a whole header
    /// prefix: those are judged by the rules alone.
    fn of(pkt: &PacketView) -> Option<Self> {
        let (sport, dport) = (pkt.src_port()?, pkt.dst_port()?);
        let flags = if pkt.proto == ip::IP_PROTO_TCP { pkt.tcp_flags()? } else { 0 };
        Some(Tuple {
            src: u32::from_be_bytes(pkt.src),
            dst: u32::from_be_bytes(pkt.dst),
            sport,
            dport,
            proto: pkt.proto,
            flags,
        })
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
    src: u32,
    dst: u32,
    sport: u16,
    dport: u16,
    proto: u8,
    state: u8,
    /// Timebase tick at which the entry stops counting; 0 for a free slot.
    expires: u64,
}

impl Flow {
    const EMPTY: Flow = Flow { src: 0, dst: 0, sport: 0, dport: 0, proto: 0, state: 0, expires: 0 };

    fn live(&self, now: u64) -> bool {
        self.expires > now
    }

    /// Nobody has answered it, or it is ending: the first to go when a set is full.
    fn embryonic(&self) -> bool {
        self.state & ST_REPLIED == 0 || self.state & ST_CLOSING != 0
    }

    fn direction(&self, t: &Tuple) -> Option<Dir> {
        if self.proto != t.proto {
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

    /// First match wins; no match gets the default policy.
    fn rule_verdict(&self, hook: Hook, pkt: &PacketView) -> Verdict {
        for r in &self.rules[..self.nrules] {
            if r.matches(hook, pkt) {
                return r.action;
            }
        }
        if hook == Hook::Egress { Verdict::Accept } else { self.inbound }
    }

    /// The first slot of the set both directions of the flow share.
    fn set_of(&self, t: &Tuple) -> usize {
        let a = (t.src as u64) << 16 | t.sport as u64;
        let b = (t.dst as u64) << 16 | t.dport as u64;
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let mut h = self.seed ^ t.proto as u64;
        for w in [lo, hi] {
            h = (h ^ w).wrapping_mul(0x9E37_79B9_7F4A_7C15);
            h ^= h >> 29;
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
