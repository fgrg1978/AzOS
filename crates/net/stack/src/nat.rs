// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! NAPT for the forwarding path of `ip.rs`: the masquerade of the LAN behind
//! the uplink, and its connection table.
//!
//! **Where it sits.** `ip::forward` calls this module, it is not a
//! `PacketFilter`: a filter answers a verdict about a packet it may not
//! change, and a translation rewrites the packet. The order is the one a
//! Linux gateway has, so a firewall row means the same thing: the filter's
//! forward hook sees the packet with the LAN's addresses on both legs (an
//! outbound packet before the source is rewritten, an answer after the
//! destination has been put back), and the translation is the last step before
//! the packet is queued on the link. [`ConnState`] is how the translation
//! tells the hook what it knows of the flow.
//!
//! **What is translated.** A packet forwarded out of the uplink from another
//! interface gets the uplink's address as source and a port from
//! `NAT_PORT_MIN..=NAT_PORT_MAX` as source port (an ICMP echo's identifier
//! stands for the port). The answer that arrives on the uplink for that port,
//! from the remote the flow was opened to, is translated back. An ICMP error
//! about a translated flow is translated back too: the outer destination, the
//! source address and port of the quoted packet, the quoted header's checksum
//! and the error's own checksum, so the LAN host recognises the packet it sent.
//! Only a TCP SYN, a UDP datagram or an ICMP echo request opens a mapping.
//! TCP, UDP and ICMP echo are the protocols with a port to translate; any other
//! is [`Refused::Unsupported`]. Nothing arriving from outside opens a mapping:
//! there is no port forwarding.
//!
//! **The table.** [`NAT_SLOTS`] entries of 24 B, 4-way set-associative, never
//! grown. A mapping is per 5-tuple (and uplink), so two flows of one LAN host
//! never share a translated port, and the answer is accepted only from the
//! remote the flow went to. The translated port is not drawn at random: it
//! is chosen congruent to the mapping's *set*, so the one table is indexed
//! from both directions. The outbound lookup hashes the 5-tuple (seed from boot
//! entropy) to a set; the inbound one takes the set from the port it arrives
//! on; each looks at four entries. A flow whose set is full of live answered
//! mappings is refused ([`Refused::TableFull`]), never the table grown; within
//! a set a new flow evicts an expired mapping, then the oldest one nobody has
//! answered (or that is closing), so a flood of SYNs cannot push out an
//! established flow.
//!
//! **Timeouts** are per protocol (`NAT_UDP_TIMEOUT_S`, `NAT_TCP_TIMEOUT_S`,
//! `NAT_TCP_TRANSIENT_S`, `NAT_ICMP_TIMEOUT_S`); every packet in either
//! direction renews the mapping, so the clock is the table's only state, there
//! is no sweeper.
//!
//! **Checksums.** The IP header's is recomputed (at most 60 bytes); the
//! transport's is updated incrementally (RFC 1624) for the words that changed,
//! so a payload is never read. A UDP checksum of 0 means "none" and stays 0.
use super::{checksum, ICMP_DEST_UNREACHABLE, ICMP_TIME_EXCEEDED, IP_PROTO_ICMP, IP_PROTO_TCP, IP_PROTO_UDP};
use crate::filter::{ConnPhase, ConnState};
use azos_sync::SpinLock;
use core::sync::atomic::{AtomicBool, Ordering};

/// Entries of one set.
const WAYS: usize = 4;
/// Mappings the table holds: Kconfig `NAT_TABLE_MAX` rounded down to a whole
/// number of sets.
pub const NAT_SLOTS: usize = azos_limits::NAT_TABLE_MAX / WAYS * WAYS;
const SETS: usize = NAT_SLOTS / WAYS;
const _: () = assert!(SETS > 0, "NAT_TABLE_MAX holds at least one set of 4");

/// The translated port range (Kconfig `NAT_PORT_MIN..=NAT_PORT_MAX`).
const PORT_MIN: u16 = azos_limits::NAT_PORT_MIN as u16;
const PORT_MAX: u16 = azos_limits::NAT_PORT_MAX as u16;
const _: () = assert!(
    azos_limits::NAT_PORT_MIN <= azos_limits::NAT_PORT_MAX && azos_limits::NAT_PORT_MAX <= 65535,
    "NAT_PORT_MIN must be at most NAT_PORT_MAX, which is at most 65535"
);
/// Ports a reply to this node's own TCP connection could arrive on: a
/// translated port must never be one of them.
const _: () = assert!(
    azos_limits::NAT_PORT_MAX < azos_limits::TCP_EPHEMERAL_PORT_MIN
        || azos_limits::NAT_PORT_MIN > azos_limits::TCP_EPHEMERAL_PORT_MAX,
    "NAT_PORT_MIN..NAT_PORT_MAX must not overlap TCP_EPHEMERAL_PORT_MIN..MAX"
);
const PORTS: usize = PORT_MAX as usize - PORT_MIN as usize + 1;
/// Ports congruent to one set: the candidates for a mapping that lives there.
const PORTS_PER_SET: usize = PORTS / SETS;
const _: () = assert!(
    PORTS_PER_SET >= WAYS,
    "NAT_PORT_MIN..NAT_PORT_MAX must hold at least 4 ports per set of NAT_TABLE_MAX/4"
);

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_PARAMETER_PROBLEM: u8 = 12;

/// Why a packet got no translation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refused {
    /// A protocol or ICMP type with no port to translate, or a header too short
    /// to hold one.
    Unsupported,
    /// A TCP segment that does not open a flow, or an ICMP error, with no mapping
    /// behind it.
    NoMapping,
    /// The packet's set holds only live answered mappings.
    TableFull,
}

// State bits of `Entry::flags`; the high nibble is the uplink's interface number.
const ST_REPLIED: u8 = 1; // the peer has answered
const ST_CLOSING: u8 = 2; // a FIN or an RST went by
const ST_MASK: u8 = 0x0F;

/// One mapping, in the direction that opened it. For an ICMP echo the "ports"
/// are the identifier (`in_port` as the host sent it, `wan_port` as the remote
/// sees it) and `remote_port` is 0.
#[derive(Clone, Copy)]
struct Entry {
    inside: u32,
    remote: u32,
    in_port: u16,
    remote_port: u16,
    wan_port: u16,
    proto: u8,
    flags: u8,
    /// Timebase tick at which the mapping stops counting; 0 for a free slot.
    expires: u64,
}

impl Entry {
    const EMPTY: Entry = Entry {
        inside: 0, remote: 0, in_port: 0, remote_port: 0, wan_port: 0, proto: 0, flags: 0, expires: 0,
    };

    fn live(&self, now: u64) -> bool {
        self.expires > now
    }

    fn wan_if(&self) -> u8 {
        self.flags >> 4
    }

    fn replied(&self) -> bool {
        self.flags & ST_REPLIED != 0
    }

    /// Nobody has answered it, or it is ending: the first to go when a set is full.
    fn embryonic(&self) -> bool {
        !self.replied() || self.flags & ST_CLOSING != 0
    }

    fn lifetime_ticks(&self) -> u64 {
        let secs = match self.proto {
            IP_PROTO_UDP => azos_limits::NAT_UDP_TIMEOUT_S,
            IP_PROTO_ICMP => azos_limits::NAT_ICMP_TIMEOUT_S,
            _ if self.embryonic() => azos_limits::NAT_TCP_TRANSIENT_S,
            _ => azos_limits::NAT_TCP_TIMEOUT_S,
        };
        (secs as u64).saturating_mul(azos_drv_sys::timebase::TIMER_FREQ)
    }
}

/// What an outbound packet says: who is talking to whom.
#[derive(Clone, Copy)]
struct Out {
    proto: u8,
    inside: u32,
    in_port: u16,
    remote: u32,
    remote_port: u16,
    /// The TCP flag byte; 0 for the others.
    flags: u8,
}

impl Out {
    /// May this packet open a mapping: any UDP datagram or echo request, a TCP
    /// SYN without ACK.
    fn starts_flow(&self) -> bool {
        self.proto != IP_PROTO_TCP || self.flags & (TCP_SYN | TCP_ACK) == TCP_SYN
    }
}

/// What an inbound packet says: which mapping it would belong to.
#[derive(Clone, Copy)]
struct In {
    proto: u8,
    wan_port: u16,
    remote: u32,
    remote_port: u16,
    flags: u8,
    /// An ICMP error about a flow of ours (the key is the quoted packet's).
    error: bool,
    /// The quoted packet's header length, as [`quoted`] checked it (`0` unless
    /// `error`). [`rewrite_error`] uses this value instead of re-reading the
    /// byte, so the length it indexes with is the length that was proven to
    /// fit.
    eihl: usize,
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// The key of an outbound packet, or why it has none. `pkt` is a whole IPv4
/// packet with its header length `ihl`.
fn parse_out(pkt: &[u8], ihl: usize) -> Result<Out, Refused> {
    let l4 = pkt.get(ihl..).ok_or(Refused::Unsupported)?;
    let (inside, remote) = (be32(&pkt[12..16]), be32(&pkt[16..20]));
    let (in_port, remote_port, flags) = match pkt[9] {
        IP_PROTO_TCP if l4.len() >= 20 => (be16(&l4[0..2]), be16(&l4[2..4]), l4[13]),
        IP_PROTO_UDP if l4.len() >= 8 => (be16(&l4[0..2]), be16(&l4[2..4]), 0),
        IP_PROTO_ICMP if l4.len() >= 8 && l4[0] == ICMP_ECHO_REQUEST && l4[1] == 0 => {
            (be16(&l4[4..6]), 0, 0)
        }
        // An ICMP error (or anything else) from the LAN with no flow of ours behind it.
        IP_PROTO_ICMP if l4.len() >= 8 && l4[0] != ICMP_ECHO_REQUEST => return Err(Refused::NoMapping),
        _ => return Err(Refused::Unsupported),
    };
    Ok(Out { proto: pkt[9], inside, in_port, remote, remote_port, flags })
}

/// The key of an inbound packet, or `None` when it cannot belong to a mapping.
fn parse_in(pkt: &[u8], ihl: usize) -> Option<In> {
    let l4 = pkt.get(ihl..)?;
    let src = be32(&pkt[12..16]);
    let direct = |proto, wan_port, remote_port, flags| In { proto, wan_port, remote: src, remote_port, flags, error: false, eihl: 0 };
    match pkt[9] {
        IP_PROTO_TCP if l4.len() >= 20 => Some(direct(IP_PROTO_TCP, be16(&l4[2..4]), be16(&l4[0..2]), l4[13])),
        IP_PROTO_UDP if l4.len() >= 8 => Some(direct(IP_PROTO_UDP, be16(&l4[2..4]), be16(&l4[0..2]), 0)),
        IP_PROTO_ICMP if l4.len() >= 8 => match l4[0] {
            ICMP_ECHO_REPLY if l4[1] == 0 => Some(direct(IP_PROTO_ICMP, be16(&l4[4..6]), 0, 0)),
            ICMP_DEST_UNREACHABLE | ICMP_TIME_EXCEEDED | ICMP_PARAMETER_PROBLEM => {
                let (e, eihl) = quoted(l4, &pkt[16..20])?;
                let el4 = &e[eihl..];
                let (proto, wan_port, remote_port) = match e[9] {
                    IP_PROTO_TCP | IP_PROTO_UDP => (e[9], be16(&el4[0..2]), be16(&el4[2..4])),
                    IP_PROTO_ICMP if el4[0] == ICMP_ECHO_REQUEST => (IP_PROTO_ICMP, be16(&el4[4..6]), 0),
                    _ => return None,
                };
                Some(In { proto, wan_port, remote: be32(&e[16..20]), remote_port, flags: 0, error: true, eihl })
            }
            _ => None,
        },
        _ => None,
    }
}

/// The packet an ICMP error quotes and its header length, when it is an IPv4
/// packet sent from `wan_ip` that carries at least eight bytes behind its header
/// (RFC 792: the header and the first eight bytes of the datagram).
fn quoted<'a>(icmp: &'a [u8], wan_ip: &[u8]) -> Option<(&'a [u8], usize)> {
    let e = icmp.get(8..)?;
    if e.len() < 20 || e[0] >> 4 != 4 {
        return None;
    }
    let eihl = (e[0] & 0x0F) as usize * 4;
    if eihl < 20 || e.len() < eihl + 8 || &e[12..16] != wan_ip {
        return None;
    }
    Some((e, eihl))
}

struct Inner {
    /// Keeps the table's set index out of a LAN host's hands; drawn on first use.
    seed: u64,
    /// Rotates the port a set hands out, so a freed port is not the next one.
    cursor: u32,
    ents: [Entry; NAT_SLOTS],
}

impl Inner {
    const fn new() -> Self {
        Inner { seed: 0, cursor: 0, ents: [Entry::EMPTY; NAT_SLOTS] }
    }

    fn seed_once(&mut self) {
        if self.seed == 0 {
            let mut key = [0u8; 8];
            if !crate::net_random_fill(&mut key) {
                key = azos_drv_sys::timebase::now().to_le_bytes();
            }
            self.seed = u64::from_le_bytes(key) | 1;
        }
    }

    /// The set an outbound 5-tuple hashes to.
    fn out_set(&self, k: &Out, wan_if: u8) -> usize {
        let mut h = self.seed ^ (k.proto as u64) << 8 ^ wan_if as u64;
        for w in [(k.inside as u64) << 16 | k.in_port as u64, (k.remote as u64) << 16 | k.remote_port as u64] {
            h = (h ^ w).wrapping_mul(0x9E37_79B9_7F4A_7C15);
            h ^= h >> 29;
        }
        (h >> 32) as usize % SETS
    }

    fn find_out(&self, k: &Out, wan_if: u8, now: u64) -> Option<usize> {
        let base = self.out_set(k, wan_if) * WAYS;
        (base..base + WAYS).find(|&i| {
            let e = &self.ents[i];
            e.live(now)
                && e.proto == k.proto
                && e.wan_if() == wan_if
                && (e.inside, e.in_port, e.remote, e.remote_port) == (k.inside, k.in_port, k.remote, k.remote_port)
        })
    }

    fn find_in(&self, k: &In, wan_if: u8, now: u64) -> Option<usize> {
        if !(PORT_MIN..=PORT_MAX).contains(&k.wan_port) {
            return None;
        }
        let base = (k.wan_port - PORT_MIN) as usize % SETS * WAYS;
        (base..base + WAYS).find(|&i| {
            let e = &self.ents[i];
            e.live(now)
                && e.proto == k.proto
                && e.wan_if() == wan_if
                && (e.wan_port, e.remote, e.remote_port) == (k.wan_port, k.remote, k.remote_port)
        })
    }

    /// A packet went by on mapping `i`: renew it. FIN and RST start its end.
    fn renew(&mut self, i: usize, tcp_flags: u8, now: u64) {
        let e = &mut self.ents[i];
        if e.proto == IP_PROTO_TCP && tcp_flags & (TCP_FIN | TCP_RST) != 0 {
            e.flags |= ST_CLOSING;
        }
        e.expires = now.saturating_add(e.lifetime_ticks());
    }

    /// Map a new flow. `None`: the set holds only live answered mappings.
    fn insert(&mut self, k: &Out, wan_if: u8, now: u64) -> Option<usize> {
        let set = self.out_set(k, wan_if);
        let base = set * WAYS;
        let mut victim: Option<usize> = None;
        for i in base..base + WAYS {
            let e = &self.ents[i];
            if !e.live(now) {
                victim = Some(i);
                break;
            }
            if e.embryonic() && victim.map_or(true, |v| e.expires < self.ents[v].expires) {
                victim = Some(i);
            }
        }
        let v = victim?;
        // A port congruent to the set (so both lookups find the entry in it)
        // that no other live mapping of the protocol in the set holds. The set
        // holds at most three others and PORTS_PER_SET is at least 4, so one
        // is always there.
        let mut wan_port = None;
        for j in 0..PORTS_PER_SET {
            let n = (self.cursor as usize + j) % PORTS_PER_SET;
            let p = (PORT_MIN as usize + set + n * SETS) as u16;
            let taken = (base..base + WAYS).any(|i| {
                let e = &self.ents[i];
                i != v && e.live(now) && e.proto == k.proto && e.wan_port == p
            });
            if !taken {
                wan_port = Some(p);
                self.cursor = self.cursor.wrapping_add(n as u32 + 1);
                break;
            }
        }
        self.ents[v] = Entry {
            inside: k.inside,
            remote: k.remote,
            in_port: k.in_port,
            remote_port: k.remote_port,
            wan_port: wan_port?,
            proto: k.proto,
            flags: wan_if << 4,
            expires: 0,
        };
        self.renew(v, k.flags, now);
        Some(v)
    }
}

static NAT: SpinLock<Inner> = SpinLock::new(Inner::new());
static MASQUERADE: AtomicBool = AtomicBool::new(azos_limits::NET_NAT);

/// Is the masquerade on (Kconfig `NET_NAT`)? One relaxed load.
#[inline(always)]
pub fn masquerading() -> bool {
    MASQUERADE.load(Ordering::Relaxed)
}

/// Test-only: switch the masquerade and forget every mapping and the seed.
pub fn reset_for_test(on: bool) {
    MASQUERADE.store(on, Ordering::Relaxed);
    let mut g = NAT.lock();
    g.seed = 0;
    g.cursor = 0;
    g.ents.fill(Entry::EMPTY);
}

/// Mappings the table holds at `now` (those not yet expired).
pub fn tracked(now: u64) -> usize {
    NAT.lock().ents.iter().filter(|e| e.live(now)).count()
}

// ── Checksums ────────────────────────────────────────────────────────────────

/// Recompute the header checksum of the IPv4 packet `pkt`.
fn fix_ip_checksum(pkt: &mut [u8], ihl: usize) {
    pkt[10] = 0;
    pkt[11] = 0;
    let c = checksum(&pkt[..ihl]).to_be_bytes();
    pkt[10] = c[0];
    pkt[11] = c[1];
}

/// RFC 1624 eqn. 3: the checksum at `b[at..at + 2]` after the 16-bit words of
/// `old` were replaced by those of `new`.
fn adjust(b: &mut [u8], at: usize, old: &[u8], new: &[u8]) {
    let mut c = be16(&b[at..]);
    for (o, n) in old.chunks_exact(2).zip(new.chunks_exact(2)) {
        let mut s = (!c) as u32 + (!be16(o)) as u32 + be16(n) as u32;
        s = (s & 0xFFFF) + (s >> 16);
        s = (s & 0xFFFF) + (s >> 16);
        c = !(s as u16);
    }
    b[at..at + 2].copy_from_slice(&c.to_be_bytes());
}

/// Put `addr` and `port` in place of the source (`src`) or destination of a TCP
/// or UDP packet and bring both checksums along.
fn rewrite_l4(pkt: &mut [u8], ihl: usize, src: bool, addr: [u8; 4], port: u16) {
    let proto = pkt[9];
    let (ao, po) = if src { (12, ihl) } else { (16, ihl + 2) };
    let co = ihl + if proto == IP_PROTO_TCP { 16 } else { 6 };
    let old_addr = [pkt[ao], pkt[ao + 1], pkt[ao + 2], pkt[ao + 3]];
    let old_port = [pkt[po], pkt[po + 1]];
    let new_port = port.to_be_bytes();
    pkt[ao..ao + 4].copy_from_slice(&addr);
    pkt[po..po + 2].copy_from_slice(&new_port);
    // A UDP checksum of 0 says there is none, and stays that way.
    if proto == IP_PROTO_TCP || be16(&pkt[co..]) != 0 {
        adjust(pkt, co, &old_addr, &addr);
        adjust(pkt, co, &old_port, &new_port);
        if proto == IP_PROTO_UDP && be16(&pkt[co..]) == 0 {
            pkt[co] = 0xFF;
            pkt[co + 1] = 0xFF;
        }
    }
    fix_ip_checksum(pkt, ihl);
}

/// Put `id` in the identifier of the ICMP echo message at `pkt[at..]`.
fn rewrite_echo_id(pkt: &mut [u8], at: usize, id: u16) {
    let old = [pkt[at + 4], pkt[at + 5]];
    let new = id.to_be_bytes();
    pkt[at + 4..at + 6].copy_from_slice(&new);
    adjust(pkt, at + 2, &old, &new);
}

// ── Translation ──────────────────────────────────────────────────────────────

/// What the filter's forward hook would be told of an outbound packet: whether
/// its flow is one the table has seen answered. Changes nothing.
pub fn phase_out(pkt: &[u8], ihl: usize, wan_if: u8, now: u64) -> ConnPhase {
    let Ok(k) = parse_out(pkt, ihl) else { return ConnPhase::New };
    let g = NAT.lock();
    match g.find_out(&k, wan_if, now) {
        Some(i) if g.ents[i].replied() => ConnPhase::Established,
        _ => ConnPhase::New,
    }
}

/// Translate an outbound packet in place: `pkt` is a whole IPv4 packet being
/// forwarded out of the uplink `wan_if` whose address is `wan_ip`. Opens or
/// renews the mapping and puts the uplink's address and the mapped port in
/// place of the sender's.
pub fn outbound(pkt: &mut [u8], ihl: usize, wan_if: u8, wan_ip: [u8; 4], now: u64) -> Result<ConnState, Refused> {
    let k = parse_out(pkt, ihl)?;
    let mut g = NAT.lock();
    g.seed_once();
    let (i, phase) = match g.find_out(&k, wan_if, now) {
        Some(i) => {
            // A SYN on the tuple of a flow that was closing is a new connection.
            if k.proto == IP_PROTO_TCP && k.flags & (TCP_SYN | TCP_ACK) == TCP_SYN && g.ents[i].flags & ST_CLOSING != 0 {
                g.ents[i].flags &= !ST_MASK;
            }
            let phase = if g.ents[i].replied() { ConnPhase::Established } else { ConnPhase::New };
            g.renew(i, k.flags, now);
            (i, phase)
        }
        None if k.starts_flow() => (g.insert(&k, wan_if, now).ok_or(Refused::TableFull)?, ConnPhase::New),
        None => return Err(Refused::NoMapping),
    };
    let wan_port = g.ents[i].wan_port;
    drop(g);
    if k.proto == IP_PROTO_ICMP {
        pkt[12..16].copy_from_slice(&wan_ip);
        fix_ip_checksum(pkt, ihl);
        rewrite_echo_id(pkt, ihl, wan_port);
    } else {
        rewrite_l4(pkt, ihl, true, wan_ip, wan_port);
    }
    Ok(ConnState { phase, reply: false })
}

/// Does an inbound packet on the uplink `wan_if` belong to a mapping? Changes
/// nothing: it decides whether the packet is copied for [`inbound`] or goes to
/// the local stack.
pub fn matches_inbound(pkt: &[u8], ihl: usize, wan_if: u8, now: u64) -> bool {
    match parse_in(pkt, ihl) {
        Some(k) => NAT.lock().find_in(&k, wan_if, now).is_some(),
        None => false,
    }
}

/// Translate an inbound packet in place, the answer to a mapped flow (or an ICMP
/// error about one): put the LAN host's address and port back. `None`: no
/// mapping, `pkt` is untouched.
pub fn inbound(pkt: &mut [u8], ihl: usize, wan_if: u8, now: u64) -> Option<ConnState> {
    let k = parse_in(pkt, ihl)?;
    let mut g = NAT.lock();
    let i = g.find_in(&k, wan_if, now)?;
    if !k.error {
        g.ents[i].flags |= ST_REPLIED;
        g.renew(i, k.flags, now);
    }
    let Entry { inside, in_port, .. } = g.ents[i];
    drop(g);
    let inside = inside.to_be_bytes();
    if k.error {
        rewrite_error(pkt, ihl, k.eihl, k.proto, inside, in_port);
        return Some(ConnState { phase: ConnPhase::Related, reply: true });
    }
    if k.proto == IP_PROTO_ICMP {
        pkt[16..20].copy_from_slice(&inside);
        fix_ip_checksum(pkt, ihl);
        rewrite_echo_id(pkt, ihl, in_port);
    } else {
        rewrite_l4(pkt, ihl, false, inside, in_port);
    }
    Some(ConnState { phase: ConnPhase::Established, reply: true })
}

/// Translate an ICMP error back: the outer destination, the quoted packet's
/// source address and port (or echo identifier), the quoted header's checksum
/// and, where the quote reaches it, the quoted transport checksum; then the
/// error's own checksum.
///
/// `eihl` and `eproto` are the quoted header's length and protocol as
/// [`parse_in`] read and [`quoted`] bounded them (`pkt` holds at least
/// `ihl + 8 + eihl + 8` bytes): neither is read again from `pkt`.
fn rewrite_error(pkt: &mut [u8], ihl: usize, eihl: usize, eproto: u8, inside: [u8; 4], in_port: u16) {
    pkt[16..20].copy_from_slice(&inside);
    fix_ip_checksum(pkt, ihl);
    let eo = ihl + 8;
    let old_addr = [pkt[eo + 12], pkt[eo + 13], pkt[eo + 14], pkt[eo + 15]];
    pkt[eo + 12..eo + 16].copy_from_slice(&inside);
    fix_ip_checksum(&mut pkt[eo..], eihl);
    let lo = eo + eihl;
    let new_port = in_port.to_be_bytes();
    match eproto {
        IP_PROTO_TCP | IP_PROTO_UDP => {
            let old_port = [pkt[lo], pkt[lo + 1]];
            pkt[lo..lo + 2].copy_from_slice(&new_port);
            // The quote is at least eight bytes of the transport header: the
            // UDP checksum is in it (unless it is 0, "none"), the TCP one is
            // only there if the quote is longer.
            let co = lo + if eproto == IP_PROTO_TCP { 16 } else { 6 };
            if pkt.len() >= co + 2 && (eproto == IP_PROTO_TCP || be16(&pkt[co..]) != 0) {
                adjust(pkt, co, &old_addr, &inside);
                adjust(pkt, co, &old_port, &new_port);
            }
        }
        _ => rewrite_echo_id(pkt, lo, in_port),
    }
    pkt[ihl + 2] = 0;
    pkt[ihl + 3] = 0;
    let c = checksum(&pkt[ihl..]).to_be_bytes();
    pkt[ihl + 2] = c[0];
    pkt[ihl + 3] = c[1];
}
