// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// UDP layer — port of net/udp.c
///
/// Simple UDP send/receive with 8 bound ports.
/// Ring-buffer per socket (4 packets, one full-MTU datagram each).

use core::sync::atomic::{AtomicU32, Ordering};

use azos_sync::SpinLock;
use super::ip;

pub const UDP_MAX_SOCKETS: usize = 8;
/// Kconfig `UDP_RX_SLOTS` (default 4; a power of two, asserted below and
/// in crates/core/limits/build.rs).
const UDP_RX_SLOTS: usize = azos_limits::UDP_RX_SLOTS;

/// Maximum UDP payload including header (MTU minus IP header).
const UDP_MAX_DGRAM: usize = ip::ETH_MTU - ip::IP_HDR_MIN;

/// Largest payload a receive slot holds: a full-MTU datagram.
///
/// Derived, not chosen. This used to be a bare 512, and it was the only
/// place on the receive path that was not sized for a real datagram:
/// `dhcp.rs` reserves `ETH_MTU`, and `tftp/src/client.rs` reserves its own
/// 516-byte DATA-sized buffer (smaller than this slot, which still has to
/// hold a full-MTU datagram for everything else). The 512-byte mismatch
/// silently truncated every datagram above it and reported the short read
/// as a complete one, which broke TFTP at its default 512-byte block size
/// (4 bytes of TFTP header push the datagram to 516) and would corrupt
/// option parsing on any DHCP reply carrying a long option list.
const UDP_RX_PKT_MAX: usize = UDP_MAX_DGRAM - UDP_HDR_SIZE;

#[repr(C, packed)]
struct UdpHdr {
    src_port: [u8; 2],
    dst_port: [u8; 2],
    length:   [u8; 2],
    checksum: [u8; 2],
}

const UDP_HDR_SIZE: usize = core::mem::size_of::<UdpHdr>();

// ── Receive-path drop counters ───────────────────────────────────────────────
//
// The rule every mature stack follows on the receive path is one rule, applied
// at two different layers: never hand a caller a partial datagram while
// claiming it is whole.
//
//   - At queue time (`push`) that means never truncating. A datagram that does
//     not fit is dropped entire and counted. Linux does exactly this on
//     `sk_rcvbuf` overflow — `UDP_MIB_RCVBUFERRORS`, surfaced by `netstat -su`
//     as "receive buffer errors".
//   - At delivery time (`pop`) POSIX does allow truncating to the caller's
//     buffer and discarding the rest, but it signals it: `MSG_TRUNC` in
//     `msg_flags`. We do not have that flag yet, so we count instead — see the
//     note on `pop`.
//
// A silent loss the operator cannot see is the same defect either way. These
// counters are the visibility half; the drop is the correctness half.

/// Datagrams refused at queue time for exceeding a receive slot.
static RX_OVERSIZE_DROPS: AtomicU32 = AtomicU32::new(0);

/// Datagrams evicted at queue time because the socket's ring was full.
///
/// "Evicted" is load-bearing: this counts the OLDEST already-queued datagram
/// being pushed out to make room, not the new arrival being refused. Owner
/// decision (2026-09-05, see the eviction site in `UdpRxBuf::push`): head-drop,
/// not tail-drop. The count means the same thing either policy would give —
/// exactly one datagram lost per full-ring event — so nothing here needed to
/// change when the policy was settled; only which datagram is the one lost
/// differs, and that is not observable from the counter alone.
static RX_RING_FULL_DROPS: AtomicU32 = AtomicU32::new(0);

/// Deliveries where the caller's buffer was smaller than the datagram, so the
/// tail was discarded.
static RX_TRUNCATED_DELIVERIES: AtomicU32 = AtomicU32::new(0);

/// Receive-path drop counters: `(oversize, ring_full, truncated)`.
///
/// Monotonic and never reset, so a caller comparing them must take a snapshot
/// and assert on the delta, not on an absolute value.
pub fn rx_drop_stats() -> (u32, u32, u32) {
    (
        RX_OVERSIZE_DROPS.load(Ordering::Relaxed),
        RX_RING_FULL_DROPS.load(Ordering::Relaxed),
        RX_TRUNCATED_DELIVERIES.load(Ordering::Relaxed),
    )
}

// ── Per-packet receive slot ──────────────────────────────────────────────────

struct UdpRxPkt {
    data:     [u8; UDP_RX_PKT_MAX],
    len:      usize,
    src_ip:   [u8; 4],
    src_port: u16,
}

impl UdpRxPkt {
    const fn new() -> Self {
        UdpRxPkt { data: [0u8; UDP_RX_PKT_MAX], len: 0, src_ip: [0; 4], src_port: 0 }
    }
}

// ── Ring buffer for received packets ─────────────────────────────────────────

// Deliberately NOT `Copy`. A slot is a full MTU, so a ring is ~6 KiB and a
// socket a little more; a secondary hart runs on a 16 KiB stack. Moving one by
// value would be a third of that stack, so the absence of the derive is what
// makes such a move a compile error instead of a stack overflow found on
// hardware.
struct UdpRxBuf {
    pkts: [UdpRxPkt; UDP_RX_SLOTS],
    head: usize,   // next slot to read
    tail: usize,   // next slot to write
    count: usize,
}

impl UdpRxBuf {
    const fn new() -> Self {
        UdpRxBuf {
            pkts: [const { UdpRxPkt::new() }; UDP_RX_SLOTS],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Reset the ring without touching the payload storage.
    ///
    /// Zeroing the slots would memset ~6 KiB on every `bind`, and building a
    /// fresh `UdpRxBuf` to assign over this one would put that much on the
    /// stack. Neither buys anything: `pop` returns early while `count` is 0,
    /// and it never reads past `len`, which only `push` writes. Stale bytes are
    /// therefore unreachable, not merely unlikely to be read.
    fn clear(&mut self) {
        self.head  = 0;
        self.tail  = 0;
        self.count = 0;
    }

    fn push(&mut self, src_ip: [u8; 4], src_port: u16, payload: &[u8]) {
        // Size first, eviction second. The other order drops a datagram we
        // already accepted in order to make room for one we are about to
        // refuse — paying for the refusal with somebody else's data.
        if payload.len() > UDP_RX_PKT_MAX {
            RX_OVERSIZE_DROPS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.count >= UDP_RX_SLOTS {
            // Head-drop. Decided (owner, 2026-09-05): evict the OLDEST
            // datagram already queued to make room for the one that just
            // arrived, not the other way around.
            //
            // This ring carries sensor telemetry. An IMU reading from 200 ms
            // ago is worth nothing next to the one that just arrived on the
            // wire, while a consumer that is momentarily behind must not be
            // handed that stale reading as if it were current — the value is
            // individually plausible, so nothing downstream, least of all a
            // safety envelope built on top of it, can tell it is stale.
            // Tail-drop (refuse the new arrival, keep what is already queued)
            // is what Linux does, and it is the right choice for a
            // general-purpose socket that might be carrying a command instead
            // of a sample — there, losing the reply you are waiting for is
            // worse than losing a stale one. This is not that socket.
            //
            // The trade-off accepted here, spelled out rather than left
            // implicit: under sustained overflow the datagrams that survive
            // are no longer a contiguous prefix of what arrived. They become
            // a sliding window of the newest four, with a gap wherever an
            // older one was evicted mid-stream. A consumer that assumes
            // "if I see datagram N, I must also have seen N-1" no longer gets
            // that guarantee once the ring has overflowed even once. Ordering
            // *among* the survivors is still preserved (oldest of what
            // remains is still popped first); what is given up is
            // completeness, not order.
            //
            // Either policy loses exactly one datagram here, and a silent
            // eviction would be worse than either — so it is still counted.
            RX_RING_FULL_DROPS.fetch_add(1, Ordering::Relaxed);
            self.head = (self.head + 1) % UDP_RX_SLOTS;
            self.count -= 1;
        }
        let n = payload.len();
        let slot = &mut self.pkts[self.tail];
        slot.data[..n].copy_from_slice(&payload[..n]);
        slot.len      = n;
        slot.src_ip   = src_ip;
        slot.src_port = src_port;
        self.tail  = (self.tail + 1) % UDP_RX_SLOTS;
        self.count += 1;
    }

    fn pop(&mut self, buf: &mut [u8], src_ip: &mut [u8; 4], src_port: &mut u16) -> i32 {
        if self.count == 0 { return 0; }
        let slot = &self.pkts[self.head];
        // POSIX truncation: the caller asked for fewer bytes than arrived, so
        // the tail goes. What POSIX also does and we cannot yet is report it —
        // `recvmsg` raises `MSG_TRUNC` in `msg_flags`, and returns the real
        // datagram length when the caller passes that flag in. Returning the
        // full length from here instead of the copied length would silently
        // break every caller that slices `&buf[..n]`, so the signal has to
        // arrive as a flag, which means widening the syscall ABI in all three
        // places it is declared. Until then the loss is at least visible in
        // the counter rather than invisible entirely.
        let n = slot.len.min(buf.len());
        if n < slot.len {
            RX_TRUNCATED_DELIVERIES.fetch_add(1, Ordering::Relaxed);
        }
        buf[..n].copy_from_slice(&slot.data[..n]);
        *src_ip   = slot.src_ip;
        *src_port = slot.src_port;
        self.head  = (self.head + 1) % UDP_RX_SLOTS;
        self.count -= 1;
        n as i32
    }
}

// ── Socket state ─────────────────────────────────────────────────────────────

/// Socket identity. Deliberately carries no payload — see `UdpTable`.
pub struct UdpSocket {
    pub local_port:  u16,
    pub remote_ip:   u32,
    pub remote_port: u16,
    pub bound:       bool,
}

impl UdpSocket {
    pub const fn new() -> Self {
        UdpSocket {
            local_port:  0,
            remote_ip:   0,
            remote_port: 0,
            bound:       false,
        }
    }
}

// ── Global socket table ──────────────────────────────────────────────────────

/// Identity and payload, side by side rather than interleaved.
///
/// The ring used to live inside `UdpSocket`, which made one socket ~5993 bytes
/// and the table 47 KiB. `dispatch` reads two fields — `bound` and
/// `local_port` — from each of the eight in turn to find the addressee of an
/// arriving datagram, and with that stride the eight it touches sit on eight
/// separate cache lines and eight separate 4 KiB pages. Every datagram paid
/// that before it could be routed anywhere.
///
/// Split, the identities are contiguous and the whole scan is under two cache
/// lines, prefetched together. The rings are untouched until a socket actually
/// matches. Nothing about the behaviour changes; the const assertion below is
/// what keeps it that way, since no test can tell two layouts apart.
///
/// **One lock, deliberately.** A separate static for the hot fields would be a
/// second lock over one state machine: between reading the ports and taking
/// the socket lock, an `unbind` could land and the datagram would be delivered
/// to a closed — or worse, recycled and rebound — socket. Both arrays live
/// under this one guard, and `socks` sits first so acquiring the lock is
/// likely to pull the scan data in with it.
struct UdpTable {
    socks: [UdpSocket; UDP_MAX_SOCKETS],
    rx:    [UdpRxBuf;  UDP_MAX_SOCKETS],
}

impl UdpTable {
    const fn new() -> Self {
        UdpTable {
            socks: [const { UdpSocket::new() }; UDP_MAX_SOCKETS],
            rx:    [const { UdpRxBuf::new()  }; UDP_MAX_SOCKETS],
        }
    }
}

// The point of the split, enforced rather than described. A comment saying
// "this is two cache lines" rots the day somebody puts a fat field back in
// `UdpSocket`; this does not compile that day.
const _: () = assert!(
    core::mem::size_of::<[UdpSocket; UDP_MAX_SOCKETS]>() <= 128,
    "the socket identities must stay within two cache lines: dispatch scans \
     all of them for every arriving datagram",
);

// `%` on a power of two is a mask; on anything else it is a division, and it
// sits on the receive path in both `push` and `pop`.
const _: () = assert!(
    UDP_RX_SLOTS.is_power_of_two(),
    "UDP_RX_SLOTS must be a power of two or the ring indexing costs a divide",
);

static UDP_SOCKETS: SpinLock<UdpTable> = SpinLock::new(UdpTable::new());

/// Bind a UDP socket to a local port.  Returns socket index or -1.
pub fn bind(port: u16) -> i32 {
    let mut t = UDP_SOCKETS.lock();
    for i in 0..UDP_MAX_SOCKETS {
        if !t.socks[i].bound {
            t.socks[i].bound       = true;
            t.socks[i].local_port  = port;
            t.socks[i].remote_ip   = 0;
            t.socks[i].remote_port = 0;
            t.rx[i].clear();
            return i as i32;
        }
    }
    -1
}

/// Unbind (close) a UDP socket.
pub fn unbind(idx: usize) {
    if idx >= UDP_MAX_SOCKETS { return; }
    let mut t = UDP_SOCKETS.lock();
    t.socks[idx].bound = false;
}

/// Send a UDP datagram to `dst_ip:dst_port`.
/// Returns 0 on success, -1 on error.
pub fn sendto(
    sock:     i32,
    dst_ip:   &[u8; 4],
    dst_port: u16,
    data:     &[u8],
) -> i32 {
    if sock < 0 || sock as usize >= UDP_MAX_SOCKETS { return -1; }
    let idx = sock as usize;
    let (bound, src_port) = {
        let t = UDP_SOCKETS.lock();
        (t.socks[idx].bound, t.socks[idx].local_port)
    };
    if !bound { return -1; }

    let (mac, ip) = (crate::net_get_mac(), crate::net_get_ip());
    send_raw(&mac, &ip, dst_ip, src_port, dst_port, data)
}

/// Send a raw UDP datagram (used internally and by DHCP).
pub fn send_raw(
    our_mac:  &[u8; 6],
    our_ip:   &[u8; 4],
    dst_ip:   &[u8; 4],
    src_port: u16,
    dst_port: u16,
    data:     &[u8],
) -> i32 {
    let total_len = UDP_HDR_SIZE + data.len();
    if total_len > UDP_MAX_DGRAM { return -1; }

    let mut buf = [0u8; UDP_MAX_DGRAM];
    let hdr = unsafe { &mut *(buf.as_mut_ptr() as *mut UdpHdr) };
    hdr.src_port = src_port.to_be_bytes();
    hdr.dst_port = dst_port.to_be_bytes();
    hdr.length   = (total_len as u16).to_be_bytes();
    hdr.checksum = [0, 0];  // Optional for IPv4 UDP
    buf[UDP_HDR_SIZE..total_len].copy_from_slice(data);

    ip::send(our_mac, our_ip, dst_ip, ip::IP_PROTO_UDP, &buf[..total_len])
}

/// Receive a datagram from a bound socket (non-blocking).
/// Returns bytes copied (>0), 0 if nothing pending, -1 on error.
/// Fills `src_ip` and `src_port` with the sender's address.
pub fn recvfrom(
    sock:     i32,
    buf:      &mut [u8],
    src_ip:   &mut [u8; 4],
    src_port: &mut u16,
) -> i32 {
    if sock < 0 || sock as usize >= UDP_MAX_SOCKETS { return -1; }
    let idx = sock as usize;
    let mut t = UDP_SOCKETS.lock();
    if !t.socks[idx].bound { return -1; }
    t.rx[idx].pop(buf, src_ip, src_port)
}

/// Simple recv (no source address).  Kept for backward compat with socket layer.
pub fn recv(idx: usize, buf: &mut [u8]) -> i32 {
    if idx >= UDP_MAX_SOCKETS { return -1; }
    let mut t = UDP_SOCKETS.lock();
    if !t.socks[idx].bound { return -1; }
    let mut _ip  = [0u8; 4];
    let mut _port = 0u16;
    t.rx[idx].pop(buf, &mut _ip, &mut _port)
}

/// Close a UDP socket by index.
pub fn close(sock: i32) {
    if sock < 0 { return; }
    unbind(sock as usize);
}

/// True if a socket is bound to `port`.
///
/// The DNS resolver asks before it picks a query's source port: a reply to a
/// port some socket owns would otherwise be taken by the resolver's intercept
/// in `dispatch`, and that socket's traffic with it.
pub fn port_bound(port: u16) -> bool {
    let t = UDP_SOCKETS.lock();
    t.socks.iter().any(|s| s.bound && s.local_port == port)
}

/// NTP client source port — intercept NTP responses before socket dispatch.
/// Crate-visible so the DNS resolver never picks it as a query's source port.
pub(crate) const NTP_CLIENT_PORT: u16 = 1123;

/// Validate the UDP length field against what IP actually delivered and return
/// the datagram trimmed to it.
///
/// RFC 768: `length` covers header + payload and is never below the 8-byte
/// header.  IP may hand us trailing padding (minimum Ethernet frame size), and
/// a crafted packet may declare a length longer than the bytes received — both
/// must be rejected/trimmed *before* any range is derived from the field, or
/// the slice below panics (kernel halt under `panic = "abort"`).
fn udp_segment(data: &[u8]) -> Option<&[u8]> {
    if data.len() < UDP_HDR_SIZE { return None; }
    let hdr = unsafe { &*(data.as_ptr() as *const UdpHdr) };
    let len = u16::from_be_bytes(hdr.length) as usize;
    if len < UDP_HDR_SIZE || len > data.len() { return None; }
    Some(&data[..len])
}

/// Handle an incoming UDP datagram with receive-side checksum validation.
/// Called from `ip::handle`, which forwards both IP endpoints.
///
/// Requires both endpoints because the UDP checksum covers the IPv4
/// pseudo-header (src, dst, proto, length).  This is the ONLY ingress path:
/// there is deliberately no unvalidated entry point, so a future caller cannot
/// accidentally bypass the checks below.
pub fn handle_checked(src_ip: &[u8; 4], dst_ip: &[u8; 4], data: &[u8]) {
    let seg = match udp_segment(data) { Some(s) => s, None => return };

    // RFC 768: for IPv4 the UDP checksum is OPTIONAL, and an all-zero field
    // means "the sender did not compute one".  Such a datagram must be
    // accepted unvalidated, not dropped — `dhcp.rs` transmits this way and so
    // do many real DHCP/TFTP servers, so rejecting it here would silently
    // break address acquisition.
    let hdr  = unsafe { &*(seg.as_ptr() as *const UdpHdr) };
    let csum = u16::from_be_bytes(hdr.checksum);
    if csum != 0 {
        // Verification sums the segment *including* the stored checksum; a
        // correct datagram folds to 0xFFFF, so the complement must be zero.
        // (A computed zero is transmitted as 0xFFFF, which verifies the same.)
        let pseudo = ip::pseudo_checksum(src_ip, dst_ip, ip::IP_PROTO_UDP, seg.len() as u16);
        if super::tcp::tcp_checksum(pseudo, seg) != 0 { return; }
    }

    dispatch(src_ip, seg);
}

/// Route a length-validated datagram to its interceptor or bound socket.
/// `seg` is guaranteed to be at least `UDP_HDR_SIZE` bytes by `udp_segment`.
fn dispatch(src_ip: &[u8; 4], seg: &[u8]) {
    let hdr = unsafe { &*(seg.as_ptr() as *const UdpHdr) };
    let dst_port = u16::from_be_bytes(hdr.dst_port);
    let src_port = u16::from_be_bytes(hdr.src_port);
    let payload  = &seg[UDP_HDR_SIZE..];

    // F05 / F05.2: intercept DNS and NTP responses.
    //
    // Both handlers receive the source endpoint, not just the payload. Routing
    // on `dst_port` alone tells you only which of OUR ports a datagram was
    // aimed at — which is public knowledge and exactly what an off-path
    // forgery targets. Only the source, checked against the server the query
    // actually went to, distinguishes an answer from an injection, and neither
    // handler can perform that check without these two arguments.
    //
    // DNS is matched on the outstanding query's own source port, drawn fresh
    // per query (RFC 5452 §9.2), not on a fixed 5353. With no query
    // outstanding `active_port` is 0, nothing matches, and a late reply falls
    // through to the socket table like a datagram to any other port: dropped,
    // since `dns::new_source_port` never picks a port a socket holds.
    let dns_port = super::dns::active_port();
    if dns_port != 0 && dst_port == dns_port {
        super::dns::handle_response(src_ip, src_port, dst_port, payload);
        return;
    }

    if dst_port == NTP_CLIENT_PORT {
        super::ntp::handle_response(src_ip, src_port, payload);
        return;
    }

    let mut t = UDP_SOCKETS.lock();
    for i in 0..UDP_MAX_SOCKETS {
        if t.socks[i].bound && t.socks[i].local_port == dst_port {
            t.rx[i].push(*src_ip, src_port, payload);
            return;
        }
    }
}

/// Receive a UDP-over-IPv6 datagram.
///
/// Called from `ipv6::ipv6_rx` when `next_hdr == NEXTHDR_UDP`.
/// Routes the payload to the matching bound socket by destination port.
///
/// # Source address and the v4 socket table
///
/// There is no AF_INET6 socket API in this stack, so a v6 datagram has to be
/// delivered — if at all — through the same table the IPv4 path uses, whose
/// `src_ip` field is four bytes wide. This function used to fill that field
/// with the last four bytes of the IPv6 source address. That is a forgery
/// primitive: those four bytes are entirely under a remote sender's control,
/// so any consumer that authenticates a peer by comparing `src_ip` (the
/// boot-time TFTP fetch in `tftp_client.rs` is the in-tree example) could be
/// handed a datagram that claims to be from the server while coming from an
/// arbitrary IPv6 host — and unlike the IPv4 path, nothing on the way here
/// checked it against a real v4 peer.
///
/// The source is therefore reported as the unspecified address `0.0.0.0`,
/// which is never a valid unicast peer, so every equality check against a real
/// server address fails closed. A future AF_INET6 socket layer should carry
/// the full 128-bit source instead of narrowing it; until one exists, refusing
/// to synthesize is the honest answer.
pub fn udpv6_rx(src_ipv6: &[u8; 16], dst_ipv6: &[u8; 16], data: &[u8]) {
    // Same rule as the IPv4 path: trim to the declared UDP length before any
    // range is derived from it, and reject a length below the header size or
    // beyond what IP actually delivered.
    let seg = match udp_segment(data) { Some(s) => s, None => return };
    let hdr = unsafe { &*(seg.as_ptr() as *const UdpHdr) };

    // RFC 8200 §8.1 INVERTS the IPv4 rule: over IPv6 the UDP checksum is
    // mandatory.  A zero checksum field is not "sender opted out" — it is
    // malformed and MUST be dropped.  A non-zero checksum must verify against
    // the IPv6 pseudo-header (both 128-bit addresses, UDP length, next-header).
    if u16::from_be_bytes(hdr.checksum) == 0 { return; }
    // `ipv6::pseudo_checksum` returns the RFC-1071 complement over the
    // pseudo-header plus `seg` (checksum field included); a valid datagram
    // folds to 0xFFFF, so the complement must be zero.
    if super::ipv6::pseudo_checksum(src_ipv6, dst_ipv6, super::ipv6::NEXTHDR_UDP, seg) != 0 {
        return;
    }

    let dst_port = u16::from_be_bytes(hdr.dst_port);
    let src_port = u16::from_be_bytes(hdr.src_port);
    let payload  = &seg[UDP_HDR_SIZE..];

    // Do NOT narrow the IPv6 source into the v4 field — see the note above.
    // 0.0.0.0 is the unspecified address: no peer legitimately has it, so a
    // consumer comparing it against an expected server address rejects.
    const SRC_UNSPECIFIED: [u8; 4] = [0, 0, 0, 0];
    let src_ip4 = SRC_UNSPECIFIED;

    let mut t = UDP_SOCKETS.lock();
    for i in 0..UDP_MAX_SOCKETS {
        if t.socks[i].bound && t.socks[i].local_port == dst_port {
            t.rx[i].push(src_ip4, src_port, payload);
            return;
        }
    }
}
