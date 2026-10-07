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

pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP:  u8 = 6;
pub const IP_PROTO_UDP:  u8 = 17;

/// ICMP Destination Unreachable (RFC 792).
pub const ICMP_DEST_UNREACHABLE: u8 = 3;
/// Its code 4, Fragmentation Needed and DF Set (RFC 792, RFC 1191 §4).
pub const ICMP_FRAG_NEEDED: u8 = 4;

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
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
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
    build_header_flags(buf, proto, src, dst, options, data_len, 0)
}

/// [`build_header_with_options`] with Don't Fragment set when `flags` carries
/// `IP_FLAG_DF`. Nothing else of `flags` is written: this stack never sends a
/// fragment, so MF and the offset stay 0.
fn build_header_flags(
    buf:      &mut [u8],
    proto:    u8,
    src:      &[u8; 4],
    dst:      &[u8; 4],
    options:  &[u8],
    data_len: u16,
    flags:    u16,
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
    buf[1]  = 0;
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
    let flags = if proto == IP_PROTO_TCP { IP_FLAG_DF } else { 0 };
    send_flags(our_mac, our_ip, dst_ip, proto, &[], payload, flags)
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
    send_flags(our_mac, our_ip, dst_ip, proto, options, payload, 0)
}

fn send_flags(
    our_mac:  &[u8; 6],
    our_ip:   &[u8; 4],
    dst_ip:   &[u8; 4],
    proto:    u8,
    options:  &[u8],
    payload:  &[u8],
    flags:    u16,
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
    let mut ip_payload = [0u8; ETH_MTU];
    if build_header_flags(&mut ip_payload[..hdr_len], proto, our_ip, dst_ip,
                          options, payload.len() as u16, flags) != hdr_len {
        return -1;
    }
    ip_payload[hdr_len..total_len].copy_from_slice(payload);

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
    if dst_ip == our_ip && *our_ip != [0, 0, 0, 0] {
        // **Recursion guard.** `handle` delivers to UDP and TCP, and TCP
        // **answers**: an ACK over loopback would re-enter here with no
        // bottom. Depth 1 — the packet is delivered and any reply it triggers
        // is dropped. TCP retries a lost ACK; nobody retries a blown stack.
        return if loopback_deliver(&ip_payload[..total_len], our_mac, our_ip) { 0 } else { -1 };
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
    //   * **subnet** `network | ~mask` (RFC 922) — everyone on this link
    //
    // Both go to the broadcast MAC `ff:ff:ff:ff:ff:ff` without asking ARP.
    let mask = super::net_get_mask();
    let subnet_bcast = {
        let mut b = [0u8; 4];
        for i in 0..4 { b[i] = (our_ip[i] & mask[i]) | !mask[i]; }
        b
    };
    let is_broadcast = *dst_ip == [0xff; 4] || *dst_ip == subnet_bcast;

    // ── Routing (RFC 1122 §3.3.1): off-subnet unicast goes to the gateway ──
    //
    // U06-4: **there was no route beyond the local segment.** Every
    // destination — broadcast and multicast excepted below — was ARPed
    // directly regardless of subnet: an off-link host (`dns.rs`'s
    // `8.8.8.8` default, `ntp.rs`'s default, or a brain/OTA host on another
    // network) drew a broadcast ARP request for an address nobody on this
    // link could answer, and the queued frame (`enqueue_for_arp`) expired
    // after `ARP_TXQ_TTL_TICKS` with no MAC ever resolving.
    // `net_get_gateway()` was stored (DHCP option 3, or CONFIG.INI) and
    // never read by the data path — this is the first read.
    //
    // Only the *next hop* changes here: the IP header above already carries
    // the real `dst_ip`, unchanged. There is one gateway, no forwarding
    // table, so an off-link destination with no gateway configured still
    // falls back to ARPing `dst_ip` directly (the pre-existing behaviour,
    // and the correct one on an unrouted /24 like SLIRP's).
    let next_hop: [u8; 4] = if is_broadcast || super::igmp::is_multicast(dst_ip) {
        *dst_ip
    } else {
        let on_link = (0..4).all(|i| (dst_ip[i] & mask[i]) == (our_ip[i] & mask[i]));
        if on_link {
            *dst_ip
        } else {
            let gw = super::net_get_gateway();
            if gw == [0, 0, 0, 0] { *dst_ip } else { gw }
        }
    };

    // ── Multicast (RFC 1112 §6.4) ──────────────────────────────────────
    //
    // A group address is mapped straight to `01:00:5E:xx:xx:xx`; asking ARP
    // for it is meaningless — no host owns a group — and would have failed
    // exactly the way broadcast did before RFC 919/922 was implemented here.
    let dst_mac = if super::igmp::is_multicast(dst_ip) {
        super::igmp::multicast_mac(dst_ip)
    } else if is_broadcast {
        [0xffu8; 6]
    } else {
        match arp::lookup(&next_hop) {
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
                // costs and what is dropped instead. Keyed on `next_hop` (the
                // gateway when off-link), matching what `arp::send_request`
                // asked for — U06-4.
                arp::send_request(our_mac, our_ip, &next_hop);
                return enqueue_for_arp(our_mac, &next_hop, &ip_payload[..total_len]);
            }
        }
    };

    let frame_len = ethernet::EthHdr::SIZE + total_len;
    // Use a fixed-size stack frame (max Ethernet frame)
    let mut frame = [0u8; ethernet::ETH_FRAME_MAX];
    if frame_len > frame.len() { return -1; }

    ethernet::build(&mut frame[..frame_len], &dst_mac, our_mac, ETH_TYPE_IP,
                    &ip_payload[..total_len]);

    if super::net_raw_send(&frame[..frame_len]) > 0 { 0 } else { -1 }
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
    dst_ip:   [u8; 4],
    deadline: u64,
    valid:    bool,
}

impl QueuedFrame {
    const fn new() -> Self {
        QueuedFrame {
            frame: [0u8; ethernet::ETH_FRAME_MAX],
            len: 0,
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
fn enqueue_for_arp(our_mac: &[u8; 6], dst_ip: &[u8; 4], ip_payload: &[u8]) -> i32 {
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
    q[slot].dst_ip   = *dst_ip;
    q[slot].deadline = now + ARP_TXQ_TTL_TICKS;
    q[slot].valid    = true;
    TXQ_QUEUED.fetch_add(1, Ordering::Relaxed);
    0
}

/// An ARP reply landed: send everything that was waiting on this address.
///
/// Called from `arp::handle` AFTER it has released `ARP_TABLE` — the frames go
/// out through `net_raw_send` and nothing here may run under another net lock.
/// Same discipline as `channel_destroy` releasing the pool before orphaning.
pub fn arp_resolved(ip: &[u8; 4], mac: &[u8; 6]) {
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
                if q[i].dst_ip == *ip {
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
    if *our_ip != [0, 0, 0, 0] && dst != *our_ip && dst != [0xff; 4] {
        let admitted = if super::igmp::is_multicast(&dst) {
            super::igmp::is_joined(&dst)
        } else {
            let mask = super::net_get_mask();
            (0..4).all(|i| dst[i] == (our_ip[i] & mask[i]) | !mask[i])
        };
        if !admitted { return; }
    }

    // Learn sender IP→MAC from ARP (we already added it when ARP was processed,
    // but also update here from IP source)
    let src_ip = hdr.src;
    let _ = (src_ip, our_mac); // suppress unused warning

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
        IP_PROTO_TCP  => super::tcp::handle_checked(&hdr.src, &hdr.dst, data),
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
