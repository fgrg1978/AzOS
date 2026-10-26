// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DHCP client — auto-configuration via DHCP DISCOVER/OFFER/REQUEST/ACK, and
//! the lease kept (RFC 2131 §4.4.5): renewed with its server at T1, rebound
//! with any server at T2, and given up at its end.
//!
//! Uses the UDP module for transport (port 68 client, port 67 server).
//! Simplified: fixed 300-byte message buffer.

use crate::udp;
use azos_sync::SpinLock;

// DHCP ports
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;

// DHCP message types (option 53)
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER:    u8 = 2;
const DHCP_REQUEST:  u8 = 3;
const DHCP_ACK:      u8 = 5;
const DHCP_NAK:      u8 = 6;

// DHCP option codes
const OPT_SUBNET_MASK:  u8 = 1;
const OPT_ROUTER:       u8 = 3;
const OPT_DNS:          u8 = 6;
const OPT_NTP:          u8 = 42;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME:   u8 = 51;
const OPT_MSG_TYPE:     u8 = 53;
const OPT_PARAM_REQ:    u8 = 55;
const OPT_SERVER_ID:    u8 = 54;
const OPT_RENEWAL_T1:   u8 = 58;
const OPT_REBINDING_T2: u8 = 59;
const OPT_END:          u8 = 255;

/// A lease time of all ones is infinite (RFC 2132 §9.2): nothing to renew.
const LEASE_INFINITE: u32 = 0xFFFF_FFFF;

/// RFC 2131 §4.4.5: a REQUEST that went unanswered in RENEWING is sent again
/// after half the time left to T2, in REBINDING after half the time left on
/// the lease, but not sooner than this.
pub const RETRY_MIN_S: u64 = 60;

// Magic cookie (DHCP over BOOTP)
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

const DHCP_MSG_SIZE: usize = 300;

// FNV-1a 32-bit constants — used to mix the XID entropy sources.
const FNV_OFFSET_BASIS: u32 = 0x811C_9DC5;
const FNV_PRIME:        u32 = 0x0100_0193;

/// Upper bound on the number of TLV options we will walk in one response.
/// The walk already advances by >= 1 byte per step so it terminates on its
/// own; this is a second, independent stop so a pathological (but legal)
/// all-padding 1500-byte frame cannot burn unbounded time in the RX path.
const MAX_OPTIONS: usize = 64;

/// How long `dhcp_start` waits for an OFFER, and separately for an ACK,
/// before giving up.
///
/// U06-3: this used to be "200 iterations of `yield_fn()`", not a duration —
/// on an idle hart a yield returns immediately, so both phases together
/// closed in well under a millisecond of wall time; SLIRP synthesises the
/// OFFER inside the `send` call, so the gate never exercised the timeout at
/// all. A real server (ISC dhcpd does a 1 s ping-check before OFFER by
/// default) would never make that window. RFC 2131 §4.4.1 leaves the retry
/// interval to the client; 10 s matches the deadline-in-ticks pattern
/// `dns::resolve_with_yield` and `ntp_sync_with_yield` already use instead of
/// an iteration count.
const DHCP_PHASE_TIMEOUT_TICKS: u64 = 10 * azos_drv_sys::timebase::TIMER_FREQ;

/// UDP header size (bytes).
const UDP_HDR_SIZE: usize = 8;

// DHCP/BOOTP header offsets (RFC 2131).
const OFF_OP:     usize = 0;
const OFF_HTYPE:  usize = 1;
const OFF_HLEN:   usize = 2;
const OFF_HOPS:   usize = 3;
const OFF_XID:    usize = 4;
const OFF_SECS:   usize = 8;
const OFF_FLAGS:  usize = 10;
const OFF_CIADDR: usize = 12;
const OFF_YIADDR: usize = 16;
const OFF_SIADDR: usize = 20;
const OFF_GIADDR: usize = 24;
const OFF_CHADDR: usize = 28;
const OFF_SNAME:  usize = 44;
const OFF_FILE:   usize = 108;
const OFF_COOKIE: usize = 236;
const OFF_OPTS:   usize = 240;

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// Transaction ID (RFC 2131 §2)
// ---------------------------------------------------------------------------

/// Transaction ID of the exchange currently in flight, valid only while
/// `XID_VALID` is set.  Was previously a compile-time constant ("RCOS"),
/// which let an off-path attacker who had never seen a single one of our
/// packets craft an OFFER/ACK that passed the XID check — handing the robot
/// an attacker-chosen IP, gateway and DNS.
static CUR_XID: AtomicU32 = AtomicU32::new(0);

/// Set once `CUR_XID` holds a real, runtime-generated value.  Before that,
/// `parse_response` rejects everything: a zeroed static must never be
/// something an attacker can match by sending `xid == 0`.
static XID_VALID: AtomicBool = AtomicBool::new(false);

/// Per-boot transaction counter — guarantees two XIDs generated in the same
/// timer tick still differ.
static XID_SEQ: AtomicU32 = AtomicU32::new(0);

/// Generate and install a fresh transaction ID for a new DHCP exchange.
///
/// From the kernel entropy pool through `crate::net_random_fill` when a seeded
/// source is installed; otherwise from [`counter_xid`], whose limits are
/// documented there.
fn new_xid() -> u32 {
    let mut pool = [0u8; 4];
    let h = if crate::net_random_fill(&mut pool) {
        u32::from_le_bytes(pool)
    } else {
        counter_xid()
    };
    CUR_XID.store(h, Ordering::Release);
    XID_VALID.store(true, Ordering::Release);
    h
}

/// The unseeded fallback for [`new_xid`].
///
/// Entropy honesty: **these are counters, not a TRNG.**  The value is derived from
/// the RISC-V `rdcycle` CSR (`wcet::read_cycles`), the CLINT `mtime` counter
/// (`timebase::now`) and a per-boot sequence counter, avalanched so the few
/// live bits are spread across all 32.  Both counters advance at runtime, so
/// the XID is *not* recoverable by reading the binary — which is exactly the
/// bar that blind off-path forgery has to clear, and the reason the old fixed
/// constant was a hole.
///
/// It is **not** cryptographically random, and nothing here should be treated
/// as if it were.  `rdcycle` at DHCP time is a fairly narrow function of boot
/// time and clock rate, and under QEMU TCG it is noisy but far from uniform;
/// an attacker who can observe our traffic, or who can bound our boot instant
/// and clock closely enough, can still shrink the search space well below
/// 2^32.  This raises the cost of blind forgery, it does not make it
/// infeasible.  [`new_xid`] takes the pool instead whenever one is seeded.
fn counter_xid() -> u32 {
    let cycles = azos_drv_sys::wcet::read_cycles();
    let mtime  = azos_drv_sys::timebase::now();
    let seq    = XID_SEQ.fetch_add(1, Ordering::Relaxed);

    // FNV-1a over the three sources.  All arithmetic is explicitly wrapping:
    // release builds run `overflow-checks = true` and any panic here is a
    // full board reset.
    let mut h = FNV_OFFSET_BASIS;
    for b in cycles.to_le_bytes().iter()
        .chain(mtime.to_le_bytes().iter())
        .chain(seq.to_le_bytes().iter())
    {
        h ^= *b as u32;
        h = h.wrapping_mul(FNV_PRIME);
    }
    // Final avalanche — the differing bits between two nearby transactions
    // live in the low end of both counters; without this they would stay
    // clustered in the low bits of the XID.
    h ^= h >> 16;
    h  = h.wrapping_mul(0x7FEB_352D);
    h ^= h >> 15;
    h  = h.wrapping_mul(0x846C_A68B);
    h ^= h >> 16;
    h
}

/// Current transaction ID, or `None` if no exchange has been started.
fn cur_xid() -> Option<u32> {
    if XID_VALID.load(Ordering::Acquire) {
        Some(CUR_XID.load(Ordering::Acquire))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Server identifier binding (RFC 2131 §4.3.2 / option 54)
// ---------------------------------------------------------------------------

/// Server identifier of the OFFER we accepted, packed big-endian, valid only
/// while `SERVER_ID_VALID` is set.  Without this binding a rogue server that
/// loses the OFFER race can still hijack the exchange by racing an ACK.
static ACCEPTED_SERVER_ID: AtomicU32 = AtomicU32::new(0);

/// Set once `ACCEPTED_SERVER_ID` holds the server-id of an accepted OFFER.
static SERVER_ID_VALID: AtomicBool = AtomicBool::new(false);

/// Forget any accepted server binding (start of a new exchange).
fn clear_server_id() { SERVER_ID_VALID.store(false, Ordering::Release); }

/// Close the current exchange: no XID is in flight any more, so late or
/// replayed OFFER/ACK frames are rejected by `parse_response` outright
/// instead of being matched against a stale but still-valid XID.
fn end_transaction() {
    XID_VALID.store(false, Ordering::Release);
    clear_server_id();
}

/// Bind subsequent ACK validation to this server identifier.
fn set_server_id(id: &[u8; 4]) {
    ACCEPTED_SERVER_ID.store(u32::from_be_bytes(*id), Ordering::Release);
    SERVER_ID_VALID.store(true, Ordering::Release);
}

/// Server identifier we are bound to, or `None` if no OFFER was accepted.
fn accepted_server_id() -> Option<[u8; 4]> {
    if SERVER_ID_VALID.load(Ordering::Acquire) {
        Some(ACCEPTED_SERVER_ID.load(Ordering::Acquire).to_be_bytes())
    } else {
        None
    }
}

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum DhcpState {
    Idle        = 0,
    Discovering = 1,
    Requesting  = 2,
    Bound       = 3,
    /// Past T1: asking the lease's server to extend it.
    Renewing    = 4,
    /// Past T2: asking any server.
    Rebinding   = 5,
}

static DHCP_STATE: AtomicU8 = AtomicU8::new(DhcpState::Idle as u8);

fn set_dhcp_state(s: DhcpState) { DHCP_STATE.store(s as u8, Ordering::Release); }

fn get_dhcp_state() -> DhcpState {
    match DHCP_STATE.load(Ordering::Acquire) {
        1 => DhcpState::Discovering,
        2 => DhcpState::Requesting,
        3 => DhcpState::Bound,
        4 => DhcpState::Renewing,
        5 => DhcpState::Rebinding,
        _ => DhcpState::Idle,
    }
}

/// Parsed DHCP offer/ack fields.
struct DhcpInfo {
    offered_ip: [u8; 4],
    server_ip:  [u8; 4],
    /// Option 54 as sent by the server.  Kept separate from `server_ip`
    /// (which falls back to `siaddr`) because the ACK/OFFER binding check
    /// must compare the actual option, not a header field a rogue server
    /// can leave zeroed.
    server_id:  [u8; 4],
    /// Whether option 54 was actually present.  RFC 2131 §4.3.1/§4.3.2 make
    /// it mandatory in OFFER and ACK; absence is treated as a reject rather
    /// than as "matches anything".
    has_server_id: bool,
    subnet:     [u8; 4],
    gateway:    [u8; 4],
    dns:        [u8; 4],
    /// Option 42: the first NTP server the lease names (0.0.0.0: none).
    ntp:        [u8; 4],
    /// Options 51, 58 and 59 (RFC 2132 §9.2, §9.11, §9.12), seconds.
    lease_s:    Option<u32>,
    t1_s:       Option<u32>,
    t2_s:       Option<u32>,
    msg_type:   u8,
}

impl DhcpInfo {
    const fn new() -> Self {
        DhcpInfo {
            offered_ip: [0; 4],
            server_ip:  [0; 4],
            server_id:  [0; 4],
            has_server_id: false,
            subnet:     [255, 255, 255, 0],
            gateway:    [0; 4],
            dns:        [0; 4],
            ntp:        [0; 4],
            lease_s:    None,
            t1_s:       None,
            t2_s:       None,
            msg_type:   0,
        }
    }
}

/// Build a base DHCP message with common fields filled in.
///
/// `xid` is the transaction ID of the exchange in flight — DISCOVER creates
/// it, REQUEST must reuse the *same* value (RFC 2131 §3.1) so the server
/// correlates the two.
///
/// `ciaddr`: the address of a lease being renewed or rebound (RFC 2131 Table
/// 5). With one the BROADCAST flag is clear: a client with an address takes a
/// unicast reply (§4.1).
fn build_base_msg(buf: &mut [u8; DHCP_MSG_SIZE], mac: &[u8; 6], xid: u32, ciaddr: Option<[u8; 4]>) {
    // Zero the entire buffer
    let mut i = 0;
    while i < DHCP_MSG_SIZE { buf[i] = 0; i += 1; }

    buf[OFF_OP]    = 1;   // BOOTREQUEST
    buf[OFF_HTYPE] = 1;   // Ethernet
    buf[OFF_HLEN]  = 6;   // MAC length
    buf[OFF_HOPS]  = 0;
    buf[OFF_XID..OFF_XID + 4].copy_from_slice(&xid.to_be_bytes());
    buf[OFF_SECS]  = 0;
    buf[OFF_SECS + 1] = 0;
    // FLAGS: broadcast bit set (0x8000) while we have no address
    buf[OFF_FLAGS]     = if ciaddr.is_some() { 0x00 } else { 0x80 };
    buf[OFF_FLAGS + 1] = 0x00;
    if let Some(a) = ciaddr {
        buf[OFF_CIADDR..OFF_CIADDR + 4].copy_from_slice(&a);
    }
    // CHADDR: our MAC in first 6 bytes (rest zero)
    buf[OFF_CHADDR..OFF_CHADDR + 6].copy_from_slice(mac);
    // Magic cookie
    buf[OFF_COOKIE..OFF_COOKIE + 4].copy_from_slice(&MAGIC_COOKIE);
}

/// Option 55, the parameter request list (RFC 2132 §9.8): the options this
/// client uses, which a server sends only when asked (an NTP server, option
/// 42, in particular). Written at the start of `buf`; the octets used.
fn put_param_request_list(buf: &mut [u8]) -> usize {
    const WANTED: [u8; 4] = [OPT_SUBNET_MASK, OPT_ROUTER, OPT_DNS, OPT_NTP];
    buf[0] = OPT_PARAM_REQ;
    buf[1] = WANTED.len() as u8;
    buf[2..2 + WANTED.len()].copy_from_slice(&WANTED);
    2 + WANTED.len()
}

/// Send DHCP DISCOVER via broadcast.
pub fn dhcp_discover() {
    let mac = crate::net_get_mac();
    // Fresh XID per exchange, and drop any server binding from a previous
    // attempt — the OFFER that answers *this* DISCOVER decides the server.
    let xid = new_xid();
    clear_server_id();
    let mut msg = [0u8; DHCP_MSG_SIZE];
    build_base_msg(&mut msg, &mac, xid, None);

    // Options
    let mut o = OFF_OPTS;
    // Option 53: DHCP Message Type = DISCOVER
    msg[o] = OPT_MSG_TYPE; msg[o + 1] = 1; msg[o + 2] = DHCP_DISCOVER; o += 3;
    o += put_param_request_list(&mut msg[o..]);
    // End
    msg[o] = OPT_END;

    // Send broadcast: src 0.0.0.0:68 → dst 255.255.255.255:67
    send_broadcast(&mac, &[0; 4], &msg);
    set_dhcp_state(DhcpState::Discovering);
    azos_drv_sys::kprintln!("[DHCP] DISCOVER sent");
}

/// Broadcast `msg` from `src_ip`:68 to 255.255.255.255:67, as a raw frame:
/// a client with no address has no route and no ARP to go through. `src_ip`
/// is 0.0.0.0 before a lease, the lease's address when rebinding.
fn send_broadcast(mac: &[u8; 6], src_ip: &[u8; 4], msg: &[u8; DHCP_MSG_SIZE]) {
    use super::ethernet;
    use super::ip;
    let dst_ip  = [255u8; 4];
    let dst_mac = [0xFFu8; 6];
    let udp_len = UDP_HDR_SIZE + DHCP_MSG_SIZE;
    let ip_total = ip::IP_HDR_MIN + udp_len;
    let frame_len = ethernet::EthHdr::SIZE + ip_total;

    let mut frame = [0u8; ethernet::ETH_FRAME_MAX];
    if frame_len > frame.len() { return; }

    // IP header
    let mut ip_hdr = [0u8; ip::IP_HDR_MIN];
    ip::build_header(&mut ip_hdr, ip::IP_PROTO_UDP, src_ip, &dst_ip, udp_len as u16);

    // UDP header
    let mut udp_buf = [0u8; UDP_HDR_SIZE];
    udp_buf[0..2].copy_from_slice(&DHCP_CLIENT_PORT.to_be_bytes());
    udp_buf[2..4].copy_from_slice(&DHCP_SERVER_PORT.to_be_bytes());
    udp_buf[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp_buf[6..8].copy_from_slice(&[0, 0]); // checksum optional

    // Assemble IP payload: IP hdr + UDP hdr + DHCP msg
    let mut ip_payload = [0u8; ip::ETH_MTU];
    ip_payload[..ip::IP_HDR_MIN].copy_from_slice(&ip_hdr);
    ip_payload[ip::IP_HDR_MIN..ip::IP_HDR_MIN + UDP_HDR_SIZE].copy_from_slice(&udp_buf);
    ip_payload[ip::IP_HDR_MIN + UDP_HDR_SIZE..ip::IP_HDR_MIN + UDP_HDR_SIZE + DHCP_MSG_SIZE].copy_from_slice(msg);

    ethernet::build(&mut frame[..frame_len], &dst_mac, mac,
                    ethernet::ETH_TYPE_IP, &ip_payload[..ip_total]);

    let _ = super::net_raw_send(&frame[..frame_len]);
}

/// Parse a DHCP response (OFFER or ACK) from raw UDP payload.
fn parse_response(data: &[u8]) -> Option<DhcpInfo> {
    if data.len() < OFF_OPTS + 4 { return None; }
    // Verify op=2 (BOOTREPLY) and magic cookie
    if data[OFF_OP] != 2 { return None; }
    if data[OFF_COOKIE..OFF_COOKIE + 4] != MAGIC_COOKIE { return None; }
    // Verify XID against the exchange we actually started.  No exchange in
    // flight → nothing can be a valid reply.
    let expected = cur_xid()?;
    let xid = u32::from_be_bytes([data[OFF_XID], data[OFF_XID+1], data[OFF_XID+2], data[OFF_XID+3]]);
    if xid != expected { return None; }

    let mut info = DhcpInfo::new();
    info.offered_ip.copy_from_slice(&data[OFF_YIADDR..OFF_YIADDR + 4]);
    info.server_ip.copy_from_slice(&data[OFF_SIADDR..OFF_SIADDR + 4]);

    // Parse options.  Everything below OFF_OPTS is attacker-controlled TLV
    // data, so every index is bounds-checked *before* the slice: release
    // builds are `panic = "abort"`, so one out-of-range slice is a board
    // reset, not an error.  `len` is a u8 (<= 255) and `o < data.len()` with
    // `data.len() <= ETH_MTU`, so `o + 2 + len` cannot overflow usize even
    // with `overflow-checks = true`.
    //
    // Re-verified 2026-09-06 (claims_check audit): `parse_response` is
    // private (only this file calls it), and its only caller passes
    // `&buf[..n]` where `buf: [0u8; ip::ETH_MTU]` — so `data.len() <=
    // ETH_MTU = 1500` holds by construction, not by convention. But the
    // conclusion is true even without that premise: `usize` is 64 bits on
    // every target this tree builds for (`riscv64*-unknown-none-elf`; no
    // RV32 target exists in this tree), so `o + 2 + len` cannot reach
    // `usize::MAX` for any `data.len()` a real buffer could hold. If a
    // 32-bit target is ever added, re-derive this bound — it stops being
    // free.
    let mut o = OFF_OPTS;
    let mut seen = 0usize;
    // Which known options have been taken (one bit each). A known option
    // present twice is ambiguous (RFC 2131 §4.1 sends each once) and refuses
    // the whole message rather than letting the later copy win. The END marker
    // is not required: RFC 1542 §2.1 has the receiver trust the UDP length, so
    // a datagram that ends right after a whole option is whole. An option that
    // is cut by that length ends the walk (below).
    let mut taken = 0u16;
    while o < data.len() {
        let opt = data[o];
        if opt == OPT_END { break; }
        if opt == 0 { o += 1; continue; } // padding: 1 byte, no length field

        // Independent iteration bound — see MAX_OPTIONS.  Counted only for
        // real TLVs: pad bytes advance `o` by 1 each and are already bounded
        // by `data.len()`.  Past the budget the message is refused: the
        // fields already read are not a lease.
        seen += 1;
        if seen > MAX_OPTIONS { return None; }

        // Need the length byte to exist before reading it.
        if o + 1 >= data.len() { break; }
        let len = data[o + 1] as usize;
        // Truncated option: the declared value runs past the packet.  Stop
        // rather than clamping — a short read here would let a crafted
        // length splice adjacent option bytes into a field we act on. What was
        // read whole before it stands (RFC 1542 §2.1: the UDP length is the
        // message); an OFFER still needs its server identifier to count.
        if o + 2 + len > data.len() { break; }
        let val = &data[o + 2..o + 2 + len];
        let bit = match opt {
            OPT_MSG_TYPE     => 1u16 << 0,
            OPT_SUBNET_MASK  => 1 << 1,
            OPT_ROUTER       => 1 << 2,
            OPT_DNS          => 1 << 3,
            OPT_SERVER_ID    => 1 << 4,
            OPT_NTP          => 1 << 5,
            OPT_LEASE_TIME   => 1 << 6,
            OPT_RENEWAL_T1   => 1 << 7,
            OPT_REBINDING_T2 => 1 << 8,
            _ => 0,
        };
        if taken & bit != 0 { return None; }
        taken |= bit;
        // Each known option has a fixed shape (RFC 2132): message type and
        // server id and mask are exactly 1 / 4 / 4 octets; router and DNS are
        // a list of addresses, so a multiple of 4, of which the first is used.
        // A wrong length is not "the first bytes of it".
        match opt {
            OPT_MSG_TYPE    => { if len != 1 { return None; } info.msg_type = val[0]; }
            OPT_SUBNET_MASK => { if len != 4 { return None; } info.subnet.copy_from_slice(val); }
            OPT_ROUTER      => {
                if len == 0 || len % 4 != 0 { return None; }
                info.gateway.copy_from_slice(&val[..4]);
            }
            OPT_DNS         => {
                if len == 0 || len % 4 != 0 { return None; }
                info.dns.copy_from_slice(&val[..4]);
            }
            // Option 42, NTP servers (RFC 2132 §8.3): a list of addresses in
            // order of preference, of which the first is used.
            OPT_NTP         => {
                if len == 0 || len % 4 != 0 { return None; }
                info.ntp.copy_from_slice(&val[..4]);
            }
            OPT_SERVER_ID   => {
                if len != 4 { return None; }
                info.server_id.copy_from_slice(val);
                info.has_server_id = true;
                info.server_ip.copy_from_slice(val);
            }
            // Options 51, 58, 59: a 32-bit count of seconds each.
            OPT_LEASE_TIME | OPT_RENEWAL_T1 | OPT_REBINDING_T2 => {
                if len != 4 { return None; }
                let v = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]]));
                match opt {
                    OPT_LEASE_TIME => info.lease_s = v,
                    OPT_RENEWAL_T1 => info.t1_s = v,
                    _              => info.t2_s = v,
                }
            }
            _ => {}
        }
        // Advances by >= 2 even when len == 0, so a zero-length option can
        // never spin the loop in place.
        o += 2 + len;
    }
    if (info.msg_type == DHCP_OFFER || info.msg_type == DHCP_ACK) && !lease_is_sane(&info) {
        return None;
    }
    Some(info)
}

/// True for an address a host may be given or told to use as a unicast peer:
/// not in 0.0.0.0/8 ("this network"), not loopback, not multicast / reserved /
/// broadcast (224.0.0.0 and up).
fn is_unicast_v4(a: &[u8; 4]) -> bool {
    a[0] != 0 && a[0] != 127 && a[0] < 224
}

/// Whether an OFFER/ACK carries a lease the interface could actually take.
/// `net_set_ip` applies these values unchecked, so this is where a server
/// handing out 0.0.0.0, 255.255.255.255, a multicast address, the subnet's own
/// network or broadcast address, a non-contiguous mask or a group as the
/// gateway is refused.
fn lease_is_sane(info: &DhcpInfo) -> bool {
    if !is_unicast_v4(&info.offered_ip) { return false; }
    if info.has_server_id && !is_unicast_v4(&info.server_id) { return false; }
    if info.gateway != [0u8; 4] && !is_unicast_v4(&info.gateway) { return false; }
    if info.dns != [0u8; 4] && !is_unicast_v4(&info.dns) { return false; }
    if info.ntp != [0u8; 4] && !is_unicast_v4(&info.ntp) { return false; }
    let mask = u32::from_be_bytes(info.subnet);
    // Contiguous ones from the top and at least one: the complement is then
    // 2^k - 1, whose successor shares no bit with it.
    if mask == 0 || (!mask).wrapping_add(1) & !mask != 0 { return false; }
    // With two or more host bits, neither the all-zeros nor the all-ones host
    // is an address (a /31 or /32 has no such pair to exclude).
    if mask <= 0xFFFF_FFFC {
        let host = u32::from_be_bytes(info.offered_ip) & !mask;
        if host == 0 || host == !mask { return false; }
    }
    true
}

/// Handle a DHCP OFFER: extract and return offered IP + server IP.
pub fn dhcp_handle_offer(data: &[u8]) -> Option<([u8; 4], [u8; 4])> {
    let info = parse_response(data)?;
    if info.msg_type != DHCP_OFFER { return None; }
    // Option 54 is mandatory in an OFFER (RFC 2131 §4.3.1).  Without it there
    // is nothing to bind the later ACK to, so accepting the OFFER would leave
    // the exchange hijackable — reject instead.
    if !info.has_server_id {
        azos_drv_sys::kwarn!("[DHCP] OFFER rejected: no server identifier (opt 54)");
        return None;
    }
    // Bind this exchange to the offering server; the ACK must match.
    set_server_id(&info.server_id);
    azos_drv_sys::kprintln!(
        "[DHCP] OFFER: {}.{}.{}.{} from server {}.{}.{}.{}",
        info.offered_ip[0], info.offered_ip[1], info.offered_ip[2], info.offered_ip[3],
        info.server_id[0], info.server_id[1], info.server_id[2], info.server_id[3],
    );
    Some((info.offered_ip, info.server_id))
}

/// Send DHCP REQUEST for the offered IP.
pub fn dhcp_request(offered_ip: [u8; 4], server_ip: [u8; 4]) {
    let mac = crate::net_get_mac();
    // Reuse the DISCOVER's XID — a REQUEST with a fresh one would not be
    // correlated by the server, and our own ACK check would reject the reply.
    let xid = match cur_xid() {
        Some(x) => x,
        None    => return, // no exchange in flight
    };
    let mut msg = [0u8; DHCP_MSG_SIZE];
    build_base_msg(&mut msg, &mac, xid, None);

    // Options
    let mut o = OFF_OPTS;
    // Option 53: DHCP Message Type = REQUEST
    msg[o] = OPT_MSG_TYPE; msg[o + 1] = 1; msg[o + 2] = DHCP_REQUEST; o += 3;
    // Option 50: Requested IP
    msg[o] = OPT_REQUESTED_IP; msg[o + 1] = 4;
    msg[o + 2..o + 6].copy_from_slice(&offered_ip); o += 6;
    // Option 54: Server Identifier
    msg[o] = OPT_SERVER_ID; msg[o + 1] = 4;
    msg[o + 2..o + 6].copy_from_slice(&server_ip); o += 6;
    o += put_param_request_list(&mut msg[o..]);
    // End
    msg[o] = OPT_END;

    // Send broadcast (still using 0.0.0.0 as src until ACK)
    send_broadcast(&mac, &[0; 4], &msg);
    set_dhcp_state(DhcpState::Requesting);
    azos_drv_sys::kprintln!("[DHCP] REQUEST sent");
}

/// Handle a DHCP ACK: apply the IP configuration.  Returns true on success.
pub fn dhcp_handle_ack(data: &[u8]) -> bool {
    let info = match parse_response(data) {
        Some(i) => i,
        None    => return false,
    };
    if info.msg_type != DHCP_ACK { return false; }

    // The ACK must come from the same server whose OFFER we accepted.
    // Without this a rogue server that lost the OFFER race can still race an
    // ACK in and dictate our IP, gateway and DNS after the fact.  Option 54
    // is mandatory in an ACK (RFC 2131 §4.3.1); a missing one is a reject.
    // In REBINDING any server may answer (RFC 2131 §4.4.5), and the lease
    // is then that server's.
    let bound = match accepted_server_id() {
        Some(id) => id,
        None if get_dhcp_state() == DhcpState::Rebinding && info.has_server_id => info.server_id,
        None => {
            azos_drv_sys::kwarn!("[DHCP] ACK rejected: no accepted OFFER to match");
            return false;
        }
    };
    if !info.has_server_id || info.server_id != bound {
        azos_drv_sys::kwarn!(
            "[DHCP] ACK rejected: server id {}.{}.{}.{} != accepted {}.{}.{}.{}",
            info.server_id[0], info.server_id[1], info.server_id[2], info.server_id[3],
            bound[0], bound[1], bound[2], bound[3],
        );
        return false;
    }

    crate::net_set_ip(info.offered_ip, info.subnet, info.gateway);
    // F05: Apply DNS server from DHCP lease
    if info.dns != [0, 0, 0, 0] {
        crate::dns::set_dns_server(info.dns);
        azos_drv_sys::kprintln!(
            "[DHCP] DNS server: {}.{}.{}.{}",
            info.dns[0], info.dns[1], info.dns[2], info.dns[3],
        );
    }
    // Option 42: the lease names a time server, which the NTP client prefers
    // to the configured one for as long as the lease says; a lease that names
    // none takes back the one a previous lease named.
    crate::ntp::set_leased_server((info.ntp != [0, 0, 0, 0]).then_some(info.ntp));
    if info.ntp != [0, 0, 0, 0] {
        azos_drv_sys::kprintln!(
            "[DHCP] NTP server: {}.{}.{}.{}",
            info.ntp[0], info.ntp[1], info.ntp[2], info.ntp[3],
        );
    }
    let lease = Lease::from_ack(&info, azos_drv_sys::timebase::now());
    *LEASE.lock() = Some(lease);
    set_dhcp_state(DhcpState::Bound);
    azos_drv_sys::kprintln!(
        "[DHCP] ACK: bound to {}.{}.{}.{}  mask {}.{}.{}.{}  gw {}.{}.{}.{}",
        info.offered_ip[0], info.offered_ip[1], info.offered_ip[2], info.offered_ip[3],
        info.subnet[0], info.subnet[1], info.subnet[2], info.subnet[3],
        info.gateway[0], info.gateway[1], info.gateway[2], info.gateway[3],
    );
    match lease.secs {
        Some((l, t1, t2)) =>
            azos_drv_sys::kprintln!("[DHCP] lease {} s: renew at {} s, rebind at {} s", l, t1, t2),
        None => azos_drv_sys::kprintln!("[DHCP] lease without end: never renewed"),
    }
    true
}

/// Whether `data` is a DHCPNAK for the exchange in flight from the server it
/// was sent to (in REBINDING, from any server).
fn dhcp_handle_nak(data: &[u8]) -> bool {
    let Some(info) = parse_response(data) else { return false };
    if info.msg_type != DHCP_NAK || !info.has_server_id { return false; }
    match accepted_server_id() {
        Some(id) => id == info.server_id,
        None => get_dhcp_state() == DhcpState::Rebinding,
    }
}

// ---------------------------------------------------------------------------
// The lease (RFC 2131 §4.4.5)
// ---------------------------------------------------------------------------

/// The lease the last ACK gave, and when what follows it falls due, in ticks.
#[derive(Clone, Copy)]
struct Lease {
    ip:     [u8; 4],
    mask:   [u8; 4],
    server: [u8; 4],
    /// (lease, T1, T2) in seconds as taken; `None` for an infinite lease.
    secs:   Option<(u32, u32, u32)>,
    t2:     u64,
    end:    u64,
    /// When `dhcp_maintain` next has work: T1, a retransmission, T2, the end.
    next:   u64,
}

impl Lease {
    /// T1 and T2 as the server set them (options 58, 59), or RFC 2131
    /// §4.4.5's 0.5 and 0.875 of the lease when it did not or when they are
    /// not in order (T1 <= T2 <= lease). A lease time of all ones, or none, is
    /// a lease that does not end.
    fn from_ack(info: &DhcpInfo, now: u64) -> Lease {
        let f = azos_drv_sys::timebase::TIMER_FREQ;
        let at = |s: u32| now.saturating_add((s as u64).saturating_mul(f));
        let secs = match info.lease_s {
            None | Some(LEASE_INFINITE) => None,
            Some(l) => {
                let (d1, d2) = (l / 2, (l as u64 * 7 / 8) as u32);
                Some(match (info.t1_s, info.t2_s) {
                    (Some(t1), Some(t2)) if t1 <= t2 && t2 <= l => (l, t1, t2),
                    (Some(t1), None) if t1 <= d2 => (l, t1, d2),
                    (None, Some(t2)) if d1 <= t2 && t2 <= l => (l, d1, t2),
                    _ => (l, d1, d2),
                })
            }
        };
        let (next, t2, end) = match secs {
            Some((l, t1, t2)) => (at(t1), at(t2), at(l)),
            None => (u64::MAX, u64::MAX, u64::MAX),
        };
        Lease { ip: info.offered_ip, mask: info.subnet, server: info.server_id, secs, t2, end, next }
    }
}

static LEASE: SpinLock<Option<Lease>> = SpinLock::new(None);

/// When [`dhcp_maintain`] next has work (tick): T1 of the lease held, a
/// retransmission, T2, its end. `None` with no lease, or one that does not
/// end.
pub fn lease_deadline() -> Option<u64> {
    LEASE.lock().map(|l| l.next).filter(|&n| n != u64::MAX)
}

/// What an exchange for a lease heard.
enum Reply { Ack, Nak, Nothing }

/// One RENEWING or REBINDING exchange (RFC 2131 Table 5): a REQUEST with
/// `ciaddr` the lease's address and neither option 50 nor 54, unicast to the
/// lease's server or, `rebinding`, broadcast from the lease's address; then
/// up to [`DHCP_PHASE_TIMEOUT_TICKS`] for its answer.
fn lease_exchange(l: &Lease, rebinding: bool, yield_fn: fn()) -> Reply {
    let sock = udp::bind(DHCP_CLIENT_PORT);
    if sock < 0 { return Reply::Nothing; }
    let mac = crate::net_get_mac();
    let xid = new_xid();
    if rebinding { clear_server_id(); } else { set_server_id(&l.server); }
    let mut msg = [0u8; DHCP_MSG_SIZE];
    build_base_msg(&mut msg, &mac, xid, Some(l.ip));
    let mut o = OFF_OPTS;
    msg[o] = OPT_MSG_TYPE; msg[o + 1] = 1; msg[o + 2] = DHCP_REQUEST; o += 3;
    o += put_param_request_list(&mut msg[o..]);
    msg[o] = OPT_END;
    if rebinding {
        send_broadcast(&mac, &l.ip, &msg);
    } else {
        let _ = udp::sendto(sock, &l.server, DHCP_SERVER_PORT, &msg);
    }
    azos_drv_sys::kprintln!("[DHCP] {} REQUEST sent", if rebinding { "REBINDING" } else { "RENEWING" });

    let mut buf = [0u8; super::ip::ETH_MTU];
    let (mut src_ip, mut src_port) = ([0u8; 4], 0u16);
    let mut reply = Reply::Nothing;
    let deadline = azos_drv_sys::timebase::now() + DHCP_PHASE_TIMEOUT_TICKS;
    while azos_drv_sys::timebase::now() < deadline {
        yield_fn();
        crate::net_poll();
        let n = udp::recvfrom(sock, &mut buf, &mut src_ip, &mut src_port);
        if n <= 0 { continue; }
        let d = &buf[..n as usize];
        if dhcp_handle_ack(d) { reply = Reply::Ack; break; }
        if dhcp_handle_nak(d) { reply = Reply::Nak; break; }
    }
    udp::close(sock);
    end_transaction();
    reply
}

/// Give the lease up: the address stops being used (RFC 2131 §4.4.5: "MUST
/// immediately stop any other network processing"), and a new one is asked
/// for from the start.
fn lease_lost(l: &Lease, why: &str, yield_fn: fn()) {
    *LEASE.lock() = None;
    set_dhcp_state(DhcpState::Idle);
    azos_drv_sys::kwarn!("[DHCP] lease of {}.{}.{}.{} {}: address dropped, discovering again",
                         l.ip[0], l.ip[1], l.ip[2], l.ip[3], why);
    crate::net_set_ip([0; 4], l.mask, [0; 4]);
    let _ = dhcp_start(yield_fn);
}

/// Keep the lease (RFC 2131 §4.4.5), for the task that calls it at
/// [`lease_deadline`]: at T1 ask the lease's server to extend it, at T2 any
/// server, at its end give it up and start again. A REQUEST nobody answers
/// goes again after half the time left to T2 (to the end, when rebinding),
/// [`RETRY_MIN_S`] at least. `yield_fn` is called while an exchange waits,
/// as for `dhcp_start`. Nothing to do before the deadline, or with no lease.
pub fn dhcp_maintain(yield_fn: fn()) {
    let now = azos_drv_sys::timebase::now();
    let Some(l) = *LEASE.lock() else { return };
    if now < l.next { return; }
    if now >= l.end {
        lease_lost(&l, "expired", yield_fn);
        return;
    }
    let rebinding = now >= l.t2;
    set_dhcp_state(if rebinding { DhcpState::Rebinding } else { DhcpState::Renewing });
    match lease_exchange(&l, rebinding, yield_fn) {
        // `dhcp_handle_ack` took the new lease and is Bound again.
        Reply::Ack => {}
        Reply::Nak => lease_lost(&l, "refused (NAK)", yield_fn),
        Reply::Nothing => {
            let now = azos_drv_sys::timebase::now();
            let limit = if rebinding { l.end } else { l.t2 };
            let wait = (limit.saturating_sub(now) / 2)
                .max(RETRY_MIN_S * azos_drv_sys::timebase::TIMER_FREQ);
            if let Some(cur) = LEASE.lock().as_mut() {
                cur.next = now.saturating_add(wait).min(limit);
            }
        }
    }
}

/// Run the full DHCP handshake: DISCOVER → OFFER → REQUEST → ACK.
/// Yields between steps to allow net_poll() to process packets.
/// `yield_fn` is called to yield the CPU (e.g., `azos_sched::task_yield`).
/// Returns true if an IP was obtained, false on timeout.
pub fn dhcp_start(yield_fn: fn()) -> bool {
    // Bind to port 68 (DHCP client)
    let sock = udp::bind(DHCP_CLIENT_PORT);
    if sock < 0 {
        azos_drv_sys::kerr!("[DHCP] ERROR: cannot bind port 68");
        return false;
    }

    // Phase 1: send DISCOVER
    dhcp_discover();

    // Wait for OFFER, up to DHCP_PHASE_TIMEOUT_TICKS of wall time (U06-3).
    use super::ip;
    let mut buf = [0u8; ip::ETH_MTU];
    let mut src_ip   = [0u8; 4];
    let mut src_port = 0u16;
    let mut got_offer = false;
    let mut offered_ip = [0u8; 4];
    let mut server_ip  = [0u8; 4];

    let deadline = azos_drv_sys::timebase::now() + DHCP_PHASE_TIMEOUT_TICKS;
    while azos_drv_sys::timebase::now() < deadline {
        yield_fn();
        crate::net_poll();
        let n = udp::recvfrom(sock, &mut buf, &mut src_ip, &mut src_port);
        if n > 0 {
            if let Some((oip, sip)) = dhcp_handle_offer(&buf[..n as usize]) {
                offered_ip = oip;
                server_ip  = sip;
                got_offer  = true;
                break;
            }
        }
    }

    if !got_offer {
        azos_drv_sys::kwarn!("[DHCP] TIMEOUT: no OFFER received");
        udp::close(sock);
        end_transaction();
        return false;
    }

    // Phase 2: send REQUEST
    dhcp_request(offered_ip, server_ip);

    // Wait for ACK, same deadline shape as the OFFER phase (U06-3).
    let mut got_ack = false;
    let deadline = azos_drv_sys::timebase::now() + DHCP_PHASE_TIMEOUT_TICKS;
    while azos_drv_sys::timebase::now() < deadline {
        yield_fn();
        crate::net_poll();
        let n = udp::recvfrom(sock, &mut buf, &mut src_ip, &mut src_port);
        if n > 0 {
            if dhcp_handle_ack(&buf[..n as usize]) {
                got_ack = true;
                break;
            }
        }
    }

    udp::close(sock);
    end_transaction();

    if !got_ack {
        azos_drv_sys::kwarn!("[DHCP] TIMEOUT: no ACK received");
        return false;
    }

    azos_drv_sys::kprintln!("[DHCP] Configuration complete");
    true
}

/// Return the current DHCP state.
pub fn dhcp_state() -> DhcpState {
    get_dhcp_state()
}
