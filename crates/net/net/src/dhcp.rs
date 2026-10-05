// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DHCP client — auto-configuration via DHCP DISCOVER/OFFER/REQUEST/ACK.
//!
//! Uses the UDP module for transport (port 68 client, port 67 server).
//! Simplified: fixed 300-byte message buffer, no lease renewal.

use crate::udp;

// DHCP ports
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;

// DHCP message types (option 53)
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER:    u8 = 2;
const DHCP_REQUEST:  u8 = 3;
const DHCP_ACK:      u8 = 5;

// DHCP option codes
const OPT_SUBNET_MASK:  u8 = 1;
const OPT_ROUTER:       u8 = 3;
const OPT_DNS:          u8 = 6;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_MSG_TYPE:     u8 = 53;
const OPT_SERVER_ID:    u8 = 54;
const OPT_END:          u8 = 255;

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
/// `dns::resolve` and `ntp_sync` already use instead of an iteration count.
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
}

static DHCP_STATE: AtomicU8 = AtomicU8::new(DhcpState::Idle as u8);

fn set_dhcp_state(s: DhcpState) { DHCP_STATE.store(s as u8, Ordering::Release); }

fn get_dhcp_state() -> DhcpState {
    match DHCP_STATE.load(Ordering::Acquire) {
        1 => DhcpState::Discovering,
        2 => DhcpState::Requesting,
        3 => DhcpState::Bound,
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
            msg_type:   0,
        }
    }
}

/// Build a base DHCP message with common fields filled in.
///
/// `xid` is the transaction ID of the exchange in flight — DISCOVER creates
/// it, REQUEST must reuse the *same* value (RFC 2131 §3.1) so the server
/// correlates the two.
fn build_base_msg(buf: &mut [u8; DHCP_MSG_SIZE], mac: &[u8; 6], xid: u32) {
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
    // FLAGS: broadcast bit set (0x8000)
    buf[OFF_FLAGS]     = 0x80;
    buf[OFF_FLAGS + 1] = 0x00;
    // CHADDR: our MAC in first 6 bytes (rest zero)
    buf[OFF_CHADDR..OFF_CHADDR + 6].copy_from_slice(mac);
    // Magic cookie
    buf[OFF_COOKIE..OFF_COOKIE + 4].copy_from_slice(&MAGIC_COOKIE);
}

/// Send DHCP DISCOVER via broadcast.
pub fn dhcp_discover() {
    let mac = crate::net_get_mac();
    // Fresh XID per exchange, and drop any server binding from a previous
    // attempt — the OFFER that answers *this* DISCOVER decides the server.
    let xid = new_xid();
    clear_server_id();
    let mut msg = [0u8; DHCP_MSG_SIZE];
    build_base_msg(&mut msg, &mac, xid);

    // Options
    let mut o = OFF_OPTS;
    // Option 53: DHCP Message Type = DISCOVER
    msg[o] = OPT_MSG_TYPE; msg[o + 1] = 1; msg[o + 2] = DHCP_DISCOVER; o += 3;
    // End
    msg[o] = OPT_END;

    // Send broadcast: src 0.0.0.0:68 → dst 255.255.255.255:67
    let src_ip  = [0u8; 4];
    let dst_ip  = [255u8; 4];
    let dst_mac = [0xFFu8; 6];

    // Build and send raw (bypass ARP — broadcast)
    use super::ethernet;
    use super::ip;
    let udp_len = UDP_HDR_SIZE + DHCP_MSG_SIZE;
    let ip_total = ip::IP_HDR_MIN + udp_len;
    let frame_len = ethernet::EthHdr::SIZE + ip_total;

    let mut frame = [0u8; ethernet::ETH_FRAME_MAX];
    if frame_len > frame.len() { return; }

    // IP header
    let mut ip_hdr = [0u8; ip::IP_HDR_MIN];
    ip::build_header(&mut ip_hdr, ip::IP_PROTO_UDP, &src_ip, &dst_ip, udp_len as u16);

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
    ip_payload[ip::IP_HDR_MIN + UDP_HDR_SIZE..ip::IP_HDR_MIN + UDP_HDR_SIZE + DHCP_MSG_SIZE].copy_from_slice(&msg);

    ethernet::build(&mut frame[..frame_len], &dst_mac, &mac,
                    ethernet::ETH_TYPE_IP, &ip_payload[..ip_total]);

    let _ = super::net_raw_send(&frame[..frame_len]);
    set_dhcp_state(DhcpState::Discovering);
    azos_drv_sys::kprintln!("[DHCP] DISCOVER sent");
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
    while o < data.len() {
        let opt = data[o];
        if opt == OPT_END { break; }
        if opt == 0 { o += 1; continue; } // padding: 1 byte, no length field

        // Independent iteration bound — see MAX_OPTIONS.  Counted only for
        // real TLVs: pad bytes advance `o` by 1 each and are already bounded
        // by `data.len()`, so charging them against the budget would only
        // risk truncating a legitimate, heavily-padded packet.
        seen += 1;
        if seen > MAX_OPTIONS { break; }

        // Need the length byte to exist before reading it.
        if o + 1 >= data.len() { break; }
        let len = data[o + 1] as usize;
        // Truncated option: the declared value runs past the packet.  Bail
        // out rather than clamping — a short read here would let a crafted
        // length splice adjacent option bytes into a field we act on.
        if o + 2 + len > data.len() { break; }
        let val = &data[o + 2..o + 2 + len];
        match opt {
            OPT_MSG_TYPE    if len >= 1 => { info.msg_type = val[0]; }
            OPT_SUBNET_MASK if len >= 4 => { info.subnet.copy_from_slice(&val[..4]); }
            OPT_ROUTER      if len >= 4 => { info.gateway.copy_from_slice(&val[..4]); }
            OPT_DNS         if len >= 4 => { info.dns.copy_from_slice(&val[..4]); }
            OPT_SERVER_ID   if len >= 4 => {
                info.server_id.copy_from_slice(&val[..4]);
                info.has_server_id = true;
                info.server_ip.copy_from_slice(&val[..4]);
            }
            _ => {}
        }
        // Advances by >= 2 even when len == 0, so a zero-length option can
        // never spin the loop in place.
        o += 2 + len;
    }
    Some(info)
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
    build_base_msg(&mut msg, &mac, xid);

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
    // End
    msg[o] = OPT_END;

    // Send broadcast (still using 0.0.0.0 as src until ACK)
    let src_ip  = [0u8; 4];
    let dst_ip  = [255u8; 4];
    let dst_mac = [0xFFu8; 6];

    use super::ethernet;
    use super::ip;
    let udp_len = UDP_HDR_SIZE + DHCP_MSG_SIZE;
    let ip_total = ip::IP_HDR_MIN + udp_len;
    let frame_len = ethernet::EthHdr::SIZE + ip_total;

    let mut frame = [0u8; ethernet::ETH_FRAME_MAX];
    if frame_len > frame.len() { return; }

    let mut ip_hdr = [0u8; ip::IP_HDR_MIN];
    ip::build_header(&mut ip_hdr, ip::IP_PROTO_UDP, &src_ip, &dst_ip, udp_len as u16);

    let mut udp_buf = [0u8; UDP_HDR_SIZE];
    udp_buf[0..2].copy_from_slice(&DHCP_CLIENT_PORT.to_be_bytes());
    udp_buf[2..4].copy_from_slice(&DHCP_SERVER_PORT.to_be_bytes());
    udp_buf[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp_buf[6..8].copy_from_slice(&[0, 0]);

    let mut ip_payload = [0u8; ip::ETH_MTU];
    ip_payload[..ip::IP_HDR_MIN].copy_from_slice(&ip_hdr);
    ip_payload[ip::IP_HDR_MIN..ip::IP_HDR_MIN + UDP_HDR_SIZE].copy_from_slice(&udp_buf);
    ip_payload[ip::IP_HDR_MIN + UDP_HDR_SIZE..ip::IP_HDR_MIN + UDP_HDR_SIZE + DHCP_MSG_SIZE].copy_from_slice(&msg);

    ethernet::build(&mut frame[..frame_len], &dst_mac, &mac,
                    ethernet::ETH_TYPE_IP, &ip_payload[..ip_total]);

    let _ = super::net_raw_send(&frame[..frame_len]);
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
    let bound = match accepted_server_id() {
        Some(id) => id,
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
    set_dhcp_state(DhcpState::Bound);
    azos_drv_sys::kprintln!(
        "[DHCP] ACK: bound to {}.{}.{}.{}  mask {}.{}.{}.{}  gw {}.{}.{}.{}",
        info.offered_ip[0], info.offered_ip[1], info.offered_ip[2], info.offered_ip[3],
        info.subnet[0], info.subnet[1], info.subnet[2], info.subnet[3],
        info.gateway[0], info.gateway[1], info.gateway[2], info.gateway[3],
    );
    true
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
