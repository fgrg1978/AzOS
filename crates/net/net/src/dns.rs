// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DNS resolver — minimal A-record lookup over UDP (F05).
//!
//! Sends a DNS query to the configured DNS server (from DHCP) and waits
//! for a response. Caches the last successful result.

use super::udp;
use core::sync::atomic::{AtomicU32, Ordering};
use azos_sync::SpinLock;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// DNS server port.
const DNS_SERVER_PORT: u16 = 53;

/// Maximum DNS response size we handle.
const DNS_MAX_RESPONSE: usize = 512;

/// DNS query type A (IPv4 address).
const DNS_TYPE_A: u16 = 1;

/// DNS query class IN (Internet).
const DNS_CLASS_IN: u16 = 1;

/// Maximum hostname length.
const DNS_MAX_NAME_LEN: usize = 63;

/// DNS header size in bytes.
const DNS_HDR_SIZE: usize = 12;

/// Maximum number of cached DNS entries. Kconfig `DNS_CACHE_SIZE` (default 4).
const DNS_CACHE_SIZE: usize = azos_limits::DNS_CACHE_SIZE;

/// Maximum size of the encoded question section we keep for echo matching:
/// a `DNS_MAX_NAME_LEN`-byte name encodes to at most `len + 2` bytes of
/// labels, plus 4 bytes of QTYPE/QCLASS.  80 leaves headroom.
const DNS_QUESTION_MAX: usize = 80;

/// FNV-1a constants for the transaction-ID mixer (see `new_tx_id`).
const FNV_OFFSET_BASIS: u32 = 0x811C_9DC5;
const FNV_PRIME:        u32 = 0x0100_0193;

/// DNS cache entry TTL in CLINT ticks (5 minutes).
const DNS_CACHE_TTL_TICKS: u64 = 5 * 60 * azos_drv_sys::timebase::TIMER_FREQ;

// ---------------------------------------------------------------------------
// DNS header flags
// ---------------------------------------------------------------------------

/// QR bit: this is a response.
const DNS_FLAG_QR: u16 = 1 << 15;
/// RD bit: recursion desired.
const DNS_FLAG_RD: u16 = 1 << 8;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// DNS server IP (set by DHCP or manually).
static mut DNS_SERVER: [u8; 4] = [8, 8, 8, 8]; // default: Google DNS

/// Cached DNS entries.
struct DnsCacheEntry {
    name: [u8; DNS_MAX_NAME_LEN],
    name_len: u8,
    ip: [u8; 4],
    timestamp: u64,
    valid: bool,
}

impl DnsCacheEntry {
    const fn empty() -> Self {
        Self {
            name: [0; DNS_MAX_NAME_LEN],
            name_len: 0,
            ip: [0; 4],
            timestamp: 0,
            valid: false,
        }
    }
}

static DNS_CACHE: SpinLock<[DnsCacheEntry; DNS_CACHE_SIZE]> = SpinLock::new({
    const EMPTY: DnsCacheEntry = DnsCacheEntry::empty();
    [EMPTY; DNS_CACHE_SIZE]
});

/// The single in-flight query, and the answer that matched it.
///
/// Everything in here exists to answer one question: *did this datagram come
/// back from the server we asked, in reply to the question we asked?*  The
/// previous version could not answer it — it kept only a `0x1234 + n`
/// transaction ID and latched whatever arrived on port 5353 — so one spoofed
/// UDP packet, from any source, poisoned the next resolution for the whole
/// 5-minute cache TTL.
struct DnsQuery {
    /// True only between sending a query and finishing with its answer.
    /// An unsolicited response arriving outside that window is discarded:
    /// there is nothing it could be an answer to.
    active:         bool,
    /// Transaction ID of the outstanding query (`new_tx_id`, runtime entropy).
    tx_id:          u16,
    /// Server we sent it to — a response from anyone else is not ours.
    server_ip:      [u8; 4],
    /// Port we sent it to; the reply must come back from it.
    server_port:    u16,
    /// Our source port for this query (`new_source_port`); the reply must be
    /// addressed to it.
    client_port:    u16,
    /// The encoded question section exactly as transmitted, so the response's
    /// echoed question can be compared byte for byte.  Off-path forgery has to
    /// reproduce this as well as the ID, and it is what stops an answer for
    /// one name being accepted as the answer for another.
    question:       [u8; DNS_QUESTION_MAX],
    question_len:   usize,
    /// The first response that passed every check above.
    response:       [u8; DNS_MAX_RESPONSE],
    response_len:   usize,
    response_ready: bool,
}

impl DnsQuery {
    const fn new() -> Self {
        Self {
            active:         false,
            tx_id:          0,
            server_ip:      [0; 4],
            server_port:    0,
            client_port:    0,
            question:       [0; DNS_QUESTION_MAX],
            question_len:   0,
            response:       [0; DNS_MAX_RESPONSE],
            response_len:   0,
            response_ready: false,
        }
    }
}

static DNS_QUERY: SpinLock<DnsQuery> = SpinLock::new(DnsQuery::new());

/// Source port of the outstanding query; 0 while none is outstanding.
///
/// `udp::dispatch` reads it for every datagram it receives, ahead of the
/// socket table, so it is an atomic and not a look into `DNS_QUERY`: that
/// lock on every UDP datagram would put the resolver on the receive path of
/// all UDP traffic. It only routes. `handle_response` checks the port again
/// under the lock, against the query it is actually matching.
static DNS_ACTIVE_PORT: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);

/// The port `udp::dispatch` hands to [`handle_response`], or 0 for none.
pub fn active_port() -> u16 {
    DNS_ACTIVE_PORT.load(Ordering::Acquire)
}

/// RFC 5452 §9.2: source ports come from "53, or 1024 and above", from a
/// range "as large as possible and practicable". 53 is left out: it is the
/// server port, and a query leaving from it looks like a server's answer.
const DNS_SOURCE_PORT_MIN: u16 = 1024;
/// How many ports `DNS_SOURCE_PORT_MIN..=65535` holds.
const DNS_SOURCE_PORT_SPAN: u64 = 65536 - DNS_SOURCE_PORT_MIN as u64;
/// mDNS (RFC 6762). The resolver used to send every query from it.
const MDNS_PORT: u16 = 5353;
/// Draws before `new_source_port` gives up. At most `UDP_MAX_SOCKETS` + 2 of
/// the 64 512 ports are ever refused, so eight misses in a row do not happen
/// by chance.
const DNS_SOURCE_PORT_DRAWS: usize = 8;

/// Per-boot query counter — keeps two IDs minted in the same tick distinct.
static DNS_TX_SEQ: AtomicU32 = AtomicU32::new(0);

/// Mint a transaction ID from runtime entropy.
///
/// From the kernel entropy pool when a seeded source is installed (see
/// [`runtime_entropy`]).  Entropy honesty for the fallback, same as
/// `dhcp::counter_xid`: **counters, not a TRNG.**  The value is then derived
/// from `rdcycle`, the CLINT `mtime` counter and a per-boot sequence,
/// avalanched so the few live bits reach all 16.  That is
/// enough to stop the attack the old `0x1234 + n` counter allowed outright —
/// reading the binary told you every future ID — but it is not cryptographic
/// randomness, and an attacker who can observe our traffic or bound our boot
/// instant can still shrink the space.  The source pin and question echo in
/// `handle_response` are what carry the real weight; the ID is one factor of
/// several, which is exactly the posture RFC 5452 asks for.
fn new_tx_id() -> u16 {
    let h = runtime_entropy();
    // Fold both halves in so the 16-bit result keeps the whole avalanche.
    ((h >> 16) ^ h) as u16
}

/// Pick the source port for one query (RFC 5452 §9.2).
///
/// A fresh port per query from `1024..=65535`, never 5353 (mDNS), never the
/// NTP client port that `udp::dispatch` intercepts, and never a port a socket
/// is bound to. `None` only if every draw hit one of those.
///
/// **Unpredictability.** The draw comes from `runtime_entropy`, the same
/// source as the TCP ISN's secret: the entropy pool when it is seeded,
/// runtime counters (`rdcycle`, `mtime`) mixed when it is not. On the counter
/// path the port is only as unpredictable as those counters; it widens what a
/// blind forger must guess by up to 16 bits beside the ID, and claims nothing
/// beyond that.
fn new_source_port() -> Option<u16> {
    for _ in 0..DNS_SOURCE_PORT_DRAWS {
        // Multiply-shift onto the span rather than `%`, which would favour
        // the low ports. `< DNS_SOURCE_PORT_SPAN`, so the sum stays <= 65535.
        let off = (runtime_entropy() as u64 * DNS_SOURCE_PORT_SPAN) >> 32;
        let port = DNS_SOURCE_PORT_MIN + off as u16;
        if port != MDNS_PORT && port != udp::NTP_CLIENT_PORT && !udp::port_bound(port) {
            return Some(port);
        }
    }
    None
}

/// 32 bits for an ID or a port draw: from the kernel entropy pool through
/// `crate::net_random_fill` when a seeded source is installed; otherwise
/// avalanched `rdcycle`, `mtime` and a per-boot sequence — see the entropy
/// note on [`new_tx_id`]: runtime-unpredictable, not random.
fn runtime_entropy() -> u32 {
    let mut pool = [0u8; 4];
    if crate::net_random_fill(&mut pool) {
        return u32::from_le_bytes(pool);
    }
    let cycles = azos_drv_sys::wcet::read_cycles();
    let mtime  = azos_drv_sys::timebase::now();
    let seq    = DNS_TX_SEQ.fetch_add(1, Ordering::Relaxed);

    // All arithmetic explicitly wrapping: release builds run with
    // `overflow-checks = true` and any panic here is a full board reset.
    let mut h = FNV_OFFSET_BASIS;
    for b in cycles.to_le_bytes().iter()
        .chain(mtime.to_le_bytes().iter())
        .chain(seq.to_le_bytes().iter())
    {
        h ^= *b as u32;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h ^= h >> 16;
    h  = h.wrapping_mul(0x7FEB_352D);
    h ^= h >> 15;
    h  = h.wrapping_mul(0x846C_A68B);
    h ^= h >> 16;
    h
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Set the DNS server IP address (called by DHCP on lease).
pub fn set_dns_server(ip: [u8; 4]) {
    unsafe { DNS_SERVER = ip; }
}

/// Get the currently configured DNS server IP.
pub fn get_dns_server() -> [u8; 4] {
    unsafe { DNS_SERVER }
}

/// [`resolve`], busy-spinning the hart while it waits (`core::hint::spin_loop`).
///
/// M24 / U06-8: kept only for source compatibility with whatever ring-0
/// caller cannot yield; every ring-3 syscall path (`SYS_DNS_RESOLVE`) should
/// call [`resolve_with_yield`] instead, the same way `dhcp_start` takes a
/// `yield_fn` (U06-3) rather than pinning the hart. This still parks the
/// caller's hart in S-mode for up to 2 s with nothing else able to run on
/// it.
pub fn resolve(hostname: &str) -> Option<[u8; 4]> {
    resolve_with_yield(hostname, core::hint::spin_loop)
}

/// Resolve a hostname to an IPv4 address, calling `yield_fn` every poll
/// instead of busy-spinning the hart for the whole timeout window.
/// Returns the IP or None on failure/timeout.
///
/// Checks cache first, then sends UDP query and polls for response.
pub fn resolve_with_yield(hostname: &str, yield_fn: fn()) -> Option<[u8; 4]> {
    if hostname.is_empty() || hostname.len() > DNS_MAX_NAME_LEN {
        return None;
    }

    let now = azos_drv_sys::timebase::now();

    // Check cache
    {
        let cache = DNS_CACHE.lock();
        for entry in cache.iter() {
            if entry.valid
                && entry.name_len as usize == hostname.len()
                && &entry.name[..entry.name_len as usize] == hostname.as_bytes()
                && now.saturating_sub(entry.timestamp) < DNS_CACHE_TTL_TICKS
            {
                return Some(entry.ip);
            }
        }
    }

    // Build the query.  The encoded question lives at `query_buf[12..]`; we
    // keep a copy so the response's echoed question can be matched exactly.
    let tx_id = new_tx_id();
    let mut query_buf = [0u8; 128];
    let query_len = build_query(&mut query_buf, tx_id, hostname)?;
    let question_len = query_len - DNS_HDR_SIZE;
    if question_len > DNS_QUESTION_MAX { return None; }

    // A fresh source port for this query (RFC 5452 §9.2). Drawn before the
    // record is armed: `udp::port_bound` takes the socket table's lock, and
    // `DNS_QUERY` is never held across another lock in this function.
    let client_port = new_source_port()?;

    let server_ip = unsafe { DNS_SERVER };
    let (mac, our_ip) = (super::net_get_mac(), super::net_get_ip());

    // Arm the pending record BEFORE transmitting: the reply can arrive inside
    // the very first `net_poll()` below, and `handle_response` refuses
    // anything that does not match an armed query.
    {
        let mut q = DNS_QUERY.lock();
        q.tx_id          = tx_id;
        q.server_ip      = server_ip;
        q.server_port    = DNS_SERVER_PORT;
        q.client_port    = client_port;
        q.question[..question_len]
            .copy_from_slice(&query_buf[DNS_HDR_SIZE..query_len]);
        q.question_len   = question_len;
        q.response_len   = 0;
        q.response_ready = false;
        q.active         = true;
    }
    // Route to `handle_response` only once the record it checks against exists.
    DNS_ACTIVE_PORT.store(client_port, Ordering::Release);

    // Send query via raw UDP (don't need a socket)
    udp::send_raw(&mac, &our_ip, &server_ip,
                   client_port, DNS_SERVER_PORT,
                   &query_buf[..query_len]);

    // Poll for response (up to 2 seconds).
    //
    // NOTE: `DNS_QUERY` must never be held across `net_poll()` — that call
    // reaches `handle_response`, which takes the same non-reentrant spinlock,
    // and the hart would spin on itself forever.  Every access below is
    // therefore in its own scope.
    let timeout_ticks = 2 * azos_drv_sys::timebase::TIMER_FREQ; // 2 seconds
    let deadline = now + timeout_ticks;
    let mut answered = false;
    let mut result: Option<[u8; 4]> = None;
    while azos_drv_sys::timebase::now() < deadline {
        super::net_poll();
        {
            // Parsing under the lock is fine — it is a pure function that
            // cannot re-enter the stack.  It also avoids copying the 512-byte
            // response onto a 16 KiB kernel stack that `net_poll` has already
            // used several KiB of.
            let q = DNS_QUERY.lock();
            if q.response_ready {
                answered = true;
                // `handle_response` already matched the ID, source and
                // question; the ID is re-checked inside `parse_response` so
                // that parsing stays correct on its own terms.
                result = parse_response(&q.response[..q.response_len], tx_id);
            }
        }
        if answered { break; }
        yield_fn();
    }

    // Disarm: from here on nothing is routed to the resolver and nothing may
    // latch a response. A reply to this port is now a datagram to a port
    // nobody holds.
    DNS_ACTIVE_PORT.store(0, Ordering::Release);
    { DNS_QUERY.lock().active = false; }

    let ip = result?; // no answer, or an answer we could not parse
    cache_result(hostname, ip, now);
    Some(ip)
}

/// Handle an incoming DNS response (called from `udp::dispatch` for the
/// outstanding query's source port), with the datagram's source endpoint and
/// the port it was addressed to.
///
/// Accepts a datagram only if all of the following hold:
///   * a query is currently outstanding (`active`) and unanswered,
///   * it was addressed to that query's source port,
///   * it came from the IP and port we sent that query to,
///   * its transaction ID matches,
///   * the QR bit is set and QDCOUNT is 1,
///   * the echoed question is byte-identical to the one we asked.
///
/// Any one of these failing means the datagram is not an answer to our
/// question, whatever it claims to be.  The endpoints come from
/// `udp::dispatch` because a destination port alone identifies nothing — it
/// is the one field every off-path forgery aims at.
pub fn handle_response(src_ip: &[u8; 4], src_port: u16, dst_port: u16, data: &[u8]) {
    if data.len() < DNS_HDR_SIZE || data.len() > DNS_MAX_RESPONSE {
        return;
    }

    let mut q = DNS_QUERY.lock();

    // No question outstanding → this cannot be an answer.
    if !q.active { return; }
    // First valid answer wins.  Without this a forgery racing behind a genuine
    // reply could still overwrite it in the window before `resolve` reads it.
    if q.response_ready { return; }

    // `dispatch` routed on `DNS_ACTIVE_PORT`, read without this lock. A query
    // that ended and a new one armed on another port in between would pass
    // that read; this is the check that holds.
    if dst_port != q.client_port { return; }

    if src_ip != &q.server_ip || src_port != q.server_port { return; }

    if u16::from_be_bytes([data[0], data[1]]) != q.tx_id { return; }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & DNS_FLAG_QR == 0 { return; }          // a query, not a response
    if u16::from_be_bytes([data[4], data[5]]) != 1 { return; } // QDCOUNT != 1

    let q_end = DNS_HDR_SIZE + q.question_len;
    if data.len() < q_end { return; }
    if data[DNS_HDR_SIZE..q_end] != q.question[..q.question_len] { return; }

    let n = data.len();
    q.response[..n].copy_from_slice(data);
    q.response_len   = n;
    q.response_ready = true;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build a DNS A-record query. Returns query length or None.
fn build_query(buf: &mut [u8; 128], tx_id: u16, hostname: &str) -> Option<usize> {
    // Header: ID, flags(RD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    buf[0..2].copy_from_slice(&tx_id.to_be_bytes());
    buf[2..4].copy_from_slice(&DNS_FLAG_RD.to_be_bytes());
    buf[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    // ANCOUNT, NSCOUNT, ARCOUNT = 0 (already zeroed)

    // Question: encode hostname as labels
    let mut pos = DNS_HDR_SIZE;
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 || pos + 1 + label.len() >= 128 {
            return None;
        }
        buf[pos] = label.len() as u8;
        pos += 1;
        buf[pos..pos + label.len()].copy_from_slice(label.as_bytes());
        pos += label.len();
    }
    buf[pos] = 0; // null terminator
    pos += 1;

    // QTYPE = A (1), QCLASS = IN (1)
    buf[pos..pos + 2].copy_from_slice(&DNS_TYPE_A.to_be_bytes());
    pos += 2;
    buf[pos..pos + 2].copy_from_slice(&DNS_CLASS_IN.to_be_bytes());
    pos += 2;

    Some(pos)
}

/// Parse a DNS response and extract the first A record IP.
/// Parse a DNS response and return the first A record, or `None`.
///
/// `pub` so the boot-time conformance checks can drive it with hand-built
/// bytes: this is a parser for data that arrives from a remote server, and
/// with `panic = "abort"` a reachable panic in here is a board reset an
/// off-path attacker can trigger. Testing it through `handle_response` would
/// only observe the cache, which cannot distinguish "rejected" from "parsed
/// wrongly and produced nothing".
pub fn parse_response(data: &[u8], expected_tx_id: u16) -> Option<[u8; 4]> {
    if data.len() < DNS_HDR_SIZE { return None; }

    let tx_id = u16::from_be_bytes([data[0], data[1]]);
    if tx_id != expected_tx_id { return None; }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & DNS_FLAG_QR == 0 { return None; } // not a response
    let rcode = flags & 0x000F;
    if rcode != 0 { return None; } // error

    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 { return None; }

    // Skip question section
    let mut pos = DNS_HDR_SIZE;
    // Skip name (labels until null or pointer)
    pos = skip_name(data, pos)?;
    pos += 4; // QTYPE + QCLASS

    // Parse answer records
    for _ in 0..ancount {
        if pos >= data.len() { return None; }
        pos = skip_name(data, pos)?;
        if pos + 10 > data.len() { return None; }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]);
        pos += 10;
        if rtype == DNS_TYPE_A && rdlength == 4 && pos + 4 <= data.len() {
            return Some([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        }
        pos += rdlength as usize;
    }

    None
}

/// Skip a DNS name (handles both labels and compression pointers).
fn skip_name(data: &[u8], mut pos: usize) -> Option<usize> {
    let max_jumps = 10; // prevent infinite loops
    let mut jumps = 0;
    let mut first_end = None;

    loop {
        if pos >= data.len() || jumps > max_jumps { return None; }
        let b = data[pos];
        if b == 0 {
            pos += 1;
            break;
        }
        if b & 0xC0 == 0xC0 {
            // Compression pointer
            if first_end.is_none() {
                first_end = Some(pos + 2);
            }
            if pos + 1 >= data.len() { return None; }
            pos = ((b as usize & 0x3F) << 8) | data[pos + 1] as usize;
            jumps += 1;
        } else {
            pos += 1 + b as usize;
        }
    }

    Some(first_end.unwrap_or(pos))
}

/// Cache a DNS result.
fn cache_result(hostname: &str, ip: [u8; 4], now: u64) {
    let mut cache = DNS_CACHE.lock();
    // Find oldest or free slot
    let mut oldest_idx = 0;
    let mut oldest_ts = u64::MAX;
    for i in 0..DNS_CACHE_SIZE {
        if !cache[i].valid {
            oldest_idx = i;
            break;
        }
        if cache[i].timestamp < oldest_ts {
            oldest_ts = cache[i].timestamp;
            oldest_idx = i;
        }
    }
    let entry = &mut cache[oldest_idx];
    let name_len = hostname.len().min(DNS_MAX_NAME_LEN);
    entry.name[..name_len].copy_from_slice(&hostname.as_bytes()[..name_len]);
    entry.name_len = name_len as u8;
    entry.ip = ip;
    entry.timestamp = now;
    entry.valid = true;
}
