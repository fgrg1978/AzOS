// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DNS resolver — minimal A-record lookup over UDP (F05).
//!
//! Sends a DNS query to the configured DNS server (from DHCP) and waits
//! for a response. Caches the last successful result.

use super::udp;
use core::sync::atomic::{AtomicU32, Ordering};
use azos_rings::{Log, Writer};
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

/// AAAA record type (RFC 3596): an IPv6 address, 16 bytes of rdata.
const DNS_TYPE_AAAA: u16 = 28;

/// CNAME record type: the owner name is an alias of the name in the rdata.
const DNS_TYPE_CNAME: u16 = 5;

/// Aliases a lookup follows before it gives up. A chain longer than this, or
/// a loop, is not an answer.
pub const DNS_MAX_CNAME_HOPS: usize = 8;

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

/// DNS server IP (set by DHCP or manually): a latest-value cell, a `Log` of
/// one slot. Default: Google DNS.
static DNS_SERVER: Log<[u8; 4], 1> = Log::new([8, 8, 8, 8]);
/// `DNS_SERVER`'s one writer, taken on the first set. The lock orders the
/// setters and masks preemption for a store.
static DNS_SERVER_TX: SpinLock<Option<Writer<'static, [u8; 4], 1>>> = SpinLock::new(None);

/// Cached DNS entries.
struct DnsCacheEntry {
    name: [u8; DNS_MAX_NAME_LEN],
    name_len: u8,
    /// The record type the entry answers: A or AAAA. A name has one entry
    /// per type.
    qtype: u16,
    /// The address: an A record's four bytes in the first four, or the 16
    /// of an AAAA record.
    ip: [u8; 16],
    timestamp: u64,
    valid: bool,
}

impl DnsCacheEntry {
    const fn empty() -> Self {
        Self {
            name: [0; DNS_MAX_NAME_LEN],
            name_len: 0,
            qtype: 0,
            ip: [0; 16],
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
    /// The type asked for; an answer of any other type is not an answer.
    qtype:          u16,
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
            qtype:          0,
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
    DNS_SERVER_TX
        .lock()
        .get_or_insert_with(|| DNS_SERVER.writer().expect("DNS_SERVER: second writer"))
        .publish(ip);
}

/// Get the currently configured DNS server IP.
pub fn get_dns_server() -> [u8; 4] {
    DNS_SERVER.latest().1
}

/// Resolve a hostname to an IPv4 address, calling `yield_fn` every poll
/// instead of busy-spinning the hart for the whole timeout window.
/// Returns the IP or None on failure/timeout.
///
/// Checks cache first, then sends UDP query and polls for response. One query
/// is in flight at a time (`DNS_GATE`): a second caller waits its turn, with
/// `yield_fn`, for at most the query timeout. Callers: the kernel's NTP client
/// (`kernel/src/tasks/net_clients.rs`, the server's name) and the `Net`
/// interface's `resolve` op (`crates/core/syscall/src/net_host.rs`, toolbox
/// `host`).
pub fn resolve_with_yield(hostname: &str, yield_fn: fn()) -> Option<[u8; 4]> {
    let ip = resolve_type(hostname, DNS_TYPE_A, yield_fn)?;
    Some([ip[0], ip[1], ip[2], ip[3]])
}

/// Resolve `hostname` to an IPv6 address (an AAAA query), waiting as
/// [`resolve_with_yield`] does. The query travels to the configured server
/// over IPv4, like an A query: the record type is what differs, not the
/// transport. Caller: the `Net` interface's `resolve` op with family 6.
pub fn resolve_aaaa_with_yield(hostname: &str, yield_fn: fn()) -> Option<[u8; 16]> {
    resolve_type(hostname, DNS_TYPE_AAAA, yield_fn)
}

/// The cached answer for `hostname`/`qtype`, if one is younger than the TTL.
fn cached(hostname: &str, qtype: u16, now: u64) -> Option<[u8; 16]> {
    let cache = DNS_CACHE.lock();
    cache.iter().find(|e| {
        e.valid
            && e.name_len as usize == hostname.len()
            && &e.name[..e.name_len as usize] == hostname.as_bytes()
            && e.qtype == qtype
            && now.saturating_sub(e.timestamp) < DNS_CACHE_TTL_TICKS
    }).map(|e| e.ip)
}

/// Whether a resolution is in flight. Held from before the pending record is
/// armed to after it is disarmed, so two callers cannot overwrite each
/// other's question.
static DNS_GATE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The right to run the one resolution; released on drop, on every path.
struct DnsGate;

impl DnsGate {
    fn take() -> Option<DnsGate> {
        DNS_GATE
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| DnsGate)
    }
}

impl Drop for DnsGate {
    fn drop(&mut self) {
        DNS_GATE.store(false, Ordering::Release);
    }
}

/// One query of `qtype` (A or AAAA) and its answer; the address is 4 bytes in
/// the first four of the result for A, 16 for AAAA.
fn resolve_type(hostname: &str, qtype: u16, yield_fn: fn()) -> Option<[u8; 16]> {
    if hostname.is_empty() || hostname.len() > DNS_MAX_NAME_LEN {
        return None;
    }

    let timeout_ticks = azos_limits::NET_DNS_TIMEOUT_MS as u64
        * azos_drv_sys::timebase::TIMER_FREQ / 1000;

    if let Some(ip) = cached(hostname, qtype, azos_drv_sys::timebase::now()) {
        return Some(ip);
    }

    // One query in flight: `DNS_QUERY` is one slot. A caller that finds it
    // taken waits its turn, for as long as a query of its own would wait.
    let mut yield_fn = yield_fn;
    let gate_deadline = azos_drv_sys::timebase::now() + timeout_ticks;
    let _gate = loop {
        if let Some(g) = DnsGate::take() { break g; }
        if azos_drv_sys::timebase::now() >= gate_deadline { return None; }
        yield_fn();
    };

    // The caller ahead of us may have asked the same question.
    let now = azos_drv_sys::timebase::now();
    if let Some(ip) = cached(hostname, qtype, now) {
        return Some(ip);
    }

    // Build the query.  The encoded question lives at `query_buf[12..]`; we
    // keep a copy so the response's echoed question can be matched exactly.
    let tx_id = new_tx_id();
    let mut query_buf = [0u8; 128];
    let query_len = build_query(&mut query_buf, tx_id, hostname, qtype)?;
    let question_len = query_len - DNS_HDR_SIZE;
    if question_len > DNS_QUESTION_MAX { return None; }

    // A fresh source port for this query (RFC 5452 §9.2). Drawn before the
    // record is armed: `udp::port_bound` takes the socket table's lock, and
    // `DNS_QUERY` is never held across another lock in this function.
    let client_port = new_source_port()?;

    let server_ip = DNS_SERVER.latest().1;
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
        q.qtype          = qtype;
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
    let deadline = now + timeout_ticks;
    let mut answered = false;
    let mut result: Option<[u8; 16]> = None;
    // N7: the answer's `handle_response` wakes this task (see `crate::wait`).
    let armed = crate::wait::DNS_WAITERS.arm();
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
                result = parse_answer(&q.response[..q.response_len], tx_id, qtype);
            }
        }
        if answered { break; }
        armed.wait(deadline, &mut yield_fn);
    }

    // Disarm: from here on nothing is routed to the resolver and nothing may
    // latch a response. A reply to this port is now a datagram to a port
    // nobody holds.
    DNS_ACTIVE_PORT.store(0, Ordering::Release);
    { DNS_QUERY.lock().active = false; }

    let ip = result?; // no answer, or an answer we could not parse
    cache_result(hostname, qtype, ip, now);
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
    drop(q);
    // N7: the resolver waiting on this answer looks now (lock dropped above).
    crate::wait::DNS_WAITERS.notify();
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build a DNS A-record query. Returns query length or None.
fn build_query(buf: &mut [u8; 128], tx_id: u16, hostname: &str, qtype: u16) -> Option<usize> {
    // Header: ID, flags(RD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    buf[0..2].copy_from_slice(&tx_id.to_be_bytes());
    buf[2..4].copy_from_slice(&DNS_FLAG_RD.to_be_bytes());
    buf[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    // ANCOUNT, NSCOUNT, ARCOUNT = 0 (already zeroed)

    // Question: encode hostname as labels
    let mut pos = DNS_HDR_SIZE;
    for label in hostname.split('.') {
        // Room for this label, the root byte and QTYPE + QCLASS.
        if label.is_empty() || label.len() > 63 || pos + 1 + label.len() + 1 + 4 > 128 {
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
    buf[pos..pos + 2].copy_from_slice(&qtype.to_be_bytes());
    pos += 2;
    buf[pos..pos + 2].copy_from_slice(&DNS_CLASS_IN.to_be_bytes());
    pos += 2;

    Some(pos)
}

/// Parse a DNS response and return the first A record that answers the
/// question (see [`parse_answer`]: the owner name, CNAME chains), or `None`.
///
/// `pub` so the boot-time conformance checks can drive it with hand-built
/// bytes: this is a parser for data that arrives from a remote server, and
/// with `panic = "abort"` a reachable panic in here is a board reset an
/// off-path attacker can trigger. Testing it through `handle_response` would
/// only observe the cache, which cannot distinguish "rejected" from "parsed
/// wrongly and produced nothing".
pub fn parse_response(data: &[u8], expected_tx_id: u16) -> Option<[u8; 4]> {
    let ip = parse_answer(data, expected_tx_id, DNS_TYPE_A)?;
    Some([ip[0], ip[1], ip[2], ip[3]])
}

/// The AAAA counterpart of [`parse_response`]: the first AAAA record that
/// answers the question, whose rdata must be exactly 16 bytes and inside the
/// message.
pub fn parse_response_aaaa(data: &[u8], expected_tx_id: u16) -> Option<[u8; 16]> {
    parse_answer(data, expected_tx_id, DNS_TYPE_AAAA)
}

/// The first address record of `qtype` in a response that answers the
/// question, following the question name's aliases: A (4 bytes of rdata,
/// returned in the first four) or AAAA (16).
///
/// **An answer must be about the name asked.** A record counts only if its
/// owner name equals the name being looked for (ASCII case-insensitively,
/// RFC 4343): the question's name to start with, then, for each CNAME whose
/// owner is that name, the CNAME's target. At most [`DNS_MAX_CNAME_HOPS`]
/// aliases are followed, so a chain that loops (`a` to `b` to `a`) or runs on
/// is refused rather than chased. A record of another owner, another type, or
/// the right type with the wrong rdata length is skipped, not taken: a server
/// (or a forger who got the transaction ID and the port right) that adds
/// `evil.example A 6.6.6.6` to an answer for `host.example` gets nothing.
fn parse_answer(data: &[u8], expected_tx_id: u16, qtype: u16) -> Option<[u8; 16]> {
    if data.len() < DNS_HDR_SIZE { return None; }

    let tx_id = u16::from_be_bytes([data[0], data[1]]);
    if tx_id != expected_tx_id { return None; }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & DNS_FLAG_QR == 0 { return None; } // not a response
    let rcode = flags & 0x000F;
    if rcode != 0 { return None; } // error

    // One question, as `handle_response` also requires: the walk below skips
    // exactly one, and a count that says otherwise puts the answers elsewhere.
    if u16::from_be_bytes([data[4], data[5]]) != 1 { return None; }
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 { return None; }

    // The question: a name, then QTYPE + QCLASS, all inside `data`. The name
    // is what the answers must be about.
    let mut want = Name::new();
    let mut pos = read_name(data, DNS_HDR_SIZE, &mut want)?;
    if pos + 4 > data.len() { return None; }
    pos += 4;

    // Walk the answers once per name: the first pass looks for the question's
    // name, each further pass for the target of the alias the last one found.
    // Records of a chain need not come in order.
    let mut hops = 0;
    loop {
        match scan_answers(data, pos, ancount, &want, qtype)? {
            Found::Address(ip) => return Some(ip),
            Found::Alias(target) => {
                hops += 1;
                if hops > DNS_MAX_CNAME_HOPS { return None; }
                want = target;
            }
            Found::Nothing => return None,
        }
    }
}

/// What one pass over the answer section found for a name.
enum Found {
    /// An address record of the asked type owned by the name.
    Address([u8; 16]),
    /// A CNAME owned by the name, and the name it points to.
    Alias(Name),
    /// Neither.
    Nothing,
}

/// One pass over the `ancount` records at `pos` for records owned by `want`:
/// the first address of `qtype`, or else the first alias. `None` when the
/// section is malformed. Each record takes at least 11 octets of the message
/// (a name, then 10 of header), so a huge ANCOUNT costs no more than the
/// message is long.
fn scan_answers(data: &[u8], mut pos: usize, ancount: u16, want: &Name, qtype: u16) -> Option<Found> {
    let want_len = if qtype == DNS_TYPE_AAAA { 16 } else { 4 };
    let mut alias: Option<Name> = None;
    let mut owner = Name::new();
    for _ in 0..ancount {
        pos = read_name(data, pos, &mut owner)?;
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2), then the rdata.
        if pos + 10 > data.len() { return None; }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;
        // The rdata must lie inside the message whatever its type: a length
        // that runs past the end ends the walk, it does not skip into the void.
        if rdlength > data.len() - pos { return None; }
        if rclass == DNS_CLASS_IN && owner == *want {
            if rtype == qtype && rdlength == want_len {
                let mut ip = [0u8; 16];
                ip[..want_len].copy_from_slice(&data[pos..pos + want_len]);
                // An answer naming no host, a group or this host is not an
                // address to connect to; it is skipped like a record of
                // another type, and a later good one still counts.
                if address_is_usable(&ip[..want_len]) { return Some(Found::Address(ip)); }
            } else if rtype == DNS_TYPE_CNAME && alias.is_none() {
                // The target is a name inside the rdata; it must end there.
                let mut target = Name::new();
                if read_name(data, pos, &mut target)? <= pos + rdlength {
                    alias = Some(target);
                }
            }
        }
        pos += rdlength;
    }
    Some(alias.map_or(Found::Nothing, Found::Alias))
}

/// A domain name in a flat form that compares: the labels as on the wire
/// (length octet, then the label), without the root, ASCII-lowercased. A
/// length octet is at most 63 and so is not a letter: lowercasing the whole
/// buffer cannot change one.
#[derive(Clone)]
struct Name {
    buf: [u8; 255],
    len: usize,
}

impl Name {
    const fn new() -> Self {
        Name { buf: [0; 255], len: 0 }
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Name) -> bool {
        self.buf[..self.len] == other.buf[..other.len]
    }
}

/// Decode the name at `pos` into `out`, following compression pointers, and
/// return the offset just past it in the record it belongs to (RFC 1035
/// §3.1, §4.1.4).
///
/// A pointer must point strictly backwards and past the header, as the RFC's
/// "prior occurrence" requires; a forward or self pointer is how loops are
/// written, and is refused. Labels may still lead back to the same pointer
/// from further on, so the walk is also bounded by the 255 octets a name may
/// have (RFC 1035 §2.3.4): every pass round such a cycle adds a label to
/// `out`, and the name is refused when it no longer fits. The label types with
/// top bits `01` and `10` are reserved (RFC 1035 §4.1.4) and refused. Only the
/// pointer's own bytes belong to the record: the offset returned is past the
/// first pointer, and the name it points to is read, never skipped.
fn read_name(data: &[u8], pos: usize, out: &mut Name) -> Option<usize> {
    out.len = 0;
    let mut p = pos;
    let mut end = None;
    loop {
        let b = *data.get(p)?;
        match b & 0xC0 {
            0x00 => {
                if b == 0 { return Some(end.unwrap_or(p + 1)); }
                let len = b as usize;
                // The label and its length octet must fit the message and the name.
                if p + 1 + len > data.len() || out.len + 1 + len > out.buf.len() { return None; }
                out.buf[out.len] = b;
                for (d, s) in out.buf[out.len + 1..out.len + 1 + len].iter_mut().zip(&data[p + 1..p + 1 + len]) {
                    *d = s.to_ascii_lowercase();
                }
                out.len += 1 + len;
                p += 1 + len;
            }
            0xC0 => {
                let lo = *data.get(p + 1)?;
                let target = (((b & 0x3F) as usize) << 8) | lo as usize;
                if target < DNS_HDR_SIZE || target >= p { return None; }
                if end.is_none() { end = Some(p + 2); }
                p = target;
            }
            _ => return None, // reserved label types
        }
    }
}

/// True for an A (4 octets) or AAAA (16) address a resolver may hand out:
/// not in 0.0.0.0/8 or ::/8 (unspecified, loopback, IPv4-compatible), not loopback, not multicast (and, for IPv4, not the
/// reserved/broadcast range). A name that "resolves" to one of those is a
/// rebinding trick against whatever connects to the result.
fn address_is_usable(a: &[u8]) -> bool {
    match a.len() {
        4 => a[0] != 0 && a[0] != 127 && a[0] < 224,
        16 => {
            a[0] != 0x00 && a[0] != 0xFF
        }
        _ => false,
    }
}

/// Cache a DNS result.
fn cache_result(hostname: &str, qtype: u16, ip: [u8; 16], now: u64) {
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
    entry.qtype = qtype;
    entry.ip = ip;
    entry.timestamp = now;
    entry.valid = true;
}
