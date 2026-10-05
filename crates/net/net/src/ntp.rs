// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SNTP client — Simple Network Time Protocol (RFC 4330, F05.2).
//!
//! Sends a unicast SNTP request to the configured NTP server and adjusts
//! the kernel's wall-clock offset so that callers can compute Unix time.
//!
//! # Design
//!
//! - Pure UDP, no TCP dependency.
//! - Single-request / single-response (SNTP, not full NTP).
//! - Stores `(ntp_seconds, clint_ticks_at_sync)` — from these two values,
//!   `ntp_now()` computes current Unix seconds without further syscalls.
//! - Retry on timeout with exponential backoff.
//! - NTP server is set by DHCP (F05.3) or defaults to pool.ntp.org IP below.

use super::udp;
use core::sync::atomic::{AtomicU32, Ordering};
use azos_sync::SpinLock;

// ── Constants ────────────────────────────────────────────────────────────────

/// UDP port for NTP.
const NTP_PORT: u16 = 123;

/// Client source port for NTP queries (ephemeral).
const NTP_CLIENT_PORT: u16 = 1123;

/// NTP packet size (48 bytes, no authentication).
const NTP_PKT_SIZE: usize = 48;

/// Offset of the transmit timestamp in an NTP packet (seconds, big-endian u32).
const NTP_TRANSMIT_TS_OFFSET: usize = 40;

/// Offset of the originate timestamp in an NTP packet (RFC 5905 §7.3).
/// A server copies the client's transmit timestamp verbatim into this field,
/// which is what makes it usable as an anti-spoofing nonce.
const NTP_ORIGINATE_TS_OFFSET: usize = 24;

/// Length of an NTP timestamp (32-bit seconds + 32-bit fraction).
const NTP_TS_LEN: usize = 8;

/// Offset of the stratum byte.
const NTP_STRATUM_OFFSET: usize = 1;

/// FNV-1a constants for the transmit-timestamp nonce mixer.
const FNV_OFFSET_BASIS: u64 = 0xCBF2_9CE4_8422_2325;
const FNV_PRIME:        u64 = 0x0000_0100_0000_01B3;

/// NTP era offset: seconds between NTP epoch (1900-01-01) and Unix epoch (1970-01-01).
const NTP_UNIX_EPOCH_OFFSET: u32 = 2_208_988_800;

/// Earliest era-0 NTP timestamp we will accept: 2020-01-01 (Unix 1_577_836_800).
/// No build of this kernel predates it, so an earlier "current time" is
/// never legitimate. Era 0 only: every era-1 second is 2036 or later.
const NTP_MIN_PLAUSIBLE_SEC: u32 = NTP_UNIX_EPOCH_OFFSET + 1_577_836_800;

/// Bit 0 (the most significant bit) of the Transmit Timestamp seconds.
/// RFC 4330 §3: set, the time is in 1968-2036, reckoned from 1900-01-01
/// (era 0); clear, it is in 2036-2104, reckoned from 2036-02-07T06:28:16Z
/// (era 1).
const NTP_ERA0_BIT: u32 = 0x8000_0000;

/// LI=0 (no leap), VN=4 (NTPv4), Mode=3 (client): byte 0 = 0b00_100_011.
const NTP_FLAGS_CLIENT: u8 = 0b00_100_011;

/// Timeout for a single NTP response poll (2 seconds in CLINT ticks at 10 MHz).
const NTP_TIMEOUT_TICKS: u64 = 20_000_000;

/// Maximum retry attempts before giving up.
const NTP_MAX_RETRIES: u32 = 3;

/// Backoff multiplier between retries (ticks added per retry).
const NTP_RETRY_BACKOFF_TICKS: u64 = azos_drv_sys::timebase::TIMER_FREQ; // +1 second per retry

/// CLINT timer frequency (10 MHz on QEMU/VF2).
const NTP_CLINT_FREQ: u64 = azos_drv_sys::timebase::TIMER_FREQ;

/// Default NTP server: time.cloudflare.com = 162.159.200.1
const NTP_DEFAULT_SERVER: [u8; 4] = [162, 159, 200, 1];

// ── State ────────────────────────────────────────────────────────────────────

struct NtpState {
    /// NTP server IP.
    server: [u8; 4],
    /// Unix timestamp (seconds) at last successful sync.
    synced_unix_sec: u32,
    /// CLINT ticks at last successful sync.
    synced_clint_ticks: u64,
    /// Whether we have a valid sync.
    valid: bool,
    /// Pending response flag (set by handle_response).
    response_ready: bool,
    /// Last received NTP packet.
    response_buf: [u8; NTP_PKT_SIZE],
    /// True only while a request is outstanding.  A response arriving outside
    /// that window is not an answer to anything and is discarded.
    awaiting: bool,
    /// The nonce we put in the request's transmit-timestamp field.
    ///
    /// SNTP's only anti-spoofing mechanism (RFC 4330 §5) is that the server
    /// echoes this back in the originate field: a response that does not carry
    /// it did not come from a host that saw our request.  The old code sent an
    /// all-zero transmit timestamp, so the check was not merely skipped — it
    /// was *impossible*, and any host on the path could set the robot's wall
    /// clock to any value after 1970.
    tx_nonce: [u8; NTP_TS_LEN],
}

impl NtpState {
    const fn new() -> Self {
        NtpState {
            server: NTP_DEFAULT_SERVER,
            synced_unix_sec: 0,
            synced_clint_ticks: 0,
            valid: false,
            response_ready: false,
            response_buf: [0; NTP_PKT_SIZE],
            awaiting: false,
            tx_nonce: [0; NTP_TS_LEN],
        }
    }
}

/// Per-boot request counter — keeps two nonces minted in the same tick apart.
static NONCE_SEQ: AtomicU32 = AtomicU32::new(0);

/// Mint the 64-bit transmit-timestamp nonce for one request.
///
/// From the kernel entropy pool when a seeded source is installed.  Otherwise,
/// entropy honesty as in `dhcp::counter_xid`: **counters, not a TRNG.**
/// The value then mixes `rdcycle`, CLINT `mtime` and a per-boot counter through
/// FNV-1a plus an avalanche.  It is not cryptographic randomness, but it is
/// not recoverable from the binary, which is the bar blind off-path forgery
/// has to clear.  Combined with the source-address pin in `handle_response`,
/// an attacker must both be able to reach us from the server's address and
/// guess 64 bits.
fn new_tx_nonce() -> [u8; NTP_TS_LEN] {
    let mut pool = [0u8; NTP_TS_LEN];
    if crate::net_random_fill(&mut pool) {
        return pool;
    }
    let cycles = azos_drv_sys::wcet::read_cycles();
    let mtime  = azos_drv_sys::timebase::now();
    let seq    = NONCE_SEQ.fetch_add(1, Ordering::Relaxed);

    // Explicitly wrapping throughout: release builds run with
    // `overflow-checks = true` and a panic here is a full board reset.
    let mut h = FNV_OFFSET_BASIS;
    for b in cycles.to_le_bytes().iter()
        .chain(mtime.to_le_bytes().iter())
        .chain(seq.to_le_bytes().iter())
    {
        h ^= *b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h ^= h >> 33;
    h  = h.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    h ^= h >> 33;
    h  = h.wrapping_mul(0xC4CE_B9FE_1A85_EC53);
    h ^= h >> 33;
    h.to_be_bytes()
}

static NTP: SpinLock<NtpState> = SpinLock::new(NtpState::new());

// ── Public API ────────────────────────────────────────────────────────────────

/// Set the NTP server address (called by DHCP on lease, or manually).
pub fn set_ntp_server(ip: [u8; 4]) {
    NTP.lock().server = ip;
}

/// Get the currently configured NTP server.
pub fn get_ntp_server() -> [u8; 4] {
    NTP.lock().server
}

/// [`ntp_sync`], busy-spinning the hart while it waits
/// (`core::hint::spin_loop`).
///
/// M24 / U06-8: kept only for source compatibility with whatever ring-0
/// caller cannot yield; every ring-3 syscall path (`SYS_NTP_SYNC`) should
/// call [`ntp_sync_with_yield`] instead, the same way `dhcp_start` takes a
/// `yield_fn` (U06-3). This still parks the caller's hart in S-mode for up
/// to `NTP_MAX_RETRIES * (2 + retry)` seconds with nothing else able to run
/// on it.
pub fn ntp_sync() -> u32 {
    ntp_sync_with_yield(core::hint::spin_loop)
}

/// Synchronize the kernel wall clock with the NTP server, calling `yield_fn`
/// every poll instead of busy-spinning the hart for the whole timeout
/// window.
///
/// Blocks the calling task for up to `NTP_MAX_RETRIES * (2 + retry)` seconds.
/// Returns the Unix timestamp on success, or 0 on failure.
pub fn ntp_sync_with_yield(yield_fn: fn()) -> u32 {
    let (mac, our_ip, server) = {
        let ntp = NTP.lock();
        (super::net_get_mac(), super::net_get_ip(), ntp.server)
    };

    let mut pkt = [0u8; NTP_PKT_SIZE];
    pkt[0] = NTP_FLAGS_CLIENT;
    // All other fields zero (valid for SNTP client request) except the
    // transmit timestamp, filled per attempt below.

    for attempt in 0..NTP_MAX_RETRIES {
        // Fresh nonce per attempt: a late reply to attempt N must not be
        // accepted as the reply to attempt N+1.
        let nonce = new_tx_nonce();
        pkt[NTP_TRANSMIT_TS_OFFSET..NTP_TRANSMIT_TS_OFFSET + NTP_TS_LEN]
            .copy_from_slice(&nonce);

        // Arm before transmitting — the reply can land inside the first
        // `net_poll()` below.  Scoped so the lock is never held across it.
        {
            let mut n = NTP.lock();
            n.response_ready = false;
            n.tx_nonce       = nonce;
            n.awaiting       = true;
        }

        // Send NTP request
        udp::send_raw(&mac, &our_ip, &server,
                      NTP_CLIENT_PORT, NTP_PORT, &pkt);

        // Poll for response with timeout
        let timeout = NTP_TIMEOUT_TICKS + attempt as u64 * NTP_RETRY_BACKOFF_TICKS;
        let send_ticks = azos_drv_sys::timebase::now();
        let deadline = send_ticks + timeout;

        loop {
            let now = azos_drv_sys::timebase::now();
            if now >= deadline { break; }

            super::net_poll();

            // Never hold NTP across `net_poll()`: that call reaches
            // `handle_response`, which takes this same non-reentrant
            // spinlock.  Each access is its own temporary.
            let ready = NTP.lock().response_ready;
            if ready {
                // Disarm first: whatever happens below, this request is done
                // and nothing further may latch a response against its nonce.
                {
                    let mut n = NTP.lock();
                    n.awaiting = false;
                }
                // Extract transmit timestamp (NTP seconds, big-endian)
                let buf = NTP.lock().response_buf;
                let ntp_sec = u32::from_be_bytes([
                    buf[NTP_TRANSMIT_TS_OFFSET],
                    buf[NTP_TRANSMIT_TS_OFFSET + 1],
                    buf[NTP_TRANSMIT_TS_OFFSET + 2],
                    buf[NTP_TRANSMIT_TS_OFFSET + 3],
                ]);
                // RFC 4330 §3: the seconds field wraps on 2036-02-07, and
                // bit 0 says which side of it the time is on.
                let era1 = ntp_sec & NTP_ERA0_BIT == 0;
                // RFC 4330 §5: a reply with a zero Transmit Timestamp is
                // discarded. All eight octets: seconds 0 with a nonzero
                // fraction is a real instant, the first second of era 1.
                let zero = buf[NTP_TRANSMIT_TS_OFFSET..NTP_TRANSMIT_TS_OFFSET + NTP_TS_LEN]
                    == [0u8; NTP_TS_LEN];
                // Plausibility floor, era 0 only. The comment here used to
                // claim a post-2020 check while the code only rejected
                // pre-1970, so the value could be set to any instant in the
                // 20th century. Now the code does what it says: an era-0 time
                // before `NTP_MIN_PLAUSIBLE_SEC` is a broken server or a stale
                // replay, and the clock is left alone. Before the era rule
                // this floor also refused every era-1 time, so from 2036 the
                // clock would never have synced again.
                if zero || (!era1 && ntp_sec < NTP_MIN_PLAUSIBLE_SEC) {
                    break; // zero, implausible, or invalid
                }
                // Unix seconds are a u32 here (`synced_unix_sec`). Era 0 is
                // `ntp_sec - offset`; era 1 is `ntp_sec + 2^32 - offset`,
                // which is what the wrapping subtraction yields in u32. Era 1
                // tops out at 0x7FFF_FFFF + 2^32 - offset = 4_233_462_143,
                // below 2^32, so neither era wraps the result.
                let unix_sec = ntp_sec.wrapping_sub(NTP_UNIX_EPOCH_OFFSET);
                {
                    let mut ntp = NTP.lock();
                    ntp.synced_unix_sec = unix_sec;
                    ntp.synced_clint_ticks = now;
                    ntp.valid = true;
                }
                azos_drv_sys::kprintln!(
                    "[NTP] Synced — Unix time: {} (attempt {})",
                    unix_sec, attempt + 1
                );
                return unix_sec;
            }
            yield_fn();
        }

        // Attempt over (timeout, or a response we rejected as implausible):
        // disarm so a straggler cannot be matched against the next attempt.
        { NTP.lock().awaiting = false; }

        azos_drv_sys::kprintln!("[NTP] Timeout (attempt {}), retrying...", attempt + 1);
    }

    azos_drv_sys::kwarn!("[NTP] Sync failed after {} attempts", NTP_MAX_RETRIES);
    0
}

/// Return the current Unix time (seconds) based on the last sync plus elapsed CLINT ticks.
///
/// Returns 0 if no sync has been performed.
pub fn ntp_now() -> u32 {
    let ntp = NTP.lock();
    if !ntp.valid { return 0; }

    let now = azos_drv_sys::timebase::now();
    let elapsed_ticks = now.saturating_sub(ntp.synced_clint_ticks);
    let elapsed_sec = (elapsed_ticks / NTP_CLINT_FREQ) as u32;
    ntp.synced_unix_sec.saturating_add(elapsed_sec)
}

/// Returns the Unix time offset from the last sync point (seconds since epoch, 0 if unsynced).
pub fn ntp_offset() -> u32 {
    ntp_now()
}

/// Returns true if an NTP sync has been completed successfully.
pub fn ntp_is_synced() -> bool {
    NTP.lock().valid
}

/// Handle an incoming NTP response (called from `udp::dispatch` for the client
/// port), with the datagram's source endpoint.
///
/// The wall clock drives log timestamps, certificate/lease validity and
/// anything else that reasons about "now", so letting an arbitrary host set it
/// is a control-plane primitive, not a nuisance.  A datagram is accepted only
/// if it:
///   * arrives while a request is outstanding,
///   * comes from the configured server's IP and port 123,
///   * is a server-mode packet (mode 4) from a synchronised, non-KoD source,
///   * echoes the exact 64-bit nonce we transmitted (RFC 4330 §5).
///
/// The endpoint arguments come from `udp::dispatch`: destination port 1123
/// identifies nothing, being precisely what a forgery would aim at.
/// Does this packet's header qualify as a usable server reply (RFC 5905 §7.3)?
///
/// Split out of `handle_response` so the boot-time conformance checks can drive
/// it with hand-built bytes. The rest of `handle_response` is gated on live
/// transaction state (`awaiting`, the nonce, the server address), which cannot
/// be reached from a test without faking a sync in flight — and it is this
/// header gate, not that state, that decides whether a *stranger's* packet is
/// even looked at.
///
/// Rejects, in order: anything shorter than a packet; mode != 4, i.e. not a
/// server reply; LI = 3, the server declaring itself unsynchronised; stratum 0,
/// which is a kiss-o'-death whose timestamp fields carry an ASCII code rather
/// than a time; and stratum > 15, unsynchronised.
pub fn header_acceptable(data: &[u8]) -> bool {
    if data.len() < NTP_PKT_SIZE { return false; }
    let li   = (data[0] >> 6) & 0x03;
    let mode = data[0] & 0x07;
    if mode != 4 || li == 3 { return false; }
    let stratum = data[NTP_STRATUM_OFFSET];
    if stratum == 0 || stratum > 15 { return false; }
    true
}

pub fn handle_response(src_ip: &[u8; 4], src_port: u16, data: &[u8]) {
    if !header_acceptable(data) { return; }

    let mut ntp = NTP.lock();

    if !ntp.awaiting { return; }        // nothing outstanding to answer
    if ntp.response_ready { return; }   // first valid reply wins
    if src_ip != &ntp.server { return; }
    if src_port != NTP_PORT { return; }

    // Originate timestamp must echo the nonce we sent.
    if data[NTP_ORIGINATE_TS_OFFSET..NTP_ORIGINATE_TS_OFFSET + NTP_TS_LEN]
        != ntp.tx_nonce
    {
        return;
    }

    ntp.response_buf[..NTP_PKT_SIZE].copy_from_slice(&data[..NTP_PKT_SIZE]);
    ntp.response_ready = true;
}
