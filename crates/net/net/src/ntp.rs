// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SNTP client — Simple Network Time Protocol (RFC 4330, F05.2).
//!
//! Sends a unicast SNTP request to the configured NTP server and hands the
//! measurement (the four timestamps of the exchange, [`Exchange`]) to the
//! clock discipline, which slews the kernel's wall clock toward it (or steps
//! it at boot, or over its threshold): `azos_syscall::clock`.
//!
//! # Design
//!
//! - Pure UDP, no TCP dependency.
//! - Single-request / single-response (SNTP, not full NTP).
//! - Keeps what the `Net` interface reports of the client (`status`): the
//!   server, whether an exchange has succeeded, when, and how many have.
//! - Retry on timeout with exponential backoff.
//! - The server is the lease's option 42 (`set_leased_server`, `dhcp.rs`) while
//!   the lease names one, else the address the kernel's NTP client task made
//!   from the configured name (`set_ntp_server`,
//!   `kernel/src/tasks/net_clients.rs`, Kconfig `NTP_SERVER`). Until one of
//!   them has, there is no server and no exchange is sent.

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

/// Offset of the receive timestamp (T2) in an NTP packet (RFC 5905 §7.3).
const NTP_RECEIVE_TS_OFFSET: usize = 32;

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

// ── State ────────────────────────────────────────────────────────────────────

struct NtpState {
    /// The server the configuration names (`set_ntp_server`).
    configured: Option<[u8; 4]>,
    /// The server the lease names (`set_leased_server`); it wins.
    leased: Option<[u8; 4]>,
    /// Unix timestamp (seconds) at last successful sync.
    synced_unix_sec: u32,
    /// CLINT ticks at last successful sync.
    synced_clint_ticks: u64,
    /// Whether we have a valid sync.
    valid: bool,
    /// Syncs that succeeded since boot.
    exchanges: u32,
    /// Syncs that gave up after every attempt since boot.
    failures: u32,
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
            configured: None,
            leased: None,
            synced_unix_sec: 0,
            synced_clint_ticks: 0,
            valid: false,
            exchanges: 0,
            failures: 0,
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

/// One completed request/reply pair, the four timestamps of RFC 5905 §8: the
/// client's transmit (T1) and receive (T4) on the monotonic clock, the
/// server's receive (T2) and transmit (T3) as Unix nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exchange {
    /// Monotonic nanoseconds when the request was sent (T1).
    pub t1_mono_ns: u64,
    /// Monotonic nanoseconds when the reply was taken (T4).
    pub t4_mono_ns: u64,
    /// The server's clock when it received the request (T2), Unix ns.
    pub t2_unix_ns: u64,
    /// The server's clock when it sent the reply (T3), Unix ns.
    pub t3_unix_ns: u64,
}

impl Exchange {
    /// `(offset_ns, delay_ns)` of the exchange against a wall clock that reads
    /// the monotonic clock plus `real_offset_ns` (the real offset the vDSO
    /// publishes). The offset is the server's time minus ours, positive when
    /// we are behind: `((T2 - T1) + (T3 - T4)) / 2`. The delay is the round
    /// trip less the server's holding time, `(T4 - T1) - (T3 - T2)`, never
    /// negative (a server whose two stamps are not ordered, or a clock that
    /// stepped under the exchange, has no negative travel time).
    pub fn measure(&self, real_offset_ns: u64) -> (i64, u64) {
        let real = real_offset_ns as i128;
        let t1 = self.t1_mono_ns as i128 + real;
        let t4 = self.t4_mono_ns as i128 + real;
        let (t2, t3) = (self.t2_unix_ns as i128, self.t3_unix_ns as i128);
        let offset = ((t2 - t1) + (t3 - t4)) / 2;
        let delay = ((t4 - t1) - (t3 - t2)).max(0);
        (offset.clamp(i64::MIN as i128, i64::MAX as i128) as i64, delay.min(u64::MAX as i128) as u64)
    }
}

azos_common::ro_hook! {
    /// Where a successful sync delivers its [`Exchange`]: the kernel installs the
    /// clock discipline's feed (this crate has no view of the vDSO page, of the
    /// discipline or of the topology's leap table).
    static EXCHANGE_SINK: fn(&Exchange);
}
/// Install the sink [`ntp_sync_with_yield`] calls after each sync. Called
/// once at boot.
pub fn set_exchange_sink(f: fn(&Exchange)) {
    EXCHANGE_SINK.set(f);
}

/// An NTP timestamp (seconds and 2^-32 fractions, big-endian) as one number.
fn ntp_ts(buf: &[u8; NTP_PKT_SIZE], at: usize) -> u64 {
    let mut b = [0u8; NTP_TS_LEN];
    b.copy_from_slice(&buf[at..at + NTP_TS_LEN]);
    u64::from_be_bytes(b)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Set the NTP server the configuration names: the kernel's NTP client task
/// calls this with the address of Kconfig `NTP_SERVER`. A server the lease
/// names ([`set_leased_server`]) is preferred while there is one.
pub fn set_ntp_server(ip: [u8; 4]) {
    NTP.lock().configured = Some(ip);
}

/// Set the NTP server the lease names (DHCP option 42), or `None` when the
/// lease names none: the configured one is used again.
pub fn set_leased_server(ip: Option<[u8; 4]>) {
    NTP.lock().leased = ip;
}

/// The server the lease names, if it names one.
pub fn leased_server() -> Option<[u8; 4]> {
    NTP.lock().leased
}

/// The NTP server in use, if any: the lease's, else the configured one.
pub fn get_ntp_server() -> Option<[u8; 4]> {
    let n = NTP.lock();
    n.leased.or(n.configured)
}

/// Seconds the NTP client task waits after its first failed exchange.
pub const RETRY_FIRST_S: u64 = 16;

/// How long the client task waits after a failed exchange when the failure
/// before it waited `last_s`: twice as long, up to `interval_s` (the poll
/// period of a synchronised client).
pub fn retry_after_s(last_s: u64, interval_s: u64) -> u64 {
    last_s.saturating_mul(2).min(interval_s)
}

/// `a.b.c.d` as four octets: decimal, 0..=255 each, no sign, no leading or
/// trailing text. `None` for anything else, so a name is never taken for an
/// address.
pub fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = text.split('.');
    for o in out.iter_mut() {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *o = p.parse::<u16>().ok().and_then(|v| u8::try_from(v).ok())?;
    }
    parts.next().is_none().then_some(out)
}

/// Forget the server and the counters. For host tests that must start from a
/// client nobody has configured.
#[cfg(not(target_os = "none"))]
pub fn reset_for_tests() {
    *NTP.lock() = NtpState::new();
}

/// How the client stands, for the `Net` interface's `ntp_status` op.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// The server in use; none until one is configured.
    pub server: Option<[u8; 4]>,
    /// An exchange has succeeded since boot.
    pub synced: bool,
    /// Unix seconds the server reported at the last success (0: none yet).
    pub last_unix_sec: u32,
    /// Monotonic clock ticks since that success (0 while `!synced`).
    pub age_ticks: u64,
    /// Syncs that succeeded since boot.
    pub exchanges: u32,
    /// Syncs that gave up after every attempt since boot.
    pub failures: u32,
}

/// [`Status`] now.
pub fn status() -> Status {
    let n = NTP.lock();
    Status {
        server: n.leased.or(n.configured),
        synced: n.valid,
        last_unix_sec: n.synced_unix_sec,
        age_ticks: if n.valid {
            azos_drv_sys::timebase::now().saturating_sub(n.synced_clint_ticks)
        } else {
            0
        },
        exchanges: n.exchanges,
        failures: n.failures,
    }
}

/// Synchronize the kernel wall clock with the NTP server, calling `yield_fn`
/// every poll instead of busy-spinning the hart for the whole timeout
/// window.
///
/// Blocks the calling task for up to `NTP_MAX_RETRIES * (2 + retry)` seconds.
/// Returns the Unix timestamp on success, or 0 on failure, and 0 at once while
/// no server is configured. Caller: the kernel's NTP client task.
pub fn ntp_sync_with_yield(yield_fn: fn()) -> u32 {
    let (mac, our_ip, server) = {
        let ntp = NTP.lock();
        let Some(server) = ntp.leased.or(ntp.configured) else { return 0 };
        (super::net_get_mac(), super::net_get_ip(), server)
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

        // Send NTP request; T1 is read as late as it can be, just before the
        // frame is handed to the stack.
        let t1_ticks = azos_drv_sys::timebase::now();
        udp::send_raw(&mac, &our_ip, &server,
                      NTP_CLIENT_PORT, NTP_PORT, &pkt);

        // Poll for response with timeout
        let timeout = NTP_TIMEOUT_TICKS + attempt as u64 * NTP_RETRY_BACKOFF_TICKS;
        let deadline = t1_ticks + timeout;

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
                    // When the reply was taken out of the stack, not the
                    // loop's `now` from before `net_poll` ran: that one is
                    // older by however long the poll took.
                    ntp.synced_clint_ticks = azos_drv_sys::timebase::now();
                    ntp.valid = true;
                    ntp.exchanges = ntp.exchanges.wrapping_add(1);
                }
                // Hand the exchange to the clock discipline. T4 is read now,
                // as soon as the reply was taken out of the stack; the
                // server's timestamps are the packet's.
                let sink = EXCHANGE_SINK.get();
                if let Some(deliver) = sink {
                    let frac = u32::from_be_bytes([
                        buf[NTP_TRANSMIT_TS_OFFSET + 4],
                        buf[NTP_TRANSMIT_TS_OFFSET + 5],
                        buf[NTP_TRANSMIT_TS_OFFSET + 6],
                        buf[NTP_TRANSMIT_TS_OFFSET + 7],
                    ]);
                    let t3 = (unix_sec as u64) * azos_abi::time::NS_PER_SEC
                        + ((frac as u64 * azos_abi::time::NS_PER_SEC) >> 32);
                    // The holding time T3 - T2 as a signed 32.32 difference, so
                    // an era boundary between the two stamps cancels; a zero
                    // Receive Timestamp (a server that sets none) holds 0.
                    let rx = ntp_ts(&buf, NTP_RECEIVE_TS_OFFSET);
                    let hold_q32 = if rx == 0 { 0 } else { ntp_ts(&buf, NTP_TRANSMIT_TS_OFFSET).wrapping_sub(rx) as i64 };
                    let hold_ns = ((hold_q32 as i128 * azos_abi::time::NS_PER_SEC as i128) >> 32) as i64;
                    let at = azos_drv_sys::timebase::now();
                    let to_ns = |t| azos_abi::time::ticks_to_ns(t, azos_drv_sys::timebase::TIMER_FREQ);
                    deliver(&Exchange {
                        t1_mono_ns: to_ns(t1_ticks),
                        t4_mono_ns: to_ns(at),
                        t2_unix_ns: t3.saturating_add_signed(-hold_ns),
                        t3_unix_ns: t3,
                    });
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

    {
        let mut ntp = NTP.lock();
        ntp.failures = ntp.failures.wrapping_add(1);
    }
    azos_drv_sys::kwarn!("[NTP] Sync failed after {} attempts", NTP_MAX_RETRIES);
    0
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
/// server reply; a version outside 1-4; LI = 3, the server declaring itself
/// unsynchronised; stratum 0, which is a kiss-o'-death whose timestamp fields
/// carry an ASCII code rather than a time; and stratum > 15, unsynchronised.
pub fn header_acceptable(data: &[u8]) -> bool {
    if data.len() < NTP_PKT_SIZE { return false; }
    let li   = (data[0] >> 6) & 0x03;
    let mode = data[0] & 0x07;
    // Version 1 to 4 (RFC 4330 §4: a server answers in the client's version or
    // lower). 0 and 5-7 are not a protocol this client speaks, and the rest of
    // the packet means something else in them.
    let vn = (data[0] >> 3) & 0x07;
    if mode != 4 || li == 3 || vn == 0 || vn > 4 { return false; }
    let stratum = data[NTP_STRATUM_OFFSET];
    if stratum == 0 || stratum > 15 { return false; }
    true
}

pub fn handle_response(src_ip: &[u8; 4], src_port: u16, data: &[u8]) {
    if !header_acceptable(data) { return; }

    let mut ntp = NTP.lock();

    if !ntp.awaiting { return; }        // nothing outstanding to answer
    if ntp.response_ready { return; }   // first valid reply wins
    if ntp.leased.or(ntp.configured) != Some(*src_ip) { return; }
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
