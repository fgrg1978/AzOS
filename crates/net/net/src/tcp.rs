// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// TCP layer — hardened TCP stack (RFC 793 + RFC 6298 + RFC 6528 + RFC 5681)
///
/// Simplified TCP state machine; connection count is `TCP_MAX_CONNS`
/// (`azos_limits`, per-Kconfig-profile — 8 at edge, 4 embedded, 1024
/// fleet), not a fixed number.
/// Supports listen/connect/send/recv/close with:
///   - ISN randomization (RFC 6528)
///   - A send queue holding every unacknowledged byte once, several segments
///     in flight, retransmission from SND.UNA (RFC 793 §3.7, RFC 6298)
///   - Keep-alive probes
///   - Sequence number validation
///   - Congestion control (RFC 5681) with NewReno recovery (RFC 6582)
///   - MSS negotiation
///   - Window scaling (RFC 7323), only when both SYNs carry the option
///   - SACK (RFC 2018): blocks for the out-of-order queue, and a scoreboard of
///     the blocks the peer sends so a retransmission skips what it holds
///   - Simultaneous open (RFC 793 §3.4)

use azos_sync::SpinLock;

use crate::seq::{seq_in_window, fin_next_ack, seq_le, seq_lt};
use super::ip;
pub use azos_limits::TCP_MAX_CONNS;
use wcet_macro::wcet;

// ---------------------------------------------------------------------------
// Connection limits
// ---------------------------------------------------------------------------

/// Per-connection receive ring buffer size (bytes), from `.config`
/// (`CONFIG_TCP_BUF_SIZE`, a per-profile default in `config/Kconfig.network`).
/// Must be a power of two for efficient modular arithmetic
/// (`crates/core/limits/build.rs` rejects anything else), and large enough for
/// loss recovery (see the assertion after `DUP_ACK_THRESHOLD`).
/// Sized to keep OTA / large transfers flowing without window-stalls: a
/// 4 KB buffer fills in ~3 segments at MSS=1460 and stalls the sender if
/// the consumer task can't drain instantly. 128 KiB (edge, embedded) gives the
/// OTA recv task generous breathing room across FAT32 write latencies and
/// burst arrivals; fleet, with 1024 connections, uses 16 KiB. Everything below
/// that depends on the size derives from this one constant.
const TCP_BUF_SIZE: usize = azos_limits::TCP_BUF_SIZE;

/// Ring buffer index mask — used instead of modulo for power-of-two buffers.
const TCP_BUF_MASK: usize = TCP_BUF_SIZE - 1;

/// Per-connection send ring: every byte between SND.UNA and SND.NXT, kept once.
///
/// The same size as the receive ring, which is what `config/Kconfig.limits` already
/// budgets per connection ("RX + TX"). It is also the hard ceiling on bytes in
/// flight: `cwnd` and the peer's window may both be larger, but a byte that is
/// not in this ring cannot be retransmitted, so it is never sent.
const TCP_SND_BUF_SIZE: usize = TCP_BUF_SIZE;

/// Send ring index mask.
const TCP_SND_BUF_MASK: usize = TCP_SND_BUF_SIZE - 1;

/// Most bytes one `recv` may copy while holding `TCP.lock()`.
///
/// The copy is byte-at-a-time through a ring, roughly eleven RV64 instructions
/// per byte once the mask and wraparound bookkeeping are counted. It was bounded
/// only by `min(bytes buffered, caller's buffer)` -- a property of the CALLER,
/// not of this function. Today every caller happens to cap at 4 KiB because
/// `SYS_RECV` does, which is ~45,000 instructions; nothing stopped a future one
/// from asking for the whole 128 KiB ring and holding the lock for ~1.4 million.
///
/// That was merely rude until K-C29 step 2 made every `SpinLock` section
/// non-preemptible. Now it is a real-time latency floor set by whoever calls
/// `recv`, which is exactly the kind of bound that should belong to the
/// function rather than to its callers being careful.
///
/// A short read is not a failure in TCP -- returning fewer bytes than asked for
/// is ordinary and every correct caller already loops -- so the cap costs
/// nothing but an extra call.
const TCP_RECV_MAX_PER_CALL: usize = azos_limits::TCP_RECV_MAX_PER_CALL;

/// TCP Maximum Segment Size — max payload bytes per segment.
/// Standard Ethernet MTU (1500) minus IP header (20) minus TCP header (20).
const TCP_MSS: usize = 1460;

/// Maximum TCP segment buffer size (MSS + max TCP header with options).
const TCP_SEGMENT_BUF_SIZE: usize = TCP_MSS + TCP_HDR_MAX;

/// The largest value the 16-bit window field can carry, capped by what the
/// receive ring can hold.
///
/// This is the window of every SYN and SYN-ACK (RFC 7323 §2.2: the window of a
/// segment carrying SYN is never scaled), and the whole receive window of a
/// connection that did not negotiate scaling.
///
/// The ring holds `TCP_BUF_SIZE - 1` bytes, not `TCP_BUF_SIZE`: `rx_free_space`
/// keeps one slot free so that a full ring is not read as an empty one. From a
/// 65536-byte ring up the field's own 65535 is the lower bound and the two
/// agree; below it, `TCP_BUF_SIZE` would promise a byte there is no room for.
const TCP_WINDOW_SIZE: u16 = window_clamp(TCP_BUF_SIZE - 1);

/// Saturate a byte count into the 16-bit window field.
const fn window_clamp(free: usize) -> u16 {
    if free > u16::MAX as usize { u16::MAX } else { free as u16 }
}

/// Our window-scale shift (RFC 7323), offered in every SYN we originate and
/// echoed in a SYN-ACK when the peer offered one.
///
/// The smallest shift that lets the field describe the whole receive ring:
/// for 128 KiB that is 1, and for a ring of 64 KiB or less it is 0 — the
/// unscaled field already covers it, and the option is still offered so that
/// the PEER's window can be scaled. A larger shift only costs precision — the field is
/// rounded down by `2^shift` bytes on every segment — and buys nothing, since
/// no free-space value above `TCP_BUF_SIZE - 1` exists to advertise.
const RCV_WSCALE: u8 = {
    let mut s = 0u8;
    while ((TCP_BUF_SIZE - 1) >> s) > u16::MAX as usize && s < TCP_WSCALE_MAX {
        s += 1;
    }
    s
};

/// Largest shift RFC 7323 §2.3 allows. A peer offering more is treated as
/// offering exactly this.
const TCP_WSCALE_MAX: u8 = 14;

/// The window field for `free` bytes under `shift`, rounded DOWN.
///
/// Rounding down is the only direction that never promises space the ring
/// does not have: the peer multiplies the field back by `2^shift`.
const fn adv_window(free: usize, shift: u8) -> u16 {
    window_clamp(free >> shift)
}

// ---------------------------------------------------------------------------
// TCP header constants
// ---------------------------------------------------------------------------

/// Minimum TCP header length in bytes (5 × 4-byte words).
const TCP_HDR_MIN: usize = 20;

/// Maximum TCP header length: a data offset of 15 words (RFC 793), i.e. 40
/// bytes of options.
const TCP_HDR_MAX: usize = 60;

/// Most option bytes one segment can carry.
const TCP_OPT_MAX: usize = TCP_HDR_MAX - TCP_HDR_MIN;

// ---------------------------------------------------------------------------
// TCP flags
// ---------------------------------------------------------------------------

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

// ---------------------------------------------------------------------------
// MSS option
// ---------------------------------------------------------------------------

/// TCP option kind for Maximum Segment Size.
const TCP_OPT_MSS: u8 = 2;

/// TCP option length for MSS (kind + len + 2-byte value).
const TCP_OPT_MSS_LEN: u8 = 4;

/// TCP option kind: End of Options List.
const TCP_OPT_EOL: u8 = 0;

/// TCP option kind: No-Operation (padding).
const TCP_OPT_NOP: u8 = 1;

/// Default remote MSS when peer does not advertise one (RFC 879).
const TCP_DEFAULT_REMOTE_MSS: u16 = 536;

/// TCP option kind: Window Scale (RFC 7323 §2.2), length 3.
const TCP_OPT_WSCALE: u8 = 3;
const TCP_OPT_WSCALE_LEN: u8 = 3;

/// TCP option kind: SACK-Permitted (RFC 2018 §2), length 2. SYN only.
const TCP_OPT_SACK_PERM: u8 = 4;
const TCP_OPT_SACK_PERM_LEN: u8 = 2;

/// TCP option kind: SACK (RFC 2018 §3), length 2 + 8 per block.
const TCP_OPT_SACK: u8 = 5;

/// SACK blocks per segment. Two NOPs, kind and length plus 8 bytes a block
/// fit four blocks in the 40 option bytes, and the out-of-order queue never
/// holds more than `OOO_MAX_SEGMENTS` = 4 disjoint ranges anyway.
const SACK_MAX_BLOCKS: usize = 4;

// ---------------------------------------------------------------------------
// ISN generation (RFC 6528)
// ---------------------------------------------------------------------------

/// Runtime-seeded secret for ISN generation. Was previously a compile-time
/// constant; an attacker with the binary could predict every initial sequence
/// number and trivially hijack a TCP session (RFC 6528 explicitly warns
/// against this).
///
/// Two sources, in order. `net_init()` XORs in the boot mtime
/// (`isn_secret_seed`): not strong randomness, but unpredictable from a
/// static analysis of the binary alone. Then `init` replaces the secret with
/// bytes from the kernel entropy pool when a seeded source is installed
/// (`isn_secret_from_pool`); without one the mtime seed is what stays.
///
/// U06-6: was a 32-bit `AtomicU32` fed into FNV-1a, a bijection mod 2^32 at
/// every step — one observed ISN minus the low-variance `mtime`-derived time
/// term (`generate_isn`'s `ticks as u32`) recovers this secret exactly, after
/// which every later ISN for any 4-tuple is computable, turning a blind
/// injection (U06-1) from a ~2^16 guess into a certainty. 32 bytes (256-bit)
/// is the full HMAC-SHA256 key size, well past RFC 6528's 128-bit floor.
static ISN_SECRET: SpinLock<[u8; 32]> = SpinLock::new([
    // Same role the old `0xA5F0_3C7B` constant played: a fixed, non-zero
    // default so an unseeded board is not predictable from an all-zero key.
    // `isn_secret_seed` XORs boot entropy over the first 4 bytes below, same
    // as it always did; `isn_secret_from_pool` overwrites the whole key with
    // pool output once a seeded entropy source exists.
    0xA5, 0xF0, 0x3C, 0x7B, 0x91, 0xE2, 0x6D, 0x14,
    0x58, 0xB3, 0x2A, 0xC7, 0xF1, 0x09, 0x84, 0xDE,
    0x33, 0x7A, 0xC1, 0x5E, 0x9B, 0x02, 0x6F, 0xD8,
    0x41, 0xBE, 0x77, 0x1C, 0xA9, 0x50, 0xE3, 0x8F,
]);

/// Replace the ISN secret with pool bytes through `crate::net_random_fill`.
/// Returns `false`, and leaves the secret as it was, when no seeded source is
/// installed.
fn isn_secret_from_pool() -> bool {
    let mut s = [0u8; 32];
    if !crate::net_random_fill(&mut s) {
        return false;
    }
    *ISN_SECRET.lock() = s;
    true
}

/// Seed the ISN secret from a runtime entropy source. Called once during
/// `net_init`. Each call XORs into the secret's first 4 bytes, so a later
/// seed adds to an earlier one rather than replacing it (matching the old
/// `u32`-wide behaviour on the bytes that carry it).
pub fn isn_secret_seed(entropy: u32) {
    let eb = entropy.to_le_bytes();
    {
        let mut s = ISN_SECRET.lock();
        for i in 0..4 {
            s[i] ^= eb[i];
        }
    }
    // The ephemeral port cursor starts somewhere new on every boot, so a
    // reboot does not redial a 4-tuple the peer may still hold.
    let mut t = TCP.lock();
    t.eph_next ^= entropy;
}

// ---------------------------------------------------------------------------
// Retransmission timer (RFC 6298)
// ---------------------------------------------------------------------------

/// Initial retransmission timeout in milliseconds.
const RTO_INITIAL_MS: u64 = 1000;

/// Minimum retransmission timeout in milliseconds.
const RTO_MIN_MS: u64 = 200;

/// Maximum retransmission timeout in milliseconds (60 seconds).
const RTO_MAX_MS: u64 = 60_000;

/// The least the variance term adds to SRTT in the RTO: RFC 6298 §2.3's
/// `max(G, K*RTTVAR)`, with this floor above G. On a path whose round trip
/// does not vary, RTTVAR decays towards 0, and G alone (1 ms) puts the RTO a
/// millisecond above SRTT — shorter than a resend's round trip, so above
/// `RTO_MIN_MS` a loss recovery times out while its resend is on the way
/// (measured in `net-tests` `tcp_rto_estimate`, 2026-09-14). 200 ms is
/// `RTO_MIN_MS` and Linux's `tcp_rto_min`, the floor Linux keeps under
/// `mdev_max`. The RTO is never below RFC 6298's, so the floor adds no
/// timeout; a real one fires up to this much later.
const RTO_VAR_FLOOR_MS: u64 = 200;

/// Maximum retransmission attempts before connection is considered dead.
const RETX_MAX_ATTEMPTS: u8 = 8;

// ---------------------------------------------------------------------------
// Handshake (half-open) timer
// ---------------------------------------------------------------------------

/// Interval between SYN / SYN-ACK retransmissions, in milliseconds.
///
/// Deliberately a fixed interval and NOT `rto_ticks`: backing off the
/// connection's RTO during the handshake would carry an inflated value into
/// `Established`, where nothing resets it until the first RTT sample, and the
/// first lost data segment would then wait seconds instead of ~1 s.
const SYN_RETRY_INTERVAL_MS: u64 = 1_000;

/// SYN / SYN-ACK retransmissions before a half-open slot is abandoned.
///
/// This is what bounds the lifetime of a half-open connection: 4 retries at
/// `SYN_RETRY_INTERVAL_MS` means a `SynSent` / `SynRcvd` slot lives at most
/// ~5 s without progress, then returns to `Closed`.
///
/// Before this existed nothing reaped those slots at all — `tcp_tick`'s only
/// reaper was gated on `unacked`, which neither `connect()` nor the listener
/// path ever sets — so `MAX_HALF_OPEN_PER_LISTENER`'s comment about slots
/// being "reaped on RTO" described a mechanism that did not exist.  Four
/// SYNs that were never completed silenced a listener permanently, and eight
/// consumed `TCP_MAX_CONNS`, so the robot could not dial out either.  Both
/// conditions survived until reboot.
const SYN_MAX_RETRIES: u8 = 4;

// ---------------------------------------------------------------------------
// Zero-window persist timer
// ---------------------------------------------------------------------------

/// RFC 1122 §4.2.2.17 persist timer: how long to wait before probing a peer
/// that advertised a zero window.
///
/// **Why this must exist at all.** When the peer's window closes, `send_data`
/// returns 0 and the sender simply stops. Reopening is entirely the peer's
/// job: it sends a window update when its application drains the buffer. That
/// update is a bare ACK — it carries no data, so the peer never retransmits it.
/// Lose that one segment and both ends wait for each other forever: the peer
/// believes it has told us the window is open, and we believe it is still
/// closed. Nothing times out, because nothing is unacknowledged. The
/// connection is not slow, it is dead, and the retransmission machinery cannot
/// see it because there is nothing outstanding to retransmit.
///
/// So the sender must be the one to break the tie. Start at 500 ms rather than
/// the RTO, because this is not a loss estimate — it is "the peer is busy, ask
/// again later" — and the point is to be cheap while the peer legitimately has
/// a full buffer.
const PERSIST_INITIAL_MS: u64 = 500;

/// Ceiling for the persist backoff. RFC 1122 requires the probe interval to
/// grow but never to stop: a persist timer that gives up recreates exactly the
/// deadlock it exists to break, so there is no maximum probe COUNT here — only
/// a maximum interval.
const PERSIST_MAX_MS: u64 = 60_000;

/// Consecutive persist probes the peer may leave UNANSWERED before the
/// connection is torn down.
///
/// The distinction this rests on, and the one the first version of the persist
/// timer got wrong. RFC 1122 §4.2.2.17 forbids dropping a connection *because
/// its window is zero* -- a peer whose application is slow is healthy, and
/// killing it recreates the deadlock the timer exists to break. It says
/// nothing about a peer that has stopped answering at all, and those are not
/// the same state: one replies to every probe with `win=0`, the other replies
/// to nothing.
///
/// Without this the second case was immortal. Moving persist above the
/// retransmission timer was right -- retransmitting into a zero window can
/// never be acknowledged -- but it also took that path's `RETX_MAX_ATTEMPTS`
/// teardown away from the one state that still needed it. A peer that
/// advertised `win=0` and then had its cable pulled probed every 60 s forever,
/// holding one of 16 connection slots, with keepalive skipped because the
/// persist branch `continue`s past it.
///
/// So: count probes, and reset the count on ANY segment from the peer, which
/// is what makes "still there, still full" cost nothing and "gone" terminate.
/// This is `tcp_probe_timer`'s rule in Linux, bounded by `tcp_retries2`.
///
/// Eight, to match `RETX_MAX_ATTEMPTS`: it is the same judgement -- "this peer
/// has stopped responding" -- and two different numbers for one judgement is
/// how they drift apart.
const PERSIST_MAX_UNANSWERED: u8 = RETX_MAX_ATTEMPTS;

/// How long a connection may sit in `FinWait2` before the slot is reclaimed.
///
/// `FinWait2` means we closed, the peer acknowledged our FIN, and we are now
/// waiting for the peer to close its own direction. Nothing obliges it to
/// hurry, and nothing obliges it to ever do it: a peer that crashes here, or
/// one whose application simply never calls close, leaves us waiting forever.
/// Every other teardown state now has a bound; this one held a slot for the
/// life of the boot, and eight of them is a robot that can neither dial out nor
/// accept a connection.
///
/// 60 s, matching Linux's `tcp_fin_timeout` default. Long enough that a peer
/// with a slow application is not cut off mid-work, short enough that a dead
/// one does not cost a slot until reboot.
const FIN_WAIT2_TIMEOUT_MS: u64 = 60_000;

/// Timer ticks per millisecond (10 MHz clock).
/// CLINT ticks in one millisecond, **derived from the board** rather than
/// assumed.
///
/// This was `10_000` — the qemu `mtime` rate divided by a thousand — and every
/// timer in this file is built on it: the RTO floor and ceiling, the SYN retry
/// interval, TIME-WAIT, keep-alive, the persist backoff. `platform.rs` records
/// the real rates and flags the one that matters: **4 MHz on the JH7110
/// (VF2)** and 24 MHz on the K1.
///
/// So on the board this project is being brought up on, every one of those
/// durations ran **2.5x long**: a 30-second keep-alive at 75 seconds, and a
/// death budget of up to eight RTOs stretching past seven minutes. Nothing in
/// the gate could catch it, because the host suites and QEMU both run at
/// 10 MHz — the failure only exists on hardware, which is precisely the class
/// of bug a bring-up gate is supposed to be for.
///
/// `crates/drivers/irqchip/src/clint.rs` already had the right pattern
/// (`TIMER_FREQ = platform::hw::TIMER_FREQ`, ticks computed from it) and
/// `motor_pid`, `wcet` and `bench` already used it. All of `crates/net/net` did
/// not.
const TICKS_PER_MS: u64 = azos_drv_sys::timebase::TIMER_FREQ / 1_000;

// ---------------------------------------------------------------------------
// Delayed acknowledgements (RFC 1122 §4.2.3.2, RFC 5681 §4.2)
// ---------------------------------------------------------------------------

/// Longest an in-order segment's ACK is held (`CONFIG_TCP_DELACK_MS`), in
/// ticks. 0: every in-order segment is acknowledged at once, as before wave 15.
const TCP_DELACK_TICKS: u64 = azos_limits::TCP_DELACK_MS as u64 * TICKS_PER_MS;

/// Full-sized segments of unacknowledged in-order data that force the ACK out
/// at once (`CONFIG_TCP_DELACK_SEGS`; RFC 1122: "at least every second").
const TCP_DELACK_SEGS: u32 = azos_limits::TCP_DELACK_SEGS as u32;
const _: () = assert!(TCP_DELACK_SEGS >= 1, "CONFIG_TCP_DELACK_SEGS must be at least 1");

/// A read that moves the advertised right edge by this much sends the window
/// update at once instead of holding it (`CONFIG_TCP_WINDOW_UPDATE_SHIFT`:
/// the ring >> shift). Between this and the half-window rule, a sender
/// limited by our ring sees most of it each round trip.
const TCP_WINDOW_UPDATE_BYTES: u32 =
    (TCP_BUF_SIZE >> azos_limits::TCP_WINDOW_UPDATE_SHIFT) as u32;

/// Held ACKs leave at the end of each `net_poll` pass (`CONFIG_TCP_DELACK_PASS_FLUSH`).
pub const TCP_DELACK_PASS_FLUSH: bool = azos_limits::TCP_DELACK_PASS_FLUSH;

/// Some connection may hold an ACK: set (after the connection's own
/// `ack_pending`, under the lock) by whoever holds one, cleared by the scan
/// in [`flush_held_acks`] before it looks. A pass with nothing held costs one
/// atomic swap instead of a table scan.
static ACK_HELD: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Pure ACKs, by what sent them: `[at once on the receive path, end of a poll
/// pass, delayed-ACK timer, window update from recv, piggybacked on our own
/// segment (no pure ACK needed)]`. Relaxed counters for the gate and QEMU rows.
static ACK_STATS: [core::sync::atomic::AtomicU64; 5] =
    [const { core::sync::atomic::AtomicU64::new(0) }; 5];
const ACKS_NOW: usize = 0;
const ACKS_PASS: usize = 1;
const ACKS_TIMER: usize = 2;
const ACKS_WINDOW: usize = 3;
const ACKS_PIGGYBACK: usize = 4;

/// [`ACK_STATS`], in its order.
pub fn ack_stats() -> [u64; 5] {
    core::array::from_fn(|i| ACK_STATS[i].load(core::sync::atomic::Ordering::Relaxed))
}

fn ack_count(which: usize) {
    ACK_STATS[which].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

/// Whether any connection holds an ACK (the poller shortens its sleep to
/// [`TCP_DELACK_TICKS`] while one does).
pub fn acks_held() -> bool {
    ACK_HELD.load(core::sync::atomic::Ordering::Acquire)
}

/// [`TCP_DELACK_TICKS`], for the poller's sleep bound.
pub const fn delack_ticks() -> u64 { TCP_DELACK_TICKS }

// ---------------------------------------------------------------------------
// Keep-alive
// ---------------------------------------------------------------------------

/// Keep-alive interval: 30 seconds, derived from `TIMER_FREQ` so it stays
/// 30 real seconds on every board (`platform.rs`: 10 MHz QEMU, 4 MHz VF2,
/// 24 MHz K1, 1 GHz aarch64 — a hard-coded tick count would silently be
/// the wrong duration on three of those four).
const KEEPALIVE_INTERVAL_TICKS: u64 = 30 * azos_drv_sys::timebase::TIMER_FREQ;

/// Maximum keep-alive probes before declaring connection dead.
const KEEPALIVE_MAX_PROBES: u8 = 3;

// ---------------------------------------------------------------------------
// Congestion control (Reno)
// ---------------------------------------------------------------------------

/// Initial congestion window: 2 segments.
const CWND_INITIAL: u32 = TCP_MSS as u32 * 2;

/// Initial slow-start threshold: equals receive buffer size.
const SSTHRESH_INITIAL: u32 = TCP_BUF_SIZE as u32;

/// Fast retransmit threshold: 3 duplicate ACKs. RFC 6675's DupThresh too, where
/// it also sets `IsLost`: DupThresh SACKed ranges, or more than DupThresh - 1
/// segments' worth of SACKed bytes, above a sequence number mark it lost.
const DUP_ACK_THRESHOLD: u8 = 3;

/// The send ring holds at least `DUP_ACK_THRESHOLD + 1` full segments.
///
/// Loss recovery starts from duplicate ACKs, or with SACK from DupThresh
/// segments' worth of SACKed bytes above a hole, and both come only from
/// segments sent after the lost one. A ring that cannot hold that flight leaves
/// every loss to the retransmission timer. On the host at a 4096-byte ring
/// (2026-09-14) `tcp_throughput::a_lost_middle_segment_is_recovered_with_the_stream_intact`
/// saw the lost segment resent 240 ms after it left, by timeout. The smallest
/// power of two that passes is 8192; `crates/core/limits/build.rs` rejects a smaller
/// `CONFIG_TCP_BUF_SIZE` with a readable message before this is evaluated.
const _: () = assert!(
    TCP_SND_BUF_SIZE >= (DUP_ACK_THRESHOLD as usize + 1) * TCP_MSS,
    "TCP_BUF_SIZE must hold DUP_ACK_THRESHOLD + 1 full-size segments",
);

/// SACK blocks remembered from the peer (RFC 2018). Four, because that is the
/// most one ACK can carry. Losing a block never loses a byte: for skipping
/// retransmissions it costs a resend of bytes the peer already holds, and for
/// RFC 6675 recovery the forgotten bytes count as still in the network, which
/// makes `pipe` larger and `IsLost` rarer — the conservative direction for both.
const SACK_SCOREBOARD: usize = 4;

/// Most segments one event may release for retransmission: an inbound ACK
/// after a timeout, an inbound ACK during SACK recovery (RFC 6675 §5 (C), whose
/// own note says (A) and (C) can burst), or one `send_data` call that finds a
/// lost range ahead of its new data. Slow start from one segment releases two
/// per ACK; the bound exists so an ACK that jumps far cannot turn the receive
/// path into a long burst. Every burst puts at least one segment in flight,
/// and its ACK continues where the bound stopped.
const RECOVERY_RETX_BURST: usize = 4;

/// Least interval between two ACKs sent in reply to unacceptable segments on
/// one connection (RFC 793 §3.9 asks for one each time).
///
/// Without an answer a peer whose ACK was lost retransmits data we already
/// hold until it gives up, and a keep-alive probe goes unanswered. With an
/// answer to every one, anyone who can spoof the 4-tuple gets one segment
/// toward the real peer per segment sent. 500 ms is Linux's
/// `tcp_invalid_ratelimit`: two replies a second per connection, whatever
/// arrives.
const INVALID_ACK_INTERVAL_MS: u64 = 500;

// ---------------------------------------------------------------------------
// Path MTU discovery (RFC 1191, with RFC 5927's validation)
// ---------------------------------------------------------------------------

/// Smallest path MTU a Fragmentation Needed message may set: 576, the
/// datagram every IPv4 host must be able to receive (RFC 791, RFC 1122
/// §3.3.3). A report below it is ignored rather than clamped: no IPv4 path
/// can legitimately carry less, so it is broken or forged, and obeying it
/// would let one packet cut the robot's segments to a few octets each.
const PMTU_FLOOR: u16 = 576;

/// IPv4 plus TCP header octets in a data segment. This stack puts TCP options
/// only on segments without payload, so a full data segment carries none.
const PMTU_HDR_OCTETS: u16 = 40;

/// The MSS that fits `PMTU_FLOOR`: 536, RFC 879's default MSS. Also the floor
/// of the black-hole fallback.
const PMTU_MSS_FLOOR: u16 = PMTU_FLOOR - PMTU_HDR_OCTETS;

/// RFC 1191 §7 plateaus at or above `PMTU_FLOOR`, highest first. A router
/// that predates RFC 1191 reports a next-hop MTU of 0; the estimate is then
/// the highest plateau below the length of the datagram it quotes.
const PMTU_PLATEAUS: [u16; 7] = [32000, 17914, 8166, 4352, 2002, 1492, 1006];

/// Consecutive timeouts of a segment one full SMSS long after which the path
/// is taken to be dropping segments of that size without saying so — a PMTU
/// black hole (RFC 2923) — and the MSS is halved, floored at
/// `PMTU_MSS_FLOOR`, in the manner of RFC 4821's fallback (its upward search
/// is not implemented). Three is Linux's `tcp_retries1`, the point at which
/// its black-hole handling lowers the MSS when `tcp_mtu_probing` is enabled
/// (it is off by default there). A wrong guess — a congested path that lost
/// the same full segment three times — costs throughput for the rest of the
/// connection, never data.
const PMTU_BLACKHOLE_RTOS: u8 = 3;

/// Fragmentation Needed messages examined per `PMTU_ICMP_WINDOW_TICKS`,
/// across all connections, before any checksum is computed.
const PMTU_ICMP_BUDGET_PER_WINDOW: u32 = 10;

/// 100 ms, as for resets. A genuine drop in path MTU draws one message per
/// oversized segment in flight, a handful; a flood gets ten a window.
const PMTU_ICMP_WINDOW_TICKS: u64 = azos_drv_sys::timebase::TIMER_FREQ / 10;

// ---------------------------------------------------------------------------
// Out-of-order reassembly (F01)
// ---------------------------------------------------------------------------

/// Maximum number of out-of-order segments buffered per connection.
const OOO_MAX_SEGMENTS: usize = 4;

/// Maximum data bytes per out-of-order segment: one full-size segment
/// (`TCP_MSS`, the MSS our SYN advertises), so a segment a peer cuts at that
/// MSS is held whole. A longer one is truncated to it, and the ACK and SACK
/// blocks cover only what was kept. 4 × 1460 B of `TcpConn` per connection;
/// 256 B until 2026-09-14, less than one segment.
const OOO_SEGMENT_MAX_LEN: usize = TCP_MSS;

// ---------------------------------------------------------------------------
// FIN state machine (F01)
// ---------------------------------------------------------------------------

/// TIME-WAIT duration in milliseconds (2 × MSL, MSL = 1 second for LAN).
const TIME_WAIT_MS: u64 = 2_000;

// ---------------------------------------------------------------------------
// RTT fixed-point scaling
// ---------------------------------------------------------------------------

/// Fixed-point multiplier for SRTT/RTTVAR (×1000).
const RTT_SCALE: u64 = 1000;

/// SRTT smoothing factor: alpha = 1/8, so (1 - alpha) = 7/8.
const SRTT_ALPHA_INV: u64 = 8;

/// RTTVAR smoothing factor: beta = 1/4, so (1 - beta) = 3/4.
const RTTVAR_BETA_INV: u64 = 4;

/// Clock granularity for RTO lower bound (1 ms in ticks).
const CLOCK_GRANULARITY_TICKS: u64 = TICKS_PER_MS;

// ---------------------------------------------------------------------------
// TCP checksum field offset in header
// ---------------------------------------------------------------------------

/// Byte offset of the checksum field within the TCP header.
const TCP_CHECKSUM_OFFSET: usize = 16;

/// Byte offset + 1 of the checksum field (second byte).
const TCP_CHECKSUM_OFFSET_HI: usize = 17;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Where loss recovery stands (RFC 5681 §3.2, RFC 6582, RFC 6675).
#[derive(Clone, Copy, PartialEq)]
enum Recovery {
    /// No loss being repaired.
    Open = 0,
    /// NewReno fast recovery (RFC 6582), for a peer that did not negotiate
    /// SACK. Entered on the third duplicate ACK, left by an ACK at or past
    /// `recover`.
    Fast = 1,
    /// Entered on a retransmission timeout: everything in flight is presumed
    /// lost and is resent from SND.UNA as the collapsed window reopens.
    Loss = 2,
    /// SACK-based loss recovery (RFC 6675 §5), for a peer that negotiated
    /// SACK. Entered on DupThresh duplicate ACKs or when the scoreboard shows
    /// SND.UNA lost; what goes out is bounded by `cwnd - pipe`, not by
    /// counting duplicates. Left by an ACK at or past `recover`.
    Sack = 3,
    /// The path MTU fell (RFC 1191, `icmp_frag_needed`): what is in flight was
    /// cut for a larger MSS and is resent from SND.UNA at the new one as ACKs
    /// arrive, as in `Loss`, but with no congestion response — nothing was
    /// lost to congestion. Left by an ACK at or past `recover`.
    PathMtu = 4,
}

#[derive(Clone, Copy, PartialEq)]
pub enum TcpState {
    Closed     = 0,
    Listen     = 1,
    SynSent    = 2,
    SynRcvd    = 3,
    Established= 4,
    FinWait1   = 5,
    FinWait2   = 6,
    CloseWait  = 7,
    LastAck    = 8,
    TimeWait   = 9,
}

#[repr(C, packed)]
struct TcpHdr {
    src_port: [u8; 2],
    dst_port: [u8; 2],
    seq:      [u8; 4],
    ack:      [u8; 4],
    data_off: u8,     // header length in 32-bit words (high 4 bits)
    flags:    u8,
    window:   [u8; 2],
    checksum: [u8; 2],
    urgent:   [u8; 2],
}

// ---------------------------------------------------------------------------
// Out-of-order segment buffer
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct OooSegment {
    seq:   u32,
    len:   u16,
    data:  [u8; OOO_SEGMENT_MAX_LEN],
    valid: bool,
}

impl OooSegment {
    const fn empty() -> Self {
        Self { seq: 0, len: 0, data: [0u8; OOO_SEGMENT_MAX_LEN], valid: false }
    }
}

// ---------------------------------------------------------------------------
// TcpConn
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct TcpConn {
    pub state:        TcpState,
    pub local_ip:     [u8; 4],
    pub local_port:   u16,
    pub remote_ip:    [u8; 4],
    pub remote_port:  u16,
    pub seq:          u32,
    pub ack:          u32,
    pub was_accepted: bool,   // socket_accept() has claimed this slot
    pub rx_buf:       [u8; TCP_BUF_SIZE],
    pub rx_head:      usize,
    pub rx_tail:      usize,

    // --- Send queue and retransmission (RFC 793 §3.7, RFC 6298) ---
    /// SND.UNA, the oldest byte the peer has not acknowledged. `seq` is
    /// SND.NXT; the bytes between the two are in flight, and "anything
    /// unacknowledged" is exactly `snd_una != seq` — there is no separate
    /// flag to disagree with it.
    snd_una:          u32,
    /// Every byte in flight, once, as a ring: the byte at SND.UNA is at
    /// `tx_head`. Retransmissions are cut from here, from SND.UNA, rather than
    /// replayed from per-segment copies — so a retransmission may carry more
    /// than the segment that was lost, as Linux's does, and a SACKed range is
    /// skipped by arithmetic instead of by searching copies.
    tx_buf:           [u8; TCP_SND_BUF_SIZE],
    tx_head:          usize,
    /// When the retransmission timer was last (re)started: on sending into
    /// an empty queue (§5.1), on an ACK of new data (§5.3), on a timeout
    /// (§5.6), and on an ACK reporting new SACKed bytes during SACK recovery
    /// (`process_ack`). In the handshake and FIN states it times those retries instead.
    retx_time:        u64,
    rto_ticks:        u64,            // current RTO in ticks
    srtt:             u64,            // smoothed RTT (×1000 fixed-point)
    rttvar:           u64,            // RTT variance (×1000 fixed-point)
    /// Whether `srtt` and `rttvar` hold a measurement. A sample of 0 ticks —
    /// an ACK in the tick its segment left — leaves `srtt` at 0, so `srtt`
    /// itself cannot say whether one was taken.
    rtt_measured:     bool,
    /// Consecutive timeouts without the peer acknowledging anything new.
    retx_count:       u8,
    /// One segment is timed at a time (RFC 6298 §3): `rtt_seq` is the
    /// sequence just past it and `rtt_time` when it left. Cleared by any
    /// retransmission, which is Karn's algorithm: an ACK after a
    /// retransmission cannot say which transmission it answers.
    rtt_on:           bool,
    rtt_seq:          u32,
    rtt_time:         u64,

    // --- Keep-alive ---
    last_activity:    u64,            // last rx/tx timestamp (ticks)
    keepalive_probes: u8,             // probes sent without reply
    /// Tick at which the current persist cycle last probed, 0 when the peer's
    /// window is open. Kept separate from `last_activity` because a probe IS
    /// activity, and folding them would let the keepalive timer and this one
    /// reset each other.
    persist_time:     u64,
    /// Current persist interval in ticks, doubling per probe up to
    /// `PERSIST_MAX_MS`. Zero means no persist cycle is running.
    persist_ticks:    u64,
    /// Persist probes sent since the peer last said anything at all. Reset by
    /// any inbound segment, NOT by a window that is still zero.
    persist_probes:   u8,

    // --- Congestion control (RFC 5681, RFC 6582) ---
    cwnd:             u32,            // congestion window (bytes)
    ssthresh:         u32,            // slow-start threshold
    dup_ack_count:    u8,             // duplicate ACK counter
    recovery:         Recovery,
    /// SND.NXT when the current recovery began (RFC 6582 `recover`). An ACK
    /// below it is partial: more of that flight is still missing. Outside
    /// recovery it only answers whether SND.UNA is past the last recovery
    /// point, so once an ACK passes it, it follows one byte behind SND.UNA
    /// (`process_ack`).
    recover:          u32,
    /// Next byte recovery may retransmit. Bytes below it (and at or above
    /// SND.UNA) were already resent in this recovery. RFC 6675's HighRxt + 1.
    rtx_next:         u32,
    /// RFC 6675 RescueRxt + 1: one past the last byte of this recovery's
    /// rescue retransmission, or of its first retransmission until a rescue
    /// is sent. A rescue (NextSeg rule 4) is allowed only once SND.UNA is past
    /// it, which after a rescue — `rescue` = `recover` — is never again in the
    /// same recovery.
    rescue:           u32,
    /// Ranges the peer reported holding (RFC 2018), sorted by distance from
    /// SND.UNA, disjoint, all inside [SND.UNA, SND.NXT].
    sacked:           [(u32, u32); SACK_SCOREBOARD],
    sacked_n:         u8,
    /// When the last ACK answering an unacceptable segment went out; 0 when
    /// none has. See `INVALID_ACK_INTERVAL_MS`.
    last_invalid_ack: u64,

    // --- MSS negotiation ---
    remote_mss:       u16,            // MSS advertised by remote peer
    /// The MSS the path allows as far as this connection has learned; 0 until
    /// an ICMP Fragmentation Needed (`icmp_frag_needed`) or a black-hole
    /// timeout (`tcp_tick`) lowers it. Only ever lowered. Kept apart from
    /// `remote_mss`, which records what the peer advertised.
    pmtu_mss:         u16,

    // --- Peer's advertised receive window (RFC 793 SND.WND) ---
    /// Last advertised receive window from the peer, in BYTES — already
    /// multiplied by `snd_wscale`. Bound on how many bytes we can have in
    /// flight. Updated on every inbound ACK.
    /// Pre-fix: not stored at all; sender ignored the peer's window
    /// and could overshoot it, causing the peer to drop segments.
    remote_window:    u32,

    // --- Window scaling (RFC 7323) ---
    /// Both SYNs carried a Window Scale option. Kept apart from the shifts
    /// because a negotiated shift may legitimately be 0, and because a
    /// SYN-ACK retransmission must repeat exactly the options the first one
    /// carried.
    wscale_ok:        bool,
    /// The peer's shift, applied to every window field we READ after the
    /// handshake. 0 unless `wscale_ok`.
    snd_wscale:       u8,
    /// Our shift, applied to every window field we WRITE after the handshake.
    /// 0 unless `wscale_ok`.
    rcv_wscale:       u8,

    // --- SACK (RFC 2018) ---
    /// Both SYNs carried SACK-Permitted, so our ACKs may carry SACK blocks.
    sack_ok:          bool,

    // --- Out-of-order reassembly (F01) ---
    ooo_buf:          [OooSegment; OOO_MAX_SEGMENTS],
    /// Sequence of the most recent segment queued out of order. RFC 2018 §4
    /// puts the block holding it first, so a sender that reads only the first
    /// block still learns about the newest arrival.
    ooo_recent:       u32,

    // --- FIN state machine (F01) ---
    fin_seq:          u32,            // sequence number of our FIN
    time_wait_start:  u64,            // tick when TimeWait began

    // --- Delayed ACK (RFC 1122 §4.2.3.2, RFC 5681 §4.2; wave 15 N6) ---
    /// RCV.NXT has moved past what our last segment acknowledged and no ACK
    /// has left for it yet. Cleared by every segment we send that carries the
    /// current `ack` (see [`TcpConn::advertise`]).
    ack_pending:      bool,
    /// The held ACK came with PSH or a short segment: the read that empties
    /// the ring sends it (Linux `ICSK_ACK_PUSHED` in `tcp_cleanup_rbuf`).
    ack_pushed:       bool,
    /// The held ACK answers data that arrived in a poll pass, which flushes
    /// it when it ends (`TCP_DELACK_PASS_FLUSH`). A window update `recv`
    /// held is not: it waits for the next data ACK or the timer.
    ack_rx:           bool,
    /// When a held ACK must leave (tick), set when it starts being held.
    ack_due:          u64,
    /// In-order bytes taken since the last ACK we sent.
    rcv_unacked:      u32,
    /// The right edge of the window our last ACK advertised (RCV.NXT +
    /// window). Only grows; a stale (lower) value makes `recv` update early,
    /// never late.
    rcv_adv:          u32,

    /// Generation of this slot: bumped each time [`TcpLayer::alloc`] hands
    /// the slot out. A [`TcpHandle`] carries the value it was issued with,
    /// and every operation through a handle whose generation no longer
    /// matches is refused, so a slot freed under its owner (a peer's RST, a
    /// timer) and re-issued to someone else cannot be acted on through the
    /// old owner's handle. Never reset: `reset_conn_state` leaves it alone.
    gen:              u32,
}

impl TcpConn {
    pub const fn new() -> Self {
        TcpConn {
            state:        TcpState::Closed,
            local_ip:     [0; 4],
            local_port:   0,
            remote_ip:    [0; 4],
            remote_port:  0,
            seq:          0,
            ack:          0,
            was_accepted: false,
            gen:          0,
            rx_buf:       [0u8; TCP_BUF_SIZE],
            rx_head:      0,
            rx_tail:      0,

            snd_una:      0,
            tx_buf:       [0u8; TCP_SND_BUF_SIZE],
            tx_head:      0,
            retx_time:    0,
            rto_ticks:    0,
            srtt:         0,
            rttvar:       0,
            rtt_measured: false,
            retx_count:   0,
            rtt_on:       false,
            rtt_seq:      0,
            rtt_time:     0,

            last_activity:    0,
            keepalive_probes: 0,
            persist_time:  0,
            persist_ticks: 0,
            persist_probes: 0,

            cwnd:          0,
            ssthresh:      0,
            dup_ack_count: 0,
            // Every field of a fresh slot is zero, `Recovery::Open` included,
            // so the whole table stays in .bss rather than in the image.
            recovery:      Recovery::Open,
            recover:       0,
            rtx_next:      0,
            rescue:        0,
            sacked:        [(0, 0); SACK_SCOREBOARD],
            sacked_n:      0,
            last_invalid_ack: 0,

            remote_mss:    0,
            pmtu_mss:      0,
            remote_window: 0,

            wscale_ok:     false,
            snd_wscale:    0,
            rcv_wscale:    0,
            sack_ok:       false,

            ooo_buf:       [OooSegment::empty(); OOO_MAX_SEGMENTS],
            ooo_recent:    0,

            fin_seq:       0,
            time_wait_start: 0,

            ack_pending:   false,
            ack_pushed:    false,
            ack_rx:        false,
            ack_due:       0,
            rcv_unacked:   0,
            rcv_adv:       0,
        }
    }

    pub fn rx_available(&self) -> usize {
        if self.rx_tail >= self.rx_head {
            self.rx_tail - self.rx_head
        } else {
            TCP_BUF_SIZE - self.rx_head + self.rx_tail
        }
    }

    /// Reset congestion and retransmission state for a fresh connection.
    ///
    /// Called at slot creation on both open paths (`connect` and the listener's
    /// `SynRcvd`), so `retx_time` doubles as the slot's creation timestamp:
    /// `tcp_tick` uses it to age out half-open connections.  It is seeded to
    /// *now* rather than 0 for exactly that reason — a zero would read as
    /// "sent at boot" and make the first tick retransmit immediately.
    fn reset_conn_state(&mut self) {
        self.retx_time        = azos_drv_sys::timebase::now();
        self.rto_ticks        = RTO_INITIAL_MS * TICKS_PER_MS;
        self.srtt             = 0;
        self.rttvar           = 0;
        self.rtt_measured     = false;
        self.retx_count       = 0;
        self.tx_head          = 0;
        self.clear_send_queue();
        self.last_invalid_ack = 0;
        self.last_activity    = azos_drv_sys::timebase::now();
        self.keepalive_probes = 0;
        self.persist_time     = 0;
        self.persist_ticks    = 0;
        self.persist_probes   = 0;
        self.cwnd             = CWND_INITIAL;
        self.ssthresh         = SSTHRESH_INITIAL;
        self.remote_mss       = TCP_DEFAULT_REMOTE_MSS;
        // What one path allowed says nothing about the next connection's.
        self.pmtu_mss         = 0;
        self.rx_head          = 0;
        self.rx_tail          = 0;
        // Negotiated per connection, never inherited from a slot's previous
        // occupant: a stale shift would misread every window the new peer
        // sends.
        self.wscale_ok        = false;
        self.snd_wscale       = 0;
        self.rcv_wscale       = 0;
        self.sack_ok          = false;
        // The out-of-order queue too. It was not cleared here, so a reused
        // slot kept the previous connection's held segments: bytes from one
        // peer that a flush could splice into another's stream if the new
        // RCV.NXT ever reached their sequence, and ranges a SACK block would
        // now report as received.
        for seg in self.ooo_buf.iter_mut() {
            seg.valid = false;
        }
        self.ooo_recent       = 0;
        self.ack_pending      = false;
        self.ack_pushed       = false;
        self.ack_rx           = false;
        self.ack_due          = 0;
        self.rcv_unacked      = 0;
        self.rcv_adv          = 0;
        // U06-2: was NOT cleared here. `accept()` (below) hands a slot to the
        // caller only `!was_accepted`, and this flag was cleared only on the
        // RST arm and the SynRcvd reaper — never on an orderly close
        // (`close()`/FIN teardown/`LastAck`→`Closed`). Both open paths call
        // this fn (`connect` and the listener's SynRcvd setup), so clearing
        // it here means every fresh connection — reused slot or not — starts
        // unclaimed, and a listener that `accept()`s once is not permanently
        // deaf to the next client landing in the same slot.
        self.was_accepted     = false;
    }

    /// Start the send sequence at `iss`: nothing in flight, and no recovery
    /// point ahead of the first byte.
    fn set_iss(&mut self, iss: u32) {
        self.seq      = iss;
        self.snd_una  = iss;
        self.rtx_next = iss;
        self.recover  = iss;
    }

    /// Forget everything in flight: SND.UNA catches up with SND.NXT. For a
    /// slot that is being closed or reset — nothing will ever acknowledge
    /// those bytes.
    fn clear_send_queue(&mut self) {
        self.snd_una       = self.seq;
        self.rtx_next      = self.seq;
        self.recovery      = Recovery::Open;
        self.sacked_n      = 0;
        self.dup_ack_count = 0;
        self.rtt_on        = false;
    }

    /// Bytes in flight: SND.NXT - SND.UNA.
    fn flight(&self) -> u32 {
        self.seq.wrapping_sub(self.snd_una)
    }

    /// The largest segment this connection sends (RFC 5681 SMSS): the peer's
    /// MSS, ours, and the path's once it has been lowered.
    fn smss(&self) -> u32 {
        let path = if self.pmtu_mss == 0 { TCP_MSS as u32 } else { self.pmtu_mss as u32 };
        (self.remote_mss as u32).min(TCP_MSS as u32).min(path)
    }

    /// Copy `bytes` into the send ring `off` bytes past SND.UNA.
    fn tx_write(&mut self, off: usize, bytes: &[u8]) {
        let at = (self.tx_head + off) & TCP_SND_BUF_MASK;
        let first = bytes.len().min(TCP_SND_BUF_SIZE - at);
        self.tx_buf[at..at + first].copy_from_slice(&bytes[..first]);
        self.tx_buf[..bytes.len() - first].copy_from_slice(&bytes[first..]);
    }

    /// Copy `out.len()` bytes out of the send ring, starting `off` bytes past
    /// SND.UNA.
    fn tx_read(&self, off: usize, out: &mut [u8]) {
        let at = (self.tx_head + off) & TCP_SND_BUF_MASK;
        let first = out.len().min(TCP_SND_BUF_SIZE - at);
        out[..first].copy_from_slice(&self.tx_buf[at..at + first]);
        let rest = out.len() - first;
        out[first..].copy_from_slice(&self.tx_buf[..rest]);
    }

    /// The window field for this connection's current free space.
    fn adv_window(&self) -> u16 {
        adv_window(rx_free_space(self), self.rcv_wscale)
    }

    /// [`adv_window`](Self::adv_window) for a segment that is about to leave
    /// carrying `self.ack`: whatever ACK was held is now sent with it, and the
    /// right edge it advertises is remembered for `recv`'s window-update rule.
    fn advertise(&mut self) -> u16 {
        let win = self.adv_window();
        if self.ack_pending { ack_count(ACKS_PIGGYBACK); }
        self.note_ack_sent(win);
        win
    }

    fn note_ack_sent(&mut self, win: u16) {
        self.ack_pending = false;
        self.ack_pushed  = false;
        self.ack_rx      = false;
        self.rcv_unacked = 0;
        let edge = self.ack.wrapping_add((win as u32) << self.rcv_wscale);
        // Only forward: a window field rounded down by the scale must not
        // make the remembered edge retreat.
        if edge.wrapping_sub(self.rcv_adv) < 1u32 << 31 { self.rcv_adv = edge; }
    }

    /// The pure ACK this connection would send now, recorded as sent.
    fn take_ack(&mut self) -> AckOut {
        let win = self.adv_window();
        let mut opts = [0u8; TCP_OPT_MAX];
        let opts_len = sack_option(self, &mut opts);
        self.note_ack_sent(win);
        AckOut {
            dst: self.remote_ip, sp: self.local_port, dp: self.remote_port,
            seq: self.seq, ack: self.ack, win, opts, opts_len,
        }
    }

    /// Hold the ACK for what just arrived instead of sending it now.
    /// `rx`: it answers inbound data (the end of the poll pass sends it);
    /// otherwise it is a window update from `recv` (the timer or the next
    /// data ACK sends it).
    fn hold_ack(&mut self, now: u64, pushed: bool, rx: bool) {
        if !self.ack_pending {
            self.ack_pending = true;
            self.ack_due = now.wrapping_add(TCP_DELACK_TICKS);
        }
        self.ack_pushed |= pushed;
        self.ack_rx     |= rx;
        ACK_HELD.store(true, core::sync::atomic::Ordering::Release);
    }
}

/// A pure ACK snapshotted under the TCP lock, sent after it is dropped.
struct AckOut {
    dst: [u8; 4], sp: u16, dp: u16, seq: u32, ack: u32, win: u16,
    opts: [u8; TCP_OPT_MAX], opts_len: usize,
}

fn send_ack(mac: &[u8; 6], ip: &[u8; 4], a: &AckOut) {
    send_segment_opts(mac, ip, &a.dst, a.sp, a.dp, TCP_ACK, a.seq, a.ack, a.win,
                      &a.opts[..a.opts_len], &[]);
}

/// Send the ACKs connections hold: at the end of a poll pass
/// (`due_only == false`) every one that answers inbound data, and any whose
/// [`TCP_DELACK_TICKS`] ran out; from `tcp_tick` (`due_only`) only the latter.
/// Returns how many left. A pass with nothing held costs one atomic swap.
pub fn flush_held_acks(due_only: bool) -> usize {
    use core::sync::atomic::Ordering;
    if !ACK_HELD.swap(false, Ordering::AcqRel) { return 0; }
    let now = azos_drv_sys::timebase::now();
    const BATCH: usize = 4;
    let mut sent = 0usize;
    let mut still_held = false;
    let mut idx = 0usize;
    while idx < TCP_MAX_CONNS {
        // Up to BATCH ACKs per lock hold; none is sent with the lock held.
        let mut out: [Option<AckOut>; BATCH] = [const { None }; BATCH];
        let mut n = 0usize;
        let (mac, ip) = {
            let mut t = TCP.lock();
            let (mac, ip) = (t.our_mac, t.our_ip);
            while idx < TCP_MAX_CONNS && n < BATCH {
                let c = &mut t.conns[idx];
                idx += 1;
                if !c.ack_pending { continue; }
                if !matches!(c.state, TcpState::Established | TcpState::CloseWait
                             | TcpState::FinWait1 | TcpState::FinWait2) {
                    c.ack_pending = false;
                    continue;
                }
                if (due_only || !c.ack_rx) && (now.wrapping_sub(c.ack_due) as i64) < 0 {
                    still_held = true;
                    continue;
                }
                if due_only { timer_fired(c.ack_due, now); }
                out[n] = Some(c.take_ack());
                n += 1;
            }
            (mac, ip)
        };
        for a in out[..n].iter().flatten() {
            send_ack(&mac, &ip, a);
            ack_count(if due_only { ACKS_TIMER } else { ACKS_PASS });
        }
        sent += n;
    }
    if still_held { ACK_HELD.store(true, Ordering::Release); }
    sent
}

impl TcpConn {

    /// The largest receive window this connection can ever have advertised,
    /// in bytes: what "in window" means for an inbound segment.
    ///
    /// Without scaling that is 65535, exactly the constant every acceptability
    /// check used before, so a connection that negotiated nothing — which
    /// includes every peer that does not offer the option — keeps the same
    /// blind-injection cost. With scaling it is the whole ring.
    fn rcv_wnd_max(&self) -> u32 {
        ((TCP_WINDOW_SIZE as u32) << self.rcv_wscale).min(TCP_BUF_SIZE as u32)
    }
}

// ---------------------------------------------------------------------------
// TcpLayer
// ---------------------------------------------------------------------------

struct TcpLayer {
    conns:        [TcpConn; TCP_MAX_CONNS],
    our_mac:      [u8; 6],
    our_ip:       [u8; 4],
    /// M26: hint for `find_conn` — the slot it matched last time.
    ///
    /// `TcpConn` is 268 KB at the edge profile (38 KB at fleet), so a plain
    /// linear scan of `conns` touches one cache line per slot at a stride
    /// far larger than any prefetcher follows — every inbound segment paid
    /// that, up to `TCP_MAX_CONNS` touches (8 at edge, 1024 at fleet), under
    /// the single global lock every OTHER inbound segment is also waiting
    /// on. TCP traffic is bursty per-connection: many consecutive segments
    /// share the same 4-tuple, so checking this slot first turns the common
    /// case into ONE touch instead of the whole table.
    ///
    /// Purely a hint, never trusted blind: `find_conn` re-checks the
    /// 4-tuple (and that the slot is not `Closed`) before returning it, so
    /// a stale value — the slot closed, or was reused for a different
    /// peer — costs exactly the fallback scan below, never a wrong answer.
    /// `TCP_MAX_CONNS` itself is the "no hint yet" sentinel (`new()`'s
    /// value), since it is never a valid index.
    last_matched: usize,
    /// Next offset into the ephemeral port range ([`TcpLayer::ephemeral_port`]);
    /// seeded from boot entropy by [`isn_secret_seed`].
    eph_next:     u32,
}

/// Slots `find_conn` actually examined (hint check + fallback scan combined),
/// summed since boot. Exists so a host test can measure exactly what M26
/// changed — this crate has no cycle counter or `-icount` on the host,
/// where neither instructions nor a hardware cache-miss counter exist, but
/// "how many slots did the lookup touch" is countable in Rust alone and is
/// the number the fix claims to move.
static FIND_CONN_SLOT_TOUCHES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Read [`FIND_CONN_SLOT_TOUCHES`]. `pub` so `tests/host/net-tests` (which pulls
/// this file in whole via `#[path]`) can read it directly, the same as any
/// other function here.
pub fn find_conn_slot_touches() -> u64 {
    FIND_CONN_SLOT_TOUCHES.load(core::sync::atomic::Ordering::Relaxed)
}

impl TcpLayer {
    const fn new() -> Self {
        TcpLayer {
            conns:        [TcpConn::new(); TCP_MAX_CONNS],
            our_mac:      [0; 6],
            our_ip:       [0; 4],
            last_matched: TCP_MAX_CONNS, // out of range: "no hint yet"
            eph_next:     0,
        }
    }

    fn find_conn(&mut self, local_port: u16, remote_ip: &[u8; 4], remote_port: u16) -> Option<usize> {
        if self.last_matched < TCP_MAX_CONNS {
            FIND_CONN_SLOT_TOUCHES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let c = &self.conns[self.last_matched];
            if c.state != TcpState::Closed
                && c.local_port == local_port
                && &c.remote_ip == remote_ip
                && c.remote_port == remote_port
            {
                return Some(self.last_matched);
            }
        }
        for i in 0..TCP_MAX_CONNS {
            FIND_CONN_SLOT_TOUCHES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let c = &self.conns[i];
            if c.state != TcpState::Closed
                && c.local_port == local_port
                && &c.remote_ip == remote_ip
                && c.remote_port == remote_port
            {
                self.last_matched = i;
                return Some(i);
            }
        }
        None
    }

    fn find_listener(&self, port: u16) -> Option<usize> {
        for i in 0..TCP_MAX_CONNS {
            if self.conns[i].state == TcpState::Listen && self.conns[i].local_port == port {
                return Some(i);
            }
        }
        None
    }

    /// A free slot, with its generation advanced: every [`TcpHandle`] issued
    /// for an earlier owner of the slot is stale from here on. The one place
    /// a slot changes hands, so the one place the generation moves.
    fn alloc(&mut self) -> Option<usize> {
        for i in 0..TCP_MAX_CONNS {
            if self.conns[i].state == TcpState::Closed {
                #[cfg(not(feature = "tcp-handle-gen-canary"))]
                { self.conns[i].gen = self.conns[i].gen.wrapping_add(1); }
                return Some(i);
            }
        }
        None
    }

    /// The handle of slot `idx` as it stands now.
    fn handle(&self, idx: usize) -> TcpHandle {
        TcpHandle { slot: idx as u32, gen: self.conns[idx].gen }
    }

    /// Does `r` still name the connection it was issued for?
    #[inline]
    fn live(&self, r: Ref) -> bool {
        r.idx < TCP_MAX_CONNS && r.gen.map_or(true, |g| self.conns[r.idx].gen == g)
    }

    /// A free local port from the ephemeral range
    /// (`CONFIG_TCP_EPHEMERAL_PORT_MIN..=MAX`), or `None` when every port in
    /// it is taken. A port is taken while any slot that is not `Closed`
    /// holds it as its local port -- listeners and `TimeWait` included, so a
    /// fresh connect never names the 4-tuple of a connection the peer may
    /// still hold. The cursor moves past every port handed out, so two
    /// consecutive connects never get the same port even when the first
    /// connection is already gone (Linux's `__inet_hash_connect` walks its
    /// range the same way).
    fn ephemeral_port(&mut self) -> Option<u16> {
        let span = EPHEMERAL_SPAN;
        for _ in 0..span {
            let p = EPHEMERAL_MIN.wrapping_add((self.eph_next % span) as u16);
            #[cfg(not(feature = "tcp-ephemeral-port-canary"))]
            { self.eph_next = self.eph_next.wrapping_add(1); }
            #[cfg(not(feature = "tcp-ephemeral-port-canary"))]
            if self.conns.iter().any(|c| c.state != TcpState::Closed && c.local_port == p) {
                continue;
            }
            return Some(p);
        }
        None
    }
}

/// Lowest port of the ephemeral range (`CONFIG_TCP_EPHEMERAL_PORT_MIN`).
pub const EPHEMERAL_MIN: u16 = azos_limits::TCP_EPHEMERAL_PORT_MIN as u16;
/// Highest port of the ephemeral range (`CONFIG_TCP_EPHEMERAL_PORT_MAX`).
pub const EPHEMERAL_MAX: u16 = azos_limits::TCP_EPHEMERAL_PORT_MAX as u16;
const _: () = assert!(azos_limits::TCP_EPHEMERAL_PORT_MAX <= 65535
    && EPHEMERAL_MIN != 0 && EPHEMERAL_MIN <= EPHEMERAL_MAX,
    "CONFIG_TCP_EPHEMERAL_PORT_MIN must be in 1..=CONFIG_TCP_EPHEMERAL_PORT_MAX <= 65535");
/// Ports in the ephemeral range.
const EPHEMERAL_SPAN: u32 = EPHEMERAL_MAX as u32 - EPHEMERAL_MIN as u32 + 1;

/// One TCP connection, as its owner holds it: the slot and the generation the
/// slot had when it was issued (see `TcpConn::gen`).
///
/// **The only way to reach a connection from outside this crate.** Every
/// operation on a handle whose slot has since been freed and re-issued is a
/// no-op: `close`/`abort`/`shutdown_write` do nothing, `send` and `recv`
/// answer -1, `state` answers `Closed`. A bare slot index has no such check:
/// a kernel task that closed "its" slot after a wait closed whichever
/// connection held the slot by then -- the brain link's, after a refused
/// connect let RST free the slot and the link's dial took it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TcpHandle {
    slot: u32,
    gen:  u32,
}

/// What the in-crate functions below take: a slot, with the generation to
/// check when the caller holds one. A bare `usize` (the stack itself, the
/// socket table's tests) checks nothing; a [`TcpHandle`] checks its
/// generation at every lock hold that touches the slot.
#[derive(Clone, Copy)]
pub(crate) struct Ref {
    idx: usize,
    gen: Option<u32>,
}

impl From<usize> for Ref {
    fn from(idx: usize) -> Ref { Ref { idx, gen: None } }
}

impl From<TcpHandle> for Ref {
    fn from(h: TcpHandle) -> Ref { Ref { idx: h.slot as usize, gen: Some(h.gen) } }
}

static TCP: SpinLock<TcpLayer> = SpinLock::new(TcpLayer::new());

// ---------------------------------------------------------------------------
// ISN generation (RFC 6528)
// ---------------------------------------------------------------------------

/// ISN generator, RFC 6528: `ISN = M + F(localip, localport, remoteip,
/// remoteport, secretkey)`. `M` is the 4 µs timer below; `F` is HMAC-SHA256
/// keyed on `ISN_SECRET`, taking the 4-tuple as its message.
///
/// U06-6: this replaced an invertible FNV-1a hash (each step a bijection
/// mod 2^32) over the same inputs. FNV is not the keyed cryptographic hash
/// RFC 6528 §3 asks for — one observed ISN let an attacker subtract the
/// (bounded, low-variance) time term and invert every FNV step in order to
/// recover the 32-bit secret, after which the ISN for any other 4-tuple was
/// just another hash computation. HMAC-SHA256 has no such inversion: only
/// the low 32 bits of the 256-bit MAC are used, and a preimage attack on
/// those is the same cost as guessing them outright.
fn generate_isn(src_ip: &[u8; 4], dst_ip: &[u8; 4], src_port: u16, dst_port: u16) -> u32 {
    let sp = src_port.to_be_bytes();
    let dp = dst_port.to_be_bytes();
    let secret = *ISN_SECRET.lock();
    let mac = azos_crypto::entropy::hmac_sha256(
        &secret,
        &[&src_ip[..], &sp[..], &dst_ip[..], &dp[..]],
    );
    let h = u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]);

    // Add time component for uniqueness across reboots and so an ISN never
    // repeats for the same 4-tuple within one boot even if F() ever did.
    let ticks = azos_drv_sys::timebase::now();
    h.wrapping_add(ticks as u32)
}

// ---------------------------------------------------------------------------
// MSS option parsing
// ---------------------------------------------------------------------------

/// What a peer's SYN or SYN-ACK offered.
#[derive(Clone, Copy)]
struct SynOptions {
    /// Advertised MSS, floored; `TCP_DEFAULT_REMOTE_MSS` if absent.
    mss:     u16,
    /// Window Scale shift, clamped to `TCP_WSCALE_MAX`; `None` if absent.
    wscale:  Option<u8>,
    /// SACK-Permitted was present.
    sack_ok: bool,
}

/// Which options a SYN or SYN-ACK we send carries, beyond the MSS every one of
/// them has.
#[derive(Clone, Copy)]
struct SynOffer {
    wscale: bool,
    sack:   bool,
}

impl SynOffer {
    /// An active open offers everything; the SYN-ACK decides what sticks.
    const ALL: SynOffer = SynOffer { wscale: true, sack: true };
}

/// Walk the options of a SYN or SYN-ACK.
///
/// The MSS rules are the ones this walk has always had, and the boot
/// conformance block asserts them: the first MSS option wins, a malformed MSS
/// stops the walk and leaves the RFC 879 default, and the value is floored.
/// Window Scale and SACK-Permitted are collected along the way under the same
/// discipline — a malformed instance stops the walk, so a truncated or
/// mis-sized option can never switch scaling on.
fn parse_syn_options(data: &[u8], hdr_len: usize) -> SynOptions {
    let mut out = SynOptions { mss: TCP_DEFAULT_REMOTE_MSS, wscale: None, sack_ok: false };
    if hdr_len <= TCP_HDR_MIN || data.len() < hdr_len {
        return out;
    }
    let opts = &data[TCP_HDR_MIN..hdr_len];
    let mut mss_seen = false;
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            TCP_OPT_EOL => break,
            TCP_OPT_NOP => { i += 1; }
            TCP_OPT_MSS if !mss_seen => {
                if i + (TCP_OPT_MSS_LEN as usize) <= opts.len()
                    && opts[i + 1] == TCP_OPT_MSS_LEN
                {
                    let mss = u16::from_be_bytes([opts[i + 2], opts[i + 3]]);
                    // Floor the peer's value: `send_data` sizes every segment
                    // by `remote_mss`, so an advertised MSS of 0 makes it
                    // return 0 forever and `send_all_with_yield` burns its
                    // whole yield budget without progress — a peer-inflicted
                    // stall. 64 is the same defensive floor Linux applies
                    // (tcp_min_snd_mss) for exactly this attack.
                    out.mss = mss.max(64);
                    mss_seen = true;
                    i += TCP_OPT_MSS_LEN as usize;
                    continue;
                }
                break;
            }
            TCP_OPT_WSCALE if out.wscale.is_none() => {
                if i + (TCP_OPT_WSCALE_LEN as usize) <= opts.len()
                    && opts[i + 1] == TCP_OPT_WSCALE_LEN
                {
                    // RFC 7323 §2.3: a shift above 14 is used as 14.
                    out.wscale = Some(opts[i + 2].min(TCP_WSCALE_MAX));
                    i += TCP_OPT_WSCALE_LEN as usize;
                    continue;
                }
                break;
            }
            TCP_OPT_SACK_PERM if !out.sack_ok => {
                if i + (TCP_OPT_SACK_PERM_LEN as usize) <= opts.len()
                    && opts[i + 1] == TCP_OPT_SACK_PERM_LEN
                {
                    out.sack_ok = true;
                    i += TCP_OPT_SACK_PERM_LEN as usize;
                    continue;
                }
                break;
            }
            _ => {
                // Unknown option, or a repeat of one already taken — skip
                // using length byte
                if i + 1 >= opts.len() { break; }
                let opt_len = opts[i + 1] as usize;
                if opt_len < 2 { break; } // malformed
                i += opt_len;
                continue;
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Sequence number validation
// ---------------------------------------------------------------------------



/// Is `ack` inside `[SND.UNA - MAX.SND.WND, SND.NXT]` (RFC 5961 §5.2)?
///
/// Inclusive at both ends: a pure window update legitimately carries
/// `ACK == SND.UNA`, and an ACK for everything we sent carries `SND.NXT`. The
/// lower slack of one window admits a genuine peer's segments that were in
/// flight when a later ACK already advanced `SND.UNA`. Everything else is
/// acknowledging data we never sent, which no peer that can see the flow does.
fn ack_acceptable(ack: u32, snd_una: u32, snd_nxt: u32) -> bool {
    let lower = snd_una.wrapping_sub(TCP_WINDOW_SIZE as u32);
    ack.wrapping_sub(lower) <= snd_nxt.wrapping_sub(lower)
}

/// RFC 793 §3.3 acceptability test for a segment on a synchronised connection.
///
/// Every inbound segment must pass this — not only the ones carrying data.
/// The window check used to sit inside `if !payload.is_empty()`, so a
/// payload-free segment skipped it entirely and still reached the ACK
/// processing that stores the peer's advertised window: a single spoofed bare
/// ACK advertising window 0 stopped the transmit side forever (`send_data`
/// returns 0 on a closed window) while the connection went on looking healthy.
/// The same unchecked path drove `dup_ack_count` and the congestion window.
///
/// With this in place, an off-path attacker who has already guessed the
/// 4-tuple must additionally land `seq` inside a 64 KiB window out of the
/// 2^32 sequence space — the whole ring on a connection that negotiated window
/// scaling, because that is the window we really offer there (128 KiB on
/// edge; a ring below 64 KiB, as on fleet, caps both).
///
/// The window used is `rcv_wnd_max`, not the live advertised window: it is a
/// superset of what we have really advertised, which keeps legitimate peers
/// (retransmissions, segments in flight when our window shrank) from being
/// rejected while still costing a blind attacker ~2^16 (~2^15 scaled).
///
/// `seg_len` counts a FIN as one byte. The RFC's table has four cases, and the
/// one that matters in practice is the last: a segment whose FIRST byte is
/// behind RCV.NXT but whose LAST is not. That is an ordinary retransmission
/// that overlaps what already arrived, and testing the first byte alone
/// dropped it in silence. `process_inbound_payload` trims the front.
///
/// A zero-length segment at `RCV.NXT - 1` — the keep-alive probe, and our own
/// persist probe — is NOT acceptable. It used to be, as an exception, on the
/// reasoning that a node dropping the other's probes would be torn down by
/// its keep-alive timer. Accepting it did not help that: a probe asks for an
/// answer, and nothing answered. The caller now replies to every unacceptable
/// segment with an ACK (RFC 793 §3.9), which is the answer the probe wants.
fn segment_acceptable(seq_num: u32, seg_len: usize, rcv_nxt: u32, rcv_wnd: u32) -> bool {
    if seq_in_window(seq_num, rcv_nxt, rcv_wnd) {
        return true;
    }
    seg_len > 0
        && seq_in_window(seq_num.wrapping_add(seg_len as u32 - 1), rcv_nxt, rcv_wnd)
}

// ---------------------------------------------------------------------------
// RTT / RTO update (RFC 6298)
// ---------------------------------------------------------------------------

/// Update SRTT, RTTVAR, and RTO from a measured RTT sample.
fn update_rtt(conn: &mut TcpConn, measured_ticks: u64) {
    let r = measured_ticks * RTT_SCALE; // scale to fixed-point

    if !conn.rtt_measured {
        // First measurement (RFC 6298 §2.2). Keyed on the flag, not on
        // `srtt == 0`: a 0-tick sample is a measurement too.
        conn.srtt   = r;
        conn.rttvar = r / 2;
        conn.rtt_measured = true;
    } else {
        // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|
        let diff = if conn.srtt > r { conn.srtt - r } else { r - conn.srtt };
        conn.rttvar = (conn.rttvar * (RTTVAR_BETA_INV - 1) + diff) / RTTVAR_BETA_INV;

        // SRTT = (1 - alpha) * SRTT + alpha * R
        conn.srtt = (conn.srtt * (SRTT_ALPHA_INV - 1) + r) / SRTT_ALPHA_INV;
    }

    // RTO = SRTT + max(G, 4 * RTTVAR, RTO_VAR_FLOOR). G, 1 ms, is below the
    // floor; it stays because RFC 6298 §2.3 writes the term with it.
    let rttvar_component = conn.rttvar * 4 / RTT_SCALE;
    let floor = CLOCK_GRANULARITY_TICKS.max(RTO_VAR_FLOOR_MS * TICKS_PER_MS);
    let k_rttvar = if rttvar_component > floor { rttvar_component } else { floor };
    let rto = conn.srtt / RTT_SCALE + k_rttvar;

    // Clamp to [RTO_MIN, RTO_MAX]
    let rto_min = RTO_MIN_MS * TICKS_PER_MS;
    let rto_max = RTO_MAX_MS * TICKS_PER_MS;
    conn.rto_ticks = if rto < rto_min {
        rto_min
    } else if rto > rto_max {
        rto_max
    } else {
        rto
    };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Configure the TCP layer with our network addresses.
pub fn init(mac: [u8; 6], ip: [u8; 4]) {
    isn_secret_from_pool();
    let mut t = TCP.lock();
    t.our_mac = mac;
    t.our_ip  = ip;
}

/// Re-point the TCP layer at a new local address.
///
/// TCP keeps its own copy of the address because every segment needs it for the
/// pseudo-header. `init` used to be the only writer, so anything that changed
/// the address afterwards — DHCP is the one that matters — left TCP building
/// and verifying checksums against the OLD address while the rest of the stack
/// had moved on. Symptom: every TCP segment silently fails checksum and the
/// connection never establishes, with no error anywhere.
///
/// Called from `net_set_ip`, so callers configure the address in one place.
/// Changing the address with connections live is not meaningful — existing
/// slots keep the endpoints they were opened with — but at boot, which is when
/// DHCP runs, there are none.
pub fn set_our_ip(ip: [u8; 4]) {
    let mut t = TCP.lock();
    t.our_ip = ip;
}

/// Listen on a port.  Returns connection slot index or -1 on failure.
/// Listen on `port`. Returns the slot index or -1. By slot: for this crate's
/// host tests; everything else holds a [`TcpHandle`] ([`TcpHandle::listen`]).
#[allow(dead_code)]
pub(crate) fn listen(port: u16) -> i32 {
    listen_h(port).map_or(-1, |h| h.slot as i32)
}

fn listen_h(port: u16) -> Option<TcpHandle> {
    let mut t = TCP.lock();
    let ip = t.our_ip;
    let idx = t.alloc()?;
    t.conns[idx].state      = TcpState::Listen;
    t.conns[idx].local_ip   = ip;
    t.conns[idx].local_port = port;
    t.conns[idx].remote_ip  = [0; 4];
    t.conns[idx].remote_port = 0;
    Some(t.handle(idx))
}


/// Initiate an outgoing TCP connection.  Returns connection index or -1.
/// Connection is not established until state == Established.
///
/// -1 also when another slot holds the same 4-tuple in any state but
/// `TimeWait` (see below); the caller retries once that connection is gone.
///
/// **First-SYN behavior**: this function does NOT block on ARP — if the
/// destination MAC is not cached, `ip::send` returns -1, the SYN is dropped
/// silently, and the caller must retry (typically via the brain-task's
/// outer reconnect loop).  Use `connect_with_yield` instead for a
/// blocking-with-yield variant that issues the SYN only once ARP has
/// resolved, eliminating the "first attempt always stalls" pattern under
/// SLIRP/QEMU.
///
/// `src_port == 0` picks a free port from the ephemeral range under the same
/// lock hold that takes the slot ([`TcpLayer::ephemeral_port`]); -1 when the
/// range is exhausted. By slot: for this crate's host tests; everything else
/// holds a [`TcpHandle`] ([`TcpHandle::connect`]).
#[allow(dead_code)]
pub(crate) fn connect(dst_ip: [u8; 4], dst_port: u16, src_port: u16) -> i32 {
    connect_h(dst_ip, dst_port, src_port).map_or(-1, |h| h.slot as i32)
}

fn connect_h(dst_ip: [u8; 4], dst_port: u16, src_port: u16) -> Option<TcpHandle> {
    let mut t = TCP.lock();
    let (mac, ip) = (t.our_mac, t.our_ip);
    let src_port = if src_port == 0 { t.ephemeral_port()? } else { src_port };

    // **A 4-tuple held by a live connection refuses the connect.** A 4-tuple
    // names one connection (RFC 793 §2.7), and an OPEN of one that exists is
    // an error (§3.9). The case that arrives in practice is a redial from a
    // fixed local port while the old connection is still closing (FIN-WAIT-1,
    // FIN-WAIT-2, LAST-ACK): `alloc` handed out a second slot, `find_conn`
    // kept routing the 4-tuple to the old one, and the new slot sat in
    // SYN-SENT while its SYN-ACK was dropped or answered with the old
    // connection's numbers. Linux refuses the same connect (EADDRNOTAVAIL).
    // The caller retries; the old connection's own teardown bounds the wait,
    // and TIME-WAIT below does not refuse at all. Aborting the old connection
    // instead would reset the peer and discard whatever it had not yet read.
    for c in t.conns.iter() {
        if c.state != TcpState::Closed
            && c.state != TcpState::Listen
            && c.state != TcpState::TimeWait
            && c.local_port == src_port
            && c.remote_ip == dst_ip
            && c.remote_port == dst_port
        {
            return None;
        }
    }

    // **A 4-tuple still in TIME-WAIT is reclaimed, not duplicated.** The brain
    // link dials from a fixed local port, so after `close()` from Established
    // its reconnect names exactly the 4-tuple our old slot holds for
    // `TIME_WAIT_MS`. Nothing checked: `alloc` handed out a second slot for
    // the same 4-tuple, `find_conn` returns whichever has the lower index, and
    // when that was the TIME-WAIT slot the SYN-ACK was swallowed by its arm —
    // the handshake stalled until the old slot expired.
    //
    // What TIME-WAIT protects is the new incarnation from segments of the old
    // one. We choose the new ISS, so we can place it past every sequence
    // number the old connection used — its FIN was the last — and strictly
    // past the RCV.NXT a peer holding its own TIME-WAIT compares a SYN against
    // (RFC 1122 §4.2.2.13). RFC 6191 rests the same reuse on the same rule.
    let mut iss_floor: Option<u32> = None;
    for c in t.conns.iter_mut() {
        if c.state == TcpState::TimeWait
            && c.local_port == src_port
            && c.remote_ip == dst_ip
            && c.remote_port == dst_port
        {
            iss_floor = Some(c.seq.wrapping_add(1));
            c.state = TcpState::Closed;
            c.clear_send_queue();
        }
    }

    let idx = t.alloc()?;
    let h = t.handle(idx);
    let mut seq = generate_isn(&ip, &dst_ip, src_port, dst_port);
    if let Some(floor) = iss_floor {
        if !seq_lt(floor, seq) {
            seq = floor.wrapping_add(1);
        }
    }
    t.conns[idx].state       = TcpState::SynSent;
    t.conns[idx].local_ip    = ip;
    t.conns[idx].local_port  = src_port;
    t.conns[idx].remote_ip   = dst_ip;
    t.conns[idx].remote_port = dst_port;
    t.conns[idx].ack         = 0;
    t.conns[idx].reset_conn_state();
    t.conns[idx].set_iss(seq);

    // Send SYN with MSS, Window Scale and SACK-Permitted
    send_syn_segment(&mac, &ip, &dst_ip, src_port, dst_port, TCP_SYN, seq, 0, SynOffer::ALL);
    drop(t);
    // The SYN's retransmission needs `tcp_tick`, and this runs in the
    // caller's context, not the poller's: tell the poller.
    timer_kick();
    Some(h)
}

/// Like `connect`, but yields until the ARP cache has the destination MAC
/// before issuing the SYN.
///
/// U06 §4 comment audit (2026-09-26): this doc used to say the first
/// `ip::send` inside `crate::send_syn_segment` "would normally trigger an
/// ARP request and return -1" on a cold cache — stale. `ip::send` queues an
/// unresolved frame instead of dropping it (see its own doc), so a plain
/// `connect()` SYN is no longer lost on an ARP miss either. What this
/// function still buys over that: the queued SYN waits for
/// `arp::arp_resolved` to release it, on no particular schedule relative to
/// this function's own budget, and it still counts as "sent" for `tcp_tick`'s
/// retransmission timer the instant it is queued — so a slow ARP reply can
/// make the very first retransmission fire before the original frame ever
/// reached the wire. Resolving up front, then calling the standard
/// `connect` (which now hits the populated cache and sends the SYN in one
/// pass), keeps the SYN and its retransmission clock in step.
///
/// `yield_fn` is injected to keep `crates/net/net` scheduler-agnostic — same
/// pattern as `send_all_with_yield`.  Falls back to the non-blocking
/// `connect` after [`CONNECT_ARP_BUDGET_US`] to bound worst-case latency.
#[allow(dead_code)]
pub(crate) fn connect_with_yield<F: FnMut()>(
    dst_ip:   [u8; 4],
    dst_port: u16,
    src_port: u16,
    yield_fn: F,
) -> i32 {
    connect_with_yield_h(dst_ip, dst_port, src_port, yield_fn).map_or(-1, |h| h.slot as i32)
}

fn connect_with_yield_h<F: FnMut()>(
    dst_ip:   [u8; 4],
    dst_port: u16,
    src_port: u16,
    mut yield_fn: F,
) -> Option<TcpHandle> {
    // Snapshot our addresses to issue the ARP request without holding TCP.lock.
    let (our_mac, our_ip) = { let t = TCP.lock(); (t.our_mac, t.our_ip) };

    // If the cache already has the entry (subsequent connects, gateway hot),
    // skip the resolution step entirely.
    // If we time out, fall through to plain `connect` anyway — it'll fire
    // another ARP and return SynSent; the caller's reconnect loop is still the
    // last-resort fallback.
    let _ = resolve_peer_mac(&our_mac, &our_ip, &dst_ip, CONNECT_ARP_BUDGET_US, &mut yield_fn);

    connect_h(dst_ip, dst_port, src_port)
}

/// Wall-clock budget for resolving the peer's MAC before a DATA segment, in µs.
///
/// **Derived from the deadlines on this path, then checked against a
/// measurement** — neither half alone was enough.
///
/// The deadlines: `rt_motor_task`'s watchdog SAFE-STOPs after 500 ms without a
/// command, and `brain_client` runs its loop every 50 ms. A send that blocks
/// for a loop period delays one command; one that blocks for the watchdog
/// interval stops the robot. So the ceiling is an order of magnitude under the
/// watchdog, and at most one loop period.
///
/// The measurement (2026-09-09, `arp-timing`, with the ARP microbenchmarks
/// restored to wiping the live cache as a hostile load): resolution completed
/// in **9 428 µs and 9 742 µs** over two runs, ~5 700 yields each. So 50 ms is
/// ~5x the observed worst case, and the earlier 500-yield budget failed simply
/// because ~5 700 were needed.
///
/// **On real hardware this number is wrong and must be re-measured.** ARP
/// answers in tens of µs there; ~9.5 ms is QEMU TCG. Build with `arp-timing`
/// and read `[ARPTIME]` — that is what the feature is for.
// NOTE (2026-09-10): the layer below no longer LOSES a packet on an ARP miss —
// `ip::send` queues it and delivers it when the reply lands. That makes this
// pre-resolve an optimisation (it keeps the segment in order and avoids a
// round trip's worth of latency on the first send) rather than the difference
// between a datagram arriving and vanishing. The budget below is still a QEMU
// number and still needs measuring on the board.
pub const SEND_ARP_BUDGET_US: u64 = 50_000;

/// Same, for `connect`. Larger because connecting is a one-off that no control
/// loop is waiting on, and the old count was documented as "a fraction of a
/// second under QEMU".
pub const CONNECT_ARP_BUDGET_US: u64 = 500_000;

/// Fail-safe iteration cap for [`resolve_peer_mac`]. Not the budget — the
/// deadline is. This exists only so a timer that stops advancing cannot turn
/// the loop into a hang.
pub const ARP_RESOLVE_SPIN_CAP: u32 = 5_000_000;

/// [`send_data`], but resolve the peer's MAC first if the ARP cache has lost it.
///
/// **The defect this closes.** `ip::send` answers an ARP miss by emitting a
/// request and returning -1, and `send_data` turns any transmit failure into
/// -1 — which reaches ring 3 as a fatal error. `brain_client` treats any
/// negative as fatal and tears down a healthy `Established` connection over a
/// cache miss. Measured 2026-09-08: the ARP microbenchmarks were evicting the
/// gateway's entry, and the symptom read as a TCP transport bug three layers
/// away.
///
/// `connect_with_yield` has done exactly this since it was written, and its
/// doc says why — "the first `ip::send` would normally trigger an ARP request
/// and return -1". The data path never got the same treatment.
///
/// **Why pre-resolve instead of reporting the transient.** Returning 0
/// ("retry later", which is what this function already answers for a closed
/// peer window and for a full send window) was considered and REJECTED by the
/// owner on 2026-09-08: callers that read 0 as success — `brain_client` does —
/// would silently drop the frame, trading a visible failure for silent data
/// loss. Pre-resolving keeps the return contract untouched, so no existing
/// caller changes behaviour.
///
/// **Cost in the common case: one cache lookup.** The yield loop is entered
/// only on a miss.
pub(crate) fn send_data_with_yield<F: FnMut()>(r: impl Into<Ref>, data: &[u8], mut yield_fn: F) -> i32 {
    let r = r.into();
    let (our_mac, our_ip, dst_ip) = {
        let t = TCP.lock();
        if !t.live(r) { return -1; }
        (t.our_mac, t.our_ip, t.conns[r.idx].remote_ip)
    };
    // Timed out: fall through anyway. `send_data` will fire another ARP through
    // `ip::send` and report the failure as it always did — this makes the
    // common miss survivable, it does not promise delivery to a peer that never
    // answers.
    let _ = resolve_peer_mac(&our_mac, &our_ip, &dst_ip, SEND_ARP_BUDGET_US, &mut yield_fn);
    send_data(r, data)
}

/// Resolve the peer's MAC, bounded in TIME, before a segment goes out.
///
/// **Shared by `connect_with_yield` and `send_data_with_yield`**, which had
/// the same loop written twice with two different yield-count constants.
///
/// **Why a deadline and not a yield count.** Both budgets used to be counts,
/// and a count is not a bound on anything a robot cares about: one yield costs
/// tens of µs on hardware and orders of magnitude more under QEMU TCG, so the
/// same constant meant two unrelated stalls. `send` sits on the actuation path
/// — `rt_motor_task`'s watchdog SAFE-STOPs the machine after 500 ms without a
/// command, and `brain_client` drives its loop at 50 ms — so the question that
/// matters is "how long can this block", and only a clock answers it.
///
/// **The iteration cap is a fail-safe, not the budget.** If the timer ever
/// stops advancing, a pure deadline loop spins forever; this cannot. It is set
/// far above any realistic count so the deadline is what normally ends the
/// loop.
///
/// Returns `true` if the MAC is in the cache when it gives up.
fn resolve_peer_mac<F: FnMut()>(
    our_mac: &[u8; 6], our_ip: &[u8; 4], dst_ip: &[u8; 4],
    budget_us: u64, mut yield_fn: F,
) -> bool {
    // M21 / U06-5: `lookup_solicited_verified`, not `lookup` — an
    // unsolicited entry (planted by a request nobody asked,
    // `arp::learn_unsolicited`) must not short-circuit resolution for a
    // connection WE are opening. Before this, one crafted request claiming
    // to be `dst_ip`, sent before this dial ever ran, was enough: `lookup`
    // returned it, no request went out, and the SYN below went straight to
    // the attacker. Now a fresh, solicited request always goes out when the
    // only thing cached is unsolicited. `_verified` additionally fires a
    // NUD-style unicast re-check when the cached entry, though solicited, has
    // gone stale (`ARP_REACHABLE_TICKS`) — see its own doc.
    if crate::arp::lookup_solicited_verified(our_mac, our_ip, dst_ip).is_some() { return true; }
    // N7: registered before the request leaves and before every look below,
    // so the reply's `arp::handle` wakes this task (see `crate::wait`).
    let armed = crate::wait::ARP_WAITERS.arm();
    crate::arp::send_request(our_mac, our_ip, dst_ip);

    let freq = azos_drv_sys::timebase::TIMER_FREQ;
    let deadline_ticks = budget_us.saturating_mul(freq) / 1_000_000;
    let start = azos_drv_sys::timebase::now();
    let mut spins: u32 = 0;
    loop {
        if crate::arp::lookup_solicited_verified(our_mac, our_ip, dst_ip).is_some() {
            #[cfg(feature = "arp-timing")]
            {
                let el = azos_drv_sys::timebase::now().wrapping_sub(start);
                azos_drv_sys::kprintln!("[ARPTIME] resolved in {} us ({} spins)",
                    el.saturating_mul(1_000_000) / freq, spins);
            }
            return true;
        }
        if azos_drv_sys::timebase::now().wrapping_sub(start) >= deadline_ticks {
            #[cfg(feature = "arp-timing")]
            azos_drv_sys::kprintln!("[ARPTIME] gave up after {} us ({} spins)",
                budget_us, spins);
            return false;
        }
        if spins >= ARP_RESOLVE_SPIN_CAP {
            return false;   // clock is not advancing; do not hang here
        }
        armed.wait(start.wrapping_add(deadline_ticks), &mut yield_fn);
        spins += 1;
    }
}

/// Send data on an established connection.
///
/// **At most one segment per call**, and only bytes that actually leave: the
/// return value is what went on the wire in this call, 0 when nothing may be
/// sent now (the caller retries), -1 when the connection cannot send or the
/// segment could not be transmitted. `socket_send` hands that straight to
/// ring 3, and `brain_client` reads any negative as fatal, so none of it is
/// allowed to mean "queued for later".
///
/// **Several segments may be in flight.** What may be sent is bounded by
/// `min(cwnd, peer's window)` less the bytes already in flight (RFC 793 §3.7,
/// RFC 5681 §3.1) and by the send ring. Each byte sent is copied into the ring
/// once, and every retransmission is cut from there.
pub(crate) fn send_data(r: impl Into<Ref>, data: &[u8]) -> i32 {
    let r = r.into();
    let n = send_data_inner(r, data);
    // The first byte in flight starts the retransmission timer.
    if n > 0 { note_conn(r.idx); }
    n
}

fn send_data_inner(r: Ref, data: &[u8]) -> i32 {
    let idx = r.idx;
    let now = azos_drv_sys::timebase::now();
    // Reserve the range and copy it into the send ring under ONE lock hold:
    // two senders on one connection (a kernel task and a ring-3 socket on
    // another hart) must not both be handed the same SND.NXT.
    let (mac, ip, start, n, ack_val, dst_ip, src_port, dst_port, our_win) = {
        let mut t = TCP.lock();
        if !t.live(r) { return -1; }
        let (mac, ip) = (t.our_mac, t.our_ip);
        let c = &mut t.conns[idx];
        // RFC 1122 §4.2.2.13 half-close: once the peer's FIN has moved us to
        // `CloseWait`, our own send direction is still open. The application
        // may keep writing until IT calls `close`/`shutdown_write` — only the
        // peer's direction is done. Before this, `send_data` refused anything
        // that was not `Established`, so a peer's FIN silently killed the
        // direction it never touched.
        if c.state != TcpState::Established && c.state != TcpState::CloseWait { return -1; }

        // Peer's window is closed — caller should retry later. The persist
        // timer is what reopens it.
        if c.remote_window == 0 { return 0; }

        let flight = c.flight() as usize;
        let usable = if c.recovery == Recovery::Sack {
            // RFC 6675 NextSeg rule (2): new data only after rule (1), and only
            // while `cwnd - pipe` admits a whole segment — `pipe`, not the
            // flight, because SACKed and lost bytes are no longer in the
            // network. A lost range still waiting (the ACK path stops after
            // `RECOVERY_RETX_BURST`) goes first, and this call sends nothing
            // new; the caller retries as it does for a full window.
            let smss = c.smss();
            let room = c.cwnd.saturating_sub(sack_pipe(c, smss));
            if room < smss { return 0; }
            if sack_next_seg(c, smss, false).is_some() {
                drop(t);
                retransmit(idx, &mac, &ip, Resend::SackLost);
                return 0;
            }
            (room as usize).min(
                (c.remote_window as usize).min(TCP_SND_BUF_SIZE).saturating_sub(flight),
            )
        } else {
            let window = (c.cwnd as usize)
                .min(c.remote_window as usize)
                .min(TCP_SND_BUF_SIZE);
            window.saturating_sub(flight)
        };
        // Never larger than the peer's MSS or our own.
        let want = data.len().min(c.smss() as usize);
        let n = want.min(usable);
        if n == 0 { return 0; }
        // Sender silly-window avoidance (RFC 1122 §4.2.3.4): with bytes still
        // in flight, a sliver of window is not worth a segment when the
        // caller has a whole one to give. The ACK that is coming opens more.
        // With nothing in flight there is no ACK coming, so send what fits.
        if n < want && flight != 0 { return 0; }

        let start = c.seq;
        c.tx_write(flight, &data[..n]);
        c.seq = start.wrapping_add(n as u32);
        if flight == 0 {
            // RFC 6298 §5.1: the timer starts when data goes out and none was
            // outstanding.
            c.retx_time  = now;
            c.retx_count = 0;
        }
        if !c.rtt_on {
            c.rtt_on   = true;
            c.rtt_seq  = c.seq;
            c.rtt_time = now;
        }
        c.last_activity = now;
        (mac, ip, start, n, c.ack, c.remote_ip, c.local_port, c.remote_port, c.advertise())
    };
    let send_data_slice = &data[..n];

    // **Advertise the live receive window, not the constant.**
    //
    // `send_segment` writes `TCP_WINDOW_SIZE` — a constant — into every segment
    // it builds. On the data-receive path that is already avoided: each ACK for
    // an inbound segment goes out through `send_segment_with_window` carrying
    // `rx_free_space`. But a segment WE originate took the constant, and a TCP
    // window is advisory-latest: the peer believes the most recent number it
    // saw.
    //
    // So the hole was: the peer fills our buffer, our ACK correctly says "100
    // bytes left", we then send a byte of our own, and that segment announces
    // 65535 — the window has reopened as far as the peer is concerned. It sends
    // a full window, we have nowhere to put it, the ring-full break above drops
    // the excess, and the peer spends round-trips retransmitting into a buffer
    // we already told it was empty.
    //
    // Harmless only while the buffer is mostly empty, which is the case in
    // every test here and not the case during an OTA image transfer with a slow
    // consumer. It is also the prerequisite for RFC 7323 window scaling: with a
    // shift applied, this same constant would promise the entire 128 KiB buffer
    // on every segment (the vsbench TCP lane).
    // The bytes on the wire are the caller's, which are the ring's: no second
    // copy on the stack.
    let result = send_segment_with_window(&mac, &ip, &dst_ip, src_port, dst_port,
                                          TCP_ACK, start, ack_val, send_data_slice,
                                          our_win);
    if result == 0 {
        return n as i32;
    }

    // The segment did not leave. Take the reservation back so -1 still means
    // what it always did: nothing of this call is in the stream. Possible only
    // while nothing has happened on top of it — no later send appended past
    // it, no ACK moved SND.UNA into it (only a forged one could).
    let end = start.wrapping_add(n as u32);
    let mut t = TCP.lock();
    // The slot changed hands while the lock was dropped: the connection
    // these bytes were queued on is gone, and the new owner's must not be
    // touched.
    if !t.live(r) { return -1; }
    let c = &mut t.conns[idx];
    // `advertise` above counted the ACK this segment carried as sent; it was
    // not. Hold one again (N6), so the end of the pass or the timer sends it
    // rather than the peer's retransmission timer finding out.
    c.hold_ack(now, false, true);
    if c.seq == end && seq_le(c.snd_una, start) {
        c.seq = start;
        if seq_lt(start, c.rtx_next) {
            c.rtx_next = start;
        }
        if c.rtt_on && c.rtt_seq == end {
            c.rtt_on = false;
        }
        return -1;
    }
    // Something did: the bytes are in the queue and the retransmission timer
    // owns them now, exactly like a segment the network lost. Reporting -1
    // here would make the caller send them twice.
    n as i32
}

/// Maximum number of `yield_fn` calls `send_all_with_yield` will spin before
/// giving up.  Acts as a soft timeout — if the peer never advances cwnd /
/// never ACKs, we don't loop forever.  Sized for tens of seconds under QEMU
/// TCG (where each yield may cost ~milliseconds) and a few hundred ms on
/// real hardware.
pub const SEND_ALL_MAX_YIELDS: u32 = 10_000;

/// Is anything this connection sent still unacknowledged (SND.UNA != SND.NXT)?
pub(crate) fn is_unacked(r: impl Into<Ref>) -> bool {
    let r = r.into();
    let t = TCP.lock();
    t.live(r) && t.conns[r.idx].flight() != 0
}

/// Send all bytes of `data`, looping over partial `send_data` calls.
///
/// `send_data` returns at most one TCP segment's worth (bounded by cwnd,
/// remote MSS, or remote window — whichever is smallest).  Callers that
/// trust the first return value drop every byte past the segment boundary
/// (root cause of #39 / sensor-pump pt2).
///
/// This helper loops until all `data.len()` bytes have been handed to the
/// stack OR the connection drops OR the yield budget is exhausted (timeout).
///
/// **It does not wait for an ACK between segments.** It used to, because the
/// connection had a single retransmission slot and a second segment would
/// have overwritten the first's only copy — and that wait is what made every
/// kernel sender stop-and-wait whatever the window said. Every byte in flight
/// is in the send ring now, so it sends as long as `send_data` accepts, and
/// yields only when `send_data` answers 0: the window is full and an ACK has
/// to open it.
///
/// `yield_fn` is injected (instead of pulling in `crates/core/sched`) to keep the
/// `net` crate scheduler-agnostic.  Kernel callers pass
/// `azos_sched::task_yield`; userspace can pass a syscall yield.
///
/// Returns bytes successfully sent (≤ `data.len()`).  Callers should check
/// `sent < data.len()` to detect partial completion (rare — peer stall).
/// "Sent" is "handed to the wire", not "acknowledged".
pub(crate) fn send_all_with_yield<F: FnMut()>(
    r: impl Into<Ref>,
    data: &[u8],
    mut yield_fn: F,
) -> usize {
    let r = r.into();
    let mut sent_total: usize = 0;
    let mut yields: u32 = 0;
    // One TX batch per run of segments: their frames share doorbells. It is
    // closed (flushed) around every yield, so nothing waits on a task that
    // is not running, and the segments the peer must ACK are on the wire.
    crate::net_tx_batch_begin();
    while sent_total < data.len() && yields < SEND_ALL_MAX_YIELDS {
        let n = send_data(r, &data[sent_total..]);
        if n < 0 {
            // Connection dropped or fd invalid — caller will observe partial.
            break;
        }
        if n == 0 {
            // Peer window closed / cwnd not yet open — yield and retry.
            crate::net_tx_batch_end();
            yield_fn();
            crate::net_tx_batch_begin();
            yields += 1;
            continue;
        }
        sent_total += n as usize;
    }
    crate::net_tx_batch_end();
    sent_total
}

/// Fail-safe iteration cap for [`send_all_until`]. Not the budget — the
/// deadline is; this only keeps a timer that stops advancing from turning the
/// loop into a hang (same role as [`ARP_RESOLVE_SPIN_CAP`]).
pub const SEND_ALL_UNTIL_SPIN_CAP: u32 = 5_000_000;

/// [`send_all_with_yield`], bounded by a CLOCK budget instead of a count of
/// `wait_fn` calls.
///
/// **Why a second function.** `send_all_with_yield` gives up after
/// [`SEND_ALL_MAX_YIELDS`] calls of its callback, and a count of callbacks is
/// a duration only for one cost per call: a yield is tens of µs on a board
/// and grows with host load under QEMU, and a sleeping callback turns the
/// same 10,000 into tens of seconds. Here the caller states how long a closed
/// window may hold it (`budget_us`, read against `timebase::now()`), so
/// `wait_fn` can SLEEP between attempts — which a caller at a high priority
/// must do: a yield hands the hart only to tasks at its own priority or
/// above, never to the lower ones sharing it.
///
/// `wait_fn` is called only when `send_data` answers 0 (the window is full)
/// and the budget is not spent; a budget of 0 therefore never calls it.
/// Returns the bytes handed to the stack, as `send_all_with_yield` does.
pub(crate) fn send_all_until<F: FnMut()>(
    r: impl Into<Ref>,
    data: &[u8],
    budget_us: u64,
    mut wait_fn: F,
) -> usize {
    let r = r.into();
    let freq = azos_drv_sys::timebase::TIMER_FREQ;
    let budget_ticks = budget_us.saturating_mul(freq) / 1_000_000;
    let start = azos_drv_sys::timebase::now();
    let mut sent_total: usize = 0;
    let mut waits: u32 = 0;
    // N7: an ACK that opens the window wakes this task (see `crate::wait`).
    let armed = crate::wait::TCP_WAITERS.arm();
    // TX batch as in `send_all_with_yield`: closed around every wait.
    crate::net_tx_batch_begin();
    while sent_total < data.len() {
        let n = send_data(r, &data[sent_total..]);
        if n < 0 {
            break;
        }
        if n == 0 {
            if azos_drv_sys::timebase::now().wrapping_sub(start) >= budget_ticks
                || waits >= SEND_ALL_UNTIL_SPIN_CAP
            {
                break;
            }
            crate::net_tx_batch_end();
            armed.wait(start.wrapping_add(budget_ticks), &mut wait_fn);
            crate::net_tx_batch_begin();
            waits += 1;
            continue;
        }
        sent_total += n as usize;
    }
    crate::net_tx_batch_end();
    sent_total
}

/// Read received data from a connection.  Returns bytes read, 0 if none.
pub(crate) fn recv(r: impl Into<Ref>, buf: &mut [u8]) -> i32 {
    let r = r.into();
    let n = recv_inner(r, buf);
    // A held window update has a delayed-ACK deadline.
    if n > 0 { note_conn(r.idx); }
    n
}

fn recv_inner(r: Ref, buf: &mut [u8]) -> i32 {
    let idx = r.idx;
    let (n, params, kick) = {
        let mut t = TCP.lock();
        if !t.live(r) { return -1; }
        let c = &mut t.conns[idx];
        let avail = c.rx_available();
        if avail == 0 {
            if matches!(c.state, TcpState::CloseWait | TcpState::LastAck
                        | TcpState::TimeWait | TcpState::Closed) {
                return -1;
            }
            return 0;
        }
        let n = avail.min(buf.len()).min(TCP_RECV_MAX_PER_CALL);
        for i in 0..n {
            buf[i] = c.rx_buf[c.rx_head & TCP_BUF_MASK];
            c.rx_head = (c.rx_head + 1) & TCP_BUF_MASK;
        }
        // Window update (N6). It used to go out as a pure ACK on EVERY read
        // that returned a byte. Now, with RFC 1122 §4.2.3.3's receiver SWS
        // floor (the edge must move by min(ring/2, SMSS)):
        // - at once when the peer is close to stalling on it: the window we
        //   can offer is at least twice what is left of the one last
        //   advertised (Linux's `tcp_cleanup_rbuf` rule), or this read
        //   emptied the ring while an ACK for a pushed (PSH or short)
        //   segment is held (the request was consumed, its ACK need not wait
        //   for a reply to ride on);
        // - otherwise held like a delayed ACK: the next data segment's ACK,
        //   the end of the next poll pass or `TCP_DELACK_TICKS` carries it,
        //   one update however many reads happened in between.
        let free     = rx_free_space(c) as u32;
        let left     = c.rcv_adv.wrapping_sub(c.ack);
        let left     = if left >= 1u32 << 31 { 0 } else { left };
        let gain     = c.ack.wrapping_add(free).wrapping_sub(c.rcv_adv);
        let gain     = if gain >= 1u32 << 31 { 0 } else { gain };
        let sws      = ((TCP_BUF_SIZE / 2) as u32).min(c.smss());
        let opened   = n > 0 && gain >= sws;
        let urgent   = TCP_DELACK_TICKS == 0
            || (opened && (free >= left.saturating_mul(2) || gain >= TCP_WINDOW_UPDATE_BYTES))
            || (n > 0 && c.ack_pending && c.ack_pushed && c.rx_available() == 0);
        let mut kick = false;
        let params   = if urgent {
            let a = c.take_ack();
            Some((t.our_mac, t.our_ip, a))
        } else {
            if opened {
                kick = !c.ack_pending;
                c.hold_ack(azos_drv_sys::timebase::now(), false, false);
            }
            None
        };
        (n, params, kick)
    };
    if let Some((mac, ip, a)) = params {
        send_ack(&mac, &ip, &a);
        ack_count(ACKS_WINDOW);
    }
    // A held update made outside a poll pass: a poller parked on a long
    // timer must learn that `tcp_tick` has a deadline sooner.
    if kick { timer_kick(); }
    n as i32
}

/// Close a connection (proper FIN state machine — F01).
///
/// Established → send FIN → FinWait1 (active close)
/// CloseWait  → send FIN → LastAck   (passive close response)
/// Abort a connection: tell the peer, then drop the slot.
///
/// `close()` is the orderly teardown -- FIN, wait for the peer's FIN, TIME-WAIT
/// -- and on any state other than `Established`/`CloseWait` it silently sets
/// `Closed` and tells the peer nothing at all. That leaves a half-open peer
/// with no way to learn the connection is gone until its own retransmission
/// budget expires, which on a link carrying motor commands is minutes of an
/// operator believing they still have a channel.
///
/// This is the other half: RST, immediately, no waiting. Use it when the
/// connection is known bad rather than finished.
///
/// The RST carries `snd.nxt` because that is the sequence the peer's own
/// acceptability check expects -- a reset outside the peer's window is
/// discarded, and a reset that is discarded is the same as sending nothing.
pub(crate) fn abort(r: impl Into<Ref>) {
    let r = r.into();
    let idx = r.idx;
    let (mac, ip, state, lp, rp, rip, seq) = {
        let t = TCP.lock();
        if !t.live(r) { return; }
        let c = &t.conns[idx];
        (t.our_mac, t.our_ip, c.state, c.local_port, c.remote_port, c.remote_ip, c.seq)
    };
    if state == TcpState::Closed || state == TcpState::Listen { return; }

    // A RST's window is ignored by its receiver; the constant is as good as any.
    let _ = send_segment(&mac, &ip, &rip, lp, rp, TCP_RST, seq, 0, &[], TCP_WINDOW_SIZE);

    let mut t = TCP.lock();
    if !t.live(r) { return; }
    t.conns[idx].state   = TcpState::Closed;
    t.conns[idx].reset_conn_state();
}

/// Send our FIN and advance to the matching half of the close handshake:
/// `Established` → `FinWait1` (active close), `CloseWait` → `LastAck`
/// (passive close, the peer had already FIN'd us). Returns `true` iff a FIN
/// was actually sent — any other state is not this function's problem, and
/// the two callers below disagree on purpose about what to do when it is not.
fn send_fin_and_advance(r: Ref) -> bool {
    let idx = r.idx;
    let (mac, ip, state, seq, ack_val, dst_ip, src_port, dst_port, win) = {
        let mut t = TCP.lock();
        if !t.live(r) { return false; }
        let (mac, ip) = (t.our_mac, t.our_ip);
        let c = &mut t.conns[idx];
        (mac, ip, c.state, c.seq, c.ack, c.remote_ip, c.local_port, c.remote_port,
         c.advertise())
    };
    let next_state = match state {
        TcpState::Established => TcpState::FinWait1,
        TcpState::CloseWait   => TcpState::LastAck,
        _ => return false,
    };
    send_segment(&mac, &ip, &dst_ip, src_port, dst_port, TCP_FIN | TCP_ACK, seq, ack_val, &[], win);
    let mut t = TCP.lock();
    // Freed and re-issued while the FIN was going out (a RST on another
    // hart): the FIN was this connection's last word; the slot's new owner
    // keeps its state. `true`: the caller has nothing left to do either.
    if !t.live(r) { return true; }
    t.conns[idx].fin_seq = seq;
    t.conns[idx].state   = next_state;
    // Arm the teardown timer. Sending the FIN and setting the state is not
    // enough -- nothing marks anything outstanding, so no branch of
    // `tcp_tick` would ever resend it, and a single lost FIN left the slot in
    // this state until reboot. Eight of those and the robot can neither dial
    // out nor listen.
    //
    // Only with nothing in flight. With data outstanding the same two fields
    // are that data's retransmission timer and its count of timeouts, and
    // stamping them here would restart the timer at the moment of `close()`
    // and hand a peer that has stopped answering a fresh set of backed-off
    // retries. The FIN's timer starts instead when the last of that data is
    // acknowledged: `process_ack` stamps both fields then.
    if t.conns[idx].flight() == 0 {
        t.conns[idx].retx_time  = azos_drv_sys::timebase::now();
        t.conns[idx].retx_count = 0;
    }
    true
}

pub(crate) fn close(r: impl Into<Ref>) {
    let r = r.into();
    if r.idx >= TCP_MAX_CONNS { return; }
    // The FIN's retransmission timer (or FIN-WAIT/LAST-ACK's).
    if send_fin_and_advance(r) { note_conn(r.idx); return; }
    // For any other state, force close: tell the peer nothing, free the slot
    // -- unless the slot is no longer this caller's (see [`TcpHandle`]).
    let mut t = TCP.lock();
    if !t.live(r) { return; }
    t.conns[r.idx].state = TcpState::Closed;
    t.conns[r.idx].clear_send_queue();
}

/// Close only OUR send direction (`shutdown(SHUT_WR)`), leaving the receive
/// direction open.
///
/// RFC 1122 §4.2.2.13 half-close: the peer is told "no more data is coming"
/// via a FIN, and the connection walks the exact same
/// `FinWait1`/`FinWait2`/`TimeWait` (or `LastAck`, from `CloseWait`) path
/// `close()` drives — there is no separate wire behaviour for a half-close,
/// only a different caller contract. What actually distinguishes this from
/// `close()` lives one layer up, in `socket::socket_shutdown`: it does not
/// free the socket's fd, so the application can keep calling `recv` — and,
/// because `FinWait1`/`FinWait2` now run `process_inbound_payload` (see
/// `handle`), whatever the peer sends before ITS OWN FIN keeps arriving and
/// being acknowledged instead of being silently dropped.
///
/// A no-op on any state other than `Established`/`CloseWait` — unlike
/// `close()`, this does NOT force-close everything else. Shutting down a
/// write direction that is not open, or a connection already mid-teardown,
/// has nothing useful to do, and must not destroy a connection in an
/// unrelated state the way `close()`'s catch-all deliberately does.
pub(crate) fn shutdown_write(r: impl Into<Ref>) {
    let r = r.into();
    if r.idx >= TCP_MAX_CONNS { return; }
    send_fin_and_advance(r);
}

/// Accept an established TCP connection on `local_port`.
/// Returns the connection slot index or -1 if none is ready.
/// Marks the slot as accepted to prevent double-accept. By slot: for this
/// crate's host tests; everything else holds a [`TcpHandle`]
/// ([`TcpHandle::accept`]).
#[allow(dead_code)]
pub(crate) fn accept(local_port: u16) -> i32 {
    accept_h(local_port).map_or(-1, |h| h.slot as i32)
}

fn accept_h(local_port: u16) -> Option<TcpHandle> {
    let mut t = TCP.lock();
    for i in 0..TCP_MAX_CONNS {
        let c = &mut t.conns[i];
        // `CloseWait` too: a peer that sends everything and half-closes
        // (`tools/ota_send.py` does exactly that) can finish between two
        // polls of the accepting task, and its data is still in `rx_buf`,
        // readable until EOF. Accepting only `Established` left such a
        // connection unaccepted for good — an OTA push lost with no line on
        // the console (seen under TCG on the safe-mode gate row, wave 10).
        if matches!(c.state, TcpState::Established | TcpState::CloseWait)
            && c.local_port == local_port
            && !c.was_accepted
        {
            c.was_accepted = true;
            return Some(t.handle(i));
        }
    }
    None
}

/// Handle an incoming TCP segment with receive-side checksum validation.
///
/// Called from `ip::handle`, which forwards both IP endpoints.
///
/// Requires both endpoints because the TCP checksum covers the IPv4
/// pseudo-header (src, dst, proto, length).  This is the ONLY ingress path —
/// the segment processor below is private, so no future caller can reach it
/// without passing through this validation.
///
/// Unlike UDP the TCP checksum is mandatory (RFC 793 §3.1): there is no
/// "sender opted out" encoding, so any mismatch is an unconditional drop.
pub fn handle_checked(src_ip: &[u8; 4], dst_ip: &[u8; 4], data: &[u8]) {
    handle_checked_inner(src_ip, dst_ip, data);
    // A segment taken outside the net poll task (loopback delivery from a
    // sender's syscall, a `net_poll` from the shell or a boot smoke) may
    // have armed a TCP deadline the sleeping poll task does not know about.
    note_all();
}

fn handle_checked_inner(src_ip: &[u8; 4], dst_ip: &[u8; 4], data: &[u8]) {
    if data.len() < TCP_HDR_MIN { return; }
    // TCP carries no length field of its own — the segment length comes from
    // the IP total length, i.e. exactly what `ip::handle` sliced for us.
    let tcp_len = match u16::try_from(data.len()) { Ok(n) => n, Err(_) => return };

    // Sum the segment *including* the stored checksum; a correct segment folds
    // to 0xFFFF, so the complement must be zero.
    let pseudo = ip::pseudo_checksum(src_ip, dst_ip, ip::IP_PROTO_TCP, tcp_len);
    if tcp_checksum(pseudo, data) != 0 { return; }

    handle(src_ip, data);
    // N7: whatever this segment changed — a handshake completed, a
    // connection reset, a window opened — the tasks waiting on TCP look
    // again now, not at their next 1 ms poll. No lock is held here.
    crate::wait::TCP_WAITERS.notify();
}

/// Store an inbound data payload against a connection's receive state (or
/// buffer it out of order) and ACK exactly what was actually stored.
///
/// Shared by every state where the peer may still legitimately be sending:
/// `Established` and `CloseWait` (the ordinary receive path — see the merged
/// match arm in `handle`), and `FinWait1`/`FinWait2` (we have sent our own
/// FIN, but RFC 1122 §4.2.2.13 half-close does not stop the PEER from sending
/// until it sends its own FIN — before half-close, `close()` was the only way
/// into these two states and nothing that could reach them called
/// `send_data`, so this path was unreachable rather than merely untested).
///
/// A no-op when `payload` is empty, so calling it for a pure ACK or a bare
/// FIN costs nothing and touches no state.
fn process_inbound_payload(
    idx: usize, mac: &[u8; 6], ip: &[u8; 4], src_ip: &[u8; 4],
    dst_port: u16, src_port: u16, seq: u32, payload: &[u8],
    expected_ack: u32, rcv_wnd: u32, fin: bool, psh: bool, now: u64,
) {
    // Every ACK this sends is built from the connection itself (`take_ack`);
    // the segment's addressing is only read by the `qemu` trace.
    let _ = (src_ip, dst_port, src_port, fin);
    if payload.is_empty() { return; }
    // A segment that starts behind RCV.NXT. Peers retransmit whole segments,
    // so one that overlaps what already arrived is ordinary, and matching on
    // `seq == expected_ack` alone dropped it — the new tail never landed and
    // the peer retransmitted it until it gave up. Keep only the new bytes.
    //
    // A segment with nothing new is a retransmission whose ACK was lost: say
    // so again (RFC 793 §3.9), or the peer keeps retransmitting it. Not when a
    // FIN rides along — the FIN's own acknowledgement answers it.
    let behind = expected_ack.wrapping_sub(seq);
    let (seq, payload) = if behind != 0 && behind < 1u32 << 31 {
        if behind as usize >= payload.len() {
            if !fin { send_invalid_ack(idx, mac, ip, now); }
            return;
        }
        (expected_ack, &payload[behind as usize..])
    } else {
        (seq, payload)
    };
    if seq == expected_ack {
        // In-order segment — write to rx_buf directly.
        // CRITICAL: we MUST only ACK bytes we actually stored.
        // The previous version ACKed `payload.len()` even when
        // the rx ring was full, silently dropping bytes —
        // the sender then advanced its window thinking the
        // data arrived, causing the connection to "complete"
        // with missing bytes and OTA payload CRC mismatch.
        let mut t = TCP.lock();
        let c = &mut t.conns[idx];
        let mut stored: u32 = 0;
        for &b in payload {
            let next = (c.rx_tail + 1) & TCP_BUF_MASK;
            if next == c.rx_head {
                // Ring full — stop here, do NOT ACK the rest.
                // Peer will retransmit once we drain + open the window.
                break;
            }
            c.rx_buf[c.rx_tail] = b;
            c.rx_tail = next;
            stored += 1;
        }
        c.ack = seq.wrapping_add(stored);
        c.last_activity = now;
        c.rcv_unacked = c.rcv_unacked.saturating_add(stored);

        // Flush any OOO segments that are now contiguous
        let had_ooo = c.ooo_buf.iter().any(|s| s.valid);
        flush_ooo_segments(c);

        // N6: hold the ACK (RFC 1122 §4.2.3.2) unless one of these says the
        // peer needs it now:
        // - delayed ACK configured off (`TCP_DELACK_MS = 0`);
        // - `TCP_DELACK_SEGS` full-sized segments unacknowledged (RFC 5681
        //   §4.2: at least every second one);
        // - the segment filled (part of) a hole (RFC 5681 §4.2: immediately),
        //   or something is still held beyond one (its SACK blocks);
        // - the ring could not take it all, or less than a segment of window
        //   is left: the sender is about to stall and must learn why.
        // A FIN riding along is answered by its own ACK right after this.
        let smss = c.smss();
        let quick = TCP_DELACK_TICKS == 0
            || c.rcv_unacked >= TCP_DELACK_SEGS.saturating_mul(smss)
            || had_ooo
            || (stored as usize) < payload.len()
            || rx_free_space(c) < smss as usize;
        if !quick {
            let pushed = psh || (payload.len() as u32) < smss;
            c.hold_ack(now, pushed, true);
            return;
        }
        // Send ACK with actual free window (flow control — F01), and SACK
        // blocks for whatever is still held beyond a remaining hole.
        let a = c.take_ack();
        drop(t);
        send_ack(mac, ip, &a);
        ack_count(ACKS_NOW);
    } else if seq.wrapping_sub(expected_ack) < rcv_wnd {
        // Out-of-order but within window — buffer it (F01)
        let mut t = TCP.lock();
        let c = &mut t.conns[idx];
        store_ooo_segment(c, seq, payload);
        c.ooo_recent = seq;
        c.last_activity = now;
        // Send duplicate ACK (signals missing data to sender). With SACK it
        // also says exactly what did arrive, so the sender need not resend it.
        // Never held (RFC 5681 §4.2: out-of-order data is ACKed at once).
        let a = c.take_ack();
        drop(t);
        #[cfg(feature = "qemu")]
        trace_tx(dst_port, src_ip, src_port, TCP_ACK, a.seq, a.ack, &[]);
        send_ack(mac, ip, &a);
        ack_count(ACKS_NOW);
    }
    // else: outside window, already filtered by the caller (or, for
    // FinWait1/FinWait2 which run no acceptability gate up front, simply left
    // unacknowledged — the peer's own retransmission timer will resend it).
}

/// Process a TCP segment whose checksum has already been verified.
///
/// Private by design: `handle_checked` is the only way in, so this cannot be
/// reached without the mandatory checksum validation having run first.
/// Re-verified 2026-09-26 (U06 §4 comment audit: the previous line numbers
/// here — 1256/1265/1267 — had already drifted false): `handle_checked` is
/// `fn handle`'s sole call site, and that call is unconditionally preceded
/// by the checksum-mismatch `return` in the same function, a few lines
/// above it. If a second call site to `handle` is ever added, or the
/// checksum check moves after that call, this claim goes false silently —
/// re-grep `handle(` in this file before trusting it again, rather than
/// trusting line numbers, which is exactly what let this go stale once.
fn handle(src_ip: &[u8; 4], data: &[u8]) {
    if data.len() < TCP_HDR_MIN { return; }
    let hdr = unsafe { &*(data.as_ptr() as *const TcpHdr) };
    let dst_port  = u16::from_be_bytes(hdr.dst_port);
    let src_port  = u16::from_be_bytes(hdr.src_port);
    let seq       = u32::from_be_bytes(hdr.seq);
    let ack_num   = u32::from_be_bytes(hdr.ack);
    let flags     = hdr.flags;

    // Sensor-pump (#39) trace probe: log every inbound TCP segment with
    // flags + seq + ack + payload length so we can compare against what
    // the brain claims to send.  Gated on `--features qemu` so production
    // builds pay nothing.
    #[cfg(feature = "qemu")]
    {
        let off_hdr = ((hdr.data_off >> 4) as usize) * 4;
        let off_hdr = if off_hdr < TCP_HDR_MIN { TCP_HDR_MIN } else { off_hdr };
        let pl_len = data.len().saturating_sub(off_hdr);
        azos_drv_sys::kprintln!(
            "[TCP-RX] src={}.{}.{}.{}:{} -> :{} flags=0x{:02x} seq={} ack={} pl={}B",
            src_ip[0], src_ip[1], src_ip[2], src_ip[3], src_port,
            dst_port, flags, seq, ack_num, pl_len
        );
    }
    // Peer's advertised receive window — we cap our outbound size by
    // this so we don't overshoot and force the peer to drop segments.
    let peer_win  = u16::from_be_bytes(hdr.window);
    let off       = ((hdr.data_off >> 4) as usize) * 4;
    // RFC 793: data_off >= 5 (20-byte minimum header) and the header cannot
    // extend past the segment end.  Both are malformed — DROP, don't guess.
    // The previous clamp (off < 20 → treat as 20) reinterpreted option bytes
    // as payload; the `off > len → payload = &[]` fallback processed flags
    // from a header that claims bytes the segment doesn't contain.
    if off < TCP_HDR_MIN || off > data.len() { return; }
    let payload   = &data[off..];

    let (mac, ip) = { let t = TCP.lock(); (t.our_mac, t.our_ip) };
    let now = azos_drv_sys::timebase::now();

    // Find an existing connection
    let idx_opt = { TCP.lock().find_conn(dst_port, src_ip, src_port) };

    // A new SYN for a 4-tuple in TIME-WAIT, to a port that is listening: the
    // peer is reconnecting from the same port. RFC 1122 §4.2.2.13 lets it in
    // when its sequence is past the old connection's RCV.NXT, which is what
    // keeps a stale duplicate of the old SYN out. The TIME-WAIT arm answers
    // only FINs, so this used to be swallowed until the old slot expired.
    let idx_opt = match idx_opt {
        Some(i) if flags & (TCP_SYN | TCP_ACK | TCP_RST) == TCP_SYN => {
            let mut t = TCP.lock();
            let listening = t.find_listener(dst_port).is_some();
            let c = &mut t.conns[i];
            if c.state == TcpState::TimeWait && listening && seq_lt(c.ack, seq) {
                c.state = TcpState::Closed;
                c.clear_send_queue();
                None
            } else {
                Some(i)
            }
        }
        other => other,
    };

    if let Some(idx) = idx_opt {
        // RFC 793 §3.4 — RST handling: in any synchronised state, a valid
        // RST closes the connection immediately. We must release retx
        // state and free the slot so resources don't leak. Without this
        // an attacker that sees a flow can inject one RST and the kernel
        // keeps the slot allocated forever (resource-exhaustion DoS), and
        // the send queue keeps the retransmission timer and cwnd running.
        if flags & TCP_RST != 0 {
            // Every state validates the RST before acting on it. The previous
            // version exempted SynSent/SynRcvd with the comment "validated
            // elsewhere" — there was no elsewhere, so a RST bearing any
            // sequence number closed a connecting socket.
            let (st, rcv_nxt, iss) = {
                let t = TCP.lock();
                (t.conns[idx].state, t.conns[idx].ack, t.conns[idx].seq)
            };
            let acceptable = match st {
                // RFC 793 §3.4: a RST is only meaningful here if it
                // acknowledges our SYN, i.e. it came from a host that actually
                // saw it. Without the ACK check the ISN randomisation buys
                // nothing on this path: any RST at all killed the connect.
                TcpState::SynSent => {
                    flags & TCP_ACK != 0 && ack_num == iss.wrapping_add(1)
                }
                // RFC 793: ignore a RST while listening. `find_conn` can match
                // a Listen slot (its remote endpoint is 0.0.0.0:0), so a
                // spoofed segment from 0.0.0.0:0 would otherwise destroy the
                // listener — the server socket vanishes with no other symptom.
                TcpState::Listen | TcpState::Closed => false,
                // SynRcvd and every synchronised state: the sequence must be
                // EXACTLY `RCV.NXT` (RFC 5961 §3.2).
                //
                // This accepted anything inside the 64 KiB receive window,
                // which is the half of RFC 5961 that does not hold: it cuts a
                // blind reset from 2^32 guesses to 2^32 / 2^16 = 65 536 spoofed
                // segments against a 4-tuple that was public knowledge (the
                // brain's local port was fixed at 12345). About a second of
                // packets tore the brain link down. The kernel now dials the
                // brain from a port drawn per connection from the dynamic range
                // (`kernel/src/main.rs`), so the 4-tuple is predictable, not
                // fixed.
                //
                // The RFC answers an in-window-but-not-exact RST with a
                // challenge ACK so a genuine peer can re-send an exact one.
                // Deliberately NOT done here: a challenge ACK per spoofed RST is
                // a new reflection path, and this stack already had to budget
                // the one it has (`send_rst`). The cost is that a real reset
                // whose sequence overtook data we never received is ignored,
                // and the connection ends by retransmission timeout or
                // keep-alive instead of at once.
                _ => seq == rcv_nxt,
            };
            if !acceptable {
                return; // unacceptable RST — ignore (do not tear down)
            }
            let mut t = TCP.lock();
            let c = &mut t.conns[idx];
            c.state          = TcpState::Closed;
            c.clear_send_queue();
            c.retx_count     = 0;
            c.was_accepted   = false;
            return;
        }
        let state = { TCP.lock().conns[idx].state };
        match state {
            TcpState::SynSent if flags & TCP_ACK != 0 => {
                // RFC 793 §3.4: a SYN-ACK is only ours if it acknowledges our
                // SYN — SEG.ACK must equal ISS+1. `c.seq` still holds the ISS
                // here (it is incremented on the transition below).
                //
                // This arm used to match on flags alone and never read
                // `ack_num`, which made the RFC 6528 ISN randomisation
                // decorative on the active-open path: an off-path attacker who
                // guessed the 4-tuple (16 tries, given the deterministic
                // ephemeral port) could complete our handshake without ever
                // seeing the SYN-ACK, and hand the application a connection to
                // a host of their choosing.
                //
                // Any other ACK is answered with a reset at SEG.ACK (RFC 793
                // §3.9, SYN-SENT) — the peer holds a connection we do not, a
                // half-open left by a reboot, and nothing else tells it. The
                // connection itself is left alone: the reset carries the
                // peer's own number, so it cannot be used to close ours. It
                // goes through `send_rst`, so it shares the reflection budget
                // of the closed-port resets. This is a reply to a bad ACK, not
                // an RFC 5961 challenge ACK; those stay out.
                let iss = { TCP.lock().conns[idx].seq };
                if ack_num != iss.wrapping_add(1) {
                    send_rst(&mac, &ip, src_ip, dst_port, src_port, flags, seq, ack_num, 0);
                    return;
                }
                // Acknowledges our SYN but carries none of its own: nothing
                // to do in this state.
                if flags & TCP_SYN == 0 { return; }
                // SYN-ACK received → parse its options, send ACK, move to Established
                let peer_opts = parse_syn_options(data, off);
                {
                    let mut t = TCP.lock();
                    let c = &mut t.conns[idx];
                    // Our SYN consumed one sequence number (RFC 793 §3.3): the
                    // peer ACKs ISN+1, so SND.NXT must advance to ISN+1 before
                    // the first data byte. The passive-open path (SynRcvd→ACK
                    // below) already does this; the active-open path did not,
                    // leaving c.seq one BEHIND. Effect: the first data segment
                    // started at ISN, whose first byte the peer treats as the
                    // already-ACKed SYN slot and discards — so the app received
                    // (len-1) bytes of the FIRST post-connect segment. Streaming
                    // senders (sensor pump) self-realign after one frame and the
                    // brain MAGIC-resyncs past it, which is why this stayed
                    // latent; a one-shot request/response (the RFC-0019 handshake
                    // reply, #34/#74) has no second frame to recover, so it
                    // surfaced as "stub reads 65 of 66 bytes" → handshake stall.
                    c.seq   = c.seq.wrapping_add(1);
                    c.snd_una  = c.seq;
                    c.rtx_next = c.seq;
                    c.ack   = seq.wrapping_add(1);
                    c.state = TcpState::Established;
                    // What our SYN advertised (unscaled): the edge `recv`'s
                    // window-update rule measures from until an ACK moves it.
                    c.rcv_adv = c.ack.wrapping_add(TCP_WINDOW_SIZE as u32);
                    c.remote_mss    = peer_opts.mss;
                    // Our SYN offered both options (`SynOffer::ALL`), so each
                    // is on exactly when this SYN-ACK carries it back.
                    if let Some(shift) = peer_opts.wscale {
                        c.wscale_ok  = true;
                        c.snd_wscale = shift;
                        c.rcv_wscale = RCV_WSCALE;
                    }
                    c.sack_ok       = peer_opts.sack_ok;
                    // The window of a SYN-ACK is never scaled (RFC 7323 §2.2).
                    c.remote_window = peer_win as u32;
                    c.last_activity = now;
                    c.keepalive_probes = 0;
                }
                // The first segment without SYN: its window is scaled.
                let (seq_n, ack_n, win) = {
                    let mut t = TCP.lock();
                    let c = &mut t.conns[idx];
                    (c.seq, c.ack, c.advertise())
                };
                send_segment(&mac, &ip, src_ip, dst_port, src_port, TCP_ACK, seq_n, ack_n, &[], win);
            }
            // Simultaneous open (RFC 793 §3.4, figure 8): our SYN crossed the
            // peer's. It is answered with a SYN-ACK from our own ISS, and the
            // connection waits in SynRcvd for the peer's SYN-ACK, exactly as a
            // passive open waits for the third leg. Before this a bare SYN in
            // SynSent matched no arm, so two ends dialling each other at once
            // both sat in SynSent until their retries ran out.
            //
            // Our SYN offered every option, so each one is on exactly when the
            // peer's SYN carries it — the same rule as the SYN-ACK arm above.
            TcpState::SynSent if flags & TCP_SYN != 0 => {
                let peer_opts = parse_syn_options(data, off);
                let (iss, ack_n, offer) = {
                    let mut t = TCP.lock();
                    let c = &mut t.conns[idx];
                    c.ack   = seq.wrapping_add(1);
                    c.state = TcpState::SynRcvd;
                    c.remote_mss = peer_opts.mss;
                    if let Some(shift) = peer_opts.wscale {
                        c.wscale_ok  = true;
                        c.snd_wscale = shift;
                        c.rcv_wscale = RCV_WSCALE;
                    }
                    c.sack_ok = peer_opts.sack_ok;
                    // A SYN's window is never scaled (RFC 7323 §2.2).
                    c.remote_window = peer_win as u32;
                    // The SynRcvd retry timer resends the SYN-ACK from here.
                    c.retx_time  = now;
                    c.retx_count = 0;
                    c.last_activity = now;
                    (c.seq, c.ack, SynOffer { wscale: c.wscale_ok, sack: c.sack_ok })
                };
                send_syn_segment(&mac, &ip, src_ip, dst_port, src_port,
                                 TCP_SYN | TCP_ACK, iss, ack_n, offer);
            }
            TcpState::SynRcvd if flags & TCP_ACK != 0 => {
                // Client's ACK completing the 3-way handshake → Established.
                //
                // RFC 793 §3.4 / RFC 6528: the ACK must acknowledge the SYN-ACK
                // we sent, i.e. SEG.ACK == our ISS + 1. Without this the
                // handshake completes on an ACK the peer could not have
                // computed: an off-path attacker spoofs a SYN from a victim
                // address, then immediately spoofs a bare ACK without ever
                // seeing our SYN-ACK, and `accept()` hands the application a
                // connection that appears to come from the victim. Checking
                // the ISN on the way back in is the entire reason for
                // generating it unpredictably.
                //
                // An ACK that fails the check draws a reset at SEG.ACK (RFC 793
                // §3.9, SYN-RECEIVED) and leaves the half-open slot as it was:
                // the reset names the sender's number, not ours. Budgeted with
                // every other reset in `send_rst`.
                let mut t = TCP.lock();
                let c = &mut t.conns[idx];
                if ack_num != c.seq.wrapping_add(1) {
                    drop(t);
                    send_rst(&mac, &ip, src_ip, dst_port, src_port, flags, seq, ack_num, 0);
                    return;
                }
                if flags & TCP_SYN != 0 {
                    // The second half of a simultaneous open: the peer's
                    // SYN-ACK. Its SYN must be the one already acknowledged,
                    // and its ACK has just been checked against our ISS.
                    if seq.wrapping_add(1) != c.ack { return; }
                    c.seq      = c.seq.wrapping_add(1);
                    c.snd_una  = c.seq;
                    c.rtx_next = c.seq;
                    c.state    = TcpState::Established;
                    c.rcv_adv  = c.ack.wrapping_add(TCP_WINDOW_SIZE as u32);
                    // Still a SYN, so still unscaled.
                    c.remote_window = peer_win as u32;
                    c.last_activity = now;
                    c.keepalive_probes = 0;
                    let (seq_n, ack_n, win) = (c.seq, c.ack, c.advertise());
                    drop(t);
                    send_segment(&mac, &ip, src_ip, dst_port, src_port,
                                 TCP_ACK, seq_n, ack_n, &[], win);
                    return;
                }
                c.seq   = c.seq.wrapping_add(1);
                c.snd_una  = c.seq;
                c.rtx_next = c.seq;
                c.state = TcpState::Established;
                // Our SYN-ACK's window (unscaled): see the SynSent arm.
                c.rcv_adv = c.ack.wrapping_add(TCP_WINDOW_SIZE as u32);
                // Not a SYN, so scaled by whatever the SYN exchange agreed.
                c.remote_window = (peer_win as u32) << c.snd_wscale;
                c.last_activity = now;
                c.keepalive_probes = 0;
            }
            // `CloseWait` shares Established's segment processing: the peer
            // has sent its FIN, but RFC 1122 §4.2.2.13 says nothing stops US
            // from still sending, and nothing stops the ACK/congestion
            // bookkeeping for those sends from working exactly as it does in
            // Established. Before half-close, `CloseWait` had no arm at all
            // here, so an ACK for data sent from that state (unreachable
            // before `send_data` accepted it) would never have cleared
            // `unacked` — the RTO timer would have retransmitted the segment
            // forever and eventually torn the connection down at
            // `RETX_MAX_ATTEMPTS`, even though the peer had already
            // acknowledged it.
            //
            // The FIN-consumption block at the bottom of this arm is inert on
            // a second entry: `CloseWait` is reached only by already having
            // advanced `c.ack` past the peer's FIN, so a retransmitted FIN
            // (the peer's ACK of our ACK was lost) fails the "consumed once
            // landed" check below and is silently ignored — the same outcome
            // as before this change (there was no arm to answer it either).
            TcpState::Established | TcpState::CloseWait => {
                // --- Sequence number validation ---
                //
                // Applied to EVERY segment, data-bearing or not. See
                // `segment_acceptable`: the check used to be nested inside the
                // payload branch, so a bare ACK reached the window/congestion
                // bookkeeping below with no validation at all.
                let fin = flags & TCP_FIN != 0;
                let (expected_ack, rcv_wnd) = {
                    let t = TCP.lock();
                    (t.conns[idx].ack, t.conns[idx].rcv_wnd_max())
                };
                if !segment_acceptable(seq, payload.len() + fin as usize, expected_ack, rcv_wnd) {
                    // RFC 793 §3.9: an unacceptable segment is dropped and
                    // answered with an ACK. Never with a reset, and a reset
                    // never reaches here — the RST arm returned above. The ACK
                    // is what a peer whose ACK was lost, and a keep-alive
                    // probe, are waiting for; `send_invalid_ack` bounds it per
                    // connection so a spoofed flood buys two segments a second.
                    send_invalid_ack(idx, &mac, &ip, now);
                    return;
                }

                // --- ACK acceptability (RFC 5961 §5.2) ---
                //
                // The sequence check above is the ONLY thing a segment used to
                // need, and the ACK processing below trusts the segment with
                // `remote_window`, `persist_probes` and `last_activity`. So a
                // blind attacker who landed `seq` in the 64 KiB window — 2^16
                // guesses — could advertise window 0 with any ACK value and
                // stall our send side, or keep a dead connection looking alive.
                // Requiring the ACK to acknowledge something we could actually
                // have sent multiplies that by another ~2^16.
                //
                // U06-1 (2026-09-26): an unacceptable ACK used to SKIP only the
                // ACK processing below, not the segment — `process_inbound_payload`
                // ran regardless, and its out-of-order queue (`store_ooo_segment`)
                // stores on `seq` alone. That made "inject data into the stream"
                // a ~2^16 guess (`seq` inside the receive window), not the ~2^32
                // this comment used to claim, because the ACK half of the guess
                // was never checked. RFC 5961 §5 (Blind Data Injection Attack
                // Mitigation) and Linux's `tcp_ack()`/`tcp_rcv_established()`
                // posture: a segment that carries the ACK bit with an
                // unacceptable ACK is dropped in its entirety, silently, before
                // payload or FIN are looked at. See the `return` right below.
                let ack_present = flags & TCP_ACK != 0;
                let ack_ok = ack_present && {
                    let (snd_una, snd_nxt) = {
                        let t = TCP.lock();
                        let c = &t.conns[idx];
                        (c.snd_una, c.seq)
                    };
                    ack_acceptable(ack_num, snd_una, snd_nxt)
                };

                // Drop the WHOLE segment — no payload, no FIN, no reply — when
                // it carries ACK but the ACK is not acceptable. Cost: a genuine
                // peer whose ACK lags more than one window loses this segment to
                // its own retransmission timer; rare on a one-hop robot link.
                if ack_present && !ack_ok {
                    return;
                }

                // --- ACK processing ---
                if ack_ok {
                    process_ack(idx, &mac, &ip, ack_num, peer_win,
                                payload.is_empty() && flags & (TCP_SYN | TCP_FIN) == 0,
                                &data[TCP_HDR_MIN..off], now);
                }

                // --- Payload processing with OOO reassembly (F01) ---
                process_inbound_payload(idx, &mac, &ip, src_ip, dst_port, src_port,
                                        seq, payload, expected_ack, rcv_wnd, fin,
                                        flags & TCP_PSH != 0, now);

                // --- FIN handling ---
                if flags & TCP_FIN != 0 {
                    // Only honour a FIN whose sequence is in the receive window
                    // (RFC 5961). The check at the top of this arm is broader —
                    // it also admits the RFC 1122 keep-alive shape at
                    // `RCV.NXT - 1`, which must never be read as a connection
                    // teardown — so a FIN is re-tested against the window here.
                    if !seq_in_window(seq, expected_ack, rcv_wnd) {
                        return;
                    }
                    let mut t = TCP.lock();
                    let c = &mut t.conns[idx];
                    // The FIN occupies sequence number seq + payload_len.  Only
                    // consume it once every byte before it has actually landed
                    // in the rx ring (c.ack caught up to it).  Two failure
                    // modes otherwise: (a) ring filled mid-segment — c.ack
                    // advanced only by `stored`, and +1 here would acknowledge
                    // a data byte we dropped, silently losing the tail of the
                    // stream; (b) the FIN segment arrived out of order (its
                    // payload went to the OOO buffer) — +1 would desync the
                    // flow entirely.  In both cases just skip: the earlier ACK
                    // reported what we stored, and the peer retransmits the
                    // remaining payload + FIN.
                    if c.ack != seq.wrapping_add(payload.len() as u32) {
                        return;
                    }
                    c.ack = c.ack.wrapping_add(1); // FIN consumes one sequence number
                    c.state = TcpState::CloseWait;
                    c.last_activity = now;
                    let (seq_n, ack_n, win) = (c.seq, c.ack, c.advertise());
                    drop(t);
                    // ACK the FIN
                    send_segment(&mac, &ip, src_ip, dst_port, src_port,
                                 TCP_ACK, seq_n, ack_n, &[], win);
                }
            }
            // --- FIN state machine states (F01) ---
            //
            // Both states below now run `process_inbound_payload` first. Half-
            // close means WE sent the FIN; the peer has not, and RFC 1122
            // §4.2.2.13 permits it to keep sending until it does. Before this
            // there was no `shutdown_write` (only `close`, which no live
            // connection called with anything left for the peer to send), so
            // this branch was unreachable in practice; now that `send_data`
            // works from `CloseWait` and `shutdown_write` exists, a peer's
            // trailing data arriving here must be stored and ACKed, not
            // dropped.
            TcpState::FinWait1 => {
                let fin = flags & TCP_FIN != 0;
                let (expected_ack, rcv_wnd) = {
                    let t = TCP.lock();
                    (t.conns[idx].ack, t.conns[idx].rcv_wnd_max())
                };
                process_inbound_payload(idx, &mac, &ip, src_ip, dst_port, src_port,
                                        seq, payload, expected_ack, rcv_wnd, fin,
                                        flags & TCP_PSH != 0, now);
                ack_data_in_fin_state(idx, &mac, &ip, seq, ack_num, flags, peer_win,
                                      payload.len(), expected_ack, rcv_wnd,
                                      &data[TCP_HDR_MIN..off], now);
                if flags & TCP_ACK != 0 {
                    let mut t = TCP.lock();
                    let c = &mut t.conns[idx];
                    // Our FIN has been ACKed
                    if ack_num == c.fin_seq.wrapping_add(1) {
                        // Same rule as the branch below: the FIN must fall in
                        // the receive window before we consume it, or a
                        // spoofed FIN bearing any sequence at all pushes us
                        // into TimeWait. An out-of-window FIN is not ours to
                        // consume — the ACK above is still valid, so fall
                        // through to FinWait2 rather than dropping it.
                        //
                        // The third condition is the same "only consume once
                        // landed" guard the Established/CloseWait arm applies
                        // to every FIN: `process_inbound_payload` may have
                        // stored fewer bytes than `payload.len()` (ring full)
                        // or none at all (the segment went to the OOO buffer
                        // because it was itself out of order), and `c.ack` has
                        // already been advanced by exactly what landed. Without
                        // this a FIN riding a ring-full segment would be
                        // acknowledged as if the peer's last bytes had been
                        // kept, silently losing them.
                        if flags & TCP_FIN != 0
                            && seq_in_window(seq, expected_ack, rcv_wnd)
                            && c.ack == seq.wrapping_add(payload.len() as u32)
                        {
                            // Simultaneous close: FIN+ACK → TimeWait
                            c.ack = fin_next_ack(seq, payload.len());
                            c.state = TcpState::TimeWait;
                            c.time_wait_start = now;
                            let (seq_n, ack_n, win) = (c.seq, c.ack, c.advertise());
                            drop(t);
                            send_segment(&mac, &ip, src_ip, dst_port, src_port,
                                         TCP_ACK, seq_n, ack_n, &[], win);
                        } else {
                            c.state = TcpState::FinWait2;
                            // Stamp the entry: the FinWait2 bound in `tcp_tick`
                            // measures from here, and `retx_time` is free in
                            // this state — the FIN it was tracking has just
                            // been acknowledged, which is what got us here.
                            c.retx_time = now;
                        }
                    }
                } else if flags & TCP_FIN != 0 {
                    // Peer FIN before our FIN is ACKed → simultaneous close.
                    // Unvalidated, any spoofed FIN carrying any sequence at all
                    // pushed us into TimeWait and desynchronised the flow.
                    let mut t = TCP.lock();
                    let c = &mut t.conns[idx];
                    if !seq_in_window(seq, expected_ack, rcv_wnd) { return; }
                    if c.ack != seq.wrapping_add(payload.len() as u32) { return; }
                    c.ack = fin_next_ack(seq, payload.len());
                    c.state = TcpState::TimeWait;
                    c.time_wait_start = now;
                    let (seq_n, ack_n, win) = (c.seq, c.ack, c.advertise());
                    drop(t);
                    send_segment(&mac, &ip, src_ip, dst_port, src_port,
                                 TCP_ACK, seq_n, ack_n, &[], win);
                }
            }
            TcpState::FinWait2 => {
                let (expected_ack, rcv_wnd) = {
                    let t = TCP.lock();
                    (t.conns[idx].ack, t.conns[idx].rcv_wnd_max())
                };
                process_inbound_payload(idx, &mac, &ip, src_ip, dst_port, src_port,
                                        seq, payload, expected_ack, rcv_wnd,
                                        flags & TCP_FIN != 0, flags & TCP_PSH != 0, now);
                if flags & TCP_FIN != 0 {
                    let mut t = TCP.lock();
                    let c = &mut t.conns[idx];
                    // The FIN must fall in the receive window. This state
                    // previously accepted a FIN bearing any sequence number
                    // whatsoever, which both closed the connection on command
                    // and left `c.ack` pointing somewhere arbitrary.
                    if !seq_in_window(seq, expected_ack, rcv_wnd) { return; }
                    // Only consume once every byte ahead of it has actually
                    // landed — see the identical guard in FinWait1 above.
                    if c.ack != seq.wrapping_add(payload.len() as u32) { return; }
                    c.ack = fin_next_ack(seq, payload.len());
                    c.state = TcpState::TimeWait;
                    c.time_wait_start = now;
                    let (seq_n, ack_n, win) = (c.seq, c.ack, c.advertise());
                    drop(t);
                    send_segment(&mac, &ip, src_ip, dst_port, src_port,
                                 TCP_ACK, seq_n, ack_n, &[], win);
                }
            }
            TcpState::LastAck => {
                if flags & TCP_ACK != 0 {
                    // Data sent from CloseWait may still be in flight.
                    let (expected_ack, rcv_wnd) = {
                        let t = TCP.lock();
                        (t.conns[idx].ack, t.conns[idx].rcv_wnd_max())
                    };
                    ack_data_in_fin_state(idx, &mac, &ip, seq, ack_num, flags, peer_win,
                                          payload.len(), expected_ack, rcv_wnd,
                                          &data[TCP_HDR_MIN..off], now);
                    let mut t = TCP.lock();
                    let c = &mut t.conns[idx];
                    // Only the ACK of OUR FIN closes the connection
                    // (SEG.ACK == FIN sequence + 1). Any ACK used to do it,
                    // including one carrying a stale or forged acknowledgement
                    // number, so the slot could be freed while the peer still
                    // considered the connection open — and reused for a new
                    // peer while the old one's segments were still arriving.
                    if ack_num != c.fin_seq.wrapping_add(1) { return; }
                    c.state = TcpState::Closed;
                    c.clear_send_queue();
                }
            }
            TcpState::TimeWait => {
                // RFC 793 §3.5: a FIN arriving here is the peer retransmitting
                // because our final ACK was lost. Ignoring it is not harmless
                // — it is the exact reason the peer is stuck: it sits in
                // LastAck resending a FIN nobody answers, and now that this
                // stack retransmits its own FIN, a peer running the same code
                // spends its whole budget and then tears the connection down
                // as if we had vanished.
                //
                // So re-ACK, and restart the timer. Restarting matters as much
                // as the ACK: the point of TIME-WAIT is to outlive every
                // in-flight segment of this connection, and a retransmitted
                // FIN is proof that something is still in flight. Leaving the
                // original deadline would let the slot be reused while the
                // peer is still talking to it.
                //
                // Only for a FIN. A stray ACK or data segment here gets
                // nothing, or two stacks in TIME-WAIT would answer each other.
                if flags & TCP_FIN != 0 {
                    let (seq_n, ack_n, win) = {
                        let mut t = TCP.lock();
                        let c = &mut t.conns[idx];
                        c.time_wait_start = now;
                        (c.seq, c.ack, c.advertise())
                    };
                    send_segment(&mac, &ip, src_ip, dst_port, src_port,
                                 TCP_ACK, seq_n, ack_n, &[], win);
                }
            }
            _ => {}
        }
        return;
    }

    // Check if we have a listener
    let listener_idx = { TCP.lock().find_listener(dst_port) };
    if listener_idx.is_none() {
        // No connection matched above and no listener here: tell the peer,
        // instead of leaving it to time out. `seg_len` counts SYN and FIN as
        // one byte each, which is what the peer's own acceptability check
        // expects our ACK to cover.
        // `data` is the whole segment, header included — the payload starts at
        // `off`. Using `data.len()` here made a bare SYN acknowledge 21 bytes
        // instead of 1, and a reset acknowledging the wrong sequence is
        // discarded by the peer, which is the same as never sending it.
        let seg_len = data.len().saturating_sub(off) as u32
            + if flags & TCP_SYN != 0 { 1 } else { 0 }
            + if flags & TCP_FIN != 0 { 1 } else { 0 };
        send_rst(&mac, &ip, src_ip, dst_port, src_port, flags, seq, ack_num, seg_len);
        return;
    }
    if let Some(listen_idx) = listener_idx {
        // RFC 793 §3.9, LISTEN, in this order. A reset is ignored. Anything
        // carrying an ACK acknowledges something this port never sent — a
        // SYN-ACK included — and draws a reset at SEG.ACK, through the same
        // budget as a closed port: it is the same 1:1 reflection. Only then
        // does a SYN open a connection.
        if flags & TCP_RST != 0 { return; }
        if flags & TCP_ACK != 0 {
            send_rst(&mac, &ip, src_ip, dst_port, src_port, flags, seq, ack_num, 0);
            return;
        }
        if flags & TCP_SYN != 0 {
            // Anti-SYN-flood: cap the number of half-open connections
            // (SynRcvd) per listener at half the connection table. With
            // TCP_MAX_CONNS=8 we allow at most 4 half-open SYNs at any
            // time; a further SYN reaps the oldest half-open slot for this
            // listener (U06-7) rather than being dropped outright. Without
            // this cap an attacker could fill the table with SYN_RECV slots
            // in a few packets and starve legitimate clients.
            const MAX_HALF_OPEN_PER_LISTENER: usize = TCP_MAX_CONNS / 2;
            let half_open = {
                let t = TCP.lock();
                let mut n = 0usize;
                for c in t.conns.iter() {
                    if c.state == TcpState::SynRcvd && c.local_port == dst_port {
                        n += 1;
                    }
                }
                n
            };
            if half_open >= MAX_HALF_OPEN_PER_LISTENER {
                // U06-7: a SYN trickle at or below the reaper's own cadence
                // (one every `SYN_MAX_RETRIES` x `SYN_RETRY_INTERVAL_MS` =
                // ~5 s) keeps this cap saturated forever — the comment this
                // replaced claimed the cap "can only ever delay a connection,
                // never deafen the listener permanently", which held only for
                // a single burst, not a sustained trickle. The audit's [rec]
                // is SYN cookies (stateless until the third leg, once the ISN
                // is the HMAC from U06-6); that is a bigger change than fits
                // here, so this is the documented fallback it names instead:
                // reap the OLDEST half-open slot for this listener and let
                // the new SYN take it. An attacker sending one SYN per
                // reaped slot still churns the table indefinitely (no CPU or
                // memory cost beyond today's), but a legitimate client is no
                // longer dropped behind the trickle — it displaces the
                // longest-waiting half-open attempt, which is either the
                // attacker's own oldest slot or a peer who was about to be
                // reaped anyway.
                let oldest = {
                    let t = TCP.lock();
                    let mut found: Option<(usize, u64)> = None;
                    for (i, c) in t.conns.iter().enumerate() {
                        if c.state == TcpState::SynRcvd && c.local_port == dst_port
                            && found.map_or(true, |(_, oldest_time)| c.retx_time < oldest_time)
                        {
                            found = Some((i, c.retx_time));
                        }
                    }
                    found.map(|(i, _)| i)
                };
                match oldest {
                    Some(victim) => {
                        let mut t = TCP.lock();
                        t.conns[victim].state = TcpState::Closed;
                        t.conns[victim].reset_conn_state();
                    }
                    // Cap reached with nothing of ours to reap — should not
                    // happen (the count above only reaches the cap by
                    // counting these same slots), but drop rather than alloc
                    // into a slot nothing made room for.
                    None => return,
                }
            }
            // Accept: create new connection for this peer
            let new_idx_opt = { TCP.lock().alloc() };
            if let Some(mut new_idx) = new_idx_opt {
                let our_seq = generate_isn(&ip, src_ip, dst_port, src_port);
                let peer_opts = parse_syn_options(data, off);
                // Echo only what the SYN offered: a SYN-ACK may carry Window
                // Scale only if the SYN did (RFC 7323 §2.2), and an option one
                // side never offered is an option the other cannot honour.
                let offer = SynOffer {
                    wscale: peer_opts.wscale.is_some(),
                    sack:   peer_opts.sack_ok,
                };
                {
                    let mut t = TCP.lock();
                    // The slot was free when the lock was dropped above; a
                    // `connect` on another hart may have taken it since.
                    // Claiming it anyway would hand one slot to two owners.
                    if t.conns[new_idx].state != TcpState::Closed {
                        match t.alloc() {
                            Some(i) => new_idx = i,
                            None    => return,
                        }
                    }
                    let c = &mut t.conns[new_idx];
                    c.state       = TcpState::SynRcvd;
                    c.local_ip    = ip;
                    c.local_port  = dst_port;
                    c.remote_ip   = *src_ip;
                    c.remote_port = src_port;
                    c.seq         = our_seq;
                    c.ack         = seq.wrapping_add(1);
                    c.remote_mss  = peer_opts.mss;
                    c.reset_conn_state();
                    // Restore values that reset_conn_state cleared
                    c.set_iss(our_seq);
                    c.ack = seq.wrapping_add(1);
                    c.remote_mss = peer_opts.mss;
                    // The negotiation is decided here: the SYN-ACK below echoes
                    // exactly what the peer offered, so both ends agree before
                    // the first segment that could carry a scaled window.
                    if let Some(shift) = peer_opts.wscale {
                        c.wscale_ok  = true;
                        c.snd_wscale = shift;
                        c.rcv_wscale = RCV_WSCALE;
                    }
                    c.sack_ok = peer_opts.sack_ok;
                    let _ = listen_idx; // keep listener alive
                }
                // Send SYN-ACK with MSS and whatever the SYN offered
                let ack_n = { TCP.lock().conns[new_idx].ack };
                send_syn_segment(&mac, &ip, src_ip, dst_port, src_port,
                             TCP_SYN | TCP_ACK, our_seq, ack_n, offer);
                // A listener's child left `Listen`/`Closed`: its SYN-ACK
                // retransmission now needs `tcp_tick`.
                timer_kick();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Acknowledgements and loss recovery (RFC 5681, RFC 6582, RFC 2018)
// ---------------------------------------------------------------------------

/// What an inbound ACK asks the sender to resend once the lock is dropped.
#[derive(Clone, Copy, PartialEq)]
enum Resend {
    None,
    /// One segment: the first byte not yet resent in this recovery and not
    /// SACKed, below `limit`.
    One { limit: u32 },
    /// After a timeout: as many segments as the collapsed window admits, at
    /// most `RECOVERY_RETX_BURST`, below `recover`.
    Window,
    /// RFC 6675 §5 steps (4.3)-(4.5): the segment at SND.UNA, then (C).
    SackEntry,
    /// RFC 6675 §5 (C): while `cwnd - pipe` admits a segment, what `NextSeg`
    /// names by rules (1), (3) and (4). Rule (2), new data, is `send_data`'s:
    /// the send ring holds no unsent bytes for the ACK path to choose.
    Sack,
    /// (C) restricted to rule (1), for `send_data`, which does have new data
    /// and must send lost ranges ahead of it.
    SackLost,
}

/// Process the acknowledgement field of an acceptable segment.
///
/// Two definitions of a duplicate ACK meet here. A peer that negotiated SACK
/// gets RFC 6675's: the ACK reports SACKed bytes not reported before, and
/// `sack_learn` decides that. A peer that did not gets RFC 5681's, below.
///
/// `dup_candidate` is the part of RFC 5681's duplicate-ACK definition only
/// the caller can see: the segment carries no data and neither SYN nor FIN.
/// The rest is checked here — the ACK equals SND.UNA, something is in flight,
/// and the window is the same as the last one advertised. The window test is
/// what the old counter lacked: a window update is an ACK repeating SND.UNA,
/// and three of them — a peer draining its buffer does exactly that — read as
/// a loss, halving the window and resending a segment nobody lost. So did
/// three data segments from a peer with nothing new to acknowledge, which on a
/// link that talks both ways is ordinary traffic.
fn process_ack(
    idx: usize, mac: &[u8; 6], ip: &[u8; 4], ack_num: u32, peer_win: u16,
    dup_candidate: bool, opts: &[u8], now: u64,
) {
    let resend = {
        let mut t = TCP.lock();
        let c = &mut t.conns[idx];
        c.last_activity = now;
        c.keepalive_probes = 0;
        // Beside keepalive because it answers the same question: is the peer
        // still there. A `win=0` ACK resets this -- "still full" is a healthy
        // answer, and only silence is not.
        c.persist_probes = 0;
        // Track the peer's advertised window — every ACK carries an updated
        // value, used by send_data() to avoid overshooting the peer's receive
        // buffer. Scaled by the peer's shift: every segment here is past the
        // SYN exchange.
        let prev_window = c.remote_window;
        c.remote_window = (peer_win as u32) << c.snd_wscale;
        let smss = c.smss();
        // The only ACK past SND.NXT that gets here is one covering our FIN
        // too; the data it acknowledges ends at SND.NXT.
        let ack = if seq_lt(c.seq, ack_num) { c.seq } else { ack_num };
        // RFC 6675 Update(). Blocks are checked against the SND.UNA they were
        // sent against; any that this same ACK then covers are pruned below.
        // `sack_new` is RFC 6675 §2's duplicate ACK: it SACKs bytes above the
        // cumulative ACK that were not SACKed before — whatever else the
        // segment carries, data, a new window or a cumulative advance.
        let sack_new = c.sack_ok && sack_learn(c, opts, ack);

        let mut resend = if seq_lt(c.snd_una, ack) {
            // New data acknowledged: free it from the ring.
            let acked = ack.wrapping_sub(c.snd_una);
            c.tx_head = (c.tx_head + acked as usize) & TCP_SND_BUF_MASK;
            c.snd_una = ack;
            if seq_lt(c.rtx_next, ack) {
                c.rtx_next = ack;
            }
            sack_prune(c);
            if c.rtt_on && seq_le(c.rtt_seq, ack) {
                let sample = now.saturating_sub(c.rtt_time);
                update_rtt(c, sample);
                c.rtt_on = false;
            }
            c.retx_count    = 0;
            c.dup_ack_count = 0;
            // RFC 6298 §5.3: restart the timer for whatever is still in flight.
            c.retx_time = now;

            match c.recovery {
                Recovery::Open => {
                    // RFC 6582 §3.2 step 1 asks whether SND.UNA is past the
                    // last recovery point. Once it is, `recover` follows one
                    // byte behind: left where that recovery set it, the
                    // circular comparison would read it as ahead of SND.UNA
                    // again 2^31 bytes later, and fast retransmit would stay
                    // off for the 2^31 bytes after that.
                    if seq_lt(c.recover, ack) {
                        c.recover = ack.wrapping_sub(1);
                    }
                    grow_cwnd(c, acked, smss);
                    Resend::None
                }
                Recovery::Fast if seq_le(c.recover, ack) => {
                    // RFC 6582 §3.2 step 3, full acknowledgement: deflate to
                    // ssthresh, or less if the flight is smaller, so the
                    // recovery does not end in a burst.
                    c.cwnd = c.ssthresh.min(c.flight().max(smss) + smss);
                    c.recovery = Recovery::Open;
                    Resend::None
                }
                Recovery::Fast => {
                    // Partial acknowledgement (step 5): the ACK stopped at the
                    // next hole of the same flight. Resend it, deflate by what
                    // was acknowledged, and add one segment back if at least
                    // one was.
                    c.cwnd = c.cwnd.saturating_sub(acked);
                    if acked >= smss {
                        c.cwnd = c.cwnd.saturating_add(smss);
                    }
                    c.cwnd = c.cwnd.max(smss);
                    Resend::One { limit: c.recover }
                }
                // RFC 6675 §5 (A): a cumulative ACK past RecoveryPoint ends
                // recovery. `cwnd` is already `ssthresh` and did not grow
                // during it. The scoreboard above the new SND.UNA is kept.
                Recovery::Sack if seq_le(c.recover, ack) => {
                    c.recovery = Recovery::Open;
                    Resend::None
                }
                // (B): the ACK does not cover RecoveryPoint. Update() ran
                // above; SetPipe() and (C) run in `retransmit`.
                Recovery::Sack => Resend::Sack,
                Recovery::Loss | Recovery::PathMtu => {
                    grow_cwnd(c, acked, smss);
                    if seq_le(c.recover, ack) {
                        c.recovery = Recovery::Open;
                        Resend::None
                    } else {
                        Resend::Window
                    }
                }
            }
        } else if !c.sack_ok
            && dup_candidate
            && ack == c.snd_una
            && c.flight() != 0
            && c.remote_window == prev_window
        {
            // RFC 5681's duplicate ACK, for a peer without SACK. A SACK peer's
            // duplicates are RFC 6675's, counted below.
            c.dup_ack_count = c.dup_ack_count.saturating_add(1);
            match c.recovery {
                Recovery::Fast => {
                    // RFC 5681 §3.2 step 4: each further duplicate is a segment
                    // that left the network, so the window is inflated and new
                    // data may follow.
                    c.cwnd = c.cwnd.saturating_add(smss);
                    Resend::None
                }
                // Fast retransmit on the third duplicate (RFC 5681 §3.2), not
                // while SND.UNA is still at or behind the previous recovery
                // point: those duplicates may answer that recovery's own
                // retransmissions (RFC 6582 §3.2 step 1).
                Recovery::Open
                    if c.dup_ack_count == DUP_ACK_THRESHOLD
                        && seq_lt(c.recover, c.snd_una) =>
                {
                    c.ssthresh = (c.flight() / 2).max(2 * smss);
                    c.cwnd     = c.ssthresh.saturating_add(3 * smss);
                    c.recovery = Recovery::Fast;
                    c.recover  = c.seq;
                    c.rtx_next = c.snd_una;
                    Resend::One { limit: c.seq }
                }
                _ => Resend::None,
            }
        } else {
            Resend::None
        };

        // RFC 6675 §5, after the cumulative part of the ACK: DupAcks was
        // cleared above if SND.UNA advanced, and an ACK carrying new SACK
        // information counts as a duplicate whatever else it did.
        if c.sack_ok {
            match c.recovery {
                Recovery::Open if sack_new => {
                    c.dup_ack_count = c.dup_ack_count.saturating_add(1);
                    // Step (1): DupThresh duplicates, which also catches
                    // segments too small for `IsLost`'s byte count. Step (2):
                    // IsLost(HighACK + 1), the scoreboard alone proving the
                    // first unacknowledged byte lost.
                    //
                    // No guard on the previous RecoveryPoint is needed here
                    // (§5.1): `Open` is reached from `Loss` and `Sack` only by
                    // an ACK at or past `recover`.
                    //
                    // Step (3), Limited Transmit, is not implemented.
                    if c.dup_ack_count >= DUP_ACK_THRESHOLD
                        || seq_lt(c.snd_una, sack_lost_below(c, smss))
                    {
                        // (4.1) RecoveryPoint = HighData.
                        c.recover  = c.seq;
                        // (4.2) ssthresh = cwnd = FlightSize / 2, floored at
                        // two segments (RFC 5681 eq. 4). No inflation: `pipe`
                        // replaces it.
                        c.ssthresh = (c.flight() / 2).max(2 * smss);
                        c.cwnd     = c.ssthresh;
                        c.recovery = Recovery::Sack;
                        // (4.3) sets HighRxt and RescueRxt when the segment
                        // at SND.UNA is cut, in `retransmit`.
                        c.rtx_next = c.snd_una;
                        c.rescue   = c.snd_una;
                        resend = Resend::SackEntry;
                    }
                }
                // (B)/(C) run for every ACK processed during recovery, not
                // only for duplicates: a data-bearing ACK or a window update
                // changes the scoreboard, SND.UNA or the window as much as a
                // bare one does.
                Recovery::Sack => resend = Resend::Sack,
                _ => {}
            }
            // The retransmission timer restarts on SACK progress during SACK
            // recovery, the ACK that starts recovery included. RFC 6298 §5.3
            // restarts it on an ACK of new data; during recovery the
            // cumulative ACK stands at the lost segment while the receiver
            // goes on reporting segments it holds, and RFC 6675 takes those
            // bytes out of the network (`sack_pipe`). Timed from the last
            // cumulative ACK instead, a recovery ends in a timeout whenever
            // it takes longer than one RTO — about two round trips: the
            // duplicates arrive one after that ACK, the resend's ACK one
            // later — with its resend still on the way (`tcp_rto_estimate`,
            // 2026-09-14). Only bytes never SACKed before count (`sack_new`),
            // all inside the flight, so one recovery restarts the timer a
            // bounded number of times. Outside SACK recovery a new SACK does
            // not restart it: a tail loss that draws one or two duplicates
            // still times out from its last cumulative ACK.
            if sack_new && c.recovery == Recovery::Sack {
                c.retx_time = now;
            }
        }
        resend
    };
    retransmit(idx, mac, ip, resend);
}

/// Grow `cwnd` for `acked` newly acknowledged bytes, counted in BYTES
/// (RFC 3465, as Linux does): slow start below `ssthresh` grows by what the
/// ACK covers, up to L = 2 SMSS per ACK; congestion avoidance above it by
/// SMSS × acked / cwnd, about one segment per window of bytes acknowledged.
/// Counting per ACK instead (at most one SMSS each, the RFC 5681 §3.1
/// minimum) halves both rates against a receiver that delays its ACKs to
/// every second segment, as RFC 1122 asks and this stack's own receiver does
/// (N6). Never past the send ring, which is all that can ever be in flight.
fn grow_cwnd(c: &mut TcpConn, acked: u32, smss: u32) {
    let inc = if c.cwnd < c.ssthresh {
        // Never past ssthresh in one step: the rest of this ACK belongs to
        // congestion avoidance (Linux `tcp_slow_start`), so a cumulative ACK
        // after a timeout does not jump the window over the halved estimate.
        acked.min(smss.saturating_mul(2)).min(c.ssthresh - c.cwnd)
    } else {
        let acked = acked.min(c.cwnd.max(1)) as u64;
        ((smss as u64 * acked / c.cwnd.max(1) as u64) as u32).max(1)
    };
    c.cwnd = c.cwnd.saturating_add(inc).min(TCP_SND_BUF_SIZE as u32);
}

/// Resend what `process_ack` decided, one segment per lock hold.
///
/// Every byte comes out of the send ring, from SND.UNA onward, skipping what
/// the peer has SACKed and never past the peer's window. `rtx_next` records
/// how far this recovery has resent, so a later ACK continues rather than
/// repeats. Any retransmission ends the RTT measurement (Karn).
fn retransmit(idx: usize, mac: &[u8; 6], ip: &[u8; 4], resend: Resend) {
    let max = match resend {
        Resend::None       => return,
        Resend::One { .. } => 1,
        Resend::Window | Resend::SackEntry | Resend::Sack | Resend::SackLost => RECOVERY_RETX_BURST,
    };
    let mut buf = [0u8; TCP_MSS];
    for i in 0..max {
        let (seq, len, ack, rip, lp, rp, win) = {
            let mut t = TCP.lock();
            let c = &mut t.conns[idx];
            let from = if seq_lt(c.rtx_next, c.snd_una) { c.snd_una } else { c.rtx_next };
            // `rescue`: this segment is NextSeg rule (4)'s, which moves
            // RescueRxt instead of HighRxt.
            let (s, mut len, rescue) = match resend {
                Resend::None => return,
                Resend::One { limit } => match next_hole(c, from, limit) {
                    Some((s, len)) => (s, len, false),
                    None => return,
                },
                Resend::Window => match next_hole(c, from, c.recover) {
                    Some((s, len)) => (s, len, false),
                    None => return,
                },
                // (4.3): the first segment presumed dropped, whatever `pipe`
                // says. SND.UNA is never SACKed, so this starts there and
                // stops at the first SACKed range.
                Resend::SackEntry if i == 0 => {
                    if c.recovery != Recovery::Sack { return; }
                    match next_hole(c, c.snd_una, c.seq) {
                        Some((s, len)) => (s, len, false),
                        None => return,
                    }
                }
                // (C), with SetPipe() recomputed for every segment: each one
                // sent moves HighRxt, and another hart's ACK may have moved
                // the scoreboard in between.
                Resend::SackEntry | Resend::Sack | Resend::SackLost => {
                    if c.recovery != Recovery::Sack { return; }
                    let smss = c.smss();
                    if c.cwnd.saturating_sub(sack_pipe(c, smss)) < smss { return; }
                    match sack_next_seg(c, smss, resend != Resend::SackLost) {
                        Some(seg) => seg,
                        None => return,
                    }
                }
            };
            let wnd_end = c.snd_una.wrapping_add(c.remote_window);
            if !seq_lt(s, wnd_end) {
                return;
            }
            len = len.min(wnd_end.wrapping_sub(s) as usize);
            // After a timeout, everything from SND.UNA to the end of this
            // segment counts against the one-segment window as it reopens.
            if resend == Resend::Window
                && s.wrapping_sub(c.snd_una).saturating_add(len as u32) > c.cwnd
            {
                return;
            }
            c.tx_read(s.wrapping_sub(c.snd_una) as usize, &mut buf[..len]);
            if rescue {
                // Rule (4): RescueRxt = RecoveryPoint, and HighRxt MUST NOT
                // move.
                c.rescue = c.recover;
            } else {
                // (C.2) HighRxt is the last byte of this segment; for (4.3)
                // RescueRxt is too.
                c.rtx_next = s.wrapping_add(len as u32);
                if resend == Resend::SackEntry && i == 0 {
                    c.rescue = c.rtx_next;
                }
            }
            c.rtt_on = false;
            (s, len, c.ack, c.remote_ip, c.local_port, c.remote_port, c.advertise())
        };
        // Live window, same reason as `send_data`: a retransmission carrying
        // the constant would reopen a window we had already closed.
        send_segment_with_window(mac, ip, &rip, lp, rp, TCP_ACK, seq, ack, &buf[..len], win);
    }
}

/// The first run of bytes at or after `from` and before `limit` that the peer
/// has not SACKed: its start, and a length of at most one segment that stops
/// at the next SACKed range.
fn next_hole(c: &TcpConn, from: u32, limit: u32) -> Option<(u32, usize)> {
    let blocks = &c.sacked[..c.sacked_n as usize];
    let mut s = from;
    // Sorted and disjoint, so one pass steps over every range covering `s`.
    for &(l, r) in blocks {
        if seq_le(l, s) && seq_lt(s, r) {
            s = r;
        }
    }
    if !seq_lt(s, limit) {
        return None;
    }
    let mut end = limit;
    for &(l, _) in blocks {
        if seq_lt(s, l) && seq_lt(l, end) {
            end = l;
        }
    }
    Some((s, end.wrapping_sub(s).min(c.smss()) as usize))
}

/// The end of the highest range the peer has SACKed.
fn sack_high(c: &TcpConn) -> Option<u32> {
    if c.sacked_n == 0 { None } else { Some(c.sacked[c.sacked_n as usize - 1].1) }
}

/// RFC 6675 `IsLost`, as a boundary: every byte below the returned sequence
/// that is not SACKed is lost, every byte at or above it is not. SND.UNA when
/// nothing is.
///
/// `IsLost(S)` holds when DupThresh discontiguous SACKed sequences, or more
/// than (DupThresh - 1) * SMSS SACKed bytes, lie above S. Lowering S only adds
/// SACKed bytes above it, so the lost bytes are a prefix, and walking the
/// ranges down from the highest finds where it ends: at the left edge of the
/// first range that completes either count.
///
/// Segment boundaries are not recorded — the send ring is a byte stream — so
/// "discontiguous SACKed sequences" are counted as scoreboard ranges. Adjacent
/// SACKed segments merge into one range and count once; for segments of an
/// SMSS the byte count decides anyway, and for smaller ones DupThresh
/// duplicate ACKs start recovery without `IsLost` (§5 step 1).
fn sack_lost_below(c: &TcpConn, smss: u32) -> u32 {
    let mut ranges = 0u8;
    let mut bytes = 0u32;
    for k in (0..c.sacked_n as usize).rev() {
        let (l, r) = c.sacked[k];
        ranges += 1;
        bytes = bytes.saturating_add(r.wrapping_sub(l));
        if ranges >= DUP_ACK_THRESHOLD
            || bytes > (DUP_ACK_THRESHOLD as u32 - 1).saturating_mul(smss)
        {
            return l;
        }
    }
    c.snd_una
}

/// RFC 6675 `SetPipe()`: the bytes between SND.UNA and SND.NXT still believed
/// to be in the network. Each byte not SACKed counts once if it is not lost
/// (its original transmission may still arrive) and once more if it was
/// retransmitted in this recovery (HighRxt). Written in closed form over the
/// scoreboard rather than per byte: the lost bytes are a prefix
/// (`sack_lost_below`), and so are the retransmitted ones (below `rtx_next`).
fn sack_pipe(c: &TcpConn, smss: u32) -> u32 {
    let una = c.snd_una;
    let flight = c.flight();
    // Bytes not SACKed in the first `x` bytes past SND.UNA.
    let unsacked_below = |x: u32| -> u32 {
        let mut held = 0u32;
        for &(l, r) in &c.sacked[..c.sacked_n as usize] {
            let lo = l.wrapping_sub(una);
            let hi = r.wrapping_sub(una).min(x);
            if lo < hi {
                held += hi - lo;
            }
        }
        x.saturating_sub(held)
    };
    let lost = sack_lost_below(c, smss).wrapping_sub(una).min(flight);
    let resent = if seq_lt(una, c.rtx_next) { c.rtx_next.wrapping_sub(una).min(flight) } else { 0 };
    (unsacked_below(flight) - unsacked_below(lost)) + unsacked_below(resent)
}

/// RFC 6675 `NextSeg()` during recovery: the start, length and rule-(4) flag
/// of the next segment to retransmit, or `None`. Rule (2), new data, is not
/// here: the send ring holds only bytes already sent, and `send_data` sends
/// new ones. With `beyond_lost` false only rule (1) is consulted — the caller
/// has new data waiting, which rule (2) puts ahead of rules (3) and (4).
fn sack_next_seg(c: &TcpConn, smss: u32, beyond_lost: bool) -> Option<(u32, usize, bool)> {
    let from = if seq_lt(c.rtx_next, c.snd_una) { c.snd_una } else { c.rtx_next };
    // (1) The first byte above HighRxt that is not SACKed and is lost — which
    // puts it below the highest SACKed byte, since the loss boundary is the
    // left edge of a SACKed range.
    if let Some((s, len)) = next_hole(c, from, sack_lost_below(c, smss)) {
        return Some((s, len, false));
    }
    if !beyond_lost {
        return None;
    }
    // (3) The same, without the loss test.
    if let Some(high) = sack_high(c) {
        if let Some((s, len)) = next_hole(c, from, high) {
            return Some((s, len, false));
        }
    }
    // (4) One rescue retransmission per recovery, once HighACK is past
    // RescueRxt: up to a segment ending at the highest byte not SACKed, so a
    // loss at the tail of the flight still draws an ACK before the timer.
    if seq_lt(c.rescue, c.snd_una) {
        let n = c.sacked_n as usize;
        // [lo, top): the highest run of bytes not SACKed.
        let (lo, top) = if n == 0 {
            (c.snd_una, c.seq)
        } else if c.sacked[n - 1].1 == c.seq {
            (if n >= 2 { c.sacked[n - 2].1 } else { c.snd_una }, c.sacked[n - 1].0)
        } else {
            (c.sacked[n - 1].1, c.seq)
        };
        if seq_lt(lo, top) {
            let len = top.wrapping_sub(lo).min(smss);
            return Some((top.wrapping_sub(len), len as usize, true));
        }
    }
    None
}

/// Read the SACK blocks of an inbound ACK into the scoreboard, and say whether
/// any of them reported bytes above `ack`, the segment's cumulative ACK, that
/// the scoreboard did not already hold (RFC 6675 §2's duplicate ACK).
///
/// A block is believed only if it names bytes strictly above SND.UNA and not
/// past SND.NXT: anything else is stale, a duplicate report (RFC 2883), or
/// made up. A block at SND.UNA itself contradicts the cumulative ACK in the
/// same segment, and the cumulative ACK wins. What the scoreboard is allowed
/// to cost is bounded by what it is used for: skipping a retransmission, and
/// in SACK recovery deciding what is lost and how much is in the network. A
/// false block delays those bytes to the next timeout, which forgets every
/// block (RFC 2018 §8) — it can never lose one. It can make `pipe` smaller
/// than what is really in the network, by at most the bytes it names, all of
/// which lie below SND.NXT inside a window the peer already offered; a segment
/// that passed `ack_acceptable` could inflate the sender as much by
/// acknowledging those bytes outright.
fn sack_learn(c: &mut TcpConn, opts: &[u8], ack: u32) -> bool {
    let mut new = false;
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            TCP_OPT_EOL => break,
            TCP_OPT_NOP => { i += 1; continue; }
            _ => {}
        }
        if i + 1 >= opts.len() { break; }
        let len = opts[i + 1] as usize;
        if len < 2 || i + len > opts.len() { break; }
        if opts[i] == TCP_OPT_SACK && len >= 10 && (len - 2) % 8 == 0 {
            for b in opts[i + 2..i + len].chunks_exact(8) {
                let l = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                let r = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
                if seq_lt(c.snd_una, l) && seq_lt(l, r) && seq_le(r, c.seq) {
                    let above = if seq_lt(l, ack) { ack } else { l };
                    if seq_lt(above, r) && !sack_holds(c, above, r) {
                        new = true;
                    }
                    sack_insert(c, l, r);
                }
            }
        }
        i += len;
    }
    new
}

/// Does one scoreboard range already cover all of [l, r)? Ranges that touch
/// are merged on insert, so one range is enough to ask about.
fn sack_holds(c: &TcpConn, l: u32, r: u32) -> bool {
    c.sacked[..c.sacked_n as usize]
        .iter()
        .any(|&(a, b)| seq_le(a, l) && seq_le(r, b))
}

/// Merge [l, r) into the scoreboard, keeping it sorted by distance from
/// SND.UNA. When it is full the highest range is dropped: forgetting a range
/// costs one needless retransmission, never a byte.
fn sack_insert(c: &mut TcpConn, mut l: u32, mut r: u32) {
    let una = c.snd_una;
    let mut kept = [(0u32, 0u32); SACK_SCOREBOARD + 1];
    let mut n = 0usize;
    for &(a, b) in &c.sacked[..c.sacked_n as usize] {
        if seq_le(a, r) && seq_le(l, b) {
            if seq_lt(a, l) { l = a; }
            if seq_lt(r, b) { r = b; }
        } else {
            kept[n] = (a, b);
            n += 1;
        }
    }
    let off = l.wrapping_sub(una);
    let mut k = n;
    while k > 0 && kept[k - 1].0.wrapping_sub(una) > off {
        kept[k] = kept[k - 1];
        k -= 1;
    }
    kept[k] = (l, r);
    let n = (n + 1).min(SACK_SCOREBOARD);
    c.sacked[..n].copy_from_slice(&kept[..n]);
    c.sacked_n = n as u8;
}

/// Drop every range SND.UNA has reached. One that SND.UNA stopped inside was
/// reneged on, so it goes too.
fn sack_prune(c: &mut TcpConn) {
    let una = c.snd_una;
    let mut n = 0usize;
    for k in 0..c.sacked_n as usize {
        let (l, r) = c.sacked[k];
        if seq_lt(una, l) {
            c.sacked[n] = (l, r);
            n += 1;
        }
    }
    c.sacked_n = n as u8;
}

/// Acknowledgement processing for our data still in flight in `FinWait1` or
/// `LastAck`.
///
/// `close()` sends its FIN at SND.NXT whatever is still unacknowledged, and
/// with several segments in flight that is the ordinary case. These states
/// used to process no acknowledgement of data and `tcp_tick` retried only the
/// FIN, so a segment lost just before a close was never resent: the peer,
/// missing it, never acknowledged the FIN either, and the slot was reaped with
/// the stream short.
///
/// The same two gates as `Established`: the segment is in the receive window,
/// and the ACK acknowledges nothing we never sent — the FIN counts as sent.
fn ack_data_in_fin_state(
    idx: usize, mac: &[u8; 6], ip: &[u8; 4], seq: u32, ack_num: u32, flags: u8,
    peer_win: u16, payload_len: usize, expected_ack: u32, rcv_wnd: u32,
    opts: &[u8], now: u64,
) {
    if flags & TCP_ACK == 0 { return; }
    let (snd_una, snd_nxt) = {
        let t = TCP.lock();
        (t.conns[idx].snd_una, t.conns[idx].seq)
    };
    if snd_una == snd_nxt { return; }
    let fin = flags & TCP_FIN != 0;
    if !segment_acceptable(seq, payload_len + fin as usize, expected_ack, rcv_wnd) { return; }
    if !ack_acceptable(ack_num, snd_una, snd_nxt.wrapping_add(1)) { return; }
    process_ack(idx, mac, ip, ack_num, peer_win,
                payload_len == 0 && !fin && flags & TCP_SYN == 0, opts, now);
}

/// Answer an unacceptable segment with an ACK of where we are (RFC 793 §3.9),
/// at most once per `INVALID_ACK_INTERVAL_MS` per connection.
fn send_invalid_ack(idx: usize, mac: &[u8; 6], ip: &[u8; 4], now: u64) {
    let (rip, lp, rp, seq_n, ack_n, win, opts, opts_len) = {
        let mut t = TCP.lock();
        let c = &mut t.conns[idx];
        if c.last_invalid_ack != 0
            && now.wrapping_sub(c.last_invalid_ack) < INVALID_ACK_INTERVAL_MS * TICKS_PER_MS
        {
            return;
        }
        c.last_invalid_ack = now.max(1);
        // An ACK like any other, so it repeats what is held out of order.
        let mut opts = [0u8; TCP_OPT_MAX];
        let opts_len = sack_option(c, &mut opts);
        (c.remote_ip, c.local_port, c.remote_port, c.seq, c.ack, c.advertise(), opts, opts_len)
    };
    #[cfg(feature = "qemu")]
    trace_tx(lp, &rip, rp, TCP_ACK, seq_n, ack_n, &[]);
    send_segment_opts(mac, ip, &rip, lp, rp, TCP_ACK, seq_n, ack_n, win, &opts[..opts_len], &[]);
}

// ---------------------------------------------------------------------------
// OOO reassembly helpers (F01)
// ---------------------------------------------------------------------------

/// Every held entry fits in one SACK option, so every one is reported: what
/// `store_ooo_segment` relies on when it refuses to evict.
const _: () = assert!(OOO_MAX_SEGMENTS <= SACK_MAX_BLOCKS);

/// Store an out-of-order segment in the connection's OOO buffer, or drop it
/// when no slot is free.
fn store_ooo_segment(c: &mut TcpConn, seg_seq: u32, data: &[u8]) {
    let copy_len = data.len().min(OOO_SEGMENT_MAX_LEN);
    if copy_len == 0 { return; }

    // Check if we already have this segment. A segment at the same sequence
    // is not necessarily the same segment: a sender that re-cuts its
    // retransmissions from SND.UNA — this stack's does, so does Linux's — may
    // resend a short held segment as a longer one. Keep whichever copy holds
    // more, or the longer one's tail is thrown away and has to come round
    // again.
    for i in 0..OOO_MAX_SEGMENTS {
        if c.ooo_buf[i].valid && c.ooo_buf[i].seq == seg_seq {
            if copy_len > c.ooo_buf[i].len as usize {
                c.ooo_buf[i].data[..copy_len].copy_from_slice(&data[..copy_len]);
                c.ooo_buf[i].len = copy_len as u16;
            }
            return;
        }
    }

    // A free slot, or the arrival is dropped, whatever its sequence: beyond
    // every held entry, before them, or over one. A held entry is never
    // evicted (owner decision 2026-09-14). Every held entry has been
    // reported: the ACK answering it named it in a SACK block when SACK was
    // negotiated, and all of them fit in one option (the assert above).
    // Evicting one is reneging (RFC 2018 §8). The sender keeps the range as
    // delivered, SACK recovery skips it, and only a retransmission timeout
    // repairs it. With one-MSS slots each block covers a whole segment: the
    // eviction this replaced (the farthest entry, for any arrival) left a
    // sender scoreboard of 128,480 B against 5,840 B held, and timeouts that
    // backed off to 3.5 s (`tcp_throughput`, 2026-09-14). A dropped arrival
    // was never acknowledged or reported, so the peer sends it again.
    let Some(s) = (0..OOO_MAX_SEGMENTS).find(|&i| !c.ooo_buf[i].valid) else { return };
    c.ooo_buf[s].seq = seg_seq;
    c.ooo_buf[s].len = copy_len as u16;
    c.ooo_buf[s].data[..copy_len].copy_from_slice(&data[..copy_len]);
    c.ooo_buf[s].valid = true;
}

/// Flush OOO segments that are now contiguous with conn.ack.
///
/// "Contiguous" includes an entry that RCV.NXT has moved INTO: the peer
/// retransmits whole segments, so an in-order segment routinely covers the
/// front of a held one. Such an entry used to be matched only on
/// `seq == c.ack` exactly, so once RCV.NXT passed its first byte it never
/// matched again — its tail was never delivered, and it sat below RCV.NXT
/// holding a slot until evicted. Now its already-received front is skipped and
/// the rest delivered, and an entry wholly behind RCV.NXT is retired. Both
/// matter to SACK: a block must never report a range below the cumulative ACK.
fn flush_ooo_segments(c: &mut TcpConn) {
    // Repeat until no more contiguous segments found
    let mut flushed = true;
    while flushed {
        flushed = false;
        for i in 0..OOO_MAX_SEGMENTS {
            if !c.ooo_buf[i].valid { continue; }
            let len = c.ooo_buf[i].len as usize;
            // How far RCV.NXT already is past this entry's first byte. An entry
            // still ahead of RCV.NXT is within one window of it, so its
            // wrapping distance back reads as more than 2^31.
            let behind = c.ack.wrapping_sub(c.ooo_buf[i].seq);
            if behind >= 1u32 << 31 { continue; }
            if behind as usize >= len {
                // Every byte it holds already arrived in order.
                c.ooo_buf[i].valid = false;
                continue;
            }
            // This segment is now contiguous — write to rx_buf.
            // Same correctness rule as the in-order path: only advance
            // c.ack by the bytes we actually stored.
            let mut j = behind as usize;
            while j < len {
                let next = (c.rx_tail + 1) & TCP_BUF_MASK;
                if next == c.rx_head { break; }
                c.rx_buf[c.rx_tail] = c.ooo_buf[i].data[j];
                c.rx_tail = next;
                j += 1;
            }
            c.ack = c.ack.wrapping_add((j - behind as usize) as u32);
            if j == len {
                // Whole segment landed — retire the OOO slot.
                c.ooo_buf[i].valid = false;
                flushed = true;
                break; // restart scan since ack changed
            }
            // The ring filled mid-segment. Keep only what did not fit, re-based
            // at the new RCV.NXT, so the next flush after a drain picks it up
            // instead of finding it stranded below RCV.NXT. Don't loop again or
            // we'd spin.
            let seg = &mut c.ooo_buf[i];
            seg.data.copy_within(j..len, 0);
            seg.seq = seg.seq.wrapping_add(j as u32);
            seg.len = (len - j) as u16;
            return;
        }
    }
}

/// Calculate free space in the receive buffer (for flow control — F01).
fn rx_free_space(c: &TcpConn) -> usize {
    let used = c.rx_available();
    TCP_BUF_SIZE.saturating_sub(used).saturating_sub(1) // -1 to avoid full==empty ambiguity
}

/// Build the SACK option (RFC 2018 §3) describing `c`'s out-of-order queue into
/// `out`, and return its length — 0 when SACK was not negotiated or nothing is
/// held beyond RCV.NXT.
///
/// **Every block is a range actually STORED**, not a range received: a held
/// segment is truncated to `OOO_SEGMENT_MAX_LEN`, and a block covering the
/// truncated tail would tell the sender bytes it must never resend are safe
/// with us. Entries at or below RCV.NXT are skipped — a block there is either
/// nonsense or a duplicate report the sender does not expect.
///
/// Adjacent and overlapping entries are merged, and the block holding the most
/// recent arrival goes first (§4). Evicting a reported entry later is reneging,
/// which §8 permits: the sender keeps SACKed data until it is cumulatively
/// ACKed, so the cost is a retransmission, never a hole.
fn sack_option(c: &TcpConn, out: &mut [u8; TCP_OPT_MAX]) -> usize {
    if !c.sack_ok { return 0; }
    let wnd = c.rcv_wnd_max();

    // (start, end) as offsets from RCV.NXT, sorted by start.
    let mut blocks = [(0u32, 0u32); OOO_MAX_SEGMENTS];
    let mut n = 0usize;
    for seg in c.ooo_buf.iter() {
        if !seg.valid || seg.len == 0 { continue; }
        let off = seg.seq.wrapping_sub(c.ack);
        if off == 0 || off >= wnd { continue; }
        let mut k = n;
        while k > 0 && blocks[k - 1].0 > off {
            blocks[k] = blocks[k - 1];
            k -= 1;
        }
        blocks[k] = (off, off + seg.len as u32);
        n += 1;
    }
    if n == 0 { return 0; }

    let mut m = 0usize;
    for k in 0..n {
        if m > 0 && blocks[k].0 <= blocks[m - 1].1 {
            blocks[m - 1].1 = blocks[m - 1].1.max(blocks[k].1);
        } else {
            blocks[m] = blocks[k];
            m += 1;
        }
    }

    let recent = c.ooo_recent.wrapping_sub(c.ack);
    if let Some(p) = (0..m).find(|&k| recent >= blocks[k].0 && recent < blocks[k].1) {
        let first = blocks[p];
        let mut k = p;
        while k > 0 {
            blocks[k] = blocks[k - 1];
            k -= 1;
        }
        blocks[0] = first;
    }

    let m = m.min(SACK_MAX_BLOCKS);
    out[0] = TCP_OPT_NOP;
    out[1] = TCP_OPT_NOP;
    out[2] = TCP_OPT_SACK;
    out[3] = (2 + 8 * m) as u8;
    for (k, &(start, end)) in blocks[..m].iter().enumerate() {
        let at = 4 + 8 * k;
        out[at..at + 4].copy_from_slice(&c.ack.wrapping_add(start).to_be_bytes());
        out[at + 4..at + 8].copy_from_slice(&c.ack.wrapping_add(end).to_be_bytes());
    }
    4 + 8 * m
}

// ---------------------------------------------------------------------------
// send_segment with custom window (F01 flow control)
// ---------------------------------------------------------------------------

/// Like send_segment but with a custom advertised window (for flow control).
fn send_segment_with_window(
    our_mac: &[u8; 6], our_ip: &[u8; 4], dst_ip: &[u8; 4],
    src_port: u16, dst_port: u16, flags: u8,
    seq: u32, ack: u32, data: &[u8], window: u16,
) -> i32 {
    send_segment_opts(our_mac, our_ip, dst_ip, src_port, dst_port,
                      flags, seq, ack, window, &[], data)
}

/// Build and send one segment. Every TCP header this stack emits is written
/// here.
///
/// `opts` sits between the fixed header and the payload and must already be
/// padded to whole 32-bit words: `data_off` counts words, and the receiver
/// finds the payload by it. Callers put options only on payload-free segments
/// — a full MSS plus options would exceed the MTU.
fn send_segment_opts(
    our_mac: &[u8; 6], our_ip: &[u8; 4], dst_ip: &[u8; 4],
    src_port: u16, dst_port: u16, flags: u8,
    seq: u32, ack: u32, window: u16, opts: &[u8], data: &[u8],
) -> i32 {
    if opts.len() > TCP_OPT_MAX || opts.len() % 4 != 0 { return -1; }
    let hdr_len = TCP_HDR_MIN + opts.len();
    let tcp_len = hdr_len + data.len();
    // Returns the `ip::send` result rather than nothing. `send_data` advances
    // `seq` only when the segment actually left, and swallowing the failure
    // here would advance it over bytes the peer never saw -- a silent hole in
    // the stream that shows up as a stalled transfer, not as an error.
    if tcp_len > TCP_SEGMENT_BUF_SIZE { return -1; }

    let mut buf = [0u8; TCP_SEGMENT_BUF_SIZE];
    let hdr = unsafe { &mut *(buf.as_mut_ptr() as *mut TcpHdr) };
    hdr.src_port = src_port.to_be_bytes();
    hdr.dst_port = dst_port.to_be_bytes();
    hdr.seq      = seq.to_be_bytes();
    hdr.ack      = ack.to_be_bytes();
    hdr.data_off = ((hdr_len / 4) as u8) << 4;
    hdr.flags    = flags;
    hdr.window   = window.to_be_bytes(); // custom window (flow control)
    hdr.checksum = [0, 0];
    hdr.urgent   = [0, 0];
    buf[TCP_HDR_MIN..hdr_len].copy_from_slice(opts);
    buf[hdr_len..tcp_len].copy_from_slice(data);

    let pseudo = ip::pseudo_checksum(our_ip, dst_ip, ip::IP_PROTO_TCP, tcp_len as u16);
    let cs = tcp_checksum(pseudo, &buf[..tcp_len]);
    buf[TCP_CHECKSUM_OFFSET]    = (cs >> 8) as u8;
    buf[TCP_CHECKSUM_OFFSET_HI] = (cs & 0xff) as u8;

    // Don't Fragment on every segment (RFC 1191 §3): a smaller path answers
    // with Fragmentation Needed (`icmp_frag_needed`) or, if it says nothing,
    // shows up as a black hole in `tcp_tick`.
    ip::send(our_mac, our_ip, dst_ip, ip::IP_PROTO_TCP, &buf[..tcp_len])
}

/// Periodic tick — call from timer interrupt to drive retransmissions and keep-alive.
/// Whether [`tcp_tick`] has any work that a clock can make due.
///
/// `tcp_tick` skips every connection in `Closed` or `Listen` and touches
/// nothing outside its per-connection loop, so this is its own skip test
/// negated: `false` means no retransmission, persist probe, keep-alive,
/// TIME-WAIT, FIN-WAIT-2 or SYN retry can fall due until a connection
/// leaves those two states. A connection leaves them only in
/// [`connect`] (caller's context) or on an inbound SYN to a listener
/// (receive path); both call [`timer_kick`].
pub fn tick_needed() -> bool {
    let t = TCP.lock();
    t.conns.iter().any(|c| c.state != TcpState::Closed && c.state != TcpState::Listen)
}

/// Callback run when a connection leaves `Closed`/`Listen`, i.e. when
/// [`tick_needed`] may have turned true. `0` = none registered. The kernel
/// registers the network poller's wake here, so a poller parked without a
/// timer learns that `tcp_tick` has work again.
static TIMER_KICK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Register the [`TIMER_KICK`] callback. It runs in task context, without
/// the TCP lock held.
pub fn set_timer_kick(f: fn()) {
    TIMER_KICK.store(f as usize, core::sync::atomic::Ordering::Release);
}

fn timer_kick() {
    let p = TIMER_KICK.load(core::sync::atomic::Ordering::Acquire);
    if p != 0 {
        // SAFETY: only `set_timer_kick` stores a non-zero value, and it
        // stores a `fn()`.
        let f: fn() = unsafe { core::mem::transmute::<usize, fn()>(p) };
        f();
    }
}

// ---------------------------------------------------------------------------
// TCP deadlines on the kernel timer (wave 15: the stack is woken when a timer
// falls due, not by the net poll task's cadence)
// ---------------------------------------------------------------------------

/// When the net poll task will next wake by itself, in ticks; 0 while it
/// runs (it recomputes its deadline before sleeping, so nothing it arms
/// needs a kick). Set by [`poll_sleep_until`] / [`poll_running`].
static POLL_WAKE_AT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// TCP timer events that fired (delayed ACK, RTO, SYN/FIN retry, keep-alive)
/// and the latest any of them fired past its deadline, in ticks: how well the
/// stack is woken at its deadlines (QEMU rows read them with gdb).
static TIMER_FIRED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static TIMER_LATE_MAX: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn timer_fired(due: u64, now: u64) {
    use core::sync::atomic::Ordering;
    TIMER_FIRED.fetch_add(1, Ordering::Relaxed);
    TIMER_LATE_MAX.fetch_max(now.saturating_sub(due), Ordering::Relaxed);
}

/// `(timer events fired, latest past its deadline in ticks)`.
pub fn timer_lateness() -> (u64, u64) {
    use core::sync::atomic::Ordering;
    (TIMER_FIRED.load(Ordering::Relaxed), TIMER_LATE_MAX.load(Ordering::Relaxed))
}

/// The earliest tick at which [`tcp_tick`] has work for connection `c`: a
/// held ACK's delay, the SYN/FIN retry, FIN-WAIT-2's timeout, the persist
/// probe, the retransmission timeout, TIME-WAIT's end, the keep-alive
/// probe. It mirrors the conditions of `tcp_timers` (a deadline here never
/// lies later than the one `tcp_tick` acts on; 0 means "at once": a persist
/// cycle to start or reset, which `tcp_tick` does on its next run).
fn conn_deadline(c: &TcpConn) -> Option<u64> {
    let mut d: Option<u64> = None;
    let mut at = |t: u64| d = Some(d.map_or(t, |x: u64| x.min(t)));
    // Only where `flush_held_acks` sends it; it drops the rest itself.
    if c.ack_pending && matches!(c.state, TcpState::Established | TcpState::CloseWait
                                 | TcpState::FinWait1 | TcpState::FinWait2) {
        at(c.ack_due);
    }
    let ms = |v: u64| v * TICKS_PER_MS;
    match c.state {
        TcpState::Closed | TcpState::Listen => {}
        TcpState::SynSent | TcpState::SynRcvd => at(c.retx_time + ms(SYN_RETRY_INTERVAL_MS)),
        TcpState::FinWait2 => at(c.retx_time + ms(FIN_WAIT2_TIMEOUT_MS)),
        TcpState::FinWait1 | TcpState::LastAck if c.flight() == 0 =>
            at(c.retx_time + ms(SYN_RETRY_INTERVAL_MS)),
        _ => {
            let est = matches!(c.state, TcpState::Established | TcpState::CloseWait);
            if est && c.remote_window == 0 {
                if c.persist_time == 0 {
                    at(0);
                } else {
                    let iv = if c.persist_ticks == 0 { ms(PERSIST_INITIAL_MS) } else { c.persist_ticks };
                    at(c.persist_time + iv);
                }
            } else {
                if c.persist_ticks != 0 { at(0); }
                if c.flight() != 0 { at(c.retx_time + c.rto_ticks); }
                if c.state == TcpState::TimeWait { at(c.time_wait_start + ms(TIME_WAIT_MS)); }
                if est && c.flight() == 0 { at(c.last_activity + KEEPALIVE_INTERVAL_TICKS); }
            }
        }
    }
    d
}

/// The earliest tick at which [`tcp_tick`] has work on any connection, or
/// `None` when no clock can give it any. The net poll task sleeps until
/// this (bounded by its ceiling), on the kernel's timer: no periodic tick.
pub fn next_deadline() -> Option<u64> {
    let t = TCP.lock();
    t.conns.iter().filter_map(conn_deadline).min()
}

/// The net poll task is running: nothing armed now needs a kick.
pub fn poll_running() {
    POLL_WAKE_AT.store(0, core::sync::atomic::Ordering::SeqCst);
}

/// The net poll task is about to sleep until `dl`. Publishes it, then looks
/// once more: a deadline armed after the caller's own [`next_deadline`]
/// but before this store was not kicked, and is seen here instead. Returns
/// `false` (do not sleep; run again) when one earlier than `dl` exists.
/// One armed after the store kicks the task ([`set_timer_kick`]), which
/// is stamped if the task has not blocked yet.
pub fn poll_sleep_until(dl: u64) -> bool {
    use core::sync::atomic::Ordering;
    POLL_WAKE_AT.store(dl.max(1), Ordering::SeqCst);
    match next_deadline() {
        Some(d) if d < dl => { POLL_WAKE_AT.store(0, Ordering::SeqCst); false }
        _ => true,
    }
}

/// Kick the poll task if `d` falls before its next wake.
fn note_deadline(d: Option<u64>) {
    let Some(d) = d else { return };
    let w = POLL_WAKE_AT.load(core::sync::atomic::Ordering::SeqCst);
    if w != 0 && d < w {
        timer_kick();
    }
}

/// [`note_deadline`] for connection `idx`, from a caller outside the poll
/// task that just changed it (O(1); nothing while the poll task runs).
fn note_conn(idx: usize) {
    if idx >= TCP_MAX_CONNS
        || POLL_WAKE_AT.load(core::sync::atomic::Ordering::SeqCst) == 0
    {
        return;
    }
    let d = { let t = TCP.lock(); conn_deadline(&t.conns[idx]) };
    note_deadline(d);
}

/// [`note_deadline`] over every connection (the receive path, which does
/// not say which connection it touched; nothing while the poll task runs).
fn note_all() {
    if POLL_WAKE_AT.load(core::sync::atomic::Ordering::SeqCst) == 0 { return; }
    note_deadline(next_deadline());
}

pub fn tcp_tick() {
    // Delayed ACKs whose `TCP_DELACK_TICKS` ran out (N6). Before the timers
    // below, so a retransmission decided this tick is not preceded by an ACK
    // the peer has been waiting on longer.
    flush_held_acks(true);
    tcp_timers();
    // N7: a handshake given up, a connection timed out: its waiter learns
    // now rather than at its own deadline.
    crate::wait::TCP_WAITERS.notify();
}

fn tcp_timers() {
    let now = azos_drv_sys::timebase::now();
    let (mac, ip) = { let t = TCP.lock(); (t.our_mac, t.our_ip) };

    for idx in 0..TCP_MAX_CONNS {
        let (state, outstanding, retx_time, rto, retx_count, last_act, ka_probes,
             conn_seq, ack_val, lp, rp, rip, our_win, synack_offer,
             remote_win, persist_time, persist_ticks, persist_probes) = {
            let t = TCP.lock();
            let c = &t.conns[idx];
            (c.state, c.flight() != 0, c.retx_time, c.rto_ticks, c.retx_count,
             c.last_activity, c.keepalive_probes,
             c.seq, c.ack, c.local_port, c.remote_port, c.remote_ip,
             c.adv_window(), SynOffer { wscale: c.wscale_ok, sack: c.sack_ok },
             c.remote_window, c.persist_time, c.persist_ticks, c.persist_probes)
        };

        if state == TcpState::Closed || state == TcpState::Listen {
            continue;
        }

        // --- Handshake (half-open) timer ---
        //
        // The retransmission branch below is gated on data in flight, and
        // there is none for the whole handshake — a SYN carries no data to
        // put in the send ring.
        // That is why half-open slots previously lived forever: this was the
        // reaper `MAX_HALF_OPEN_PER_LISTENER` assumed existed. Four SYNs that
        // were opened and abandoned deafened a listener until reboot; eight
        // took every slot in the table.
        //
        // `retx_time` is seeded to the creation instant by `reset_conn_state`,
        // so it serves as both "when the last SYN went out" and "when this
        // slot was born", and `retx_count` — unused while nothing is in
        // flight — counts the retries. Retransmitting rather than only reaping is also
        // the correct behaviour: a dropped SYN-ACK now recovers in ~1 s
        // instead of stalling until the peer gives up.
        if state == TcpState::SynSent || state == TcpState::SynRcvd {
            let interval = SYN_RETRY_INTERVAL_MS * TICKS_PER_MS;
            if now.saturating_sub(retx_time) >= interval {
                timer_fired(retx_time + interval, now);
                if retx_count >= SYN_MAX_RETRIES {
                    // Budget spent — free the slot.
                    let mut t = TCP.lock();
                    let c = &mut t.conns[idx];
                    c.state        = TcpState::Closed;
                    c.clear_send_queue();
                    c.retx_count   = 0;
                    c.was_accepted = false;
                    continue;
                }
                // Re-send our SYN (active open) or SYN-ACK (passive open).
                // `conn_seq` is still the ISS in both states: it is only
                // advanced on the transition to Established.
                // The retry repeats the first transmission's options exactly:
                // a SYN-ACK retransmission that dropped Window Scale would
                // leave the peer scaling windows we read unscaled.
                let (syn_flags, syn_ack, offer) = if state == TcpState::SynSent {
                    (TCP_SYN, 0, SynOffer::ALL)
                } else {
                    (TCP_SYN | TCP_ACK, ack_val, synack_offer)
                };
                send_syn_segment(&mac, &ip, &rip, lp, rp, syn_flags, conn_seq, syn_ack, offer);

                let mut t = TCP.lock();
                let c = &mut t.conns[idx];
                c.retx_count = c.retx_count.saturating_add(1);
                c.retx_time  = now;
            }
            // Nothing below applies to a half-open connection.
            continue;
        }

        // ORDERING: this sits ABOVE the retransmission timer, and that is the
        // whole point rather than a stylistic choice.
        //
        // `remote_window` is updated by EVERY ACK, but SND.UNA only moves on an
        // ACK that advances. So a peer can hold our segment, acknowledge
        // nothing, and drop its window to zero -- leaving data in flight and
        // `remote_win == 0` at the same time. With the retransmission timer
        // first, that state retransmits a segment into a window the peer has
        // just said is zero. The peer has nowhere to put it, so it cannot
        // acknowledge it, so `retx_count` climbs, `cwnd` collapses and
        // `ssthresh` halves on each pass as if this were congestion -- and after
        // RETX_MAX_ATTEMPTS the connection is declared dead and closed.
        //
        // A healthy peer that was merely busy for a few seconds thus gets its
        // connection torn down, by the machinery meant to survive loss. RFC 1122
        // §4.2.2.17 is explicit that a connection must NOT be dropped for
        // persisting against a zero window; probing is what that state calls
        // for, and a probe carries no data, so it costs the peer nothing to
        // answer and nothing counts against the retransmission budget.

        // --- FinWait2: the peer owes us a FIN and may never send one ---
        //
        // Reclaimed rather than retransmitted, because there is nothing to
        // retransmit: our FIN was acknowledged, and the missing segment is the
        // peer's. Resending anything would be asking a question we have already
        // had answered.
        if state == TcpState::FinWait2 {
            if now.saturating_sub(retx_time) >= FIN_WAIT2_TIMEOUT_MS * TICKS_PER_MS {
                let mut t = TCP.lock();
                let c = &mut t.conns[idx];
                c.state = TcpState::Closed;
                c.clear_send_queue();
            }
            continue;
        }

        // --- Teardown retransmission: FinWait1 / LastAck ---
        //
        // A FIN occupies a byte of sequence space and must be retransmitted
        // like any other, and until now nothing did. `close()` sent it through
        // `send_segment`, set `fin_seq` and the state, and marked nothing
        // outstanding -- so no branch below ever looked at it again. One lost
        // FIN parked the slot in `FinWait1` or `LastAck` permanently, and with
        // eight slots the robot could neither dial out nor accept a
        // connection. The same class `SYN_MAX_RETRIES` already closed for
        // half-open slots, stopped at the handshake.
        //
        // Reuses `retx_time`/`retx_count`, which no other branch touches in
        // these two states, and the same interval and budget as the SYN
        // reaper: the judgement is identical -- "this peer has stopped
        // answering" -- and a second set of constants for one judgement is how
        // they drift apart.
        //
        // On budget exhaustion the slot is freed rather than left. An
        // unreclaimable slot is the failure this exists to prevent, so giving
        // up must not recreate it.
        //
        // Only once no data is in flight. Data sent before `close()` must be
        // acknowledged before the FIN behind it can be, so until then these
        // states fall through to the retransmission timer below, which
        // resends the data — retrying the FIN alone would retry the one
        // segment the peer cannot yet accept.
        if (state == TcpState::FinWait1 || state == TcpState::LastAck) && !outstanding {
            let interval = SYN_RETRY_INTERVAL_MS * TICKS_PER_MS;
            if now.saturating_sub(retx_time) >= interval {
                if retx_count >= SYN_MAX_RETRIES {
                    let mut t = TCP.lock();
                    let c = &mut t.conns[idx];
                    c.state      = TcpState::Closed;
                    c.clear_send_queue();
                    c.retx_count = 0;
                    continue;
                }
                // `fin_seq` is the semantically right field -- the sequence
                // `close()` recorded the FIN at -- but it is worth saying that
                // NO reachable input distinguishes it from `conn_seq` today:
                // `close()` sets `fin_seq = seq` and nothing advances `seq`
                // over the FIN afterwards, so the two are equal in both
                // teardown states. Substituting `conn_seq` fails no test, and
                // that is recorded here rather than papered over with a test
                // that would pass against either.
                //
                // They diverge the moment `snd.nxt` is advanced over the FIN,
                // which RFC 793 wants and this stack does not yet do. Using
                // `fin_seq` is what makes that change safe to land later.
                let fin_seq = { TCP.lock().conns[idx].fin_seq };
                send_segment(&mac, &ip, &rip, lp, rp, TCP_FIN | TCP_ACK,
                             fin_seq, ack_val, &[], our_win);
                let mut t = TCP.lock();
                t.conns[idx].retx_time  = now;
                t.conns[idx].retx_count = t.conns[idx].retx_count.saturating_add(1);
            }
            continue;
        }

        // --- Persist timer (RFC 1122 §4.2.2.17) ---
        //
        // Before keepalive, because the two would otherwise fight: a closed
        // window is not an idle connection, and letting keepalive handle it
        // would tear down a peer that is merely busy.
        //
        // The probe is the same shape as the keepalive one — an ACK carrying
        // `snd.nxt - 1`, which is a sequence number the peer has already
        // acknowledged. It forces the peer to answer with a bare ACK, and that
        // ACK carries its CURRENT window. That is all we need: we are not
        // asking it to accept data, we are asking it to restate the window,
        // because the last time it did the segment was lost.
        //
        // Deliberately unbounded in count. Backing off to a minute and staying
        // there is right; giving up is not, because giving up leaves exactly
        // the deadlock this timer exists to break.
        // Extended to `CloseWait`: half-close lets `send_data` run there too
        // (RFC 1122 §4.2.2.13), so a peer that closes its window while we are
        // draining the last of our own send direction must get the same
        // "probe, do not retransmit" treatment Established gets — otherwise
        // the generic retransmission timer below would treat a full window as
        // loss and tear the connection down while it is legitimately still
        // finishing.
        if (state == TcpState::Established || state == TcpState::CloseWait)
            && remote_win == 0
        {
            let interval = if persist_ticks == 0 {
                PERSIST_INITIAL_MS * TICKS_PER_MS
            } else {
                persist_ticks
            };
            let started = if persist_time == 0 { now } else { persist_time };

            if persist_time == 0 {
                let mut t = TCP.lock();
                t.conns[idx].persist_time  = now;
                t.conns[idx].persist_ticks = interval;
            } else if now.saturating_sub(started) >= interval {
                // Checked before sending, not after: the peer has already had
                // PERSIST_MAX_UNANSWERED chances to say anything at all, and
                // one more probe into silence buys nothing.
                if persist_probes >= PERSIST_MAX_UNANSWERED {
                    let mut t = TCP.lock();
                    t.conns[idx].state          = TcpState::Closed;
                    t.conns[idx].clear_send_queue();
                    t.conns[idx].persist_time   = 0;
                    t.conns[idx].persist_ticks  = 0;
                    t.conns[idx].persist_probes = 0;
                    continue;
                }
                let seq_val = { TCP.lock().conns[idx].seq.wrapping_sub(1) };
                send_segment_with_window(&mac, &ip, &rip, lp, rp, TCP_ACK,
                                         seq_val, ack_val, &[],
                                         our_win);
                let mut t = TCP.lock();
                t.conns[idx].persist_time  = now;
                t.conns[idx].persist_ticks =
                    (interval * 2).min(PERSIST_MAX_MS * TICKS_PER_MS);
                t.conns[idx].persist_probes =
                    t.conns[idx].persist_probes.saturating_add(1);
            }
            continue;
        }

        // The window reopened: end the persist cycle. Kept beside the persist
        // block and above the retransmission timer, because that branch
        // `continue`s: leaving the reset below it means a connection with an
        // outstanding segment carries its backoff across the reopen until the
        // first tick that does not retransmit.
        // The window reopened: end the persist cycle so the next close starts
        // from the initial interval rather than inheriting a minute of backoff
        // from an unrelated earlier stall.
        if persist_ticks != 0 && remote_win != 0 {
            let mut t = TCP.lock();
            t.conns[idx].persist_time   = 0;
            t.conns[idx].persist_ticks  = 0;
            t.conns[idx].persist_probes = 0;
        }

        // --- Retransmission timer (RFC 6298 §5.4-5.6) ---
        //
        // Also reached from FinWait1 and LastAck while data is in flight; see
        // the teardown branch above.
        if outstanding && now.saturating_sub(retx_time) >= rto {
            timer_fired(retx_time + rto, now);
            if retx_count >= RETX_MAX_ATTEMPTS {
                // Connection is dead — close it
                let mut t = TCP.lock();
                t.conns[idx].state = TcpState::Closed;
                t.conns[idx].clear_send_queue();
                continue;
            }

            let mut retx_copy = [0u8; TCP_MSS];
            let (retx_seq, retx_len) = {
                let mut t = TCP.lock();
                let c = &mut t.conns[idx];
                // PMTU black hole: the PMTU_BLACKHOLE_RTOS-th timeout in a row
                // of a resend one full SMSS long halves the path MSS before
                // this resend is cut. Every segment leaves with DF set, so a
                // path that drops the large ones without an ICMP — a filtering
                // firewall, a tunnel — would otherwise time out the same
                // segment until the connection dies.
                if c.retx_count.saturating_add(1) >= PMTU_BLACKHOLE_RTOS
                    && c.flight() >= c.smss()
                    && c.smss() > PMTU_MSS_FLOOR as u32
                {
                    c.pmtu_mss = (c.smss() / 2).max(PMTU_MSS_FLOOR as u32) as u16;
                    PMTU_STATS.blackhole.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                }
                let smss   = c.smss();
                let flight = c.flight();

                // Congestion response (RFC 5681 §3.1): ssthresh from what was
                // in flight (eq. 4), the window down to one segment. ssthresh
                // only on the first timeout of an episode — a second timeout
                // of the same flight is not a second signal, and halving again
                // would compound one loss.
                if c.recovery != Recovery::Loss {
                    c.ssthresh = (flight / 2).max(2 * smss);
                }
                c.cwnd          = smss;
                // RFC 6675 §5.1: a timeout during SACK recovery ends it, with
                // RecoveryPoint = HighData. `Loss` is left only by an ACK at
                // or past `recover`, and a new SACK recovery starts only from
                // `Open`, so none begins before HighACK reaches it.
                c.recovery      = Recovery::Loss;
                c.recover       = c.seq;
                c.dup_ack_count = 0;
                // RFC 2018 §8: a timeout forgets what the peer reported
                // holding — it may have reneged — and resending starts from
                // SND.UNA regardless.
                c.sacked_n = 0;
                // Karn: nothing acknowledged from here on times this flight.
                c.rtt_on = false;

                // The earliest unacknowledged bytes, one segment's worth, cut
                // from the ring. ACKs that follow resend the rest as the
                // window reopens (`Resend::Window`).
                let len = flight.min(smss) as usize;
                c.tx_read(0, &mut retx_copy[..len]);
                c.rtx_next = c.snd_una.wrapping_add(len as u32);

                // Exponential backoff (RFC 6298 §5.5)
                c.retx_count = c.retx_count.saturating_add(1);
                c.retx_time  = now;
                c.rto_ticks  = c.rto_ticks.saturating_mul(2).min(RTO_MAX_MS * TICKS_PER_MS);
                (c.snd_una, len)
            };

            // Live window, as in `send_data` and the ACK-driven retransmissions.
            send_segment_with_window(&mac, &ip, &rip, lp, rp,
                         TCP_ACK, retx_seq, ack_val, &retx_copy[..retx_len],
                         our_win);
            continue;
        }

        // --- TIME-WAIT timer (F01) ---
        if state == TcpState::TimeWait {
            let tw_start = { TCP.lock().conns[idx].time_wait_start };
            let tw_duration = TIME_WAIT_MS * TICKS_PER_MS;
            if now.saturating_sub(tw_start) >= tw_duration {
                let mut t = TCP.lock();
                t.conns[idx].state = TcpState::Closed;
                t.conns[idx].clear_send_queue();
            }
            continue;
        }

        // --- Keep-alive (Established and CloseWait) ---
        //
        // `CloseWait` previously had no bound at all: the peer has already
        // sent its FIN, so `FinWait2`'s "peer owes us a FIN" reaper does not
        // apply, and before half-close nothing else in this state was ever
        // exercised (no data flowed, so `unacked` and the retransmission
        // timer never applied either). If our own application never calls
        // `close`/`shutdown_write` and the peer has vanished — crashed,
        // rebooted, cable pulled — the slot is idle and would sit forever,
        // the exact failure `FIN_WAIT2_TIMEOUT_MS` exists to prevent on the
        // other side of a close. `CloseWait` is otherwise ordinary
        // Established-shaped traffic now (see the merged match arm in
        // `handle`), so it gets the same protection: this same probe timer
        // that already resets `keepalive_probes` on ANY inbound segment
        // (bare ACK included, per the `ACK processing` block shared with
        // Established).
        if (state == TcpState::Established || state == TcpState::CloseWait) && !outstanding {
            if now.saturating_sub(last_act) >= KEEPALIVE_INTERVAL_TICKS {
                timer_fired(last_act + KEEPALIVE_INTERVAL_TICKS, now);
                if ka_probes >= KEEPALIVE_MAX_PROBES {
                    // No response — close connection
                    let mut t = TCP.lock();
                    t.conns[idx].state = TcpState::Closed;
                    t.conns[idx].clear_send_queue();
                    continue;
                }

                // Send keep-alive probe: ACK with seq = snd.nxt - 1
                let seq_val = {
                    let t = TCP.lock();
                    t.conns[idx].seq.wrapping_sub(1)
                };
                send_segment(&mac, &ip, &rip, lp, rp, TCP_ACK, seq_val, ack_val, &[], our_win);

                let mut t = TCP.lock();
                t.conns[idx].keepalive_probes = t.conns[idx].keepalive_probes.saturating_add(1);
                t.conns[idx].last_activity    = now;
            }
        }
    }
}

/// Return connection state for a given index.
pub(crate) fn conn_state(r: impl Into<Ref>) -> TcpState {
    let r = r.into();
    let t = TCP.lock();
    if !t.live(r) { return TcpState::Closed; }
    t.conns[r.idx].state
}

/// The MSS this connection negotiated with its peer.
///
/// Exposed so the boot-time conformance checks can assert RFC 793 §3.1 option
/// parsing against a hand-built SYN, rather than testing `parse_syn_options`
/// directly: the option walk is only correct if it is reached with the right
/// `data_off`, so going through `handle_checked` is what actually proves it.
pub(crate) fn conn_remote_mss(r: impl Into<Ref>) -> u16 {
    let r = r.into();
    let t = TCP.lock();
    if !t.live(r) { return 0; }
    t.conns[r.idx].remote_mss
}

/// What this connection's handshake negotiated: the Window Scale shifts
/// `(send, receive)` when both SYNs carried the option, and whether both
/// carried SACK-Permitted.
///
/// Exposed for the two-node boot smoke, which is the only QEMU path where both
/// ends are this stack. User-mode networking (slirp) parses nothing but the
/// MSS, so every other boot runs the unscaled, SACK-less path and would pass
/// the same way if the options were never offered.
pub(crate) fn conn_negotiated(r: impl Into<Ref>) -> (Option<(u8, u8)>, bool) {
    let r = r.into();
    let t = TCP.lock();
    if !t.live(r) { return (None, false); }
    let c = &t.conns[r.idx];
    (if c.wscale_ok { Some((c.snd_wscale, c.rcv_wscale)) } else { None }, c.sack_ok)
}

/// A connection's retransmission-timer estimate, as `update_rtt` left it.
#[derive(Clone, Copy, PartialEq)]
pub struct RttEstimate {
    /// Whether a sample has been taken. Before one, `srtt` and `rttvar` are 0.
    pub measured:  bool,
    /// SRTT, in ticks × `RTT_SCALE` (1000).
    pub srtt:      u64,
    /// RTTVAR, in ticks × `RTT_SCALE`.
    pub rttvar:    u64,
    /// The current RTO in ticks, exponential backoff included.
    pub rto_ticks: u64,
    /// The sequence number whose acknowledgement will give the next RTT
    /// sample (RFC 6298 §3, one segment timed at a time), or `None` when no
    /// segment is being timed.
    pub timed_seq: Option<u32>,
    /// When the retransmission timer was last (re)started (`retx_time`).
    pub timer_start: u64,
}

/// Read a connection's RTT estimate. For measurement: nothing in the stack
/// reads it.
pub(crate) fn conn_rtt(r: impl Into<Ref>) -> Option<RttEstimate> {
    let r = r.into();
    let t = TCP.lock();
    if !t.live(r) { return None; }
    let c = &t.conns[r.idx];
    Some(RttEstimate {
        measured:  c.rtt_measured,
        srtt:      c.srtt,
        rttvar:    c.rttvar,
        rto_ticks: c.rto_ticks,
        timed_seq: if c.rtt_on { Some(c.rtt_seq) } else { None },
        timer_start: c.retx_time,
    })
}

// ---------------------------------------------------------------------------
// TcpHandle: the connection API outside this crate
// ---------------------------------------------------------------------------

impl TcpHandle {
    /// Open a connection to `dst_ip:dst_port` from `src_port` (0: a free
    /// port from the ephemeral range). Sends the SYN and returns at once;
    /// the connection is usable once [`TcpHandle::state`] is `Established`.
    /// `None`: no free slot, no free ephemeral port, or the 4-tuple is held
    /// by a live connection (see `connect`).
    pub fn connect(dst_ip: [u8; 4], dst_port: u16, src_port: u16) -> Option<TcpHandle> {
        connect_h(dst_ip, dst_port, src_port)
    }

    /// [`TcpHandle::connect`] after resolving the peer's MAC, calling
    /// `yield_fn` between looks (see `connect_with_yield`).
    pub fn connect_with_yield<F: FnMut()>(
        dst_ip: [u8; 4], dst_port: u16, src_port: u16, yield_fn: F,
    ) -> Option<TcpHandle> {
        connect_with_yield_h(dst_ip, dst_port, src_port, yield_fn)
    }

    /// Listen on `port`. `None` when no slot is free.
    pub fn listen(port: u16) -> Option<TcpHandle> {
        listen_h(port)
    }

    /// An established (or half-closed by the peer) connection on
    /// `local_port` nobody has accepted yet.
    pub fn accept(local_port: u16) -> Option<TcpHandle> {
        accept_h(local_port)
    }

    /// The first connection on `local_port` in `state`, for checks that
    /// look at a connection the stack opened itself (a listener's
    /// `SynRcvd` child) rather than one they were handed.
    pub fn find(local_port: u16, state: TcpState) -> Option<TcpHandle> {
        let t = TCP.lock();
        (0..TCP_MAX_CONNS)
            .find(|&i| t.conns[i].state == state && t.conns[i].local_port == local_port)
            .map(|i| t.handle(i))
    }

    /// The slot index, for log lines. Not a way back to the connection.
    pub fn slot(self) -> usize { self.slot as usize }

    /// Local port of the connection; 0 when the handle is stale.
    pub fn local_port(self) -> u16 {
        let t = TCP.lock();
        if t.live(self.into()) { t.conns[self.slot as usize].local_port } else { 0 }
    }

    /// Connection state; `Closed` when the handle is stale.
    pub fn state(self) -> TcpState { conn_state(self) }
    /// See `recv`; -1 when the handle is stale.
    pub fn recv(self, buf: &mut [u8]) -> i32 { recv(self, buf) }
    /// See `send_data`; -1 when the handle is stale.
    pub fn send_data(self, data: &[u8]) -> i32 { send_data(self, data) }
    /// See `send_data_with_yield`; -1 when the handle is stale.
    pub fn send_data_with_yield<F: FnMut()>(self, data: &[u8], yield_fn: F) -> i32 {
        send_data_with_yield(self, data, yield_fn)
    }
    /// See `send_all_with_yield`; 0 when the handle is stale.
    pub fn send_all_with_yield<F: FnMut()>(self, data: &[u8], yield_fn: F) -> usize {
        send_all_with_yield(self, data, yield_fn)
    }
    /// See `send_all_until`; 0 when the handle is stale.
    pub fn send_all_until<F: FnMut()>(self, data: &[u8], budget_us: u64, wait_fn: F) -> usize {
        send_all_until(self, data, budget_us, wait_fn)
    }
    /// See `is_unacked`; false when the handle is stale.
    pub fn is_unacked(self) -> bool { is_unacked(self) }
    /// See `close`; a no-op when the handle is stale.
    pub fn close(self) { close(self) }
    /// See `abort`; a no-op when the handle is stale.
    pub fn abort(self) { abort(self) }
    /// See `shutdown_write`; a no-op when the handle is stale.
    pub fn shutdown_write(self) { shutdown_write(self) }
    /// See `conn_remote_mss`; 0 when the handle is stale.
    pub fn remote_mss(self) -> u16 { conn_remote_mss(self) }
    /// See `conn_negotiated`; `(None, false)` when the handle is stale.
    pub fn negotiated(self) -> (Option<(u8, u8)>, bool) { conn_negotiated(self) }
    /// See `conn_rtt`; `None` when the handle is stale.
    pub fn rtt(self) -> Option<RttEstimate> { conn_rtt(self) }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build and send a SYN or SYN-ACK: MSS always, plus the options in `offer`.
///
/// Layout is Linux's without timestamps — MSS, then NOP + Window Scale, then
/// NOP NOP + SACK-Permitted — each padded to a word so `data_off` is exact.
fn send_syn_segment(
    our_mac:  &[u8; 6],
    our_ip:   &[u8; 4],
    dst_ip:   &[u8; 4],
    src_port: u16,
    dst_port: u16,
    flags:    u8,
    seq:      u32,
    ack:      u32,
    offer:    SynOffer,
) -> i32 {
    let mut opts = [0u8; 12];
    let mss = (TCP_MSS as u16).to_be_bytes();
    opts[..4].copy_from_slice(&[TCP_OPT_MSS, TCP_OPT_MSS_LEN, mss[0], mss[1]]);
    let mut n = 4;
    if offer.wscale {
        opts[n..n + 4].copy_from_slice(
            &[TCP_OPT_NOP, TCP_OPT_WSCALE, TCP_OPT_WSCALE_LEN, RCV_WSCALE]);
        n += 4;
    }
    if offer.sack {
        opts[n..n + 4].copy_from_slice(
            &[TCP_OPT_NOP, TCP_OPT_NOP, TCP_OPT_SACK_PERM, TCP_OPT_SACK_PERM_LEN]);
        n += 4;
    }
    // RFC 7323 §2.2: the window of a segment carrying SYN is never scaled,
    // whatever shift this same segment offers.
    send_segment_opts(our_mac, our_ip, dst_ip, src_port, dst_port,
                      flags, seq, ack, TCP_WINDOW_SIZE, &opts[..n], &[])
}
/// Answer a segment that belongs to no connection, per RFC 793 §3.4.
///
/// **Why silence is the wrong answer here.** Three concrete failures on this
/// machine, all of them recovery problems rather than protocol pedantry:
///
/// * **After the robot reboots**, the brain's socket survives. We come up with
///   an empty connection table, its segments match no slot, and we say nothing.
///   The brain sees a black hole until its own retransmission budget runs out
///   — on Linux defaults that is `tcp_retries2` = 15, minutes — and for that
///   whole window the operator believes they are commanding a robot that is
///   not listening. An RST ends it in microseconds on a one-hop link.
/// * **A SYN to a port with no listener** makes a client wait out its entire
///   SYN budget instead of failing immediately.
/// * **A half-open peer** left by our own teardown has nothing to tell it.
///
/// The sequence rules are the fiddly part and are not negotiable, because a
/// reset carrying the wrong sequence is discarded by the peer's own
/// acceptability check and is therefore the same as sending nothing:
///
/// * If the offending segment carried ACK: `SEQ = SEG.ACK`, no ACK bit.
/// * Otherwise: `SEQ = 0`, `ACK = SEG.SEQ + SEG.LEN`, ACK bit set.
///
/// `seg_len` counts SYN and FIN as one byte each, which is why it is passed in
/// rather than derived from the payload length.
///
/// **Never in response to a RST.** Two stacks that both answered resets with
/// resets would trade them forever.
fn send_rst(
    our_mac:  &[u8; 6],
    our_ip:   &[u8; 4],
    dst_ip:   &[u8; 4],
    src_port: u16,
    dst_port: u16,
    in_flags: u8,
    in_seq:   u32,
    in_ack:   u32,
    seg_len:  u32,
) {
    if in_flags & TCP_RST != 0 { return; }
    if !rst_budget_allows(azos_drv_sys::timebase::now()) { return; }

    let (flags, seq, ack) = if in_flags & TCP_ACK != 0 {
        (TCP_RST, in_ack, 0)
    } else {
        (TCP_RST | TCP_ACK, 0, in_seq.wrapping_add(seg_len))
    };
    let _ = send_segment(our_mac, our_ip, dst_ip, src_port, dst_port, flags, seq, ack, &[],
                         TCP_WINDOW_SIZE);
}


/// Resets we will send per [`RST_WINDOW_TICKS`], at most.
const RST_BUDGET_PER_WINDOW: u32 = 10;
/// 100 ms: the budget is 100 resets a second, far above anything a working
/// peer provokes and far below what a flood of spoofed segments asks for.
const RST_WINDOW_TICKS: u64 = azos_drv_sys::timebase::TIMER_FREQ / 10;

static RST_WINDOW_START: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static RST_SENT_IN_WINDOW: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// May `send_rst` answer one more segment now?
///
/// **Every segment for no connection drew a reset, unmetered.** Correct per
/// RFC 793 and a 1:1 reflector: spoof a victim as source, aim a flood at any
/// closed port, and the robot spends its transmit path and its link — a
/// safety resource here — resetting someone else's connection attempts. A
/// fixed budget per window keeps the useful behaviour (a peer that dials a
/// dead port is told at once) and caps the rest. Races between harts can let
/// a window run a few over; the bound only has to hold in order of magnitude.
fn rst_budget_allows(now: u64) -> bool {
    use core::sync::atomic::Ordering;
    let start = RST_WINDOW_START.load(Ordering::Relaxed);
    if now.wrapping_sub(start) >= RST_WINDOW_TICKS {
        RST_WINDOW_START.store(now, Ordering::Relaxed);
        RST_SENT_IN_WINDOW.store(1, Ordering::Relaxed);
        return true;
    }
    RST_SENT_IN_WINDOW.fetch_add(1, Ordering::Relaxed) < RST_BUDGET_PER_WINDOW
}

// ---------------------------------------------------------------------------
// ICMP Fragmentation Needed (RFC 1191 §4, validated per RFC 5927)
// ---------------------------------------------------------------------------

/// What became of the Fragmentation Needed messages `icmp_frag_needed` saw,
/// and of black-hole fallbacks, since boot.
#[derive(Clone, Copy)]
pub struct PmtuStats {
    /// Lowered a connection's MSS.
    pub accepted:      u32,
    /// Dropped unexamined, past `PMTU_ICMP_BUDGET_PER_WINDOW`.
    pub over_budget:   u32,
    /// Bad ICMP checksum, or a quote too short or not IPv4 carrying TCP.
    pub malformed:     u32,
    /// The quoted segment is not ours: its source is not our address, or no
    /// connection that can have data in flight has its 4-tuple.
    pub foreign:       u32,
    /// The quoted sequence number is outside [SND.UNA, SND.NXT).
    pub out_of_window: u32,
    /// The MTU lowers nothing: not below the quoted datagram's length, or an
    /// MSS not below the connection's current one.
    pub not_lower:     u32,
    /// The MTU is below `PMTU_FLOOR`.
    pub below_floor:   u32,
    /// Black-hole fallbacks taken by the retransmission timer.
    pub blackhole:     u32,
}

struct PmtuCounters {
    accepted:      core::sync::atomic::AtomicU32,
    over_budget:   core::sync::atomic::AtomicU32,
    malformed:     core::sync::atomic::AtomicU32,
    foreign:       core::sync::atomic::AtomicU32,
    out_of_window: core::sync::atomic::AtomicU32,
    not_lower:     core::sync::atomic::AtomicU32,
    below_floor:   core::sync::atomic::AtomicU32,
    blackhole:     core::sync::atomic::AtomicU32,
}

static PMTU_STATS: PmtuCounters = {
    use core::sync::atomic::AtomicU32;
    PmtuCounters {
        accepted:      AtomicU32::new(0),
        over_budget:   AtomicU32::new(0),
        malformed:     AtomicU32::new(0),
        foreign:       AtomicU32::new(0),
        out_of_window: AtomicU32::new(0),
        not_lower:     AtomicU32::new(0),
        below_floor:   AtomicU32::new(0),
        blackhole:     AtomicU32::new(0),
    }
};

/// The PMTU counters, read now.
pub fn pmtu_stats() -> PmtuStats {
    use core::sync::atomic::Ordering::Relaxed;
    let s = &PMTU_STATS;
    PmtuStats {
        accepted:      s.accepted.load(Relaxed),
        over_budget:   s.over_budget.load(Relaxed),
        malformed:     s.malformed.load(Relaxed),
        foreign:       s.foreign.load(Relaxed),
        out_of_window: s.out_of_window.load(Relaxed),
        not_lower:     s.not_lower.load(Relaxed),
        below_floor:   s.below_floor.load(Relaxed),
        blackhole:     s.blackhole.load(Relaxed),
    }
}

static PMTU_WINDOW_START: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static PMTU_IN_WINDOW: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// May one more Fragmentation Needed message be examined now? The same shape
/// as `rst_budget_allows`, and the same tolerance for a few over under races.
fn pmtu_budget_allows(now: u64) -> bool {
    use core::sync::atomic::Ordering;
    let start = PMTU_WINDOW_START.load(Ordering::Relaxed);
    if now.wrapping_sub(start) >= PMTU_ICMP_WINDOW_TICKS {
        PMTU_WINDOW_START.store(now, Ordering::Relaxed);
        PMTU_IN_WINDOW.store(1, Ordering::Relaxed);
        return true;
    }
    PMTU_IN_WINDOW.fetch_add(1, Ordering::Relaxed) < PMTU_ICMP_BUDGET_PER_WINDOW
}

/// ICMP Destination Unreachable, Fragmentation Needed and DF Set, from
/// `ip::handle_icmp` (which has checked only that it is addressed to our
/// unicast address): lower the MSS of the connection whose segment it quotes,
/// and resend that connection's flight at the new size.
///
/// An ICMP message costs an attacker one packet and needs no connection
/// state, so it is believed only as far as it proves itself (RFC 5927 §4):
/// within the global budget; a valid checksum; a quote of an IPv4 datagram
/// from our address carrying TCP; a live connection with that 4-tuple and
/// data in flight; a quoted sequence number in [SND.UNA, SND.NXT), which an
/// off-path sender has to guess among 2^32 like any blind injection; an MTU
/// at or above `PMTU_FLOOR` and below the length of the datagram quoted; and
/// an MSS below the connection's current one. The worst a message that
/// passes can do is lower one connection's MSS to 536 — never raise it, never
/// touch the congestion window, never close anything.
pub fn icmp_frag_needed(msg: &[u8], our_ip: &[u8; 4]) {
    use core::sync::atomic::Ordering::Relaxed;
    let s = &PMTU_STATS;
    let now = azos_drv_sys::timebase::now();
    if !pmtu_budget_allows(now) {
        s.over_budget.fetch_add(1, Relaxed);
        return;
    }
    // Type, code, checksum, 2 unused octets, next-hop MTU (RFC 1191 §4); then
    // the quoted IPv4 header and at least the 8 octets after it (RFC 792),
    // which for TCP are the ports and the sequence number.
    if msg.len() < 8 + ip::IP_HDR_MIN + 8 || ip::checksum(msg) != 0 {
        s.malformed.fetch_add(1, Relaxed);
        return;
    }
    let quote = &msg[8..];
    let ihl = ((quote[0] & 0x0F) as usize) * 4;
    if quote[0] >> 4 != 4 || ihl < ip::IP_HDR_MIN || quote.len() < ihl + 8
        || quote[9] != ip::IP_PROTO_TCP
    {
        s.malformed.fetch_add(1, Relaxed);
        return;
    }
    if &quote[12..16] != our_ip {
        s.foreign.fetch_add(1, Relaxed);
        return;
    }
    let quoted_len  = u16::from_be_bytes([quote[2], quote[3]]);
    let remote_ip   = [quote[16], quote[17], quote[18], quote[19]];
    let local_port  = u16::from_be_bytes([quote[ihl], quote[ihl + 1]]);
    let remote_port = u16::from_be_bytes([quote[ihl + 2], quote[ihl + 3]]);
    let seq = u32::from_be_bytes([quote[ihl + 4], quote[ihl + 5], quote[ihl + 6], quote[ihl + 7]]);

    let mut mtu = u16::from_be_bytes([msg[6], msg[7]]);
    if mtu == 0 {
        mtu = PMTU_PLATEAUS.iter().copied().find(|&p| p < quoted_len).unwrap_or(0);
    }
    if mtu < PMTU_FLOOR {
        s.below_floor.fetch_add(1, Relaxed);
        return;
    }
    // A router reports the MTU a datagram did not fit; one that fitted it
    // was not refused.
    if mtu >= quoted_len {
        s.not_lower.fetch_add(1, Relaxed);
        return;
    }
    let mss = mtu - PMTU_HDR_OCTETS;

    let (mac, ip_addr, idx) = {
        let mut t = TCP.lock();
        let (mac, ip_addr) = (t.our_mac, t.our_ip);
        let idx = match t.find_conn(local_port, &remote_ip, remote_port) {
            Some(i) => i,
            None => {
                s.foreign.fetch_add(1, Relaxed);
                return;
            }
        };
        let c = &mut t.conns[idx];
        match c.state {
            TcpState::Established | TcpState::CloseWait
            | TcpState::FinWait1 | TcpState::LastAck => {}
            _ => {
                s.foreign.fetch_add(1, Relaxed);
                return;
            }
        }
        if seq.wrapping_sub(c.snd_una) >= c.flight() {
            s.out_of_window.fetch_add(1, Relaxed);
            return;
        }
        if mss as u32 >= c.smss() {
            s.not_lower.fetch_add(1, Relaxed);
            return;
        }
        c.pmtu_mss = mss;
        s.accepted.fetch_add(1, Relaxed);
        // The flight was cut for the old size and the path drops it: resend
        // it from SND.UNA at the new one (RFC 1191 §6.5), skipping what the
        // peer SACKed, with no congestion response (RFC 5927 §4.1's advice,
        // Linux's `tcp_simple_retransmit`). The scoreboard is byte ranges, so
        // nothing in it depends on the old size. A SACK or NewReno recovery in
        // progress ends here, as at a timeout, but without collapsing `cwnd`;
        // NewReno's inflation is taken back. A timeout's recovery keeps its
        // state and only resends from the start again.
        if c.recovery == Recovery::Fast {
            c.cwnd = c.ssthresh;
        }
        if c.recovery != Recovery::Loss {
            c.recovery = Recovery::PathMtu;
        }
        c.recover       = c.seq;
        c.rtx_next      = c.snd_una;
        c.dup_ack_count = 0;
        (mac, ip_addr, idx)
    };
    retransmit(idx, &mac, &ip_addr, Resend::Window);
}

/// Build and send a TCP segment.  Returns 0 on success.
#[wcet(200_us)]
fn send_segment(
    our_mac:  &[u8; 6],
    our_ip:   &[u8; 4],
    dst_ip:   &[u8; 4],
    src_port: u16,
    dst_port: u16,
    flags:    u8,
    seq:      u32,
    ack:      u32,
    data:     &[u8],
    window:   u16,
) -> i32 {
    let tcp_len = TCP_HDR_MIN + data.len();
    if tcp_len > TCP_SEGMENT_BUF_SIZE { return -1; }

    #[cfg(feature = "qemu")]
    trace_tx(src_port, dst_ip, dst_port, flags, seq, ack, data);

    send_segment_opts(our_mac, our_ip, dst_ip, src_port, dst_port,
                      flags, seq, ack, window, &[], data)
}

/// Sensor-pump (#39) trace probe: log an outbound TCP segment.
/// Pairs with the [TCP-RX] probe in `handle()` so we have full
/// visibility into the wire conversation under `--features qemu`.
/// Also dump the first 16 bytes of payload for non-trivial segments
/// so we can see WHAT got serialised vs what the peer reads.
#[cfg(feature = "qemu")]
fn trace_tx(src_port: u16, dst_ip: &[u8; 4], dst_port: u16,
            flags: u8, seq: u32, ack: u32, data: &[u8]) {
    azos_drv_sys::kprintln!(
        "[TCP-TX] :{} -> {}.{}.{}.{}:{} flags=0x{:02x} seq={} ack={} pl={}B",
        src_port,
        dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], dst_port,
        flags, seq, ack, data.len()
    );
    if !data.is_empty() {
        let n = data.len().min(16);
        // Pre-format 16 bytes (zero-padded if shorter) so kprintln doesn't
        // need a slice-formatting helper.
        let mut hex = [0u8; 32];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for i in 0..n {
            hex[2*i]   = HEX[(data[i] >> 4) as usize];
            hex[2*i+1] = HEX[(data[i] & 0x0f) as usize];
        }
        azos_drv_sys::kprintln!(
            "[TCP-TX]   first {}B: {}",
            n,
            core::str::from_utf8(&hex[..2*n]).unwrap_or("?")
        );
    }
}

/// Internet checksum seeded with a pseudo-header partial sum.
/// Used on the TCP TX path, and on both the TCP and UDP RX paths for
/// verification (a valid segment yields 0).  `udp.rs` reuses this rather than
/// carrying a second copy of the fold loop.
pub(crate) fn tcp_checksum(pseudo_sum: u32, data: &[u8]) -> u16 {
    let mut sum = pseudo_sum;
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
