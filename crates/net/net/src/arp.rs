// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// ARP layer — port of net/arp.c
///
/// ARP request/reply + a 16-entry cache. Eviction is least-recently-INSERTED,
/// not LRU: `ArpEntry::age` is a monotonic insertion counter that `get`
/// (what `lookup` calls) never refreshes, so a busy entry nobody re-inserts
/// ages out exactly as fast as an idle one.

use azos_sync::SpinLock;
use super::ethernet::{self, ETH_TYPE_ARP, MAC_BROADCAST};
use wcet_macro::wcet;

/// Kconfig `ARP_CACHE_SIZE` (default 16).
pub const ARP_CACHE_SIZE: usize = azos_limits::ARP_CACHE_SIZE;

/// Number of outstanding ARP requests we remember (see `ARP_PENDING`).
/// Sized above `ARP_CACHE_SIZE / 2`: the only in-tree requesters are
/// `ip::send` on a cache miss and `tcp::connect_with_yield`, so a handful of
/// concurrent resolutions is the realistic worst case. Kconfig
/// `ARP_PENDING_SIZE` (default 8).
const ARP_PENDING_SIZE: usize = azos_limits::ARP_PENDING_SIZE;

/// How long an outstanding request stays eligible to be answered: 5 seconds,
/// derived from `TIMER_FREQ` so it stays 5 real seconds on every board (the
/// clock is 10 MHz on QEMU, 4 MHz on VF2, 24 MHz on K1, 1 GHz on aarch64 —
/// `platform.rs` — not a fixed 10 MHz).
///
/// Bounded on purpose: without expiry, one request for an address would leave
/// a permanent licence for anyone on the segment to overwrite that entry at a
/// moment of their choosing.  5 s is orders of magnitude above a LAN ARP RTT
/// (tens of µs on hardware, low ms under QEMU TCG) and still short enough that
/// the window is closed long before an attacker can react to seeing the
/// request on the wire.
const ARP_PENDING_TTL_TICKS: u64 = 5 * azos_drv_sys::timebase::TIMER_FREQ;

const ARP_HARDWARE_ETHERNET: u16 = 1;
const ARP_PROTO_IP:          u16 = 0x0800;
const ARP_HLEN_ETH:          u8  = 6;
const ARP_PLEN_IP:           u8  = 4;
const ARP_OP_REQUEST:        u16 = 1;
const ARP_OP_REPLY:          u16 = 2;

#[repr(C, packed)]
struct ArpPkt {
    htype:    [u8; 2],
    ptype:    [u8; 2],
    hlen:     u8,
    plen:     u8,
    oper:     [u8; 2],
    sha:      [u8; 6],  // sender MAC
    spa:      [u8; 4],  // sender IP
    tha:      [u8; 6],  // target MAC
    tpa:      [u8; 4],  // target IP
}

const ARP_PKT_SIZE: usize = core::mem::size_of::<ArpPkt>();

#[derive(Clone, Copy)]
pub struct ArpEntry {
    pub ip:    [u8; 4],
    pub mac:   [u8; 6],
    pub valid: bool,
    pub age:   u32,
    /// Learned from an answer to a question WE asked (or written by the
    /// kernel through [`insert`]), as opposed to picked up from somebody
    /// else's request. Eviction spends unsolicited entries first — see
    /// [`ArpCache::learn_unsolicited`].
    pub solicited: bool,
    /// CLINT ticks when this entry was last CONFIRMED solicited (a real
    /// request/reply round trip, or the kernel's own [`insert`]) — NUD-style
    /// reachable-time aging. `0` for an entry that has never been solicited
    /// (an unsolicited-only entry has no reachable-time claim to make in the
    /// first place; [`get_solicited`](ArpCache::get_solicited) already
    /// refuses those regardless of this field).
    pub verified_at: u64,
}

impl ArpEntry {
    pub const fn new() -> Self {
        ArpEntry {
            ip: [0; 4], mac: [0; 6], valid: false, age: 0, solicited: false,
            verified_at: 0,
        }
    }
}

/// How long a solicited entry stays "fresh" before a caller about to reuse
/// it fires a re-verification probe (Linux's NUD `base_reachable_time`,
/// which is 30 s ± randomization; this is the same 30 s, derived from
/// `TIMER_FREQ` like `tcp.rs`'s `KEEPALIVE_INTERVAL_TICKS` so it stays 30
/// real seconds on every board).
///
/// The entry is not thrown away at this age — a NIC does not usually change
/// mid-flow — it is used (Linux's STALE state: still reachable-looking) and
/// re-verified in the background at the same time, on the theory that most
/// robots reuse the same brain/gateway for a session far longer than this.
const ARP_REACHABLE_TICKS: u64 = 30 * azos_drv_sys::timebase::TIMER_FREQ;

/// The ARP cache as a data structure, independent of the machine's live one.
///
/// **Public so it can be measured and exercised without touching
/// [`ARP_TABLE`].** Until 2026-09-08 `domains/robot/bench/src/net.rs` benchmarked
/// `arp::insert` — the global — on every boot: 100 iterations x 5 repeats of
/// `insert([10, 0, 2, i], TEST_MAC)` into a 16-entry LRU table, which wiped
/// every real entry several times over and, at `i == 2`, replaced the SLIRP
/// gateway's MAC (`10.0.2.2`) with a fabricated one. It did that while
/// `net-poll` was live on another hart.
///
/// The visible consequence was three layers away and looked like a transport
/// bug: ring 3's `brain_client` connected, its first data segment hit
/// `ip::send` -> `arp::lookup` miss -> `-1`, and `tcp::send_data` reports that
/// as a fatal error, so a healthy `Established` connection was torn down.
///
/// A benchmark must not mutate the machine it measures. The bench now builds
/// one of these on its own stack, which is the same code and the same layout.
pub struct ArpCache {
    entries: [ArpEntry; ARP_CACHE_SIZE],
    tick:    u32,
}

impl ArpCache {
    /// An empty cache. `const` so the global can still be a `static`.
    pub const fn new() -> Self {
        ArpCache { entries: [ArpEntry::new(); ARP_CACHE_SIZE], tick: 0 }
    }

    /// MAC for `ip`, or `None`. What [`lookup`] does to the global one.
    pub fn get(&self, ip: &[u8; 4]) -> Option<[u8; 6]> {
        self.find(ip).map(|i| self.entries[i].mac)
    }

    /// Like [`get`], but only a SOLICITED entry counts — one we asked about
    /// and had answered through [`ArpCache::insert`] (or the kernel's own
    /// [`insert`]), never one [`learn_unsolicited`] planted from a request
    /// nobody asked. What [`lookup_solicited`] does to the global one; see
    /// its doc for why a caller would want this instead of [`get`].
    pub fn get_solicited(&self, ip: &[u8; 4]) -> Option<[u8; 6]> {
        self.find(ip).filter(|&i| self.entries[i].solicited).map(|i| self.entries[i].mac)
    }

    /// Like [`get_solicited`], but also reports whether the entry is due
    /// for NUD-style re-verification: `(mac, is_stale)`, `is_stale` true
    /// once `now - verified_at >= ARP_REACHABLE_TICKS`. What
    /// [`lookup_solicited_verified`] uses to decide whether to fire a
    /// probe alongside the (still returned) cached MAC.
    pub fn get_solicited_with_age(&self, ip: &[u8; 4], now: u64) -> Option<([u8; 6], bool)> {
        self.find(ip).filter(|&i| self.entries[i].solicited).map(|i| {
            let stale = now.saturating_sub(self.entries[i].verified_at) >= ARP_REACHABLE_TICKS;
            (self.entries[i].mac, stale)
        })
    }

    fn find(&self, ip: &[u8; 4]) -> Option<usize> {
        for i in 0..ARP_CACHE_SIZE {
            if self.entries[i].valid && &self.entries[i].ip == ip {
                return Some(i);
            }
        }
        None
    }

    /// Insert or update a TRUSTED binding — an answer to our own question, or
    /// the kernel itself — evicting when full.
    ///
    /// Eviction spends an unsolicited entry before a solicited one, oldest
    /// first within each class. Without that preference a peer that filled
    /// the free slots with unsolicited junk would make the NEXT legitimate
    /// resolution evict the gateway, which was inserted at boot and is
    /// therefore always the oldest entry in the table.
    pub fn insert(&mut self, ip: [u8; 4], mac: [u8; 6]) {
        // NUD reachable-time: stamped with the REAL clock, not `self.tick`
        // (an insertion-order counter with no relationship to wall time —
        // see `age`'s own doc). A test-only cache reset starts this at 0,
        // which reads as "ancient" against any nonzero clock, the safe
        // direction: a fresh test cache re-verifies on first use rather
        // than skipping verification because 0 looked recent.
        let now = azos_drv_sys::timebase::now();
        if let Some(i) = self.find(&ip) {
            self.entries[i].mac = mac;
            self.entries[i].age = self.tick;
            self.entries[i].solicited = true;
            self.entries[i].verified_at = now;
            self.tick = self.tick.wrapping_add(1);
            return;
        }
        let idx = self.free_slot().unwrap_or_else(|| {
            (0..ARP_CACHE_SIZE)
                .filter(|&i| !self.entries[i].solicited)
                .min_by_key(|&i| self.entries[i].age)
                .or_else(|| (0..ARP_CACHE_SIZE).min_by_key(|&i| self.entries[i].age))
                .unwrap_or(0)
        });
        self.entries[idx] = ArpEntry {
            ip, mac, valid: true, age: self.tick, solicited: true, verified_at: now,
        };
        self.tick = self.tick.wrapping_add(1);
    }

    fn free_slot(&self) -> Option<usize> {
        (0..ARP_CACHE_SIZE).find(|&i| !self.entries[i].valid)
    }

    /// Learn a binding NOBODY ASKED FOR — the sender of a request for our
    /// address. Never overwrites, never evicts.
    ///
    /// **Why both.** This used to be a plain [`insert`], and a request is
    /// something anyone on the segment can send, with any `spa`:
    ///
    /// * **Overwrite** — one 42-byte request with `spa = <gateway>` and
    ///   `sha = <attacker>` rewrote the gateway's MAC, and `arp_resolved` then
    ///   flushed every frame queued for that address to the attacker. The whole
    ///   `ARP_PENDING` defence guarded only the reply arm; this arm walked
    ///   around it.
    /// * **Evict** — fifteen requests with distinct `spa`s filled the table and
    ///   the LRU dropped the entries in constant use, because `get` never
    ///   refreshes `age` and the gateway is the oldest insert there is.
    ///
    /// A learn nobody asked for must not displace one we did. A MAC that
    /// DIFFERS from the cached one is not simply refused, though: the caller
    /// asks the question itself (see `handle`), so a peer whose NIC really did
    /// change proves it through the pending path — and an attacker has to win
    /// a race against the genuine answer instead of sending one frame.
    pub fn learn_unsolicited(&mut self, ip: [u8; 4], mac: [u8; 6]) -> UnsolicitedLearn {
        if let Some(i) = self.find(&ip) {
            if self.entries[i].mac != mac {
                return UnsolicitedLearn::Conflict;
            }
            self.entries[i].age = self.tick;
            self.tick = self.tick.wrapping_add(1);
            return UnsolicitedLearn::Confirmed;
        }
        match self.free_slot() {
            Some(idx) => {
                self.entries[idx] = ArpEntry {
                    ip, mac, valid: true, age: self.tick, solicited: false, verified_at: 0,
                };
                self.tick = self.tick.wrapping_add(1);
                UnsolicitedLearn::Learned
            }
            None => UnsolicitedLearn::NoRoom,
        }
    }
}

/// What [`ArpCache::learn_unsolicited`] did with a binding nobody asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnsolicitedLearn {
    /// New address, free slot: cached.
    Learned,
    /// Already cached with this very MAC: nothing to change.
    Confirmed,
    /// Already cached with a DIFFERENT MAC: refused, and worth verifying.
    Conflict,
    /// New address, no free slot: refused. Nothing we asked about is evicted.
    NoRoom,
}

static ARP_TABLE: SpinLock<ArpCache> = SpinLock::new(ArpCache::new());

// ── Outstanding-request table (anti-poisoning) ───────────────────────────────

/// One address we have asked about and not yet had answered.
#[derive(Clone, Copy)]
struct PendingArp {
    ip:    [u8; 4],
    sent:  u64,   // CLINT tick when the request went out
    valid: bool,
}

impl PendingArp {
    const fn new() -> Self {
        PendingArp { ip: [0; 4], sent: 0, valid: false }
    }
}

/// Addresses we have an ARP request outstanding for.
///
/// This is the state the old "replies for IPs we never queried are ignored"
/// comment described but that no code kept: without it, `tpa == our_ip` is
/// true of ANY unsolicited reply sent to us, so a single crafted reply with
/// `spa = <gateway>` rewrote the gateway entry and redirected every packet we
/// route off-link.  A reply is now only learned if it answers a question we
/// actually asked, recently.
static ARP_PENDING: SpinLock<[PendingArp; ARP_PENDING_SIZE]> =
    SpinLock::new([PendingArp::new(); ARP_PENDING_SIZE]);

/// Record that we have just asked for `ip`.
///
/// Re-asking for the same address refreshes its timestamp rather than
/// consuming a second slot (`ip::send` fires a request on every cache miss,
/// so a stalled resolution would otherwise evict every other pending entry).
fn record_pending(ip: &[u8; 4], now: u64) {
    let mut p = ARP_PENDING.lock();
    for i in 0..ARP_PENDING_SIZE {
        if p[i].valid && &p[i].ip == ip {
            p[i].sent = now;
            return;
        }
    }
    // Free slot, else the oldest — an expired or stale question is the one we
    // care least about keeping.
    let mut free = None;
    for i in 0..ARP_PENDING_SIZE {
        if !p[i].valid { free = Some(i); break; }
    }
    let idx = match free {
        Some(i) => i,
        None => {
            let mut best = 0usize;
            for i in 1..ARP_PENDING_SIZE {
                if p[i].sent < p[best].sent { best = i; }
            }
            best
        }
    };
    p[idx] = PendingArp { ip: *ip, sent: now, valid: true };
}

/// Consume an outstanding request for `ip`.
///
/// Returns true only if we asked about `ip` within `ARP_PENDING_TTL_TICKS`.
/// The entry is retired on a match so that the answer cannot be replayed
/// later by a third party — a second, genuine reply for an address already in
/// the cache is simply redundant.
///
/// Re-verified 2026-09-06 (claims_check audit): the find-and-invalidate
/// above runs entirely under `ARP_PENDING.lock()`, so a second hart racing
/// a duplicate reply for the same `ip` cannot observe `valid == true` twice
/// — there is no window between the freshness check and `p[i].valid =
/// false` for a second caller to land in. `valid` is cleared unconditionally
/// (even when `fresh` is false), so a late, non-fresh reply also consumes
/// the slot rather than leaving it available to a later replay. This does
/// NOT cover `handle`'s other admission path: an inbound ARP *request*
/// (`is_request_for_us`) is learned unconditionally without touching
/// `ARP_PENDING` at all — that path is deliberate (RFC 826 neighbour
/// discovery) and out of `take_pending`'s scope, not a bypass of it.
/// Is a question about `ip` already outstanding and fresh?
///
/// Rate-limits the verification request `handle` sends on a conflicting
/// request: without it a peer repeating the same conflict every frame makes
/// the robot broadcast an ARP request per frame.
fn pending_is_fresh(ip: &[u8; 4], now: u64) -> bool {
    let p = ARP_PENDING.lock();
    (0..ARP_PENDING_SIZE).any(|i| {
        p[i].valid && &p[i].ip == ip && now.saturating_sub(p[i].sent) < ARP_PENDING_TTL_TICKS
    })
}

fn take_pending(ip: &[u8; 4], now: u64) -> bool {
    let mut p = ARP_PENDING.lock();
    for i in 0..ARP_PENDING_SIZE {
        if p[i].valid && &p[i].ip == ip {
            let fresh = now.saturating_sub(p[i].sent) < ARP_PENDING_TTL_TICKS;
            p[i].valid = false;
            return fresh;
        }
    }
    false
}

/// Look up a MAC address for an IP in the ARP cache.
#[wcet(10_us)]
pub fn lookup(ip: &[u8; 4]) -> Option<[u8; 6]> {
    ARP_TABLE.lock().get(ip)
}

/// Like [`lookup`], but a binding [`learn_unsolicited`] planted from an
/// inbound request nobody asked about does not count.
///
/// M21 / U06-5: a dial's first packet used to trust whatever [`lookup`]
/// returned, including an unsolicited entry — so one crafted request,
/// claiming to be the peer we are about to dial, sent before that dial,
/// steered the SYN to the attacker with no race to win at all (the real
/// answer never even got asked for). `resolve_peer_mac` (`tcp.rs`) uses this
/// instead, so an unsolicited entry no longer short-circuits resolution: a
/// fresh, solicited request always goes out, and the attacker now has to
/// win the same race the reply path already makes them win against a
/// CONFLICTING entry (`ARP_PENDING`'s `take_pending`) — a real improvement
/// over "nothing to race against at all", though not a defence against an
/// on-link attacker who answers every single request faster than the real
/// host (RFC 826 has no authentication; neither does Linux's ARP).
#[wcet(10_us)]
pub fn lookup_solicited(ip: &[u8; 4]) -> Option<[u8; 6]> {
    ARP_TABLE.lock().get_solicited(ip)
}

/// Like [`lookup_solicited`], but for a caller about to DIAL — open a
/// fresh connection, or otherwise about to trust this MAC for new traffic
/// — rather than one merely routing an already-open flow.
///
/// NUD reachable-time aging (the coordinator's second ask, alongside M26):
/// a solicited entry past [`ARP_REACHABLE_TICKS`] is still RETURNED — a
/// NIC does not usually change mid-session, and refusing it here would
/// just make every dial after 30 s of idle pay a full round trip again —
/// but a unicast probe (straight to the cached MAC, not broadcast) goes
/// out alongside it, so a MAC that DID change (new hardware, a moved DHCP
/// lease) is caught and corrected by the time the NEXT dial reads this
/// cache, rather than staying trusted forever once solicited once.
/// `pending_is_fresh` rate-limits it: a caller that dials the same address
/// repeatedly while stale does not re-probe on every single call, the same
/// discipline `handle`'s own conflict-verification already uses.
pub fn lookup_solicited_verified(
    our_mac: &[u8; 6], our_ip: &[u8; 4], ip: &[u8; 4],
) -> Option<[u8; 6]> {
    let now = azos_drv_sys::timebase::now();
    let found = ARP_TABLE.lock().get_solicited_with_age(ip, now);
    if let Some((mac, stale)) = found {
        if stale && !pending_is_fresh(ip, now) {
            send_request_unicast(our_mac, our_ip, ip, &mac);
        }
        return Some(mac);
    }
    None
}

/// A unicast ARP request: the same question [`send_request`] asks, sent
/// directly to `dst_mac` at the Ethernet layer instead of to the broadcast
/// address.
///
/// This is the NUD "probe" (Linux's `neigh_probe`, sent for a REACHABLE
/// entry about to age into STALE): a targeted re-check of one already-known
/// host, not a segment-wide broadcast for a re-check that only concerns one
/// of them. `record_pending` is the SAME table `send_request` uses, so the
/// reply — which the peer can now unicast straight back, since this frame
/// carried our own MAC — is learned through the ordinary solicited-reply
/// path in `handle`, refreshing `verified_at` exactly as a fresh resolution
/// would.
fn send_request_unicast(
    our_mac: &[u8; 6], our_ip: &[u8; 4], target_ip: &[u8; 4], dst_mac: &[u8; 6],
) {
    record_pending(target_ip, azos_drv_sys::timebase::now());

    let mut arp_buf = [0u8; ARP_PKT_SIZE];
    let pkt = unsafe { &mut *(arp_buf.as_mut_ptr() as *mut ArpPkt) };
    pkt.htype = ARP_HARDWARE_ETHERNET.to_be_bytes();
    pkt.ptype = ARP_PROTO_IP.to_be_bytes();
    pkt.hlen  = ARP_HLEN_ETH;
    pkt.plen  = ARP_PLEN_IP;
    pkt.oper  = ARP_OP_REQUEST.to_be_bytes();
    pkt.sha   = *our_mac;
    pkt.spa   = *our_ip;
    pkt.tha   = *dst_mac;
    pkt.tpa   = *target_ip;

    let mut frame = [0u8; ethernet::EthHdr::SIZE + ARP_PKT_SIZE];
    ethernet::build(&mut frame, dst_mac, our_mac, ETH_TYPE_ARP, &arp_buf);
    let _ = super::net_raw_send(&frame);
}

/// Insert or update an ARP cache entry.
/// Test-only: forget every learned address and every outstanding question.
///
/// Exists because a host suite that resets only what it thinks it touched is
/// order-dependent: one test that learns `10.0.0.45` makes the next test's
/// `ip::send` to that address RESOLVE instead of queueing, and the failure
/// shows up as a count that is short by one, in whichever test the runner
/// happened to schedule second. Measured — the same suite gave 5/1 and then
/// 6/0. A precondition has to be stated, not inherited.
pub fn cache_reset_for_test() {
    *ARP_TABLE.lock() = ArpCache::new();
    let mut p = ARP_PENDING.lock();
    for i in 0..ARP_PENDING_SIZE { p[i] = PendingArp::new(); }
}

pub fn insert(ip: [u8; 4], mac: [u8; 6]) {
    ARP_TABLE.lock().insert(ip, mac);
}

/// Handle an incoming ARP packet (called after stripping ETH header).
/// `our_mac` and `our_ip` are this host's addresses.
///
/// Cache-poisoning hardening: only learn (spa→sha) if the packet is
/// genuinely related to us — either a request asking about our IP
/// (legitimate neighbour discovery) or a reply to a request WE sent and
/// have not yet had answered (`ARP_PENDING`).
///
/// The `tpa == our_ip` test alone is not that property: every unsolicited
/// reply an attacker addresses to us satisfies it.  That is the hole this
/// function's comment used to claim was closed while the code left it open.
pub fn handle(payload: &[u8], our_mac: &[u8; 6], our_ip: &[u8; 4]) {
    if payload.len() < ARP_PKT_SIZE { return; }
    let pkt = unsafe { &*(payload.as_ptr() as *const ArpPkt) };

    // Fixed-header validation (RFC 826).  These four fields define what the
    // address fields *mean*; parsing `sha`/`spa` as a MAC/IPv4 pair without
    // checking them means trusting the sender's word for the layout.  Anything
    // that is not Ethernet/IPv4 with the canonical lengths is not something
    // this cache can represent, so it is dropped rather than reinterpreted.
    if u16::from_be_bytes(pkt.htype) != ARP_HARDWARE_ETHERNET { return; }
    if u16::from_be_bytes(pkt.ptype) != ARP_PROTO_IP          { return; }
    if pkt.hlen != ARP_HLEN_ETH || pkt.plen != ARP_PLEN_IP    { return; }

    let op   = u16::from_be_bytes(pkt.oper);
    let tpa  = &pkt.tpa;
    let spa  = &pkt.spa;
    let sha  = &pkt.sha;

    // Reject obviously bogus senders: 0.0.0.0 and 255.255.255.255 must
    // never be cached, and the broadcast/multicast MAC bits must be 0
    // (an ARP source-MAC with the multicast bit is RFC-illegal).
    let zero_ip       = [0u8; 4];
    let broadcast_ip  = [0xff; 4];
    let mcast_mac_bit = sha[0] & 0x01;
    if *spa == zero_ip || *spa == broadcast_ip || mcast_mac_bit != 0 {
        return;
    }

    // Only learn the sender if:
    //   - they're requesting OUR IP (legitimate question — we'll reply,
    //     so we want their MAC to send the reply), OR
    //   - they're answering a question we asked: the reply is addressed to us
    //     AND `spa` matches a live entry in `ARP_PENDING`.
    // Gratuitous ARPs, and replies for IPs we never queried, are ignored —
    // and now that is enforced, not merely asserted.
    // An unconfigured host (0.0.0.0) holds no address anyone can ask about or
    // answer to, so neither arm may match on `tpa == 0.0.0.0`.
    let configured        = *our_ip != zero_ip;
    let is_request_for_us = configured && op == ARP_OP_REQUEST && tpa == our_ip;
    let is_reply_to_us    = configured && op == ARP_OP_REPLY   && tpa == our_ip;
    // Set when this frame taught us a MAC, so the transmit queue is drained
    // OUTSIDE the `ARP_TABLE` critical section below. Draining sends frames
    // through `net_raw_send`, which takes the driver's lock; doing that under
    // the ARP table would nest the NIC beneath the cache for the length of a
    // transmit. Same discipline as `channel_destroy` releasing the pool before
    // it orphans.
    let mut learned: Option<([u8; 4], [u8; 6])> = None;
    let mut verify = false;
    if is_request_for_us {
        // Unsolicited: may fill a free slot, may never overwrite or evict —
        // see `ArpCache::learn_unsolicited`.
        let outcome = ARP_TABLE.lock().learn_unsolicited(*spa, *sha);
        match outcome {
            UnsolicitedLearn::Learned  => learned = Some((*spa, *sha)),
            UnsolicitedLearn::Conflict => verify = true,
            UnsolicitedLearn::Confirmed | UnsolicitedLearn::NoRoom => {}
        }
    } else if is_reply_to_us {
        // `take_pending` also retires the request, so the same answer cannot
        // be replayed later to overwrite the entry.
        let now = azos_drv_sys::timebase::now();
        if take_pending(spa, now) {
            ARP_TABLE.lock().insert(*spa, *sha);
            learned = Some((*spa, *sha));
        }
    }
    // A frame held for want of this MAC can now leave. Also on the REQUEST
    // arm, not just the reply: a peer that asks us a question has told us its
    // address just as surely as one that answers ours, and refusing to use it
    // would keep a packet queued behind an ARP round trip we no longer need.
    if let Some((ip, mac)) = learned {
        crate::ip::arp_resolved(&ip, &mac);
        // N7: a task resolving this address (`tcp::resolve_peer_mac`) looks
        // again now. No lock is held here.
        crate::wait::ARP_WAITERS.notify();
    }

    // A request claimed a different MAC for an address we already hold. Ask
    // the question ourselves: the genuine owner answers through `ARP_PENDING`,
    // and only that answer may change the binding. Not re-asked while an
    // earlier question is still fresh, so repeating the conflict costs the
    // sender a frame per frame and the robot one request per TTL.
    if verify && !pending_is_fresh(spa, azos_drv_sys::timebase::now()) {
        send_request(our_mac, our_ip, spa);
    }

    if !is_request_for_us { return; }

    // Answered even when nothing was learned: the reply goes to `sha`
    // straight from the frame and does not need the cache.
    send_reply(our_mac, our_ip, sha, spa);
}

/// Send an ARP request for `target_ip`.
///
/// Also records the question in `ARP_PENDING`: `handle` will only learn a
/// reply for an address that appears there, so every requester must come
/// through this function for resolution to work.
pub fn send_request(our_mac: &[u8; 6], our_ip: &[u8; 4], target_ip: &[u8; 4]) {
    record_pending(target_ip, azos_drv_sys::timebase::now());

    let mut arp_buf = [0u8; ARP_PKT_SIZE];
    let pkt = unsafe { &mut *(arp_buf.as_mut_ptr() as *mut ArpPkt) };
    pkt.htype = ARP_HARDWARE_ETHERNET.to_be_bytes();
    pkt.ptype = ARP_PROTO_IP.to_be_bytes();
    pkt.hlen  = ARP_HLEN_ETH;
    pkt.plen  = ARP_PLEN_IP;
    pkt.oper  = ARP_OP_REQUEST.to_be_bytes();
    pkt.sha   = *our_mac;
    pkt.spa   = *our_ip;
    pkt.tha   = [0u8; 6];
    pkt.tpa   = *target_ip;

    let mut frame = [0u8; ethernet::EthHdr::SIZE + ARP_PKT_SIZE];
    ethernet::build(&mut frame, &MAC_BROADCAST, our_mac, ETH_TYPE_ARP, &arp_buf);
    let _ = super::net_raw_send(&frame);
}

fn send_reply(our_mac: &[u8; 6], our_ip: &[u8; 4], dst_mac: &[u8; 6], dst_ip: &[u8; 4]) {
    let mut arp_buf = [0u8; ARP_PKT_SIZE];
    let pkt = unsafe { &mut *(arp_buf.as_mut_ptr() as *mut ArpPkt) };
    pkt.htype = ARP_HARDWARE_ETHERNET.to_be_bytes();
    pkt.ptype = ARP_PROTO_IP.to_be_bytes();
    pkt.hlen  = ARP_HLEN_ETH;
    pkt.plen  = ARP_PLEN_IP;
    pkt.oper  = ARP_OP_REPLY.to_be_bytes();
    pkt.sha   = *our_mac;
    pkt.spa   = *our_ip;
    pkt.tha   = *dst_mac;
    pkt.tpa   = *dst_ip;

    let mut frame = [0u8; ethernet::EthHdr::SIZE + ARP_PKT_SIZE];
    ethernet::build(&mut frame, dst_mac, our_mac, ETH_TYPE_ARP, &arp_buf);
    let _ = super::net_raw_send(&frame);
}

/// Print ARP cache.
pub fn dump() {
    let t = ARP_TABLE.lock();
    azos_drv_sys::kconsoleln!("[ARP] Cache:");
    for i in 0..ARP_CACHE_SIZE {
        if t.entries[i].valid {
            let ip  = &t.entries[i].ip;
            let mac = &t.entries[i].mac;
            azos_drv_sys::kconsoleln!(
                "[ARP]   {}.{}.{}.{} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                ip[0], ip[1], ip[2], ip[3],
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );
        }
    }
}
