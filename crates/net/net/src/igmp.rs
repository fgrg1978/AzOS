// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! IPv4 multicast group membership and IGMPv2 (RFC 1112 / RFC 2236).
//!
//! **Why this exists.** The IPv4 receive filter in `ip::handle` admits our
//! unicast address and the two broadcast forms, and drops everything else.
//! A datagram to `239.1.2.3` was therefore discarded no matter what userspace
//! wanted, and `ip::send` mapped a multicast destination through `arp::lookup`,
//! where nobody answers — the same shape of bug that made broadcast impossible
//! from ring 3 until RFC 919/922 was implemented.
//!
//! IPv6 already had the equivalent: `ipv6::is_joined` gates reception and
//! `ethernet::send_ipv6` maps `FF02::` to `33:33:`. This is the v4 half.
//!
//! **Deviation from RFC 2236, recorded deliberately.** A full implementation
//! delays a Membership Report by a random interval in `[0, Max Resp Time]` and
//! cancels it if another member reports first, which suppresses duplicate
//! reports on a shared segment. This stack reports immediately. On a segment
//! with one host — which is this robot's link — the suppression never fires,
//! so the observable behaviour is identical; on a busy segment it means one
//! extra report per query. Implementing it needs a timer wheel entry per
//! group, and the trade was not worth it. It is a deviation, not conformance.

use core::sync::atomic::{AtomicU32, Ordering};
use azos_sync::SpinLock;

use super::ip;

/// IGMP is IP protocol 2 (RFC 1112 §7.1, IANA).
pub const IP_PROTO_IGMP: u8 = 2;

/// IGMPv2 message types (RFC 2236 §2.1).
pub const IGMP_MEMBERSHIP_QUERY: u8 = 0x11;
pub const IGMP_V2_REPORT:        u8 = 0x16;
pub const IGMP_V1_REPORT:        u8 = 0x12;
pub const IGMP_LEAVE_GROUP:      u8 = 0x17;

/// `224.0.0.1` — the all-hosts group. Every IPv4 host is a permanent member
/// and **must not** report membership in it (RFC 2236 §6).
pub const ALL_HOSTS:   [u8; 4] = [224, 0, 0, 1];
/// `224.0.0.2` — all-routers, the destination for a Leave Group message.
pub const ALL_ROUTERS: [u8; 4] = [224, 0, 0, 2];

/// Groups joined explicitly. `ALL_HOSTS` is NOT stored here: it is implicit,
/// so a full table can never lock us out of the group the standard says we
/// always belong to.
pub const MAX_GROUPS: usize = 8;

/// The membership table: each joined group and how many joiners hold it.
///
/// **Refcounted, because the host has several subscribers and the wire sees
/// one.** IGMP speaks for the interface, not for a socket: two sockets in the
/// same group are one membership to a router. Without the count, the first of
/// two sockets to leave dropped the group — and the Leave message — from under
/// the other, which was still subscribed and silently stopped receiving.
///
/// `refs` lives under the SAME lock as `addr`. A second static would be a
/// second lock over one state machine: a join could find the address present
/// and a leave clear it before the join's increment landed.
struct Groups {
    /// `[0; 4]` marks a free slot — never a group, since `0.0.0.0` is not
    /// multicast.
    addr: [[u8; 4]; MAX_GROUPS],
    refs: [u32; MAX_GROUPS],
}

static GROUPS: SpinLock<Groups> = SpinLock::new(Groups {
    addr: [[0u8; 4]; MAX_GROUPS],
    refs: [0; MAX_GROUPS],
});
/// Number of live entries; read on the RX fast path without taking the lock.
///
/// **The lockless read races with `join`, benignly and on purpose.** `join`
/// writes the slot and then increments this, so a reader that sees a non-zero
/// count and takes the lock always finds a coherent table. A reader that sees a
/// stale zero skips the lock and drops one datagram inside the join window —
/// self-correcting, and cheaper than taking a lock on every received packet
/// when no group is joined, which is the normal case for this robot.
static GROUP_COUNT: AtomicU32 = AtomicU32::new(0);

/// True for `224.0.0.0/4` (RFC 1112 §4): the top four bits are `1110`.
#[inline]
pub fn is_multicast(addr: &[u8; 4]) -> bool {
    addr[0] & 0xF0 == 0xE0
}

/// Map an IPv4 multicast group to its Ethernet address (RFC 1112 §6.4).
///
/// `01:00:5E` followed by the **low 23 bits** of the group. The 24th bit is
/// dropped, so 32 different groups share one MAC — `224.128.1.1` and
/// `225.0.1.1` both map to `01:00:5e:00:01:01`. That aliasing is in the
/// standard, not a shortcut here: it is why the IP-level group check in
/// `is_joined` cannot be replaced by MAC filtering in the NIC.
#[inline]
pub fn multicast_mac(group: &[u8; 4]) -> [u8; 6] {
    [0x01, 0x00, 0x5E, group[1] & 0x7F, group[2], group[3]]
}

/// True if `addr` is a group we receive traffic for.
///
/// `ALL_HOSTS` is always true (RFC 1112 §6.1: permanent membership).
pub fn is_joined(addr: &[u8; 4]) -> bool {
    if *addr == ALL_HOSTS { return true; }
    if GROUP_COUNT.load(Ordering::Relaxed) == 0 { return false; }
    let g = GROUPS.lock();
    g.addr.iter().any(|e| e == addr)
}

/// Take one reference on `group` in the table, without touching the wire.
///
/// `Ok(true)` when this was the FIRST reference — the caller owes the network
/// a Membership Report, and must send it with [`send_report`] once it holds no
/// lock. `Ok(false)` when the group was already held (or is `ALL_HOSTS`):
/// nothing to say, the interface is already a member. `Err(-1)` for a
/// non-multicast address, `Err(-2)` when the table is full.
///
/// Split from [`join`] so the socket layer can record a membership and take
/// its reference under its own lock, atomically with respect to a close of
/// the same socket, and still emit the report with every lock released.
pub fn acquire(group: &[u8; 4]) -> Result<bool, i32> {
    if !is_multicast(group) { return Err(-1); }
    // `ALL_HOSTS` is implicit; accepting the join keeps callers simple, and
    // storing it would waste a slot and later emit a report the RFC forbids.
    if *group == ALL_HOSTS { return Ok(false); }

    let mut g = GROUPS.lock();
    if let Some(i) = g.addr.iter().position(|e| e == group) {
        // Saturation would need four billion joiners; refusing is still the
        // answer that cannot later clear a group somebody holds.
        g.refs[i] = match g.refs[i].checked_add(1) { Some(r) => r, None => return Err(-2) };
        return Ok(false);
    }
    match g.addr.iter().position(|e| *e == [0u8; 4]) {
        Some(i) => {
            g.addr[i] = *group;
            g.refs[i] = 1;
            GROUP_COUNT.fetch_add(1, Ordering::Relaxed);
            Ok(true)
        }
        None => Err(-2),
    }
}

/// Drop one reference on `group`, without touching the wire.
///
/// `Ok(true)` when that was the LAST reference and the group is gone — the
/// caller owes a Leave Group message ([`send_leave`], outside any lock).
/// `Ok(false)` while other joiners still hold it. `Err(-1)` for a
/// non-multicast address or `ALL_HOSTS`, `Err(-2)` when not joined.
pub fn release(group: &[u8; 4]) -> Result<bool, i32> {
    if !is_multicast(group) { return Err(-1); }
    if *group == ALL_HOSTS { return Err(-1); }
    let mut g = GROUPS.lock();
    match g.addr.iter().position(|e| e == group) {
        Some(i) if g.refs[i] > 1 => {
            g.refs[i] -= 1;
            Ok(false)
        }
        Some(i) => {
            g.addr[i] = [0u8; 4];
            g.refs[i] = 0;
            GROUP_COUNT.fetch_sub(1, Ordering::Relaxed);
            Ok(true)
        }
        None => Err(-2),
    }
}

/// Join a multicast group, emitting an unsolicited Membership Report when this
/// is the group's first joiner.
///
/// Returns 0 on success, -1 for a non-multicast address, -2 when the table is
/// full. Joining a group already joined succeeds and takes another reference
/// — repeated joins are normal for independent subscribers on one host — so
/// each join needs its own [`leave`].
pub fn join(group: &[u8; 4]) -> i32 {
    match acquire(group) {
        // Report AFTER releasing the lock: `send_report` reaches the driver,
        // and holding a lock across the network path is how a spinlock
        // becomes a latency bug on the RT harts.
        Ok(true) => { send_report(group); 0 }
        Ok(false) => 0,
        Err(e) => e,
    }
}

/// Leave a group. The Leave Group message to `224.0.0.2` (RFC 2236 §3) goes
/// out only when the last joiner leaves; before that the interface is still a
/// member and saying otherwise would make a router stop forwarding traffic a
/// local subscriber is waiting for.
///
/// Returns 0 on success, -1 for a non-multicast address, -2 when not joined.
pub fn leave(group: &[u8; 4]) -> i32 {
    match release(group) {
        Ok(true) => { send_leave(group); 0 }
        Ok(false) => 0,
        Err(e) => e,
    }
}

/// Copy the joined groups into `out`, returning how many were written.
/// `ALL_HOSTS` is not included: it is implicit, never reported, never left.
pub fn joined_groups(out: &mut [[u8; 4]; MAX_GROUPS]) -> usize {
    let g = GROUPS.lock();
    let mut n = 0;
    for e in g.addr.iter() {
        if *e != [0u8; 4] { out[n] = *e; n += 1; }
    }
    n
}

/// Build an 8-byte IGMPv2 message (RFC 2236 §2).
///
/// `type | max_resp_time | checksum(2) | group(4)`. The checksum is the
/// standard RFC 1071 one's complement over the whole message.
pub fn build_message(kind: u8, max_resp: u8, group: &[u8; 4]) -> [u8; 8] {
    let mut m = [0u8; 8];
    m[0] = kind;
    m[1] = max_resp;
    m[4..8].copy_from_slice(group);
    let cs = ip::checksum(&m).to_be_bytes();
    m[2] = cs[0];
    m[3] = cs[1];
    m
}

/// Version 1 Router Present Timeout (RFC 2236 §8.11): 400 seconds.
pub const V1_ROUTER_PRESENT_TIMEOUT_TICKS: u64 = 400 * azos_drv_sys::timebase::TIMER_FREQ;

/// Until when (CLINT ticks) an IGMPv1 querier counts as present on the link;
/// 0 when none has been heard.
///
/// RFC 2236 §4 requires a per-interface variable saying whether the querier
/// runs IGMPv1, set by "whether or not an IGMPv1 query was heard in the last
/// [Version 1 Router Present Timeout] seconds" and never by the type of the
/// last query. A v1 router ignores V2 reports, so without it this host's
/// memberships age out on a v1 link while it keeps reporting. The stack has
/// one interface, so one static is the per-interface variable.
///
/// An atomic, not a field under `GROUPS`: nothing needs it consistent with the
/// membership table, and it takes no lock, so it cannot disturb the socket
/// layer's `SOCKS` → IGMP lock order.
static V1_QUERIER_UNTIL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// True while an IGMPv1 query has been heard within the last
/// [`V1_ROUTER_PRESENT_TIMEOUT_TICKS`].
pub fn v1_querier_present() -> bool {
    let until = V1_QUERIER_UNTIL.load(Ordering::Relaxed);
    until != 0 && azos_drv_sys::timebase::now() < until
}

/// Send a Membership Report **to the group itself** (RFC 2236 §2.9): the
/// report is addressed to the group being reported, not to all-routers, so
/// other members can hear it and suppress their own.
///
/// Version 2 (0x16), or Version 1 (0x12, RFC 1112 Appendix I) while a v1
/// querier is present — for unsolicited reports and answers to queries alike
/// (RFC 2236 §4). Every IGMP message carries the Router Alert option
/// (RFC 2236 §2).
pub fn send_report(group: &[u8; 4]) {
    let kind = if v1_querier_present() { IGMP_V1_REPORT } else { IGMP_V2_REPORT };
    let msg = build_message(kind, 0, group);
    let me  = super::net_get_ip();
    let mac = super::net_get_mac();
    let _ = ip::send_with_options(&mac, &me, group, IP_PROTO_IGMP, &ip::IP_OPT_ROUTER_ALERT, &msg);
}

/// Send a Leave Group message to all-routers (RFC 2236 §2.9).
///
/// Suppressed while a v1 querier is present, which RFC 2236 §4 allows: IGMPv1
/// has no Leave message, a v1 router cannot act on one, and it ages the group
/// out on its own. The membership itself is already gone — `release` ran.
pub fn send_leave(group: &[u8; 4]) {
    if v1_querier_present() { return; }
    let msg = build_message(IGMP_LEAVE_GROUP, 0, group);
    let me  = super::net_get_ip();
    let mac = super::net_get_mac();
    let _ = ip::send_with_options(&mac, &me, &ALL_ROUTERS, IP_PROTO_IGMP, &ip::IP_OPT_ROUTER_ALERT, &msg);
}

/// Handle a received IGMP message.
///
/// Only Membership Queries produce a response. Reports from other hosts are
/// accepted and ignored: without delayed reporting there is nothing to
/// suppress (see the deviation note at the top of this file).
pub fn handle(data: &[u8]) {
    if data.len() < 8 { return; }
    // RFC 1071: a correct message sums to 0xFFFF, so the complement is 0.
    // Checked before acting on any field — an unvalidated query would let an
    // off-path attacker make us emit reports at will.
    //
    // Over the WHOLE message, not its first 8 octets (RFC 2236 §2.3, §2.5).
    // `data` is the IP payload cut at Total Length by `ip::handle`, so this is
    // exactly the span the sender summed. The 8-octet version dropped every
    // correct IGMPv3 query (12+ octets) and accepted a longer message whose
    // tail did not verify.
    if ip::checksum(data) != 0 { return; }
    if data[0] != IGMP_MEMBERSHIP_QUERY { return; }

    // Which version of querier sent it (RFC 3376 §7.1):
    //   8 octets, Max Resp Time 0      -> IGMPv1 query
    //   8 octets, Max Resp Time non-0  -> IGMPv2 query
    //   12 octets or more              -> IGMPv3 query
    // The length is half of the test: an IGMPv3 query may carry Max Resp Code
    // 0, and taking it for v1 would switch this host to v1 reports for 400 s
    // on a link with no v1 router. v2 and v3 queries are both answered with v2
    // reports on their first 8 octets (RFC 2236 §2.5, RFC 3376 §7.2.1).
    //
    // Recorded BEFORE answering, so the reply to this very query is a v1 report.
    if data.len() == 8 && data[1] == 0 {
        let until = azos_drv_sys::timebase::now()
            .saturating_add(V1_ROUTER_PRESENT_TIMEOUT_TICKS);
        V1_QUERIER_UNTIL.store(until, Ordering::Relaxed);
    }

    let group = [data[4], data[5], data[6], data[7]];
    if group == [0u8; 4] {
        // General query: report every joined group.
        let mut gs = [[0u8; 4]; MAX_GROUPS];
        let n = joined_groups(&mut gs);
        for g in gs.iter().take(n) { send_report(g); }
    } else if is_joined(&group) && group != ALL_HOSTS {
        // Group-specific query. `ALL_HOSTS` is excluded because RFC 2236 §6
        // forbids reporting it, and `is_joined` returns true for it.
        send_report(&group);
    }
}

/// Drop every membership. Used when the interface is reconfigured: the groups
/// were joined against an address that no longer exists, and keeping them
/// would make us accept traffic nobody asked for under the new identity.
///
/// It does NOT reach the per-socket records in `socket.rs`. Nothing in the
/// kernel calls it today; a caller added later must drop socket memberships
/// too, or a socket's close would give back a reference taken by whoever
/// joined the group again after the clear.
///
/// It also forgets a v1 querier: that state was learned on the old
/// configuration, and a v1 router still on the link is heard again at its
/// next General Query.
pub fn clear() {
    let mut g = GROUPS.lock();
    g.addr = [[0u8; 4]; MAX_GROUPS];
    g.refs = [0; MAX_GROUPS];
    GROUP_COUNT.store(0, Ordering::Relaxed);
    V1_QUERIER_UNTIL.store(0, Ordering::Relaxed);
}
