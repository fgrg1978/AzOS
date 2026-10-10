// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-endpoint call queues (Kconfig `IPC_ENDPOINT_QUEUES`, wave 15 N5).
//!
//! The fast call (`SYS_IPC_FAST_CALL_EP`) is queued on the endpoint it names,
//! not in one machine-wide table:
//!
//! * **One call record per task slot** (`MAX_TASKS` of them). A caller
//!   blocks for its reply, so a task has at most one call in flight, and the
//!   record is its own: nothing is allocated, nothing can run out before the
//!   tasks do. The old table (`fast_ipc.rs`, the Kconfig-off fallback) had
//!   64 slots shared by the machine, and a call that found them all taken
//!   failed.
//! * **Per endpoint, a send queue**: the calls no server has taken, oldest
//!   first, singly linked through the records, under that endpoint's own
//!   `SpinLock`, always taken with interrupts off (`lock_irqsave`), so an
//!   interrupt handler may complete a call. A call a server has taken is on
//!   no list: its record's tag names the endpoint and says ACCEPTED, which is
//!   how the endpoint's death finds it. A server's death or the endpoint's
//!   destruction completes every call queued there or in service with a code
//!   (`drain`); the accept and the reply do no list work for it.
//! * **Per task slot, a ready mask**: bit `e` set while endpoint `e`, served
//!   by that task, has calls queued. `accept` takes no argument (ABI
//!   unchanged): it finds work in O(1) from the mask instead of scanning.
//!
//! A record's identity is one atomic word, `tag` = generation (48 bits) |
//! endpoint index | state. Every other field of a record is written only
//! under the lock of the endpoint its tag names, or by the owning caller
//! while the record is free. A reader that holds an endpoint lock and finds a
//! tag naming that endpoint may read the rest; a tag naming another endpoint
//! means the record is someone else's business. The handle given to both
//! sides of a call is `generation << REC_BITS | record`: a reply or a collect
//! with a handle whose generation is gone finds nothing to touch.
//!
//! Lock order: `ENDPOINTS` (control plane, `endpoint.rs`) → one endpoint
//! queue lock. Two queue locks are never held together, and nothing wakes,
//! blocks, donates or touches a capability table under a queue lock: those
//! are returned to the caller (`Completed`) and done after the lock is
//! released.
//!
//! This file names no kernel crate but `azos_sync` and `azos_limits`, both
//! behind the `target_os = "none"` switch, so `tests/host/ipc-fast-tests`
//! runs its tests on the host with the substitutes at the bottom.

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};

#[cfg(target_os = "none")]
use azos_sync::SpinLock;
#[cfg(not(target_os = "none"))]
use self::host::SpinLock;

/// Endpoints (Kconfig `IPC_ENDPOINTS`); the endpoint pool in `endpoint.rs`
/// has the same size.
#[cfg(target_os = "none")]
pub const EPS: usize = azos_limits::IPC_ENDPOINTS;
#[cfg(not(target_os = "none"))]
pub const EPS: usize = 32;

/// Call records: one per task slot (Kconfig `MAX_TASKS`). The host build has
/// more than 64, the old table's size, so its tests can queue past it.
#[cfg(target_os = "none")]
pub const RECS: usize = azos_limits::MAX_TASKS;
#[cfg(not(target_os = "none"))]
pub const RECS: usize = 160;

/// Words in a message (the fast call's four registers).
pub const WORDS: usize = 4;

/// "No donation rides on this call" (same value as `fast_ipc::NO_DONEE`).
pub const NO_DONEE: u32 = u32::MAX;

/// An endpoint with no serving task (same value as `endpoint::UNCLAIMED`).
pub const UNCLAIMED: u32 = u32::MAX;

const NIL: u32 = u32::MAX;

/// Bits of a handle that carry the record index: enough for `RECS`.
pub const REC_BITS: u32 = bits_for(RECS);
const REC_MASK: u64 = (1u64 << REC_BITS) - 1;
/// Generation bits of a record. 2^48 calls by ONE task before a held handle
/// can match again: 8.9 years at one call per microsecond.
pub const GEN_BITS: u32 = 48;
const GEN_MASK: u64 = (1u64 << GEN_BITS) - 1;

const fn bits_for(n: usize) -> u32 {
    let mut b = 1;
    while (1usize << b) < n {
        b += 1;
    }
    b
}

const _: () = assert!(EPS >= 1 && EPS <= 255, "an endpoint index is 8 bits of a tag");
const _: () = assert!(RECS >= 1 && RECS < NIL as usize);
const _: () = assert!(REC_BITS + GEN_BITS <= 63, "a handle is a non-negative i64");

// ── Record tag ──────────────────────────────────────────────────────────────

const S_FREE: u64 = 0;
const S_PENDING: u64 = 1;
const S_ACCEPTED: u64 = 2;
const S_REPLIED: u64 = 3;
const S_DONE: u64 = 4;
/// The endpoint field of a free record.
const EP_NONE: u64 = 0xFF;

#[inline(always)]
const fn tag(gen: u64, ep: u64, state: u64) -> u64 {
    (gen << 16) | (ep << 8) | state
}
#[inline(always)]
const fn tag_gen(t: u64) -> u64 { t >> 16 }
#[inline(always)]
const fn tag_ep(t: u64) -> usize { ((t >> 8) & 0xFF) as usize }
#[inline(always)]
const fn tag_state(t: u64) -> u64 { t & 0xFF }

/// The handle of record `rec`'s call in generation `gen`.
#[inline(always)]
pub const fn make_handle(rec: usize, gen: u64) -> u64 {
    ((gen & GEN_MASK) << REC_BITS) | (rec as u64 & REC_MASK)
}

/// The record a handle names, or `None` for a value this file never issues
/// (bit 63 set, or an index past `RECS`).
#[inline(always)]
pub const fn handle_rec(h: u64) -> Option<usize> {
    if h > i64::MAX as u64 {
        return None;
    }
    let i = (h & REC_MASK) as usize;
    if i < RECS { Some(i) } else { None }
}

#[inline(always)]
const fn handle_gen(h: u64) -> u64 {
    (h >> REC_BITS) & GEN_MASK
}

// ── State ───────────────────────────────────────────────────────────────────

struct Rec {
    tag: AtomicU64,
    caller: AtomicU32,
    /// The task that accepted the call (0 before).
    server: AtomicU32,
    words: [AtomicU64; WORDS],
    /// Handle the capability moved with the request took in the server's
    /// table, 0 for none. A record: the move happened in the caller's trap.
    moved_cap: AtomicU32,
    /// The task the caller's priority was lent to for this call, or
    /// [`NO_DONEE`]. Taken (reset) by whichever retires the call first.
    donee: AtomicU32,
    /// The completion code of a call in state DONE.
    status: AtomicI32,
    /// The next record in the endpoint's send queue (`NIL` at the tail).
    next: AtomicU32,
    /// Wave 15 N11: the badge of the endpoint capability a v2 call went
    /// through, valid only while `badge_gen` is the tag's generation (a v1
    /// call never writes either, so it reads as unbadged, never as the
    /// badge of an earlier call).
    badge: AtomicU32,
    badge_gen: AtomicU64,
}

impl Rec {
    const fn new() -> Self {
        Rec {
            tag: AtomicU64::new(tag(0, EP_NONE, S_FREE)),
            caller: AtomicU32::new(0),
            server: AtomicU32::new(0),
            words: [const { AtomicU64::new(0) }; WORDS],
            moved_cap: AtomicU32::new(0),
            donee: AtomicU32::new(NO_DONEE),
            status: AtomicI32::new(0),
            next: AtomicU32::new(NIL),
            badge: AtomicU32::new(0),
            badge_gen: AtomicU64::new(NO_BADGE_GEN),
        }
    }
}

struct Queue {
    /// Generation of the endpoint open in this slot; 0 = closed.
    gen: u32,
    /// The serving task, or [`UNCLAIMED`].
    owner: u32,
    /// The send queue: singly linked through `Rec::next`, oldest first.
    send_head: u32,
    send_tail: u32,
}

impl Queue {
    const fn closed() -> Self {
        Queue { gen: 0, owner: UNCLAIMED, send_head: NIL, send_tail: NIL }
    }
}

const RW: usize = EPS.div_ceil(64);

static RECORDS: [Rec; RECS] = [const { Rec::new() }; RECS];
static QUEUES: [SpinLock<Queue>; EPS] = [const { SpinLock::new(Queue::closed()) }; EPS];
/// Per task slot: endpoints served by it with calls queued.
static READY: [[AtomicU64; RW]; RECS] = [const { [const { AtomicU64::new(0) }; RW] }; RECS];
/// `Queue::owner`, readable without the lock (the exit sweep's filter).
static OWNERS: [AtomicU32; EPS] = [const { AtomicU32::new(UNCLAIMED) }; EPS];

/// Gate canary `ipc-no-peer-died`: a server's death leaves its accepted
/// calls in service, so their callers are never completed.
static CANARY_NO_PEER_DIED: AtomicBool = AtomicBool::new(false);

/// Arm the `ipc-no-peer-died` canary (runtime `canary=` flag, boot only).
pub fn canary_no_peer_died() {
    CANARY_NO_PEER_DIED.store(true, Ordering::Relaxed);
}

/// Gate canary `ipc-reply-twice` (wave 15 N11): a reply on a warrant whose
/// call was already answered is delivered again instead of refused.
static CANARY_REPLY_TWICE: AtomicBool = AtomicBool::new(false);

/// Arm the `ipc-reply-twice` canary (runtime `canary=` flag, boot only).
pub fn canary_reply_twice() {
    CANARY_REPLY_TWICE.store(true, Ordering::Relaxed);
}

/// `badge_gen` of a record no v2 call stamped (no generation reaches it).
const NO_BADGE_GEN: u64 = u64::MAX;

/// Records whose reply warrant was delegated to a task that is not the
/// endpoint's server: the exit sweep looks for a dead holder only when
/// this is not 0.
static DELEGATED: AtomicU32 = AtomicU32::new(0);

#[inline(always)]
fn rec(i: usize) -> &'static Rec {
    &RECORDS[i]
}

#[inline(always)]
fn ready_word(idx: usize, ep: usize) -> Option<&'static AtomicU64> {
    READY.get(idx).and_then(|r| r.get(ep / 64))
}

#[inline(always)]
fn ready_set(idx: usize, ep: usize) {
    if let Some(w) = ready_word(idx, ep) {
        w.fetch_or(1u64 << (ep % 64), Ordering::Release);
    }
}

#[inline(always)]
fn ready_clear(idx: usize, ep: usize) {
    if let Some(w) = ready_word(idx, ep) {
        let bit = 1u64 << (ep % 64);
        if w.load(Ordering::Relaxed) & bit != 0 {
            w.fetch_and(!bit, Ordering::Relaxed);
        }
    }
}

/// Task slot `idx` serves an endpoint with calls queued (its ready mask).
#[inline(always)]
fn ready_any(idx: usize) -> bool {
    READY.get(idx).is_some_and(|m| m.iter().any(|w| w.load(Ordering::Acquire) != 0))
}

// ── Intrusive lists (under the queue lock) ──────────────────────────────────

#[inline(always)]
fn push_send(q: &mut Queue, i: usize) {
    rec(i).next.store(NIL, Ordering::Relaxed);
    if q.send_tail == NIL {
        q.send_head = i as u32;
    } else {
        rec(q.send_tail as usize).next.store(i as u32, Ordering::Relaxed);
    }
    q.send_tail = i as u32;
}

/// Take the oldest queued record (the common case: O(1)).
#[inline(always)]
fn pop_send(q: &mut Queue) -> usize {
    let i = q.send_head as usize;
    let n = rec(i).next.load(Ordering::Relaxed);
    q.send_head = n;
    if n == NIL {
        q.send_tail = NIL;
    }
    i
}

/// Remove record `i` from anywhere in the send queue: a caller withdrawing
/// a call no server took (`abandon`, the exit sweep). O(queue length); not
/// on the call path.
fn unlink_send(q: &mut Queue, i: usize) {
    if q.send_head == i as u32 {
        pop_send(q);
        return;
    }
    let mut p = q.send_head;
    while p != NIL {
        let n = rec(p as usize).next.load(Ordering::Relaxed);
        if n == i as u32 {
            let after = rec(i).next.load(Ordering::Relaxed);
            rec(p as usize).next.store(after, Ordering::Relaxed);
            if q.send_tail == i as u32 {
                q.send_tail = p;
            }
            return;
        }
        p = n;
    }
}

/// End record `i`'s call: back to free, one generation on, so every handle
/// issued for it stops matching. Under the lock of the endpoint its tag
/// names (or by its caller while it is not on a list).
#[inline(always)]
fn free(i: usize, gen: u64) {
    let r = rec(i);
    r.donee.store(NO_DONEE, Ordering::Relaxed);
    r.moved_cap.store(0, Ordering::Relaxed);
    r.tag.store(tag(gen.wrapping_add(1) & GEN_MASK, EP_NONE, S_FREE), Ordering::Release);
}

// ── Endpoint lifecycle (called by `endpoint.rs` under `ENDPOINTS`) ─────────

/// Endpoint slot `ep` now holds the endpoint of generation `gen`, served by
/// `owner` (or [`UNCLAIMED`]).
pub fn open(ep: usize, gen: u32, owner: u32) {
    let Some(l) = QUEUES.get(ep) else { return };
    let mut q = l.lock_irqsave();
    *q = Queue::closed();
    q.gen = gen;
    q.owner = owner;
    OWNERS[ep].store(owner, Ordering::Relaxed);
}

/// The endpoint in slot `ep` (generation `gen`) is now served by `owner`
/// ([`UNCLAIMED`] when its server died and it is kept for a successor).
pub fn set_owner(ep: usize, gen: u32, owner: u32) {
    let Some(l) = QUEUES.get(ep) else { return };
    let mut q = l.lock_irqsave();
    if q.gen == gen {
        q.owner = owner;
        OWNERS[ep].store(owner, Ordering::Relaxed);
    }
}

/// The endpoint in slot `ep` is gone: no call is queued or accepted on it
/// from now on. Its calls are completed by [`drain`].
pub fn close(ep: usize) {
    let Some(l) = QUEUES.get(ep) else { return };
    let mut q = l.lock_irqsave();
    q.gen = 0;
    q.owner = UNCLAIMED;
    OWNERS[ep].store(UNCLAIMED, Ordering::Relaxed);
}

/// The endpoint slot `ep` is served by `tid` right now (lock-free filter).
pub fn served_by(ep: usize, tid: u32) -> bool {
    OWNERS.get(ep).is_some_and(|o| o.load(Ordering::Relaxed) == tid)
}

/// One call completed with a code by [`drain`], for the caller of `drain`
/// to act on with no lock held: wake `caller` on `handle`; return the
/// donation to `donee` unless it is [`NO_DONEE`]; and revoke `moved_cap` in
/// `server`'s table unless it is 0 (the request was never delivered, so the
/// capability moved with it belongs to nothing).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Completed {
    pub caller: u32,
    pub handle: u64,
    pub donee: u32,
    pub server: u32,
    pub moved_cap: u32,
}

/// Complete every call queued on, or accepted from, endpoint slot `ep` with
/// `code` (a negative `Errno` value), one record per hold of the lock,
/// handing each to `done` after the lock is released. `server` is the task
/// that served the endpoint (for a stranded capability). Returns how many.
///
/// Called after [`close`] (`EREVOKED`, or `EPEERDIED` when the server died)
/// or after [`set_owner`] to `UNCLAIMED` (`EPEERDIED`): no call can be
/// queued or accepted on `ep` meanwhile, so this ends. The queued calls are
/// the send queue; the calls in service are found by their tags (endpoint
/// `ep`, state ACCEPTED), one pass over the records with no lock held but
/// the endpoint's, per record found: an in-service call is on no list, which
/// keeps the accept and the reply free of list work.
pub fn drain(ep: usize, code: i32, server: u32, mut done: impl FnMut(Completed)) -> usize {
    let Some(l) = QUEUES.get(ep) else { return 0 };
    let mut n = 0usize;
    // The queued calls.
    loop {
        let c = {
            let mut q = l.lock_irqsave();
            if q.send_head == NIL {
                break;
            }
            let i = pop_send(&mut q);
            complete_locked(i, ep, code, server, true)
        };
        n += 1;
        done(c);
    }
    // The calls in service. Canary `ipc-no-peer-died`: left in service.
    if code == PEER_DIED && CANARY_NO_PEER_DIED.load(Ordering::Relaxed) {
        return n;
    }
    for (i, r) in RECORDS.iter().enumerate() {
        let t = r.tag.load(Ordering::Acquire);
        if tag_ep(t) != ep || tag_state(t) != S_ACCEPTED {
            continue;
        }
        let c = {
            let _q = l.lock_irqsave();
            let t = r.tag.load(Ordering::Relaxed);
            if tag_ep(t) != ep || tag_state(t) != S_ACCEPTED {
                continue;
            }
            complete_locked(i, ep, code, server, false)
        };
        n += 1;
        done(c);
    }
    n
}

/// End record `i`'s call with `code` (state DONE), under `ep`'s lock.
#[inline]
fn complete_locked(i: usize, ep: usize, code: i32, server: u32, pending: bool) -> Completed {
    let r = rec(i);
    let t = r.tag.load(Ordering::Relaxed);
    r.status.store(code, Ordering::Relaxed);
    let donee = r.donee.swap(NO_DONEE, Ordering::Relaxed);
    let moved = if pending { r.moved_cap.swap(0, Ordering::Relaxed) } else { 0 };
    r.tag.store(tag(tag_gen(t), ep as u64, S_DONE), Ordering::Release);
    Completed {
        caller: r.caller.load(Ordering::Relaxed),
        handle: make_handle(i, tag_gen(t)),
        donee,
        server,
        moved_cap: moved,
    }
}

/// `-EPEERDIED`: the serving task died with the call queued or in service.
pub const PEER_DIED: i32 = -(azos_abi_errno::EPEERDIED as i32);
/// `-EREVOKED`: the endpoint was destroyed with the call queued or in
/// service.
pub const REVOKED: i32 = -(azos_abi_errno::EREVOKED as i32);

/// The errno values, through the same seam as the rest (the host suite has
/// no `azos_abi`).
#[cfg(target_os = "none")]
mod azos_abi_errno {
    pub const EPEERDIED: i64 = azos_abi::error::Errno::EPEERDIED as i64;
    pub const EREVOKED: i64 = azos_abi::error::Errno::EREVOKED as i64;
}
#[cfg(not(target_os = "none"))]
mod azos_abi_errno {
    pub const EPEERDIED: i64 = 211;
    pub const EREVOKED: i64 = 212;
}

// ── The call ────────────────────────────────────────────────────────────────

/// Queue `caller`'s call (task slot `caller_idx`) on endpoint slot `ep`,
/// which must still hold generation `gen` served by `owner` (task slot
/// `owner_idx`). Returns the call's handle, or `None`: the endpoint is gone
/// or changed server, or the caller's record is still in a call.
#[allow(clippy::too_many_arguments)]
#[inline]
pub fn call(
    caller_idx: usize,
    caller: u32,
    ep: usize,
    gen: u32,
    owner: u32,
    owner_idx: usize,
    words: [u64; WORDS],
    moved_cap: u32,
    donee: u32,
) -> Option<u64> {
    let r = RECORDS.get(caller_idx)?;
    let l = QUEUES.get(ep)?;
    let t = r.tag.load(Ordering::Relaxed);
    if tag_state(t) != S_FREE {
        return None;
    }
    let g = tag_gen(t);
    let mut q = l.lock_irqsave();
    if q.gen != gen || q.owner != owner || gen == 0 {
        return None;
    }
    r.caller.store(caller, Ordering::Relaxed);
    r.server.store(0, Ordering::Relaxed);
    for (d, s) in r.words.iter().zip(words) {
        d.store(s, Ordering::Relaxed);
    }
    r.moved_cap.store(moved_cap, Ordering::Relaxed);
    r.donee.store(donee, Ordering::Relaxed);
    r.tag.store(tag(g, ep as u64, S_PENDING), Ordering::Relaxed);
    let was_empty = q.send_head == NIL;
    push_send(&mut q, caller_idx);
    if was_empty {
        ready_set(owner_idx, ep);
    }
    drop(q);
    Some(make_handle(caller_idx, g))
}

/// A request a server took: `(handle, caller, words, moved_cap)`.
pub type Accepted = (u64, u32, [u64; WORDS], u32);

/// Under `q` (endpoint slot `ep`): take the oldest queued call for server
/// `server` (task slot `server_idx`), or clear `ep`'s ready bit when there is
/// none for it.
#[inline(always)]
fn take_locked(q: &mut Queue, ep: usize, server_idx: usize, server: u32) -> Option<Accepted> {
    if q.gen == 0 || q.owner != server || q.send_head == NIL {
        ready_clear(server_idx, ep);
        return None;
    }
    let i = pop_send(q);
    if q.send_head == NIL {
        ready_clear(server_idx, ep);
    }
    let r = rec(i);
    r.server.store(server, Ordering::Relaxed);
    let t = r.tag.load(Ordering::Relaxed);
    r.tag.store(tag(tag_gen(t), ep as u64, S_ACCEPTED), Ordering::Relaxed);
    let mut w = [0u64; WORDS];
    for (d, s) in w.iter_mut().zip(r.words.iter()) {
        *d = s.load(Ordering::Relaxed);
    }
    Some((make_handle(i, tag_gen(t)), r.caller.load(Ordering::Relaxed), w, r.moved_cap.load(Ordering::Relaxed)))
}

/// Server `server` (task slot `server_idx`) takes its oldest queued call on
/// the lowest-numbered endpoint it serves that has one. O(1) when nothing is
/// queued: one load of its ready mask.
#[inline]
pub fn accept(server_idx: usize, server: u32) -> Option<Accepted> {
    let masks = READY.get(server_idx)?;
    for (w, word) in masks.iter().enumerate() {
        let mut m = word.load(Ordering::Acquire);
        while m != 0 {
            let ep = w * 64 + m.trailing_zeros() as usize;
            m &= m - 1;
            if let Some(a) = take_ep(ep, server_idx, server) {
                return Some(a);
            }
        }
    }
    None
}

/// [`take_locked`] on endpoint slot `ep`, with its lock. Out of line: the
/// lock's code inlined into [`accept`]'s loop made that loop save every
/// callee-saved register on entry.
#[inline(never)]
fn take_ep(ep: usize, server_idx: usize, server: u32) -> Option<Accepted> {
    let l = QUEUES.get(ep)?;
    let mut q = l.lock_irqsave();
    take_locked(&mut q, ep, server_idx, server)
}

/// Outcome of a reply (same meaning as `fast_ipc::FastIpcReply`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reply {
    /// Delivered: wake `caller` on the handle; `donee` is owed one
    /// `return_donation` by the replier unless it is [`NO_DONEE`].
    Woke { caller: u32, rec: usize, donee: u32 },
    /// The call this server accepted under that handle is over.
    Stale,
    /// Anything else: not a handle of an accepted call of this server.
    Refused,
}

/// Lock the endpoint record `i`'s tag names and check, under it, that the
/// tag still names it. `None` for a free record or one past `EPS`.
#[inline(always)]
fn lock_rec(i: usize) -> Option<(usize, u64, impl core::ops::DerefMut<Target = Queue> + 'static)> {
    let r = rec(i);
    for _ in 0..2 {
        let t = r.tag.load(Ordering::Acquire);
        let ep = tag_ep(t);
        let l = QUEUES.get(ep)?;
        let q = l.lock_irqsave();
        let t2 = r.tag.load(Ordering::Relaxed);
        if tag_ep(t2) == ep {
            return Some((ep, t2, q));
        }
        // The record moved to another endpoint between the load and the
        // lock: its call ended and a new one began. Look again.
    }
    None
}

/// The checks and the deposit of a reply, under the lock of the endpoint
/// record `i`'s tag `t` names. With `keep_donee`, the donation stays in the
/// record for the client to return when it collects (and `Woke` reports
/// none): written before the state is published, because a collect reads
/// the record without the lock.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn reply_locked(_q: &mut Queue, i: usize, t: u64, g: u64, replier: u32, privileged: bool, words: [u64; WORDS], keep_donee: bool) -> Reply {
    let r = rec(i);
    if tag_state(t) != S_ACCEPTED {
        return Reply::Refused;
    }
    if !privileged && r.server.load(Ordering::Relaxed) != replier {
        return Reply::Refused;
    }
    // Last, after ownership: only the call's own server learns that its
    // handle is stale (no generation oracle; see `fast_ipc::FastIpcReply`).
    if tag_gen(t) != g {
        return Reply::Stale;
    }
    for (d, s) in r.words.iter().zip(words) {
        d.store(s, Ordering::Relaxed);
    }
    let donee = if keep_donee { NO_DONEE } else { r.donee.swap(NO_DONEE, Ordering::Relaxed) };
    r.tag.store(tag(g, tag_ep(t) as u64, S_REPLIED), Ordering::Release);
    Reply::Woke { caller: r.caller.load(Ordering::Relaxed), rec: i, donee }
}

/// Answer the call `handle` names with `words`. `replier` is the task making
/// the call; `privileged` (a kernel task) skips the ownership check, never
/// the generation check.
pub fn reply(handle: u64, replier: u32, privileged: bool, words: [u64; WORDS]) -> Reply {
    let Some(i) = handle_rec(handle) else { return Reply::Refused };
    let Some((_, t, mut q)) = lock_rec(i) else { return Reply::Refused };
    reply_locked(&mut q, i, t, handle_gen(handle), replier, privileged, words, false)
}

/// [`reply`], then, only when it delivered, [`accept`] for `server` (task
/// slot `server_idx`): the same endpoint first, in the reply's own hold of
/// its lock. With no next call on that endpoint, the donation the reply took
/// goes back into the answered record for the CLIENT to return when it
/// collects (the server is about to hand the CPU to it and block; see
/// `fast_ipc::fast_ipc_reply_then_accept`), and a server with calls queued
/// on another of its endpoints takes the next one there.
pub fn reply_then_accept(
    handle: u64,
    replier: u32,
    privileged: bool,
    words: [u64; WORDS],
    server_idx: usize,
) -> (Reply, Option<Accepted>) {
    let Some(i) = handle_rec(handle) else { return (Reply::Refused, None) };
    let Some((ep, t, mut q)) = lock_rec(i) else { return (Reply::Refused, None) };
    // A next call queued here for this server: its bit is in the server's
    // ready mask (set by the call that found the queue empty), so an empty
    // mask answers "none anywhere" with one load.
    let any = ready_any(server_idx);
    let here = any && q.gen != 0 && q.owner == replier && q.send_head != NIL;
    let r = reply_locked(&mut q, i, t, handle_gen(handle), replier, privileged, words, !here);
    if !matches!(r, Reply::Woke { .. }) {
        return (r, None);
    }
    if here {
        return (r, take_locked(&mut q, ep, server_idx, replier));
    }
    drop(q);
    (r, if any { accept(server_idx, replier) } else { None })
}

/// What a caller finds when it collects (see [`collect`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Collected {
    /// The reply, and a donation the caller owes back (or [`NO_DONEE`]).
    Reply([u64; WORDS], u32),
    /// The call was completed with a code (`drain`), and a donation owed.
    Done(i32, u32),
    /// Nothing to collect (not answered yet, or not this caller's call).
    Nothing,
}

/// Collect `caller`'s answer to the call `handle` names, freeing the record.
///
/// Takes no lock. An answered record (REPLIED or DONE) is on no list and is
/// written by nobody but its caller: the reply or the drain wrote every field
/// before publishing the state with a release store, a late reply or abandon
/// finds the state and touches nothing, and only the caller frees it.
#[inline]
pub fn collect(handle: u64, caller: u32) -> Collected {
    let Some(i) = handle_rec(handle) else { return Collected::Nothing };
    let r = rec(i);
    let t = r.tag.load(Ordering::Acquire);
    if tag_gen(t) != handle_gen(handle) || r.caller.load(Ordering::Relaxed) != caller {
        return Collected::Nothing;
    }
    let donee = r.donee.load(Ordering::Relaxed);
    let out = match tag_state(t) {
        S_REPLIED => {
            let mut w = [0u64; WORDS];
            for (d, s) in w.iter_mut().zip(r.words.iter()) {
                *d = s.load(Ordering::Relaxed);
            }
            Collected::Reply(w, donee)
        }
        S_DONE => Collected::Done(r.status.load(Ordering::Relaxed), donee),
        _ => return Collected::Nothing,
    };
    free(i, tag_gen(t));
    out
}

/// Where `caller`'s call `handle` stands (same meaning as
/// `fast_ipc::FastIpcWait`): 0 gone, 1 waiting, 2 ready. Lock-free: one
/// load of the tag.
pub fn wait_state(handle: u64, caller: u32) -> u8 {
    let Some(i) = handle_rec(handle) else { return 0 };
    let r = rec(i);
    let t = r.tag.load(Ordering::Acquire);
    if tag_gen(t) != handle_gen(handle) || r.caller.load(Ordering::Relaxed) != caller {
        return 0;
    }
    match tag_state(t) {
        S_PENDING | S_ACCEPTED => 1,
        S_REPLIED | S_DONE => 2,
        _ => 0,
    }
}

/// What [`abandon`] took back.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Abandoned {
    /// The donation the caller owes back, or [`NO_DONEE`].
    pub donee: u32,
    /// The call was still queued: no server saw it, so a capability moved
    /// with it may be moved back to the caller.
    pub was_queued: bool,
}

/// `caller` leaves its call `handle` without an answer (its retries ran out,
/// or it was killed): the call is withdrawn and the record freed, so the
/// caller's next call has it. A server that accepted it gets `Stale` when it
/// replies.
pub fn abandon(handle: u64, caller: u32) -> Abandoned {
    let none = Abandoned { donee: NO_DONEE, was_queued: false };
    let Some(i) = handle_rec(handle) else { return none };
    let r = rec(i);
    let Some((_, t, mut q)) = lock_rec(i) else { return none };
    if tag_gen(t) != handle_gen(handle) || r.caller.load(Ordering::Relaxed) != caller {
        return none;
    }
    let st = tag_state(t);
    match st {
        S_PENDING => unlink_send(&mut q, i),
        S_ACCEPTED | S_REPLIED | S_DONE => {}
        _ => return none,
    }
    let donee = r.donee.swap(NO_DONEE, Ordering::Relaxed);
    free(i, tag_gen(t));
    Abandoned { donee, was_queued: st == S_PENDING }
}

/// The task in slot `idx` (TID `tid`) is exiting: withdraw its own call if
/// it is in one. Returns what the exit sweep must do after (the stranded
/// capability, `Completed::moved_cap`, belongs to `server` = the endpoint's
/// owner; `donee` is the dying caller's donation to give back).
pub fn release_caller(idx: usize, tid: u32) -> Option<Completed> {
    let r = RECORDS.get(idx)?;
    let t = r.tag.load(Ordering::Acquire);
    if tag_state(t) == S_FREE || r.caller.load(Ordering::Relaxed) != tid {
        return None;
    }
    let (_, t, mut q) = lock_rec(idx)?;
    if tag_state(t) == S_FREE || r.caller.load(Ordering::Relaxed) != tid {
        return None;
    }
    let pending = tag_state(t) == S_PENDING;
    match tag_state(t) {
        S_PENDING => unlink_send(&mut q, idx),
        _ => {}
    }
    let c = Completed {
        caller: tid,
        handle: make_handle(idx, tag_gen(t)),
        donee: r.donee.swap(NO_DONEE, Ordering::Relaxed),
        server: if pending { q.owner } else { 0 },
        moved_cap: if pending { r.moved_cap.load(Ordering::Relaxed) } else { 0 },
    };
    free(idx, tag_gen(t));
    Some(c)
}

// ── Wave 15 N11: the v2 call's badge and its reply warrant ─────────────────

/// Before a v2 call by the task in slot `caller_idx`: the call [`call`] is
/// about to queue goes through an endpoint capability badged `badge`.
/// Written while the record is free (only its own task makes calls on it),
/// published by `call`'s hold of the queue lock. When the call is refused,
/// [`unstamp_badge`] takes it back before the next call can reuse the
/// generation.
pub fn stamp_badge(caller_idx: usize, badge: u32) {
    let Some(r) = RECORDS.get(caller_idx) else { return };
    let t = r.tag.load(Ordering::Relaxed);
    r.badge.store(badge, Ordering::Relaxed);
    r.badge_gen.store(tag_gen(t), Ordering::Relaxed);
}

/// A v2 call stamped with [`stamp_badge`] was refused: unstamp.
pub fn unstamp_badge(caller_idx: usize) {
    if let Some(r) = RECORDS.get(caller_idx) {
        r.badge_gen.store(NO_BADGE_GEN, Ordering::Relaxed);
    }
}

/// The badge of the call `handle` names, for the task holding its reply
/// warrant (`holder`), right after it accepted it: `Some(badge)` for a v2
/// call (0 = an unbadged capability), `None` for a v1 call or a handle that
/// is not `holder`'s accepted call.
pub fn accept_badge(handle: u64, holder: u32) -> Option<u32> {
    let i = handle_rec(handle)?;
    let r = rec(i);
    let t = r.tag.load(Ordering::Acquire);
    if tag_state(t) != S_ACCEPTED || tag_gen(t) != handle_gen(handle) || r.server.load(Ordering::Relaxed) != holder {
        return None;
    }
    if r.badge_gen.load(Ordering::Relaxed) != tag_gen(t) {
        return None;
    }
    Some(r.badge.load(Ordering::Relaxed))
}

/// Outcome of [`delegate`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Delegated {
    /// `to` now holds the reply warrant; the holder does not.
    Moved,
    /// The call is over (answered, completed or withdrawn).
    Stale,
    /// Not a call `holder` accepted and still holds.
    Refused,
}

/// Move the reply warrant of the call `handle` names from `holder` (the
/// task that accepted it, or the one it was last moved to) to `to`: from
/// now on only `to` may answer it, once. The send-once rule is the record's
/// state: the first reply moves it from ACCEPTED to REPLIED, and every later
/// reply, by anyone, is refused. A holder that dies with the warrant
/// completes the call with `-EPEERDIED` ([`release_holder`]).
///
/// Who `to` may be (a thread of the server's own domain, or the transport
/// proxy) is the syscall's rule, not this one's.
pub fn delegate(handle: u64, holder: u32, to: u32) -> Delegated {
    let Some(i) = handle_rec(handle) else { return Delegated::Refused };
    let Some((_, t, q)) = lock_rec(i) else { return Delegated::Refused };
    let r = rec(i);
    if tag_state(t) != S_ACCEPTED || r.server.load(Ordering::Relaxed) != holder {
        return Delegated::Refused;
    }
    if tag_gen(t) != handle_gen(handle) {
        return Delegated::Stale;
    }
    let owner = q.owner;
    r.server.store(to, Ordering::Relaxed);
    // Counted while some record's holder is not its endpoint's server.
    match (holder == owner, to == owner) {
        (true, false) => {
            DELEGATED.fetch_add(1, Ordering::Relaxed);
        }
        (false, true) => {
            DELEGATED.fetch_sub(1, Ordering::Relaxed);
        }
        _ => {}
    }
    drop(q);
    Delegated::Moved
}

/// Answer the call `handle` names as the holder of its reply warrant
/// (`holder`): [`reply`] with the holder's identity, and the delegation
/// count kept. Canary `ipc-reply-twice`: an answered call takes a second
/// reply.
pub fn reply_warrant(handle: u64, holder: u32, words: [u64; WORDS]) -> Reply {
    let Some(i) = handle_rec(handle) else { return Reply::Refused };
    let Some((_, t, mut q)) = lock_rec(i) else { return Reply::Refused };
    let r = rec(i);
    if CANARY_REPLY_TWICE.load(Ordering::Relaxed) && tag_state(t) == S_REPLIED && tag_gen(t) == handle_gen(handle) {
        for (d, s) in r.words.iter().zip(words) {
            d.store(s, Ordering::Relaxed);
        }
        return Reply::Woke { caller: r.caller.load(Ordering::Relaxed), rec: i, donee: NO_DONEE };
    }
    let delegated = tag_state(t) == S_ACCEPTED && r.server.load(Ordering::Relaxed) != q.owner;
    let out = reply_locked(&mut q, i, t, handle_gen(handle), holder, false, words, false);
    if delegated && matches!(out, Reply::Woke { .. }) {
        DELEGATED.fetch_sub(1, Ordering::Relaxed);
    }
    out
}

/// The exit sweep's warrant half: complete with `-EPEERDIED` every call
/// whose reply warrant `tid` (exiting) holds on an endpoint it does not
/// serve (the calls on its own endpoints are its endpoints' drain). One
/// load when no warrant was ever delegated; else one pass over the records.
pub fn release_holder(tid: u32, mut done: impl FnMut(Completed)) -> usize {
    if DELEGATED.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    let mut n = 0;
    for (i, r) in RECORDS.iter().enumerate() {
        let t = r.tag.load(Ordering::Acquire);
        if tag_state(t) != S_ACCEPTED || r.server.load(Ordering::Relaxed) != tid {
            continue;
        }
        let Some((ep, t, q)) = lock_rec(i) else { continue };
        if tag_state(t) != S_ACCEPTED || r.server.load(Ordering::Relaxed) != tid || q.owner == tid {
            continue;
        }
        DELEGATED.fetch_sub(1, Ordering::Relaxed);
        let c = complete_locked(i, ep, PEER_DIED, tid, false);
        drop(q);
        n += 1;
        done(c);
    }
    n
}

/// `(queued, accepted, replied, done)` over every record (diagnostic).
pub fn census() -> (u32, u32, u32, u32) {
    let mut c = (0u32, 0u32, 0u32, 0u32);
    for r in RECORDS.iter() {
        match tag_state(r.tag.load(Ordering::Relaxed)) {
            S_PENDING => c.0 += 1,
            S_ACCEPTED => c.1 += 1,
            S_REPLIED => c.2 += 1,
            S_DONE => c.3 += 1,
            _ => {}
        }
    }
    c
}

/// Every record in a call: `(record, state 1..=4, caller, server)` into
/// `out`; how many.
pub fn ids(out: &mut [(u8, u8, u32, u32)]) -> usize {
    let mut n = 0;
    for (i, r) in RECORDS.iter().enumerate() {
        let st = tag_state(r.tag.load(Ordering::Relaxed));
        if st == S_FREE {
            continue;
        }
        let Some(o) = out.get_mut(n) else { break };
        *o = (i as u8, st as u8, r.caller.load(Ordering::Relaxed), r.server.load(Ordering::Relaxed));
        n += 1;
    }
    n
}

// ===========================================================================
// Host substitutes — off-board only, never in the kernel binary.
// ===========================================================================

#[cfg(not(target_os = "none"))]
#[allow(dead_code)]
mod host {
    use core::cell::UnsafeCell;
    use core::ops::{Deref, DerefMut};
    use core::sync::atomic::{AtomicBool, Ordering};

    pub struct SpinLock<T> {
        locked: AtomicBool,
        data: UnsafeCell<T>,
    }
    unsafe impl<T: Send> Sync for SpinLock<T> {}

    impl<T> SpinLock<T> {
        pub const fn new(v: T) -> Self {
            SpinLock { locked: AtomicBool::new(false), data: UnsafeCell::new(v) }
        }
        pub fn lock_irqsave(&self) -> Guard<'_, T> {
            while self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
                core::hint::spin_loop();
            }
            Guard { lock: self }
        }
    }

    pub struct Guard<'a, T> {
        lock: &'a SpinLock<T>,
    }
    impl<T> Deref for Guard<'_, T> {
        type Target = T;
        fn deref(&self) -> &T {
            unsafe { &*self.lock.data.get() }
        }
    }
    impl<T> DerefMut for Guard<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            unsafe { &mut *self.lock.data.get() }
        }
    }
    impl<T> Drop for Guard<'_, T> {
        fn drop(&mut self) {
            self.lock.locked.store(false, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static SERIAL: Mutex<()> = Mutex::new(());

    const SERVER: u32 = 7;
    const SERVER_IDX: usize = 3;
    const EP: usize = 5;
    const GEN: u32 = 9;
    const REQ: [u64; WORDS] = [0x11, 0x22, 0x33, 0x44];
    const RSP: [u64; WORDS] = [0xAA, 0xBB, 0xCC, 0xDD];

    fn env() -> MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        for ep in 0..EPS {
            close(ep);
            let _ = drain(ep, REVOKED, 0, |_| {});
        }
        for (i, r) in RECORDS.iter().enumerate() {
            let t = r.tag.load(Ordering::Relaxed);
            if tag_state(t) != S_FREE {
                free(i, tag_gen(t));
            }
            for w in READY[i].iter() {
                w.store(0, Ordering::Relaxed);
            }
        }
        CANARY_NO_PEER_DIED.store(false, Ordering::Relaxed);
        CANARY_REPLY_TWICE.store(false, Ordering::Relaxed);
        DELEGATED.store(0, Ordering::Relaxed);
        open(EP, GEN, SERVER);
        g
    }

    fn client(i: usize) -> (usize, u32) {
        (4 + i, 1000 + i as u32)
    }

    fn call_from(i: usize) -> Option<u64> {
        let (idx, tid) = client(i);
        call(idx, tid, EP, GEN, SERVER, SERVER_IDX, [i as u64, 0, 0, 0], 0, NO_DONEE)
    }

    #[test]
    fn call_accept_reply_collect_round_trip() {
        let _e = env();
        let (idx, tid) = (10, 77);
        let h = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE).unwrap();
        assert_eq!(wait_state(h, tid), 1);
        let (sh, caller, w, cap) = accept(SERVER_IDX, SERVER).unwrap();
        assert_eq!((sh, caller, w, cap), (h, tid, REQ, 0));
        assert_eq!(accept(SERVER_IDX, SERVER), None, "one call, taken once");
        assert_eq!(reply(h, SERVER, false, RSP), Reply::Woke { caller: tid, rec: idx, donee: NO_DONEE });
        assert_eq!(wait_state(h, tid), 2);
        assert_eq!(collect(h, tid), Collected::Reply(RSP, NO_DONEE));
        assert_eq!(wait_state(h, tid), 0, "the record is free again");
        assert_eq!(reply(h, SERVER, false, RSP), Reply::Refused, "answered once");
    }

    /// The property the old 64-slot table could not hold: more calls in
    /// flight than it had slots. 150 callers queue on one endpoint and every
    /// one is served, in arrival order.
    #[test]
    fn more_than_64_concurrent_calls_all_succeed() {
        let _e = env();
        const N: usize = 150;
        assert!(N > 64 && 4 + N <= RECS);
        let hs: Vec<u64> = (0..N).map(|i| call_from(i).expect("queued")).collect();
        assert_eq!(census().0, N as u32);
        for (i, &h) in hs.iter().enumerate() {
            let (sh, caller, w, _) = accept(SERVER_IDX, SERVER).expect("served");
            assert_eq!((sh, caller, w[0]), (h, client(i).1, i as u64), "FIFO");
        }
        assert_eq!(accept(SERVER_IDX, SERVER), None);
        for (i, &h) in hs.iter().enumerate() {
            assert!(matches!(reply(h, SERVER, false, [i as u64 + 1, 0, 0, 0]), Reply::Woke { .. }));
        }
        for (i, &h) in hs.iter().enumerate() {
            assert_eq!(collect(h, client(i).1), Collected::Reply([i as u64 + 1, 0, 0, 0], NO_DONEE));
        }
        assert_eq!(census(), (0, 0, 0, 0));
    }

    #[test]
    fn server_death_completes_queued_and_accepted_calls_with_peer_died() {
        let _e = env();
        let h0 = call_from(0).unwrap();
        let h1 = call_from(1).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap(); // h0 in service
        set_owner(EP, GEN, UNCLAIMED);
        let mut seen = Vec::new();
        assert_eq!(drain(EP, PEER_DIED, SERVER, |c| seen.push(c)), 2);
        assert_eq!(seen.len(), 2);
        assert!(seen.iter().any(|c| c.handle == h0) && seen.iter().any(|c| c.handle == h1));
        assert_eq!(wait_state(h0, client(0).1), 2);
        assert_eq!(collect(h0, client(0).1), Collected::Done(PEER_DIED, NO_DONEE));
        assert_eq!(collect(h1, client(1).1), Collected::Done(PEER_DIED, NO_DONEE));
        assert_eq!(reply(h0, SERVER, false, RSP), Reply::Refused, "a completed call takes no reply");
    }

    /// Canary `ipc-no-peer-died`: the in-service call is left in service, so
    /// its caller would wait forever.
    #[test]
    fn canary_leaves_the_accepted_call_uncompleted() {
        let _e = env();
        let h0 = call_from(0).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        canary_no_peer_died();
        set_owner(EP, GEN, UNCLAIMED);
        assert_eq!(drain(EP, PEER_DIED, SERVER, |_| {}), 0);
        assert_eq!(wait_state(h0, client(0).1), 1, "still waiting: nobody completes it");
    }

    #[test]
    fn endpoint_destroyed_completes_with_revoked_and_returns_a_stranded_cap() {
        let _e = env();
        let (idx, tid) = client(0);
        let h = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0x5_0001, SERVER).unwrap();
        close(EP);
        let mut seen = Vec::new();
        drain(EP, REVOKED, SERVER, |c| seen.push(c));
        assert_eq!(seen, vec![Completed { caller: tid, handle: h, donee: SERVER, server: SERVER, moved_cap: 0x5_0001 }]);
        assert_eq!(collect(h, tid), Collected::Done(REVOKED, NO_DONEE));
        assert_eq!(call_from(1), None, "a closed endpoint queues nothing");
    }

    #[test]
    fn a_call_to_a_changed_endpoint_is_refused() {
        let _e = env();
        let (idx, tid) = client(0);
        assert_eq!(call(idx, tid, EP, GEN + 1, SERVER, SERVER_IDX, REQ, 0, NO_DONEE), None, "stale generation");
        assert_eq!(call(idx, tid, EP, GEN, SERVER + 1, SERVER_IDX, REQ, 0, NO_DONEE), None, "another server");
        assert_eq!(census(), (0, 0, 0, 0));
    }

    #[test]
    fn only_the_accepting_server_replies_and_a_stale_handle_is_stale() {
        let _e = env();
        let h = call_from(0).unwrap();
        assert_eq!(reply(h, SERVER, false, RSP), Reply::Refused, "not accepted yet");
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        assert_eq!(reply(h, SERVER + 1, false, RSP), Reply::Refused, "impostor");
        let old = make_handle(handle_rec(h).unwrap(), handle_gen(h).wrapping_sub(1) & GEN_MASK);
        assert_eq!(reply(old, SERVER, false, RSP), Reply::Stale);
        assert!(matches!(reply(h, SERVER + 1, true, RSP), Reply::Woke { .. }), "privileged skips ownership");
    }

    #[test]
    fn abandon_withdraws_a_queued_call_and_frees_the_record() {
        let _e = env();
        let (idx, tid) = client(0);
        let h = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, SERVER).unwrap();
        assert_eq!(abandon(h, tid), Abandoned { donee: SERVER, was_queued: true });
        assert_eq!(accept(SERVER_IDX, SERVER), None, "nothing left to serve");
        let h2 = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE).expect("the record is free");
        assert_ne!(h2, h);
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        assert_eq!(abandon(h2, tid), Abandoned { donee: NO_DONEE, was_queued: false });
        assert_eq!(reply(h2, SERVER, false, RSP), Reply::Refused, "the call is over");
        // The seat re-let to the same server's next call: the old handle is
        // `Stale` there, never delivered into the new call.
        let h3 = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        assert_eq!(reply(h2, SERVER, false, RSP), Reply::Stale);
        assert!(matches!(reply(h3, SERVER, false, RSP), Reply::Woke { .. }));
    }

    #[test]
    fn abandoning_a_queued_call_in_the_middle_keeps_the_queue_whole() {
        let _e = env();
        let h0 = call_from(0).unwrap();
        let h1 = call_from(1).unwrap();
        let h2 = call_from(2).unwrap();
        let h3 = call_from(3).unwrap();
        assert!(abandon(h1, client(1).1).was_queued);
        assert!(abandon(h3, client(3).1).was_queued, "the tail");
        let h4 = call_from(4).unwrap();
        let got: Vec<u64> = core::iter::from_fn(|| accept(SERVER_IDX, SERVER).map(|a| a.0)).collect();
        assert_eq!(got, vec![h0, h2, h4]);
    }

    #[test]
    fn reply_then_accept_takes_the_next_call_in_one_hold() {
        let _e = env();
        let h0 = call_from(0).unwrap();
        let h1 = call_from(1).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        let (r, next) = reply_then_accept(h0, SERVER, false, RSP, SERVER_IDX);
        assert!(matches!(r, Reply::Woke { .. }));
        assert_eq!(next.map(|a| a.0), Some(h1));
        let (r, next) = reply_then_accept(h1, SERVER, false, RSP, SERVER_IDX);
        assert!(matches!(r, Reply::Woke { .. }));
        assert_eq!(next, None);
    }

    #[test]
    fn with_no_next_call_the_donation_goes_back_to_the_client() {
        let _e = env();
        let (idx, tid) = client(0);
        let h = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, SERVER).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        let (r, next) = reply_then_accept(h, SERVER, false, RSP, SERVER_IDX);
        assert_eq!((r, next), (Reply::Woke { caller: tid, rec: idx, donee: NO_DONEE }, None));
        assert_eq!(collect(h, tid), Collected::Reply(RSP, SERVER), "the client returns it");
    }

    #[test]
    fn exit_of_a_queued_caller_strands_its_cap_for_revocation() {
        let _e = env();
        let (idx, tid) = client(0);
        let _h = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0x7_0002, SERVER).unwrap();
        let c = release_caller(idx, tid).unwrap();
        assert_eq!((c.server, c.moved_cap, c.donee), (SERVER, 0x7_0002, SERVER));
        assert_eq!(accept(SERVER_IDX, SERVER), None);
        assert_eq!(release_caller(idx, tid), None, "once");
    }

    #[test]
    fn ready_mask_serves_two_endpoints() {
        let _e = env();
        open(EP + 1, GEN, SERVER);
        let (idx, tid) = client(0);
        let h = call(idx, tid, EP + 1, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE).unwrap();
        let h2 = call_from(1).unwrap();
        assert_eq!(accept(SERVER_IDX, SERVER).map(|a| a.0), Some(h2), "lowest endpoint first");
        assert_eq!(accept(SERVER_IDX, SERVER).map(|a| a.0), Some(h));
        assert_eq!(accept(SERVER_IDX, SERVER), None);
        assert_eq!(READY[SERVER_IDX][0].load(Ordering::Relaxed), 0, "bits cleared when empty");
    }

    #[test]
    fn handles_reject_bit_63_and_out_of_range_records() {
        assert_eq!(handle_rec(1u64 << 63), None);
        if RECS < (1usize << REC_BITS) {
            assert_eq!(handle_rec(RECS as u64), None);
        }
        assert_eq!(handle_rec(make_handle(3, 5)), Some(3));
        assert_eq!(handle_gen(make_handle(3, 5)), 5);
    }

    // ── Wave 15 N11: reply warrant and badge ────────────────────────────────

    const WORKER: u32 = 31;

    #[test]
    fn a_reply_warrant_moved_to_a_worker_answers_once() {
        let _e = env();
        let (idx, tid) = client(0);
        let h = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, SERVER).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        assert_eq!(delegate(h, WORKER, WORKER), Delegated::Refused, "only the holder moves it");
        assert_eq!(delegate(h, SERVER, WORKER), Delegated::Moved);
        assert_eq!(reply_warrant(h, SERVER, RSP), Reply::Refused, "the server gave it away");
        assert_eq!(reply_warrant(h, WORKER, RSP), Reply::Woke { caller: tid, rec: idx, donee: SERVER },
            "the worker answers; the donation lent to the server is owed back");
        assert_eq!(DELEGATED.load(Ordering::Relaxed), 0);
        assert_eq!(reply_warrant(h, WORKER, [9; WORDS]), Reply::Refused, "a second reply is refused");
        assert_eq!(reply(h, WORKER, false, [9; WORDS]), Reply::Refused, "and on the v1 path too");
        assert_eq!(collect(h, tid), Collected::Reply(RSP, NO_DONEE), "the first answer, intact");
    }

    #[test]
    fn canary_reply_twice_delivers_a_second_reply() {
        let _e = env();
        CANARY_REPLY_TWICE.store(true, Ordering::Relaxed);
        let (idx, tid) = client(0);
        let h = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        assert!(matches!(reply_warrant(h, SERVER, RSP), Reply::Woke { .. }));
        assert!(matches!(reply_warrant(h, SERVER, [9; WORDS]), Reply::Woke { .. }), "the canary bites");
        assert_eq!(collect(h, tid), Collected::Reply([9; WORDS], NO_DONEE), "the answer was overwritten");
    }

    #[test]
    fn a_dead_warrant_holder_completes_the_call_peer_died() {
        let _e = env();
        let (idx, tid) = client(0);
        let h = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        assert_eq!(delegate(h, SERVER, WORKER), Delegated::Moved);
        assert_eq!(release_holder(SERVER, |_| {}), 0, "the server holds nothing now");
        let mut got = Vec::new();
        assert_eq!(release_holder(WORKER, |c| got.push(c.handle)), 1);
        assert_eq!(got, vec![h]);
        assert_eq!(collect(h, tid), Collected::Done(PEER_DIED, NO_DONEE));
        assert_eq!(release_holder(WORKER, |_| {}), 0, "one load once nothing is delegated");
    }

    #[test]
    fn a_v2_call_delivers_its_badge_and_a_v1_call_none() {
        let _e = env();
        let (idx, tid) = client(0);
        stamp_badge(idx, 0xB0B);
        let h = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        assert_eq!(accept_badge(h, WORKER), None, "only the holder reads it");
        assert_eq!(accept_badge(h, SERVER), Some(0xB0B));
        let _ = reply(h, SERVER, false, RSP);
        let _ = collect(h, tid);
        // The same record's next call is v1: unbadged, never the old badge.
        let h2 = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        assert_eq!(accept_badge(h2, SERVER), None);
        let _ = reply(h2, SERVER, false, RSP);
        let _ = collect(h2, tid);
        // A refused v2 call unstamps: the next v1 call is not badged.
        stamp_badge(idx, 7);
        assert_eq!(call(idx, tid, EP, GEN + 1, SERVER, SERVER_IDX, REQ, 0, NO_DONEE), None);
        unstamp_badge(idx);
        let h3 = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        assert_eq!(accept_badge(h3, SERVER), None);
    }
}
