// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-endpoint call queues (wave 15 N5).
//!
//! The fast call (`SYS_IPC_FAST_CALL_EP`) is queued on the endpoint it names,
//! not in one machine-wide table:
//!
//! * **One call record per task slot** (`MAX_TASKS` of them). A caller
//!   blocks for its reply, so a task has at most one call in flight, and the
//!   record is its own: nothing is allocated, nothing can run out before the
//!   tasks do.
//! * **Per endpoint, a send queue**: the calls no server has taken, oldest
//!   first, singly linked through the records, under that endpoint's own
//!   `SpinLock`, always taken with interrupts off (`lock_irqsave`, or
//!   `lock_irqs_off` on the fast path, whose interrupts are already off), so an
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

/// "No donation rides on this call" (same value as `fastcall::NO_DONEE`).
pub const NO_DONEE: u32 = u32::MAX;

/// An endpoint with no serving task (same value as `endpoint::UNCLAIMED`).
pub const UNCLAIMED: u32 = u32::MAX;

/// `Queue::owner` while the endpoint is in a live-update handover
/// ([`begin_handover`]): `Handover(old, new)`, with `old` and `new` in the
/// queue's own fields. A value no task has (a task id is never this), and
/// one no caller passes as an owner: every hot-path check `q.owner == x`
/// (the fast call, the accept) fails on it with no extra load, so during a
/// handover nothing is delivered to either server; only the ordinary
/// [`call`] looks behind it, on the miss.
const HANDOVER: u32 = u32::MAX - 1;

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
const _: () = assert!(core::mem::size_of::<Rec>() == 64, "a call record is 64 B: the v1 path indexes it by a shift");
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
}

/// Wave 15 N11, per record: the badge of the endpoint capability a v2 call
/// went through, valid only while `gen` is the record tag's generation (a
/// v1 call never writes either, so it reads as unbadged, never as the badge
/// of an earlier call). Beside the records, not in them: a `Rec` stays 64 B,
/// so the v1 path's record address is still a shift.
struct Badge {
    badge: AtomicU32,
    gen: AtomicU64,
}

static BADGES: [Badge; RECS] = [const { Badge { badge: AtomicU32::new(0), gen: AtomicU64::new(NO_BADGE_GEN) } }; RECS];

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
        }
    }
}

struct Queue {
    /// Generation of the endpoint open in this slot; 0 = closed.
    gen: u32,
    /// The serving task, [`UNCLAIMED`], or [`HANDOVER`].
    owner: u32,
    /// While `owner` is [`HANDOVER`]: the server being replaced, still the
    /// one the callers resolved, and the one that finishes its calls in
    /// service; and the server that takes the endpoint over at [`rebind`].
    old: u32,
    new: u32,
    /// The send queue: singly linked through `Rec::next`, oldest first.
    send_head: u32,
    send_tail: u32,
}

impl Queue {
    const fn closed() -> Self {
        Queue { gen: 0, owner: UNCLAIMED, old: UNCLAIMED, new: UNCLAIMED, send_head: NIL, send_tail: NIL }
    }

    /// The task whose table the endpoint's queued calls moved their
    /// capabilities into: the owner, or the server being replaced.
    #[inline(always)]
    fn serving(&self) -> u32 {
        if self.owner == HANDOVER { self.old } else { self.owner }
    }
}

const RW: usize = EPS.div_ceil(64);

static RECORDS: [Rec; RECS] = [const { Rec::new() }; RECS];
static QUEUES: [SpinLock<Queue>; EPS] = [const { SpinLock::new(Queue::closed()) }; EPS];
/// Kernel memory one endpoint's call queue takes: its locked queue and its
/// owner word (what `endpoint.rs` charges the Domain that owns it).
pub const QUEUE_BYTES: usize = core::mem::size_of::<SpinLock<Queue>>() + core::mem::size_of::<AtomicU32>();
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

/// Runtime canary `ipc-v1-takes-v2` (wave 15 N11c): the v1 accept takes a
/// v2 call as it did before the owner's decision of 10-10 (its first four
/// words and first capability; the rest stay unnamed in the server's
/// table), so the ktest `ipc_v2_call_refused_by_v1_accept` must fail.
static CANARY_V1_TAKES_V2: AtomicBool = AtomicBool::new(false);

/// Arm the `ipc-v1-takes-v2` canary (runtime `canary=` flag, boot only).
pub fn canary_v1_takes_v2() {
    CANARY_V1_TAKES_V2.store(true, Ordering::Relaxed);
}

/// `badge_gen` of a record no v2 call stamped (no generation reaches it).
const NO_BADGE_GEN: u64 = u64::MAX;

/// Records whose reply warrant was delegated to a task that is not the
/// endpoint's server: the exit sweep looks for a dead holder only when
/// this is not 0. It may over-count, never under-count: a delegated call
/// answered through the v1 reply, withdrawn by its caller, or drained is
/// not subtracted, and every later exit then pays one pass over the
/// records (RECS loads). Wrapping below 0 also only means a pass.
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

// ── Live update: the endpoint changes server without a drain ───────────────

/// Why a handover step was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandoverError {
    /// The slot holds no endpoint of that generation: closed, reused, or a
    /// rebind carrying the generation of an endpoint that is gone.
    Stale,
    /// `old` is not the endpoint's server, or the successor is not a task
    /// (the sentinels) or is `old` itself.
    NotOwner,
    /// The endpoint is not in a handover, or it is one to another successor.
    NotInHandover,
    /// A handover is under way already.
    Busy,
    /// `n` calls of the old server are still in service; [`represent`] them
    /// or wait for their replies.
    InService(usize),
}

/// Test-only canaries (host build): each breaks one check of the handover on
/// purpose, so a test can show the property it guards turns red.
#[cfg(test)]
static BREAK: [AtomicBool; 5] = [const { AtomicBool::new(false) }; 5];
const BREAK_GEN: usize = 0;
const BREAK_IN_SERVICE: usize = 1;
const BREAK_QUIESCE: usize = 2;
const BREAK_REPRESENT: usize = 3;
const BREAK_RETARGET: usize = 4;

#[inline(always)]
fn broken(_k: usize) -> bool {
    #[cfg(test)]
    {
        BREAK[_k].load(Ordering::Relaxed)
    }
    #[cfg(not(test))]
    {
        false
    }
}

/// Calls of `server` in service on endpoint `ep` (state ACCEPTED, the
/// record names `server`). Under the endpoint's lock when called from the
/// steps below; a lock-free count otherwise.
fn count_in_service(ep: usize, server: u32) -> usize {
    RECORDS
        .iter()
        .filter(|r| {
            let t = r.tag.load(Ordering::Acquire);
            tag_ep(t) == ep && tag_state(t) == S_ACCEPTED && r.server.load(Ordering::Relaxed) == server
        })
        .count()
}

/// How many calls `server` has in service on endpoint `ep` right now: what
/// the supervisor waits to reach 0 before [`rebind`] (or [`represent`]s).
pub fn in_service(ep: usize, server: u32) -> usize {
    count_in_service(ep, server)
}

/// Start the handover of endpoint slot `ep` (generation `gen`) from `old`
/// to `new`: `Handover(old, new)`.
///
/// From here: a call queues as before (the callers still resolve `old`; the
/// endpoint's identity word is unchanged until the rebind) but is delivered
/// to nobody: not the fast call (its owner check misses), not `old`'s
/// accept, not `new`'s. The calls `old` has in service are its own to
/// complete: it keeps replying to them. Nothing is drained, no call ends.
pub fn begin_handover(ep: usize, gen: u32, old: u32, new: u32) -> Result<(), HandoverError> {
    let l = QUEUES.get(ep).ok_or(HandoverError::Stale)?;
    let mut q = l.lock_irqsave();
    if q.gen != gen || gen == 0 {
        return Err(HandoverError::Stale);
    }
    if q.owner == HANDOVER {
        return Err(HandoverError::Busy);
    }
    if q.owner != old || old == UNCLAIMED || old == HANDOVER {
        return Err(HandoverError::NotOwner);
    }
    if new == old || new == UNCLAIMED || new == HANDOVER || new == 0 {
        return Err(HandoverError::NotOwner);
    }
    q.owner = HANDOVER;
    q.old = old;
    q.new = new;
    Ok(())
}

/// Hand the calls `old` has in service back to the queue, to be served by
/// the successor: each goes back to PENDING at the head of the send queue
/// (before the calls that arrived during the handover, which came later),
/// in record order. Returns `(re-presented, left in service)`.
///
/// A call is left in service, and `old` must reply to it, when it moved a
/// capability into `old`'s table (the successor takes that table over, but a
/// capability already delivered is not the request it is re-presented as),
/// when it is a v2 call (its capability list is `old`'s; a plain v2 call
/// without capabilities is re-presented), or when `old` has staged its
/// answer. A re-presented call is delivered a second time: the server must
/// treat a call as at-least-once across a handover. The old server's reply
/// to it is refused (the call is PENDING again). A priority donation the call
/// carries stays pointed at `old` (the record's `donee`): it is returned when
/// the successor's reply or the caller's collect ends the call, to a task that
/// may be gone by then. Open: Level 1 does not move it.
pub fn represent(ep: usize, gen: u32, old: u32) -> Result<(usize, usize), HandoverError> {
    let l = QUEUES.get(ep).ok_or(HandoverError::Stale)?;
    let mut q = l.lock_irqsave();
    if q.gen != gen || gen == 0 {
        return Err(HandoverError::Stale);
    }
    if q.owner != HANDOVER || q.old != old {
        return Err(HandoverError::NotInHandover);
    }
    if broken(BREAK_REPRESENT) {
        return Ok((0, 0));
    }
    let (mut moved, mut kept) = (0usize, 0usize);
    // Pushed to the front one by one: walk the records high to low so the
    // lowest record index ends up first.
    for i in (0..RECS).rev() {
        let r = rec(i);
        let t = r.tag.load(Ordering::Relaxed);
        if tag_ep(t) != ep || tag_state(t) != S_ACCEPTED || r.server.load(Ordering::Relaxed) != old {
            continue;
        }
        let g = tag_gen(t);
        let v2 = BADGES[i].gen.load(Ordering::Relaxed) == g;
        let pinned = r.moved_cap.load(Ordering::Relaxed) != 0
            || (v2 && {
                let m = &V2MSGS[i];
                m.gen.load(Ordering::Relaxed) != g || (m.counts.load(Ordering::Relaxed) >> 8) & 0xff != 0
            });
        if pinned {
            kept += 1;
            continue;
        }
        r.server.store(0, Ordering::Relaxed);
        r.tag.store(tag(g, ep as u64, S_PENDING), Ordering::Release);
        r.next.store(q.send_head, Ordering::Relaxed);
        if q.send_head == NIL {
            q.send_tail = i as u32;
        }
        q.send_head = i as u32;
        moved += 1;
    }
    Ok((moved, kept))
}

/// Finish the handover: endpoint slot `ep` (generation `gen`) is served by
/// `new` from now on, `old` is out. The flip is one update under the
/// endpoint's lock, with no drain and without a new generation: every
/// capability to the endpoint, every queued call and every handle stays
/// valid. `old_idx` and `new_idx` are the two servers' task slots (their
/// ready masks): `old`'s bit for `ep` is cleared, and `new`'s is set when
/// calls are queued, so its next accept finds them.
///
/// Refused while `old` still has calls in service (`InService(n)`): they
/// would be left with a server nobody answers for ([`represent`] them, or
/// wait for the replies), and with a generation other than the endpoint's.
///
/// `retarget(caller_idx, donee)` moves the priority donation of every queued
/// call whose donee is `old` (a re-presented call included) to the successor:
/// it returns the call's new donee, [`NO_DONEE`] for none. It runs under the
/// endpoint's lock, so no call queues, is answered or is withdrawn meanwhile,
/// and the flip and the donations change together; it takes the wait graph's
/// lock (queue lock, then graph lock, as nothing takes them the other way).
pub fn rebind(
    ep: usize, gen: u32, new: u32, old_idx: usize, new_idx: usize, mut retarget: impl FnMut(usize, u32) -> u32,
) -> Result<(), HandoverError> {
    let l = QUEUES.get(ep).ok_or(HandoverError::Stale)?;
    let mut q = l.lock_irqsave();
    rebind_refusal(&q, ep, gen, new)?;
    let old = q.old;
    let mut p = q.send_head;
    while p != NIL {
        let r = rec(p as usize);
        if r.donee.load(Ordering::Relaxed) == old && !broken(BREAK_RETARGET) {
            r.donee.store(retarget(p as usize, old), Ordering::Relaxed);
        }
        p = r.next.load(Ordering::Relaxed);
    }
    q.owner = new;
    q.old = UNCLAIMED;
    q.new = UNCLAIMED;
    OWNERS[ep].store(new, Ordering::Relaxed);
    ready_clear(old_idx, ep);
    if q.send_head != NIL && !broken(BREAK_QUIESCE) {
        ready_set(new_idx, ep);
    }
    Ok(())
}

/// Would [`rebind`] refuse slot `ep` now? The same answer, nothing changed:
/// the endpoint layer asks it of every endpoint before it flips the first
/// one, so a set of endpoints moves to the successor whole or not at all.
/// The answer holds while the caller keeps `ENDPOINTS`: the generation and
/// the handover change only under it, and nothing accepts during a handover
/// (`take_locked` wants `owner == server`), so the calls in service only fall.
pub fn rebind_check(ep: usize, gen: u32, new: u32) -> Result<(), HandoverError> {
    let l = QUEUES.get(ep).ok_or(HandoverError::Stale)?;
    let q = l.lock_irqsave();
    rebind_refusal(&q, ep, gen, new)
}

/// [`rebind`]'s refusals: one test for it and for [`rebind_check`].
fn rebind_refusal(q: &Queue, ep: usize, gen: u32, new: u32) -> Result<(), HandoverError> {
    // Canary: the generation is not compared, so a rebind aimed at an
    // earlier endpoint of this slot flips the present one.
    if (q.gen != gen && !broken(BREAK_GEN)) || q.gen == 0 {
        return Err(HandoverError::Stale);
    }
    if q.owner != HANDOVER || q.new != new {
        return Err(HandoverError::NotInHandover);
    }
    let n = count_in_service(ep, q.old);
    if n != 0 && !broken(BREAK_IN_SERVICE) {
        return Err(HandoverError::InService(n));
    }
    Ok(())
}

/// Give up a handover that has not been rebound: `old` serves again, the
/// queued calls are delivered to it as if nothing had happened.
pub fn abort_handover(ep: usize, gen: u32, old_idx: usize) -> Result<(), HandoverError> {
    let l = QUEUES.get(ep).ok_or(HandoverError::Stale)?;
    let mut q = l.lock_irqsave();
    if q.gen != gen || gen == 0 {
        return Err(HandoverError::Stale);
    }
    if q.owner != HANDOVER {
        return Err(HandoverError::NotInHandover);
    }
    q.owner = q.old;
    q.old = UNCLAIMED;
    q.new = UNCLAIMED;
    if q.send_head != NIL {
        ready_set(old_idx, ep);
    }
    Ok(())
}

/// Endpoint slot `ep` is in a handover to `new` (the endpoint layer's check
/// that a claim is the designated successor's).
pub fn handing_over_to(ep: usize, new: u32) -> bool {
    QUEUES.get(ep).is_some_and(|l| {
        let q = l.lock_irqsave();
        q.owner == HANDOVER && q.new == new
    })
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
    /// A v2 call's capabilities (`v2_caps[..n_v2_caps]`, the handles they
    /// took in `server`'s table; `v2_caps[0]` is `moved_cap`), for the same
    /// revocation: a v2 call moves up to `V2_CAPS`, not one. 0 for a v1 call
    /// and wherever `moved_cap` is 0.
    pub n_v2_caps: u8,
    pub v2_caps: [u32; V2_CAPS],
}

impl Completed {
    /// Every capability stranded in `server`'s table that the sweep must
    /// revoke: the v2 call's list, or the v1 call's one `moved_cap`.
    pub fn stranded(&self) -> impl Iterator<Item = u32> + '_ {
        let v1 = (self.n_v2_caps == 0 && self.moved_cap != 0).then_some(self.moved_cap);
        self.v2_caps.iter().take(self.n_v2_caps as usize).copied().filter(|&h| h != 0).chain(v1)
    }
}

/// The capabilities of record `i`'s v2 request of generation `gen`, taken
/// once (the request slot is retired, so no second sweep revokes them
/// again): `(count, handles in the server's table)`; `(0, _)` for a v1 call.
/// Under the record's endpoint lock, before the record is freed.
fn take_v2_caps(i: usize, gen: u64) -> (u8, [u32; V2_CAPS]) {
    let mut caps = [0u32; V2_CAPS];
    let Some(m) = V2MSGS.get(i) else { return (0, caps) };
    if m.gen.load(Ordering::Relaxed) != gen {
        return (0, caps);
    }
    let p = get_msg(m);
    m.gen.store(NO_BADGE_GEN, Ordering::Relaxed);
    caps = p.caps;
    (p.n_caps, caps)
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
    // A queued v2 call's every capability, not only the first (`moved`).
    let (n_v2_caps, v2_caps) = if pending { take_v2_caps(i, tag_gen(t)) } else { (0, [0; V2_CAPS]) };
    r.tag.store(tag(tag_gen(t), ep as u64, S_DONE), Ordering::Release);
    Completed {
        caller: r.caller.load(Ordering::Relaxed),
        handle: make_handle(i, tag_gen(t)),
        donee,
        server,
        moved_cap: moved,
        n_v2_caps,
        v2_caps,
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
    pub const EV1ACCEPT: i64 = azos_abi::error::Errno::EV1ACCEPT as i64;
}
#[cfg(not(target_os = "none"))]
mod azos_abi_errno {
    pub const EPEERDIED: i64 = 211;
    pub const EREVOKED: i64 = 212;
    pub const EV1ACCEPT: i64 = 215;
}

/// `-EV1ACCEPT`: a v2 call taken by the v1 accept, refused there (owner
/// decision 10-10): the server never sees it, and the caller gives every
/// capability it moved back to itself (`azos_syscall::ipc_v2`).
pub const V1_ACCEPT: i32 = -(azos_abi_errno::EV1ACCEPT as i32);

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
    // A handover is looked behind only on a miss: the callers resolved the
    // server being replaced (the endpoint's identity word names it until the
    // rebind publishes the successor), or, across that flip, the successor;
    // their calls queue for the successor.
    if q.gen != gen || gen == 0 || (q.owner != owner && !(q.owner == HANDOVER && (q.old == owner || q.new == owner))) {
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

/// Record `i` (tag `t`, under its endpoint's lock) holds a v2 call that the
/// v1 accept must refuse: [`stamp_badge`] wrote its generation before
/// [`call`] published it, and every free advances the generation, so a v1
/// call never matches. The canary is read only for a v2 record.
#[inline(always)]
fn v1_refuses(i: usize, t: u64) -> bool {
    BADGES.get(i).is_some_and(|b| b.gen.load(Ordering::Relaxed) == tag_gen(t))
        && !CANARY_V1_TAKES_V2.load(Ordering::Relaxed)
}

/// Under `q` (endpoint slot `ep`): take the oldest queued call for server
/// `server` (task slot `server_idx`), or clear `ep`'s ready bit when there is
/// none for it.
///
/// `V1` is the v1 accept (110, 580): a v2 call it pops is not taken but
/// completed [`V1_ACCEPT`] (state DONE) into `refused`, for the caller of
/// this function to wake once the lock is released. The v2 accept (`V1 =
/// false`) takes every call.
#[inline(always)]
fn take_locked<const V1: bool>(
    q: &mut Queue, ep: usize, server_idx: usize, server: u32, refused: &mut Option<Completed>,
) -> Option<Accepted> {
    if q.gen == 0 || q.owner != server || q.send_head == NIL {
        ready_clear(server_idx, ep);
        return None;
    }
    let i = pop_send(q);
    if q.send_head == NIL {
        ready_clear(server_idx, ep);
    }
    let r = rec(i);
    let t = r.tag.load(Ordering::Relaxed);
    if V1 && v1_refuses(i, t) {
        // `pending = false`: the moved capabilities stay where they are (the
        // server's table) for the caller to take back, not to be revoked.
        // The record names that table, for a caller that exits before it
        // collects ([`release_caller`] revokes them then).
        r.server.store(server, Ordering::Relaxed);
        *refused = Some(complete_locked(i, ep, V1_ACCEPT, server, false));
        return None;
    }
    r.server.store(server, Ordering::Relaxed);
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
///
/// `V1`: the v1 accept, which refuses a v2 call (see [`take_locked`]);
/// `refused` is called once for each, with no queue lock held, and must
/// wake its caller (and return its donation). The scan then goes on.
#[inline]
pub fn accept<const V1: bool>(server_idx: usize, server: u32, mut refused: impl FnMut(Completed)) -> Option<Accepted> {
    let masks = READY.get(server_idx)?;
    for (w, word) in masks.iter().enumerate() {
        let mut m = word.load(Ordering::Acquire);
        while m != 0 {
            let ep = w * 64 + m.trailing_zeros() as usize;
            m &= m - 1;
            loop {
                let mut c = None;
                let a = take_ep::<V1>(ep, server_idx, server, &mut c);
                if a.is_some() {
                    return a;
                }
                match c {
                    // The next call queued here may be one to take.
                    Some(c) => refused(c),
                    None => break,
                }
            }
        }
    }
    None
}

/// [`take_locked`] on endpoint slot `ep`, with its lock. Out of line: the
/// lock's code inlined into [`accept`]'s loop made that loop save every
/// callee-saved register on entry.
#[inline(never)]
fn take_ep<const V1: bool>(ep: usize, server_idx: usize, server: u32, refused: &mut Option<Completed>) -> Option<Accepted> {
    let l = QUEUES.get(ep)?;
    let mut q = l.lock_irqsave();
    take_locked::<V1>(&mut q, ep, server_idx, server, refused)
}

/// Outcome of a reply (same meaning as `fastcall::FastIpcReply`).
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
    // handle is stale (no generation oracle; see `fastcall::FastIpcReply`).
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
/// `fastcall::reply_then_accept`), and a server with calls queued
/// on another of its endpoints takes the next one there.
pub fn reply_then_accept(
    handle: u64,
    replier: u32,
    privileged: bool,
    words: [u64; WORDS],
    server_idx: usize,
    refused: impl FnMut(Completed),
) -> (Reply, Option<Accepted>) {
    let Some(i) = handle_rec(handle) else { return (Reply::Refused, None) };
    let Some((ep, t, mut q)) = lock_rec(i) else { return (Reply::Refused, None) };
    // A next call queued here for this server: its bit is in the server's
    // ready mask (set by the call that found the queue empty), so an empty
    // mask answers "none anywhere" with one load.
    let any = ready_any(server_idx);
    let here = any && q.gen != 0 && q.owner == replier && q.send_head != NIL;
    // This is the v1 accept: a v2 call at the head is refused, which cannot
    // happen in this hold (its caller is woken with no lock held), so the
    // answer keeps the donation as when the next call is elsewhere, and
    // `accept` below refuses it and goes on.
    let here = here && {
        let h = q.send_head as usize;
        !v1_refuses(h, rec(h).tag.load(Ordering::Relaxed))
    };
    let r = reply_locked(&mut q, i, t, handle_gen(handle), replier, privileged, words, !here);
    if !matches!(r, Reply::Woke { .. }) {
        return (r, None);
    }
    if here {
        // The head was checked in this hold: take it as the v2 accept would.
        return (r, take_locked::<false>(&mut q, ep, server_idx, replier, &mut None));
    }
    drop(q);
    (r, if any { accept::<true>(server_idx, replier, refused) } else { None })
}

// ── The IPC fast path (Kconfig IPC_FASTPATH, Chain E stage a) ──────────────
//
// `azos_syscall::fastpath` finishes a call or a reply whose peer is parked in
// the matching wait without the endpoint queue. Both halves below do the
// record work the ordinary path does, in one hold of the endpoint's lock, and
// hand the peer's claim (the scheduler's `Blocked -> Ready` CAS, through the
// [`Claim`] trait so this file still names no scheduler) the last word under
// that lock: a claim that fails leaves nothing written, and a claim that
// succeeds keeps the peer off every CPU until the caller of these functions
// switches to it or enqueues it, so what is written after the claim is
// visible to it.

/// The fast path's claim of the parked peer in task slot `slot` (the
/// server's for [`fast_call`], the caller's for [`fast_reply`]): the
/// scheduler's `Blocked -> Ready` CAS, given by the caller of these
/// functions. A trait and not a closure so its implementation can be
/// `#[inline(always)]`: a closure's body is a call of its own under the lock.
pub trait Claim {
    /// Claim the task in slot `slot`; `false` leaves it untouched.
    fn claim(&mut self, slot: usize) -> bool;
    /// Asked by [`fast_call`] once [`Claim::claim`] succeeded, still under
    /// the lock, with the call made (its record ACCEPTED, `handle`, from
    /// `caller`, `words`): hand it to the claimed server directly, as its
    /// accept's own take of the deposit would (Chain E commit 9, the server's
    /// resume point). `true`: handed, and no deposit is left; the record stays
    /// ACCEPTED, in that server's service, as after a take. The default hands
    /// nothing.
    #[inline(always)]
    fn hand_call(&mut self, handle: u64, caller: u32, words: &[u64; WORDS]) -> bool {
        let _ = (handle, caller, words);
        false
    }
    /// Asked by [`fast_reply`] once [`Claim::claim`] succeeded, still under
    /// the lock, for a call that carries no donation: hand `words` to the
    /// claimed caller directly, as its collect would (Chain E commit 9, the
    /// caller's resume point). `true`: handed, and the record is freed as that
    /// collect frees it, never published REPLIED. The default hands nothing.
    #[inline(always)]
    fn hand_reply(&mut self, words: &[u64; WORDS]) -> bool {
        let _ = words;
        false
    }
}

/// No deposit (a handle is a non-negative `i64`, so this is never one).
const NO_DEPOSIT: u64 = u64::MAX;

/// Per server task slot: the handle of a call the fast path accepted on the
/// server's behalf while it was parked in its accept, for that accept to take
/// when it resumes ([`take_deposit`]). At most one at a time: the server is
/// claimed (no longer `Blocked`) from the deposit until it takes it, and only
/// a parked server is deposited to.
static DEPOSIT: [AtomicU64; RECS] = [const { AtomicU64::new(NO_DEPOSIT) }; RECS];

/// The fast path's call: queue nothing, but write `caller`'s record (task
/// slot `caller_idx`) as already ACCEPTED by `owner` (task slot `owner_idx`)
/// on endpoint slot `ep` of generation `gen`, with `donee` (the wait-graph
/// edge's token, or [`NO_DONEE`]: the fast path lends no counted donation),
/// and deposit its handle for the server, or hand it to the server directly
/// ([`Claim::hand_call`]). Exactly what [`call`] then [`take_locked`] would
/// leave, with no list or ready-mask work: the call is on no list either way
/// once accepted.
///
/// Refused (`None`, nothing written) unless, under the endpoint's lock: the
/// endpoint still holds `gen` served by `owner`, nothing is queued on it, the
/// server has no call queued on any endpoint (its ready mask is empty: FIFO),
/// the caller's record is free, and `claim` of `owner_idx` succeeded.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn fast_call(
    caller_idx: usize,
    caller: u32,
    ep: usize,
    gen: u32,
    owner: u32,
    owner_idx: usize,
    words: [u64; WORDS],
    donee: u32,
    mut claim: impl Claim,
) -> Option<u64> {
    let r = RECORDS.get(caller_idx)?;
    let l = QUEUES.get(ep)?;
    let d = DEPOSIT.get(owner_idx)?;
    let t = r.tag.load(Ordering::Relaxed);
    if tag_state(t) != S_FREE || gen == 0 {
        return None;
    }
    let g = tag_gen(t);
    // Interrupts are off (the fast path's, from before the claim to the
    // switch): the bare lock, see `SpinLock::lock_irqs_off`.
    let q = l.lock_irqs_off();
    if q.gen != gen || q.owner != owner || q.send_head != NIL || ready_any(owner_idx) || !claim.claim(owner_idx) {
        return None;
    }
    r.caller.store(caller, Ordering::Relaxed);
    r.server.store(owner, Ordering::Relaxed);
    for (d, s) in r.words.iter().zip(words) {
        d.store(s, Ordering::Relaxed);
    }
    r.moved_cap.store(0, Ordering::Relaxed);
    r.donee.store(donee, Ordering::Relaxed);
    // Release: the drain's lock-free scan reads the tag with Acquire.
    r.tag.store(tag(g, ep as u64, S_ACCEPTED), Ordering::Release);
    let h = make_handle(caller_idx, g);
    if !claim.hand_call(h, caller, &words) {
        d.store(h, Ordering::Relaxed);
    }
    drop(q);
    Some(h)
}

/// The fast path's reply: `replier` (task slot `replier_idx`) answers the
/// call `handle` names with `words`, exactly as [`reply_then_accept`] does
/// when no next call is waiting for it (the donation stays in the record
/// for the client to return when it collects), or, for a call without a
/// donation, hands the answer to the claimed caller directly and frees the
/// record as its collect would ([`Claim::hand_reply`]). With `token` (the
/// wait graph's call edge: the record's donee is the edge's token, which
/// the caller does not return) every call may be handed. Returns the
/// caller's task slot (its record's index), its TID, and the record's donee,
/// which the caller of this function retires.
///
/// Refused (`None`, nothing written) unless, under the endpoint's lock: the
/// call is the one `handle` names, ACCEPTED, and `replier` holds its reply
/// warrant (no privileged override: a kernel task answering another's call
/// takes the ordinary path); `replier` has no call queued on any endpoint
/// (else the ordinary path takes it at once); and `claim` of the caller's
/// slot (the record's index) succeeded.
#[inline(always)]
pub fn fast_reply(
    handle: u64,
    replier: u32,
    replier_idx: usize,
    words: [u64; WORDS],
    token: bool,
    mut claim: impl Claim,
) -> Option<(usize, u32, u32)> {
    let i = handle_rec(handle)?;
    let r = rec(i);
    let t = r.tag.load(Ordering::Acquire);
    if tag_state(t) != S_ACCEPTED || tag_gen(t) != handle_gen(handle) {
        return None;
    }
    let l = QUEUES.get(tag_ep(t))?;
    // Interrupts are off, as in `fast_call`.
    let q = l.lock_irqs_off();
    let caller = r.caller.load(Ordering::Relaxed);
    if r.tag.load(Ordering::Relaxed) != t
        || r.server.load(Ordering::Relaxed) != replier
        || ready_any(replier_idx)
        || !claim.claim(i)
    {
        return None;
    }
    // A donation is the caller's collect's to return: such a call is
    // answered through the record. A wait-graph token is not returned.
    let donee = r.donee.load(Ordering::Relaxed);
    if (token || donee == NO_DONEE) && claim.hand_reply(&words) {
        free(i, tag_gen(t));
    } else {
        for (d, s) in r.words.iter().zip(words) {
            d.store(s, Ordering::Relaxed);
        }
        r.tag.store(tag(tag_gen(t), tag_ep(t) as u64, S_REPLIED), Ordering::Release);
    }
    drop(q);
    Some((i, caller, donee))
}

/// The call [`fast_call`] deposited for `server` (task slot `server_idx`),
/// taken once: its record index and handle, or `None`. A deposit whose call
/// ended meanwhile (its caller withdrew or died, or its endpoint was drained)
/// is dropped: the record's generation, state or server no longer match, and
/// the server goes on to its ordinary accept as if the call had never come.
#[inline(always)]
pub fn take_deposit(server_idx: usize, server: u32) -> Option<(usize, u64)> {
    let d = DEPOSIT.get(server_idx)?;
    if d.load(Ordering::Relaxed) == NO_DEPOSIT {
        return None;
    }
    let h = d.swap(NO_DEPOSIT, Ordering::Acquire);
    let i = handle_rec(h)?;
    let r = rec(i);
    let t = r.tag.load(Ordering::Acquire);
    if tag_state(t) != S_ACCEPTED || tag_gen(t) != handle_gen(h) || r.server.load(Ordering::Relaxed) != server {
        return None;
    }
    Some((i, h))
}

/// Word `k` of record `i`'s message and its caller, for the server that
/// just took the record's call with [`take_deposit`].
#[inline(always)]
pub fn deposit_word(i: usize, k: usize) -> u64 {
    rec(i).words[k & (WORDS - 1)].load(Ordering::Relaxed)
}

/// The caller of record `i` (see [`deposit_word`]).
#[inline(always)]
pub fn deposit_caller(i: usize) -> u32 {
    rec(i).caller.load(Ordering::Relaxed)
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
/// `fastcall::FastIpcWait`): 0 gone, 1 waiting, 2 ready. Lock-free: one
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
/// capabilities, [`Completed::stranded`], belong to `server`; `donee` is
/// the dying caller's donation to give back).
///
/// A call no server took strands every capability it moved: a queued one
/// in the endpoint owner's table, and one the v1 accept refused
/// ([`V1_ACCEPT`], not yet collected) in the table of the server that
/// refused it. A call a server accepted, or answered, strands none (the
/// request's capabilities were delivered; the answer's are in the dying
/// caller's own table).
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
    if pending {
        unlink_send(&mut q, idx);
    }
    let refused = tag_state(t) == S_DONE
        && r.status.load(Ordering::Relaxed) == V1_ACCEPT;
    let strands = pending || refused;
    let (n_v2_caps, v2_caps) = if strands { take_v2_caps(idx, tag_gen(t)) } else { (0, [0; V2_CAPS]) };
    let c = Completed {
        caller: tid,
        handle: make_handle(idx, tag_gen(t)),
        donee: r.donee.swap(NO_DONEE, Ordering::Relaxed),
        server: if pending {
            q.serving()
        } else if refused {
            r.server.load(Ordering::Relaxed)
        } else {
            0
        },
        moved_cap: if strands { r.moved_cap.load(Ordering::Relaxed) } else { 0 },
        n_v2_caps,
        v2_caps,
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
    let (Some(r), Some(b)) = (RECORDS.get(caller_idx), BADGES.get(caller_idx)) else { return };
    let t = r.tag.load(Ordering::Relaxed);
    b.badge.store(badge, Ordering::Relaxed);
    b.gen.store(tag_gen(t), Ordering::Relaxed);
}

/// A v2 call stamped with [`stamp_badge`] was refused: unstamp.
pub fn unstamp_badge(caller_idx: usize) {
    if let Some(b) = BADGES.get(caller_idx) {
        b.gen.store(NO_BADGE_GEN, Ordering::Relaxed);
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
    let b = &BADGES[i];
    if b.gen.load(Ordering::Relaxed) != tag_gen(t) {
        return None;
    }
    Some(b.badge.load(Ordering::Relaxed))
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
    let owner = q.serving();
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
    let delegated = tag_state(t) == S_ACCEPTED && r.server.load(Ordering::Relaxed) != q.serving();
    let out = reply_locked(&mut q, i, t, handle_gen(handle), holder, false, words, false);
    if delegated && matches!(out, Reply::Woke { .. }) {
        DELEGATED.fetch_sub(1, Ordering::Relaxed);
    }
    out
}

// ── Wave 15 N11b: the v2 message beyond the record's four words ────────────

/// Kconfig `IPC_MSG_INLINE_WORDS`: inline words one v2 message carries.
/// The host build uses the descriptor's ABI ceiling (8).
#[cfg(target_os = "none")]
pub const V2_WORDS: usize = azos_limits::IPC_MSG_INLINE_WORDS as usize;
#[cfg(not(target_os = "none"))]
pub const V2_WORDS: usize = 8;
/// Kconfig `IPC_MSG_MAX_CAPS`: capability entries one v2 message carries.
/// The host build uses the descriptor's ABI ceiling (8).
#[cfg(target_os = "none")]
pub const V2_CAPS: usize = azos_limits::IPC_MSG_MAX_CAPS as usize;
#[cfg(not(target_os = "none"))]
pub const V2_CAPS: usize = 8;

/// A v2 message as it waits in its record: the inline words and the
/// receiver's handles of the capabilities moved with it (the move happened
/// in the sender's trap, before the message was published).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Payload {
    /// Inline words used, `0..=V2_WORDS`.
    pub n_words: u8,
    /// Capability handles used, `0..=V2_CAPS`.
    pub n_caps: u8,
    /// Inline data.
    pub words: [u64; V2_WORDS],
    /// The receiver's handles.
    pub caps: [u32; V2_CAPS],
    /// The caller's deadline (`MsgDesc::deadline`): absolute ns on
    /// `clock_id`, 0 = none. Carried so the server reads it (deadline
    /// inheritance); an answer carries none.
    pub deadline: u64,
    /// The clock `deadline` is on (`ClockId` raw value, 0 = MONO).
    pub clock_id: u32,
    /// The provenance label (`MsgDesc::label`): the sender's own principal
    /// already ORed in by the syscall layer. Travels with the message in
    /// both directions, so the server reads the union in the request and the
    /// caller in the answer (innovation B4).
    pub label: u32,
}

impl Payload {
    /// No words, no capabilities, no deadline, no label.
    pub const EMPTY: Self = Payload {
        n_words: 0, n_caps: 0, words: [0; V2_WORDS], caps: [0; V2_CAPS], deadline: 0, clock_id: 0, label: 0,
    };
}

/// Per record, beside it like [`BADGES`]: the v2 request (valid while `gen`
/// is the record's generation) and then the v2 answer (`gen` with
/// [`REPLY_MARK`]). One slot serves both: the request is read on accept,
/// before any answer can be staged. A v1 call never writes it.
struct V2Msg {
    gen: AtomicU64,
    counts: AtomicU32,
    words: [AtomicU64; V2_WORDS],
    caps: [AtomicU32; V2_CAPS],
    deadline: AtomicU64,
    clock_id: AtomicU32,
    label: AtomicU32,
}

static V2MSGS: [V2Msg; RECS] = [const {
    V2Msg {
        gen: AtomicU64::new(NO_BADGE_GEN),
        counts: AtomicU32::new(0),
        words: [const { AtomicU64::new(0) }; V2_WORDS],
        caps: [const { AtomicU32::new(0) }; V2_CAPS],
        deadline: AtomicU64::new(0),
        clock_id: AtomicU32::new(0),
        label: AtomicU32::new(0),
    }
}; RECS];

/// Marks a [`V2Msg`] that holds an answer, not a request.
const REPLY_MARK: u64 = 1 << 63;

fn put_msg(m: &V2Msg, p: &Payload, gen: u64) {
    let nw = (p.n_words as usize).min(V2_WORDS);
    let nc = (p.n_caps as usize).min(V2_CAPS);
    for (d, s) in m.words.iter().zip(p.words.iter()).take(nw) {
        d.store(*s, Ordering::Relaxed);
    }
    for (d, s) in m.caps.iter().zip(p.caps.iter()).take(nc) {
        d.store(*s, Ordering::Relaxed);
    }
    m.deadline.store(p.deadline, Ordering::Relaxed);
    m.clock_id.store(p.clock_id, Ordering::Relaxed);
    m.label.store(p.label, Ordering::Relaxed);
    m.counts.store(nw as u32 | (nc as u32) << 8, Ordering::Relaxed);
    m.gen.store(gen, Ordering::Relaxed);
}

fn get_msg(m: &V2Msg) -> Payload {
    let c = m.counts.load(Ordering::Relaxed);
    let mut p = Payload::EMPTY;
    p.deadline = m.deadline.load(Ordering::Relaxed);
    p.clock_id = m.clock_id.load(Ordering::Relaxed);
    p.label = m.label.load(Ordering::Relaxed);
    p.n_words = ((c & 0xff) as usize).min(V2_WORDS) as u8;
    p.n_caps = (((c >> 8) & 0xff) as usize).min(V2_CAPS) as u8;
    for (d, s) in p.words.iter_mut().zip(m.words.iter()).take(p.n_words as usize) {
        *d = s.load(Ordering::Relaxed);
    }
    for (d, s) in p.caps.iter_mut().zip(m.caps.iter()).take(p.n_caps as usize) {
        *d = s.load(Ordering::Relaxed);
    }
    p
}

/// Before a v2 call by the task in slot `caller_idx`: its message, beside
/// the badge [`stamp_badge`] writes (same rule: written while the record is
/// free, published by [`call`]'s hold of the queue lock).
pub fn stamp_msg(caller_idx: usize, p: &Payload) {
    let (Some(r), Some(m)) = (RECORDS.get(caller_idx), V2MSGS.get(caller_idx)) else { return };
    put_msg(m, p, tag_gen(r.tag.load(Ordering::Relaxed)));
}

/// A v2 call stamped with [`stamp_msg`] was refused: unstamp.
pub fn unstamp_msg(caller_idx: usize) {
    if let Some(m) = V2MSGS.get(caller_idx) {
        m.gen.store(NO_BADGE_GEN, Ordering::Relaxed);
    }
}

/// The v2 request of the call `handle` names, for the holder of its reply
/// warrant right after it accepted it; `None` for a v1 call, an answered
/// one, or a task that does not hold the warrant.
pub fn accept_msg(handle: u64, holder: u32) -> Option<Payload> {
    let i = handle_rec(handle)?;
    let r = rec(i);
    let t = r.tag.load(Ordering::Acquire);
    if tag_state(t) != S_ACCEPTED || tag_gen(t) != handle_gen(handle) || r.server.load(Ordering::Relaxed) != holder {
        return None;
    }
    let m = &V2MSGS[i];
    if m.gen.load(Ordering::Relaxed) != tag_gen(t) {
        return None;
    }
    Some(get_msg(m))
}

/// The caller of the call `handle` names, and whether it is a v2 call, when
/// `holder` holds its reply warrant and it is unanswered; else `None`.
pub fn warrant_peer(handle: u64, holder: u32) -> Option<(u32, bool)> {
    let i = handle_rec(handle)?;
    let (_, t, q) = lock_rec(i)?;
    let r = rec(i);
    if tag_state(t) != S_ACCEPTED || tag_gen(t) != handle_gen(handle) || r.server.load(Ordering::Relaxed) != holder {
        return None;
    }
    let v2 = BADGES[i].gen.load(Ordering::Relaxed) == tag_gen(t);
    let caller = r.caller.load(Ordering::Relaxed);
    drop(q);
    Some((caller, v2))
}

/// Stage the v2 answer `p` to the call `handle` names, as the holder of its
/// warrant; the answer itself is published by the [`reply_warrant`] that
/// must follow (its hold of the lock orders these stores before the state a
/// collect reads). `false` when `holder` does not hold an unanswered call.
pub fn stage_reply(handle: u64, holder: u32, p: &Payload) -> bool {
    let Some(i) = handle_rec(handle) else { return false };
    let Some((_, t, q)) = lock_rec(i) else { return false };
    let r = rec(i);
    if tag_state(t) != S_ACCEPTED || tag_gen(t) != handle_gen(handle) || r.server.load(Ordering::Relaxed) != holder {
        return false;
    }
    put_msg(&V2MSGS[i], p, tag_gen(t) | REPLY_MARK);
    drop(q);
    true
}

/// After [`collect`] gave the task in slot `caller_idx` the answer to
/// `handle`: the v2 answer staged for it, once; `None` when the answer was
/// a v1 reply (its four words are the whole answer).
pub fn take_reply(caller_idx: usize, handle: u64) -> Option<Payload> {
    let m = V2MSGS.get(caller_idx)?;
    if handle_rec(handle) != Some(caller_idx) || m.gen.load(Ordering::Acquire) != handle_gen(handle) | REPLY_MARK {
        return None;
    }
    let p = get_msg(m);
    m.gen.store(NO_BADGE_GEN, Ordering::Relaxed);
    Some(p)
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
        if tag_state(t) != S_ACCEPTED || r.server.load(Ordering::Relaxed) != tid || q.serving() == tid {
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
        pub fn lock_irqs_off(&self) -> Guard<'_, T> {
            self.lock_irqsave()
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
        for d in DEPOSIT.iter() {
            d.store(NO_DEPOSIT, Ordering::Relaxed);
        }
        CANARY_NO_PEER_DIED.store(false, Ordering::Relaxed);
        CANARY_REPLY_TWICE.store(false, Ordering::Relaxed);
        CANARY_V1_TAKES_V2.store(false, Ordering::Relaxed);
        DELEGATED.store(0, Ordering::Relaxed);
        for b in BREAK.iter() {
            b.store(false, Ordering::Relaxed);
        }
        open(EP, GEN, SERVER);
        g
    }

    /// The v1 accept, with refusals dropped (a test collects them itself).
    fn accept(server_idx: usize, server: u32) -> Option<Accepted> {
        super::accept::<true>(server_idx, server, |_| {})
    }

    /// The v2 accept: takes every call.
    fn accept_v2(server_idx: usize, server: u32) -> Option<Accepted> {
        super::accept::<false>(server_idx, server, |_| panic!("the v2 accept refuses nothing"))
    }

    fn reply_then_accept(
        handle: u64, replier: u32, privileged: bool, words: [u64; WORDS], server_idx: usize,
    ) -> (Reply, Option<Accepted>) {
        super::reply_then_accept(handle, replier, privileged, words, server_idx, |_| {})
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

    /// More calls in flight than any fixed table would hold: 150 callers queue on one endpoint and every
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
        let want = Completed {
            caller: tid, handle: h, donee: SERVER, server: SERVER, moved_cap: 0x5_0001, n_v2_caps: 0, v2_caps: [0; V2_CAPS],
        };
        assert_eq!(seen, vec![want]);
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

    /// **A call is handed to the thread the endpoint is stamped with, and to no
    /// other thread of that process.** A thread a server creates is a task of its
    /// own (a slot and a TID of its own): the topology's `READ` grant stamped the
    /// endpoint with the TID the program started as, the call queues on that
    /// task's ready mask, and an accept by the sibling finds nothing, for as long
    /// as the call waits. `INPUTD.ELF` accepted on the thread it created, and
    /// every `input status` waited for ever. A server serves on the thread it
    /// started as and gives the other work (a poller, a worker that answers by
    /// `SYS_IPC_REPLY_DELEGATE`) to the threads it creates.
    ///
    /// **Canary.** Make `accept` read the ready mask of slot `server_idx | 1`
    /// and `take_locked` stop comparing `q.owner` with `server`: the sibling
    /// (slot 2, TID 8) takes the call and the first assertion is red.
    #[test]
    fn a_thread_the_server_created_takes_no_call_of_the_stamped_endpoint() {
        let _e = env();
        const SIBLING_IDX: usize = SERVER_IDX - 1;
        const SIBLING: u32 = SERVER + 1;
        let (idx, tid) = client(0);
        let h = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE).unwrap();
        assert_eq!(accept_v2(SIBLING_IDX, SIBLING), None, "the thread the server created is not the one the endpoint is stamped with");
        assert_eq!(wait_state(h, tid), 1, "the caller still waits: nothing took the call");
        assert_eq!(accept_v2(SERVER_IDX, SERVER).map(|a| a.0), Some(h), "the stamped thread takes it, nothing lost");
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
        let _ = accept_v2(SERVER_IDX, SERVER).unwrap();
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

    // ── Wave 15 N11b: the v2 message ────────────────────────────────────────

    fn payload(seed: u64) -> Payload {
        let mut p = Payload::EMPTY;
        p.n_words = V2_WORDS as u8;
        p.n_caps = V2_CAPS as u8;
        for (k, w) in p.words.iter_mut().enumerate() {
            *w = seed + k as u64;
        }
        for (k, c) in p.caps.iter_mut().enumerate() {
            *c = seed as u32 + 0x100 + k as u32;
        }
        // The caller's deadline and clock travel with the message (the
        // queue carries any `clock_id`; the syscall layer refuses non-MONO).
        p.deadline = 0x1000_0000_0000 + seed;
        p.clock_id = 0x0300_0000 + seed as u32;
        p
    }

    /// Innovation B4, the fast path: the provenance label rides in the
    /// record beside the words. The server reads the caller's in the request,
    /// the caller reads the server's in the answer, and neither leaks into
    /// the record's next call. **Canary.** Skip the `label` store in
    /// `put_msg`: the request assertion goes red; skip the load in
    /// `get_msg`: both do.
    #[test]
    fn the_label_travels_with_the_request_and_the_answer() {
        let _e = env();
        let (idx, tid) = client(0);
        let mut req = payload(0x10);
        req.label = 0b1010;
        stamp_msg(idx, &req);
        let h = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE).unwrap();
        let _ = accept_v2(SERVER_IDX, SERVER).unwrap();
        assert_eq!(accept_msg(h, SERVER).unwrap().label, 0b1010, "the server reads the label of the request");
        let mut rsp = payload(0x77);
        rsp.label = 0b0100;
        assert!(stage_reply(h, SERVER, &rsp));
        assert!(matches!(reply_warrant(h, SERVER, RSP), Reply::Woke { .. }));
        assert_eq!(collect(h, tid), Collected::Reply(RSP, NO_DONEE));
        assert_eq!(take_reply(idx, h).unwrap().label, 0b0100, "the caller reads the label of the answer");
        // The next call of the record carries its own label, none left over.
        let mut next = payload(0x20);
        next.label = 0;
        stamp_msg(idx, &next);
        let h2 = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE).unwrap();
        let _ = accept_v2(SERVER_IDX, SERVER).unwrap();
        assert_eq!(accept_msg(h2, SERVER).unwrap().label, 0, "no label stays none");
    }

    #[test]
    fn the_server_reads_the_callers_deadline_and_clock() {
        let _e = env();
        let (idx, tid) = client(0);
        let req = payload(0x10);
        stamp_msg(idx, &req);
        let h = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE).unwrap();
        let _ = accept_v2(SERVER_IDX, SERVER).unwrap();
        let got = accept_msg(h, SERVER).unwrap();
        assert_eq!((got.deadline, got.clock_id), (0x1000_0000_0010, 0x0300_0010));
        // An answer staged without a deadline reads back without one: the
        // request's does not leak into the reply.
        let mut rsp = payload(0x77);
        rsp.deadline = 0;
        rsp.clock_id = 0;
        assert!(stage_reply(h, SERVER, &rsp));
        assert!(matches!(reply_warrant(h, SERVER, RSP), Reply::Woke { .. }));
        assert_eq!(collect(h, tid), Collected::Reply(RSP, NO_DONEE));
        let back = take_reply(idx, h).unwrap();
        assert_eq!((back.deadline, back.clock_id), (0, 0));
        // The record's next v2 call carries its own: nothing is left over.
        let mut next = payload(0x20);
        next.deadline = 0;
        next.clock_id = 0;
        stamp_msg(idx, &next);
        let h2 = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE).unwrap();
        let _ = accept_v2(SERVER_IDX, SERVER).unwrap();
        let got2 = accept_msg(h2, SERVER).unwrap();
        assert_eq!((got2.deadline, got2.clock_id), (0, 0), "no deadline stays none");
    }

    #[test]
    fn a_v2_message_carries_every_word_and_cap_both_ways() {
        let _e = env();
        let (idx, tid) = client(0);
        let req = payload(0x10);
        stamp_badge(idx, 5);
        stamp_msg(idx, &req);
        let h = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE).unwrap();
        let _ = accept_v2(SERVER_IDX, SERVER).unwrap();
        assert_eq!(accept_msg(h, WORKER), None, "only the holder reads it");
        assert_eq!(accept_msg(h, SERVER), Some(req));
        assert_eq!(warrant_peer(h, SERVER), Some((tid, true)));
        assert_eq!(warrant_peer(h, WORKER), None);
        let rsp = payload(0x77);
        assert!(!stage_reply(h, WORKER, &rsp), "a non-holder stages nothing");
        assert!(stage_reply(h, SERVER, &rsp));
        assert_eq!(accept_msg(h, SERVER), None, "the request slot now holds the answer");
        assert!(matches!(reply_warrant(h, SERVER, RSP), Reply::Woke { .. }));
        assert_eq!(collect(h, tid), Collected::Reply(RSP, NO_DONEE));
        assert_eq!(take_reply(idx, h), Some(rsp));
        assert_eq!(take_reply(idx, h), None, "taken once");
        assert_eq!(warrant_peer(h, SERVER), None, "answered: the warrant names nobody (the sound host lends the call's caller only while it is served)");
        // The record's next call is v1: no message, no staged answer.
        let h2 = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        assert_eq!(accept_msg(h2, SERVER), None);
        assert_eq!(warrant_peer(h2, SERVER), Some((tid, false)));
        let _ = reply(h2, SERVER, false, RSP);
        let _ = collect(h2, tid);
        assert_eq!(take_reply(idx, h2), None, "a v1 answer stages nothing");
    }

    // ── Wave 15 N11c: the v1 accept refuses a v2 call ───────────────────────

    /// A v2 call (badge and message stamped) from client `i`.
    fn call_v2_from(i: usize, cap: u32) -> u64 {
        let (idx, tid) = client(i);
        stamp_badge(idx, 0);
        stamp_msg(idx, &payload(0x40));
        call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, cap, NO_DONEE).unwrap()
    }

    #[test]
    fn the_v1_accept_refuses_a_v2_call_and_takes_the_v1_call_behind_it() {
        let _e = env();
        let hv2 = call_v2_from(0, 0x21);
        let hv1 = call_from(1).unwrap();
        let mut seen = Vec::new();
        let a = super::accept::<true>(SERVER_IDX, SERVER, |c| seen.push(c));
        assert_eq!(a.map(|a| (a.0, a.1)), Some((hv1, client(1).1)), "the v1 call behind it is taken");
        assert_eq!(seen.len(), 1, "one refusal, reported once");
        assert_eq!((seen[0].caller, seen[0].handle, seen[0].donee), (client(0).1, hv2, NO_DONEE));
        assert_eq!(seen[0].moved_cap, 0, "nothing is revoked: the caller takes its capabilities back");
        assert_eq!(accept_badge(hv2, SERVER), None, "the server never held it");
        assert_eq!(accept_msg(hv2, SERVER), None);
        assert_eq!(reply(hv2, SERVER, false, RSP), Reply::Refused, "no warrant to answer with");
        assert_eq!(wait_state(hv2, client(0).1), 2, "over, for its caller to collect");
        assert_eq!(collect(hv2, client(0).1), Collected::Done(V1_ACCEPT, NO_DONEE));
        assert_eq!(wait_state(hv2, client(0).1), 0, "the record is free again");
        assert_eq!(V1_ACCEPT, -215);
    }

    #[test]
    fn the_v2_accept_takes_the_v2_call_the_v1_accept_refuses() {
        let _e = env();
        let h = call_v2_from(0, 0x21);
        let a = accept_v2(SERVER_IDX, SERVER).unwrap();
        assert_eq!((a.0, a.3), (h, 0x21));
        assert_eq!(accept_badge(h, SERVER), Some(0));
    }

    #[test]
    fn canary_v1_takes_v2_restores_the_projection() {
        let _e = env();
        canary_v1_takes_v2();
        let h = call_v2_from(0, 0x21);
        let mut n = 0;
        let a = super::accept::<true>(SERVER_IDX, SERVER, |_| n += 1).unwrap();
        assert_eq!((a.0, a.2, a.3, n), (h, REQ, 0x21, 0), "four words and the first cap, as before 10-10");
    }

    // ── FX3: a v2 call's capabilities never stay with a server that did not
    // take it ──────────────────────────────────────────────────────────────

    #[test]
    fn a_caller_exiting_after_a_refusal_strands_every_cap_with_the_refuser() {
        let _e = env();
        let (idx, tid) = client(0);
        let req = payload(0x40);
        let h = call_v2_from(0, req.caps[0]);
        let mut seen = Vec::new();
        assert_eq!(super::accept::<true>(SERVER_IDX, SERVER, |c| seen.push(c)), None);
        assert_eq!(seen.len(), 1, "refused");
        // The caller dies before it collects: the exit sweep must revoke
        // every capability in the refusing server's table.
        let c = release_caller(idx, tid).unwrap();
        assert_eq!(c.handle, h);
        assert_eq!(c.server, SERVER, "the table the capabilities sit in");
        let got: Vec<u32> = c.stranded().collect();
        assert_eq!(got, req.caps[..V2_CAPS].to_vec(), "a capability stays with a server that never took the call");
        assert_eq!(release_caller(idx, tid), None, "once");
    }

    #[test]
    fn a_queued_v2_call_strands_every_cap_on_exit_and_on_drain() {
        let _e = env();
        let (idx, tid) = client(0);
        let req = payload(0x40);
        let _ = call_v2_from(0, req.caps[0]);
        let c = release_caller(idx, tid).unwrap();
        assert_eq!(c.server, SERVER);
        assert_eq!(c.stranded().collect::<Vec<_>>(), req.caps[..V2_CAPS].to_vec(), "exit: only the first revoked");
        // The endpoint destroyed under a queued v2 call: every one, once.
        let _ = call_v2_from(1, req.caps[0]);
        let mut seen = Vec::new();
        close(EP);
        assert_eq!(drain(EP, REVOKED, SERVER, |c| seen.push(c)), 1);
        assert_eq!(seen[0].stranded().collect::<Vec<_>>(), req.caps[..V2_CAPS].to_vec(), "drain: only the first");
        assert_eq!(collect(seen[0].handle, client(1).1), Collected::Done(REVOKED, NO_DONEE));
        assert_eq!(release_caller(client(1).0, client(1).1), None, "nothing left to strand twice");
    }

    #[test]
    fn an_accepted_or_answered_v2_call_strands_nothing_on_exit() {
        let _e = env();
        let (idx, tid) = client(0);
        let _ = call_v2_from(0, 0x21);
        let _ = accept_v2(SERVER_IDX, SERVER).unwrap();
        let c = release_caller(idx, tid).unwrap();
        assert_eq!((c.server, c.stranded().count()), (0, 0), "the server took it with v2: its capabilities are its");
    }

    #[test]
    fn reply_then_accept_refuses_a_v2_call_at_the_head() {
        let _e = env();
        let h0 = call_from(0).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        let hv2 = call_v2_from(1, 0);
        let h2 = call_from(2).unwrap();
        let mut seen = Vec::new();
        let (r, next) = super::reply_then_accept(h0, SERVER, false, RSP, SERVER_IDX, |c| seen.push(c));
        assert!(matches!(r, Reply::Woke { .. }));
        assert_eq!(next.map(|a| a.0), Some(h2), "the v1 call behind the refused one");
        assert_eq!(seen.iter().map(|c| c.handle).collect::<Vec<_>>(), vec![hv2]);
        assert_eq!(collect(hv2, client(1).1), Collected::Done(V1_ACCEPT, NO_DONEE));
        assert_eq!(collect(h0, client(0).1), Collected::Reply(RSP, NO_DONEE));
    }

    // ── The IPC fast path (Kconfig IPC_FASTPATH) ───────────────────────────

    /// A claim that answers its value, and checks the slot when given one.
    struct Yes(bool, Option<usize>);

    impl Claim for Yes {
        fn claim(&mut self, slot: usize) -> bool {
            if let Some(want) = self.1 {
                assert_eq!(slot, want, "the claim is asked for the peer's slot");
            }
            self.0
        }
    }

    /// The claim a test expects never to be asked.
    struct Never;

    impl Claim for Never {
        fn claim(&mut self, _: usize) -> bool {
            panic!("the claim was asked although a precondition failed")
        }
    }

    /// [`fast_call`] from client `i` with a claim that answers `claimed`.
    fn fast_from(i: usize, claimed: bool) -> Option<u64> {
        let (idx, tid) = client(i);
        fast_call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, NO_DONEE, Yes(claimed, Some(SERVER_IDX)))
    }

    #[test]
    fn fast_call_and_fast_reply_leave_what_the_ordinary_path_leaves() {
        let _e = env();
        let (idx, tid) = client(0);
        let g = tag_gen(RECORDS[idx].tag.load(Ordering::Relaxed));
        let h = fast_from(0, true).expect("a parked server takes the call");
        assert_eq!(h, make_handle(idx, g), "the record's own handle");
        assert_eq!(census(), (0, 1, 0, 0), "ACCEPTED at once, on no list");
        assert_eq!(wait_state(h, tid), 1);
        assert_eq!(accept(SERVER_IDX, SERVER), None, "nothing was queued");
        assert_eq!(take_deposit(SERVER_IDX, SERVER), Some((idx, h)));
        assert_eq!(take_deposit(SERVER_IDX, SERVER), None, "taken once");
        assert_eq!((deposit_caller(idx), [0, 1, 2, 3].map(|k| deposit_word(idx, k))), (tid, REQ));
        let got = fast_reply(h, SERVER, SERVER_IDX, RSP, false, Yes(true, Some(idx)));
        assert_eq!(got, Some((idx, tid, NO_DONEE)));
        assert_eq!(wait_state(h, tid), 2);
        assert_eq!(collect(h, tid), Collected::Reply(RSP, NO_DONEE));
        assert_eq!(census(), (0, 0, 0, 0));
        // The ordinary path can answer a fast call too, and the reverse.
        let h = fast_from(0, true).unwrap();
        assert_eq!(take_deposit(SERVER_IDX, SERVER), Some((idx, h)));
        assert!(matches!(reply(h, SERVER, false, RSP), Reply::Woke { .. }));
        assert_eq!(collect(h, tid), Collected::Reply(RSP, NO_DONEE));
        let h = call_from(0).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        assert_eq!(fast_reply(h, SERVER, SERVER_IDX, RSP, false, Yes(true, Some(idx))), Some((idx, tid, NO_DONEE)));
        assert_eq!(collect(h, tid), Collected::Reply(RSP, NO_DONEE));
    }

    #[test]
    fn a_refused_claim_leaves_nothing_written() {
        let _e = env();
        let (idx, tid) = client(0);
        let g = tag_gen(RECORDS[idx].tag.load(Ordering::Relaxed));
        assert_eq!(fast_from(0, false), None);
        assert_eq!(census(), (0, 0, 0, 0));
        assert_eq!(take_deposit(SERVER_IDX, SERVER), None);
        // The record's generation did not move: the next call has the same.
        let h = make_handle(idx, g);
        assert_eq!(call_from(0), Some(h));
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        assert_eq!(fast_reply(h, SERVER, SERVER_IDX, RSP, false, Yes(false, Some(idx))), None);
        assert_eq!(wait_state(h, tid), 1, "still accepted, unanswered");
        assert_eq!(collect(h, tid), Collected::Nothing);
    }

    #[test]
    fn the_fast_call_never_jumps_a_queued_call_or_a_changed_endpoint() {
        let _e = env();
        // A call queued on this endpoint.
        let h1 = call_from(1).unwrap();
        let (idx, tid) = client(0);
        assert_eq!(fast_call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, NO_DONEE, Never), None);
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        assert!(matches!(reply(h1, SERVER, false, RSP), Reply::Woke { .. }));
        // A call queued for the server on another of its endpoints.
        open(EP + 1, GEN, SERVER);
        let h2 = call(client(2).0, client(2).1, EP + 1, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE).unwrap();
        assert_eq!(fast_call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, NO_DONEE, Never), None);
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        assert!(matches!(reply(h2, SERVER, false, RSP), Reply::Woke { .. }));
        // A changed endpoint, another server, a busy record.
        assert_eq!(fast_call(idx, tid, EP, GEN + 1, SERVER, SERVER_IDX, REQ, NO_DONEE, Never), None);
        assert_eq!(fast_call(idx, tid, EP, GEN, SERVER + 1, SERVER_IDX, REQ, NO_DONEE, Never), None);
        let _ = call_from(0).unwrap();
        assert_eq!(fast_call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, NO_DONEE, Never), None, "one call per task");
    }

    #[test]
    fn the_fast_reply_never_jumps_a_queued_call_nor_answers_for_another() {
        let _e = env();
        let (idx, tid) = client(0);
        let h = fast_from(0, true).unwrap();
        let _ = take_deposit(SERVER_IDX, SERVER).unwrap();
        assert_eq!(fast_reply(h, SERVER + 1, SERVER_IDX, RSP, false, Never), None, "not its server");
        assert_eq!(fast_reply(h ^ (1 << REC_BITS), SERVER, SERVER_IDX, RSP, false, Never), None, "stale");
        let h1 = call_from(1).unwrap();
        assert_eq!(fast_reply(h, SERVER, SERVER_IDX, RSP, false, Never), None, "a call is queued");
        // The ordinary reply answers it and takes the queued one.
        let (r, next) = reply_then_accept(h, SERVER, false, RSP, SERVER_IDX);
        assert_eq!(r, Reply::Woke { caller: tid, rec: idx, donee: NO_DONEE });
        assert_eq!(next.map(|a| a.0), Some(h1));
    }

    /// A claim that hands the call or the answer over (Chain E commit 9, a
    /// peer's resume point) and keeps what it was handed.
    struct Hand {
        slot: usize,
        call: Option<(u64, u32, [u64; WORDS])>,
        reply: Option<[u64; WORDS]>,
    }

    impl Hand {
        fn new(slot: usize) -> Self {
            Self { slot, call: None, reply: None }
        }
    }

    impl Claim for &mut Hand {
        fn claim(&mut self, slot: usize) -> bool {
            assert_eq!(slot, self.slot, "the claim is asked for the peer's slot");
            true
        }
        fn hand_call(&mut self, handle: u64, caller: u32, words: &[u64; WORDS]) -> bool {
            self.call = Some((handle, caller, *words));
            true
        }
        fn hand_reply(&mut self, words: &[u64; WORDS]) -> bool {
            self.reply = Some(*words);
            true
        }
    }

    /// Canary: storing the deposit after a hand-over (the server would take
    /// the call twice), or publishing a handed answer REPLIED instead of
    /// freeing the record (the caller's next call finds it busy), turns this
    /// red.
    #[test]
    fn a_handed_call_leaves_no_deposit_and_a_handed_answer_frees_the_record() {
        let _e = env();
        let (idx, tid) = client(0);
        let g = tag_gen(RECORDS[idx].tag.load(Ordering::Relaxed));
        let mut hand = Hand::new(SERVER_IDX);
        let h = fast_call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, NO_DONEE, &mut hand).expect("a parked server");
        assert_eq!(hand.call, Some((h, tid, REQ)), "the server is handed this call");
        assert_eq!(take_deposit(SERVER_IDX, SERVER), None, "handed, not deposited");
        assert_eq!(census(), (0, 1, 0, 0), "ACCEPTED, in the server's service");
        assert_eq!(wait_state(h, tid), 1);
        let mut hand = Hand::new(idx);
        assert_eq!(fast_reply(h, SERVER, SERVER_IDX, RSP, false, &mut hand), Some((idx, tid, NO_DONEE)));
        assert_eq!(hand.reply, Some(RSP), "the caller is handed the answer");
        assert_eq!(census(), (0, 0, 0, 0), "the record is freed, as the collect frees it");
        assert_eq!(collect(h, tid), Collected::Nothing, "nothing is left to collect");
        // The generation moved as a collect moves it: the next call is new.
        assert_eq!(call_from(0), Some(make_handle(idx, (g + 1) & GEN_MASK)));
    }

    /// A handed call is in its server's service like an accepted one: the
    /// server's death completes it, and the server's late answer reaches
    /// nobody. Canary: a hand-over that frees the call's record (as if it
    /// were the answer's) turns this red.
    #[test]
    fn a_handed_call_ends_with_its_server_like_an_accepted_one() {
        let _e = env();
        let (_, tid) = client(0);
        let mut hand = Hand::new(SERVER_IDX);
        let h = fast_call(client(0).0, tid, EP, GEN, SERVER, SERVER_IDX, REQ, NO_DONEE, &mut hand).unwrap();
        set_owner(EP, GEN, UNCLAIMED);
        assert_eq!(drain(EP, PEER_DIED, SERVER, |_| {}), 1, "the handed call is completed");
        assert!(!matches!(reply(h, SERVER, false, RSP), Reply::Woke { .. }), "the late answer reaches nobody");
        assert_eq!(collect(h, tid), Collected::Done(PEER_DIED, NO_DONEE));
    }

    /// A call that carries a donation is answered through the record even
    /// when the claim would hand it over: its caller's collect returns the
    /// donation. Canary: asking `hand_reply` regardless turns this red.
    #[test]
    fn a_donated_call_is_answered_through_the_record() {
        let _e = env();
        let (idx, tid) = client(0);
        let h = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, SERVER).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        let mut hand = Hand::new(idx);
        assert_eq!(fast_reply(h, SERVER, SERVER_IDX, RSP, false, &mut hand), Some((idx, tid, SERVER)));
        assert_eq!(hand.reply, None, "not handed");
        assert_eq!(collect(h, tid), Collected::Reply(RSP, SERVER), "the collect returns the donation");
    }

    /// WAIT_GRAPH (Chain E): a fast call carries its edge's token as its
    /// donee, so every path that ends the call retires the edge (the reply,
    /// the drain, the collect); the fast reply hands such a call over all the
    /// same (`token`: nothing to return) and reports the token. Canary:
    /// writing NO_DONEE in the fast call's record turns this red.
    #[test]
    fn a_fast_call_keeps_its_edge_token_for_whoever_ends_it() {
        let _e = env();
        let (idx, tid) = client(0);
        let mut hand = Hand::new(SERVER_IDX);
        let h = fast_call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, SERVER, &mut hand).unwrap();
        let mut hand = Hand::new(idx);
        assert_eq!(fast_reply(h, SERVER, SERVER_IDX, RSP, true, &mut hand), Some((idx, tid, SERVER)));
        assert_eq!(hand.reply, Some(RSP), "a token is not a donation: handed");
        assert_eq!(census(), (0, 0, 0, 0));
        // Not handed (no resume point): published, the token in the record.
        let h = fast_call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, SERVER, Yes(true, None)).unwrap();
        let _ = take_deposit(SERVER_IDX, SERVER).unwrap();
        assert!(matches!(reply(h, SERVER, false, RSP), Reply::Woke { donee: SERVER, .. }), "the ordinary reply takes it");
        assert_eq!(collect(h, tid), Collected::Reply(RSP, NO_DONEE), "taken once");
        // The drain completes it with the token too.
        let h = fast_call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, SERVER, Yes(true, None)).unwrap();
        let mut seen = NO_DONEE;
        set_owner(EP, GEN, UNCLAIMED);
        assert_eq!(drain(EP, PEER_DIED, SERVER, |c| seen = c.donee), 1);
        assert_eq!(seen, SERVER, "the drain did not see the token");
        assert_eq!(collect(h, tid), Collected::Done(PEER_DIED, NO_DONEE), "taken once");
    }

    #[test]
    fn a_deposit_whose_call_ended_is_dropped() {
        let _e = env();
        let (_, tid) = client(0);
        // The server died before it took the deposit.
        let h = fast_from(0, true).unwrap();
        set_owner(EP, GEN, UNCLAIMED);
        assert_eq!(drain(EP, PEER_DIED, SERVER, |_| {}), 1, "an accepted call is completed");
        assert_eq!(take_deposit(SERVER_IDX, SERVER), None);
        assert_eq!(collect(h, tid), Collected::Done(PEER_DIED, NO_DONEE));
        // The caller withdrew (it was killed) before the server took it.
        set_owner(EP, GEN, SERVER);
        let h = fast_from(0, true).unwrap();
        assert!(!abandon(h, tid).was_queued);
        assert_eq!(take_deposit(SERVER_IDX, SERVER), None);
        // Another task in the server's slot never takes the old one's.
        let _ = fast_from(0, true).unwrap();
        assert_eq!(take_deposit(SERVER_IDX, SERVER + 9), None);
    }

    // ── Live update: the handover ──────────────────────────────────────────

    const NEW: u32 = 8;
    const NEW_IDX: usize = 2;

    fn handover() {
        begin_handover(EP, GEN, SERVER, NEW).expect("begin");
    }

    /// The rebind, with the donations left where they are.
    fn rebind(ep: usize, gen: u32, new: u32, old_idx: usize, new_idx: usize) -> Result<(), HandoverError> {
        super::rebind(ep, gen, new, old_idx, new_idx, |_, d| d)
    }

    /// A call carrying a donation to `donee`, from client `i`.
    fn donating_call_from(i: usize, donee: u32) -> u64 {
        let (idx, tid) = client(i);
        call(idx, tid, EP, GEN, SERVER, SERVER_IDX, [i as u64, 0, 0, 0], 0, donee).unwrap()
    }

    /// The donation of every call queued for the old server moves to the new
    /// one at the flip: a queued call, a re-presented one, and the one that
    /// arrived during the handover; a call that carried none, or one lent to
    /// another task, is left alone.
    #[test]
    fn the_rebind_moves_the_donation_of_a_re_presented_call_to_the_new_server() {
        let _e = env();
        let h0 = donating_call_from(0, SERVER);
        let _ = accept(SERVER_IDX, SERVER).unwrap(); // h0 in service, re-presented below
        handover();
        let _h1 = donating_call_from(1, SERVER); // during the handover
        let _h2 = donating_call_from(2, NO_DONEE);
        let _h3 = donating_call_from(3, 99); // lent to someone else
        assert_eq!(represent(EP, GEN, SERVER), Ok((1, 0)));
        let mut seen = Vec::new();
        let r = super::rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX, |caller_idx, d| {
            seen.push((caller_idx, d));
            NEW
        });
        assert_eq!(r, Ok(()));
        let mut want = vec![(client(0).0, SERVER), (client(1).0, SERVER)];
        want.sort();
        seen.sort();
        assert_eq!(seen, want, "exactly the calls lent to the old server");
        // The records carry the new donee; the others keep theirs.
        for (i, d) in [(0, NEW), (1, NEW), (2, NO_DONEE), (3, 99)] {
            assert_eq!(rec(client(i).0).donee.load(Ordering::Relaxed), d, "client {i}");
        }
        // The new server's reply returns the donation it now owes.
        let (h, ..) = accept(NEW_IDX, NEW).unwrap();
        assert_eq!(h, h0);
        assert_eq!(reply(h, NEW, false, RSP), Reply::Woke { caller: client(0).1, rec: client(0).0, donee: NEW });
    }

    #[test]
    fn canary_a_rebind_that_leaves_the_donation_pointed_at_the_old_server() {
        let _e = env();
        handover();
        let _ = donating_call_from(0, SERVER);
        BREAK[BREAK_RETARGET].store(true, Ordering::Relaxed);
        assert_eq!(super::rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX, |_, _| NEW), Ok(()));
        assert_eq!(rec(client(0).0).donee.load(Ordering::Relaxed), SERVER, "still lent to the old server");
    }

    /// A call queued during the handover is served by the new owner, and
    /// the one in service when it began completes with its old server.
    #[test]
    fn a_call_queued_during_a_handover_is_served_by_the_new_owner() {
        let _e = env();
        let h0 = call_from(0).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap(); // h0 in service with the old server
        handover();
        // New calls queue as before, resolved to the old server.
        let h1 = call_from(1).expect("a call queues during a handover");
        let h2 = call_from(2).expect("and another");
        // Delivered to nobody until the rebind.
        assert_eq!(accept(SERVER_IDX, SERVER), None, "the old server takes no new call");
        assert_eq!(accept(NEW_IDX, NEW), None, "the new server takes none before the rebind");
        // The in-service call completes with its server.
        assert!(matches!(reply(h0, SERVER, false, RSP), Reply::Woke { .. }));
        assert_eq!(collect(h0, client(0).1), Collected::Reply(RSP, NO_DONEE));
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Ok(()));
        // The new owner serves them, in arrival order, the old one none.
        assert_eq!(accept(SERVER_IDX, SERVER), None);
        let (a, who, w, _) = accept(NEW_IDX, NEW).expect("the new server finds the queue");
        assert_eq!((a, who, w[0]), (h1, client(1).1, 1));
        let (b, who, w, _) = accept(NEW_IDX, NEW).unwrap();
        assert_eq!((b, who, w[0]), (h2, client(2).1, 2));
        assert_eq!(reply(h1, SERVER, false, RSP), Reply::Refused, "the old server answers for nothing now");
        assert!(matches!(reply(h1, NEW, false, RSP), Reply::Woke { .. }));
        assert!(matches!(reply(h2, NEW, false, RSP), Reply::Woke { .. }));
        assert_eq!(collect(h1, client(1).1), Collected::Reply(RSP, NO_DONEE));
        assert_eq!(collect(h2, client(2).1), Collected::Reply(RSP, NO_DONEE));
        // The endpoint is the new owner's: a call resolved to it queues,
        // one still resolved to the old server is refused, not lost.
        assert!(served_by(EP, NEW) && !served_by(EP, SERVER));
        let (idx, tid) = client(3);
        assert_eq!(call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0, NO_DONEE), None);
        assert!(call(idx, tid, EP, GEN, NEW, NEW_IDX, REQ, 0, NO_DONEE).is_some());
        assert_eq!(census(), (1, 0, 0, 0));
    }

    /// Nothing is lost and nothing ends `PEER_DIED`: every call in flight
    /// across the handover reaches a reply.
    #[test]
    fn a_handover_loses_no_call_and_completes_none_with_peer_died() {
        let _e = env();
        let n_before = 6usize;
        let hs: Vec<u64> = (0..n_before).map(|i| call_from(i).unwrap()).collect();
        for _ in 0..2 {
            let _ = accept(SERVER_IDX, SERVER).unwrap(); // hs[0], hs[1] in service
        }
        handover();
        let late: Vec<u64> = (n_before..n_before + 4).map(|i| call_from(i).unwrap()).collect();
        for &h in &hs[..2] {
            assert!(matches!(reply(h, SERVER, false, RSP), Reply::Woke { .. }));
        }
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Ok(()));
        let mut served = 0;
        while let Some((h, _, _, _)) = accept(NEW_IDX, NEW) {
            assert!(matches!(reply(h, NEW, false, RSP), Reply::Woke { .. }));
            served += 1;
        }
        assert_eq!(served, 4 + 4, "four queued before and four during, in service ones excluded");
        for (i, &h) in hs.iter().chain(late.iter()).enumerate() {
            assert_eq!(collect(h, client(i).1), Collected::Reply(RSP, NO_DONEE), "call {i}");
        }
        assert_eq!(census(), (0, 0, 0, 0), "no record left in a call");
    }

    /// Across the flip of the identity word (published just before the
    /// rebind) a caller that resolved the successor queues too, and a caller
    /// that resolved a third task does not.
    #[test]
    fn a_call_resolved_to_the_successor_during_the_flip_queues() {
        let _e = env();
        handover();
        let (idx, tid) = client(0);
        assert!(call(idx, tid, EP, GEN, NEW, NEW_IDX, REQ, 0, NO_DONEE).is_some());
        let (idx, tid) = client(1);
        assert_eq!(call(idx, tid, EP, GEN, NEW + 1, NEW_IDX, REQ, 0, NO_DONEE), None, "a stranger");
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Ok(()));
        assert!(accept(NEW_IDX, NEW).is_some());
    }

    /// A rebind that names the generation of an endpoint that is gone is
    /// refused, and leaves the handover as it was.
    #[test]
    fn a_rebind_with_a_stale_generation_is_refused() {
        let _e = env();
        handover();
        let h = call_from(0).unwrap();
        assert_eq!(rebind(EP, GEN + 1, NEW, SERVER_IDX, NEW_IDX), Err(HandoverError::Stale));
        assert_eq!(rebind(EP, 0, NEW, SERVER_IDX, NEW_IDX), Err(HandoverError::Stale));
        assert_eq!(begin_handover(EP, GEN + 1, SERVER, NEW), Err(HandoverError::Stale));
        assert!(served_by(EP, SERVER), "the owner did not change");
        assert_eq!(accept(NEW_IDX, NEW), None);
        // The right generation still goes through, and the queued call is the new owner's.
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Ok(()));
        assert_eq!(accept(NEW_IDX, NEW).map(|a| a.0), Some(h));
        // An endpoint closed and opened again (another generation) is not rebound by the old word.
        close(EP);
        open(EP, GEN + 1, SERVER);
        assert_eq!(begin_handover(EP, GEN + 1, SERVER, NEW), Ok(()));
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Err(HandoverError::Stale));
    }

    #[test]
    fn begin_and_rebind_check_who_is_who() {
        let _e = env();
        assert_eq!(begin_handover(EP, GEN, SERVER + 1, NEW), Err(HandoverError::NotOwner), "not the owner");
        assert_eq!(begin_handover(EP, GEN, SERVER, SERVER), Err(HandoverError::NotOwner));
        assert_eq!(begin_handover(EP, GEN, SERVER, UNCLAIMED), Err(HandoverError::NotOwner));
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Err(HandoverError::NotInHandover));
        handover();
        assert_eq!(begin_handover(EP, GEN, SERVER, NEW + 1), Err(HandoverError::Busy));
        assert_eq!(rebind(EP, GEN, NEW + 1, SERVER_IDX, NEW_IDX), Err(HandoverError::NotInHandover), "another successor");
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Ok(()));
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Err(HandoverError::NotInHandover), "rebound once");
    }

    /// The rebind waits for the old server's calls in service: left behind
    /// they would never be answered.
    #[test]
    fn the_rebind_refuses_while_the_old_server_has_a_call_in_service() {
        let _e = env();
        let h0 = call_from(0).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        handover();
        assert_eq!(in_service(EP, SERVER), 1);
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Err(HandoverError::InService(1)));
        assert!(matches!(reply(h0, SERVER, false, RSP), Reply::Woke { .. }));
        assert_eq!(in_service(EP, SERVER), 0);
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Ok(()));
    }

    /// `rebind_check` answers what `rebind` would, and changes nothing: the
    /// endpoint layer asks it of every endpoint before flipping any.
    #[test]
    fn the_rebind_check_answers_as_the_rebind_and_flips_nothing() {
        let _e = env();
        assert_eq!(rebind_check(EP, GEN, NEW), Err(HandoverError::NotInHandover), "no handover");
        let h0 = call_from(0).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        handover();
        assert_eq!(rebind_check(EP, GEN + 1, NEW), Err(HandoverError::Stale));
        assert_eq!(rebind_check(EP, GEN, NEW + 1), Err(HandoverError::NotInHandover), "another successor");
        assert_eq!(rebind_check(EP, GEN, NEW), Err(HandoverError::InService(1)));
        assert!(matches!(reply(h0, SERVER, false, RSP), Reply::Woke { .. }));
        let h1 = call_from(1).unwrap();
        assert_eq!(rebind_check(EP, GEN, NEW), Ok(()));
        assert!(served_by(EP, SERVER), "the check flipped the owner");
        assert_eq!(accept(NEW_IDX, NEW), None, "the check handed the queue over");
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Ok(()));
        assert_eq!(accept(NEW_IDX, NEW).map(|a| a.0), Some(h1));
    }

    /// A call in service is re-presented to the new server instead of
    /// waited for: it goes first, before the calls queued during the
    /// handover, and the old server's late reply is refused.
    #[test]
    fn an_in_service_call_can_be_re_presented_to_the_new_owner() {
        let _e = env();
        let h0 = call_from(0).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        handover();
        let h1 = call_from(1).unwrap();
        assert_eq!(represent(EP, GEN, SERVER), Ok((1, 0)));
        assert_eq!(in_service(EP, SERVER), 0);
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Ok(()));
        assert_eq!(reply(h0, SERVER, false, RSP), Reply::Refused, "the old server's late answer");
        assert_eq!(accept(NEW_IDX, NEW).map(|a| a.0), Some(h0), "first");
        assert_eq!(accept(NEW_IDX, NEW).map(|a| a.0), Some(h1));
        assert!(matches!(reply(h0, NEW, false, RSP), Reply::Woke { .. }));
        assert_eq!(collect(h0, client(0).1), Collected::Reply(RSP, NO_DONEE));
    }

    /// A call that moved a capability into the old server's table is not
    /// re-presented (it stays in service for the old server to answer).
    #[test]
    fn a_call_that_moved_a_capability_stays_with_the_old_server() {
        let _e = env();
        let (idx, tid) = client(0);
        let h = call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, 0x5_0001, NO_DONEE).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        handover();
        assert_eq!(represent(EP, GEN, SERVER), Ok((0, 1)));
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Err(HandoverError::InService(1)));
        assert!(matches!(reply(h, SERVER, false, RSP), Reply::Woke { .. }));
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Ok(()));
    }

    /// The fast path does not deliver to either server during a handover.
    #[test]
    fn the_fast_call_misses_during_a_handover() {
        struct Yes;
        impl Claim for Yes {
            fn claim(&mut self, _idx: usize) -> bool { true }
            fn hand_call(&mut self, _h: u64, _c: u32, _w: &[u64; WORDS]) -> bool { false }
            fn hand_reply(&mut self, _w: &[u64; WORDS]) -> bool { false }
        }
        let _e = env();
        let (idx, tid) = client(0);
        assert!(fast_call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, NO_DONEE, Yes).is_some(), "precondition: it hits");
        let h = handle_of_first();
        assert!(matches!(reply(h, SERVER, false, RSP), Reply::Woke { .. }));
        let _ = collect(h, tid);
        handover();
        assert_eq!(fast_call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, NO_DONEE, Yes), None, "old owner");
        assert_eq!(fast_call(idx, tid, EP, GEN, NEW, NEW_IDX, REQ, NO_DONEE, Yes), None, "new owner, too early");
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Ok(()));
        assert_eq!(fast_call(idx, tid, EP, GEN, SERVER, SERVER_IDX, REQ, NO_DONEE, Yes), None, "old owner after");
        assert!(fast_call(idx, tid, EP, GEN, NEW, NEW_IDX, REQ, NO_DONEE, Yes).is_some(), "new owner after");
    }

    fn handle_of_first() -> u64 {
        let mut out = [(0u8, 0u8, 0u32, 0u32); 4];
        assert_eq!(ids(&mut out), 1);
        let (i, ..) = out[0];
        make_handle(i as usize, tag_gen(RECORDS[i as usize].tag.load(Ordering::Relaxed)))
    }

    /// An aborted handover gives the queue back to the old server.
    #[test]
    fn an_aborted_handover_serves_the_queue_with_the_old_server() {
        let _e = env();
        handover();
        let h = call_from(0).unwrap();
        assert_eq!(abort_handover(EP, GEN, SERVER_IDX), Ok(()));
        assert_eq!(accept(SERVER_IDX, SERVER).map(|a| a.0), Some(h));
        assert_eq!(abort_handover(EP, GEN, SERVER_IDX), Err(HandoverError::NotInHandover));
    }

    /// Canary, one per check: break it, and the property it guards turns
    /// red (the assertion the tests above make is the one that fails here).
    #[test]
    fn canary_a_rebind_that_ignores_the_generation_flips_a_later_endpoint() {
        let _e = env();
        handover();
        BREAK[BREAK_GEN].store(true, Ordering::Relaxed);
        assert_eq!(rebind(EP, GEN + 1, NEW, SERVER_IDX, NEW_IDX), Ok(()), "the stale rebind went through");
        assert!(served_by(EP, NEW), "and moved an endpoint it never named");
    }

    #[test]
    fn canary_a_rebind_that_ignores_the_calls_in_service_strands_them() {
        let _e = env();
        let h0 = call_from(0).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        handover();
        BREAK[BREAK_IN_SERVICE].store(true, Ordering::Relaxed);
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Ok(()), "went through with a call in service");
        // The call is in service for a task that is no longer the server;
        // the exit sweep of the endpoint (owner now NEW) never finds it.
        assert_eq!(in_service(EP, SERVER), 1);
        assert_eq!(wait_state(h0, client(0).1), 1, "its caller still waits");
    }

    #[test]
    fn canary_a_rebind_that_forgets_the_ready_bit_loses_the_queued_calls() {
        let _e = env();
        handover();
        let _h = call_from(0).unwrap();
        BREAK[BREAK_QUIESCE].store(true, Ordering::Relaxed);
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Ok(()));
        assert_eq!(accept(NEW_IDX, NEW), None, "the queued call is invisible to its new server");
        assert_eq!(census().0, 1, "and still queued");
    }

    #[test]
    fn canary_a_represent_that_does_nothing_leaves_the_call_in_service() {
        let _e = env();
        let _h0 = call_from(0).unwrap();
        let _ = accept(SERVER_IDX, SERVER).unwrap();
        handover();
        BREAK[BREAK_REPRESENT].store(true, Ordering::Relaxed);
        assert_eq!(represent(EP, GEN, SERVER), Ok((0, 0)));
        assert_eq!(in_service(EP, SERVER), 1, "still the old server's: the rebind refuses");
        assert_eq!(rebind(EP, GEN, NEW, SERVER_IDX, NEW_IDX), Err(HandoverError::InService(1)));
    }

    /// Canary, the other way: the legacy path (an orphan, then a drain) is
    /// what ends calls `PEER_DIED`; the handover does not go through it. The
    /// check `no call ends PEER_DIED` is red under that path.
    #[test]
    fn canary_the_drain_path_ends_the_calls_peer_died() {
        let _e = env();
        let h0 = call_from(0).unwrap();
        handover();
        set_owner(EP, GEN, UNCLAIMED);
        assert_eq!(drain(EP, PEER_DIED, SERVER, |_| {}), 1);
        assert_eq!(collect(h0, client(0).1), Collected::Done(PEER_DIED, NO_DONEE));
    }

}
