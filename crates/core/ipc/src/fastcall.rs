// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The fast call's kernel side.
//!
//! `crates/core/syscall`'s fast-call arms and the task-exit hook call this,
//! never `ep_queue` directly: a call queues on the endpoint it names
//! (`ep_queue.rs`).
//!
//! What lives here is what both need from the rest of the kernel: the
//! caller's and the server's task slots, the priority donation (lent before
//! the call is published, returned exactly once), the tracepoints, and, for a
//! call completed by its endpoint's death, the wake, the stranded capability
//! and the donation, all done with no queue lock held.

use crate::endpoint::Dest;
use crate::ep_queue::{self, Collected as QCollected, Reply as QReply};

/// "No donation rides on this exchange" in a call record's `donee` field and
/// in [`FastIpcReply::Woke`]. `u32::MAX` is never a TID (`NEXT_TID` skips it).
pub const NO_DONEE: u32 = u32::MAX;

/// Maximum number of 64-bit words in a fast IPC message.
pub const FAST_IPC_MAX_WORDS: usize = 4;

/// Words in a fast-call message.
pub const WORDS: usize = FAST_IPC_MAX_WORDS;

/// What a reply did (SYS_IPC_FAST_REPLY and its relatives).
///
/// `Refused` must not be read as "try again": the handle named no call this
/// replier may answer (never accepted, already answered, not its warrant),
/// and a retry cannot make it one. `Stale` is the handle of an exchange that
/// ended (its caller died or already collected); nothing was written. The
/// two are kept apart so a caller's log can tell a lost race from a misuse,
/// and nothing else may tell them apart: ring 3 sees one error either way,
/// or the reply would be an oracle over other tasks' calls.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FastIpcReply {
    /// Reply deposited. Wake `caller_tid`, which is blocked on
    /// `WaitReason::FastIpcClient(slot_idx)`.
    ///
    /// `slot_idx` is the caller's call record, returned rather than left for
    /// the caller to decode out of the handle, so the wait reason is keyed on
    /// one derivation only.
    ///
    /// `donee` is the task the caller's priority was donated to for this
    /// exchange, or [`NO_DONEE`]: the replier owes exactly one
    /// `return_donation(donee)`, after the queue lock is dropped. It is the
    /// TID recorded at the call, not the replier.
    Woke { caller_tid: u32, slot_idx: usize, donee: u32 },
    /// The handle names an exchange that ended. **Nothing was written.**
    Stale,
    /// Rejected for any other reason.
    Refused,
}

/// Answer to "should I block again, or give up?" — see [`wait_state`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FastIpcWait {
    /// The call is not this caller's any more. Blocking again would sleep
    /// forever: give up.
    Gone,
    /// The call is still this caller's and the server has not replied yet. A
    /// wake seen in this state is spurious; blocking again is correct and
    /// will not be lost.
    Waiting,
    /// The reply is deposited. [`collect`] will succeed.
    Ready,
}

/// A request a server took: `(handle, caller_tid, words, moved_cap)`.
pub type AcceptedReq = (u64, u32, [u64; WORDS], u32);

/// What a caller finds when it collects.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Collected {
    /// The reply, and a donation the caller owes back (or [`NO_DONEE`]).
    Reply([u64; WORDS], u32),
    /// The call was completed without an answer: `code` is `-EPEERDIED` or
    /// `-EREVOKED`; and a donation owed back.
    Done(i64, u32),
    /// Nothing yet, or not this caller's.
    Nothing,
}

/// What [`abandon`] took back.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Abandoned {
    /// The donation the caller owes back, or [`NO_DONEE`].
    pub donee: u32,
    /// No server took the request: a capability moved with it may go back.
    pub was_queued: bool,
}


// ── Wave 15 N7g: the call's donation as a wait-graph edge ───────────────────
//
// With Kconfig WAIT_GRAPH, a call does not lend a
// counted donation: the caller blocks on its server's `IpcCall` node in the
// wait graph, so the server runs at the most urgent of its callers (the
// over-boost of two counted donations to one server is gone, owner decision
// 10-10), a chain of calls inherits transitively, a call that would close a
// cycle is refused, and the ring-3 floor applies through the graph's
// `ClassPi::write_floor`. The record's donee stays the token that says who
// retires the call: whoever takes it unblocks instead of returning. The
// caller also leaves its own edge when it collects or abandons (the replier's
// unblock runs after the answer is published, so the caller may already be
// past it); every donee that leaves this file is then NO_DONEE, and
// `syscall::dispatch` and `ipc_v2` return nothing. Every y body is in the
// `NodeSel<true>` impl below: with n none of it is compiled.

use azos_sync::waitgraph::{self, DonorNode, NodeSel, PiWaiters, SelectNode, UnblockReason, WaitError};

/// The call edge is the graph's: Kconfig WAIT_GRAPH (without it the call
/// lends a counted donation).
const GRAPH: bool = waitgraph::ENABLED;

/// One `IpcCall` node per server task slot; zero-sized with WAIT_GRAPH n.
#[allow(clippy::declare_interior_mutable_const)]
static CALL_NODES: [DonorNode; azos_limits::MAX_TASKS] =
    [const { <NodeSel<{ waitgraph::ENABLED }> as SelectNode>::IPC_CALL }; azos_limits::MAX_TASKS];

/// A node as the graph sees it: `PiWaiters` (y) or nothing (n).
trait AsPi {
    fn pi(&self) -> Option<&PiWaiters>;
}

impl AsPi for PiWaiters {
    #[inline(always)]
    fn pi(&self) -> Option<&PiWaiters> {
        Some(self)
    }
}

impl AsPi for () {
    #[inline(always)]
    fn pi(&self) -> Option<&PiWaiters> {
        None
    }
}

/// The call edge's operations; [`Edge`] picks the build's.
trait CallEdge {
    /// At the call: `Some(donee)` (the server's TID when an edge was taken,
    /// else NO_DONEE), `None` when the edge would close a cycle (no call).
    fn lend(caller_idx: usize, server_idx: usize, server: u32, donate: bool) -> Option<u32>;
    /// The task in slot `caller_idx` leaves its own call edge, if it has one.
    fn leave(caller_idx: usize);
    /// Someone else retires the call of record `caller_idx` whose token
    /// `donee` it took: the edge to `donee`'s node goes.
    fn retire(caller_idx: usize, donee: u32);
    /// The fast path's call (Chain E, under WAIT_GRAPH): the edge [`lend`]
    /// would take, only when it is lazy (the call boosts nothing, carries no
    /// chain, closes no cycle): `Some(donee)` as [`lend`]'s, `None` with no
    /// edge (the ordinary path lends it). The graph lock only to set the
    /// node's owner, once per server slot, as [`lend`] does.
    fn lend_quiet(caller_idx: usize, server_idx: usize, server: u32) -> Option<u32>;
    /// [`lend_quiet`]'s edge to the server in slot `server_idx` goes again
    /// (the fast call was not made), or the replier `server_idx` retires it.
    fn retire_at(caller_idx: usize, server_idx: usize);
    /// The call of record `caller_idx` boosts nothing: its edge, if any, is
    /// lazy (a reply that would unboost takes the ordinary path).
    fn quiet(caller_idx: usize) -> bool;
}

type Edge = NodeSel<GRAPH>;

impl CallEdge for NodeSel<true> {
    #[inline]
    fn lend(caller_idx: usize, server_idx: usize, server: u32, donate: bool) -> Option<u32> {
        let node = match CALL_NODES.get(server_idx).and_then(AsPi::pi) {
            Some(n) if donate && runtime_edge_on() => n,
            _ => return Some(NO_DONEE),
        };
        // The node is the server slot's: its owner is set once and stays
        // (a lock-free read skips set_owner's lock on every later call).
        if node.owner() != Some(server_idx as waitgraph::TaskId) {
            node.set_owner(Some(server_idx as waitgraph::TaskId));
        }
        // Lock-free when the call boosts nothing (the common case): see
        // `waitgraph::block_on_lazy`.
        match waitgraph::block_on_lazy(&azos_sched::classes::PI_INLINE, caller_idx as waitgraph::TaskId, node) {
            Ok(()) => Some(server),
            Err(WaitError::Deadlock) => None,
            Err(_) => Some(NO_DONEE),
        }
    }

    #[inline]
    fn leave(caller_idx: usize) {
        use waitgraph::SchedPi;
        let Some(on) = azos_sched::classes::PI.blocked_on(caller_idx as waitgraph::TaskId) else { return };
        let base = CALL_NODES.as_ptr() as usize;
        let size = core::mem::size_of::<DonorNode>().max(1);
        let off = on.addr().wrapping_sub(base);
        if off % size != 0 {
            return;
        }
        if let Some(node) = CALL_NODES.get(off / size).and_then(AsPi::pi) {
            waitgraph::unblock_lazy(&azos_sched::classes::PI_INLINE, caller_idx as waitgraph::TaskId, node, UnblockReason::ObjectGone);
        }
    }

    #[inline]
    fn retire(caller_idx: usize, donee: u32) {
        if donee == NO_DONEE {
            return;
        }
        let Some(s) = azos_sched::idx_for_tid(donee) else { return };
        if let Some(node) = CALL_NODES.get(s).and_then(AsPi::pi) {
            waitgraph::unblock_lazy(&azos_sched::classes::PI_INLINE, caller_idx as waitgraph::TaskId, node, UnblockReason::Acquired);
        }
    }

    #[inline(always)]
    fn lend_quiet(caller_idx: usize, server_idx: usize, server: u32) -> Option<u32> {
        let Some(node) = CALL_NODES.get(server_idx).and_then(AsPi::pi) else { return Some(NO_DONEE) };
        if !runtime_edge_on() {
            return Some(NO_DONEE);
        }
        // The node is the server slot's: its owner is set once and stays, as
        // in `lend` (the one graph-lock take of this path, once per server
        // slot, or again after a server died with callers on its node).
        if node.owner() != Some(server_idx as waitgraph::TaskId) {
            node.set_owner(Some(server_idx as waitgraph::TaskId));
        }
        waitgraph::block_on_quiet(&azos_sched::classes::PI_INLINE, caller_idx as waitgraph::TaskId, node).then_some(server)
    }

    #[inline(always)]
    fn retire_at(caller_idx: usize, server_idx: usize) {
        if let Some(node) = CALL_NODES.get(server_idx).and_then(AsPi::pi) {
            waitgraph::unblock_lazy(&azos_sched::classes::PI_INLINE, caller_idx as waitgraph::TaskId, node, UnblockReason::Acquired);
        }
    }

    #[inline(always)]
    fn quiet(caller_idx: usize) -> bool {
        waitgraph::edge_is_quiet(&azos_sched::classes::PI_INLINE, caller_idx as waitgraph::TaskId)
    }
}

impl CallEdge for NodeSel<false> {
    #[inline(always)]
    fn lend(_: usize, _: usize, _: u32, _: bool) -> Option<u32> {
        Some(NO_DONEE)
    }
    #[inline(always)]
    fn leave(_: usize) {}
    #[inline(always)]
    fn retire(_: usize, _: u32) {}
    #[inline(always)]
    fn lend_quiet(_: usize, _: usize, _: u32) -> Option<u32> {
        Some(NO_DONEE)
    }
    #[inline(always)]
    fn retire_at(_: usize, _: usize) {}
    #[inline(always)]
    fn quiet(_: usize) -> bool {
        true
    }
}

/// Runtime canary `ipc-call-no-edge`: a call takes no wait-graph edge, so a
/// low-priority server answers at its own priority (ktest
/// `waitgraph_ipc_call_boosts_server`, WAIT_GRAPH y). Zero-sized with n.
static CANARY_NO_EDGE: [core::sync::atomic::AtomicBool; GRAPH as usize] =
    [const { core::sync::atomic::AtomicBool::new(false) }; GRAPH as usize];

#[inline(always)]
fn runtime_edge_on() -> bool {
    !CANARY_NO_EDGE.iter().any(|c| c.load(core::sync::atomic::Ordering::Relaxed))
}

/// Arm `canary=ipc-call-no-edge` (boot, once). A no-op with WAIT_GRAPH n.
#[inline]
pub fn canary_ipc_call_no_edge() {
    for c in &CANARY_NO_EDGE {
        c.store(true, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Queue `caller_tid`'s call (task slot `caller_idx`, the current task) on
/// `dest` (lending the caller's priority to the
/// server when `donate`), and return its handle; `None` when it cannot be
/// made (the server is the caller, gone or exiting, or the endpoint changed
/// since `dest` was looked up). Nothing is owed on `None`.
#[inline]
pub fn call(caller_idx: usize, caller_tid: u32, dest: Dest, words: [u64; WORDS], moved_cap: u32, donate: bool) -> Option<u64> {
    azos_trace::ipc_call(caller_tid, dest.owner, words[0] as u32);
    let server = dest.owner;
    // A self-call would block on a reply only the caller could send.
    if caller_tid == server {
        return None;
    }
    let server_idx = azos_sched::idx_for_tid(server)?;
    // The server's exit hook may have run with its slot not yet freed:
    // refuse a call nobody would answer (U04-2 route b).
    if azos_sched::scheduler::slot_is_exiting(server_idx) {
        return None;
    }
    // Lent before the call is published, recorded in the record in the same
    // hold of the queue lock: the server may accept and reply on another CPU
    // before this one runs its next instruction.
    let donee = if GRAPH {
        Edge::lend(caller_idx, server_idx, server, donate)?
    } else if donate && azos_sched::scheduler::donate_priority_for_call_at(server_idx, server) {
        server
    } else {
        NO_DONEE
    };
    let h = ep_queue::call(
        caller_idx, caller_tid, dest.index(), dest.generation(), server, server_idx,
        words, moved_cap, donee,
    );
    if h.is_none() && donee != NO_DONEE {
        if GRAPH {
            Edge::leave(caller_idx);
        } else {
            azos_sched::return_donation(donee);
        }
    }
    h
}

/// A live-update rebind moves the donation of the queued call of the task
/// in slot `caller_idx`, lent to `old` (its donee), to the new server `new`
/// (task slot `new_idx`): with the wait graph, the caller's call edge leaves
/// `old`'s node and goes to `new`'s; else the counted donation is returned
/// (a counted donation lends the running task's priority, so it cannot be
/// taken again for the caller). Returns the call's new donee ([`NO_DONEE`]
/// when `new` takes none: a cycle, or the donation is off). Called by
/// `ep_queue::rebind` under the endpoint's lock.
pub fn retarget_donation(caller_idx: usize, old: u32, new: u32, new_idx: usize) -> u32 {
    if GRAPH {
        Edge::leave(caller_idx);
        Edge::lend(caller_idx, new_idx, new, true).unwrap_or(NO_DONEE)
    } else {
        // A counted donation lends the CURRENT task's priority, and this runs
        // in the supervisor, not the caller: it is returned and not taken
        // again (without the wait graph the re-presented call is not boosted).
        azos_sched::return_donation(old);
        NO_DONEE
    }
}

// ── The IPC fast path (Kconfig IPC_FASTPATH, Chain E stage a) ──────────────

/// The fast path, as far as this crate decides it: Kconfig IPC_FASTPATH.
/// With the wait graph's call edge ([`CALL_EDGE`]) a
/// fast call records the edge the ordinary call would, and only a lazy one
/// (`waitgraph::block_on_quiet`: the call boosts nothing, carries no chain
/// and closes no cycle); a call the graph must act on keeps the ordinary
/// path, and so does a reply whose call's edge is no longer lazy.
pub const FAST_PATH: bool = azos_limits::IPC_FASTPATH;

/// A call lends its priority through its wait-graph edge (Kconfig
/// WAIT_GRAPH), not a counted donation: the fast
/// path's donation check is the edge's quiet predicate instead.
pub const CALL_EDGE: bool = GRAPH;

/// The fast path's call (see `ep_queue::fast_call`): `caller_tid` (task slot
/// `caller_idx`) calls `dest`, served by the task in slot `server_idx`, with
/// `words`; `claim` takes the parked server. The handle, or `None` with
/// nothing done. The call's tracepoint is the one [`call`] records.
///
/// With [`CALL_EDGE`] the caller's lazy edge to the server's node is
/// recorded first, before the call is published, as [`call`] lends it, and
/// the record keeps its token, so whoever ends the call (the reply, the
/// drain, the collect, the abandon) retires it as for an ordinary call. Not
/// quiet: `None` with no edge, for the ordinary path to lend it.
#[inline(always)]
pub fn fast_call(
    caller_idx: usize,
    caller_tid: u32,
    dest: Dest,
    server_idx: usize,
    words: [u64; WORDS],
    claim: impl ep_queue::Claim,
) -> Option<u64> {
    let donee = Edge::lend_quiet(caller_idx, server_idx, dest.owner)?;
    let Some(h) = ep_queue::fast_call(
        caller_idx, caller_tid, dest.index(), dest.generation(), dest.owner, server_idx, words, donee, claim,
    ) else {
        if GRAPH && donee != NO_DONEE {
            Edge::retire_at(caller_idx, server_idx);
        }
        return None;
    };
    azos_trace::ipc_call(caller_tid, dest.owner, words[0] as u32);
    Some(h)
}

/// The fast path's reply (see `ep_queue::fast_reply`): the caller's task
/// slot and TID, or `None` with nothing done. The reply's tracepoint is the
/// one [`reply`] records. With [`CALL_EDGE`] only a call whose edge is lazy
/// (or absent) is answered here, and the replier retires that edge before
/// the caller can run again, as [`reply`] does.
#[inline(always)]
pub fn fast_reply(
    handle: u64,
    replier: u32,
    replier_idx: usize,
    words: [u64; WORDS],
    claim: impl ep_queue::Claim,
) -> Option<(usize, u32)> {
    if GRAPH && !ep_queue::handle_rec(handle).is_some_and(Edge::quiet) {
        return None;
    }
    let (rec, caller, donee) = ep_queue::fast_reply(handle, replier, replier_idx, words, GRAPH, claim)?;
    if GRAPH && donee != NO_DONEE {
        if donee == replier {
            Edge::retire_at(rec, replier_idx);
        } else {
            Edge::retire(rec, donee);
        }
    }
    if azos_trace::ipc_on() {
        azos_trace::raw::ipc_reply(replier, caller, 0);
    }
    Some((rec, caller))
}

/// The call the fast path accepted for `server_tid` (task slot
/// `server_idx`) while it was parked in its accept: `(record, handle)`, read
/// with [`deposit_word`] and [`deposit_caller`]. Always `None` without the
/// fast path.
#[inline(always)]
pub fn take_deposit(server_idx: usize, server_tid: u32) -> Option<(usize, u64)> {
    if !FAST_PATH {
        return None;
    }
    ep_queue::take_deposit(server_idx, server_tid)
}

pub use crate::ep_queue::{deposit_caller, deposit_word, Claim};

/// The task slot of the caller of the call `handle` names (its record's
/// index), or `None` for no handle at all: a hint, read before any lock.
#[inline(always)]
pub fn handle_slot(handle: u64) -> Option<usize> {
    ep_queue::handle_rec(handle)
}

/// The current task, `server_tid` in task slot `server_idx`, takes its next
/// call (the v1 accept). A v2 call it finds is refused, not taken: its
/// caller is completed `-EV1ACCEPT` and woken here (owner decision 10-10,
/// wave 15 N11c; see `ep_queue::take_locked`).
#[inline]
pub fn accept(server_idx: usize, server_tid: u32) -> Option<AcceptedReq> {
    ep_queue::accept::<true>(server_idx, server_tid, complete_one)
}

/// [`accept`] for the v2 accept (`SYS_IPC_ACCEPT_V2`): every call is taken.
#[inline]
pub fn accept_v2(server_idx: usize, server_tid: u32) -> Option<AcceptedReq> {
    ep_queue::accept::<false>(server_idx, server_tid, complete_one)
}

#[inline(always)]
fn map_reply(r: QReply, replier: u32) -> FastIpcReply {
    let out = match r {
        QReply::Woke { caller, rec, donee } => {
            if GRAPH {
                Edge::retire(rec, donee);
            }
            FastIpcReply::Woke { caller_tid: caller, slot_idx: rec, donee: if GRAPH { NO_DONEE } else { donee } }
        }
        QReply::Stale => FastIpcReply::Stale,
        QReply::Refused => FastIpcReply::Refused,
    };
    if azos_trace::ipc_on() {
        let (caller, status) = match out {
            FastIpcReply::Woke { caller_tid, .. } => (caller_tid, 0),
            FastIpcReply::Stale => (0, 1),
            FastIpcReply::Refused => (0, 2),
        };
        azos_trace::raw::ipc_reply(replier, caller, status);
    }
    out
}

/// Answer the call `handle` names (see `ep_queue::reply` for the checks and
/// [`FastIpcReply`] for the outcomes).
#[inline]
pub fn reply(handle: u64, replier: u32, privileged: bool, words: [u64; WORDS]) -> FastIpcReply {
    map_reply(ep_queue::reply(handle, replier, privileged, words), replier)
}

/// [`reply`] and, when it delivered, [`accept`] for the current task, in task
/// slot `server_idx` — see `ep_queue::reply_then_accept` for the
/// donation's hand-back rule.
#[inline]
pub fn reply_then_accept(
    handle: u64,
    replier: u32,
    privileged: bool,
    words: [u64; WORDS],
    server_idx: usize,
) -> (FastIpcReply, Option<AcceptedReq>) {
    let (r, next) = ep_queue::reply_then_accept(handle, replier, privileged, words, server_idx, complete_one);
    (map_reply(r, replier), next)
}

/// `caller_tid` collects its answer to `handle`.
#[inline]
pub fn collect(handle: u64, caller_tid: u32) -> Collected {
    let out = match ep_queue::collect(handle, caller_tid) {
        QCollected::Reply(w, d) => Collected::Reply(w, d),
        QCollected::Done(code, d) => Collected::Done(i64::from(code), d),
        QCollected::Nothing => Collected::Nothing,
    };
    if GRAPH {
        return graph_collected(out, caller_tid);
    }
    out
}

/// [`collect`]'s answer with WAIT_GRAPH: the caller leaves its call edge
/// and owes nothing back.
#[inline(always)]
fn graph_collected(out: Collected, caller_tid: u32) -> Collected {
    let out = match out {
        Collected::Reply(w, _) => Collected::Reply(w, NO_DONEE),
        Collected::Done(code, _) => Collected::Done(code, NO_DONEE),
        Collected::Nothing => return Collected::Nothing,
    };
    if let Some(idx) = azos_sched::idx_for_tid(caller_tid) {
        Edge::leave(idx);
    }
    out
}

/// Where `caller_tid`'s call `handle` stands.
#[inline]
pub fn wait_state(handle: u64, caller_tid: u32) -> FastIpcWait {
    match ep_queue::wait_state(handle, caller_tid) {
        1 => FastIpcWait::Waiting,
        2 => FastIpcWait::Ready,
        _ => FastIpcWait::Gone,
    }
}

/// `caller_tid` leaves its call `handle` without an answer.
///
/// The call is withdrawn and the record freed (the caller's next call needs
/// it); `was_queued` is exact: no server saw the request.
pub fn abandon(handle: u64, caller_tid: u32) -> Abandoned {
    let a = ep_queue::abandon(handle, caller_tid);
    if GRAPH {
        if let Some(idx) = azos_sched::idx_for_tid(caller_tid) {
            Edge::leave(idx);
        }
        return Abandoned { donee: NO_DONEE, was_queued: a.was_queued };
    }
    Abandoned { donee: a.donee, was_queued: a.was_queued }
}

/// The task-exit hook's caller half: withdraw `tid`'s own call. (Its server
/// half is the endpoint's: `endpoint_release_all` / `endpoint_orphan_all`
/// complete every call on the endpoints `tid` served with `-EPEERDIED`.)
pub fn release_all(tid: u32) {
    // Reply warrants `tid` was handed (wave 15 N11): their callers would
    // otherwise wait for an answer nobody holds the right to give.
    ep_queue::release_holder(tid, complete_one);
    let Some(idx) = azos_sched::idx_for_tid(tid) else { return };
    let Some(c) = ep_queue::release_caller(idx, tid) else { return };
    // A dying client's donation goes back to its server; nobody else is
    // left to return it.
    if GRAPH {
        Edge::leave(idx);
    } else if c.donee != NO_DONEE && c.donee != tid {
        azos_sched::return_donation(c.donee);
    }
    // A request never delivered (queued, or refused by a v1 accept and not
    // collected): every capability moved with it is in the server's table
    // and belongs to nothing now. Revoked, not returned (the sender is the
    // one dying).
    for h in c.stranded() {
        crate::cap_store::revoke_moved(c.server, azos_abi::cap::CapHandle(h));
    }
}

/// Complete every call queued on endpoint slot `i` or in service there with
/// `code` (`-EPEERDIED` when its server `server` died, `-EREVOKED` when the
/// endpoint was destroyed), waking each caller. `endpoint.rs` calls this
/// with `ENDPOINTS` released.
pub fn drain_endpoint(i: usize, code: i32, server: u32) {
    ep_queue::drain(i, code, server, |c| {
        // Every capability a queued call moved (a v2 call's whole list).
        for h in c.stranded() {
            crate::cap_store::revoke_moved(c.server, azos_abi::cap::CapHandle(h));
        }
        // A dying server's own boost is not returned: the target is the task
        // being torn down (its slot zeroes the count when reused).
        if c.donee != NO_DONEE && !(code == ep_queue::PEER_DIED && c.donee == server) {
            if GRAPH {
                retire_completed(&c);
            } else {
                azos_sched::return_donation(c.donee);
            }
        }
        // By TID, stamping a caller not yet blocked: the drain can land
        // between its call and its block.
        azos_sched::wait::wake_fast_ipc_client_tid(c.caller, c.handle);
    });
}

/// One call a dead warrant holder strands, completed `-EPEERDIED`, or one
/// the v1 accept refused, completed `-EV1ACCEPT`: the caller is woken and
/// the donation (lent to the endpoint's server, alive) goes back. Nothing
/// is revoked: an accepted request's capabilities are delivered, and a
/// refused v2 call's are taken back by its caller (`azos_syscall::ipc_v2`),
/// or revoked by [`release_all`] when the caller exits first.
fn complete_one(c: ep_queue::Completed) {
    if c.donee != NO_DONEE {
        if GRAPH {
            retire_completed(&c);
        } else {
            azos_sched::return_donation(c.donee);
        }
    }
    azos_sched::wait::wake_fast_ipc_client_tid(c.caller, c.handle);
}

/// WAIT_GRAPH: a call completed by its endpoint (`c.donee` taken) leaves
/// its server's node. A dead server's is left to the caller's collect.
#[inline(always)]
fn retire_completed(c: &ep_queue::Completed) {
    if let Some(rec) = ep_queue::handle_rec(c.handle) {
        Edge::retire(rec, c.donee);
    }
}

// ── ABI v2 of the call (wave 15 N11) ────────────────────────────────────────
//
// A v2 call is a v1 call with the badge stamped on the caller's record
// first; a v2 accept takes every call and also reads the badge, while the
// v1 accept refuses a v2 call (N11c: the one check `ep_queue::take_locked`
// adds to the v1 accept); and the reply warrant is the record's holder
// field, which v1 already checks.

pub use crate::ep_queue::Delegated;

/// [`call`] through an endpoint capability badged `badge` (v2).
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn call_v2(
    caller_idx: usize, caller_tid: u32, dest: Dest, words: [u64; WORDS], moved_cap: u32, donate: bool, badge: u32,
) -> Option<u64> {
    ep_queue::stamp_badge(caller_idx, badge);
    let h = call(caller_idx, caller_tid, dest, words, moved_cap, donate);
    if h.is_none() {
        ep_queue::unstamp_badge(caller_idx);
    }
    h
}

/// The badge of the call `handle` (just accepted by `holder`): `Some` for
/// a v2 call, `None` for a v1 one.
#[inline]
pub fn accept_badge(handle: u64, holder: u32) -> Option<u32> {
    ep_queue::accept_badge(handle, holder)
}

/// Move the reply warrant of `handle` from `holder` to `to`.
pub fn delegate(handle: u64, holder: u32, to: u32) -> Delegated {
    ep_queue::delegate(handle, holder, to)
}

/// Answer `handle` as the holder of its reply warrant; a second answer is
/// refused (canary `ipc-reply-twice` lets it through).
pub fn reply_warrant(handle: u64, holder: u32, words: [u64; WORDS]) -> FastIpcReply {
    map_reply(ep_queue::reply_warrant(handle, holder, words), holder)
}

pub use crate::ep_queue::{Payload, V2_CAPS, V2_WORDS};

/// [`call_v2`] carrying the whole v2 message `msg` (wave 15 N11b): its
/// first four words and first capability also fill the v1 record, which
/// the exit and drain paths read (a v1 accept refuses the call, N11c).
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn call_v2_msg(
    caller_idx: usize, caller_tid: u32, dest: Dest, words: [u64; WORDS], moved_cap: u32, donate: bool, badge: u32,
    msg: &Payload,
) -> Option<u64> {
    ep_queue::stamp_msg(caller_idx, msg);
    let h = call_v2(caller_idx, caller_tid, dest, words, moved_cap, donate, badge);
    if h.is_none() {
        ep_queue::unstamp_msg(caller_idx);
    }
    h
}

/// The v2 request of `handle`, just accepted by `holder`; `None` for v1.
#[inline]
pub fn accept_msg(handle: u64, holder: u32) -> Option<Payload> {
    ep_queue::accept_msg(handle, holder)
}

/// `(caller, is v2)` of the unanswered call whose warrant `holder` holds.
pub fn warrant_peer(handle: u64, holder: u32) -> Option<(u32, bool)> {
    ep_queue::warrant_peer(handle, holder)
}

/// Stage the v2 answer; [`reply_warrant`] publishes it.
pub fn stage_reply(handle: u64, holder: u32, p: &Payload) -> bool {
    ep_queue::stage_reply(handle, holder, p)
}

/// The v2 answer to `handle`, after [`collect`] returned its reply.
pub fn take_reply(caller_idx: usize, handle: u64) -> Option<Payload> {
    ep_queue::take_reply(caller_idx, handle)
}

/// `(pending, accepted, replied, in use)` (diagnostic).
pub fn census() -> (u32, u32, u32, u32) {
    let (p, a, r, d) = ep_queue::census();
    (p, a, r + d, p + a + r + d)
}

/// Every call in flight: `(slot, state 1..=3, caller, server)`.
pub fn slot_ids(out: &mut [(u8, u8, u32, u32)]) -> usize {
    ep_queue::ids(out)
}

