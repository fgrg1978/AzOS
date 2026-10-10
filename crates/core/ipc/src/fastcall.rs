// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The fast call's kernel side, over either implementation (wave 15 N5).
//!
//! `crates/core/syscall`'s fast-call arms and the task-exit hook call this,
//! never `ep_queue` or `fast_ipc` directly. With Kconfig
//! `IPC_ENDPOINT_QUEUES` (the default) a call queues on its endpoint
//! (`ep_queue.rs`); without it the old machine-wide slot table
//! (`fast_ipc.rs`) answers, and its statics are not referenced (the linker
//! drops them).
//!
//! What lives here is what both need from the rest of the kernel: the
//! caller's and the server's task slots, the priority donation (lent before
//! the call is published, returned exactly once), the tracepoints, and, for a
//! call completed by its endpoint's death, the wake, the stranded capability
//! and the donation, all done with no queue lock held.

use crate::endpoint::Dest;
use crate::ep_queue::{self, Collected as QCollected, Reply as QReply};
use crate::fast_ipc;

pub use crate::fast_ipc::{FastIpcReply, FastIpcWait, NO_DONEE};

/// Kconfig `IPC_ENDPOINT_QUEUES`.
pub const QUEUES: bool = azos_limits::IPC_ENDPOINT_QUEUES;

/// Words in a fast-call message.
pub const WORDS: usize = fast_ipc::FAST_IPC_MAX_WORDS;

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


/// Queue `caller_tid`'s call (task slot `caller_idx`, the current task) on
/// `dest` (lending the caller's priority to the
/// server when `donate`), and return its handle; `None` when it cannot be
/// made (the server is the caller, gone or exiting, or the endpoint changed
/// since `dest` was looked up). Nothing is owed on `None`.
#[inline]
pub fn call(caller_idx: usize, caller_tid: u32, dest: Dest, words: [u64; WORDS], moved_cap: u32, donate: bool) -> Option<u64> {
    if !QUEUES {
        return fast_ipc::fast_ipc_call_donating(caller_tid, dest.owner, words, moved_cap, donate);
    }
    azos_trace::ipc_call(caller_tid, dest.owner, words[0] as u32);
    let server = dest.owner;
    // A self-call would block on a reply only the caller could send.
    if caller_tid == server {
        return None;
    }
    let server_idx = azos_sched::idx_for_tid(server)?;
    // The server's exit hook may have run with its slot not yet freed:
    // refuse a call nobody would answer (U04-2 route b).
    if azos_sched::tid_is_exiting(server) {
        return None;
    }
    // Lent before the call is published, recorded in the record in the same
    // hold of the queue lock: the server may accept and reply on another CPU
    // before this one runs its next instruction.
    let donee = if donate && azos_sched::scheduler::donate_priority_for_call_at(server_idx, server) {
        server
    } else {
        NO_DONEE
    };
    let h = ep_queue::call(
        caller_idx, caller_tid, dest.index(), dest.generation(), server, server_idx,
        words, moved_cap, donee,
    );
    if h.is_none() && donee != NO_DONEE {
        azos_sched::return_donation(donee);
    }
    h
}

/// The current task, `server_tid` in task slot `server_idx`, takes its next
/// call.
#[inline]
pub fn accept(server_idx: usize, server_tid: u32) -> Option<AcceptedReq> {
    if !QUEUES {
        return fast_ipc::fast_ipc_accept(server_tid);
    }
    ep_queue::accept(server_idx, server_tid)
}

#[inline(always)]
fn map_reply(r: QReply, replier: u32) -> FastIpcReply {
    let out = match r {
        QReply::Woke { caller, rec, donee } => FastIpcReply::Woke { caller_tid: caller, slot_idx: rec, donee },
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

/// Answer the call `handle` names (see `fast_ipc::fast_ipc_reply` for the
/// checks and the outcomes).
#[inline]
pub fn reply(handle: u64, replier: u32, privileged: bool, words: [u64; WORDS]) -> FastIpcReply {
    if !QUEUES {
        return fast_ipc::fast_ipc_reply(handle, replier, privileged, words);
    }
    map_reply(ep_queue::reply(handle, replier, privileged, words), replier)
}

/// [`reply`] and, when it delivered, [`accept`] for `server_tid` (the
/// current task, in task slot `server_idx`) — see `fast_ipc::fast_ipc_reply_then_accept` for the
/// donation's hand-back rule.
#[inline]
pub fn reply_then_accept(
    handle: u64,
    replier: u32,
    privileged: bool,
    words: [u64; WORDS],
    server_idx: usize,
    server_tid: u32,
) -> (FastIpcReply, Option<AcceptedReq>) {
    if !QUEUES {
        return fast_ipc::fast_ipc_reply_then_accept(handle, replier, privileged, words, server_tid);
    }
    let (r, next) = ep_queue::reply_then_accept(handle, replier, privileged, words, server_idx);
    (map_reply(r, replier), next)
}

/// `caller_tid` collects its answer to `handle`.
#[inline]
pub fn collect(handle: u64, caller_tid: u32) -> Collected {
    if !QUEUES {
        return match fast_ipc::fast_ipc_collect_donated(handle, caller_tid) {
            Some((w, d)) => Collected::Reply(w, d),
            None => Collected::Nothing,
        };
    }
    match ep_queue::collect(handle, caller_tid) {
        QCollected::Reply(w, d) => Collected::Reply(w, d),
        QCollected::Done(code, d) => Collected::Done(i64::from(code), d),
        QCollected::Nothing => Collected::Nothing,
    }
}

/// Where `caller_tid`'s call `handle` stands.
#[inline]
pub fn wait_state(handle: u64, caller_tid: u32) -> FastIpcWait {
    if !QUEUES {
        return fast_ipc::fast_ipc_wait_state(handle, caller_tid);
    }
    match ep_queue::wait_state(handle, caller_tid) {
        1 => FastIpcWait::Waiting,
        2 => FastIpcWait::Ready,
        _ => FastIpcWait::Gone,
    }
}

/// `caller_tid` leaves its call `handle` without an answer.
///
/// With the queues the call is withdrawn and the record freed (the caller's
/// next call needs it); `was_queued` is exact: no server saw the request.
/// The old table keeps the slot (the exit sweep frees it) and can only say
/// the server has not answered, which includes "accepted and about to act".
pub fn abandon(handle: u64, caller_tid: u32) -> Abandoned {
    if !QUEUES {
        let donee = fast_ipc::fast_ipc_withdraw_donation(handle, caller_tid);
        let was_queued = fast_ipc::fast_ipc_wait_state(handle, caller_tid) == FastIpcWait::Waiting;
        return Abandoned { donee, was_queued };
    }
    let a = ep_queue::abandon(handle, caller_tid);
    Abandoned { donee: a.donee, was_queued: a.was_queued }
}

/// The task-exit hook's caller half: withdraw `tid`'s own call. (Its server
/// half is the endpoint's: `endpoint_release_all` / `endpoint_orphan_all`
/// complete every call on the endpoints `tid` served with `-EPEERDIED`.)
pub fn release_all(tid: u32) {
    if !QUEUES {
        fast_ipc::fast_ipc_release_all(tid);
        return;
    }
    // Reply warrants `tid` was handed (wave 15 N11): their callers would
    // otherwise wait for an answer nobody holds the right to give.
    ep_queue::release_holder(tid, complete_one);
    let Some(idx) = azos_sched::idx_for_tid(tid) else { return };
    let Some(c) = ep_queue::release_caller(idx, tid) else { return };
    // A dying client's donation goes back to its server; nobody else is
    // left to return it.
    if c.donee != NO_DONEE && c.donee != tid {
        azos_sched::return_donation(c.donee);
    }
    // A request never delivered: the capability moved with it is in the
    // server's table and belongs to nothing now. Revoked, not returned (the
    // sender is the one dying).
    if c.moved_cap != 0 {
        crate::cap_store::revoke_moved(c.server, azos_abi::cap::CapHandle(c.moved_cap));
    }
}

/// Complete every call queued on endpoint slot `i` or in service there with
/// `code` (`-EPEERDIED` when its server `server` died, `-EREVOKED` when the
/// endpoint was destroyed), waking each caller. `endpoint.rs` calls this
/// with `ENDPOINTS` released.
pub fn drain_endpoint(i: usize, code: i32, server: u32) {
    ep_queue::drain(i, code, server, |c| {
        if c.moved_cap != 0 {
            crate::cap_store::revoke_moved(c.server, azos_abi::cap::CapHandle(c.moved_cap));
        }
        // A dying server's own boost is not returned: the target is the task
        // being torn down (its slot zeroes the count when reused).
        if c.donee != NO_DONEE && !(code == ep_queue::PEER_DIED && c.donee == server) {
            azos_sched::return_donation(c.donee);
        }
        // By TID, stamping a caller not yet blocked: the drain can land
        // between its call and its block.
        azos_sched::wait::wake_fast_ipc_client_tid(c.caller, c.handle);
    });
}

/// One call a dead warrant holder strands, completed `-EPEERDIED`: the
/// caller is woken and the donation (lent to the endpoint's server, alive)
/// goes back. Nothing was moved with an accepted request that is not
/// already delivered.
fn complete_one(c: ep_queue::Completed) {
    if c.donee != NO_DONEE {
        azos_sched::return_donation(c.donee);
    }
    azos_sched::wait::wake_fast_ipc_client_tid(c.caller, c.handle);
}

// ── ABI v2 of the call (wave 15 N11) ────────────────────────────────────────
//
// The v1 functions above are untouched: a v2 call is a v1 call with the
// badge stamped on the caller's record first, a v2 accept is a v1 accept
// that also reads the badge, and the reply warrant is the record's holder
// field, which v1 already checks. With Kconfig IPC_ENDPOINT_QUEUES off
// (the old table) there is no warrant to move: v2 refuses.

pub use crate::ep_queue::Delegated;

/// [`call`] through an endpoint capability badged `badge` (v2).
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn call_v2(
    caller_idx: usize, caller_tid: u32, dest: Dest, words: [u64; WORDS], moved_cap: u32, donate: bool, badge: u32,
) -> Option<u64> {
    if !QUEUES {
        return None;
    }
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
    if !QUEUES {
        return None;
    }
    ep_queue::accept_badge(handle, holder)
}

/// Move the reply warrant of `handle` from `holder` to `to`.
pub fn delegate(handle: u64, holder: u32, to: u32) -> Delegated {
    if !QUEUES {
        return Delegated::Refused;
    }
    ep_queue::delegate(handle, holder, to)
}

/// Answer `handle` as the holder of its reply warrant; a second answer is
/// refused (canary `ipc-reply-twice` lets it through).
pub fn reply_warrant(handle: u64, holder: u32, words: [u64; WORDS]) -> FastIpcReply {
    if !QUEUES {
        return FastIpcReply::Refused;
    }
    map_reply(ep_queue::reply_warrant(handle, holder, words), holder)
}

/// `(pending, accepted, replied, in use)` (diagnostic).
pub fn census() -> (u32, u32, u32, u32) {
    if !QUEUES {
        return fast_ipc::fast_ipc_census();
    }
    let (p, a, r, d) = ep_queue::census();
    (p, a, r + d, p + a + r + d)
}

/// Every call in flight: `(slot, state 1..=3, caller, server)`.
pub fn slot_ids(out: &mut [(u8, u8, u32, u32)]) -> usize {
    if !QUEUES {
        return fast_ipc::fast_ipc_slot_ids(out);
    }
    ep_queue::ids(out)
}

/// Fast-IPC lock taken from interrupt context (the old table's watch; the
/// queues' locks are interrupt-safe, so 0 with them).
pub fn irq_ctx_violations() -> u32 {
    if !QUEUES {
        return fast_ipc::fast_ipc_irq_ctx_violations();
    }
    0
}
