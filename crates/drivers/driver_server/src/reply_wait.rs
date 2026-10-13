// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Blocking wait for a ring-3 driver's reply, for an in-kernel client (the
//! `UserDriverProxy` in `crates/drivers/sys`).
//!
//! # The protocol: arm under the submit lock, re-test, block
//!
//! * **Arm.** [`crate::driver_submit_request_armed`] records the waiter
//!   `(tid, token, deadline)` in the same `REGISTRY` hold that queues the
//!   request. The driver cannot fetch the request before that hold is
//!   released, so it cannot reply before the waiter exists.
//! * **Wake.** [`crate::driver_reply`] writes the reply into the row of the
//!   waiter whose token it answers in one hold, then calls the installed
//!   [`ProxyHooks::wake`] after releasing it (the `port.rs` order: the wake
//!   takes run-queue locks).
//! * **Re-test, then block.** [`wait_for_reply`] tests for the reply before
//!   every block. A reply that lands between the test and the block wakes a
//!   task that has not committed to `Blocked`; the scheduler stamps it (K-C9)
//!   and the block returns at once, so the next test finds the reply. That is
//!   the whole lost-wake argument: every reply after the arm produces a wake,
//!   and a wake is never lost, only early.
//!
//! The block is `WaitReason::Timer(deadline)` and the wake is addressed by TID
//! with the predicate `Timer(d) if d == deadline` — the notify path
//! (`crates/core/ipc/src/notify.rs`), so the timeout needs no timer of its own: the
//! timer sweep ends the block at the deadline.
//!
//! # Why hooks
//!
//! Neither this crate nor `azos_drv_sys` depends on the scheduler. The
//! kernel installs [`ProxyHooks`] once at boot (`install_sched_hooks`). Until
//! it has, the proxy refuses instead of falling back to spinning: a fallback
//! would keep every scenario green with the block path broken.
//!
//! # One reply slot per request
//!
//! Each armed request owns its waiter row until its client withdraws it, and
//! the reply is delivered INTO that row ([`ReplyWaiters::deliver`]). This
//! replaced a single `last_reply` per kind, where a second client's reply
//! could overwrite the first's before it was taken and the first client then
//! timed out. A request whose client timed out stays queued; its reply finds
//! no row and goes to the kind's polling ring (`crate::ReplyRing`), where
//! nobody reads it.

use core::sync::atomic::{AtomicPtr, Ordering};

/// What the proxy and the reply path need from the scheduler.
pub struct ProxyHooks {
    /// Block the caller on `WaitReason::Timer(deadline)`. `true` when the
    /// scheduler refused to block (K-C29: a critical section is open).
    pub block: fn(u64) -> bool,
    /// Wake `tid` if it is blocked on `Timer(deadline)`, stamping it if it has
    /// not blocked yet. Callable from any context the reply path runs in.
    pub wake: fn(u32, u64),
    /// The calling task's TID.
    pub current_tid: fn() -> u32,
    /// Donate `donor`'s live priority to `target` when the donation rule allows
    /// it (`azos_sched::donation`). `true` = one `undonate(target)` is owed.
    pub donate: fn(u32, u32) -> bool,
    /// Undo one donation to `target`.
    pub undonate: fn(u32),
    /// Is `tid` running on a hart other than the caller's right now? Gates
    /// the bounded spin in [`wait_for_reply`].
    pub peer_running: fn(u32) -> bool,
}

static HOOKS: AtomicPtr<ProxyHooks> = AtomicPtr::new(core::ptr::null_mut());

/// Install the hooks. Called once at boot, before any in-kernel client of a
/// ring-3 driver runs.
pub fn set_proxy_hooks(h: &'static ProxyHooks) {
    HOOKS.store(h as *const ProxyHooks as *mut ProxyHooks, Ordering::Release);
}

/// The installed hooks, if any.
pub fn proxy_hooks() -> Option<&'static ProxyHooks> {
    let p = HOOKS.load(Ordering::Acquire);
    // SAFETY: only ever set from a `&'static ProxyHooks`.
    if p.is_null() { None } else { Some(unsafe { &*p }) }
}

/// A client blocked on one token.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReplyWaiter {
    pub tid: u32,
    pub token: u64,
    pub deadline: u64,
}

/// Waiter rows per kind: in-kernel clients of one kind blocked on a reply at
/// once. 4, below the queue depth (8), by owner decision 2026-09-28 (kernel
/// image size: rows per kind, `DRIVER_MAX_KINDS` kinds). A fifth armed client of the
/// same kind is refused at submit (`driver_submit_request_armed` answers
/// `None`, nothing queued), which the proxy reports as busy.
pub const MAX_REPLY_WAITERS: usize = 4;

/// What [`ReplyWaiters::deliver`] did with a reply.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Delivery {
    /// Written into row `.0`, whose waiter is `.1` (the one to wake).
    ToWaiter(usize, ReplyWaiter),
    /// The row of that token already holds a reply: this one is dropped.
    Duplicate,
    /// No row is armed on that token.
    NoWaiter,
}

/// What [`ReplyWaiters::withdraw`] found.
#[derive(Clone, Copy)]
pub enum Withdrawn {
    /// No row of that `(tid, token)`: never armed, or already withdrawn.
    NotArmed,
    /// The row was armed and had no reply yet.
    Armed,
    /// The row held its reply, which is returned.
    Replied(crate::DriverReply),
}

/// The armed waiters of one driver kind, each with the reply delivered to it.
/// Mutated only under `REGISTRY`.
#[derive(Clone, Copy)]
pub struct ReplyWaiters {
    rows: [Option<ReplyWaiter>; MAX_REPLY_WAITERS],
    replies: [Option<crate::DriverReply>; MAX_REPLY_WAITERS],
}

impl ReplyWaiters {
    pub const fn new() -> Self {
        ReplyWaiters { rows: [None; MAX_REPLY_WAITERS], replies: [None; MAX_REPLY_WAITERS] }
    }

    /// File `w`. The row index, or `None` when every row is taken.
    pub fn arm(&mut self, w: ReplyWaiter) -> Option<usize> {
        for (i, r) in self.rows.iter_mut().enumerate() {
            if r.is_none() {
                *r = Some(w);
                self.replies[i] = None;
                return Some(i);
            }
        }
        None
    }

    /// Reply side: put `reply` in the row armed on its token. The row stays
    /// until its client withdraws it, so the reply cannot be overwritten by
    /// another token's.
    pub fn deliver(&mut self, reply: crate::DriverReply) -> Delivery {
        for i in 0..MAX_REPLY_WAITERS {
            if let Some(w) = self.rows[i] {
                if w.token == reply.token {
                    if self.replies[i].is_some() {
                        return Delivery::Duplicate;
                    }
                    self.replies[i] = Some(reply);
                    return Delivery::ToWaiter(i, w);
                }
            }
        }
        Delivery::NoWaiter
    }

    /// Client side, at the end of its wait: free its row and take the reply
    /// in it, if one was delivered.
    pub fn withdraw(&mut self, tid: u32, token: u64) -> Withdrawn {
        for i in 0..MAX_REPLY_WAITERS {
            if matches!(self.rows[i], Some(w) if w.tid == tid && w.token == token) {
                self.rows[i] = None;
                return match self.replies[i].take() {
                    Some(r) => Withdrawn::Replied(r),
                    None => Withdrawn::Armed,
                };
            }
        }
        Withdrawn::NotArmed
    }

    /// Drop every row (the kind was released).
    pub fn clear(&mut self) -> [Option<ReplyWaiter>; MAX_REPLY_WAITERS] {
        let out = self.rows;
        *self = ReplyWaiters::new();
        out
    }

    pub fn armed(&self) -> usize {
        self.rows.iter().filter(|r| r.is_some()).count()
    }
}

/// What the wait loop needs: a clock in the unit of `deadline`, and the block.
pub trait ReplyWaitEnv {
    fn now(&self) -> u64;
    /// `true` when the scheduler refused to block.
    fn block(&self, deadline: u64) -> bool;
    /// Is the task that will answer running on another hart right now? Only
    /// then does [`wait_for_reply`] spin before it blocks. Default: never.
    fn peer_running(&self) -> bool {
        false
    }
    /// The spin bound, in `now()` ticks. Default: no spin.
    fn spin_ticks(&self) -> u64 {
        0
    }
    /// Called when a spin found the reply (telemetry).
    fn note_spin_hit(&self) {}
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitOutcome {
    /// The reply was taken.
    Replied,
    /// The deadline passed with no reply.
    TimedOut,
    /// The scheduler refused to block (K-C29) and no reply had arrived.
    Refused,
}

/// Wait until `reply_ready` finds the reply, the deadline passes, or the
/// scheduler refuses to block. `disarm` is called exactly once, on every way
/// out, before the final verdict is read — so a reply that races the timeout
/// is still reported as a reply.
///
/// After `disarm` the reply path can no longer TAKE this waiter, but a wake it
/// took just before may still be in flight and land on the caller's next
/// block as an early return. Every block in this kernel is re-tested by its
/// caller (`BlockOutcome::Returned`'s contract), so that costs one extra test,
/// never a missed condition.
///
/// # The bounded spin (wave 9)
///
/// Before each block, and only while the answering task is RUNNING on another
/// hart ([`ReplyWaitEnv::peer_running`], re-read on every poll), the loop polls
/// `reply_ready` for up to [`ReplyWaitEnv::spin_ticks`] (the proxy passes
/// ~20 µs), never past `deadline`. A reply found there skips the block and the
/// wake: no switch on this hart, no IPI from the replier. A driver that is not
/// running (blocked, preempted, or on this very hart) cannot answer within the
/// bound, so the loop blocks at once — the spin never delays a block that the
/// reply could not have avoided. One spin per block: the loop cannot turn into
/// a spin to the deadline.
pub fn wait_for_reply<E: ReplyWaitEnv>(
    env: &E,
    deadline: u64,
    mut reply_ready: impl FnMut() -> bool,
    mut disarm: impl FnMut(),
) -> WaitOutcome {
    loop {
        if reply_ready() {
            disarm();
            return WaitOutcome::Replied;
        }
        if env.now() >= deadline {
            disarm();
            return if reply_ready() { WaitOutcome::Replied } else { WaitOutcome::TimedOut };
        }
        if env.peer_running() {
            let end = env.now().saturating_add(env.spin_ticks()).min(deadline);
            while env.now() < end && env.peer_running() {
                if reply_ready() {
                    env.note_spin_hit();
                    disarm();
                    return WaitOutcome::Replied;
                }
                core::hint::spin_loop();
            }
        }
        if env.block(deadline) {
            // Blocking again would be refused again: never spin on it.
            disarm();
            return if reply_ready() { WaitOutcome::Replied } else { WaitOutcome::Refused };
        }
        // Woken (a reply, an early stamp, or the deadline): test again.
    }
}
