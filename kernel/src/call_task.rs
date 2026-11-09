// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A kernel task that makes the calls a kernel component has for a ring-3
//! server, so that a client waits for the answer with a timer.
//!
//! The kernel's endpoint call (`azos_syscall::kcall`) waits for the server for
//! as long as it takes, and the component's callers are tasks on their own
//! syscall paths. The task owns the server's capabilities (the component's
//! `run` makes the call from its table), makes one call at a time, and a
//! client waits for it for at most the budget it names: a server that is alive
//! and not answering costs a client that budget, never more. The slot's rules
//! (`azos_devif::call_slot`) are checked on the host.
//!
//! A client that is more urgent than the task lends it its priority while it
//! waits, and takes it back however it leaves.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use azos_abi::ipc_msg::MsgDesc;
use azos_devif::call_slot::{deadline_in, park_reason, CallSlot, Poll};
use azos_devif::{IdlError, IdlResult};
use azos_drv_sys::kwarn;
use azos_sched::{BlockOutcome, WaitReason};
use azos_sync::SpinLock;
use azos_syscall::kcall;

pub(crate) struct CallTask<const C: usize, const W: usize> {
    name: &'static str,
    /// Makes one call (to the node it names, or the server's directory) in the
    /// task's own table, and closes any capability the answer carries beyond
    /// what the caller keeps.
    run: fn(Option<u32>, &mut MsgDesc) -> IdlResult,
    /// Gives back a capability of the task's table.
    close: fn(u32),
    slot: SpinLock<CallSlot<C, W>>,
    started: AtomicBool,
    tid: AtomicU32,
}

fn wake(tid: u32, deadline: u64) {
    if tid != 0 {
        let _ = azos_sched::scheduler::wake_task_by_tid(tid, &|r| matches!(r, WaitReason::Timer(d) if *d == deadline));
    }
}

impl<const C: usize, const W: usize> CallTask<C, W> {
    /// `share`: a request equal to the one under way joins it.
    pub(crate) const fn new(
        name: &'static str,
        share: bool,
        run: fn(Option<u32>, &mut MsgDesc) -> IdlResult,
        close: fn(u32),
    ) -> Self {
        Self {
            name,
            run,
            close,
            slot: SpinLock::new(CallSlot::new(share)),
            started: AtomicBool::new(false),
            tid: AtomicU32::new(0),
        }
    }

    /// Start the task, once, from a kernel context.
    pub(crate) fn start(&'static self) {
        if !self.started.swap(true, Ordering::AcqRel) {
            azos_sched::task_create_affinity(self.name, Self::task, self as *const Self as usize, azos_sched::DEFAULT_PRIORITY, -1);
        }
    }

    /// The task's TID, 0 before it ran.
    pub(crate) fn tid(&self) -> u32 {
        self.tid.load(Ordering::Acquire)
    }

    fn kick(&self) {
        wake(self.tid(), park_reason(azos_drv_sys::timebase::now()));
    }

    fn task(arg: usize) {
        // SAFETY: `start` passes a `&'static Self`.
        let this = unsafe { &*(arg as *const Self) };
        this.tid.store(azos_sched::current_task_tid(), Ordering::Release);
        loop {
            let (closes, n, job) = {
                let mut s = this.slot.lock();
                let (closes, n) = s.take_closes();
                (closes, n, s.take())
            };
            for &h in &closes[..n] {
                (this.close)(h);
            }
            let Some(job) = job else {
                if n == 0 {
                    let _ = azos_sched::task_block_outcome(WaitReason::Timer(park_reason(azos_drv_sys::timebase::now())));
                }
                continue;
            };
            let mut msg = job.msg;
            let res = (this.run)(job.node, &mut msg);
            let woken = this.slot.lock().finish(job.seq, &msg, res);
            if woken.orphan {
                let n = (msg.n_caps as usize).min(msg.caps.len());
                for c in &msg.caps[..n] {
                    (this.close)(c.handle);
                }
            }
            for &(tid, deadline) in &woken.waiters {
                wake(tid, deadline);
            }
        }
    }

    /// The request in `*msg` to `node` (`None`: the server's directory)
    /// through the task, answered within `reply_ms` or not at all
    /// (`IdlError::DeadlineExpired`). Blocks the caller: never from an
    /// interrupt handler or with a lock held.
    pub(crate) fn call(&self, node: Option<u32>, msg: &mut MsgDesc, reply_ms: u64) -> IdlResult {
        const BUSY: IdlError = azos_devif::call_slot::BUSY;
        // Refused where the caller may not block, before anything is posted,
        // as `kcall::call` refuses (counted, `-EBUSY`).
        kcall::admit_blocking().map_err(|e| IdlError::Transport(e as isize))?;
        if !self.started.load(Ordering::Acquire) {
            return Err(IdlError::Transport(-1));
        }
        let me = azos_sched::current_task_tid();
        let deadline = deadline_in(azos_drv_sys::timebase::now(), azos_drv_sys::timebase::freq(), reply_ms);
        let posted = self.slot.lock().post(me, deadline, node, msg)?;
        let _lent = Lent::to(self.tid(), me);
        if posted.wake {
            self.kick();
        }
        loop {
            match self.slot.lock().poll(posted.waiter, azos_drv_sys::timebase::now()) {
                Poll::Answer(m, res) => {
                    *msg = m;
                    return res;
                }
                Poll::Expired => return Err(IdlError::DeadlineExpired),
                Poll::Pending => {}
            }
            if azos_sched::task_block_killable(WaitReason::Timer(deadline)) == BlockOutcome::Refused {
                if !self.slot.lock().leave(posted.waiter) {
                    kwarn!("[{}] close queue full: a lent capability stays in the call task's table", self.name);
                }
                self.kick();
                return Err(BUSY);
            }
        }
    }

    /// A capability of the task's table the caller is done with: the task
    /// closes it before its next call.
    #[cfg(feature = "fs-ext4-ring3")]
    pub(crate) fn close(&self, handle: u32) -> bool {
        let queued = self.slot.lock().queue_close(handle);
        if queued {
            self.kick();
        }
        queued
    }
}

/// A client's priority lent to the task (`azos_sched::boost_ready_task`,
/// counted: the task's base priority comes back when the last lender leaves).
/// Only a client more urgent than the task's own lends. Runtime canary
/// `call-no-lend`: nobody lends.
struct Lent(u32);

impl Lent {
    fn to(task: u32, client: u32) -> Option<Lent> {
        let prio = azos_sched::task_priority(client)?;
        if task == 0 || prio >= azos_sched::DEFAULT_PRIORITY || canary!("call-no-lend") {
            return None;
        }
        azos_sched::boost_ready_task(task, prio);
        Some(Lent(task))
    }
}

impl Drop for Lent {
    fn drop(&mut self) {
        azos_sched::restore_ready_task(self.0);
    }
}
