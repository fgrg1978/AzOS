// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The state of a kernel call task: the one call posted or under way, the
//! clients waiting for its answer, and the capabilities to close.
//!
//! A kernel component that calls a ring-3 server from the syscall path of any
//! task hands the call to a task of its own and waits for it with a timer
//! (`kernel/src/call_task.rs`). This is that hand-off without the scheduler:
//! every method is a step the caller makes under its lock, so the rules (one
//! call in flight, who joins it, what an abandoned call costs, how long an
//! idle task may sleep) are checked on the host.

use azos_abi::ipc_msg::MsgDesc;
use azos_idl::{IdlError, Result as IdlResult};

/// The `Timer` value a call task with nothing posted sleeps on, and that a
/// client's wake names. One value for every park, whatever the time: a wake
/// names the value read before the task committed to sleep, and a task that
/// parked on another by then is found asleep on a reason the wake does not
/// match and is left asleep. With one value, a wake that comes before the sleep
/// is kept by the scheduler (a stamp that the commit consumes) and one that
/// comes after matches.
pub fn park_reason(now: u64) -> u64 {
    if cfg!(feature = "call-slot-park-canary") {
        return now | 1;
    }
    u64::MAX
}

/// The absolute tick `ms` from `now`.
pub fn deadline_in(now: u64, freq: u64, ms: u64) -> u64 {
    now.saturating_add(freq.saturating_mul(ms) / 1000)
}

/// The call a client posted, or joined.
#[derive(Clone, Copy)]
pub struct Posted {
    /// The waiter's place in the slot, for [`CallSlot::poll`] and [`CallSlot::leave`].
    pub waiter: usize,
    /// The call task must be woken: the call is posted and not yet taken.
    pub wake: bool,
}

/// What a call task takes to make.
#[derive(Clone, Copy)]
pub struct Take {
    pub seq: u32,
    pub node: Option<u32>,
    pub msg: MsgDesc,
}

/// What a waiting client finds.
pub enum Poll {
    Pending,
    Answer(MsgDesc, IdlResult),
    /// Its deadline passed. A call nobody took is withdrawn; one under way runs
    /// to its end and its answer is dropped.
    Expired,
}

/// Clients to wake once a call is answered: `(tid, deadline)` of each.
pub struct Woken<const W: usize> {
    pub waiters: [(u32, u64); W],
    /// Nobody was waiting: the answer's capabilities have no taker.
    pub orphan: bool,
}

#[derive(Clone, Copy)]
struct Job {
    seq: u32,
    node: Option<u32>,
    req: MsgDesc,
    taken: bool,
}

#[derive(Clone, Copy)]
struct Waiter {
    tid: u32,
    deadline: u64,
    seq: u32,
    answer: Option<(MsgDesc, IdlResult)>,
}

/// One call at a time, at most `W` clients waiting for it, and at most `C`
/// capabilities of the call task's table to close.
pub struct CallSlot<const C: usize, const W: usize> {
    job: Option<Job>,
    last: u32,
    waiters: [Option<Waiter>; W],
    closes: [u32; C],
    n_closes: usize,
    /// A request equal to the one under way joins it and shares its answer.
    share: bool,
}

/// The refusal of a call that cannot be posted now: another is under way, or
/// no place is left to wait.
pub const BUSY: IdlError = IdlError::Transport(-16);

impl<const C: usize, const W: usize> CallSlot<C, W> {
    pub const fn new(share: bool) -> Self {
        Self { job: None, last: 0, waiters: [None; W], closes: [0; C], n_closes: 0, share }
    }

    /// Post `msg` (to `node`: `None` is the server's directory), or join the
    /// call under way when it asks the same and the slot shares.
    pub fn post(&mut self, tid: u32, deadline: u64, node: Option<u32>, msg: &MsgDesc) -> Result<Posted, IdlError> {
        let Some(waiter) = self.waiters.iter().position(Option::is_none) else { return Err(BUSY) };
        let (seq, wake) = match self.job {
            Some(j) if self.share && j.node == node && j.req == *msg => {
                (j.seq, !j.taken && !cfg!(feature = "call-slot-joiner-canary"))
            }
            Some(_) => return Err(BUSY),
            None => {
                self.last = self.last.wrapping_add(1);
                self.job = Some(Job { seq: self.last, node, req: *msg, taken: false });
                (self.last, true)
            }
        };
        self.waiters[waiter] = Some(Waiter { tid, deadline, seq, answer: None });
        Ok(Posted { waiter, wake })
    }

    /// Queue a capability of the call task's table to close; `false`: the
    /// queue is full.
    pub fn queue_close(&mut self, handle: u32) -> bool {
        let Some(at) = self.closes.get_mut(self.n_closes) else { return false };
        *at = handle;
        self.n_closes += 1;
        true
    }

    /// The capabilities queued to close, taken.
    pub fn take_closes(&mut self) -> ([u32; C], usize) {
        (self.closes, core::mem::take(&mut self.n_closes))
    }

    /// The call posted and not yet taken, now taken.
    pub fn take(&mut self) -> Option<Take> {
        let j = self.job.as_mut().filter(|j| !j.taken)?;
        j.taken = true;
        Some(Take { seq: j.seq, node: j.node, msg: j.req })
    }

    /// The call `seq` is answered: every client waiting for it has the answer.
    pub fn finish(&mut self, seq: u32, msg: &MsgDesc, res: IdlResult) -> Woken<W> {
        let mut out = Woken { waiters: [(0, 0); W], orphan: true };
        self.job = None;
        for (w, o) in self.waiters.iter_mut().flatten().filter(|w| w.seq == seq).zip(out.waiters.iter_mut()) {
            w.answer = Some((*msg, res));
            *o = (w.tid, w.deadline);
            out.orphan = false;
        }
        out
    }

    /// A client's look at its wait.
    pub fn poll(&mut self, waiter: usize, now: u64) -> Poll {
        let Some(w) = self.waiters[waiter].as_mut() else { return Poll::Expired };
        if let Some((msg, res)) = w.answer.take() {
            self.waiters[waiter] = None;
            return Poll::Answer(msg, res);
        }
        if now >= w.deadline {
            self.leave(waiter);
            return Poll::Expired;
        }
        Poll::Pending
    }

    /// A client stops waiting. The call it posted, if nobody took it and
    /// nobody else waits for it, is withdrawn. The capabilities of an answer
    /// that had come and that the client did not read are queued to close
    /// (they are in the call task's table); `false`: the queue was full and
    /// some stay there.
    pub fn leave(&mut self, waiter: usize) -> bool {
        let Some(w) = self.waiters[waiter].take() else { return true };
        let others = self.waiters.iter().flatten().any(|o| o.seq == w.seq);
        if !others && self.job.is_some_and(|j| j.seq == w.seq && !j.taken) {
            self.job = None;
        }
        let Some((m, _)) = w.answer else { return true };
        let n = (m.n_caps as usize).min(m.caps.len());
        m.caps[..n].iter().fold(true, |all, c| self.queue_close(c.handle) && all)
    }
}
