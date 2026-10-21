// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! When a busy CPU may stop its periodic tick (Kconfig NOHZ_FULL), with no
//! hardware and no scheduler state in it.
//!
//! `timebase` owns the comparator and the scheduler owns the queues; this
//! module only answers the questions between them, over plain numbers, so the
//! host suite (`tests/host/sched-policy-tests`, pulled in with `#[path]`) runs
//! the same code the kernel runs:
//!
//! * [`lone_rt`]: is the CPU isolated and running exactly one real-time task,
//!   with nothing else ready and nothing waiting to be queued?
//! * [`observe`]: the stop is taken at the second consecutive tick that sees
//!   the same lone task ([`LONE_TICKS_TO_STOP`]), not at the first;
//! * [`stop_bound`]: how far out a stopped tick may sleep.
//!
//! # Why the second tick
//!
//! A task enters user mode for the first time through the context switch's
//! entry path, not through a trap return, so that one entry does not leave
//! RCU's extended quiescent state in the state it would be in after any
//! other return (`qsbr.rs`: the guard of a trap return does). A tick that
//! stops at the very tick that found the task new could therefore leave the
//! CPU "in the kernel" for RCU for as long as the task never traps. By the
//! second tick the task has been interrupted in user mode once and the
//! return of that interrupt has put the CPU in the state. A different task
//! on the CPU starts the count again.

/// Consecutive ticks that must see the same lone task before the tick stops.
pub const LONE_TICKS_TO_STOP: u8 = 2;

/// What the scheduler reads of one CPU at a tick.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cpu {
    /// The CPU is in `[sched] isolcpus`.
    pub isolated: bool,
    /// The task the tick interrupted is running and in the real-time band.
    pub running_rt: bool,
    /// Another task is ready on this CPU's queues (idle excluded).
    pub other_ready: bool,
    /// A wake for this CPU is on its deferred list, not yet queued.
    pub wake_pending: bool,
}

/// Whether `cpu` is in `mask` (bit n = CPU n); a CPU past the mask's width is
/// in no mask.
#[inline(always)]
pub const fn in_mask(mask: u64, cpu: usize) -> bool {
    cpu < u64::BITS as usize && mask >> cpu & 1 != 0
}

/// Is a task of priority `prio` and state "running" in the real-time band
/// (priorities below `rt_threshold`)?
#[inline(always)]
pub const fn running_rt(running: bool, prio: u32, rt_threshold: u32) -> bool {
    running && prio < rt_threshold
}

/// Is any level but the idle one set in a CPU's ready bitmap? The idle task
/// is always ready, so its bit does not count.
#[inline(always)]
pub const fn others_ready(ready_bitmap: u32, idle_prio: u32) -> bool {
    ready_bitmap & !(1u32 << idle_prio) != 0
}

/// The CPU is isolated, its one runnable task is real-time, and nothing is
/// queued or about to be.
#[inline(always)]
pub const fn lone_rt(c: Cpu) -> bool {
    c.isolated && c.running_rt && !c.other_ready && !c.wake_pending
}

/// One tick's observation, kept per CPU: the task seen and how many ticks in
/// a row have seen it alone.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Seen {
    pub tid: u32,
    pub ticks: u8,
}

/// The state after a tick that found `tid` running and the CPU lone (`lone`)
/// or not, and whether the tick may stop now.
///
/// A CPU that is not lone, or whose lone task is not the one seen last time,
/// starts the count over. The count saturates at [`LONE_TICKS_TO_STOP`]: a
/// stopped tick that fires again (its residual, a timer deadline) goes on
/// answering "stop" while the task stays alone.
#[inline]
pub const fn observe(prev: Seen, tid: u32, lone: bool) -> (Seen, bool) {
    if !lone {
        return (Seen { tid: 0, ticks: 0 }, false);
    }
    let ticks = if prev.tid == tid && prev.ticks < LONE_TICKS_TO_STOP {
        prev.ticks + 1
    } else if prev.tid == tid {
        prev.ticks
    } else {
        1
    };
    (Seen { tid, ticks }, ticks >= LONE_TICKS_TO_STOP)
}

/// Pack a [`Seen`] into one word (a per-CPU atomic).
#[inline(always)]
pub const fn pack(s: Seen) -> u64 {
    (s.tid as u64) << 8 | s.ticks as u64
}

/// Inverse of [`pack`].
#[inline(always)]
pub const fn unpack(w: u64) -> Seen {
    Seen { tid: (w >> 8) as u32, ticks: w as u8 }
}

/// How far out a stopped tick may sleep, in counter ticks: the residual
/// (`NOHZ_FULL_RESIDUAL_MS`), cut to hart 0's watchdog keepalive when one is
/// armed (the feed runs from hart 0's tick) and to the idle-poll bound while
/// kernel work that only the tick observes is pending. Whatever the
/// scheduler programs is then the earlier of this and the nearest timer
/// deadline (`timer_arm::next_event` with `Cap::IdleKeepalive`).
#[inline]
pub const fn stop_bound(residual: u64, keepalive: Option<u64>, poll: Option<u64>) -> u64 {
    let mut b = residual;
    if let Some(k) = keepalive {
        if k < b { b = k; }
    }
    if let Some(p) = poll {
        if p < b { b = p; }
    }
    b
}
