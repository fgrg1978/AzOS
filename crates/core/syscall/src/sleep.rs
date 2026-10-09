// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SYS_SLEEP` and `SYS_SLEEP_UNTIL` (RFC-0044): the caller blocks on the
//! timer counter instead of running while the time passes.
//!
//! Both block on `WaitReason::Timer`, the reason kernel tasks sleep on. The
//! timer interrupt wakes expired sleepers (`wake_expired_timers`) and programs
//! the next interrupt for the nearest sleeping deadline (`set_next_tick_smart`),
//! so a deadline more than one tick away wakes on time and a nearer one waits
//! at most for the tick already programmed.

use azos_abi::time::ns_to_ticks_ceil;
use azos_drv_sys::timebase::{now as get_time, TIMER_FREQ};

/// Block until the counter reaches `deadline`. A wake before it, stamped for
/// another reason, blocks again.
///
/// A block refused because preemption is off on this hart (K-C29) would be
/// refused again on every turn, so that caller waits on the counter instead of
/// re-entering the scheduler in a loop.
fn block_until(deadline: u64) {
    use azos_sched::{task_block_killable, BlockOutcome, WaitReason};
    while get_time() < deadline {
        if task_block_killable(WaitReason::Timer(deadline)) == BlockOutcome::Refused {
            // A forced kill ends the sleep (plan item 7): the task dies at
            // its next syscall instead of sleeping out its deadline first.
            if azos_sched::current_task_killed() {
                return;
            }
            while get_time() < deadline {
                core::hint::spin_loop();
            }
        }
    }
}

/// `SYS_SLEEP` (15): `ms` milliseconds from now. Returns 0.
pub fn sys_sleep(ms: u64) -> i64 {
    let interval = ns_to_ticks_ceil(ms.saturating_mul(1_000_000), TIMER_FREQ);
    block_until(get_time().saturating_add(interval));
    0
}

/// `SYS_SLEEP_UNTIL` (590): until `deadline_ns` nanoseconds on the counter.
/// Returns 0 after blocking, 1 without blocking when the deadline had already
/// passed at entry.
pub fn sys_sleep_until(deadline_ns: u64) -> i64 {
    let deadline = ns_to_ticks_ceil(deadline_ns, TIMER_FREQ);
    if get_time() >= deadline {
        return 1;
    }
    block_until(deadline);
    0
}

/// Counter ticks in `ms` milliseconds, rounded up.
pub fn ms_to_ticks(ms: u64) -> u64 {
    ns_to_ticks_ceil(ms.saturating_mul(1_000_000), TIMER_FREQ)
}

/// Kernel-context sleep: block the calling task for `ms` milliseconds on the
/// counter, as `SYS_SLEEP` does for ring 3.
///
/// For kernel tasks and handlers that wait on another task or on the network:
/// a `task_yield()` loop hands the hart only to tasks at the caller's priority
/// or above, and a bound counted in yields measures how much CPU the host gave
/// the guest, not time (gate 187, gate 193).
pub fn sleep_ms(ms: u64) {
    sleep_until_tick(get_time().saturating_add(ms_to_ticks(ms)));
}

/// [`block_until`] for the kernel-context helpers below, the same loop.
///
/// A copy rather than a third caller on purpose: `block_until` has exactly the
/// two `SYS_SLEEP` callers it had, so the inlining that shapes the
/// `SYS_SLEEP_UNTIL` arm (vsbench's `sleep-until0` lane) is untouched. With
/// the helpers calling it, it was outlined into a symbol of its own.
fn sleep_until_tick(deadline: u64) {
    use azos_sched::{task_block_outcome, BlockOutcome, WaitReason};
    while get_time() < deadline {
        if task_block_outcome(WaitReason::Timer(deadline)) == BlockOutcome::Refused {
            while get_time() < deadline {
                core::hint::spin_loop();
            }
        }
    }
}

/// Wait until `ready()` answers true or `timeout_ms` milliseconds of counter
/// time have passed, sleeping `step_ms` (at least 1) between looks. Returns
/// whether `ready()` held.
///
/// `ready()` is asked first, before any sleep, and once more after the
/// deadline has passed: a condition that is already true costs no sleep, and
/// one that turns true during the last step is not reported as a timeout.
pub fn wait_until_ms(timeout_ms: u64, step_ms: u64, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = get_time().saturating_add(ms_to_ticks(timeout_ms));
    let step = ms_to_ticks(step_ms.max(1));
    loop {
        if ready() {
            return true;
        }
        let t = get_time();
        if t >= deadline {
            return false;
        }
        sleep_until_tick(t.saturating_add(step).min(deadline));
    }
}
