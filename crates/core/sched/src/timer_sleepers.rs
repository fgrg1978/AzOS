// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Child module of `scheduler.rs` (pulled in with `#[path]`), moved out of it unchanged.

use super::{TaskState, WaitReason, MAX_TASKS, TASKS, TASK_VALID};
use crate::timer_heap::TimerHeap;
use azos_arch::Interrupts;
use crate::sc::{SlackMode, QOS_LEVELS};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// `SCHED_TIMER_HEAP_PER_CPU` (owner decision, wave 15 VW): one heap per
// CPU, like Linux's per-CPU hrtimer bases. A sleeper is armed on the
// heap of the CPU it blocks on, and only that CPU's tick pops it and
// programs its comparator from it, so each lock below is taken only by
// its own CPU (interrupts masked) and never waits on another hart.
// Before (one global lock): 28 contended acquires a boot on riscv64
// `-icount -smp 2`, the longest spin 50 ms inside the tick ISR, its
// holder a hart `-icount` was not running. Off, there is one heap
// (index 0) and the old global lock.
const PER_CPU: bool = azos_limits::SCHED_TIMER_HEAP_PER_CPU;
const NHEAPS: usize = if PER_CPU { super::MAX_CPUS } else { 1 };

/// The heaps, in the per-CPU areas (allocated at boot from the frame
/// allocator, for the possible CPUs only): RAM scales with the CPUs the
/// board has, not with `NR_CPUS`. Before `setup_per_cpu_areas` no CPU
/// has one, and no task can sleep yet; a tick in that window finds no
/// heap and does nothing (see [`attached`]). Off, only CPU 0's is used.
///
/// Scope `PerCpu` (`azos_sync::scope`, the first instance of the owner's
/// scope types): each heap is touched by its own CPU only, interrupts
/// masked; lockdep checks both at each access. Off
/// (SCHED_TIMER_HEAP_PER_CPU=n) the one heap every CPU uses is CPU 0's
/// instance behind the global lock: a Global scope, reached through
/// `PerCpu::storage`.
pub(crate) static TIMER_HEAPS: azos_sync::scope::PerCpu<TimerHeap<MAX_TASKS>> =
    azos_sync::scope::PerCpu::with_init(init_heap);

unsafe fn init_heap(p: *mut TimerHeap<MAX_TASKS>) {
    // SAFETY: `PerCpuVar::attach`'s contract: zeroed, aligned, ours.
    unsafe { TimerHeap::init_zeroed(p) }
}

/// Has heap `h` its per-CPU instance yet?
#[inline(always)]
fn attached(h: usize) -> bool {
    TIMER_HEAPS.attached(h)
}

static LOCKS: [AtomicBool; NHEAPS] = [const { AtomicBool::new(false) }; NHEAPS];
/// The heap that holds each slot's live entry: written at every arm,
/// under that heap's lock. An entry left in another heap by an earlier
/// sleep is stale there: that heap drops it instead of waking or
/// re-arming it.
static OWNER: [core::sync::atomic::AtomicU8; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU8::new(0) }; MAX_TASKS];
const _: () = assert!(NHEAPS <= u8::MAX as usize);

// QoS timer tolerance (Kconfig `QOS_TIMER_TOLERANCE`): a sleeper whose tier
// has slack is armed AT an instant the heap already wakes for, inside
// `[deadline, deadline + slack]`. The task's `wait_reason` keeps saying
// `Timer(deadline)`: callers match on it (`proxy_wake` wakes by exact
// deadline) and the timer wake tests `now >= deadline`, both still true at
// the later instant. What the HEAP holds for the slot is `deadline +
// SLACK[slot]`, so every place that tells the heap what a slot sleeps on
// ([`live_on`]: `peek_live`'s fix-up, the retry re-arm) adds the slack back
// and the heap's own invariant (entry == what the slot sleeps on) holds.
// `SLACK[slot]` is written in `arm`, under the lock of the heap `OWNER` names,
// and read by `live_on` under that same lock. One window: between
// `block_current`'s commit and its `arm` the slot's `OWNER` may still name
// this heap, and `peek_live` may move a stale entry to the new deadline plus
// the OLD slack for those few microseconds; `arm` overwrites it (it moved
// such an entry to the bare deadline before).
const MODE: SlackMode = if !azos_limits::QOS_TIMER_TOLERANCE {
    SlackMode::Off
} else if azos_limits::QOS_TIMER_TOLERANCE_ROWS_ONLY {
    SlackMode::Rows
} else {
    SlackMode::All
};
/// The slack of each QoS hint, in microseconds, indexed by the hint.
const TIERS_US: [u32; QOS_LEVELS] = [
    azos_limits::QOS_SLACK_DEFAULT_US as u32,
    azos_limits::QOS_SLACK_LATENCY_US as u32,
    azos_limits::QOS_SLACK_THROUGHPUT_US as u32,
    azos_limits::QOS_SLACK_BACKGROUND_US as u32,
];
const _: () = assert!(
    crate::sc::QOS_DEFAULT == 0 && crate::sc::QOS_LATENCY == 1
        && crate::sc::QOS_THROUGHPUT == 2 && crate::sc::QOS_BACKGROUND == 3,
    "TIERS_US is indexed by the QoS hint"
);
/// Per slot: how many ticks after its deadline the slot's heap entry sits.
/// Written by [`arm`] under the heap's lock, read by [`live_on`] under the
/// same lock (the slot's owning heap only). No storage when off.
///
/// A `ktest` build keeps the storage even with the option off, so the
/// in-kernel test of the coalescing path (`ktest_coalescing`) runs the same
/// code the option-on kernel runs (`slack_ticks` reads 0 there, so nothing
/// but that test writes a non-zero value).
const SLACK_SLOTS: usize = if matches!(MODE, SlackMode::Off) && !cfg!(feature = "ktest") { 0 } else { MAX_TASKS };
static SLACK: [AtomicU32; SLACK_SLOTS] = [const { AtomicU32::new(0) }; SLACK_SLOTS];

/// The window, in timebase ticks, the timers `idx` arms now may slip by:
/// its tier's slack (`sc::timer_slack_us`: the fair class only), 0 when the
/// option is off. Reads the task's SC, takes no lock.
#[inline]
pub fn slack_ticks(idx: usize) -> u64 {
    if matches!(MODE, SlackMode::Off) {
        return 0;
    }
    let Some(sc) = crate::classes::sc_of(idx) else { return 0 };
    let us = crate::sc::timer_slack_us(sc.class(), sc.qos(), sc.timer_slack_row(), MODE, &TIERS_US);
    (us as u64 * azos_drv_sys::timebase::TIMER_FREQ / 1_000_000).min(u32::MAX as u64)
}

/// The instant `slot`'s heap entry sits at when it sleeps on `deadline`.
#[inline]
pub(super) fn fire_of(slot: usize, deadline: u64) -> u64 {
    match SLACK.get(slot) {
        // `qos-fire-canary` (cargo feature, never in a build): the slack is
        // forgotten, so `peek_live` and the retry re-arm pull a coalesced
        // entry back to the bare deadline. ktest `qos_timer_coalescing_path`
        // must go red.
        Some(s) if !cfg!(feature = "qos-fire-canary") => deadline.saturating_add(s.load(Ordering::Relaxed) as u64),
        _ => deadline,
    }
}

/// This CPU's heap. Interrupts must be masked (the hart cannot change).
#[inline(always)]
fn here() -> usize {
    // percpu-hint: documented above: every caller masks first (Guard::local)
    if PER_CPU { crate::smp::current_cpu_id().min(NHEAPS - 1) } else { 0 }
}

struct Guard {
    h: usize,
    prev: azos_arch::InterruptState,
}

impl Guard {
    /// This CPU's heap: interrupts masked BEFORE the hart id is read.
    #[inline]
    fn local() -> Self {
        let prev = azos_arch::ARCH.disable_all();
        Self::take(here(), prev)
    }

    /// Heap `h`, read by a caller already masked on that CPU.
    #[inline]
    fn on(h: usize) -> Self {
        let prev = azos_arch::ARCH.disable_all();
        Self::take(h, prev)
    }

    #[inline(always)]
    fn take(h: usize, prev: azos_arch::InterruptState) -> Self {
        while LOCKS[h]
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Guard { h, prev }
    }

    #[inline]
    fn heap(&mut self) -> &mut TimerHeap<MAX_TASKS> {
        let p: *mut TimerHeap<MAX_TASKS> = if PER_CPU {
            // SAFETY: the guard masked interrupts before it read `h`
            // (`local`, `on`): this CPU's heap. Lockdep checks both.
            let irq = unsafe { azos_sync::scope::IrqOff::assume() };
            TIMER_HEAPS.with_mut_on(&irq, self.h, |t| t as *mut _)
        } else {
            // SAFETY: the one shared heap, under the global `LOCKS[0]`.
            unsafe { TIMER_HEAPS.storage() }.ptr(self.h)
        };
        // SAFETY: `LOCKS[h]` is held for the guard's lifetime, the
        // returned borrow cannot outlive `&mut self`, and every caller
        // checked `attached(h)` (the instance is never freed).
        unsafe { &mut *p }
    }
}

impl Drop for Guard {
    #[inline]
    fn drop(&mut self) {
        LOCKS[self.h].store(false, Ordering::Release);
        azos_arch::ARCH.restore(self.prev);
    }
}

/// The instant `slot`'s entry in heap `h` sits at while it sleeps (its
/// timer deadline plus its slack), if heap `h` owns it.
#[inline]
fn live_on(h: usize, slot: usize) -> Option<u64> {
    if OWNER[slot].load(Ordering::Relaxed) as usize != h {
        return None;
    }
    still_sleeping(slot).map(|d| fire_of(slot, d))
}

/// Does this CPU's heap own `slot`? (Census cross-checks.)
#[cfg(feature = "ipc-census")]
pub(super) fn owned_here(slot: usize) -> bool {
    OWNER[slot].load(Ordering::Relaxed) as usize == here()
}

/// `block_current`'s arm, after the commit left `idx` `Blocked`: on the
/// heap of the CPU it blocks on. Returns the instant the entry was armed at:
/// `deadline`, or a wake-up the heap already had inside the task's slack
/// window (QoS timer tolerance), which is the instant the comparator needs.
#[inline]
pub(super) fn arm(idx: usize, deadline: u64) -> u64 {
    // The window first, from the task's SC: nothing the heap lock guards.
    let slack = if deadline == u64::MAX { 0 } else { slack_ticks(idx) };
    let mut g = Guard::local();
    if !attached(g.h) {
        return deadline; // no task sleeps before the per-CPU areas exist
    }
    let h = g.h;
    arm_on(g.heap(), h, idx, deadline, slack)
}

/// [`arm`] on heap `heap` (the one of CPU `h`, its lock held) with the
/// window `slack` already read: the part of the arm that moves the entry,
/// writes the slot's slack and answers the instant armed at. A function of
/// its heap so `ktest_coalescing` can run it on a heap of its own.
#[inline(always)]
fn arm_on(heap: &mut TimerHeap<MAX_TASKS>, h: usize, idx: usize, deadline: u64, slack: u64) -> u64 {
    OWNER[idx].store(h as u8, Ordering::Relaxed);
    let fire = if slack == 0 {
        deadline
    } else {
        heap.coalesce_target(deadline, slack, idx, |s| live_on(h, s).is_some())
    };
    if let Some(s) = SLACK.get(idx) {
        // `fire - deadline <= slack <= u32::MAX`.
        s.store((fire - deadline) as u32, Ordering::Relaxed);
    }
    heap.arm(idx, fire);
    // `qos-armed-at-canary` (cargo feature, never in a build): the caller is
    // told the bare deadline, so `block_current` programs the comparator for
    // an instant the heap no longer wakes for (the governor sees the
    // uncoalesced schedule). ktest `qos_timer_coalescing_path` must go red.
    if cfg!(feature = "qos-armed-at-canary") { deadline } else { fire }
}

/// The deadline `slot` still sleeps on, if it is `Blocked` on a timer.
#[inline]
pub(super) fn still_sleeping(slot: usize) -> Option<u64> {
    unsafe {
        if !TASK_VALID[slot].load(Ordering::Relaxed) {
            return None;
        }
        let t = &*core::ptr::addr_of!(TASKS[slot]);
        if t.state_acquire() != TaskState::Blocked {
            return None;
        }
        match t.wait_reason {
            WaitReason::Timer(d) => Some(d),
            _ => None,
        }
    }
}

/// [`still_sleeping`] as the heap holds it: the deadline plus the slot's
/// slack (the census compares instants the heap fires at).
#[cfg(feature = "ipc-census")]
fn still_sleeping_fire(slot: usize) -> Option<u64> {
    still_sleeping(slot).map(|d| fire_of(slot, d))
}

/// CPU hotplug (Kconfig `CPU_HOTPLUG`): CPU `from` is going offline, so its
/// timer sleepers move to the heap of CPU `to`: only the CPU's own tick pops its
/// heap, and nothing would wake them. Runs on `from`, interrupts masked (its
/// guard), after the online prefix was cut. Returns how many moved.
///
/// An entry is popped under `from`'s lock, then armed under `to`'s: the two
/// locks are never held together. The slot's `OWNER` moves with a
/// compare-exchange from `from` to `to`, so a sleeper that woke and slept again
/// on a third CPU in between (whose arm wrote its own `OWNER`) keeps its new
/// entry: the one armed here is then stale, which every pop already drops. The
/// instant armed is the popped one, slack included. With one heap
/// (`SCHED_TIMER_HEAP_PER_CPU=n`) there is nothing to move.
///
/// The caller rings `to` afterwards: an idle CPU's comparator may be far past
/// the earliest of these.
pub(super) fn migrate_off(from: usize, to: usize) -> usize {
    if !PER_CPU || from == to || !attached(from) || !attached(to) {
        return 0;
    }
    let mut moved = 0;
    loop {
        let popped = {
            let mut g = Guard::on(from);
            g.heap().pop()
        };
        let Some((fire, slot)) = popped else { return moved };
        // Not this heap's entry any more (the sleeper woke, or sleeps elsewhere): drop.
        if OWNER[slot]
            .compare_exchange(from as u8, to as u8, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
            || still_sleeping(slot).is_none()
        {
            continue;
        }
        let prev = azos_arch::ARCH.disable_all();
        let g = Guard::take(to, prev);
        // SAFETY: `LOCKS[to]` is held, the exclusion every access to this heap
        // takes (its own CPU's `Guard::local` included); the scope check of
        // `with_mut_on` is the per-CPU one, which a cross-CPU arm cannot satisfy.
        unsafe { (*TIMER_HEAPS.storage().ptr(to)).arm(slot, fire) };
        drop(g);
        moved += 1;
    }
}

/// Drop `idx`'s entry (tick-probe cleanup).
#[allow(dead_code)]
pub(super) fn cancel(idx: usize) {
    let mut g = Guard::local();
    if attached(g.h) {
        g.heap().cancel(idx);
    }
}

/// `ipc-census`: per slot, ticks that popped it and are not yet
/// through their wake-or-re-arm step — the pop -> re-arm window, named
/// so a mismatch that falls in it can be told from one that does not.
/// A count, not a flag: a slot popped, woken, re-blocked and popped
/// again by another hart's tick is in two windows at once, and the
/// first tick to finish must not clear the second one's.
#[cfg(feature = "ipc-census")]
static INFLIGHT: [core::sync::atomic::AtomicU32; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; MAX_TASKS];

/// Whether a tick has `slot` popped and not yet woken or re-armed.
#[cfg(feature = "ipc-census")]
pub(super) fn inflight(slot: usize) -> bool {
    INFLIGHT.get(slot).is_some_and(|c| c.load(Ordering::Relaxed) != 0)
}

#[cfg(feature = "ipc-census")]
pub(super) fn landed(slot: usize) {
    // Release: a census reader that sees the count drop (Acquire) also
    // sees the wake this tick made before it.
    INFLIGHT[slot].fetch_sub(1, Ordering::Release);
}

/// The top of the heap after fixing it up against the live tasks
/// (`TimerHeap::peek_live` with `still_sleeping`): stale entries are
/// dropped so a woken sleeper cannot make the tickless path program an
/// early interrupt, and an entry whose slot sleeps on a different
/// deadline is moved to it, not dropped.
pub(super) fn nearest() -> Option<u64> {
    let mut g = Guard::local();
    let h = g.h;
    if !attached(h) {
        return None;
    }
    nearest_on(g.heap(), h)
}

/// [`nearest`] on heap `heap` (the one of CPU `h`).
#[inline(always)]
fn nearest_on(heap: &mut TimerHeap<MAX_TASKS>, h: usize) -> Option<u64> {
    heap.peek_live(|s| live_on(h, s))
}

/// Ktest `qos_timer_coalescing_path`: the integrated path of the QoS timer
/// tolerance, on a heap of its own and two forged `Blocked` slots (free
/// ones, never dispatched or enqueued, restored before returning; the pool
/// lock keeps anyone else from taking them): `arm_on` -> `coalesce_target`
/// -> `SLACK` -> `fire_of`/`live_on` -> `peek_live` -> the instant `arm`
/// answers (`block_current`'s `armed_at`). Two fair background sleepers
/// must share one heap instant and `peek_live` must leave the coalesced
/// entry where it is; a sleeper with nothing inside its window is armed at
/// its deadline, and re-arming a slot overwrites its slack. The slack is
/// passed in (`slack_ticks` is judged by its own ktest), and the heap is
/// the test's, so no real sleeper can be inside a window or above the entry.
#[cfg(feature = "ktest")]
pub fn ktest_coalescing() -> Result<(), &'static str> {
    use crate::task::sched_word;
    static mut SCRATCH: TimerHeap<MAX_TASKS> = TimerHeap::new();

    let _pool = super::PoolGuard::acquire(); // masks interrupts, freezes the slot pool
    let mut free = (0..MAX_TASKS).rev().filter(|&i| {
        // SAFETY: `TASK_VALID` is a static of atomics; the pool lock is held.
        !unsafe { TASK_VALID[i].load(Ordering::Relaxed) }
    });
    let (Some(a), Some(b)) = (free.next(), free.next()) else {
        return Err("no two free task slots");
    };
    let h = here();
    // SAFETY: the one user of `SCRATCH`, a ktest run once, interrupts masked.
    let heap = unsafe { &mut *core::ptr::addr_of_mut!(SCRATCH) };
    while heap.pop().is_some() {}

    // The slot sleeps on `Timer(deadline)`, as `block_current` leaves it.
    let forge = |slot: usize, deadline: u64| {
        // SAFETY: a free slot under the pool lock; nothing reads it as a task
        // but `still_sleeping`, which checks exactly what is written here.
        unsafe {
            let t = super::task_mut(slot);
            t.wait_reason = WaitReason::Timer(deadline);
            t.state_word.store(sched_word::pack(TaskState::Blocked), Ordering::Relaxed);
        }
        core::sync::atomic::fence(Ordering::Release);
        // SAFETY: as above.
        unsafe { TASK_VALID[slot].store(true, Ordering::Relaxed) };
    };
    let saved: [(usize, WaitReason, u32); 2] = [a, b].map(|s| {
        // SAFETY: as above.
        let t = unsafe { super::task_mut(s) };
        (s, t.wait_reason, t.state_word.load(Ordering::Relaxed))
    });

    // Instants an hour away: no tick on any hart can find these due.
    let base = azos_drv_sys::timebase::now() + 3600 * azos_drv_sys::timebase::TIMER_FREQ + 12_345;
    const WINDOW: u64 = 1_000;
    const GAP: u64 = 400;
    let r = (|| {
        // `a` sleeps without slack at base + GAP.
        forge(a, base + GAP);
        if arm_on(heap, h, a, base + GAP, 0) != base + GAP {
            return Err("a sleeper without slack was not armed at its deadline");
        }
        // `b` wakes GAP earlier and may slip by WINDOW: it rides on `a`'s entry.
        forge(b, base);
        if arm_on(heap, h, b, base, WINDOW) != base + GAP {
            return Err("a sleeper with slack was not armed at the wake-up inside its window");
        }
        if fire_of(b, base) != base + GAP || fire_of(a, base + GAP) != base + GAP {
            return Err("a slot's slack was not kept for the instant its entry sits at");
        }
        if heap.armed_deadline(a) != Some(base + GAP) || heap.armed_deadline(b) != Some(base + GAP) {
            return Err("two sleepers inside one window do not share one heap instant");
        }
        // `a` leaves; `b`'s entry is the top. `peek_live` must keep it at the
        // coalesced instant (it asks `live_on`, which adds the slack back).
        heap.cancel(a);
        if nearest_on(heap, h) != Some(base + GAP) || heap.armed_deadline(b) != Some(base + GAP) {
            return Err("peek_live pulled a coalesced entry back to the bare deadline");
        }
        // Nothing inside the window: armed at the deadline, the slack back to 0
        // (the 400 ticks of the last arm must not outlive it).
        forge(a, base + GAP);
        arm_on(heap, h, a, base + GAP, 0);
        let late = base + 3 * WINDOW;
        forge(b, late);
        if arm_on(heap, h, b, late, WINDOW) != late || fire_of(b, late) != late {
            return Err("a sleeper with nothing inside its window was not armed at its deadline");
        }
        if heap.armed_deadline(b) != Some(late) || nearest_on(heap, h) != Some(base + GAP) {
            return Err("the heap does not hold each sleeper at the instant it was armed at");
        }
        Ok(())
    })();

    for (s, reason, word) in saved {
        // SAFETY: as above.
        unsafe {
            TASK_VALID[s].store(false, Ordering::Relaxed);
            let t = super::task_mut(s);
            t.wait_reason = reason;
            t.state_word.store(word, Ordering::Relaxed);
        }
        if let Some(c) = SLACK.get(s) {
            c.store(0, Ordering::Relaxed);
        }
        heap.cancel(s);
    }
    r
}

/// The live heap and task table as `timer_heap::wake_due` sees them.
/// A tick's pass over the heap `h` of the CPU taking the tick.
pub(super) struct Due {
    h: usize,
}

impl Due {
    /// For the calling CPU, whose interrupts are masked (the tick ISR).
    #[inline]
    pub(super) fn here() -> Self {
        Due { h: here() }
    }

    /// Has this pass's heap its instance yet (a tick before
    /// `setup_per_cpu_areas` has nothing to pop)?
    #[inline]
    pub(super) fn ready(&self) -> bool {
        attached(self.h)
    }
}

impl crate::timer_heap::DueSleepers<MAX_TASKS> for Due {
    #[inline]
    fn locked<R>(&self, f: impl FnOnce(&mut TimerHeap<MAX_TASKS>) -> R) -> R {
        f(Guard::on(self.h).heap())
    }

    #[inline]
    fn live(&self, slot: usize) -> Option<u64> {
        live_on(self.h, slot)
    }

    #[inline]
    fn wake(&self, slot: usize, now: u64) {
        // Stale here: the slot slept again on another CPU's heap since.
        if OWNER[slot].load(Ordering::Relaxed) as usize != self.h {
            return;
        }
        super::try_wake_task(slot, &|r: &WaitReason| {
            matches!(r, WaitReason::Timer(d) if now >= *d)
        });
    }

    #[cfg(feature = "ipc-census")]
    #[inline]
    fn popped(&self, slot: usize) {
        INFLIGHT[slot].fetch_add(1, Ordering::Relaxed);
        POPS[slot].fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "ipc-census")]
    #[inline]
    fn landed(&self, slot: usize) {
        landed(slot);
    }
}

/// `ipc-census`: heap vs sweep, counted per `nearest_timer_deadline`
/// call, and sleepers the sweep would still wake after the heap's tick
/// pass (a missed arm shows here). Tallies print at powers of two.
#[cfg(feature = "ipc-census")]
pub static NEAREST_CHECKS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(feature = "ipc-census")]
pub static NEAREST_MISMATCH: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(feature = "ipc-census")]
pub static TICK_CHECKS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(feature = "ipc-census")]
pub static MISSED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[cfg(feature = "ipc-census")]
pub(super) fn check_nearest(heap: Option<u64>, sweep: Option<u64>) {
    let n = NEAREST_CHECKS.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    if heap != sweep {
        let (class, note) = classify_mismatch(heap, sweep);
        if let Some(n) = note {
            n.print("UNEXPLAINED", sweep.unwrap_or(0));
        }
        MISMATCH_BY[class as usize].fetch_add(1, Ordering::Relaxed);
        if NEAREST_MISMATCH.fetch_add(1, Ordering::Relaxed) == 0 {
            azos_drv_sys::kprintln!(
                "[SCHED] TIMER_NEAREST_MISMATCH first: heap={:?} sweep={:?} class={}",
                heap, sweep, class as usize,
            );
        }
        if class == Mismatch::Unexplained
            && MISMATCH_BY[Mismatch::Unexplained as usize].load(Ordering::Relaxed) == 1
        {
            azos_drv_sys::kprintln!(
                "[SCHED] TIMER_NEAREST_UNEXPLAINED first: heap={:?} sweep={:?}", heap, sweep,
            );
        }
    }
    if n >= 64 && n.is_power_of_two() {
        let by = |c: Mismatch| MISMATCH_BY[c as usize].load(Ordering::Relaxed);
        azos_drv_sys::kprintln!(
            "[SCHED] timer-check nearest={} mismatches={} (early={} gone={} armed={} \
             pop_rearm={} commit_arm={} unexplained={}) ticks={} missed={} \
             (inflight={} saving={} current={} lost={})",
            n,
            NEAREST_MISMATCH.load(Ordering::Relaxed),
            by(Mismatch::HeapEarlier), by(Mismatch::Gone), by(Mismatch::ArmedSince),
            by(Mismatch::PopRearm), by(Mismatch::CommitArm), by(Mismatch::Unexplained),
            TICK_CHECKS.load(Ordering::Relaxed),
            MISSED.load(Ordering::Relaxed),
            MISSED_BY[0].load(Ordering::Relaxed), MISSED_BY[1].load(Ordering::Relaxed),
            MISSED_BY[2].load(Ordering::Relaxed), MISSED_BY[3].load(Ordering::Relaxed),
        );
    }
}

/// Why the heap's nearest deadline and the sweep's differed, judged
/// right after both were read (the classification itself races the
/// same transitions, which is what `Gone` / `ArmedSince` absorb).
#[cfg(feature = "ipc-census")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mismatch {
    /// Heap earlier than the sweep: its top was live when read and
    /// was woken before the sweep ran.
    HeapEarlier = 0,
    /// No slot sleeps on the sweep's deadline any more.
    Gone = 1,
    /// The sleeper is armed at that deadline now (its arm landed
    /// between the two reads).
    ArmedSince = 2,
    /// Popped by a tick, not yet re-armed or woken.
    PopRearm = 3,
    /// Committed `Blocked` and still on its hart (`context_saving`
    /// set, or current): the arm is pending or it is an unswitched block.
    CommitArm = 4,
    /// None of the above: a sleeper with no entry and no reason.
    Unexplained = 5,
}

#[cfg(feature = "ipc-census")]
static MISMATCH_BY: [core::sync::atomic::AtomicU32; 6] =
    [const { core::sync::atomic::AtomicU32::new(0) }; 6];

#[cfg(feature = "ipc-census")]
fn classify_mismatch(heap: Option<u64>, sweep: Option<u64>) -> (Mismatch, Option<LostNote>) {
    let Some(sd) = sweep else { return (Mismatch::HeapEarlier, None) };
    if matches!(heap, Some(hd) if hd < sd) {
        return (Mismatch::HeapEarlier, None);
    }
    let mut g = Guard::local();
    let h = g.heap();
    let mut class = Mismatch::Gone;
    let mut note = None;
    for i in 0..MAX_TASKS {
        if still_sleeping_fire(i) != Some(sd) {
            continue;
        }
        let c = if h.armed_deadline(i) == Some(sd) {
            Mismatch::ArmedSince
        } else {
            match sleeper_why(i, sd) {
                SleeperWhy::InFlight => Mismatch::PopRearm,
                SleeperWhy::Saving | SleeperWhy::Current => Mismatch::CommitArm,
                SleeperWhy::Woken => Mismatch::Gone,
                SleeperWhy::Lost => Mismatch::Unexplained,
            }
        };
        if c == Mismatch::Unexplained && note.is_none() {
            note = Some(LostNote::take(i, sd, h.armed_deadline(i)));
        }
        // The least benign explanation of any sleeper on `sd` wins.
        if (c as u8) > (class as u8) {
            class = c;
        }
    }
    (class, note)
}

/// First tick (`now`) at which each slot was seen `Blocked` on a due
/// `Timer(d)` without being armed at `d`, and that `d`; 0 = not suspect.
#[cfg(feature = "ipc-census")]
static SUSPECT_SINCE: [core::sync::atomic::AtomicU64; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; MAX_TASKS];
#[cfg(feature = "ipc-census")]
static SUSPECT_DEADLINE: [core::sync::atomic::AtomicU64; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; MAX_TASKS];

/// After the heap pass: a slot `Blocked` on a `Timer(d)` due at `now`
/// and not armed at `d` is one no later tick will visit either — lost —
/// provided it STAYS that way. A sleeper whose `block_current` has
/// committed but not yet armed (it may be spinning on this very lock,
/// which this check holds) looks the same for a few microseconds, so a
/// slot counts as missed only when seen in that state on the same `d`
/// at least `CONFIRM_TICKS` (1 ms at 10 MHz) after it was first seen.
#[cfg(feature = "ipc-census")]
pub(super) fn check_tick(now: u64) {
    const CONFIRM_TICKS: u64 = 10_000;
    TICK_CHECKS.fetch_add(1, Ordering::Relaxed);
    // Printed after the guard drops: `LOCK` stays a leaf (no UART_LOCK
    // under it), census build included.
    let mut first: Option<(usize, u64, u64, SleeperWhy)> = None;
    let mut opened: Option<LostNote> = None;
    let mut closed: Option<LostNote> = None;
    let mut g = Guard::local();
    let h = g.heap();
    unsafe {
        for i in 0..MAX_TASKS {
            let mut suspect = None;
            if TASK_VALID[i].load(Ordering::Relaxed) {
                let t = &*core::ptr::addr_of!(TASKS[i]);
                if t.state_acquire() == TaskState::Blocked {
                    if let WaitReason::Timer(d) = t.wait_reason {
                        // The instant the heap fires the slot at (QoS slack).
                        let d = fire_of(i, d);
                        if now >= d && owned_here(i) && h.armed_deadline(i) != Some(d) {
                            suspect = Some(d);
                        }
                    }
                }
            }
            let Some(d) = suspect else {
                SUSPECT_SINCE[i].store(0, Ordering::Relaxed);
                let open = LOST_OPEN[i].swap(0, Ordering::Relaxed);
                if open != 0 && closed.is_none() {
                    closed = Some(LostNote::take(i, now.saturating_sub(open), h.armed_deadline(i)));
                }
                continue;
            };
            let since = SUSPECT_SINCE[i].load(Ordering::Relaxed);
            if since == 0 || SUSPECT_DEADLINE[i].load(Ordering::Relaxed) != d {
                SUSPECT_SINCE[i].store(now.max(1), Ordering::Relaxed);
                SUSPECT_DEADLINE[i].store(d, Ordering::Relaxed);
            } else if since != u64::MAX && now.saturating_sub(since) >= CONFIRM_TICKS {
                // Count once per suspect episode, by what the sleeper
                // is doing when confirmed.
                SUSPECT_SINCE[i].store(u64::MAX, Ordering::Relaxed);
                let why = sleeper_why(i, d);
                if why == SleeperWhy::Woken {
                    // Woken while being classified: not a sleeper
                    // the heap left behind (see `sleeper_why`).
                    SUSPECT_SINCE[i].store(0, Ordering::Relaxed);
                    continue;
                }
                if why == SleeperWhy::Lost {
                    LOST_OPEN[i].store(now.max(1), Ordering::Relaxed);
                    LOST_POPS[i].store(POPS[i].load(Ordering::Relaxed), Ordering::Relaxed);
                    if opened.is_none() {
                        opened = Some(LostNote::take(i, d, h.armed_deadline(i)));
                    }
                }
                if MISSED_BY[why as usize].fetch_add(1, Ordering::Relaxed) == 0 && first.is_none() {
                    first = Some((i, d, since, why));
                }
                MISSED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    drop(g);
    if let Some((i, d, since, why)) = first {
        azos_drv_sys::kprintln!(
            "[SCHED] TIMER_MISSED first of class {}: slot={} deadline={} now={} since={}",
            why as usize, i, d, now, since,
        );
    }
    if let Some(n) = opened {
        n.print("LOST_OPEN", now);
    }
    if let Some(n) = closed {
        n.print("LOST_CLOSE", now);
    }
}

/// Per slot, entries `pop_due` has popped (census). A `Lost` episode
/// that ends with this count moved was found by the heap again (a
/// delay); one that ends without it was ended by another waker.
#[cfg(feature = "ipc-census")]
static POPS: [core::sync::atomic::AtomicU32; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; MAX_TASKS];
/// `now` at which a `Lost` episode was confirmed for the slot, 0 = none.
#[cfg(feature = "ipc-census")]
static LOST_OPEN: [core::sync::atomic::AtomicU64; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; MAX_TASKS];
/// `POPS[slot]` when the open episode was confirmed.
#[cfg(feature = "ipc-census")]
static LOST_POPS: [core::sync::atomic::AtomicU32; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; MAX_TASKS];
#[cfg(feature = "ipc-census")]
static LOST_PRINTS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// A snapshot of one slot for the `Lost` episode lines, taken under
/// `LOCK` and printed after it is released.
#[cfg(feature = "ipc-census")]
#[derive(Clone, Copy)]
struct LostNote {
    slot: usize,
    /// Deadline slept on (open) or episode length in ticks (close).
    val: u64,
    armed: Option<u64>,
    word: u32,
    reason: Option<u64>,
    site: u8,
    pops: u32,
    name: [u8; 16],
}

#[cfg(feature = "ipc-census")]
impl LostNote {
    fn take(i: usize, val: u64, armed: Option<u64>) -> Self {
        let t = unsafe { &*core::ptr::addr_of!(TASKS[i]) };
        let mut name = [0u8; 16];
        let n = t.name.len().min(16);
        name[..n].copy_from_slice(&t.name[..n]);
        LostNote {
            slot: i,
            val,
            armed,
            word: t.state_word.load(Ordering::Acquire),
            reason: match t.wait_reason {
                WaitReason::Timer(d) => Some(d),
                _ => None,
            },
            site: t.ready_site.load(Ordering::Relaxed),
            pops: POPS[i].load(Ordering::Relaxed).wrapping_sub(LOST_POPS[i].load(Ordering::Relaxed)),
            name,
        }
    }

    fn print(&self, what: &str, now: u64) {
        if LOST_PRINTS.fetch_add(1, Ordering::Relaxed) >= 64 {
            return;
        }
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(16);
        let name = core::str::from_utf8(&self.name[..end]).unwrap_or("?");
        azos_drv_sys::kprintln!(
            "[SCHED] {} slot={} name={} val={} now={} armed={:?} word={:#x} timer={:?} \
             ready_site={:#x} pops_since_open={}",
            what, self.slot, name, self.val, now, self.armed, self.word, self.reason,
            self.site, self.pops,
        );
    }
}

/// What a `Blocked`-on-a-timer sleeper with no heap entry at its
/// deadline is doing (census classification of `MISSED`).
#[cfg(feature = "ipc-census")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum SleeperWhy {
    /// Popped by a tick that has not re-armed or woken it yet.
    InFlight = 0,
    /// `context_saving` set: switching away, or an unswitched block.
    Saving = 1,
    /// Current on some hart with `context_saving` clear.
    Current = 2,
    /// Parked, not popped, no entry: lost.
    Lost = 3,
    /// No longer asleep on the deadline by the end of the check: a
    /// waker (a tick that had popped it, typically) finished while the
    /// check ran. Never counted in `MISSED_BY`.
    Woken = 4,
}

#[cfg(feature = "ipc-census")]
pub static MISSED_BY: [core::sync::atomic::AtomicU32; 4] =
    [const { core::sync::atomic::AtomicU32::new(0) }; 4];

#[cfg(feature = "ipc-census")]
///
/// `d` is the deadline the caller saw slot `i` asleep on. That read and
/// the `INFLIGHT` read below are two instants, and a tick that popped
/// the entry before the caller took `LOCK` needs no lock to finish its
/// wake: it can move the task to `Ready` and drop `INFLIGHT` in between,
/// which read as "asleep, no entry, nothing in flight". So `Lost` is
/// only returned if the slot is STILL asleep on `d` after `INFLIGHT`
/// was read as zero; a slot that is not was woken during the check.
/// (Census builds before wave 8 lacked the re-read: every `unexplained`
/// they printed that was followed up was this race.)
fn sleeper_why(i: usize, d: u64) -> SleeperWhy {
    if INFLIGHT[i].load(Ordering::Acquire) != 0 {
        return SleeperWhy::InFlight;
    }
    let t = unsafe { &*core::ptr::addr_of!(TASKS[i]) };
    if t.context_saving.load(Ordering::Acquire) {
        return SleeperWhy::Saving;
    }
    let current = (0..super::ncpu())
        .any(|c| unsafe { super::PER_CPU[c].current_idx.load(Ordering::Relaxed) } == i);
    if current {
        SleeperWhy::Current
    } else if still_sleeping_fire(i) != Some(d) {
        SleeperWhy::Woken
    } else {
        SleeperWhy::Lost
    }
}
