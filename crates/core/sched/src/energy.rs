// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RFC-0051 E1/E2 on the dispatch path (kernel feature `energy`, Kconfig
//! ENERGY): the per-task and per-CPU utilisation signals, and the energy
//! model installed at boot. A child module of `scheduler.rs` (pulled in with
//! `#[path]`, like `rt.rs`) so it reaches the task pool without widening its
//! visibility; the arithmetic is `azos_energy::util`, which the host
//! suite tests (`tests/host/energy-tests`).
//!
//! # Where the signals are updated
//!
//! RFC-0051 §4.1 says "at enqueue, dequeue and tick". On this dispatch path
//! that is:
//!
//! * **dispatch** (the dequeue that matters: the task starts running) and
//!   **switch-out** — [`on_switch`], from `do_schedule`'s dispatch tail, from
//!   the direct IPC hand-off (`ipc_wake_then_block` outcome 4, which bypasses
//!   `do_schedule`), and from `start()`'s first dispatch. These are the only
//!   places a task starts or stops running.
//! * **tick** — [`on_tick`], from `schedule()`, for the running task and the
//!   CPU.
//! * **enqueue** (a wake-up) updates nothing: a task that is not running
//!   accrues no busy time, and the interval since its switch-out is accounted
//!   as idle by its next update. A reader that needs the value now (wake-up
//!   placement, stage E5) asks for [`task_util`], which projects the signal to
//!   the present without writing it. Writing it at the wake would put a second
//!   writer (the waker's hart) on a task its own hart may still be switching
//!   away from.
//!
//! # Who writes what
//!
//! A task's signal is written only by the hart that is switching it in or out
//! or ticking it — the same ownership `Task::total_runtime` relies on. A task
//! that migrates is switched out on one hart and in on another; the second
//! hart waits for `context_saving` to clear (Acquire) before its dispatch
//! tail runs, and the first hart's switch-out hook ran before the release
//! that clears it. A CPU's signal is written only by that CPU and published
//! as a snapshot ([`cpu_util`]) for everyone else.
//!
//! A pool slot is reused by later tasks; a signal remembers the TID it
//! belongs to and starts over when the slot's TID changes.
//!
//! Idle tasks are not tracked (their "utilisation" is the absence of work);
//! a CPU running its idle task counts as idle.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use azos_drv_sys::timebase::{now, TIMER_FREQ};
use azos_energy::util::{UtilState, UtilTracker};
use azos_energy::{EnergyMode, EnergyModel, Seams};

use crate::task::IDLE_PRIORITY;

use super::{task_ref, MAX_CPUS, MAX_TASKS, TASK_VALID};

/// Ticks of `us` microseconds of the timebase.
const fn ticks(us: u64) -> u64 {
    us * TIMER_FREQ / 1_000_000
}

/// The tracker Kconfig chose (`ENERGY_UTIL`), its time constant in ticks.
pub const TRACKER: UtilTracker = if azos_limits::ENERGY_UTIL_PELT {
    UtilTracker::pelt(ticks(azos_limits::ENERGY_PELT_PERIOD_US))
} else {
    UtilTracker::window(ticks(azos_limits::ENERGY_UTIL_WINDOW_US))
};

/// Gate canary `energy-util-canary`: dispatch records the task as NOT
/// running, so no busy time is ever accounted and the smoke's `util` check
/// (a task that computes for 300 ms reads busy) must fail.
const UTIL_CANARY: bool = cfg!(feature = "energy-util-canary");
/// Gate canary `energy-switchout-canary`: switch-out leaves the task recorded
/// as running, so a task that blocks keeps accruing busy time and the
/// smoke's `util` check (it must read idle after sleeping) must fail.
const SWITCHOUT_CANARY: bool = cfg!(feature = "energy-switchout-canary");

#[derive(Clone, Copy)]
struct TaskSignal {
    /// TID the signal belongs to; 0 = none yet (TIDs start at 1).
    tid: u32,
    st: UtilState,
}

/// Per-slot storage written under the ownership rule in the module doc.
struct Owned<T, const N: usize>(UnsafeCell<[T; N]>);
// SAFETY: every element has one writer at a time (module doc, "Who writes
// what"), ordered by the scheduler's own context_saving release/acquire.
unsafe impl<T, const N: usize> Sync for Owned<T, N> {}

static TASK_SIGNALS: Owned<TaskSignal, MAX_TASKS> =
    Owned(UnsafeCell::new([TaskSignal { tid: 0, st: UtilState::ZERO }; MAX_TASKS]));
static CPU_SIGNALS: Owned<UtilState, MAX_CPUS> = Owned(UnsafeCell::new([UtilState::ZERO; MAX_CPUS]));
static CPU_SNAPSHOT: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];

#[inline]
unsafe fn is_idle(idx: usize) -> bool {
    unsafe { task_ref(idx) }.priority.load(Ordering::Relaxed) == IDLE_PRIORITY
}

/// Account `idx` up to `now` and record whether it runs from now on.
#[inline]
unsafe fn task_set(idx: usize, at: u64, running: bool) {
    let tid = unsafe { task_ref(idx) }.tid;
    // SAFETY: `idx < MAX_TASKS` (callers check); single writer per module doc.
    let s = unsafe { &mut (*TASK_SIGNALS.0.get())[idx] };
    if s.tid != tid {
        *s = TaskSignal { tid, st: TRACKER.new_state(at) };
    }
    TRACKER.set_running(&mut s.st, at, running);
}

#[inline]
unsafe fn cpu_set(cpu: usize, at: u64, busy: Option<bool>) {
    // SAFETY: `cpu < MAX_CPUS` (callers check); only `cpu` itself writes it.
    let st = unsafe { &mut (*CPU_SIGNALS.0.get())[cpu] };
    match busy {
        Some(b) => TRACKER.set_running(st, at, b),
        None => TRACKER.update(st, at),
    }
    CPU_SNAPSHOT[cpu].store(TRACKER.util(st), Ordering::Relaxed);
}

/// A switch on `cpu` from `old` (`usize::MAX`: none, or a slot already
/// freed) to `next`. Called with the CPU's scheduling state settled and
/// before `context_switch`.
#[inline]
pub(super) unsafe fn on_switch(cpu: usize, old: usize, next: usize) {
    if cpu >= MAX_CPUS {
        return;
    }
    let at = now();
    unsafe {
        if old < MAX_TASKS && old != next && !is_idle(old) {
            task_set(old, at, SWITCHOUT_CANARY);
        }
        let busy = next < MAX_TASKS && !is_idle(next);
        if busy {
            task_set(next, at, !UTIL_CANARY);
        }
        cpu_set(cpu, at, Some(busy));
    }
}

/// The timer tick on `cpu`, `cur` running (`usize::MAX`: nothing).
#[inline]
pub(super) unsafe fn on_tick(cpu: usize, cur: usize) {
    if cpu >= MAX_CPUS {
        return;
    }
    let at = now();
    unsafe {
        if cur < MAX_TASKS && !is_idle(cur) {
            let s = &mut (*TASK_SIGNALS.0.get())[cur];
            if s.tid == task_ref(cur).tid {
                TRACKER.update(&mut s.st, at);
            }
        }
        cpu_set(cpu, at, None);
    }
    if GOV_ON.load(Ordering::Relaxed) {
        let _ = gov_maybe(cpu, at);
    }
}

/// Utilisation of the task in pool slot `idx` as of now, on
/// `azos_energy::SCALE` (0 for an empty slot or a task never run). Exact
/// for a task that is not running; for one running on another hart, the value
/// at that hart's last tick or switch, projected to now.
pub fn task_util(idx: usize) -> u32 {
    // SAFETY: `TASK_VALID` is a `static mut` array of atomics; this is an
    // atomic load through it, as everywhere else in `scheduler.rs`.
    if idx >= MAX_TASKS || !unsafe { TASK_VALID[idx].load(Ordering::Acquire) } {
        return 0;
    }
    // SAFETY: a read of a `Copy` value; see the doc for what a concurrent
    // update on the task's own hart means for the result.
    let s = unsafe { core::ptr::read_volatile(&(*TASK_SIGNALS.0.get())[idx]) };
    if s.tid != unsafe { task_ref(idx) }.tid {
        return 0;
    }
    TRACKER.util_at(&s.st, now())
}

/// Utilisation of `cpu` at its last tick or switch, on
/// `azos_energy::SCALE`. A CPU that went idle tickless keeps reading the
/// value it had when it last switched.
pub fn cpu_util(cpu: usize) -> u32 {
    CPU_SNAPSHOT.get(cpu).map_or(0, |a| a.load(Ordering::Relaxed))
}

/// Instructions-under-`-icount` probe for the smoke's cost line: run the
/// switch hook `n` times on `cpu`, `idx` switching to itself (the state it
/// touches is the caller's own), and return the timebase ticks it took.
pub fn probe_switch_cost(cpu: usize, idx: usize, n: u32) -> u64 {
    let t0 = now();
    for _ in 0..n {
        unsafe { on_switch(cpu, usize::MAX, idx) };
    }
    now().saturating_sub(t0)
}

/// Same for the tick hook.
pub fn probe_tick_cost(cpu: usize, idx: usize, n: u32) -> u64 {
    let t0 = now();
    for _ in 0..n {
        unsafe { on_tick(cpu, idx) };
    }
    now().saturating_sub(t0)
}

// ── The installed model (E2) ────────────────────────────────────────────

struct Installed {
    model: EnergyModel,
    mode: EnergyMode,
    seams: Seams,
}
struct Once(UnsafeCell<Installed>);
// SAFETY: written once by `install`, at boot, before `INSTALLED` is
// published (Release); read only after it is seen (Acquire).
unsafe impl Sync for Once {}
static MODEL: Once = Once(UnsafeCell::new(Installed {
    model: EnergyModel::NONE,
    mode: EnergyMode::Performance,
    seams: Seams::TODAY,
}));
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install the resolved model, the topology's mode and the seams they select.
/// Once, at boot, before the scheduler starts; a second call is ignored and
/// returns `false`.
pub fn install(model: EnergyModel, mode: EnergyMode, seams: Seams) -> bool {
    if INSTALLED.load(Ordering::Acquire) {
        return false;
    }
    // SAFETY: boot, single hart, nothing reads before `INSTALLED`.
    unsafe { *MODEL.0.get() = Installed { model, mode, seams } };
    GOV_ON.store(seams.governor != azos_energy::Governor::Fixed, Ordering::Relaxed);
    INSTALLED.store(true, Ordering::Release);
    true
}

/// The model in use ([`EnergyModel::NONE`] before `install` or without one).
pub fn model() -> &'static EnergyModel {
    static NONE: EnergyModel = EnergyModel::NONE;
    if INSTALLED.load(Ordering::Acquire) {
        // SAFETY: published, never written again.
        unsafe { &(*MODEL.0.get()).model }
    } else {
        &NONE
    }
}

/// The energy mode in use (`Performance` before `install`).
pub fn mode() -> EnergyMode {
    if INSTALLED.load(Ordering::Acquire) {
        unsafe { (*MODEL.0.get()).mode }
    } else {
        EnergyMode::Performance
    }
}

/// The seams in use (`Seams::TODAY` before `install`, and with no model or
/// in `performance` mode).
pub fn seams() -> Seams {
    if INSTALLED.load(Ordering::Acquire) {
        unsafe { (*MODEL.0.get()).seams }
    } else {
        Seams::TODAY
    }
}

// ── Stage E3: the frequency governor ────────────────────────────────────────
//
// Evaluated per performance domain, rate-limited (`governor::RATE_LIMIT_US`),
// from any CPU's tick and idle entry (an idle hart is tick-less, so a domain
// whose CPUs all went idle is re-evaluated by a hart that still runs, from
// projected signals). Inputs: the busiest CPU signal of the domain and the most
// loaded hart's admitted real-time density (`rt::ADMITTED_PPM`, lock-free).
// There is no clock driver on any board, so the decision is recorded here and
// counted, never applied.

use azos_energy::governor::{self, Why};
use azos_energy::idle::{self, Limit, TeoCpu};
use azos_energy::model::{MAX_DOMAINS, MAX_IDLE_STATES};
use azos_energy::{Governor, IdleGovernor};

use core::sync::atomic::{AtomicU64, AtomicU8};

/// "No decision yet": the domain runs at whatever clock firmware left.
pub const OPP_BOOT: u8 = u8::MAX;

/// The installed governor is not `Fixed` (one relaxed load on the tick).
static GOV_ON: AtomicBool = AtomicBool::new(false);
static GOV_LAST: [AtomicU64; MAX_DOMAINS] = [const { AtomicU64::new(0) }; MAX_DOMAINS];
static GOV_OPP: [AtomicU8; MAX_DOMAINS] = [const { AtomicU8::new(OPP_BOOT) }; MAX_DOMAINS];
static GOV_EVALS: AtomicU32 = AtomicU32::new(0);
static GOV_CHANGES: AtomicU32 = AtomicU32::new(0);
/// Per `Why`: schedutil, deadline floor, safety floor.
static GOV_WHY: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];

/// What the governor has recorded so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GovStats {
    /// Evaluations (after the rate limit).
    pub evals: u32,
    /// Evaluations whose OPP differed from the domain's previous one.
    pub changes: u32,
    /// Evaluations decided by schedutil / the deadline floor / the safety floor.
    pub why: [u32; 3],
}

/// The governor's counters.
pub fn gov_stats() -> GovStats {
    GovStats {
        evals: GOV_EVALS.load(Ordering::Relaxed),
        changes: GOV_CHANGES.load(Ordering::Relaxed),
        why: [0, 1, 2].map(|i| GOV_WHY[i].load(Ordering::Relaxed)),
    }
}

/// The OPP last recorded for domain `d` ([`OPP_BOOT`] if none).
pub fn domain_opp(d: usize) -> u8 {
    GOV_OPP.get(d).map_or(OPP_BOOT, |o| o.load(Ordering::Relaxed))
}

/// The domain index of `cpu` in the installed model.
fn domain_index(cpu: usize) -> Option<usize> {
    let bit = 1u32.checked_shl(cpu as u32)?;
    model().domains().iter().position(|d| d.cpus & bit != 0)
}

/// `cpu`'s utilisation projected to `at`: exact for the calling hart; for
/// another hart, its last tick or switch projected forward, so an idle,
/// tick-less hart reads as decaying instead of frozen at its last value.
pub fn cpu_util_at(cpu: usize, at: u64) -> u32 {
    if cpu >= MAX_CPUS {
        return 0;
    }
    // SAFETY: a read of a `Copy` value written only by `cpu` (as `task_util`).
    let st = unsafe { core::ptr::read_volatile(&(*CPU_SIGNALS.0.get())[cpu]) };
    TRACKER.util_at(&st, at)
}

/// Evaluate every domain that is due, if the governor is not `Fixed`. Called
/// from any CPU's tick and idle entry: an idle hart is tick-less, so its
/// domain is re-evaluated by whichever hart still runs (at least hart 0's
/// keepalive), from projected signals. Returns the number of domains
/// evaluated.
pub fn gov_maybe(_cpu: usize, at: u64) -> u32 {
    let g = seams().governor;
    if g == Governor::Fixed {
        return 0;
    }
    let mut n = 0;
    for (di, d) in model().domains().iter().enumerate() {
        let last = GOV_LAST[di].load(Ordering::Relaxed);
        if !governor::due(last, at, TIMER_FREQ) {
            continue;
        }
        // One hart evaluates a domain per interval.
        if GOV_LAST[di].compare_exchange(last, at.max(1), Ordering::AcqRel, Ordering::Relaxed).is_err() {
            continue;
        }
        let (mut util, mut ppm) = (0u32, 0u32);
        for c in 0..super::ncpu().min(32) {
            if d.cpus & (1 << c) != 0 {
                util = util.max(cpu_util_at(c, at));
                ppm = ppm.max(super::rt::ADMITTED_PPM[c].load(Ordering::Relaxed));
            }
        }
        let prev = GOV_OPP[di].load(Ordering::Relaxed);
        let cur = if prev == OPP_BOOT { d.opps().len().saturating_sub(1) } else { prev as usize };
        let Some(dec) = g.target_opp(d, util, cur, ppm) else { continue };
        n += 1;
        GOV_EVALS.fetch_add(1, Ordering::Relaxed);
        GOV_WHY[match dec.why {
            Why::Schedutil => 0,
            Why::DeadlineFloor => 1,
            Why::SafetyFloor => 2,
        }]
        .fetch_add(1, Ordering::Relaxed);
        if prev != dec.opp as u8 {
            GOV_OPP[di].store(dec.opp as u8, Ordering::Relaxed);
            GOV_CHANGES.fetch_add(1, Ordering::Relaxed);
        }
    }
    n
}

// ── Stage E4: the idle governor ─────────────────────────────────────────────
//
// The sleep bound is the earlier of the nearest timer sleeper
// (`nearest_timer_deadline`: the timer heap, in the default build since wave
// 13 — RFC-0051 P2; the O(MAX_TASKS) sleeper sweep without `sched-timer-heap`)
// and what the
// hart has programmed (`timebase::programmed`, which includes the hart-0
// keepalive and the SCHED-RT enforcement arms). The real-time slack is
// `rt::rt_slack`. The choice is counted; every state is entered as `wfi`
// (no HSM suspend / PSCI binding exists), and nothing here touches a timer,
// so the hart-0 watchdog keepalive is never moved (I6).

struct TeoAll(UnsafeCell<[TeoCpu; MAX_CPUS]>);
// SAFETY: slot `cpu` is touched only by `cpu`'s own idle task.
unsafe impl Sync for TeoAll {}
static TEO: TeoAll = TeoAll(UnsafeCell::new([TeoCpu::NEW; MAX_CPUS]));

static IDLE_PICKS: [[AtomicU32; MAX_IDLE_STATES]; MAX_CPUS] =
    [const { [const { AtomicU32::new(0) }; MAX_IDLE_STATES] }; MAX_CPUS];
/// Choices limited by the real-time slack (I3) / by the wake-up history.
static IDLE_BY_SLACK: AtomicU32 = AtomicU32::new(0);
static IDLE_BY_HISTORY: AtomicU32 = AtomicU32::new(0);
static IDLE_INTERCEPTS: AtomicU32 = AtomicU32::new(0);
/// A choice deeper than the slack allowed. Must stay 0 (I3, checked live).
static IDLE_I3_VIOLATIONS: AtomicU32 = AtomicU32::new(0);

/// The idle governor's counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdleStats {
    /// Choices per state, for the CPU asked about.
    pub picks: [u32; MAX_IDLE_STATES],
    /// Choices limited by the real-time slack (all CPUs).
    pub by_slack: u32,
    /// Choices limited by the history (all CPUs).
    pub by_history: u32,
    /// Wake-ups that came before the timer bound (all CPUs).
    pub intercepts: u32,
    /// Choices whose exit latency exceeded the slack (all CPUs): I3 broken.
    pub i3_violations: u32,
}

/// The idle governor's counters, with `cpu`'s per-state choices.
pub fn idle_stats(cpu: usize) -> IdleStats {
    let mut picks = [0; MAX_IDLE_STATES];
    if let Some(p) = IDLE_PICKS.get(cpu) {
        for (i, c) in p.iter().enumerate() {
            picks[i] = c.load(Ordering::Relaxed);
        }
    }
    IdleStats {
        picks,
        by_slack: IDLE_BY_SLACK.load(Ordering::Relaxed),
        by_history: IDLE_BY_HISTORY.load(Ordering::Relaxed),
        intercepts: IDLE_INTERCEPTS.load(Ordering::Relaxed),
        i3_violations: IDLE_I3_VIOLATIONS.load(Ordering::Relaxed),
    }
}

#[inline]
fn us_of(ticks: u64) -> u64 {
    if ticks == u64::MAX {
        return u64::MAX;
    }
    ((ticks as u128) * 1_000_000 / (TIMER_FREQ as u128)).min(u64::MAX as u128) as u64
}

/// One idle wait of `cpu` (the calling hart) through the installed idle
/// governor; `wfi` is the ISA's wait.
pub fn idle_wait(cpu: usize, wfi: impl Fn()) {
    let at = now();
    if GOV_ON.load(Ordering::Relaxed) {
        let _ = gov_maybe(cpu, at);
    }
    if seams().idle == IdleGovernor::WfiOnly || cpu >= MAX_CPUS {
        wfi();
        return;
    }
    let states = match domain_index(cpu) {
        Some(di) => model().domains()[di].idle_states(),
        None => &[],
    };
    // `programmed()` reads 0 (`timer_arm::NOT_ARMED`) before the hart's
    // first arm: no bound from it then.
    let armed = match azos_drv_sys::timebase::programmed() {
        0 => u64::MAX,
        p => p,
    };
    let bound = super::nearest_timer_deadline().unwrap_or(u64::MAX).min(armed);
    let sleep_us = us_of(bound.saturating_sub(at));
    let slack_us = us_of(super::rt::rt_slack(cpu, at));
    // SAFETY: only this hart's idle task touches its slot.
    let h = unsafe { &mut (*TEO.0.get())[cpu] };
    let (c, lim) = idle::select(states, sleep_us, slack_us, h);
    IDLE_PICKS[cpu][c.min(MAX_IDLE_STATES - 1)].fetch_add(1, Ordering::Relaxed);
    match lim {
        Limit::Timer => {}
        Limit::RtSlack => {
            IDLE_BY_SLACK.fetch_add(1, Ordering::Relaxed);
        }
        Limit::History => {
            IDLE_BY_HISTORY.fetch_add(1, Ordering::Relaxed);
        }
    }
    if c > 0 && states[c].exit_latency_us as u64 > slack_us {
        IDLE_I3_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
    }
    // Every state is entered as `wfi` (see above).
    wfi();
    let slept_us = us_of(now().saturating_sub(at));
    if idle::reflect(states, h, slept_us, sleep_us) {
        IDLE_INTERCEPTS.fetch_add(1, Ordering::Relaxed);
    }
}
