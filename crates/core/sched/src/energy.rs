// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Energy stages E1/E2 on the dispatch path (kernel feature `energy`, Kconfig
//! ENERGY): the per-task and per-CPU utilisation signals, and the energy
//! model installed at boot. A child module of `scheduler.rs` (pulled in with
//! `#[path]`, like `rt.rs`) so it reaches the task pool without widening its
//! visibility; the arithmetic is `azos_energy::util`, which the host
//! suite tests (`tests/host/energy-tests`).
//!
//! # Where the signals are updated
//!
//! Says "at enqueue, dequeue and tick". On this dispatch path
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
use azos_energy::model::invariant_util;
use azos_energy::policy::{BatteryLimits, DegradeRow};
use azos_energy::{EnergyMode, EnergyModel, Policy, Refusal, Seams};

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
    // The power service's report ages here, whatever governor is chosen: a
    // stale report holds the reserve, which turns the governor on.
    if POLICY.check_report_age(at) {
        GOV_ON.store(POLICY.effective_governor() != Governor::Fixed, Ordering::Relaxed);
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
// SAFETY: written once by `install`, by the boot CPU before any other CPU
// enters the scheduler, and before `INSTALLED` is published (Release); read
// only after it is seen (Acquire).
unsafe impl Sync for Once {}
static MODEL: Once = Once(UnsafeCell::new(Installed {
    model: EnergyModel::NONE,
    mode: EnergyMode::Performance,
    seams: Seams::TODAY,
}));
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install the resolved model, the topology's mode and the seams they select.
/// Once, by the boot CPU, before any other CPU enters the scheduler (a second
/// call is ignored and returns `false`). x86_64 resolves a hybrid part's model
/// from the core types its secondaries record, so it holds them in their entry
/// (interrupts off) until this has run (`entry/x86_64/smp.rs`); every other
/// source resolves before they are woken. The model is published first
/// (`INSTALLED`, Release) and the flags that act on it (`GOV_ON`, `EAS_ON`)
/// are raised after it, so an interrupt on the installing CPU never finds a
/// flag up over no model.
pub fn install(model: EnergyModel, mode: EnergyMode, seams: Seams) -> bool {
    if INSTALLED.load(Ordering::Acquire) {
        return false;
    }
    // SAFETY: boot CPU, no other CPU in the scheduler, nothing reads before
    // `INSTALLED`.
    unsafe { *MODEL.0.get() = Installed { model, mode, seams } };
    POLICY.init(seams.governor);
    INSTALLED.store(true, Ordering::Release);
    GOV_ON.store(seams.governor != azos_energy::Governor::Fixed, Ordering::Release);
    // E5: the same opt-in as the governors (a model, a mode that is not
    // `performance`, invariants I4 and I5), and only where CPUs differ.
    EAS_ON.store(
        azos_limits::SCHED_EAS
            && model.is_present()
            && mode != EnergyMode::Performance
            && model.is_asymmetric(),
        Ordering::Release,
    );
    true
}

/// The live policy: what user space may change at run time within the
/// kernel's limits (`azos_energy::policy`, set through the `power` endpoint).
/// Boots as the seams chose; the governor and idle governor read it.
static POLICY: Policy = Policy::new(azos_energy::Governor::Fixed);

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

// ── Stage E5: energy-aware wake placement ───────────────────────────────────
//
// `wake_target_cpu` asks [`eas_place`] first for a fair task of this build
// when [`eas_active`]. The comparison is `azos_energy::EnergyModel::eas_pick`
// (host-tested); this half gathers its inputs and nothing else. The signals
// are busy fractions at whatever OPP the CPU ran at, so each is scaled by the
// capacity of the OPP its domain's governor last recorded (the fastest one
// before a decision, which is where firmware leaves the clock until one is
// applied).

/// Energy-aware placement is on: `SCHED_EAS`, a model, a mode other than
/// `performance`, and CPUs that differ in capacity. One relaxed load.
static EAS_ON: AtomicBool = AtomicBool::new(false);

/// Whether wake-up placement consults the energy model.
#[inline]
pub fn eas_active() -> bool {
    EAS_ON.load(Ordering::Relaxed)
}

/// The CPUs of the domains the QoS class of the task in slot `idx` is mapped
/// to (`Policy::set_qos_domains`); every CPU until a mapping is set.
fn qos_cpus(idx: usize) -> u32 {
    let class = crate::classes::sc_of(idx).map_or(0, |sc| sc.qos() as usize);
    let allowed = POLICY.qos_domains(class);
    model()
        .domains()
        .iter()
        .enumerate()
        .filter(|(di, _)| allowed >> di & 1 != 0)
        .fold(0, |m, (_, d)| m | d.cpus)
}

/// Capacity of `cpu` at the OPP its domain was last recorded to run at;
/// `None` for a CPU in no domain.
fn cpu_capacity(cpu: usize) -> Option<u16> {
    let di = domain_index(cpu)?;
    let opps = model().domains()[di].opps();
    let opp = match domain_opp(di) {
        OPP_BOOT => opps.last(),
        o => opps.get(o as usize).or(opps.last()),
    }?;
    Some(opp.capacity)
}

/// The CPU a fair task in pool slot `idx`, last run on `prev_cpu`, should be
/// woken on, among `candidates` (bit n = CPU n; the model names at most 32 CPUs); `None` when the energy
/// comparison does not apply (the load balancer's placement then decides):
/// the machine is overutilised, the task fits no candidate, or the model does
/// not describe `prev_cpu`.
pub fn eas_place(idx: usize, prev_cpu: usize, candidates: u32) -> Option<usize> {
    // The policy's steering, within the kernel's limits: no parked CPU, and
    // the domains the task's QoS class is mapped to. This is the only reader
    // of either (`find_best_cpu` and the balancer place without them).
    let candidates = candidates & !POLICY.parked() & qos_cpus(idx);
    let at = now();
    let mut util = [0u32; MAX_CPUS];
    for (c, u) in util.iter_mut().enumerate().take(super::ncpu().min(MAX_CPUS)) {
        *u = invariant_util(cpu_util_at(c, at), cpu_capacity(c)?);
    }
    let task = invariant_util(task_util(idx), cpu_capacity(prev_cpu)?);
    match model().eas_pick(&util, task, prev_cpu, candidates) {
        azos_energy::model::EasChoice::Cpu(c) => Some(c),
        azos_energy::model::EasChoice::Overutilised => None,
    }
}

// ── Stage E3: the frequency governor ────────────────────────────────────────
//
// Evaluated per performance domain, rate-limited (`governor::RATE_LIMIT_US`),
// from any CPU's tick and idle entry (an idle hart is tick-less, so a domain
// whose CPUs all went idle is re-evaluated by a hart that still runs, from
// projected signals). Inputs: the busiest CPU signal of the domain and the most
// loaded hart's admitted real-time density (`rt::ADMITTED_PPM`, lock-free).
// The decision is recorded here, never applied here: no clock may be moved
// from the tick (a mailbox round trip, a rail over I2C). The board's apply
// step (the kernel's `thermal` task, `kernel/src/boot/thermal.rs`, with or
// without Kconfig `THERMAL`) is woken when a choice changes, moves the clock
// and acknowledges the outcome ([`gov_ack`]). The governor asserts that it
// did: a choice for a domain the board can move that is still not
// acknowledged after the apply deadline is overdue, counted and recorded
// (`Rule::OppApply`). A board with no actuator (QEMU) installs no apply step,
// so nothing is asserted there.

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

/// The apply step's task (0: none, nothing is asserted).
static APPLY_TID: AtomicU32 = AtomicU32::new(0);
/// Domains the apply step can move (bit d); an answer of "no actuator"
/// clears the domain's bit.
static GOV_ACTUATED: AtomicU32 = AtomicU32::new(0);
/// A choice changed since the apply step last took the flag.
static APPLY_PENDING: AtomicBool = AtomicBool::new(false);
/// Per domain, the choice the apply step last answered for.
static GOV_ACKED: [AtomicU8; MAX_DOMAINS] = [const { AtomicU8::new(OPP_BOOT) }; MAX_DOMAINS];
/// Per domain, since when the choice has differed from the acknowledged one.
static GOV_SINCE: [AtomicU64; MAX_DOMAINS] = [const { AtomicU64::new(0) }; MAX_DOMAINS];
/// Domains whose last outcome did not reach the clock (bit d).
static GOV_LOST: AtomicU32 = AtomicU32::new(0);
/// Choices that reached the clock, of them capped by the heat, refused by the
/// actuator, overdue.
static GOV_REACHED: AtomicU32 = AtomicU32::new(0);
static GOV_CAPPED: AtomicU32 = AtomicU32::new(0);
static GOV_UNAPPLIED: AtomicU32 = AtomicU32::new(0);
static GOV_OVERDUE: AtomicU32 = AtomicU32::new(0);

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

/// What became of the governor's choices so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplyStats {
    /// Choices the apply step put on the clock (at the choice, the heat's cap
    /// or a floor).
    pub reached: u32,
    /// Of those, the ones the heat capped.
    pub capped: u32,
    /// Choices the actuator refused or failed.
    pub unapplied: u32,
    /// Choices no apply step answered by the deadline. Must stay 0.
    pub overdue: u32,
    /// Domains the apply step can move (bit d).
    pub actuated: u32,
}

/// The apply step's counters.
pub fn apply_stats() -> ApplyStats {
    ApplyStats {
        reached: GOV_REACHED.load(Ordering::Relaxed),
        capped: GOV_CAPPED.load(Ordering::Relaxed),
        unapplied: GOV_UNAPPLIED.load(Ordering::Relaxed),
        overdue: GOV_OVERDUE.load(Ordering::Relaxed),
        actuated: GOV_ACTUATED.load(Ordering::Relaxed),
    }
}

/// The board's apply step is the task `tid`, and can move the domains of
/// `actuated` (bit d). From then on a changed choice wakes it, and a choice it
/// leaves unanswered past Kconfig `ENERGY_APPLY_DEADLINE_MS` is overdue. The
/// wait starts here: a choice the governor made before the step existed (at
/// boot, before the task was created) is not overdue for having waited for it.
pub fn apply_install(tid: u32, actuated: u32) {
    let at = now();
    for since in GOV_SINCE.iter() {
        since.store(at, Ordering::Relaxed);
    }
    GOV_ACTUATED.store(actuated, Ordering::Relaxed);
    APPLY_TID.store(tid, Ordering::Release);
}

/// Take the "a choice changed" flag: the apply step ticks again instead of
/// sleeping when it was set.
pub fn apply_take() -> bool {
    APPLY_PENDING.swap(false, Ordering::AcqRel)
}

/// The apply step answers for the choice `choice` of domain `d`: it asked the
/// actuator for `target` (the choice under the heat's cap and the floors) and
/// got `a`. The first answer of a run that did not reach the clock leaves a
/// refusal record, the first that reached it again an admission.
pub fn gov_ack(d: usize, choice: u8, target: u8, a: azos_energy::opp::GovApply) {
    use azos_energy::opp::{apply_record, ApplyRecord, GovApply};
    if d >= MAX_DOMAINS {
        return;
    }
    let bit = 1u32 << d;
    match a {
        GovApply::NoActuator => {
            // The board cannot move this domain: nothing to assert there.
            GOV_ACTUATED.fetch_and(!bit, Ordering::Relaxed);
        }
        GovApply::Unapplied(_) => {
            GOV_UNAPPLIED.fetch_add(1, Ordering::Relaxed);
        }
        GovApply::Capped => {
            GOV_REACHED.fetch_add(1, Ordering::Relaxed);
            GOV_CAPPED.fetch_add(1, Ordering::Relaxed);
        }
        GovApply::Applied | GovApply::Raised => {
            GOV_REACHED.fetch_add(1, Ordering::Relaxed);
        }
    }
    GOV_ACKED[d].store(choice, Ordering::Release);
    let lost = GOV_LOST.load(Ordering::Relaxed) & bit != 0;
    let verdict = match apply_record(lost, a) {
        ApplyRecord::None => return,
        ApplyRecord::Lost => {
            GOV_LOST.fetch_or(bit, Ordering::Relaxed);
            azos_decision::Verdict::Refuse
        }
        ApplyRecord::Back => {
            GOV_LOST.fetch_and(!bit, Ordering::Relaxed);
            azos_decision::Verdict::Admit
        }
    };
    azos_decision::record(azos_decision::Rule::OppApply, verdict, d as u32, [choice as u64, target as u64, a.code() as u64]);
}

/// The governor's assertion for domain `di` at `at`, from the tick: a choice
/// the board can move and no apply step answered by the deadline is counted
/// once and recorded (`Deny`, which stays in the ring: the tick takes no lock
/// the durable path might) until an answer reaches the clock again.
fn assert_applied(di: usize, at: u64) {
    let bit = 1u32 << di;
    if GOV_ACTUATED.load(Ordering::Relaxed) & bit == 0 || GOV_LOST.load(Ordering::Relaxed) & bit != 0 {
        return;
    }
    let choice = GOV_OPP[di].load(Ordering::Relaxed);
    let acked = GOV_ACKED[di].load(Ordering::Acquire);
    let since = GOV_SINCE[di].load(Ordering::Relaxed);
    let deadline = ticks(azos_limits::ENERGY_APPLY_DEADLINE_MS as u64 * 1_000);
    if !azos_energy::opp::apply_overdue(choice, acked, since, at, deadline) {
        return;
    }
    if GOV_LOST.fetch_or(bit, Ordering::Relaxed) & bit != 0 {
        return;
    }
    GOV_OVERDUE.fetch_add(1, Ordering::Relaxed);
    azos_decision::record(
        azos_decision::Rule::OppApply,
        azos_decision::Verdict::Deny,
        di as u32,
        [choice as u64, OPP_BOOT as u64, azos_energy::opp::APPLY_OVERDUE as u64],
    );
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
    let g = POLICY.effective_governor();
    if g == Governor::Fixed {
        return 0;
    }
    let mut n = 0;
    let rate_us = POLICY.rate_limit_us() as u64;
    for (di, d) in model().domains().iter().enumerate() {
        let last = GOV_LAST[di].load(Ordering::Relaxed);
        if !governor::due(last, at, TIMER_FREQ, rate_us) {
            continue;
        }
        // One hart evaluates a domain per interval.
        if GOV_LAST[di].compare_exchange(last, at.max(1), Ordering::AcqRel, Ordering::Relaxed).is_err() {
            continue;
        }
        let mut util = 0u32;
        for c in 0..super::ncpu().min(32) {
            if d.cpus & (1 << c) != 0 {
                util = util.max(cpu_util_at(c, at));
            }
        }
        let ppm = domain_admitted_ppm(di);
        let prev = GOV_OPP[di].load(Ordering::Relaxed);
        let cur = if prev == OPP_BOOT { d.opps().len().saturating_sub(1) } else { prev as usize };
        let Some(dec) = g.target_opp(d, util, cur, ppm, POLICY.headroom_pct()) else { continue };
        // The user's range bounds the request; the floors win again.
        let dec = POLICY.clamp(di, dec);
        n += 1;
        GOV_EVALS.fetch_add(1, Ordering::Relaxed);
        GOV_WHY[match dec.why {
            Why::Schedutil => 0,
            Why::DeadlineFloor => 1,
            Why::SafetyFloor => 2,
        }]
        .fetch_add(1, Ordering::Relaxed);
        if prev != dec.opp as u8 {
            // The wait for an answer starts at the first choice that differs
            // from the acknowledged one, not at the latest: a choice that
            // keeps changing under a dead apply step is still overdue.
            if GOV_ACKED[di].load(Ordering::Acquire) == prev {
                GOV_SINCE[di].store(at, Ordering::Relaxed);
            }
            GOV_OPP[di].store(dec.opp as u8, Ordering::Relaxed);
            GOV_CHANGES.fetch_add(1, Ordering::Relaxed);
            // One wake per apply round: a flag already up has its wake on the
            // way (a task not yet asleep keeps it as a pending wake).
            if GOV_ACTUATED.load(Ordering::Relaxed) & (1 << di) != 0 && !APPLY_PENDING.swap(true, Ordering::AcqRel) {
                let tid = APPLY_TID.load(Ordering::Acquire);
                if tid != 0 {
                    let _ = crate::scheduler::wake_task_by_tid(tid, &|r| matches!(r, crate::task::WaitReason::Timer(_)));
                }
            }
        }
        assert_applied(di, at);
    }
    n
}

/// The real-time density admitted on the most loaded hart of domain `di`
/// (the I1 floor's input; the thermal task hands it to the framework so heat
/// never lowers a clock under it).
pub fn domain_admitted_ppm(di: usize) -> u32 {
    let Some(d) = model().domains().get(di) else { return 0 };
    (0..super::ncpu().min(32))
        .filter(|c| d.cpus & (1 << c) != 0)
        .map(|c| super::rt::ADMITTED_PPM[c].load(Ordering::Relaxed))
        .max()
        .unwrap_or(0)
}

// ── The run-time policy (limit-checked setters) ─────────────────────────────
//
// User space owns the policy, the kernel enforces limits: each setter checks
// its argument against `azos_energy::policy`'s hard floors, refuses and
// records what is outside them. Reached from the `power` endpoint.

/// Choose the governor (`POLICY_GOV_*`).
pub fn policy_set_governor(gov: u32) -> Result<(), Refusal> {
    let r = POLICY.set_governor(model(), gov);
    GOV_ON.store(POLICY.effective_governor() != Governor::Fixed, Ordering::Relaxed);
    r
}

/// Restrict `domain` to OPPs `min..=max`.
pub fn policy_set_opp_range(domain: u32, min: u32, max: u32) -> Result<(), Refusal> {
    POLICY.set_opp_range(model(), domain, min, max, domain_admitted_ppm(domain as usize))
}

/// Set the schedutil headroom, percent.
pub fn policy_set_headroom(pct: u32) -> Result<(), Refusal> {
    POLICY.set_headroom(pct)
}

/// Set the shortest interval between governor evaluations, microseconds.
pub fn policy_set_rate_limit(us: u32) -> Result<(), Refusal> {
    POLICY.set_rate_limit(us)
}

/// Limit the idle governor to states `0..=depth`.
pub fn policy_set_idle_depth(depth: u32) -> Result<(), Refusal> {
    POLICY.set_idle_depth(model(), depth)
}

/// Cap `domain` at `mw` milliwatts (0 lifts the cap).
pub fn policy_set_power_cap(domain: u32, mw: u32) -> Result<(), Refusal> {
    POLICY.set_power_cap(model(), domain, mw, domain_admitted_ppm(domain as usize))
}

/// Park the CPUs of `mask` and unpark the others.
pub fn policy_set_parked(mask: u32) -> Result<(), Refusal> {
    let mut ppm = [0u32; 32];
    for (c, p) in ppm.iter_mut().enumerate().take(super::ncpu().min(32)) {
        *p = super::rt::ADMITTED_PPM[c].load(Ordering::Relaxed);
    }
    POLICY.set_parked(model(), mask, &ppm)
}

/// Map QoS class `class` to the domains of `domains`.
pub fn policy_set_qos_domains(class: u32, domains: u32) -> Result<(), Refusal> {
    POLICY.set_qos_domains(model(), class, domains)
}

/// Hand over the signed topology's `[degrade.NAME]` rows (level, enter
/// charge, leave charge), once at boot after `install`, with the reserve and
/// the report timeout Kconfig chose. The report age starts now.
pub fn install_battery(rows: &[DegradeRow]) {
    let limits = BatteryLimits {
        reserve_pct: azos_limits::ENERGY_BATTERY_RESERVE_PCT as u8,
        report_timeout_ticks: ticks(azos_limits::ENERGY_BATTERY_REPORT_TIMEOUT_MS as u64 * 1_000),
    };
    POLICY.init_battery(rows, limits, now());
    GOV_ON.store(POLICY.effective_governor() != Governor::Fixed, Ordering::Relaxed);
}

/// The power service reports the charge it estimated and the degrade level it
/// holds. A change of the level leaves a `Rule::BatteryDegrade` record: the
/// charge, the level before and the level now; the subject is the level now.
pub fn policy_report_battery(soc_pct: u32, level: u32) -> Result<(), Refusal> {
    let change = POLICY.report_battery(soc_pct, level)?;
    POLICY.battery_alive(now());
    // The reserve turns the deadline-floor governor on or off.
    GOV_ON.store(POLICY.effective_governor() != Governor::Fixed, Ordering::Relaxed);
    if let Some(c) = change {
        azos_decision::record(
            azos_decision::Rule::BatteryDegrade,
            azos_decision::Verdict::Place,
            c.to as u32,
            [c.soc_pct as u64, c.from as u64, c.to as u64],
        );
    }
    Ok(())
}

/// The policy state word `sel` (`POLICY_STATE_*`), `None` for an unknown one.
pub fn policy_state(sel: u64) -> Option<u64> {
    POLICY.state_word(model(), mode(), domain_opp, sel)
}

/// The policy statistics word `sel` (`POLICY_STATS_*`), `None` for an
/// unknown one.
pub fn policy_stats(sel: u64) -> Option<u64> {
    use azos_abi::power::{POLICY_STATS_OPP_CAPPED, POLICY_STATS_OPP_OVERDUE, POLICY_STATS_OPP_REACHED, POLICY_STATS_OPP_UNAPPLIED};
    let a = apply_stats();
    Some(match sel {
        POLICY_STATS_OPP_REACHED => a.reached as u64,
        POLICY_STATS_OPP_CAPPED => a.capped as u64,
        POLICY_STATS_OPP_UNAPPLIED => a.unapplied as u64,
        POLICY_STATS_OPP_OVERDUE => a.overdue as u64,
        _ => {
            let g = gov_stats();
            return POLICY.stats_word(g.evals, g.changes, sel);
        }
    })
}

// ── Stage E4: the idle governor ─────────────────────────────────────────────
//
// The sleep bound is the earlier of the nearest timer sleeper
// (`nearest_timer_deadline`: the timer heap, in the default build since wave
// 13; the O(MAX_TASKS) sleeper sweep without `sched-timer-heap`)
// and what the
// hart has programmed (`timebase::programmed`, which includes the hart-0
// keepalive and the SCHED-RT enforcement arms). The real-time slack is
// `rt::rt_slack`. The choice is counted and entered through the arch idle seam
// (`Cpu::cpu_idle(depth)`, which reports the time slept), and nothing here touches a timer,
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

/// Band tasks pinned to `cpu` that have not exited, asleep or not (their
/// timer wake lands on `cpu`). A scan of the pool, as `pinned_to`: unlocked,
/// a stale answer is off by a task being created or freed.
fn bound_band_tasks(cpu: usize) -> u32 {
    let mut n = 0;
    for idx in 0..MAX_TASKS {
        // SAFETY: a static table of atomics, read.
        if !unsafe { TASK_VALID[idx].load(Ordering::Relaxed) } {
            continue;
        }
        // SAFETY: a valid slot; plain words read, see above.
        let t = unsafe { task_ref(idx) };
        if t.cpu_affinity == cpu as i8
            && crate::task::is_rt_priority(t.priority.load(Ordering::Relaxed))
            && !matches!(t.state(), super::TaskState::Zombie | super::TaskState::Invalid)
        {
            n += 1;
        }
    }
    n
}

/// One idle wait of `cpu` (the calling hart) through the installed idle
/// governor; `enter(depth)` is the ISA's idle seam (`Cpu::cpu_idle`): it
/// idles in the state of that index and returns the microseconds slept.
pub fn idle_wait(cpu: usize, enter: impl Fn(u8) -> u64) {
    let at = now();
    if GOV_ON.load(Ordering::Relaxed) {
        let _ = gov_maybe(cpu, at);
    }
    if seams().idle == IdleGovernor::ShallowOnly || cpu >= MAX_CPUS {
        enter(0);
        return;
    }
    let states = match domain_index(cpu) {
        Some(di) => model().domains()[di].idle_states(),
        None => &[],
    };
    // The policy's depth limit only shortens the list the governor picks
    // from, so the real-time slack (I3) still applies on top.
    // A parked CPU is not held to it: parking is the policy asking this CPU
    // to sleep as deep as the slack allows.
    let parked = cpu < 32 && POLICY.parked() >> cpu & 1 != 0;
    let states = match POLICY.idle_depth() {
        _ if parked => states,
        azos_energy::policy::NONE_U8 => states,
        depth => &states[..states.len().min(depth as usize + 1)],
    };
    // A CPU with real-time state (`idle::holds_real_time`) never sleeps in a
    // state that loses its context, whatever its slack: the slack knows the
    // next reservation deadline, not the firmware's re-entry and the restore
    // the exit latency of such a state holds. The bound-task scan runs only
    // when a state of the list could be cut.
    let states = if states.iter().any(|s| s.loses_context) {
        let rt_cpu = idle::holds_real_time(
            super::cpu_has_rt_state(cpu),
            bound_band_tasks(cpu),
            super::isolated_cpu_mask() >> cpu & 1 != 0,
        );
        idle::allowed(states, rt_cpu)
    } else {
        states
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
    let slept_us = enter(c as u8);
    if idle::reflect(states, h, slept_us, sleep_us) {
        IDLE_INTERCEPTS.fetch_add(1, Ordering::Relaxed);
    }
}

// ── System power assertions ─────────────────────────────────────────────────
//
// The ledger of `azos_energy::assertion`, one for the machine, reached from
// the `powerassert` endpoint (`azos_syscall::power_assert`) and read by the
// suspend sequence's gate (`kernel/src/boot/energy.rs`). Every op reaps
// first: an assertion past its timeout is released here and recorded
// (`Rule::PowerAssertion`, `Deny`), so a holder that died or forgot cannot
// keep the machine awake. Task context only (the endpoint, the suspend
// gate); the lapses are recorded with the lock released.

pub use azos_energy::assertion::AssertError;
use azos_energy::assertion::{Assertion, Ledger, Quota, MAX_ASSERTIONS};

static ASSERTIONS: azos_sync::SpinLock<Ledger> = azos_sync::SpinLock::new(Ledger::new(Quota::new(
    azos_limits::POWER_ASSERTIONS_PER_TASK as u32,
    azos_limits::POWER_ASSERTION_TTL_MAX_MS as u32,
)));

fn now_ms() -> u64 {
    now() / (TIMER_FREQ / 1_000).max(1)
}

/// Run `f` on the ledger at `now`, after the reap; then record what lapsed.
fn with_assertions<R>(f: impl FnOnce(&mut Ledger, u64) -> R) -> R {
    let at = now_ms();
    let mut lapsed = [None::<Assertion>; MAX_ASSERTIONS];
    let r = {
        let mut l = ASSERTIONS.lock();
        let mut n = 0;
        l.reap(at, |a| {
            lapsed[n] = Some(*a);
            n += 1;
        });
        f(&mut l, at)
    };
    for a in lapsed.iter().flatten() {
        azos_drv_sys::kwarn!(
            "[POWER] assertion {} of tid {} (reason {}) released at its timeout of {} ms (recorded)",
            a.id, a.owner, a.reason, a.ttl_ms,
        );
        azos_decision::record(
            azos_decision::Rule::PowerAssertion,
            azos_decision::Verdict::Deny,
            a.owner,
            [a.reason as u64, a.ttl_ms as u64, a.id as u64],
        );
    }
    r
}

/// `owner` asks to keep the machine out of system suspend for `ttl_ms`, for
/// `reason`: the assertion's id. A refusal is recorded.
pub fn assert_hold(owner: u32, reason: u32, ttl_ms: u32) -> Result<u32, AssertError> {
    let r = with_assertions(|l, at| l.hold(owner, reason, ttl_ms, at));
    if r.is_err() {
        azos_decision::record(
            azos_decision::Rule::PowerAssertion,
            azos_decision::Verdict::Refuse,
            owner,
            [reason as u64, ttl_ms as u64, 0],
        );
    }
    r
}

/// `owner` gives assertion `id` back.
pub fn assert_release(owner: u32, id: u32) -> Result<(), AssertError> {
    with_assertions(|l, _| l.release(owner, id).map(|_| ()))
}

/// The live assertions: what keeps the machine out of system suspend now.
pub fn assert_live() -> u32 {
    with_assertions(|l, at| l.live(at))
}

/// A `PowerAssert::stats` counter (`azos_devif::power_assert::STAT_*`).
pub fn assert_stat(sel: u32) -> Option<u64> {
    use azos_devif::power_assert::{STAT_EXPIRED, STAT_GRANTED, STAT_LIVE, STAT_REFUSED, STAT_RELEASED};
    with_assertions(|l, at| {
        let c = l.counters;
        Some(match sel {
            STAT_LIVE => l.live(at) as u64,
            STAT_GRANTED => c.granted as u64,
            STAT_RELEASED => c.released as u64,
            STAT_EXPIRED => c.expired as u64,
            STAT_REFUSED => c.refused as u64,
            _ => return None,
        })
    })
}
