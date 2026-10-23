// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Real-time band budget and EDF + CBS on the dispatch path (wave 11
//! SCHED-RT). A child module of `scheduler.rs` (pulled in
//! with `#[path]`), so it reaches the ready queues and the task pool without
//! widening their visibility; the arithmetic it applies is `rt_core.rs`, which
//! the host suite tests.
//!
//! # What it does
//!
//! * **Band budget, per hart.** While a task of the real-time band
//!   (priority < `RT_PRIORITY_THRESHOLD`) runs on a hart and a non-band task is
//!   ready there, the band may use at most `RT_BAND_CAP_PCT` of each
//!   `RT_BAND_WINDOW_MS` window. Past it the pick skips the band levels until
//!   the window ends. With nothing else ready the band keeps the hart. The
//!   kernel safety loops (rt-motor, imu, flight-ctrl, sys-wdt) are exempt
//!   (owner decision): never skipped, never charged ([`exempt_from_band_cap`],
//!   kernel-only).
//! * **EDF + CBS, per hart.** A task with a reservation (`Task::rt`, admitted
//!   by [`reserve`]) is pinned to the hart admission placed it on and listed
//!   in that hart's reservation set. Inside one priority level reservation
//!   tasks run before the level's FIFO tasks, earliest absolute deadline
//!   first, and preempt a running task of the same level with a later
//!   deadline. Run time is charged against the server budget; a hard
//!   reservation that runs out is throttled until its deadline (the pick
//!   skips it), a soft one has its deadline postponed by a period.
//!
//! * **Proxy execution: a passive server runs on its caller's reservation**
//!   (seL4 MCS passive servers; the wait graph's stage 2, `azos_sync::
//!   waitgraph`). A reservation whose task is blocked in a call (its
//!   wait-graph IPC call edge) is run by the task at the end of that chain of
//!   calls ([`proxy_of`]) when that task holds no reservation of its own: the
//!   pick orders it by the caller's absolute deadline, and its run time is
//!   charged to the caller's budget (the dispatch tail books it on the
//!   caller's slot). A budget that runs out throttles the proxy exactly as it
//!   would the caller, and the server is told (a timeout notice on its
//!   endpoint, [`set_proxy_timeout_hook`]). Only a server placed on the
//!   reservation's hart can be its proxy (the IPC wake co-locates it,
//!   `wake::ipc_wake_target_cpu`); elsewhere it runs at the priority the
//!   wait graph boosts it to.
//!
//! # What it costs when unused
//!
//! The dispatch tail tests one per-hart word ([`FLAGS`]) and the next task's
//! priority; with no band task involved and no reservation on the hart
//! nothing else runs and nothing is armed. The pick path and the tick test
//! the same word. The direct IPC switch is refused only while the word is
//! set or either side is a band task (it bypasses the pick, so it would
//! bypass the accounting too).
//!
//! # Timers
//!
//! Every enforcement instant (band exhaustion, end of an exhausted window,
//! the running reservation's budget, the earliest replenishment of a
//! throttled one) is armed with `timebase::arm_if_earlier`, after the tick
//! handler and the idle boundary have programmed their own event, so it is
//! never overwritten by a later one. A write happens only when the instant
//! is earlier than what the hart already has.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::rt_core::{self, Band, Cbs, HartLoad, Refusal};
use crate::task::{TaskState, IDLE_PRIORITY, RT_PRIORITY_THRESHOLD};

use super::{
    cpu_remove, ncpu, prio_bucket, task_mut, task_ref, CpuLockGuard, MAX_CPUS, MAX_TASKS, PER_CPU,
};

/// Reservations one hart can hold.
pub const SET_CAP: usize = 16;

/// Ready-bitmap levels of the band.
const BAND_LEVELS: u32 = (1u32 << RT_PRIORITY_THRESHOLD) - 1;
/// Ready-bitmap levels outside the band, idle excluded (idle is always ready).
const NONBAND_LEVELS: u32 = !BAND_LEVELS & !(1u32 << IDLE_PRIORITY);

/// `FLAGS` bits. Owner-hart bits are set and cleared with RMWs because
/// admission sets [`F_RESV`] from another hart.
const F_BAND_RUN: u32 = 1;
const F_EXHAUSTED: u32 = 2;
const F_RESV: u32 = 4;

/// The window, in counter ticks.
const WINDOW: u64 = azos_drv_sys::timebase::TIMER_FREQ
    .saturating_mul(azos_limits::RT_BAND_WINDOW_MS)
    / 1_000;

/// The band's share of the window, in percent. `rt-band-canary` turns the
/// budget off (100 %): a band task that never blocks owns its hart again.
#[cfg(not(feature = "rt-band-canary"))]
const CAP_PCT: u32 = azos_limits::RT_BAND_CAP_PCT as u32;
#[cfg(feature = "rt-band-canary")]
const CAP_PCT: u32 = 100;

/// Band run time per window, in counter ticks (`u64::MAX` = no cap).
const CAP: u64 = rt_core::band_cap_ticks(WINDOW, CAP_PCT);

/// Admission limit for the band's reservations on one hart, ppm.
const BAND_LIMIT_PPM: u32 = (azos_limits::RT_BAND_CAP_PCT as u32).saturating_mul(10_000);

/// `rt-cbs-canary`: reservations are never charged, so an overrun is never
/// throttled and its deadline never moves.
const CBS_ON: bool = !cfg!(feature = "rt-cbs-canary");
/// `rt-edf-canary`: inside a level the reservation tasks are taken FIFO.
const EDF_ON: bool = !cfg!(feature = "rt-edf-canary");
/// `rt-admit-canary`: run-time admission accepts every well-formed reservation.
const ADMIT_ON: bool = !cfg!(feature = "rt-admit-canary");

static FLAGS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
/// One hart's reservation state, in its per-CPU area (wave 15, NRCPUS:
/// about 1 KiB a CPU, which a `[_; MAX_CPUS]` static charged for every CPU of
/// the Kconfig ceiling). Touched only after `FLAGS[cpu]` says the hart has a
/// reservation, or by admission under [`ADMIT`] for a CPU below `ncpu()`.
pub(crate) struct RtCpu {
    /// Reservation set (`usize::MAX` = empty slot). Written under [`ADMIT`];
    /// read lock-free by the owner hart (`Acquire` pairs with the publishing
    /// `Release`, so the task's `rt` is complete when read).
    set: [AtomicUsize; SET_CAP],
    /// The reservations themselves, one per set slot: written by admission
    /// before the slot is published in `set`, then only by the owner hart.
    /// Not in `Task`: the TCB is layout-frozen (`TASK_SATP_OFFSET`) and sized
    /// per `MAX_TASKS` slot, while reservations are a handful per hart.
    res: core::cell::UnsafeCell<[Cbs; SET_CAP]>,
    /// Owner-hart state (see [`Owner`]).
    owner: core::cell::UnsafeCell<Owner>,
}

/// Initial state, written in place when a CPU's area is attached.
unsafe fn rt_cpu_init(p: *mut RtCpu) {
    // SAFETY: the caller hands a zeroed, aligned, exclusive slot.
    unsafe {
        p.write(RtCpu {
            set: [const { AtomicUsize::new(usize::MAX) }; SET_CAP],
            res: core::cell::UnsafeCell::new([Cbs::NONE; SET_CAP]),
            owner: core::cell::UnsafeCell::new(Owner {
                band: Band::NEW, cur: usize::MAX, cur_slot: 0, cur_since: 0, timeout_due: usize::MAX,
            }),
        })
    };
}

/// Every hart's [`RtCpu`].
///
/// Scope: not one of `azos_sync::scope`'s yet (a bare `PerCpuRemote`): the
/// owner-hart state wants a `PerCpu`, the set is read by other harts
/// lock-free (a `PerCpu<_, true>` read), admission writes under `ADMIT`.
pub(crate) static RT_CPU: azos_percpu::PerCpuRemote<RtCpu> = azos_percpu::PerCpuRemote::with_init(rt_cpu_init);

/// `cpu`'s reservation set. `cpu < ncpu()`.
#[inline(always)]
fn set_of(cpu: usize) -> &'static [AtomicUsize; SET_CAP] {
    // SAFETY: attached at boot for every CPU below `ncpu()`, never freed.
    unsafe { &(*RT_CPU.ptr(cpu)).set }
}

/// `cpu`'s owner state. `cpu < ncpu()`; the owner-hart contract of [`Owner`].
#[inline(always)]
fn owner_of(cpu: usize) -> *mut Owner {
    // SAFETY: as `set_of`; the pointer is dereferenced under `Owner`'s rule.
    unsafe { (*RT_CPU.ptr(cpu)).owner.get() }
}

/// Owner-hart state: written only by the hart it describes, with interrupts
/// off (dispatch, tick), so it needs no lock.
struct Owner {
    band: Band,
    /// The reservation task running now (`usize::MAX` = none) and its slot.
    cur: usize,
    cur_slot: usize,
    /// When `cur` was last charged.
    cur_since: u64,
    /// A reservation that ran out while a proxy ran on it: its holder, whose
    /// call's server is told once the dispatch path is left
    /// ([`flush_timeout`]). `usize::MAX` = none.
    timeout_due: usize,
}


/// Per-hart admitted load. Admission and release only.
static ADMIT: azos_sync::SpinLock<[HartLoad; MAX_CPUS]> =
    azos_sync::SpinLock::new([HartLoad { total_ppm: 0, band_ppm: 0 }; MAX_CPUS]);

/// A lock-free copy of each hart's admitted density
/// (`ADMIT[cpu].total_ppm`), written under [`ADMIT`] after every change, read
/// by the energy governor from the tick (where `ADMIT` must not be taken).
#[cfg(feature = "energy")]
pub static ADMITTED_PPM: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];

/// Invariant I3: the slack, in counter ticks from `now`, to the
/// nearest real-time deadline a reservation on `cpu` can have — for each
/// reservation, its relative deadline `d` (a release at any instant from now
/// on gets a deadline at least that far), or the time left to its current
/// absolute deadline when that is closer. `u64::MAX` with none.
///
/// Called by `cpu`'s own idle task. The reservations are written by the same
/// hart with interrupts off, so a read here may see one tick's update half
/// done; the answer is an advisory bound for an idle-state choice, and every
/// field read is a naturally aligned word.
#[cfg(feature = "energy")]
pub fn rt_slack(cpu: usize, now: u64) -> u64 {
    let mut slack = u64::MAX;
    if cfg!(feature = "energy-slack-canary") || cpu >= ncpu() || FLAGS[cpu].load(Ordering::Acquire) & F_RESV == 0 {
        return slack;
    }
    for k in 0..SET_CAP {
        if set_of(cpu)[k].load(Ordering::Acquire) == usize::MAX {
            continue;
        }
        // SAFETY: the slot is published; see above for the concurrent writer.
        let r = unsafe { *res(cpu, k) };
        if !r.active() {
            continue;
        }
        let mut s = r.d;
        if r.deadline > now {
            s = s.min(r.deadline - now);
        }
        slack = slack.min(s);
    }
    slack
}

/// Counters, read by [`stats`].
static BAND_THROTTLES: AtomicU32 = AtomicU32::new(0);
static CBS_EXHAUSTED: AtomicU32 = AtomicU32::new(0);
static REFUSALS: AtomicU32 = AtomicU32::new(0);
static ADMITTED: AtomicU32 = AtomicU32::new(0);
static ARM_WRITES: AtomicU32 = AtomicU32::new(0);
static ARM_CALLS: AtomicU32 = AtomicU32::new(0);

/// Kernel safety loops exempt from the band budget (owner decision, wave 11):
/// rt-motor, flight-ctrl, imu and sys-wdt are never throttled when the band
/// runs out, and their run time is not charged to it. Set only by
/// [`exempt_from_band_cap`], which the kernel calls for those tasks right
/// after creating them; no syscall and no topology field reaches it. Cleared
/// when the slot is freed or reused.
static EXEMPT: [core::sync::atomic::AtomicBool; MAX_TASKS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; MAX_TASKS];

/// Whether task `idx` is exempt from the band budget. `rt-exempt-canary`:
/// nobody is.
#[inline(always)]
fn exempt(idx: usize) -> bool {
    !cfg!(feature = "rt-exempt-canary")
        && idx < MAX_TASKS
        && EXEMPT[idx].load(Ordering::Relaxed)
}

/// Exempt kernel task `idx` from the band budget: it is never skipped by the
/// pick while the band is exhausted, and its run time is not charged to the
/// band. **Kernel-only**: for the safety loops (actuation, e-stop, watchdog),
/// called once at their creation. Not reachable from ring 3 or the topology —
/// do not add a caller that a user request or a configuration key can drive.
pub fn exempt_from_band_cap(idx: usize) {
    if idx < MAX_TASKS {
        EXEMPT[idx].store(true, Ordering::Relaxed);
        // An exempt loop's SC is the stop class.
        let base = unsafe { task_ref(idx) }.base_priority.load(Ordering::Relaxed);
        super::classes::on_base_priority(idx, base);
    }
}

/// Whether task `idx` is exempt (for the rows and the host-visible counters).
pub fn is_exempt_from_band_cap(idx: usize) -> bool {
    exempt(idx)
}

/// `SCHED_CLASS_RT=n`: no task is in the band, so the band budget is never
/// charged and its paths fold out.
#[inline(always)]
fn is_band(prio: u32) -> bool {
    azos_limits::SCHED_CLASS_RT && prio < RT_PRIORITY_THRESHOLD
}

#[inline(always)]
fn now() -> u64 {
    azos_drv_sys::timebase::now()
}

/// Whether `cpu` needs the RT paths at all.
#[inline(always)]
pub(super) fn active(cpu: usize) -> bool {
    FLAGS[cpu].load(Ordering::Relaxed) != 0
}

/// Must the direct IPC switch on `cpu` be refused? It bypasses the pick and
/// the dispatch tail, so it must not run while the hart has RT state, nor
/// switch from or to a band task (whose run time the tail charges).
#[inline(always)]
pub(super) fn holds_direct_switch(cpu: usize, target_prio: u32, cur_prio: u32) -> bool {
    active(cpu) || is_band(target_prio) || is_band(cur_prio)
}

/// Bring the owner bits of `FLAGS[cpu]` in line with `o`.
#[inline]
fn sync_flags(cpu: usize, o: &Owner) {
    let want = if o.band.since != 0 { F_BAND_RUN } else { 0 }
        | if o.band.exhausted { F_EXHAUSTED } else { 0 };
    let have = FLAGS[cpu].load(Ordering::Relaxed) & (F_BAND_RUN | F_EXHAUSTED);
    if have != want {
        FLAGS[cpu].fetch_and(!(have & !want), Ordering::Relaxed);
        FLAGS[cpu].fetch_or(want & !have, Ordering::Relaxed);
    }
}

/// The reservation tasks of `cpu` as `(slot, task index)`, in slot order.
///
/// Empty without looking at a slot when `F_RESV` is clear (w14 RTMAX):
/// [`reserve`] fills the slot before it sets the flag, and [`release`] clears
/// the flag only once every slot of the hart is empty, so a clear flag means
/// an empty set (a reservation admitted from another hart is seen from the
/// next pass, as with any reader that loads its slot just before the store).
/// The tick, the pick and the dispatch tail each walked the 16 empty slots
/// while only the band was in use (about 130 instructions per walk in
/// `arm`, measured on riscv64), on the interrupt-to-switch path.
#[inline]
fn set_iter(cpu: usize) -> impl Iterator<Item = (usize, usize)> {
    let n = if FLAGS[cpu].load(Ordering::Acquire) & F_RESV != 0 { SET_CAP } else { 0 };
    set_of(cpu)[..n].iter().enumerate()
        .map(|(k, s)| (k, s.load(Ordering::Acquire)))
        .filter(|&(_, i)| i < MAX_TASKS)
}

/// The slot of `idx` in `cpu`'s set.
#[inline]
fn slot_of(cpu: usize, idx: usize) -> Option<usize> {
    set_of(cpu).iter().position(|s| s.load(Ordering::Acquire) == idx)
}

/// The longest chain of calls [`proxy_of`] follows (the wait graph's own
/// bound, Kconfig `PI_MAX_DEPTH`).
const PROXY_DEPTH: usize = azos_sync::waitgraph::PI_MAX_DEPTH;

azos_common::ro_hook! {
    /// The server a task is blocked calling: `fn(slot) -> Option<server
    /// slot>`, `azos_ipc::fastcall::call_server_of` (the task's wait-graph
    /// edge is an IPC call node). Unset: no proxy execution (host suites, a
    /// build without `WAIT_GRAPH`). A function address because `azos_ipc` is
    /// above this crate.
    static CALL_SERVER_HOOK: fn(usize) -> Option<usize>;
}

/// Install [`CALL_SERVER_HOOK`]. Once, at boot.
pub fn set_call_server_hook(hook: fn(usize) -> Option<usize>) {
    CALL_SERVER_HOOK.set(hook);
}

/// The proxy of reservation holder `holder` (see the module doc): the task
/// at the end of its chain of calls ([`rt_core::proxy_chain`], at most
/// [`PROXY_DEPTH`] hops), if it holds no reservation of its own. `None`
/// otherwise: the holder runs itself, or nothing runs on the reservation.
#[inline]
fn proxy_of(holder: usize) -> Option<usize> {
    let hook = CALL_SERVER_HOOK.get()?;
    if holder >= MAX_TASKS {
        return None;
    }
    rt_core::proxy_chain(
        holder,
        PROXY_DEPTH,
        |t| unsafe { task_ref(t) }.state() == TaskState::Blocked,
        |t| hook(t).filter(|&s| s < MAX_TASKS),
        |t| super::classes::class_of(t) == Some(crate::sc::Class::Dl),
    )
}

/// The task that runs reservation `k` of `cpu` (holder `holder`) when one of
/// the two is queued and ready here: the holder itself, else its proxy.
#[inline]
unsafe fn runner(cpu: usize, holder: usize) -> Option<usize> {
    let ready_here = |i: usize| {
        let t = unsafe { task_ref(i) };
        t.queued.load(Ordering::Relaxed) && t.state() == TaskState::Ready
    };
    if ready_here(holder) {
        return Some(holder);
    }
    proxy_of(holder).filter(|&s| ready_here(s) && unsafe { task_ref(s) }.context.tp as usize == cpu)
}

/// The slot of `cpu` whose reservation `idx` runs on: its own, else the one
/// it is the proxy of.
#[inline]
fn charged_slot(cpu: usize, idx: usize) -> Option<usize> {
    slot_of(cpu, idx).or_else(|| set_iter(cpu).find(|&(_, h)| proxy_of(h) == Some(idx)).map(|(k, _)| k))
}

azos_common::ro_hook! {
    /// A reservation ran out while a proxy served its holder's call: `fn(holder
    /// slot)`, `azos_ipc::fastcall::proxy_timed_out` (the server gets a timeout
    /// notice on its endpoint). Unset: nobody is told.
    static PROXY_TIMEOUT_HOOK: fn(usize);
}

/// Install [`PROXY_TIMEOUT_HOOK`]. Once, at boot.
pub fn set_proxy_timeout_hook(hook: fn(usize)) {
    PROXY_TIMEOUT_HOOK.set(hook);
}

/// Tell the server of a reservation that ran out under it ([`Owner::timeout_due`]).
/// Called by the pick and the tick of `cpu` once its owner state is written
/// and before a run-queue lock is taken; the hook wakes a port's waiters, as
/// an interrupt's delivery does.
#[inline]
fn flush_timeout(o: &mut Owner) {
    if o.timeout_due == usize::MAX {
        return;
    }
    let holder = core::mem::replace(&mut o.timeout_due, usize::MAX);
    if let Some(hook) = PROXY_TIMEOUT_HOOK.get() {
        hook(holder);
    }
}

/// Must a server `idx` woken on `cpu` by `waker` stay there, whatever
/// outranks its own priority (`wake::ipc_wake_target_cpu`)? Yes when the
/// waker holds a reservation on `cpu` and the server none: the server runs
/// on the waker's reservation there ([`proxy_of`]).
#[inline]
pub(super) fn proxy_target(cpu: usize, waker: usize, idx: usize) -> bool {
    waker < MAX_TASKS
        && reserved_here(cpu, waker)
        && super::classes::class_of(idx) != Some(crate::sc::Class::Dl)
}

/// Does `cpu` hold a reservation for `idx`? A reservation is the DL class's,
/// whatever level it queues at: the fair pick (`fairq.rs`) leaves it out.
#[inline]
pub(super) fn reserved_here(cpu: usize, idx: usize) -> bool {
    FLAGS[cpu].load(Ordering::Relaxed) & F_RESV != 0 && slot_of(cpu, idx).is_some()
}

/// The reservation in slot `k` of `cpu`. Owner hart, or admission under
/// [`ADMIT`] before the slot is published.
#[inline(always)]
unsafe fn res(cpu: usize, k: usize) -> &'static mut Cbs {
    unsafe { &mut (*(*RT_CPU.ptr(cpu)).res.get())[k] }
}

/// The CBS release rule at a wake (`Cbs::release`). `rt-wake-rate-canary`
/// tests the budget against the bandwidth `q / t` instead of the density
/// `q / d`: a self-suspending server with `d < t` then runs above its density.
#[inline(always)]
fn wake(r: &mut Cbs, now: u64) {
    if cfg!(feature = "rt-wake-rate-canary") {
        r.release_at_rate(now, r.t);
    } else {
        r.release(now);
    }
}

/// Apply the clock to the hart's reservations at `now`: replenish the
/// throttled ones whose deadline has come, release the ones that woke.
#[inline]
unsafe fn refresh_set(cpu: usize, now: u64) {
    for (k, idx) in set_iter(cpu) {
        let r = unsafe { res(cpu, k) };
        if r.throttled && r.replenish_if_due(now) {
            irq_sc_changed(idx, false);
        }
        if r.release_due && unsafe { task_ref(idx) }.state() == TaskState::Ready {
            wake(r, now);
        }
    }
}

/// Arm the earliest enforcement instant of `cpu` (see the module doc).
unsafe fn arm(cpu: usize, now: u64) {
    let o = unsafe { &*owner_of(cpu) };
    let mut at = u64::MAX;
    if o.band.since != 0 && !o.band.exhausted && CAP != u64::MAX {
        let bm = unsafe { PER_CPU[cpu].ready_bitmap.load(Ordering::Relaxed) };
        if bm & NONBAND_LEVELS != 0 {
            at = at.min(o.band.exhaust_at(now, CAP));
        }
    }
    if o.band.exhausted {
        at = at.min(o.band.window_end(WINDOW));
    }
    if CBS_ON && o.cur < MAX_TASKS {
        let r = unsafe { res(cpu, o.cur_slot) };
        if !r.throttled {
            at = at.min(o.cur_since.saturating_add(r.budget).max(now.saturating_add(1)));
        }
    }
    for (k, _) in set_iter(cpu) {
        let r = unsafe { res(cpu, k) };
        if r.throttled {
            at = at.min(r.deadline.max(now.saturating_add(1)));
        }
    }
    if at != u64::MAX {
        ARM_CALLS.fetch_add(1, Ordering::Relaxed);
        if azos_drv_sys::timebase::arm_if_earlier(at) {
            ARM_WRITES.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Re-arm after something reprogrammed this hart's comparator (the idle
/// boundary's `set_next_tick_tickless`): a throttled reservation or an
/// exhausted window must not be slept past.
#[inline(always)]
pub(super) unsafe fn rearm(cpu: usize) {
    if active(cpu) {
        unsafe { arm(cpu, now()) };
    }
}

/// Charge the running reservation of `cpu` up to `now`. With `running`, a
/// budget that ran out is an overrun (exhaust: throttle or postpone).
/// Returns whether it ran out.
#[inline]
unsafe fn charge_cur(cpu: usize, o: &mut Owner, now: u64, running: bool) -> bool {
    let r = unsafe { res(cpu, o.cur_slot) };
    let out = CBS_ON && r.charge(now.saturating_sub(o.cur_since));
    o.cur_since = now;
    if out && running {
        r.exhaust(now);
        CBS_EXHAUSTED.fetch_add(1, Ordering::Relaxed);
        if r.throttled {
            irq_sc_changed(o.cur, true);
        }
        // A proxy ran it out: the holder's call has used the budget it lent.
        let holder = set_of(cpu)[o.cur_slot].load(Ordering::Relaxed);
        if holder != o.cur && holder < MAX_TASKS {
            o.timeout_due = holder;
        }
    }
    out
}

/// The dispatch tail: `cpu` switches from `old_idx` (`usize::MAX` for none)
/// to `next_idx`. Called right before `context_switch`, after every other
/// comparator write of the switch.
#[inline(always)]
pub(super) unsafe fn on_switch(cpu: usize, next_idx: usize) {
    let next_prio = unsafe { task_ref(next_idx).priority.load(Ordering::Relaxed) };
    unsafe { on_switch_prio(cpu, next_idx, next_prio) };
}

/// [`on_switch`] for a caller that already loaded `next`'s priority.
#[inline(always)]
pub(super) unsafe fn on_switch_prio(cpu: usize, next_idx: usize, next_prio: u32) {
    if FLAGS[cpu].load(Ordering::Relaxed) == 0 && !is_band(next_prio) {
        return;
    }
    unsafe { on_switch_slow(cpu, next_idx, next_prio) };
}

#[inline(never)]
unsafe fn on_switch_slow(cpu: usize, next_idx: usize, next_prio: u32) {
    let now = now();
    let o = unsafe { &mut *owner_of(cpu) };
    if o.band.since != 0 {
        o.band.stop(now, WINDOW, CAP);
    }
    if o.cur < MAX_TASKS {
        let st = unsafe { task_ref(o.cur) }.state();
        // Blocked: the CBS release rule runs when it is picked again.
        // Preempted (Ready) with nothing left: the overrun the tick or the
        // one-shot caught a little late.
        let running = st != TaskState::Blocked && st != TaskState::Zombie;
        unsafe { charge_cur(cpu, o, now, running) };
        if st == TaskState::Blocked {
            unsafe { res(cpu, o.cur_slot) }.release_due = true;
        }
        o.cur = usize::MAX;
    }
    if rt_core::band_charged(next_prio, RT_PRIORITY_THRESHOLD, exempt(next_idx)) {
        o.band.start(now);
    }
    if FLAGS[cpu].load(Ordering::Relaxed) & F_RESV != 0 {
        if let Some(k) = charged_slot(cpu, next_idx) {
            let r = unsafe { res(cpu, k) };
            if r.release_due {
                wake(r, now);
            }
            o.cur = next_idx;
            o.cur_slot = k;
            o.cur_since = now;
        }
    }
    sync_flags(cpu, o);
    unsafe { arm(cpu, now) };
}

/// Is `idx` a throttled reservation of `cpu`?
#[inline]
unsafe fn throttled(cpu: usize, idx: usize) -> bool {
    match slot_of(cpu, idx) {
        Some(k) => unsafe { res(cpu, k) }.throttled,
        None => false,
    }
}

/// Ready queue `level` of `cpu`: the first entry that is not a throttled
/// reservation. Caller holds `CPU_LOCKS[cpu]`.
unsafe fn ring_first_eligible(cpu: usize, level: usize, resv: bool) -> Option<usize> {
    let q = &super::cpu_queues(cpu)[level];
    q.iter(&super::RQ_NEXT).find(|&idx| idx < MAX_TASKS && !(resv && unsafe { throttled(cpu, idx) }))
}

/// Ring `level` of `cpu`: the first exempt entry that is not a throttled
/// reservation. Caller holds `CPU_LOCKS[cpu]`.
unsafe fn ring_first_exempt(cpu: usize, level: usize, resv: bool) -> Option<usize> {
    let q = &super::cpu_queues(cpu)[level];
    q.iter(&super::RQ_NEXT).find(|&idx| exempt(idx) && !(resv && unsafe { throttled(cpu, idx) }))
}

// ───────────────────── N6 class peeks (`classes.rs`) ──────────────────────

/// Ready-bitmap levels of the band, outside it (idle excluded), and idle.
pub(super) const LEVELS_BAND: u32 = BAND_LEVELS;
pub(super) const LEVELS_NONBAND: u32 = NONBAND_LEVELS;
pub(super) const LEVELS_IDLE: u32 = 1u32 << IDLE_PRIORITY;

/// The absolute deadline of `idx`'s reservation on `cpu`. Owner state.
pub(super) unsafe fn dl_deadline(cpu: usize, idx: usize) -> Option<u64> {
    slot_of(cpu, idx).map(|k| unsafe { res(cpu, k) }.deadline)
}

/// Is `cpu`'s band skipped by the pick (exhausted, a non-band task ready)?
/// Owner state: call on `cpu` itself.
pub(super) unsafe fn band_skipped(cpu: usize) -> bool {
    if !active(cpu) {
        return false;
    }
    let o = unsafe { &*owner_of(cpu) };
    let bm = PER_CPU[cpu].ready_bitmap.load(Ordering::Relaxed);
    o.band.exhausted && bm & NONBAND_LEVELS != 0
}

/// The DL class's peek: the queued, eligible reservation on `cpu` that EDF
/// runs first (level, then absolute deadline), throttled ones skipped. Not
/// removed from its queue. Owner state: call on `cpu` itself.
pub(super) unsafe fn peek_dl(cpu: usize) -> Option<usize> {
    let skip_band = unsafe { band_skipped(cpu) };
    let classes = super::classes::dl_above_band();
    let mut best = None;
    let (mut bp, mut bd) = (u32::MAX, u64::MAX);
    for (k, holder) in set_iter(cpu) {
        let r = unsafe { res(cpu, k) };
        if r.throttled {
            continue;
        }
        let Some(idx) = (unsafe { runner(cpu, holder) }) else { continue };
        let t = unsafe { task_ref(idx) };
        let p = prio_bucket(t.priority.load(Ordering::Relaxed)) as u32;
        if rt_core::band_throttled(p, RT_PRIORITY_THRESHOLD, exempt(idx), skip_band) {
            continue;
        }
        let p = rt_core::dl_rank(classes, p);
        if best.is_none() || rt_core::edf_before(p, r.deadline, bp, bd) {
            best = Some(idx);
            bp = p;
            bd = r.deadline;
        }
    }
    best
}

/// The first eligible queued task in the most urgent of `cpu`'s ready levels
/// inside `mask` (reservations skipped: they are the DL class's). Not
/// removed from its queue.
pub(super) unsafe fn peek_levels(cpu: usize, mask: u32) -> Option<usize> {
    let resv = FLAGS[cpu].load(Ordering::Relaxed) & F_RESV != 0;
    let _g = CpuLockGuard::acquire(cpu);
    let mut levels = PER_CPU[cpu].ready_bitmap.load(Ordering::Relaxed) & mask;
    while levels != 0 {
        let l = levels.trailing_zeros() as usize;
        let q = &super::cpu_queues(cpu)[l];
        let first = q.iter(&super::RQ_NEXT)
            .find(|&idx| idx < MAX_TASKS && !(resv && slot_of(cpu, idx).is_some()));
        if first.is_some() {
            return first;
        }
        levels &= levels - 1;
    }
    None
}

/// The most urgent queued exempt band loop of `cpu` (its level, its task),
/// throttled reservations skipped. Caller holds `CPU_LOCKS[cpu]`; `bm` is
/// the ready bitmap read under it.
unsafe fn first_exempt(cpu: usize, bm: u32, resv: bool) -> Option<(u32, usize)> {
    let mut bl = bm & BAND_LEVELS;
    while bl != 0 {
        let l = bl.trailing_zeros() as usize;
        if let Some(idx) = unsafe { ring_first_exempt(cpu, l, resv) } {
            return Some((l as u32, idx));
        }
        bl &= bl - 1;
    }
    None
}

/// The stop class's peek (`classes::StopClass`): the
/// most urgent queued exempt band loop. Not removed from its queue.
pub(super) unsafe fn peek_exempt(cpu: usize) -> Option<usize> {
    let resv = FLAGS[cpu].load(Ordering::Relaxed) & F_RESV != 0;
    let _g = CpuLockGuard::acquire(cpu);
    let bm = PER_CPU[cpu].ready_bitmap.load(Ordering::Relaxed);
    unsafe { first_exempt(cpu, bm, resv) }.map(|(_, idx)| idx)
}

/// What the RT pick decided.
pub(super) enum Pick {
    /// Dispatch this task (already removed from its ready queue). `force`:
    /// the running task must give up the hart even to a lower priority (its
    /// band is exhausted, or its reservation is throttled).
    Task { idx: usize, force: bool },
    /// Nothing better than the running task: keep it.
    Keep,
}

/// The pick for a hart with RT state ([`active`]). `old_idx` is the task
/// current on `cpu`, still `Running` if it was preempted.
pub(super) unsafe fn pick(cpu: usize, old_idx: usize) -> Pick {
    let now = now();
    let o = unsafe { &mut *owner_of(cpu) };
    if o.band.since != 0 {
        o.band.charge(now, WINDOW, CAP);
    } else if o.band.exhausted {
        o.band.roll(now, WINDOW);
    }
    if o.cur < MAX_TASKS && o.cur == old_idx
        && unsafe { task_ref(old_idx) }.state() == TaskState::Running
    {
        unsafe { charge_cur(cpu, o, now, true) };
    }
    unsafe { refresh_set(cpu, now) };
    sync_flags(cpu, o);
    flush_timeout(o);
    let resv = FLAGS[cpu].load(Ordering::Relaxed) & F_RESV != 0;
    // Every reservation ranks above the band (`rt_core::dl_rank`).
    let classes = super::classes::dl_above_band();

    let _g = CpuLockGuard::acquire(cpu);
    let bm = unsafe { PER_CPU[cpu].ready_bitmap.load(Ordering::Relaxed) };
    let skip_band = o.band.exhausted && bm & NONBAND_LEVELS != 0;

    // The running task as a candidate: a Running reservation task that still
    // comes first keeps the hart rather than being switched for a worse pick.
    let mut force = false;
    let mut keep: Option<(u32, u64)> = None;
    if old_idx < MAX_TASKS {
        let t = unsafe { task_ref(old_idx) };
        if t.state() == TaskState::Running {
            let p = prio_bucket(t.priority.load(Ordering::Relaxed)) as u32;
            let r = if o.cur == old_idx { Some(unsafe { res(cpu, o.cur_slot) }) } else { None };
            if rt_core::band_throttled(p, RT_PRIORITY_THRESHOLD, exempt(old_idx), skip_band) {
                force = true;
                BAND_THROTTLES.fetch_add(1, Ordering::Relaxed);
            } else if let Some(r) = r {
                if r.throttled {
                    force = true;
                } else {
                    keep = Some((rt_core::dl_rank(classes, p), r.deadline));
                }
            }
        }
    }

    // The exempt band loops are the stop class, above DL and the rest of the
    // band (owner decision 10-10).
    let running = if old_idx < MAX_TASKS && !force && exempt(old_idx)
        && unsafe { task_ref(old_idx) }.state() == TaskState::Running
    {
        Some(prio_bucket(unsafe { task_ref(old_idx) }.priority.load(Ordering::Relaxed)) as u32)
    } else {
        None
    };
    let queued = unsafe { first_exempt(cpu, bm, resv) };
    match rt_core::stop_pick(running, queued.map(|(l, _)| l)) {
        rt_core::StopPick::Keep => return Pick::Keep,
        rt_core::StopPick::Take => {
            if let Some((_, idx)) = queued {
                if unsafe { cpu_remove(cpu, idx) } {
                    return Pick::Task { idx, force: true };
                }
            }
        }
        rt_core::StopPick::Pass => {}
    }

    // The best eligible queued reservation (its holder, or its proxy).
    let mut best = usize::MAX;
    let (mut bp, mut bd) = (u32::MAX, u64::MAX);
    for (k, holder) in set_iter(cpu) {
        let r = unsafe { res(cpu, k) };
        if r.throttled {
            continue;
        }
        let Some(idx) = (unsafe { runner(cpu, holder) }) else { continue };
        let t = unsafe { task_ref(idx) };
        let p = prio_bucket(t.priority.load(Ordering::Relaxed)) as u32;
        if rt_core::band_throttled(p, RT_PRIORITY_THRESHOLD, exempt(idx), skip_band) {
            continue;
        }
        let p = rt_core::dl_rank(classes, p);
        if best == usize::MAX || rt_core::edf_before(p, r.deadline, bp, bd) {
            best = idx;
            bp = p;
            bd = r.deadline;
        }
    }

    // While the band is skipped, the exempt safety loops in it are not: the
    // first one queued, most urgent level first.
    if skip_band {
        let mut bl = bm & BAND_LEVELS;
        while bl != 0 {
            let l = bl.trailing_zeros() as usize;
            if let Some(idx) = unsafe { ring_first_exempt(cpu, l, resv) } {
                let best_rank = if best == usize::MAX { None } else { Some(bp) };
                if rt_core::exempt_first(classes, l as u32, best_rank) {
                    if unsafe { cpu_remove(cpu, idx) } {
                        return Pick::Task { idx, force };
                    }
                }
            }
            bl &= bl - 1;
        }
    }

    let mut levels = if skip_band { bm & !BAND_LEVELS } else { bm };
    loop {
        let l = if levels != 0 { levels.trailing_zeros() } else { u32::MAX };
        if let Some((kp, kd)) = keep {
            let wins = best == usize::MAX || !rt_core::edf_before(bp, bd, kp, kd);
            if wins && kp <= l {
                return Pick::Keep;
            }
        }
        if best != usize::MAX && bp <= l {
            let idx = if EDF_ON || bp < l {
                best
            } else {
                // Canary: FIFO among the level's eligible entries.
                unsafe { ring_first_eligible(cpu, l as usize, resv) }.unwrap_or(best)
            };
            if unsafe { cpu_remove(cpu, idx) } {
                // The reservation may sit at a worse level
                // than the running band task it displaces; `do_schedule`'s
                // worse-priority guard must not put it back.
                return Pick::Task { idx, force: force || classes };
            }
            return Pick::Keep;
        }
        if l == u32::MAX {
            return Pick::Keep;
        }
        // The fair levels are one EEVDF queue (`fairq.rs`), not one list per
        // level: the running fair task is a candidate, and when it is still
        // the best nothing is dispatched.
        if super::fairq::is_fair(l) {
            match unsafe { super::fairq::pick(cpu) } {
                super::fairq::Fair::Task(idx) => {
                    if unsafe { cpu_remove(cpu, idx) } {
                        return Pick::Task { idx, force };
                    }
                    return Pick::Keep;
                }
                super::fairq::Fair::Keep => return Pick::Keep,
                // Only reservations queued at these levels: past them.
                super::fairq::Fair::Empty => {
                    levels &= !NONBAND_LEVELS;
                    continue;
                }
            }
        }
        if let Some(idx) = unsafe { ring_first_eligible(cpu, l as usize, resv) } {
            if unsafe { cpu_remove(cpu, idx) } {
                return Pick::Task { idx, force };
            }
        }
        levels &= levels - 1;
    }
}

/// The timer tick (and reschedule IPI) on `cpu` with `cur_idx` running
/// (`usize::MAX` when nothing real runs). Charges, rolls, replenishes and
/// arms; returns whether the current task must be preempted.
pub(super) unsafe fn tick(cpu: usize, cur_idx: usize) -> bool {
    let now = now();
    let o = unsafe { &mut *owner_of(cpu) };
    let bm = unsafe { PER_CPU[cpu].ready_bitmap.load(Ordering::Relaxed) };
    let mut preempt = false;
    if o.band.since != 0 {
        o.band.charge(now, WINDOW, CAP);
        if o.band.exhausted && bm & NONBAND_LEVELS != 0 {
            preempt = true;
        }
    } else if o.band.exhausted && o.band.roll(now, WINDOW) && bm & BAND_LEVELS != 0 {
        preempt = true;
    }
    let mut cur_res: Option<(u32, u64)> = None;
    if o.cur < MAX_TASKS && o.cur == cur_idx {
        if unsafe { charge_cur(cpu, o, now, true) } {
            preempt = true;
        }
        let r = unsafe { res(cpu, o.cur_slot) };
        let p = prio_bucket(unsafe { task_ref(cur_idx) }.priority.load(Ordering::Relaxed)) as u32;
        cur_res = Some((p, r.deadline));
    }
    unsafe { refresh_set(cpu, now) };
    if !preempt {
        // A ready reservation that must run before the current task. Every
        // reservation ranks above the band.
        let classes = super::classes::dl_above_band();
        if let Some((cp, cd)) = cur_res {
            cur_res = Some((rt_core::dl_rank(classes, cp), cd));
        }
        // A queued exempt loop (the stop class) preempts any other task, and
        // no reservation preempts a running one.
        let cur_exempt = cur_idx < MAX_TASKS && exempt(cur_idx);
        {
            let resv = FLAGS[cpu].load(Ordering::Relaxed) & F_RESV != 0;
            let queued = {
                let _g = CpuLockGuard::acquire(cpu);
                let bm = PER_CPU[cpu].ready_bitmap.load(Ordering::Relaxed);
                unsafe { first_exempt(cpu, bm, resv) }.is_some()
            };
            if rt_core::stop_preempts(cur_exempt, queued) {
                preempt = true;
            }
        }
        let cp = if cur_idx < MAX_TASKS {
            prio_bucket(unsafe { task_ref(cur_idx) }.priority.load(Ordering::Relaxed)) as u32
        } else {
            u32::MAX
        };
        let skip_band = o.band.exhausted && bm & NONBAND_LEVELS != 0;
        for (k, holder) in set_iter(cpu) {
            let r = unsafe { res(cpu, k) };
            if preempt || cur_exempt || r.throttled {
                continue;
            }
            let Some(idx) = (unsafe { runner(cpu, holder) }) else { continue };
            if idx == cur_idx {
                continue;
            }
            let t = unsafe { task_ref(idx) };
            let p = prio_bucket(t.priority.load(Ordering::Relaxed)) as u32;
            if rt_core::band_throttled(p, RT_PRIORITY_THRESHOLD, exempt(idx), skip_band) {
                continue;
            }
            let p = rt_core::dl_rank(classes, p);
            let before = match cur_res {
                Some((cp, cd)) => p < cp || (EDF_ON && rt_core::edf_before(p, r.deadline, cp, cd)),
                // Reservation tasks run before the FIFO tasks of their level.
                None => p <= cp,
            };
            if before {
                preempt = true;
                break;
            }
        }
    }
    sync_flags(cpu, o);
    unsafe { arm(cpu, now) };
    flush_timeout(o);
    preempt
}

// ───────────────────────────── admission ───────────────────────────────────

/// A reservation request, in microseconds (the units of a topology row).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation {
    /// Runtime per period.
    pub runtime_us: u64,
    /// Period.
    pub period_us: u64,
    /// Relative deadline; 0 = the period.
    pub deadline_us: u64,
    /// Hard CBS (throttle on overrun) rather than soft (postpone).
    pub hard: bool,
    /// Harts it may be placed on; 0 = any online hart. Narrowed to the
    /// task's pin if it has one.
    pub cpu_mask: u32,
    /// The task runs in the band (its priority is, or will be once admitted,
    /// below `RT_PRIORITY_THRESHOLD`): the hart's band cap applies.
    pub band: bool,
    /// The priority the task runs at once admitted (set after `reserve` on
    /// the spawn and autorun paths, so it is declared here): the
    /// cross-level check ([`rt_core::levels_check`]) books it.
    pub level: u32,
}

/// The cross-level check for `cpu` with `cand` added (`rt_core::levels_check`),
/// in the order the dispatch runs reservations in (`classes::level_order`):
/// it binds only under fixed priority between levels. Under `ADMIT`; reads
/// only what admission wrote before publishing a slot (`q`, `d`,
/// `density_ppm`, `level`), never the owner's budget/deadline.
fn levels_ok(cpu: usize, cand: rt_core::Booked) -> bool {
    if !ADMIT_ON {
        return true;
    }
    let mut b = [cand; SET_CAP + 1];
    let mut n = 1;
    for k in 0..SET_CAP {
        if set_of(cpu)[k].load(Ordering::Acquire) == usize::MAX {
            continue;
        }
        // SAFETY: a published slot; its admission fields never change while
        // it is published (the owner hart writes budget and deadline only).
        let r = unsafe { &*(res(cpu, k) as *const Cbs) };
        b[n] = rt_core::Booked { level: r.level, q: r.q, d: r.d, density_ppm: r.density_ppm };
        n += 1;
    }
    rt_core::levels_check(super::classes::level_order(), &b[..n]).is_ok()
}

/// `r` as the cross-level check books it.
fn booked(r: &Reservation, density: u32) -> rt_core::Booked {
    let freq = azos_drv_sys::timebase::TIMER_FREQ;
    let d_us = if r.deadline_us == 0 { r.period_us } else { r.deadline_us };
    rt_core::Booked {
        level: prio_bucket(r.level) as u32,
        q: rt_core::us_to_ticks(r.runtime_us, freq),
        d: rt_core::us_to_ticks(d_us, freq),
        density_ppm: density,
    }
}

/// Run-time admission: give task `idx` the reservation `r`, on the first hart
/// of its mask with room, and pin it there. Refusals are loud: a
/// `[SCHED-RT] admission REFUSED` line names the task, the reason and the
/// load, and the caller gets the reason (`Refusal::errno` for a syscall).
///
/// The task must not be running on another hart than the one it is placed
/// on: a pinned task is only placed on its pin; an unpinned task that is the
/// caller is only placed on the calling hart.
pub fn reserve(idx: usize, r: Reservation) -> Result<usize, Refusal> {
    // The Domain's `rt_time` envelope row (Documentation/effects.md), asked
    // once, before admission takes a lock or masks anything (`held_by_row`).
    // A caller that names no task is not asked: admission refuses it below.
    let tid = if idx < MAX_TASKS { unsafe { task_ref(idx).tid } } else { 0 };
    let held = idx < MAX_TASKS
        && crate::rt_receipt::held_by_row(tid, r.runtime_us, r.period_us, r.deadline_us);
    // Admission (the hart read, the mask, the pin) runs with preemption off:
    // the caller is the task that may be admitted, and a tick between
    // reading the hart it runs on and pinning it there would move it, so it
    // would be pinned to a hart it has already left (and `PER_CPU[me]`
    // would name another hart's task). A `PreemptGuard` holds the task on its
    // hart without masking the interrupts the admission lock masks anyway.
    let admission = azos_sync::preempt::critical_section();
    let me = crate::smp::current_cpu_id();
    let online = crate::smp::NUM_ONLINE_CPUS.load(Ordering::Acquire).clamp(1, MAX_CPUS);
    // The harts the request could have gone to, for the refusal's record;
    // 0 until the mask is known.
    let mut asked_mask = 0u32;
    let res_ = (|| {
        if held {
            return Err(Refusal::Envelope);
        }
        // `SCHED_CLASS_DL=n`: nothing is admitted, so no hart ever sets
        // `F_RESV` and the reservation paths are never entered.
        if !azos_limits::SCHED_CLASS_DL {
            return Err(Refusal::ClassOff);
        }
        if idx >= MAX_TASKS {
            return Err(Refusal::Malformed);
        }
        let density = rt_core::density_ppm(r.runtime_us, r.period_us, r.deadline_us)?;
        let t = unsafe { task_mut(idx) };
        let online_mask = if online >= 32 { u32::MAX } else { (1u32 << online) - 1 };
        let mut mask = if r.cpu_mask == 0 { online_mask } else { r.cpu_mask & online_mask };
        if t.cpu_affinity >= 0 {
            // A reservation mask is a u32 (the syscall ABI's): a pin past
            // CPU 31 cannot be named in it and leaves nothing to fit.
            mask &= 1u32.checked_shl(t.cpu_affinity as u32).unwrap_or(0);
        } else if unsafe { PER_CPU[me].current_idx.load(Ordering::Relaxed) } == idx {
            mask &= 1u32.checked_shl(me as u32).unwrap_or(0);
        }
        asked_mask = mask;
        let mut load = ADMIT.lock_irqsave();
        if (0..ncpu()).any(|c| slot_of(c, idx).is_some()) {
            return Err(Refusal::Busy);
        }
        let cand = booked(&r, density);
        let cpu = if ADMIT_ON {
            rt_core::first_fit_by(&load[..online], mask, density, r.band, BAND_LIMIT_PPM,
                |h| levels_ok(h, cand))?
        } else if mask != 0 {
            mask.trailing_zeros() as usize
        } else {
            return Err(Refusal::NoRoom);
        };
        let k = set_of(cpu).iter().position(|s| s.load(Ordering::Relaxed) == usize::MAX)
            .ok_or(Refusal::Busy)?;
        let freq = azos_drv_sys::timebase::TIMER_FREQ;
        let d_us = if r.deadline_us == 0 { r.period_us } else { r.deadline_us };
        // The slot is unpublished: nothing else reads it until the store below.
        unsafe {
            *res(cpu, k) = Cbs::new(
                rt_core::us_to_ticks(r.runtime_us, freq),
                rt_core::us_to_ticks(r.period_us, freq),
                rt_core::us_to_ticks(d_us, freq),
                r.hard, cpu as u8, density,
            );
            res(cpu, k).band = r.band;
            res(cpu, k).level = cand.level;
        }
        t.cpu_affinity = cpu as i8;
        load[cpu].total_ppm = load[cpu].total_ppm.saturating_add(density);
        if r.band {
            load[cpu].band_ppm = load[cpu].band_ppm.saturating_add(density);
        }
        #[cfg(feature = "energy")]
        ADMITTED_PPM[cpu].store(load[cpu].total_ppm, Ordering::Relaxed);
        set_of(cpu)[k].store(idx, Ordering::Release);
        FLAGS[cpu].fetch_or(F_RESV, Ordering::Release);
        Ok((cpu, density, load[cpu]))
    })();
    // Pinned (or refused): the task may move again, to wherever its pin says.
    drop(admission);
    match res_ {
        Ok((cpu, density, load)) => {
            // Pinned now: a task already sitting in another hart's ready queue
            // (an unpinned child created before its reservation) moves to the
            // queue of the hart it was admitted on, after `ADMIT` is released
            // (a CPU lock is never taken under it).
            if unsafe { task_ref(idx) }.state() == TaskState::Ready {
                if let Some(from) = unsafe { super::cpu_remove_anywhere(idx) } {
                    let _ = from;
                    unsafe { super::cpu_enqueue_locked(cpu, idx) };
                }
            }
            ADMITTED.fetch_add(1, Ordering::Relaxed);
            super::classes::on_reserved(idx, &r);
            // N7: the task is DL now; where it waits, it re-sorts.
            super::classes::pi_attr_changed(idx);
            azos_drv_sys::kprintln!(
                "[SCHED-RT] admitted tid={} hart={} runtime_us={} period_us={} deadline_us={} \
                 {} band={} level={} density_ppm={} hart_load_ppm={} band_load_ppm={}",
                tid, cpu, r.runtime_us, r.period_us, r.deadline_us,
                if r.hard { "hard" } else { "soft" }, r.band, r.level, density, load.total_ppm, load.band_ppm,
            );
            Ok(cpu)
        }
        Err(why) => {
            REFUSALS.fetch_add(1, Ordering::Relaxed);
            let load = *ADMIT.lock_irqsave();
            azos_drv_sys::kwarn!(
                "[SCHED-RT] admission REFUSED tid={} reason={} errno=-{} runtime_us={} period_us={} \
                 deadline_us={} band={} mask={:#x} hart0_load_ppm={} hart0_band_ppm={} band_limit_ppm={}",
                tid, why.name(), why.errno(), r.runtime_us, r.period_us, r.deadline_us, r.band,
                r.cpu_mask, load[0].total_ppm, load[0].band_ppm, BAND_LIMIT_PPM,
            );
            // The receipt (Kconfig DECISION_REFUSALS_DURABLE / DECISION_RECORDS_DEV):
            // the budget and period asked and what the best hart could still
            // give. After the `ADMIT` guard above is gone: the sink may queue
            // a flight-recorder record, and an RT caller's is only queued.
            // (A refusal by the Domain's row leaves no record here: the effect
            // gate wrote it.)
            crate::rt_receipt::record_refusal(
                tid,
                why,
                rt_core::Ask { runtime_us: r.runtime_us, period_us: r.period_us, deadline_us: r.deadline_us, band: r.band },
                &load[..online],
                asked_mask,
                BAND_LIMIT_PPM,
            );
            Err(why)
        }
    }
}

/// Drop task `idx`'s reservation, if it has one: out of its hart's set and
/// ledger. Called when the slot is freed (exit) and when it is reused.
pub(super) fn release(idx: usize) {
    if idx < MAX_TASKS {
        EXEMPT[idx].store(false, Ordering::Relaxed);
    }
    // Only the CPUs this boot has: admission sets `F_RESV` below `ncpu()`
    // alone. Walking all `MAX_CPUS` (the Kconfig ceiling, 64 by default) on
    // every slot free and reuse cost thread create+join ~+700 instructions
    // at `-smp 1` when NR_CPUS replaced the fixed 8 (wave 15).
    if FLAGS[..ncpu().min(MAX_CPUS)].iter().all(|f| f.load(Ordering::Relaxed) & F_RESV == 0) {
        return;
    }
    let mut load = ADMIT.lock_irqsave();
    for cpu in 0..ncpu() {
        let Some(k) = slot_of(cpu, idx) else { continue };
        set_of(cpu)[k].store(usize::MAX, Ordering::Release);
        super::classes::on_released(idx);
        let r = unsafe { res(cpu, k) };
        load[cpu].total_ppm = load[cpu].total_ppm.saturating_sub(r.density_ppm);
        if r.band {
            load[cpu].band_ppm = load[cpu].band_ppm.saturating_sub(r.density_ppm);
        }
        #[cfg(feature = "energy")]
        ADMITTED_PPM[cpu].store(load[cpu].total_ppm, Ordering::Relaxed);
        if set_of(cpu).iter().all(|s| s.load(Ordering::Relaxed) == usize::MAX) {
            FLAGS[cpu].fetch_and(!F_RESV, Ordering::Release);
        }
        if cpu == crate::smp::current_cpu_id() {
            let o = unsafe { &mut *owner_of(cpu) };
            // Its own task or a proxy running on it.
            if o.cur == idx || (o.cur < MAX_TASKS && o.cur_slot == k) {
                o.cur = usize::MAX;
            }
        }
    }
}

// ── Interrupt lines served by a reservation (L5) ───────────────────────────
//
// An interrupt line's handler runs as a thread with a scheduling context: the
// thread of the task that bound the line, on its hard reservation (CBS). The
// reservation is admitted like any other, so the line's cost is inside the
// hart's booked load; what the line adds is that the reservation running out
// stops the line. `irq_bind` masks the lines of a throttled reservation and
// unmasks them when it is replenished; the two edges are told to it through
// the hook below, and only for an SC that serves a line (`sc.irq != 0`), so a
// reservation without lines pays one load at each edge.

azos_common::ro_hook! {
    /// What the overrun and replenishment edges tell `irq_bind` (`fn(tid,
    /// throttled)`); unset = nobody listens (host suites, a build without the hook
    /// installed). A function address rather than a call because `irq_bind` is
    /// above this crate.
    static IRQ_SC_HOOK: fn(u32, bool);
}

/// Install the hook ([`IRQ_SC_HOOK`]). Once, at boot.
pub fn set_irq_sc_hook(hook: fn(u32, bool)) {
    IRQ_SC_HOOK.set(hook);
}

/// Task `idx`'s reservation was throttled (`throttled`) or replenished: tell
/// `irq_bind` if its SC serves a line. Owner hart, interrupts off.
#[inline]
fn irq_sc_changed(idx: usize, throttled: bool) {
    if super::classes::sc_of(idx).is_none_or(|sc| sc.irq_lines() == 0) {
        return;
    }
    if let Some(hook) = IRQ_SC_HOOK.get() {
        hook(unsafe { task_ref(idx) }.tid, throttled);
    }
}

/// Why a task cannot serve an interrupt line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqScRefusal {
    /// The task holds no reservation (or no longer exists): its run time is
    /// not budgeted, so a storm on its line would be unbounded.
    NoReservation,
    /// The reservation is soft (postpones its deadline instead of
    /// throttling): it never stops the line.
    Soft,
}

/// Task `tid` will serve one more interrupt line on its reservation: its SC
/// counts it, and the hart the reservation was admitted on is returned (the
/// line is routed there, so the top half and the handler share a hart) with
/// whether the reservation is throttled at this instant (the binding starts
/// in that state).
pub fn irq_attach(tid: u32) -> Result<(usize, bool), IrqScRefusal> {
    let idx = super::idx_for_tid(tid).ok_or(IrqScRefusal::NoReservation)?;
    for cpu in 0..ncpu() {
        let Some(k) = slot_of(cpu, idx) else { continue };
        // SAFETY: a published slot; `hard` never changes while it is.
        let r = unsafe { &*(res(cpu, k) as *const Cbs) };
        if !r.hard {
            return Err(IrqScRefusal::Soft);
        }
        let sc = super::classes::sc_of(idx).ok_or(IrqScRefusal::NoReservation)?;
        if !sc.irq_attach() {
            return Err(IrqScRefusal::NoReservation);
        }
        return Ok((cpu, r.throttled));
    }
    Err(IrqScRefusal::NoReservation)
}

/// Task `tid` serves one line fewer ([`irq_attach`]'s undo). A task that no
/// longer exists serves none.
pub fn irq_detach(tid: u32) {
    if let Some(sc) = super::idx_for_tid(tid).and_then(super::classes::sc_of) {
        sc.irq_detach();
    }
}

/// Counters for the rows: `(band_throttles, cbs_exhausted, admitted,
/// refused, arm_calls, arm_writes)`.
pub fn stats() -> (u32, u32, u32, u32, u32, u32) {
    (
        BAND_THROTTLES.load(Ordering::Relaxed),
        CBS_EXHAUSTED.load(Ordering::Relaxed),
        ADMITTED.load(Ordering::Relaxed),
        REFUSALS.load(Ordering::Relaxed),
        ARM_CALLS.load(Ordering::Relaxed),
        ARM_WRITES.load(Ordering::Relaxed),
    )
}

/// `(overruns, throttled, absolute deadline)` of task `idx`'s reservation.
pub fn task_reservation(idx: usize) -> Option<(u32, bool, u64)> {
    for cpu in 0..ncpu() {
        if let Some(k) = slot_of(cpu, idx) {
            let r = unsafe { res(cpu, k) };
            return Some((r.overruns, r.throttled, r.deadline));
        }
    }
    None
}

/// The reservation the task in slot `idx` runs on, if it is the task running
/// on this hart and it runs on one: `(budget left, absolute deadline)` of its
/// current server period, counter ticks (a throttled reservation has none
/// left). What a call with a deadline lends its server
/// (`azos_syscall::ipc_deadline::Lent`). Owner state, read on this hart with
/// interrupts off.
pub fn running_reservation(idx: usize) -> Option<(u64, u64)> {
    use azos_arch::Interrupts as _;
    let s = azos_arch::ARCH.disable_all();
    let cpu = crate::smp::current_cpu_id();
    let mut out = None;
    if idx < MAX_TASKS && cpu < ncpu() && FLAGS[cpu].load(Ordering::Relaxed) & F_RESV != 0 {
        let o = unsafe { &*owner_of(cpu) };
        if o.cur == idx {
            let r = unsafe { res(cpu, o.cur_slot) };
            let left = if r.throttled { 0 } else { r.budget.saturating_sub(now().saturating_sub(o.cur_since)) };
            out = Some((left, r.deadline));
        }
    }
    azos_arch::ARCH.restore(s);
    out
}

/// Dry run of [`reserve`] for a task that does not exist yet (`SYS_SPAWN_EX`
/// decides before it creates the child): the hart `r` would be placed on, or
/// why it would be refused. Nothing is booked; the caller reserves for real
/// once the task exists, and that call can still refuse (another reservation
/// may land in between), loudly, as every refusal is.
pub fn check(r: &Reservation) -> Result<usize, Refusal> {
    let density = rt_core::density_ppm(r.runtime_us, r.period_us, r.deadline_us)?;
    let online = crate::smp::NUM_ONLINE_CPUS.load(Ordering::Acquire).clamp(1, MAX_CPUS);
    let online_mask = if online >= 32 { u32::MAX } else { (1u32 << online) - 1 };
    let mask = if r.cpu_mask == 0 { online_mask } else { r.cpu_mask & online_mask };
    let load = ADMIT.lock_irqsave();
    if !ADMIT_ON {
        return if mask != 0 { Ok(mask.trailing_zeros() as usize) } else { Err(Refusal::NoRoom) };
    }
    let cand = booked(r, density);
    rt_core::first_fit_by(&load[..online], mask, density, r.band, BAND_LIMIT_PPM, |h| levels_ok(h, cand))
}

/// Give task `idx` the base priority `prio`, re-bucketing it if it is queued,
/// under its donation lock (a donation in progress keeps its boost; the base
/// lands when the last one returns). For a task that is not running: a
/// spawned child that is still parked enters the band this way once its
/// reservation is admitted.
pub fn set_base_priority(idx: usize, prio: u32) {
    use crate::donation::DonationCell;
    if idx >= MAX_TASKS {
        return;
    }
    super::classes::on_base_priority(idx, prio);
    let c = super::TaskDonation::new(idx);
    c.lock();
    unsafe { task_ref(idx) }.base_priority.store(prio, Ordering::Relaxed);
    if c.count() == 0 && c.prio() != prio {
        c.apply_prio(prio);
    }
    c.unlock();
    // N7: a boost the wait graph holds comes back on top of the new base.
    super::classes::pi_attr_changed(idx);
}
