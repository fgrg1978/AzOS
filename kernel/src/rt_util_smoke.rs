// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Are admitted deadlines met near the admission bound? (`sched-rt-util`,
//! wave 15). The `sched-rt-smoke` checks prove EDF + CBS at a light load
//! (two or three reservations); this one loads each hart up to what
//! run-time admission accepts and counts every job that finishes late.
//! Booted under `-icount shift=0,sleep=off`, so every time here is an
//! instruction count, and the verdicts do not depend on host load.
//!
//! Each phase gives every hart it uses the same set of four periodic tasks,
//! all at priority level [`EDF_PRIO`] (the band) with a hard CBS reservation
//! taken through [`rt::reserve`] — the same call `SYS_SPAWN` and the autorun
//! loader make for a profiled topology row — pinned with `cpu_mask = 1 << h`.
//! A best-effort hog on each hart keeps a non-band task ready, so the band
//! cap is armed the whole time. Every job is released at its period from a
//! common critical instant, computes [`WORK_PCT`] % of its budget (the rest
//! pays for its own release and switch), and is late when it finishes after
//! release + deadline. On a single-hart boot:
//!
//! * `u70-h1` / `u93-h1` — 70 % and 93 % summed density on hart 0. 93 %, not
//!   95 %: the band cap (`RT_BAND_CAP_PCT`, 95 %) is also the band admission
//!   limit, and density is rounded up.
//! * `overrun` — the 70 % set on hart 0 plus a task that books 1 ms per
//!   10 ms and computes 6 ms per job. PASS needs zero misses among the
//!   others and the overrunner throttled. Canary `rt-util-cbs-canary` (no
//!   budget charging, `azos_sched/rt-cbs-canary`): the overrunner keeps the
//!   level and the others miss.
//! * `suspend` — A (4 ms per 10 ms) beside B, a server of 1 ms per 20 ms
//!   with a 2 ms deadline (density 50 %; 90 % in all) that never finishes:
//!   it computes [`SUSPEND_RUN_US`], sleeps [`SUSPEND_GAP_US`], and again. A
//!   CBS must hold B to its density whatever it does; PASS: A never misses.
//!   The wake rule decides it: a server that wakes with budget left keeps
//!   its deadline only while that budget fits the reserved rate up to it,
//!   and that rate must be the density `q / d` the admission booked, not the
//!   bandwidth `q / t` (with `q / t`, B took a fresh budget and a deadline
//!   2 ms away at every wake and A missed every job).
//! * `mixed` — two reservations on hart 0 at DIFFERENT levels (75 % in
//!   all): H at level [`EDF_PRIO`] (5 ms per 20 ms) and L at level
//!   [`EDF_PRIO`] + 2 (1 ms per 20 ms, deadline 2 ms), released together.
//!   EDF orders reservations inside one level only; across levels the fixed
//!   priority decides, so H's 5 ms runs first and L, when the density sum
//!   alone admitted it, missed every job. PASS: L is refused with `levels`
//!   (`rt_core::levels_fit`) and H keeps every deadline. Canary
//!   `rt-util-admit-canary` (no admission): L is admitted and misses.
//!
//! On a boot with a second hart, instead:
//!
//! * `u70-hart1` / `u93-hart1` — the same sets on hart 1, with hart 0 left to the kernel's own
//!   loops. Under `-icount` QEMU runs the harts in turn on ONE virtual
//!   clock, so the time a hart sees includes every instruction the other
//!   hart executes: with both harts busy each gets about half the clock and
//!   every reservation "misses" (measured: 750 of 750 jobs at 70 % on two
//!   loaded harts, each with CBS overruns although each job computed 95 %
//!   of its budget — the budget was charged for time the hart never ran).
//!   Two loaded harts can only be measured without `-icount`.
//!
//!
//! Lines: one `[RTUTIL] task ...` per task (jobs, misses, worst lateness,
//! worst response, CBS overruns), one `[RTUTIL] <phase> PASS|FAIL ...` per
//! phase, and `[RTUTIL] done` at the end.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};
use azos_sched::rt::{self, Reservation};
use azos_sched::rt_core::Refusal;
use azos_sched::{task_block_outcome, BlockOutcome, WaitReason};

const CTL_PRIO: u32 = 2;
const EDF_PRIO: u32 = 4;
const HOG_PRIO: u32 = 23;
const SETTLE_MS: u64 = 5_000;
/// With a second hart the boot's worker tasks run there for ~6 s.
const SETTLE_SMP_MS: u64 = 8_000;
/// Virtual time each phase's jobs are released for.
const PHASE_MS: u64 = 1_000;
/// A job computes this share of its reservation's budget.
const WORK_PCT: u64 = 95;
/// The `suspend` phase's server computes this long, then sleeps
/// [`SUSPEND_GAP_US`], and again, for the whole phase.
const SUSPEND_RUN_US: u64 = 400;
const SUSPEND_GAP_US: u64 = 20;
/// Tasks one phase can hold (four per hart on two harts, plus the overrunner).
const SLOTS: usize = 10;
/// A gap longer than this between two clock reads of `burn` is time the task
/// did not run.
const GAP_US: u64 = 50;

/// (runtime, period, deadline) in microseconds: 20 % + 20 % + 20 % + 10 %.
const SET_70: [(u64, u64, u64); 4] =
    [(1_000, 5_000, 5_000), (2_000, 10_000, 10_000), (3_000, 20_000, 15_000), (4_000, 40_000, 40_000)];
/// 24 % + 24 % + 24 % + 21 %.
const SET_93: [(u64, u64, u64); 4] =
    [(1_200, 5_000, 5_000), (2_400, 10_000, 10_000), (3_600, 20_000, 15_000), (8_400, 40_000, 40_000)];

const NAMES: [&str; SLOTS] =
    ["rtu-0", "rtu-1", "rtu-2", "rtu-3", "rtu-4", "rtu-5", "rtu-6", "rtu-7", "rtu-8", "rtu-9"];

static STOP: AtomicBool = AtomicBool::new(false);

struct JobStats {
    jobs: AtomicU32,
    misses: AtomicU32,
    worst: AtomicU64,
    resp: AtomicU64,
    overruns: AtomicU32,
    /// Gaps longer than [`GAP_US`] inside `burn` (time the job did not run
    /// while it had work), and their sum in ticks.
    gaps: AtomicU32,
    gap_sum: AtomicU64,
    done: AtomicBool,
}
impl JobStats {
    const fn new() -> Self {
        Self {
            jobs: AtomicU32::new(0), misses: AtomicU32::new(0), worst: AtomicU64::new(0),
            resp: AtomicU64::new(0), overruns: AtomicU32::new(0), gaps: AtomicU32::new(0),
            gap_sum: AtomicU64::new(0), done: AtomicBool::new(false),
        }
    }
    fn reset(&self) {
        self.jobs.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.worst.store(0, Ordering::Relaxed);
        self.resp.store(0, Ordering::Relaxed);
        self.overruns.store(0, Ordering::Relaxed);
        self.gaps.store(0, Ordering::Relaxed);
        self.gap_sum.store(0, Ordering::Relaxed);
        self.done.store(false, Ordering::Release);
    }
    fn record(&self, release: u64, finish: u64, due: u64) {
        self.jobs.fetch_add(1, Ordering::Relaxed);
        self.resp.fetch_max(finish.saturating_sub(release), Ordering::Relaxed);
        if finish > due {
            self.misses.fetch_add(1, Ordering::Relaxed);
            self.worst.fetch_max(finish - due, Ordering::Relaxed);
        }
    }
}
static STATS: [JobStats; SLOTS] = [const { JobStats::new() }; SLOTS];

/// One task of a phase.
#[derive(Clone, Copy)]
struct Spec { q_us: u64, t_us: u64, d_us: u64, work: u64, prio: u32, hart: usize, offset: u64, end: u64 }
static mut SPECS: [Option<Spec>; SLOTS] = [None; SLOTS];

fn us(us: u64) -> u64 {
    TIMER_FREQ.saturating_mul(us) / 1_000_000
}
fn ms(ms: u64) -> u64 {
    us(ms * 1_000)
}
fn ns(t: u64) -> u64 {
    ((t as u128) * 1_000_000_000u128 / TIMER_FREQ.max(1) as u128) as u64
}
fn isa() -> &'static str {
    if cfg!(target_arch = "riscv64") { "riscv64" } else { "aarch64" }
}

fn block_until(deadline: u64) {
    while now() < deadline {
        if task_block_outcome(WaitReason::Timer(deadline)) == BlockOutcome::Refused {
            while now() < deadline {
                core::hint::spin_loop();
            }
        }
    }
}

/// Compute for `ticks` of the caller's own run time (gaps longer than
/// [`GAP_US`] between clock reads are time it did not run, counted in `st`).
fn burn(ticks: u64, st: &JobStats) {
    let gap = us(GAP_US);
    let (mut last, mut ran) = (now(), 0u64);
    while ran < ticks {
        let t = now();
        let d = t.saturating_sub(last);
        if d < gap {
            ran += d;
        } else {
            st.gaps.fetch_add(1, Ordering::Relaxed);
            st.gap_sum.fetch_add(d, Ordering::Relaxed);
        }
        last = t;
    }
}

fn self_idx() -> usize {
    azos_sched::idx_for_tid(azos_sched::current_task_tid()).unwrap_or(usize::MAX)
}

fn periodic_task(slot: usize) {
    let s = unsafe { (*core::ptr::addr_of!(SPECS))[slot] }.expect("rtu slot");
    let (period, deadline) = (us(s.t_us), us(s.d_us));
    let mut release = s.offset;
    while release < s.end {
        block_until(release);
        burn(s.work, &STATS[slot]);
        STATS[slot].record(release, now(), release + deadline);
        release += period;
    }
    // Read while the reservation is still held (exit releases it).
    let over = rt::task_reservation(self_idx()).map_or(0, |r| r.0);
    STATS[slot].overruns.store(over, Ordering::Relaxed);
    STATS[slot].done.store(true, Ordering::Release);
}

fn hog_task(_: usize) {
    let mut x = 0x9E37_79B9u32;
    while !STOP.load(Ordering::Acquire) {
        for _ in 0..1_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
        }
        core::hint::black_box(x);
    }
}

pub fn spawn() {
    azos_sched::task_create_affinity("rtu-ctl", ctl_task, 0, CTL_PRIO, 0);
    kprintln!("[RTUTIL] created rtu-ctl on hart 0");
}

/// Start the task of `slot`, then take its reservation on its hart. The task
/// blocks until `offset` first, so it is never running when admission pins it.
fn start(slot: usize, s: Spec) -> bool {
    STATS[slot].reset();
    unsafe { (*core::ptr::addr_of_mut!(SPECS))[slot] = Some(s) };
    let idx = azos_sched::task_create_affinity(NAMES[slot], periodic_task, slot, s.prio, s.hart as i8);
    let r = Reservation {
        runtime_us: s.q_us, period_us: s.t_us, deadline_us: s.d_us, hard: true,
        cpu_mask: 1 << s.hart, band: s.prio < azos_sched::RT_PRIORITY_THRESHOLD, level: s.prio,
    };
    match rt::reserve(idx, r) {
        Ok(_) => true,
        Err(e) => {
            kprintln!("[RTUTIL] {} reservation refused: {}", NAMES[slot], e.name());
            false
        }
    }
}

/// Wait for the phase's tasks, print one line per task, and return the jobs
/// and misses of the tasks that count.
fn collect(phase: &str, n: usize, counted: impl Fn(usize) -> bool, end: u64) -> (u32, u32) {
    block_until(end + ms(60));
    for slot in 0..n {
        while !STATS[slot].done.load(Ordering::Acquire) {
            block_until(now() + ms(5));
        }
    }
    let (mut jobs, mut misses) = (0u32, 0u32);
    for slot in 0..n {
        let s = unsafe { (*core::ptr::addr_of!(SPECS))[slot] }.expect("rtu slot");
        let st = &STATS[slot];
        let (j, m) = (st.jobs.load(Ordering::Relaxed), st.misses.load(Ordering::Relaxed));
        kprintln!(
            "[RTUTIL] task {} {} {} hart={} prio={} q_us={} t_us={} d_us={} jobs={} misses={} worst_late_ns={} max_resp_ns={} overruns={} gaps={} gap_us={}{}",
            isa(), phase, NAMES[slot], s.hart, s.prio, s.q_us, s.t_us, s.d_us, j, m,
            ns(st.worst.load(Ordering::Relaxed)), ns(st.resp.load(Ordering::Relaxed)),
            st.overruns.load(Ordering::Relaxed), st.gaps.load(Ordering::Relaxed),
            ns(st.gap_sum.load(Ordering::Relaxed)) / 1_000, if counted(slot) { "" } else { " (not counted)" });
        if counted(slot) {
            jobs += j;
            misses += m;
        }
    }
    (jobs, misses)
}

/// The phase `name`: `set` on each of the harts `first..first + harts`.
fn phase_set(name: &str, set: &[(u64, u64, u64); 4], first: usize, harts: usize, extra: Option<Spec>) {
    STOP.store(false, Ordering::Release);
    let t0 = now() + ms(30);
    let end = t0 + ms(PHASE_MS);
    for h in first..first + harts {
        azos_sched::task_create_affinity("rtu-hog", hog_task, 0, HOG_PRIO, h as i8);
    }
    let (band0, cbs0, ..) = rt::stats();
    let mut ok = true;
    let mut n = 0;
    for h in first..first + harts {
        for &(q, t, d) in set.iter() {
            ok &= start(n, Spec { q_us: q, t_us: t, d_us: d, work: us(q) * WORK_PCT / 100,
                prio: EDF_PRIO, hart: h, offset: t0, end });
            n += 1;
        }
    }
    let watch = extra.map(|mut e| {
        e.offset = t0;
        e.end = end;
        ok &= start(n, e);
        n += 1;
        n - 1
    });
    let (jobs, misses) = collect(name, n, |s| Some(s) != watch, end);
    STOP.store(true, Ordering::Release);
    let (band1, cbs1, ..) = rt::stats();
    let density: u64 = set.iter().map(|&(q, _, d)| q * 100 / d).sum();
    // Every counted job of a full phase: PHASE_MS / period per task.
    let expect: u64 = set.iter().map(|&(_, t, _)| PHASE_MS * 1_000 / t).sum::<u64>() * harts as u64;
    let over = watch.map_or(0, |w| STATS[w].overruns.load(Ordering::Relaxed));
    let pass = ok && misses == 0 && jobs as u64 >= expect && (watch.is_none() || over >= 50);
    kprintln!(
        "[RTUTIL] {} {} {} harts={} first_hart={} density_pct_per_hart={} jobs={} expected_jobs={} misses={} overrunner_overruns={} band_throttles={} cbs_exhausted={} admitted={}",
        name, if pass { "PASS" } else { "FAIL" }, isa(), harts, first, density, jobs, expect, misses, over,
        band1 - band0, cbs1 - cbs0, ok);
    block_until(now() + ms(20));
}

/// The self-suspending server of the `suspend` phase: computes
/// [`SUSPEND_RUN_US`], sleeps [`SUSPEND_GAP_US`], until `end`.
fn suspender_task(slot: usize) {
    let s = unsafe { (*core::ptr::addr_of!(SPECS))[slot] }.expect("rtu slot");
    block_until(s.offset);
    while now() < s.end {
        burn(us(SUSPEND_RUN_US), &STATS[slot]);
        STATS[slot].jobs.fetch_add(1, Ordering::Relaxed);
        block_until(now() + us(SUSPEND_GAP_US));
    }
    let over = rt::task_reservation(self_idx()).map_or(0, |r| r.0);
    STATS[slot].overruns.store(over, Ordering::Relaxed);
    STATS[slot].done.store(true, Ordering::Release);
}

/// A periodic task beside a self-suspending server (see the module doc).
fn phase_suspend() {
    STOP.store(false, Ordering::Release);
    let t0 = now() + ms(30);
    let end = t0 + ms(PHASE_MS);
    azos_sched::task_create_affinity("rtu-hog", hog_task, 0, HOG_PRIO, 0);
    let ok = start(0, Spec { q_us: 4_000, t_us: 10_000, d_us: 10_000, work: us(4_000) * WORK_PCT / 100,
        prio: EDF_PRIO, hart: 0, offset: t0, end });
    STATS[1].reset();
    let b = Spec { q_us: 1_000, t_us: 20_000, d_us: 2_000, work: 0, prio: EDF_PRIO, hart: 0, offset: t0, end };
    unsafe { (*core::ptr::addr_of_mut!(SPECS))[1] = Some(b) };
    let idx = azos_sched::task_create_affinity(NAMES[1], suspender_task, 1, EDF_PRIO, 0);
    let ok = ok & rt::reserve(idx, Reservation {
        runtime_us: b.q_us, period_us: b.t_us, deadline_us: b.d_us, hard: true, cpu_mask: 1, band: true,
        level: EDF_PRIO,
    }).is_ok();
    let (jobs, misses) = collect("suspend", 2, |s| s == 0, end);
    STOP.store(true, Ordering::Release);
    // The server's own run time: its bursts, each SUSPEND_RUN_US.
    let ran_ppm = STATS[1].jobs.load(Ordering::Relaxed) as u64 * SUSPEND_RUN_US * 1_000 / PHASE_MS;
    let pass = ok && misses == 0 && jobs as u64 >= PHASE_MS * 1_000 / 10_000;
    kprintln!("[RTUTIL] suspend {} {} density_pct=90 jobs={} misses={} suspender_density_ppm=500000 suspender_ran_ppm={} admitted={}",
        if pass { "PASS" } else { "FAIL" }, isa(), jobs, misses, ran_ppm, ok);
    block_until(now() + ms(20));
}

/// Two reservations at different levels (see the module doc).
fn phase_mixed() {
    STOP.store(false, Ordering::Release);
    let t0 = now() + ms(30);
    let end = t0 + ms(PHASE_MS);
    azos_sched::task_create_affinity("rtu-hog", hog_task, 0, HOG_PRIO, 0);
    let h = start(0, Spec { q_us: 5_000, t_us: 20_000, d_us: 20_000, work: us(5_000) * WORK_PCT / 100,
        prio: EDF_PRIO, hart: 0, offset: t0, end });
    let l = Spec { q_us: 1_000, t_us: 20_000, d_us: 2_000, work: us(1_000) * WORK_PCT / 100,
        prio: EDF_PRIO + 2, hart: 0, offset: t0, end };
    STATS[1].reset();
    unsafe { (*core::ptr::addr_of_mut!(SPECS))[1] = Some(l) };
    let idx = azos_sched::task_create_affinity(NAMES[1], periodic_task, 1, l.prio, 0);
    let lr = rt::reserve(idx, Reservation {
        runtime_us: l.q_us, period_us: l.t_us, deadline_us: l.d_us, hard: true, cpu_mask: 1,
        band: true, level: l.prio,
    });
    // L counts only if it was admitted: refused, it runs without a
    // reservation and no deadline was promised to it.
    let admitted_l = lr.is_ok();
    let (jobs, misses) = collect("mixed", 2, |s| s == 0 || admitted_l, end);
    STOP.store(true, Ordering::Release);
    let pass = h && lr == Err(Refusal::Levels) && misses == 0 && jobs as u64 >= PHASE_MS * 1_000 / 20_000;
    kprintln!("[RTUTIL] mixed {} {} density_pct=75 high={:?} low={:?} counted_jobs={} counted_misses={} low_misses={}",
        if pass { "PASS" } else { "FAIL" }, isa(), if h { "ok" } else { "refused" },
        lr.map(|_| "ok").map_err(|e| e.name()), jobs, misses, STATS[1].misses.load(Ordering::Relaxed));
    block_until(now() + ms(20));
}

fn ctl_task(_: usize) {
    let harts = azos_sched::smp::NUM_ONLINE_CPUS.load(Ordering::Acquire);
    if harts >= 2 {
        // Hart 1 alone, hart 0 left to the kernel's own loops (see the module
        // doc: under -icount both harts share one clock, so a phase may only
        // load one of them). After the boot's worker tasks (hart 1) are done.
        block_until(now() + ms(SETTLE_SMP_MS));
        phase_set("u70-hart1", &SET_70, 1, 1, None);
        phase_set("u93-hart1", &SET_93, 1, 1, None);
    } else {
        block_until(now() + ms(SETTLE_MS));
        phase_set("u70-h1", &SET_70, 0, 1, None);
        phase_set("u93-h1", &SET_93, 0, 1, None);
        phase_set("overrun", &SET_70, 0, 1, Some(Spec {
            q_us: 1_000, t_us: 10_000, d_us: 10_000, work: ms(6), prio: EDF_PRIO, hart: 0, offset: 0, end: 0 }));
        phase_suspend();
        phase_mixed();
    }
    let (_, exhausted, admitted, refused, ..) = rt::stats();
    kprintln!("[RTUTIL] done {} harts={} admitted={} refused={} cbs_exhausted={}", isa(), harts, admitted, refused, exhausted);
}
