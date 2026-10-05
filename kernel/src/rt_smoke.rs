// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The SCHED-RT rows (`sched-rt-smoke`, wave 11): the RT band budget and
//! EDF + CBS on the Legacy scheduler, measured on hart 0 under `-smp 1
//! -icount shift=0,sleep=off` (one nanosecond of virtual time per guest
//! instruction, so every number here is an instruction count).
//!
//! Four checks, one after the other, each ending in a verdict line only its
//! own path prints (`[SCHEDRT] <check> PASS` / `[SCHEDRT] <check> FAIL`):
//!
//! * **band** — a band task (priority [`RUNAWAY_PRIO`]) that never blocks
//!   runs for [`BAND_MS`]; a best-effort task on the same hart measures how
//!   much of that time it ran. PASS: the runaway took at most the cap plus
//!   [`BAND_SLACK_PPM`] and the best-effort task at least [`BE_MIN_PPM`].
//!   Canary `rt-band-canary` (no cap): the best-effort task gets nothing.
//! * **edf** — A (1.5 ms per 10 ms, deadline 3 ms, 1 ms of work) and B (5 ms
//!   per 20 ms, 4 ms of work) share priority level [`EDF_PRIO`] under a
//!   best-effort hog and a console spammer; B is released 100 us before A, so
//!   it is running when A arrives. Their reservations come from the signed
//!   topology's rows `rt-edf-a`/`rt-edf-b` (boot admission placed them on
//!   hart 0). Each job's lateness against its own deadline is recorded, the
//!   LAT instrument's measure (`now - deadline`). PASS: no job of A or B
//!   finished after its deadline. Canary `rt-edf-canary` (FIFO inside the
//!   level): A waits for B's 4 ms and misses.
//! * **cbs** — X (hard CBS, 1 ms per 10 ms) never stops running once it
//!   starts; A2 (same level, 1.5/10 ms, deadline 3 ms) and C (level
//!   [`EDF_PRIO`]+2, 2/20 ms, deadline 10 ms) must keep their deadlines.
//!   PASS: no miss, and X was throttled (its overrun counter grew). Canary
//!   `rt-cbs-canary` (no charging): X's deadline never moves, it keeps the
//!   level, A2 and C miss.
//! * **admit** — run-time admission on hart 0: a band reservation of 60 %
//!   fits; a second of 40 % does not fit the band cap (95 %) and is REFUSED
//!   with `EBUSY` and a `[SCHED-RT] admission REFUSED` line; a non-band one of
//!   30 % fits; a non-band one of 20 % does not fit the hart. Canary
//!   `rt-admit-canary` (no admission): the over-subscriptions are accepted.
//! * **exempt** — during the `band` check the best-effort task also watches
//!   rt-motor's heartbeat while the band is throttled. The safety loops are
//!   exempt from the cap (owner decision), so rt-motor (1 ms period) must keep
//!   running: PASS when the heartbeat never stood still for more than
//!   [`HB_STILL_MAX_US`] of the observer's own run time. Canary
//!   `rt-exempt-canary` (no exemption): rt-motor is throttled with the band and
//!   the heartbeat stands still for the whole throttle (~50 ms).
//! * **ring3** — the row lookup `SYS_SPAWN` and the autorun loader apply
//!   (`topo_sched::resolve`) keeps the class priority 4 of a profiled band row
//!   together with its reservation, and raises the same row without a profile
//!   (`rt-r3-noprof`) to the ring-3 floor, 12.
//!
//! The run ends with `[SCHEDRT] cost`: the instructions of one comparator
//! write through `timebase::arm_if_earlier`, and of one call that finds the
//! comparator already earlier (the figures `RT_BAND_CAP_PCT`'s help quotes).

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};
use azos_sched::rt::{self, Reservation};
use azos_sched::rt_core::Refusal;
use azos_sched::{task_block_outcome, BlockOutcome, WaitReason};

const HART: i8 = 0;
const CTL_PRIO: u32 = 2;
/// Below rt-motor and flight-ctrl (8), above sys-wdt (11): the runaway does
/// not take the control loops' hart, and every non-band task is below it.
const RUNAWAY_PRIO: u32 = 10;
const BE_PRIO: u32 = 12;
const EDF_PRIO: u32 = 4;
const HOG_PRIO: u32 = 23;
const SPAM_PRIO: u32 = 20;

const SETTLE_MS: u64 = 1_500;
/// Three band windows at the default 1 s.
const BAND_MS: u64 = 3_000;
const EDF_MS: u64 = 2_000;
const CBS_MS: u64 = 2_000;
/// A gap longer than this between two clock reads of a measuring loop is time
/// the loop did not run (it was preempted).
const GAP_US: u64 = 50;
/// Tolerance on the band's share above the cap.
const BAND_SLACK_PPM: u64 = 20_000;
/// The least the best-effort task must have run while the band ran away:
/// 2 % of the time, against the 5 % the default cap leaves to everything
/// outside the band.
const BE_MIN_PPM: u64 = 20_000;

static STOP: AtomicBool = AtomicBool::new(false);
static RUNAWAY_RAN: AtomicU64 = AtomicU64::new(0);
static BE_RAN: AtomicU64 = AtomicU64::new(0);
static LOAD_ROUNDS: AtomicU32 = AtomicU32::new(0);

/// Per measured task: jobs, misses, worst lateness and worst response time
/// (ticks).
struct JobStats { jobs: AtomicU32, misses: AtomicU32, worst: AtomicU64, resp: AtomicU64 }
impl JobStats {
    const fn new() -> Self {
        Self { jobs: AtomicU32::new(0), misses: AtomicU32::new(0), worst: AtomicU64::new(0), resp: AtomicU64::new(0) }
    }
    fn record(&self, release: u64, finish: u64, due: u64) {
        self.jobs.fetch_add(1, Ordering::Relaxed);
        let r = finish.saturating_sub(release);
        if r > self.resp.load(Ordering::Relaxed) {
            self.resp.store(r, Ordering::Relaxed);
        }
        if finish > due {
            self.misses.fetch_add(1, Ordering::Relaxed);
            let late = finish - due;
            if late > self.worst.load(Ordering::Relaxed) {
                self.worst.store(late, Ordering::Relaxed);
            }
        }
    }
}
static STAT_A: JobStats = JobStats::new();
static STAT_B: JobStats = JobStats::new();
static STAT_A2: JobStats = JobStats::new();
static STAT_C: JobStats = JobStats::new();
static X_IDX: AtomicU64 = AtomicU64::new(u64::MAX);

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

/// Run time of the calling task, measured by its own clock reads: a gap
/// longer than [`GAP_US`] is time it did not run.
struct Meter { last: u64, ran: u64, gap: u64 }
impl Meter {
    fn new() -> Self { Self { last: now(), ran: 0, gap: us(GAP_US) } }
    #[inline]
    fn step(&mut self) {
        let t = now();
        let d = t.saturating_sub(self.last);
        if d < self.gap {
            self.ran += d;
        }
        self.last = t;
    }
}

/// Compute for `ticks` of the caller's own run time.
fn burn(ticks: u64) {
    let mut m = Meter::new();
    while m.ran < ticks {
        m.step();
    }
}

/// Create the controller; it creates every other task when its phase starts.
pub fn spawn() {
    azos_sched::task_create_affinity("rt-ctl", ctl_task, 0, CTL_PRIO, HART);
    kprintln!("[SCHEDRT] created rt-ctl on hart {}", HART);
}

fn self_idx() -> usize {
    azos_sched::idx_for_tid(azos_sched::current_task_tid()).unwrap_or(usize::MAX)
}

// ── band ────────────────────────────────────────────────────────────────

fn runaway_task(end: usize) {
    let end = end as u64;
    let mut m = Meter::new();
    while now() < end {
        m.step();
    }
    RUNAWAY_RAN.store(m.ran, Ordering::Release);
}

/// Also the observer of the safety loop: while it runs during the band's
/// throttle, the longest stretch of its own uninterrupted running in which
/// rt-motor's heartbeat did not move. With the exemption rt-motor (1 ms
/// period, priority 8) preempts it every period; without it rt-motor is
/// throttled with the band and the stretch is the whole throttle.
fn be_task(end: usize) {
    let end = end as u64;
    let mut m = Meter::new();
    let mut hb = azos_actuation::watchdog::control_heartbeat();
    let (mut still, mut worst) = (0u64, 0u64);
    while now() < end {
        let before = m.ran;
        m.step();
        let h = azos_actuation::watchdog::control_heartbeat();
        if h != hb {
            hb = h;
            still = 0;
        } else {
            still += m.ran - before;
            worst = worst.max(still);
        }
    }
    BE_RAN.store(m.ran, Ordering::Release);
    HB_STILL.store(worst, Ordering::Release);
}

static HB_STILL: AtomicU64 = AtomicU64::new(0);
/// rt-motor's period is 1 ms; while the band is throttled it must keep it.
const HB_STILL_MAX_US: u64 = 5_000;

// ── load ────────────────────────────────────────────────────────────────

fn hog_task(_: usize) {
    let mut x = 0x9E37_79B9u32;
    while !STOP.load(Ordering::Acquire) {
        for _ in 0..1_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
        }
        core::hint::black_box(x);
        LOAD_ROUNDS.fetch_add(1, Ordering::Relaxed);
    }
}

fn spam_task(_: usize) {
    let mut n = 0u32;
    while !STOP.load(Ordering::Acquire) {
        kprintln!("[SCHEDRTLOAD] {:06} the quick brown fox jumps over the lazy dog 0123456789", n);
        n = n.wrapping_add(1);
        block_until(now() + ms(5));
    }
}

// ── periodic reservation tasks ──────────────────────────────────────────

/// One periodic job stream: release every `period` from `offset` until
/// `end`, `work` of its own run time per job, due `deadline` after release.
#[derive(Clone, Copy)]
struct Periodic { period: u64, deadline: u64, work: u64, offset: u64, end: u64, stats: &'static JobStats }

static mut PERIODIC: [Option<Periodic>; 4] = [None; 4];

fn periodic_task(slot: usize) {
    let p = unsafe { (*core::ptr::addr_of!(PERIODIC))[slot] }.expect("periodic slot");
    let mut release = p.offset;
    while release < p.end {
        block_until(release);
        burn(p.work);
        p.stats.record(release, now(), release + p.deadline);
        release += p.period;
    }
}

fn start_periodic(name: &str, slot: usize, prio: u32, p: Periodic) -> usize {
    unsafe { (*core::ptr::addr_of_mut!(PERIODIC))[slot] = Some(p) };
    azos_sched::task_create_affinity(name, periodic_task, slot, prio, HART)
}

fn reserve_or_say(idx: usize, name: &str, r: Reservation) -> bool {
    match rt::reserve(idx, r) {
        Ok(_) => true,
        Err(e) => {
            kprintln!("[SCHEDRT] {} reservation refused: {}", name, e.name());
            false
        }
    }
}

/// The reservation the signed topology's row `name` declares, placed where
/// boot admission put it.
fn reserve_row(idx: usize, name: &str) -> bool {
    match azos_syscall::topo_sched::row_reservation(name.as_bytes()) {
        Some(r) => {
            kprintln!("[SCHEDRT] row {} reservation runtime_us={} period_us={} deadline_us={} mask={:#x} band={}",
                name, r.runtime_us, r.period_us, r.deadline_us, r.cpu_mask, r.band);
            reserve_or_say(idx, name, r)
        }
        None => {
            kprintln!("[SCHEDRT] row {} has no admitted profile", name);
            false
        }
    }
}

fn x_task(end: usize) {
    X_IDX.store(self_idx() as u64, Ordering::Release);
    let end = end as u64;
    while now() < end {
        core::hint::spin_loop();
    }
}

// ── controller ──────────────────────────────────────────────────────────

fn ppm(part: u64, whole: u64) -> u64 {
    if whole == 0 { 0 } else { ((part as u128) * 1_000_000 / whole as u128) as u64 }
}

fn verdict(check: &str, pass: bool, detail: core::fmt::Arguments) {
    if pass {
        kprintln!("[SCHEDRT] {} PASS {} {}", check, isa(), detail);
    } else {
        kprintln!("[SCHEDRT] {} FAIL {} {}", check, isa(), detail);
    }
}

fn ctl_task(_: usize) {
    block_until(now() + ms(SETTLE_MS));

    // ── band ──
    let t0 = now() + ms(10);
    let end = t0 + ms(BAND_MS);
    azos_sched::task_create_affinity("rt-be", be_task, end as usize, BE_PRIO, HART);
    azos_sched::task_create_affinity("rt-runaway", runaway_task, end as usize, RUNAWAY_PRIO, HART);
    block_until(end + ms(20));
    let span = end.saturating_sub(t0);
    let (run, be) = (RUNAWAY_RAN.load(Ordering::Acquire), BE_RAN.load(Ordering::Acquire));
    let cap_ppm = azos_limits::RT_BAND_CAP_PCT as u64 * 10_000;
    let (run_ppm, be_ppm) = (ppm(run, span), ppm(be, span));
    let (throttles, _, _, _, _, _) = rt::stats();
    verdict("band", run_ppm <= cap_ppm + BAND_SLACK_PPM && be_ppm >= BE_MIN_PPM, format_args!(
        "runaway_ppm={} be_ppm={} cap_ppm={} window_ms={} span_ms={} band_throttles={}",
        run_ppm, be_ppm, cap_ppm, azos_limits::RT_BAND_WINDOW_MS, ns(span) / 1_000_000, throttles));
    // The safety loops are exempt from the cap: rt-motor kept its period
    // through the throttles the runaway caused.
    let still = HB_STILL.load(Ordering::Acquire);
    verdict("exempt", throttles >= 1 && still <= us(HB_STILL_MAX_US), format_args!(
        "rt_motor_heartbeat_still_max_us={} bound_us={} band_throttles={}",
        ns(still) / 1_000, HB_STILL_MAX_US, throttles));

    // ── edf ──
    azos_sched::task_create_affinity("rt-hog", hog_task, 0, HOG_PRIO, HART);
    azos_sched::task_create_affinity("rt-spam", spam_task, 0, SPAM_PRIO, HART);
    let t0 = now() + ms(20);
    let end = t0 + ms(EDF_MS);
    let b = start_periodic("rt-edf-b", 0, EDF_PRIO, Periodic {
        period: ms(20), deadline: ms(20), work: us(4_000), offset: t0, end, stats: &STAT_B });
    let a = start_periodic("rt-edf-a", 1, EDF_PRIO, Periodic {
        period: ms(10), deadline: us(3_000), work: us(1_000), offset: t0 + us(100), end, stats: &STAT_A });
    let ok_b = reserve_row(b, "rt-edf-b");
    let ok_a = reserve_row(a, "rt-edf-a");
    block_until(end + ms(30));
    let (ja, ma, wa) = (STAT_A.jobs.load(Ordering::Relaxed), STAT_A.misses.load(Ordering::Relaxed), STAT_A.worst.load(Ordering::Relaxed));
    let (jb, mb, wb) = (STAT_B.jobs.load(Ordering::Relaxed), STAT_B.misses.load(Ordering::Relaxed), STAT_B.worst.load(Ordering::Relaxed));
    verdict("edf", ok_a && ok_b && ma == 0 && mb == 0 && ja >= 150 && jb >= 75, format_args!(
        "a_jobs={} a_misses={} a_worst_late_ns={} a_max_resp_ns={} b_jobs={} b_misses={} b_worst_late_ns={} b_max_resp_ns={} load_rounds={}",
        ja, ma, ns(wa), ns(STAT_A.resp.load(Ordering::Relaxed)), jb, mb, ns(wb),
        ns(STAT_B.resp.load(Ordering::Relaxed)), LOAD_ROUNDS.load(Ordering::Relaxed)));

    // ── cbs ──
    let t0 = now() + ms(20);
    let end = t0 + ms(CBS_MS);
    let x = azos_sched::task_create_affinity("rt-cbs-x", x_task, end as usize, EDF_PRIO, HART);
    let a2 = start_periodic("rt-cbs-a2", 2, EDF_PRIO, Periodic {
        period: ms(10), deadline: us(3_000), work: us(1_000), offset: t0 + us(300), end, stats: &STAT_A2 });
    let c = start_periodic("rt-cbs-c", 3, EDF_PRIO + 2, Periodic {
        period: ms(20), deadline: ms(10), work: us(1_500), offset: t0 + us(500), end, stats: &STAT_C });
    let band = |runtime_us, period_us, deadline_us| Reservation {
        runtime_us, period_us, deadline_us, hard: true, cpu_mask: 1 << HART, band: true };
    let ok = reserve_or_say(x, "rt-cbs-x", band(1_000, 10_000, 0))
        & reserve_or_say(a2, "rt-cbs-a2", band(1_500, 10_000, 3_000))
        & reserve_or_say(c, "rt-cbs-c", band(2_000, 20_000, 10_000));
    // X's overruns are read while it still holds its reservation.
    block_until(end - ms(5));
    let x_over = rt::task_reservation(x).map_or(0, |r| r.0);
    block_until(end + ms(30));
    let (j2, m2, w2) = (STAT_A2.jobs.load(Ordering::Relaxed), STAT_A2.misses.load(Ordering::Relaxed), STAT_A2.worst.load(Ordering::Relaxed));
    let (jc, mc, wc) = (STAT_C.jobs.load(Ordering::Relaxed), STAT_C.misses.load(Ordering::Relaxed), STAT_C.worst.load(Ordering::Relaxed));
    let (_, exhausted, _, _, _, _) = rt::stats();
    verdict("cbs", ok && m2 == 0 && mc == 0 && j2 >= 150 && jc >= 75 && x_over >= 100, format_args!(
        "a2_jobs={} a2_misses={} a2_worst_late_ns={} a2_max_resp_ns={} c_jobs={} c_misses={} c_worst_late_ns={} c_max_resp_ns={} x_overruns={} cbs_exhausted={}",
        j2, m2, ns(w2), ns(STAT_A2.resp.load(Ordering::Relaxed)), jc, mc, ns(wc),
        ns(STAT_C.resp.load(Ordering::Relaxed)), x_over, exhausted));
    STOP.store(true, Ordering::Release);
    block_until(now() + ms(20));

    // ── admit ──
    let mk = |prio| azos_sched::task_create_affinity("rt-adm", idle_holder, 0, prio, HART);
    let (h1, h2, h3, h4) = (mk(EDF_PRIO), mk(EDF_PRIO), mk(20), mk(20));
    let r = |runtime_us, band| Reservation {
        runtime_us, period_us: 10_000, deadline_us: 0, hard: true, cpu_mask: 1 << HART, band };
    let r1 = rt::reserve(h1, r(6_000, true));
    let r2 = rt::reserve(h2, r(4_000, true));
    let r3 = rt::reserve(h3, r(3_000, false));
    let r4 = rt::reserve(h4, r(2_000, false));
    let (_, _, admitted, refused, arm_calls, arm_writes) = rt::stats();
    verdict("admit",
        r1.is_ok() && r2 == Err(Refusal::BandCap) && r3.is_ok() && r4 == Err(Refusal::NoRoom),
        format_args!("band60={:?} band40={:?} errno={} nonband30={:?} nonband20={:?} admitted={} refused={}",
            r1.map(|_| "ok"), r2.map(|_| "ok"), r2.err().map_or(0, |e| -e.errno()),
            r3.map(|_| "ok"), r4.map(|_| "ok"), admitted, refused));
    HOLD.store(false, Ordering::Release);

    ring3_check();
    arm_cost();
    kprintln!("[SCHEDRT] done {} arm_calls={} arm_writes={} tick_preempts={}", isa(), arm_calls, arm_writes,
        azos_sched::RT_TICK_PREEMPTS.load(Ordering::Relaxed));
}

/// A ring-3 row enters the band only with a reservation (owner decision,
/// wave 11): `topo_sched::resolve` — what `SYS_SPAWN` and the autorun loader
/// apply — keeps `rt-edf-a`'s class priority 4 with its reservation, and
/// raises `rt-r3-noprof` (same class and priority, no profile) to the floor.
fn ring3_check() {
    use azos_syscall::topo_sched::{band_refused_priority, resolve, TopoSched};
    let a = resolve(b"rt-edf-a");
    let n = resolve(b"rt-r3-noprof");
    let a_ok = matches!(a, TopoSched::Apply { priority: 4, floored: false, rt: Some(r), .. } if r.band);
    let n_ok = matches!(n, TopoSched::Apply { priority: 12, floored: true, rt: None, .. });
    let show = |t: TopoSched| match t {
        TopoSched::Apply { priority, floored, rt, .. } => (priority, floored, rt.is_some()),
        _ => (0, false, false),
    };
    verdict("ring3", a_ok && n_ok && band_refused_priority(4) == 12, format_args!(
        "with_reservation(prio,floored,rt)={:?} without={:?} refused_prio={}",
        show(a), show(n), band_refused_priority(4)));
}

/// The cost behind `RT_BAND_CAP_PCT`'s help: one comparator write through
/// `arm_if_earlier` (each call earlier than the last, so each writes), and one
/// call that finds the comparator already earlier (no write). Interrupts
/// masked so the tick cannot move the record mid-loop; instructions, since the
/// row boots under `-icount shift=0`.
fn arm_cost() {
    use azos_arch::{Interrupts, ARCH};
    use azos_drv_sys::timebase::{arm_if_earlier, programmed};
    const N: u64 = 256;
    block_until(now() + ms(2));
    let prev = ARCH.disable_all();
    let p = programmed();
    let t0 = now();
    let mut wrote = 0u64;
    for k in 1..=N {
        wrote += u64::from(arm_if_earlier(p.saturating_sub(k)));
    }
    let t1 = now();
    for _ in 0..N {
        wrote += u64::from(arm_if_earlier(p.saturating_add(1_000)));
    }
    let t2 = now();
    ARCH.restore(prev);
    kprintln!("[SCHEDRT] cost {} arm_write_instr={} arm_skip_instr={} writes={} of {}",
        isa(), ns(t1 - t0) / N, ns(t2 - t1) / N, wrote, 2 * N);
}

static HOLD: AtomicBool = AtomicBool::new(true);

fn idle_holder(_: usize) {
    while HOLD.load(Ordering::Acquire) {
        block_until(now() + ms(10));
    }
}
