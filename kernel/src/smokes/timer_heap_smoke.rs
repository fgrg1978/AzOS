// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wave 13 (RT7, P2): timer sleepers under the interleavings that lost
//! rt-motor's wake with `sched-timer-heap` (gate 185), on every hart.
//! Feature `timer-heap-smoke`; meaningful with and without the heap.
//!
//! [`PER_HART`] sleepers per online hart, pinned, block on
//! `WaitReason::Timer(d)`: even ones with periods of 1..=7 ms, odd ones with
//! 20..=100 us — `vsbench`'s spawn+wait naps 50 us, and a deadline that
//! short is often due while its sleeper is still switching out, the window
//! the wave-5 bug lived in. One racer per hart wakes
//! a sleeper early by TID with the `Timer(_)` predicate — a notify wake's
//! shape — but only while that sleeper's deadline is still more than 1 ms
//! away, so a racer never rescues a sleeper whose timer wake was lost. An
//! early-woken sleeper blocks again, half the time on a NEW deadline: the
//! heap then holds a stale entry for it while a tick on another hart pops
//! due entries — the pop / mid-switch stamp / re-arm / `nearest` sequence
//! that dropped the entry before the wave-5 fix.
//!
//! After [`RUN_MS`] the observer stops them and prints one line per check
//! and a verdict, `[THEAP] PASS ...` or `[THEAP] FAIL <why>`:
//! * no sleeper is stuck: each woke on its timer in the run's second half,
//!   and none is still blocked on a deadline [`STUCK_MS`] past (a sleeper
//!   with no heap entry is never woken again); the worst lateness is printed
//!   per sleeper above a quarter second, not judged (see [`STUCK_MS`]);
//! * with `ipc-census` and the heap, the census's `lost` count (a sleeper
//!   `Blocked` on a due timer with no heap entry, nothing in flight, for
//!   1 ms) is 0.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};
use azos_sched::WaitReason;

/// Sleepers per online hart.
const PER_HART: usize = 3;
/// Most harts the smoke uses.
const MAX_HARTS: usize = 4;
const N: usize = PER_HART * MAX_HARTS;
/// Settling time after boot before the run starts (boot work at higher
/// priorities would otherwise be measured as sleeper lateness).
const SETTLE_MS: u64 = 4_000;
/// Run length.
const RUN_MS: u64 = 10_000;
/// A sleeper whose deadline passed this long ago at the end of the run is
/// stuck. Not a lateness bound: lateness is printed, never judged — the
/// guest clock follows the host's, and a vCPU descheduled under host load
/// was measured late by up to 1 s with the heap on AND off (wave 13, 5+5
/// boots at load 9-15). A lost wake is unbounded: the sleeper never wakes.
const STUCK_MS: u64 = 2_000;
/// Racer period.
const RACER_MS: u64 = 3;

static STOP: AtomicBool = AtomicBool::new(false);
static TID: [AtomicU32; N] = [const { AtomicU32::new(0) }; N];
/// The deadline sleeper `i` is blocked on (0 = not sleeping).
static DEADLINE: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static TIMER_WAKES: [AtomicU32; N] = [const { AtomicU32::new(0) }; N];
static EARLY_WAKES: [AtomicU32; N] = [const { AtomicU32::new(0) }; N];
static LAST_TIMER_WAKE: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static MAX_LATE: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static RACER_WAKES: AtomicU32 = AtomicU32::new(0);
/// When sleeper `i`'s worst lateness was measured.
static MAX_LATE_AT: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
/// The run's start (`now()` ticks), set by `spawn`.
static T_START: AtomicU64 = AtomicU64::new(0);

/// Sleep until the run starts.
fn wait_start() {
    let s = T_START.load(Ordering::Acquire);
    while now() < s {
        azos_sched::task_block(WaitReason::Timer(s));
    }
}

fn ms(n: u64) -> u64 {
    n * (TIMER_FREQ / 1000)
}

fn lcg(x: &mut u32) -> u32 {
    *x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    *x >> 8
}

fn harts() -> usize {
    azos_sched::smp::NUM_ONLINE_CPUS.load(Ordering::Acquire).clamp(1, MAX_HARTS)
}

/// Create the sleepers, the racers and the observer. Called from
/// `kernel_main` with the other smokes.
pub(crate) fn spawn() {
    T_START.store(now() + ms(SETTLE_MS), Ordering::Release);
    let h = harts();
    for i in 0..PER_HART * h {
        azos_sched::task_create_affinity("theap-sleep", sleeper, i,
            azos_sched::DEFAULT_PRIORITY, (i % h) as i8);
    }
    for c in 0..h {
        azos_sched::task_create_affinity("theap-race", racer, c,
            azos_sched::DEFAULT_PRIORITY, c as i8);
    }
    azos_sched::task_create("theap-obs", observer, 0, azos_sched::DEFAULT_PRIORITY);
    kprintln!("[THEAP] {} sleepers, {} racers on {} harts; heap={} census={}",
        PER_HART * h, h, h, cfg!(feature = "sched-timer-heap"), cfg!(feature = "ipc-census"));
}

/// Sleeper `i`'s next period: 1..=7 ms for even `i`, 20..=100 us for odd.
fn period(i: usize, rng: &mut u32) -> u64 {
    if i % 2 == 0 {
        ms(1 + (lcg(rng) % 7) as u64)
    } else {
        (20 + (lcg(rng) % 81) as u64) * (TIMER_FREQ / 1_000_000)
    }
}

fn sleeper(i: usize) {
    TID[i].store(azos_sched::current_task_tid(), Ordering::Release);
    wait_start();
    let mut rng = 0x9e37_79b9u32 ^ (i as u32).wrapping_mul(0x85eb_ca6b);
    while !STOP.load(Ordering::Acquire) {
        let mut d = now() + period(i, &mut rng);
        loop {
            DEADLINE[i].store(d, Ordering::Release);
            azos_sched::task_block(WaitReason::Timer(d));
            let t = now();
            if t >= d {
                DEADLINE[i].store(0, Ordering::Release);
                TIMER_WAKES[i].fetch_add(1, Ordering::Relaxed);
                LAST_TIMER_WAKE[i].store(t, Ordering::Relaxed);
                if MAX_LATE[i].fetch_max(t - d, Ordering::Relaxed) < t - d {
                    MAX_LATE_AT[i].store(t, Ordering::Relaxed);
                }
                break;
            }
            EARLY_WAKES[i].fetch_add(1, Ordering::Relaxed);
            // Half the early wakes re-block on a new deadline: the heap
            // keeps a stale entry at the old one.
            if lcg(&mut rng) & 1 == 1 {
                d = t + period(i, &mut rng);
            }
        }
    }
    DEADLINE[i].store(0, Ordering::Release);
}

fn racer(c: usize) {
    let n = PER_HART * harts();
    let mut rng = 0x7f4a_7c15u32 ^ (c as u32).wrapping_mul(0xc2b2_ae35);
    wait_start();
    let mut next = now();
    while !STOP.load(Ordering::Acquire) {
        next += ms(RACER_MS);
        while now() < next {
            azos_sched::task_block(WaitReason::Timer(next));
        }
        let i = (lcg(&mut rng) as usize) % n;
        let tid = TID[i].load(Ordering::Acquire);
        let d = DEADLINE[i].load(Ordering::Acquire);
        // Never a sleeper whose deadline is due or nearly: a racer must not
        // rescue a sleeper whose timer wake was lost.
        if tid != 0 && d > now() + ms(1)
            && azos_sched::scheduler::wake_task_by_tid(
                tid, &|r| matches!(r, WaitReason::Timer(x) if *x == d))
        {
            RACER_WAKES.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn observer(_: usize) {
    wait_start();
    let t0 = now();
    let end = t0 + ms(RUN_MS);
    while now() < end {
        azos_sched::task_block(WaitReason::Timer(end));
    }
    let t_end = now();
    let n = PER_HART * harts();
    // Judge before stopping: a stuck sleeper is still stuck at this instant.
    let mut why: &str = "";
    let mut worst = 0u64;
    let (mut wakes, mut early) = (0u64, 0u64);
    for i in 0..n {
        let w = TIMER_WAKES[i].load(Ordering::Relaxed);
        let last = LAST_TIMER_WAKE[i].load(Ordering::Relaxed);
        let late = MAX_LATE[i].load(Ordering::Relaxed);
        let d = DEADLINE[i].load(Ordering::Acquire);
        wakes += w as u64;
        early += EARLY_WAKES[i].load(Ordering::Relaxed) as u64;
        worst = worst.max(late);
        if late > ms(250) {
            kprintln!("[THEAP] sleeper {} (hart {}) late {} us at +{} ms", i, i % harts(),
                late * 1_000_000 / TIMER_FREQ,
                MAX_LATE_AT[i].load(Ordering::Relaxed).saturating_sub(t0) / ms(1));
        }
        let stuck_ms = if d != 0 && t_end > d { (t_end - d) / ms(1) } else { 0 };
        if w == 0 || last < t0 + ms(RUN_MS / 2) || stuck_ms > STUCK_MS {
            kprintln!("[THEAP] sleeper {} tid={} stuck: timer wakes={} last {} ms before the end, \
                       deadline passed {} ms ago", i, TID[i].load(Ordering::Relaxed), w,
                (t_end.saturating_sub(last)) / ms(1), stuck_ms);
            if why.is_empty() {
                why = "a sleeper stopped waking on its timer";
            }
        }
    }
    STOP.store(true, Ordering::Release);
    let worst_us = worst * 1_000_000 / TIMER_FREQ;
    #[cfg(all(feature = "sched-timer-heap", feature = "ipc-census"))]
    let lost = azos_sched::scheduler::timer_sleepers::MISSED_BY[3].load(Ordering::Relaxed);
    #[cfg(not(all(feature = "sched-timer-heap", feature = "ipc-census")))]
    let lost = 0u32;
    if why.is_empty() && lost != 0 {
        why = "the census counted a lost sleeper";
    }
    kprintln!("[THEAP] timer wakes={} early wakes={} racer wakes={} max late {} us; census lost={}",
        wakes, early, RACER_WAKES.load(Ordering::Relaxed), worst_us, lost);
    if why.is_empty() {
        kprintln!("[THEAP] PASS");
    } else {
        kprintln!("[THEAP] FAIL {}", why);
    }
}
