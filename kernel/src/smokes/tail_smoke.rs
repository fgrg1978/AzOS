// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wave 13 (RT7): periodic-wake TAIL latency under contention
//! (`tail-smoke`), the AzOS half of a cyclictest + hackbench comparison;
//! the Linux half is `tools/lat_linux/tail.c`, run the same way.
//!
//! On hart [`HART`], [`PAIRS`] ping-pong pairs at `DEFAULT_PRIORITY` keep the
//! hart saturated with short slices: each side copies a 100-byte message,
//! wakes its peer by TID and blocks until woken back (hackbench's pipe
//! groups, without the pipe). Against them a waker sleeps to absolute
//! deadlines [`PERIOD_US`] apart for [`N`] periods and records how late each
//! wake ran (`now - deadline`), twice:
//! * `mode=rt-cbs` — the waker in the RT band (priority [`RT_PRIO`]) with a
//!   soft CBS reservation of [`CBS_RUNTIME_US`] per period;
//! * `mode=best-effort` — the waker at `DEFAULT_PRIORITY`, competing as an
//!   equal.
//! One line each: `[TAIL] isa=.. mode=.. heap=.. n=.. mean_ns=.. p50_ns=..
//! p99_ns=.. p999_ns=.. max_ns=.. worst=.. overruns=..`, then `[TAIL] done`.
//! Measured under `-smp 1 -icount shift=0,sleep=off`: one virtual ns per
//! guest instruction, so the numbers do not move with host load.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use alloc::vec::Vec;
use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};
use azos_sched::WaitReason;

const HART: i8 = 0;
const PAIRS: usize = 4;
const PERIOD_US: u64 = 1_000;
const N: usize = 10_000;
const SETTLE_MS: u64 = 1_500;
const RT_PRIO: u32 = 4;
const CBS_RUNTIME_US: u64 = 100;

static STOP: AtomicBool = AtomicBool::new(false);
static PEER: [AtomicU32; 2 * PAIRS] = [const { AtomicU32::new(0) }; 2 * PAIRS];
static MSGS: AtomicU32 = AtomicU32::new(0);

fn us(n: u64) -> u64 {
    TIMER_FREQ * n / 1_000_000
}

fn ticks_to_ns(t: u64) -> u64 {
    ((t as u128) * 1_000_000_000 / TIMER_FREQ as u128) as u64
}

fn block_forever() {
    let _ = azos_sched::task_block_outcome(WaitReason::Timer(u64::MAX));
}

fn wake(tid: u32) {
    if tid != 0 {
        let _ = azos_sched::scheduler::wake_task_by_tid(
            tid, &|r| matches!(r, WaitReason::Timer(u64::MAX)));
    }
}

pub(crate) fn spawn() {
    for i in 0..2 * PAIRS {
        azos_sched::task_create_affinity("tail-pp", pingpong, i,
            azos_sched::DEFAULT_PRIORITY, HART);
    }
    azos_sched::task_create("tail-ctl", controller, 0, azos_sched::DEFAULT_PRIORITY);
}

/// One side of a pair: side `i` talks to `i ^ 1`; the even side starts.
fn pingpong(i: usize) {
    PEER[i].store(azos_sched::current_task_tid(), Ordering::Release);
    let mut msg = [0u8; 100];
    let mut seq = 0u8;
    if i % 2 == 1 {
        block_forever();
    }
    while !STOP.load(Ordering::Acquire) {
        seq = seq.wrapping_add(1);
        for b in msg.iter_mut() {
            *b = b.wrapping_add(seq);
        }
        core::hint::black_box(&msg);
        MSGS.fetch_add(1, Ordering::Relaxed);
        let mut peer = PEER[i ^ 1].load(Ordering::Acquire);
        while peer == 0 {
            azos_sched::task_yield();
            peer = PEER[i ^ 1].load(Ordering::Acquire);
        }
        wake(peer);
        block_forever();
    }
    wake(PEER[i ^ 1].load(Ordering::Acquire));
}

static mut SAMPLES: [u64; N] = [0; N];

/// The waker: `N` absolute periodic sleeps into `SAMPLES`; returns `(worst, overruns)`.
fn measure() -> (usize, u32) {
    let period = us(PERIOD_US);
    let t0 = now() + period;
    let (mut worst, mut max, mut overruns) = (0usize, 0u64, 0u32);
    for k in 0..N {
        let d = t0 + k as u64 * period;
        if now() >= d {
            overruns += 1;
        }
        while now() < d {
            let _ = azos_sched::task_block_outcome(WaitReason::Timer(d));
        }
        let late = now() - d;
        unsafe { (*core::ptr::addr_of_mut!(SAMPLES))[k] = late };
        if late > max {
            max = late;
            worst = k;
        }
    }
    (worst, overruns)
}

static MODE: AtomicU32 = AtomicU32::new(0);
static WAKER_DONE: AtomicBool = AtomicBool::new(false);

fn waker(_: usize) {
    let mode = MODE.load(Ordering::Acquire);
    // With `lat-trace`: the masked windows of this run alone, named after it.
    #[cfg(feature = "lat-trace")]
    azos_arch::lat_hook::lat::reset();
    let (worst, overruns) = measure();
    let mut v: Vec<u64> = unsafe { (*core::ptr::addr_of!(SAMPLES)).to_vec() };
    v.sort_unstable();
    let pct = |p: usize, of: usize| v[(v.len() * p).div_ceil(of).saturating_sub(1)];
    let mean = v.iter().sum::<u64>() / v.len() as u64;
    kprintln!("[TAIL] isa={} mode={} heap={} n={} mean_ns={} p50_ns={} p99_ns={} p999_ns={} max_ns={} \
               worst={} overruns={} msgs={}",
        if cfg!(target_arch = "riscv64") { "riscv64" } else { "aarch64" },
        if mode == 0 { "rt-cbs" } else { "best-effort" }, cfg!(feature = "sched-timer-heap"),
        N, ticks_to_ns(mean), ticks_to_ns(pct(50, 100)), ticks_to_ns(pct(99, 100)),
        ticks_to_ns(pct(999, 1000)), ticks_to_ns(v[N - 1]), worst, overruns,
        MSGS.load(Ordering::Relaxed));
    #[cfg(feature = "lat-trace")]
    crate::lat_trace::print_summary(if mode == 0 { "tail-rt" } else { "tail-be" }, 5);
    WAKER_DONE.store(true, Ordering::Release);
}

fn controller(_: usize) {
    let t = now() + us(SETTLE_MS * 1000);
    while now() < t {
        let _ = azos_sched::task_block_outcome(WaitReason::Timer(t));
    }
    for mode in 0..2u32 {
        MODE.store(mode, Ordering::Release);
        WAKER_DONE.store(false, Ordering::Release);
        let prio = if mode == 0 { RT_PRIO } else { azos_sched::DEFAULT_PRIORITY };
        let idx = azos_sched::task_create_affinity("tail-waker", waker, 0, prio, HART);
        if mode == 0 {
            let r = azos_sched::rt::Reservation {
                runtime_us: CBS_RUNTIME_US, period_us: PERIOD_US, deadline_us: 0, hard: false,
                cpu_mask: 1 << HART as u32, band: true, level: RT_PRIO,
            };
            if let Err(e) = azos_sched::rt::reserve(idx, r) {
                kprintln!("[TAIL] rt-cbs reservation refused: {}", e.name());
            }
        }
        while !WAKER_DONE.load(Ordering::Acquire) {
            let t = now() + us(100_000);
            while now() < t {
                let _ = azos_sched::task_block_outcome(WaitReason::Timer(t));
            }
        }
    }
    STOP.store(true, Ordering::Release);
    kprintln!("[TAIL] done");
}
