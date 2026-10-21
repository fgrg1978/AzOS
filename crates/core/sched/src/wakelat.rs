// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Child module of `scheduler.rs` (pulled in with `#[path]`), moved out of it unchanged.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::task::MAX_TASKS;

/// Same role as `unswitched::CANARY`: a row of zeros from a module that was
/// never compiled is indistinguishable from a real measurement.
pub static CANARY: u32 = 0x5EED;

/// A wake is "long" past this many CLINT ticks. 10 MHz on QEMU, so 10_000
/// ticks = **1 ms** — two orders of magnitude above the ~10 us a healthy
/// cross-hart wake takes, and an order below the 10 ms tick, so it cannot
/// catch ordinary scheduling jitter and cannot miss a tick-length stall.
pub const LONG_TICKS: u64 = 10_000;

/// CLINT time when this slot was last made `Ready`. 0 = not armed.
pub static READY_AT: [AtomicU64; MAX_TASKS] =
    [const { AtomicU64::new(0) }; MAX_TASKS];
/// Whether a doorbell was rung for the enqueue that armed `READY_AT`.
pub static RANG: [AtomicBool; MAX_TASKS] =
    [const { AtomicBool::new(false) }; MAX_TASKS];

/// Dispatches whose Ready->Running delay exceeded `LONG_TICKS`, and how
/// many of those had a doorbell rung for them.
pub static LONG: AtomicU32 = AtomicU32::new(0);
pub static LONG_RANG: AtomicU32 = AtomicU32::new(0);
/// Worst delay seen, in CLINT ticks.
pub static MAX_DELAY: AtomicU64 = AtomicU64::new(0);
/// Identity of the worst case: tid, the `ready_site` byte (site | hart<<4)
/// that armed it, and the hart that finally dispatched it.
///
/// A bare maximum says a wake was slow; it does not say whether the same
/// task is always the victim, whether one hart is always the culprit, or
/// which of the six `Ready` publishers armed it. Without that the next
/// hypothesis is a guess -- and in this investigation every guess that
/// explained the average failed on the tail.
pub static MAX_TID:  AtomicU32 = AtomicU32::new(0);
pub static MAX_SITE: AtomicU32 = AtomicU32::new(0);
pub static MAX_HART: AtomicU32 = AtomicU32::new(0);
/// Coarse histogram of long waits, so the shape is visible rather than
/// only its extreme: 1-2 ms, 2-4 ms, 4-8 ms, >8 ms.
pub static B1: AtomicU32 = AtomicU32::new(0);
pub static B2: AtomicU32 = AtomicU32::new(0);
pub static B4: AtomicU32 = AtomicU32::new(0);
pub static B8: AtomicU32 = AtomicU32::new(0);
/// Total dispatches measured, so `LONG` has a denominator.
pub static MEASURED: AtomicU32 = AtomicU32::new(0);

/// Arm the stopwatch: called right after a task is published `Ready`.
#[inline]
pub fn arm(idx: usize) {
    if idx < MAX_TASKS {
        READY_AT[idx].store(azos_drv_sys::timebase::now(), Ordering::Relaxed);
        RANG[idx].store(false, Ordering::Relaxed);
    }
}

/// Record that a doorbell was rung for this slot's enqueue.
#[inline]
pub fn rang(idx: usize) {
    if idx < MAX_TASKS { RANG[idx].store(true, Ordering::Relaxed); }
}

/// Stop the stopwatch: called when the task is actually set `Running`.
#[inline]
pub fn measure(idx: usize) {
    if idx >= MAX_TASKS { return; }
    let armed = READY_AT[idx].swap(0, Ordering::Relaxed);
    if armed == 0 { return; }   // not armed, or already measured
    let now = azos_drv_sys::timebase::now();
    let delay = now.saturating_sub(armed);
    MEASURED.fetch_add(1, Ordering::Relaxed);
    MAX_DELAY.fetch_max(delay, Ordering::Relaxed);
    if delay > LONG_TICKS {
        LONG.fetch_add(1, Ordering::Relaxed);
        if RANG[idx].load(Ordering::Relaxed) {
            LONG_RANG.fetch_add(1, Ordering::Relaxed);
        }
        let ms = delay / 10_000;
        if      ms < 2 { B1.fetch_add(1, Ordering::Relaxed); }
        else if ms < 4 { B2.fetch_add(1, Ordering::Relaxed); }
        else if ms < 8 { B4.fetch_add(1, Ordering::Relaxed); }
        else           { B8.fetch_add(1, Ordering::Relaxed); }
        // Racy against a concurrent worse case; acceptable because these
        // are read only after the fact and a torn identity would show as
        // an impossible combination rather than a plausible wrong one.
        if delay >= MAX_DELAY.load(Ordering::Relaxed) {
            // SAFETY: `idx < MAX_TASKS` was checked at entry, and this runs
            // on the dispatch path where the slot is live by construction —
            // the caller is about to make it `Running`.
            let t = unsafe { crate::scheduler::task_ref(idx) };
            MAX_TID.store(t.tid, Ordering::Relaxed);
            MAX_SITE.store(t.ready_site.load(Ordering::Relaxed) as u32, Ordering::Relaxed);
            // percpu-hint: a diagnostic on the dispatch path, interrupts off
            MAX_HART.store(crate::scheduler::current_cpu_id() as u32, Ordering::Relaxed);
        }
    }
}

/// `(tid, ready_site_byte, dispatching_hart, b1, b2, b4, b8)`
pub fn worst() -> (u32, u32, u32, u32, u32, u32, u32) {
    (MAX_TID.load(Ordering::Relaxed),
     MAX_SITE.load(Ordering::Relaxed),
     MAX_HART.load(Ordering::Relaxed),
     B1.load(Ordering::Relaxed), B2.load(Ordering::Relaxed),
     B4.load(Ordering::Relaxed), B8.load(Ordering::Relaxed))
}

/// Doorbells sent, and how many of those SBI refused.
///
/// The send site discards the return value on purpose -- ringing a hart
/// that never came up is harmless -- but "harmless when the hart is dead"
/// and "silently dropped for a live hart" look identical from there.
pub static IPI_SENT: AtomicU32 = AtomicU32::new(0);
pub static IPI_ERR:  AtomicU32 = AtomicU32::new(0);
/// Doorbells actually taken by a hart, counted in the `INT_SOFTWARE_S`
/// trap arm. If this trails `IPI_SENT`, the IPI is being lost between
/// SBI and the target; if it tracks it, the IPI arrives and the target's
/// `schedule()` is what fails to dispatch.
pub static IPI_RECV: AtomicU32 = AtomicU32::new(0);

#[inline]
pub fn ipi_sent(err: bool) {
    IPI_SENT.fetch_add(1, Ordering::Relaxed);
    if err { IPI_ERR.fetch_add(1, Ordering::Relaxed); }
}

#[inline]
pub fn ipi_recv() { IPI_RECV.fetch_add(1, Ordering::Relaxed); }

/// `(sent, err, recv)`
pub fn ipi_read() -> (u32, u32, u32) {
    (IPI_SENT.load(Ordering::Relaxed),
     IPI_ERR.load(Ordering::Relaxed),
     IPI_RECV.load(Ordering::Relaxed))
}

/// `(long, long_with_bell, max_delay_ticks, measured)`
pub fn read() -> (u32, u32, u64, u32) {
    (LONG.load(Ordering::Relaxed),
     LONG_RANG.load(Ordering::Relaxed),
     MAX_DELAY.load(Ordering::Relaxed),
     MEASURED.load(Ordering::Relaxed))
}
