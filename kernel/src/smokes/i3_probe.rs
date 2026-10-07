// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! I3 experiment probe (RFC-0031, qemu only): measure priority inversion
//! through the lease/capability layer on the **legacy priority** scheduler
//! (the live dispatcher), under the COMPILE-TIME policy
//! `azos_limits::LEASE_PRIORITY_INHERITANCE`.
//!
//! All tasks are pinned to CPU 0 and placed in priority band 1..6 — ABOVE every
//! standing kernel task (rt-motor / flight-ctrl sit at priority 8), so the
//! scenario runs uncontended and 1-hart dispatch is deterministic (lower number
//! = higher priority; RT_MOTOR_PRIORITY = 8).
//!   - lessor   (prio 2) grants a lease then BLOCKS awaiting its return
//!   - K spinners (prio 4) run a fixed CPU-bound burst then exit
//!   - lessee   (prio 6) accepts the lease, returns it, wakes the lessor
//!
//! OFF (baseline A): the lessor blocks; the priority scheduler runs the prio-4
//! spinners to completion before the prio-6 lessee is ever scheduled, so the
//! lease return — and thus the lessor — is held off for ~all the spinner work.
//! With a non-expiring lease (expire_ticks=0) this is unbounded by construction.
//!
//! ON (B): when the high-priority lessor blocks on a lease held by a
//! lower-priority lessee, boost the lessee's PRIORITY to the lessor's (classic
//! priority inheritance, reusing `pi_boost_task`), so the lessee runs ahead of
//! the spinners and returns immediately. Inversion collapses to the lessee's
//! critical section. Const-eliminated when OFF.
//!
//! Emits one `[I3]` line with `lease_inversion_cyc`. Build-time A/B like I2.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};
use azos_drv_sys::wcet::read_cycles;
use azos_sched::{
    task_create_affinity, task_exit, task_yield, current_task_tid,
    tid_for_idx, wq_block_current, wq_wake_by_tid,
};
use azos_ipc::{shm_create, ShmPerms, lease_grant, lease_accept,
                   lease_return, lease_wait_return};

// Priority band above all standing tasks (rt-motor/flight = 8).
pub const PROBE_PRIO:  u32 = 1;   // the runner — must outrun everything
const LESSOR_PRIO: u32 = 2;       // high-priority waiter
const SPIN_PRIO:   u32 = 4;       // medium starvers
const LESSEE_PRIO: u32 = 6;       // low-priority lease holder

const N_SPINNERS: usize = 4;
const SPIN_ITERS: u64 = 1_000_000;  // fixed CPU-bound burst per spinner
const NO_TID: u32 = u32::MAX;

static PROBE_TID:  AtomicU32 = AtomicU32::new(NO_TID);
static INVERSION_CYC: AtomicU64 = AtomicU64::new(0);
/// Spinners that had finished when the lessor's wait ended — the
/// ordering the verdict reads. Cycles are a duration and follow the
/// host; this is which task the scheduler ran first.
static SPINNERS_DONE: AtomicU32 = AtomicU32::new(0);
static SPINNERS_DONE_AT_RETURN: AtomicU32 = AtomicU32::new(u32::MAX);
static LESSOR_DONE: AtomicBool = AtomicBool::new(false);
/// The lessor's TID, published by the lessor before it grants.
/// `lease_accept` takes only a lease from the lessor it names, and the
/// lessee is created before the lessor, so it reads the TID here.
static LESSOR_TID: AtomicU32 = AtomicU32::new(NO_TID);

fn lessee_entry(_: usize) {
    let tid = current_task_tid();
    loop {
        // `NO_TID` until the lessor publishes itself: no lease names it,
        // so the accept returns `None` and the loop yields.
        if let Some((lid, _shm)) = lease_accept(tid, LESSOR_TID.load(Ordering::SeqCst)) {
            // Tiny critical section (the work the lessor is waiting on).
            core::hint::black_box(lid);
            // lease_return wakes the lessor internally (WaitQueue).
            //
            // `privileged = false` on purpose (IPC-6). This task *is* the
            // lessee, so it passes the new ownership check on its own
            // merits; asking for the kernel bypass here would make the
            // bench the one call site that never exercises the gate it
            // shares with `SYS_IPC_LEASE_RETURN`.
            let _ = lease_return(lid, tid, false);
            task_exit();
        }
        task_yield();
    }
}

fn spinner_entry(_: usize) {
    let mut acc: u64 = 0;
    let mut i: u64 = 0;
    while i < SPIN_ITERS {
        acc = acc.wrapping_add(i ^ 0x9E37_79B9);
        core::hint::black_box(acc);
        i += 1;
    }
    core::hint::black_box(acc);
    SPINNERS_DONE.fetch_add(1, Ordering::SeqCst);
    task_exit();
}

fn lessor_entry(lessee_tid: usize) {
    let lessee = lessee_tid as u32;
    let my_tid = current_task_tid();
    // Before the grant, so a pending lease always names a published TID.
    LESSOR_TID.store(my_tid, Ordering::SeqCst);
    // Own SHM page to lease out (content irrelevant — measuring scheduling).
    let shm = shm_create(my_tid, 1, ShmPerms::ReadWrite).unwrap_or(0);
    // expire_ticks = 0 → no expiry → baseline inversion is unbounded.
    let lid = match lease_grant(shm as usize, my_tid, lessee, 0) {
        Some(l) => l,
        None => { LESSOR_DONE.store(true, Ordering::SeqCst); task_exit(); }
    };

    // Measure the PRODUCTION wait path: lease_wait_return() applies the
    // priority-inheritance policy internally (gated by the const) and blocks
    // until the lessee returns. This probe exercises the real mechanism, not
    // an ad-hoc copy — what we measure is what production gets.
    let t0 = read_cycles();
    lease_wait_return(lid);
    SPINNERS_DONE_AT_RETURN.store(SPINNERS_DONE.load(Ordering::SeqCst), Ordering::SeqCst);
    INVERSION_CYC.store(read_cycles().wrapping_sub(t0), Ordering::SeqCst);
    LESSOR_DONE.store(true, Ordering::SeqCst);
    let p = PROBE_TID.load(Ordering::SeqCst);
    if p != NO_TID {
        wq_wake_by_tid(p);
    }
    task_exit();
}

/// Runs the probe. `hart` is the CPU every task it spawns is pinned to —
/// the caller decides (see the call site in `kernel_main`): hart 0 alone
/// on a 1-hart boot, hart 3 on SMP so the spinners' RT-band, never-yield
/// burst lands away from hart 0's rt-motor/flight-ctrl.
pub fn run(hart: i8) {
    let inh = azos_limits::LEASE_PRIORITY_INHERITANCE;
    PROBE_TID.store(current_task_tid(), Ordering::SeqCst);

    // Create the lessee first so we can hand its tid to the lessor.
    let lessee_idx = task_create_affinity(
        "i3-lessee", lessee_entry, 0, LESSEE_PRIO, hart);
    let lessee_tid = tid_for_idx(lessee_idx).unwrap_or(NO_TID);

    for _ in 0..N_SPINNERS {
        let _ = task_create_affinity(
            "i3-spin", spinner_entry, 0, SPIN_PRIO, hart);
    }
    let _ = task_create_affinity(
        "i3-lessor", lessor_entry, lessee_tid as usize, LESSOR_PRIO, hart);

    // Block until the lessor reports its measurement (it wakes us). The
    // scenario cannot progress until we yield the CPU here, so the wake
    // always follows this block — no lost-wake in this controlled setup.
    while !LESSOR_DONE.load(Ordering::SeqCst) {
        wq_block_current();
    }

    let cyc = INVERSION_CYC.load(Ordering::SeqCst);
    let done = SPINNERS_DONE_AT_RETURN.load(Ordering::SeqCst);
    crate::kprintln!(
        "[I3] inheritance={} spinners={} spin_iters={} lease_inversion_cyc={} \
         spinners_done_at_return={}",
        if inh { "on" } else { "off" }, N_SPINNERS, SPIN_ITERS, cyc, done,
    );
    // The verdict: all spinners run in the RT band, where the tick does
    // not preempt, so without inheritance the prio-6 lessee cannot run
    // until every prio-4 spinner has finished, and the lessor's wait ends
    // after all of them. With it the lessee runs at the lessor's 2 and the
    // wait ends before any of them.
    if done < N_SPINNERS as u32 {
        crate::kprintln!("[I3] PASS inversion avoided: the lessor's wait ended with {} of {} \
                          spinners finished", done, N_SPINNERS);
    } else {
        crate::kprintln!("[I3] FAIL inversion: the lessor waited for all {} spinners \
                          (inheritance={})", N_SPINNERS, if inh { "on" } else { "off" });
    }
}

/// Task entry: run the probe once on its top-priority host task, then
/// exit. Runs above the standing tasks so it is scheduled promptly even
/// in a 1-hart boot (behavior_task is hart-2-affined and never runs then).
/// `arg` is the hart the call site pinned this task to (and that its own
/// affinity was set with) — `run` reuses it to pin every task it spawns
/// to the same hart.
#[cfg(not(feature = "ktest"))]
pub fn runner(arg: usize) {
    run(arg as i8);
    task_exit();
}

#[cfg(feature = "ktest")]
fn ktest_entry(hart: usize) {
    run(hart as i8);
}

// RFC-0031 lease inversion through the lease layer: a priority-2 lessor
// blocked on a lease held by a priority-6 lessee, four priority-4 spinners
// on the same CPU. With `LEASE_PRIORITY_INHERITANCE` the lessee is boosted
// and returns the lease before the spinners finish (the row `sched: lease
// inversion`, `[I3] PASS inversion avoided`). The test waits for every
// spinner to exit too: they would otherwise steal their CPU from the tests
// after it. Canary: a configuration without LEASE_PRIORITY_INHERITANCE.
#[cfg(feature = "ktest")]
azos_ktest::ktest_late! {
    fn sched_lease_inversion() {
        let hart: usize = if azos_percpu::nr_cpu_ids() > 3 { 3 } else { 0 };
        crate::ktest::probe("i3-probe", ktest_entry, hart, PROBE_PRIO, hart as i8)?;
        let done = SPINNERS_DONE_AT_RETURN.load(Ordering::SeqCst);
        crate::ktest::wait("the spinners did not finish",
            || SPINNERS_DONE.load(Ordering::SeqCst) >= N_SPINNERS as u32)?;
        if !LESSOR_DONE.load(Ordering::SeqCst) {
            Err("the lessor never got its lease back")
        } else if done >= N_SPINNERS as u32 {
            Err("inversion: the lessor waited for every spinner")
        } else {
            Ok(())
        }
    }
}
