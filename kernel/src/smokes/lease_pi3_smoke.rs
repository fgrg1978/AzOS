// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! lease-pi3-smoke (wave 9): lease priority inheritance applies when the
//! LESSOR is a ring-3 task waiting through `SYS_IPC_LEASE_WAIT`.
//!
//! The lessor is IPCTEST (autorun, priority 16), phase L2. The lessee and a
//! hog are kernel tasks here, both pinned to `HART`:
//!   * the lessee at `LESSEE_PRIO` (24) registers the service `leasepi`, waits
//!     for IPCTEST to register `leasepi.lessor`, then creates the hog;
//!   * the hog at `HOG_PRIO` (20) only yields — strict priority dispatch
//!     re-selects it over the lessee on every yield, so from that moment the
//!     lessee runs only if something lends it a priority above 20.
//!
//! IPCTEST grants the lessee a lease and waits on it with its `Cap<Lease>`;
//! the wait donates 16. The lessee's verdict is its OWN live priority at the
//! moment it gets past the hog: 16 (< 20) means the ring-3 wait's donation
//! is what let it run. Without lease priority inheritance
//! (`# CONFIG_LEASE_PRIORITY_INHERITANCE is not set`, the I3 row's canary) it
//! runs only when the hog stops at its ceiling, at its base 24, and prints
//! `[LEASEPI3] FAIL`, a line only that path prints.

use core::sync::atomic::{AtomicBool, Ordering};
use crate::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};

const LESSEE_PRIO: u32 = 24;
const HOG_PRIO: u32 = 20;
const HART: i8 = 2;
/// How long the lessee waits for its donation to be taken back after the
/// return before it judges the restore.
const RESTORE_WAIT_MS: u64 = 500;
const HOG_CEILING_S: u64 = 5;
/// How long the lessee waits for IPCTEST to appear (disk mount + exec).
const LESSOR_WAIT_S: u64 = 120;
/// How long the lessee tries to take the lease once the hog runs: past
/// the hog's ceiling, so a lessee left without a donation still takes it
/// after the hog stops and prints the FAIL line that path owns. It was
/// 1,000,000 yields, a count.
const ACCEPT_WAIT_MS: u64 = (HOG_CEILING_S + 10) * 1000;
static DONE: AtomicBool = AtomicBool::new(false);

pub fn spawn() {
    azos_sched::task_create_affinity("leasepi3-lessee", lessee, 0, LESSEE_PRIO, HART);
    kprintln!("[LEASEPI3] lessee created at {} on hart {}", LESSEE_PRIO, HART);
}

fn hog(_: usize) {
    let end = now() + HOG_CEILING_S * TIMER_FREQ;
    while !DONE.load(Ordering::Acquire) && now() < end {
        azos_sched::task_yield();
    }
}

fn lessee(_: usize) {
    let me = azos_sched::current_task_tid();
    if azos_service::service_register(b"leasepi", me, 0) != 0 {
        kprintln!("[LEASEPI3] FAIL setup: could not register the lessee's name");
        return;
    }
    kprintln!("[LEASEPI3] lessee tid {} registered as `leasepi`", me);
    let give_up = now() + LESSOR_WAIT_S * TIMER_FREQ;
    let lessor = loop {
        if let Some(e) = azos_service::service_discover(b"leasepi.lessor") {
            break e.tid;
        }
        if now() >= give_up {
            kprintln!("[LEASEPI3] FAIL setup: no ring-3 lessor registered in {} s",
                      LESSOR_WAIT_S);
            return;
        }
        azos_syscall::sleep::sleep_ms(1);
    };
    let t0 = now();
    azos_sched::task_create_affinity("leasepi3-hog", hog, 0, HOG_PRIO, HART);
    // Hand the hart to the hog before the first try. Without this the
    // first try can run at 24 ahead of the hog and take a lease the
    // lessor has granted but not yet waited on (no donation yet): seen
    // once the lessor-discovery loop above slept instead of yielding,
    // which finds the name up to a millisecond later, after the grant.
    azos_syscall::sleep::sleep_ms(1);
    // From here on this task runs only above the hog (donated) or after it.
    // Each try comes before the deadline check, so a lessee first run
    // after the hog's ceiling still takes the lease and reports it.
    let mut lease = None;
    azos_syscall::sleep::wait_until_ms(ACCEPT_WAIT_MS, 1, || {
        lease = azos_ipc::lease::lease_accept(me, lessor).map(|(id, _shm)| id);
        lease.is_some()
    });
    let running_at = azos_sched::task_priority(me).unwrap_or(u32::MAX);
    let waited_us = now().wrapping_sub(t0).saturating_mul(1_000_000) / TIMER_FREQ;
    let Some(id) = lease else {
        kprintln!("[LEASEPI3] FAIL no lease from tid {} (running at {})", lessor, running_at);
        DONE.store(true, Ordering::Release);
        return;
    };
    let _ = azos_ipc::lease::lease_return(id, me, true);
    DONE.store(true, Ordering::Release);
    // The donation is taken back by the lessor, on its own hart, when its
    // `lease_wait` wakes: wait for that on the guest clock, not a yield
    // count, which expires early under host load (gate 193; here, 1 of 3
    // aarch64 -smp 4 boots read 16 after 1000 yields while the lessor had
    // not yet returned from its wait).
    azos_syscall::sleep::wait_until_ms(RESTORE_WAIT_MS, 1, || {
        azos_sched::task_priority(me) == Some(LESSEE_PRIO)
    });
    let after = azos_sched::task_priority(me).unwrap_or(u32::MAX);
    if running_at < HOG_PRIO && after == LESSEE_PRIO {
        kprintln!("[LEASEPI3] PASS ring-3 lessor tid {} lent lease {}'s lessee {} past a \
                   prio-{} hog ({} us); lessee back at {}",
                  lessor, id, running_at, HOG_PRIO, waited_us, after);
    } else if running_at < HOG_PRIO {
        kprintln!("[LEASEPI3] FAIL not-restored: lessee at {} after the return, base {}",
                  after, LESSEE_PRIO);
    } else {
        kprintln!("[LEASEPI3] FAIL lessee ran at {} (no donation from the ring-3 wait): \
                   only after the prio-{} hog stopped ({} us)",
                  running_at, HOG_PRIO, waited_us);
    }
}
