// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The lease worker (wave 11, LEASE3): revokes expired leases without the
//! lessor's help.
//!
//! The timer interrupt marks a lease `Expired` (`azos_ipc::lease_tick`)
//! but edits no page table: the PTE walk's kernel-table guard takes
//! `KERNEL_PT`'s plain lock, which a same-hart interrupt could deadlock on.
//! Until this worker existed the lessee's mapping went only when the lessor
//! woke in `lease_wait` or freed the lease, so a lessor that did neither left
//! an expired buffer writable by the lessee. The tick now also wakes this
//! task, which removes the expired leases' mappings (and gives a sealed
//! lessor its write back) from task context
//! (`azos_ipc::lease::lease_reap_expired`).
//!
//! It blocks on the wait queue with no deadline, so it costs nothing until a
//! lease with a deadline expires. A wake that lands before its block is
//! stamped, and the block returns at once (K-C9), so the reap after it never
//! misses an expiry.

use core::sync::atomic::{AtomicU32, Ordering};

/// The worker's TID, `0` before it runs. Read by both ISAs' timer interrupts.
static LEASE_WORKER_TID: AtomicU32 = AtomicU32::new(0);

/// Create the worker. Once, from `kernel_main`, before the first user task.
pub(crate) fn start_lease_worker() {
    let idx = azos_sched::task_create("lease-worker", lease_worker_task, 0,
                                          azos_sched::DEFAULT_PRIORITY);
    if let Some(tid) = azos_sched::tid_for_idx(idx) {
        LEASE_WORKER_TID.store(tid, Ordering::Release);
    }
}

/// From the timer interrupt, after `lease_tick` expired at least one lease:
/// wake the worker (it waits only on the wait queue).
#[inline]
pub(crate) fn wake_lease_worker() {
    let tid = LEASE_WORKER_TID.load(Ordering::Acquire);
    if tid != 0 {
        azos_sched::wq_wake_by_tid(tid);
    }
}

fn lease_worker_task(_: usize) {
    LEASE_WORKER_TID.store(azos_sched::current_task_tid(), Ordering::Release);
    loop {
        // The gate canary: the worker wakes and revokes nothing, so an
        // expired lessee keeps its mapping until its lessor acts.
        if !cfg!(feature = "lease-expiry-worker-canary") {
            let _ = azos_ipc::lease::lease_reap_expired();
        }
        azos_sched::wq_block_current();
    }
}
