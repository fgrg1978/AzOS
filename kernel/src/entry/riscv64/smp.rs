// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! riscv64 secondary-hart wake (the `wake_secondaries` hook): SBI HSM
//! `hart_start` per hart.

use core::sync::atomic::Ordering;
use azos_drv_sys::kprintln;

/// Start every secondary hart via SBI HSM `hart_start`, correct
/// `NUM_ONLINE_CPUS` down to the real count, and rescue any task an
/// optimistic pre-wake `task_create*` stranded on a hart that never came
/// up. Verbatim cut from the former riscv64 `kernel_main`'s own tail.
pub(crate) fn wake_secondaries(num_cpus: usize) {
    // Enable SMP UART lock before secondary CPUs can print.
    azos_drv_sys::uart::enable_smp_lock();
    kprintln!("[SMP] UART lock enabled");

    // Start secondary harts via SBI HSM hart_start (OpenSBI parks them by default).
    {
        kprintln!("[SMP] Starting {} secondary harts via SBI HSM...", num_cpus - 1);
        let online = unsafe { azos_sched::smp::wake_harts(num_cpus) };
        if online != num_cpus {
            azos_drv_sys::kwarn!(
                "[SMP] WARNING: only {}/{} harts started — degraded to {} online CPU(s)",
                online, num_cpus, online
            );
        }
        // Correct NUM_ONLINE_CPUS from the optimistic pre-boot estimate
        // (set above, before task creation, so the boot-time task_create
        // calls could spread across the intended CPU count) to the real
        // count wake_harts() confirmed. This is what protects any task
        // created from here on (e.g. fork() in crates/core/sched/src/process.rs)
        // from being load-balanced onto a hart that never came up — see
        // NUM_ONLINE_CPUS's doc comment in crates/core/sched/src/smp.rs.
        azos_sched::smp::NUM_ONLINE_CPUS.store(online, Ordering::SeqCst);

        // Rescue tasks that the *pre-boot optimistic* task_create calls
        // (above, before wake_harts() ran) assigned to a hart that then
        // failed to start — those per-CPU ready queues would otherwise sit
        // forever, since this scheduler has no runtime work-stealing
        // (verified: no steal/rebalance/migrate logic anywhere in
        // crates/core/sched/src/scheduler.rs). This is the only point in the
        // whole boot sequence where ready queues can be moved between CPUs
        // without racing another consumer: the boot hart hasn't called
        // sched::start() yet, hasn't enabled its own timer interrupt yet
        // (a few lines below), and dead harts by definition never run any
        // code at all. See `rebalance_from_offline_cpus`'s doc comment for
        // why it still routes every touch through the locked queue
        // wrappers regardless (an *alive* secondary hart can start ticking
        // independently of the boot hart's progress here).
        // **The condition is `online < MAX_CPUS`, NOT `online != num_cpus`.**
        //
        // The previous version assumed tasks can only be stranded when fewer
        // harts came up than the DTB promised. That is false: several tasks
        // are created with **explicit affinity** to a specific hart, and that
        // pin is not bounded by `num_cpus`. With `-smp 1`,
        // `online == num_cpus == 1`, the condition was false and the rescue
        // **was never called** — with six tasks, `autorun` among them, queued
        // on CPUs 1, 2 and 3.
        //
        // Measured before: `per_cpu_queues = [0, 3, 1, 2]`, and the ring-3 ELF
        // never executing a single instruction while the kernel looked
        // healthy.
        //
        // Every queue above `online` must be drained, whether or not the DTB
        // says that hart exists.
        if online < azos_sched::MAX_CPUS {
            azos_sched::rebalance_from_offline_cpus(online, num_cpus);
        }
    }
}
