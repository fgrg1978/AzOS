// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel tasks `kernel_main` creates once the scheduler is initialised
//! and before any secondary CPU runs, in its order: the two stretches of task
//! creation its boot smokes sit between (`smokes::spawn_sched_smokes`, then
//! `smokes::spawn_system_smokes`).

use crate::*;

/// The online-CPU estimate, one idle task per CPU, aarch64's scheduler
/// self-tests, sched-hooks smoke and system watchdog, and the recovery
/// console. Inlined, as every boot phase (see `boot`'s module doc).
#[inline(always)]
pub(crate) fn create_first_tasks(num_cpus: usize) {
    // Tell the scheduler how many CPUs are *expected* to come online so the
    // task_create calls below — which run before any secondary hart exists —
    // distribute evenly across all of them. This is an optimistic estimate
    // from the DTB, not a confirmation: secondary harts aren't started until
    // wake_harts() runs near the end of this function (after the UART SMP
    // lock is enabled and every task is enqueued — per-CPU ready queues
    // can't be touched cross-CPU once a hart is live). Once wake_harts()
    // reports how many harts actually started, NUM_ONLINE_CPUS is corrected
    // down to the real count so that later task creation (e.g. fork()) never
    // targets a hart that failed to start.
    azos_sched::smp::NUM_ONLINE_CPUS.store(num_cpus, Ordering::SeqCst);

    // One idle task per hart, each pinned to its own CPU.
    //
    // **WHY per-CPU and not the single CPU-0 idle this used to create.**
    // Ready queues are per-CPU, so a hart with an empty queue has nothing to
    // pick. `do_schedule` answers that by returning — and its comment says
    // "caller will idle", which is true for the timer-tick caller and **false
    // for `block_current`**, which returns through the syscall to ring 3. A
    // task that has already published `Blocked` therefore keeps executing: not
    // queued, not current anywhere the wakers look, and nobody will ever
    // dispatch it. Measured before this change: of 7850 blocks, **7830** hit
    // that return with the current task already `Blocked` (counters under
    // `ipc-census`; K-C26 genesis 2).
    //
    // With an idle per hart the queue is never empty, so `do_schedule` always
    // has something to switch to and a blocked task always yields its hart.
    // `IDLE_PRIORITY` is the lowest, so these never starve real work.
    //
    // `num_cpus` here is the DTB's optimistic count, taken before
    // `wake_harts()`. An idle pinned to a hart that never starts is harmless:
    // the K-C24 rescue moves tasks off dead harts, and a rescued idle is just
    // one more lowest-priority task.
    for cpu in 0..num_cpus {
        azos_sched::task_create_affinity(
            "idle", idle_task, 0, azos_sched::IDLE_PRIORITY, cpu as i8);
    }
    kprintln!("[SCHED] Created {} idle tasks (one per hart)", num_cpus);

    #[cfg(target_arch = "aarch64")]
    {
        // **Both on hart 0, pinned.** The property is two equal-priority
        // tasks sharing ONE hart and taking turns only because the scheduler
        // preempts them. Unpinned, placement put A on hart 0 and B on hart 1
        // and each ran alone: on `--features qemu` at `-smp 2` with the
        // ipctest disk, B sat on hart 1 behind `behavior` (priority 14,
        // rescued there from the absent hart 2) until A had finished all 60
        // iterations; without a disk B finished before A's first iteration.
        // Every such boot printed "did not interleave" (8/8 and 2/2). The rows
        // that passed booted without `qemu`: they passed by placement.
        // Boot self-tests (Kconfig BOOT_SELFTESTS), as the probe below.
        #[cfg(feature = "boot-selftests")]
        azos_sched::task_create_affinity(
            "phase3-a", phase3_task_a, 0, azos_sched::DEFAULT_PRIORITY, PHASE3_HART);
        #[cfg(feature = "boot-selftests")]
        azos_sched::task_create_affinity(
            "phase3-b", phase3_task_b, 0, azos_sched::DEFAULT_PRIORITY, PHASE3_HART);
        #[cfg(feature = "boot-selftests")]
        kprintln!("[SCHED] task A and task B created (priority {}, round-robin, \
                   {} iterations each, both on hart {})",
                   azos_sched::DEFAULT_PRIORITY, PHASE3_TARGET_ITERS, PHASE3_HART);

        // `install_sched_hooks`'s marker cluster — see that function's own doc.
        // Off by default (`sched-hooks-smoke` feature); compiles to nothing
        // otherwise. Spawned HERE, next to `phase3-a`/`phase3-b`, not right
        // after `install_sched_hooks()` above (riscv64's placement). Measured,
        // not assumed, that the earlier site does not work: spawned there, the
        // waitqueue task read back `counter at wake = 0` on every boot —
        // `wait()` returning long before the producer had done any work —
        // while the cap marker next to it read back correctly
        // from that same early point. THE CAUSE was not isolated (this ISA's
        // boot has enough moving parts between that point and this one — SMP
        // bring-up, GIC, the timer tick going live — that several are
        // plausible candidates and none was singled out); moved to here, all
        // three read back correctly on every boot tried (the gate row was
        // `aarch64: sched hooks`; the ktest `sched_hooks_wired` now).
        #[cfg(all(feature = "sched-hooks-smoke", not(feature = "ktest")))]
        sched_hooks_smoke::spawn();

        // Migration probe (item 7 of this task's brief) — a task that blocks
        // and is woken repeatedly, the ONLY placement path that can move an
        // unpinned task between cores (`crates/core/sched::scheduler::
        // wake_target_cpu` re-runs `find_best_cpu` on every wake;
        // `task_yield()` alone never does — see that function's own doc
        // comment). `phase3_task_a`/`b` above never block, so they cannot
        // migrate and are not evidence either way.
        #[cfg(feature = "boot-selftests")]
        azos_sched::task_create(
            "smp-migrate-probe", aarch64_migrate_probe_task, 0, azos_sched::DEFAULT_PRIORITY);
        #[cfg(feature = "boot-selftests")]
        kprintln!("[SCHED] Created smp-migrate-probe task");

        // Phase 16: the system watchdog — the SAME task riscv64 runs, from the
        // same shared `create_sys_wdt_task` (see its doc for the pin argument,
        // and `install_ota_boot_good_hook` above in the disk-gated block for the
        // half of this that closes the OTA rollback).
        //
        // HERE and not earlier, for two reasons that both have to hold:
        //   * it is a task, so it belongs with the other `task_create*` calls,
        //     after `NUM_ONLINE_CPUS` is published (a pin computed before that
        //     publish would be placed against a CPU count of 1) and before
        //     `wake_harts` below, whose rescue step can re-home anything the
        //     optimistic pre-wake placement stranded;
        //   * the hook it fires is installed further up this function, so
        //     "hook before spawn" holds on this ISA too.
        //
        // `num_cpus` is the same optimistic pre-`wake_harts` count the idle
        // tasks above are placed against, so a hart that fails to come up is
        // handled by that rescue and not by this line.
        create_sys_wdt_task(place::pin(place::SYS_WDT));
    }

    // Recovery console task: priority 13 (high normal — above workers, runs in RT task sleep gaps).
    // No CPU pin so it works on both 1-CPU and 4-CPU QEMU.
    //
    // It is the RECOVERY console. It parks until no user shell has
    // the console (`console_mode::wait_for_recovery`), and under
    // `CONSOLE_LOCKDOWN` or `RECOVERY_CONSOLE=n` it is not created at all.
    if azos_limits::CONSOLE_LOCKDOWN {
        kprintln!("[CONSOLE] lockdown: no kernel console task");
    } else if !azos_limits::RECOVERY_CONSOLE {
        kprintln!("[CONSOLE] no recovery console (RECOVERY_CONSOLE=n)");
    } else {
        azos_sched::task_create("recovery", recovery_task, 0,
                                azos_limits::TASK_RECOVERY_PRIORITY as u32);
        kprintln!("[SCHED] Created recovery task");
    }
}
