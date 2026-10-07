// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

// AZOS Phase 1 W4 — multi-policy scheduler scaffolding.
// New code lives alongside the existing scheduler; integration into
// the live dispatch path is a separate wave.
//
// The whole W4 backend is behind the `sched-aps` cargo feature (see
// Cargo.toml). `class` stays unconditional: `Task::sched_class_raw` and the
// topology admission path use `SchedClass` whichever backend dispatches.
// `partitions` is gated too — its only consumer is `aps_state`.
#[cfg(feature = "sched-aps")]
pub mod aps_state;
pub mod class;
#[cfg(feature = "sched-aps")]
pub mod partitions;
#[cfg(feature = "sched-aps")]
pub mod policies;
// RFC-0002 runtime layer for the scheduler subsystem. Phase 1: typed
// wrapper over the existing legacy/APS toggle; reserved enum slots
// for the per-policy standalone backends that land in Phase 2+.
#[cfg(feature = "sched-aps")]
pub mod runtime;

pub mod donation;
pub mod filter;
pub mod task;
pub mod ready_list;
/// Wave 11 SCHED-RT: band budget and EDF + CBS arithmetic (host-tested).
pub mod rt_core;
pub mod timer_heap;
pub mod scheduler;
pub mod swcensus;
pub mod smp;
pub mod wait;
pub mod seccomp;
pub mod driver;
pub mod supervisor;
pub mod process;
/// Wave 13: process life-cycle phase profile (feature `fork-profile`).
pub mod prof;
/// `current_cpu_id()` cross-check against the hardware id (gate only).
#[cfg(feature = "cpuid-probe")]
pub mod cpuid_probe;
/// Wave 13: thread groups and futexes.
pub mod group;
pub mod futex;
pub mod spawn;
// RFC-0047 stage 3: riscv64 F/D state of Linux tasks.
pub mod fp;
pub mod spawn_policy;
pub mod user_window;

pub use scheduler::{
    init, start, schedule, task_create, task_create_affinity, try_task_create_affinity, free_task_slots,
    try_task_create_init,
    task_yield, task_preempt_deferred, task_exit, set_task_exit_hook, set_task_exit_late_hook, set_task_fork_hook,
    tid_holds_address_space, task_row, task_rows, task_visible_to, TaskRow,
    task_create_with_class, task_set_class, idx_for_tid, tid_for_idx, tid_is_exiting,
    aps_dispatch_enabled,
    mm_charge, mm_discharge, mm_reset_charge, set_current_user_page_limit,
    mm_discharge_tid, mm_charge_if_current, install_mm_hooks, take_current_pt_build,
    current_mem_policy, current_mem_locked, current_mem_report, mm_install_frames,
    set_task_mem, note_mm_quota_refusal,
    set_current_sched_params, current_sched_params, task_class_raw,
    task_user_pt, mm_charge_tid,
    current_user_pages, mm_quota_refusals, mm_peak_pages, mm_peak_global,
    current_task_name, current_task_tid, current_task_parent_tid, current_task_stack_top,
    current_task_switches, current_task_hart,
    current_user_pt, kernel_task_satp, current_proc_tid, current_task_satp,
    stack_canary_check, MAX_CPUS, STACK_CANARY,
    pi_boost_task, pi_restore_task, boost_ready_task, restore_ready_task, task_priority,
    donate_priority, return_donation, task_cpu_affinity,
    set_donation_floor_recorder, DONATIONS_FLOORED, LAST_DONATION,
    task_running_on_other_hart,
    task_exit_with_code, current_exit_code, take_exit_note, take_exit_note_for, WaitpidMiss,
    exit_stat,
    task_census, wake_counters, blocked_fastipc_ids, ready_unqueued_ids, unswitched, top_runtime,
    reap_stamped_sleepers, current_snapshot,
    alloc_asid,
    wq_block_current, wq_wake_by_tid,
    current_syscall_filter, current_syscall_filter_enabled, set_current_syscall_filter,
    set_task_syscall_filter, task_create_filtered,
    nearest_timer_deadline,
    rebalance_from_offline_cpus,
};

/// Wave 11 SCHED-RT: run-time admission of EDF + CBS reservations
/// (`rt::reserve`), their counters, and the band budget's.
pub use scheduler::rt;
pub use scheduler::stamp_pending;

/// RFC-0051 E1/E2: utilisation signals and the installed energy model
/// (kernel feature `energy`).
#[cfg(feature = "energy")]
pub use scheduler::energy;
pub use scheduler::RT_TICK_PREEMPTS;

/// Flips the live dispatch path to APS. Only exists when the APS backend is
/// compiled in; a Legacy build has nothing to flip to, and
/// `aps_dispatch_enabled()` is a `const fn` returning `false` there.
#[cfg(feature = "sched-aps")]
pub use scheduler::use_aps_dispatch;

/// K-C29 preemption-audit counters. Always compiled; `read()` returns
/// `(resched_deferred, yield_atomic, block_atomic, exit_atomic,
///   switch_atomic, last_block_offender_packed)`.
///
/// The old `preempt_disable` / `preempt_enable` / `preempt_disabled` trio was
/// exported from here and had no caller anywhere in the tree. The mechanism
/// now lives in `azos_sync::preempt`; see the deletion note in
/// `scheduler.rs` for the three defects that made re-using it a bad idea.
pub use scheduler::preempt_audit;

/// Only exists with the diagnostic counters compiled in.
#[cfg(feature = "ipc-census")]
pub use scheduler::top_sched_callers;

/// Times the `context_saving` spin-gate hit its deadline and handed the task
/// back. **Must stay zero**; always compiled, unlike the census counters.
pub use scheduler::spin_gate_expired;
pub use scheduler::prio_guard_no_switch;
pub use scheduler::ring_claim_audit;

/// `(long, long_with_bell, max_delay_ticks, measured)` — see
/// `scheduler::wakelat`.
#[cfg(feature = "ipc-census")]
pub fn wakelat_read() -> (u32, u32, u64, u32) { scheduler::wakelat::read() }

/// Canary proving `wakelat` was actually compiled into this crate.
#[cfg(feature = "ipc-census")]
pub fn wakelat_canary() -> u32 { scheduler::wakelat::CANARY }

/// `(ipi_sent, ipi_err, ipi_recv)` — see `scheduler::wakelat`.
#[cfg(feature = "ipc-census")]
pub fn wakelat_ipi() -> (u32, u32, u32) { scheduler::wakelat::ipi_read() }

/// Called from the kernel's `INT_SOFTWARE_S` trap arm.
#[cfg(feature = "ipc-census")]
pub fn wakelat_ipi_recv() { scheduler::wakelat::ipi_recv() }

/// `(tid, ready_site_byte, hart, b1, b2, b4, b8)` — see `scheduler::wakelat`.
#[cfg(feature = "ipc-census")]
pub fn wakelat_worst() -> (u32, u32, u32, u32, u32, u32, u32) {
    scheduler::wakelat::worst()
}

#[cfg(not(feature = "no-mmu"))]
pub use scheduler::{setup_stack_guard_pages, stack_guard_readback, stack_guard_addr};

pub use scheduler::{
    set_current_user_info, set_task_user_info, update_user_brk,
};

pub use task::{
    DEFAULT_PRIORITY, IDLE_PRIORITY, STACK_SIZE, MAX_TASKS,
    RT_MOTOR_PRIORITY, NET_POLL_PRIORITY, BEHAVIOR_PRIORITY,
    SENSOR_AHRS_PRIORITY, FLIGHT_CTRL_PRIORITY, WATCHDOG_PRIORITY,
    RT_PRIORITY_THRESHOLD, RT_TIME_SLICE_TICKS,
    WaitReason, SyscallFilter, TaskInit, SYSCALL_FILTER_MAX,
    UserRegs,
};

pub use driver::{
    driver_register, driver_set_mmio, driver_set_irq,
    // `driver_heartbeat` (no timestamp) was removed — see driver.rs for why.
    driver_start, driver_heartbeat_with_time,
    driver_on_crash, driver_on_crash_with_time, driver_check_health,
    driver_info, driver_count,
    driver_add_spawn_descriptor, driver_spawn_count, driver_spawn_descriptor,
    driver_spawn_register,
    DriverState, DriverEntry, DriverDescriptor, MmioRegion,
};

pub use wait::{
    task_block, task_block_outcome, BlockOutcome,
    wake_by_irq, wake_by_channel, wake_by_ring, wake_by_port,
    wake_expired_timers,
    wake_fast_ipc_server, wake_fast_ipc_client,
};

/// The shared-memory / MMIO VA window, `[base, limit)`.
///
/// Exported because `sys_munmap` has to release the task's own frames and must
/// not release the ones mapped here: `shm_map_user` and `mmio_map_user` install
/// real `USER` leaves whose frames belong to a device or to another task. The
/// exit path already skips exactly this window, and restating the bounds in the
/// syscall crate is how the two would drift.
pub fn user_shm_window() -> (usize, usize) {
    (process::USER_MMIO_BASE, process::USER_MMIO_LIMIT)
}

pub use process::{
    exec_user, exec_user_mem, MemSpec, take_current_task_exec_ctx, sret_to_user, ExecHandoff,
    copy_from_user, copy_to_user, copy_cstr_from_user, user_range_writable,
    user_range_prepare_write,
    sys_brk_impl,
    mmio_map_user, shm_map_user,
};

/// The per-CPU variables this crate keeps in the per-CPU areas (wave 15,
/// NRCPUS), for the kernel's `setup_per_cpu_areas`: the ready queues, the RT
/// band's reservation state and, with the APS backend, its policy tables.
/// Every one must be attached for every possible CPU before the first task is
/// created.
pub fn for_each_percpu_var(f: &mut dyn FnMut(&'static dyn azos_percpu::PerCpuVar)) {
    f(&scheduler::PER_CPU_QUEUES);
    f(&scheduler::rt::RT_CPU);
    #[cfg(feature = "sched-aps")]
    f(&aps_state::V2_STATE);
}
