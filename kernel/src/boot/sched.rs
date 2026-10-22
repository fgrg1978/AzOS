// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Scheduler wiring: the hook table, the proxy-donation hooks, the task-exit
//! resource release, and the system watchdog task.

use crate::*;

/// `WaitQueue::wait_if_for`'s block: sleep on a timer for at most `slice_ns`,
/// a TID wake ([`wq_wake_timed`]) ending it early. Says whether the block
/// happened at all and whether the deadline had passed when it returned; a
/// block the scheduler refuses (a critical section is open) is `Refused`.
fn wq_block_for(slice_ns: u64) -> azos_sync::waitqueue::Slept {
    use azos_sync::waitqueue::Slept;
    let ticks = slice_ns.saturating_mul(azos_drv_sys::timebase::TIMER_FREQ) / 1_000_000_000;
    let deadline = azos_drv_sys::timebase::now().saturating_add(ticks);
    match azos_sched::task_block_outcome(azos_sched::WaitReason::Timer(deadline)) {
        azos_sched::BlockOutcome::Refused => Slept::Refused,
        azos_sched::BlockOutcome::Returned if azos_drv_sys::timebase::now() >= deadline => Slept::Expired,
        azos_sched::BlockOutcome::Returned => Slept::Woken,
    }
}

/// The wake of a task asleep in [`wq_block_for`] (on a timer, not on the wait
/// queue's reason): by TID, stamped when the task has not blocked yet, so a
/// wake between the sleeper's last look and its block is not lost.
fn wq_wake_timed(tid: u32) {
    azos_sched::scheduler::wake_task_by_tid(tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
}

/// Wire the four scheduler callbacks that `crates/core/sync`/`crates/core/sched`
/// register a function pointer for instead of depending on each other
/// directly, plus the exit hook that reclaims a dying task's resources.
///
/// Must run before any task can be woken, blocked, boosted, or can exit —
/// in practice, before `wake_harts()`/`scheduler::start()` on either ISA,
/// since task creation itself only enqueues (`install_topology` runs first
/// on both ISAs for the same "before anything spawns" reason, and this
/// follows immediately after `azos_sched::init()` on riscv64; aarch64
/// has no equivalent `init()` call at all — a separate, still-open gap,
/// not fixed by this function — so this is called as early as this
/// `kernel_main` safely can, right after `install_ring3_seams`).
///
/// Shared between both `kernel_main`s: riscv64 had all four calls inline
/// in its own body until this hoist; aarch64 never called any of them,
/// which is a silent-failure class distinct from `install_topology`'s
/// (that one halts the board on a REFUSED deadline admission — loud).
/// Every one of these degrades quietly instead:
///
///   - `preempt::set_resched_callback`: K-C29's deferred-preemption debt
///     is paid here when the outermost `PreemptGuard` drops with a tick
///     owed. INERT today on both ISAs — nothing constructs a guard until
///     `SpinLockGuard` carries one — registered anyway so the mechanism
///     is never half-wired (a deferral with no callback is a tick
///     silently dropped the day something does construct one).
///   - `azos_sched::set_task_exit_hook`: without it,
///     `task_release_all_resources` never runs on task exit, so typed
///     capabilities, legacy IPC handles, shared-memory references, file
///     descriptors and driver-server slots all leak silently on every
///     exit — `crates/core/sched/src/scheduler.rs`'s own doc for this hook
///     states there is no error and no failing test for the omission.
///   - `waitqueue::wq_set_callbacks`: without it, `WaitQueue::wait()`
///     degrades to a busy spinloop instead of blocking (`crates/core/sync/src/
///     waitqueue.rs`'s own doc, "safe for early boot" — but never
///     upgraded past that boot-time fallback on aarch64). This is what
///     `Completion` blocks on; it does NOT gate
///     `sys::sleep` (`crates/core/syscall/src/sleep.rs` blocks through
///     `task_block_outcome(WaitReason::Timer)` directly, not through a
///     WaitQueue), so `reflex`'s own 25 ms polling period is unaffected
///     by this particular gap — static analysis plus an empirical boot
///     (`aarch64: sched hooks` gate row exercises what this DOES fix; see
///     kernel/src/main.rs's task history for the reflex reboot check).
///
/// `task_release_all_resources` used to be `#[cfg(target_arch =
/// "riscv64")]` — dead code on aarch64 with no caller, same reasoning
/// `install_robot_hw`'s own doc gives for its own former gate — and lost
/// that `#[cfg]` in the same change that added this function, since it is
/// now called from both `kernel_main`s.
#[inline(always)]
pub(crate) fn install_sched_hooks() {
    // A deferred TICK preemption, paid at the guard drop: counted as one.
    azos_sync::preempt::set_resched_callback(azos_sched::task_preempt_deferred);
    // FX12: a FAT32 claim waiter (log-flush in fat32_fsync) lends its
    // priority to the claim's owner (fs-wb), so prio 13..19 load cannot
    // starve the owner while the waiter waits.
    azos_fs::fat32_claim_pi_hooks(&FAT_CLAIM_PI_HOOKS);
    // Kconfig LOCKDEP (owner rule F7): which task is real-time, by its base
    // priority (its class, not a donation). With LOCKDEP=y outside ktest
    // the `log-flush` task prints lockdep's reports (never a lock path).
    if azos_sync::lockdep::RT_CROSS_CPU {
        azos_sync::lockdep::set_rt_probe(|| {
            azos_sched::scheduler::current_task_base_priority() < azos_sched::RT_PRIORITY_THRESHOLD
        });
    }
    if azos_sync::lockdep::DRAIN_IN_LOG {
        azos_actuation::logger::logger_set_pass_hook(crate::lockdep_log::drain);
    }
    // W3-F7: this hook used to be `handle_revoke_all`, which cleans only the
    // legacy global handle table. Two other per-task resource classes leaked
    // through it: typed capabilities (`cap_store`, whose own doc claimed
    // task_exit reset it while having zero callers) and shared-memory
    // references. `task_release_all_resources` is the single entry point
    // that does all three; registering anything narrower here re-opens the
    // leak silently, because nothing reports an un-revoked capability.
    azos_sched::set_task_exit_hook(task_release_all_resources);
    // Wave 12 (EXIT2): what must wait for the dying task's address space to
    // go — the driver supervisor's wake.
    azos_sched::set_task_exit_late_hook(crate::drv_supervisor::exit_after_teardown);
    // Wave 15 (plan 4a): an exec from a thread that is not its process's
    // leader takes the leader's identity; what is kept per pool slot outside
    // `azos_sched` moves with it.
    azos_sched::set_task_identity_hook(task_identity_moved);
    // The component manager starts the console program, so the console's
    // start timeout begins at that `SYS_SPAWN_EX`, and the program gets its
    // console there (`console_mode::console_start`).
    azos_syscall::ushell::set_spawn_ex_hook(crate::console_mode::note_spawn_ex);
    azos_syscall::ushell::set_console_start_hook(crate::console_mode::console_start);
    // A MOVE, a revoke or a shrink of a MemObj removes a holder's mapping
    // through this hook. Before the first user task.
    azos_ipc::memobj::set_unmap_hook(mapping_unmap);
    // `SYS_MO_MAP`'s protect form changes a mapping's write permission
    // through this hook.
    azos_ipc::memobj::set_protect_hook(mapping_protect);
    // D4/L6: a MOVE of a MemObj capability hands the object's references,
    // charge and ownership to the receiver and removes the sender's mapping
    // (`azos_ipc::memobj::memobj_move`). Before the first user task.
    azos_ipc::cap_store::set_move_hook(azos_ipc::memobj::memobj_moved);
    // A revoked share loses its mapping: the sweep that revokes the
    // descendants of a warrant (`SYS_CAP_REVOKE`) hands each swept `Cap<Shm>` to
    // `azos_ipc::memobj::memobj_warrant_swept`, which unmaps the Domain's
    // holders on every hart and gives back their references. Before the first
    // user task.
    azos_ipc::cap_store::set_swept_hook(azos_ipc::memobj::memobj_warrant_swept);
    // Wave 11: a channel/io_ring port binding dies with the
    // capability it was made through and follows it when it moves
    // (`azos_ipc::port::port_cap_event`). Before the first user task.
    azos_ipc::cap_store::set_cap_event_hook(azos_ipc::port::port_cap_event);
    // KMEM-CHARGE: the capability table, endpoints and MemObjs a Domain owns
    // are charged to its kernel-memory ledger (`azos_sched::domain`), against
    // its row's `kmem_kib`. Before the first user task.
    azos_ipc::cap_store::set_kmem_hooks(kmem_charge, kmem_discharge);
    // D3/L4: a warrant's deadline is read against the monotonic clock the v2
    // call's deadline uses (`ipc_v2::sys_ipc_call_v2`). Before the first user
    // task: unset, a warrant with a deadline reads as expired.
    azos_ipc::cap::set_clock(cap_clock_ns);
    // B3: a `RECEIPT` caveat on a warrant is read against the flight
    // recorder's receipt index (what a device last did, O(1)). Unset, the
    // caveat finds no receipt and refuses. The two "no receipt" ages are one
    // value.
    const _: () = assert!(azos_actuation::logger::NO_RECEIPT_AGE == azos_ipc::cap::NO_RECEIPT);
    azos_ipc::cap::set_receipt_probe(azos_actuation::logger::receipt_ages);
    // Wave 15 N5 runtime canary: a dead server's in-service calls are never
    // completed with -EPEERDIED.
    if canary!("ipc-no-peer-died") {
        azos_ipc::ep_queue::canary_no_peer_died();
    }
    // Chain E stage a runtime canary: the IPC fast path (Kconfig
    // IPC_FASTPATH) is off, every call takes the ordinary path (ktest
    // `ipc_fastpath_taken_when_parked`; vsbench shows the ordinary cost).
    if canary!("ipc-force-slow") {
        azos_syscall::fastpath::force_slow();
    }
    // Chain E commit 9 runtime canaries (Kconfig IPC_FASTPATH_RESUME): no
    // resume point is left (ktest `ipc_fastpath_resumes_at_the_point`; vsbench
    // shows the unwound cost), or one is kept by a resume that did not use it
    // (ktests `ipc_fastpath_resume_point_*`).
    if !canary!("ipc-resume-off") {
        azos_syscall::fastpath::set_resume_stub(crate::entry::ipc_resume_stub());
    }
    if canary!("ipc-resume-stale") {
        azos_sched::scheduler::canary_ipc_resume_stale();
    }
    // N6 runtime canary: the dispatch-class walk runs its precedence
    // backwards (idle > fair > RT > DL > stop).
    if canary!("sched-class-invert") {
        azos_sched::sc::canary_invert_precedence();
    }
    // Wave 15 N9 runtime canary: a futex requeue wakes every waiter and
    // moves none (ktest `futex_requeue_wakes_one_not_the_herd`).
    if canary!("futex-requeue-wake-all") {
        azos_sched::futex::canary_requeue_wake_all();
    }
    // N6b runtime canary: a reservation is ranked inside its
    // level again (ktest `sched_dl_above_rt`).
    if canary!("sched-dl-in-level") {
        azos_sched::classes::canary_dl_in_level();
    }
    // N6b runtime canary: `SYS_SCHEDCTL` binds RT and DL without a time
    // warrant (ktest `schedctl_self_promotion_refused`).
    if canary!("schedctl-no-warrant") {
        azos_syscall::schedctl::canary_no_warrant();
    }
    // N12 runtime canary: an ASID rollover does not flush the TLB.
    if canary!("asid-rollover-noflush") {
        azos_sched::asid::CANARY_NO_ROLLOVER_FLUSH.store(true, core::sync::atomic::Ordering::Relaxed);
    }
    // N12b runtime canary: switch-ins do not record their hart in the
    // per-address-space hart mask.
    if canary!("tlb-space-mask-drop") {
        azos_arch_api::tlb_gen::CANARY_SPACE_MASK_DROP.store(true, core::sync::atomic::Ordering::Relaxed);
    }
    // N12c runtime canary: a re-tag takes a fresh ASID per thread instead of
    // the space's recorded one.
    if canary!("asid-per-thread") {
        azos_sched::asid::CANARY_ASID_PER_THREAD.store(true, core::sync::atomic::Ordering::Relaxed);
    }
    // Wave 15 N5b (Kconfig IPC_PORT_NOTICES): every send capability to an
    // endpoint is counted where a table slot changes, and an endpoint left
    // with none tells the port its server bound it to. Before the first
    // user task (the topology seed grants the first ones).
    if azos_limits::IPC_PORT_NOTICES {
        azos_ipc::cap::senders::set_hooks(azos_ipc::endpoint::sender_delta, azos_ipc::endpoint::flush_notices);
    }
    // Runtime canaries: a task's exit forgets its send capabilities; a gone
    // port source stays bound and silent.
    if canary!("ipc-no-senders-wipe") {
        azos_ipc::cap::senders::canary_no_wipe();
    }
    if canary!("port-no-vanish") {
        azos_ipc::port::canary_no_vanish();
    }
    // Wave 15 N11 runtime canary: a second reply on one reply warrant is
    // delivered instead of refused.
    if canary!("ipc-reply-twice") {
        azos_ipc::ep_queue::canary_reply_twice();
    }
    // Wave 15 N11b runtime canary: the v2 accept reads every call as v1.
    if canary!("ipc-v2-as-v1") {
        azos_syscall::ipc_v2::canary_as_v1();
    }
    // Wave 15 N11c runtime canary: the v1 accept takes a v2 call.
    if canary!("ipc-v1-takes-v2") {
        azos_ipc::ep_queue::canary_v1_takes_v2();
    }
    // N7: the wait graph's scheduler side, before the first task can block
    // on a graph object. Compiled out without `WAIT_GRAPH`.
    if azos_sync::waitgraph::ENABLED {
        azos_sync::waitgraph::register_sched(&azos_sched::classes::PI);
    }
    // N7 runtime canary: every wait-graph walk stops after one owner, so a
    // transitive chain is not boosted past its first link.
    if canary!("pi-depth-1") {
        azos_sync::waitgraph::canary_cap_depth(1);
    }
    // N8 runtime canary: `Mutex::unlocked_for_io` keeps the mutex across
    // the device wait (rule F1 broken); ktest `kmutex_unlocked_for_io` red.
    if canary!("kmutex-io-held") {
        azos_sync::kmutex::canary_io_held();
    }
    // N8b runtime canary: a contended release frees the word with a waiter
    // queued (the steal rule broken); ktest `kmutex_steal_rule_holds_for_top_waiter`.
    if canary!("kmutex-steal-any") {
        azos_sync::kmutex::canary_steal_any();
    }
    // Runtime canary: a held-back newcomer parks on its word alone, the
    // bucket's wake generation ignored, after a window that lets the queued
    // waiter take and release; the wake is lost (ktest
    // `kmutex_held_back_newcomer_is_in_the_graph`).
    if canary!("kmutex-park-aba") {
        azos_sync::kmutex::canary_park_aba();
    }
    // N7b runtime canary: the exit path keeps the task's wait-graph state
    // (ktest `waitgraph_exit_clears_state`).
    if canary!("exit-keeps-graph") {
        azos_sched::classes::canary_exit_keeps_graph();
    }
    // N7c runtime canary: an owner exiting with waiters only detaches its
    // objects, no OwnerDiedHook runs (ktest `kmutex_owner_died_wakes_waiter`).
    if canary!("owner-died-silent") {
        azos_sync::waitgraph::canary_owner_died_silent(true);
    }
    // N7d runtime canary: a dead Mutex holder stays in the held table
    // (ktest `kmutex_dead_holder_leaves_the_held_table`).
    if canary!("held-keeps-dead") {
        azos_sync::held::canary_held_keeps_dead();
    }
    // Owner decision 10-10: a dead claim owner stays in the F1 table (ktest
    // `claim_dead_owner_leaves_the_held_table`).
    if canary!("claim-held-keeps-dead") {
        azos_sync::claim::canary_held_keeps_dead();
    }
    // Rule F1: the gate feature `exec-bounce-pi-canary` makes the owner of
    // `EXEC_BOUNCE` keep the claim's exchange mutex, so a Mutex is held
    // across its image read; the `lat-fat` smoke's `pi_io_site` line names
    // `EXEC_BOUNCE`. (Runtime canary `claim-mutex-held` does the same for the
    // ktest's own claim, in the ktest.)
    if cfg!(feature = "exec-bounce-pi-canary") {
        azos_sync::claim::canary_mutex_held(azos_syscall::handlers::exec_bounce_addr());
    }
    // Owner decision 10-10: a wait-graph boost ignores the ring-3 floor
    // (ktest `waitgraph_ring3_owner_floored`).
    if canary!("pi-ring3-unclamped") {
        azos_sched::classes::canary_pi_ring3_unclamped();
    }
    // Wave 15 N7g: a fast call boosts its server through the wait graph
    // (ktest `waitgraph_ipc_call_boosts_server`); the canary takes no edge.
    if azos_sync::waitgraph::ENABLED && canary!("ipc-call-no-edge") {
        azos_ipc::fastcall::canary_ipc_call_no_edge();
    }
    // Runtime canary: a thread's exit drops a process signal pending on it.
    if canary!("sig-exit-drop") {
        azos_sched::scheduler::signal::canary_exit_drop();
    }
    // Owner decision 10-10: the robust exit walk keys a word of a shm region
    // by (region, offset), as the Linux personality keys a shared futex.
    if azos_sched::futex_table::SHARED {
        azos_sched::futex::register_shm_word_of(robust_shm_word_of);
    }
    // Wave 15 N10, Kconfig FUTEX_PI: the PI futex operations and the slot ->
    // TID map their words need, and the futex table's PiTable (N9) that runs
    // them under the key's lock for the Linux personality and the robust exit.
    // Runtime canary: a PI waiter never boosts the word's owner.
    if azos_sync::pi_futex::ENABLED {
        azos_sync::pi_futex::register_tid_of(pi_futex_tid_of);
        azos_sync::pi_futex::register(&azos_sync::pi_futex::PI_FUTEX);
        azos_sync::pi_futex::register_table(&azos_sched::futex::PI_TABLE);
        if canary!("futex-pi-no-edge") {
            azos_sync::pi_futex::canary_no_edge();
        }
        // N10b: an owner that exits holding a PI word with waiters hands it
        // to the top waiter (Linux exit_pi_state_list; the graph calls the
        // hook after the robust walk). Runtime canary: the hook does nothing.
        if azos_sync::waitgraph::ENABLED {
            azos_sync::waitgraph::register_owner_died(
                azos_sync::waitgraph::EdgeKind::FutexPi,
                &azos_sched::futex::PI_TABLE,
            );
        }
        if canary!("futex-pi-exit-silent") {
            azos_sync::pi_futex::canary_exit_silent();
        }
        if canary!("futex-requeue-pi-plain") {
            azos_sched::futex::canary_requeue_pi_plain();
        }
        if canary!("futex-requeue-pi-no-proxy") {
            azos_sched::futex::canary_requeue_pi_no_proxy();
        }
    }
    // Page tables charged to the task that owns them, and user
    // page faults counted per task. Before the first user address space.
    azos_sched::install_mm_hooks();
    // The fork-time mirror of the hook above. Without this,
    // `sys_fork_impl`'s `invoke_task_fork_hook` call finds nothing
    // registered and every forked child's cap table stays empty — silently,
    // same failure shape the exit hook's own doc warns about. See
    // `azos_ipc::task_fork_grant` and `azos_ipc::endpoint::
    // endpoint_inherit_at_fork` for the relation minted (owner_tid ==
    // parent_tid, not capability class).
    azos_sched::set_task_fork_hook(azos_ipc::task_fork_grant);
    azos_sync::waitqueue::wq_set_callbacks(
        azos_sched::wq_block_current,
        azos_sched::wq_wake_by_tid,
        // Per-CPU, deliberately: see `WQ_TID_FN`'s own note on why the
        // global current-tid is wrong the moment a second core exists.
        azos_sched::scheduler::current_task_tid,
    );
    // The timed half: a sleep that waits for another task or a device blocks
    // on a timer for at most one slice (`WaitQueue::wait_if_for`).
    azos_sync::waitqueue::wq_set_timed_callbacks(wq_block_for, wq_wake_timed);
    // Wave 15 N8: the kernel mutex's adaptive-spin probe and wait-graph ids.
    azos_sync::kmutex::set_probes(&KMUTEX_PROBES);
    // N7c, owner decision 10-10: a Mutex owner that exits holding it hands
    // it to its top waiter (EOWNERDEAD). No-op with WAIT_GRAPH n.
    azos_sync::kmutex::register_owner_died();
    // Owner rule (wave 15): an RT task never does block I/O. Dev builds
    // (Kconfig RT_BLOCK_IO_CHECK) panic at the block layer's entry.
    azos_drv_block::blkdev::set_rt_io_check(rt_block_io_check);
    // The block request layer charges a request to the calling task's Domain.
    azos_drv_block::blkdev::set_owner_source(block_request_owner);
    // A task that waits for a block request sleeps on a timer and is woken by
    // TID: the same pair the disk's completion interrupt uses, so no wait in
    // the request layer is unbounded.
    azos_drv_block::queue::set_sleep_hooks(super::blk_block_until, super::blk_wake);
    // ... and the bytes of every write the device completes to its ledger.
    azos_drv_block::write_observer::set_account(azos_sched::domain::add_written);
    // Owner rule (wave 15, C2): an RT caller of the kernel log only appends
    // to the console (Kconfig CONSOLE_RT_APPEND_ONLY); dev builds (Kconfig
    // RT_CONSOLE_WIRE_CHECK) panic if one waits for the wire.
    azos_drv_sys::uart::set_rt_console_hooks(rt_console_caller, rt_console_wire_check);
    // Gate canary `console-drop` (XC): the ktest probe's kernel line may not
    // wait for the console, and is dropped into the full deferred buffer.
    if canary!("console-drop") {
        azos_drv_sys::uart::set_console_wait_veto(console_drop_veto);
    }
    // Wave 15 (S1): a synchronous I2C transfer sleeps between the
    // controller steps of its own transaction (VisionFive 2 DesignWare).
    #[cfg(any(feature = "vf2", feature = "k1"))]
    azos_drv_bus::i2c::set_sleep_hook(i2c_sleep_us);
    // The flight recorder asks the same question: an RT caller of
    // `logger_flush` hands the flush to the `log-flush` task.
    azos_actuation::logger::logger_set_rt_probe(current_task_is_rt);
    // Kconfig BLK_IOSCHED_RT_DEADLINE: which block requests are of the
    // real-time class.
    azos_drv_block::queue::set_rt_class_source(block_request_serves_record);
    // A command that times out, and a device found dead, are decision records.
    crate::drv_supervisor::register_block_sink();
    // Kconfig DECISION_REFUSALS_DURABLE: a refusal that goes through
    // `azos_decision::record` also becomes a flight-recorder record. The
    // recorder defers an RT caller's write to the flusher, and the sink does
    // nothing until the recorder is armed.
    if azos_decision::DURABLE {
        azos_decision::set_durable_sink(azos_actuation::logger::decision_refusal_sink);
    }
    // The clock the records are stamped with (the ring's and the journal's)
    // and a capability denial's durable record is rate-limited on
    // (DECISION_DENY_DURABLE_PER_SEC): the timebase.
    if azos_decision::DURABLE || azos_decision::ON {
        azos_decision::set_clock(azos_drv_sys::timebase::now, azos_drv_sys::timebase::TIMER_FREQ);
        // Records are stamped on TAI (owner decision 16-10): the timebase plus
        // the offset the vDSO publishes once PTP or NTP has set it.
        azos_decision::set_tai_offset(|| azos_mm::vdso::clock_offsets().tai);
    }
    // The guards the CPU lacked at the `[ISA]` report leave their records now
    // that the sink and the clock exist.
    crate::boot::isa::record_fallbacks();
    // The user-driver proxy's block/wake/donation. Without it an in-kernel
    // client of a ring-3 driver refuses every call (`ProxyError::CannotBlock`)
    // — deliberately not a fallback to spinning, which would keep every
    // scenario green with the block path broken.
    azos_driver_server::reply_wait::set_proxy_hooks(&PROXY_HOOKS);
}

/// `azos_fs::ClaimPiHooks` (FX12): the scheduler's counted donation pair,
/// with its `donation_for` rule and ring-3 floor, and the graph id for
/// `WAIT_GRAPH` y.
static FAT_CLAIM_PI_HOOKS: azos_fs::ClaimPiHooks = azos_fs::ClaimPiHooks {
    donate: azos_sched::scheduler::donate_priority,
    give_back: azos_sched::scheduler::return_donation,
    graph_id: kmutex_graph_id,
};

/// `azos_sync::kmutex::Probes` (wave 15 N8). All lock-free: the TID's
/// published slot (`idx_for_tid`, O(1) on its hint) and the per-CPU current
/// task (O(NR_CPUS)).
static KMUTEX_PROBES: azos_sync::kmutex::Probes = azos_sync::kmutex::Probes {
    on_cpu: kmutex_on_cpu,
    graph_id: kmutex_graph_id,
    attr: kmutex_attr,
};

/// The steal rule's attribute: the graph's boost of the task if it holds
/// one, else its base attribute from the dispatch classes.
fn kmutex_attr(tid: u32) -> Option<azos_sync::waitgraph::PiAttr> {
    use azos_sync::waitgraph::SchedPi;
    let i = azos_sched::scheduler::idx_for_tid(tid)? as u32;
    Some(azos_sync::waitgraph::effective(i).unwrap_or_else(|| azos_sched::classes::PI.base_attr(i)))
}

fn kmutex_on_cpu(tid: u32) -> bool {
    azos_sched::scheduler::idx_for_tid(tid)
        .is_some_and(|i| azos_sched::scheduler::classes::on_cpu(i) != azos_sched::sc::NO_CPU)
}

fn kmutex_graph_id(tid: u32) -> Option<u32> {
    azos_sched::scheduler::idx_for_tid(tid).map(|i| i as u32)
}

/// The TID a PI futex word holds for scheduler slot `t` (Kconfig FUTEX_PI).
fn pi_futex_tid_of(t: u32) -> Option<u32> {
    azos_sched::scheduler::tid_for_idx(t as usize)
}

/// The robust walk's shm lookup (sched -> ipc): `(region, offset)` of the
/// word at `va` of process `proc_id`, if a shm region it maps holds it.
/// Takes `MEMOBJS` only; never called under the futex table lock.
fn robust_shm_word_of(proc_id: u32, va: u64) -> Option<(u32, u32)> {
    let (region, off, _) = azos_ipc::memobj::memobj_resolve_mapped(proc_id, usize::try_from(va).ok()?)?;
    Some((region, u32::try_from(off).ok()?))
}

/// `azos_ipc::memobj::ProtectHook`: take the write permission from
/// (`write == false`) or give it back to (`true`) the holder's user leaves in
/// the range, then shoot the range down on every hart
/// (`vmm::set_user_range_write`). Called with the MemObj table held, never
/// from an interrupt, as `mapping_unmap` is.
fn mapping_protect(root: usize, va: usize, pages: usize, write: bool) -> usize {
    let end = va.saturating_add(pages.saturating_mul(azos_arch::PAGE_SIZE));
    azos_mm::vmm::set_user_range_write(root, va, end, write)
}

/// `azos_ipc::memobj::UnmapHook`: remove a MOVE's, a revoke's or a shrink's
/// mapping from the holder's page table and shoot it down on every hart that may hold it. The skip
/// window is the whole range, so no frame is freed (`user_leaf_is_task_owned`
/// answers before `page_decref`): the frames are the region's, given back by
/// the booked reference afterwards. Called with the MemObj table held, never
/// from an interrupt: the walk's kernel-table guard takes `KERNEL_PT`'s plain
/// lock.
fn mapping_unmap(root: usize, va: usize, pages: usize) {
    let end = va.saturating_add(pages.saturating_mul(azos_arch::PAGE_SIZE));
    let _ = azos_mm::vmm::unmap_user_range_and_free(root, va, end, va, end);
}

/// `azos_driver_server::reply_wait`'s view of the scheduler: the notify
/// path's block and wake (`WaitReason::Timer(deadline)`, woken by TID with
/// the matching deadline — the timer sweep ends a wait nobody answers), and
/// the priority donation.
static PROXY_HOOKS: azos_driver_server::reply_wait::ProxyHooks =
    azos_driver_server::reply_wait::ProxyHooks {
        block: proxy_block,
        wake: proxy_wake,
        current_tid: azos_sched::scheduler::current_task_tid,
        #[cfg(not(feature = "proxy-donation-canary"))]
        donate: azos_sched::donate_priority,
        #[cfg(feature = "proxy-donation-canary")]
        donate: proxy_never_donates,
        undonate: azos_sched::return_donation,
        peer_running: azos_sched::task_running_on_other_hart,
    };

/// `proxy-donation-canary`: the proxy blocks and wakes as usual but never
/// donates. `proxy-pi-smoke` must then time out on every attempt.
#[cfg(feature = "proxy-donation-canary")]
fn proxy_never_donates(_donor: u32, _target: u32) -> bool {
    false
}

fn proxy_block(deadline: u64) -> bool {
    use azos_sched::{task_block_outcome, BlockOutcome, WaitReason};
    task_block_outcome(WaitReason::Timer(deadline)) == BlockOutcome::Refused
}

fn proxy_wake(tid: u32, deadline: u64) {
    azos_sched::scheduler::wake_task_by_tid(
        tid,
        &|r| matches!(r, azos_sched::WaitReason::Timer(d) if *d == deadline),
    );
}

/// Wave 15 (plan 4a): the process's per-slot state outside `azos_sched`
/// moves from the leader's slot `from` to the exec'ing thread's `to`, now
/// named `tid` (`scheduler::exec_take_over`): the seed row a fork reseeds
/// from. The capability table and the frame budget stay where they are, in
/// the process's domain.
fn task_identity_moved(from: usize, to: usize, tid: u32) {
    azos_syscall::natfork::hand_over(from, to, tid);
}

/// The dying task `tid`'s wheels: every wheel it still commands is stopped
/// (duty 0, coast) and the stop recorded with its reason; it does not latch
/// the e-stop (Kconfig `MOTOR_COMMANDER_EXIT_STOP`,
/// `azos_syscall::motor_commander`).
fn commander_exit_stop(tid: u32) {
    let (taken, stopped) = azos_syscall::motor_commander::exit_stop(tid);
    if taken != 0 {
        #[cfg(all(feature = "ktest", feature = "use-robot"))]
        crate::smokes::commander_exit::note_stopped(tid);
        use azos_actuation::{estop, logger};
        let detail = estop::commander_lost_detail(tid, taken);
        let _ = logger::log_safety_violation_durable(
            logger::SAFETY_ESTOP, estop::ESTOP_ACTION_COMMANDER_LOST, detail);
        azos_drv_sys::kwarn!(
            "[MOTOR] commander tid {} exited: wheels {:#x} SAFE STOP (duty 0 on {:#x}; SAFETY_ESTOP action {} detail {:#x}, not latched)",
            tid, taken, stopped, estop::ESTOP_ACTION_COMMANDER_LOST, detail);
    }
}

/// Release every per-task resource when a task dies.
///
/// The exit hook takes a single `fn(u32)`, and two crates need to clean up:
/// `azos_ipc` (legacy handles, typed caps, shared-memory references) and
/// `azos_net` (sockets). Neither can call the other — `crates/net/net` is
/// deliberately scheduler-agnostic and `crates/core/ipc` has no business knowing
/// about sockets — so the kernel is the only place the two can be joined.
///
/// **Ordering is deliberate: IPC first, sockets second.** `socket_release_all`
/// is not pure bookkeeping — for a socket in `Established`/`CloseWait` it
/// TRANSMITS a FIN synchronously through the NIC. Doing that after the
/// capability teardown means a task cannot be holding a half-revoked
/// capability while its connection is still being closed on the wire.
///
/// **Do not move this hook later in `task_exit`.** `cap_store::reset` resolves
/// the TID back to a task-pool slot and only works while `TASK_VALID[idx]` is
/// still true; the hook fires before the Zombie marking and long before
/// `do_schedule` frees the slot. Moved past either point it becomes a silent
/// no-op, which is exactly the failure mode this cleanup exists to prevent.
///
/// Shared between both ISAs since `install_sched_hooks` registers this on
/// both — nothing in the body below is riscv64-specific (every crate it
/// calls, `azos_syscall`/`azos_ipc`/`azos_net`/
/// `azos_driver_server`, is a plain `[dependencies]` entry in
/// `kernel/Cargo.toml`, not ISA-gated). The `#[cfg(target_arch =
/// "riscv64")]` this used to carry existed only because aarch64 had no
/// caller, same as `install_robot_hw`'s former gate.
fn task_release_all_resources(tid: u32) {
    let t_ph = azos_sched::prof::t();
    // Wave 15 (owner decision): a ring-3 task that dies commanding a wheel
    // leaves it at a SAFE STOP (duty 0), first of all: before every release
    // below, the file writeback above all, which can wait on the disk while
    // the wheel would keep turning (`commander_exit_stop`). Runtime canary
    // `commander-exit-late`: the stop runs after the releases instead (ktest
    // `motor_commander_exit_stops_its_wheels`).
    let stop_late = canary!("commander-exit-late");
    if !stop_late {
        commander_exit_stop(tid);
    }
    // A `mem = "locked"` task reports its page faults when it
    // exits, the dying task being the current one here. The gate reads the
    // NUMBER: a locked task must end with `faults=0`.
    {
        let (faults, peak, locked) = azos_sched::current_mem_report();
        if locked {
            kprintln!("[MEM] locked task {} exits: faults={} peak={} pages", tid, faults, peak);
        }
    }
    // The dying task's shared file mappings go back to their files while the
    // object bookings that mark their pages dirty still stand (the references
    // are given back by `task_release_all` below).
    azos_syscall::file_map::exit_writeback(tid);
    // The queues the dying task attached to a `Uart` port or an `Adc` channel
    // end with it (`azos_syscall::devices`).
    azos_syscall::devices::release_all(tid);
    // The display server's claim on the screen ends with it: the text console
    // draws again and the surfaces it attached are let go (`azos_syscall::display`).
    azos_syscall::display::release_all(tid);
    #[cfg(all(feature = "ktest", feature = "use-robot"))]
    crate::smokes::commander_exit::note_released(tid);
    if stop_late {
        commander_exit_stop(tid);
    }
    // Is this a supervised driver the kernel will restart? Then
    // its driver-server slot, its named endpoints and its service names are
    // HELD for the successor instead of released (everything else is released
    // as for any task). Decided first; the supervisor is woken last, once
    // everything it will hand over is held.
    let sup = drv_supervisor::exit_verdict(tid);
    let held = sup.holds();
    let code = azos_sched::current_exit_code();
    // The named endpoints of a child the component manager starts again are
    // kept too (`console_mode::manager_restarts`): the manager, not the
    // kernel's supervisor, restarts every ring-3 row but its own.
    let keep_endpoints = held || crate::console_mode::manager_restarts(tid, code);
    // The console's input owner (the user shell) releases it here,
    // and the console mode learns whether a successor is coming.
    if azos_drv_sys::uart::CONSOLE_RX.release(tid) {
        crate::console_mode::user_shell_exited(tid, held || crate::console_mode::restart_expected(tid, code));
    }
    // Wave 13: a job the input was lent to gives it back, and its signal
    // words go (nothing is delivered to a task that has exited).
    let _ = azos_drv_sys::uart::CONSOLE_RX.end_lend(tid);
    azos_sched::scheduler::signal::detach(tid);
    // Children spawned with `SPAWN_F_DIE_WITH_PARENT` stop with
    // it, and a forced stop that ended this task is settled.
    let orphans = azos_sched::scheduler::stop_die_with_parent_children(tid);
    if orphans > 0 {
        kprintln!("[KILL] {} child(ren) of tid {} stopped with it (die-with-parent)", orphans, tid);
    }
    let _ = azos_sched::scheduler::take_current_forced_exit();
    // The dying task's slot, resolved once for the per-slot releases below;
    // valid until the slot is freed, long after this hook.
    let slot = azos_sched::scheduler::idx_for_tid(tid);
    if let Some(idx) = slot {
        azos_sched::scheduler::seal_forced_stop(idx, tid);
        // The slot's endpoint resolve cache goes with its task (Kconfig
        // IPC_RESOLVE_CACHE; a later task in the slot would miss on its TID
        // anyway).
        azos_ipc::endpoint::resolve_cache::clear(idx);
    }
    // A task killed mid-flood must not take its suppressed-denial count with it.
    azos_syscall::handlers::cap_denial_task_exit(tid);
    // A supervised driver's endpoints are held for its successor.
    azos_sched::prof::add(22, t_ph);
    let t_ph = azos_sched::prof::t();
    if keep_endpoints {
        azos_ipc::task_release_all_supervised(tid);
    } else {
        azos_ipc::task_release_all(tid);
    }
    azos_sched::prof::add(18, t_ph);
    let t_ph = azos_sched::prof::t();
    azos_net::socket_release_all(tid);
    azos_sched::prof::add(20, t_ph);
    let t_ph = azos_sched::prof::t();
    // File descriptors were the one object table this hook did not reclaim,
    // because `FileDesc` had no owner field to reclaim by. A ring-3 task that
    // opened a file and was then killed — by the watchdog, by a fault, by
    // anything that is not a clean `exit` — left its slot in use forever,
    // against a table sized for the whole machine. Nothing could even
    // attribute the leak, since there was no owner recorded.
    //
    // Goes through the `FileOps` seam rather than touching a table directly:
    // this crate is the composition root, but `crates/core/syscall` is core and
    // must not learn that a descriptor table exists.
    if let Some(ops) = azos_syscall::file_ops::file_ops() {
        let freed = ops.release_all(tid);
        if freed > 0 {
            kprintln!("[FS] reclaimed {} fd(s) from task {}", freed, tid);
        }
    }
    // Wave 15 (COHERENCE-AUDIT, dead client): a Linux module server's
    // unused verification tokens go with it instead of holding a slot until
    // some later grant evicts them.
    #[cfg(feature = "lx-server")]
    {
        let tokens = azos_syscall::module_ops::module_tokens_release(tid);
        if tokens > 0 {
            kprintln!("[LX] dropped {} module token(s) of task {}", tokens, tid);
        }
    }
    // Driver-server slots. Nothing released these either: a ring-3 driver that
    // crashed left its slot `active` forever, and now that the traffic is
    // owner-checked that would make the kind permanently unclaimable — every
    // client paying the proxy's full reply timeout before giving up.
    //
    // A supervised driver's slot is orphaned instead: still registered, its
    // queue kept, handed to the successor by the supervisor.
    azos_sched::prof::add(19, t_ph);
    let t_ph = azos_sched::prof::t();
    if held {
        let drv = azos_driver_server::driver_orphan_all(tid);
        if drv > 0 {
            kprintln!("[DRV] held {} driver slot(s) of task {} for its successor", drv, tid);
        }
    } else {
        let drv = azos_driver_server::driver_release_all(tid);
        if drv > 0 {
            kprintln!("[DRV] released {} driver slot(s) from task {}", drv, tid);
        }
    }
    drv_supervisor::exit_done(tid, sup);
    azos_sched::prof::add(21, t_ph);
}

/// Create the Phase 16 system watchdog. Both ISAs, one call site each.
///
/// `hart` is the pin, and it is a PARAMETER rather than a constant because
/// the two ISAs do not have the same harts. riscv64 passes a literal 2 — see
/// `WATCHDOG_PRIORITY`'s measured four-run matrix for why the pin and the
/// priority are both load-bearing there, and why hart 2 specifically (its
/// only other resident is `behavior` at 14). aarch64 boots gate rows at
/// `-smp 2`, where a literal 2 names a hart that never comes online and the
/// task would sit in a queue nothing drains — the same stale-pin hazard
/// `net_poll_task`'s own comment documents on that ISA — so it passes
/// `min(2, dtb_num_cpus - 1)`: hart 2 wherever the board has one, the last
/// online hart otherwise.
///
/// The priority is NOT a parameter. 11 is a property of what the task
/// carries, not of the board: inside the RT band so a canary sweep is not
/// cut in half by the tick, and below the two control loops at 8 so the
/// watchdog can never preempt the actuation it supervises.
pub(crate) fn create_sys_wdt_task(hart: i8) {
    let idx = azos_sched::task_create_affinity(
        "sys-wdt", system_wdt_task, 0, azos_sched::WATCHDOG_PRIORITY, hart);
    // It latches the actuators on a stack overflow: in the safety path, so
    // exempt from the RT band budget like the control loops (wave 11).
    azos_sched::rt::exempt_from_band_cap(idx);
    kprintln!("[SCHED] Created sys-wdt task (Phase 16: canaries + timer liveness) \
               [hart {}]", hart);
    // Owner rule (wave 15): an RT task never does block I/O. The watchdog
    // above is RT (11): its periodic flush, its durable e-stop records and
    // the OTA boot-good mark go to this task, outside the RT band. Created
    // with it so every kernel that runs the watchdog runs the flusher.
    azos_sched::task_create(
        "log-flush", azos_actuation::logger::logger_flusher_task, 0,
        azos_limits::LOG_FLUSHER_PRIORITY as u32);
    kprintln!("[SCHED] Created log-flush task (prio {})", azos_limits::LOG_FLUSHER_PRIORITY);
    // Runtime canary: the latching record's durable write is deferred past
    // any kill (logger.rs `LOG_CANARY_LATCH_DEFER`).
    if canary!("log-latch-defer") {
        azos_actuation::logger::logger_canary_latch_defer();
    }
    // Runtime canary: FAT32 claim waiters lend no priority (fat32.rs
    // `ClaimPi`; ktest `fat_claim_waiter_donates_to_owner`).
    if canary!("claim-no-donate") {
        azos_fs::fat32_canary_claim_no_donate();
    }
}

/// The `fs-wb` task's TID once it runs (0 before): the watermark waker's target.
static FS_WB_TID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Set by a writer that crossed the dirty watermark; ends the task's sleep.
static FS_WB_KICK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub(crate) fn fs_wb_now_ms() -> u64 {
    azos_drv_sys::timebase::now() / (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1)
}

/// The watermark waker of FAT32's cache and of the page cache (any task
/// context, no lock held).
pub(crate) fn fs_wb_wake() {
    use core::sync::atomic::Ordering::SeqCst;
    if FS_WB_KICK.swap(true, SeqCst) { return; }
    let tid = FS_WB_TID.load(SeqCst);
    if tid != 0 {
        azos_sched::scheduler::wake_task_by_tid(tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
    }
}

/// Kconfig `FS_WRITEBACK`: the task that writes the FAT32 cache's dirty lines
/// back (`azos_fs::fat32_writeback_tick`) every quarter of
/// `FS_WRITEBACK_MAX_AGE_MS`, or at once when a writer crosses
/// `FS_WRITEBACK_WATERMARK_PCT`. Never RT (owner rule: an RT task never does
/// block I/O). Created by `kernel_main` on every ISA once FAT32 is mounted;
/// with the option off it is not created.
fn fs_writeback_task(_: usize) {
    use core::sync::atomic::Ordering::SeqCst;
    FS_WB_TID.store(azos_sync::waitqueue::caller_tid(), SeqCst);
    // Evidence for the interrupt-driven disk (wave 15, `boot::blk_irq`): one
    // read from task context, then the driver's counts. Taken > 0 and slept
    // > 0: a waiter slept and the line woke it.
    if azos_drv_virtio::virtio::blk::irq_mode() {
        let mut s0 = [0u8; 512];
        let _ = azos_drv_block::blkdev::read_quiet(0, 1, &mut s0);
        let (taken, slept) = azos_drv_virtio::virtio::blk::blk_irq_counts();
        kprintln!("[VIRTIO-BLK] by interrupt: {} taken, {} waits slept", taken, slept);
    }
    // The same evidence for an NVMe boot disk (Kconfig DRV_NVME): a read of
    // sector 0 from task context, a flush, then the MSI counts. `taken` > 0
    // and `slept` > 0 show the completion interrupt woke a sleeping waiter.
    #[cfg(feature = "nvme")]
    if azos_drv_block::nvme::irq_mode() {
        let mut s0 = [0u8; 512];
        let rd = azos_drv_block::blkdev::read_quiet(0, 1, &mut s0).is_ok();
        let fl = azos_drv_block::blkdev::flush();
        let (taken, slept) = azos_drv_block::nvme::irq_counts();
        kprintln!("[NVME] by interrupt: {} taken, {} waits slept (read {}, flush {:?}, sig {:02x}{:02x})",
            taken, slept, if rd { "ok" } else { "FAILED" }, fl, s0[510], s0[511]);
        nvme_prp_selftest();
    }
    // The same evidence for a SATA boot disk (Kconfig DRV_AHCI).
    #[cfg(feature = "ahci")]
    if azos_drv_block::ahci::irq_mode() {
        let mut s0 = [0u8; 512];
        let rd = azos_drv_block::blkdev::read_quiet(0, 1, &mut s0).is_ok();
        let fl = azos_drv_block::blkdev::flush();
        let (taken, slept) = azos_drv_block::ahci::irq_counts();
        kprintln!("[AHCI] by interrupt: {} taken, {} waits slept (read {}, flush {:?}, sig {:02x}{:02x})",
            taken, slept, if rd { "ok" } else { "FAILED" }, fl, s0[510], s0[511]);
    }
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    loop {
        FS_WB_KICK.store(false, SeqCst);
        // io_ring OP_FSYNC (K1): a flush asked for runs now, whatever the
        // age, and its completions are posted from here.
        if azos_fs::fat32_flush_service() {
            azos_ipc::io_ring::io_ring_flush_posted();
        }
        azos_fs::fat32_writeback_tick(fs_wb_now_ms());
        let end = azos_drv_sys::timebase::now() + azos_fs::fat32_writeback_period_ms() * per_ms;
        while azos_drv_sys::timebase::now() < end && !FS_WB_KICK.load(SeqCst) {
            azos_sched::task_block(azos_sched::WaitReason::Timer(end));
        }
    }
}

/// The `ioring-wk` task's TID once it runs (0 before).
static IORING_WK_TID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Set by a hand-off; ends the worker's sleep.
static IORING_WK_KICK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The io_ring worker's waker (any task context, no lock held): an RT
/// submitter's pass handed a ring off (`io_ring_worker_pass`).
fn ioring_wk_wake() {
    use core::sync::atomic::Ordering::SeqCst;
    if IORING_WK_KICK.swap(true, SeqCst) { return; }
    let tid = IORING_WK_TID.load(SeqCst);
    if tid != 0 {
        azos_sched::scheduler::wake_task_by_tid(tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
    }
}

/// Kconfig `IORING_WORKER`: runs the file entries (and the passes behind
/// them) that a real-time submitter may not run itself (owner rule: RT only
/// enqueues). Never RT. Sleeps until kicked; the 100 ms bound only covers a
/// kick that raced the sleep's start.
fn ioring_worker_task(_: usize) {
    use core::sync::atomic::Ordering::SeqCst;
    IORING_WK_TID.store(azos_sync::waitqueue::caller_tid(), SeqCst);
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    loop {
        IORING_WK_KICK.store(false, SeqCst);
        azos_ipc::io_ring::io_ring_worker_pass();
        let end = azos_drv_sys::timebase::now() + 100 * per_ms;
        while azos_drv_sys::timebase::now() < end && !IORING_WK_KICK.load(SeqCst) {
            azos_sched::task_block(azos_sched::WaitReason::Timer(end));
        }
    }
}

/// Create the io_ring worker (Kconfig `IORING_WORKER`, every ISA, disk or
/// not) and arm the `ioring-rt-inline` runtime canary.
pub(crate) fn create_ioring_worker_task() {
    if canary!("ioring-rt-inline") {
        azos_syscall::ioring_ops::RT_INLINE_CANARY.store(true, core::sync::atomic::Ordering::SeqCst);
    }
    if !azos_limits::IORING_WORKER { return; }
    azos_syscall::ioring_ops::set_worker_wake(ioring_wk_wake);
    azos_sched::task_create(
        "ioring-wk", ioring_worker_task, 0, azos_limits::IORING_WORKER_PRIORITY as u32);
    kprintln!("[SCHED] Created ioring-wk task (prio {})", azos_limits::IORING_WORKER_PRIORITY);
}

fn rcu_now_ms() -> u64 {
    azos_drv_sys::timebase::now() / (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1)
}

/// A grace-period waiter's sleep (`qsbr::set_hooks`): a timer block.
fn rcu_sleep_ms(ms: u64) {
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    let due = azos_drv_sys::timebase::now().saturating_add(ms.saturating_mul(per_ms));
    azos_sched::task_block(azos_sched::WaitReason::Timer(due));
}

fn rcu_callback_task(_: usize) {
    azos_sync::qsbr::callback_task()
}

/// Kconfig RCU_QSBR (wave 15 N4): the clock and sleep of grace-period
/// waiters, and the callback task, pinned to the lowest CPU outside
/// RCU_NOCBS_CPUS (every ISA). Arms the `rcu-free-no-grace` runtime canary.
pub(crate) fn create_rcu_callback_task() {
    if !azos_sync::qsbr::ON { return; }
    if canary!("rcu-free-no-grace") {
        azos_sync::qsbr::canary_free_without_grace();
    }
    azos_sync::qsbr::set_hooks(rcu_now_ms, rcu_sleep_ms);
    let cpu = match azos_sync::qsbr::callback_cpu() {
        Some(c) => c,
        None => {
            azos_drv_sys::kwarn!("[RCU] RCU_NOCBS_CPUS {:#x} names every CPU: callbacks run on CPU 0",
                azos_sync::qsbr::NOCBS_CPUS);
            0
        }
    };
    azos_sched::task_create_affinity("rcu-cb", rcu_callback_task, 0,
        azos_limits::RCU_CALLBACK_PRIORITY as u32, cpu as i8);
    kprintln!("[SCHED] Created rcu-cb task (prio {}, CPU {}, nocbs {:#x})",
        azos_limits::RCU_CALLBACK_PRIORITY, cpu, azos_sync::qsbr::NOCBS_CPUS);
}

pub(crate) fn create_fs_writeback_task() {
    if !azos_limits::FS_WRITEBACK { return; }
    azos_fs::fat32_writeback_hooks(fs_wb_now_ms, fs_wb_wake);
    azos_sched::task_create(
        "fs-wb", fs_writeback_task, 0, azos_limits::FS_WRITEBACK_PRIORITY as u32);
    kprintln!("[SCHED] Created fs-wb task (prio {}, age {} ms, watermark {}%)",
        azos_limits::FS_WRITEBACK_PRIORITY, azos_limits::FS_WRITEBACK_MAX_AGE_MS,
        azos_limits::FS_WRITEBACK_WATERMARK_PCT);
}

/// Whether the task running on this CPU is real-time: its own (base)
/// priority is in the RT band. A donation does not make a task RT.
fn current_task_is_rt() -> bool {
    azos_sched::RT_PRIORITY_THRESHOLD > azos_sched::scheduler::current_task_base_priority()
}

/// The console's "is the caller real-time" question (`uart::RT_CALLER_*`):
/// the task running on this CPU has its own priority in the RT band. Gate
/// canary `rt-console-own`: the canary's task is told to wait for the wire.
fn rt_console_caller() -> u8 {
    if !current_task_is_rt() {
        return azos_drv_sys::uart::RT_CALLER_NONE;
    }
    if (canary!("rt-console-own") || canary!("rt-console-own-user"))
        && crate::canary_rt::RT_CONSOLE_TID.load(core::sync::atomic::Ordering::Relaxed)
            == azos_sched::current_task_tid()
    {
        return azos_drv_sys::uart::RT_CALLER_CANARY;
    }
    azos_drv_sys::uart::RT_CALLER_RT
}

/// Gate canary `console-drop`: is the caller the ktest probe it applies to?
fn console_drop_veto() -> bool {
    let tid = crate::canary_rt::CONSOLE_DROP_TID.load(core::sync::atomic::Ordering::Relaxed);
    tid != 0 && tid == azos_sched::current_task_tid()
}

/// Kconfig `RT_CONSOLE_WIRE_CHECK`: an RT task is about to wait for room on
/// the console wire. Panics naming the task (dev builds only). Not once a
/// panic is under way: the panic report goes out synchronously by design.
fn rt_console_wire_check() {
    if current_task_is_rt() && !azos_common::is_panicked() {
        panic!("[RT-CONSOLE] tid {} '{}' (base prio {}) waited for the console wire: \
                an RT task only appends",
            azos_sched::current_task_tid(), azos_sched::current_task_name(),
            azos_sched::scheduler::current_task_base_priority());
    }
}

/// A synchronous I2C transfer's wait between controller steps: sleep `us`
/// if this context may sleep (a task, preemption on, interrupts on), else
/// return `false` and the caller steps again at once (early boot, a caller
/// under a spinlock).
#[cfg(any(feature = "vf2", feature = "k1"))]
fn i2c_sleep_us(us: u64) -> bool {
    use azos_arch::Interrupts;
    if azos_sched::current_task_tid() == 0
        || azos_sync::preempt::depth() != 0
        || !azos_arch::ARCH.interrupts_enabled()
    {
        return false;
    }
    let ticks = (azos_drv_sys::timebase::TIMER_FREQ * us / 1_000_000).max(1);
    azos_sched::task_block(azos_sched::WaitReason::Timer(azos_drv_sys::timebase::now() + ticks));
    true
}

/// Kconfig `RT_BLOCK_IO_CHECK`: the block layer's entry check. A task whose
/// own (base) priority is in the RT band has reached the disk — the owner
/// rule says it never does; its records go through the logger's ring and the
/// `log-flush` task. Panics naming the task (dev builds only; the option is
/// off in every deployment profile, where nothing registers this). Not once
/// a panic is under way: the panic path's crash-log dump is the one disk
/// write a dying RT task makes.
fn rt_block_io_check() {
    if current_task_is_rt() && !azos_common::is_panicked() {
        panic!("[RT-IO] tid {} '{}' (base prio {}) entered the block layer: \
                an RT task never does block I/O",
            azos_sched::current_task_tid(), azos_sched::current_task_name(),
            azos_sched::scheduler::current_task_base_priority());
    }
}

/// Kconfig `BLK_IOSCHED_RT_DEADLINE`: does the block request made now serve a
/// durable flight-recorder record (the e-stop latch, the release nonce floor,
/// a decision refusal) that waits for the medium? The flush that carries it,
/// or a write-back pass of the FAT32 cache its lines go through (the `fs-wb`
/// task, or any task that runs a pass meanwhile).
fn block_request_serves_record() -> bool {
    azos_actuation::logger::rt_request_class_now()
        || (azos_fs::fat32_wb_pass_here() && azos_actuation::logger::durable_record_pending())
}

/// The Domain a block request made now is for: the running task's (0, which
/// the block layer reads as the kernel, in a context with none).
fn block_request_owner() -> u32 {
    azos_sched::scheduler::current_task_slot().map_or(0, |(idx, _)| azos_sched::task_domain(idx))
}

// The accessors of "the task running here" (`current_task_slot`,
// `current_proc_tid`, `current_user_pt`, the syscall-filter verdicts, the
// writer `set_current_task_satp`, ...) read the hart id and then a per-hart
// table; a tick between the two moves the task and the second read returns
// another hart's task (found 2026-10-20: a kernel page fault copying to a
// user VA). Late: the runner calls each, every one opens the masked window
// (`on_this_hart`) and returns what its own slot holds. Canary cargo feature
// `percpu-accessor-race-canary` (no mask): `not ok`.
#[cfg(feature = "ktest")]
mod percpu_accessor_ktests {
    azos_ktest::ktest_late! {
        fn percpu_accessors_read_masked() {
            azos_sched::scheduler::accessor_audit::ktest_accessor_contracts()
        }
    }
}

// N6: the dispatch-class model. Early: the precedence walk takes stop > DL >
// RT > fair > idle, a compiled-out class is skipped, preemption across
// classes follows precedence. Late: the running task's SC holds the class its
// priority puts it in (the hooks fired) and this CPU's live walk finds a
// runnable task. Canary `canary=sched-class-invert` (the walk runs
// backwards): `sched_class_precedence` is `not ok`.
#[cfg(feature = "ktest")]
mod sched_class_ktests {
    use azos_sched::sc::{pick_in_precedence, should_preempt, Class, ClassTable, SchedClassOps};

    struct Stub(Class, Option<usize>);
    impl SchedClassOps for Stub {
        fn class(&self) -> Class { self.0 }
        fn enqueue(&self, _: usize, _: usize) -> bool { false }
        fn dequeue(&self, _: usize, _: usize) -> bool { false }
        fn pick(&self, _: usize) -> Option<usize> { self.1 }
        fn tick(&self, _: usize, _: usize) -> bool { false }
        fn preempt_check(&self, _: usize, cur: usize, cand: usize) -> bool { cand < cur }
    }

    static STOP: Stub = Stub(Class::Stop, None);
    static DL: Stub = Stub(Class::Dl, Some(11));
    static RT: Stub = Stub(Class::Rt, Some(22));
    static FAIR: Stub = Stub(Class::Fair, Some(33));
    static IDLE: Stub = Stub(Class::Idle, Some(44));

    azos_ktest::ktest! {
        fn sched_class_precedence() {
            let all: ClassTable<'static> = [Some(&STOP), Some(&DL), Some(&RT), Some(&FAIR), Some(&IDLE)];
            if pick_in_precedence(&all, 0) != Some((Class::Dl, 11)) {
                return Err("the class walk did not take DL first (stop empty)");
            }
            let no_dl: ClassTable<'static> = [None, None, Some(&RT), Some(&FAIR), Some(&IDLE)];
            if pick_in_precedence(&no_dl, 0) != Some((Class::Rt, 22)) {
                return Err("with DL compiled out the walk did not take RT");
            }
            if !should_preempt(&all, 0, (Class::Fair, 33), (Class::Rt, 22))
                || should_preempt(&all, 0, (Class::Rt, 22), (Class::Fair, 33))
            {
                return Err("preemption across classes does not follow precedence");
            }
            Ok(())
        }
    }

    // N6b: a reservation at the band's least urgent level ranks before an
    // RT task at level 0, in the pick, the tick and the exempt-loop test,
    // through the same switch (`dl_above_band`) and rank functions
    // `rt::pick` / `rt::tick` read. The exempt band loops are the stop
    // class and run before any reservation. Canary
    // `canary=sched-dl-in-level`: `not ok`.
    azos_ktest::ktest! {
        fn sched_dl_above_rt() {
            use azos_sched::rt_core::{self, dl_rank, edf_before, exempt_first};
            let worst_band = azos_sched::task::RT_PRIORITY_THRESHOLD.saturating_sub(1);
            let on = azos_sched::classes::dl_above_band();
            let r = dl_rank(on, worst_band);
            // Pick: `bp <= l` against band level 0.
            if r > 0 {
                return Err("a reservation at the band's last level does not rank above RT level 0");
            }
            // Owner decision 10-10: the exempt band loops (e-stop, watchdog,
            // actuation) are the stop class, above DL, even at the band's
            // last level and while the band is skipped.
            if !exempt_first(on, worst_band, Some(r))
                || rt_core::stop_pick(None, Some(worst_band)) != rt_core::StopPick::Take
                || rt_core::stop_pick(Some(worst_band), None) != rt_core::StopPick::Keep
                || !rt_core::stop_preempts(false, true)
            {
                return Err("an eligible reservation runs before an exempt (stop-class) loop");
            }
            // Between reservations: deadline alone, whatever their levels.
            if !edf_before(dl_rank(on, worst_band), 10, dl_rank(on, 0), 20) {
                return Err("reservations are not ordered by deadline alone");
            }
            Ok(())
        }
    }

    // N6b: `SYS_SCHEDCTL` refuses a self-promotion to RT or DL without a
    // time warrant: the late runner is a kernel task whose table holds no
    // a `time` endpoint capability, so both calls fail and its class and base
    // priority are unchanged. Canary `canary=schedctl-no-warrant`: the RT
    // call succeeds (`not ok`; the runner's base priority is put back).
    azos_ktest::ktest_late! {
        fn schedctl_self_promotion_refused() {
            use azos_abi::syscall_nr::{SCHEDCTL_CLASS_DL, SCHEDCTL_CLASS_RT};
            let Some(me) = azos_sched::classes::current() else {
                return Err("the late runner is not a task");
            };
            let base = azos_sched::scheduler::current_task_base_priority();
            let class = azos_sched::classes::class_of(me);
            let rt = azos_syscall::schedctl::sys_schedctl(0, SCHEDCTL_CLASS_RT, 1, 0, 0, 0);
            // DL only once RT was refused: a canary boot must not leave the
            // runner holding a reservation.
            let dl = if rt < 0 {
                azos_syscall::schedctl::sys_schedctl(0, SCHEDCTL_CLASS_DL, 1, 1_000, 10_000, 0)
            } else {
                -1
            };
            let moved = azos_sched::scheduler::current_task_base_priority() != base
                || azos_sched::classes::class_of(me) != class;
            if rt >= 0 {
                azos_sched::rt::set_base_priority(me, base);
            }
            if rt >= 0 || dl >= 0 {
                return Err("SYS_SCHEDCTL bound RT or DL without a time warrant");
            }
            if moved {
                return Err("a refused SYS_SCHEDCTL changed the caller's class or priority");
            }
            Ok(())
        }
    }

    // QoS timer tolerance: only the fair class has timer slack. Early: the
    // policy `timer_slack_us` over every class, mode, hint and row flag with
    // every tier non-zero (the table the kernel configured may be all zero,
    // which would prove nothing). Late: the same through the real path the
    // timer heap takes at each arm (`timer_sleepers::slack_ticks`): the
    // runner's own SC, put in the RT band with the most generous hint and its
    // row's flag, gets no window; put back in the fair class, it gets the
    // tier's window when the build has one (the policy half of it is judged
    // in every build; `slack_ticks` itself only where QOS_TIMER_TOLERANCE is
    // on). Cargo-feature canary `qos-rt-slack-canary` (a hot path takes no
    // runtime canary): both `not ok`.
    azos_ktest::ktest! {
        fn qos_timer_slack_never_real_time() {
            use azos_sched::sc::{timer_slack_us, Class, SlackMode, QOS_MAX};
            let tiers = [1_000; azos_sched::sc::QOS_LEVELS];
            for class in [Class::Stop, Class::Dl, Class::Rt, Class::Idle] {
                for mode in [SlackMode::Off, SlackMode::Rows, SlackMode::All] {
                    for qos in 0..=QOS_MAX {
                        if timer_slack_us(class, qos, true, mode, &tiers) != 0 {
                            return Err("a stop, deadline, real-time or idle task was given timer slack");
                        }
                    }
                }
            }
            if timer_slack_us(Class::Fair, QOS_MAX, true, SlackMode::All, &tiers) != 1_000 {
                return Err("a fair task did not get its tier's slack");
            }
            Ok(())
        }
    }

    #[cfg(feature = "sched-timer-heap")]
    azos_ktest::ktest_late! {
        fn qos_timer_slack_rt_task_gets_zero() {
            use azos_sched::scheduler::timer_sleepers::slack_ticks;
            use azos_sched::sc::{timer_slack_us, SlackMode};
            let Some(me) = azos_sched::classes::current() else {
                return Err("the late runner is not a task");
            };
            let Some(sc) = azos_sched::classes::sc_of(me) else {
                return Err("the late runner has no scheduling context");
            };
            let base = azos_sched::scheduler::current_task_base_priority();
            let (qos, row) = (sc.qos(), sc.timer_slack_row());
            sc.set_qos(azos_sched::sc::QOS_BACKGROUND);
            sc.set_timer_slack_row(true);
            azos_sched::rt::set_base_priority(me, 1);
            let rt_class = azos_sched::classes::class_of(me);
            let rt_slack = slack_ticks(me);
            // The policy over the class the SC really holds, in every mode
            // with every tier non-zero: a kernel without the option (the
            // gate's) still judges the class rule on a live SC.
            let tiers = [1_000; azos_sched::sc::QOS_LEVELS];
            let rt_policy = rt_class.map(|c| timer_slack_us(c, sc.qos(), true, SlackMode::All, &tiers));
            azos_sched::rt::set_base_priority(me, 20);
            let fair_class = azos_sched::classes::class_of(me);
            let fair_slack = slack_ticks(me);
            let fair_policy = fair_class.map(|c| timer_slack_us(c, sc.qos(), true, SlackMode::All, &tiers));
            azos_sched::rt::set_base_priority(me, base);
            sc.set_qos(qos);
            sc.set_timer_slack_row(row);
            if azos_limits::SCHED_CLASS_RT && rt_class != Some(azos_sched::sc::Class::Rt) {
                return Err("priority 1 did not put the runner in the RT class");
            }
            if fair_class != Some(azos_sched::sc::Class::Fair) {
                return Err("priority 20 did not put the runner in the fair class");
            }
            if rt_class == Some(azos_sched::sc::Class::Rt) && (rt_slack != 0 || rt_policy != Some(0)) {
                return Err("a real-time task armed a timer with a slack window");
            }
            if fair_policy != Some(1_000) {
                return Err("a fair task's slack is not its tier's");
            }
            // The control: the same task, fair, background, its row's flag set.
            let want = azos_limits::QOS_TIMER_TOLERANCE && azos_limits::QOS_SLACK_BACKGROUND_US > 0;
            if want != (fair_slack != 0) {
                return Err("a fair background task's window does not follow the configuration");
            }
            Ok(())
        }
    }

    // QoS timer tolerance, the integrated arm path (`arm` -> `coalesce_target`
    // -> the slot's slack -> `fire_of`/`live_on` -> `peek_live` -> the instant
    // `block_current` programs), on a heap of its own and two forged sleepers
    // (`timer_sleepers::ktest_coalescing`), in every build: a kernel with the
    // option off keeps the slack storage under `ktest`. The two halves the
    // other tests cover (the class rule, `slack_ticks`) are not repeated.
    // Cargo-feature canaries `qos-fire-canary` (the slack is forgotten) and
    // `qos-armed-at-canary` (the bare deadline is reported): `not ok`.
    #[cfg(feature = "sched-timer-heap")]
    azos_ktest::ktest_late! {
        fn qos_timer_coalescing_path() {
            azos_sched::scheduler::timer_sleepers::ktest_coalescing()
        }
    }

    // Late: the scheduler runs, so the runner is a task created through
    // `try_task_create_init` (its SC written there) and this CPU's idle task
    // is queued.
    azos_ktest::ktest_late! {
        fn sched_class_live() {
            let Some(cur) = azos_sched::classes::current() else {
                return Err("the late runner is not a task");
            };
            let base = azos_sched::scheduler::current_task_base_priority();
            if azos_sched::classes::class_of(cur) != Some(azos_sched::classes::class_for(cur, base)) {
                return Err("the running task's SC is not in its priority's class");
            }
            if azos_sched::classes::pick_here().is_none() {
                return Err("no class has a runnable task on this CPU");
            }
            Ok(())
        }
    }

    // N10, Kconfig FUTEX_PI: the PI word protocol in the kernel's own
    // environment (the real slot -> TID map), on a word the test owns. The
    // contended half (graph waiters, a LOCK_PI chain through a kernel Mutex,
    // the robust handover to a sleeper) needs N7, N8 and N9's table.
    azos_ktest::ktest_late! {
        fn futex_pi_word_protocol() {
            use azos_sync::pi_futex::*;
            if !ENABLED {
                return Ok(());
            }
            struct Word(u32, u32);
            impl PiBucket for Word {
                fn pi_slot(&mut self) -> &mut u32 { &mut self.1 }
                fn read_word(&self) -> Result<u32, UserFault> { Ok(self.0) }
                fn cmpxchg_word(&mut self, e: u32, n: u32) -> Result<u32, UserFault> {
                    let seen = self.0;
                    if seen == e { self.0 = n; }
                    Ok(seen)
                }
                fn task_of_tid(&self, tid: u32) -> Option<u32> {
                    azos_sched::scheduler::live_idx_for_tid(tid).map(|i| i as u32)
                }
            }
            let tid = azos_sched::scheduler::current_task_tid();
            let Some(me) = azos_sched::scheduler::idx_for_tid(tid).map(|i| i as u32) else {
                return Err("the late runner has no scheduler slot");
            };
            let Some(ops) = ops() else { return Err("FUTEX_PI is y but nothing is registered") };
            let used = states_in_use();
            let mut w = Word(0, 0);
            if !matches!(ops.lock_pi_prepare(&mut w, me, false), LockPiStep::Acquired) || w.0 != tid {
                return Err("LOCK_PI on a free word did not write the caller's TID");
            }
            if !matches!(ops.lock_pi_prepare(&mut w, me, true), LockPiStep::Err(e) if e == -EDEADLK) {
                return Err("a second LOCK_PI by the owner was not EDEADLK");
            }
            if ops.unlock_pi(&mut w, me) != Ok(None) || w.0 != 0 {
                return Err("UNLOCK_PI with no waiter did not free the word");
            }
            w.0 = tid | FUTEX_WAITERS;
            if ops.owner_died(&mut w, me) != Ok(None) || w.0 != FUTEX_OWNER_DIED | FUTEX_WAITERS {
                return Err("the robust exit did not leave FUTEX_OWNER_DIED");
            }
            if states_in_use() != used || w.1 != 0 {
                return Err("an uncontended word took a pi_state");
            }
            Ok(())
        }
    }
}

// N7: the wait graph, stage 1. Early, on a private graph driven by a
// recording scheduler (the kernel's graph moves real tasks, and it has no
// slots without `WAIT_GRAPH`): the transitive chain A <- B <- C boosts A to
// C and each release gives back what it no longer earns; a cycle is EDEADLK
// with both tasks unchanged; a DL donor's absolute deadline is inherited;
// `attr_changed` of a waiter re-boosts its owner; a chain one link past
// PI_MAX_DEPTH is counted and not boosted at its root. Late, with
// `WAIT_GRAPH`: the registered class hooks read the running task. Canary
// `canary=pi-depth-1` (one owner per walk): `waitgraph_transitive_chain`,
// `waitgraph_dl_donor_and_attr_changed` (attr_changed never reaches the
// owner) and `waitgraph_depth_cap` (only the last link is boosted) are
// `not ok`; `waitgraph_cycle_edeadlk` stays `ok`.
#[cfg(feature = "ktest")]
mod waitgraph_ktests {
    use azos_sync::spinlock::SpinLock;
    use azos_sync::waitgraph::{
        EdgeKind, Graph, PiAttr, PiWaiters, SchedPi, TaskId, UnblockReason, WaitError, WaitObj,
        PI_MAX_DEPTH,
    };
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const N: usize = 64;

    struct Rec {
        base: SpinLock<[PiAttr; N]>,
        cur: SpinLock<[PiAttr; N]>,
        on: [AtomicUsize; N],
    }

    impl Rec {
        fn set_base(&self, t: TaskId, a: PiAttr) {
            self.base.lock_irqsave()[t as usize] = a;
            self.cur.lock_irqsave()[t as usize] = a;
        }
        fn cur(&self, t: TaskId) -> PiAttr {
            self.cur.lock_irqsave()[t as usize]
        }
    }

    impl SchedPi for Rec {
        fn base_attr(&self, t: TaskId) -> PiAttr { self.base.lock_irqsave()[t as usize] }
        fn boost(&self, t: TaskId, to: PiAttr) { self.cur.lock_irqsave()[t as usize] = to; }
        fn unboost(&self, t: TaskId, to: PiAttr) { self.cur.lock_irqsave()[t as usize] = to; }
        fn set_blocked_on(&self, t: TaskId, on: Option<WaitObj>) {
            self.on[t as usize].store(on.map_or(0, WaitObj::addr), Ordering::Relaxed);
        }
        fn blocked_on(&self, t: TaskId) -> Option<WaitObj> {
            WaitObj::from_addr(self.on[t as usize].load(Ordering::Relaxed))
        }
        fn on_cpu(&self, _t: TaskId) -> bool { false }
    }

    static S: Rec = Rec {
        base: SpinLock::new([PiAttr::Fair; N]),
        cur: SpinLock::new([PiAttr::Fair; N]),
        on: [const { AtomicUsize::new(0) }; N],
    };
    static G: Graph<N> = Graph::new();
    static REG: AtomicBool = AtomicBool::new(false);
    static O: [PiWaiters; 48] = [const { PiWaiters::new(EdgeKind::Mutex) }; 48];

    fn g() -> &'static Graph<N> {
        if !REG.swap(true, Ordering::Relaxed) {
            G.register_sched(&S);
        }
        &G
    }

    const fn rt(p: u8) -> PiAttr {
        PiAttr::Rt { prio: p }
    }

    azos_ktest::ktest! {
        fn waitgraph_transitive_chain() {
            let g = g();
            S.set_base(1, PiAttr::Fair);
            S.set_base(2, rt(20));
            S.set_base(3, rt(5));
            g.set_owner(&O[0], Some(1));
            g.set_owner(&O[1], Some(2));
            g.block_on(2, &O[0]).map_err(|_| "B could not block on A's object")?;
            g.block_on(3, &O[1]).map_err(|_| "C could not block on B's object")?;
            if S.cur(2) != rt(5) {
                return Err("B was not boosted to C");
            }
            if S.cur(1) != rt(5) {
                return Err("A was not boosted to C through B (transitive inversion)");
            }
            if g.release(1, &O[0]) != Some(2) || S.cur(1) != PiAttr::Fair {
                return Err("A's release did not unboost it or name B");
            }
            g.set_owner(&O[0], Some(2));
            g.unblock(2, &O[0], UnblockReason::Acquired);
            if g.release(2, &O[1]) != Some(3) || S.cur(2) != rt(20) {
                return Err("B's release of O1 left C's boost");
            }
            g.unblock(3, &O[1], UnblockReason::Acquired);
            let _ = g.release(2, &O[0]);
            Ok(())
        }
    }

    azos_ktest::ktest! {
        fn waitgraph_cycle_edeadlk() {
            let g = g();
            S.set_base(6, rt(30));
            S.set_base(7, rt(10));
            g.set_owner(&O[3], Some(6));
            g.set_owner(&O[4], Some(7));
            g.block_on(6, &O[4]).map_err(|_| "D could not block on E's object")?;
            let before = (S.cur(6), S.cur(7), g.stats().deadlocks);
            if g.block_on(7, &O[3]) != Err(WaitError::Deadlock) || WaitError::Deadlock.errno() != 35 {
                return Err("the cycle D -> E -> D was not refused with EDEADLK");
            }
            if S.blocked_on(7).is_some() || O[3].has_waiters() {
                return Err("the refused block stayed enqueued");
            }
            if (S.cur(6), S.cur(7), g.stats().deadlocks) != (before.0, before.1, before.2 + 1) {
                return Err("a refused block moved a priority or was not counted");
            }
            g.unblock(6, &O[4], UnblockReason::Interrupted);
            Ok(())
        }
    }

    azos_ktest::ktest! {
        fn waitgraph_dl_donor_and_attr_changed() {
            let g = g();
            S.set_base(8, rt(30));
            S.set_base(9, PiAttr::Dl { deadline_ns: 1_000 });
            g.set_owner(&O[6], Some(8));
            g.block_on(9, &O[6]).map_err(|_| "the DL donor could not block")?;
            if S.cur(8) != (PiAttr::Dl { deadline_ns: 1_000 }) {
                return Err("the owner did not inherit the DL donor's deadline");
            }
            S.set_base(11, PiAttr::Fair);
            S.set_base(12, rt(40));
            g.set_owner(&O[7], Some(11));
            g.block_on(12, &O[7]).map_err(|_| "the RT waiter could not block")?;
            S.set_base(12, rt(3));
            g.attr_changed(12);
            if S.cur(11) != rt(3) {
                return Err("attr_changed of a waiter did not re-boost its owner");
            }
            g.unblock(9, &O[6], UnblockReason::Timeout);
            g.unblock(12, &O[7], UnblockReason::Timeout);
            if S.cur(8) != rt(30) || S.cur(11) != PiAttr::Fair {
                return Err("leaving waiters left their owners boosted");
            }
            Ok(())
        }
    }

    azos_ktest::ktest! {
        fn waitgraph_depth_cap() {
            let g = g();
            // A chain of PI_MAX_DEPTH + 1 owners, built from its root.
            let links = PI_MAX_DEPTH + 1;
            let (first, obj0) = (13u32, 8usize);
            if first as usize + links + 1 > N || obj0 + links > O.len() {
                return Err("the ktest's graph is too small for PI_MAX_DEPTH");
            }
            for k in 0..=links as u32 {
                S.set_base(first + k, PiAttr::Fair);
            }
            for k in 0..links {
                g.set_owner(&O[obj0 + k], Some(first + k as u32));
            }
            for k in 1..links {
                g.block_on(first + k as u32, &O[obj0 + k - 1]).map_err(|_| "a chain link could not block")?;
            }
            let capped = g.stats().depth_capped;
            S.set_base(first + links as u32, rt(1));
            g.block_on(first + links as u32, &O[obj0 + links - 1]).map_err(|_| "the chain's head could not block")?;
            if g.stats().depth_capped != capped + 1 {
                return Err("a walk past PI_MAX_DEPTH was not counted");
            }
            if S.cur(first) != PiAttr::Fair || S.cur(first + 1) != rt(1) {
                return Err("the walk did not stop boosting exactly at PI_MAX_DEPTH");
            }
            Ok(())
        }
    }

    // Late: the registered hooks read the running task (a created task).
    azos_ktest::ktest_late! {
        fn waitgraph_live_hooks() {
            if !azos_sync::waitgraph::ENABLED {
                return Ok(());
            }
            let Some(cur) = azos_sched::classes::current() else {
                return Err("the late runner is not a task");
            };
            let pi = &azos_sched::classes::PI;
            let t = cur as TaskId;
            if pi.blocked_on(t).is_some() || !pi.on_cpu(t) {
                return Err("the running task looks blocked or off-CPU to the graph");
            }
            let base = azos_sched::scheduler::current_task_base_priority();
            let want = match azos_sched::classes::class_of(cur) {
                Some(azos_sched::sc::Class::Rt) => PiAttr::Rt { prio: base as u8 },
                Some(azos_sched::sc::Class::Fair) => PiAttr::Fair,
                _ => return Ok(()),
            };
            if pi.base_attr(t) != want {
                return Err("ClassPi::base_attr disagrees with the task's class and base");
            }
            Ok(())
        }
    }

    // Chain E cut 6: the quiet key each live task carries is its base
    // attribute's (`ClassPi::base_attr`, out of line, from the SC's class
    // and `base_priority`), for every task the boot created, autorun
    // re-classed and admission reserved. A key a writer missed stays at its
    // initial `Fair` (or a previous occupant's), so a missed store on an RT,
    // idle or DL task is a mismatch. A writer racing this read (a spawn
    // installing its base) is re-read after a yield before it fails.
    azos_ktest::ktest_late! {
        fn waitgraph_quiet_keys_match_base() {
            if !azos_sync::waitgraph::ENABLED {
                return Ok(());
            }
            let pi = &azos_sched::classes::PI;
            let ok = |idx: usize| {
                azos_sched::scheduler::tid_for_idx(idx).is_none()
                    || azos_sched::classes::quiet_key(idx) == pi.base_attr(idx as TaskId).quiet_key()
            };
            let mut live = 0;
            for idx in 0..azos_limits::MAX_TASKS {
                if azos_sched::scheduler::tid_for_idx(idx).is_some() {
                    live += 1;
                }
                let mut tries = 0;
                while !ok(idx) {
                    tries += 1;
                    if tries > 3 {
                        azos_drv_sys::kprintln!(
                            "[KTEST] quiet key of slot {} is {:#x}, its base attribute's is {:#x}",
                            idx, azos_sched::classes::quiet_key(idx),
                            pi.base_attr(idx as TaskId).quiet_key());
                        return Err("a live task's quiet key is not its base attribute's");
                    }
                    azos_sched::task_yield();
                }
            }
            if live < 2 {
                return Err("fewer than two live tasks: nothing was compared");
            }
            Ok(())
        }
    }
}

// N8: the kernel mutex in a task (late: `lock` names its caller by TID).
// Rule F1: `unlocked_for_io` frees the mutex for the device wait, so another
// task could take it there; lockdep notes a Mutex held across
// `might_wait_device`. Canary `canary=kmutex-io-held` (the mutex stays held
// across the wait): `kmutex_unlocked_for_io` is `not ok`. N8b: the PI and
// steal-rule ktests below need WAIT_GRAPH y and return Ok at once
// otherwise. Canary `canary=kmutex-steal-any` (a release frees the word
// with a waiter queued): `kmutex_steal_rule_holds_for_top_waiter` not ok.
#[cfg(feature = "ktest")]
mod kmutex_ktests {
    use azos_sync::kmutex::Mutex;
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use azos_sched::{current_task_tid, task_create_affinity, task_exit, task_priority, wq_wake_by_tid};

    /// The PI ktests run only where the mutex is wired to the graph.
    fn pi_on() -> bool {
        azos_sync::waitgraph::ENABLED
    }

    const CPU0: i8 = 0;
    /// The runner outranks everything it waits for and blocks, never spins.
    const RUNNER_PRIO: u32 = 1;
    /// Above the standing RT tasks (priority 8).
    const RT_WAITER_PRIO: u32 = 4;
    /// A fair owner: at or past RT_PRIORITY_THRESHOLD (12).
    const FAIR_OWNER_PRIO: u32 = azos_sched::task::RT_PRIORITY_THRESHOLD + 4;
    const HOLD_WORK: u32 = 2_000_000;

    static PM: Mutex<u32> = Mutex::new(0);
    static PI_RUNNER: AtomicU32 = AtomicU32::new(0);
    static PI_CONTENDING: AtomicBool = AtomicBool::new(false);
    static PI_ACQUIRED: AtomicBool = AtomicBool::new(false);
    static PI_HELD: AtomicU32 = AtomicU32::new(u32::MAX);
    static PI_AFTER: AtomicU32 = AtomicU32::new(u32::MAX);

    fn pi_owner(_: usize) {
        let g = PM.lock();
        let _ = task_create_affinity("kmx-rt-waiter", pi_waiter, 0, RT_WAITER_PRIO, CPU0);
        let _ = azos_syscall::sleep::wait_until_ms(10_000, 1, || PI_CONTENDING.load(Ordering::SeqCst));
        // No yield: only the boost lets this fair task run past the RT
        // waiter's band; sample the best priority seen while holding.
        let me = current_task_tid();
        let mut acc = 0u32;
        for i in 0..HOLD_WORK {
            acc = acc.wrapping_add(i);
            if i % 4_096 == 0 {
                if let Some(now) = task_priority(me) {
                    PI_HELD.fetch_min(now, Ordering::SeqCst);
                }
            }
        }
        core::hint::black_box(acc);
        drop(g);
        PI_AFTER.store(task_priority(me).unwrap_or(u32::MAX), Ordering::SeqCst);
        task_exit();
    }

    fn pi_waiter(_: usize) {
        PI_CONTENDING.store(true, Ordering::SeqCst);
        let g = PM.lock();
        PI_ACQUIRED.store(true, Ordering::SeqCst);
        drop(g);
        wq_wake_by_tid(PI_RUNNER.load(Ordering::SeqCst));
        task_exit();
    }

    fn pi_run(_: usize) {
        PI_RUNNER.store(current_task_tid(), Ordering::SeqCst);
        let _ = task_create_affinity("kmx-fair-owner", pi_owner, 0, FAIR_OWNER_PRIO, CPU0);
        let _ = azos_syscall::sleep::wait_until_ms(10_000, 10, || PI_ACQUIRED.load(Ordering::SeqCst));
    }

    // An RT waiter boosts a fair owner of a kernel Mutex through the wait
    // graph, and the owner is back at its base priority after the unlock.
    azos_ktest::ktest_late! {
        fn kmutex_pi_rt_waiter_boosts_fair_owner() {
            if !pi_on() {
                return Ok(());
            }
            crate::ktest::probe("kmx-pi", pi_run, 0, RUNNER_PRIO, CPU0)?;
            if !PI_ACQUIRED.load(Ordering::SeqCst) {
                Err("the RT waiter never acquired the Mutex")
            } else if PI_HELD.load(Ordering::SeqCst) > RT_WAITER_PRIO {
                Err("no boost: the fair owner ran below the RT waiter's priority while it held the Mutex")
            } else if PI_AFTER.load(Ordering::SeqCst) != FAIR_OWNER_PRIO {
                Err("not restored: the owner kept a boost after the unlock")
            } else {
                Ok(())
            }
        }
    }

    // Owner decision 10-10: the graph's boost keeps the ring-3 floor. A
    // kernel RT waiter (4) on a Mutex held by a task flagged ring-3 lifts it
    // to RT_PRIORITY_THRESHOLD (12), not to 4. Canary
    // `canary=pi-ring3-unclamped`: not ok (the owner reaches 4).
    static RM: Mutex<u32> = Mutex::new(0);
    static R_RUNNER: AtomicU32 = AtomicU32::new(0);
    static R_CONTENDING: AtomicBool = AtomicBool::new(false);
    static R_ACQUIRED: AtomicBool = AtomicBool::new(false);
    static R_HELD: AtomicU32 = AtomicU32::new(u32::MAX);

    fn r_owner(_: usize) {
        azos_sched::scheduler::ktest_flag_ring3(azos_sched::classes::current());
        let g = RM.lock();
        let _ = task_create_affinity("kmx-r3-waiter", r_waiter, 0, RT_WAITER_PRIO, CPU0);
        let _ = azos_syscall::sleep::wait_until_ms(10_000, 1, || R_CONTENDING.load(Ordering::SeqCst));
        let me = current_task_tid();
        let mut acc = 0u32;
        for i in 0..HOLD_WORK {
            acc = acc.wrapping_add(i);
            if i % 4_096 == 0 {
                if let Some(now) = task_priority(me) {
                    R_HELD.fetch_min(now, Ordering::SeqCst);
                }
            }
        }
        core::hint::black_box(acc);
        drop(g);
        azos_sched::scheduler::ktest_flag_ring3(None);
        task_exit();
    }

    fn r_waiter(_: usize) {
        R_CONTENDING.store(true, Ordering::SeqCst);
        let g = RM.lock();
        R_ACQUIRED.store(true, Ordering::SeqCst);
        drop(g);
        wq_wake_by_tid(R_RUNNER.load(Ordering::SeqCst));
        task_exit();
    }

    fn r_run(_: usize) {
        R_RUNNER.store(current_task_tid(), Ordering::SeqCst);
        let _ = task_create_affinity("kmx-r3-owner", r_owner, 0, FAIR_OWNER_PRIO, CPU0);
        let _ = azos_syscall::sleep::wait_until_ms(10_000, 10, || R_ACQUIRED.load(Ordering::SeqCst));
        azos_sched::scheduler::ktest_flag_ring3(None);
    }

    azos_ktest::ktest_late! {
        fn waitgraph_ring3_owner_floored() {
            if !pi_on() {
                return Ok(());
            }
            crate::ktest::probe("kmx-r3", r_run, 0, RUNNER_PRIO, CPU0)?;
            let held = R_HELD.load(Ordering::SeqCst);
            if !R_ACQUIRED.load(Ordering::SeqCst) {
                Err("the RT waiter never acquired the Mutex")
            } else if held >= FAIR_OWNER_PRIO {
                Err("no boost at all: the test proves nothing")
            } else if held < azos_sched::task::RT_PRIORITY_THRESHOLD {
                Err("a ring-3 owner was boosted past RT_PRIORITY_THRESHOLD by the wait graph")
            } else {
                Ok(())
            }
        }
    }

    static CM: Mutex<u32> = Mutex::new(0);
    static C_RUNNER: AtomicU32 = AtomicU32::new(0);
    static C_QUEUED: AtomicU32 = AtomicU32::new(0);
    static C_DONE: AtomicU32 = AtomicU32::new(0);
    /// Acquisition order: each waiter appends its priority (4 bits each).
    static C_ORDER: AtomicU32 = AtomicU32::new(0);
    static C_TRY_WHILE_QUEUED: AtomicBool = AtomicBool::new(false);
    static C_STOLE: AtomicBool = AtomicBool::new(false);
    /// The owner (RT 6), a more urgent waiter (RT 3), a less urgent one
    /// (RT 7) and a late one created after the release (RT 10), on CPU 0.
    const C_OWNER_PRIO: u32 = 6;
    const C_HI: u32 = 3;
    const C_LO: u32 = 7;
    const C_LATE: u32 = 10;

    fn c_waiter(prio: usize) {
        C_QUEUED.fetch_add(1, Ordering::SeqCst);
        {
            let mut g = CM.lock();
            let n = *g;
            // Exclusion: a second holder would interleave here.
            azos_sched::task_yield();
            *g = n + 1;
            let _ = C_ORDER.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |o| Some(o << 4 | prio as u32));
        }
        C_DONE.fetch_add(1, Ordering::SeqCst);
        wq_wake_by_tid(C_RUNNER.load(Ordering::SeqCst));
        task_exit();
    }

    fn c_owner(_: usize) {
        let g = CM.lock();
        // Both outrank this owner: each runs at creation and blocks on CM.
        let _ = task_create_affinity("kmx-hi", c_waiter, C_HI as usize, C_HI, CPU0);
        let _ = task_create_affinity("kmx-lo", c_waiter, C_LO as usize, C_LO, CPU0);
        let _ = azos_syscall::sleep::wait_until_ms(10_000, 1, || C_QUEUED.load(Ordering::SeqCst) == 2);
        drop(g);
        // C_HI preempted at the wake and C_LO (less urgent than this owner)
        // still waits. Its wake left the word ownerless with C_LO queued.
        let _ = task_create_affinity("kmx-late", c_waiter, C_LATE as usize, C_LATE, CPU0);
        task_exit();
    }

    fn c_run(_: usize) {
        C_RUNNER.store(current_task_tid(), Ordering::SeqCst);
        let _ = task_create_affinity("kmx-owner", c_owner, 0, C_OWNER_PRIO, CPU0);
        let _ = azos_syscall::sleep::wait_until_ms(10_000, 10, || C_DONE.load(Ordering::SeqCst) == 3);
    }

    // Contended: an owner and three RT waiters on one CPU. Every waiter
    // acquires once, the count is exact (exclusion across a yield inside
    // the section), and the waiters acquire most urgent first.
    azos_ktest::ktest_late! {
        fn kmutex_contended_most_urgent_first() {
            if !pi_on() {
                return Ok(());
            }
            crate::ktest::probe("kmx-cont", c_run, 0, RUNNER_PRIO, CPU0)?;
            let want = (C_HI << 8) | (C_LO << 4) | C_LATE;
            if C_DONE.load(Ordering::SeqCst) != 3 {
                Err("a waiter never acquired the contended Mutex")
            } else if *CM.lock() != 3 {
                Err("exclusion broken: the count is not one per holder")
            } else if C_ORDER.load(Ordering::SeqCst) != want {
                Err("the waiters did not acquire most urgent first")
            } else {
                Ok(())
            }
        }
    }

    static S_M: Mutex<u32> = Mutex::new(0);
    static S_QUEUED: AtomicBool = AtomicBool::new(false);
    static S_DONE: AtomicBool = AtomicBool::new(false);
    static S_RUNNER: AtomicU32 = AtomicU32::new(0);
    /// A queued waiter less urgent than the releasing owner.
    const S_WAITER_PRIO: u32 = 10;
    const S_OWNER_PRIO: u32 = 5;

    fn s_waiter(_: usize) {
        S_QUEUED.store(true, Ordering::SeqCst);
        drop(S_M.lock());
        S_DONE.store(true, Ordering::SeqCst);
        wq_wake_by_tid(S_RUNNER.load(Ordering::SeqCst));
        task_exit();
    }

    fn s_owner(_: usize) {
        let g = S_M.lock();
        let _ = task_create_affinity("kmx-steal-w", s_waiter, 0, S_WAITER_PRIO, CPU0);
        // The waiter is less urgent: sleep until it is queued in the graph.
        let _ = azos_syscall::sleep::wait_until_ms(10_000, 1, || S_QUEUED.load(Ordering::SeqCst)
            && S_M.wait_node().has_waiters());
        drop(g);
        // Woken, the waiter cannot preempt this more urgent owner. The rule:
        // the word stays ownerless (try_lock's one CAS fails), and this
        // strictly more urgent task may still take it through lock().
        C_TRY_WHILE_QUEUED.store(S_M.try_lock().is_some(), Ordering::SeqCst);
        let g = S_M.lock();
        C_STOLE.store(true, Ordering::SeqCst);
        drop(g);
        task_exit();
    }

    fn s_run(_: usize) {
        S_RUNNER.store(current_task_tid(), Ordering::SeqCst);
        let _ = task_create_affinity("kmx-steal-o", s_owner, 0, S_OWNER_PRIO, CPU0);
        let _ = azos_syscall::sleep::wait_until_ms(10_000, 10, || S_DONE.load(Ordering::SeqCst));
    }

    // Steal rule (KMUTEX_STEAL_RULE): after a release with a waiter queued
    // the fast path cannot take the Mutex, a strictly more urgent task can,
    // and the queued waiter still gets it afterwards.
    azos_ktest::ktest_late! {
        fn kmutex_steal_rule_holds_for_top_waiter() {
            if !pi_on() || !azos_sync::kmutex::STEAL_RULE {
                return Ok(());
            }
            crate::ktest::probe("kmx-steal", s_run, 0, RUNNER_PRIO, CPU0)?;
            if C_TRY_WHILE_QUEUED.load(Ordering::SeqCst) {
                Err("the one-CAS path took a released Mutex ahead of its queued waiter")
            } else if !C_STOLE.load(Ordering::SeqCst) {
                Err("a more urgent task could not take the Mutex ahead of a less urgent waiter")
            } else if !S_DONE.load(Ordering::SeqCst) {
                Err("the queued waiter never acquired after the steal")
            } else {
                Ok(())
            }
        }
    }

    // N7b: a task that waited behind a Mutex owner leaves the wait graph on
    // its exit path, not at its slot's reuse. The owner, contended by an RT
    // waiter (so the graph computed its effective attribute), releases and
    // exits; the runner waits for its graph state to go while the slot is
    // still a Zombie. Canary `canary=exit-keeps-graph`: not ok (the state
    // survives until the slot is reused).
    static X_M: Mutex<u32> = Mutex::new(0);
    static X_CONTENDING: AtomicBool = AtomicBool::new(false);
    static X_DONE: AtomicBool = AtomicBool::new(false);
    static X_RUNNER: AtomicU32 = AtomicU32::new(0);
    static X_SLOT: AtomicU32 = AtomicU32::new(u32::MAX);
    static X_IN_GRAPH: AtomicBool = AtomicBool::new(false);

    fn x_waiter(_: usize) {
        X_CONTENDING.store(true, Ordering::SeqCst);
        drop(X_M.lock());
        X_DONE.store(true, Ordering::SeqCst);
        wq_wake_by_tid(X_RUNNER.load(Ordering::SeqCst));
        task_exit();
    }

    fn x_owner(_: usize) {
        let g = X_M.lock();
        let _ = task_create_affinity("kmx-exit-w", x_waiter, 0, RT_WAITER_PRIO, CPU0);
        let _ = azos_syscall::sleep::wait_until_ms(10_000, 1, || X_CONTENDING.load(Ordering::SeqCst)
            && X_M.wait_node().has_waiters());
        drop(g);
        let me = azos_sched::classes::current().map_or(u32::MAX, |i| i as u32);
        X_IN_GRAPH.store(azos_sync::waitgraph::effective(me).is_some(), Ordering::SeqCst);
        X_SLOT.store(me, Ordering::SeqCst);
        task_exit();
    }

    fn x_run(_: usize) {
        X_RUNNER.store(current_task_tid(), Ordering::SeqCst);
        let _ = task_create_affinity("kmx-exit-o", x_owner, 0, FAIR_OWNER_PRIO, CPU0);
        let _ = azos_syscall::sleep::wait_until_ms(10_000, 10, || X_DONE.load(Ordering::SeqCst)
            && X_SLOT.load(Ordering::SeqCst) != u32::MAX);
        // The owner runs its exit path after the waiter: poll until its
        // graph state is gone (bounded; the canary keeps it).
        let slot = X_SLOT.load(Ordering::SeqCst);
        let _ = azos_syscall::sleep::wait_until_ms(2_000, 5, || azos_sync::waitgraph::effective(slot).is_none());
    }

    azos_ktest::ktest_late! {
        fn waitgraph_exit_clears_state() {
            if !pi_on() {
                return Ok(());
            }
            crate::ktest::probe("kmx-exit", x_run, 0, RUNNER_PRIO, CPU0)?;
            let slot = X_SLOT.load(Ordering::SeqCst);
            if !X_DONE.load(Ordering::SeqCst) || slot == u32::MAX {
                Err("the contended owner or its waiter never finished")
            } else if !X_IN_GRAPH.load(Ordering::SeqCst) {
                Err("the contended owner was never in the wait graph (the test proves nothing)")
            } else if azos_sync::waitgraph::effective(slot).is_some() {
                Err("an exited task kept its wait-graph state")
            } else {
                Ok(())
            }
        }
    }

    // N7c, owner decision 10-10: a Mutex owner that exits still holding it,
    // with an RT waiter queued in the wait graph, does not strand the
    // waiter: the graph's OwnerDiedHook frees the word and wakes the bucket,
    // and the waiter takes the Mutex within the bound; its guard reports
    // `owner_died()`, and the lock after its unlock does not (N7d). Canary
    // `canary=owner-died-silent`: not ok (the waiter sleeps on; the bound is
    // wall clock, so the run is not held up).
    static OD_M: Mutex<u32> = Mutex::new(0);
    static OD_QUEUED: AtomicBool = AtomicBool::new(false);
    static OD_GOT: AtomicBool = AtomicBool::new(false);
    static OD_RUNNER: AtomicU32 = AtomicU32::new(0);
    // N7d: the waiter's guard reported owner-died; the next lock did not.
    static OD_FLAG: AtomicBool = AtomicBool::new(false);
    static OD_CLEARED: AtomicBool = AtomicBool::new(false);

    fn od_waiter(_: usize) {
        let g = OD_M.lock();
        OD_FLAG.store(g.owner_died(), Ordering::SeqCst);
        drop(g);
        OD_CLEARED.store(!OD_M.lock().owner_died(), Ordering::SeqCst);
        OD_GOT.store(true, Ordering::SeqCst);
        wq_wake_by_tid(OD_RUNNER.load(Ordering::SeqCst));
        task_exit();
    }

    fn od_owner(_: usize) {
        let g = OD_M.lock();
        let _ = task_create_affinity("kmx-died-w", od_waiter, 0, RT_WAITER_PRIO, CPU0);
        let _ = azos_syscall::sleep::wait_until_ms(10_000, 1, || OD_M.wait_node().has_waiters());
        OD_QUEUED.store(OD_M.wait_node().has_waiters(), Ordering::SeqCst);
        // Exit holding the Mutex (the kernel bug this rule survives). Its
        // lockdep entry is dropped first, so the exit is not a lockdep
        // violation charged to this ktest: the property here is the wake.
        azos_sync::lockdep::release(&OD_M as *const Mutex<u32> as usize, azos_sync::lockdep::Kind::Mutex);
        core::mem::forget(g);
        task_exit();
    }

    fn od_run(_: usize) {
        OD_RUNNER.store(current_task_tid(), Ordering::SeqCst);
        let _ = task_create_affinity("kmx-died-o", od_owner, 0, FAIR_OWNER_PRIO, CPU0);
        let _ = azos_syscall::sleep::wait_until_ms(3_000, 10, || OD_GOT.load(Ordering::SeqCst));
    }

    azos_ktest::ktest_late! {
        fn kmutex_owner_died_wakes_waiter() {
            if !pi_on() {
                return Ok(());
            }
            let before = azos_sync::kmutex::owner_died_count();
            crate::ktest::probe("kmx-died", od_run, 0, RUNNER_PRIO, CPU0)?;
            if !OD_QUEUED.load(Ordering::SeqCst) {
                Err("the waiter never queued in the wait graph (the test proves nothing)")
            } else if !OD_GOT.load(Ordering::SeqCst) {
                Err("EOWNERDEAD: the waiter of a dead Mutex owner was never woken")
            } else if azos_sync::kmutex::owner_died_count() == before {
                Err("the waiter took the Mutex without the owner-died hook")
            } else if !OD_FLAG.load(Ordering::SeqCst) {
                Err("EOWNERDEAD: the next owner's guard did not report owner_died()")
            } else if !OD_CLEARED.load(Ordering::SeqCst) {
                Err("owner_died() survived the next owner's unlock")
            } else {
                Ok(())
            }
        }
    }

    // N7d: a task that exits holding a Mutex is no longer counted in
    // `held`'s table once its exit ran, so
    // the panic policy's `mutex-held` check never sees a dead holder.
    // Canary `canary=held-keeps-dead`: not ok.
    static HD_L: Mutex<u32> = Mutex::new(0);
    static HD_TID: AtomicU32 = AtomicU32::new(0);
    static HD_COUNTED: AtomicU32 = AtomicU32::new(0);

    fn hd_holder(_: usize) {
        let me = current_task_tid();
        HD_L.lock().leak();
        HD_COUNTED.store(azos_sync::held::held_by(me), Ordering::SeqCst);
        HD_TID.store(me, Ordering::SeqCst);
        task_exit();
    }

    fn hd_run(_: usize) {
        let _ = task_create_affinity("pil-dead-h", hd_holder, 0, FAIR_OWNER_PRIO, CPU0);
        // The exit path drops the count before the slot turns Zombie; the
        // bound is wall clock, so the canary does not hold the run up.
        let _ = azos_syscall::sleep::wait_until_ms(3_000, 10, || {
            let t = HD_TID.load(Ordering::SeqCst);
            t != 0 && azos_sync::held::held_by(t) == 0
        });
    }

    azos_ktest::ktest_late! {
        fn kmutex_dead_holder_leaves_the_held_table() {
            crate::ktest::probe("pil-dead", hd_run, 0, RUNNER_PRIO, CPU0)?;
            let t = HD_TID.load(Ordering::SeqCst);
            if t == 0 || HD_COUNTED.load(Ordering::SeqCst) == 0 {
                Err("the holder was never counted in the held table (the test proves nothing)")
            } else if azos_sync::held::held_by(t) != 0 {
                Err("a dead Mutex holder is still counted in the held table")
            } else {
                Ok(())
            }
        }
    }

    // Rule F1 (owner decision 10-10): a task that exits owning claims
    // (`azos_sync::claim`, the table `claim::held_by` the panic path reads) is
    // no longer counted once its exit ran. Canary `canary=claim-held-keeps-dead`:
    // not ok.
    static CD_A: azos_sync::claim::Claim<u32> = azos_sync::claim::Claim::new(0);
    static CD_B: azos_sync::claim::Claim<u32> = azos_sync::claim::Claim::new(0);
    static CD_TID: AtomicU32 = AtomicU32::new(0);
    static CD_COUNTED: AtomicU32 = AtomicU32::new(0);

    fn cd_owner(_: usize) {
        let me = current_task_tid();
        // Exit owning both (the kernel bug this table survives).
        core::mem::forget(CD_A.acquire());
        core::mem::forget(CD_B.acquire());
        CD_COUNTED.store(azos_sync::claim::held_by(me), Ordering::SeqCst);
        CD_TID.store(me, Ordering::SeqCst);
        task_exit();
    }

    fn cd_run(_: usize) {
        let _ = task_create_affinity("claim-dead-o", cd_owner, 0, FAIR_OWNER_PRIO, CPU0);
        let _ = azos_syscall::sleep::wait_until_ms(3_000, 10, || {
            let t = CD_TID.load(Ordering::SeqCst);
            t != 0 && azos_sync::claim::held_by(t) == 0
        });
    }

    azos_ktest::ktest_late! {
        fn claim_dead_owner_leaves_the_held_table() {
            crate::ktest::probe("claim-dead", cd_run, 0, RUNNER_PRIO, CPU0)?;
            let t = CD_TID.load(Ordering::SeqCst);
            if t == 0 || CD_COUNTED.load(Ordering::SeqCst) != 2 {
                Err("the owner was never counted in the claim table (the test proves nothing)")
            } else if azos_sync::claim::held_by(t) != 0 {
                Err("a dead claim owner is still counted in the held table")
            } else {
                Ok(())
            }
        }
    }

    // Rule F1 on the claim: its owner holds no Mutex, so a device wait made
    // while it owns the claim is not "a Mutex held across a device wait"
    // (lockdep's note count does not move) and the held-Mutex count is 0.
    // The held-Mutex check needs no lockdep. Canary `canary=claim-mutex-held`:
    // the owner keeps the exchange mutex of this test's claim, not ok.
    static CM_C: azos_sync::claim::Claim<u32> = azos_sync::claim::Claim::new(0);

    azos_ktest::ktest_late! {
        fn claim_holds_no_mutex_across_a_device_wait() {
            if canary!("claim-mutex-held") {
                azos_sync::claim::canary_mutex_held(&CM_C as *const _ as usize);
            }
            let me = current_task_tid();
            let g = CM_C.acquire();
            let notes = azos_sync::lockdep::stats().device_wait_notes;
            let held = azos_sync::held::held_by(me);
            azos_sync::lockdep::might_wait_device("ktest device wait under a claim");
            let noted = azos_sync::lockdep::stats().device_wait_notes != notes;
            drop(g);
            if held != 0 {
                Err("F1: the claim's owner holds a Mutex")
            } else if noted {
                Err("F1: lockdep noted a Mutex held across a device wait under a claim")
            } else if azos_sync::held::held_by(me) != 0 {
                Err("the claim's release left a Mutex held")
            } else {
                Ok(())
            }
        }
    }

    // The claim excludes across the owner's wait (it sleeps, as on a device)
    // and gives the resource to a contender that slept on it: the contender
    // does not enter while the claim is owned, and enters after the release.
    static CE_C: azos_sync::claim::Claim<u32> = azos_sync::claim::Claim::new(0);
    static CE_TRYING: AtomicBool = AtomicBool::new(false);
    static CE_OWNED: AtomicBool = AtomicBool::new(false);
    static CE_EARLY: AtomicBool = AtomicBool::new(false);
    static CE_GOT: AtomicBool = AtomicBool::new(false);

    fn ce_contender(_: usize) {
        CE_TRYING.store(true, Ordering::SeqCst);
        let mut g = CE_C.acquire();
        CE_EARLY.store(CE_OWNED.load(Ordering::SeqCst), Ordering::SeqCst);
        *g += 1;
        CE_GOT.store(true, Ordering::SeqCst);
        drop(g);
        task_exit();
    }

    fn ce_run(_: usize) {
        let mut g = CE_C.acquire();
        CE_OWNED.store(true, Ordering::SeqCst);
        *g += 1;
        // The runner outranks the contender (priority 1): the contender runs
        // once this task sleeps for its "device wait" and sleeps on the claim.
        let _ = task_create_affinity("claim-excl-c", ce_contender, 0, FAIR_OWNER_PRIO, CPU0);
        // The "device wait": the claim is owned and this task is asleep.
        let _ = azos_syscall::sleep::wait_until_ms(30, 5, || false);
        CE_OWNED.store(false, Ordering::SeqCst);
        drop(g);
        let _ = azos_syscall::sleep::wait_until_ms(3_000, 5, || CE_GOT.load(Ordering::SeqCst));
    }

    azos_ktest::ktest_late! {
        fn claim_excludes_across_a_wait_and_wakes_a_contender() {
            crate::ktest::probe("claim-excl", ce_run, 0, RUNNER_PRIO, CPU0)?;
            if !CE_TRYING.load(Ordering::SeqCst) {
                Err("the contender never ran (the test proves nothing)")
            } else if CE_EARLY.load(Ordering::SeqCst) {
                Err("the contender entered while the claim was owned across the wait")
            } else if !CE_GOT.load(Ordering::SeqCst) {
                Err("the contender was never woken by the claim's release")
            } else if *CE_C.acquire() != 2 {
                Err("an owner's update was lost")
            } else {
                Ok(())
            }
        }
    }

    // Rule F1 on the raw block path: `block_io` (the io_ring's `OP_BLOCK_READ`)
    // takes a bounce buffer of its own, so two readers on two harts never see each other's sectors
    // (they shared one buffer behind a sleeping lock held across the device
    // wait). Two tasks read two different sectors over and over through
    // the call; each must always get its own. Ok at once without a disk. No
    // runtime canary: the race needs the shared buffer put back unlocked
    // (the host guard `no_syscall_handler_keeps_an_unsynchronised_static_mut_buffer`
    // reads the source for it).
    static DB_REF: azos_sync::SpinLock<[[u8; 512]; 2]> = azos_sync::SpinLock::new([[0; 512]; 2]);
    static DB_SECTOR_B: AtomicU32 = AtomicU32::new(0);
    static DB_BAD: AtomicU32 = AtomicU32::new(0);
    static DB_READS: AtomicU32 = AtomicU32::new(0);
    static DB_DONE: AtomicU32 = AtomicU32::new(0);
    const DB_ROUNDS: u32 = 48;

    fn db_reader(which: usize) {
        let sector = if which == 0 { 0 } else { DB_SECTOR_B.load(Ordering::SeqCst) as u64 };
        let mut buf = [0u8; 512];
        for _ in 0..DB_ROUNDS {
            if azos_syscall::block_host::block_io(1, false, sector, buf.as_mut_ptr(), 512).is_err() {
                DB_BAD.fetch_add(1, Ordering::SeqCst);
                break;
            }
            DB_READS.fetch_add(1, Ordering::SeqCst);
            if buf != DB_REF.lock()[which] {
                DB_BAD.fetch_add(1, Ordering::SeqCst);
            }
        }
        DB_DONE.fetch_add(1, Ordering::SeqCst);
        task_exit();
    }

    fn db_run(_: usize) {
        let _ = task_create_affinity("disk-bounce-a", db_reader, 0, FAIR_OWNER_PRIO, 0);
        let _ = task_create_affinity("disk-bounce-b", db_reader, 1, FAIR_OWNER_PRIO, -1);
        let _ = azos_syscall::sleep::wait_until_ms(10_000, 10, || DB_DONE.load(Ordering::SeqCst) == 2);
    }

    azos_ktest::ktest_late! {
        fn block_read_has_a_bounce_buffer_per_call() {
            if !azos_fs::fat32_mounted() {
                return Ok(());
            }
            // Two sectors with different bytes, as the device holds them.
            // Partition 0 (badge 1), sectors named relative to it.
            let Some((start, plen)) = azos_drv_block::partition::partition(0) else {
                return Ok(());
            };
            let mut a = [0u8; 512];
            if azos_drv_block::blkdev::read_raw(start, 1, &mut a).is_err() {
                return Err("the partition's first sector could not be read");
            }
            let mut b = [0u8; 512];
            let mut found = 0u32;
            for sec in 1u64..256.min(plen) {
                if azos_drv_block::blkdev::read_raw(start + sec, 1, &mut b).is_err() {
                    return Err("a sector could not be read");
                }
                if b != a {
                    found = sec as u32;
                    break;
                }
            }
            if found == 0 {
                return Ok(());
            }
            *DB_REF.lock() = [a, b];
            DB_SECTOR_B.store(found, Ordering::SeqCst);
            crate::ktest::probe("disk-bounce", db_run, 0, RUNNER_PRIO, CPU0)?;
            if DB_DONE.load(Ordering::SeqCst) != 2 {
                Err("a reader never finished")
            } else if DB_READS.load(Ordering::SeqCst) == 0 {
                Err("no block read succeeded (the test proves nothing)")
            } else if DB_BAD.load(Ordering::SeqCst) != 0 {
                Err("a block read returned another call's sector")
            } else {
                Ok(())
            }
        }
    }

    // N7b, owner decision 10-10: a newcomer the steal rule holds back joins
    // the wait graph before it sleeps, so the task that takes the Mutex next
    // inherits from it. The owner and its queued waiter share one priority:
    // the woken waiter does not preempt the releasing owner, which then
    // calls `lock` on the ownerless word as an equally urgent newcomer (not
    // strictly more urgent: held back). The waiter, now holding the Mutex,
    // samples: it is the graph owner and the newcomer is its top waiter,
    // blocked on this Mutex.
    static D_M: Mutex<u32> = Mutex::new(0);
    static D_QUEUED: AtomicBool = AtomicBool::new(false);
    static D_WINDOW: AtomicBool = AtomicBool::new(false);
    static D_SEEN: AtomicU32 = AtomicU32::new(0);
    static D_DONE: AtomicU32 = AtomicU32::new(0);
    static D_RUNNER: AtomicU32 = AtomicU32::new(0);
    static D_NEWCOMER: AtomicU32 = AtomicU32::new(u32::MAX);
    const D_PRIO: u32 = 10;
    /// D_SEEN bits, set by the waiter while it holds the Mutex.
    const D_OWNER_OK: u32 = 1;
    const D_TOP_OK: u32 = 2;
    const D_BLOCKED_OK: u32 = 4;

    fn d_waiter(_: usize) {
        D_QUEUED.store(true, Ordering::SeqCst);
        let g = D_M.lock();
        use azos_sync::waitgraph::{SchedPi, WaitObj};
        let me = azos_sched::classes::current().map_or(u32::MAX, |i| i as u32);
        let nc = D_NEWCOMER.load(Ordering::SeqCst);
        let node = D_M.wait_node();
        let mut seen = 0;
        if node.owner() == Some(me) {
            seen |= D_OWNER_OK;
        }
        if azos_sync::waitgraph::top_waiter(node).is_some_and(|(t, _)| t == nc) {
            seen |= D_TOP_OK;
        }
        if azos_sched::classes::PI.blocked_on(nc) == Some(WaitObj::of(node)) {
            seen |= D_BLOCKED_OK;
        }
        D_SEEN.store(seen, Ordering::SeqCst);
        drop(g);
        D_DONE.fetch_add(1, Ordering::SeqCst);
        wq_wake_by_tid(D_RUNNER.load(Ordering::SeqCst));
        task_exit();
    }

    fn d_owner(_: usize) {
        let g = D_M.lock();
        D_NEWCOMER.store(azos_sched::classes::current().map_or(u32::MAX, |i| i as u32), Ordering::SeqCst);
        let _ = task_create_affinity("kmx-defer-w", d_waiter, 0, D_PRIO, CPU0);
        let _ = azos_syscall::sleep::wait_until_ms(10_000, 1, || D_QUEUED.load(Ordering::SeqCst)
            && D_M.wait_node().has_waiters());
        drop(g);
        // The ownerless window: released, the waiter still queued.
        D_WINDOW.store(!D_M.is_locked() && D_M.wait_node().has_waiters(), Ordering::SeqCst);
        drop(D_M.lock());
        D_DONE.fetch_add(1, Ordering::SeqCst);
        wq_wake_by_tid(D_RUNNER.load(Ordering::SeqCst));
        task_exit();
    }

    fn d_run(_: usize) {
        D_RUNNER.store(current_task_tid(), Ordering::SeqCst);
        let _ = task_create_affinity("kmx-defer-o", d_owner, 0, D_PRIO, CPU0);
        let _ = azos_syscall::sleep::wait_until_ms(10_000, 10, || D_DONE.load(Ordering::SeqCst) == 2);
    }

    azos_ktest::ktest_late! {
        fn kmutex_held_back_newcomer_is_in_the_graph() {
            if !pi_on() || !azos_sync::kmutex::STEAL_RULE {
                return Ok(());
            }
            crate::ktest::probe("kmx-defer", d_run, 0, RUNNER_PRIO, CPU0)?;
            let seen = D_SEEN.load(Ordering::SeqCst);
            if D_DONE.load(Ordering::SeqCst) != 2 {
                Err("the owner or the waiter never finished")
            } else if !D_WINDOW.load(Ordering::SeqCst) {
                Err("no ownerless window: the newcomer was never held back (the test proves nothing)")
            } else if seen & D_OWNER_OK == 0 {
                Err("the waiter that took the Mutex is not its graph owner")
            } else if seen & (D_TOP_OK | D_BLOCKED_OK) != D_TOP_OK | D_BLOCKED_OK {
                Err("the held-back newcomer slept outside the wait graph: it boosts nobody")
            } else {
                Ok(())
            }
        }
    }

    static M: Mutex<u32> = Mutex::new(0);

    azos_ktest::ktest_late! {
        fn kmutex_unlocked_for_io() {
            let mut g = M.lock();
            if M.try_lock().is_some() {
                return Err("try_lock took a held Mutex");
            }
            *g += 1;
            let free = g.unlocked_for_io("ktest blk wait", || M.try_lock().map(|mut h| *h += 1).is_some());
            if !free {
                return Err("F1: the Mutex stayed held across the device wait");
            }
            if !M.is_locked() || *g != 2 {
                return Err("the Mutex was not re-acquired after the wait");
            }
            drop(g);
            if M.is_locked() {
                return Err("the Mutex is still held after the guard dropped");
            }
            Ok(())
        }
    }

    // N8c, rule F1 on the disk path: `BLK_LOCK` is a kmutex and a FAT32
    // write's device waits (`virtio-blk wait`, `might_wait_device`) run with
    // no Mutex held: lockdep's held-across-device-wait note count does not
    // move. Ok at once without lockdep or with no FAT32 volume mounted. No canary reaches this path yet: the driver drops
    // the lock before the wait itself (not through `unlocked_for_io`), and
    // `blk-lock-wait-canary` takes it after `might_wait_device` has run.
    azos_ktest::ktest_late! {
        fn fat_write_device_wait_holds_no_mutex() {
            if !azos_sync::lockdep::ON || !azos_fs::fat32_mounted() {
                return Ok(());
            }
            const NAME: [u8; 11] = *b"KTN8C   TMP";
            let data = [0x5au8; 1536];
            let before = azos_sync::lockdep::stats().device_wait_notes;
            if azos_fs::fat32_write_file(&NAME, &data).is_err() {
                return Err("the FAT32 write failed");
            }
            if azos_sync::lockdep::stats().device_wait_notes != before {
                return Err("F1: a Mutex was held across a FAT32 write's device wait");
            }
            Ok(())
        }
    }

    azos_ktest::ktest_late! {
        fn kmutex_held_across_device_wait_is_noted() {
            if !azos_sync::lockdep::ON {
                return Ok(());
            }
            static H: Mutex<()> = Mutex::new(());
            let before = azos_sync::lockdep::stats().device_wait_notes;
            {
                let _g = H.lock();
                azos_sync::lockdep::might_wait_device("ktest device wait under a Mutex");
            }
            if azos_sync::lockdep::stats().device_wait_notes <= before {
                return Err("lockdep did not note a Mutex held across a device wait");
            }
            Ok(())
        }
    }
}

// The classes `azos_ipc::cap_store` charges are bytes, numbered as the ledger's.
const _: () = {
    use azos_ipc::cap_store::{KMEM_CAP_TABLE, KMEM_EP_QUEUE, KMEM_MEMOBJ_META};
    use azos_sched::domain::KmemClass;
    assert!(KMEM_CAP_TABLE == KmemClass::CapTable as u8);
    assert!(KMEM_EP_QUEUE == KmemClass::EpQueue as u8);
    assert!(KMEM_MEMOBJ_META == KmemClass::MemObjMeta as u8);
};

/// `azos_ipc::cap_store::set_kmem_hooks`: charge a Domain's ledger. A class
/// the ledger does not know is refused (the const assertions above keep the
/// numbering equal, so this is unreachable).
fn kmem_charge(key: u32, class: u8, bytes: u64) -> bool {
    azos_mm::budget::KmemClass::from_index(class)
        .is_some_and(|c| azos_sched::domain::kmem_charge(key, c, bytes))
}

/// `azos_ipc::cap_store::set_kmem_hooks`: give a Domain's ledger back.
fn kmem_discharge(key: u32, class: u8, bytes: u64) {
    if let Some(c) = azos_mm::budget::KmemClass::from_index(class) {
        azos_sched::domain::kmem_discharge(key, c, bytes);
    }
}

/// The monotonic nanoseconds a capability's deadline is compared with
/// (`azos_ipc::cap::set_clock`).
fn cap_clock_ns() -> u64 {
    azos_abi::time::ticks_to_ns(azos_drv_sys::timebase::now(), azos_drv_sys::timebase::TIMER_FREQ)
}
