// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Scheduler wiring: the hook table, the proxy-donation hooks, the task-exit
//! resource release, and the system watchdog task.

use crate::*;

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
/// Every one of these four degrades quietly instead:
///
///   - `pi_mutex::pi_set_callbacks`: without it, `PiMutex::lock()` never
///     boosts the holder's priority, so priority inheritance is a no-op
///     and priority inversion goes unprotected. No error, no failing
///     test — a lower-priority holder just keeps a higher-priority
///     waiter parked for as long as it likes.
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
///     `lease_accept_wait`/`lease_wait_return` (`crates/core/ipc/src/
///     lease.rs`) and `Completion` block on; it does NOT gate
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
    azos_sync::pi_mutex::pi_set_callbacks(
        azos_sched::pi_boost_task,
        azos_sched::pi_restore_task,
        // Yield: a contended PiMutex waiter must release the hart, or the
        // owner it just boosted cannot run to finish the critical section.
        azos_sched::task_yield,
        // Who is calling, per CPU — see `pi_mutex::CURRENT_TID` for the
        // e-stop stall the global pair caused on SMP.
        azos_sched::scheduler::current_task_tid,
        azos_sched::scheduler::current_task_priority,
    );
    // A deferred TICK preemption, paid at the guard drop: counted as one.
    azos_sync::preempt::set_resched_callback(azos_sched::task_preempt_deferred);
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
    // Wave 11 (LEASE2): a lease's end removes the lessee's mapping through
    // this hook (`azos_ipc::lease`, "Leases that bite"). Before the first
    // user task, so no lease can be mapped without it.
    azos_ipc::lease::set_unmap_hook(lease_unmap);
    // Wave 11 (LEASE3): a sealed grant takes the lessor's write away and the
    // lease's end gives it back, through this hook.
    azos_ipc::lease::set_seal_hook(lease_seal);
    // Wave 11 (LEASE3): a channel/io_ring port binding dies with the
    // capability it was made through and follows it when it moves
    // (`azos_ipc::port::port_cap_event`). Before the first user task.
    azos_ipc::cap_store::set_cap_event_hook(azos_ipc::port::port_cap_event);
    // Wave 15 N5 runtime canary: a dead server's in-service calls are never
    // completed with -EPEERDIED.
    if canary!("ipc-no-peer-died") {
        azos_ipc::ep_queue::canary_no_peer_died();
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
    // N12 runtime canary: an ASID rollover does not flush the TLB.
    if canary!("asid-rollover-noflush") {
        azos_sched::asid::CANARY_NO_ROLLOVER_FLUSH.store(true, core::sync::atomic::Ordering::Relaxed);
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
    // RFC-0049 M1: page tables charged to the task that owns them, and user
    // page faults counted per task. Before the first user address space.
    azos_sched::install_mm_hooks();
    azos_syscall::handlers::set_exec_mem_resolver(azos_syscall::topo_sched::exec_mem_for);
    // RFC-0047: exec refuses an image whose row is a Linux row.
    azos_syscall::handlers::set_exec_linux_row(azos_syscall::linux::row_is_linux);
    // Wave 11 (LEASE3): a row with `lease_seal = true` refuses unsealed grants.
    azos_syscall::handlers::set_lease_seal_resolver(azos_syscall::topo_sched::lease_seal_required_for);
    // RFC-0040 gap 3: the fork-time mirror of the hook above. Without this,
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
    // Owner rule (wave 15): an RT task never does block I/O. Dev builds
    // (Kconfig RT_BLOCK_IO_CHECK) panic at the block layer's entry.
    azos_drv_block::blkdev::set_rt_io_check(rt_block_io_check);
    // Owner rule (wave 15, C2): an RT caller of the kernel log only appends
    // to the console (Kconfig CONSOLE_RT_APPEND_ONLY); dev builds (Kconfig
    // RT_CONSOLE_WIRE_CHECK) panic if one waits for the wire.
    azos_drv_sys::uart::set_rt_console_hooks(rt_console_caller, rt_console_wire_check);
    // Wave 15 (S1): a synchronous I2C transfer sleeps between the
    // controller steps of its own transaction (VisionFive 2 DesignWare).
    #[cfg(feature = "vf2")]
    azos_drv_bus::i2c::set_sleep_hook(i2c_sleep_us);
    // The flight recorder asks the same question: an RT caller of
    // `logger_flush` hands the flush to the `log-flush` task.
    azos_actuation::logger::logger_set_rt_probe(current_task_is_rt);
    // The user-driver proxy's block/wake/donation. Without it an in-kernel
    // client of a ring-3 driver refuses every call (`ProxyError::CannotBlock`)
    // — deliberately not a fallback to spinning, which would keep every
    // scenario green with the block path broken.
    azos_driver_server::reply_wait::set_proxy_hooks(&PROXY_HOOKS);
}

/// `azos_ipc::lease::SealHook` (wave 11, LEASE3): take the write
/// permission from (`write == false`) or give it back to (`true`) the lessor's
/// user leaves in the range, then shoot the range down on every hart
/// (`vmm::set_user_range_write`). Called with `LEASES` held, never from an
/// interrupt, as `lease_unmap` is.
fn lease_seal(root: usize, va: usize, pages: usize, write: bool) -> usize {
    // The gate canary: the seal takes nothing away (the give-back still runs
    // and finds nothing to widen).
    if cfg!(feature = "lease-seal-canary") && !write {
        return pages;
    }
    let end = va.saturating_add(pages.saturating_mul(azos_arch::PAGE_SIZE));
    azos_mm::vmm::set_user_range_write(root, va, end, write)
}

/// `azos_ipc::lease::UnmapHook`: remove a lease mapping from the lessee's
/// page table and shoot it down on every hart that may hold it. The skip
/// window is the whole range, so no frame is freed (`user_leaf_is_task_owned`
/// answers before `page_decref`): the frames are the region's, given back by
/// the lease's booked reference afterwards. Called with `LEASES` held, never
/// from an interrupt: the walk's kernel-table guard takes `KERNEL_PT`'s plain
/// lock.
fn lease_unmap(root: usize, va: usize, pages: usize) {
    #[cfg(not(feature = "lease-revoke-canary"))]
    {
        let end = va.saturating_add(pages.saturating_mul(azos_arch::PAGE_SIZE));
        let _ = azos_mm::vmm::unmap_user_range_and_free(root, va, end, va, end);
    }
    #[cfg(feature = "lease-revoke-canary")]
    let _ = (root, va, pages);
}

/// `azos_driver_server::reply_wait`'s view of the scheduler: the notify
/// path's block and wake (`WaitReason::Timer(deadline)`, woken by TID with
/// the matching deadline — the timer sweep ends a wait nobody answers), and
/// the donation `lease_wait_return` also uses.
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
/// named `tid` (`scheduler::exec_take_over`): the capability table and the
/// seed row a fork reseeds from.
fn task_identity_moved(from: usize, to: usize, tid: u32) {
    azos_ipc::cap_store::hand_over(from, to, tid);
    azos_syscall::natfork::hand_over(from, to, tid);
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
    // RFC-0049 M1c: a `mem = "locked"` task reports its page faults when it
    // exits, the dying task being the current one here. The gate reads the
    // NUMBER: a locked task must end with `faults=0`.
    {
        let (faults, peak, locked) = azos_sched::current_mem_report();
        if locked {
            kprintln!("[MEM] locked task {} exits: faults={} peak={} pages", tid, faults, peak);
        }
    }
    // Wave 15 (owner decision): a ring-3 task that dies commanding a wheel
    // leaves it at a SAFE STOP (duty 0), first of all, and the stop is
    // recorded with its reason; it does not latch the e-stop (Kconfig
    // `MOTOR_COMMANDER_EXIT_STOP`, `azos_syscall::motor_commander`).
    let (taken, stopped) = azos_syscall::motor_commander::exit_stop(tid);
    if taken != 0 {
        use azos_actuation::{estop, logger};
        let detail = estop::commander_lost_detail(tid, taken);
        let _ = logger::log_safety_violation_durable(
            logger::SAFETY_ESTOP, estop::ESTOP_ACTION_COMMANDER_LOST, detail);
        azos_drv_sys::kwarn!(
            "[MOTOR] commander tid {} exited: wheels {:#x} SAFE STOP (duty 0 on {:#x}; SAFETY_ESTOP action {} detail {:#x}, not latched)",
            tid, taken, stopped, estop::ESTOP_ACTION_COMMANDER_LOST, detail);
    }
    // RFC-0049 M4: is this a supervised driver the kernel will restart? Then
    // its driver-server slot, its named endpoints and its service names are
    // HELD for the successor instead of released (everything else is released
    // as for any task). Decided first; the supervisor is woken last, once
    // everything it will hand over is held.
    let sup = drv_supervisor::exit_verdict(tid);
    let held = sup.holds();
    // RFC-0055: the console's input owner (the user shell) releases it here,
    // and the console mode learns whether a successor is coming.
    if azos_drv_sys::uart::CONSOLE_RX.release(tid) {
        crate::console_mode::user_shell_exited(tid, held);
    }
    // Wave 13: a job the input was lent to gives it back, and its signal
    // words go (nothing is delivered to a task that has exited).
    let _ = azos_drv_sys::uart::CONSOLE_RX.end_lend(tid);
    azos_sched::scheduler::signal::detach(tid);
    // RFC-0055: children spawned with `SPAWN_F_DIE_WITH_PARENT` stop with
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
    }
    // A task killed mid-flood must not take its suppressed-denial count with it.
    azos_syscall::handlers::cap_denial_task_exit(tid);
    // Wave 11 (LEASE2): robust notify words this task still holds become
    // OWNER_DIED and their sleepers are woken. Before `task_release_all`
    // below in BOTH branches: the sweep reads the words through this task's
    // own shared-memory mappings, which that call gives back.
    #[cfg(not(feature = "robust-sweep-canary"))]
    let robust = azos_syscall::vdso_notify::notify_robust_exit(tid);
    #[cfg(feature = "robust-sweep-canary")]
    let robust = 0u32;
    if robust > 0 {
        kprintln!("[NOTIFY] task {} died holding {} robust word(s): owner-died set, waiters woken", tid, robust);
    }
    // Service-registry entries die with their owner: otherwise the name stays
    // taken and `discover` answers a dead (or later reused) TID. A supervised
    // driver's are held, `Stopped`, for its successor.
    azos_sched::prof::add(22, t_ph);
    let t_ph = azos_sched::prof::t();
    if held {
        let svc = azos_service::service_orphan_all(tid);
        if svc > 0 {
            kprintln!("[SVC] held {} service name(s) of task {} for its successor", svc, tid);
        }
        azos_ipc::task_release_all_supervised(tid);
    } else {
        let svc = azos_service::service_release_all(tid);
        if svc > 0 {
            kprintln!("[SVC] released {} service name(s) of task {}", svc, tid);
        }
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
    // Wave 15 (COHERENCE-AUDIT, dead client): pub/sub subscriptions are
    // keyed by pool slot, so they go while the slot still resolves (a later
    // task in the slot must not be woken for them); a Linux module server's
    // unused verification tokens go with it instead of holding a slot until
    // some later grant evicts them.
    if let Some(idx) = slot {
        let subs = azos_pubsub::topic_unsubscribe_all(idx);
        if subs > 0 {
            kprintln!("[PUBSUB] dropped {} subscription(s) of task {}", subs, tid);
        }
    }
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
}

/// The `fs-wb` task's TID once it runs (0 before): the watermark waker's target.
static FS_WB_TID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Set by a writer that crossed the dirty watermark; ends the task's sleep.
static FS_WB_KICK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn fs_wb_now_ms() -> u64 {
    azos_drv_sys::timebase::now() / (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1)
}

/// FAT32's watermark waker (any task context, no lock held).
fn fs_wb_wake() {
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
#[cfg(feature = "vf2")]
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
}

// N7: the wait graph, stage 1. Early, on a private graph driven by a
// recording scheduler (the kernel's graph moves real tasks, and it has no
// slots without `WAIT_GRAPH`): the transitive chain A <- B <- C boosts A to
// C and each release gives back what it no longer earns; a cycle is EDEADLK
// with both tasks unchanged; a DL donor's absolute deadline is inherited;
// `attr_changed` of a waiter re-boosts its owner; a chain one link past
// PI_MAX_DEPTH is counted and not boosted at its root. Late, with
// `WAIT_GRAPH`: the registered class hooks read the running task. Canary
// `canary=pi-depth-1` (one owner per walk): `waitgraph_transitive_chain` is
// `not ok`.
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
}
