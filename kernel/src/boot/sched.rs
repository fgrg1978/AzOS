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
}
