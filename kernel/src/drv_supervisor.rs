// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel side of the cold-restart supervisor: what the kernel keeps up
//! itself. The decisions live in `azos_sched::supervisor` (a pure table with
//! host tests); this file is what acts on them.
//!
//! Every ring-3 component of the topology, drivers included, is the component
//! manager's (`userspace/services/compmgr`): it starts them with
//! `SYS_SPAWN_EX` and restarts them by their row's `restart` key and the
//! failure contract of what they serve. The kernel supervises only what no
//! ring-3 supervisor could keep up: the manager itself and the ML service
//! ([`spawn_supervised`], `SupOrigin::Spawned`), and the host task of a driver
//! placed in the kernel ([`start_kernel_host`], `SupOrigin::KernelHost`).
//! For a manager child the kernel keeps one mechanism: the exit hook holds
//! the dead server's named endpoints, unclaimed with the same generation, for
//! the successor the manager starts (`console_mode::manager_restarts`).
//!
//! # The path, from a death to a task serving again
//!
//! 1. The task dies — a fault, a seccomp kill, a stop request or its own
//!    exit. The exit hook (`task_release_all_resources`) asks
//!    [`exit_verdict`] first.
//! 2. `Restart`: the hook HOLDS what a client reaches the task through — the
//!    named endpoints (unclaimed, same generation) — and releases everything
//!    else as for any task. Then [`exit_done`] wakes the supervisor task.
//! 3. The supervisor task (created at boot, from a kernel context) spawns the
//!    successor from the same path (`respawn_spawned`: same digest check, row,
//!    class, budget and capabilities, re-claiming the named endpoints), or a
//!    new kernel task on the host's entry, and records the restart on the
//!    flight recorder.
//! 4. `GiveUp` (a failure after `SUP_RESTART_BURST` restarts within
//!    `SUP_RESTART_INTERVAL_S`): the hook releases everything; the supervisor
//!    records it. The image stays down.
//! 5. `Exited` (the task exited 0): released like any task, not restarted
//!    and not recorded — systemd's `Restart=on-failure`. Its row's `restart`
//!    key changes that: `always` restarts an exit 0 as in step 2, `no` ends
//!    every death here (`NoRestart`).
//!
//! # The interface (what a kernel caller uses)
//!
//! * [`spawn_supervised`] — the one way a kernel task starts a ring-3 image
//!   that it keeps up itself: the component manager (`boot::launch`) and the
//!   ML service. It is `SYS_SPAWN_EX`'s machinery (`spawn_path`). The entry is
//!   made before the child is released, so there is no instant at which the
//!   child runs unsupervised.
//! * [`start`] creates the supervisor task. `kernel_main` calls it once, on a
//!   boot that can start anything supervised, before any of the above.
//! * [`exit_verdict`] / [`exit_done`] are the exit hook's two calls.
//! * [`current_tid`] — the task currently standing for an image path, for a
//!   kernel client that names the service it started (the ML link).
//!
//! The policy is the same for every origin: `Restart=on-failure` within
//! `SUP_RESTART_BURST` / `SUP_RESTART_INTERVAL_S`, a give-up recorded on the
//! flight recorder (`SAFETY_DRIVER_SUPERVISOR`, `SUP_ACTION_GAVE_UP`), unless
//! the image's topology row says `restart = always` or `restart = no`
//! ([`row_restart`]). An end under `restart = no` is recorded too
//! (`SUP_ACTION_NO_RESTART`), by the same loop.
//!
//! # Why a task, and not a restart from the exit hook
//!
//! A new task inherits its creator's page-table root
//! (`try_task_create_init` stamps `task_satp` from the current `satp`). The
//! exit hook runs on the dying ring-3 task's root, which is freed when its
//! slot is reused. The supervisor task is created by `kernel_main`, on the
//! kernel root, and so is every successor it creates.

use core::sync::atomic::{AtomicBool, AtomicI8, AtomicU32, Ordering};

use azos_actuation::logger::{
    log_safety_violation_durable, sup_record_detail, SAFETY_DRIVER_SUPERVISOR,
    SUP_ACTION_GAVE_UP, SUP_ACTION_NO_RESTART, SUP_ACTION_RESPAWN_FAILED, SUP_ACTION_RESTART,
};
use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{freq, now};
use azos_sched::supervisor::{
    sup_entry, sup_find_image, sup_held, sup_mark_recorded, sup_next_due, sup_next_swap,
    sup_next_unrecorded, sup_note_started, sup_on_exit, sup_respawn_failed,
    sup_respawn_refused, sup_respawned, sup_set_restart, sup_swap_abort, sup_swap_begin,
    sup_swap_commit, sup_swap_refused, ExitVerdict, SupEntry, SupFall, SupOrigin, SupPolicy, SupRestart,
    DRIVER_RESTART_COOLDOWN_MS, MAX_SUPERVISED,
};
use azos_sched::WaitReason;

/// The supervisor task's TID, 0 until it runs.
static SUP_TID: AtomicU32 = AtomicU32::new(0);

/// Per supervisor slot: the hart the dead kernel host was pinned to, read in
/// its exit hook, where the successor is created: the live hart, not a
/// constant, since a task pinned at run time to a hart that never started is
/// never dispatched. -1 = any hart.
static SUCCESSOR_HART: [AtomicI8; MAX_SUPERVISED] = {
    const ANY: AtomicI8 = AtomicI8::new(-1);
    [ANY; MAX_SUPERVISED]
};

/// What re-creates a supervised kernel host (`SupOrigin::KernelHost`, wave
/// 13), per supervisor slot: the task's name, entry point and priority.
#[derive(Clone, Copy)]
struct KernelHost {
    name: &'static str,
    entry: fn(usize),
    priority: u32,
}

static KERNEL_HOSTS: azos_sync::SpinLock<[Option<KernelHost>; MAX_SUPERVISED]> =
    azos_sync::SpinLock::new([None; MAX_SUPERVISED]);

/// [`start`] has run.
static STARTED: AtomicBool = AtomicBool::new(false);

/// Timebase ticks per millisecond, never 0.
fn ticks_per_ms() -> u64 {
    (freq() / 1000).max(1)
}

/// Restarts allowed within [`RESTART_INTERVAL_S`] (Kconfig
/// `SUP_RESTART_BURST`, systemd's `StartLimitBurst`).
pub(crate) const RESTART_BURST: u8 = azos_limits::SUP_RESTART_BURST as u8;
/// The window [`RESTART_BURST`] is counted in (Kconfig
/// `SUP_RESTART_INTERVAL_S`, systemd's `StartLimitIntervalSec`).
pub(crate) const RESTART_INTERVAL_S: u64 = azos_limits::SUP_RESTART_INTERVAL_S as u64;

/// The restart limit in timebase ticks.
fn policy() -> SupPolicy {
    SupPolicy {
        burst: RESTART_BURST,
        interval: RESTART_INTERVAL_S.saturating_mul(freq()),
        cooldown: DRIVER_RESTART_COOLDOWN_MS.saturating_mul(ticks_per_ms()),
    }
}

/// Create the supervisor task. Called once, by `kernel_main`, on a boot that
/// can start something supervised: a topology row says `start = true` (the
/// component manager), a driver may move between hosts (the supervisor task
/// does the moves), or ML is enabled (the ML service). It blocks with
/// no deadline until a supervised task dies, so it costs no wake-ups.
pub(crate) fn start() {
    if STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let idx = azos_sched::task_create("drv-supervisor", supervisor_task, 0,
                                          azos_sched::DEFAULT_PRIORITY);
    if let Some(tid) = azos_sched::tid_for_idx(idx) {
        SUP_TID.store(tid, Ordering::Release);
    }
}

/// Create the host task of a driver placed in the kernel (Kconfig
/// `DRV_*_PLACEMENT = kernel`) and supervise it (`SupOrigin::KernelHost`,
/// wave 13): when a panic in it is contained (the panic policy, exit status
/// 134) the supervisor creates a new task on the same entry, under the same
/// restart policy as a ring-3 driver. Starts the supervisor task if no other
/// boot condition did. Returns the host's TID.
///
/// A task cannot be created stopped, so the entry is made right after the
/// creation: a death in the host's first instructions, before this returns,
/// would go unsupervised. Without a table entry (table full) the host runs
/// unsupervised, as every kernel host did before wave 13.
#[cfg(feature = "board-io")]
pub(crate) fn start_kernel_host(name: &'static str, entry: fn(usize), priority: u32) -> Option<u32> {
    start();
    let idx = azos_sched::task_create(name, entry, 0, priority);
    let tid = azos_sched::tid_for_idx(idx)?;
    match azos_sched::supervisor::sup_note_kernel_host(tid, name.as_bytes()) {
        Some(slot) => {
            KERNEL_HOSTS.lock()[slot] = Some(KernelHost { name, entry, priority });
            kprintln!("[SUP] kernel host {} tid={} supervised (slot {})", name, tid, slot);
        }
        None => azos_drv_sys::kwarn!("[SUP] kernel host {} tid={} NOT supervised: table full", name, tid),
    }
    Some(tid)
}

/// Start the ring-3 image at `path` as `SYS_SPAWN_EX` would (`spawn_path`), and
/// supervise it from its first instruction. Returns the child's TID, or what
/// `spawn_path` returns on a refusal (no entry is made then: a program that
/// never started has nothing to restart).
///
pub(crate) fn spawn_supervised(path: &[u8]) -> i64 {
    let mut slot = None;
    let restart = row_restart(path);
    let mut hook = |tid| {
        slot = sup_note_started(tid, path);
        if let Some(s) = slot {
            let _ = sup_set_restart(s, restart);
        }
    };
    let rc = azos_syscall::spawn::spawn_path_hooked(path, &mut hook);
    if rc > 0 {
        match slot {
            Some(_) => kprintln!("[SUP] {} tid={} supervised from its start: restart = {} ({} \
                                  within {} s)", image_str(path), rc, restart_word(restart),
                                 RESTART_BURST, RESTART_INTERVAL_S),
            None => azos_drv_sys::kwarn!("[SUP] {} tid={} NOT supervised: the table ({} entries) is full \
                               or the path does not fit", image_str(path), rc, MAX_SUPERVISED),
        }
    }
    rc
}

/// Wave 11 (DRVPLACE): the `restart` key of the topology row named after
/// the image at `path` (`/fat/<NAME>` -> row `<NAME>`), `on-failure` when no
/// row names it or no topology is installed. (The `restart` gate row's canary
/// is the component manager's view, `boot::inspect_views::view_restart`.)
pub(crate) fn row_restart(path: &[u8]) -> SupRestart {
    let name = path.rsplit(|&b| b == b'/').next().unwrap_or(path);
    match azos_topology::get().map(|t| t.restart_of(name)) {
        Some(azos_topology::RestartPolicy::Always) => SupRestart::Always,
        Some(azos_topology::RestartPolicy::No) => SupRestart::No,
        _ => SupRestart::OnFailure,
    }
}

/// The row word for `r`.
fn restart_word(r: SupRestart) -> &'static str {
    match r {
        SupRestart::OnFailure => "on-failure",
        SupRestart::Always => "always",
        SupRestart::No => "no",
    }
}

/// The task standing for the image at `path`, if the supervisor has an entry
/// for it: the live one, or, while a successor is due or after a give-up,
/// the one that died last.
#[cfg_attr(any(feature = "no-ml", not(feature = "use-robot")), allow(dead_code))]
pub(crate) fn current_tid(path: &[u8]) -> Option<u32> {
    sup_find_image(path).map(|(_, e)| if e.tid != 0 { e.tid } else { e.dead_tid })
}

/// What the exit hook decided for one dying task.
#[derive(Clone, Copy)]
pub(crate) struct Exit(ExitVerdict);

impl Exit {
    /// Hold the named endpoints for a successor,
    /// instead of releasing them.
    pub(crate) fn holds(&self) -> bool {
        matches!(self.0, ExitVerdict::Restart { .. })
    }
}

/// Step 1: is `tid`, dying now with the code it passed to
/// `task_exit_with_code`, a supervised driver to restart?
///
/// `sup-canary` switches the supervisor off here — every death releases
/// everything, as before M4 — so the gate row's canary build fails on the line
/// only a driver that never came back prints.
pub(crate) fn exit_verdict(tid: u32) -> Exit {
    if cfg!(feature = "sup-canary") {
        return Exit(ExitVerdict::NotSupervised);
    }
    // The kernel host of a driver whose row may move (`stateless`) is not
    // restarted in the kernel: its death is a fault the placement controller
    // decides on, and the supervisor task starts the other host
    // (`crate::buzzer`).
    #[cfg(feature = "board-io")]
    if let Some((_, e)) = sup_find_image(crate::buzzer::HOST_NAME.as_bytes()) {
        if e.tid == tid && e.origin == SupOrigin::KernelHost && crate::buzzer::host_died() {
            let _ = azos_sched::supervisor::sup_retire(tid);
            defer_wake(tid);
            return Exit(ExitVerdict::NotSupervised);
        }
    }
    Exit(sup_on_exit(tid, now(), azos_sched::current_exit_code(), policy()))
}

/// Step 2's end: everything to hand over is held; say so, and leave the
/// supervisor's wake to [`exit_after_teardown`]. The flight-recorder write is
/// the supervisor task's, not this hook's: a durable write here would put a
/// disk flush on the exit path.
pub(crate) fn exit_done(tid: u32, e: Exit) {
    match e.0 {
        ExitVerdict::NotSupervised => return,
        ExitVerdict::Restart { slot, attempt, not_before } => {
            // Still valid here: the hook runs before the slot is freed.
            let hart = azos_sched::task_cpu_affinity(tid).unwrap_or(-1);
            if let Some(h) = SUCCESSOR_HART.get(slot) {
                h.store(hart, Ordering::Relaxed);
            }
            // Everything the successor takes over is held by now (this runs
            // at the end of the hook): only from here may the supervisor
            // create it. Before, it would find no orphaned slot to adopt.
            let _ = sup_held(slot);
            let wait_ms = not_before.saturating_sub(now()) / ticks_per_ms();
            azos_drv_sys::kwarn!("[SUP] supervised driver tid={} died: restart {}/{} within {} s due in {} ms",
                      tid, attempt, RESTART_BURST, RESTART_INTERVAL_S, wait_ms);
        }
        ExitVerdict::GiveUp { restarts, .. } => {
            azos_drv_sys::kerr!("[SUP] supervised driver tid={} died with its budget spent ({} restarts \
                       within {} s, {} in total): released, it stays down",
                      tid, RESTART_BURST, RESTART_INTERVAL_S, restarts);
        }
        ExitVerdict::Exited { restarts, .. } => {
            kprintln!("[SUP] supervised driver tid={} exited 0: not restarted (on-failure only; \
                       {} restarts before); released", tid, restarts);
            return;
        }
        ExitVerdict::NoRestart { restarts, code, .. } => {
            // No return: the supervisor task writes the flight-recorder
            // record (`next_unrecorded`), and it may be blocked until woken.
            kprintln!("[SUP] supervised driver tid={} ended (exit {}): not restarted (restart = no; \
                       {} restarts before); released", tid, code, restarts);
        }
    }
    defer_wake(tid);
}

/// Wake the supervisor task: a placement move is waiting for it
/// (`crate::buzzer`'s callers).
#[cfg(any(feature = "use-robot", feature = "ring3-drv-smoke", feature = "drv-contain-smoke",
          feature = "supall-smoke", feature = "hung-smoke", feature = "restart-smoke"))]
pub(crate) fn wake() {
    let sup = SUP_TID.load(Ordering::Acquire);
    if sup != 0 {
        azos_sched::scheduler::wake_task_by_tid(sup, &|r| matches!(r, WaitReason::Timer(_)));
    }
}

/// Dying supervised drivers whose supervisor wake waits for their address
/// space to go ([`exit_after_teardown`]); 0 = free entry. One entry per
/// supervised slot is enough: a slot has at most one dying task at a time.
static WAKE_AFTER_TEARDOWN: [AtomicU32; MAX_SUPERVISED] = {
    const FREE: AtomicU32 = AtomicU32::new(0);
    [FREE; MAX_SUPERVISED]
};

/// Supervisor wakes issued while the dying task still held its address
/// space: 0 while the wake follows the teardown. The `sup-smoke` verdict
/// reads it, as `EARLY_EXIT_NOTICES` is read for the exit notice.
static EARLY_SUP_WAKES: AtomicU32 = AtomicU32::new(0);

fn defer_wake(tid: u32) {
    for w in WAKE_AFTER_TEARDOWN.iter() {
        if w.compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return;
        }
    }
    // No free entry (cannot happen with one per slot): wake now rather than
    // never.
    wake_supervisor(tid);
}

/// The scheduler's post-teardown exit hook (`set_task_exit_late_hook`): runs
/// after the dying task's address space is gone. Wakes the supervisor if the
/// exit hook decided it has work from this death — a restart it would
/// otherwise start beside the dead driver's memory (EXIT2: the wake used to
/// come from `exit_done`, inside the exit hook, before the teardown).
pub(crate) fn exit_after_teardown(tid: u32) {
    if tid == 0 {
        return;
    }
    for w in WAKE_AFTER_TEARDOWN.iter() {
        if w.compare_exchange(tid, 0, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            wake_supervisor(tid);
            return;
        }
    }
}

fn wake_supervisor(dying: u32) {
    if azos_sched::tid_holds_address_space(dying) {
        EARLY_SUP_WAKES.fetch_add(1, Ordering::Relaxed);
    }
    let sup = SUP_TID.load(Ordering::Acquire);
    if sup != 0 {
        azos_sched::scheduler::wake_task_by_tid(
            sup, &|r| matches!(r, WaitReason::Timer(_)));
    }
}

fn supervisor_task(_: usize) {
    let me = azos_sched::current_task_tid();
    SUP_TID.store(me, Ordering::Release);
    azos_sched::supervisor::sup_set_task(me);
    loop {
        // Every `Spawned` successor is this task's child, and its death leaves
        // an exit notice addressed here. Nothing waits for them: take them, so
        // they never crowd the shared notice table a ring-3 parent's `wait`
        // reads.
        while azos_sched::take_exit_note(me).is_some() {}
        // Give-ups and `restart = no` ends the exit hook decided: record
        // each once.
        while let Some((slot, e, fall)) = sup_next_unrecorded() {
            let img = image_str(&e.image[..e.image_len as usize]);
            match fall {
                SupFall::GaveUp => {
                    record(SUP_ACTION_GAVE_UP, slot, e.restarts);
                    azos_drv_sys::kerr!("[SUP] gave up on {} after {} restarts: recorded",
                              img, e.restarts);
                }
                SupFall::NoRestart => {
                    record(SUP_ACTION_NO_RESTART, slot, e.restarts);
                    kprintln!("[SUP] {} ended under restart = no after {} restarts: recorded",
                              img, e.restarts);
                }
            }
            sup_mark_recorded(slot);
        }
        // A driver's move between hosts, asked for by a fault in its kernel
        // host or by its measured cost.
        #[cfg(feature = "board-io")]
        if crate::buzzer::work_pending() {
            crate::buzzer::run_work();
            continue;
        }
        // A live update asked for: a swap is not a restart and does not
        // wait for a due time.
        if let Some(slot) = sup_next_swap() {
            swap(slot);
            continue;
        }
        match sup_next_due(now()) {
            (Some(slot), _) => respawn(slot),
            // The timer sweep ends the wait at the earliest due restart; an
            // exit hook's wake ends it earlier. A wake that lands before the
            // block is stamped and the block returns at once (K-C9), so the
            // re-test above never misses one.
            (None, Some(due)) => azos_sched::task_block(WaitReason::Timer(due)),
            (None, None) => azos_sched::task_block(WaitReason::Timer(u64::MAX)),
        }
    }
}

/// Step 3: create the successor for `slot`.
fn respawn(slot: usize) {
    let Some(e) = sup_entry(slot) else { return };
    if e.origin == SupOrigin::Spawned {
        respawn_spawned(slot, &e);
        return;
    }
    if e.origin == SupOrigin::KernelHost {
        respawn_kernel_host(slot, &e);
    }
}

/// Step 3 for a kernel host: a new kernel task on the dead one's entry, on
/// its hart. Nothing to hand over; the host registers itself when it starts.
fn respawn_kernel_host(slot: usize, e: &SupEntry) {
    let dead = e.dead_tid;
    let host = KERNEL_HOSTS.lock()[slot];
    let hart = SUCCESSOR_HART.get(slot).map_or(-1, |h| h.load(Ordering::Relaxed));
    let heir = host.and_then(|h| {
        azos_sched::try_task_create_affinity(h.name, h.entry, 0, h.priority, hart)
            .and_then(azos_sched::tid_for_idx)
    });
    match heir {
        Some(heir) => {
            let t = now();
            let _ = sup_respawned(slot, heir, t);
            kprintln!("[SUP] restart {}/{} of kernel host {}: successor tid={} for tid={} created \
                       {} ms after the death", e.window_n, RESTART_BURST, image_str(e.image()),
                      heir, dead, t.saturating_sub(e.died_at) / ticks_per_ms());
            record(SUP_ACTION_RESTART, slot, e.restarts);
        }
        None => {
            let _ = sup_respawn_failed(slot);
            record(SUP_ACTION_RESPAWN_FAILED, slot, e.restarts);
            sup_mark_recorded(slot);
            azos_drv_sys::kerr!("[SUP] restart {}/{} of kernel host {} REFUSED: no task; it stays down",
                      e.window_n, RESTART_BURST, image_str(e.image()));
        }
    }
}

/// Step 3 for a `Spawned` image: spawn it again from its path, from this
/// kernel task, and hand the successor what its predecessor held inside the
/// spawn, before it is released. A spawn that is refused before any task
/// exists (image gone, digest mismatch, no instance left, actuation gate
/// absent, safe mode) is a failure like a death: it spends budget, the next
/// attempt keeps the cooldown, and the attempt after the burst gives up.
fn respawn_spawned(slot: usize, e: &SupEntry) {
    let dead = e.dead_tid;
    let refusal = if !azos_actuation::gate::gate_installed() {
        Some("the actuation gate is not installed")
    } else if azos_actuation::estop::safe_mode_active() {
        Some("safe mode")
    } else {
        None
    };
    let mut heir = 0u32;
    let rc = match refusal {
        Some(_) => -1,
        None => {
            let mut hook = |tid| {
                if sup_respawned(slot, tid, now()) {
                    heir = tid;
                }
            };
            azos_syscall::spawn::spawn_path_hooked(e.image(), &mut hook)
        }
    };
    if rc > 0 && heir as i64 == rc {
        kprintln!("[SUP] restart {}/{} of {}: successor tid={} for tid={} spawned {} ms after \
                   the death",
                  e.window_n, RESTART_BURST, image_str(e.image()), heir, dead,
                  now().saturating_sub(e.died_at) / ticks_per_ms());
        record(SUP_ACTION_RESTART, slot, e.restarts);
        return;
    }
    record(SUP_ACTION_RESPAWN_FAILED, slot, e.restarts);
    match sup_respawn_refused(slot, now(), policy()) {
        ExitVerdict::Restart { attempt, not_before, .. } => {
            azos_drv_sys::kwarn!("[SUP] restart {}/{} of {} REFUSED ({}): attempt {}/{} due in {} ms",
                      e.window_n, RESTART_BURST, image_str(e.image()),
                      refusal.unwrap_or("spawn refused"), attempt, RESTART_BURST,
                      not_before.saturating_sub(now()) / ticks_per_ms());
        }
        ExitVerdict::GiveUp { .. } => {
            // The give-up itself is recorded by the loop (`next_unrecorded`).
            azos_drv_sys::kerr!("[SUP] restart {}/{} of {} REFUSED ({}): budget spent, released, it \
                       stays down", e.window_n, RESTART_BURST, image_str(e.image()),
                      refusal.unwrap_or("spawn refused"));
        }
        ExitVerdict::NotSupervised | ExitVerdict::Exited { .. } | ExitVerdict::NoRestart { .. } => {}
    }
}

// ── Live update, Level 1 hooks: swap a server without draining its endpoints ──

/// How long a swap waits for the old server's calls in service to finish
/// (half of it, then they are re-presented to the successor where they
/// can be) before it is given up and the old server stays.
const SWAP_QUIESCE_MS: u64 = 2_000;

/// The swap verb, for `slot` (its entry asked for it): 1) open the old
/// server's named endpoints to a successor's grant; 2) create the successor
/// from the same signed row, its endpoint grants seeded without claiming
/// anything, and begin the handover (new calls queue, nothing is delivered);
/// 3) let the old server finish its calls in service, re-presenting them to
/// the successor halfway; 4) move the capability table to the successor, flip
/// every endpoint to it ([`azos_ipc::endpoint::endpoint_rebind_all`]: no
/// drain, no new generation) and make the successor the entry's task; 5) stop the old server, which is
/// no longer supervised. Any step that fails before 4 cancels: the old server
/// serves on, its queued calls delivered, the successor stopped.
///
/// The successor runs from its release and must not take calls before the
/// flip: its accept finds nothing until then (the queue delivers to no one
/// during a handover). A standby protocol for state transfer is Level 2.
fn swap(slot: usize) {
    use azos_ipc::endpoint::{
        endpoint_handover_begin_all, endpoint_handover_in_service, endpoint_handover_represent_all,
        endpoint_rebind_all, endpoint_swap_cancel, endpoint_swap_open,
    };
    let Some(e) = sup_entry(slot) else { return };
    let old = e.tid;
    let refusal = if old == 0 || e.origin != SupOrigin::Spawned {
        Some("not a serving spawned image")
    } else if !azos_actuation::gate::gate_installed() {
        Some("the actuation gate is not installed")
    } else if azos_actuation::estop::safe_mode_active() {
        Some("safe mode")
    } else {
        None
    };
    if let Some(why) = refusal {
        sup_swap_refused(slot);
        azos_drv_sys::kwarn!("[SUP] swap of {} REFUSED: {}", image_str(e.image()), why);
        return;
    }
    let (mut new, mut begun, mut begin_err) = (0u32, false, None);
    endpoint_swap_open(old);
    let rc = {
        let mut hook = |tid: u32| {
            new = tid;
            begun = sup_swap_begin(slot, tid);
            if begun {
                begin_err = endpoint_handover_begin_all(old, tid).err();
            }
        };
        azos_syscall::spawn::spawn_path_hooked(e.image(), &mut hook)
    };
    let give_up = |why: &str, new: u32| {
        let _ = endpoint_swap_cancel(old);
        let succ = sup_swap_abort(slot);
        if new != 0 || succ != 0 {
            azos_sched::scheduler::task_stop(if new != 0 { new } else { succ }, true, 9);
        }
        azos_drv_sys::kerr!("[SUP] swap of {} (tid={}) given up: {}; the old server serves on",
                  image_str(e.image()), old, why);
    };
    if rc <= 0 || new == 0 || rc as u32 != new || !begun || begin_err.is_some() {
        give_up(if begin_err.is_some() { "the handover was refused" } else { "the successor was not created" }, new);
        return;
    }
    // 3) Quiesce.
    let t0 = now();
    let limit = azos_syscall::sleep::ms_to_ticks(SWAP_QUIESCE_MS);
    let mut represented = false;
    loop {
        let still = matches!(sup_entry(slot), Some(x) if x.tid == old && x.successor == new);
        if !still || azos_sched::idx_for_tid(new).is_none() || azos_sched::idx_for_tid(old).is_none() {
            give_up("a task of the swap ended", new);
            return;
        }
        if endpoint_handover_in_service(old) == 0 {
            break;
        }
        let waited = now().saturating_sub(t0);
        if !represented && waited > limit / 2 {
            represented = true;
            let (moved, kept) = endpoint_handover_represent_all(old);
            kprintln!("[SUP] swap: {} call(s) re-presented to the successor, {} left with the old server",
                      moved, kept);
        }
        if waited > limit {
            give_up("the old server's calls did not finish", new);
            return;
        }
        azos_syscall::sleep::sleep_ms(1);
    }
    // 4) The flip. Nothing in service, nothing delivered: the queued calls'
    // capabilities are in the old server's table, which is its domain's. The
    // successor's own seeded table is wiped (its senders counted out once),
    // then it joins that domain: the same table, the same handles, nothing
    // moved. The old server's exit leaves the domain, not the table.
    let (Some(oi), Some(ni)) = (azos_sched::idx_for_tid(old), azos_sched::idx_for_tid(new)) else {
        give_up("a task of the swap ended", new);
        return;
    };
    azos_ipc::cap_store::reset(new);
    if !azos_sched::task_adopt_domain(new, old) {
        give_up("the successor could not join the old server's domain", new);
        return;
    }
    azos_ipc::endpoint::resolve_cache::clear(oi);
    azos_ipc::endpoint::resolve_cache::clear(ni);
    match endpoint_rebind_all(old, new) {
        Ok(n) => {
            // Calls queued during the handover wait for a server blocked in its
            // accept: the queue's wake went to the old one.
            azos_sched::wake_fast_ipc_server(new);
            if let Some((o, n2)) = sup_swap_commit(slot, now()) {
                kprintln!("[SUP] swap of {}: tid={} replaced by tid={} ({} endpoint(s) rebound)",
                          image_str(e.image()), o, n2, n);
            }
            // 5) The old server is nobody's: its end is not a death.
            azos_sched::scheduler::task_stop(old, true, 15);
        }
        Err(err) => {
            azos_drv_sys::kerr!("[SUP] FAIL swap of {}: the rebind was refused after the successor joined the domain ({:?})",
                      image_str(e.image()), err);
            // The successor holds the old server's table now: stopped like
            // every other failure's, or it lives on, unsupervised, with the
            // server's whole authority. Its exit leaves the shared domain,
            // not the table.
            give_up("the rebind was refused", new);
        }
    }
}

// ── Block devices that stop answering ───────────────────────────────────────

/// `Rule::BlockTimeout` / `Rule::NetTimeout` subject when no `[device.*]` row
/// names the device (a board's SD card or a USB disk, whose rows are not the
/// QEMU names).
const BLOCK_NO_ROW: u32 = u32::MAX;

/// The topology row of the boot block device: the `[device.*]` row the QEMU
/// images name `virtio-blk`, `nvme` or `ahci`.
fn block_device_row() -> u32 {
    azos_topology::get()
        .and_then(|t| t.devices().iter().position(|d| matches!(d.name.as_bytes(), b"virtio-blk" | b"nvme" | b"ahci")))
        .map_or(BLOCK_NO_ROW, |i| i as u32)
}

/// Where the block request layer reports a command that did not complete in
/// time and a device it found dead (`azos_drv_block::queue::set_timeout_sink`,
/// registered by [`register_block_sink`]): the `Rule::BlockTimeout` decision
/// record (`sector`, `waited_ms`, `action` 3 failed the request / 4 took the
/// device offline; the driver's own reset and latch are 2, 5 and 6,
/// [`device_timeout_sink`]) and a line on the console.
///
/// The verdict is `Deny`, the ring only: a `Refuse` is a durable receipt, and
/// the durable sink is a block write on the device that just stopped
/// answering, from inside the request layer's own reap. The supervisor task
/// is not asked to act: every block device is kernel-placed today and its
/// driver has already reset the controller (or latched itself dead, its
/// resets spent), and no ring-3 block driver exists whose restart this could
/// request (`driver_request_stop` of a supervised block host would, the day
/// one is added).
pub(crate) fn block_timeout_sink(action: azos_drv_block::queue::TimeoutAction, sector: u64, waited_ms: u64) {
    azos_decision::record(
        azos_decision::Rule::BlockTimeout,
        azos_decision::Verdict::Deny,
        block_device_row(),
        [sector, waited_ms, action as u64],
    );
    match action {
        azos_drv_block::queue::TimeoutAction::Failed => {
            azos_drv_sys::kerr!("[BLK] command at sector {} timed out after {} ms: request failed", sector, waited_ms)
        }
        azos_drv_block::queue::TimeoutAction::Offline => {
            azos_drv_sys::kerr!("[BLK] device is dead (found at sector {}): offline, every request fails", sector)
        }
    }
}

/// The topology row of the device a driver names (`[device.<name>]`), or
/// [`BLOCK_NO_ROW`] when the image has none (a board whose rows are not the
/// QEMU names).
fn device_row(name: &str) -> u32 {
    azos_topology::get()
        .and_then(|t| t.devices().iter().position(|d| d.name.as_bytes() == name.as_bytes()))
        .map_or(BLOCK_NO_ROW, |i| i as u32)
}

/// Where a kernel-placed block, network or USB host driver reports what the
/// device timeout policy did (`azos_drv_api::recovery::set_sink`): reset the
/// device (action 2), latched it dead with its resets spent (5), or found the
/// reset did not bring it back (6). The `Rule::BlockTimeout` record (`sector`,
/// `waited_ms`, `action`), the `Rule::NetTimeout` one (`pending`, `waited_ms`,
/// `action`) or the `Rule::UsbHostFault` one (`cause_trb`, `waited_ms`,
/// `action`), subject the device's topology row, and a console line. `Deny`, the ring only, for the reason [`block_timeout_sink`] gives:
/// the durable sink may be the very disk that just timed out.
pub(crate) fn device_timeout_sink(
    class: azos_drv_api::recovery::Class,
    device: &'static str,
    action: azos_drv_api::recovery::Action,
    detail: u64,
    waited_ms: u64,
) {
    use azos_drv_api::recovery::{Action, Class};
    let rule = match class {
        Class::Block => azos_decision::Rule::BlockTimeout,
        Class::Net => azos_decision::Rule::NetTimeout,
        Class::Usb => azos_decision::Rule::UsbHostFault,
    };
    azos_decision::record(rule, azos_decision::Verdict::Deny, device_row(device), [detail, waited_ms, action as u64]);
    let tag = match class {
        Class::Block => "BLK",
        Class::Net => "NET",
        Class::Usb => "USB",
    };
    // A USB host controller's own error (`azos_usb::xhci::Fault`, the second
    // byte of `detail`: 2 host system error, 3 host controller error).
    let reported = match (class, detail >> 8) {
        (Class::Usb, 2) => Some("a host system error"),
        (Class::Usb, 3) => Some("a host controller error"),
        _ => None,
    };
    match (action, reported) {
        (Action::Reset, Some(e)) => {
            azos_drv_sys::kerr!("[{}] {} reported {}: device reset, back in service", tag, device, e)
        }
        (Action::Latched, Some(e)) => {
            azos_drv_sys::kerr!("[{}] {} reported {} with its resets spent: latched dead until reboot", tag, device, e)
        }
        (Action::Reset, None) => {
            azos_drv_sys::kerr!("[{}] {} timed out after {} ms: device reset, back in service", tag, device, waited_ms)
        }
        (Action::Latched, None) => {
            azos_drv_sys::kerr!("[{}] {} timed out again after {} ms with its resets spent: latched dead until reboot", tag, device, waited_ms)
        }
        (Action::ResetFailed, _) => {
            azos_drv_sys::kerr!("[{}] {}: the reset after a timeout did not bring it back: latched dead until reboot", tag, device)
        }
    }
}

/// Route the block layer's timeout reports to [`block_timeout_sink`], and the
/// device timeout policy's to [`device_timeout_sink`]. Called once at boot, on
/// every boot (the supervisor task is not).
pub(crate) fn register_block_sink() {
    azos_drv_block::queue::set_timeout_sink(block_timeout_sink);
    azos_drv_api::recovery::set_sink(device_timeout_sink);
}

fn record(action: u8, slot: usize, count: u8) {
    let _ = log_safety_violation_durable(
        SAFETY_DRIVER_SUPERVISOR, action, sup_record_detail(slot as u32, count));
}

fn image_str(b: &[u8]) -> &str {
    core::str::from_utf8(b).unwrap_or("?")
}

// ── sup-smoke: the component manager's restart limit, on a driver ──────────

#[cfg(feature = "sup-smoke")]
pub(crate) fn start_smoke() {
    azos_sched::task_create_affinity("sup-smoke", smoke::run, 0,
                                         azos_sched::DEFAULT_PRIORITY, 1);
}

/// The ring-3 INA219 host (`INADRV.ELF` on `endpoint.powermon`), a
/// `start = true` row of the component manager, stopped by force (exit 137)
/// under the manager's restart limit: Kconfig `SUP_RESTART_BURST` restarts
/// within `SUP_RESTART_INTERVAL_S`, the symbols this file's policy reads too.
///
/// Kills 1..=burst: a task other than the dead one must serve the endpoint and
/// answer a read within `BACK_WITHIN_MS`, and a call through the
/// capability the smoke took before the first kill must reach it: the kernel
/// holds a dead child's named endpoint (slot and generation) for the
/// successor the manager starts (`console_mode::manager_restarts`). The kill
/// after the burst: nothing may serve the endpoint or answer for
/// `DOWN_FOR_MS`, and the held capability is refused, not left
/// waiting. Then the manager itself is stopped: the kernel restarts it
/// ([`spawn_supervised`]) and its successor starts a new host behind the
/// held endpoint. The manager's own lines (`[compmgr] restart INADRV.ELF ...
/// attempt=N`, `[compmgr] give-up INADRV.ELF`) are the gate row's to check.
///
/// `sup-window-smoke` (built, kernel and COMPMGR.ELF, with a short
/// `SUP_RESTART_INTERVAL_S`): kill, wait the interval out, kill again; both
/// must be served again, and the row checks that the manager counted the
/// second restart as attempt 1 of a fresh window.
///
/// Verdict lines `[SUP] PASS ...` / `[SUP] FAIL ...`. Only a manager that does
/// not restart its rows prints `[SUP] FAIL not restarted after kill 1`
/// (`supall-canary`); only a kernel that frees a dying child's named
/// endpoints prints `[SUP] FAIL kill 1: the capability taken before the kills
/// is refused` (runtime canary `manager-hold-skip`).
#[cfg(feature = "sup-smoke")]
mod smoke {
    use super::*;
    use azos_devif::powermon::ENDPOINT_NAME;
    use azos_devif::{PowerMonCall as _, PowerMonClient};
    use azos_syscall::kcall::{self, KernelEndpoint};

    /// How long the host may take to be serving at boot (the launcher reads
    /// the manager's ELF off FAT32, and the manager starts the driver).
    const SETUP_MS: u64 = 60_000;
    /// How long a killed host may take to answer again (TCG, loaded host, the
    /// manager's poll and its restart cooldown).
    const BACK_WITHIN_MS: u64 = 20_000;
    /// How long the host must stay down after the kill past the burst: more
    /// than the manager's cooldown, so a restart it should not make is seen.
    #[cfg(not(feature = "sup-window-smoke"))]
    const DOWN_FOR_MS: u64 = 3_000;
    const STEP_MS: u64 = 5;

    fn sleep_ms(ms: u64) {
        let end = now() + ms * ticks_per_ms();
        while now() < end {
            azos_sched::task_block(WaitReason::Timer(end));
        }
    }

    fn ms_since(t: u64) -> u64 {
        now().saturating_sub(t) / ticks_per_ms()
    }

    /// The task serving the endpoint now.
    fn host() -> Option<u32> {
        crate::powermon::ring3_host_tid()
    }

    /// A read through the kernel's power API (by the endpoint's name).
    fn answers() -> bool {
        azos_drv_sensor::ina219::ina219_stats().is_some()
    }

    /// A call through the capability `h`, held since before the first kill.
    fn held_answers(h: u32) -> bool {
        matches!(PowerMonClient::new(KernelEndpoint(h)).stats(), Ok(o) if o.is_ok())
    }

    /// A task other than `not` serves the endpoint and answers, within `ms`.
    fn serving(not: u32, ms: u64) -> Option<u32> {
        let t0 = now();
        loop {
            if let Some(t) = host().filter(|&t| t != not) {
                if answers() {
                    return Some(t);
                }
            }
            if ms_since(t0) > ms {
                return None;
            }
            sleep_ms(STEP_MS);
        }
    }

    /// Stop the host by force and wait until it no longer serves. The dead
    /// TID, or `None` with a `[SUP] FAIL` printed.
    fn kill(step: u32) -> Option<u32> {
        let Some(victim) = host() else {
            kprintln!("[SUP] FAIL kill {}: no INA219 host to stop", step);
            return None;
        };
        azos_sched::scheduler::task_stop(victim, true, 9);
        let t0 = now();
        while host() == Some(victim) {
            if ms_since(t0) > BACK_WITHIN_MS {
                kprintln!("[SUP] FAIL kill {}: tid={} asked to stop, still serving after {} ms",
                          step, victim, BACK_WITHIN_MS);
                return None;
            }
            sleep_ms(1);
        }
        Some(victim)
    }

    /// Kill `step`, which must be restarted: the successor's TID and the ms
    /// from the death to its first answer, or `None` with a FAIL printed.
    fn kill_and_back(step: u32, h: u32) -> Option<(u32, u32, u64)> {
        let victim = kill(step)?;
        let t0 = now();
        let Some(heir) = serving(victim, BACK_WITHIN_MS) else {
            kprintln!("[SUP] FAIL not restarted after kill {}: tid={} stopped, no host answered \
                       within {} ms", step, victim, BACK_WITHIN_MS);
            return None;
        };
        let back = ms_since(t0);
        if !held_answers(h) {
            kprintln!("[SUP] FAIL kill {}: the capability taken before the kills is refused by \
                       tid={}", step, heir);
            return None;
        }
        kprintln!("[SUP] kill {}: tid={} died -> tid={} serving after {} ms; the held capability \
                   reaches it", step, victim, heir, back);
        Some((victim, heir, back))
    }

    pub(super) fn run(_: usize) {
        let Some(t0) = serving(0, SETUP_MS) else {
            kprintln!("[SUP] FAIL setup: the INA219 host {:?} is not serving within {} ms",
                      host(), SETUP_MS);
            return;
        };
        let Some(h) = kcall::endpoint_handle(ENDPOINT_NAME.as_bytes()).filter(|&h| held_answers(h)) else {
            kprintln!("[SUP] FAIL setup: no capability on endpoint.{} that answers", ENDPOINT_NAME);
            return;
        };
        kprintln!("[SUP] INA219 host tid={} serving; restart limit {} within {} s",
                  t0, RESTART_BURST, RESTART_INTERVAL_S);
        #[cfg(feature = "sup-window-smoke")]
        window(h);
        #[cfg(not(feature = "sup-window-smoke"))]
        budget(h);
    }

    /// Kills 1..=burst restarted, the next one final.
    #[cfg(not(feature = "sup-window-smoke"))]
    fn budget(h: u32) {
        let mut back = [0u64; azos_sched::supervisor::SUP_BURST_MAX];
        for step in 1..=RESTART_BURST as u32 {
            let Some((_, _, ms)) = kill_and_back(step, h) else { return };
            back[step as usize - 1] = ms;
        }
        let last = RESTART_BURST as u32 + 1;
        let Some(victim) = kill(last) else { return };
        let t0 = now();
        let mut refused = 0u32;
        while ms_since(t0) < DOWN_FOR_MS {
            if let Some(t) = host() {
                kprintln!("[SUP] FAIL restarted past the limit: tid={} serves after kill {}", t, last);
                return;
            }
            if answers() || held_answers(h) {
                kprintln!("[SUP] FAIL restarted past the limit: a read was answered after kill {}", last);
                return;
            }
            refused += 1;
            sleep_ms(100);
        }
        kprintln!("[SUP] kill {}: tid={} died past the limit: no host and {} reads refused over \
                   {} ms", last, victim, refused, DOWN_FOR_MS);
        let Some(m) = manager_restarted(h) else { return };
        let s = &mut back[..RESTART_BURST as usize];
        s.sort_unstable();
        kprintln!("[SUP] PASS budget {}: {} restarts served, the kill past them stays down, the \
                   manager restarted by the kernel serves it again after {} ms; death -> first \
                   answer {} / {} / {} ms min/median/max",
                  RESTART_BURST, RESTART_BURST, m, s[0], s[s.len() / 2], s[s.len() - 1]);
    }

    /// The component manager itself, which only the kernel restarts
    /// ([`spawn_supervised`]): stopped by force, a successor must start, and
    /// with it a new INA219 host behind the endpoint the kernel held (the
    /// held capability reaches it). Its wake must follow the dead manager's
    /// teardown ([`EARLY_SUP_WAKES`]). The ms from the kill to the host's
    /// first answer, or `None` with a FAIL printed.
    #[cfg(not(feature = "sup-window-smoke"))]
    fn manager_restarted(h: u32) -> Option<u64> {
        const DIR: &[u8] = b"/fat/";
        let name = azos_topology::builder::TASK_COMPMGR_IMAGE;
        let mut path = [0u8; azos_sched::supervisor::SUP_IMAGE_MAX];
        let n = DIR.len() + name.len();
        path[..DIR.len()].copy_from_slice(DIR);
        path[DIR.len()..n].copy_from_slice(name);
        let Some(old) = current_tid(&path[..n]) else {
            kprintln!("[SUP] FAIL manager: {} is not supervised by the kernel", image_str(&path[..n]));
            return None;
        };
        azos_sched::scheduler::task_stop(old, true, 9);
        let t0 = now();
        let back = loop {
            let mgr = current_tid(&path[..n]).filter(|&t| t != old);
            if mgr.is_some() && host().is_some() && answers() {
                break ms_since(t0);
            }
            if ms_since(t0) > SETUP_MS {
                kprintln!("[SUP] FAIL manager: tid={} killed, manager {:?} and no INA219 host \
                           serving within {} ms", old, mgr, SETUP_MS);
                return None;
            }
            sleep_ms(20);
        };
        if !held_answers(h) {
            kprintln!("[SUP] FAIL manager: the capability taken before the kills is refused");
            return None;
        }
        let early = EARLY_SUP_WAKES.load(Ordering::Relaxed);
        if early != 0 {
            kprintln!("[SUP] FAIL the supervisor was woken {} time(s) while the dead manager still \
                       held its address space", early);
            return None;
        }
        Some(back)
    }

    /// A restart older than the interval no longer counts.
    #[cfg(feature = "sup-window-smoke")]
    fn window(h: u32) {
        if RESTART_INTERVAL_S > 30 {
            kprintln!("[SUP] FAIL window smoke needs SUP_RESTART_INTERVAL_S <= 30, built with {}",
                      RESTART_INTERVAL_S);
            return;
        }
        let Some(_) = kill_and_back(1, h) else { return };
        let t1 = now();
        sleep_ms((RESTART_INTERVAL_S + 2) * 1000);
        let Some((_, heir, _)) = kill_and_back(2, h) else { return };
        kprintln!("[SUP] PASS window: kill 2 {} ms after the first restart (interval {} s) \
                   served by tid={}", ms_since(t1), RESTART_INTERVAL_S, heir);
    }
}

// ── supall-smoke: the wave 11 gate row ──────────────────────────────────────

#[cfg(feature = "supall-smoke")]
pub(crate) fn start_supall_smoke() {
    azos_sched::task_create_affinity("supall-smoke", supall::run, 0,
                                         azos_sched::DEFAULT_PRIORITY, 1);
}

#[cfg(feature = "hung-smoke")]
pub(crate) fn start_hung_smoke() {
    azos_sched::task_create_affinity("hung-smoke", hung_act::run, 0,
                                         azos_sched::DEFAULT_PRIORITY, -1);
}

/// The hung-task detector's action, end to end (Kconfig `HUNG_ACTION`, the
/// watchdog's own pass, no test hook in between). A kernel task blocks on a
/// wait-graph edge owned by the ring-3 buzzer driver, as a task waiting for a
/// driver's answer does, and the answer never comes. After `HUNG_TASK_TIMEOUT_MS`
/// the sys-wdt pass reports it and the configured action must follow:
/// restart (the driver is stopped and the component manager brings a new one up),
/// safe stop (the e-stop latches) or none (nothing of either). Verdict line
/// `[HUNGACT] PASS` or `[HUNGACT] FAIL`; the gate row builds the kernel with the
/// action under test (`hung_row`). Runtime canary `canary=hung-action-skip`:
/// the report is made and the action is not run.
#[cfg(feature = "hung-smoke")]
mod hung_act {
    use super::*;
    use azos_sync::waitgraph::{self, EdgeKind, PiWaiters, UnblockReason};
    use core::sync::atomic::{AtomicBool, Ordering};

    const SETUP_MS: u64 = 60_000;
    /// The report plus the action, with the watchdog's 500 ms pass and a loaded host.
    const ACT_WITHIN_MS: u64 = 20_000;

    static OBJ: PiWaiters = PiWaiters::new(EdgeKind::Mutex);
    static WQ: azos_sync::WaitQueue = azos_sync::WaitQueue::new();
    static BLOCKED: AtomicBool = AtomicBool::new(false);
    static FREE: AtomicBool = AtomicBool::new(false);

    fn sleep_ms(ms: u64) {
        let end = now() + ms * ticks_per_ms();
        while now() < end {
            azos_sched::task_block(WaitReason::Timer(end));
        }
    }

    /// A task other than `not` serves `endpoint.buzzer` and answers, within `ms`.
    fn buzzer_serving(not: u32, ms: u64) -> Option<u32> {
        let t0 = now();
        loop {
            if let Some(t) = crate::buzzer::driver_tid() {
                if t != not && crate::buzzer::buzzer_off() {
                    return Some(t);
                }
            }
            if now() - t0 > ms * ticks_per_ms() {
                return None;
            }
            sleep_ms(20);
        }
    }

    /// Waits for a driver's answer that never comes.
    fn waiter(_: usize) {
        let Some((slot, _)) = azos_sched::scheduler::current_task_slot() else { return };
        if waitgraph::block_on(slot as u32, &OBJ).is_err() {
            return;
        }
        BLOCKED.store(true, Ordering::SeqCst);
        WQ.wait_if(|| !FREE.load(Ordering::SeqCst));
        waitgraph::unblock(slot as u32, &OBJ, UnblockReason::Interrupted);
    }

    pub(super) fn run(_: usize) {
        if canary!("hung-action-skip") {
            azos_actuation::sys_wdt::canary_skip_action();
        }
        let Some(b0) = buzzer_serving(0, SETUP_MS) else {
            kprintln!("[HUNGACT] FAIL setup: buzzer not serving within {} ms", SETUP_MS);
            return;
        };
        let Some(slot) = azos_sched::idx_for_tid(b0) else {
            kprintln!("[HUNGACT] FAIL setup: buzzer tid={} has no slot", b0);
            return;
        };
        OBJ.set_owner(Some(slot as u32));
        azos_sched::task_create_affinity("hung-wait", waiter, 0, azos_sched::DEFAULT_PRIORITY, -1);
        let t0 = now();
        while !BLOCKED.load(Ordering::SeqCst) {
            if now() - t0 > ACT_WITHIN_MS * ticks_per_ms() {
                kprintln!("[HUNGACT] FAIL setup: the waiter never blocked on the driver");
                return;
            }
            sleep_ms(5);
        }
        kprintln!("[HUNGACT] waiter blocked on buzzer tid={}; action {:?}", b0, azos_actuation::sys_wdt::HUNG_ACTION);
        let t1 = now();
        let within = |ms: u64| now() - t1 <= ms * ticks_per_ms();
        let passed = match azos_actuation::sys_wdt::HUNG_ACTION {
            azos_actuation::sys_wdt::HungAction::Restart => {
                while within(ACT_WITHIN_MS) && crate::buzzer::driver_tid() == Some(b0) {
                    sleep_ms(10);
                }
                match buzzer_serving(b0, ACT_WITHIN_MS) {
                    Some(b1) => {
                        kprintln!("[HUNGACT] driver tid={} stopped, tid={} serving again", b0, b1);
                        true
                    }
                    None => {
                        kprintln!("[HUNGACT] driver tid={} not stopped and replaced within {} ms", b0, ACT_WITHIN_MS);
                        false
                    }
                }
            }
            azos_actuation::sys_wdt::HungAction::SafeStop => {
                while within(ACT_WITHIN_MS) && !azos_actuation::estop::estop_is_active() {
                    sleep_ms(10);
                }
                azos_actuation::estop::estop_is_active()
            }
            azos_actuation::sys_wdt::HungAction::None => {
                sleep_ms(ACT_WITHIN_MS / 4);
                crate::buzzer::driver_tid() == Some(b0) && !azos_actuation::estop::estop_is_active()
            }
        };
        FREE.store(true, Ordering::SeqCst);
        WQ.wake_all();
        if passed {
            kprintln!("[HUNGACT] PASS: action {:?} done", azos_actuation::sys_wdt::HUNG_ACTION);
        } else {
            kprintln!("[HUNGACT] FAIL: action {:?} not done", azos_actuation::sys_wdt::HUNG_ACTION);
        }
    }
}

/// The ring-3 host of the buzzer, the one driver whose row moves between
/// hosts, killed under the component manager's supervision (its row is the
/// manager's like any `start = true` row; the placement controller only
/// routes calls to it).
///
/// The buzzer is stopped once (a forced stop, the kernel's kill): a new task
/// must own `endpoint.buzzer` and answer `buzzer_off` through it.
///
/// Every verdict that is not a pass prints `[SUPALL] FAIL`; the one only a
/// manager that does not restart what it started prints is
/// `[SUPALL] FAIL buzzer not restarted` (`supall-canary`: the manager is
/// shown every row as `restart = no`).
#[cfg(feature = "supall-smoke")]
mod supall {
    use super::*;

    /// How long the driver may take to be serving at boot (the launcher reads
    /// the manager's ELF off FAT32 after the volume is mounted, and the
    /// manager starts the buzzer).
    const SETUP_MS: u64 = 60_000;
    /// How long a killed driver may take to answer again (TCG, loaded host,
    /// the manager's poll and its restart cooldown).
    const BACK_WITHIN_MS: u64 = 20_000;

    fn sleep_ms(ms: u64) {
        let end = now() + ms * ticks_per_ms();
        while now() < end {
            azos_sched::task_block(WaitReason::Timer(end));
        }
    }

    /// The buzzer's [`serving`]: a task other than `not` serves
    /// `endpoint.buzzer` and answers `buzzer_off`, within `ms`.
    fn buzzer_serving(not: u32, ms: u64) -> Option<u32> {
        let t0 = now();
        loop {
            if let Some(t) = crate::buzzer::driver_tid() {
                if t != not && crate::buzzer::buzzer_off() {
                    return Some(t);
                }
            }
            if now() - t0 > ms * ticks_per_ms() {
                return None;
            }
            sleep_ms(20);
        }
    }

    /// Stop the buzzer's ring-3 host (a forced stop) and wait until it no
    /// longer serves the endpoint. The dead TID, or `None` with a
    /// `[SUPALL] FAIL` printed.
    fn kill_buzzer(step: u32) -> Option<u32> {
        let Some(victim) = crate::buzzer::driver_tid() else {
            kprintln!("[SUPALL] FAIL buzzer kill {}: no driver to stop", step);
            return None;
        };
        azos_sched::scheduler::task_stop(victim, true, 9);
        let t0 = now();
        loop {
            if crate::buzzer::driver_tid() != Some(victim) {
                return Some(victim);
            }
            if now() - t0 > BACK_WITHIN_MS * ticks_per_ms() {
                kprintln!("[SUPALL] FAIL buzzer kill {}: tid={} asked to stop, still serving after \
                           {} ms", step, victim, BACK_WITHIN_MS);
                return None;
            }
            sleep_ms(2);
        }
    }

    pub(super) fn run(_: usize) {
        let Some(b0) = buzzer_serving(0, SETUP_MS) else {
            kprintln!("[SUPALL] FAIL setup: buzzer {:?} not serving within {} ms",
                      crate::buzzer::driver_tid(), SETUP_MS);
            return;
        };
        kprintln!("[SUPALL] buzzer tid={} serving", b0);

        // One kill, one restart.
        let Some(v) = kill_buzzer(1) else { return };
        let t0 = now();
        let Some(b1) = buzzer_serving(v, BACK_WITHIN_MS) else {
            kprintln!("[SUPALL] FAIL buzzer not restarted: tid={} killed, no new driver answered \
                       within {} ms", v, BACK_WITHIN_MS);
            return;
        };
        kprintln!("[SUPALL] buzzer: tid={} killed -> tid={} answering after {} ms",
                  v, b1, (now() - t0) / ticks_per_ms());
        kprintln!("[SUPALL] PASS: buzzer killed and restarted by the component manager");
    }
}

/// Wave 11 (DRVPLACE): the `restart-smoke` task (see [`restart`]).
#[cfg(feature = "restart-smoke")]
pub(crate) fn start_restart_smoke() {
    azos_sched::task_create_affinity("restart-smoke", restart::run, 0,
                                         azos_sched::DEFAULT_PRIORITY, 1);
}

/// The topology row key `restart`, honoured by the component manager (which
/// reads it from its `inspect.components` view). The drv disk's ring-3 buzzer driver,
/// the one driver whose row moves between hosts, under the `restart-smoke`
/// topology: BUZZDRV.ELF says `restart = no`.
///
/// The buzzer is killed (a forced stop): under `on-failure` the manager
/// restarts it; under `no` nothing may serve `endpoint.buzzer` or answer
/// `buzzer_off` for [`restart::DOWN_FOR_MS`]. (The manager's reading of the
/// key, `always` included, is host-tested in `tests/host/compmgr-tests`.)
///
/// `restart-canary` (the manager is shown every row as `on-failure`, whatever
/// the topology says) fails on
/// `[RESTART] FAIL buzzer restarted under restart = no`, which only a manager
/// that treats `no` as `on-failure` prints.
#[cfg(feature = "restart-smoke")]
mod restart {
    use super::*;

    /// How long the driver may take to be serving at boot.
    const SETUP_MS: u64 = 60_000;
    /// How long a killed driver may take to die (TCG, loaded host).
    const BACK_WITHIN_MS: u64 = 20_000;
    /// How long the buzzer must stay down after its death under `no`.
    pub(super) const DOWN_FOR_MS: u64 = 3_000;

    fn sleep_ms(ms: u64) {
        let end = now() + ms * ticks_per_ms();
        while now() < end {
            azos_sched::task_block(WaitReason::Timer(end));
        }
    }

    /// The buzzer is serving `endpoint.buzzer` and answers, within `ms`: its
    /// TID.
    fn buzzer_serving(ms: u64) -> Option<u32> {
        let t0 = now();
        loop {
            if let Some(t) = crate::buzzer::driver_tid() {
                if crate::buzzer::buzzer_off() {
                    return Some(t);
                }
            }
            if now() - t0 > ms * ticks_per_ms() {
                return None;
            }
            sleep_ms(20);
        }
    }

    pub(super) fn run(_: usize) {
        let Some(b0) = buzzer_serving(SETUP_MS) else {
            kprintln!("[RESTART] FAIL setup: buzzer {:?} not serving within {} ms",
                      crate::buzzer::driver_tid(), SETUP_MS);
            return;
        };
        kprintln!("[RESTART] buzzer tid={}", b0);

        // `no`: a kill is final.
        azos_sched::scheduler::task_stop(b0, true, 9);
        let t1 = now();
        let mut refused = 0u32;
        // The dead TID can still own the endpoint until its release lands.
        while now() - t1 < BACK_WITHIN_MS * ticks_per_ms()
            && crate::buzzer::driver_tid() == Some(b0)
        {
            sleep_ms(5);
        }
        let t2 = now();
        while now() - t2 < DOWN_FOR_MS * ticks_per_ms() {
            // Only a different owner than the dead one is a restart.
            if let Some(t) = crate::buzzer::driver_tid().filter(|&t| t != b0) {
                kprintln!("[RESTART] FAIL buzzer restarted under restart = no: tid={} serves it", t);
                return;
            }
            if crate::buzzer::buzzer_off() {
                kprintln!("[RESTART] FAIL buzzer restarted under restart = no: a call was answered");
                return;
            }
            refused += 1;
            sleep_ms(100);
        }
        kprintln!("[RESTART] PASS: buzzer (restart = no) tid={} killed and not restarted: no server \
                   and {} calls refused over {} ms", b0, refused, DOWN_FOR_MS);
    }
}
