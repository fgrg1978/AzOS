// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel side of the cold-restart supervisor for ring-3
//! drivers. The decisions live in `azos_sched::supervisor` (a pure table
//! with host tests); this file is what acts on them.
//!
//! # The path, from a death to a driver serving again
//!
//! 1. The driver's task dies — a fault, a seccomp kill, a stop request from
//!    the kernel (`driver_request_stop`) or its own exit. The exit hook
//!    (`task_release_all_resources`) asks [`exit_verdict`] first.
//! 2. `Restart`: the hook HOLDS what a client reaches the driver through —
//!    the driver-server slot (active, queue and waiters kept, no owner), the
//!    named endpoints (unclaimed, same generation) — and releases everything else as for any task. Then
//!    [`exit_done`] wakes the supervisor task.
//! 3. The supervisor task (created at boot, from a kernel context) creates
//!    the successor on the dead driver's hart, hands it the slot before it can run, and records the restart on the flight recorder.
//! 4. The successor runs the autorun loader on the same path: it re-reads
//!    the image, re-checks its digest against its seccomp profile, is granted
//!    its topology capabilities (re-claiming its named endpoints), and execs.
//!    The image registers its kind exactly as the first one did; the driver
//!    server accepts the owner it was handed to, and the queued requests are
//!    served.
//! 5. `GiveUp` (a failure after `SUP_RESTART_BURST` restarts within
//!    `SUP_RESTART_INTERVAL_S`): the hook releases everything; the supervisor
//!    records it. The kind stays down.
//! 6. `Exited` (the driver exited 0): released like any task, not restarted
//!    and not recorded — systemd's `Restart=on-failure`. Its row's
//!    `restart` key (wave 11) changes that: `always` restarts an exit 0 as
//!    in step 2, `no` ends every death here (`NoRestart`).
//!
//! # The interface (what a kernel caller uses)
//!
//! * [`spawn_supervised`] — the one way a kernel task starts a ring-3 image
//!   that it keeps up itself: the component manager (`boot::launch`), which
//!   no ring-3 supervisor could keep up, and the ML service. Every other
//!   `start = true` row of the topology is the component manager's
//!   (`userspace/services/compmgr`), the ring-3 host of a driver that moves
//!   between hosts (`crate::buzzer`) included: it starts them with
//!   `SYS_SPAWN_EX` and restarts them by the row's `restart` key and the
//!   failure contract of what they serve; the kernel holds no entry for those.
//!   It is `SYS_SPAWN_EX`'s machinery (`spawn_path`):
//!   same digest check, row, class, budget and capabilities. The entry is
//!   made before the child is released, so there is no instant at which the
//!   child runs unsupervised. Its successors are spawned the same way, from
//!   the same path, by the supervisor task (`respawn`, `SupOrigin::Spawned`).
//! * The autorun loader (`load_and_exec_image` in `kernel/src/tasks/loader.rs`) notes its image
//!   itself (`sup_note_spawn`); it is supervised once it registers a kind.
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
//! ([`row_restart`], wave 11). An end under `restart = no` is recorded too
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
    sup_swap_commit, sup_swap_refused, ExitVerdict, SupEntry, SupFall, SupOrigin, SupPolicy, SupRestart, SupState,
    DRIVER_RESTART_COOLDOWN_MS, MAX_SUPERVISED, SUP_IMAGE_MAX,
};
use azos_sched::WaitReason;

/// The supervisor task's TID, 0 until it runs.
static SUP_TID: AtomicU32 = AtomicU32::new(0);

/// Per supervisor slot: the hart the dead driver was pinned to, read in its
/// exit hook, where the successor is created. Not the autorun hart constant:
/// on a machine with fewer harts, the boot's autorun task was moved off a
/// hart that never started (`rebalance_from_offline_cpus`), and a task pinned
/// at run time to such a hart is never dispatched. -1 = any hart.
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
/// can start something supervised: an autorun image is configured, a topology
/// row says `start = true` (the component manager), a driver may move between
/// hosts (the supervisor task does the moves), or ML is enabled (the ML
/// service). It blocks with
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
    /// Hold the driver-server slot and named endpoints for a successor,
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
/// (`crate::buzzer`).
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
/// space: 0 while the wake follows the teardown (wave 12, EXIT2). The
/// `sup-smoke` verdict reads it, as `EARLY_EXIT_NOTICES` is read for the exit
/// notice.
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
                    record(SUP_ACTION_GAVE_UP, e.kind, e.restarts);
                    azos_drv_sys::kerr!("[SUP] gave up on {} (kind {:#x}) after {} restarts: recorded",
                              img, e.kind, e.restarts);
                }
                SupFall::NoRestart => {
                    record(SUP_ACTION_NO_RESTART, e.kind, e.restarts);
                    kprintln!("[SUP] {} (kind {:#x}) ended under restart = no after {} \
                               restarts: recorded", img, e.kind, e.restarts);
                }
            }
            sup_mark_recorded(slot);
        }
        // A driver's move between hosts, asked for by a fault in its kernel
        // host or by its measured cost.
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

/// Step 3: create the successor for `slot`, hand it what its predecessor
/// held, then let it run.
fn respawn(slot: usize) {
    let Some(e) = sup_entry(slot) else { return };
    if e.origin == SupOrigin::Spawned {
        respawn_spawned(slot, &e);
        return;
    }
    if e.origin == SupOrigin::KernelHost {
        respawn_kernel_host(slot, &e);
        return;
    }
    let dead = e.dead_tid;
    let hart = SUCCESSOR_HART.get(slot).map_or(-1, |h| h.load(Ordering::Relaxed));
    match azos_sched::try_task_create_affinity(
        "drv-restart", successor_task, slot, crate::AUTORUN_PRIORITY, hart)
        .and_then(azos_sched::tid_for_idx)
    {
        Some(heir) => {
            // Before `sup_respawned`: the successor waits for that before it
            // loads anything, so the slot is its own by the time its image
            // registers.
            let slots = azos_driver_server::driver_adopt(dead, heir);
            let t = now();
            let _ = sup_respawned(slot, heir, t);
            kprintln!("[SUP] restart {}/{} of {}: successor tid={} for tid={} created {} ms after \
                       the death ({} driver slot(s) handed over)",
                      e.window_n, RESTART_BURST, image_str(e.image()), heir, dead,
                      t.saturating_sub(e.died_at) / ticks_per_ms(), slots);
            record(SUP_ACTION_RESTART, e.kind, e.restarts);
        }
        None => {
            let _ = sup_respawn_failed(slot);
            let _ = azos_driver_server::driver_release_orphans(dead);
            record(SUP_ACTION_RESPAWN_FAILED, e.kind, e.restarts);
            sup_mark_recorded(slot);
            azos_drv_sys::kerr!("[SUP] restart {}/{} of {} REFUSED: task pool full; released, it stays down",
                      e.window_n, RESTART_BURST, image_str(e.image()));
        }
    }
}

/// Step 3 for a kernel host: a new kernel task on the dead one's entry, on
/// its hart. Nothing to hand over (a kernel host holds no driver-server slot);
/// the host registers itself when it starts.
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
            record(SUP_ACTION_RESTART, e.kind, e.restarts);
        }
        None => {
            let _ = sup_respawn_failed(slot);
            record(SUP_ACTION_RESPAWN_FAILED, e.kind, e.restarts);
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
    let (mut slots, mut heir) = (0usize, 0u32);
    let rc = match refusal {
        Some(_) => -1,
        None => {
            let mut hook = |tid| {
                slots = azos_driver_server::driver_adopt(dead, tid);
                if sup_respawned(slot, tid, now()) {
                    heir = tid;
                }
            };
            azos_syscall::spawn::spawn_path_hooked(e.image(), &mut hook)
        }
    };
    if rc > 0 && heir as i64 == rc {
        kprintln!("[SUP] restart {}/{} of {}: successor tid={} for tid={} spawned {} ms after \
                   the death ({} driver slot(s) handed over)",
                  e.window_n, RESTART_BURST, image_str(e.image()), heir, dead,
                  now().saturating_sub(e.died_at) / ticks_per_ms(), slots);
        record(SUP_ACTION_RESTART, e.kind, e.restarts);
        return;
    }
    record(SUP_ACTION_RESPAWN_FAILED, e.kind, e.restarts);
    match sup_respawn_refused(slot, now(), policy()) {
        ExitVerdict::Restart { attempt, not_before, .. } => {
            azos_drv_sys::kwarn!("[SUP] restart {}/{} of {} REFUSED ({}): attempt {}/{} due in {} ms",
                      e.window_n, RESTART_BURST, image_str(e.image()),
                      refusal.unwrap_or("spawn refused"), attempt, RESTART_BURST,
                      not_before.saturating_sub(now()) / ticks_per_ms());
        }
        ExitVerdict::GiveUp { .. } => {
            // As the death after the burst would: nothing is held any more.
            // The give-up itself is recorded by the loop (`next_unrecorded`).
            let _ = azos_driver_server::driver_release_orphans(dead);
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
/// drain, no new generation), move the driver-server slots,
/// and make the successor the entry's task; 5) stop the old server, which is
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
    } else if e.kind != azos_sched::supervisor::SUP_NO_KIND {
        // A driver-server kind is held by its registrant: the successor's own
        // registration at startup is refused until the slot is handed over,
        // which is after the flip. Level 1 swaps a pure IPC server.
        Some("a driver-server task needs Level 2 (its kind is registered by the old task)")
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
            let slots = azos_driver_server::driver_adopt(old, new);
            // Calls queued during the handover wait for a server blocked in its
            // accept: the queue's wake went to the old one.
            azos_sched::wake_fast_ipc_server(new);
            if let Some((o, n2)) = sup_swap_commit(slot, now()) {
                kprintln!("[SUP] swap of {}: tid={} replaced by tid={} ({} endpoint(s) rebound, {} driver \
                           slot(s) handed over)", image_str(e.image()), o, n2, n, slots);
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

/// Step 4: a successor. Waits until the supervisor has made it the entry's
/// task (the hand-over is done by then), then runs the autorun loader on the
/// entry's path. It returns only if the image could not be started, and that
/// exit counts against the budget like any death.
fn successor_task(slot: usize) {
    let me = azos_sched::current_task_tid();
    // Sleep-polled on the counter, with a ceiling: it was an unbounded yield
    // loop, and a yield hands the hart only to tasks at this one's priority
    // or above — never to a lower-priority supervisor on the same hart.
    let give_up = now().saturating_add(azos_syscall::sleep::ms_to_ticks(SUCCESSOR_WAIT_MS));
    let e = loop {
        match sup_entry(slot) {
            Some(e) if e.tid == me => break e,
            Some(e) if e.state == SupState::Restarting && e.tid == 0 => {
                if now() >= give_up {
                    azos_drv_sys::kerr!("[SUP] FAIL successor tid={} was not handed slot {} in {} ms",
                              me, slot, SUCCESSOR_WAIT_MS);
                    return;
                }
                azos_syscall::sleep::sleep_ms(1);
            }
            _ => return,
        }
    };
    let mut path = [0u8; SUP_IMAGE_MAX];
    let n = e.image_len as usize;
    path[..n].copy_from_slice(&e.image[..n]);
    crate::load_and_exec_image(&path[..n]);
    // Reached only when the image could not be started (gone, digest
    // mismatch, gate absent): a FAILURE, so it spends budget like a crash.
    // Returning would exit 0 through `task_entry_wrapper`, which the
    // supervisor reads as a clean exit (`Restart=on-failure`) and would stop
    // the driver for good without a give-up record.
    azos_sched::task_exit_with_code(SUCCESSOR_LOAD_FAILED);
}

/// How long a successor waits for the supervisor to make it the entry's task.
const SUCCESSOR_WAIT_MS: u64 = 10_000;

/// Exit code of a successor whose image could not be started. Non-zero: a
/// failure to the supervisor. Not `128 + signal`: nothing killed it.
const SUCCESSOR_LOAD_FAILED: i32 = 1;

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
/// `action`) or the `Rule::UsbTimeout` one (`trb_type`, `waited_ms`,
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
        Class::Usb => azos_decision::Rule::UsbTimeout,
    };
    azos_decision::record(rule, azos_decision::Verdict::Deny, device_row(device), [detail, waited_ms, action as u64]);
    let tag = match class {
        Class::Block => "BLK",
        Class::Net => "NET",
        Class::Usb => "USB",
    };
    match action {
        Action::Reset => {
            azos_drv_sys::kerr!("[{}] {} timed out after {} ms: device reset, back in service", tag, device, waited_ms)
        }
        Action::Latched => {
            azos_drv_sys::kerr!("[{}] {} timed out again after {} ms with its resets spent: latched dead until reboot", tag, device, waited_ms)
        }
        Action::ResetFailed => {
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

fn record(action: u8, kind: u32, count: u8) {
    let _ = log_safety_violation_durable(
        SAFETY_DRIVER_SUPERVISOR, action, sup_record_detail(kind, count));
}

fn image_str(b: &[u8]) -> &str {
    core::str::from_utf8(b).unwrap_or("?")
}

// ── sup-smoke: the gate row ─────────────────────────────────────────────────

#[cfg(feature = "sup-smoke")]
pub(crate) fn start_smoke() {
    azos_sched::task_create_affinity("sup-smoke", smoke::run, 0,
                                         azos_sched::DEFAULT_PRIORITY, 1);
}

/// Kill the ring-3 GPIO driver four times. Kills 1–3: it must come back and
/// answer a ping, and the time from the death to that first answer is the
/// restart latency (wall clock under TCG). Kill 4: it must stay down — no
/// owner, pings refused for the whole observation window. Then the flight
/// recorder must hold exactly three restarts and one give-up more than before
/// the first kill.
///
/// Every verdict that is not a pass prints a `[SUP] FAIL` line; the one only a
/// kernel without the supervisor prints is `FAIL not restarted after kill 1`.
#[cfg(feature = "sup-smoke")]
mod smoke {
    use super::*;
    use azos_driver_server::DRV_KIND_GPIO;
    use azos_drv_api::{DriverIsolation, DriverManifest};
    use azos_drv_sys::user_driver_proxy::{ProxyError, UserDriverProxy};
    use azos_sched::supervisor::sup_find_kind;

    const GPIO_OP_PING: u32 = 0;
    const PING_REPLY_TAG: u8 = 0xA5;
    // The row's arithmetic and its PASS line are written for a budget of 3
    // (Kconfig `SUP_RESTART_BURST`'s default).
    const DRIVER_MAX_RESTARTS: u8 = RESTART_BURST;
    const _: () = assert!(DRIVER_MAX_RESTARTS == 3, "sup-smoke is written for a budget of 3");
    /// How long a killed driver may take to answer again (TCG, loaded host).
    const BACK_WITHIN_MS: u64 = 20_000;
    /// How long the driver must stay down after the fourth kill.
    const DOWN_FOR_MS: u64 = 3_000;
    const STEP_MS: u64 = 2;

    fn sleep_ms(ms: u64) {
        azos_sched::task_block(WaitReason::Timer(now() + ms * ticks_per_ms()));
    }

    fn ping(proxy: &UserDriverProxy) -> Result<(), ProxyError> {
        let mut out = [0u8; 8];
        match proxy.call(GPIO_OP_PING, &[0x5A], &mut out) {
            Ok(n) if n >= 2 && out[0] == PING_REPLY_TAG => Ok(()),
            Ok(_) => Err(ProxyError::OutputTooLarge),
            Err(e) => Err(e),
        }
    }

    pub(super) fn run(_: usize) {
        // Wait for the AQ3 smoke to finish with the driver.
        while !crate::GPIO_SMOKE_DONE.load(Ordering::Acquire) {
            sleep_ms(50);
        }
        let proxy = UserDriverProxy::new(DriverManifest::new(
            DRV_KIND_GPIO, "gpio-user", DriverIsolation::UserProcess { tid: 0 },
            azos_abi::cap::CapPerms::RW,
        ));
        // The driver may come up after the AQ3 smoke has given up on it.
        let t_setup = now();
        while ping(&proxy).is_err() || sup_find_kind(DRV_KIND_GPIO).is_none() {
            if now() - t_setup > BACK_WITHIN_MS * ticks_per_ms() {
                kprintln!("[SUP] FAIL setup: the GPIO driver is not serving under supervision \
                           after {} ms", BACK_WITHIN_MS);
                return;
            }
            sleep_ms(50);
        }
        #[cfg(feature = "sup-window-smoke")]
        window::run(&proxy);
        #[cfg(not(feature = "sup-window-smoke"))]
        budget(&proxy);
    }

    /// The four-kill budget sequence above.
    #[cfg(not(feature = "sup-window-smoke"))]
    fn budget(proxy: &UserDriverProxy) {
        kprintln!("[SUP] smoke: GPIO driver tid={} serving under supervision; stopping it {} times",
                  azos_driver_server::driver_owner_tid(DRV_KIND_GPIO).unwrap_or(0),
                  DRIVER_MAX_RESTARTS + 1);
        let (r0, g0) = count_records();
        // Per restart: successor created -> first reply (the mechanism: load,
        // hash, exec, register, serve), and the death -> creation wait (the
        // cooldown from the second restart on, a few ms for the first).
        let mut lat = [0u64; DRIVER_MAX_RESTARTS as usize];
        let mut wait = [0u64; DRIVER_MAX_RESTARTS as usize];
        let mut first = 0u64;
        for kill in 1..=(DRIVER_MAX_RESTARTS + 1) {
            let Some(victim) = azos_driver_server::driver_request_stop(DRV_KIND_GPIO) else {
                kprintln!("[SUP] FAIL kill {}: no GPIO driver to stop", kill);
                return;
            };
            // The death, as the supervisor saw it.
            let t0 = now();
            let died_at = loop {
                if let Some((_, e)) = sup_find_kind(DRV_KIND_GPIO) {
                    if e.dead_tid == victim && e.tid != victim {
                        break Some(e.died_at);
                    }
                }
                if now() - t0 > BACK_WITHIN_MS * ticks_per_ms() {
                    break None;
                }
                sleep_ms(STEP_MS);
            };
            if kill <= DRIVER_MAX_RESTARTS {
                // Any death must be SEEN by a supervisor, and followed by an
                // answer from a new task.
                let back = loop {
                    let owner = azos_driver_server::driver_owner_tid(DRV_KIND_GPIO);
                    if owner.is_some() && owner != Some(victim) && ping(&proxy).is_ok() {
                        break Some(now());
                    }
                    if now() - t0 > BACK_WITHIN_MS * ticks_per_ms() {
                        break None;
                    }
                    sleep_ms(STEP_MS);
                };
                let (Some(died_at), Some(back)) = (died_at, back) else {
                    kprintln!("[SUP] FAIL not restarted after kill {}: tid={} stopped, no \
                               driver answered within {} ms (death seen by a supervisor: {})",
                              kill, victim, BACK_WITHIN_MS, died_at.is_some());
                    return;
                };
                let e = sup_find_kind(DRV_KIND_GPIO).map(|(_, e)| e).unwrap();
                let ms = |t: u64| t.saturating_sub(died_at) / ticks_per_ms();
                lat[kill as usize - 1] = ms(back).saturating_sub(ms(e.respawned_at));
                wait[kill as usize - 1] = ms(e.respawned_at);
                if kill == 1 {
                    first = ms(back);
                }
                kprintln!("[SUP] kill {}: tid={} died, restart {}/{} -> tid={} serving: \
                           successor created +{} ms, registered +{} ms, first reply +{} ms",
                          kill, victim, e.restarts, DRIVER_MAX_RESTARTS, e.tid,
                          ms(e.respawned_at), ms(e.bound_at), ms(back));
                if e.restarts != kill {
                    kprintln!("[SUP] FAIL kill {}: the supervisor counts {} restarts", kill,
                              e.restarts);
                    return;
                }
            } else {
                if died_at.is_none() {
                    kprintln!("[SUP] FAIL kill {}: tid={} did not die", kill, victim);
                    return;
                }
                // Budget spent: it must stay down for the whole window.
                let t1 = now();
                let mut refused = 0u32;
                while now() - t1 < DOWN_FOR_MS * ticks_per_ms() {
                    if let Some(t) = azos_driver_server::driver_owner_tid(DRV_KIND_GPIO) {
                        kprintln!("[SUP] FAIL restarted past the budget: tid={} owns GPIO after \
                                   kill {}", t, kill);
                        return;
                    }
                    match ping(&proxy) {
                        Ok(()) => {
                            kprintln!("[SUP] FAIL restarted past the budget: a ping was answered \
                                       after kill {}", kill);
                            return;
                        }
                        Err(_) => refused += 1,
                    }
                    sleep_ms(100);
                }
                let state = sup_find_kind(DRV_KIND_GPIO).map(|(_, e)| e.state);
                if state != Some(SupState::Down) {
                    kprintln!("[SUP] FAIL kill {}: supervisor state {:?}, not Down", kill, state);
                    return;
                }
                kprintln!("[SUP] kill {}: tid={} died with the budget spent: no owner and {} \
                           pings refused over {} ms", kill, victim, refused, DOWN_FOR_MS);
            }
        }
        // The give-up is recorded by the supervisor task; wait for its mark.
        let t2 = now();
        while !sup_find_kind(DRV_KIND_GPIO).map_or(false, |(_, e)| e.recorded) {
            if now() - t2 > BACK_WITHIN_MS * ticks_per_ms() {
                kprintln!("[SUP] FAIL the give-up was never recorded");
                return;
            }
            sleep_ms(20);
        }
        let _ = azos_actuation::logger::logger_flush();
        let (r1, g1) = count_records();
        if (r1.wrapping_sub(r0), g1.wrapping_sub(g0)) != (DRIVER_MAX_RESTARTS as u32, 1) {
            kprintln!("[SUP] FAIL flight recorder: {} restart and {} give-up record(s) added, \
                       want {} and 1", r1.wrapping_sub(r0), g1.wrapping_sub(g0),
                      DRIVER_MAX_RESTARTS);
            return;
        }
        let early = EARLY_SUP_WAKES.load(Ordering::Relaxed);
        if early != 0 {
            kprintln!("[SUP] FAIL the supervisor was woken {} time(s) while the dead driver \
                       still held its address space", early);
            return;
        }
        let mut s = lat;
        s.sort_unstable();
        kprintln!("[SUP] PASS budget {}: {} restarts served, the death after the last stays \
                   down; recorded {} restarts + 1 give-up. Restart latency: first restart death \
                   -> first reply {} ms; successor created -> first reply {} / {} / {} ms \
                   min/median/max; death -> successor created {} / {} / {} ms (cooldown from \
                   the second)",
                  DRIVER_MAX_RESTARTS, DRIVER_MAX_RESTARTS, DRIVER_MAX_RESTARTS, first,
                  s[0], s[s.len() / 2], s[s.len() - 1], wait[0], wait[1], wait[2]);
    }

    /// `sup-window-smoke`: the two owner decisions of 2026-09-28, on a kernel
    /// built with a short `SUP_RESTART_INTERVAL_S` (the gate row sets it).
    ///
    /// 1. Kill (137) -> restart 1 of the window. Wait the interval out, plus a
    ///    margin, after that restart. Kill again -> restarted, and counted as
    ///    restart **1** of a fresh window: the first restart no longer counts.
    ///    A supervisor that never forgets counts it as 2 and fails here, on
    ///    `FAIL window`.
    /// 2. Stop with exit code 0, the code a driver's own `exit(0)` passes to
    ///    `task_exit_with_code` -> NOT restarted: no owner and every ping
    ///    refused for `DOWN_FOR_MS`, entry `Exited`. A supervisor that restarts
    ///    on any death fails on `FAIL restarted after exit 0`.
    #[cfg(feature = "sup-window-smoke")]
    mod window {
        use super::*;

        /// Stop the GPIO driver with exit `code` and wait until the supervisor has
        /// seen that death. The dead TID, or `None` (a `[SUP] FAIL` is printed).
        fn stop_and_see_death(step: &str, code: i32) -> Option<u32> {
            let Some(victim) = azos_driver_server::driver_request_stop_code(DRV_KIND_GPIO, code)
            else {
                kprintln!("[SUP] FAIL {}: no GPIO driver to stop", step);
                return None;
            };
            let t0 = now();
            loop {
                if let Some((_, e)) = sup_find_kind(DRV_KIND_GPIO) {
                    if e.dead_tid == victim && e.tid != victim {
                        return Some(victim);
                    }
                }
                if now() - t0 > BACK_WITHIN_MS * ticks_per_ms() {
                    kprintln!("[SUP] FAIL {}: tid={} stopped with exit {}, no death seen within {} ms",
                              step, victim, code, BACK_WITHIN_MS);
                    return None;
                }
                sleep_ms(STEP_MS);
            }
        }

        /// A new task owns the GPIO kind and answers a ping, within the bound.
        fn back_serving(proxy: &UserDriverProxy, victim: u32) -> bool {
            let t0 = now();
            loop {
                let owner = azos_driver_server::driver_owner_tid(DRV_KIND_GPIO);
                if owner.is_some() && owner != Some(victim) && ping(proxy).is_ok() {
                    return true;
                }
                if now() - t0 > BACK_WITHIN_MS * ticks_per_ms() {
                    return false;
                }
                sleep_ms(STEP_MS);
            }
        }


        pub(in super::super) fn run(proxy: &UserDriverProxy) {
            kprintln!("[SUP] window smoke: burst {} within {} s; GPIO driver tid={} serving",
                      RESTART_BURST, RESTART_INTERVAL_S,
                      azos_driver_server::driver_owner_tid(DRV_KIND_GPIO).unwrap_or(0));
            if RESTART_INTERVAL_S > 30 {
                kprintln!("[SUP] FAIL window smoke needs SUP_RESTART_INTERVAL_S <= 30, built \
                           with {}", RESTART_INTERVAL_S);
                return;
            }
            // 1a. First failure: restart 1 of a window.
            let Some(v1) = stop_and_see_death("kill 1", azos_abi::exit_status::KILLED_KILL)
            else { return };
            if !back_serving(proxy, v1) {
                kprintln!("[SUP] FAIL kill 1: tid={} not restarted within {} ms", v1, BACK_WITHIN_MS);
                return;
            }
            let Some((_, e1)) = sup_find_kind(DRV_KIND_GPIO) else { return };
            if e1.window_n != 1 || e1.restarts != 1 {
                kprintln!("[SUP] FAIL kill 1: window {} total {}, want 1 and 1", e1.window_n,
                          e1.restarts);
                return;
            }
            kprintln!("[SUP] window kill 1: tid={} died (exit 137) -> tid={} serving, restart 1/{} \
                       of the window", v1, e1.tid, RESTART_BURST);
            // 1b. Let the interval pass after that restart was granted.
            let wait_until = e1.died_at + (RESTART_INTERVAL_S + 2) * freq();
            while now() < wait_until {
                sleep_ms(100);
            }
            let Some(v2) = stop_and_see_death("kill 2", azos_abi::exit_status::KILLED_KILL)
            else { return };
            if !back_serving(proxy, v2) {
                kprintln!("[SUP] FAIL kill 2: tid={} not restarted within {} ms", v2, BACK_WITHIN_MS);
                return;
            }
            let Some((_, e2)) = sup_find_kind(DRV_KIND_GPIO) else { return };
            let apart_ms = (e2.died_at - e1.died_at) / ticks_per_ms();
            if e2.window_n != 1 {
                kprintln!("[SUP] FAIL window: the restart {} ms earlier (interval {} s) still \
                           counts: restart {} of the window, want 1", apart_ms,
                          RESTART_INTERVAL_S, e2.window_n);
                return;
            }
            kprintln!("[SUP] window kill 2: {} ms after kill 1 -> tid={} serving, restart 1/{} of a \
                       fresh window ({} in total)", apart_ms, e2.tid, RESTART_BURST, e2.restarts);
            // 2. A clean exit is not restarted.
            let Some(v3) = stop_and_see_death("exit 0", 0) else { return };
            let t1 = now();
            let mut refused = 0u32;
            while now() - t1 < DOWN_FOR_MS * ticks_per_ms() {
                // The dead driver itself may still hold the slot until the
                // supervisor task releases it: only ANOTHER owner is a restart.
                if let Some(t) = azos_driver_server::driver_owner_tid(DRV_KIND_GPIO)
                    .filter(|&t| t != v3)
                {
                    kprintln!("[SUP] FAIL restarted after exit 0: tid={} owns GPIO", t);
                    return;
                }
                match ping(proxy) {
                    Ok(()) => {
                        kprintln!("[SUP] FAIL restarted after exit 0: a ping was answered");
                        return;
                    }
                    Err(_) => refused += 1,
                }
                sleep_ms(100);
            }
            let state = sup_find_kind(DRV_KIND_GPIO).map(|(_, e)| e.state);
            if state != Some(SupState::Exited) {
                kprintln!("[SUP] FAIL exit 0: supervisor state {:?}, not Exited", state);
                return;
            }
            kprintln!("[SUP] PASS window: a restart {} ms old (interval {} s) no longer counted; \
                       tid={} exited 0 and was not restarted: no owner and {} pings refused over \
                       {} ms", apart_ms, RESTART_INTERVAL_S, v3, refused, DOWN_FOR_MS);
        }
    }

    /// `SAFETY_DRIVER_SUPERVISOR` records on disk: (restarts, give-ups), in
    /// THIS session's file. Not `LOG00000.BIN`: a disk that was booted before
    /// resumes at the next serial (U08-3), and the gate's gpio_drv disk has
    /// been booted twice (the GPIO and proxy rows) before this row copies it.
    #[cfg(not(feature = "sup-window-smoke"))]
    fn count_records() -> (u32, u32) {
        use azos_actuation::logger as lg;
        let (mut r, mut g) = (0u32, 0u32);
        let mut path = [0u8; 17];
        lg::make_log_path(lg::logger_current_serial(), &mut path);
        let Ok(vol) = azos_fs::fat32_mount_volume() else { return (0, 0) };
        let Ok(file) = azos_fs::fat32_open(vol, &path,
                                               azos_fs::open_flags::READ) else {
            return (0, 0);
        };
        let mut hdr = [0u8; lg::LOG_FILE_HEADER_BYTES];
        let _ = azos_fs::fat32_read(file, &mut hdr);
        loop {
            let mut raw = [0u8; lg::LOG_RECORD_SIZE];
            match azos_fs::fat32_read(file, &mut raw) {
                Ok(n) if n == lg::LOG_RECORD_SIZE => {
                    let rec = lg::LogRecord::decode(&raw);
                    if rec.kind == lg::LOG_EVT_SAFETY_VIOLATION
                        && rec.payload[0] == SAFETY_DRIVER_SUPERVISOR
                    {
                        match rec.payload[1] {
                            SUP_ACTION_RESTART => r += 1,
                            SUP_ACTION_GAVE_UP => g += 1,
                            _ => {}
                        }
                    }
                }
                _ => break,
            }
        }
        let _ = azos_fs::fat32_close(file);
        (r, g)
    }
}

// ── supall-smoke: the wave 11 gate row ──────────────────────────────────────

#[cfg(feature = "supall-smoke")]
pub(crate) fn start_supall_smoke() {
    azos_sched::task_create_affinity("supall-smoke", supall::run, 0,
                                         azos_sched::DEFAULT_PRIORITY, 1);
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
