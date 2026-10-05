// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RFC-0049 M4: the kernel side of the cold-restart supervisor for ring-3
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
//!    named endpoints (unclaimed, same generation) and the service names
//!    (`Stopped`) — and releases everything else as for any task. Then
//!    [`exit_done`] wakes the supervisor task.
//! 3. The supervisor task (created at boot, from a kernel context) creates
//!    the successor on the dead driver's hart, hands it the slot and the names
//!    before it can run, and records the restart on the flight recorder.
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
//!   the system declares (a topology `start = true` row, the ML service) so
//!   that it is supervised. It is `SYS_SPAWN`'s machinery (`spawn_path`):
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
use azos_drv_sys::timebase::{now, TIMER_FREQ};
use azos_sched::supervisor::{
    sup_entry, sup_find_image, sup_held, sup_mark_recorded, sup_next_due, sup_next_unrecorded,
    sup_note_started, sup_on_exit, sup_respawn_failed, sup_respawn_refused, sup_respawned,
    sup_set_restart, ExitVerdict, SupEntry, SupFall, SupOrigin, SupPolicy, SupRestart, SupState,
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
    (TIMER_FREQ / 1000).max(1)
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
        interval: RESTART_INTERVAL_S.saturating_mul(TIMER_FREQ),
        cooldown: DRIVER_RESTART_COOLDOWN_MS.saturating_mul(ticks_per_ms()),
    }
}

/// Create the supervisor task. Called once, by `kernel_main`, on a boot that
/// can start something supervised: an autorun image is configured, a topology
/// row says `start = true`, or ML is enabled (the ML service). It blocks with
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
#[cfg(any(feature = "buzzer-kernel", feature = "ina219-kernel"))]
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

/// Start the ring-3 image at `path` as `SYS_SPAWN` would (`spawn_path`), and
/// supervise it from its first instruction. Returns the child's TID, or what
/// `spawn_path` returns on a refusal (no entry is made then: a program that
/// never started has nothing to restart).
///
/// `supall-canary` starts it unsupervised, as every kernel spawn was before
/// wave 11: the gate rows' canary build fails on the line only an image that
/// never came back prints.
pub(crate) fn spawn_supervised(path: &[u8]) -> i64 {
    if cfg!(feature = "supall-canary") {
        return azos_syscall::spawn::spawn_path(path);
    }
    let mut slot = None;
    let restart = row_restart(path);
    let rc = azos_syscall::spawn::spawn_path_hooked(path, &mut |tid| {
        slot = sup_note_started(tid, path);
        if let Some(s) = slot {
            let _ = sup_set_restart(s, restart);
        }
    });
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
/// row names it or no topology is installed.
///
/// `restart-canary` ignores the row (every image restarts on failure only,
/// as before the key existed): the `restart` gate row must then fail.
pub(crate) fn row_restart(path: &[u8]) -> SupRestart {
    if cfg!(feature = "restart-canary") {
        return SupRestart::OnFailure;
    }
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
#[cfg_attr(any(feature = "no-ml", not(feature = "domain-robot")), allow(dead_code))]
pub(crate) fn current_tid(path: &[u8]) -> Option<u32> {
    sup_find_image(path).map(|(_, e)| if e.tid != 0 { e.tid } else { e.dead_tid })
}

/// What the exit hook decided for one dying task.
#[derive(Clone, Copy)]
pub(crate) struct Exit(ExitVerdict);

impl Exit {
    /// Hold the driver-server slot, named endpoints and service names for a
    /// successor, instead of releasing them.
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
            // loads anything, so the slot and names are its own by the time
            // its image registers.
            let slots = azos_driver_server::driver_adopt(dead, heir);
            let names = azos_service::service_adopt(dead, heir);
            let t = now();
            let _ = sup_respawned(slot, heir, t);
            kprintln!("[SUP] restart {}/{} of {}: successor tid={} for tid={} created {} ms after \
                       the death ({} driver slot(s), {} name(s) handed over)",
                      e.window_n, RESTART_BURST, image_str(e.image()), heir, dead,
                      t.saturating_sub(e.died_at) / ticks_per_ms(), slots, names);
            record(SUP_ACTION_RESTART, e.kind, e.restarts);
        }
        None => {
            let _ = sup_respawn_failed(slot);
            let _ = azos_driver_server::driver_release_orphans(dead);
            let _ = azos_service::service_release_all(dead);
            record(SUP_ACTION_RESPAWN_FAILED, e.kind, e.restarts);
            sup_mark_recorded(slot);
            azos_drv_sys::kerr!("[SUP] restart {}/{} of {} REFUSED: task pool full; released, it stays down",
                      e.window_n, RESTART_BURST, image_str(e.image()));
        }
    }
}

/// Step 3 for a kernel host: a new kernel task on the dead one's entry, on
/// its hart. Nothing to hand over (a kernel host holds no driver-server slot
/// or service name); the host registers itself when it starts.
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
    let (mut slots, mut names, mut heir) = (0usize, 0usize, 0u32);
    let rc = match refusal {
        Some(_) => -1,
        None => azos_syscall::spawn::spawn_path_hooked(e.image(), &mut |tid| {
            slots = azos_driver_server::driver_adopt(dead, tid);
            names = azos_service::service_adopt(dead, tid);
            if sup_respawned(slot, tid, now()) {
                heir = tid;
            }
        }),
    };
    if rc > 0 && heir as i64 == rc {
        kprintln!("[SUP] restart {}/{} of {}: successor tid={} for tid={} spawned {} ms after \
                   the death ({} driver slot(s), {} name(s) handed over)",
                  e.window_n, RESTART_BURST, image_str(e.image()), heir, dead,
                  now().saturating_sub(e.died_at) / ticks_per_ms(), slots, names);
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
            let _ = azos_service::service_release_all(dead);
            azos_drv_sys::kerr!("[SUP] restart {}/{} of {} REFUSED ({}): budget spent, released, it \
                       stays down", e.window_n, RESTART_BURST, image_str(e.image()),
                      refusal.unwrap_or("spawn refused"));
        }
        ExitVerdict::NotSupervised | ExitVerdict::Exited { .. } | ExitVerdict::NoRestart { .. } => {}
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
            let wait_until = e1.died_at + (RESTART_INTERVAL_S + 2) * TIMER_FREQ;
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

/// The two ring-3 drivers the topology starts (`start = true`: the buzzer and
/// the INA219), killed under supervision.
///
/// 1. The buzzer is stopped once (exit 137, the kernel's stop): a new task
///    must own `DRV_KIND_BUZZER` and answer `buzzer_off`.
/// 2. The INA219 crash-loops: it is stopped each time it is serving again,
///    four times. Kills 1-3 must be restarted (a new owner answers a power
///    read); kill 4 finds the budget (3 within the interval) spent: no owner
///    and every read refused for 3 s, entry `Down`, the give-up recorded.
/// 3. The flight recorder must hold, for these two kinds, exactly one restart
///    of the buzzer, three of the INA219 and one give-up of the INA219 more
///    than before step 1.
///
/// Every verdict that is not a pass prints `[SUPALL] FAIL`; the one only a
/// kernel that does not supervise its spawned drivers prints is
/// `[SUPALL] FAIL buzzer not restarted`.
#[cfg(feature = "supall-smoke")]
mod supall {
    use super::*;
    use azos_driver_server::{driver_owner_tid, driver_request_stop, DRV_KIND_BUZZER,
                                 DRV_KIND_POWER_MON};
    use azos_sched::supervisor::sup_find_kind;

    const _: () = assert!(RESTART_BURST == 3, "supall-smoke is written for a budget of 3");
    /// How long the drivers may take to be serving at boot (the launcher reads
    /// their ELFs off FAT32 after the volume is mounted).
    const SETUP_MS: u64 = 60_000;
    /// How long a killed driver may take to answer again (TCG, loaded host).
    const BACK_WITHIN_MS: u64 = 20_000;
    /// How long the INA219 must stay down after the death past the budget.
    const DOWN_FOR_MS: u64 = 3_000;

    fn sleep_ms(ms: u64) {
        let end = now() + ms * ticks_per_ms();
        while now() < end {
            azos_sched::task_block(WaitReason::Timer(end));
        }
    }

    fn buzzer_answers() -> bool {
        azos_drv_actuator::buzzer::buzzer_off()
    }

    fn ina_answers() -> bool {
        use azos_drv_sensor::ina219::{ina219_read_power, POWER_DATA_SIZE};
        let mut b = [0u8; POWER_DATA_SIZE];
        ina219_read_power(&mut b) == POWER_DATA_SIZE
    }

    /// A task other than `not` owns the kind and answers, within `ms`. Its
    /// TID, or `None`. Only an owner the supervisor's entry stands for
    /// (`Serving`, same TID) counts, except at setup (`not == 0`): there the
    /// canary build, which supervises nothing, must still get to its kill.
    fn serving(kind: u32, answers: fn() -> bool, not: u32, ms: u64) -> Option<u32> {
        let t0 = now();
        loop {
            if let Some(t) = driver_owner_tid(kind) {
                let supervised = sup_find_kind(kind)
                    .is_some_and(|(_, e)| e.tid == t && e.state == SupState::Serving);
                if t != not && (supervised || not == 0) && answers() {
                    return Some(t);
                }
            }
            if now() - t0 > ms * ticks_per_ms() {
                return None;
            }
            sleep_ms(20);
        }
    }

    /// Stop the kind's driver and wait until it is dead: it no longer owns
    /// the kind (held for a successor or released). The dead TID, or `None`
    /// with a `[SUPALL] FAIL` printed.
    fn kill(name: &str, kind: u32, step: u32) -> Option<u32> {
        let Some(victim) = driver_request_stop(kind) else {
            kprintln!("[SUPALL] FAIL {} kill {}: no driver to stop", name, step);
            return None;
        };
        let t0 = now();
        loop {
            if driver_owner_tid(kind) != Some(victim) {
                return Some(victim);
            }
            if now() - t0 > BACK_WITHIN_MS * ticks_per_ms() {
                kprintln!("[SUPALL] FAIL {} kill {}: tid={} asked to stop, still the owner after \
                           {} ms", name, step, victim, BACK_WITHIN_MS);
                return None;
            }
            sleep_ms(2);
        }
    }

    pub(super) fn run(_: usize) {
        let (Some(b0), Some(i0)) = (serving(DRV_KIND_BUZZER, buzzer_answers, 0, SETUP_MS),
                                    serving(DRV_KIND_POWER_MON, ina_answers, 0, SETUP_MS)) else {
            kprintln!("[SUPALL] FAIL setup: buzzer {:?} / INA219 {:?} not serving under supervision \
                       within {} ms", driver_owner_tid(DRV_KIND_BUZZER),
                      driver_owner_tid(DRV_KIND_POWER_MON), SETUP_MS);
            return;
        };
        kprintln!("[SUPALL] buzzer tid={} and INA219 tid={} serving (supervised: {} / {})",
                  b0, i0, sup_find_kind(DRV_KIND_BUZZER).is_some(),
                  sup_find_kind(DRV_KIND_POWER_MON).is_some());
        let before = count(DRV_KIND_BUZZER, DRV_KIND_POWER_MON);

        // 1. The buzzer: one kill, one restart.
        let Some(v) = kill("buzzer", DRV_KIND_BUZZER, 1) else { return };
        let t0 = now();
        let Some(b1) = serving(DRV_KIND_BUZZER, buzzer_answers, v, BACK_WITHIN_MS) else {
            kprintln!("[SUPALL] FAIL buzzer not restarted: tid={} killed, no new driver answered \
                       within {} ms", v, BACK_WITHIN_MS);
            return;
        };
        kprintln!("[SUPALL] buzzer: tid={} killed -> tid={} answering after {} ms (restart 1/{})",
                  v, b1, (now() - t0) / ticks_per_ms(), RESTART_BURST);

        // 2. The INA219: a crash loop.
        for step in 1..=(RESTART_BURST as u32 + 1) {
            let Some(v) = kill("INA219", DRV_KIND_POWER_MON, step) else { return };
            if step <= RESTART_BURST as u32 {
                let t0 = now();
                let Some(t) = serving(DRV_KIND_POWER_MON, ina_answers, v, BACK_WITHIN_MS) else {
                    kprintln!("[SUPALL] FAIL INA219 not restarted after kill {}: tid={} killed, no \
                               new driver answered within {} ms", step, v, BACK_WITHIN_MS);
                    return;
                };
                kprintln!("[SUPALL] INA219 kill {}: tid={} -> tid={} answering after {} ms",
                          step, v, t, (now() - t0) / ticks_per_ms());
                continue;
            }
            let t1 = now();
            let mut refused = 0u32;
            while now() - t1 < DOWN_FOR_MS * ticks_per_ms() {
                if let Some(t) = driver_owner_tid(DRV_KIND_POWER_MON) {
                    kprintln!("[SUPALL] FAIL INA219 restarted past the budget: tid={} owns it after \
                               kill {}", t, step);
                    return;
                }
                if ina_answers() {
                    kprintln!("[SUPALL] FAIL INA219 restarted past the budget: a read was answered \
                               after kill {}", step);
                    return;
                }
                refused += 1;
                sleep_ms(100);
            }
            let e = sup_find_kind(DRV_KIND_POWER_MON).map(|(_, e)| e);
            if e.map(|e| e.state) != Some(SupState::Down) {
                kprintln!("[SUPALL] FAIL INA219 kill {}: supervisor state {:?}, not Down", step,
                          e.map(|e| e.state));
                return;
            }
            kprintln!("[SUPALL] INA219 kill {}: tid={} died with the budget spent: no owner and {} \
                       reads refused over {} ms", step, v, refused, DOWN_FOR_MS);
        }
        let t2 = now();
        while !sup_find_kind(DRV_KIND_POWER_MON).map_or(false, |(_, e)| e.recorded) {
            if now() - t2 > BACK_WITHIN_MS * ticks_per_ms() {
                kprintln!("[SUPALL] FAIL the INA219 give-up was never recorded");
                return;
            }
            sleep_ms(20);
        }
        let _ = azos_actuation::logger::logger_flush();
        let after = count(DRV_KIND_BUZZER, DRV_KIND_POWER_MON);
        let added = (after.0.wrapping_sub(before.0), after.1.wrapping_sub(before.1),
                     after.2.wrapping_sub(before.2));
        if added != (1, RESTART_BURST as u32, 1) {
            kprintln!("[SUPALL] FAIL flight recorder: buzzer restarts +{}, INA219 restarts +{}, \
                       INA219 give-ups +{}; want +1, +{}, +1", added.0, added.1, added.2,
                      RESTART_BURST);
            return;
        }
        kprintln!("[SUPALL] PASS: buzzer killed and restarted; INA219 restarted {} times then given \
                   up on, down for {} ms; recorded 1 + {} restarts and 1 give-up",
                  RESTART_BURST, DOWN_FOR_MS, RESTART_BURST);
    }

    /// `SAFETY_DRIVER_SUPERVISOR` records in this session's log file:
    /// (restarts of `a`, restarts of `b`, give-ups of `b`), by the kind in
    /// the record's detail word (`sup_record_detail`).
    fn count(a: u32, b: u32) -> (u32, u32, u32) {
        use azos_actuation::logger as lg;
        let (mut ra, mut rb, mut gb) = (0u32, 0u32, 0u32);
        let mut path = [0u8; 17];
        lg::make_log_path(lg::logger_current_serial(), &mut path);
        let Ok(vol) = azos_fs::fat32_mount_volume() else { return (0, 0, 0) };
        let Ok(file) = azos_fs::fat32_open(vol, &path, azos_fs::open_flags::READ) else {
            return (0, 0, 0);
        };
        let mut hdr = [0u8; lg::LOG_FILE_HEADER_BYTES];
        let _ = azos_fs::fat32_read(file, &mut hdr);
        loop {
            let mut raw = [0u8; lg::LOG_RECORD_SIZE];
            match azos_fs::fat32_read(file, &mut raw) {
                Ok(n) if n == lg::LOG_RECORD_SIZE => {
                    let rec = lg::LogRecord::decode(&raw);
                    if rec.kind != lg::LOG_EVT_SAFETY_VIOLATION
                        || rec.payload[0] != SAFETY_DRIVER_SUPERVISOR
                    {
                        continue;
                    }
                    let detail = u32::from_le_bytes([rec.payload[4], rec.payload[5],
                                                     rec.payload[6], rec.payload[7]]);
                    let kind = detail >> 16;
                    match (rec.payload[1], kind) {
                        (SUP_ACTION_RESTART, k) if k == a & 0xFFFF => ra += 1,
                        (SUP_ACTION_RESTART, k) if k == b & 0xFFFF => rb += 1,
                        (SUP_ACTION_GAVE_UP, k) if k == b & 0xFFFF => gb += 1,
                        _ => {}
                    }
                }
                _ => break,
            }
        }
        let _ = azos_fs::fat32_close(file);
        (ra, rb, gb)
    }
}

/// Wave 11 (DRVPLACE): the `restart-smoke` task (see [`restart`]).
#[cfg(feature = "restart-smoke")]
pub(crate) fn start_restart_smoke() {
    azos_sched::task_create_affinity("restart-smoke", restart::run, 0,
                                         azos_sched::DEFAULT_PRIORITY, 1);
}

/// The topology row key `restart`, honoured. The drv disk's two ring-3
/// drivers, under the `restart-smoke` topology: BUZZDRV.ELF says
/// `restart = always`, INADRV.ELF `restart = no`.
///
/// 1. The buzzer is stopped with exit code 0 (what its own `exit(0)` passes):
///    under `on-failure` that is final; under `always` a new task must own
///    `DRV_KIND_BUZZER` and answer `buzzer_off`.
/// 2. The INA219 is stopped with exit 137 (a kill): under `on-failure` it is
///    restarted; under `no` nothing may own `DRV_KIND_POWER_MON` or answer a
///    power read for [`restart::DOWN_FOR_MS`], and its entry is final.
///
/// `restart-canary` (the supervisor ignores the row) fails step 1 on
/// `[RESTART] FAIL buzzer not restarted after exit 0`, which only a
/// supervisor that treats `always` as `on-failure` prints.
#[cfg(feature = "restart-smoke")]
mod restart {
    use super::*;
    use azos_driver_server::{driver_owner_tid, driver_request_stop_code, DRV_KIND_BUZZER,
                                 DRV_KIND_POWER_MON};
    use azos_sched::supervisor::sup_find_kind;

    /// How long the drivers may take to be serving at boot.
    const SETUP_MS: u64 = 60_000;
    /// How long a stopped driver may take to die, and a restarted one to
    /// answer again (TCG, loaded host).
    const BACK_WITHIN_MS: u64 = 20_000;
    /// How long the INA219 must stay down after its death under `no`.
    pub(super) const DOWN_FOR_MS: u64 = 3_000;

    fn sleep_ms(ms: u64) {
        let end = now() + ms * ticks_per_ms();
        while now() < end {
            azos_sched::task_block(WaitReason::Timer(end));
        }
    }

    fn buzzer_answers() -> bool {
        azos_drv_actuator::buzzer::buzzer_off()
    }

    fn ina_answers() -> bool {
        use azos_drv_sensor::ina219::{ina219_read_power, POWER_DATA_SIZE};
        let mut b = [0u8; POWER_DATA_SIZE];
        ina219_read_power(&mut b) == POWER_DATA_SIZE
    }

    /// A supervised task other than `not` owns `kind` and answers, within
    /// `ms`: its TID.
    fn serving(kind: u32, answers: fn() -> bool, not: u32, ms: u64) -> Option<u32> {
        let t0 = now();
        loop {
            if let Some(t) = driver_owner_tid(kind) {
                let supervised = sup_find_kind(kind)
                    .is_some_and(|(_, e)| e.tid == t && e.state == SupState::Serving);
                if t != not && supervised && answers() {
                    return Some(t);
                }
            }
            if now() - t0 > ms * ticks_per_ms() {
                return None;
            }
            sleep_ms(20);
        }
    }

    /// Stop `kind`'s driver with exit `code` and wait until the supervisor
    /// has seen the death. The dead TID, or `None` with a FAIL printed.
    fn stop(name: &str, kind: u32, code: i32) -> Option<u32> {
        let Some(victim) = driver_request_stop_code(kind, code) else {
            kprintln!("[RESTART] FAIL {}: no driver to stop", name);
            return None;
        };
        let t0 = now();
        loop {
            if sup_find_kind(kind).is_some_and(|(_, e)| e.dead_tid == victim && e.tid != victim) {
                return Some(victim);
            }
            if now() - t0 > BACK_WITHIN_MS * ticks_per_ms() {
                kprintln!("[RESTART] FAIL {}: tid={} stopped with exit {}, no death seen within {} ms",
                          name, victim, code, BACK_WITHIN_MS);
                return None;
            }
            sleep_ms(5);
        }
    }

    pub(super) fn run(_: usize) {
        if azos_drv_sensor::ina219::IN_KERNEL {
            kprintln!("[RESTART] FAIL setup: needs the ring-3 INA219 (DRV_INA219_PLACEMENT = ring3)");
            return;
        }
        let (Some(b0), Some(i0)) = (serving(DRV_KIND_BUZZER, buzzer_answers, 0, SETUP_MS),
                                    serving(DRV_KIND_POWER_MON, ina_answers, 0, SETUP_MS)) else {
            kprintln!("[RESTART] FAIL setup: buzzer {:?} / INA219 {:?} not serving under supervision \
                       within {} ms", driver_owner_tid(DRV_KIND_BUZZER),
                      driver_owner_tid(DRV_KIND_POWER_MON), SETUP_MS);
            return;
        };
        let policy = |k| sup_find_kind(k).map(|(_, e)| e.restart);
        kprintln!("[RESTART] buzzer tid={} restart={:?}, INA219 tid={} restart={:?}",
                  b0, policy(DRV_KIND_BUZZER), i0, policy(DRV_KIND_POWER_MON));

        // 1. `always`: a clean exit is restarted. A failure here does not
        //    stop step 2, so the canary shows both halves discriminate.
        let Some(v) = stop("buzzer exit 0", DRV_KIND_BUZZER, 0) else { return };
        let t0 = now();
        let b1 = serving(DRV_KIND_BUZZER, buzzer_answers, v, BACK_WITHIN_MS);
        let back_ms = (now() - t0) / ticks_per_ms();
        match b1 {
            Some(b1) => kprintln!("[RESTART] buzzer: tid={} exited 0 -> tid={} answering after {} ms",
                                  v, b1, back_ms),
            None => kprintln!("[RESTART] FAIL buzzer not restarted after exit 0: tid={} exited 0, no \
                               new driver answered within {} ms (supervisor state {:?})", v,
                              BACK_WITHIN_MS, sup_find_kind(DRV_KIND_BUZZER).map(|(_, e)| e.state)),
        }

        // 2. `no`: a kill is final.
        let Some(w) = stop("INA219 kill", DRV_KIND_POWER_MON, azos_abi::exit_status::KILLED_KILL)
        else { return };
        let t1 = now();
        let mut refused = 0u32;
        while now() - t1 < DOWN_FOR_MS * ticks_per_ms() {
            // The dead TID can still own the slot until the supervisor's
            // release lands (it runs after teardown since EXIT2); only a
            // different owner is a restart. A slot never released fails below.
            if let Some(t) = driver_owner_tid(DRV_KIND_POWER_MON).filter(|&t| t != w) {
                kprintln!("[RESTART] FAIL INA219 restarted under restart = no: tid={} owns it", t);
                return;
            }
            if ina_answers() {
                kprintln!("[RESTART] FAIL INA219 restarted under restart = no: a read was answered");
                return;
            }
            refused += 1;
            sleep_ms(100);
        }
        if let Some(t) = driver_owner_tid(DRV_KIND_POWER_MON) {
            kprintln!("[RESTART] FAIL INA219 under restart = no: tid={} still owns the slot after {} ms",
                      t, DOWN_FOR_MS);
            return;
        }
        let state = sup_find_kind(DRV_KIND_POWER_MON).map(|(_, e)| e.state);
        if state != Some(SupState::Exited) {
            kprintln!("[RESTART] FAIL INA219 under restart = no: supervisor state {:?}, not Exited",
                      state);
            return;
        }
        let Some(b1) = b1 else { return };
        kprintln!("[RESTART] PASS: buzzer (restart = always) exited 0 and tid={} answered {} ms \
                   later; INA219 (restart = no) tid={} killed and not restarted: no owner and {} \
                   reads refused over {} ms", b1, back_ms, w, refused, DOWN_FOR_MS);
    }
}
