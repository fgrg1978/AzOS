// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cold-restart supervisor for ring-3 drivers (RFC-0049 M4).
//!
//! A ring-3 task that the autorun loader started from an image on disk, and
//! that then registered a driver-server kind, or that the kernel spawned
//! because the system declares it (see *Origins*), is **supervised**: when it dies
//! (a fault, a seccomp kill, a kernel stop request or a plain exit) the kernel
//! keeps its driver-server slot, its named endpoints and its service names,
//! re-creates the task from the same image, and hands those to the new task.
//!
//! # When it restarts (owner decision 2026-09-28: systemd's model)
//!
//! * **Only on failure** (`Restart=on-failure`, the default): a task killed
//!   by a fault, a seccomp kill or a kernel stop request, or one that exits
//!   with a code other than 0. A driver that exits 0 finished on purpose: its
//!   entry goes [`SupState::Exited`] and everything is released as for any
//!   task.
//! * **Per row** (wave 11, DRVPLACE): the signed topology's `restart` key
//!   ([`SupRestart`], set by the kernel with [`sup_set_restart`] before the
//!   task runs) may say `always` (a clean exit is restarted too, against the
//!   same window) or `no` (no end is restarted: the entry goes `Exited` at
//!   once, [`ExitVerdict::NoRestart`], and that end is recorded on the flight
//!   recorder as a give-up is, [`SupFall::NoRestart`]).
//! * **Within a window** (`StartLimitBurst` / `StartLimitIntervalSec`): at
//!   most [`SupPolicy::burst`] restarts within [`SupPolicy::interval`]. The
//!   failure after that is final ([`SupState::Down`]): everything is released
//!   and the kind stays down until the machine restarts. A restart older than
//!   the interval no longer counts, so a driver that fails rarely is always
//!   restarted. The kernel takes both from Kconfig (`SUP_RESTART_BURST`,
//!   `SUP_RESTART_INTERVAL_S`; defaults 3 and 300 s).
//!
//! # Why a table of its own, and not the AQ2 registry in `driver.rs`
//!
//! The AQ2 table is reachable from ring 3: `SYS_DRV_REGISTER` (300) lets any
//! task fill its 16 entries by name, `SYS_DRV_HEARTBEAT` (309) stamps them,
//! and `sys_wdt` moves its `Crashed` entries back to `Registered` every
//! ~500 ms. A restart decision taken there could be exhausted, or steered, by
//! a program that is not the driver. No syscall reaches this table: it is
//! written only by the autorun loader ([`sup_note_spawn`]), by the kernel's
//! own spawn of a declared image ([`sup_note_started`]), by the driver's
//! own successful typed registration ([`sup_bind`]), by the exit hook
//! ([`sup_on_exit`]) and by the supervisor task. It shares the AQ2 cooldown
//! constant; its budget is the window above.
//!
//! # Identity
//!
//! TIDs are never reused within an uptime, so a task that is re-created has a
//! new TID. The identity that survives is the **image path** the loader read
//! (and re-reads, and re-hashes against its seccomp profile, on every
//! restart). The entry follows the task through `Candidate` (loaded, not a
//! driver yet) → `Serving` (registered a kind) → `Restarting` (died, a
//! successor is due or loading) → `Serving` again, or → `Down`.
//!
//! # Origins (wave 11; `KernelHost` wave 13)
//!
//! * [`SupOrigin::Autorun`] — an image the autorun loader started
//!   ([`sup_note_spawn`]). It is a `Candidate` until it registers a
//!   driver-server kind, and only then supervised: the autorun image may be a
//!   program that is not a driver (the brain client, a test image), and such a
//!   program is never restarted. Its successor is a kernel task that runs the
//!   autorun loader on the same path.
//! * [`SupOrigin::Spawned`] — an image the kernel itself started through
//!   `SYS_SPAWN`'s machinery because the system declares it: the topology's
//!   `start = true` rows and the ML service ([`sup_note_started`]). It is
//!   supervised from its first instruction, whether or not it ever registers
//!   a kind, so a driver that crashes before it registers is restarted and
//!   given up on like one that crashes later. Its successor is spawned again
//!   from the same path by the supervisor task.
//!
//! * [`SupOrigin::KernelHost`] (wave 13) — the host task of a driver placed
//!   in the kernel ([`sup_note_kernel_host`]). Supervised from the start like
//!   `Spawned`; it dies only through a contained kernel panic, and its
//!   successor is a new kernel task on the same entry point.
//!
//! All follow the same policy. Per row, the policy already separates the two
//! kinds of program a row can name: a server that must stay up never exits 0,
//! so every death is a failure and is restarted within the window; a one-shot
//! exits 0 when it is done and is not restarted ([`SupState::Exited`]).
//!
//! # What counts against the budget
//!
//! Every failed death of the entry's current task, including a successor that
//! dies before it registers (its image no longer matches its profile, the file
//! is gone, the actuation gate is absent). So a restart that cannot succeed
//! ends in `Down` after the same number of attempts as a driver that crashes,
//! and never loops. A driver that has used its budget stays down until the
//! machine restarts (the policy `driver_start` already documents for the AQ2
//! table).
//!
//! # Pacing
//!
//! A restart with none before it in the window is immediate, so its latency
//! is the mechanism's cost and nothing else. Each later one waits until
//! [`DRIVER_RESTART_COOLDOWN_MS`] has passed since the previous restart, so a
//! driver that dies at once cannot spend its whole budget in one burst of disk
//! reads.
//!
//! The pure table ([`SupTable`]) takes every time as an argument, in the
//! caller's clock units, so the host tests drive it without a clock.

use azos_sync::SpinLock;

pub use crate::driver::{DRIVER_MAX_RESTARTS, DRIVER_RESTART_COOLDOWN_MS};

/// Supervised images at once: the autorun image, the ML service and the
/// topology's `start = true` rows (`driver.rs`'s `MAX_SPAWN_DESCRIPTORS` is
/// the same bound). An image that does not fit runs unsupervised.
pub const MAX_SUPERVISED: usize = 8;

/// Largest restart burst a [`SupPolicy`] may name (Kconfig
/// `SUP_RESTART_BURST`'s range).
pub const SUP_BURST_MAX: usize = 16;

/// The restart limit, systemd's `StartLimitBurst` / `StartLimitIntervalSec`,
/// in the caller's clock units.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SupPolicy {
    /// Restarts allowed within `interval`, 1..=[`SUP_BURST_MAX`] (clamped).
    pub burst: u8,
    /// The window restarts are counted in.
    pub interval: u64,
    /// The pause between two restarts ([`DRIVER_RESTART_COOLDOWN_MS`]).
    pub cooldown: u64,
}

impl SupPolicy {
    fn burst_limit(&self) -> usize {
        (self.burst as usize).clamp(1, SUP_BURST_MAX)
    }
}

/// Longest image path kept. The autorun path buffer is 64 bytes with its NUL
/// (`AUTORUN_PATH_MAX` in the kernel), so every path the loader can open fits.
pub const SUP_IMAGE_MAX: usize = 64;

/// How a supervised image was first started, and so how it is restarted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SupOrigin {
    /// The autorun loader ([`SupTable::note_spawn`]): supervised once it
    /// registers a driver-server kind; restarted by re-running the loader.
    Autorun,
    /// A kernel spawn of a declared image ([`SupTable::note_started`]):
    /// supervised from the start; restarted by spawning the path again.
    Spawned,
    /// A driver placed in the kernel (Kconfig `DRV_*_PLACEMENT = kernel`),
    /// whose host is a kernel task ([`SupTable::note_kernel_host`], wave 13):
    /// supervised from the start, like `Spawned`. It can only die through a
    /// contained kernel panic (the panic policy's exit status 134); its
    /// successor is a new kernel task on the same entry point. The "image" is
    /// the host's name.
    KernelHost,
}

/// Where one supervised image is in its life.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SupState {
    /// Unused slot.
    Free,
    /// Loaded by the autorun loader; not a driver (yet). Freed when its task
    /// exits without having registered a kind.
    Candidate,
    /// Its task is alive and supervised: an `Autorun` task that registered a
    /// driver-server kind, or a `Spawned` task from its start (its `kind` is
    /// [`SUP_NO_KIND`] until it registers one).
    Serving,
    /// Its task died with budget left. `tid == 0`: the successor is not
    /// created yet (due at `not_before`); `tid != 0`: the successor exists
    /// and has not registered yet.
    Restarting,
    /// Budget spent (or the successor could not even be created). Final.
    Down,
    /// Its task exited 0 under `on-failure` (finished on purpose), or ended
    /// in any way under `restart = no`: not restarted. Final.
    Exited,
}

/// What ends of a supervised task are restarted: the topology row's
/// `restart` key (systemd's `Restart=`). The window applies to every
/// restart, whatever the policy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SupRestart {
    /// A failure is restarted, a clean exit (code 0) is final. The default.
    OnFailure,
    /// Every end is restarted, a clean exit included.
    Always,
    /// No end is restarted.
    No,
}

/// One supervised image.
#[derive(Clone, Copy, Debug)]
pub struct SupEntry {
    pub state: SupState,
    /// Which ends are restarted ([`SupTable::set_restart`]).
    pub restart: SupRestart,
    /// How the image was first started; how its successors are created.
    pub origin: SupOrigin,
    /// The path the loader opened, byte for byte.
    pub image: [u8; SUP_IMAGE_MAX],
    pub image_len: u8,
    /// The driver-server kind its task registered first. `u32::MAX` until then.
    pub kind: u32,
    /// The task currently standing for this image, 0 for none.
    pub tid: u32,
    /// The task that died last, for the report and the flight recorder.
    pub dead_tid: u32,
    /// Restarts granted so far, in total (for the report and the flight
    /// recorder). The decision reads [`Self::window`], not this.
    pub restarts: u8,
    /// When each restart still inside the policy's interval was granted, the
    /// first [`Self::window_n`] entries, oldest first.
    pub window: [u64; SUP_BURST_MAX],
    /// How many of [`Self::window`] are in use.
    pub window_n: u8,
    /// When the last death was seen (caller's clock).
    pub died_at: u64,
    /// When the last successor was created.
    pub respawned_at: u64,
    /// When the current task registered its kind.
    pub bound_at: u64,
    /// The earliest a pending successor may be created.
    pub not_before: u64,
    /// The exit hook has finished holding what the successor takes over (the
    /// driver-server slot, named endpoints, service names). Until then no
    /// successor is due: created earlier, it would find nothing to adopt, its
    /// own registration would be refused, and the slot would be left orphaned
    /// under the wrong TID. Cleared by every death, set by [`SupTable::held`].
    pub held: bool,
    /// The supervisor task has recorded the entry's fall to `Down`, or its
    /// end under `restart = no` ([`SupTable::fall`]). Cleared by every death,
    /// set by the supervisor once the record is written.
    pub recorded: bool,
}

/// Sentinel for "no kind registered yet".
pub const SUP_NO_KIND: u32 = u32::MAX;

impl SupEntry {
    pub const fn empty() -> Self {
        SupEntry {
            state: SupState::Free,
            restart: SupRestart::OnFailure,
            origin: SupOrigin::Autorun,
            image: [0; SUP_IMAGE_MAX],
            image_len: 0,
            kind: SUP_NO_KIND,
            tid: 0,
            dead_tid: 0,
            restarts: 0,
            window: [0; SUP_BURST_MAX],
            window_n: 0,
            died_at: 0,
            respawned_at: 0,
            bound_at: 0,
            not_before: 0,
            held: false,
            recorded: false,
        }
    }

    /// The image path.
    pub fn image(&self) -> &[u8] {
        &self.image[..self.image_len as usize]
    }
}

/// What registering a kind meant for the supervisor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BindOutcome {
    /// The task was not started by the autorun loader: not supervised.
    NotSupervised,
    /// First registration of a supervised image: from now on it is restarted.
    First { slot: usize },
    /// A successor registered: restart `attempt` is serving, `since_death`
    /// after the death it replaces (caller's clock units).
    Restored { slot: usize, attempt: u8, since_death: u64 },
    /// The task registered a second kind; it is already supervised.
    AlreadyServing { slot: usize },
}

/// What a task's death means for the supervisor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExitVerdict {
    /// Not a supervised driver: release everything as usual.
    NotSupervised,
    /// Keep its slot, endpoints and names for a successor: restart
    /// `attempt` of the policy's burst within its interval, due at
    /// `not_before`.
    Restart { slot: usize, attempt: u8, not_before: u64 },
    /// Budget spent: release everything; the kind stays down. `restarts` is
    /// the total granted before.
    GiveUp { slot: usize, restarts: u8 },
    /// It exited 0: release everything, no restart (`Restart=on-failure`).
    Exited { slot: usize, restarts: u8 },
    /// It ended with `code` under `restart = no`: release everything, no
    /// restart, whatever the code.
    NoRestart { slot: usize, restarts: u8, code: i32 },
}

/// A supervised driver's final end, as the supervisor task records it on the
/// flight recorder (`SAFETY_DRIVER_SUPERVISOR`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupFall {
    /// Its restart budget is spent, or no successor could be created: down.
    GaveUp,
    /// It ended under its row's `restart = no`: not restarted, by policy.
    NoRestart,
}

fn fall_of(e: &SupEntry) -> Option<SupFall> {
    match e.state {
        SupState::Down => Some(SupFall::GaveUp),
        SupState::Exited if e.restart == SupRestart::No => Some(SupFall::NoRestart),
        _ => None,
    }
}

/// The supervisor's table. Pure: no clock, no lock, no scheduler.
pub struct SupTable {
    entries: [SupEntry; MAX_SUPERVISED],
}

impl SupTable {
    pub const fn new() -> Self {
        SupTable { entries: [SupEntry::empty(); MAX_SUPERVISED] }
    }

    fn slot_of_tid(&self, tid: u32) -> Option<usize> {
        if tid == 0 {
            return None; // 0 is "no task", never a live TID
        }
        self.entries.iter().position(|e| e.state != SupState::Free && e.tid == tid)
    }

    /// The autorun loader is about to exec `image` as task `tid`.
    ///
    /// A successor the supervisor created is already on its entry and keeps
    /// it. Anything else becomes a `Candidate`. `None` when the table is full
    /// or the path does not fit: the program then runs unsupervised, as every
    /// program did before M4.
    pub fn note_spawn(&mut self, tid: u32, image: &[u8]) -> Option<usize> {
        if tid == 0 || image.is_empty() || image.len() > SUP_IMAGE_MAX {
            return None;
        }
        if let Some(i) = self.slot_of_tid(tid) {
            return Some(i);
        }
        let i = self.entries.iter().position(|e| e.state == SupState::Free)?;
        let mut e = SupEntry::empty();
        e.state = SupState::Candidate;
        e.image[..image.len()].copy_from_slice(image);
        e.image_len = image.len() as u8;
        e.tid = tid;
        self.entries[i] = e;
        Some(i)
    }

    /// The kernel is about to release `tid`, a task it spawned from `image`
    /// because the system declares it (a topology `start = true` row, the ML
    /// service). Supervised from now on, before it runs a single instruction:
    /// the entry is `Serving` with no kind. `None` when the table is full or
    /// the path does not fit: the program then runs unsupervised.
    pub fn note_started(&mut self, tid: u32, image: &[u8]) -> Option<usize> {
        self.note_supervised(tid, image, SupOrigin::Spawned)
    }

    /// The kernel has just created `tid`, the host task of a driver placed
    /// in the kernel, named `name`: supervised from now on, as
    /// [`Self::note_started`], with origin [`SupOrigin::KernelHost`].
    pub fn note_kernel_host(&mut self, tid: u32, name: &[u8]) -> Option<usize> {
        self.note_supervised(tid, name, SupOrigin::KernelHost)
    }

    fn note_supervised(&mut self, tid: u32, image: &[u8], origin: SupOrigin) -> Option<usize> {
        if tid == 0 || image.is_empty() || image.len() > SUP_IMAGE_MAX {
            return None;
        }
        if let Some(i) = self.slot_of_tid(tid) {
            return Some(i);
        }
        let i = self.entries.iter().position(|e| e.state == SupState::Free)?;
        let mut e = SupEntry::empty();
        e.state = SupState::Serving;
        e.origin = origin;
        e.image[..image.len()].copy_from_slice(image);
        e.image_len = image.len() as u8;
        e.tid = tid;
        self.entries[i] = e;
        Some(i)
    }

    /// The restart policy of `slot` (its topology row's `restart`). Set by
    /// the kernel right after [`Self::note_started`] / [`Self::note_spawn`],
    /// before the task can run. `false` for a free slot.
    pub fn set_restart(&mut self, slot: usize, restart: SupRestart) -> bool {
        match self.entries.get_mut(slot) {
            Some(e) if e.state != SupState::Free => {
                e.restart = restart;
                true
            }
            _ => false,
        }
    }

    /// Task `tid` has just registered driver-server kind `kind` at `now`.
    pub fn bind(&mut self, kind: u32, tid: u32, now: u64) -> BindOutcome {
        let Some(i) = self.slot_of_tid(tid) else {
            return BindOutcome::NotSupervised;
        };
        let e = &mut self.entries[i];
        match e.state {
            SupState::Candidate => {
                e.state = SupState::Serving;
                e.kind = kind;
                e.bound_at = now;
                BindOutcome::First { slot: i }
            }
            SupState::Restarting => {
                e.state = SupState::Serving;
                if e.kind == SUP_NO_KIND {
                    e.kind = kind;
                }
                e.bound_at = now;
                BindOutcome::Restored {
                    slot: i,
                    attempt: e.window_n,
                    since_death: now.saturating_sub(e.died_at),
                }
            }
            // A `Spawned` task's first kind: it was supervised already.
            SupState::Serving if e.kind == SUP_NO_KIND => {
                e.kind = kind;
                e.bound_at = now;
                BindOutcome::First { slot: i }
            }
            SupState::Serving => BindOutcome::AlreadyServing { slot: i },
            SupState::Free | SupState::Down | SupState::Exited => BindOutcome::NotSupervised,
        }
    }

    /// Task `tid` is dying at `now` with exit code `code` (0 = a clean exit,
    /// anything else a failure: `128 + signal` for a kill).
    pub fn on_exit(&mut self, tid: u32, now: u64, code: i32, policy: SupPolicy) -> ExitVerdict {
        let Some(i) = self.slot_of_tid(tid) else {
            return ExitVerdict::NotSupervised;
        };
        let e = &mut self.entries[i];
        match e.state {
            // Loaded but never a driver: nothing to keep, and the slot is
            // not held for a program that will not be restarted.
            SupState::Candidate => {
                *e = SupEntry::empty();
                ExitVerdict::NotSupervised
            }
            SupState::Serving | SupState::Restarting => {
                e.dead_tid = tid;
                e.tid = 0;
                e.died_at = now;
                e.recorded = false;
                if e.restart == SupRestart::No {
                    // `restart = no`: any end is final, clean or not. Left
                    // unrecorded: a supervised driver gone for good belongs on
                    // the flight recorder, as a give-up does.
                    e.state = SupState::Exited;
                    e.recorded = false;
                    return ExitVerdict::NoRestart { slot: i, restarts: e.restarts, code };
                }
                if code == 0 && e.restart == SupRestart::OnFailure {
                    // Finished on purpose: `Restart=on-failure`.
                    e.state = SupState::Exited;
                    e.recorded = true; // nothing for the supervisor to record
                    return ExitVerdict::Exited { slot: i, restarts: e.restarts };
                }
                e.held = false;
                Self::failed(e, i, now, policy)
            }
            SupState::Free | SupState::Down | SupState::Exited => ExitVerdict::NotSupervised,
        }
    }

    /// One failure of `e` at `now`, against the policy's window: another
    /// restart, or the give-up. Shared by a death ([`Self::on_exit`]) and a
    /// successor that could not be created ([`Self::respawn_refused`]).
    fn failed(e: &mut SupEntry, i: usize, now: u64, policy: SupPolicy) -> ExitVerdict {
        // Forget the restarts the interval has left behind.
        let n = e.window_n as usize;
        let kept = e.window[..n]
            .iter()
            .filter(|&&t| now.saturating_sub(t) < policy.interval)
            .count();
        e.window.copy_within(n - kept..n, 0);
        e.window_n = kept as u8;
        if kept >= policy.burst_limit() {
            e.state = SupState::Down;
            e.recorded = false;
            ExitVerdict::GiveUp { slot: i, restarts: e.restarts }
        } else {
            e.restarts = e.restarts.saturating_add(1);
            e.window[kept] = now;
            e.window_n = kept as u8 + 1;
            e.state = SupState::Restarting;
            e.not_before = if kept == 0 {
                now
            } else {
                now.max(e.respawned_at.saturating_add(policy.cooldown))
            };
            ExitVerdict::Restart { slot: i, attempt: e.window_n, not_before: e.not_before }
        }
    }

    /// The supervisor tried to spawn a successor for `slot` at `now` and the
    /// spawn was refused before any task existed (the image is gone, its bytes
    /// match no profile, its row has no instance left, the actuation gate is
    /// absent, safe mode). A failure like a death: another attempt within the
    /// window (`Restart`, due after the cooldown), or `GiveUp`.
    ///
    /// Nothing died, so what the last dead task left held stays held for the
    /// next attempt: `held` and `dead_tid` are kept, and `respawned_at` is set
    /// to `now` so the next attempt keeps the cooldown. On `GiveUp` the caller
    /// releases those orphans. `NotSupervised` when the slot was not waiting
    /// for a successor.
    pub fn respawn_refused(&mut self, slot: usize, now: u64, policy: SupPolicy) -> ExitVerdict {
        match self.entries.get_mut(slot) {
            Some(e) if e.state == SupState::Restarting && e.tid == 0 => {
                e.respawned_at = now;
                Self::failed(e, slot, now, policy)
            }
            _ => ExitVerdict::NotSupervised,
        }
    }

    /// The exit hook of `slot`'s dead task has held everything its successor
    /// takes over: from now on the successor may be created. `true` if the
    /// slot was waiting for exactly that.
    pub fn held(&mut self, slot: usize) -> bool {
        match self.entries.get_mut(slot) {
            Some(e) if e.state == SupState::Restarting && e.tid == 0 && !e.held => {
                e.held = true;
                true
            }
            _ => false,
        }
    }

    /// The first entry whose successor is due at `now`, if any, and the
    /// earliest time a pending one becomes due otherwise. An entry whose exit
    /// hook has not finished holding ([`Self::held`]) is neither.
    pub fn next_due(&self, now: u64) -> (Option<usize>, Option<u64>) {
        let mut earliest: Option<u64> = None;
        for (i, e) in self.entries.iter().enumerate() {
            if e.state == SupState::Restarting && e.tid == 0 && e.held {
                if e.not_before <= now {
                    return (Some(i), None);
                }
                earliest = Some(earliest.map_or(e.not_before, |t| t.min(e.not_before)));
            }
        }
        (None, earliest)
    }

    /// The supervisor created `heir` for `slot` at `now`. `false` (and nothing
    /// changed) when the slot is no longer waiting for one.
    pub fn respawned(&mut self, slot: usize, heir: u32, now: u64) -> bool {
        match self.entries.get_mut(slot) {
            Some(e) if e.state == SupState::Restarting && e.tid == 0 && heir != 0 => {
                e.tid = heir;
                e.respawned_at = now;
                true
            }
            _ => false,
        }
    }

    /// The supervisor could not create a successor for `slot` (task pool
    /// full): the entry goes down. `true` if it was waiting for one.
    pub fn respawn_failed(&mut self, slot: usize) -> bool {
        match self.entries.get_mut(slot) {
            Some(e) if e.state == SupState::Restarting && e.tid == 0 => {
                e.state = SupState::Down;
                e.recorded = false;
                true
            }
            _ => false,
        }
    }

    /// The first entry that went `Down`, or ended under `restart = no`,
    /// without the supervisor recording it ([`Self::fall`] says which). (A
    /// restart is recorded by the supervisor as it creates the successor, so
    /// it needs no mark; a clean exit under `on-failure` is marked recorded
    /// as it happens: nothing to record.)
    pub fn next_unrecorded(&self) -> Option<usize> {
        self.entries.iter().position(|e| !e.recorded && fall_of(e).is_some())
    }

    /// What the supervisor records for `slot`'s current state: the give-up
    /// (`Down`), the end under `restart = no` (`Exited` with that policy), or
    /// `None` for a state that is not a final end worth a record.
    pub fn fall(&self, slot: usize) -> Option<SupFall> {
        self.entries.get(slot).and_then(fall_of)
    }

    /// Mark `slot`'s current transition recorded.
    pub fn mark_recorded(&mut self, slot: usize) {
        if let Some(e) = self.entries.get_mut(slot) {
            e.recorded = true;
        }
    }

    pub fn entry(&self, slot: usize) -> Option<SupEntry> {
        self.entries.get(slot).copied().filter(|e| e.state != SupState::Free)
    }

    /// The entry of the image that registered `kind`.
    pub fn find_kind(&self, kind: u32) -> Option<(usize, SupEntry)> {
        self.entries
            .iter()
            .position(|e| e.state != SupState::Free && e.kind == kind)
            .map(|i| (i, self.entries[i]))
    }
}

impl SupTable {
    /// The entry of the image started from `image` (the path, byte for byte).
    pub fn find_image(&self, image: &[u8]) -> Option<(usize, SupEntry)> {
        self.entries
            .iter()
            .position(|e| e.state != SupState::Free && e.image() == image)
            .map(|i| (i, self.entries[i]))
    }
}

impl Default for SupTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── The kernel's one table ───────────────────────────────────────────────

static SUPERVISOR: SpinLock<SupTable> = SpinLock::new(SupTable::new());

/// [`SupTable::note_spawn`] on the kernel's table.
pub fn sup_note_spawn(tid: u32, image: &[u8]) -> Option<usize> {
    SUPERVISOR.lock().note_spawn(tid, image)
}

/// [`SupTable::note_started`] on the kernel's table.
pub fn sup_note_started(tid: u32, image: &[u8]) -> Option<usize> {
    SUPERVISOR.lock().note_started(tid, image)
}

/// [`SupTable::note_kernel_host`] on the kernel's table.
pub fn sup_note_kernel_host(tid: u32, name: &[u8]) -> Option<usize> {
    SUPERVISOR.lock().note_kernel_host(tid, name)
}

/// [`SupTable::respawn_refused`] on the kernel's table.
pub fn sup_respawn_refused(slot: usize, now: u64, policy: SupPolicy) -> ExitVerdict {
    SUPERVISOR.lock().respawn_refused(slot, now, policy)
}

/// [`SupTable::set_restart`] on the kernel's table.
pub fn sup_set_restart(slot: usize, restart: SupRestart) -> bool {
    SUPERVISOR.lock().set_restart(slot, restart)
}

/// [`SupTable::bind`] on the kernel's table.
pub fn sup_bind(kind: u32, tid: u32, now: u64) -> BindOutcome {
    SUPERVISOR.lock().bind(kind, tid, now)
}

/// [`SupTable::on_exit`] on the kernel's table.
pub fn sup_on_exit(tid: u32, now: u64, code: i32, policy: SupPolicy) -> ExitVerdict {
    SUPERVISOR.lock().on_exit(tid, now, code, policy)
}

/// [`SupTable::held`] on the kernel's table.
pub fn sup_held(slot: usize) -> bool {
    SUPERVISOR.lock().held(slot)
}

/// [`SupTable::next_due`] on the kernel's table.
pub fn sup_next_due(now: u64) -> (Option<usize>, Option<u64>) {
    SUPERVISOR.lock().next_due(now)
}

/// [`SupTable::respawned`] on the kernel's table.
pub fn sup_respawned(slot: usize, heir: u32, now: u64) -> bool {
    SUPERVISOR.lock().respawned(slot, heir, now)
}

/// [`SupTable::respawn_failed`] on the kernel's table.
pub fn sup_respawn_failed(slot: usize) -> bool {
    SUPERVISOR.lock().respawn_failed(slot)
}

/// [`SupTable::next_unrecorded`] + [`SupTable::entry`] + [`SupTable::fall`]
/// in one hold.
pub fn sup_next_unrecorded() -> Option<(usize, SupEntry, SupFall)> {
    let t = SUPERVISOR.lock();
    let slot = t.next_unrecorded()?;
    Some((slot, t.entry(slot)?, t.fall(slot)?))
}

/// [`SupTable::mark_recorded`] on the kernel's table.
pub fn sup_mark_recorded(slot: usize) {
    SUPERVISOR.lock().mark_recorded(slot)
}

/// [`SupTable::entry`] on the kernel's table.
pub fn sup_entry(slot: usize) -> Option<SupEntry> {
    SUPERVISOR.lock().entry(slot)
}

/// [`SupTable::find_kind`] on the kernel's table.
pub fn sup_find_kind(kind: u32) -> Option<(usize, SupEntry)> {
    SUPERVISOR.lock().find_kind(kind)
}

/// [`SupTable::find_image`] on the kernel's table.
pub fn sup_find_image(image: &[u8]) -> Option<(usize, SupEntry)> {
    SUPERVISOR.lock().find_image(image)
}
