// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Apply a topology row's scheduling class and priority to a ring-3 task
//! (wave 7).
//!
//! RFC-0005 has every user-space task take its scheduler class from the
//! signed topology. Until wave 7 the rows were read for admission only; the
//! autorun loader, `SYS_SPAWN` and `fork` created every ring-3 task at
//! `DEFAULT_PRIORITY`, whatever its row said.
//!
//! # Which row
//!
//! A program's row is the one named after its IMAGE (`profile.image`, the same
//! key `SYS_SPAWN` seeds capabilities from). The autorun loader falls back to
//! the generic `autorun` row when the image has none. A fork child has no row:
//! it inherits its parent's (`crates/core/sched/src/process.rs`). Kernel daemons
//! are not user-space tasks and are never looked up — a row naming one
//! changes nothing.
//!
//! # What is applied
//!
//! The row's priority clamped into its class's `priority_range`
//! (`azos_topology::RowSched`), then raised to at least
//! [`MIN_TASK_PRIORITY`] (12: nothing in ring 3 above the tick-preempted
//! band) and capped at `IDLE_PRIORITY - 1`: 31 is
//! how the scheduler recognises the per-hart idle task (the tickless hooks
//! compare against it), and a ring-3 task there would be taken for it.
//!
//! A class this build's scheduler does not have (`SchedClass::from_name` is
//! `None`) is REFUSED: the task keeps the priority it was created with, and
//! the refusal is recorded in the flight recorder by the caller
//! (`SAFETY_TOPO_CLASS_REFUSED`).

use azos_sched::class::SchedClass;
use azos_topology::RowSched;

/// The highest priority number a topology may give a ring-3 task.
pub const MAX_TASK_PRIORITY: u32 = azos_sched::IDLE_PRIORITY - 1;
/// The most urgent priority a topology may give a ring-3 task (owner decision
/// 2026-09-28, round 15): `RT_PRIORITY_THRESHOLD`, 12. Below it the timer tick
/// never preempts a task, so a ring-3 loop there would starve `net-poll` (12)
/// and `sys-wdt` (11) on its hart — the starvation that already failed the
/// `userspace: the brain lies` row once. A row asking for less is raised to
/// this and the raise is recorded; kernel daemons can always preempt ring 3.
pub const MIN_TASK_PRIORITY: u32 = azos_sched::RT_PRIORITY_THRESHOLD;

/// What looking a task's row up decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopoSched {
    /// No topology is installed, or no row has this name.
    NoRow,
    /// The row names a class this build does not schedule. Nothing applied.
    Refused,
    /// Apply these.
    Apply {
        /// Final priority (clamped to the class range, capped below idle).
        priority: u32,
        /// `SchedClass` discriminant.
        class: SchedClass,
        /// The row's `priority` as written, for the log line.
        declared: u8,
        /// The row asked for a priority below [`MIN_TASK_PRIORITY`] and was
        /// raised to it. The caller records it (`SITE_*_FLOOR`).
        floored: bool,
        /// Wave 11 SCHED-RT: the row declares a real-time profile in a class
        /// with `admission_control`. The task must be given this reservation
        /// (`azos_sched::rt::reserve`) BEFORE it runs at `priority`; when
        /// `priority` is in the band (below [`MIN_TASK_PRIORITY`]) the
        /// reservation is what admits it there (owner decision, wave 11: a
        /// ring-3 row may enter the band only with a CBS reservation that
        /// passes admission). If the reservation is refused, the caller runs
        /// the task at [`band_refused_priority`] without one, or fails.
        rt: Option<azos_sched::rt::Reservation>,
    },
}

/// Resolve the row named `name`.
pub fn resolve(name: &[u8]) -> TopoSched {
    let Some(topo) = azos_topology::get() else { return TopoSched::NoRow };
    match topo.row_sched(name) {
        RowSched::NoRow => TopoSched::NoRow,
        // An installed topology passed `admission_check`, which refuses a row
        // naming an undeclared class; if one got here anyway it is refused
        // the same way as a class the build lacks.
        RowSched::UndeclaredClass => TopoSched::Refused,
        RowSched::Apply { class_name, declared, priority } => {
            match SchedClass::from_name(class_name.as_bytes()) {
                Some(class) => {
                    let rt = row_reservation(name);
                    // A row with a reservation keeps its class priority, band
                    // included; one without stays at or above the floor.
                    let floor = if rt.is_some() { 0 } else { MIN_TASK_PRIORITY };
                    let (priority, floored) = azos_topology::ring3_priority(
                        priority as u32, floor, MAX_TASK_PRIORITY);
                    TopoSched::Apply { priority, class, declared, floored, rt }
                }
                None => TopoSched::Refused,
            }
        }
    }
}

/// The priority a ring-3 task whose band reservation was refused runs at
/// instead: its row's priority raised to the ring-3 floor, exactly what a row
/// without a profile gets (the 2026-09-28 rule stands for every task that
/// holds no admitted reservation).
pub fn band_refused_priority(priority: u32) -> u32 {
    azos_topology::ring3_priority(priority, MIN_TASK_PRIORITY, MAX_TASK_PRIORITY).0
}

/// Wave 11 SCHED-RT: the EDF + CBS reservation the row named `name` declares,
/// or `None` when it has no profile or its class has no `admission_control`
/// (a best-effort class's profile is neither admitted nor enforced).
///
/// Wired to boot admission: the row's task is pinned to the CPU the
/// topology's partitioned check placed it on (`deadline_admission` with the
/// online hart count, the same run `install_topology` makes at boot), so the
/// set that was proven feasible is the set that runs. The band flag follows
/// the row's priority clamped into its class (`priority < 12`); the CBS is
/// hard (throttle on overrun), the RFC-0052 default for admitted classes.
pub fn row_reservation(name: &[u8]) -> Option<azos_sched::rt::Reservation> {
    let topo = azos_topology::get()?;
    let (ti, task) = topo.tasks().iter().enumerate().find(|(_, t)| t.name.as_bytes() == name)?;
    if !task.profile.is_declared() {
        return None;
    }
    // In the band only with locked memory too (wave 11 owner decision); an
    // installed topology already refused such a row, this keeps it so.
    if topo.row_band_entry(ti) == azos_topology::BandEntry::NotLocked {
        return None;
    }
    let class = topo.find_class(&task.class_name)?;
    if !class.admission_control {
        return None;
    }
    let online = azos_sched::smp::NUM_ONLINE_CPUS
        .load(core::sync::atomic::Ordering::Acquire).max(1);
    let cpu_mask = match topo.deadline_admission(online).ok()?.cpu_of(ti as u16) {
        Some(cpu) => 1u32 << cpu,
        None => return None,
    };
    let (lo, hi) = class.priority_range;
    let prio = task.priority.clamp(lo, hi.max(lo)) as u32;
    let p = task.profile;
    Some(azos_sched::rt::Reservation {
        runtime_us: p.runtime_us as u64,
        period_us: p.period_us as u64,
        deadline_us: p.deadline_us as u64,
        hard: true,
        cpu_mask,
        band: prio < MIN_TASK_PRIORITY,
        // What `resolve` applies to a row with a reservation (floor 0).
        level: azos_topology::ring3_priority(prio, 0, MAX_TASK_PRIORITY).0,
    })
}

/// [`azos_topology::BandEntry`] of the row named `name`, `None` with no
/// topology or no such row. `NotLocked` is refused at spawn (`EACCES`) and
/// keeps the autorun program at the ring-3 floor; topology admission refuses
/// it first, so with an installed topology it is defence in depth.
pub fn row_band_entry(name: &[u8]) -> Option<azos_topology::BandEntry> {
    let topo = azos_topology::get()?;
    let ti = topo.tasks().iter().position(|t| t.name.as_bytes() == name)?;
    Some(topo.row_band_entry(ti))
}

// The topology's band threshold is the scheduler's.
const _: () = assert!(azos_topology::RT_BAND_THRESHOLD as u32 == azos_sched::RT_PRIORITY_THRESHOLD);

/// [`resolve`] for a program: its image's row, else `fallback`'s (if given).
/// Returns the decision and the row name it came from.
pub fn resolve_image(image: &'static str, fallback: Option<&'static str>) -> (TopoSched, &'static str) {
    match resolve(image.as_bytes()) {
        TopoSched::NoRow => match fallback {
            Some(f) => (resolve(f.as_bytes()), f),
            None => (TopoSched::NoRow, image),
        },
        other => (other, image),
    }
}

/// The class name a task's raw discriminant stands for, for log lines.
pub fn class_name_of(raw: u8) -> &'static str {
    match SchedClass::from_raw(raw) {
        Some(c) => c.name(),
        None => "?",
    }
}

/// Refusal site codes, the `action_code` of `SAFETY_TOPO_CLASS_REFUSED`.
pub const SITE_AUTORUN: u8 = 0;
/// See [`SITE_AUTORUN`].
pub const SITE_SPAWN: u8 = 1;
/// The autorun row asked for a priority below [`MIN_TASK_PRIORITY`] and was
/// raised: applied, not refused, and recorded under the same code.
pub const SITE_AUTORUN_FLOOR: u8 = 2;
/// See [`SITE_AUTORUN_FLOOR`], for `SYS_SPAWN`.
pub const SITE_SPAWN_FLOOR: u8 = 3;
/// A `sqpoll` topology permit refused because the machine has one online
/// hart: the poller would only take turns with its owner (`ioring_sqpoll.rs`).
pub const SITE_SQPOLL_SHARED_HART: u8 = 4;
/// A priority donation to a ring-3 task (a user-driver proxy client onto its
/// driver, a lessor onto its lessee) was raised to [`MIN_TASK_PRIORITY`]:
/// the donor was more urgent than a ring-3 task may run. `detail` is the
/// target's TID; recorded once per target task (`azos_sched::donate_priority`).
pub const SITE_DONATION_FLOOR: u8 = 5;
/// Wave 11 SCHED-RT: a row's real-time reservation was refused by run-time
/// admission (`detail` = the task's TID, 0 when no task was created). The
/// task never enters the band without one.
pub const SITE_SPAWN_RT: u8 = 6;
/// See [`SITE_SPAWN_RT`], for the autorun loader.
pub const SITE_AUTORUN_RT: u8 = 7;

/// Where a refusal goes, installed by the kernel at boot: this crate does not
/// depend on the flight recorder (`azos_behavior`), same arrangement as
/// `handlers::set_cap_deny_typed_recorder`.
static REFUSAL_RECORDER: azos_sync::SpinLock<Option<fn(u8, u32)>> =
    azos_sync::SpinLock::new(None);

/// Install the refusal recorder. Called once at boot.
pub fn set_refusal_recorder(f: fn(site: u8, tid: u32)) {
    *REFUSAL_RECORDER.lock() = Some(f);
}

/// Record that the row for task `tid` was refused at `site`. The lock is
/// released before the recorder runs.
pub fn record_refusal(site: u8, tid: u32) {
    let r = *REFUSAL_RECORDER.lock();
    if let Some(f) = r {
        f(site, tid);
    }
}

// ── RFC-0049 M1: the row's memory budget ────────────────────────────────────

/// The frame budget a program's row gives it: `(MemSpec, row name)`.
///
/// Same lookup order as [`resolve_image`]: the image's own row, else
/// `fallback`'s. With no row at all, the profile default ceiling
/// (`RING3_MEM_PAGES_DEFAULT`), unlocked: no ring-3 program runs unbounded.
/// No topology installed (early bring-up, host shims): no limit.
pub fn resolve_mem(image: &'static str, fallback: Option<&'static str>) -> (azos_sched::MemSpec, &'static str) {
    let default = azos_topology::RING3_DEFAULT_PAGES;
    let Some(topo) = azos_topology::get() else {
        return (azos_sched::MemSpec { limit: 0, locked: false, row: 0, instances: 0, huge_mib: 0 }, image);
    };
    match topo.row_mem(image.as_bytes(), fallback.map(str::as_bytes), default) {
        Some(m) => {
            let row = if m.row == image.as_bytes() { image } else { fallback.unwrap_or(image) };
            (mem_spec(m), row)
        }
        None => (azos_sched::MemSpec { limit: budget_frames(default), locked: false, row: 0, instances: 0, huge_mib: 0 }, image),
    }
}

/// A topology budget (4 KiB pages, `azos_topology::TOPOLOGY_PAGE`) as
/// the frames `azos_sched` charges: identical at a 4 KiB base page,
/// rounded up to whole frames under an aarch64 16/64 KiB granule. `0`
/// (unlimited) stays `0`.
fn budget_frames(units: u32) -> u32 {
    let f = azos_topology::frames_for(units as u64, azos_arch_api::PAGE_SIZE as u64);
    f.min(u32::MAX as u64) as u32
}

/// A row's budget as `azos_sched` applies it: the row index travels as
/// index + 1, so `0` can mean "no row" (nothing counted against `instances`).
fn mem_spec(m: azos_topology::RowMem<'_>) -> azos_sched::MemSpec {
    azos_sched::MemSpec {
        limit: budget_frames(m.limit),
        locked: m.locked,
        row: m.index + 1,
        instances: m.instances,
        huge_mib: m.huge_mib,
    }
}

/// The budget of the row named `image`, only if one exists — for a ring-3
/// exec, which keeps the caller's budget otherwise. Installed into
/// `handlers::set_exec_mem_resolver` at boot.
pub fn exec_mem_for(image: &'static str) -> Option<azos_sched::MemSpec> {
    let m = azos_topology::get()?.row_mem(image.as_bytes(), None, azos_topology::RING3_DEFAULT_PAGES)?;
    Some(mem_spec(m))
}

/// P2: refuse a locked row whose image's seccomp profile could fork or ask
/// for demand pages (`azos_sched::seccomp::locked_compatible`). `true`
/// when `mem` is not locked.
pub fn mem_row_admissible(mem: azos_sched::MemSpec, profile: &azos_sched::seccomp::ImageProfile) -> bool {
    !mem.locked || azos_sched::seccomp::locked_compatible(profile)
}

/// Does the topology row named `name` require sealed lease grants
/// (`lease_seal = true`, wave 11, LEASE3)? `false` without a topology or a
/// row. Installed into `handlers::set_lease_seal_resolver` at boot.
pub fn lease_seal_required_for(name: &str) -> bool {
    azos_topology::get().is_some_and(|t| t.row_lease_seal(name.as_bytes()))
}
