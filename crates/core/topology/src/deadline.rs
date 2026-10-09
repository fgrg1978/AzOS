// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Deadline feasibility: can the declared real-time tasks all meet their
//! deadlines on the CPUs they may run on?
//!
//! **Why this exists.** `ClassSpec::admission_control` was parsed, declared
//! `true` for the safety classes, and read by nothing: a safety property the
//! topology promised and the kernel never enforced. And `task_set_deadline` had
//! an admission check of its own (`scheduler::deadline_admission_check`, deleted
//! in wave 11 with the rest of that path) that summed utilisation over ALL tasks
//! regardless of CPU, so it accepted a set no single CPU could run, and had no
//! caller anyway. This module is the check
//! itself, pure and allocation-free, so the topology can be REFUSED AT BOOT
//! instead of running with "stochastic deadline misses".
//!
//! # The model
//!
//! Partitioned EDF: each task runs on exactly one CPU, and each CPU schedules its
//! own tasks by earliest deadline. A task set is feasible on one CPU if its
//! summed **density** is at most 100%, where a task's density is
//! `runtime / min(deadline, period)`.
//!
//! * Density, not utilisation. `runtime / period` is the exact bound only for
//!   implicit deadlines (`deadline == period`); with a constrained deadline it
//!   under-counts. A task that needs 2 ms of every 10 ms but must finish within 4 ms
//!   of release is a 50% task to the CPU, not a 20% one.
//! * A **sufficient** test, not a necessary one. Density-at-most-1 never admits an
//!   infeasible set; it can refuse a feasible one that only exact demand-bound
//!   analysis would admit. For a robot that is the right side to err on: a refusal
//!   is a message at boot, a wrong admission is a missed deadline on a wheel.
//! * Placement is first-fit by decreasing density, tasks with equal density taken
//!   in declaration order, so the verdict is deterministic. Bin packing is NP-hard
//!   in general, so a set that only a cleverer packing would fit can be refused
//!   too; the same side of the same trade.
//!
//! Everything is `u64` arithmetic on parts-per-million with the division rounded
//! UP: a task's density is never under-stated. Nothing here can panic, because
//! `panic = "abort"` makes a panic at boot a board that never starts.

use crate::types::MAX_CLASSES;

/// One CPU is this many parts per million (the scheduler's scale, shared
/// through `azos_abi::rt_levels`).
pub const PPM: u32 = azos_abi::rt_levels::PPM as u32;

/// Highest priority level a row's reservation runs at: the scheduler's
/// `MAX_TASK_PRIORITY` (`IDLE_PRIORITY - 1`). `azos_syscall::topo_sched`
/// asserts the two are equal at compile time, like [`RT_BAND_THRESHOLD`].
pub const MAX_ROW_LEVEL: u32 = 30;

/// CPUs a profile's mask can name. `cpu_mask` is a `u32`.
pub const MAX_ADMISSION_CPUS: usize = 32;

/// Most profiled tasks one admission run will consider. It bounds the work: the
/// placement is O(n²), and this runs at boot, where there is no watchdog to kick
/// and no preemption to save a loop that runs long.
pub const MAX_PROFILED: usize = 64;

/// Real-time parameters of one task, as declared.
///
/// All-zero (`NONE`) means "no profile declared": the task is best-effort and
/// this module ignores it. Anything else must be complete and consistent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SchedProfile {
    /// Release period, microseconds. Zero only in `NONE`.
    pub period_us: u32,
    /// Worst-case execution time per period, microseconds.
    pub runtime_us: u32,
    /// Relative deadline, microseconds. Zero means "the period" (implicit).
    pub deadline_us: u32,
    /// CPUs the task may run on, bit `n` = CPU `n`. Zero means "any CPU".
    pub cpu_mask: u32,
}

impl SchedProfile {
    /// No profile declared.
    pub const NONE: Self = Self { period_us: 0, runtime_us: 0, deadline_us: 0, cpu_mask: 0 };

    /// Whether any field is set. A partly filled profile counts as declared, so
    /// that it is rejected as malformed and not silently ignored.
    #[inline]
    pub const fn is_declared(&self) -> bool {
        self.period_us != 0 || self.runtime_us != 0 || self.deadline_us != 0 || self.cpu_mask != 0
    }
}

/// Why one profile is malformed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProfileFault {
    /// `period_us` is zero.
    ZeroPeriod,
    /// `runtime_us` is zero.
    ZeroRuntime,
    /// `runtime_us` is larger than the deadline: it cannot finish in time even
    /// alone on an idle CPU.
    RuntimeExceedsDeadline,
    /// `deadline_us` is larger than the period. Constrained deadlines only.
    DeadlineExceedsPeriod,
    /// `cpu_mask` names no CPU that exists.
    NoCpuInMask,
}

/// Why a topology's real-time tasks were refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeadlineRefusal {
    /// A profile is malformed. `task` is its index in the topology.
    Invalid {
        /// Index of the task in the topology.
        task: u16,
        /// What is wrong with it.
        fault: ProfileFault,
    },
    /// No CPU the task may run on has room for it. `task` is the first task
    /// that did not fit, in placement order.
    NoCpuFits {
        /// Index of the task in the topology.
        task: u16,
    },
    /// Room on a CPU, but not within the task's class's CPU budget.
    ClassBudget {
        /// Index of the task in the topology.
        task: u16,
    },
    /// Placed, but the real-time band's tasks on its CPU need more than the
    /// band may use there (wave 11 SCHED-RT: the band budget, Kconfig
    /// `RT_BAND_CAP_PCT`, leaves the rest of each CPU to the tasks outside
    /// the band, so admitting band reservations beyond it would promise
    /// deadlines the budget then breaks). `task` is the first band task on
    /// that CPU, in placement order, past the cap.
    BandCap {
        /// Index of the task in the topology.
        task: u16,
    },
    /// A row that would run in the real-time band with a reservation is not
    /// `mem = "locked"` (owner decision, wave 11 SCHED-RT): a ring-3 task in
    /// the band must not take demand-paging faults on its real-time path.
    BandNotLocked {
        /// Index of the task in the topology.
        task: u16,
    },
    /// Room on a CPU for the task's density, but the reservations placed
    /// there sit at different priority levels and a level could miss a
    /// deadline (`azos_abi::rt_levels::levels_fit`, the rule run-time
    /// `reserve` applies too: wave 15). Reported for the last CPU tried.
    Levels {
        /// Index of the task in the topology.
        task: u16,
        /// The CPU whose set the task did not fit.
        cpu: u8,
        /// The priority level the task's reservation runs at.
        level: u32,
        /// The level whose deadlines that set could not guarantee.
        failing_level: u32,
    },
    /// More profiled tasks than one admission run will consider.
    TooManyProfiles,
}

/// Below this priority (lower = more urgent) a task runs in the scheduler's
/// real-time band, which the tick never preempts. The scheduler's
/// `RT_PRIORITY_THRESHOLD`; `azos_syscall::topo_sched` asserts the two are
/// equal at compile time (this crate does not depend on the scheduler).
pub const RT_BAND_THRESHOLD: u8 = 12;

/// May a row's task run in the real-time band (wave 11 SCHED-RT, owner
/// decisions)? Only with an admitted CBS reservation AND `mem = "locked"`.
/// The one rule both topology admission and `SYS_SPAWN` apply.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BandEntry {
    /// The row's priority is not in the band: nothing to decide.
    NotBand,
    /// In the band, with an admitted profile and locked memory: allowed.
    Admitted,
    /// In the band without an admitted profile: a ring-3 task named after it
    /// is raised to the ring-3 floor instead (raised and recorded, the rule of
    /// 2026-09-28).
    NoReservation,
    /// In the band with an admitted profile but demand-paged memory: refused,
    /// at topology admission and at spawn.
    NotLocked,
}

/// [`BandEntry`] for a row whose priority, clamped into its class, is
/// `priority`; `admitted` when it declares a profile in a class with
/// `admission_control`; `locked` when it is `mem = "locked"`.
pub const fn band_entry(priority: u8, admitted: bool, locked: bool) -> BandEntry {
    if priority >= RT_BAND_THRESHOLD {
        BandEntry::NotBand
    } else if !admitted {
        BandEntry::NoReservation
    } else if !locked {
        BandEntry::NotLocked
    } else {
        BandEntry::Admitted
    }
}

/// One task's profile with the class it belongs to, as the checker sees it.
#[derive(Clone, Copy, Debug)]
pub struct Item {
    /// Index of the task in the topology, for the refusal to name.
    pub task: u16,
    /// Index of the task's class, `< MAX_CLASSES`.
    pub class: u8,
    /// Priority level its reservation runs at (`Topology::row_level`): the
    /// cross-level check reads it.
    pub level: u32,
    /// The declared profile.
    pub profile: SchedProfile,
}

/// What a successful run placed: the load on each CPU.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Report {
    /// Summed density on each CPU, parts per million.
    pub cpu_load_ppm: [u32; MAX_ADMISSION_CPUS],
    /// How many profiled tasks were placed.
    pub placed: u16,
    /// `(task, cpu)` of each placed task, in placement order; the first
    /// `placed` entries are meaningful. Run-time attachment pins a row's task
    /// to the CPU admission gave it (`Report::cpu_of`), which is what keeps
    /// the partitioned check sound.
    pub placement: [(u16, u8); MAX_PROFILED],
}

impl Report {
    /// The CPU admission placed topology task `task` on.
    pub fn cpu_of(&self, task: u16) -> Option<u8> {
        self.placement[..(self.placed as usize).min(MAX_PROFILED)]
            .iter()
            .find(|p| p.0 == task)
            .map(|p| p.1)
    }

    /// Check that on every CPU the summed density of the placed tasks for
    /// which `in_band(task)` holds stays within `band_limit_ppm`. `density`
    /// gives a task's density, as placed.
    pub fn band_check(
        &self,
        in_band: impl Fn(u16) -> bool,
        density: impl Fn(u16) -> u32,
        band_limit_ppm: u32,
    ) -> Result<(), DeadlineRefusal> {
        let mut band = [0u64; MAX_ADMISSION_CPUS];
        for &(task, cpu) in &self.placement[..(self.placed as usize).min(MAX_PROFILED)] {
            if !in_band(task) {
                continue;
            }
            let c = (cpu as usize).min(MAX_ADMISSION_CPUS - 1);
            band[c] += density(task) as u64;
            if band[c] > band_limit_ppm as u64 {
                return Err(DeadlineRefusal::BandCap { task });
            }
        }
        Ok(())
    }
}

/// A profile's density as admission computes it, ppm (rounded up). `None` if
/// the profile is malformed.
pub fn profile_density(p: &SchedProfile) -> Option<u32> {
    validate(p, MAX_ADMISSION_CPUS).ok()
}

/// `ceil(runtime * PPM / window)`. `window` is nonzero by the time this is called.
#[inline]
fn density_ppm(runtime_us: u32, window_us: u32) -> u32 {
    let num = (runtime_us as u64) * (PPM as u64);
    let w = window_us as u64;
    let d = num.div_ceil(w);
    // A validated profile has runtime <= window, so d <= PPM; clamp anyway,
    // since a value that cannot fit any CPU is refused rather than wrapped.
    if d > PPM as u64 { PPM + 1 } else { d as u32 }
}

/// The CPUs `mask` names among the first `ncpus`, as a bitmask.
#[inline]
fn effective_mask(mask: u32, ncpus: usize) -> u32 {
    let all = if ncpus >= 32 { u32::MAX } else { (1u32 << ncpus) - 1 };
    if mask == 0 { all } else { mask & all }
}

/// Validate one profile against `ncpus` and return its density.
fn validate(p: &SchedProfile, ncpus: usize) -> Result<u32, ProfileFault> {
    if p.period_us == 0 {
        return Err(ProfileFault::ZeroPeriod);
    }
    if p.runtime_us == 0 {
        return Err(ProfileFault::ZeroRuntime);
    }
    let deadline = if p.deadline_us == 0 { p.period_us } else { p.deadline_us };
    if deadline > p.period_us {
        return Err(ProfileFault::DeadlineExceedsPeriod);
    }
    if p.runtime_us > deadline {
        return Err(ProfileFault::RuntimeExceedsDeadline);
    }
    if effective_mask(p.cpu_mask, ncpus) == 0 {
        return Err(ProfileFault::NoCpuInMask);
    }
    // Density over the tighter of deadline and period; deadline <= period here.
    Ok(density_ppm(p.runtime_us, deadline))
}

/// Decide whether every item can be placed on some CPU.
///
/// `class_budget_ppm[c]` is the most of any one CPU that class `c` may take, in
/// parts per million (a class's `cpu_budget_max_pct` × 10,000).
///
/// Returns the per-CPU load on success. On refusal, names the task.
pub fn admit(
    items: &[Item],
    ncpus: usize,
    class_budget_ppm: &[u32; MAX_CLASSES],
) -> Result<Report, DeadlineRefusal> {
    if items.len() > MAX_PROFILED {
        return Err(DeadlineRefusal::TooManyProfiles);
    }
    let ncpus = ncpus.min(MAX_ADMISSION_CPUS);

    // Validate everything first, so a malformed profile is reported as that and
    // not as whatever packing failure it happens to cause.
    let mut density = [0u32; MAX_PROFILED];
    for (i, it) in items.iter().enumerate() {
        density[i] = validate(&it.profile, ncpus)
            .map_err(|fault| DeadlineRefusal::Invalid { task: it.task, fault })?;
    }

    // Placement order: decreasing density, ties by position. Repeated selection
    // over a `placed` set: O(n^2) with n <= MAX_PROFILED, and no sort buffer.
    let mut placed_flag = [false; MAX_PROFILED];
    let mut cpu_load = [0u32; MAX_ADMISSION_CPUS];
    let mut class_load = [[0u32; MAX_CLASSES]; MAX_ADMISSION_CPUS];
    let mut placed: u16 = 0;
    let mut placement = [(0u16, 0u8); MAX_PROFILED];
    // CPU each item was placed on, by item index; `u8::MAX` = not yet.
    let mut item_cpu = [u8::MAX; MAX_PROFILED];

    for _ in 0..items.len() {
        // Densest unplaced item; the first of equals wins because `>` is strict.
        let mut pick = usize::MAX;
        for i in 0..items.len() {
            if !placed_flag[i] && (pick == usize::MAX || density[i] > density[pick]) {
                pick = i;
            }
        }
        if pick == usize::MAX {
            break;
        }
        placed_flag[pick] = true;

        let it = &items[pick];
        let d = density[pick];
        let class = (it.class as usize).min(MAX_CLASSES - 1);
        let mask = effective_mask(it.profile.cpu_mask, ncpus);

        let mut fit: Option<usize> = None;
        let mut had_room_on_a_cpu = false;
        let mut levels: Option<(u8, u32)> = None;
        for cpu in 0..ncpus {
            if mask & (1u32 << cpu) == 0 {
                continue;
            }
            if cpu_load[cpu].saturating_add(d) > PPM {
                continue;
            }
            had_room_on_a_cpu = true;
            if class_load[cpu][class].saturating_add(d) > class_budget_ppm[class] {
                continue;
            }
            if let Err(l) = levels_on(items, &density, &item_cpu, cpu, pick) {
                levels = Some((cpu as u8, l));
                continue;
            }
            fit = Some(cpu);
            break;
        }
        match fit {
            Some(cpu) => {
                cpu_load[cpu] += d;
                class_load[cpu][class] += d;
                placement[placed as usize] = (it.task, cpu as u8);
                item_cpu[pick] = cpu as u8;
                placed += 1;
            }
            // Mirrors run-time `first_fit_by`: a CPU with room whose levels
            // do not fit is the most specific reason.
            None => return Err(match levels {
                Some((cpu, failing_level)) =>
                    DeadlineRefusal::Levels { task: it.task, cpu, level: it.level, failing_level },
                None if had_room_on_a_cpu => DeadlineRefusal::ClassBudget { task: it.task },
                None => DeadlineRefusal::NoCpuFits { task: it.task },
            }),
        }
    }
    Ok(Report { cpu_load_ppm: cpu_load, placed, placement })
}

/// The cross-level check (`azos_abi::rt_levels::levels_check`) for `cpu`'s
/// placed items (`item_cpu[i] == cpu`) plus item `cand`. `Err` names the
/// level that fails. O(n²) with n <= MAX_PROFILED, like the placement.
fn levels_on(
    items: &[Item],
    density: &[u32; MAX_PROFILED],
    item_cpu: &[u8; MAX_PROFILED],
    cpu: usize,
    cand: usize,
) -> Result<(), u32> {
    use azos_abi::rt_levels::{levels_check, Booked};
    if cfg!(feature = "deadline-levels-canary") {
        return Ok(());
    }
    let booked = |i: usize| {
        let p = &items[i].profile;
        let d = if p.deadline_us == 0 { p.period_us } else { p.deadline_us };
        Booked { level: items[i].level, q: p.runtime_us as u64, d: d as u64, density_ppm: density[i] }
    };
    let mut b = [booked(cand); MAX_PROFILED + 1];
    let mut n = 1;
    for i in 0..items.len() {
        if item_cpu[i] as usize == cpu {
            b[n] = booked(i);
            n += 1;
        }
    }
    levels_check(&b[..n])
}
