// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The hung-task and stuck-CPU detectors (Kconfig HUNG_DETECT).
//!
//! Both are samplers with no cost on the paths they watch: they read
//! counters those paths already keep, from the system watchdog's pass
//! (`azos_actuation::sys_wdt`), and a task or CPU is reported once the same
//! reading has stood for the timeout. Times are timebase ticks throughout.
//!
//! **Hung task.** A task is hung when it is `Blocked`, its wait has an owner
//! whose answer ends it, and its context-switch count has not moved for the
//! timeout (so it did not run, even briefly). "Has an owner" is the wait
//! graph's edge (`azos_sync::waitgraph`): a call waiting for its reply
//! (`IpcCall`, or a `FastIpcClient` wait with no edge), a kernel mutex, a
//! user driver serving a kernel request, a FAT claim. These end only when
//! another party acts, so a wait that outlasts the timeout is a stuck party.
//! What is never hung, however long: a server waiting for calls, an idle
//! worker on a wait queue, a ring or event-port wait, a timed sleep (none of
//! them names an owner), and a PI futex wait (a user lock whose holder's
//! pace is the program's own, as the interruptible wait it is on Linux).
//!
//! **Stuck CPU.** A CPU is stuck when it stayed in the kernel for the timeout
//! with its QSBR word (`azos_sync::qsbr::cpu_word`) unmoved, so it entered,
//! left, idled and switched nothing, and no timer tick found it preemptible
//! ([`tick`]). The second condition separates a CPU that cannot schedule
//! (preemption off in a loop, a lock nobody releases, interrupts masked) from
//! a kernel task that yields in a loop with nothing else to run: that one is
//! preemptible at every tick. A CPU in user mode or idle is quiescent, so an
//! idle CPU with its tick stopped is never reported.
//!
//! Against Linux: `hung_task` samples the same way (state D, `nvcsw +
//! nivcsw` unchanged for `hung_task_timeout_secs`), but on every
//! uninterruptible sleep, which is also every idle kernel thread's wait, so
//! it keeps a list of exceptions; here the set of waits is the ones that
//! name an owner, and the owner is in the report. Its softlockup is a
//! per-CPU high-priority thread that must get to run, and its hardlockup an
//! NMI that finds the CPU's interrupt counter still; here neither a thread
//! nor an NMI exists, so one peer reads the CPU's QSBR word (the word an idle
//! or user-mode CPU keeps even, which is what makes an idle CPU not a
//! suspect) and the tick leaves a preemptible-at-tick stamp. The action is
//! not a panic: a warning and a decision record always, then what the
//! build's HUNG_ACTION says (`sys_wdt`).

use crate::task::{WaitReason, MAX_TASKS};
use azos_sync::qsbr_core;
use azos_sync::waitgraph::EdgeKind;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Kconfig HUNG_DETECT.
pub const ON: bool = azos_limits::HUNG_DETECT;

const NTASK: usize = if ON { MAX_TASKS } else { 0 };
const NCPU: usize = if ON && azos_sync::qsbr::ON { azos_limits::NR_CPUS } else { 0 };

/// What was found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// A task waiting for a call's reply.
    Call = 0,
    /// A task waiting on another owner (a mutex, a driver, a claim).
    Owner = 1,
    /// A CPU that stopped scheduling.
    Cpu = 2,
}

/// One report: the state captured when the timeout ran out.
#[derive(Clone, Copy, Debug)]
pub struct Finding {
    pub kind: Kind,
    /// The task's tid, or the CPU's id.
    pub subject: u32,
    /// The task's slot (`Kind::Call`/`Owner`), for a culprit lookup the caller
    /// can make (`azos_ipc::fastcall::call_server_of`).
    pub slot: usize,
    /// Ticks the same reading stood.
    pub waited: u64,
    /// The tid the wait names as the one that must act, when the graph knows.
    pub culprit: Option<u32>,
    /// A call's handle (low 32 bits), the edge kind, or a CPU's progress word.
    pub detail: u32,
}

/// Which hung-task kind a blocked task is, or `None` for a wait that names no
/// owner.
pub const fn watched(reason: WaitReason, edge: Option<EdgeKind>) -> Option<Kind> {
    match (edge, reason) {
        (Some(EdgeKind::IpcCall), _) | (None, WaitReason::FastIpcClient(_)) => Some(Kind::Call),
        (Some(EdgeKind::Mutex | EdgeKind::DriverProxy | EdgeKind::Claim), _) => Some(Kind::Owner),
        _ => None,
    }
}

struct TaskSeen {
    tid: AtomicU32,
    switches: AtomicU64,
    since: AtomicU64,
    reported: AtomicBool,
}

struct CpuSeen {
    word: AtomicU64,
    since: AtomicU64,
    /// 0 not watching (quiescent or never seen), 1 watching, 2 reported.
    state: AtomicU32,
}

static BLIND_TASKS: AtomicBool = AtomicBool::new(false);
static BLIND_CPUS: AtomicBool = AtomicBool::new(false);

/// Gate canary `hung-task-blind` (ktest `hung_task_detector_reports_a_blocked_owner_wait`):
/// the scan reads no task.
pub fn canary_blind_tasks() {
    BLIND_TASKS.store(true, Ordering::Relaxed);
}

/// Gate canary `hung-cpu-blind` (ktest `stuck_cpu_detector_names_the_cpu`): the
/// scan reads no CPU.
pub fn canary_blind_cpus() {
    BLIND_CPUS.store(true, Ordering::Relaxed);
}

/// The newest tick at which each CPU was preemptible, in timebase ticks.
static PREEMPTIBLE_AT: [AtomicU64; NCPU] = [const { AtomicU64::new(0) }; NCPU];

/// A timer tick on the calling CPU (`now`: the timebase): note when this CPU
/// was last interrupted with preemption enabled. Interrupt context; a load
/// and, when the interrupted code was preemptible, a store.
#[inline]
pub fn tick(now: u64) {
    if NCPU != 0 && azos_sync::preempt::depth() == 0 {
        if let Some(at) = PREEMPTIBLE_AT.get(crate::smp::current_cpu_id()) {
            at.store(now, Ordering::Relaxed);
        }
    }
}

/// The detectors' state: what each task and CPU read at the first sighting of
/// its current reading. One owner scans (the watchdog pass; a ktest has its
/// own), so nothing here is contended.
pub struct Hung {
    tasks: [TaskSeen; NTASK],
    cpus: [CpuSeen; NCPU],
}

impl Hung {
    pub const fn new() -> Self {
        Hung {
            tasks: [const {
                TaskSeen {
                    tid: AtomicU32::new(0),
                    switches: AtomicU64::new(0),
                    since: AtomicU64::new(0),
                    reported: AtomicBool::new(false),
                }
            }; NTASK],
            cpus: [const {
                CpuSeen { word: AtomicU64::new(0), since: AtomicU64::new(0), state: AtomicU32::new(0) }
            }; NCPU],
        }
    }

    /// One scan at `now`. `task_ticks` and `cpu_ticks` are the timeouts. Each
    /// hang or stuck CPU is handed to `found` once, when its reading has stood
    /// for its timeout; a task that runs again, or a CPU that moves, is
    /// watched afresh.
    pub fn scan(&self, now: u64, task_ticks: u64, cpu_ticks: u64, mut found: impl FnMut(Finding)) {
        for (idx, seen) in self.tasks.iter().enumerate() {
            self.task(idx, seen, now, task_ticks, &mut found);
        }
        self.cpus(now, cpu_ticks, &mut found);
    }

    fn task(&self, idx: usize, seen: &TaskSeen, now: u64, timeout: u64, found: &mut impl FnMut(Finding)) {
        let row = if BLIND_TASKS.load(Ordering::Relaxed) { None } else { crate::scheduler::blocked_task_at(idx) };
        let watch = row.and_then(|r| watched(r.reason, r.edge.map(|e| e.0)).map(|k| (r, k)));
        let Some((row, kind)) = watch else {
            seen.tid.store(0, Ordering::Relaxed);
            return;
        };
        if seen.tid.load(Ordering::Relaxed) != row.tid || seen.switches.load(Ordering::Relaxed) != row.switches {
            seen.tid.store(row.tid, Ordering::Relaxed);
            seen.switches.store(row.switches, Ordering::Relaxed);
            seen.since.store(now, Ordering::Relaxed);
            seen.reported.store(false, Ordering::Relaxed);
            return;
        }
        let since = seen.since.load(Ordering::Relaxed);
        if seen.reported.load(Ordering::Relaxed) || !qsbr_core::stalled(since, now, timeout) {
            return;
        }
        seen.reported.store(true, Ordering::Relaxed);
        let (owner, detail) = match (row.edge, row.reason) {
            (Some((k, owner)), _) => (owner, k as u32),
            (None, WaitReason::FastIpcClient(h)) => (None, h as u32),
            _ => (None, 0),
        };
        found(Finding {
            kind,
            subject: row.tid,
            slot: idx,
            waited: now.wrapping_sub(since),
            culprit: owner.and_then(|s| crate::scheduler::tid_for_idx(s as usize)),
            detail,
        });
    }

    fn cpus(&self, now: u64, timeout: u64, found: &mut impl FnMut(Finding)) {
        let me = crate::smp::current_cpu_id();
        for (cpu, seen) in self.cpus.iter().enumerate().take(azos_percpu::nr_cpu_ids()) {
            let word = if cpu == me || !azos_percpu::cpu_online(cpu) || BLIND_CPUS.load(Ordering::Relaxed) {
                None
            } else {
                azos_sync::qsbr::cpu_word(cpu)
            };
            let Some(word) = word.filter(|&w| !qsbr_core::quiescent(w)) else {
                seen.state.store(0, Ordering::Relaxed);
                continue;
            };
            if seen.state.load(Ordering::Relaxed) == 0 || seen.word.load(Ordering::Relaxed) != word {
                seen.word.store(word, Ordering::Relaxed);
                seen.since.store(now, Ordering::Relaxed);
                seen.state.store(1, Ordering::Relaxed);
                continue;
            }
            let since = seen.since.load(Ordering::Relaxed);
            if seen.state.load(Ordering::Relaxed) != 1 || !qsbr_core::stalled(since, now, timeout) {
                continue;
            }
            // A tick that found the CPU preemptible after the word last moved
            // means the CPU can still schedule.
            if PREEMPTIBLE_AT[cpu].load(Ordering::Relaxed) >= since {
                continue;
            }
            seen.state.store(2, Ordering::Relaxed);
            found(Finding {
                kind: Kind::Cpu,
                subject: cpu as u32,
                slot: 0,
                waited: now.wrapping_sub(since),
                culprit: None,
                detail: word as u32,
            });
        }
    }
}

impl Default for Hung {
    fn default() -> Self {
        Self::new()
    }
}
