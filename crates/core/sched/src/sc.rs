// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The scheduling context (SC) and the dispatch-class model (N6).
//!
//! A [`SchedContext`] is what a task runs *on*: its class, its time
//! parameters, and the attributes the wait graph, mixed criticality and the
//! RT cluster need. Its layout is **frozen** here, once, with every field the
//! later steps read (SCHED-SYNC §3 step 4, owner answer Q8): the size is a
//! compile-time assertion, so adding a field is a build error, not a review
//! comment. Later steps give the reserved fields their writers; none of them
//! reshapes the object.
//!
//! [`Class`] is the dispatch class, with a fixed precedence
//! `stop > DL > RT > fair > idle` (owner answer Q6). It is not the RFC-0004
//! [`SchedClass`](crate::class::SchedClass) (`class.rs`): that one names the
//! Adaptive Partitioning budget classes of the topology (`[class.<name>]`)
//! and, per Q6, survives as the fair class's group weights; this one decides
//! which class's queue the CPU is taken from.
//!
//! Pure: no kernel dependency, so the host suite
//! (`tests/host/sched-policy-tests`) compiles it as is. The kernel's class
//! implementations over the live ready queues are `classes.rs`.

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};

/// A dispatch class. The discriminant is the precedence rank: lower runs
/// first.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Class {
    /// Per-CPU stop work (stop-machine, migration). Preempts everything.
    Stop = 0,
    /// Deadline: tasks holding an admitted EDF + CBS reservation.
    Dl = 1,
    /// Fixed-priority real-time band (`priority < RT_PRIORITY_THRESHOLD`).
    Rt = 2,
    /// Every other task (part b replaces the wrapper with EEVDF).
    Fair = 3,
    /// The per-CPU idle task.
    Idle = 4,
}

impl Class {
    /// Number of classes.
    pub const COUNT: usize = 5;
    /// The fixed precedence, highest first (owner answer Q6).
    pub const PRECEDENCE: [Class; Class::COUNT] =
        [Class::Stop, Class::Dl, Class::Rt, Class::Fair, Class::Idle];

    /// From the raw discriminant; `None` for an unknown one.
    #[inline]
    pub const fn from_raw(raw: u8) -> Option<Class> {
        match raw {
            0 => Some(Class::Stop),
            1 => Some(Class::Dl),
            2 => Some(Class::Rt),
            3 => Some(Class::Fair),
            4 => Some(Class::Idle),
            _ => None,
        }
    }

    /// The precedence rank: 0 runs first.
    #[inline]
    pub const fn rank(self) -> u8 {
        self as u8
    }

    /// Does a runnable task of `self` take the CPU from one of `other`?
    /// Strict: two tasks of one class are ordered by that class.
    #[inline]
    pub const fn preempts(self, other: Class) -> bool {
        (self as u8) < (other as u8)
    }

    /// The name `sched=` and `schedctl` will use (part b).
    pub const fn name(self) -> &'static str {
        match self {
            Class::Stop => "stop",
            Class::Dl => "dl",
            Class::Rt => "rt",
            Class::Fair => "fair",
            Class::Idle => "idle",
        }
    }

    /// The inverse of [`name`](Self::name).
    pub fn from_name(name: &[u8]) -> Option<Class> {
        Class::PRECEDENCE.into_iter().find(|c| c.name().as_bytes() == name)
    }
}

/// The class today's Legacy state puts a task in. `stop`: a per-CPU stop
/// task; `reserved`: it holds an admitted EDF + CBS reservation; `prio` its
/// effective priority against the RT band threshold and the idle priority.
#[inline]
pub const fn classify(prio: u32, reserved: bool, stop: bool, rt_threshold: u32, idle_prio: u32) -> Class {
    if stop {
        Class::Stop
    } else if reserved {
        Class::Dl
    } else if prio >= idle_prio {
        Class::Idle
    } else if prio < rt_threshold {
        Class::Rt
    } else {
        Class::Fair
    }
}

/// Mixed-criticality level of an SC (`C_LO` / `C_HI` budgets).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Criticality {
    /// Runs only in LO mode once the system switches to HI.
    Lo = 0,
    /// Keeps running with its `C_HI` budget in HI mode.
    Hi = 1,
}

/// `on_cpu` of an SC that runs nowhere.
pub const NO_CPU: u16 = u16::MAX;

/// A scheduling context. Every field is an atomic: other CPUs read it (the
/// wait-graph walk, admission, `schedctl`) while its owner writes it.
///
/// Times are microseconds (the units of a topology row and of
/// `Reservation`). A field marked *reserved* has no writer in N6; the step
/// named gives it one, without moving it.
#[repr(C)]
pub struct SchedContext {
    /// Budget per period (DL runtime, RT band share; 0 = none).
    pub budget_us: AtomicU64,
    /// Replenishment period (0 = none).
    pub period_us: AtomicU64,
    /// Relative deadline (0 = the period).
    pub deadline_us: AtomicU64,
    /// Mixed-criticality LO-mode budget (reserved: admission with criticality).
    pub c_lo_us: AtomicU64,
    /// Mixed-criticality HI-mode budget (reserved: admission with criticality).
    pub c_hi_us: AtomicU64,
    /// The wait-graph object this SC's task is blocked on: the address of
    /// its `azos_sync::waitgraph::PiWaiters`, 0 = none (an
    /// `Option<WaitObj>`; `WaitObj` is a non-null pointer). Written only by
    /// the graph, through `classes::ClassPi` (N7). A plain address so this
    /// file stays free of kernel crates (the host suite compiles it as is).
    pub blocked_on: AtomicUsize,
    /// RT/DL: the priority level; fair: the weight (part b, EEVDF).
    pub prio_or_weight: AtomicU32,
    /// QoS identity the SC is accounted to (reserved: APS group weights, L10).
    pub qos_id: AtomicU32,
    /// The CPU the SC runs on, [`NO_CPU`] = none (reserved: N7; read today
    /// through `classes::on_cpu`, computed from the per-CPU current task).
    pub on_cpu: AtomicU16,
    /// The `Cap<Irq>` source this SC serves, 0 = none (reserved: L5).
    pub irq: AtomicU16,
    /// [`Class`] discriminant.
    pub class: AtomicU8,
    /// [`Criticality`] discriminant.
    pub criticality: AtomicU8,
    /// The CPU cluster the SC is admitted to (0 = the general cluster; part
    /// b defaults `RCU_NOCBS_CPUS` from the RT cluster).
    pub cluster: AtomicU8,
    /// Flag bits (reserved).
    pub flags: AtomicU8,
}

/// The frozen size. Changing the layout is a deliberate edit of this line.
/// N7 widened `blocked_on` to a pointer by spending the 4 reserved bytes:
/// the size did not move.
pub const SC_SIZE: usize = 64;
const _: () = assert!(core::mem::size_of::<SchedContext>() == SC_SIZE);

impl SchedContext {
    /// An SC in `class` with no time parameters.
    pub const fn new(class: Class) -> Self {
        Self {
            budget_us: AtomicU64::new(0),
            period_us: AtomicU64::new(0),
            deadline_us: AtomicU64::new(0),
            c_lo_us: AtomicU64::new(0),
            c_hi_us: AtomicU64::new(0),
            blocked_on: AtomicUsize::new(0),
            prio_or_weight: AtomicU32::new(0),
            qos_id: AtomicU32::new(0),
            on_cpu: AtomicU16::new(NO_CPU),
            irq: AtomicU16::new(0),
            class: AtomicU8::new(class as u8),
            criticality: AtomicU8::new(Criticality::Lo as u8),
            cluster: AtomicU8::new(0),
            flags: AtomicU8::new(0),
        }
    }

    /// The SC's class.
    #[inline]
    pub fn class(&self) -> Class {
        Class::from_raw(self.class.load(Ordering::Relaxed)).unwrap_or(Class::Fair)
    }

    /// Put the SC in `class` at level/weight `prio`.
    #[inline]
    pub fn set_class(&self, class: Class, prio: u32) {
        self.prio_or_weight.store(prio, Ordering::Relaxed);
        self.class.store(class as u8, Ordering::Relaxed);
    }

    /// Record admitted time parameters (DL). Zeroes them for any other class.
    pub fn set_times(&self, budget_us: u64, period_us: u64, deadline_us: u64) {
        self.budget_us.store(budget_us, Ordering::Relaxed);
        self.period_us.store(period_us, Ordering::Relaxed);
        self.deadline_us.store(deadline_us, Ordering::Relaxed);
    }
}

/// One dispatch class over its run queue. Indices are task slots.
///
/// `pick` is a **peek**: it names the task the class would run next on
/// `cpu` without taking it off its queue, so a caller can walk the classes
/// in precedence and commit only the winner (`dequeue`).
pub trait SchedClassOps: Sync {
    /// Which class this is.
    fn class(&self) -> Class;
    /// Make `idx` runnable on `cpu`. `false`: refused (already queued).
    fn enqueue(&self, cpu: usize, idx: usize) -> bool;
    /// Take `idx` off `cpu`'s queue. `false`: it was not there.
    fn dequeue(&self, cpu: usize, idx: usize) -> bool;
    /// The task this class runs next on `cpu`, if it has one.
    fn pick(&self, cpu: usize) -> Option<usize>;
    /// The tick on `cpu` with `cur` running: charge it; `true` = preempt.
    fn tick(&self, cpu: usize, cur: usize) -> bool;
    /// Must `cand` (of this class) take `cpu` from `cur` (of this class)?
    fn preempt_check(&self, cpu: usize, cur: usize, cand: usize) -> bool;
}

/// `canary=sched-class-invert`: the walk runs the precedence backwards.
static INVERTED: AtomicBool = AtomicBool::new(false);

/// Arm the inverted-precedence canary (boot, once).
pub fn canary_invert_precedence() {
    INVERTED.store(true, Ordering::Relaxed);
}

/// The class table of one build: `None` for a class compiled out.
pub type ClassTable<'a> = [Option<&'a dyn SchedClassOps>; Class::COUNT];

/// The first class in precedence with a runnable task on `cpu`, and that
/// task. A class that is compiled out (`None`) is skipped.
pub fn pick_in_precedence(table: &ClassTable<'_>, cpu: usize) -> Option<(Class, usize)> {
    let inv = INVERTED.load(Ordering::Relaxed);
    for k in 0..Class::COUNT {
        let c = Class::PRECEDENCE[if inv { Class::COUNT - 1 - k } else { k }];
        if let Some(ops) = table[c as usize] {
            if let Some(idx) = ops.pick(cpu) {
                return Some((c, idx));
            }
        }
    }
    None
}

/// Must a task of class `cand` take the CPU from one of `cur`? Across classes
/// precedence decides; inside one the class's own `preempt_check`.
pub fn should_preempt(
    table: &ClassTable<'_>,
    cpu: usize,
    cur: (Class, usize),
    cand: (Class, usize),
) -> bool {
    if cand.0 != cur.0 {
        return cand.0.preempts(cur.0) != INVERTED.load(Ordering::Relaxed);
    }
    match table[cand.0 as usize] {
        Some(ops) => ops.preempt_check(cpu, cur.1, cand.1),
        None => false,
    }
}
