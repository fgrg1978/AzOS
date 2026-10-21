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
//! `stop > DL > RT > fair > idle` (owner answer Q6). It is not the budget-class
//! [`SchedClass`](crate::class::SchedClass) (`class.rs`): that one names the
//! Adaptive Partitioning budget classes of the topology (`[class.<name>]`)
//! and, per Q6, survives as the fair class's group weights; this one decides
//! which class's queue the CPU is taken from.
//!
//! Pure: no kernel dependency, so the host suite
//! (`tests/host/sched-policy-tests`) compiles it as is. The kernel's class
//! implementations over the live ready queues are `classes.rs`.

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU8, AtomicUsize, Ordering};

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

    /// The name `schedctl` uses.
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

/// The class a task's priority and state put it in. `stop`: a per-CPU stop
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

pub use azos_abi::syscall_nr::{QOS_BACKGROUND, QOS_DEFAULT, QOS_LATENCY, QOS_THROUGHPUT};
/// The highest QoS hint.
pub const QOS_MAX: u32 = QOS_BACKGROUND;
/// How many QoS hints there are (the length of a per-tier table).
pub const QOS_LEVELS: usize = QOS_MAX as usize + 1;

/// [`SchedContext::flags`] bit: the task's topology row says
/// `timer_slack = true`. Written once where the row is applied (the autorun
/// loader, `SYS_SPAWN_EX`), cleared when the slot is reused. Under
/// [`SlackMode::Rows`] it is what lets the task's QoS tier give its timers
/// a slack window.
pub const SC_FLAG_TIMER_SLACK: u8 = 1;

/// Who gets timer slack (Kconfig `QOS_TIMER_TOLERANCE`,
/// `QOS_TIMER_TOLERANCE_ROWS_ONLY`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlackMode {
    /// Nobody: every timer fires at its deadline.
    Off,
    /// Only a task whose topology row says `timer_slack = true`
    /// (robot, industrial, automotive: the owner opts a row in).
    Rows,
    /// Every task whose class allows it (desktop, IoT, wearable).
    All,
}

/// How long a timer armed by a task of `class` at QoS hint `qos` may fire
/// after its deadline, in microseconds: the tier's entry of `tiers_us`
/// (indexed by [`QOS_DEFAULT`]..=[`QOS_BACKGROUND`]; a hint above
/// [`QOS_MAX`] reads the last), or 0.
///
/// **Only the fair class has slack.** A stop, deadline or real-time task
/// (and the idle task) gets 0 whatever its hint, row or the mode: its
/// timers are its contract (an RT loop's period, a reservation's
/// replenishment), and a window there is a missed deadline. The class is
/// tested here, once, before the mode or the table is looked at, so no
/// configuration of the tiers can give a real-time task a window
/// (`qos-rt-slack-canary` removes the test; ktest
/// `qos_timer_slack_never_real_time`).
pub const fn timer_slack_us(
    class: Class,
    qos: u32,
    row_opt_in: bool,
    mode: SlackMode,
    tiers_us: &[u32; QOS_LEVELS],
) -> u32 {
    let allowed = match class {
        Class::Fair => true,
        // The canary build gives the real-time classes the fair rule.
        Class::Stop | Class::Dl | Class::Rt => cfg!(feature = "qos-rt-slack-canary"),
        Class::Idle => false,
    };
    if !allowed {
        return 0;
    }
    match mode {
        SlackMode::Off => 0,
        SlackMode::Rows if !row_opt_in => 0,
        SlackMode::Rows | SlackMode::All => {
            tiers_us[if qos > QOS_MAX { QOS_MAX } else { qos } as usize]
        }
    }
}

/// `on_cpu` of an SC that runs nowhere.
pub const NO_CPU: u16 = u16::MAX;

/// A scheduling context. Every field is an atomic: other CPUs read it (the
/// wait-graph walk, admission, `schedctl`) while its owner writes it.
///
/// Times are microseconds (the units of a topology row and of
/// `Reservation`), one machine word each: a target without 64-bit atomics
/// (the micro kernel's rv32) has no wider cell, and a period, a budget or a
/// relative deadline of more than 71 minutes (`u32::MAX` us) is not a
/// reservation the 32-bit kernel admits ([`SchedContext::set_times`]
/// saturates). A field marked *reserved* has no writer in N6; the step
/// named gives it one, without moving it.
#[repr(C)]
pub struct SchedContext {
    /// Budget per period (DL runtime, RT band share; 0 = none).
    pub budget_us: AtomicUsize,
    /// Replenishment period (0 = none).
    pub period_us: AtomicUsize,
    /// Relative deadline (0 = the period).
    pub deadline_us: AtomicUsize,
    /// Mixed-criticality LO-mode budget (reserved: admission with criticality).
    pub c_lo_us: AtomicUsize,
    /// Mixed-criticality HI-mode budget (reserved: admission with criticality).
    pub c_hi_us: AtomicUsize,
    /// The wait-graph object this SC's task is blocked on: the address of
    /// its `azos_sync::waitgraph::PiWaiters`, 0 = none (an
    /// `Option<WaitObj>`; `WaitObj` is a non-null pointer). Written only by
    /// the graph, through `classes::ClassPi` (N7). A plain address so this
    /// file stays free of kernel crates (the host suite compiles it as is).
    pub blocked_on: AtomicUsize,
    /// RT/DL: the priority level; fair: the weight (part b, EEVDF).
    pub prio_or_weight: AtomicU32,
    /// The task's QoS hint ([`QOS_DEFAULT`] .. [`QOS_BACKGROUND`]): what the
    /// task says about itself, set with `SYS_SCHEDCTL`'s [`QOS_HINT`] form.
    /// Read by the timer heap: the tier's slack window
    /// ([`timer_slack_us`]). Fair weights per level are the APS groups
    /// (L10), which will read this same field.
    pub qos_id: AtomicU32,
    /// The CPU the SC runs on, [`NO_CPU`] = none. With `WAIT_GRAPH`
    /// written by the scheduler at every switch (`classes::on_switch`, N7b);
    /// without, unused (`classes::on_cpu` scans the per-CPU current task).
    pub on_cpu: AtomicU16,
    /// How many interrupt lines this SC serves (`irq_bind`'s bindings whose
    /// owner runs on it), 0 = none. Written by [`SchedContext::irq_attach`] /
    /// [`SchedContext::irq_detach`]; read by the reservation's overrun and
    /// replenishment paths (`rt.rs`), which tell `irq_bind` only when it is
    /// non-zero (L5).
    pub irq: AtomicU16,
    /// [`Class`] discriminant.
    pub class: AtomicU8,
    /// [`Criticality`] discriminant.
    pub criticality: AtomicU8,
    /// The CPU cluster the SC is admitted to (0 = the general cluster; part
    /// b defaults `RCU_NOCBS_CPUS` from the RT cluster).
    pub cluster: AtomicU8,
    /// Flag bits: [`SC_FLAG_TIMER_SLACK`]; the rest reserved.
    pub flags: AtomicU8,
}

/// The frozen size, per word width: every word-sized field (the five times,
/// `blocked_on`) is half as wide on a 32-bit target, and nothing else moves.
/// Changing the layout is a deliberate edit of these lines. N7 widened
/// `blocked_on` to a pointer by spending the 4 reserved bytes: the 64-bit
/// size did not move.
#[cfg(target_pointer_width = "64")]
pub const SC_SIZE: usize = 64;
/// See above: 6 words of 4 bytes, then the 16 bytes of 32-bit fields.
#[cfg(target_pointer_width = "32")]
pub const SC_SIZE: usize = 40;
const _: () = assert!(core::mem::size_of::<SchedContext>() == SC_SIZE);
// The word-sized fields come first, so every field behind them sits at the
// same offset in words and the 32-bit fields keep one order on both widths.
const _: () = assert!(core::mem::offset_of!(SchedContext, blocked_on) == 5 * core::mem::size_of::<usize>());
const _: () = assert!(core::mem::offset_of!(SchedContext, prio_or_weight) == 6 * core::mem::size_of::<usize>());
const _: () = assert!(core::mem::offset_of!(SchedContext, flags) == SC_SIZE - 1);

/// A time in microseconds as the SC's word: the value, or the word's maximum.
#[inline]
const fn word_us(us: u64) -> usize {
    if us > usize::MAX as u64 { usize::MAX } else { us as usize }
}

impl SchedContext {
    /// An SC in `class` with no time parameters.
    pub const fn new(class: Class) -> Self {
        Self {
            budget_us: AtomicUsize::new(0),
            period_us: AtomicUsize::new(0),
            deadline_us: AtomicUsize::new(0),
            c_lo_us: AtomicUsize::new(0),
            c_hi_us: AtomicUsize::new(0),
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

    /// The QoS hint.
    #[inline]
    pub fn qos(&self) -> u32 {
        self.qos_id.load(Ordering::Relaxed)
    }

    /// Record a QoS hint. `false` (nothing stored) above [`QOS_MAX`].
    #[inline]
    pub fn set_qos(&self, qos: u32) -> bool {
        if qos > QOS_MAX {
            return false;
        }
        self.qos_id.store(qos, Ordering::Relaxed);
        true
    }

    /// Does the task's topology row say `timer_slack = true`?
    #[inline]
    pub fn timer_slack_row(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & SC_FLAG_TIMER_SLACK != 0
    }

    /// Record the row's `timer_slack` (where the row is applied).
    #[inline]
    pub fn set_timer_slack_row(&self, on: bool) {
        if on {
            self.flags.fetch_or(SC_FLAG_TIMER_SLACK, Ordering::Relaxed);
        } else {
            self.flags.fetch_and(!SC_FLAG_TIMER_SLACK, Ordering::Relaxed);
        }
    }

    /// Record admitted time parameters (DL). Zeroes them for any other class.
    /// A value above the word (`u32::MAX` us on a 32-bit target) is stored
    /// as the word's maximum.
    pub fn set_times(&self, budget_us: u64, period_us: u64, deadline_us: u64) {
        self.budget_us.store(word_us(budget_us), Ordering::Relaxed);
        self.period_us.store(word_us(period_us), Ordering::Relaxed);
        self.deadline_us.store(word_us(deadline_us), Ordering::Relaxed);
    }

    /// The interrupt lines this SC serves.
    #[inline]
    pub fn irq_lines(&self) -> u16 {
        self.irq.load(Ordering::Relaxed)
    }

    /// This SC serves one more interrupt line. `false` (nothing counted) at
    /// the field's width.
    pub fn irq_attach(&self) -> bool {
        self.irq
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |n| n.checked_add(1))
            .is_ok()
    }

    /// This SC serves one line fewer. A count already at 0 stays there.
    pub fn irq_detach(&self) {
        let _ = self.irq.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |n| n.checked_sub(1));
    }

    /// The budget per period, microseconds (0 = none).
    #[inline]
    pub fn budget_us(&self) -> u64 {
        self.budget_us.load(Ordering::Relaxed) as u64
    }

    /// The replenishment period, microseconds (0 = none).
    #[inline]
    pub fn period_us(&self) -> u64 {
        self.period_us.load(Ordering::Relaxed) as u64
    }

    /// The relative deadline, microseconds (0 = the period).
    #[inline]
    pub fn deadline_us(&self) -> u64 {
        self.deadline_us.load(Ordering::Relaxed) as u64
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
