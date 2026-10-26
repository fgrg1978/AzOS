// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! The cooperative loop, its stackful tasks and the [`Env`] that owns every
//! subsystem.
//!
//! # Threading model
//!
//! One AzOS thread per server runs this loop on one hart. Timer callbacks,
//! RCU callbacks and interrupt handlers are run-to-completion items of the
//! loop, in atomic context. Everything Linux runs in a task (a kernel
//! thread, the workqueue worker, a probe called from a task) is a
//! **stackful task**: it has its own stack and runs until it reaches a
//! block point (`msleep`, `wait_event`, `schedule`, a contended
//! `mutex_lock`, `wait_for_completion`, ...). There it switches back to the
//! loop, which resumes it once it is woken or its timeout passes. Nothing
//! preempts a task between two block points, so spinlocks reduce to
//! a held flag, a preemption count and the interrupt-state flag (sleeping
//! while one is held is refused, see [`crate::percpu`]), and a condition
//! checked just before a block point cannot change before the task is
//! parked: there is no lost wake-up.
//!
//! Between passes the server blocks in the AzOS port wait until the
//! deadline [`Env::run_once`] returns (`SYS_PORT_WAIT` with a deadline; no
//! kernel mechanism beyond that), or until a message arrives. An interrupt
//! arrives as a port notification and the server hands it to
//! [`Env::deliver_irq`] (see [`crate::irq`]); whatever the handler wakes runs
//! in the next pass.
//!
//! # Stacks
//!
//! The crate has no heap, so the server gives it the stacks
//! ([`Env::add_stack`], typically from a mapped region with a guard page
//! below each stack). Each task slot owns one stack for good; a slot
//! without a stack takes no task. The lowest word of every stack holds a
//! canary checked at each switch back to the loop
//! ([`LoopStats::stack_overflows`]). The switch itself is per ISA
//! (`switch/<isa>.rs`): it saves only the callee-saved registers.
//!
//! # Aliasing
//!
//! A suspended task's frames hold a dormant `&mut Env` while the loop and
//! other tasks use theirs. That is sound for the same reason it is in any
//! coroutine runtime: the reference is not used again until the loop
//! switches back to that task, and the switch is an opaque call that is
//! handed the environment's address, so no value read through the
//! reference before the switch is reused after it. The rules that keep it
//! so: the environment must not move once it has a stack (checked at every
//! pass), and [`Env::run_once`] refuses to run on a task's stack.
//!
//! # One pass
//!
//! [`Env::run_once`] runs, in order: the interrupt handlers an `enable_irq`
//! left to replay (hard-interrupt context), expired timers (softirq context), the
//! tasks that were runnable when the timers finished (in the order they
//! became runnable: woken, timed out or yielded), then the RCU quiescent
//! point. A task woken or re-queued during the pass runs in the next one,
//! so an item that re-arms itself for "now" cannot livelock the loop; the
//! pass returns "run again immediately" instead. Timers run first so a
//! delayed work item whose timer fires in this pass also runs in this pass,
//! as on Linux.
//!
//! # The workqueue
//!
//! Work items run in one worker task (`kworker`, [`WORKER_TASK`]), started
//! by the first pass that finds work queued, in FIFO order. An item may
//! sleep; the items behind it wait, as on an ordered workqueue. Linux's
//! system workqueue would start another worker instead, so an item that
//! waits for a later item of the same queue deadlocks here (open: a worker
//! pool).

use crate::device::{self, DevError, DeviceHandle, DeviceInfo, DeviceModel, Driver, DriverHandle};
use crate::irq::IrqLines;
use crate::percpu::CurrentOps;
use crate::lock::{Completion, IrqState, LockError, Mutex, Semaphore, TaskId, WaitQueueHead};
use crate::printk::Printk;
use crate::rcu::{self, Rcu, RcuError, RcuFn};
use crate::switch;
use crate::symbols::Dummies;
use crate::timer::{self, Clock, Jiffies, TimerError, TimerHandle, TimerList};
use crate::workqueue::{WorkError, WorkFn, WorkHandle, WorkQueue};
use core::fmt;

/// `current` while timer callbacks and RCU callbacks run (Linux's
/// softirq context has no task of its own; 0 is the idle task's pid).
pub const SOFTIRQ_TASK: TaskId = 0;
/// `current` while work items run: the emulated kworker.
pub const WORKER_TASK: TaskId = 1;
/// First id handed to a kernel thread.
pub const FIRST_KTHREAD: TaskId = 2;
/// Smallest stack [`Env::add_stack`] accepts.
pub const MIN_STACK: usize = 4096;
/// `MAX_SCHEDULE_TIMEOUT`: a `schedule_timeout` with no timeout.
pub const MAX_SCHEDULE_TIMEOUT: Jiffies = i64::MAX as u64;

/// A kernel thread's function (`int (*threadfn)(void *data)`): runs on the
/// thread's own stack and returns its exit code.
pub type TaskFn<C> = fn(&mut C, usize) -> i32;

/// Task state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    /// Will run in a coming pass.
    Runnable,
    /// Running now.
    Running,
    /// Blocked until woken.
    Waiting,
    /// Blocked until woken or until this monotonic time (ns).
    Sleeping(u64),
    /// Returned this exit code; kept until `kthread_stop` reaps it.
    Exited(i32),
}

/// What `set_current_state` declares. `TASK_INTERRUPTIBLE` and
/// `TASK_UNINTERRUPTIBLE` are both `Sleeping`: lxsrv tasks take no signals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurrentState {
    /// `TASK_RUNNING`: `schedule` only yields.
    Running,
    /// About to sleep: `schedule` parks the task until `wake_up_process`.
    Sleeping,
}

/// [`Env::add_stack`] refusals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackError {
    /// Smaller than [`MIN_STACK`] once aligned.
    TooSmall,
    /// Every task slot already has a stack.
    Full,
}

struct TaskSlot<C> {
    /// Some while the thread exists (until it exits, or is reaped).
    func: Option<TaskFn<C>>,
    data: usize,
    id: TaskId,
    state: TaskState,
    /// The slot's stack, `[stack, stack + stack_len)`; 0 = none given.
    stack: usize,
    stack_len: usize,
    /// Saved stack pointer while not running.
    sp: usize,
    /// Address the task is blocked on; 0 = only `wake_up_process` or the
    /// deadline.
    chan: usize,
    /// Order key: when it started waiting while blocked, when it became
    /// runnable while runnable.
    seq: u64,
    /// `set_current_state(Sleeping)` is in force.
    sleeping: bool,
    /// A semaphore unit was handed to it at `up`.
    granted: bool,
    should_stop: bool,
    /// The stack canary was found broken (counted once).
    overflowed: bool,
    /// The task's current word (its `task_struct`; see [`crate::percpu`]).
    current: usize,
}

impl<C> Clone for TaskSlot<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C> Copy for TaskSlot<C> {}

impl<C> TaskSlot<C> {
    fn blocked_on(&self, chan: usize) -> bool {
        self.func.is_some() && self.chan == chan && matches!(self.state, TaskState::Waiting | TaskState::Sleeping(_))
    }
}

/// Fixed-capacity table of tasks.
pub struct RunQueue<C, const N: usize> {
    slots: [TaskSlot<C>; N],
    next_id: TaskId,
    next_seq: u64,
    full_errors: u32,
}

impl<C, const N: usize> Default for RunQueue<C, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C, const N: usize> fmt::Debug for RunQueue<C, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunQueue").field("capacity", &N).field("threads", &self.count()).finish()
    }
}

impl<C, const N: usize> RunQueue<C, N> {
    const EMPTY: TaskSlot<C> = TaskSlot {
        func: None,
        data: 0,
        id: 0,
        state: TaskState::Waiting,
        stack: 0,
        stack_len: 0,
        sp: 0,
        chan: 0,
        seq: 0,
        sleeping: false,
        granted: false,
        should_stop: false,
        overflowed: false,
        current: 0,
    };

    /// No tasks, no stacks.
    pub const fn new() -> Self {
        RunQueue { slots: [Self::EMPTY; N], next_id: FIRST_KTHREAD, next_seq: 0, full_errors: 0 }
    }

    fn find(&self, id: TaskId) -> Option<usize> {
        self.slots.iter().position(|s| s.func.is_some() && s.id == id)
    }

    fn take_seq(&mut self) -> u64 {
        let s = self.next_seq;
        self.next_seq += 1;
        s
    }

    fn give_stack(&mut self, base: usize, len: usize) -> bool {
        match self.slots.iter_mut().find(|s| s.stack == 0) {
            Some(s) => {
                s.stack = base;
                s.stack_len = len;
                true
            }
            None => false,
        }
    }

    /// Claim a free slot that has a stack for a new runnable task. `id` is
    /// the fixed id of a system task (the worker), or `None` for the next
    /// kernel-thread id; ids are never reused.
    fn claim(&mut self, func: TaskFn<C>, data: usize, id: Option<TaskId>) -> Option<usize> {
        let Some(i) = self.slots.iter().position(|s| s.func.is_none() && s.stack != 0) else {
            self.full_errors += 1;
            return None;
        };
        let id = id.unwrap_or_else(|| {
            let id = self.next_id;
            self.next_id += 1;
            id
        });
        let seq = self.take_seq();
        let s = &mut self.slots[i];
        s.func = Some(func);
        s.data = data;
        s.id = id;
        s.state = TaskState::Runnable;
        s.chan = 0;
        s.seq = seq;
        s.sleeping = false;
        s.granted = false;
        s.should_stop = false;
        s.overflowed = false;
        Some(i)
    }

    fn make_runnable(&mut self, i: usize) {
        let seq = self.take_seq();
        let s = &mut self.slots[i];
        s.state = TaskState::Runnable;
        s.chan = 0;
        s.seq = seq;
    }

    /// The task blocked longest on `chan`.
    fn first_waiter(&self, chan: usize) -> Option<usize> {
        (0..N).filter(|&i| self.slots[i].blocked_on(chan)).min_by_key(|&i| self.slots[i].seq)
    }

    /// Wake up to `n` tasks blocked on `chan`, longest-waiting first.
    pub(crate) fn wake_chan(&mut self, chan: usize, n: usize) -> usize {
        let mut woken = 0;
        while woken < n {
            let Some(i) = self.first_waiter(chan) else { break };
            self.make_runnable(i);
            woken += 1;
        }
        woken
    }

    /// `wake_up_process`: true if the task was blocked, or was running
    /// with a pending `set_current_state(Sleeping)` that this cancels.
    pub fn wake(&mut self, id: TaskId) -> bool {
        let Some(i) = self.find(id) else { return false };
        match self.slots[i].state {
            TaskState::Waiting | TaskState::Sleeping(_) => {
                self.make_runnable(i);
                true
            }
            TaskState::Running => core::mem::replace(&mut self.slots[i].sleeping, false),
            TaskState::Runnable | TaskState::Exited(_) => false,
        }
    }

    /// Ask a task to stop without waiting for it (`kthread_should_stop`
    /// turns true), and make it runnable so it sees the request.
    pub(crate) fn request_stop(&mut self, id: TaskId) {
        if let Some(i) = self.find(id) {
            self.slots[i].should_stop = true;
            if matches!(self.slots[i].state, TaskState::Waiting | TaskState::Sleeping(_)) {
                self.make_runnable(i);
            }
        }
    }

    /// A live task's current word.
    pub(crate) fn current_word(&self, id: TaskId) -> Option<usize> {
        self.find(id).map(|i| self.slots[i].current)
    }

    pub(crate) fn set_current_word(&mut self, id: TaskId, w: usize) {
        if let Some(i) = self.find(id) {
            self.slots[i].current = w;
        }
    }

    /// Give every live task without a current word one.
    pub(crate) fn give_words(&mut self, mut f: impl FnMut(TaskId) -> usize) {
        for s in self.slots.iter_mut().filter(|s| s.func.is_some() && s.current == 0) {
            s.current = f(s.id);
        }
    }

    /// Free slot `i` (its task exited, or was reaped); returns the current
    /// word it held.
    fn free(&mut self, i: usize) -> usize {
        self.slots[i].func = None;
        core::mem::replace(&mut self.slots[i].current, 0)
    }

    /// State of a task.
    pub fn state(&self, id: TaskId) -> Option<TaskState> {
        self.find(id).map(|i| self.slots[i].state)
    }

    /// The task's `data` word.
    pub fn data(&self, id: TaskId) -> Option<usize> {
        self.find(id).map(|i| self.slots[i].data)
    }

    /// Live tasks (the worker included, exited-but-unreaped ones too).
    pub fn count(&self) -> usize {
        self.slots.iter().filter(|s| s.func.is_some()).count()
    }

    /// Slots that have a stack.
    pub fn stacks(&self) -> usize {
        self.slots.iter().filter(|s| s.stack != 0).count()
    }

    /// Spawns refused for lack of a free slot with a stack.
    pub fn full_errors(&self) -> u32 {
        self.full_errors
    }

    fn has_free_stack(&self) -> bool {
        self.slots.iter().any(|s| s.func.is_none() && s.stack != 0)
    }

    fn any_runnable(&self) -> bool {
        self.slots.iter().any(|s| s.func.is_some() && s.state == TaskState::Runnable)
    }

    fn next_wake(&self) -> Option<u64> {
        self.slots
            .iter()
            .filter_map(|s| match (s.func, s.state) {
                (Some(_), TaskState::Sleeping(at)) => Some(at),
                _ => None,
            })
            .min()
    }

    /// Sleepers whose deadline is at or before `now_ns` become runnable,
    /// earliest deadline first (then longest waiting).
    fn expire(&mut self, now_ns: u64) {
        loop {
            let due = (0..N)
                .filter_map(|i| match (self.slots[i].func, self.slots[i].state) {
                    (Some(_), TaskState::Sleeping(at)) if at <= now_ns => Some((at, self.slots[i].seq, i)),
                    _ => None,
                })
                .min();
            let Some((_, _, i)) = due else { return };
            self.make_runnable(i);
        }
    }

    /// The runnable task that became runnable first, if before `mark`.
    fn next_runnable(&self, mark: u64) -> Option<usize> {
        (0..N)
            .filter(|&i| {
                let s = &self.slots[i];
                s.func.is_some() && s.state == TaskState::Runnable && s.seq < mark
            })
            .min_by_key(|&i| self.slots[i].seq)
    }
}

/// Timer slots in an [`Env`].
pub const TIMER_SLOTS: usize = 64;
/// Work slots in an [`Env`].
pub const WORK_SLOTS: usize = 64;
/// Pending RCU callbacks in an [`Env`].
pub const RCU_SLOTS: usize = 128;
/// printk records kept by an [`Env`].
pub const LOG_RECORDS: usize = 64;
/// Tasks (and stacks) in an [`Env`], the worker included.
pub const TASK_SLOTS: usize = 16;
/// Devices on the [`Env`] bus.
pub const DEVICE_SLOTS: usize = 32;
/// Drivers on the [`Env`] bus.
pub const DRIVER_SLOTS: usize = 16;
/// Distinct unimplemented symbols remembered.
pub const DUMMY_SLOTS: usize = 64;
/// Interrupt lines an [`Env`] binds over its life.
pub const IRQ_SLOTS: usize = 16;

/// Execution context of the code running now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    /// The loop between items, or a direct call from the server.
    Idle,
    /// A timer callback: atomic, must not sleep.
    Softirq,
    /// An interrupt handler ([`Env::deliver_irq`]): atomic.
    Hardirq,
    /// The workqueue worker.
    Work,
    /// A kernel thread.
    Task(TaskId),
    /// RCU callbacks: softirq context on Linux, atomic.
    RcuCallback,
}

/// Loop counters. A gate can assert the error counters are 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoopStats {
    /// `run_once` calls.
    pub passes: u64,
    /// Timer callbacks run.
    pub timers_fired: u64,
    /// Switches from the loop into a task.
    pub task_runs: u64,
    /// Work items run.
    pub works_run: u64,
    /// RCU callbacks run.
    pub rcu_callbacks: u64,
    /// Interrupt handlers run.
    pub irqs: u64,
    /// Quiescent points refused because an item leaked a read section.
    pub rcu_leaks: u32,
    /// Items that returned with interrupts still disabled (fixed up).
    pub irq_leaks: u32,
    /// Items that returned with preemption still disabled (fixed up), and
    /// unbalanced `preempt_enable` calls.
    pub preempt_leaks: u32,
    /// Sleeping primitives called from atomic context.
    pub atomic_sleeps: u32,
    /// Sleeping primitives that had to wait but were called outside a task
    /// (the server's own code has no stack to park).
    pub would_block: u32,
    /// Tasks found to have written below the end of their stack.
    pub stack_overflows: u32,
}

/// Errors from the [`Env`] glue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvError {
    /// From the timer list.
    Timer(TimerError),
    /// From the work queue.
    Work(WorkError),
    /// The work item has no delay timer (not created by
    /// [`Env::init_delayed_work`]).
    NotDelayed,
}

impl From<TimerError> for EnvError {
    fn from(e: TimerError) -> Self {
        EnvError::Timer(e)
    }
}

impl From<WorkError> for EnvError {
    fn from(e: WorkError) -> Self {
        EnvError::Work(e)
    }
}

/// The lx_emul base: every subsystem plus the loop, owned by the caller.
/// No global state, so several environments (one per test) coexist.
pub struct Env {
    /// Jiffies clock.
    pub clock: Clock,
    /// Emulated local interrupt flag.
    pub irq: IrqState,
    /// Interrupt lines.
    pub irqs: IrqLines<IRQ_SLOTS>,
    /// `preempt_count()` (see [`crate::percpu`]).
    pub(crate) preempt: u32,
    pub(crate) current_ops: Option<CurrentOps>,
    /// The loop's current word.
    pub(crate) loop_word: usize,
    /// Timer list.
    pub timers: TimerList<Env, TIMER_SLOTS>,
    /// Work FIFO.
    pub work: WorkQueue<Env, WORK_SLOTS>,
    /// RCU state.
    pub rcu: Rcu<Env, RCU_SLOTS>,
    /// Kernel log.
    pub log: Printk<LOG_RECORDS>,
    /// Tasks.
    pub tasks: RunQueue<Env, TASK_SLOTS>,
    /// The bus.
    pub devices: DeviceModel<Env, DEVICE_SLOTS, DRIVER_SLOTS>,
    /// Unimplemented-symbol registry.
    pub dummies: Dummies<DUMMY_SLOTS>,
    context: Context,
    stats: LoopStats,
    /// Slot of the running task.
    current: Option<usize>,
    /// The loop's stack pointer while a task runs.
    loop_sp: usize,
    /// Address of this Env when it got its first stack (0 before).
    home: usize,
    /// Work enqueue mark below which every item has run (`flush_workqueue`
    /// waiters block on this field's address).
    flush_done: u64,
    /// The worker is inside a work item.
    worker_busy: bool,
    /// Opaque word for the embedding server (its own state index, a test
    /// fixture); the layer never reads it.
    pub user: usize,
}

impl Default for Env {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Env {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Env").field("context", &self.context).field("stats", &self.stats).finish()
    }
}

fn rcus(e: &mut Env) -> &mut Rcu<Env, RCU_SLOTS> {
    &mut e.rcu
}
/// Shape of `rcu::synchronize_rcu` / `rcu::rcu_barrier` instantiated on Env.
type RcuDriver = fn(&mut Env, fn(&mut Env) -> &mut Rcu<Env, RCU_SLOTS>) -> Result<usize, RcuError>;

fn devs(e: &mut Env) -> &mut DeviceModel<Env, DEVICE_SLOTS, DRIVER_SLOTS> {
    &mut e.devices
}

fn timers(e: &mut Env) -> &mut TimerList<Env, TIMER_SLOTS> {
    &mut e.timers
}

/// Timer callback behind every delayed work item: the timer's data word
/// holds the work handle. The pass kicks the worker after the timers.
fn delayed_work_timer(env: &mut Env, t: TimerHandle) {
    if let Some(raw) = env.timers.data(t) {
        // A cancelled item is no longer Delayed; delay_elapsed ignores it.
        let _ = env.work.delay_elapsed(WorkHandle::from_raw(raw as u32));
    }
}

/// Channel of an object a task blocks on: its address.
pub(crate) fn chan<T>(x: &T) -> usize {
    x as *const T as usize
}

/// The workqueue worker: runs the items queued before each batch, FIFO;
/// yields when more arrived meanwhile, parks when the queue is empty.
fn kworker(e: &mut Env, _: usize) -> i32 {
    loop {
        let mark = e.work.seq_mark();
        while let Some((h, f)) = e.work.pop(mark) {
            e.worker_busy = true;
            f(e, h);
            e.worker_busy = false;
            e.stats.works_run += 1;
        }
        e.flush_done = mark;
        let flush = chan(&e.flush_done);
        e.tasks.wake_chan(flush, usize::MAX);
        if e.work.queued() > 0 {
            e.yield_task();
        } else {
            let seq = e.tasks.take_seq();
            let work = chan(&e.work);
            e.block(work, None, seq);
        }
    }
}

/// First code of every task, on its own stack (see `switch::prepare`).
extern "C" fn task_main(ctx: *mut u8, slot: usize) -> ! {
    // SAFETY: `ctx` is the Env that prepared this stack (Env::spawn), which
    // has not moved (Env::run_once checks) and is only used by the running
    // task while the task runs (module docs, "Aliasing").
    let env = unsafe { &mut *(ctx as *mut Env) };
    let s = &env.tasks.slots[slot];
    let (f, data) = (s.func.expect("a task slot without a function was resumed"), s.data);
    let code = f(env, data);
    env.exit_task(code)
}

impl Env {
    /// A fresh environment at time 0, without stacks. `const` so the server
    /// can place it in a `static` cell instead of on its stack (it is tens
    /// of KiB).
    pub const fn new() -> Self {
        Env {
            clock: Clock::new(),
            irq: IrqState::new(),
            irqs: IrqLines::new(),
            preempt: 0,
            current_ops: None,
            loop_word: 0,
            timers: TimerList::new(),
            work: WorkQueue::new(),
            rcu: Rcu::new(),
            log: Printk::new(),
            tasks: RunQueue::new(),
            devices: DeviceModel::new(),
            dummies: Dummies::new(),
            context: Context::Idle,
            stats: LoopStats {
                passes: 0,
                timers_fired: 0,
                task_runs: 0,
                works_run: 0,
                rcu_callbacks: 0,
                irqs: 0,
                rcu_leaks: 0,
                irq_leaks: 0,
                preempt_leaks: 0,
                atomic_sleeps: 0,
                would_block: 0,
                stack_overflows: 0,
            },
            current: None,
            loop_sp: 0,
            home: 0,
            flush_done: 0,
            worker_busy: false,
            user: 0,
        }
    }

    /// Give the environment one task stack, `[base, base + len)`. Each call
    /// equips one more task slot (at most [`TASK_SLOTS`]); the worker takes
    /// one of them.
    ///
    /// # Safety
    ///
    /// The memory must be writable and used by nothing else for as long as
    /// the environment lives, and the environment must not move after this
    /// call: suspended tasks hold its address ([`Env::run_once`] panics if
    /// it moved).
    pub unsafe fn add_stack(&mut self, base: *mut u8, len: usize) -> Result<(), StackError> {
        let start = (base as usize).next_multiple_of(switch::ALIGN);
        let end = (base as usize + len) & !(switch::ALIGN - 1);
        if end < start || end - start < MIN_STACK {
            return Err(StackError::TooSmall);
        }
        if !self.tasks.give_stack(start, end - start) {
            return Err(StackError::Full);
        }
        self.home = self as *const Env as usize;
        Ok(())
    }

    /// Loop counters.
    pub fn stats(&self) -> LoopStats {
        self.stats
    }

    /// Context of the running code.
    pub fn context(&self) -> Context {
        self.context
    }

    /// `current`'s pid: the kernel thread, the kworker, or 0 outside a task.
    pub fn current(&self) -> TaskId {
        match self.context {
            Context::Task(id) => id,
            Context::Work => WORKER_TASK,
            Context::Idle | Context::Softirq | Context::Hardirq | Context::RcuCallback => SOFTIRQ_TASK,
        }
    }

    /// `in_softirq()`.
    pub fn in_softirq(&self) -> bool {
        matches!(self.context, Context::Softirq | Context::RcuCallback)
    }

    /// `in_hardirq()`.
    pub fn in_hardirq(&self) -> bool {
        self.context == Context::Hardirq
    }

    /// `in_atomic()`: softirq, hardirq, interrupts off, preemption off (a
    /// spinlock held), or inside an RCU read section. Sleeping here is a bug
    /// on Linux.
    pub fn in_atomic(&self) -> bool {
        self.in_softirq() || self.in_hardirq() || self.irq.disabled() || self.rcu.depth() > 0 || self.preempt > 0
    }

    /// `jiffies`.
    pub fn jiffies(&self) -> Jiffies {
        self.clock.jiffies()
    }

    fn check_sleep(&mut self) -> Result<(), LockError> {
        if self.in_atomic() {
            self.stats.atomic_sleeps += 1;
            return Err(LockError::Atomic);
        }
        Ok(())
    }

    /// The running task's slot, or `WouldBlock` (counted) outside a task.
    fn need_task(&mut self) -> Result<usize, LockError> {
        match self.current {
            Some(i) => Ok(i),
            None => {
                self.stats.would_block += 1;
                Err(LockError::WouldBlock)
            }
        }
    }

    /// Monotonic time now: the source's, if the clock has one.
    fn now_ns(&mut self) -> u64 {
        self.clock.refresh();
        self.clock.now_ns()
    }

    /// Jiffies left until `deadline` (0 once it is reached).
    fn left(&mut self, deadline: Jiffies) -> Jiffies {
        self.clock.refresh();
        let d = deadline.wrapping_sub(self.clock.jiffies()) as i64;
        d.max(0) as u64
    }

    /// Back to the loop; returns when the loop resumes this task.
    fn switch_to_loop(&mut self) {
        let i = self.current.expect("switch_to_loop outside a task");
        let save = &mut self.tasks.slots[i].sp as *mut usize;
        let load = self.loop_sp;
        // SAFETY: `load` is the loop's stack, saved by the `switch` in
        // `resume` that started this task's run; `save` is this slot.
        unsafe { switch::switch(save, load, self as *mut Env as *mut u8) }
    }

    /// Park the running task on `chan` (0: no object) until a wake-up or
    /// `deadline` (ns). `seq` is when it started waiting, kept across the
    /// re-blocks of one wait so its place in the queue does not move.
    fn block(&mut self, chan: usize, deadline: Option<u64>, seq: u64) {
        let i = self.current.expect("block outside a task");
        let s = &mut self.tasks.slots[i];
        s.chan = chan;
        s.seq = seq;
        s.state = match deadline {
            Some(d) => TaskState::Sleeping(d),
            None => TaskState::Waiting,
        };
        // Back from schedule() a task is TASK_RUNNING again.
        s.sleeping = false;
        self.switch_to_loop();
    }

    /// Park the running task on `chan` until a wake-up.
    pub(crate) fn park(&mut self, chan: usize) {
        let seq = self.tasks.take_seq();
        self.block(chan, None, seq);
    }

    /// Block the running task on `chan` while `busy` holds; `WouldBlock`
    /// (counted) outside a task.
    pub(crate) fn wait_on(&mut self, chan: usize, busy: impl Fn(&Env) -> bool) -> Result<(), LockError> {
        self.need_task()?;
        let seq = self.tasks.take_seq();
        while busy(self) {
            self.block(chan, None, seq);
        }
        Ok(())
    }

    /// The id of the running task, `None` outside a task.
    pub(crate) fn running_task(&self) -> Option<TaskId> {
        self.current.map(|i| self.tasks.slots[i].id)
    }

    /// Stay runnable behind every task already runnable.
    fn yield_task(&mut self) {
        let i = self.current.expect("yield outside a task");
        self.tasks.make_runnable(i);
        self.switch_to_loop();
    }

    /// The running task returned `code`.
    fn exit_task(&mut self, code: i32) -> ! {
        let i = self.current.expect("exit outside a task");
        let me = chan(&self.tasks.slots[i]);
        if self.tasks.first_waiter(me).is_some() {
            // A kthread_stop is waiting for the code: keep the slot for it.
            self.tasks.slots[i].state = TaskState::Exited(code);
            self.tasks.wake_chan(me, usize::MAX);
        } else {
            let w = self.tasks.free(i);
            self.current_released(w);
        }
        self.switch_to_loop();
        unreachable!("an exited task was resumed");
    }

    fn spawn(&mut self, func: TaskFn<Env>, data: usize, id: Option<TaskId>) -> Option<TaskId> {
        let i = self.tasks.claim(func, data, id)?;
        let s = &self.tasks.slots[i];
        let (base, len) = (s.stack, s.stack_len);
        let ctx = self as *mut Env as *mut u8;
        // SAFETY: the slot's stack was handed over in add_stack and its
        // previous task (if any) has exited, so nothing runs on it.
        let sp = unsafe { switch::prepare(base, len, task_main, ctx, i) };
        self.tasks.slots[i].sp = sp;
        let id = self.tasks.slots[i].id;
        self.current_created(id);
        Some(id)
    }

    /// Run task slot `i` until it blocks, yields or exits.
    fn resume(&mut self, i: usize) {
        let s = &mut self.tasks.slots[i];
        s.state = TaskState::Running;
        let (sp, id, base, word) = (s.sp, s.id, s.stack, s.current);
        self.current_install(word);
        self.current = Some(i);
        self.context = if id == WORKER_TASK { Context::Work } else { Context::Task(id) };
        let save = core::ptr::addr_of_mut!(self.loop_sp);
        // SAFETY: `sp` was saved by this task's last switch (or built by
        // prepare); the loop's own registers go to `loop_sp`.
        unsafe { switch::switch(save, sp, self as *mut Env as *mut u8) };
        self.current_install(self.loop_word);
        self.current = None;
        self.context = Context::Idle;
        self.stats.task_runs += 1;
        // SAFETY: `base` is this slot's prepared stack.
        if !unsafe { switch::canary_intact(base) } && !self.tasks.slots[i].overflowed {
            self.tasks.slots[i].overflowed = true;
            self.stats.stack_overflows += 1;
            self.log.pr_err(b"task stack overflow\n");
        }
        self.after_items();
    }

    /// `might_sleep()`: error in atomic context.
    pub fn might_sleep(&mut self) -> Result<(), LockError> {
        self.check_sleep()
    }

    /// `kthread_run`: a runnable kernel thread on a free stack, or `None`
    /// when every slot with a stack is taken.
    pub fn kthread_run(&mut self, func: TaskFn<Env>, data: usize) -> Option<TaskId> {
        self.spawn(func, data, None)
    }

    /// `kthread_should_stop()` for the running task.
    pub fn kthread_should_stop(&self) -> bool {
        self.current.is_some_and(|i| self.tasks.slots[i].should_stop)
    }

    /// `kthread_stop`: ask the thread to stop, wake it, wait for it to
    /// return and give back its exit code. Must be called from a task.
    pub fn kthread_stop(&mut self, id: TaskId) -> Result<i32, LockError> {
        self.check_sleep()?;
        let i = self.tasks.find(id).ok_or(LockError::NoTask)?;
        if self.current == Some(i) {
            return Err(LockError::Deadlock);
        }
        self.need_task()?;
        self.tasks.slots[i].should_stop = true;
        self.tasks.wake(id);
        let seq = self.tasks.take_seq();
        let exit = chan(&self.tasks.slots[i]);
        loop {
            if let TaskState::Exited(code) = self.tasks.slots[i].state {
                let w = self.tasks.free(i);
                self.current_released(w);
                return Ok(code);
            }
            self.block(exit, None, seq);
        }
    }

    /// `wake_up_process`.
    pub fn wake_up_process(&mut self, id: TaskId) -> bool {
        self.tasks.wake(id)
    }

    /// `set_current_state` for the running task (no-op outside one).
    pub fn set_current_state(&mut self, state: CurrentState) {
        if let Some(i) = self.current {
            self.tasks.slots[i].sleeping = state == CurrentState::Sleeping;
        }
    }

    /// `schedule()`: after `set_current_state(Sleeping)`, park until
    /// `wake_up_process`; otherwise only yield. A wake-up that came after
    /// `set_current_state` already cancelled the sleep.
    pub fn schedule(&mut self) -> Result<(), LockError> {
        self.schedule_timeout(MAX_SCHEDULE_TIMEOUT).map(|_| ())
    }

    /// `schedule_timeout`: as [`Env::schedule`], for at most `timeout`
    /// jiffies ([`MAX_SCHEDULE_TIMEOUT`]: no limit). Returns the jiffies
    /// left, 0 if the timeout passed.
    pub fn schedule_timeout(&mut self, timeout: Jiffies) -> Result<Jiffies, LockError> {
        self.check_sleep()?;
        let i = self.need_task()?;
        let forever = timeout >= MAX_SCHEDULE_TIMEOUT;
        self.clock.refresh();
        let deadline = self.clock.jiffies().wrapping_add(timeout.min(timer::MAX_JIFFY_OFFSET));
        if !core::mem::replace(&mut self.tasks.slots[i].sleeping, false) {
            self.yield_task();
        } else {
            let seq = self.tasks.take_seq();
            let at = (!forever).then(|| self.clock.deadline_ns(deadline));
            self.block(0, at, seq);
        }
        Ok(if forever { MAX_SCHEDULE_TIMEOUT } else { self.left(deadline) })
    }

    /// `cond_resched()`: let every other runnable task run first.
    pub fn cond_resched(&mut self) -> Result<(), LockError> {
        self.check_sleep()?;
        self.need_task()?;
        self.yield_task();
        Ok(())
    }

    /// Sleep at least `ns` nanoseconds; wake-ups do not cut it short.
    fn sleep_ns(&mut self, ns: u64) -> Result<(), LockError> {
        self.check_sleep()?;
        self.need_task()?;
        let deadline = self.now_ns().saturating_add(ns);
        let seq = self.tasks.take_seq();
        while self.now_ns() < deadline {
            self.block(0, Some(deadline), seq);
        }
        Ok(())
    }

    /// `msleep`: at least `ms` milliseconds. Tickless, so the sleep is not
    /// rounded up to whole jiffies.
    pub fn msleep(&mut self, ms: u64) -> Result<(), LockError> {
        self.sleep_ns(ms.saturating_mul(1_000_000))
    }

    /// `usleep_range`: at least `min_us` microseconds (the slack up to
    /// `max_us` is not used to batch wake-ups).
    pub fn usleep_range(&mut self, min_us: u64, max_us: u64) -> Result<(), LockError> {
        debug_assert!(min_us <= max_us);
        self.sleep_ns(min_us.saturating_mul(1_000))
    }

    /// `wait_event(wq, cond)`: park on `wq` until `cond` holds; `cond` is
    /// checked again after every wake-up.
    pub fn wait_event(&mut self, wq: &WaitQueueHead, mut cond: impl FnMut(&mut Env) -> bool) -> Result<(), LockError> {
        self.check_sleep()?;
        if cond(self) {
            return Ok(());
        }
        self.need_task()?;
        let seq = self.tasks.take_seq();
        loop {
            self.block(chan(wq), None, seq);
            if cond(self) {
                return Ok(());
            }
        }
    }

    /// `wait_event_timeout(wq, cond, timeout)`: 0 if `cond` is still false
    /// when `timeout` jiffies have passed, otherwise the jiffies left (at
    /// least 1), as on Linux.
    pub fn wait_event_timeout(
        &mut self,
        wq: &WaitQueueHead,
        mut cond: impl FnMut(&mut Env) -> bool,
        timeout: Jiffies,
    ) -> Result<Jiffies, LockError> {
        self.check_sleep()?;
        self.clock.refresh();
        let deadline = self.clock.jiffies().wrapping_add(timeout.min(timer::MAX_JIFFY_OFFSET));
        let mut seq = None;
        loop {
            let left = self.left(deadline);
            if cond(self) {
                return Ok(left.max(1));
            }
            if left == 0 {
                return Ok(0);
            }
            if seq.is_none() {
                self.need_task()?;
                seq = Some(self.tasks.take_seq());
            }
            let at = self.clock.deadline_ns(deadline);
            self.block(chan(wq), Some(at), seq.unwrap_or_default());
        }
    }

    /// `wake_up(wq)`: wake every task waiting on `wq`, longest-waiting
    /// first. Callable from any context (timer, interrupt, task). Returns
    /// how many were woken.
    pub fn wake_up(&mut self, wq: &WaitQueueHead) -> usize {
        wq.note_wake();
        self.tasks.wake_chan(chan(wq), usize::MAX)
    }

    /// `mutex_lock` as `current`. Contended in a task: sleeps until
    /// `mutex_unlock` hands the mutex over (first come, first served).
    pub fn mutex_lock(&mut self, m: &Mutex) -> Result<(), LockError> {
        self.check_sleep()?;
        let me = self.current();
        match m.lock(me) {
            Err(LockError::WouldBlock) => {}
            r => return r,
        }
        self.need_task()?;
        let seq = self.tasks.take_seq();
        loop {
            self.block(chan(m), None, seq);
            // Handed over by unlock, or free after a stray wake-up.
            if m.owner() == Some(me) || m.try_lock(me) {
                return Ok(());
            }
        }
    }

    /// `mutex_unlock` as `current`: the longest waiter becomes the owner.
    pub fn mutex_unlock(&mut self, m: &Mutex) -> Result<(), LockError> {
        m.unlock(self.current())?;
        if let Some(i) = self.tasks.first_waiter(chan(m)) {
            m.hand_to(self.tasks.slots[i].id);
            self.tasks.make_runnable(i);
        }
        Ok(())
    }

    /// `down`: take a unit, sleeping in a task until `up` hands one over.
    pub fn down(&mut self, s: &Semaphore) -> Result<(), LockError> {
        self.check_sleep()?;
        if s.down_trylock() {
            return Ok(());
        }
        let i = self.need_task()?;
        let seq = self.tasks.take_seq();
        loop {
            self.block(chan(s), None, seq);
            if core::mem::replace(&mut self.tasks.slots[i].granted, false) || s.down_trylock() {
                return Ok(());
            }
        }
    }

    /// `up`: hand the unit to the longest waiter, or add it to the count.
    pub fn up(&mut self, s: &Semaphore) {
        match self.tasks.first_waiter(chan(s)) {
            Some(i) => {
                self.tasks.slots[i].granted = true;
                self.tasks.make_runnable(i);
            }
            None => s.up(),
        }
    }

    /// `complete`: one waiter's worth; wakes the longest waiter.
    pub fn complete(&mut self, c: &Completion) {
        c.complete();
        self.tasks.wake_chan(chan(c), 1);
    }

    /// `complete_all`: releases every present and future waiter.
    pub fn complete_all(&mut self, c: &Completion) {
        c.complete_all();
        self.tasks.wake_chan(chan(c), usize::MAX);
    }

    /// `wait_for_completion`. A completion signalled before the wait is
    /// consumed without sleeping.
    pub fn wait_for_completion(&mut self, c: &Completion) -> Result<(), LockError> {
        self.wait_for_completion_timeout(c, MAX_SCHEDULE_TIMEOUT).map(|_| ())
    }

    /// `wait_for_completion_timeout`: 0 on timeout, otherwise the jiffies
    /// left (at least 1).
    pub fn wait_for_completion_timeout(&mut self, c: &Completion, timeout: Jiffies) -> Result<Jiffies, LockError> {
        self.check_sleep()?;
        let forever = timeout >= MAX_SCHEDULE_TIMEOUT;
        self.clock.refresh();
        let deadline = self.clock.jiffies().wrapping_add(timeout.min(timer::MAX_JIFFY_OFFSET));
        let mut seq = None;
        loop {
            let left = if forever { MAX_SCHEDULE_TIMEOUT } else { self.left(deadline) };
            if c.try_wait() {
                return Ok(left.max(1));
            }
            if left == 0 {
                return Ok(0);
            }
            if seq.is_none() {
                self.need_task()?;
                seq = Some(self.tasks.take_seq());
            }
            let at = (!forever).then(|| self.clock.deadline_ns(deadline));
            self.block(chan(c), at, seq.unwrap_or_default());
        }
    }

    /// Wake the worker if it is parked and work is queued.
    fn kick_worker(&mut self) {
        if self.work.queued() > 0 {
            let w = chan(&self.work);
            self.tasks.wake_chan(w, 1);
        }
    }

    /// `timer_setup`.
    pub fn timer_setup(&mut self, func: timer::TimerFn<Env>, data: usize) -> Result<TimerHandle, TimerError> {
        self.timers.setup(func, data)
    }

    /// `mod_timer`.
    pub fn mod_timer(&mut self, t: TimerHandle, expires: Jiffies) -> Result<bool, TimerError> {
        self.timers.mod_timer(t, expires)
    }

    /// `del_timer`.
    pub fn del_timer(&mut self, t: TimerHandle) -> Result<bool, TimerError> {
        self.timers.del_timer(t)
    }

    /// `INIT_WORK`.
    pub fn init_work(&mut self, func: WorkFn<Env>, data: usize) -> Result<WorkHandle, WorkError> {
        self.work.init(func, data)
    }

    /// `INIT_DELAYED_WORK`: a work item plus its own timer.
    pub fn init_delayed_work(&mut self, func: WorkFn<Env>, data: usize) -> Result<WorkHandle, EnvError> {
        let w = self.work.init(func, data)?;
        match self.timers.setup(delayed_work_timer, w.to_raw() as usize) {
            Ok(t) => {
                self.work.set_timer(w, t)?;
                Ok(w)
            }
            Err(e) => {
                let _ = self.work.free(w);
                Err(e.into())
            }
        }
    }

    /// Release a work item (and its delay timer).
    pub fn free_work(&mut self, w: WorkHandle) -> Result<(), EnvError> {
        if let Some(t) = self.work.free(w)? {
            self.timers.free(t)?;
        }
        Ok(())
    }

    /// `queue_work`: false if already pending.
    pub fn queue_work(&mut self, w: WorkHandle) -> Result<bool, WorkError> {
        let queued = self.work.queue(w)?;
        self.kick_worker();
        Ok(queued)
    }

    /// `queue_delayed_work`: false if already pending. A zero delay queues
    /// immediately, as on Linux.
    pub fn queue_delayed_work(&mut self, w: WorkHandle, delay: Jiffies) -> Result<bool, EnvError> {
        let t = self.work.timer(w).ok_or(EnvError::NotDelayed)?;
        if delay == 0 {
            return Ok(self.queue_work(w)?);
        }
        if !self.work.mark_delayed(w)? {
            return Ok(false);
        }
        let at = self.clock.jiffies().wrapping_add(delay.min(timer::MAX_JIFFY_OFFSET));
        self.timers.mod_timer(t, at)?;
        Ok(true)
    }

    /// `cancel_delayed_work`: true if it was pending.
    pub fn cancel_delayed_work(&mut self, w: WorkHandle) -> Result<bool, EnvError> {
        let t = self.work.timer(w).ok_or(EnvError::NotDelayed)?;
        self.timers.del_timer(t)?;
        Ok(self.work.cancel(w)?)
    }

    /// `cancel_work`.
    pub fn cancel_work(&mut self, w: WorkHandle) -> Result<bool, WorkError> {
        self.work.cancel(w)
    }


    /// `flush_workqueue`: wait until every item queued before the call has
    /// run. From a task only; from a work item it would wait for itself.
    pub fn flush_workqueue(&mut self) -> Result<(), LockError> {
        self.check_sleep()?;
        if self.context == Context::Work {
            return Err(LockError::Deadlock);
        }
        let mark = self.work.seq_mark();
        let idle = |e: &Env| e.flush_done >= mark || (e.work.queued() == 0 && !e.worker_busy);
        if idle(self) {
            return Ok(());
        }
        self.need_task()?;
        let seq = self.tasks.take_seq();
        while !idle(self) {
            let f = chan(&self.flush_done);
            self.block(f, None, seq);
        }
        Ok(())
    }

    /// `call_rcu`.
    pub fn call_rcu(&mut self, func: RcuFn<Env>, data: usize) -> Result<(), RcuError> {
        self.rcu.call_rcu(func, data)
    }

    fn rcu_run(&mut self, f: RcuDriver) -> Result<usize, RcuError> {
        let saved = self.context;
        self.context = Context::RcuCallback;
        let r = f(self, rcus);
        self.context = saved;
        if let Ok(n) = r {
            self.stats.rcu_callbacks += n as u64;
        }
        r
    }

    /// `synchronize_rcu`: refused inside a read section.
    pub fn synchronize_rcu(&mut self) -> Result<usize, RcuError> {
        self.rcu_run(rcu::synchronize_rcu)
    }

    /// `rcu_barrier`.
    pub fn rcu_barrier(&mut self) -> Result<usize, RcuError> {
        self.rcu_run(rcu::rcu_barrier)
    }

    /// `platform_device_add`-style: add a device and probe it.
    pub fn device_add(&mut self, info: DeviceInfo) -> Result<DeviceHandle, DevError> {
        device::device_add(self, devs, info)
    }

    /// `device_del`.
    pub fn device_del(&mut self, h: DeviceHandle) -> Result<(), DevError> {
        device::device_del(self, devs, h)
    }

    /// `driver_register`.
    pub fn driver_register(&mut self, drv: Driver<Env>) -> Result<DriverHandle, DevError> {
        device::driver_register(self, devs, drv)
    }

    /// `driver_unregister`.
    pub fn driver_unregister(&mut self, h: DriverHandle) -> Result<(), DevError> {
        device::driver_unregister(self, devs, h)
    }

    /// Record a call to an unimplemented Linux symbol.
    pub fn dummy_hit(&mut self, name: &'static str) {
        self.dummies.hit(name, &mut self.log);
    }

    /// Total calls to unimplemented symbols.
    pub fn dummy_hits(&self) -> u64 {
        self.dummies.total()
    }

    /// Invariants that must hold between items; violations are fixed up so
    /// one buggy item does not poison the rest of the server, and counted.
    /// Checked after each stage of callbacks and after each task run: an
    /// item that leaks disabled interrupts affects the later callbacks of
    /// the same stage before the fix.
    fn after_items(&mut self) {
        if self.irq.disabled() {
            self.stats.irq_leaks += 1;
            self.log.pr_err(b"irqs left disabled by an item\n");
            self.irq.enable();
        }
        if self.preempt != 0 {
            self.stats.preempt_leaks += 1;
            self.log.pr_err(b"preemption left disabled by an item\n");
            self.preempt = 0;
        }
    }

    pub(crate) fn stats_mut(&mut self) -> &mut LoopStats {
        &mut self.stats
    }

    /// Run an interrupt handler in hard-interrupt context. It may
    /// `complete`, `wake_up` or queue work; the tasks it wakes run in the
    /// next pass.
    pub(crate) fn run_hardirq<R>(&mut self, handler: impl FnOnce(&mut Env) -> R) -> R {
        assert!(self.current.is_none(), "an interrupt handler run from a task");
        self.context = Context::Hardirq;
        let r = handler(self);
        self.context = Context::Idle;
        self.stats.irqs += 1;
        self.after_items();
        r
    }

    /// One pass of the loop at monotonic time `now_ns`. Returns when the
    /// server should run the next pass: `Some(t)` means "block until `t`"
    /// (`t == now_ns` means "immediately", because something is still
    /// runnable or queued), `None` means nothing is armed and only an
    /// external event can make progress.
    ///
    /// # Panics
    ///
    /// When called from a task, or after the environment moved while it
    /// held a stack (both would corrupt a suspended task).
    pub fn run_once(&mut self, now_ns: u64) -> Option<u64> {
        assert!(self.current.is_none(), "run_once called from a task");
        assert!(
            self.home == 0 || self.home == self as *const Env as usize,
            "the Env moved after add_stack"
        );
        self.stats.passes += 1;
        self.clock.set_now_ns(now_ns);
        let now = self.clock.jiffies();

        self.irq_replays();

        self.context = Context::Softirq;
        self.stats.timers_fired += timer::run_expired(self, timers, now) as u64;
        self.context = Context::Idle;
        self.after_items();

        if self.work.queued() > 0 && self.tasks.find(WORKER_TASK).is_none() {
            self.spawn(kworker, 0, Some(WORKER_TASK));
        }
        self.kick_worker();
        let now_ns = self.clock.now_ns();
        self.tasks.expire(now_ns);
        let mark = self.tasks.take_seq();
        while let Some(i) = self.tasks.next_runnable(mark) {
            self.resume(i);
        }

        self.context = Context::RcuCallback;
        let q = rcu::quiescent(self, rcus);
        self.context = Context::Idle;
        match q {
            Ok(k) => self.stats.rcu_callbacks += k as u64,
            Err(_) => {
                self.stats.rcu_leaks += 1;
                self.log.pr_err(b"rcu read section held across a loop pass\n");
            }
        }
        self.after_items();

        self.next_deadline()
    }

    /// The deadline [`Env::run_once`] would return now.
    pub fn next_deadline(&self) -> Option<u64> {
        let now_ns = self.clock.now_ns();
        // Work queued and no worker yet: the next pass starts one, if it can.
        let worker_waits =
            self.work.queued() > 0 && self.tasks.find(WORKER_TASK).is_none() && self.tasks.has_free_stack();
        if worker_waits || self.rcu.queued() > 0 || self.tasks.any_runnable() || self.irq_replay_due() {
            return Some(now_ns);
        }
        let now = self.clock.jiffies();
        let t = self.timers.next_expiry(now).map(|e| self.clock.deadline_ns(e));
        let s = self.tasks.next_wake().map(|at| at.max(now_ns));
        match (t, s) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::EPROBE_DEFER;
    use crate::timer::{msecs_to_jiffies, NSEC_PER_JIFFY};
    use std::cell::{Cell, RefCell};
    use std::ops::{Deref, DerefMut};

    const MS: u64 = 1_000_000;
    const J: u64 = NSEC_PER_JIFFY;
    const STACK: usize = 128 * 1024;

    /// An Env with stacks. Field order matters: the Env is dropped before
    /// the stacks its tasks ran on.
    struct Fx {
        env: Box<Env>,
        _stacks: Vec<Box<[u8]>>,
    }

    impl Deref for Fx {
        type Target = Env;
        fn deref(&self) -> &Env {
            &self.env
        }
    }
    impl DerefMut for Fx {
        fn deref_mut(&mut self) -> &mut Env {
            &mut self.env
        }
    }

    fn env_with(stacks: usize) -> Fx {
        let mut env = Box::new(Env::new());
        let mut v = Vec::new();
        for _ in 0..stacks {
            let mut s = vec![0u8; STACK].into_boxed_slice();
            // SAFETY: the stack outlives the Env (Fx field order), which is
            // boxed and never moves.
            unsafe { env.add_stack(s.as_mut_ptr(), s.len()).unwrap() };
            v.push(s);
        }
        Fx { env, _stacks: v }
    }

    fn env() -> Fx {
        env_with(8)
    }

    thread_local! {
        static LOG: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
        static NOW: Cell<u64> = const { Cell::new(0) };
    }

    /// Record an event (each test runs on its own thread).
    fn log(v: u64) {
        LOG.with(|l| l.borrow_mut().push(v));
    }

    fn take_log() -> Vec<u64> {
        LOG.with(|l| core::mem::take(&mut *l.borrow_mut()))
    }

    fn fake_now() -> u64 {
        NOW.with(|n| n.get())
    }

    fn set_now(ns: u64) {
        NOW.with(|n| n.set(ns));
    }

    /// Run passes from `from` until nothing is armed; returns the time of
    /// the last pass. Bounded, so a scheduler bug fails the test instead of
    /// hanging it.
    fn drain(e: &mut Env, from: u64) -> u64 {
        let mut now = from;
        for _ in 0..10_000 {
            match e.run_once(now) {
                Some(at) => now = at.max(now),
                None => return now,
            }
        }
        panic!("the loop never went idle (last pass at {now} ns)");
    }

    /// Order log kept in `Env::user`: events are digits appended to it.
    fn note(e: &mut Env, d: usize) {
        e.user = e.user * 10 + d;
    }

    fn t_note(e: &mut Env, t: TimerHandle) {
        let d = e.timers.data(t).unwrap();
        note(e, d);
    }

    fn w_note(e: &mut Env, w: WorkHandle) {
        let d = e.work.data(w).unwrap();
        note(e, d);
    }

    fn r_note(e: &mut Env, d: usize) {
        note(e, d);
    }

    /// Fixtures the task functions reach through `Env::user` would collide
    /// with `note`; statics per test thread keep them apart.
    struct Objs {
        wq: WaitQueueHead,
        m: Mutex,
        c: Completion,
        c2: Completion,
        s: Semaphore,
        flag: Cell<bool>,
    }

    thread_local! {
        static OBJS: &'static Objs = Box::leak(Box::new(Objs {
            wq: WaitQueueHead::new(),
            m: Mutex::new(),
            c: Completion::new(),
            c2: Completion::new(),
            s: Semaphore::new(0),
            flag: Cell::new(false),
        }));
    }

    fn objs() -> &'static Objs {
        OBJS.with(|o| *o)
    }

    #[test]
    fn idle_env_has_no_deadline() {
        let mut e = env();
        assert_eq!(e.run_once(0), None);
        assert_eq!(e.stats().passes, 1);
    }

    #[test]
    fn timers_then_tasks_and_work_in_readiness_order_then_rcu() {
        fn task(e: &mut Env, _: usize) -> i32 {
            note(e, 2);
            0
        }
        let mut e = env();
        e.kthread_run(task, 0).unwrap();
        let w = e.init_work(w_note, 3).unwrap();
        e.queue_work(w).unwrap();
        e.call_rcu(r_note, 4).unwrap();
        let t = e.timer_setup(t_note, 1).unwrap();
        let now = e.jiffies();
        e.mod_timer(t, now).unwrap();
        assert_eq!(e.run_once(0), None);
        assert_eq!(e.user, 1234);
        assert_eq!(e.tasks.count(), 1, "only the parked worker is left");
        assert_eq!(e.tasks.state(WORKER_TASK), Some(TaskState::Waiting));
    }

    #[test]
    fn deadline_follows_the_earliest_timer() {
        let mut e = env();
        let a = e.timer_setup(t_note, 1).unwrap();
        let b = e.timer_setup(t_note, 2).unwrap();
        let j0 = e.jiffies();
        e.mod_timer(a, j0 + msecs_to_jiffies(100)).unwrap();
        e.mod_timer(b, j0 + msecs_to_jiffies(20)).unwrap();
        assert_eq!(e.run_once(0), Some(20 * MS));
        assert_eq!(e.run_once(19 * MS), Some(20 * MS));
        assert_eq!(e.user, 0);
        assert_eq!(e.run_once(20 * MS), Some(100 * MS));
        assert_eq!(e.user, 2);
        assert_eq!(e.run_once(100 * MS + 1), None);
        assert_eq!(e.user, 21);
    }

    #[test]
    fn delayed_work_runs_in_the_pass_its_timer_fires() {
        let mut e = env();
        let w = e.init_delayed_work(w_note, 7).unwrap();
        assert_eq!(e.queue_delayed_work(w, 5), Ok(true));
        assert_eq!(e.queue_delayed_work(w, 1), Ok(false), "already pending");
        assert_eq!(e.queue_work(w), Ok(false));
        assert_eq!(e.run_once(4 * J), Some(5 * J));
        assert_eq!(e.user, 0);
        assert_eq!(e.run_once(5 * J), None);
        assert_eq!(e.user, 7);
        assert!(!e.work.pending(w));
        // Again, now that the worker exists and is parked.
        assert_eq!(e.tasks.state(WORKER_TASK), Some(TaskState::Waiting));
        e.queue_delayed_work(w, 2).unwrap();
        assert_eq!(e.run_once(7 * J), None);
        assert_eq!(e.user, 77, "the pass that fires the timer wakes the worker");
    }

    #[test]
    fn cancelled_delayed_work_never_runs() {
        let mut e = env();
        let w = e.init_delayed_work(w_note, 7).unwrap();
        e.queue_delayed_work(w, 5).unwrap();
        assert_eq!(e.cancel_delayed_work(w), Ok(true));
        assert_eq!(e.cancel_delayed_work(w), Ok(false));
        assert_eq!(e.run_once(100 * J), None);
        assert_eq!(e.user, 0);
        // Plain work is not delayed work.
        let p = e.init_work(w_note, 1).unwrap();
        assert_eq!(e.queue_delayed_work(p, 3), Err(EnvError::NotDelayed));
        e.free_work(w).unwrap();
        assert_eq!(e.timers.pending_count(), 0);
    }

    #[test]
    fn zero_delay_queues_immediately() {
        let mut e = env();
        let w = e.init_delayed_work(w_note, 3).unwrap();
        e.queue_delayed_work(w, 0).unwrap();
        assert_eq!(e.next_deadline(), Some(0));
        e.run_once(0);
        assert_eq!(e.user, 3);
    }

    #[test]
    fn self_requeueing_work_does_not_livelock() {
        fn again(e: &mut Env, w: WorkHandle) {
            // Panics instead of hanging if a pass ever runs re-queued work.
            assert!(e.user < 1_000_000, "self-requeued work ran within one pass");
            note(e, 1);
            e.queue_work(w).unwrap();
        }
        let mut e = env();
        let w = e.init_work(again, 0).unwrap();
        e.queue_work(w).unwrap();
        assert_eq!(e.run_once(0), Some(0), "still queued: run again now");
        assert_eq!(e.run_once(0), Some(0));
        assert_eq!(e.user, 11);
        e.cancel_work(w).unwrap();
        assert_eq!(e.run_once(0), None);
    }

    #[test]
    fn work_without_a_stack_does_not_spin_the_loop() {
        let mut e = env_with(0);
        let w = e.init_work(w_note, 1).unwrap();
        e.queue_work(w).unwrap();
        assert_eq!(e.run_once(0), None, "no worker can start: nothing to run");
        assert_eq!(e.user, 0);
        assert_eq!(e.tasks.full_errors(), 1);
        assert_eq!(e.kthread_run(|_, _| 0, 0), None);
    }

    #[test]
    fn kthread_sleeps_waits_and_is_woken() {
        fn kt(e: &mut Env, _: usize) -> i32 {
            note(e, 1);
            e.set_current_state(CurrentState::Sleeping);
            let left = e.schedule_timeout(10).unwrap();
            note(e, if left == 0 { 2 } else { 9 });
            e.set_current_state(CurrentState::Sleeping);
            e.schedule().unwrap();
            note(e, 3);
            0
        }
        let mut e = env();
        let id = e.kthread_run(kt, 0).unwrap();
        assert_eq!(id, FIRST_KTHREAD);
        assert_eq!(e.run_once(0), Some(10 * J));
        assert_eq!(e.run_once(9 * J), Some(10 * J));
        assert_eq!(e.tasks.state(id), Some(TaskState::Sleeping(10 * J)));
        assert_eq!(e.run_once(10 * J), None, "waiting: no deadline");
        assert_eq!(e.tasks.state(id), Some(TaskState::Waiting));
        assert!(e.wake_up_process(id));
        assert!(!e.wake_up_process(id));
        assert_eq!(e.run_once(11 * J), None);
        assert_eq!(e.user, 123);
        assert_eq!(e.tasks.count(), 0);
    }

    #[test]
    fn a_wake_between_set_current_state_and_schedule_is_not_lost() {
        fn kt(e: &mut Env, _: usize) -> i32 {
            e.set_current_state(CurrentState::Sleeping);
            // The condition is signalled before the task reaches schedule().
            let me = e.current();
            let woke = e.wake_up_process(me);
            log(woke as u64);
            e.schedule().unwrap();
            note(e, 1);
            0
        }
        let mut e = env();
        e.kthread_run(kt, 0).unwrap();
        assert_eq!(e.run_once(0), Some(0), "schedule() only yielded: still runnable");
        assert_eq!(e.run_once(0), None);
        assert_eq!(e.user, 1);
        assert_eq!(take_log(), vec![1], "the wake cancelled the pending sleep");
    }

    #[test]
    fn wake_up_process_cuts_schedule_timeout_short_but_not_msleep() {
        fn kt(e: &mut Env, _: usize) -> i32 {
            e.set_current_state(CurrentState::Sleeping);
            let left = e.schedule_timeout(100).unwrap();
            log(left);
            e.msleep(40).unwrap();
            log(e.clock.now_ns() / MS);
            0
        }
        let mut e = env();
        let id = e.kthread_run(kt, 0).unwrap();
        e.run_once(0);
        assert!(e.wake_up_process(id));
        e.run_once(5 * J);
        assert_eq!(take_log(), vec![95], "woken 5 jiffies in: 95 left");
        // msleep is uninterruptible: a wake-up only re-checks the time.
        assert!(e.wake_up_process(id));
        assert_eq!(e.run_once(30 * MS), Some(60 * MS));
        assert_eq!(e.run_once(60 * MS), None);
        assert_eq!(take_log(), vec![60]);
    }

    // ── wake ordering ──────────────────────────────────────────────────────

    #[test]
    fn wake_up_runs_waiters_in_the_order_they_started_waiting() {
        // Created 1, 2, 3; they start waiting 3, 1, 2.
        fn kt(e: &mut Env, d: usize) -> i32 {
            let delay = [0, 1, 2, 0][d];
            e.msleep(delay).unwrap();
            log(d as u64);
            e.wait_event(&objs().wq, |_| objs().flag.get()).unwrap();
            log(10 + d as u64);
            0
        }
        let mut e = env();
        for d in 1..=3 {
            e.kthread_run(kt, d).unwrap();
        }
        drain(&mut e, 0);
        assert_eq!(take_log(), vec![3, 1, 2], "started waiting 3, 1, 2");
        objs().flag.set(true);
        assert_eq!(e.wake_up(&objs().wq), 3);
        assert_eq!(e.run_once(10 * MS), None);
        assert_eq!(take_log(), vec![13, 11, 12], "woken in waiting order, not creation order");
        assert_eq!(objs().wq.wakes(), 1);
    }

    #[test]
    fn a_contended_mutex_is_handed_over_first_come_first_served() {
        fn holder(e: &mut Env, _: usize) -> i32 {
            let m = &objs().m;
            e.mutex_lock(m).unwrap();
            e.msleep(10).unwrap();
            e.mutex_unlock(m).unwrap();
            0
        }
        fn waiter(e: &mut Env, d: usize) -> i32 {
            let m = &objs().m;
            e.msleep([0, 2, 3, 1][d]).unwrap();
            e.mutex_lock(m).unwrap();
            assert_eq!(m.owner(), Some(e.current()));
            log(d as u64);
            // Hold it across a sleep: the next waiter must keep waiting.
            e.msleep(1).unwrap();
            e.mutex_unlock(m).unwrap();
            0
        }
        let mut e = env();
        e.kthread_run(holder, 0).unwrap();
        for d in 1..=3 {
            e.kthread_run(waiter, d).unwrap();
        }
        drain(&mut e, 0);
        assert_eq!(take_log(), vec![3, 1, 2]);
        assert!(!objs().m.is_locked());
        assert_eq!(e.stats().would_block, 0);
    }

    #[test]
    fn a_semaphore_unit_is_handed_to_the_waiter_not_stolen() {
        fn downer(e: &mut Env, d: usize) -> i32 {
            e.down(&objs().s).unwrap();
            log(d as u64);
            0
        }
        let mut e = env();
        e.kthread_run(downer, 1).unwrap();
        e.run_once(0);
        assert!(take_log().is_empty());
        e.up(&objs().s);
        assert_eq!(objs().s.count(), 0, "handed over, not counted");
        // A newcomer that arrives before the waiter runs finds no unit.
        assert!(!objs().s.down_trylock());
        e.run_once(0);
        assert_eq!(take_log(), vec![1]);
    }

    // ── completions ───────────────────────────────────────────────────────

    #[test]
    fn a_completion_signalled_before_the_wait_does_not_sleep() {
        fn kt(e: &mut Env, _: usize) -> i32 {
            note(e, 1);
            e.wait_for_completion(&objs().c).unwrap();
            note(e, 2);
            0
        }
        let mut e = env();
        e.complete(&objs().c);
        e.kthread_run(kt, 0).unwrap();
        assert_eq!(e.run_once(0), None);
        assert_eq!(e.user, 12);
        assert_eq!(e.stats().task_runs, 1, "one run: the wait never parked the task");
        assert_eq!(objs().c.done(), 0, "consumed");
    }

    #[test]
    fn complete_wakes_one_waiter_complete_all_wakes_the_rest() {
        fn kt(e: &mut Env, d: usize) -> i32 {
            e.wait_for_completion(&objs().c).unwrap();
            log(d as u64);
            0
        }
        let mut e = env();
        for d in 1..=3 {
            e.kthread_run(kt, d).unwrap();
        }
        e.run_once(0);
        e.complete(&objs().c);
        e.run_once(0);
        assert_eq!(take_log(), vec![1]);
        e.complete_all(&objs().c);
        e.run_once(0);
        assert_eq!(take_log(), vec![2, 3]);
    }

    // ── timeouts ──────────────────────────────────────────────────────────

    #[test]
    fn wait_for_completion_timeout_expires_on_the_jiffy_not_before() {
        fn kt(e: &mut Env, _: usize) -> i32 {
            log(e.wait_for_completion_timeout(&objs().c, 10).unwrap());
            log(e.wait_for_completion_timeout(&objs().c, 10).unwrap());
            0
        }
        fn fire(e: &mut Env, _: TimerHandle) {
            e.complete(&objs().c);
        }
        let mut e = env();
        e.kthread_run(kt, 0).unwrap();
        let t = e.timer_setup(fire, 0).unwrap();
        let j0 = e.jiffies();
        assert_eq!(e.run_once(0), Some(10 * J));
        assert_eq!(e.run_once(9 * J), Some(10 * J));
        assert!(LOG.with(|l| l.borrow().is_empty()), "not timed out one jiffy early");
        e.mod_timer(t, j0 + 14).unwrap();
        assert_eq!(e.run_once(10 * J), Some(14 * J), "timed out; waits again until 20");
        assert_eq!(e.tasks.state(FIRST_KTHREAD), Some(TaskState::Sleeping(20 * J)));
        assert_eq!(e.run_once(14 * J), None);
        assert_eq!(take_log(), vec![0, 6], "timeout → 0; completed at 14 of 20 → 6 left");
    }

    #[test]
    fn wait_event_timeout_returns_what_linux_returns() {
        fn kt(e: &mut Env, _: usize) -> i32 {
            let o = objs();
            log(e.wait_event_timeout(&o.wq, |_| o.flag.get(), 10).unwrap());
            log(e.wait_event_timeout(&o.wq, |_| false, 0).unwrap());
            o.flag.set(false);
            log(e.wait_event_timeout(&o.wq, |_| o.flag.get(), 10).unwrap());
            // Signalled on the very jiffy the timeout ends: 1, not 0.
            let t = e.timer_setup(fire, 0).unwrap();
            let j = e.jiffies();
            e.mod_timer(t, j + 5).unwrap();
            log(e.wait_event_timeout(&o.wq, |_| o.flag.get(), 5).unwrap());
            0
        }
        fn fire(e: &mut Env, _: TimerHandle) {
            objs().flag.set(true);
            e.wake_up(&objs().wq);
        }
        let mut e = env();
        e.kthread_run(kt, 0).unwrap();
        let t = e.timer_setup(fire, 0).unwrap();
        let j = e.jiffies();
        e.mod_timer(t, j + 3).unwrap();
        let now = drain(&mut e, 0);
        assert_eq!(take_log(), vec![7, 0, 0, 1], "woken at 3 of 10; zero timeout; timeout; true at the deadline");
        assert_eq!(now, 18 * J);
    }

    #[test]
    fn msleep_counts_from_when_the_task_went_to_sleep() {
        fn kt(e: &mut Env, _: usize) -> i32 {
            // A long stretch of work inside the pass that started at 0.
            set_now(5 * MS);
            e.msleep(10).unwrap();
            log(e.clock.now_ns() / MS);
            0
        }
        let mut e = env();
        e.clock.set_source(fake_now);
        e.kthread_run(kt, 0).unwrap();
        assert_eq!(e.run_once(0), Some(15 * MS), "10 ms after the call at 5 ms");
        set_now(10 * MS);
        assert_eq!(e.run_once(10 * MS), Some(15 * MS));
        set_now(15 * MS);
        assert_eq!(e.run_once(15 * MS), None);
        assert_eq!(take_log(), vec![15]);
    }

    // ── nested waits ──────────────────────────────────────────────────────

    /// Callee-saved state across a block deep in a call chain: each level
    /// keeps a local the compiler is free to hold in a callee-saved
    /// register, and the bottom sleeps.
    #[inline(never)]
    fn deep(e: &mut Env, n: u64, salt: u64) -> u64 {
        let local = n.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ salt;
        let f = n as f64 * 1.5 + salt as f64;
        if n == 0 {
            e.msleep(1 + salt % 3).unwrap();
            return local;
        }
        let r = deep(e, n - 1, salt);
        // Reading `f` back checks the FP callee-saved registers too.
        r.wrapping_add(local).wrapping_add(f as u64)
    }

    fn deep_ref(n: u64, salt: u64) -> u64 {
        let local = n.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ salt;
        if n == 0 {
            return local;
        }
        let f = n as f64 * 1.5 + salt as f64;
        deep_ref(n - 1, salt).wrapping_add(local).wrapping_add(f as u64)
    }

    #[test]
    fn a_block_deep_in_a_call_chain_keeps_every_frame() {
        fn kt(e: &mut Env, salt: usize) -> i32 {
            let r = deep(e, 40, salt as u64);
            log(salt as u64);
            log(r);
            0
        }
        let mut e = env();
        for salt in 1..=4 {
            e.kthread_run(kt, salt).unwrap();
        }
        drain(&mut e, 0);
        let l = take_log();
        assert_eq!(l.len(), 8);
        for p in l.chunks(2) {
            assert_eq!(p[1], deep_ref(40, p[0]), "task {} lost a frame across its sleep", p[0]);
        }
        assert_eq!(e.stats().stack_overflows, 0);
    }

    /// Eight FP values live across a sleep: the ABI keeps them in d8..d15
    /// (aarch64) or fs0..fs11 (riscv64 D), which only the switch preserves.
    #[inline(never)]
    fn fp_across_sleep(e: &mut Env, x: f64) -> f64 {
        let x = core::hint::black_box(x);
        let v = [x * 1.25, x + 3.5, x * x, x - 7.0, x / 3.0, x * 9.5, x + 0.125, x * -2.0];
        e.msleep(1 + x as u64 % 2).unwrap();
        v.iter().enumerate().fold(0.0, |acc, (i, a)| acc * 1.5 + a * (i as f64 + 1.0))
    }

    fn fp_ref(x: f64) -> f64 {
        let v = [x * 1.25, x + 3.5, x * x, x - 7.0, x / 3.0, x * 9.5, x + 0.125, x * -2.0];
        v.iter().enumerate().fold(0.0, |acc, (i, a)| acc * 1.5 + a * (i as f64 + 1.0))
    }

    #[test]
    fn floating_point_state_survives_a_sleep() {
        fn kt(e: &mut Env, x: usize) -> i32 {
            let r = fp_across_sleep(e, x as f64);
            log(x as u64);
            log(r.to_bits());
            0
        }
        let mut e = env();
        for x in [3, 10, 17, 24] {
            e.kthread_run(kt, x).unwrap();
        }
        drain(&mut e, 0);
        let l = take_log();
        assert_eq!(l.len(), 8);
        for p in l.chunks(2) {
            assert_eq!(f64::from_bits(p[1]), fp_ref(p[0] as f64), "task x={} lost FP state", p[0]);
        }
    }

    #[test]
    fn a_chain_of_waits_unwinds_in_order() {
        // T1 waits C1; T2 waits C2, then completes C1; a work item, queued
        // by a timer at 2 ms, sleeps 5 ms and completes C2.
        fn t1(e: &mut Env, _: usize) -> i32 {
            e.wait_for_completion(&objs().c).unwrap();
            log(1);
            log(e.clock.now_ns() / MS);
            0
        }
        fn t2(e: &mut Env, _: usize) -> i32 {
            e.wait_for_completion(&objs().c2).unwrap();
            log(2);
            e.complete(&objs().c);
            0
        }
        fn work(e: &mut Env, _: WorkHandle) {
            e.msleep(5).unwrap();
            log(3);
            e.complete(&objs().c2);
        }
        fn kick(e: &mut Env, t: TimerHandle) {
            let w = WorkHandle::from_raw(e.timers.data(t).unwrap() as u32);
            e.queue_work(w).unwrap();
        }
        let mut e = env();
        e.kthread_run(t1, 0).unwrap();
        e.kthread_run(t2, 0).unwrap();
        let w = e.init_work(work, 0).unwrap();
        let t = e.timer_setup(kick, w.to_raw() as usize).unwrap();
        let j = e.jiffies();
        e.mod_timer(t, j + msecs_to_jiffies(2)).unwrap();
        let now = drain(&mut e, 0);
        // The 2 ms timer fires on its jiffy (4 ms at HZ = 250); the work
        // sleeps until 9 ms; each completion wakes the next task for the
        // following pass at the same instant.
        assert_eq!(take_log(), vec![3, 2, 1, 9]);
        assert_eq!(now, 9 * MS);
    }

    #[test]
    fn a_task_sleeping_with_a_mutex_held_is_woken_by_an_interrupt() {
        // T1 holds M across a wait on C; T2 blocks on M; the interrupt
        // completes C; T1 releases M to T2.
        fn t1(e: &mut Env, _: usize) -> i32 {
            let o = objs();
            e.mutex_lock(&o.m).unwrap();
            e.wait_for_completion(&o.c).unwrap();
            log(1);
            e.mutex_unlock(&o.m).unwrap();
            0
        }
        fn t2(e: &mut Env, _: usize) -> i32 {
            let o = objs();
            e.mutex_lock(&o.m).unwrap();
            log(2);
            e.mutex_unlock(&o.m).unwrap();
            0
        }
        fn irq(e: &mut Env, _: u32, d: usize) -> crate::irq::IrqReturn {
            assert!(e.in_hardirq() && e.in_atomic());
            assert_eq!(e.msleep(1), Err(LockError::Atomic));
            log(d as u64);
            e.complete(&objs().c);
            crate::irq::IrqReturn::Handled
        }
        let mut e = env();
        e.set_irq_chip(crate::irq::IrqChip { bind: |_, _| 0, ack: |_, _| {} });
        assert_eq!(e.request_irq(5, irq, 0, "test", 9), 0);
        e.kthread_run(t1, 0).unwrap();
        e.kthread_run(t2, 0).unwrap();
        assert_eq!(e.run_once(0), None, "both parked");
        e.deliver_irq(5);
        assert_eq!(e.run_once(MS), Some(MS), "T1 ran; T2 got the mutex, runs next pass");
        assert_eq!(e.run_once(MS), None);
        assert_eq!(take_log(), vec![9, 1, 2]);
        assert_eq!(e.stats().irqs, 1);
        assert_eq!(e.stats().atomic_sleeps, 1);
    }

    // ── kernel-thread lifetime, flush ─────────────────────────────────────

    #[test]
    fn kthread_stop_wakes_the_thread_and_returns_its_code() {
        fn worker(e: &mut Env, _: usize) -> i32 {
            while !e.kthread_should_stop() {
                e.set_current_state(CurrentState::Sleeping);
                e.schedule().unwrap();
            }
            42
        }
        fn stopper(e: &mut Env, id: usize) -> i32 {
            log(e.kthread_stop(id as TaskId).unwrap() as u64);
            assert_eq!(e.kthread_stop(id as TaskId), Err(LockError::NoTask));
            0
        }
        let mut e = env();
        let w = e.kthread_run(worker, 0).unwrap();
        assert_eq!(e.run_once(0), None);
        assert_eq!(e.kthread_stop(w), Err(LockError::WouldBlock), "the server cannot wait");
        e.kthread_run(stopper, w as usize).unwrap();
        drain(&mut e, 0);
        assert_eq!(take_log(), vec![42]);
        assert_eq!(e.tasks.count(), 0);
    }

    #[test]
    fn flush_workqueue_waits_for_a_sleeping_work_item() {
        fn work(e: &mut Env, _: WorkHandle) {
            e.msleep(3).unwrap();
            log(1);
            assert_eq!(e.flush_workqueue(), Err(LockError::Deadlock));
        }
        fn kt(e: &mut Env, w: usize) -> i32 {
            e.queue_work(WorkHandle::from_raw(w as u32)).unwrap();
            e.flush_workqueue().unwrap();
            log(2);
            0
        }
        let mut e = env();
        let w = e.init_work(work, 0).unwrap();
        e.kthread_run(kt, w.to_raw() as usize).unwrap();
        drain(&mut e, 0);
        assert_eq!(take_log(), vec![1, 2]);
    }

    // ── contexts that cannot sleep ────────────────────────────────────────

    #[test]
    fn sleeping_primitives_in_softirq_are_reported() {
        fn t(e: &mut Env, _: TimerHandle) {
            let m = Mutex::new();
            assert!(e.in_softirq() && e.in_atomic());
            assert_eq!(e.mutex_lock(&m), Err(LockError::Atomic));
            assert!(!m.is_locked(), "a refused lock must not be taken");
            assert_eq!(e.msleep(1), Err(LockError::Atomic));
        }
        let mut e = env();
        let h = e.timer_setup(t, 0).unwrap();
        let now = e.jiffies();
        e.mod_timer(h, now).unwrap();
        e.run_once(0);
        assert_eq!(e.stats().timers_fired, 1);
        assert_eq!(e.stats().atomic_sleeps, 2);
    }

    #[test]
    fn the_server_outside_a_task_gets_would_block() {
        let mut e = env();
        assert_eq!(e.msleep(1), Err(LockError::WouldBlock));
        assert_eq!(e.wait_for_completion(&objs().c), Err(LockError::WouldBlock));
        objs().m.lock(99).unwrap();
        assert_eq!(e.mutex_lock(&objs().m), Err(LockError::WouldBlock));
        // Nothing to wait for is not a block.
        e.complete(&objs().c);
        assert_eq!(e.wait_for_completion(&objs().c), Ok(()));
        assert_eq!(e.wait_event(&objs().wq, |_| true), Ok(()));
        assert_eq!(e.stats().would_block, 3);
    }

    #[test]
    fn sleeping_with_irqs_off_is_refused_and_the_leak_is_fixed() {
        fn kt(e: &mut Env, _: usize) -> i32 {
            let _flags = e.irq.save();
            assert_eq!(e.msleep(1), Err(LockError::Atomic));
            assert_eq!(e.cond_resched(), Err(LockError::Atomic));
            0
        }
        let mut e = env();
        e.kthread_run(kt, 0).unwrap();
        e.run_once(0);
        assert!(!e.irq.disabled());
        assert_eq!(e.stats().irq_leaks, 1);
        assert_eq!(e.stats().atomic_sleeps, 2);
        assert_eq!(e.log.last().unwrap().text(), b"irqs left disabled by an item\n");
    }

    #[test]
    fn a_task_that_runs_off_its_stack_is_reported_once() {
        fn kt(e: &mut Env, _: usize) -> i32 {
            // Stand-in for an overflow: the word at the stack's base.
            let i = e.current.unwrap();
            let base = e.tasks.slots[i].stack as *mut u64;
            // SAFETY: the base word of this task's own stack.
            unsafe { base.write_volatile(0) };
            e.msleep(1).unwrap();
            0
        }
        let mut e = env();
        e.kthread_run(kt, 0).unwrap();
        e.run_once(0);
        e.run_once(MS);
        assert_eq!(e.stats().stack_overflows, 1);
        assert_eq!(e.log.last().unwrap().text(), b"task stack overflow\n");
    }

    #[test]
    #[should_panic(expected = "the Env moved after add_stack")]
    fn an_env_that_moved_after_add_stack_refuses_to_run() {
        let fx = env_with(1);
        let mut moved: Box<Env> = Box::new(Env::new());
        // SAFETY: a byte copy to a new address, which is the misuse checked.
        unsafe { core::ptr::copy_nonoverlapping(&*fx.env as *const Env, &mut *moved as *mut Env, 1) };
        moved.run_once(0);
    }

    #[test]
    fn add_stack_refuses_small_stacks_and_extra_slots() {
        #[repr(align(16))]
        struct Aligned([u8; MIN_STACK]);
        let mut e = env_with(TASK_SLOTS);
        let mut small = Aligned([0; MIN_STACK]);
        let small = &mut small.0;
        // SAFETY: never used: both calls are refused.
        unsafe {
            assert_eq!(e.add_stack(small.as_mut_ptr().add(1), MIN_STACK - 1), Err(StackError::TooSmall));
            assert_eq!(e.add_stack(small.as_mut_ptr(), MIN_STACK), Err(StackError::Full));
        }
        assert_eq!(e.tasks.stacks(), TASK_SLOTS);
    }

    // ── the rest of the loop ──────────────────────────────────────────────

    #[test]
    fn leaked_irq_disable_is_fixed_up_and_counted() {
        fn w(e: &mut Env, _: WorkHandle) {
            let _flags = e.irq.save();
        }
        let mut e = env();
        let h = e.init_work(w, 0).unwrap();
        e.queue_work(h).unwrap();
        e.run_once(0);
        assert!(!e.irq.disabled());
        assert_eq!(e.stats().irq_leaks, 1);
        assert_eq!(e.log.last().unwrap().text(), b"irqs left disabled by an item\n");
    }

    #[test]
    fn leaked_rcu_read_section_blocks_callbacks_and_is_reported() {
        fn w(e: &mut Env, _: WorkHandle) {
            e.rcu.read_lock();
        }
        let mut e = env();
        let h = e.init_work(w, 0).unwrap();
        e.queue_work(h).unwrap();
        e.call_rcu(r_note, 5).unwrap();
        e.run_once(0);
        assert_eq!(e.user, 0, "the callback must not run under a leaked reader");
        assert_eq!(e.stats().rcu_leaks, 1);
        e.rcu.read_unlock().unwrap();
        e.run_once(0);
        assert_eq!(e.user, 5);
    }

    #[test]
    fn synchronize_rcu_in_a_read_section_is_refused() {
        let mut e = env();
        e.call_rcu(r_note, 1).unwrap();
        e.rcu.read_lock();
        assert_eq!(e.synchronize_rcu(), Err(RcuError::InReadSection));
        e.rcu.read_unlock().unwrap();
        assert_eq!(e.synchronize_rcu(), Ok(1));
        assert_eq!(e.rcu_barrier(), Ok(0));
    }

    #[test]
    fn device_probe_can_use_the_whole_env() {
        fn probe(e: &mut Env, h: DeviceHandle) -> i32 {
            if e.user == 0 {
                return -EPROBE_DEFER;
            }
            let t = e.timer_setup(t_note, 9).unwrap();
            let now = e.jiffies();
            e.mod_timer(t, now + 1).unwrap();
            e.devices.set_drvdata(h, t.index()).unwrap();
            0
        }
        fn provider(e: &mut Env, _: DeviceHandle) -> i32 {
            e.user = 1;
            0
        }
        let mut e = env();
        e.driver_register(Driver { name: "c", compatible: &["c"], probe, remove: None }).unwrap();
        e.driver_register(Driver { name: "p", compatible: &["p"], probe: provider, remove: None }).unwrap();
        let c = e.device_add(DeviceInfo { name: "c0", compatible: Some("c") }).unwrap();
        assert_eq!(e.devices.deferred().count(), 1);
        e.device_add(DeviceInfo { name: "p0", compatible: Some("p") }).unwrap();
        assert!(e.devices.bound_driver(c).is_some());
        assert_eq!(e.run_once(NSEC_PER_JIFFY), None);
        assert_eq!(e.user, 19);
    }

    #[test]
    fn a_probe_that_sleeps_runs_in_the_task_that_added_the_device() {
        fn probe(e: &mut Env, _: DeviceHandle) -> i32 {
            match e.msleep(2) {
                Ok(()) => 0,
                Err(_) => -crate::errno::EAGAIN,
            }
        }
        fn adder(e: &mut Env, _: usize) -> i32 {
            let d = e.device_add(DeviceInfo { name: "s0", compatible: Some("s") }).unwrap();
            log(e.devices.bound_driver(d).is_some() as u64);
            log(e.clock.now_ns() / MS);
            0
        }
        let mut e = env();
        e.driver_register(Driver { name: "s", compatible: &["s"], probe, remove: None }).unwrap();
        // From the server itself the probe cannot sleep.
        let d = e.device_add(DeviceInfo { name: "s1", compatible: Some("s") }).unwrap();
        assert!(e.devices.bound_driver(d).is_none());
        assert_eq!(e.stats().would_block, 1);
        e.kthread_run(adder, 0).unwrap();
        drain(&mut e, 0);
        assert_eq!(take_log(), vec![1, 2]);
    }

    #[test]
    fn dummy_hits_are_counted_and_logged_once() {
        let mut e = env();
        e.dummy_hit("clk_prepare");
        e.dummy_hit("clk_prepare");
        assert_eq!(e.dummy_hits(), 2);
        assert_eq!(e.log.len(), 1);
        assert_eq!(e.log.last().unwrap().text(), b"unimplemented clk_prepare\n");
    }

    // Evaluated at compile time: the build fails if Env::new stops being
    // const, which the server relies on to keep Env off its stack.
    const _: () = {
        let _ = Env::new();
    };
}
