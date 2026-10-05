// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! The cooperative loop and the [`Env`] that owns every subsystem.
//!
//! # Threading model (RFC-0053 section 3)
//!
//! One AzOS thread per server runs this loop on one hart. Everything the
//! Linux code thinks of as concurrent is a run-to-completion item of the
//! loop: timer callbacks, work items, RCU callbacks and the steps of
//! kernel threads. Nothing preempts an item, so spinlocks reduce to
//! interrupt-state flags and lockdep has nothing to find. Between passes the
//! server blocks in the AzOS wait primitive until the deadline
//! [`Env::run_once`] returns, or until a message (an interrupt, a client
//! request) arrives.
//!
//! # No stack switching in L0
//!
//! An item cannot be suspended halfway: there is one stack and it belongs
//! to the loop. A Linux kernel thread is therefore modelled as a *step
//! function* that returns what it would have done next ([`Step`]): yield,
//! sleep N jiffies, wait for a wake-up, or exit. Code that would block in
//! the middle of a function (a contended `mutex_lock`, `wait_for_completion`
//! on an incomplete completion, `msleep`) gets `WouldBlock` back. In L0 that
//! is a bug report, not a wait. Stage L1 adds stackful tasks and turns these
//! into real suspensions.
//!
//! # One pass
//!
//! [`Env::run_once`] runs, in order: expired timers (softirq context), the
//! runnable kernel-thread steps, the work FIFO, then the RCU quiescent
//! point. Each stage only runs what was ready when the stage started, so
//! an item that re-arms itself for "now" cannot livelock the loop; the
//! pass returns "run again immediately" instead. Timers run before work so
//! a delayed work item whose timer fires in this pass also runs in this
//! pass, as on Linux.

use crate::device::{self, DevError, DeviceHandle, DeviceInfo, DeviceModel, Driver, DriverHandle};
use crate::lock::{Completion, LockError, Mutex, TaskId};
use crate::printk::Printk;
use crate::rcu::{self, Rcu, RcuError, RcuFn};
use crate::symbols::Dummies;
use crate::timer::{self, Clock, Jiffies, TimerError, TimerHandle, TimerList};
use crate::workqueue::{self, WorkError, WorkFn, WorkHandle, WorkQueue};
use crate::lock::IrqState;
use core::fmt;

/// `current` while timer callbacks and RCU callbacks run (Linux's
/// softirq context has no task of its own; 0 is the idle task's pid).
pub const SOFTIRQ_TASK: TaskId = 0;
/// `current` while work items run: the single emulated kworker.
pub const WORKER_TASK: TaskId = 1;
/// First id handed to a kernel thread.
pub const FIRST_KTHREAD: TaskId = 2;

/// What a kernel-thread step asks for next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Stay runnable: run again next pass (`cond_resched`/`schedule`).
    Yield,
    /// Sleep this many jiffies (`schedule_timeout`, `msleep`).
    Sleep(Jiffies),
    /// Sleep until `wake_up_process` (`set_current_state` + `schedule`).
    Wait,
    /// The thread function returned.
    Exit,
}

/// A kernel thread's step function.
pub type TaskFn<C> = fn(&mut C, TaskId) -> Step;

/// Task state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    /// Will run next pass.
    Runnable,
    /// Its step is running now.
    Running,
    /// Sleeping until a jiffies deadline.
    Sleeping(Jiffies),
    /// Waiting for `wake_up_process`.
    Waiting,
}

struct TaskSlot<C> {
    func: Option<TaskFn<C>>,
    data: usize,
    id: TaskId,
    state: TaskState,
    /// A wake-up that arrived while the step was running: honoured when the
    /// step returns `Wait` or `Sleep`, so the classic lost wake-up (condition
    /// signalled between the check and the sleep) cannot happen.
    woken: bool,
}

impl<C> Clone for TaskSlot<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C> Copy for TaskSlot<C> {}

/// Fixed-capacity table of kernel threads.
pub struct RunQueue<C, const N: usize> {
    slots: [TaskSlot<C>; N],
    next_id: TaskId,
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
    const EMPTY: TaskSlot<C> =
        TaskSlot { func: None, data: 0, id: 0, state: TaskState::Waiting, woken: false };

    /// No threads.
    pub const fn new() -> Self {
        RunQueue { slots: [Self::EMPTY; N], next_id: FIRST_KTHREAD, full_errors: 0 }
    }

    fn find(&self, id: TaskId) -> Option<usize> {
        self.slots.iter().position(|s| s.func.is_some() && s.id == id)
    }

    /// `kthread_run`: create a runnable thread. Ids are never reused.
    pub fn spawn(&mut self, func: TaskFn<C>, data: usize) -> Option<TaskId> {
        let Some(i) = self.slots.iter().position(|s| s.func.is_none()) else {
            self.full_errors += 1;
            return None;
        };
        let id = self.next_id;
        self.next_id += 1;
        self.slots[i] = TaskSlot { func: Some(func), data, id, state: TaskState::Runnable, woken: false };
        Some(id)
    }

    /// `wake_up_process`: true if the thread was not already runnable. For
    /// a thread whose step is running, the first wake returns true (it will
    /// cancel the `Wait`/`Sleep` the step is about to return); Linux would
    /// return 0 only if the thread had not yet set a sleeping state, which
    /// a step cannot express in L0.
    pub fn wake(&mut self, id: TaskId) -> bool {
        let Some(i) = self.find(id) else { return false };
        let s = &mut self.slots[i];
        match s.state {
            TaskState::Runnable => false,
            TaskState::Running => {
                let was = s.woken;
                s.woken = true;
                !was
            }
            TaskState::Sleeping(_) | TaskState::Waiting => {
                s.state = TaskState::Runnable;
                true
            }
        }
    }

    /// `kthread_stop` without the wait: drop the thread. True if it existed.
    pub fn stop(&mut self, id: TaskId) -> bool {
        match self.find(id) {
            Some(i) => {
                self.slots[i].func = None;
                true
            }
            None => false,
        }
    }

    /// State of a thread.
    pub fn state(&self, id: TaskId) -> Option<TaskState> {
        self.find(id).map(|i| self.slots[i].state)
    }

    /// The thread's `data` word.
    pub fn data(&self, id: TaskId) -> Option<usize> {
        self.find(id).map(|i| self.slots[i].data)
    }

    /// Live threads.
    pub fn count(&self) -> usize {
        self.slots.iter().filter(|s| s.func.is_some()).count()
    }

    /// `spawn` calls refused for lack of a slot.
    pub fn full_errors(&self) -> u32 {
        self.full_errors
    }

    fn any_runnable(&self) -> bool {
        self.slots.iter().any(|s| s.func.is_some() && s.state == TaskState::Runnable)
    }

    fn next_wake(&self, now: Jiffies) -> Option<Jiffies> {
        self.slots
            .iter()
            .filter_map(|s| match (s.func, s.state) {
                (Some(_), TaskState::Sleeping(at)) => Some(at),
                _ => None,
            })
            .min_by_key(|at| at.wrapping_sub(now) as i64)
    }

    /// Ids of threads due at `now`, in id (creation) order. Sleepers whose
    /// deadline passed become runnable.
    fn due(&mut self, now: Jiffies) -> ([TaskId; N], usize) {
        for s in self.slots.iter_mut() {
            if let (Some(_), TaskState::Sleeping(at)) = (s.func, s.state) {
                if timer::time_after_eq(now, at) {
                    s.state = TaskState::Runnable;
                }
            }
        }
        let mut ids = [0; N];
        let mut n = 0;
        for s in self.slots.iter() {
            if s.func.is_some() && s.state == TaskState::Runnable {
                ids[n] = s.id;
                n += 1;
            }
        }
        ids[..n].sort_unstable();
        (ids, n)
    }

    fn begin(&mut self, id: TaskId) -> Option<TaskFn<C>> {
        let i = self.find(id)?;
        let s = &mut self.slots[i];
        if s.state != TaskState::Runnable {
            return None;
        }
        s.state = TaskState::Running;
        s.woken = false;
        s.func
    }

    fn end(&mut self, id: TaskId, step: Step, now: Jiffies) {
        let Some(i) = self.find(id) else { return };
        let s = &mut self.slots[i];
        s.state = match step {
            Step::Exit => {
                s.func = None;
                return;
            }
            Step::Yield | Step::Sleep(0) => TaskState::Runnable,
            // A wake that arrived during the step cuts a sleep short too,
            // exactly as a wake one instruction later would.
            Step::Sleep(_) | Step::Wait if s.woken => TaskState::Runnable,
            Step::Sleep(j) => TaskState::Sleeping(now.wrapping_add(j)),
            Step::Wait => TaskState::Waiting,
        };
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
/// Kernel threads in an [`Env`].
pub const TASK_SLOTS: usize = 16;
/// Devices on the [`Env`] bus.
pub const DEVICE_SLOTS: usize = 32;
/// Drivers on the [`Env`] bus.
pub const DRIVER_SLOTS: usize = 16;
/// Distinct unimplemented symbols remembered.
pub const DUMMY_SLOTS: usize = 64;

/// Execution context of the item currently running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    /// Between items (or a direct call from the server).
    Idle,
    /// A timer callback: atomic, must not sleep.
    Softirq,
    /// A work item, in the kworker.
    Work,
    /// A kernel-thread step.
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
    /// Kernel-thread steps run.
    pub task_steps: u64,
    /// Work items run.
    pub works_run: u64,
    /// RCU callbacks run.
    pub rcu_callbacks: u64,
    /// Quiescent points refused because an item leaked a read section.
    pub rcu_leaks: u32,
    /// Items that returned with interrupts still disabled (fixed up).
    pub irq_leaks: u32,
    /// Sleeping primitives called from atomic context.
    pub atomic_sleeps: u32,
    /// Waits that would have blocked (L0 cannot suspend an item).
    pub would_block: u32,
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
    /// Timer list.
    pub timers: TimerList<Env, TIMER_SLOTS>,
    /// Work FIFO.
    pub work: WorkQueue<Env, WORK_SLOTS>,
    /// RCU state.
    pub rcu: Rcu<Env, RCU_SLOTS>,
    /// Kernel log.
    pub log: Printk<LOG_RECORDS>,
    /// Kernel threads.
    pub tasks: RunQueue<Env, TASK_SLOTS>,
    /// The bus.
    pub devices: DeviceModel<Env, DEVICE_SLOTS, DRIVER_SLOTS>,
    /// Unimplemented-symbol registry.
    pub dummies: Dummies<DUMMY_SLOTS>,
    context: Context,
    stats: LoopStats,
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

fn timers(e: &mut Env) -> &mut TimerList<Env, TIMER_SLOTS> {
    &mut e.timers
}
fn works(e: &mut Env) -> &mut WorkQueue<Env, WORK_SLOTS> {
    &mut e.work
}
fn rcus(e: &mut Env) -> &mut Rcu<Env, RCU_SLOTS> {
    &mut e.rcu
}
/// Shape of `rcu::synchronize_rcu` / `rcu::rcu_barrier` instantiated on Env.
type RcuDriver = fn(&mut Env, fn(&mut Env) -> &mut Rcu<Env, RCU_SLOTS>) -> Result<usize, RcuError>;

fn devs(e: &mut Env) -> &mut DeviceModel<Env, DEVICE_SLOTS, DRIVER_SLOTS> {
    &mut e.devices
}

/// Timer callback behind every delayed work item: the timer's data word
/// holds the work handle.
fn delayed_work_timer(env: &mut Env, t: TimerHandle) {
    if let Some(raw) = env.timers.data(t) {
        // A cancelled item is no longer Delayed; delay_elapsed ignores it.
        let _ = env.work.delay_elapsed(WorkHandle::from_raw(raw as u32));
    }
}

impl Env {
    /// A fresh environment at time 0. `const` so the server can place it in
    /// a `static` cell instead of on its stack (it is tens of KiB).
    pub const fn new() -> Self {
        Env {
            clock: Clock::new(),
            irq: IrqState::new(),
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
                task_steps: 0,
                works_run: 0,
                rcu_callbacks: 0,
                rcu_leaks: 0,
                irq_leaks: 0,
                atomic_sleeps: 0,
                would_block: 0,
            },
            user: 0,
        }
    }

    /// Loop counters.
    pub fn stats(&self) -> LoopStats {
        self.stats
    }

    /// Context of the running item.
    pub fn context(&self) -> Context {
        self.context
    }

    /// `current`'s pid: the kernel thread, the kworker, or 0 in softirq.
    pub fn current(&self) -> TaskId {
        match self.context {
            Context::Task(id) => id,
            Context::Work => WORKER_TASK,
            Context::Idle | Context::Softirq | Context::RcuCallback => SOFTIRQ_TASK,
        }
    }

    /// `in_softirq()`.
    pub fn in_softirq(&self) -> bool {
        matches!(self.context, Context::Softirq | Context::RcuCallback)
    }

    /// `in_atomic()`: softirq, interrupts off, or inside an RCU read
    /// section. Sleeping here is a bug on Linux.
    pub fn in_atomic(&self) -> bool {
        self.in_softirq() || self.irq.disabled() || self.rcu.depth() > 0
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

    fn blocked<T>(&mut self, r: Result<T, LockError>) -> Result<T, LockError> {
        if matches!(r, Err(LockError::WouldBlock)) {
            self.stats.would_block += 1;
        }
        r
    }

    /// `might_sleep()`: error in atomic context.
    pub fn might_sleep(&mut self) -> Result<(), LockError> {
        self.check_sleep()
    }

    /// `mutex_lock` as `current`.
    pub fn mutex_lock(&mut self, m: &Mutex) -> Result<(), LockError> {
        self.check_sleep()?;
        let me = self.current();
        let r = m.lock(me);
        self.blocked(r)
    }

    /// `mutex_unlock` as `current`.
    pub fn mutex_unlock(&mut self, m: &Mutex) -> Result<(), LockError> {
        m.unlock(self.current())
    }

    /// `wait_for_completion`.
    pub fn wait_for_completion(&mut self, c: &Completion) -> Result<(), LockError> {
        self.check_sleep()?;
        let r = c.wait();
        self.blocked(r)
    }

    /// `msleep` from the middle of a function: cannot be honoured in L0
    /// (no stack to park). A kernel thread returns [`Step::Sleep`] instead.
    pub fn msleep(&mut self, _ms: u64) -> Result<(), LockError> {
        self.check_sleep()?;
        self.blocked(Err(LockError::WouldBlock))
    }

    /// `kthread_run`.
    pub fn kthread_run(&mut self, func: TaskFn<Env>, data: usize) -> Option<TaskId> {
        self.tasks.spawn(func, data)
    }

    /// `wake_up_process`.
    pub fn wake_up_process(&mut self, id: TaskId) -> bool {
        self.tasks.wake(id)
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
        self.work.queue(w)
    }

    /// `queue_delayed_work`: false if already pending. A zero delay queues
    /// immediately, as on Linux.
    pub fn queue_delayed_work(&mut self, w: WorkHandle, delay: Jiffies) -> Result<bool, EnvError> {
        let t = self.work.timer(w).ok_or(EnvError::NotDelayed)?;
        if delay == 0 {
            return Ok(self.work.queue(w)?);
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

    /// `flush_workqueue`: run everything queued now (in the kworker
    /// context). Returns the number of items run.
    pub fn flush_workqueue(&mut self) -> usize {
        let saved = self.context;
        self.context = Context::Work;
        let n = workqueue::run_pending(self, works);
        self.context = saved;
        self.stats.works_run += n as u64;
        self.after_items();
        n
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

    /// Invariants that must hold between stages; violations are fixed up so
    /// one buggy item does not poison the rest of the server, and counted.
    /// Checked per stage, not per item: an item that leaks disabled
    /// interrupts affects the later items of the same stage before the fix.
    fn after_items(&mut self) {
        if self.irq.disabled() {
            self.stats.irq_leaks += 1;
            self.log.pr_err(b"irqs left disabled by an item\n");
            self.irq.enable();
        }
    }

    /// One pass of the loop at monotonic time `now_ns`. Returns when the
    /// server should run the next pass: `Some(t)` means "block until `t`"
    /// (`t == now_ns` means "immediately", because work is still queued),
    /// `None` means nothing is armed and only an external event can make
    /// progress.
    pub fn run_once(&mut self, now_ns: u64) -> Option<u64> {
        self.stats.passes += 1;
        self.clock.set_now_ns(now_ns);
        let now = self.clock.jiffies();

        self.context = Context::Softirq;
        self.stats.timers_fired += timer::run_expired(self, timers, now) as u64;
        self.context = Context::Idle;
        self.after_items();

        let (ids, n) = self.tasks.due(now);
        for &id in &ids[..n] {
            let Some(f) = self.tasks.begin(id) else { continue };
            self.context = Context::Task(id);
            let step = f(self, id);
            self.context = Context::Idle;
            self.tasks.end(id, step, now);
            self.stats.task_steps += 1;
        }
        self.after_items();

        self.context = Context::Work;
        self.stats.works_run += workqueue::run_pending(self, works) as u64;
        self.context = Context::Idle;
        self.after_items();

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
        if self.work.queued() > 0 || self.rcu.queued() > 0 || self.tasks.any_runnable() {
            return Some(now_ns);
        }
        let now = self.clock.jiffies();
        let t = self.timers.next_expiry(now);
        let s = self.tasks.next_wake(now);
        let earliest = match (t, s) {
            (Some(a), Some(b)) => Some(if timer::time_before(a, b) { a } else { b }),
            (a, b) => a.or(b),
        };
        earliest.map(|e| self.clock.deadline_ns(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::EPROBE_DEFER;
    use crate::timer::{msecs_to_jiffies, NSEC_PER_JIFFY};

    const MS: u64 = 1_000_000;

    fn env() -> Box<Env> {
        Box::new(Env::new())
    }

    /// Order log kept in `Env::user` as a pointer would be overkill; tests
    /// encode events as digits appended to a u64 instead.
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

    #[test]
    fn idle_env_has_no_deadline() {
        let mut e = env();
        assert_eq!(e.run_once(0), None);
        assert_eq!(e.stats().passes, 1);
    }

    #[test]
    fn stage_order_is_timers_tasks_work_rcu() {
        fn task(e: &mut Env, _: TaskId) -> Step {
            note(e, 2);
            Step::Exit
        }
        let mut e = env();
        let w = e.init_work(w_note, 3).unwrap();
        e.queue_work(w).unwrap();
        e.call_rcu(r_note, 4).unwrap();
        e.kthread_run(task, 0).unwrap();
        let t = e.timer_setup(t_note, 1).unwrap();
        let now = e.jiffies();
        e.mod_timer(t, now).unwrap();
        assert_eq!(e.run_once(0), None);
        assert_eq!(e.user, 1234);
        assert_eq!(e.tasks.count(), 0);
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
        assert_eq!(e.run_once(4 * NSEC_PER_JIFFY), Some(5 * NSEC_PER_JIFFY));
        assert_eq!(e.user, 0);
        assert_eq!(e.run_once(5 * NSEC_PER_JIFFY), None);
        assert_eq!(e.user, 7);
        assert!(!e.work.pending(w));
    }

    #[test]
    fn cancelled_delayed_work_never_runs() {
        let mut e = env();
        let w = e.init_delayed_work(w_note, 7).unwrap();
        e.queue_delayed_work(w, 5).unwrap();
        assert_eq!(e.cancel_delayed_work(w), Ok(true));
        assert_eq!(e.cancel_delayed_work(w), Ok(false));
        assert_eq!(e.run_once(100 * NSEC_PER_JIFFY), None);
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
    fn kthread_sleep_wait_and_wake() {
        fn kt(e: &mut Env, id: TaskId) -> Step {
            assert_eq!(e.current(), id);
            note(e, 1);
            match e.user {
                1 => Step::Sleep(10),
                11 => Step::Wait,
                _ => Step::Exit,
            }
        }
        let mut e = env();
        let id = e.kthread_run(kt, 0).unwrap();
        assert_eq!(id, FIRST_KTHREAD);
        assert_eq!(e.run_once(0), Some(10 * NSEC_PER_JIFFY));
        assert_eq!(e.run_once(9 * NSEC_PER_JIFFY), Some(10 * NSEC_PER_JIFFY));
        assert_eq!(e.run_once(10 * NSEC_PER_JIFFY), None, "waiting: no deadline");
        assert_eq!(e.tasks.state(id), Some(TaskState::Waiting));
        assert!(e.wake_up_process(id));
        assert!(!e.wake_up_process(id));
        assert_eq!(e.run_once(11 * NSEC_PER_JIFFY), None);
        assert_eq!(e.user, 111);
        assert_eq!(e.tasks.count(), 0);
    }

    #[test]
    fn a_wake_during_the_step_is_not_lost() {
        fn kt(e: &mut Env, id: TaskId) -> Step {
            note(e, 1);
            // The condition was signalled while we were still running.
            e.wake_up_process(id);
            if e.user < 11 {
                Step::Wait
            } else {
                Step::Exit
            }
        }
        let mut e = env();
        e.kthread_run(kt, 0).unwrap();
        assert_eq!(e.run_once(0), Some(0), "woken during its own step: stays runnable");
        e.run_once(0);
        assert_eq!(e.user, 11);
    }

    #[test]
    fn a_wake_during_the_step_cuts_a_sleep_short() {
        fn kt(e: &mut Env, id: TaskId) -> Step {
            note(e, 1);
            e.wake_up_process(id);
            if e.user < 11 {
                Step::Sleep(100)
            } else {
                Step::Exit
            }
        }
        let mut e = env();
        e.kthread_run(kt, 0).unwrap();
        assert_eq!(e.run_once(0), Some(0), "woken during its own step: no 100-jiffy sleep");
        e.run_once(0);
        assert_eq!(e.user, 11);
    }

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
    fn contended_mutex_in_work_is_would_block_with_worker_owner() {
        fn w(e: &mut Env, _: WorkHandle) {
            let m = Mutex::new();
            e.mutex_lock(&m).unwrap();
            assert_eq!(m.owner(), Some(WORKER_TASK));
            let c = Completion::new();
            assert_eq!(e.wait_for_completion(&c), Err(LockError::WouldBlock));
            assert_eq!(e.mutex_lock(&m), Err(LockError::Deadlock));
            e.mutex_unlock(&m).unwrap();
            m.lock(99).unwrap();
            assert_eq!(e.mutex_lock(&m), Err(LockError::WouldBlock));
            note(e, 1);
        }
        let mut e = env();
        let h = e.init_work(w, 0).unwrap();
        e.queue_work(h).unwrap();
        e.run_once(0);
        assert_eq!(e.user, 1);
        assert_eq!(e.stats().would_block, 2);
    }

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
