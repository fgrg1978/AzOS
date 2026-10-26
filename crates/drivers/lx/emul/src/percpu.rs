// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! Per-CPU state on a one-CPU server: the preemption count, the spinlock
//! calls that raise it, the CPU number, and `current`.
//!
//! A server runs all of its Linux code on one AzOS thread, so to Linux it
//! is one CPU, number 0, whose per-CPU offset is 0
//! ([lx-driver-slices.md](../../../../../Documentation/design/lx-driver-slices.md),
//! "Per-CPU state and `current`"). Most of the per-CPU API is inline code
//! in the modules (`this_cpu_*`, `per_cpu`, `get_cpu`, `put_cpu`), which
//! works once three things are right: the per-CPU base reads 0, the CPU
//! number reads 0, and `current` points at the running task's
//! `task_struct`. The first two are values the glue defines and the loader
//! rewrites; the third is a register (riscv64 `tp`, aarch64 `TPIDR_EL0`) or
//! a variable (x86_64 `const_current_task`) that has to change at every
//! task switch, and that is this module's: each task has a **current
//! word**, the address of its `task_struct`, which the server's
//! [`CurrentOps`] creates, installs and releases. The struct layout comes
//! from the Linux headers, so only the glue can allocate one; this crate
//! only carries the word.
//!
//! The preemption count is the layer's own: nothing preempts a task between
//! two block points, so the count only marks atomic sections (Linux's
//! "scheduling while atomic"). [`Env::spin_lock`] and the other spinlock
//! calls raise it, as on Linux, so a task that tries to sleep while it
//! holds a spinlock is refused and counted ([`crate::sched::LoopStats`]
//! `atomic_sleeps`). An item that returns with it raised is fixed up and
//! counted (`preempt_leaks`). A block point is never reached with it
//! raised, so one count serves every task.

use crate::lock::{IrqFlags, LockError, SpinLock, TaskId};
use crate::sched::Env;

/// CPUs of a server: one thread is one CPU.
pub const NR_CPUS: u32 = 1;

/// The server's `task_struct` operations, given once
/// ([`Env::set_current_ops`]). The first argument of `create` and `release`
/// is [`Env::user`].
#[derive(Clone, Copy, Debug)]
pub struct CurrentOps {
    /// A new task's current word (its `task_struct`), or 0 if the server
    /// has none for it. Called at every task creation: kernel threads, the
    /// workqueue worker, irq threads.
    pub create: fn(usize, TaskId) -> usize,
    /// The task exited or was reaped: its word is no longer used.
    pub release: fn(usize, usize),
    /// Make `word` the current task (riscv64: `tp`; aarch64: `TPIDR_EL0`;
    /// x86_64: `const_current_task`). Called before the loop switches into
    /// a task, and with the loop's own word when the switch comes back.
    pub install: fn(usize),
}

impl Env {
    /// `smp_processor_id()`.
    pub fn smp_processor_id(&self) -> u32 {
        0
    }

    /// `num_possible_cpus()`, `nr_cpu_ids`.
    pub fn num_possible_cpus(&self) -> u32 {
        NR_CPUS
    }

    /// `preempt_count()`: the depth of the atomic sections the running
    /// code is in.
    pub fn preempt_count(&self) -> u32 {
        self.preempt
    }

    /// `preempt_disable()`.
    pub fn preempt_disable(&mut self) {
        self.preempt += 1;
    }

    /// `preempt_enable()`. Nothing waits to preempt, so there is no
    /// `preempt_schedule()` to call. An enable without a disable is counted
    /// and ignored.
    pub fn preempt_enable(&mut self) {
        match self.preempt.checked_sub(1) {
            Some(n) => self.preempt = n,
            None => self.stats_mut().preempt_leaks += 1,
        }
    }

    /// `get_cpu()`: disable preemption and return the CPU number.
    pub fn get_cpu(&mut self) -> u32 {
        self.preempt_disable();
        self.smp_processor_id()
    }

    /// `put_cpu()`.
    pub fn put_cpu(&mut self) {
        self.preempt_enable();
    }

    /// `spin_lock` (`_raw_spin_lock`): preemption off, then the lock. A
    /// self-deadlock is reported and leaves the count as it was.
    pub fn spin_lock(&mut self, l: &SpinLock) -> Result<(), LockError> {
        l.lock()?;
        self.preempt_disable();
        Ok(())
    }

    /// `spin_trylock` (`_raw_spin_trylock`).
    pub fn spin_trylock(&mut self, l: &SpinLock) -> bool {
        let got = l.try_lock();
        if got {
            self.preempt_disable();
        }
        got
    }

    /// `spin_unlock` (`_raw_spin_unlock`).
    pub fn spin_unlock(&mut self, l: &SpinLock) -> Result<(), LockError> {
        l.unlock()?;
        self.preempt_enable();
        Ok(())
    }

    /// `spin_lock_irqsave` (`_raw_spin_lock_irqsave`).
    pub fn spin_lock_irqsave(&mut self, l: &SpinLock) -> Result<IrqFlags, LockError> {
        let flags = l.lock_irqsave(&self.irq)?;
        self.preempt_disable();
        Ok(flags)
    }

    /// `spin_unlock_irqrestore` (`_raw_spin_unlock_irqrestore`).
    pub fn spin_unlock_irqrestore(&mut self, l: &SpinLock, flags: IrqFlags) -> Result<(), LockError> {
        l.unlock_irqrestore(&self.irq, flags)?;
        self.preempt_enable();
        Ok(())
    }

    /// Give the layer the server's `task_struct` operations, and the loop's
    /// own current word (the idle task's: the loop and the callbacks it
    /// runs between tasks). Tasks that exist already get a word now.
    pub fn set_current_ops(&mut self, ops: CurrentOps, loop_word: usize) {
        self.current_ops = Some(ops);
        self.loop_word = loop_word;
        let user = self.user;
        self.tasks.give_words(|id| (ops.create)(user, id));
        (ops.install)(loop_word);
    }

    /// A task's current word (0: none).
    pub fn current_word(&self, id: TaskId) -> Option<usize> {
        self.tasks.current_word(id)
    }

    /// The word of a task created just now.
    pub(crate) fn current_created(&mut self, id: TaskId) {
        if let Some(ops) = self.current_ops {
            let w = (ops.create)(self.user, id);
            self.tasks.set_current_word(id, w);
        }
    }

    /// A task's slot is free again: release its word.
    pub(crate) fn current_released(&mut self, word: usize) {
        if let (Some(ops), true) = (self.current_ops, word != 0) {
            (ops.release)(self.user, word);
        }
    }

    /// Install `word` as current (before a switch into a task, or the
    /// loop's word after it).
    pub(crate) fn current_install(&self, word: usize) {
        if let Some(ops) = self.current_ops {
            (ops.install)(word);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    const STACK: usize = 64 * 1024;
    const LOOP_WORD: usize = 0x1000;

    thread_local! {
        static INSTALLED: Cell<usize> = const { Cell::new(0) };
        static SEEN: RefCell<Vec<(TaskId, usize)>> = const { RefCell::new(Vec::new()) };
        static RELEASED: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
        static SLEEP: Cell<Option<Result<(), LockError>>> = const { Cell::new(None) };
    }

    fn create(_: usize, id: TaskId) -> usize {
        0x10_0000 + id as usize * 0x1000
    }
    fn release(_: usize, w: usize) {
        RELEASED.with(|r| r.borrow_mut().push(w));
    }
    fn install(w: usize) {
        INSTALLED.with(|c| c.set(w));
    }
    fn installed() -> usize {
        INSTALLED.with(|c| c.get())
    }

    struct Fx {
        env: Box<Env>,
        _stacks: Vec<Box<[u8]>>,
    }
    impl core::ops::Deref for Fx {
        type Target = Env;
        fn deref(&self) -> &Env {
            &self.env
        }
    }
    impl core::ops::DerefMut for Fx {
        fn deref_mut(&mut self) -> &mut Env {
            &mut self.env
        }
    }

    fn env(stacks: usize) -> Fx {
        let mut env = Box::new(Env::new());
        let mut v: Vec<Box<[u8]>> = (0..stacks).map(|_| vec![0u8; STACK].into_boxed_slice()).collect();
        for s in v.iter_mut() {
            // SAFETY: each stack outlives the Env (field order of Fx), and the
            // Env is boxed, so it does not move.
            unsafe { env.add_stack(s.as_mut_ptr(), s.len()) }.unwrap();
        }
        Fx { env, _stacks: v }
    }

    /// Records the current word each time it runs, across a sleep.
    fn reader(e: &mut Env, _: usize) -> i32 {
        let me = e.current();
        SEEN.with(|s| s.borrow_mut().push((me, installed())));
        let _ = e.msleep(1);
        SEEN.with(|s| s.borrow_mut().push((me, installed())));
        0
    }

    #[test]
    fn each_task_runs_with_its_own_current_and_the_loop_with_its_own() {
        let mut e = env(3);
        let a = e.kthread_run(reader, 0).unwrap();
        e.set_current_ops(CurrentOps { create, release, install }, LOOP_WORD);
        let b = e.kthread_run(reader, 0).unwrap();
        assert_eq!(e.current_word(a), Some(create(0, a)), "a task made before the ops gets a word too");
        assert_eq!(e.current_word(b), Some(create(0, b)));
        e.run_once(0);
        assert_eq!(installed(), LOOP_WORD, "back in the loop");
        e.run_once(1_000_000);
        let seen = SEEN.with(|s| s.take());
        assert_eq!(seen.len(), 4);
        for (id, w) in seen {
            assert_eq!(w, create(0, id), "task {id} saw another task's current");
        }
        assert_eq!(installed(), LOOP_WORD);
        let mut rel = RELEASED.with(|r| r.take());
        rel.sort();
        assert_eq!(rel, vec![create(0, a), create(0, b)], "both words released at exit");
    }

    #[test]
    fn a_kthread_stop_reap_releases_the_word_once() {
        fn waits(e: &mut Env, _: usize) -> i32 {
            while !e.kthread_should_stop() {
                let _ = e.msleep(1);
            }
            5
        }
        fn stopper(e: &mut Env, id: usize) -> i32 {
            e.kthread_stop(id as TaskId).unwrap()
        }
        let mut e = env(2);
        e.set_current_ops(CurrentOps { create, release, install }, LOOP_WORD);
        let t = e.kthread_run(waits, 0).unwrap();
        e.run_once(0);
        let s = e.kthread_run(stopper, t as usize).unwrap();
        for i in 0..5 {
            e.run_once(i * 1_000_000);
        }
        let mut rel = RELEASED.with(|r| r.take());
        rel.sort();
        assert_eq!(rel, vec![create(0, t), create(0, s)]);
    }

    #[test]
    fn sleeping_under_a_spinlock_is_refused_and_counted() {
        thread_local! {
            static L: &'static SpinLock = Box::leak(Box::new(SpinLock::new()));
        }
        fn holder(e: &mut Env, _: usize) -> i32 {
            let l = L.with(|l| *l);
            e.spin_lock(l).unwrap();
            SLEEP.with(|c| c.set(Some(e.msleep(1))));
            e.spin_unlock(l).unwrap();
            0
        }
        let mut e = env(1);
        let t = e.kthread_run(holder, 0).unwrap();
        e.run_once(0);
        assert_eq!(SLEEP.with(|c| c.get()), Some(Err(LockError::Atomic)));
        assert_eq!(e.tasks.state(t), None, "it ran to the end in one pass");
        assert_eq!(e.stats().atomic_sleeps, 1);
        assert_eq!(e.preempt_count(), 0);
    }

    #[test]
    fn spinlock_calls_nest_the_count_and_a_deadlock_leaves_it() {
        let (a, b) = (SpinLock::new(), SpinLock::new());
        let mut e = env(0);
        e.spin_lock(&a).unwrap();
        let f = e.spin_lock_irqsave(&b).unwrap();
        assert_eq!(e.preempt_count(), 2);
        assert!(e.in_atomic() && e.irq.disabled());
        assert_eq!(e.spin_lock(&a), Err(LockError::Deadlock));
        assert!(!e.spin_trylock(&a));
        assert_eq!(e.preempt_count(), 2, "a refused lock does not count");
        e.spin_unlock_irqrestore(&b, f).unwrap();
        e.spin_unlock(&a).unwrap();
        assert!(e.spin_trylock(&a));
        e.spin_unlock(&a).unwrap();
        assert_eq!(e.preempt_count(), 0);
        assert!(!e.in_atomic());
    }

    #[test]
    fn get_cpu_is_cpu_0_with_preemption_off() {
        let mut e = env(0);
        assert_eq!((e.get_cpu(), e.preempt_count(), e.in_atomic()), (0, 1, true));
        e.put_cpu();
        assert_eq!((e.preempt_count(), e.num_possible_cpus()), (0, NR_CPUS));
        e.put_cpu();
        assert_eq!(e.stats().preempt_leaks, 1, "an unbalanced enable is counted");
    }

    #[test]
    fn a_task_that_returns_with_preemption_off_is_fixed_up() {
        fn leaks(e: &mut Env, _: usize) -> i32 {
            e.preempt_disable();
            0
        }
        let mut e = env(1);
        e.kthread_run(leaks, 0).unwrap();
        e.run_once(0);
        assert_eq!((e.preempt_count(), e.stats().preempt_leaks), (0, 1));
    }
}
