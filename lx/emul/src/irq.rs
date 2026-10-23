// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! Interrupt lines: `request_irq`, `request_threaded_irq`, `free_irq`,
//! `enable_irq`, `disable_irq` and the irq threads, over the AzOS
//! mask-until-ACK delivery of a ring-3 interrupt.
//!
//! # The kernel half
//!
//! The server binds each line it serves to its event port once
//! (`DEVICE_IRQ_BIND` on the line's `Cap<Irq>`, with the Linux irq number as
//! the event key). Every interrupt on the line masks it in the kernel and
//! queues one `PORT_EVENT_IRQ`; the line stays masked until the server's
//! `DEVICE_IRQ_ACK` (`crates/core/ipc/src/irq_bind.rs`). The server's loop
//! hands each event to [`Env::deliver_irq`]. This crate never makes a system
//! call: the server gives it the two operations as an [`IrqChip`], as it
//! gives the clock a time source.
//!
//! # Linux semantics over mask-until-ACK
//!
//! The kernel's mask is the only mask, and the layer decides when to lift
//! it. A delivery masks the line and leaves an ACK owed; the ACK is sent
//!
//! * after the primary handler, for a line without a thread, or whose
//!   primary did not ask for the thread, or that is not `IRQF_ONESHOT`;
//! * after the thread function, for an `IRQF_ONESHOT` line whose primary
//!   woke the thread (a NULL primary always does), so a level device is not
//!   taken again before the thread has quietened it;
//! * at the `enable_irq` that ends a disable, if the ACK came due while the
//!   line was disabled.
//!
//! `disable_irq` is lazy, as on Linux: it only counts a depth. A delivery
//! while the depth is above zero runs nothing and keeps the line masked
//! (the event is *pending*). The `enable_irq` that brings the depth back to
//! zero ACKs a level line (`IRQF_TRIGGER_HIGH`/`LOW`: the kernel delivers it
//! again if the device still asserts it) and replays any other line's
//! handler in the next pass, since an edge is not raised twice; that is
//! Linux's resend. `IRQF_NO_AUTOEN` starts the depth at 1.
//!
//! A threaded action has its own task, Linux's `irq/N-name` thread, started
//! at the request on a free stack. It runs the thread function in task
//! context, where it may sleep (an I2C transfer, a mutex). `synchronize_irq`,
//! `disable_irq` and `free_irq` wait for a running or woken thread function.
//!
//! A freed line stays bound (the kernel has no unbind for a live task) and
//! masked: an event that arrives for it is counted and never ACKed, which is
//! Linux's shutdown. The next request of the line ACKs it.
//!
//! Open: one action per line (`IRQF_SHARED` is accepted only on a free
//! line), no irq-thread priority (Linux runs them `SCHED_FIFO`), and no
//! "nobody cared" disable of a line whose handlers keep answering
//! `IRQ_NONE` (counted in [`IrqStats::unhandled`] instead).

use crate::errno::{EBUSY, EINVAL, ENODEV, ENOMEM};
use crate::lock::{LockError, TaskId};
use crate::sched::{chan, Env};

/// `IRQF_TRIGGER_RISING` (`include/linux/interrupt.h`).
pub const IRQF_TRIGGER_RISING: u32 = 0x0000_0001;
/// `IRQF_TRIGGER_FALLING`.
pub const IRQF_TRIGGER_FALLING: u32 = 0x0000_0002;
/// `IRQF_TRIGGER_HIGH`.
pub const IRQF_TRIGGER_HIGH: u32 = 0x0000_0004;
/// `IRQF_TRIGGER_LOW`.
pub const IRQF_TRIGGER_LOW: u32 = 0x0000_0008;
/// `IRQF_SHARED`.
pub const IRQF_SHARED: u32 = 0x0000_0080;
/// `IRQF_ONESHOT`: keep the line masked until the thread function returns.
pub const IRQF_ONESHOT: u32 = 0x0000_2000;
/// `IRQF_NO_AUTOEN`: the line starts disabled; `enable_irq` starts it.
pub const IRQF_NO_AUTOEN: u32 = 0x0008_0000;

/// `irqreturn_t` (`include/linux/irqreturn.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum IrqReturn {
    /// `IRQ_NONE`: not this device's interrupt.
    None = 0,
    /// `IRQ_HANDLED`.
    Handled = 1,
    /// `IRQ_WAKE_THREAD`: run the thread function.
    WakeThread = 2,
}

/// `irq_handler_t`: `(env, irq, dev_id)`.
pub type IrqHandler = fn(&mut Env, u32, usize) -> IrqReturn;

/// The server's two operations on a line, given once
/// ([`Env::set_irq_chip`]). The first argument is [`Env::user`].
#[derive(Clone, Copy, Debug)]
pub struct IrqChip {
    /// Bind the line to the server's port with the irq number as the event
    /// key (`DEVICE_IRQ_BIND`): 0, or a negative errno that the request
    /// returns. Called once per line for the life of the server.
    pub bind: fn(usize, u32) -> i32,
    /// Unmask the line (`DEVICE_IRQ_ACK`).
    pub ack: fn(usize, u32),
}

/// Interrupt-line counters. A gate can assert the error counters are 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IrqStats {
    /// Events handed to [`Env::deliver_irq`].
    pub delivered: u64,
    /// ACKs sent through the chip.
    pub acks: u64,
    /// Thread functions run.
    pub threads_run: u64,
    /// Handlers replayed by the `enable_irq` that ended a disable.
    pub replays: u64,
    /// Handler or thread function results that were `IRQ_NONE`.
    pub unhandled: u64,
    /// Events for a line with no action (freed, or never requested).
    pub spurious: u32,
    /// `IRQ_WAKE_THREAD` from a line without a thread function.
    pub bad_wakes: u32,
    /// `enable_irq` without a matching disable, or on an unrequested line;
    /// `disable_irq` on an unrequested line; `free_irq` of a free line or
    /// with the wrong `dev_id`.
    pub misuse: u32,
}

#[derive(Clone, Copy)]
struct Action {
    handler: Option<IrqHandler>,
    thread_fn: Option<IrqHandler>,
    flags: u32,
    name: &'static str,
    dev_id: usize,
    thread: Option<TaskId>,
}

/// One line the server bound. Its slot is kept once bound, because the
/// binding is.
#[derive(Clone, Copy)]
pub(crate) struct Line {
    irq: u32,
    bound: bool,
    action: Option<Action>,
    /// Nested `disable_irq` count.
    depth: u32,
    /// The kernel masked the line on a delivery and has not had the ACK.
    owed_ack: bool,
    /// A delivery came while disabled and ran no handler.
    pending: bool,
    /// Run the handler at the next pass (an enabled edge line was pending).
    replay: bool,
    /// The thread function is due (`IRQTF_RUNTHREAD`). The thread parks on
    /// this field's address.
    thread_wake: bool,
    /// The thread function is running. `synchronize_irq` waits on this
    /// field's address.
    thread_busy: bool,
}

impl Line {
    const EMPTY: Line = Line {
        irq: 0,
        bound: false,
        action: None,
        depth: 0,
        owed_ack: false,
        pending: false,
        replay: false,
        thread_wake: false,
        thread_busy: false,
    };
}

/// The lines of an [`Env`].
pub struct IrqLines<const N: usize> {
    lines: [Line; N],
    chip: Option<IrqChip>,
    stats: IrqStats,
}

impl<const N: usize> Default for IrqLines<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> IrqLines<N> {
    /// No line, no chip.
    pub const fn new() -> Self {
        const ZERO: IrqStats = IrqStats {
            delivered: 0,
            acks: 0,
            threads_run: 0,
            replays: 0,
            unhandled: 0,
            spurious: 0,
            bad_wakes: 0,
            misuse: 0,
        };
        IrqLines { lines: [Line::EMPTY; N], chip: None, stats: ZERO }
    }

    /// Counters.
    pub fn stats(&self) -> IrqStats {
        self.stats
    }

    /// The disable depth of a requested line.
    pub fn depth(&self, irq: u32) -> Option<u32> {
        self.find(irq).filter(|&i| self.lines[i].action.is_some()).map(|i| self.lines[i].depth)
    }

    /// The irq thread of a requested threaded line.
    pub fn thread(&self, irq: u32) -> Option<TaskId> {
        self.find(irq).and_then(|i| self.lines[i].action).and_then(|a| a.thread)
    }

    fn find(&self, irq: u32) -> Option<usize> {
        self.lines.iter().position(|l| l.bound && l.irq == irq)
    }

    fn free_slot(&self) -> Option<usize> {
        self.lines.iter().position(|l| !l.bound)
    }

    fn requested(&self, irq: u32) -> Option<(usize, Action)> {
        let i = self.find(irq)?;
        self.lines[i].action.map(|a| (i, a))
    }

    fn any_replay(&self) -> bool {
        self.lines.iter().any(|l| l.replay)
    }
}

fn is_level(flags: u32) -> bool {
    flags & (IRQF_TRIGGER_HIGH | IRQF_TRIGGER_LOW) != 0
}

/// The irq thread of line slot `slot`: runs the thread function each time
/// the primary wakes it, until `free_irq` stops it.
fn irq_thread(e: &mut Env, slot: usize) -> i32 {
    loop {
        if e.kthread_should_stop() {
            return 0;
        }
        let l = e.irqs.lines[slot];
        let Some(a) = l.action.filter(|_| l.thread_wake) else {
            e.park(chan(&e.irqs.lines[slot].thread_wake));
            continue;
        };
        e.irqs.lines[slot].thread_wake = false;
        e.irqs.lines[slot].thread_busy = true;
        let f = a.thread_fn.expect("an irq thread without a thread function");
        let r = f(e, l.irq, a.dev_id);
        e.irqs.stats.threads_run += 1;
        if r == IrqReturn::None {
            e.irqs.stats.unhandled += 1;
        }
        let l = &mut e.irqs.lines[slot];
        l.thread_busy = false;
        // irq_finalize_oneshot: the ACK the primary left owed, unless the
        // line was disabled meanwhile (then the enable sends it) or the
        // thread is due again.
        if l.depth == 0 && !l.thread_wake {
            e.irq_ack(slot);
        }
        e.tasks.wake_chan(chan(&e.irqs.lines[slot].thread_busy), usize::MAX);
    }
}

impl Env {
    /// Give the layer the server's line operations. Without a chip every
    /// request fails with `-ENODEV`.
    pub fn set_irq_chip(&mut self, chip: IrqChip) {
        self.irqs.chip = Some(chip);
    }

    /// `request_irq`: a handler run in hard-interrupt context.
    pub fn request_irq(&mut self, irq: u32, handler: IrqHandler, flags: u32, name: &'static str, dev_id: usize) -> i32 {
        self.request_threaded_irq(irq, Some(handler), None, flags, name, dev_id)
    }

    /// `request_threaded_irq`: 0, or `-EINVAL` (no handler at all; a NULL
    /// primary without `IRQF_ONESHOT`; `IRQF_SHARED` with a zero `dev_id` or
    /// with `IRQF_NO_AUTOEN`), `-EBUSY` (the line has an action),
    /// `-ENODEV` (no chip), `-ENOMEM` (no line slot, or no free stack for
    /// the thread), or the chip's bind error.
    pub fn request_threaded_irq(
        &mut self,
        irq: u32,
        handler: Option<IrqHandler>,
        thread_fn: Option<IrqHandler>,
        flags: u32,
        name: &'static str,
        dev_id: usize,
    ) -> i32 {
        if flags & IRQF_SHARED != 0 && (dev_id == 0 || flags & IRQF_NO_AUTOEN != 0) {
            return -EINVAL;
        }
        if handler.is_none() && (thread_fn.is_none() || flags & IRQF_ONESHOT == 0) {
            return -EINVAL;
        }
        let Some(chip) = self.irqs.chip else { return -ENODEV };
        let slot = match self.irqs.find(irq) {
            Some(i) if self.irqs.lines[i].action.is_some() => return -EBUSY,
            Some(i) => i,
            None => {
                let Some(i) = self.irqs.free_slot() else { return -ENOMEM };
                let r = (chip.bind)(self.user, irq);
                if r < 0 {
                    return r;
                }
                self.irqs.lines[i] = Line { irq, bound: true, ..Line::EMPTY };
                i
            }
        };
        let thread = match thread_fn {
            Some(_) => match self.kthread_run(irq_thread, slot) {
                Some(id) => Some(id),
                None => return -ENOMEM,
            },
            None => None,
        };
        let l = &mut self.irqs.lines[slot];
        l.action = Some(Action { handler, thread_fn, flags, name, dev_id, thread });
        l.depth = u32::from(flags & IRQF_NO_AUTOEN != 0);
        l.pending = false;
        l.replay = false;
        l.thread_wake = false;
        if l.depth == 0 {
            // An event that came while the line had no action.
            self.irq_ack(slot);
        }
        0
    }

    /// `free_irq`: the action's name, or `None` when the line has no action
    /// with this `dev_id` (counted). Waits for a running thread function,
    /// so from a task only when one may run; the line is left masked.
    pub fn free_irq(&mut self, irq: u32, dev_id: usize) -> Option<&'static str> {
        let Some((slot, a)) = self.irqs.requested(irq).filter(|(_, a)| a.dev_id == dev_id) else {
            self.irqs.stats.misuse += 1;
            return None;
        };
        // __free_irq masks the line, then waits for the handlers.
        self.irqs.lines[slot].depth += 1;
        if self.synchronize_irq(irq).is_err() {
            self.irqs.lines[slot].depth -= 1;
            return None;
        }
        if let Some(id) = a.thread {
            // The thread checks the stop request before anything else when
            // it next runs, and nothing is due: no wait needed.
            self.tasks.request_stop(id);
        }
        let l = &mut self.irqs.lines[slot];
        l.action = None;
        l.depth = 0;
        l.pending = false;
        l.replay = false;
        l.thread_wake = false;
        Some(a.name)
    }

    /// `disable_irq_nosync`: one more level of disable; nothing waits.
    pub fn disable_irq_nosync(&mut self, irq: u32) {
        match self.irqs.requested(irq) {
            Some((i, _)) => self.irqs.lines[i].depth += 1,
            None => self.irqs.stats.misuse += 1,
        }
    }

    /// `disable_irq`: [`Env::disable_irq_nosync`], then
    /// [`Env::synchronize_irq`]. It may sleep, so atomic context is refused
    /// (and counted) before the depth changes.
    pub fn disable_irq(&mut self, irq: u32) -> Result<(), LockError> {
        self.might_sleep()?;
        self.disable_irq_nosync(irq);
        self.synchronize_irq(irq)
    }

    /// `enable_irq`: one level of disable less. At zero the line is live
    /// again: an ACK owed meanwhile is sent, and a pending edge line's
    /// handler is replayed in the next pass.
    pub fn enable_irq(&mut self, irq: u32) {
        let Some((slot, a)) = self.irqs.requested(irq) else {
            self.irqs.stats.misuse += 1;
            return;
        };
        let l = &mut self.irqs.lines[slot];
        if l.depth == 0 {
            // "Unbalanced enable for IRQ".
            self.irqs.stats.misuse += 1;
            return;
        }
        l.depth -= 1;
        if l.depth > 0 {
            return;
        }
        if core::mem::replace(&mut l.pending, false) && !is_level(a.flags) {
            l.replay = true;
        } else if a.flags & IRQF_ONESHOT == 0 || !(l.thread_busy || l.thread_wake) {
            // A ONESHOT thread that is running or due sends it when it ends.
            self.irq_ack(slot);
        }
    }

    /// `synchronize_irq`: wait until no thread function of the line is
    /// running or due. Refused from atomic context and from the line's own
    /// thread (it would wait for itself).
    pub fn synchronize_irq(&mut self, irq: u32) -> Result<(), LockError> {
        self.might_sleep()?;
        let Some((slot, a)) = self.irqs.requested(irq) else { return Ok(()) };
        let busy = |e: &Env| e.irqs.lines[slot].thread_busy || e.irqs.lines[slot].thread_wake;
        if !busy(self) {
            return Ok(());
        }
        if a.thread.is_some() && a.thread == self.running_task() {
            return Err(LockError::Deadlock);
        }
        self.wait_on(chan(&self.irqs.lines[slot].thread_busy), busy)
    }

    /// The server's `PORT_EVENT_IRQ` for `irq` (the event key it bound the
    /// line with): the kernel has masked the line. Runs the primary handler
    /// in hard-interrupt context, unless the line is disabled; the thread
    /// it wakes runs in the next pass.
    ///
    /// # Panics
    ///
    /// When called from a task.
    pub fn deliver_irq(&mut self, irq: u32) {
        assert!(self.running_task().is_none(), "deliver_irq called from a task");
        self.irqs.stats.delivered += 1;
        let Some(slot) = self.irqs.find(irq) else {
            self.irqs.stats.spurious += 1;
            return;
        };
        let l = &mut self.irqs.lines[slot];
        l.owed_ack = true;
        if l.action.is_none() {
            self.irqs.stats.spurious += 1;
        } else if l.depth > 0 {
            l.pending = true;
        } else {
            self.irq_handle(slot);
        }
    }

    /// The handlers [`Env::enable_irq`] left for this pass.
    pub(crate) fn irq_replays(&mut self) {
        if !self.irqs.any_replay() {
            return;
        }
        for slot in 0..self.irqs.lines.len() {
            let l = &mut self.irqs.lines[slot];
            if l.replay && l.depth == 0 && l.action.is_some() {
                l.replay = false;
                self.irqs.stats.replays += 1;
                self.irq_handle(slot);
            }
        }
    }

    /// A replay is due.
    pub(crate) fn irq_replay_due(&self) -> bool {
        self.irqs.any_replay()
    }

    /// Run the primary handler of a requested, enabled line; ACK or wake the
    /// thread.
    fn irq_handle(&mut self, slot: usize) {
        let l = self.irqs.lines[slot];
        let a = l.action.expect("irq_handle on a line without an action");
        let r = match a.handler {
            Some(h) => self.run_hardirq(|e| h(e, l.irq, a.dev_id)),
            // irq_default_primary_handler.
            None => IrqReturn::WakeThread,
        };
        match (r, a.thread) {
            (IrqReturn::WakeThread, Some(_)) => {
                self.irqs.lines[slot].thread_wake = true;
                self.tasks.wake_chan(chan(&self.irqs.lines[slot].thread_wake), 1);
                if a.flags & IRQF_ONESHOT == 0 {
                    self.irq_ack(slot);
                }
            }
            (IrqReturn::WakeThread, None) => {
                self.irqs.stats.bad_wakes += 1;
                self.irq_ack(slot);
            }
            (r, _) => {
                if r == IrqReturn::None {
                    self.irqs.stats.unhandled += 1;
                }
                self.irq_ack(slot);
            }
        }
    }

    /// Send the owed ACK, if one is owed.
    fn irq_ack(&mut self, slot: usize) {
        let l = &mut self.irqs.lines[slot];
        if !core::mem::replace(&mut l.owed_ack, false) {
            return;
        }
        let irq = l.irq;
        self.irqs.stats.acks += 1;
        if let Some(chip) = self.irqs.chip {
            (chip.ack)(self.user, irq);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const MS: u64 = 1_000_000;
    const STACK: usize = 64 * 1024;

    /// What the fake chip saw, per test thread.
    #[derive(Default)]
    struct Chip {
        binds: Vec<u32>,
        acks: Vec<u32>,
        log: Vec<&'static str>,
        refuse_bind: bool,
    }

    thread_local! {
        static CHIP: RefCell<Chip> = RefCell::new(Chip::default());
    }

    fn bind(_: usize, irq: u32) -> i32 {
        CHIP.with(|c| {
            let mut c = c.borrow_mut();
            if c.refuse_bind {
                return -EBUSY;
            }
            c.binds.push(irq);
            0
        })
    }
    fn ack(_: usize, irq: u32) {
        CHIP.with(|c| {
            let mut c = c.borrow_mut();
            c.acks.push(irq);
            c.log.push("ack");
        })
    }
    fn log(s: &'static str) {
        CHIP.with(|c| c.borrow_mut().log.push(s));
    }
    fn take_log() -> Vec<&'static str> {
        CHIP.with(|c| core::mem::take(&mut c.borrow_mut().log))
    }
    fn acks() -> usize {
        CHIP.with(|c| c.borrow().acks.len())
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
        CHIP.with(|c| *c.borrow_mut() = Chip::default());
        let mut env = Box::new(Env::new());
        let mut v: Vec<Box<[u8]>> = (0..stacks).map(|_| vec![0u8; STACK].into_boxed_slice()).collect();
        for s in v.iter_mut() {
            // SAFETY: each stack outlives the Env (field order of Fx), and the
            // Env is boxed, so it does not move.
            unsafe { env.add_stack(s.as_mut_ptr(), s.len()) }.unwrap();
        }
        env.set_irq_chip(IrqChip { bind, ack });
        Fx { env, _stacks: v }
    }

    fn handled(e: &mut Env, _: u32, _: usize) -> IrqReturn {
        assert!(e.in_hardirq() && e.in_atomic());
        log("hard");
        IrqReturn::Handled
    }
    fn not_mine(_: &mut Env, _: u32, _: usize) -> IrqReturn {
        IrqReturn::None
    }
    fn wake(_: &mut Env, _: u32, _: usize) -> IrqReturn {
        log("hard");
        IrqReturn::WakeThread
    }
    fn sleeping_thread(e: &mut Env, _: u32, _: usize) -> IrqReturn {
        assert!(!e.in_atomic());
        log("thread");
        e.msleep(2).unwrap();
        log("thread done");
        IrqReturn::Handled
    }

    #[test]
    fn flag_and_return_values_match_the_linux_abi() {
        assert_eq!(
            [IRQF_TRIGGER_RISING, IRQF_TRIGGER_FALLING, IRQF_TRIGGER_HIGH, IRQF_TRIGGER_LOW, IRQF_SHARED, IRQF_ONESHOT, IRQF_NO_AUTOEN],
            [0x1, 0x2, 0x4, 0x8, 0x80, 0x2000, 0x80000]
        );
        assert_eq!([IrqReturn::None as u32, IrqReturn::Handled as u32, IrqReturn::WakeThread as u32], [0, 1, 2]);
    }

    #[test]
    fn a_hard_handler_runs_in_hardirq_context_and_acks_after_it() {
        let mut e = env(1);
        assert_eq!(e.request_irq(33, handled, IRQF_TRIGGER_HIGH, "dev", 1), 0);
        CHIP.with(|c| assert_eq!(c.borrow().binds, vec![33]));
        e.deliver_irq(33);
        assert_eq!(take_log(), vec!["hard", "ack"]);
        assert_eq!(e.stats().irqs, 1);
        e.deliver_irq(33);
        assert_eq!(e.irqs.stats().acks, 2);
    }

    #[test]
    fn the_request_refusals_are_linuxs() {
        let mut e = env(1);
        assert_eq!(e.request_threaded_irq(1, None, None, 0, "x", 1), -EINVAL);
        assert_eq!(e.request_threaded_irq(1, None, Some(sleeping_thread), 0, "x", 1), -EINVAL, "NULL primary needs ONESHOT");
        assert_eq!(e.request_irq(1, handled, IRQF_SHARED, "x", 0), -EINVAL, "shared needs a dev_id");
        assert_eq!(e.request_irq(1, handled, IRQF_SHARED | IRQF_NO_AUTOEN, "x", 1), -EINVAL);
        assert_eq!(e.request_irq(1, handled, 0, "x", 1), 0);
        assert_eq!(e.request_irq(1, handled, 0, "y", 2), -EBUSY);
        CHIP.with(|c| c.borrow_mut().refuse_bind = true);
        assert_eq!(e.request_irq(2, handled, 0, "x", 1), -EBUSY, "the chip's bind error");
        let mut bare = Env::new();
        assert_eq!(bare.request_irq(1, handled, 0, "x", 1), -ENODEV);
    }

    #[test]
    fn a_oneshot_line_stays_masked_until_its_sleeping_thread_returns() {
        let mut e = env(2);
        assert_eq!(e.request_threaded_irq(40, None, Some(sleeping_thread), IRQF_ONESHOT, "i2c-hid", 7), 0);
        assert!(e.irqs.thread(40).is_some());
        e.run_once(0);
        e.deliver_irq(40);
        assert_eq!(acks(), 0, "masked until the thread returns");
        e.run_once(0);
        assert_eq!(take_log(), vec!["thread"]);
        assert_eq!(acks(), 0, "the thread sleeps: still masked");
        e.run_once(2 * MS);
        assert_eq!(take_log(), vec!["thread done", "ack"]);
        assert_eq!(e.irqs.stats().threads_run, 1);
        assert_eq!(e.stats().atomic_sleeps, 0);
    }

    #[test]
    fn a_primary_that_wakes_the_thread_of_a_line_without_oneshot_acks_at_once() {
        let mut e = env(2);
        assert_eq!(e.request_threaded_irq(41, Some(wake), Some(sleeping_thread), 0, "x", 7), 0);
        e.run_once(0);
        e.deliver_irq(41);
        assert_eq!(take_log(), vec!["hard", "ack"]);
        e.run_once(0);
        e.run_once(2 * MS);
        assert_eq!(take_log(), vec!["thread", "thread done"]);
    }

    #[test]
    fn a_disabled_level_line_holds_its_event_and_the_enable_acks_it() {
        let mut e = env(1);
        assert_eq!(e.request_irq(50, handled, IRQF_TRIGGER_LOW | IRQF_NO_AUTOEN, "x", 1), 0);
        assert_eq!(e.irqs.depth(50), Some(1));
        e.deliver_irq(50);
        assert_eq!(take_log(), Vec::<&str>::new(), "disabled: no handler, no ACK");
        e.disable_irq_nosync(50);
        e.enable_irq(50);
        assert_eq!(take_log(), Vec::<&str>::new(), "depth 2 -> 1: still disabled");
        e.enable_irq(50);
        assert_eq!(take_log(), vec!["ack"], "level: the kernel delivers it again if still asserted");
        assert_eq!(e.irqs.stats().replays, 0);
        e.enable_irq(50);
        assert_eq!(e.irqs.stats().misuse, 1, "unbalanced enable");
    }

    #[test]
    fn a_disabled_edge_line_is_replayed_in_the_next_pass() {
        let mut e = env(1);
        assert_eq!(e.request_irq(51, handled, IRQF_TRIGGER_RISING, "x", 1), 0);
        e.disable_irq(51).unwrap();
        e.deliver_irq(51);
        e.enable_irq(51);
        assert_eq!(take_log(), Vec::<&str>::new(), "nothing runs inside enable_irq");
        assert_eq!(e.next_deadline(), Some(0), "a replay is due now");
        e.run_once(0);
        assert_eq!(take_log(), vec!["hard", "ack"]);
        assert_eq!(e.irqs.stats().replays, 1);
    }

    #[test]
    fn disable_irq_waits_for_a_running_thread_function() {
        fn disabler(e: &mut Env, _: usize) -> i32 {
            e.disable_irq(42).unwrap();
            log("disabled");
            0
        }
        let mut e = env(3);
        assert_eq!(e.request_threaded_irq(42, None, Some(sleeping_thread), IRQF_ONESHOT, "x", 7), 0);
        e.run_once(0);
        e.deliver_irq(42);
        e.run_once(0);
        e.kthread_run(disabler, 0).unwrap();
        e.run_once(0);
        assert_eq!(take_log(), vec!["thread"], "the disabler waits");
        e.run_once(2 * MS);
        e.run_once(2 * MS);
        assert_eq!(take_log(), vec!["thread done", "disabled"]);
        assert_eq!(acks(), 0, "disabled before the ACK came due: the enable sends it");
        e.enable_irq(42);
        assert_eq!(take_log(), vec!["ack"]);
    }

    #[test]
    fn disable_irq_in_atomic_context_or_from_its_own_thread_is_refused() {
        fn hard_disables(e: &mut Env, irq: u32, _: usize) -> IrqReturn {
            assert_eq!(e.disable_irq(irq), Err(LockError::Atomic));
            e.disable_irq_nosync(irq);
            IrqReturn::Handled
        }
        fn thread_syncs(e: &mut Env, irq: u32, _: usize) -> IrqReturn {
            assert_eq!(e.synchronize_irq(irq), Err(LockError::Deadlock));
            IrqReturn::Handled
        }
        let mut e = env(2);
        assert_eq!(e.request_irq(60, hard_disables, 0, "x", 1), 0);
        e.deliver_irq(60);
        assert_eq!(e.irqs.depth(60), Some(1), "nosync is fine in a handler");
        assert_eq!(e.stats().atomic_sleeps, 1);
        assert_eq!(e.request_threaded_irq(61, None, Some(thread_syncs), IRQF_ONESHOT, "y", 1), 0);
        e.run_once(0);
        e.deliver_irq(61);
        e.run_once(0);
        assert_eq!(e.irqs.stats().threads_run, 1);
    }

    #[test]
    fn free_irq_stops_the_thread_keeps_the_line_masked_and_a_new_request_acks_it() {
        let mut e = env(2);
        assert_eq!(e.request_threaded_irq(43, None, Some(sleeping_thread), IRQF_ONESHOT, "i2c-hid", 7), 0);
        let t = e.irqs.thread(43).unwrap();
        e.run_once(0);
        assert_eq!(e.free_irq(43, 8), None, "wrong dev_id");
        assert_eq!(e.irqs.stats().misuse, 1);
        assert_eq!(e.free_irq(43, 7), Some("i2c-hid"));
        e.run_once(0);
        assert_eq!(e.tasks.state(t), None, "the thread exited and its stack is free");
        e.deliver_irq(43);
        assert_eq!((acks(), e.irqs.stats().spurious), (0, 1), "a freed line stays masked");
        assert_eq!(e.free_irq(43, 7), None, "already free");
        assert_eq!(e.request_irq(43, handled, 0, "again", 1), 0);
        CHIP.with(|c| assert_eq!(c.borrow().binds, vec![43], "bound once"));
        assert_eq!(acks(), 1, "the new request unmasks it");
    }

    #[test]
    fn a_thread_function_woken_again_while_it_runs_runs_again() {
        let mut e = env(2);
        assert_eq!(e.request_threaded_irq(44, Some(wake), Some(sleeping_thread), 0, "x", 7), 0);
        e.run_once(0);
        e.deliver_irq(44);
        e.run_once(0);
        e.deliver_irq(44);
        e.run_once(2 * MS);
        e.run_once(2 * MS);
        e.run_once(4 * MS);
        assert_eq!(e.irqs.stats().threads_run, 2);
        // The second wake was taken while the first run slept.
        assert!(take_log().iter().filter(|s| **s == "thread").count() == 2);
    }

    #[test]
    fn unhandled_and_bad_wakes_are_counted_and_still_acked() {
        let mut e = env(1);
        assert_eq!(e.request_irq(70, not_mine, 0, "x", 1), 0);
        assert_eq!(e.request_irq(71, wake, 0, "y", 1), 0);
        e.deliver_irq(70);
        e.deliver_irq(71);
        e.deliver_irq(99);
        let s = e.irqs.stats();
        assert_eq!((s.unhandled, s.bad_wakes, s.spurious, s.acks), (1, 1, 1, 2));
    }

    #[test]
    fn a_request_without_a_free_stack_for_its_thread_fails_and_the_line_stays_free() {
        let mut e = env(0);
        assert_eq!(e.request_threaded_irq(45, None, Some(sleeping_thread), IRQF_ONESHOT, "x", 1), -ENOMEM);
        assert_eq!(e.irqs.depth(45), None);
        assert_eq!(e.request_irq(45, handled, 0, "x", 1), 0, "no thread, no stack needed");
    }
}
