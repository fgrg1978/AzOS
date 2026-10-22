// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Interrupt policy, written once for every ISA: the bracket around an
//! interrupt arm, the work every timer tick does, and the reschedule point on
//! the way out.
//!
//! The ISA keeps what only it can know: claiming and completing the
//! interrupt at its controller (`SCAUSE` + PLIC, the GIC's `IAR`/`EOIR`, the
//! LAPIC's EOI), decoding it into timer / IPI / line, and the order of the
//! re-arm against the completion.
//!
//! A handler runs on the hart's interrupt stack; `schedule()` can switch away
//! and park the task by saving `sp`, so a handler may only *raise* the
//! reschedule flag ([`Resched::request`]). The flag is spent by
//! [`resched_exit`] from the entry asm once `sp` is back on the interrupted
//! task's own stack.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::fault::fatal_note;
use super::frame::{FaultServices, Frame, IrqServices};

/// The per-CPU "an interrupt wants the scheduler" flags, and the gate that
/// keeps them unspent until the scheduler runs on the boot CPU.
pub struct Resched<const N: usize> {
    live: AtomicBool,
    need: [AtomicBool; N],
    #[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
    preempts: AtomicU64,
}

impl<const N: usize> Resched<N> {
    pub const fn new() -> Self {
        Self { live: AtomicBool::new(false), need: [const { AtomicBool::new(false) }; N], preempts: AtomicU64::new(0) }
    }

    /// Ask for a reschedule on `cpu` on the way out of the current trap.
    /// `Release` pairs with the `AcqRel` swap of the exit: the store can run
    /// on a different CPU than the swap (an IPI-driven request).
    #[inline]
    pub fn request(&self, cpu: usize) {
        if let Some(slot) = self.need.get(cpu) {
            slot.store(true, Ordering::Release);
        }
    }

    /// Spend `cpu`'s flag. Counts a preemption when it was set.
    #[inline]
    fn take(&self, cpu: usize) -> bool {
        let Some(slot) = self.need.get(cpu) else { return false };
        let was = slot.swap(false, Ordering::AcqRel);
        if was {
            self.preempts.fetch_add(1, Ordering::Relaxed);
        }
        was
    }

    /// Open the gate: from here a raised flag is spent. Set once, `Release`,
    /// just before the boot CPU enters the scheduler. Until then
    /// [`resched_exit`] leaves a raised flag raised (not dropped), so the
    /// first exit after the gate opens consumes it. Early boot unmasks IPIs
    /// long before a task exists, and a `schedule()` with no current task is
    /// the shape of the old `current_cpu_id()` anomaly.
    pub fn set_live(&self) {
        self.live.store(true, Ordering::Release);
    }

    #[inline]
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }

    /// Times an exit entered `schedule()`: the preemption marker the aarch64
    /// scheduling smoke reads.
    #[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
    pub fn preempts(&self) -> u64 {
        self.preempts.load(Ordering::Relaxed)
    }
}

impl<const N: usize> Default for Resched<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// The interrupt arm's bracket: the QSBR boundary (it leaves idle's extended
/// quiescent state; its return to user mode reports one), and the ISR depth
/// `azos_ipc` reads to notice a lock taken from an interrupt (the precondition
/// of a same-hart fast-IPC deadlock: detected, not masked against, for
/// interrupt latency). `body` decodes and handles the interrupt. Out of line:
/// the syscall path's frame must not grow with the guard's registers.
#[inline(never)]
pub fn arm<S: IrqServices<F>, F: Frame>(frame: &mut F, body: impl FnOnce(&mut F)) {
    let _guard = S::arm_guard(frame.came_from_user());
    let cpu = <S as IrqServices<F>>::cpu();
    S::isr_enter(cpu);
    body(frame);
    S::isr_exit(cpu);
}

/// The work every timer tick does after its ISA re-armed the timer: the
/// watchdog trio, the vDSO pages, the sleepers whose deadline passed, the
/// wakes stamped onto a task that parked before consuming them (a one-shot
/// wake has no second chance: the tick is its consumer of last resort).
/// `ticks`: the counter the vDSO publishes, `None` for the watchdog's own;
/// `uptime_ms`: `None` while the clock cannot say.
#[inline]
pub fn tick_work<S: IrqServices<F>, F: Frame>(now: u64, ticks: Option<u64>, uptime_ms: Option<u64>) {
    let wd = S::watchdog_tick();
    S::vdso_tick(ticks.unwrap_or(wd), uptime_ms, now);
    // `now` is 0 until this CPU's timer is armed: nothing can have expired.
    if now != 0 {
        S::wake_expired(now);
    }
    S::reap_stamped();
}

/// The reschedule point the interrupt entry asm calls after the arm, with
/// `sp` back on the interrupted task's own stack. Never from the syscall path
/// or a nested interrupt.
///
/// A loop, as Linux's `exit_to_user_mode_loop`: the task work runs again
/// after every `schedule()`, so a forced stop or a signal that arrived while
/// the task was switched out is honoured before it returns to user mode, not
/// at its next trap (a tick later, or never on a tickless CPU). The CPU is
/// read again after each switch: the task may come back on another one, and
/// spending the old CPU's flag would take that CPU's reschedule.
pub fn resched_exit<S: IrqServices<F> + FaultServices<F>, F: Frame, const N: usize>(r: &Resched<N>, frame: &mut F) {
    let mut cpu = <S as IrqServices<F>>::cpu();
    if !S::irq_stack_intact(cpu) {
        // Same ending as a kernel page fault: the motors stop before the
        // machine does. A corrupted stack is not a state to keep driving in.
        fatal_note::<S, F>(format_args!("[FATAL] Interrupt stack of cpu {} overflowed its slot", cpu));
    }
    if !r.is_live() {
        return;
    }
    let user = frame.came_from_user();
    // Lockdep: no lock held when this returns to user mode, also after a
    // switch away and back below.
    let _guard = S::exit_guard(user);
    loop {
        if user {
            S::user_return_work(frame);
        }
        if !r.take(cpu) {
            break;
        }
        S::schedule();
        cpu = <S as IrqServices<F>>::cpu();
    }
}
