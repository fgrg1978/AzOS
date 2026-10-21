// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's implementation of the trap services: the one place the
//! generic trap policy (`syscall.rs`, `fault.rs`, `irq.rs`) meets the
//! scheduler, the memory manager, the tracer and the console.
//!
//! [`ArchFrame`] is what an ISA adds to [`Frame`] for the parts of the flow
//! that name kernel types: how the IPC fast path reads the frame's registers,
//! how the argument list and the fork snapshot are built from it, how an
//! `exec`'s new frame is laid out, how signals are delivered into it.

use core::fmt;

use azos_syscall::SyscallEntry;

use super::frame::{Cow, Disposition, EntryKind, FaultServices, Frame, IrqServices, SyscallServices};
use super::irq::Resched;

/// What an ISA adds to [`Frame`] for the kernel-typed half of the trap flow.
pub(crate) trait ArchFrame: Frame + Sized {
    /// The IPC fast path's view of this frame: arguments in, extra results out,
    /// and the resume stub.
    type Ipc<'a>: azos_syscall::fastpath::IpcRegs
    where
        Self: 'a;
    fn ipc(&mut self) -> Self::Ipc<'_>;

    /// Does a fork need a snapshot built from the frame? `false`: the frame's
    /// own register file is handed over as it is (riscv64).
    const SNAPSHOT_REGS: bool;

    /// The six argument registers.
    fn syscall_args(&self) -> [u64; 6];
    /// The user stack pointer at the trap.
    fn user_sp(&self) -> u64;
    /// Run `f` with the register file the fork arms read: built from the frame
    /// when `wanted` (only the calls that read it pay for it: the aarch64
    /// snapshot is 528 bytes of FP state, and copying it on every call cost
    /// the syscall floor 413 -> 708 instructions), else a static zero set.
    fn with_user_regs<R>(&self, wanted: bool, f: impl FnOnce(&azos_sched::UserRegs) -> R) -> R;
    /// Write the extra result registers `a1..a6` (`x1..x6`, `rdx rsi rdi r8 r9 r10`).
    /// Only arms that fill them are copied back: userspace may assume the
    /// others survive the call.
    fn write_out(&mut self, regs: &[u64; 6]);
    /// The frame an `exec` enters its new image through: the entry point, a
    /// user stack, every other register zero (the old image's must not reach
    /// a new image bound to another filter and row). The address-space word
    /// to install.
    fn exec_enter(&mut self, ctx: &azos_sched::ExecHandoff) -> u64;
    /// Deliver the signals (or apply the `rt_sigreturn`) of the current task
    /// at its return to user mode, from a syscall or from an interrupt, and
    /// finish a foreign-ABI trap its dispatch left pending. Out of line and not
    /// cold: a cold callee reshapes the hot caller.
    fn deliver_work(&mut self, from_syscall: bool);
    /// Does `cpu`'s interrupt stack still carry its magic word (riscv64's)?
    fn irq_stack_intact(_cpu: usize) -> bool {
        true
    }
    /// A diagnostic hook for a reserved syscall number (`irq-in-syscall-probe`).
    fn probe(_num: u64) -> Option<u64> {
        None
    }
    /// The ISA's own cases of a page fault (a probe's one load): handled?
    fn arch_page_fault(&mut self) -> bool {
        false
    }
    /// The ISA's own cases of an exception, before the generic policy.
    fn arch_exception(&mut self) -> Disposition {
        Disposition::Default
    }
}

/// The reschedule flags of this kernel's CPUs, and the gate that keeps them
/// unspent until the boot CPU enters the scheduler.
pub static RESCHED: Resched<{ crate::MAX_HARTS }> = Resched::new();

/// The kernel, as the services of the trap policy.
pub struct Kernel;

// ── Syscalls ────────────────────────────────────────────────────────────────

impl<F: ArchFrame> SyscallServices<F> for Kernel {
    type Entry = SyscallEntry;
    type Exec = azos_sched::ExecHandoff;

    #[inline(always)]
    fn probe(num: u64) -> Option<u64> {
        F::probe(num)
    }

    #[inline(always)]
    fn interrupts_on() {
        use azos_arch::Interrupts;
        azos_arch::ARCH.enable_all();
    }

    #[inline(always)]
    fn census_enter() {
        azos_sched::swcensus::ecall_enter();
    }

    #[inline(always)]
    fn census_exit() {
        azos_sched::swcensus::ecall_exit();
    }

    #[inline(always)]
    fn trace_on() -> bool {
        azos_trace::syscall_on()
    }

    #[inline(never)]
    fn trace_enter(num: u64, a0: u64, a1: u64) {
        azos_trace::raw::sys_enter(num as u32, azos_sched::current_task_tid(), a0, a1);
    }

    #[inline(never)]
    fn trace_exit(num: u64, ret: i64) {
        azos_trace::raw::sys_exit(num as u32, azos_sched::current_task_tid(), ret);
    }

    #[inline(always)]
    fn verdict(num: u64) -> SyscallEntry {
        azos_syscall::syscall_verdict(num)
    }

    #[inline(always)]
    fn shortcut(num: u64) -> Option<i64> {
        match azos_syscall::syscall_register_only(num) {
            SyscallEntry::Done(r) => Some(r),
            _ => None,
        }
    }

    #[inline(always)]
    fn kind(entry: &SyscallEntry) -> EntryKind {
        match entry {
            // `syscall_verdict` never answers a call.
            SyscallEntry::Done(_) | SyscallEntry::Native => EntryKind::Native,
            SyscallEntry::Linux => EntryKind::Linux,
        }
    }

    #[inline(always)]
    fn domain_entry(num: u64, case: u8, bit: u8) -> bool {
        match azos_sched::current_task_slot() {
            Some((idx, tid)) => azos_sched::domain::enter(azos_sched::task_domain(idx), tid, num, case, bit),
            None => true,
        }
    }

    /// The lean entry's IPC branch: the fast path in the caller's own frame,
    /// no frame between, then on a miss the ordinary dispatch without its own
    /// try ([`dispatch`]`::<false>`): nothing is done twice.
    #[inline(always)]
    fn fast_or_dispatch(frame: &mut F, num: u64, entry: SyscallEntry) -> i64 {
        if azos_syscall::fastpath::wants(num) && matches!(entry, SyscallEntry::Native) {
            if let Some(r) = azos_syscall::fastpath::entry(num, &mut frame.ipc()) {
                return r;
            }
        }
        dispatch::<F, false>(frame, num, entry)
    }

    #[inline(always)]
    fn dispatch(frame: &mut F, num: u64, entry: SyscallEntry) -> i64 {
        dispatch::<F, true>(frame, num, entry)
    }

    #[inline(always)]
    fn take_exec() -> Option<azos_sched::ExecHandoff> {
        azos_sched::take_current_task_exec_ctx()
    }

    /// Out of line and cold: it runs once per exec, and the flow's tail is
    /// every syscall's.
    #[cold]
    #[inline(never)]
    fn exec_enter(frame: &mut F, ctx: azos_sched::ExecHandoff) -> u64 {
        frame.exec_enter(&ctx)
    }

    #[inline(always)]
    fn return_work_pending() -> bool {
        azos_limits::LINUX_ABI && azos_sched::scheduler::signal::work_pending()
    }

    #[inline(never)]
    fn return_work(frame: &mut F) {
        frame.deliver_work(true);
    }
}

/// Everything a syscall the filter did not answer needs: its arguments, the
/// out-parameter and the copy-back of the extra result registers. Out of line
/// so the common path keeps its frame (SYSFLOOR). `TRY_FAST`: the IPC fast
/// path first (every caller but the lean entry's IPC branch, which tried it).
#[inline(never)]
fn dispatch<F: ArchFrame, const TRY_FAST: bool>(frame: &mut F, num: u64, entry: SyscallEntry) -> i64 {
    // Kconfig IPC_FASTPATH: a fast call or reply whose peer is parked is
    // finished here, after the filter verdict and before the table; `None`
    // means nothing was done.
    if TRY_FAST && azos_syscall::fastpath::wants(num) && matches!(entry, SyscallEntry::Native) {
        if let Some(r) = azos_syscall::fastpath::entry(num, &mut frame.ipc()) {
            return r;
        }
    }
    // Only the fork arms read the register file (a Linux task's `clone`
    // forks through the same snapshot): any new reader must be added here or
    // it reads zeroes.
    let wants = F::SNAPSHOT_REGS
        && (azos_syscall::foreign::needs_user_regs(num)
            || (azos_limits::LINUX_ABI
                && num == azos_linux_abi::nr::CLONE
                && azos_sched::scheduler::current_is_linux()));
    let [a0, a1, a2, a3, a4, a5] = frame.syscall_args();
    let (pc, sp) = (frame.pc(), frame.user_sp());
    let mut out = azos_syscall::SyscallOut::new();
    let result = frame.with_user_regs(wants, |regs| {
        azos_syscall::syscall_dispatch_checked(entry, num, a0, a1, a2, a3, a4, a5, pc, sp, regs, &mut out)
    });
    if out.written {
        frame.write_out(&out.regs);
    }
    result
}

// ── Faults ──────────────────────────────────────────────────────────────────

/// Console reports of user tasks killed by a fault: a burst of 10 per 5 s,
/// then one line counting what was dropped (Linux's `printk_ratelimit`
/// defaults). A program that faults in a loop would otherwise fill the
/// console. Only the report: the kill, the exit status and every record
/// still happen each time.
static USER_FAULT_REPORTS: azos_drv_sys::ratelimit::RateLimit = azos_drv_sys::ratelimit::RateLimit::new(10, 5);

/// End the running task with exit status `status` (`128 + signal`); the one
/// kill the trap layer has, for the policy and for an ISA whose frame decode
/// fails (a signal frame the stack cannot take).
pub fn kill(status: i32) -> ! {
    azos_sched::scheduler::task_exit_by_signal(status)
}

/// Whether this user-fault report prints; prints the suppressed count first
/// when reports were dropped since the last one. Out of line: the report is on
/// no hot path, and the callers are.
#[inline(never)]
pub fn user_fault_report() -> bool {
    match USER_FAULT_REPORTS.check() {
        Some(0) => true,
        Some(k) => {
            azos_drv_sys::kwarn!("[FAULT] {} user-task fault report(s) suppressed", k);
            true
        }
        None => false,
    }
}

impl<F: ArchFrame> FaultServices<F> for Kernel {
    #[inline(always)]
    fn trace_fault(addr: u64, cause: u32) {
        if azos_trace::fault_on() {
            azos_trace::raw::page_fault(addr, cause, azos_sched::current_task_tid());
        }
    }

    #[inline(always)]
    fn user_pt() -> usize {
        azos_sched::current_user_pt()
    }

    fn cow(pt: usize, va: u64) -> Cow {
        match azos_mm::vmm::handle_cow_fault(pt, va as usize) {
            Ok(()) => {
                azos_mm::vmm::note_cow_resolved();
                Cow::Resolved
            }
            Err(azos_common::error::KernelError::OutOfMemory) => Cow::OutOfMemory,
            Err(_) => Cow::No,
        }
    }

    fn demand(pt: usize, va: u64) -> bool {
        if azos_mm::vmm::handle_demand_fault(pt, va as usize).is_ok() {
            azos_mm::vmm::note_demand_resolved();
            true
        } else {
            false
        }
    }

    fn accessed(pt: usize, va: u64) -> bool {
        azos_mm::vmm::handle_accessed_fault(pt, va as usize)
    }

    fn cow_oom(va: u64) {
        azos_drv_sys::kerr!();
        azos_drv_sys::kerr!("[PAGE FAULT] OUT OF MEMORY breaking copy-on-write at {:#x} - the task did nothing \
                             wrong; the page allocator is empty", va);
        azos_drv_sys::kerr!("  task: {} (tid {})", azos_sched::current_task_name(), azos_sched::current_task_tid());
        // Durable, like every other safety event: a console line is gone by
        // the time anyone asks why a task vanished. `action_code` names the
        // SITE: 0 = the page-fault arm of the trap policy.
        let _ = azos_actuation::logger::log_safety_violation_durable(
            azos_actuation::logger::SAFETY_COW_OOM,
            0,
            va as u32,
        );
    }

    fn in_null_guard(va: u64) -> bool {
        azos_mm::vmm::in_null_guard(va as usize)
    }

    fn in_stack_area(va: u64) -> bool {
        azos_sched::process::in_stack_area(va as usize)
    }

    #[inline(always)]
    fn user_fault_report() -> bool {
        user_fault_report()
    }

    fn warn(args: fmt::Arguments<'_>) {
        azos_drv_sys::kwarn!("{}", args);
    }

    fn error(args: fmt::Arguments<'_>) {
        azos_drv_sys::kerr!("{}", args);
    }

    fn cpu() -> usize {
        azos_sched::smp::current_cpu_id()
    }

    fn tid() -> u32 {
        azos_sched::current_task_tid()
    }

    fn task_name() -> &'static str {
        azos_sched::current_task_name()
    }

    fn kill(status: i32) -> ! {
        kill(status)
    }

    #[inline(never)]
    fn crashdump(frame: &F, status: i32) {
        #[cfg(feature = "crashdump")]
        super::crash::capture(frame, status);
        #[cfg(not(feature = "crashdump"))]
        let _ = (frame, status);
    }

    fn resolved() -> (u64, u64) {
        azos_mm::vmm::faults_resolved()
    }

    fn entries() -> [u64; 3] {
        match azos_sched::current_task_slot() {
            Some((idx, _)) => azos_sched::domain::entries(azos_sched::task_domain(idx)),
            None => [0; 3],
        }
    }

    fn halt_begin() {
        crate::panic::halt_begin();
    }

    fn halt_report() {
        crate::panic::halt_report();
    }

    fn trace_dump() {
        azos_ipc::trace_dump(20);
    }

    fn stop_actuators() {
        #[cfg(feature = "use-robot")]
        azos_robot::motor_cmd_zero();
    }

    /// `set_panicked` first: `watchdog::halt_if_panicked` runs in every
    /// hart's own timer interrupt and, once the flag is visible, that hart
    /// stops its own actuators and parks itself WITHOUT feeding the watchdog,
    /// so any hart still running is brought down even if the shutdown has
    /// firmware latency before power is cut.
    fn fatal_halt() -> ! {
        use azos_arch::Boot;
        azos_common::set_panicked();
        azos_arch::ARCH.shutdown()
    }

    #[inline(always)]
    fn arch_page_fault(frame: &mut F) -> bool {
        frame.arch_page_fault()
    }

    #[inline(always)]
    fn arch_exception(frame: &mut F) -> Disposition {
        frame.arch_exception()
    }
}

// ── Interrupts ──────────────────────────────────────────────────────────────

impl<F: ArchFrame> IrqServices<F> for Kernel {
    type ArmGuard = azos_sync::qsbr::TrapBoundary;
    type ExitGuard = (azos_sync::lockdep::UserReturn, azos_sync::qsbr::TrapBoundary);

    #[inline(always)]
    fn arm_guard(user: bool) -> Self::ArmGuard {
        azos_sync::qsbr::TrapBoundary::irq(|| user)
    }

    #[inline(always)]
    fn exit_guard(user: bool) -> Self::ExitGuard {
        (azos_sync::lockdep::UserReturn::arm(|| user), azos_sync::qsbr::TrapBoundary::irq(|| user))
    }

    #[inline(always)]
    fn cpu() -> usize {
        azos_sched::smp::current_cpu_id()
    }

    #[inline(always)]
    fn irq_stack_intact(cpu: usize) -> bool {
        F::irq_stack_intact(cpu)
    }

    #[inline(always)]
    fn isr_enter(cpu: usize) {
        azos_sync::isr_depth::enter(cpu);
    }

    #[inline(always)]
    fn isr_exit(cpu: usize) {
        azos_sync::isr_depth::exit(cpu);
    }

    /// Count, then halt BEFORE feeding: a panicked hart must stop its
    /// actuators and park without kicking the watchdog, so the board resets
    /// cleanly instead of being kept alive by this interrupt.
    fn watchdog_tick() -> u64 {
        let ticks = azos_actuation::watchdog::tick();
        azos_actuation::watchdog::halt_if_panicked();
        azos_actuation::watchdog::feed_from_timer_tick();
        ticks
    }

    fn vdso_tick(ticks: u64, uptime_ms: Option<u64>, now: u64) {
        if let Some(ms) = uptime_ms {
            azos_mm::vdso::vdso_update(ticks, ms);
            // The running task's own vDSO page, if it mapped one.
            azos_syscall::vdso_notify::vdso_task_tick(now);
        }
    }

    fn wake_expired(now: u64) {
        azos_sched::wake_expired_timers(now);
    }

    fn reap_stamped() {
        azos_sched::reap_stamped_sleepers();
    }

    fn user_return_work(frame: &mut F) {
        // A task told to stop (`SYS_ALERT` force) that computes
        // without a syscall ends here, a safe point: it holds no kernel lock
        // and no console. One load when no forced stop is pending anywhere.
        if azos_sched::scheduler::forced_stop_pending() {
            azos_sched::scheduler::exit_if_forced();
        }
        // A Linux task computing without a syscall takes its signal here.
        if azos_limits::LINUX_ABI && azos_sched::scheduler::signal::work_pending() {
            frame.deliver_work(false);
        }
    }

    fn schedule() {
        azos_sched::schedule();
    }
}

// ── Work every ISA's interrupt arms share ───────────────────────────────────

impl Kernel {
    /// An inter-processor interrupt's first work, on every ISA. The panic
    /// handler's stop IPI (Kconfig PANIC_QUIESCE) is this same doorbell: once
    /// the kernel has panicked, park here (never returns, no EOI owed). Then
    /// queue the wakes another CPU left for this one (`SCHED_REMOTE_WAKE_DEFER`:
    /// its try of our queue lock failed). One load each when there are none.
    #[inline]
    pub fn ipi_work() {
        azos_actuation::watchdog::halt_if_panicked();
        azos_sched::scheduler::drain_remote_wakes();
    }

    /// The console UART's interrupt: empty the FIFO into the ring the readers
    /// use, deliver `^C` to a Linux job holding the console, and wake the
    /// reader parked on input (a TID wake of a `Timer` sleeper, which stamps a
    /// task not yet blocked, so the arm-then-retest in `readline` has no lost
    /// wakeup window). `(rx, woke)`: whether the UART had receive work, and
    /// whether a task was made ready.
    pub fn console_rx() -> (bool, bool) {
        if !azos_drv_sys::uart::irq_handler() {
            return (false, false);
        }
        if azos_drv_sys::uart::take_intr() {
            azos_syscall::linux::console_signal(2);
        }
        let tid = azos_drv_sys::uart::rx_waiter_take();
        let woke = tid != 0
            && azos_sched::scheduler::wake_task_by_tid(tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
        (true, woke)
    }
}
