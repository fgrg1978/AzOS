// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The common view of a trap frame, and the services the generic trap policy
//! asks of the kernel.
//!
//! Each ISA keeps its own native `TrapFrame` and the asm that saves it
//! (`entry/<isa>/asm/trap_entry.S`); what it adds here is the *decode*: which
//! register is the syscall number, how a cause register classifies, whether a
//! fault was a write, which signal a bad instruction earns. Everything that
//! follows from those answers (the syscall prologue, the page-fault policy, the
//! fatal tail, the interrupt bracket) is written once, in this directory, over
//! `F: Frame` and a services type `S`.
//!
//! **Why generics and not `&mut dyn`** (the older option of a
//! trait object per frame): a build has one frame type and one
//! services type, so there is one instantiation of each function and no
//! virtual call on a path measured in instructions; and the same source
//! compiles on the host against a fake frame and fake services
//! (`tests/host/trap-tests`), which a `dyn` over kernel types would not.
//!
//! This file, `syscall.rs`, `fault.rs` and `irq.rs` name nothing outside
//! `core` and `azos_abi`: everything else the policy needs is a method of
//! [`SyscallServices`], [`FaultServices`] or [`IrqServices`], implemented once
//! for the kernel in `kernel.rs`.

use core::fmt;

/// Class of trap, abstracted over the ISA-native cause encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrapClass {
    /// Hardware interrupt (timer, IPI, external).
    Interrupt,
    /// User-mode system call (`ecall` / `svc` / `syscall`).
    Syscall,
    /// Page fault or data/instruction abort.
    PageFault,
    /// Any other synchronous exception.
    OtherException,
}

/// What the report of a fatal kernel page fault is told: the generic policy
/// resolves everything that needs the kernel, the ISA lays the lines out (each
/// layout prints the fields it has a place for).
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct KernelFault {
    /// Was the faulting access a write?
    pub write: bool,
    /// The faulting virtual address.
    pub va: u64,
    /// The CPU that took the fault.
    pub cpu: usize,
    /// Is `va` in the null guard (a null pointer dereference)?
    pub null_guard: bool,
    /// Faults the system resolved silently so far: `(cow, demand)`.
    pub resolved: (u64, u64),
}

/// What the generic trap policy reads from, and writes to, a saved frame.
pub trait Frame {
    /// The ISA's name, in a fatal report.
    const ISA: &'static str;

    /// Categorise the trap (the ISA's cause decode).
    fn class(&self) -> TrapClass;

    /// Did the trap interrupt user mode (`sstatus.SPP` / `SPSR.M` / `CS.RPL`)?
    fn came_from_user(&self) -> bool;

    /// The cause as the page-fault trace record carries it (`scause`, the ESR
    /// exception class, the #PF error code).
    fn fault_cause(&self) -> u32;

    /// The faulting virtual address of a page fault.
    fn fault_addr(&self) -> u64;

    /// Was the faulting access a write?
    fn fault_is_write(&self) -> bool;

    /// The program counter of the trapped instruction.
    fn pc(&self) -> u64;

    /// The syscall number the task passed (`a7` / `x8` / `rax`).
    fn syscall_number(&self) -> u64;

    /// Syscall argument `n` (0..=5).
    fn syscall_arg(&self, n: usize) -> u64;

    /// Set the syscall's result register.
    fn set_syscall_return(&mut self, v: i64);

    /// Step over the trap instruction when the ISA leaves the PC at it
    /// (riscv64's `ecall`); nothing where the hardware already did.
    fn skip_syscall(&mut self);

    /// The exit status a user-mode exception that is not a page fault is
    /// killed with (`128 + signal`): the ISA's cause decode. `None`: not a
    /// task's fault, fatal even from user mode (x86_64's #DF and #MC,
    /// aarch64's SError and FIQ).
    fn user_kill_status(&self) -> Option<i32>;

    /// The ISA's register dump, one `warn` block headed by `what`
    /// ("user fault", "unhandled trap").
    fn print(&self, what: &str);

    /// The report of a kernel page fault, in the ISA's own layout: the gate's
    /// boot rows read these lines (`[PAGE FAULT] CPU n ... at 0x...` and
    /// `[FATAL] Kernel page fault` on riscv64, `[FATAL] <isa> kernel page fault:
    /// <kind> at 0x...` on aarch64 and x86_64) and compare the address with the
    /// probe's. The registers that find the caller (`ra sp s0` / `lr`) belong
    /// here too. Runs between `halt_begin` and `halt_report`.
    fn print_kernel_fault(&self, f: &KernelFault);
}

/// What [`SyscallServices::verdict`] decided for one number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// A native call the filter passed: dispatch it.
    Native,
    /// A Linux task's number: the personality's, not the native table's.
    Linux,
}

/// How copy-on-write resolution of a user fault ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cow {
    /// The page was copied: resume the task.
    Resolved,
    /// The task did nothing wrong; the allocator was empty.
    OutOfMemory,
    /// Not a copy-on-write fault.
    No,
}

/// What an ISA's own exception cases decided before the generic policy runs.
/// Each ISA constructs the variants its own cases need (`Kill`: x86_64's split
/// lock; `Fatal`: aarch64's failed FP trap).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Disposition {
    /// Handled: resume the trapped context.
    Resume,
    /// Nothing special: the generic policy decides.
    Default,
    /// Fatal whoever caused it.
    Fatal,
    /// Kill the current task with this exit status (`128 + signal`).
    Kill(i32),
}

/// What the syscall flow asks of the kernel (`syscall.rs`).
pub trait SyscallServices<F: Frame> {
    /// The filter's verdict, carried to the dispatch.
    type Entry;
    /// The hand-off an `exec` left for the return to user mode.
    type Exec;

    /// The `irq-in-syscall-probe` build's reserved number: its result.
    fn probe(num: u64) -> Option<u64>;
    /// Syscalls run with interrupts on once the frame is saved (owner decision O3.1).
    fn interrupts_on();
    fn census_enter();
    fn census_exit();
    /// Is the syscall trace class on?
    fn trace_on() -> bool;
    /// The entry and exit tracepoints; out of line, so the common path keeps its shape.
    fn trace_enter(num: u64, a0: u64, a1: u64);
    fn trace_exit(num: u64, ret: i64);
    /// The syscall filter's verdict on `num` for the running task: seccomp is
    /// the first thing every call meets. A denied call never returns.
    fn verdict(num: u64) -> Self::Entry;
    /// The calls answered from the number alone (`getpid`, `yield`); asked
    /// after the prologue, so they are counted like any other.
    fn shortcut(num: u64) -> Option<i64>;
    fn kind(entry: &Self::Entry) -> EntryKind;
    /// The running task's Domain takes one entry of `case` (`0`: no case) and
    /// judges it by its pledge mask bit `bit` (`azos_sched::domain::enter`):
    /// `false` when the mask refuses the call, which then does not run. A kernel
    /// task has no Domain and refuses nothing.
    fn domain_entry(num: u64, case: u8, bit: u8) -> bool;
    /// The lean IPC entry's branch: the fast path in this frame, then the dispatch.
    fn fast_or_dispatch(frame: &mut F, num: u64, entry: Self::Entry) -> i64;
    /// The ordinary dispatch (the fast path tried first).
    fn dispatch(frame: &mut F, num: u64, entry: Self::Entry) -> i64;
    fn take_exec() -> Option<Self::Exec>;
    /// Build the new image's frame; the address-space word to install.
    fn exec_enter(frame: &mut F, ctx: Self::Exec) -> u64;
    /// Signal or foreign-trap work pending for the return to user mode?
    fn return_work_pending() -> bool;
    fn return_work(frame: &mut F);
}

/// What the fault policy asks of the kernel (`fault.rs`).
pub trait FaultServices<F: Frame> {
    fn trace_fault(addr: u64, cause: u32);
    /// The running task's user page table, 0 when it has none.
    fn user_pt() -> usize;
    /// Break copy-on-write at `va`; counts a resolved fault.
    fn cow(pt: usize, va: u64) -> Cow;
    /// Demand-page `va`; counts a resolved fault.
    fn demand(pt: usize, va: u64) -> bool;
    /// Page aging's software half: set the Accessed bit the CPU did not set
    /// itself on the user leaf of `va`, so the access can be retried. Asked
    /// last, after COW and demand paging declined (a leaf this resolves is
    /// valid and permits the access, so neither of those claims it); `false`
    /// when the CPU keeps A in hardware or `va` has no such leaf.
    fn accessed(pt: usize, va: u64) -> bool;
    /// The durable record and the console line of a COW that ran out of memory.
    fn cow_oom(va: u64);
    /// Is `va` inside the null guard?
    fn in_null_guard(va: u64) -> bool;
    /// Is `va` in the area the user stack can occupy, the ceiling an image may
    /// ask for below the top of the address space? A fault there that nothing
    /// resolved is a stack that outgrew the request its image made (there is
    /// no growth), or one that never had it.
    fn in_stack_area(va: u64) -> bool;
    /// Rate limit on the console report of a user fault (the kill is not limited).
    fn user_fault_report() -> bool;
    fn warn(args: fmt::Arguments<'_>);
    fn error(args: fmt::Arguments<'_>);
    fn cpu() -> usize;
    fn tid() -> u32;
    fn task_name() -> &'static str;
    /// Kill the running task with `status`; never returns.
    fn kill(status: i32) -> !;
    /// A fault is about to kill the running ring-3 task with `status`: leave
    /// the minidump of what it was doing (Kconfig `CRASHDUMP`), while its
    /// page table and capability table still exist. Never blocks and does no
    /// I/O; the default leaves nothing (the host fakes of `trap-tests`).
    fn crashdump(_frame: &F, _status: i32) {}
    /// Faults the system resolved silently so far: `(cow, demand)`.
    fn resolved() -> (u64, u64);
    /// The running task's Domain's kernel entries so far, by case (slot 0: no
    /// case, then authority, block or wake): what a task did with the kernel
    /// before it died.
    fn entries() -> [u64; 3];
    /// First on the fatal path: bypass the console owner and other CPUs' lines.
    fn halt_begin();
    fn halt_report();
    /// The trace buffer's last records, before dying.
    fn trace_dump();
    /// The first thing a fatal path does: stop the actuators. A runaway does
    /// not wait for the console.
    fn stop_actuators();
    /// Mark the system panicked (every other CPU's timer interrupt then parks
    /// itself without feeding the watchdog) and shut down.
    fn fatal_halt() -> !;
    /// The ISA's own cases of a page fault (a probe's one load): handled?
    fn arch_page_fault(frame: &mut F) -> bool;
    /// The ISA's own cases of an exception, before the generic policy.
    fn arch_exception(frame: &mut F) -> Disposition;
}

/// What the interrupt bracket, the tick and the reschedule point ask of the
/// kernel (`irq.rs`).
pub trait IrqServices<F: Frame> {
    /// The QSBR boundary of an interrupt, held across the arm.
    type ArmGuard;
    fn arm_guard(user: bool) -> Self::ArmGuard;
    /// The same boundary plus lockdep's "no lock held at the return to user
    /// mode", held across the reschedule point.
    type ExitGuard;
    fn exit_guard(user: bool) -> Self::ExitGuard;
    fn cpu() -> usize;
    /// Does `cpu`'s interrupt stack still carry its magic word? A .bss stack
    /// has no guard page: an overflow would quietly eat the slot below and
    /// surface as another CPU's corruption. `true` on an ISA that keeps none.
    fn irq_stack_intact(cpu: usize) -> bool;
    fn isr_enter(cpu: usize);
    fn isr_exit(cpu: usize);
    /// The watchdog trio of a timer tick (count, halt if panicked, feed); the
    /// watchdog's tick count.
    fn watchdog_tick() -> u64;
    /// The vDSO pages (`ticks`, the uptime in ms) when the clock allows it.
    fn vdso_tick(ticks: u64, uptime_ms: Option<u64>, now: u64);
    fn wake_expired(now: u64);
    fn reap_stamped();
    /// Forced stop and Linux signals, at the return to user mode on the
    /// task's own stack (a task parked from the interrupt stack would resume
    /// on frames the next interrupt overwrote).
    fn user_return_work(frame: &mut F);
    fn schedule();
}
