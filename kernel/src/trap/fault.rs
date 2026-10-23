// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Page-fault, exception and fatal-fault policy, written once for every ISA.
//!
//! The rule is the same everywhere: **a fault from user mode kills that task
//! and never the kernel; a fault from the kernel is fatal.** A page fault
//! first tries copy-on-write (a write), then demand paging; only what neither
//! resolves is reported and ends the task (`SIGSEGV`). Any other synchronous
//! exception from user mode ends the task with the signal the ISA's cause
//! decode names ([`Frame::user_kill_status`]); one the ISA says is no task's
//! fault, and any from the kernel, takes the fatal tail.
//!
//! The ISA keeps only its own special cases ([`FaultServices::arch_page_fault`],
//! [`FaultServices::arch_exception`]: x86_64's NMI and split-lock, riscv64's
//! first FP use and transactional rollback, aarch64's FP trap and the
//! transactional rollback of an EL1 Alignment fault, which arrives as a data
//! abort) and the register dump of its frame ([`Frame::print`]).

use core::fmt;

use azos_abi::exit_status as es;

use super::frame::{Cow, Disposition, FaultServices, Frame, KernelFault};

/// The console report of a user task killed by an unresolved page fault: the
/// banner, what else is worth knowing, and the kill. Exactly two lines carry
/// `PAGE FAULT` (the gate counts them against its kills). The kill and its
/// exit status are not rate limited; the report is
/// ([`FaultServices::user_fault_report`]).
#[inline(never)]
fn report_user_fault<S: FaultServices<F>, F: Frame>(frame: &F, va: u64, write: bool) {
    if !S::user_fault_report() {
        return;
    }
    S::warn(format_args!(""));
    S::warn(format_args!(
        "[PAGE FAULT] CPU {} - {} at {:#x} (pc={:#x}, tid={}, task={})",
        S::cpu(), if write { "write" } else { "read/exec" }, va, frame.pc(), S::tid(), S::task_name()));
    if S::in_null_guard(va) {
        S::warn(format_args!("  null guard: this VA is never mapped (null pointer dereference)"));
    }
    if S::in_stack_area(va) {
        S::warn(format_args!("  stack: below the stack this image asked for (it has no room to grow; \
                              its PT_GNU_STACK header sizes it, -z stack-size)"));
    }
    let (cow, demand) = S::resolved();
    S::warn(format_args!("  resolved so far: {} COW, {} demand", cow, demand));
    let e = S::entries();
    S::warn(format_args!("  kernel entries so far: {} authority, {} block/wake, {} other",
        e[1], e[2], e[0]));
    S::warn(format_args!("[PAGE FAULT] Killing user task"));
}

/// The kill of a user task a fault ended: its minidump first
/// ([`FaultServices::crashdump`], for a trap that came from ring 3), then the
/// kill, which tears the task down.
/// The one place a fault kills a task, so no kill goes without its dump.
fn kill_user<S: FaultServices<F>, F: Frame>(frame: &F, status: i32) -> ! {
    // Only what ring 3 did: an ISA's own kill can come from the kernel's frame
    // (a split lock in a system call), whose registers are the kernel's.
    if frame.came_from_user() {
        S::crashdump(frame, status);
    }
    S::kill(status)
}

/// The fatal tail every unrecoverable trap shares: stop the actuators, stop
/// console contention, say what happened, dump the trace, then mark the system
/// panicked and shut down (`set_panicked` first: every other CPU's timer
/// interrupt then parks itself without feeding the watchdog).
#[cold]
#[inline(never)]
fn fatal<S: FaultServices<F>, F: Frame>(frame: &F, what: &str, fault: Option<KernelFault>) -> ! {
    S::stop_actuators();
    S::halt_begin();
    match fault {
        // A kernel page fault: where, and who called.
        Some(f) => frame.print_kernel_fault(&f),
        None => {
            frame.print(what);
            S::error(format_args!("[FATAL] {}: {} on cpu {} - shutdown", F::ISA, what, S::cpu()));
        }
    }
    S::halt_report();
    // Last chance for debugging: the trace buffer.
    S::trace_dump();
    S::fatal_halt()
}

/// A fatal condition that is not a trap's own (an interrupt stack that
/// overflowed its slot): the same tail, with `args` as the report.
#[cold]
#[inline(never)]
pub fn fatal_note<S: FaultServices<F>, F: Frame>(args: fmt::Arguments<'_>) -> ! {
    S::stop_actuators();
    S::halt_begin();
    S::error(args);
    S::halt_report();
    S::fatal_halt()
}

/// The page-fault arm of every trap (`TrapClass::PageFault`).
pub fn page_fault<S: FaultServices<F>, F: Frame>(frame: &mut F) {
    let va = frame.fault_addr();
    let write = frame.fault_is_write();
    // The fault class's tracepoint, on EVERY fault, resolved or not.
    S::trace_fault(va, frame.fault_cause());
    if S::arch_page_fault(frame) {
        return;
    }
    if frame.came_from_user() {
        // Resolve first, report only what could NOT be resolved: nearly every
        // fault is a COW break after `fork` that resolves, and a banner for
        // each of those reads exactly like a crash.
        let pt = S::user_pt();
        if pt != 0 {
            if write {
                match S::cow(pt, va) {
                    Cow::Resolved => return,
                    // The one failure where the program did nothing wrong:
                    // its own page after its own fork and an empty allocator.
                    // The task still dies (a trap has no return value to
                    // hand ring 3), but the log stops blaming a pointer.
                    Cow::OutOfMemory => S::cow_oom(va),
                    Cow::No => {}
                }
            }
            if S::demand(pt, va) {
                return;
            }
            // A page the aging scan cleared A on, touched again on a CPU that
            // does not set A itself (Svade, an aarch64 core without HAFDBS):
            // the leaf is valid and allows the access, so COW and demand paging
            // declined it above. Set A and retry; anything else is a real fault.
            if S::accessed(pt, va) {
                return;
            }
        }
        report_user_fault::<S, F>(frame, va, write);
        kill_user::<S, F>(frame, es::KILLED_SEGV);
    }
    let fault = KernelFault {
        write,
        va,
        cpu: S::cpu(),
        null_guard: S::in_null_guard(va),
        resolved: S::resolved(),
    };
    fatal::<S, F>(frame, "kernel page fault", Some(fault))
}

/// Any other synchronous exception (`TrapClass::OtherException`).
pub fn exception<S: FaultServices<F>, F: Frame>(frame: &mut F) {
    match S::arch_exception(frame) {
        Disposition::Resume => return,
        Disposition::Kill(status) => kill_user::<S, F>(frame, status),
        Disposition::Fatal => fatal::<S, F>(frame, "unhandled trap", None),
        Disposition::Default => {}
    }
    if frame.came_from_user() {
        if let Some(status) = frame.user_kill_status() {
            // Ring 3 executed something it had no business executing: kill
            // just that task. Deliberately no motor stop: the control loop is
            // still running and did not ask for one.
            if S::user_fault_report() {
                frame.print("user fault");
                S::warn(format_args!("[TRAP] Killing user task '{}' (tid {})", S::task_name(), S::tid()));
            }
            kill_user::<S, F>(frame, status);
        }
    }
    fatal::<S, F>(frame, "unhandled trap", None)
}
