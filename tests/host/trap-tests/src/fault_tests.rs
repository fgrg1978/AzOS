// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The page-fault and exception policy (`kernel/src/trap/fault.rs`) on the
//! three ISAs' frames. The rule under test: a fault from user mode kills that
//! task and never the kernel; a fault from the kernel is fatal.

use crate::fakes::*;
use crate::trap::fault::{exception, page_fault};
use crate::trap::frame::{Cow, Disposition, Frame};
use azos_abi::exit_status as es;

fn pf<F: Frame>(f: &mut F) -> Ended {
    ends(|| page_fault::<Fake, F>(f))
}

fn ex<F: Frame>(f: &mut F) -> Ended {
    ends(|| exception::<Fake, F>(f))
}

fn rv_fault(user: bool, write: bool, va: u64) -> RvFrame {
    RvFrame { scause: if write { 15 } else { 13 }, stval: va, sepc: 0x1234, s_mode: !user, ..Default::default() }
}

fn arm_fault(user: bool, write: bool, va: u64) -> ArmFrame {
    ArmFrame { esr: (if user { 0x24 } else { 0x25 } << 26) | (write as u64) << 6, far: va, elr: 0x1234, el1: !user, ..Default::default() }
}

fn x86_fault(user: bool, write: bool, va: u64) -> X86Frame {
    X86Frame { vector: X86Frame::PF, error_code: (write as u64) << 1, cr2: va, rip: 0x1234, cs: if user { 3 } else { 0 }, ..Default::default() }
}

macro_rules! on_each_isa {
    ($user:expr, $write:expr, $va:expr, |$f:ident| $body:expr) => {{
        { reset(); let mut $f = rv_fault($user, $write, $va); $body; }
        { reset(); let mut $f = arm_fault($user, $write, $va); $body; }
        { reset(); let mut $f = x86_fault($user, $write, $va); $body; }
    }};
}

/// **Nearly every fault is a COW break after `fork`: resolved silently, no
/// banner, no demand attempt, the task resumes.**
#[test]
fn a_resolved_cow_break_is_silent() {
    on_each_isa!(true, true, 0x5000, |f| {
        with(|s| s.cow = vec![Cow::Resolved]);
        assert!(matches!(pf(&mut f), Ended::Returned));
        assert!(saw("cow 0x8000 0x5000"));
        assert!(!saw("demand 0x"), "{:?}", logged());
        assert!(!saw("warn"), "a resolved fault prints nothing: {:?}", logged());
        assert!(saw("trace_fault 0x5000"), "the fault class traces every fault, resolved or not");
    });
}

#[test]
fn a_read_fault_never_tries_cow_and_demand_paging_resolves_it() {
    on_each_isa!(true, false, 0x6000, |f| {
        with(|s| s.demand_ok = true);
        assert!(matches!(pf(&mut f), Ended::Returned));
        assert!(!saw("cow 0x"), "{:?}", logged());
        assert!(saw("demand 0x8000 0x6000"));
    });
}

/// **A page the aging scan cleared A on, touched again on a CPU that does not
/// set A itself, is resolved after COW and demand paging decline it: the task
/// resumes, nothing is printed.** A write fault asks COW first and demand
/// second, so a COW page still breaks as before.
#[test]
fn an_accessed_fault_is_resolved_last_and_silently() {
    for write in [false, true] {
        on_each_isa!(true, write, 0x7000, |f| {
            with(|s| s.accessed_ok = true);
            assert!(matches!(pf(&mut f), Ended::Returned));
            let log = logged();
            let at = |what: &str| log.iter().position(|l| l.starts_with(what));
            assert!(at("demand 0x").unwrap() < at("accessed 0x8000 0x7000").unwrap(), "{log:?}");
            if write {
                assert!(at("cow 0x").unwrap() < at("accessed 0x").unwrap(), "{log:?}");
            }
            assert!(!saw("warn") && !saw("kill"), "{log:?}");
        });
    }
}

/// **A COW break or a demand page that resolves never asks about A, and a
/// fault from the kernel never does either** (the kernel reads user frames
/// through its own map, so it cannot take an Access Flag fault).
#[test]
fn the_accessed_walk_is_not_asked_when_something_else_resolved_the_fault() {
    on_each_isa!(true, true, 0x5000, |f| {
        with(|s| { s.cow = vec![Cow::Resolved]; s.accessed_ok = true; });
        assert!(matches!(pf(&mut f), Ended::Returned));
        assert!(!saw("accessed 0x"), "{:?}", logged());
    });
    on_each_isa!(true, false, 0x6000, |f| {
        with(|s| { s.demand_ok = true; s.accessed_ok = true; });
        assert!(matches!(pf(&mut f), Ended::Returned));
        assert!(!saw("accessed 0x"), "{:?}", logged());
    });
    on_each_isa!(false, false, 0x9000, |f| {
        with(|s| s.accessed_ok = true);
        assert!(matches!(pf(&mut f), Ended::Halted));
        assert!(!saw("accessed 0x"), "{:?}", logged());
    });
}

/// **What neither COW nor demand paging resolves is reported and ends the task
/// with SIGSEGV; the report names the address, the PC and the TID.**
#[test]
fn an_unresolved_user_fault_kills_the_task_with_sigsegv() {
    on_each_isa!(true, true, 0x7000, |f| {
        assert!(matches!(pf(&mut f), Ended::Killed(s) if s == es::KILLED_SEGV));
        let w = logged().into_iter().find(|l| l.contains("[PAGE FAULT]")).expect("a report");
        assert!(w.contains("write at 0x7000") && w.contains("pc=0x1234") && w.contains("tid=42"), "{w}");
        // The gate counts a kill as exactly two `PAGE FAULT` lines, the second
        // of them `[PAGE FAULT] Killing user task`.
        let lines: Vec<String> = logged().into_iter().filter(|l| l.contains("PAGE FAULT")).collect();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[1].ends_with("[PAGE FAULT] Killing user task"), "{lines:?}");
        assert!(at("[PAGE FAULT] Killing user task").unwrap() < at("kill ").unwrap(), "the report precedes the kill");
        assert!(saw("resolved so far: 7 COW, 9 demand"), "the silent traffic stays visible: {:?}", logged());
        assert!(saw("kernel entries so far: 1 authority, 2 block/wake, 5 other"),
            "what the task did with the kernel before it died: {:?}", logged());
        assert!(!saw("halt_begin") && !saw("fatal_halt"), "a task's fault is never the kernel's");
    });
}

#[test]
fn a_null_dereference_says_so() {
    on_each_isa!(true, false, 0x8, |f| {
        assert!(matches!(pf(&mut f), Ended::Killed(_)));
        assert!(saw("null guard"), "{:?}", logged());
    });
}

/// A fault in the area a stack can occupy that nothing resolved is a stack that
/// outgrew what its image asked for (there is no growth): the report says so,
/// and a fault anywhere else in user space does not.
#[test]
fn a_fault_below_the_stack_says_so() {
    on_each_isa!(true, true, 0x7fff_b670, |f| {
        assert!(matches!(pf(&mut f), Ended::Killed(_)));
        assert!(saw("below the stack this image asked for"), "{:?}", logged());
    });
    on_each_isa!(true, false, 0x9000, |f| {
        assert!(matches!(pf(&mut f), Ended::Killed(_)));
        assert!(!saw("below the stack"), "{:?}", logged());
    });
}

/// The report is rate limited; the kill and its status are not.
#[test]
fn a_suppressed_report_still_kills() {
    on_each_isa!(true, false, 0x9000, |f| {
        with(|s| s.report = false);
        assert!(matches!(pf(&mut f), Ended::Killed(s) if s == es::KILLED_SEGV));
        assert!(!saw("warn"), "{:?}", logged());
    });
}

/// **A COW that ran out of memory is not a pointer bug: the log says so and
/// leaves a durable record, and the task still dies.**
#[test]
fn a_cow_out_of_memory_is_named_and_the_task_still_dies() {
    on_each_isa!(true, true, 0xA000, |f| {
        with(|s| s.cow = vec![Cow::OutOfMemory]);
        assert!(matches!(pf(&mut f), Ended::Killed(s) if s == es::KILLED_SEGV));
        assert!(saw("cow_oom 0xa000"), "{:?}", logged());
    });
}

#[test]
fn a_task_with_no_page_table_is_killed_without_a_resolution_attempt() {
    on_each_isa!(true, true, 0xB000, |f| {
        with(|s| s.user_pt = 0);
        assert!(matches!(pf(&mut f), Ended::Killed(_)));
        assert!(!saw("cow 0x") && !saw("demand 0x"), "{:?}", logged());
    });
}

/// **A fault from the kernel is fatal: console bypass first, the report, the
/// trace, then the halt. Never a kill.**
#[test]
fn a_kernel_page_fault_is_fatal_in_a_fixed_order() {
    on_each_isa!(false, true, 0xC000, |f| {
        assert!(matches!(pf(&mut f), Ended::Halted));
        assert!(!saw("kill"), "{:?}", logged());
        let order = ["stop_actuators", "halt_begin", "print_kernel_fault", "halt_report", "trace_dump", "fatal_halt"];
        let at: Vec<usize> = order.iter().map(|n| crate::fakes::at(n).unwrap_or_else(|| panic!("{n}: {:?}", logged()))).collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{:?}", logged());
        let m = logged().into_iter().find(|l| l.contains("print_kernel_fault")).unwrap();
        assert!(m.contains("write at 0xc000") && m.contains("cpu=3") && m.contains("null=false") && m.contains("resolved=(7, 9)"), "{m}");
    });
}

/// The report is the ISA's (the gate's boot rows read each ISA's own lines);
/// the policy hands it everything it resolved, a null dereference included.
#[test]
fn the_kernel_fault_report_is_the_isas_and_knows_a_null_dereference() {
    reset();
    let mut f = x86_fault(false, false, 0x1);
    pf(&mut f);
    assert!(saw("print_kernel_fault x86_64 read/exec at 0x1 cpu=3 null=true"), "{:?}", logged());
    reset();
    let mut f = arm_fault(false, false, 0x1);
    pf(&mut f);
    assert!(saw("print_kernel_fault aarch64"), "{:?}", logged());
    reset();
    let mut f = rv_fault(false, true, 0x2000);
    pf(&mut f);
    assert!(saw("print_kernel_fault riscv64 write at 0x2000 cpu=3 null=false"), "{:?}", logged());
}

/// The ISA's own cases (x86_64's TLB probe) are asked before the policy.
#[test]
fn an_isa_may_resolve_a_page_fault_itself() {
    reset();
    with(|s| s.arch_pf = true);
    let mut f = x86_fault(false, false, 0xD000);
    assert!(matches!(pf(&mut f), Ended::Returned));
    assert!(saw("arch_page_fault") && !saw("halt_begin"), "{:?}", logged());
}

// ── Exceptions ──────────────────────────────────────────────────────────────

/// **A user task that executes something it may not dies with the signal its
/// ISA's cause decode names, and the machine stays up.**
#[test]
fn a_user_exception_kills_with_the_signal_the_cause_names() {
    for (cause, want) in [(2u64, es::KILLED_ILL), (3, es::KILLED_TRAP), (4, es::KILLED_BUS), (5, es::KILLED_SEGV)] {
        reset();
        let mut f = RvFrame { scause: cause, ..Default::default() };
        assert!(matches!(ex(&mut f), Ended::Killed(s) if s == want), "riscv64 cause {cause}");
        assert!(saw("print riscv64 user fault") && saw("Killing user task 'tester' (tid 42)"), "{:?}", logged());
    }
    for (ec, want) in [(0u64, es::KILLED_ILL), (0x22, es::KILLED_BUS), (0x3C, es::KILLED_TRAP)] {
        reset();
        let mut f = ArmFrame { esr: ec << 26, lower_el_sync: true, ..Default::default() };
        assert!(matches!(ex(&mut f), Ended::Killed(s) if s == want), "aarch64 EC {ec:#x}");
    }
    for (v, want) in [(X86Frame::UD, es::KILLED_ILL), (X86Frame::GP, es::KILLED_SEGV), (3, es::KILLED_TRAP), (17, es::KILLED_BUS)] {
        reset();
        let mut f = X86Frame { vector: v, cs: 3, ..Default::default() };
        assert!(matches!(ex(&mut f), Ended::Killed(s) if s == want), "x86_64 vector {v}");
    }
}

#[test]
fn a_suppressed_exception_report_still_kills() {
    reset();
    with(|s| s.report = false);
    let mut f = RvFrame { scause: 2, ..Default::default() };
    assert!(matches!(ex(&mut f), Ended::Killed(s) if s == es::KILLED_ILL));
    assert!(logged().iter().all(|l| !l.contains("print") && !l.contains("Killing")), "{:?}", logged());
}

/// **An exception from the kernel is fatal on every ISA, and so is one the ISA
/// says is no task's fault even from user mode (#DF, #MC; SError and FIQ).**
#[test]
fn a_kernel_exception_and_the_machines_own_are_fatal() {
    reset();
    let mut f = RvFrame { scause: 2, s_mode: true, ..Default::default() };
    assert!(matches!(ex(&mut f), Ended::Halted));
    assert!(saw("print riscv64 unhandled trap") && saw("[FATAL] riscv64: unhandled trap on cpu 3"), "{:?}", logged());
    let order = ["stop_actuators", "halt_begin", "print riscv64 unhandled trap", "halt_report", "trace_dump", "fatal_halt"];
    let at: Vec<usize> = order.iter().map(|n| crate::fakes::at(n).unwrap()).collect();
    assert!(at.windows(2).all(|w| w[0] < w[1]), "{:?}", logged());

    reset();
    let mut f = X86Frame { vector: X86Frame::DF, cs: 3, ..Default::default() };
    assert!(matches!(ex(&mut f), Ended::Halted), "#DF from ring 3 is the machine's");
    assert!(!saw("kill"));

    reset();
    let mut f = ArmFrame { esr: 0, lower_el_sync: false, ..Default::default() }; // an SError from EL0
    assert!(matches!(ex(&mut f), Ended::Halted), "an SError is not the task's fault");
}

/// The ISA's own exception cases are asked first and may resume, kill or end.
#[test]
fn an_isa_decides_its_own_exceptions_before_the_policy() {
    // Resume: x86_64's NMI, riscv64's first FP use, aarch64's FP trap.
    reset();
    with(|s| s.arch_exc = Disposition::Resume);
    let mut f = X86Frame { vector: 2, ..Default::default() };
    assert!(matches!(ex(&mut f), Ended::Returned));
    assert!(!saw("halt_begin") && !saw("kill"), "{:?}", logged());
    // Kill: x86_64's split lock.
    reset();
    with(|s| s.arch_exc = Disposition::Kill(es::KILLED_BUS));
    let mut f = X86Frame { vector: 17, cs: 0, ..Default::default() };
    assert!(matches!(ex(&mut f), Ended::Killed(s) if s == es::KILLED_BUS), "whoever caused it: the hook said kill");
    // Fatal: a failed FP trap, even from user mode.
    reset();
    with(|s| s.arch_exc = Disposition::Fatal);
    let mut f = ArmFrame { esr: 7 << 26, lower_el_sync: true, ..Default::default() };
    assert!(matches!(ex(&mut f), Ended::Halted));
    // Default: the policy decides.
    reset();
    let mut f = X86Frame { vector: X86Frame::UD, cs: 3, ..Default::default() };
    assert!(matches!(ex(&mut f), Ended::Killed(_)));
    assert!(saw("arch_exception"));
}
