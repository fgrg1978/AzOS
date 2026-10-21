// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The crash dump's hook in the fault policy (`kernel/src/trap/fault.rs`,
//! `kill_user`): a fault that kills a ring-3 task leaves its dump FIRST, once,
//! with the status the task is killed with; nothing else does. The kill tears
//! the task's page table and capability table down, so a dump taken after it
//! would read nothing.

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

fn dumps() -> usize {
    logged().iter().filter(|l| l.starts_with("crashdump ")).count()
}

/// **An unresolved user page fault dumps once, before the kill, with SIGSEGV.**
///
/// **Canary.** Call `S::kill` straight from `page_fault` (not through
/// `kill_user`): no `crashdump` line, and the first assert fails.
#[test]
fn a_killing_page_fault_dumps_before_the_kill() {
    let segv = es::KILLED_SEGV;
    let mut rv = RvFrame { scause: 13, stval: 0x10, sepc: 0x1234, ..Default::default() };
    let mut arm = ArmFrame { esr: 0x24 << 26, far: 0x10, elr: 0x1234, ..Default::default() };
    let mut x86 = X86Frame { vector: X86Frame::PF, cr2: 0x10, rip: 0x1234, cs: 3, ..Default::default() };
    for isa in 0..3 {
        reset();
        let ended = match isa {
            0 => pf(&mut rv),
            1 => pf(&mut arm),
            _ => pf(&mut x86),
        };
        assert!(matches!(ended, Ended::Killed(s) if s == segv), "isa {isa}");
        assert_eq!(dumps(), 1, "{:?}", logged());
        assert!(at(&format!("crashdump {segv}")).unwrap() < at("kill ").unwrap(), "the dump precedes the kill: {:?}", logged());
    }
}

/// **A suppressed console report still dumps**: the rate limit is on the
/// console, the dump is the record.
#[test]
fn a_suppressed_report_still_dumps() {
    reset();
    with(|s| s.report = false);
    let mut f = RvFrame { scause: 13, stval: 0x10, ..Default::default() };
    assert!(matches!(pf(&mut f), Ended::Killed(_)));
    assert_eq!(dumps(), 1, "{:?}", logged());
}

/// **A user exception dumps with the status its cause names**, and so does an
/// ISA's own kill (x86_64's split lock).
#[test]
fn a_killing_exception_dumps_with_its_status() {
    reset();
    let mut f = RvFrame { scause: 2, ..Default::default() };
    assert!(matches!(ex(&mut f), Ended::Killed(_)));
    assert!(saw(&format!("crashdump {}", es::KILLED_ILL)) && dumps() == 1, "{:?}", logged());
    assert!(at("crashdump").unwrap() < at("kill ").unwrap());

    reset();
    with(|s| s.arch_exc = Disposition::Kill(es::KILLED_BUS));
    let mut f = X86Frame { vector: 17, cs: 3, ..Default::default() };
    assert!(matches!(ex(&mut f), Ended::Killed(s) if s == es::KILLED_BUS));
    assert!(saw(&format!("crashdump {}", es::KILLED_BUS)) && dumps() == 1, "{:?}", logged());
}

/// **Nothing else dumps**: a resolved fault (the task goes on), a fault or
/// exception in the kernel and one that is the machine's own (fatal: the
/// panic path has `CRASH.LOG`).
///
/// **Canary.** Call the hook at the top of `page_fault`: the resolved COW
/// break dumps and the first assert fails.
#[test]
fn only_a_killed_user_task_dumps() {
    reset();
    with(|s| s.cow = vec![Cow::Resolved]);
    let mut f = RvFrame { scause: 15, stval: 0x5000, ..Default::default() };
    assert!(matches!(pf(&mut f), Ended::Returned));
    assert_eq!(dumps(), 0, "{:?}", logged());

    reset();
    let mut f = RvFrame { scause: 13, stval: 0x5000, s_mode: true, ..Default::default() };
    assert!(matches!(pf(&mut f), Ended::Halted));
    assert_eq!(dumps(), 0, "{:?}", logged());

    reset();
    let mut f = RvFrame { scause: 2, s_mode: true, ..Default::default() };
    assert!(matches!(ex(&mut f), Ended::Halted));
    assert_eq!(dumps(), 0, "{:?}", logged());

    reset();
    let mut f = X86Frame { vector: X86Frame::DF, cs: 3, ..Default::default() };
    assert!(matches!(ex(&mut f), Ended::Halted));
    assert_eq!(dumps(), 0, "{:?}", logged());
}

/// **A kill the ISA decides from the KERNEL's frame dumps nothing**: the
/// registers of that frame are the kernel's, and the dump is a file ring 3
/// can read. (x86_64's split lock taken in a system call.)
///
/// **Canary.** Drop the `came_from_user` test in `kill_user`: the dump is
/// taken from the kernel-mode frame and the assert fails.
#[test]
fn a_kill_from_the_kernels_frame_dumps_nothing() {
    reset();
    with(|s| s.arch_exc = Disposition::Kill(es::KILLED_BUS));
    let mut f = X86Frame { vector: 17, cs: 0, ..Default::default() };
    assert!(matches!(ex(&mut f), Ended::Killed(s) if s == es::KILLED_BUS), "the task is still killed");
    assert_eq!(dumps(), 0, "{:?}", logged());
}
