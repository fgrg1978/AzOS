// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The syscall flow (`kernel/src/trap/syscall.rs`) on the three ISAs' frames:
//! decode, order, the prologue's counters, the lean IPC entry,
//! exec and the return-to-user work.

use crate::domain::{self, ENTRY_SLOTS};
use crate::fakes::*;
use crate::trap::frame::{EntryKind, Frame};
use crate::trap::syscall;
use azos_abi::syscall_nr::*;

fn enter<F: Frame, const FAST: bool>(f: &mut F) -> u64 {
    syscall::enter::<Fake, F, FAST>(f)
}

/// A Domain whose tasks the fake kernel runs.
fn running_domain() -> u32 {
    let k = domain::create().unwrap();
    with(|s| s.domain = k);
    k
}

/// **The one flow reaches the dispatch with the task's own number on every
/// ISA's convention, writes the result where that ISA keeps it, and steps over
/// the trap instruction only where the hardware did not.**
#[test]
fn the_flow_decodes_dispatches_and_returns_on_every_isa() {
    reset();
    with(|s| s.dispatch_ret = 1234);
    let mut rv = rv_call(SYS_CAP_INFO, [7, 8]);
    assert_eq!(enter::<_, false>(&mut rv), 0, "no exec: keep the address space");
    assert_eq!((rv.regs[10], rv.sepc), (1234, 0x1004), "riscv64: a0, and sepc past the ecall");

    let mut arm = arm_call(SYS_CAP_INFO, [7, 8]);
    assert_eq!(enter::<_, false>(&mut arm), 0);
    assert_eq!((arm.regs[0], arm.elr), (1234, 0x2000), "aarch64: x0, ELR already past the svc");

    let mut x86 = x86_call(SYS_CAP_INFO, [7, 8]);
    assert_eq!(enter::<_, false>(&mut x86), 0);
    assert_eq!((x86.rax, x86.rip), (1234, 0x3000), "x86_64: rax, RIP already past the syscall");

    let calls = with(|s| s.dispatches.clone());
    assert_eq!(calls, vec![(SYS_CAP_INFO, false); 3], "the number each ISA keeps in its own register");
}

/// The order the owner decision and the SYSFLOOR work fixed: interrupts on,
/// the census, the filter, (the prologue,) the call, the census out.
#[test]
fn the_flow_runs_in_its_order() {
    reset();
    with(|s| s.trace = true);
    let mut f = rv_call(SYS_CAP_INFO, [7, 8]);
    enter::<_, false>(&mut f);
    let order = ["interrupts_on", "census_enter", "verdict", "trace_enter 1 7 8", "shortcut 1", "dispatch 1", "trace_exit 1 1000", "census_exit"];
    let at: Vec<usize> = order.iter().map(|n| crate::fakes::at(n).unwrap_or_else(|| panic!("{n} not logged: {:?}", logged()))).collect();
    assert!(at.windows(2).all(|w| w[0] < w[1]), "out of order: {:?}", logged());
}

/// **The entry tracepoint is the prologue's, once, after the filter; with the
/// class off there is none.**
#[test]
fn the_tracepoint_is_off_with_the_class() {
    reset();
    let mut f = arm_call(SYS_CAP_INFO, [1, 2]);
    enter::<_, false>(&mut f);
    assert!(!saw("trace_"), "{:?}", logged());
}

/// **A call is counted in its Domain under its foundational case; a number the
/// table does not assign has no case and goes to slot 0.**
#[test]
fn the_prologue_counts_each_call_under_its_case() {
    reset();
    let k = running_domain();
    let mut f = x86_call(SYS_CAP_INFO, [0, 0]);
    enter::<_, false>(&mut f);
    for (num, fast) in [(SYS_INVOKE, false), (SYS_YIELD, false), (SYS_IPC_FAST_CALL_EP, true), (500, false)] {
        let mut f = x86_call(num, [0, 0]);
        if fast { enter::<_, true>(&mut f) } else { enter::<_, false>(&mut f) };
    }
    let want = if azos_limits::DOMAIN_ENTRY_COUNTERS { [1, 2, 2] } else { [0; ENTRY_SLOTS] };
    assert_eq!(domain::entries(k), want, "[no case, authority, block/wake]");
    domain::leave(k);
}

/// **A Domain nobody narrowed is refused nothing: every call of every case
/// reaches its answer, exit and thread exit included (what narrows it is the
/// pledge, `pledge.rs`).**
#[test]
fn an_unnarrowed_domain_is_refused_no_call() {
    reset();
    let k = running_domain();
    for nr in 1..SYS_NR_RESERVED_UPPER {
        let mut f = rv_call(nr, [0, 0]);
        enter::<_, false>(&mut f);
        assert_eq!(f.regs[10], 1000, "syscall {nr} was answered");
    }
    let ran: Vec<u64> = with(|s| s.dispatches.iter().map(|d| d.0).collect());
    assert!(ran.contains(&SYS_EXIT) && ran.contains(&SYS_THREAD_EXIT), "{ran:?}");
    domain::leave(k);
}

/// **A Linux task's number is not in the native table, so it is counted in
/// slot 0 whatever native number it equals.**
#[test]
fn a_linux_task_is_counted_in_slot_0() {
    reset();
    let k = running_domain();
    with(|s| s.kind = EntryKind::Linux);
    // A Linux number that is ALSO a native number with a case
    // (29 is native `SYS_FUTEX_WAKE`, case 2; Linux's is `ioctl`).
    assert_eq!(syscall_case(29), CASE_BLOCK_WAKE);
    let mut f = arm_call(29, [0, 0]);
    enter::<_, false>(&mut f);
    assert_eq!(f.regs[0], 1000);
    assert_eq!(with(|s| s.dispatches.clone()), vec![(29, false)], "the personality's number reached the dispatch");
    let want = if azos_limits::DOMAIN_ENTRY_COUNTERS { [1, 0, 0] } else { [0; ENTRY_SLOTS] };
    assert_eq!(domain::entries(k), want);
    domain::leave(k);
}

/// A kernel task has no Domain: nothing is counted.
#[test]
fn a_task_with_no_domain_counts_nothing() {
    reset();
    with(|s| s.domain = domain::NONE);
    let mut f = x86_call(SYS_YIELD, [0, 0]);
    enter::<_, false>(&mut f);
    assert_eq!(f.rax, 1000);
}

/// The lean IPC entry asks no register-only shortcut (none can match) and takes
/// the fast branch of the dispatch; every other entry asks it, and takes the
/// ordinary one.
#[test]
fn the_lean_ipc_entry_skips_the_shortcut_and_takes_the_fast_branch() {
    reset();
    let mut f = rv_call(SYS_IPC_FAST_CALL_EP, [0, 0]);
    enter::<_, true>(&mut f);
    assert!(!saw("shortcut"), "{:?}", logged());
    let mut g = rv_call(SYS_CAP_INFO, [0, 0]);
    enter::<_, false>(&mut g);
    assert!(saw("shortcut 1"));
    assert_eq!(with(|s| s.dispatches.clone()), vec![(SYS_IPC_FAST_CALL_EP, true), (SYS_CAP_INFO, false)]);
}

/// The reserved probe number (`irq-in-syscall-probe`) answers before interrupts
/// are enabled and before anything is counted.
#[test]
fn the_probe_number_answers_first() {
    reset();
    with(|s| s.probe = Some(5));
    let mut f = arm_call(4_000_000, [0, 0]);
    assert_eq!(enter::<_, false>(&mut f), 5);
    assert!(logged().is_empty(), "no interrupts, no census, no filter: {:?}", logged());
}

/// **An exec inside the call hands the new image's address-space word to the
/// return path; the call's own result and trace still happen, and the census
/// closes.**
#[test]
fn an_exec_returns_the_new_address_space() {
    reset();
    with(|s| s.exec = Some(0xA5A5));
    let mut f = x86_call(SYS_SPAWN_EX, [0, 0]);
    assert_eq!(enter::<_, false>(&mut f), 0xA5A5);
    assert_eq!(f.rax, 1000, "the call's result is written before the frame is replaced");
    assert!(saw("exec_enter 0xa5a5"));
    assert!(!saw("return_work"), "an exec takes no signal work: the image is new");
    let exits = logged().iter().filter(|l| *l == "census_exit").count();
    assert_eq!(exits, 1, "the census closes once on the exec path too: {:?}", logged());
}

#[test]
fn signal_and_foreign_work_runs_at_the_return_when_pending() {
    reset();
    let mut f = rv_call(SYS_CAP_INFO, [0, 0]);
    enter::<_, false>(&mut f);
    assert!(!saw("return_work"), "one load when none is pending");
    with(|s| s.work = true);
    enter::<_, false>(&mut f);
    assert!(at("return_work").unwrap() < logged().iter().rposition(|l| l == "census_exit").unwrap());
}
