// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The pledge mask (`DOMAIN_PLEDGE`): the Domain's one-way narrowing of what its
//! members may ask of the kernel, through the real prologue (`syscall.rs`) and
//! the real Domain table (`domain.rs`) on the three ISAs' frames.
//!
//! **Canaries** (each turns the named tests red, run by hand when written):
//! make `pledge_narrow` store `req` without the `req & !cur` check (the
//! widening and inheritance tests); drop the `PLEDGE_ALWAYS` exemption in
//! `pledge_bit` (the exit test); make `enter` ignore the mask (the refusal,
//! class and Linux tests); make `create_child` store `PLEDGE_ALL` (the
//! inheritance test).

use crate::domain::{self, Door, PledgeError};
use crate::fakes::*;
use crate::trap::frame::{EntryKind, Frame};
use crate::trap::syscall;
use azos_abi::error::Errno;
use azos_abi::invoke::*;
use azos_abi::syscall_nr::*;
use azos_decision::{Rule, Verdict};

fn enter<F: Frame, const FAST: bool>(f: &mut F) -> u64 {
    syscall::enter::<Fake, F, FAST>(f)
}

fn eacces() -> u64 {
    Errno::EACCES.to_syscall_ret() as u64
}

/// A fresh task id: the decision ring outlives a test, so every task a test
/// runs is one no other test's receipts name.
fn fresh_tid() -> u32 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0x7e57_0001);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// A Domain the fake kernel runs, with a task of its own in it.
fn running() -> u32 {
    let k = domain::create().unwrap();
    with(|s| {
        s.domain = k;
        s.tid = fresh_tid();
    });
    k
}

/// The `pledge` records the running task has, oldest first.
fn refusals() -> Vec<azos_decision::Record> {
    let subject = with(|s| s.tid);
    let mut v = Vec::new();
    azos_decision::for_each(|r| {
        if r.rule == Rule::Pledge as u8 && r.subject == subject {
            v.push(*r);
        }
    });
    v
}

/// `SYS_INVOKE` with an op of `class` in the op word.
fn invoke_of(class: u8) -> u64 {
    op(azos_abi::cap::CapKind::Domain, class, 1) as u64
}

const BLOCK_WAKE: u32 = pledge_case(CASE_BLOCK_WAKE);
const AUTHORITY: u32 = pledge_case(CASE_AUTHORITY);

/// **A mask only loses bits.** Every request that keeps a subset is taken (and
/// `PLEDGE_ALWAYS` stays whatever the request says); one bit the mask no longer
/// has refuses the whole request and changes none; a bit that names nothing is
/// refused as unknown; a key that names no Domain is refused.
#[test]
fn a_mask_only_narrows() {
    reset();
    let k = domain::create().unwrap();
    // Nothing narrowed yet: the whole mask is a subset of itself.
    assert_eq!(domain::pledge_narrow(k, PLEDGE_ALL), Ok(PLEDGE_ALL));
    let steady = BLOCK_WAKE | pledge_class(CLASS_NET);
    assert_eq!(domain::pledge_narrow(k, steady), Ok(steady | PLEDGE_ALWAYS), "exit stays in whatever is asked");
    // Narrower again is fine; the same again is fine.
    assert_eq!(domain::pledge_narrow(k, BLOCK_WAKE), Ok(BLOCK_WAKE | PLEDGE_ALWAYS));
    assert_eq!(domain::pledge_narrow(k, BLOCK_WAKE), Ok(BLOCK_WAKE | PLEDGE_ALWAYS));
    // Wider is refused, whole: the request that mixes a kept bit and a lost one
    // changes nothing.
    assert_eq!(domain::pledge_narrow(k, steady), Err(PledgeError::Widen));
    assert_eq!(domain::pledge_narrow(k, BLOCK_WAKE | AUTHORITY), Err(PledgeError::Widen));
    assert_eq!(domain::pledge_narrow(k, PLEDGE_ALL), Err(PledgeError::Widen));
    assert_eq!(domain::pledge_narrow(k, 0), Ok(PLEDGE_ALWAYS), "the refusals changed nothing: narrowing to nothing is still allowed");
    // A bit no mask has.
    assert_eq!(domain::pledge_narrow(k, 1 << 30), Err(PledgeError::Unknown));
    assert_eq!(domain::pledge_narrow(k, 1 << 5), Err(PledgeError::Unknown));
    assert_eq!(domain::pledge_narrow(k, 1 << (CASES + 1)), Err(PledgeError::Unknown));
    domain::leave(k);
    assert_eq!(domain::pledge_narrow(k, 0), Err(PledgeError::NoDomain), "a dead key names nothing");
}

/// **A call outside the mask is not run, answers `-EACCES` on every ISA, is
/// counted (it entered the kernel) and leaves a record; a call inside runs.**
/// The first refusal of a mask bit is a `Refuse` (a durable receipt), the next
/// ones a `Deny` (the ring only). The record names the Domain, the bit and the
/// number.
#[test]
fn a_call_outside_the_mask_is_refused_with_a_record() {
    reset();
    let k = running();
    assert_eq!(domain::pledge_narrow(k, BLOCK_WAKE), Ok(BLOCK_WAKE | PLEDGE_ALWAYS));

    // Authority is gone: `SYS_CAP_INFO` is answered by the prologue.
    let mut rv = rv_call(SYS_CAP_INFO, [7, 8]);
    assert_eq!(enter::<_, false>(&mut rv), 0);
    assert_eq!(rv.regs[10], eacces(), "riscv64: a0");
    assert_eq!(rv.sepc, 0x1004, "the trap instruction is stepped over all the same");
    let mut arm = arm_call(SYS_CAP_INFO, [7, 8]);
    enter::<_, false>(&mut arm);
    assert_eq!(arm.regs[0], eacces(), "aarch64: x0");
    let mut x86 = x86_call(SYS_CAP_INFO, [7, 8]);
    enter::<_, false>(&mut x86);
    assert_eq!(x86.rax, eacces(), "x86_64: rax");
    assert!(with(|s| s.dispatches.is_empty()), "nothing ran: {:?}", logged());
    assert!(!saw("dispatch") && !saw("shortcut"), "the call is not even asked for its answer: {:?}", logged());

    // The shortcut call (`getpid`, authority) and the lean entry's IPC branch
    // (block/wake: allowed) keep their places.
    let mut g = rv_call(SYS_GETPID, [0, 0]);
    enter::<_, false>(&mut g);
    assert_eq!(g.regs[10], eacces(), "getpid is authority, and its answer comes from the number: still refused");
    let mut ipc = x86_call(SYS_IPC_FAST_CALL_EP, [0, 0]);
    enter::<_, true>(&mut ipc);
    assert_eq!(ipc.rax, 1000, "block/wake is inside the mask");
    let mut y = rv_call(SYS_YIELD, [0, 0]);
    enter::<_, false>(&mut y);
    assert_eq!(y.regs[10], 1000);

    // Counted: the four authority calls above entered, the two block/wake too.
    if azos_limits::DOMAIN_ENTRY_COUNTERS {
        assert_eq!(domain::entries(k), [0, 4, 2], "[no case, authority, block/wake]");
    }

    // The record: one Refuse for the authority bit, then Denys.
    let rs = refusals();
    assert_eq!(rs.len(), 4, "{rs:?}");
    assert_eq!(rs[0].verdict, Verdict::Refuse as u8);
    assert!(rs[1..].iter().all(|r| r.verdict == Verdict::Deny as u8), "{rs:?}");
    let first = rs[0];
    assert_eq!(first.n[0], u64::from(BLOCK_WAKE | PLEDGE_ALWAYS), "the mask in force");
    assert_eq!(first.n[1], Door::Trap.refused(), "a trapped call, not a ring entry");
    assert_eq!(first.n[2], SYS_CAP_INFO, "the number");
    assert_eq!(rs[3].n[2], SYS_GETPID);
    assert!(rs.iter().all(|r| r.n[1] == Door::Trap.refused() && r.n[0] == first.n[0]), "{rs:?}");
    domain::leave(k);
}

/// **A call inside the mask leaves no record.**
#[test]
fn an_allowed_call_leaves_no_record() {
    reset();
    let k = running();
    assert_eq!(domain::pledge_narrow(k, BLOCK_WAKE), Ok(BLOCK_WAKE | PLEDGE_ALWAYS));
    for nr in [SYS_YIELD, SYS_SLEEP_UNTIL, SYS_FUTEX_WAIT, SYS_PORT_WAIT, SYS_RING_ENTER] {
        let mut f = rv_call(nr, [0, 0]);
        enter::<_, false>(&mut f);
        assert_eq!(f.regs[10], 1000, "syscall {nr}");
    }
    assert!(refusals().is_empty(), "{:?}", refusals());
    domain::leave(k);
}

/// **`exit` and `thread_exit` are in every mask**, on every ISA's frame, even a
/// mask narrowed to nothing; every other native number is refused then. A Linux
/// task's number that equals a native exit number is NOT exempt (it is another
/// call).
#[test]
fn exit_and_thread_exit_are_always_allowed() {
    reset();
    let k = running();
    assert_eq!(domain::pledge_narrow(k, 0), Ok(PLEDGE_ALWAYS));
    for nr in [SYS_EXIT, SYS_THREAD_EXIT] {
        let mut rv = rv_call(nr, [0, 0]);
        enter::<_, false>(&mut rv);
        assert_eq!(rv.regs[10], 1000, "riscv64 {nr}");
        let mut arm = arm_call(nr, [0, 0]);
        enter::<_, false>(&mut arm);
        assert_eq!(arm.regs[0], 1000, "aarch64 {nr}");
        let mut x86 = x86_call(nr, [0, 0]);
        enter::<_, false>(&mut x86);
        assert_eq!(x86.rax, 1000, "x86_64 {nr}");
    }
    let ran: Vec<u64> = with(|s| s.dispatches.iter().map(|d| d.0).collect());
    assert_eq!(ran, vec![SYS_EXIT, SYS_EXIT, SYS_EXIT, SYS_THREAD_EXIT, SYS_THREAD_EXIT, SYS_THREAD_EXIT]);
    // Every other number is refused.
    let before = ran.len();
    for nr in 1..SYS_NR_RESERVED_UPPER {
        if nr == SYS_EXIT || nr == SYS_THREAD_EXIT {
            continue;
        }
        let mut f = rv_call(nr, [0, 0]);
        enter::<_, false>(&mut f);
        assert_eq!(f.regs[10], eacces(), "syscall {nr}");
    }
    assert_eq!(with(|s| s.dispatches.len()), before, "none of them ran");

    // A Linux task: the mask's bit 0 judges every call of it, exit's number included.
    with(|s| s.kind = EntryKind::Linux);
    let mut f = arm_call(SYS_EXIT, [0, 0]);
    enter::<_, false>(&mut f);
    assert_eq!(f.regs[0], eacces(), "bit 0 is gone, and a Linux number is judged by it alone");
    domain::leave(k);
}

/// **A Linux task is judged by bit 0 alone.** With the bit in the mask its
/// calls run (and are counted in slot 0); a mask without it refuses them all,
/// whatever native number they equal.
#[test]
fn a_linux_task_is_judged_by_bit_zero() {
    reset();
    let k = running();
    with(|s| s.kind = EntryKind::Linux);
    assert_eq!(domain::pledge_narrow(k, pledge_case(0) | BLOCK_WAKE), Ok(pledge_case(0) | BLOCK_WAKE | PLEDGE_ALWAYS));
    let mut f = arm_call(29, [0, 0]);
    enter::<_, false>(&mut f);
    assert_eq!(f.regs[0], 1000, "bit 0 is in the mask");
    assert_eq!(domain::pledge_narrow(k, BLOCK_WAKE), Ok(BLOCK_WAKE | PLEDGE_ALWAYS));
    let mut f = arm_call(29, [0, 0]);
    enter::<_, false>(&mut f);
    assert_eq!(f.regs[0], eacces(), "29 is a block/wake number natively; for a Linux task it has no case");
    domain::leave(k);
}

/// **`SYS_INVOKE` is judged by the class of its op, not by its case.** A mask
/// with the network class and no authority case lets a socket op through and
/// refuses an `openat`; the case bit of authority neither admits an op of an
/// unlisted class nor refuses one of a listed class.
#[test]
fn an_invoke_is_judged_by_the_class_of_its_op() {
    reset();
    let k = running();
    let steady = BLOCK_WAKE | pledge_class(CLASS_NET) | pledge_class(CLASS_WRITE);
    assert_eq!(domain::pledge_narrow(k, steady), Ok(steady | PLEDGE_ALWAYS));
    // The op word is the call's second argument, in the op's low 16 bits.
    for (class, ok) in [(CLASS_NET, true), (CLASS_WRITE, true), (CLASS_FS_OPEN, false), (CLASS_ADMIN, false), (CLASS_CTL, false), (CLASS_READ, false)] {
        let mut f = rv_call(SYS_INVOKE, [0, invoke_of(class)]);
        enter::<_, false>(&mut f);
        assert_eq!(f.regs[10], if ok { 1000 } else { eacces() }, "class {class}");
    }
    // And with the authority case in the mask but not the class, it is still refused.
    let k2 = domain::create().unwrap();
    with(|s| {
        s.domain = k2;
        s.tid = fresh_tid();
    });
    let m = AUTHORITY | BLOCK_WAKE;
    assert_eq!(domain::pledge_narrow(k2, m), Ok(m | PLEDGE_ALWAYS));
    let mut f = x86_call(SYS_INVOKE, [0, invoke_of(CLASS_NET)]);
    enter::<_, false>(&mut f);
    assert_eq!(f.rax, eacces(), "authority admits cap_derive, not every op of invoke");
    let mut f = x86_call(SYS_CAP_DERIVE, [0, 0]);
    enter::<_, false>(&mut f);
    assert_eq!(f.rax, 1000);
    // The refusal names the call and the mask that refused it.
    let rs = refusals();
    assert_eq!(rs.len(), 1);
    assert_eq!(rs[0].n[0], u64::from(m | PLEDGE_ALWAYS));
    assert_eq!(rs[0].n[2], SYS_INVOKE);
    domain::leave(k2);
    domain::leave(k);
}

/// **A Domain created beneath another starts with its creator's mask**, can
/// narrow it further and never widen it; the creator's own mask and a sibling
/// made before the narrowing are not touched by the child; a Domain whose
/// creator names no Domain starts with everything.
#[test]
fn a_child_domain_inherits_the_mask() {
    reset();
    let sibling = domain::create().unwrap();
    let parent = domain::create().unwrap();
    let steady = BLOCK_WAKE | pledge_class(CLASS_NET);
    assert_eq!(domain::pledge_narrow(parent, steady), Ok(steady | PLEDGE_ALWAYS));

    let child = domain::create_child(parent).unwrap();
    with(|s| s.domain = child);
    let mut f = rv_call(SYS_CAP_INFO, [0, 0]);
    enter::<_, false>(&mut f);
    assert_eq!(f.regs[10], eacces(), "the child begins as narrow as its creator");
    assert_eq!(domain::pledge_narrow(child, steady | AUTHORITY), Err(PledgeError::Widen), "and cannot widen");
    assert_eq!(domain::pledge_narrow(child, BLOCK_WAKE), Ok(BLOCK_WAKE | PLEDGE_ALWAYS), "but narrows further");
    // The creator keeps its own mask: a grandchild made now inherits the child's.
    let grandchild = domain::create_child(child).unwrap();
    assert_eq!(domain::pledge_narrow(grandchild, steady), Err(PledgeError::Widen), "the grandchild has the child's mask");
    let again = domain::create_child(parent).unwrap();
    assert_eq!(domain::pledge_narrow(again, steady), Ok(steady | PLEDGE_ALWAYS), "the parent's is as it was");
    // The sibling was never narrowed.
    assert_eq!(domain::pledge_narrow(sibling, PLEDGE_ALL), Ok(PLEDGE_ALL));
    // A creator that names no Domain (a kernel task's, a dead key) makes a root with everything.
    let root = domain::create_child(domain::NONE).unwrap();
    assert_eq!(domain::pledge_narrow(root, PLEDGE_ALL), Ok(PLEDGE_ALL));
    for d in [root, again, grandchild, child, parent, sibling] {
        domain::leave(d);
    }
}

/// **A slot taken again starts with everything**: the narrowing died with the
/// Domain that made it.
#[test]
fn a_reused_slot_starts_with_everything() {
    reset();
    let k = domain::create().unwrap();
    assert_eq!(domain::pledge_narrow(k, 0), Ok(PLEDGE_ALWAYS));
    domain::leave(k);
    let mut held = Vec::new();
    let again = loop {
        let n = domain::create().unwrap();
        if domain::index(n) == domain::index(k) {
            break n;
        }
        held.push(n);
    };
    assert_eq!(domain::pledge_narrow(again, PLEDGE_ALL), Ok(PLEDGE_ALL));
    held.push(again);
    for n in held {
        domain::leave(n);
    }
}

/// A task with no Domain (a kernel task) is refused nothing.
#[test]
fn a_kernel_task_is_refused_nothing() {
    reset();
    with(|s| s.domain = domain::NONE);
    let mut f = x86_call(SYS_CAP_INFO, [0, 0]);
    enter::<_, false>(&mut f);
    assert_eq!(f.rax, 1000);
}

/// **The kernel entries by case are what the metric reads**: the Domain table
/// hands back, by slot, the key and the counts the prologue made, refused calls
/// included.
#[test]
fn the_entries_are_readable_by_slot() {
    reset();
    let k = running();
    assert_eq!(domain::pledge_narrow(k, BLOCK_WAKE), Ok(BLOCK_WAKE | PLEDGE_ALWAYS));
    for nr in [SYS_CAP_INFO, SYS_YIELD, SYS_YIELD] {
        let mut f = rv_call(nr, [0, 0]);
        enter::<_, false>(&mut f);
    }
    let (key, e) = domain::slot_entries(domain::index(k)).expect("the Domain is alive");
    assert_eq!(key, k);
    let want = if azos_limits::DOMAIN_ENTRY_COUNTERS { [0, 1, 2] } else { [0; 3] };
    assert_eq!(e, want);
    domain::leave(k);
    assert_eq!(domain::slot_entries(domain::index(k)), None, "an ended Domain is not listed");
}
