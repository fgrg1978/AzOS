// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The process syscalls with no host test before this file: `SYS_EXIT`,
// `SYS_GETPID`, `SYS_YIELD`, `SYS_FORK`, `SYS_FORK_COW`, `SYS_WAIT`,
// `SYS_WAIT_STATUS` and `SYS_WAITPID`.
//
// The scheduler is the `shims/sched` stand-in: the exit-notice table, the
// yield and the fork are programmed per test (unprogrammed they are `todo!()`,
// so a handler that reaches one unexpectedly still panics). What is under
// test is the handler: which TID it asks for, what it refuses before asking,
// what it writes through the status pointer and what it answers when that
// pointer is bad. The status pointer goes through the real `translate_user`
// against a real Sv39 table, as in `file_ops_seam.rs`.

use super::harness::serial;
use azos_abi::error::Errno;
use azos_arch_api::PagePerms;
use azos_sched::ShimExitNote;

/// A VA clear of what the other guard files use.
const STATUS_VA: usize = 0x0071_0000;
/// Never mapped by this file.
const UNMAPPED_VA: usize = 0x0072_0000;

const ME: u32 = 21;

fn note(parent: u32, child: u32, code: i32) -> ShimExitNote {
    ShimExitNote { parent, child, code }
}

/// Ring 3, TID [`ME`], with one writable page at [`STATUS_VA`]. Returns the
/// host pointer backing that page.
fn ring3_with_status_page() -> *mut u8 {
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(ME);
    let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, STATUS_VA, phys, PagePerms::USER_RW).expect("map");
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0xEE, 4) };
    phys as *mut u8
}

fn read_status(host: *mut u8) -> i32 {
    let mut b = [0u8; 4];
    unsafe { core::ptr::copy_nonoverlapping(host, b.as_mut_ptr(), 4) };
    i32::from_le_bytes(b)
}

fn echild() -> i64 { Errno::ECHILD.to_syscall_ret() }
fn efault() -> i64 { Errno::EFAULT.to_syscall_ret() }

// ── SYS_GETPID / SYS_YIELD / SYS_EXIT ─────────────────────────────────────

#[test]
fn getpid_answers_the_current_tid() {
    let _g = serial();
    azos_sched::set_current_task_tid(4242);
    assert_eq!(super::sys_getpid(), 4242);
    azos_sched::set_current_task_tid(7);
    assert_eq!(super::sys_getpid(), 7);
}

#[test]
fn yield_yields_exactly_once_and_answers_zero() {
    let _g = serial();
    azos_sched::shim_arm_yield();
    assert_eq!(super::sys_yield(), 0);
    assert_eq!(azos_sched::shim_yields(), Some(1), "sys_yield did not yield once");
}

/// The exit code reaches `task_exit_with_code` — it used to be discarded in
/// this handler (`_code`) — and it is the low 32 bits of `a0`, as the ABI's
/// `i32` says: the register is not range-checked, so a code above `i32` wraps
/// rather than being refused.
#[test]
fn exit_hands_the_low_32_bits_of_a0_to_the_scheduler() {
    let _g = serial();
    let _ = azos_sched::shim_take_exit_codes();
    for (a0, want) in [(0u64, 0i32), (3, 3), (u64::MAX, -1), (0x1_0000_0005, 5)] {
        let r = std::panic::catch_unwind(|| super::sys_exit(a0));
        let msg = r.expect_err("sys_exit returned");
        let msg = msg.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(msg.contains(azos_sched::TASK_EXIT_MARKER), "a0={a0:#x}: panicked elsewhere: {msg}");
        assert_eq!(azos_sched::shim_take_exit_codes(), vec![want], "a0={a0:#x}");
    }
}

// ── SYS_FORK / SYS_FORK_COW ───────────────────────────────────────────────

/// Both numbers reach the same fork with the same three arguments, and the
/// child TID comes back unchanged. `SYS_FORK_COW` is documented as
/// "semantically identical"; this is what pins it.
#[test]
fn fork_and_fork_cow_forward_the_trap_state_unchanged() {
    let _g = serial();
    let regs: azos_sched::UserRegs = [0; 32];
    let at = &regs as *const _ as usize;

    azos_sched::process::shim_program_fork(33);
    assert_eq!(super::sys_fork(0x1_0040, 0x7fff_f000, &regs), 33);
    assert_eq!(super::sys_fork_cow(0x2_0040, 0x7fff_e000, &regs), 33);
    assert_eq!(
        azos_sched::process::shim_take_fork_calls(),
        Some(vec![(0x1_0040, 0x7fff_f000, at), (0x2_0040, 0x7fff_e000, at)]),
    );

    // A failed fork is reported as the fork reported it.
    azos_sched::process::shim_program_fork(-1);
    assert_eq!(super::sys_fork_cow(0, 0, &regs), -1);
}

// ── SYS_WAIT ──────────────────────────────────────────────────────────────

#[test]
fn wait_reaps_only_the_callers_children_and_drops_the_code() {
    let _g = serial();
    azos_sched::set_current_task_tid(ME);
    azos_sched::shim_program_exit_notes(&[note(99, 50, 1), note(ME, 51, 7)], &[]);

    assert_eq!(super::sys_wait(), 51, "reaped someone else's child, or none");
    assert_eq!(super::sys_wait(), -1, "a second reap of one notice");
    let (left, asked) = azos_sched::shim_take_exit_table().unwrap();
    assert_eq!(left, vec![note(99, 50, 1)], "another parent's notice was consumed");
    assert_eq!(asked, vec![(ME, None), (ME, None)], "asked for a parent that is not the caller");
}

// ── SYS_WAIT_STATUS ───────────────────────────────────────────────────────

#[test]
fn wait_status_writes_the_code_through_a_mapped_pointer() {
    let _g = serial();
    let host = ring3_with_status_page();
    azos_sched::shim_program_exit_notes(&[note(ME, 60, -42)], &[]);
    assert_eq!(super::sys_wait_status(STATUS_VA as u64), 60);
    assert_eq!(read_status(host), -42);
}

#[test]
fn wait_status_with_a_null_pointer_reaps_without_writing() {
    let _g = serial();
    let host = ring3_with_status_page();
    azos_sched::shim_program_exit_notes(&[note(ME, 61, 9)], &[]);
    assert_eq!(super::sys_wait_status(0), 61);
    assert_eq!(read_status(host), i32::from_le_bytes([0xEE; 4]), "wrote with a null pointer");
    assert_eq!(super::sys_wait_status(0), -1, "the notice survived the reap");
}

/// Refusal: an unmapped status pointer is `EFAULT`, and the notice is GONE —
/// the documented cost (the read is destructive and happens first). `-1`
/// here would claim no child finished, which is false.
#[test]
fn wait_status_to_an_unmapped_pointer_is_efault_and_the_notice_is_consumed() {
    let _g = serial();
    ring3_with_status_page();
    azos_sched::shim_program_exit_notes(&[note(ME, 62, 5)], &[]);
    assert_eq!(super::sys_wait_status(UNMAPPED_VA as u64), efault());
    let (left, _) = azos_sched::shim_take_exit_table().unwrap();
    assert!(left.is_empty(), "EFAULT but the notice was not consumed: {left:?}");
}

#[test]
fn wait_status_with_nothing_finished_is_minus_one_and_writes_nothing() {
    let _g = serial();
    let host = ring3_with_status_page();
    azos_sched::shim_program_exit_notes(&[note(99, 63, 5)], &[]);
    assert_eq!(super::sys_wait_status(STATUS_VA as u64), -1);
    assert_eq!(read_status(host), i32::from_le_bytes([0xEE; 4]));
}

// ── SYS_WAITPID ───────────────────────────────────────────────────────────

/// Refusal before the table: a0 that cannot name a TID is `ECHILD`, and the
/// table is never asked. It is left unprogrammed on purpose — a handler that
/// narrowed `a0` first (`u32::MAX + 1` → TID 0) would reach the `todo!()` and
/// panic, which is how this test fails.
#[test]
fn waitpid_refuses_a_tid_wider_than_u32_before_reading_the_table() {
    let _g = serial();
    azos_sched::set_current_task_tid(ME);
    for a0 in [u32::MAX as u64 + 1, u32::MAX as u64 + 60, u64::MAX] {
        assert_eq!(super::sys_waitpid(a0, 0), echild(), "a0={a0:#x}");
    }
}

#[test]
fn waitpid_reaps_that_child_and_writes_its_code() {
    let _g = serial();
    let host = ring3_with_status_page();
    azos_sched::shim_program_exit_notes(&[note(ME, 70, 1), note(ME, 71, 2)], &[]);
    assert_eq!(super::sys_waitpid(71, STATUS_VA as u64), 71);
    assert_eq!(read_status(host), 2, "wrote the other child's code");
    let (left, asked) = azos_sched::shim_take_exit_table().unwrap();
    assert_eq!(left, vec![note(ME, 70, 1)], "reaped a child it was not asked for");
    assert_eq!(asked, vec![(ME, Some(71))]);
}

/// The three answers are three answers: alive is `-1`, not ours is `ECHILD`,
/// and a notice owned by another parent is not ours AND survives.
#[test]
fn waitpid_tells_alive_from_not_ours_and_leaves_other_parents_notices() {
    let _g = serial();
    let host = ring3_with_status_page();
    azos_sched::shim_program_exit_notes(&[note(99, 80, 3)], &[(ME, 81)]);
    assert_eq!(super::sys_waitpid(81, STATUS_VA as u64), -1, "a live child");
    assert_eq!(super::sys_waitpid(80, STATUS_VA as u64), echild(), "another parent's child");
    assert_eq!(super::sys_waitpid(82, STATUS_VA as u64), echild(), "no such task");
    assert_eq!(read_status(host), i32::from_le_bytes([0xEE; 4]), "a miss wrote a status");
    let (left, _) = azos_sched::shim_take_exit_table().unwrap();
    assert_eq!(left, vec![note(99, 80, 3)], "another parent's notice was consumed");
}

/// Refusal: unmapped status pointer, `EFAULT`, notice consumed — same shape
/// as `SYS_WAIT_STATUS`, and the child's TID must not come back as success.
#[test]
fn waitpid_to_an_unmapped_pointer_is_efault_and_the_notice_is_consumed() {
    let _g = serial();
    ring3_with_status_page();
    azos_sched::shim_program_exit_notes(&[note(ME, 90, 4)], &[]);
    assert_eq!(super::sys_waitpid(90, UNMAPPED_VA as u64), efault());
    assert_eq!(super::sys_waitpid(90, 0), echild(), "the notice survived an EFAULT");
}
