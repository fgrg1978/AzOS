// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// V1.8 (owner decision, 2026-09-26) / U07-6: a seccomp filter denial ends the
// program (Linux strict-mode `SECCOMP_RET_KILL_PROCESS` semantics), it does
// not return `-1`. `dispatch.rs`'s `FilterVerdict::Deny` arm calls
// `handlers::seccomp_deny_kill` and nothing else — see that function's doc
// for why the logic lives here rather than in `dispatch.rs`, which this
// crate never compiles (U14-8: `include_str!`'d as text only).
//
// Both shim recorders this file reads (`shim_take_trace_events`,
// `shim_take_exit_codes`) are hand-written stand-ins, not the real
// `crates/core/ipc::trace::trace_event` / `crates/core/sched::task_exit_with_code` —
// see each shim's own doc for exactly what is and is not modelled. What
// they DO prove, because both live in this one process and run in program
// order: whether the record was written before the kill, and with what
// content.

use super::harness::serial;

/// **The record lands before the kill, with the denied syscall number and
/// the `0xDEAD` marker this arm has always used.**
///
/// **Canary.** Swap the two statements in `seccomp_deny_kill` (kill, then
/// record): `shim_take_trace_events()` comes back empty, because nothing
/// after the panic ever runs.
#[test]
fn an_unlisted_syscall_records_the_denial_before_it_kills_the_task() {
    let _g = serial();
    let _ = azos_ipc::shim_take_trace_events();
    let _ = azos_sched::shim_take_exit_codes();

    let result = std::panic::catch_unwind(|| {
        seccomp_deny_kill(4242);
    });

    let err = result.expect_err("seccomp_deny_kill returned instead of ending the task");
    let msg = err
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    assert!(
        msg.contains(azos_sched::TASK_EXIT_MARKER),
        "the kill did not go through task_exit_with_code: {msg:?}",
    );

    assert_eq!(
        azos_ipc::shim_take_trace_events(),
        vec![(azos_ipc::TRACE_SYSCALL, 4242u32, 0xDEADu32, 0u32, 0u32)],
        "the denial was not recorded, or not recorded before the kill",
    );
    assert_eq!(
        azos_sched::shim_take_exit_codes(),
        vec![SECCOMP_KILL_EXIT_CODE],
        "the task was not killed with the documented exit code",
    );
}

/// **`159`, not `-1` and not a fresh errno.** Pins the exact value against
/// accidental drift, and restates why it is what it is (see the constant's
/// own doc): Linux's "128 + signal number" convention, SIGSYS = 31.
#[test]
fn the_kill_exit_code_is_128_plus_sigsys() {
    assert_eq!(SECCOMP_KILL_EXIT_CODE, 128 + 31);
}

/// **One door.** `dispatch.rs`'s `Deny` arm calls `seccomp_deny_kill` and
/// does not also return, record, or kill by any other route — checked by
/// source text because this crate never compiles `dispatch.rs` (U14-8).
///
/// **Canary.** Replace the arm's call with `return E_PERM;` (the pre-V1.8
/// behaviour): the `E_PERM` assertion below goes red.
#[test]
fn the_deny_arm_calls_seccomp_deny_kill_and_only_that() {
    const DISPATCH: &str = include_str!("../../../../crates/core/syscall/src/dispatch.rs");
    let at = DISPATCH
        .find("FilterVerdict::Deny =>")
        .expect("FilterVerdict::Deny arm not found in dispatch.rs");
    let line_end = at + DISPATCH[at..].find('\n').expect("end of the Deny arm's line");
    let arm_line = &DISPATCH[at..line_end];
    assert!(
        arm_line.contains("seccomp_deny_kill(num)"),
        "the Deny arm no longer calls seccomp_deny_kill(num):\n{arm_line}",
    );
    assert!(
        !arm_line.contains("E_PERM"),
        "the Deny arm still mentions E_PERM — V1.8 replaced that return:\n{arm_line}",
    );
}

/// RFC-0055: a forced stop (`SYS_TASK_KILL`) empties the target's filter, so
/// its next syscall reaches this function. That is the ancestor's stop, not a
/// profile breach: the task ends with the code the stop asked for and no
/// `0xDEAD` denial record is written.
///
/// **Canary.** Delete the forced-exit branch at the top of
/// `seccomp_deny_kill`: the exit code is 159 and a denial is recorded.
#[test]
fn a_forced_stop_ends_with_its_own_code_and_records_no_denial() {
    let _g = serial();
    let _ = azos_ipc::shim_take_trace_events();
    let _ = azos_sched::shim_take_exit_codes();
    azos_sched::scheduler::shim_set_forced_exit(Some(130));

    let result = std::panic::catch_unwind(|| {
        seccomp_deny_kill(64);
    });
    azos_sched::scheduler::shim_set_forced_exit(None);
    assert!(result.is_err(), "seccomp_deny_kill returned instead of ending the task");
    assert_eq!(azos_sched::shim_take_exit_codes(), vec![130]);
    assert!(azos_ipc::shim_take_trace_events().is_empty(), "a stop was recorded as a denial");
}
