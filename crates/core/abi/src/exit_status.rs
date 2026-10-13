// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Exit statuses the KERNEL assigns when it kills a task, as `waitpid`
//! reports them. Same encoding a Linux shell shows for a signal death,
//! 128 + the signal number, and the one `SECCOMP_KILL_EXIT_CODE` (159,
//! SIGSYS) already uses in `crates/core/syscall`.
//!
//! Before these existed every fault kill called `task_exit()`, which exits
//! with 0: a parent waiting on a child that dereferenced NULL was told the
//! child succeeded.

/// Unresolvable page fault (Linux: SIGSEGV = 11).
pub const KILLED_SEGV: i32 = 128 + 11;
/// Undefined or illegal instruction (Linux: SIGILL = 4).
pub const KILLED_ILL: i32 = 128 + 4;
/// Misaligned PC, SP or access (Linux: SIGBUS = 7).
pub const KILLED_BUS: i32 = 128 + 7;
/// Breakpoint with no debugger attached (Linux: SIGTRAP = 5).
pub const KILLED_TRAP: i32 = 128 + 5;
/// Stopped by the kernel on request, not for anything the task did: a ring-3
/// driver the kernel asked to stop (RFC-0049 M4,
/// `azos_driver_server::driver_request_stop`). Linux: SIGKILL = 9.
pub const KILLED_KILL: i32 = 128 + 9;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codes_are_distinct_and_never_success() {
        let all = [KILLED_SEGV, KILLED_ILL, KILLED_BUS, KILLED_TRAP, KILLED_KILL];
        for (i, a) in all.iter().enumerate() {
            assert_ne!(*a, 0);
            for b in &all[i + 1..] { assert_ne!(a, b); }
        }
        assert_eq!(KILLED_SEGV, 139);
        assert_eq!(KILLED_KILL, 137);
    }
}
