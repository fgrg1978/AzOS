// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! I-13's decision, pure: may a fault be rolled back into a restart of the
//! armed control task? `txn.rs` reads the state and acts on the answer; the
//! host suite (`tests/host/actuation-tests`) pulls this file in by `#[path]`.

/// Max consecutive restarts (no tick completed) before escalating to fatal.
pub const MAX_TXN_RESTARTS: u32 = 8;

/// What the trap handler knows when a synchronous exception arrives.
#[derive(Clone, Copy, Debug)]
pub struct Fault {
    /// The ISA's decode found a fault of the whitelist (`txn.rs`: misaligned
    /// load/store) taken in kernel mode. A fault from user mode never is:
    /// the task's own frame would be sent to a kernel entry point.
    pub recoverable: bool,
    /// The task the checkpoint was armed for (0: none armed).
    pub armed_tid: u32,
    /// The task that took the fault.
    pub current_tid: u32,
    /// Restarts since the last completed tick.
    pub streak: u32,
}

/// Roll back only a whitelisted kernel-mode fault of the task that armed the
/// checkpoint, and only while the restart budget lasts: any other task on the
/// same CPU (a kernel task, or a user task the control task was preempted
/// for) would be restarted on the control task's stack, and a deterministic
/// fault would restart it forever.
pub fn may_roll_back(f: Fault) -> bool {
    f.recoverable && f.armed_tid != 0 && f.current_tid == f.armed_tid && f.streak < MAX_TXN_RESTARTS
}
