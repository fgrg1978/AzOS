// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The FS base (thread pointer) of a task, as the context switch handles it.
//!
//! Pure, so the host tests run it (`tests/host/arch-tests`).
//!
//! Ring 3 cannot change its own FS base: CR4.FSGSBASE is off (`wrfsbase`
//! is #UD) and no call sets it after the task starts. It is written by the
//! kernel only: at a task's first entry (`SYS_THREAD_CREATE`'s `tls`, a
//! Linux `clone` with `CLONE_SETTLS`, a fork's copy of its parent's), and
//! cleared by exec. The scheduler keeps it per task slot and puts it back
//! at a switch.

/// The FS base a switch from a task whose base is `prev` to one whose base
/// is `next` has to write, or `None` when the MSR already holds it: an MSR
/// write costs far more than the compare, and most switches are between
/// tasks with the same (usually zero) base.
pub const fn fs_base_to_load(prev: u64, next: u64) -> Option<u64> {
    if prev == next { None } else { Some(next) }
}

/// Is `base` a thread pointer a task may be given: a canonical address in the
/// lower (user) half under both 4- and 5-level paging. `wrmsr` of any other
/// value to `IA32_FS_BASE` raises #GP in the kernel.
pub const fn is_user_tls_base(base: u64) -> bool {
    base < (1 << 47)
}
