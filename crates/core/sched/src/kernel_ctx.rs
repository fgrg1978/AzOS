// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The rule `process::copy_to_user` and its siblings apply to a task with no
//! user page table (a kernel task, or the boot hart before the scheduler):
//! which addresses it may name.
//!
//! A kernel task legitimately passes kernel pointers through the syscall
//! handlers (the `kcall` transport hands `sys_ipc_accept_v2` a descriptor on
//! its stack). Those sit at and above the user ceiling. An address BELOW it
//! is a user address, and a task with no user page table has no translation
//! for it: the copy used to be a raw `memcpy` through that VA, which the
//! hart's translation root does not map, and ended in `[FATAL] Kernel page
//! fault` (task `thread`, store to `0x14fb8`). The helpers refuse it now.
//!
//! Pure on purpose: `tests/host/sched-wake-tests` compiles this file as it is.

/// The lowest address a task without a user page table may name, given the
/// board's `ram_base`, the user ceiling (`process::USER_STACK_TOP`) and
/// whether the kernel is riscv64.
///
/// One layout has kernel memory BELOW the ceiling: K1 (riscv64, RAM at 0),
/// whose identity map owns the low addresses a user image would use, so no
/// ceiling separates the two; it keeps the unchecked behaviour (floor 0).
/// x86_64 also reports RAM base 0 but links the kernel in the higher half,
/// so its floor is the ceiling.
pub const fn floor(ram_base: usize, user_ceiling: usize, riscv64: bool) -> usize {
    if ram_base == 0 && riscv64 { 0 } else { user_ceiling }
}

/// May a task with no user page table name `addr` (the first byte of the
/// range; the caller has already refused a range that wraps)? A range that
/// starts under `floor` and runs over it is a user range.
pub const fn addr_ok(addr: usize, floor: usize) -> bool {
    addr >= floor
}
