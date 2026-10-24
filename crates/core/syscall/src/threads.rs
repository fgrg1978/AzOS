// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The native thread calls (wave 13, THREADS): `SYS_THREAD_CREATE`,
//! `SYS_THREAD_EXIT`. The futex calls are `crate::vdso_notify`'s.
//! See `azos_abi::syscall_nr` for the ABI and `azos_sched::group` for
//! what a thread group shares. The Linux personality's `clone` (thread
//! shape), `futex`, `exit` and `set_tid_address` reach the same kernel code.

/// `SYS_THREAD_CREATE(entry, stack, arg, ctid, tls)`.
pub fn sys_thread_create(
    entry: u64,
    stack: u64,
    arg: u64,
    ctid: u64,
    tls: u64,
    regs: &azos_sched::UserRegs,
) -> i64 {
    // The argument reaches the thread in its third argument register
    // (`thread_create_impl` writes it: aarch64 hands this call no snapshot).
    if stack == 0 || stack & 15 != 0 || ctid & 3 != 0 {
        return -1;
    }
    // The thread starts with exactly `tls`, 0 included, on every ISA: a 0
    // is a thread with no thread pointer, never the creator's (riscv64 used
    // to copy the creator's `tp` from its frame; aarch64 and x86_64 gave 0).
    // Every native caller that passes 0 sets the register itself (relibc's
    // thread shim) or has no use for it (azos_stdrt, libsys threads). Gate
    // canary `thread-tls-zero-canary`: the old rule, 0 keeps the creator's.
    let tls = if cfg!(feature = "thread-tls-zero-canary") { (tls != 0).then_some(tls) } else { Some(tls) };
    azos_sched::process::thread_create_impl(entry, stack, tls, ctid, regs, Some(arg), &mut |_| true)
}

/// `SYS_THREAD_EXIT(code)`.
pub fn sys_thread_exit(code: u64) -> ! {
    azos_sched::scheduler::thread_exit(code as i32)
}
