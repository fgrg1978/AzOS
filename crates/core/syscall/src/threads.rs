// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The native thread calls (wave 13, THREADS): `SYS_THREAD_CREATE` (620),
//! `SYS_THREAD_EXIT` (621), `SYS_FUTEX_WAIT` (622), `SYS_FUTEX_WAKE` (623).
//! See `azos_abi::syscall_nr` for the ABI and `azos_sched::group` for
//! what a thread group shares. The Linux personality's `clone` (thread
//! shape), `futex`, `exit` and `set_tid_address` reach the same kernel code.

/// Read the aligned 32-bit user word at `addr`.
pub(crate) fn read_u32(addr: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    (addr != 0 && azos_sched::copy_from_user(b.as_mut_ptr(), addr as usize, 4))
        .then(|| u32::from_ne_bytes(b))
}

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
    let tls = (tls != 0).then_some(tls);
    azos_sched::process::thread_create_impl(entry, stack, tls, ctid, regs, Some(arg), &mut |_| true)
}

/// `SYS_THREAD_EXIT(code)`.
pub fn sys_thread_exit(code: u64) -> ! {
    azos_sched::scheduler::thread_exit(code as i32)
}

/// `SYS_FUTEX_WAIT(addr, expected, timeout_ns)`.
pub fn sys_futex_wait(addr: u64, expected: u64, timeout_ns: u64) -> i64 {
    let deadline = (timeout_ns != 0).then(|| {
        azos_drv_sys::timebase::now().saturating_add(azos_abi::time::ns_to_ticks_ceil(
            timeout_ns,
            azos_drv_sys::timebase::TIMER_FREQ,
        ))
    });
    azos_sched::futex::wait(addr, expected as u32, deadline, &read_u32)
}

/// `SYS_FUTEX_WAKE(addr, n)`.
pub fn sys_futex_wake(addr: u64, n: u64) -> i64 {
    azos_sched::futex::wake(addr, n.min(u32::MAX as u64) as u32)
}
