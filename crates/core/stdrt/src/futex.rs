// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The futex `std`'s mutex, condition variable, once, rwlock and parker are
//! built on (`SYS_FUTEX_WAIT`, `SYS_FUTEX_WAKE`), on the words of this
//! process.

use core::sync::atomic::AtomicU32;

use crate::sys::syscall6;
use azos_abi::syscall_nr::{SYS_FUTEX_WAIT, SYS_FUTEX_WAKE};

/// The kernel's "timed out" code (`-ETIMEDOUT`).
const TIMED_OUT: isize = -110;

/// Wait while `*addr == expected`, at most `timeout_ns` (`None`: no limit).
/// `false` only when the time ran out; a wake, a changed word and a signal
/// are all `true` (the caller re-checks the word, as `std` does).
pub fn wait(addr: &AtomicU32, expected: u32, timeout_ns: Option<u64>) -> bool {
    // 0 means "no limit" to the kernel: a zero timeout is the shortest wait.
    let t = timeout_ns.map_or(0, |n| n.max(1));
    // SAFETY: a plain call; the kernel validates the address.
    unsafe { syscall6(SYS_FUTEX_WAIT, addr.as_ptr() as u64, expected as u64, t, 0, 0, 0) != TIMED_OUT }
}

/// Wake at most `n` waiters on `addr`; how many were woken.
pub fn wake(addr: &AtomicU32, n: u32) -> usize {
    // SAFETY: as above.
    let r = unsafe { syscall6(SYS_FUTEX_WAKE, addr.as_ptr() as u64, n as u64, 0, 0, 0, 0) };
    r.max(0) as usize
}
