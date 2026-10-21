// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The riscv32 side of `libsys`: what a task of AzOS-micro (`micro/`) asks of
//! its kernel.
//!
//! Same ABI, one machine word narrower. The numbers, the register convention
//! (`ecall`, number in a7, arguments a0..a5, result a0), the capability types
//! and the op numbers are `azos_abi`'s, the crate the 64-bit half of `libsys`
//! and the main kernel read; only the words are `usize`. The names and shapes
//! are those of the 64-bit functions they correspond to
//! ([`fast_ipc_accept_req`], [`fast_ipc_reply_accept`], [`print`], [`sleep`],
//! [`exit`], [`cap_lookup`]), so a reader of one finds the other.
//!
//! This is a subset, not a port of the whole crate. The rest of `libsys` takes
//! `u64` words (and the rings it re-exports need 64-bit atomics, which an
//! `rv32imac` hart has not), so it is not compiled for riscv32: a deadline
//! silently cut to 32 bits is worse than a function that is not there.
//!
//! **No statics, no vDSO.** A task of AzOS-micro reaches only its own region,
//! so nothing here keeps state: the console handle is looked up on every
//! [`print`] (the 64-bit `console_write` caches it in a static) and the clock
//! is always the trap ([`uptime_words`]); there is no vDSO page to read.

use core::arch::asm;

use azos_abi::cap::ty;
use azos_abi::invoke::{DOMAIN_SELF, DOMAIN_UPTIME, INVOKE_REGS, LOG_CONSOLE_WRITE};
use azos_abi::syscall_nr::{
    CAP_INFO_LOOKUP, SLEEP_RELATIVE, SYS_CAP_INFO, SYS_EXIT, SYS_INVOKE, SYS_IPC_FAST_ACCEPT, SYS_IPC_FAST_CALL_EP,
    SYS_IPC_FAST_REPLY_ACCEPT, SYS_SLEEP_UNTIL,
};

/// Issue syscall `nr` with arguments `a` and return a0.
///
/// The raw trap, for a caller that sweeps the ABI itself (the captest's
/// unassigned-number rows); the wrappers below are for everything else.
#[inline(always)]
pub fn syscall(nr: u64, a: [usize; 6]) -> isize {
    let ret: isize;
    // SAFETY: `ecall` traps to the kernel; every register it writes is
    // declared.
    unsafe {
        asm!(
            "ecall",
            in("a7") nr as usize,
            inlateout("a0") a[0] => ret,
            inlateout("a1") a[1] => _,
            inlateout("a2") a[2] => _,
            inlateout("a3") a[3] => _,
            inlateout("a4") a[4] => _,
            inlateout("a5") a[5] => _,
            lateout("a6") _,
            options(nostack),
        );
    }
    ret
}

/// Terminate the calling task with `code`.
pub fn exit(code: i32) -> ! {
    syscall(SYS_EXIT, [code as usize, 0, 0, 0, 0, 0]);
    // The kernel does not return to a task that exited.
    loop {}
}

/// Sleep for `ms` milliseconds.
///
/// The relative deadline is nanoseconds in ONE word, so the longest sleep is
/// about 4.29 s; a longer `ms` sleeps that long (it saturates, it does not
/// wrap to a short one).
pub fn sleep(ms: u64) {
    let ns = usize::try_from(ms.saturating_mul(1_000_000)).unwrap_or(usize::MAX);
    syscall(SYS_SLEEP_UNTIL, [ns, SLEEP_RELATIVE as usize, 0, 0, 0, 0]);
}

/// Find the handle of a capability this task already holds: the 64-bit
/// `cap_lookup`, answered the same way (a positive handle, `-ENOENT`).
pub fn cap_lookup(kind: u8, resource: u32) -> isize {
    syscall(SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, kind as usize, resource as usize, 0, 0])
}

/// Invoke op `op` on `handle` in the register form (`azos_abi::invoke`): the
/// words go in `a2..a5`, the value comes back in `a0` and four reply words in
/// `a1..a4` (the words passed in when the op replies none).
#[inline(always)]
pub fn invoke(handle: u32, op: u16, w: [usize; 4]) -> (isize, [usize; 4]) {
    let opw = (INVOKE_REGS | op as u64) as usize;
    let ret: isize;
    let (r1, r2, r3, r4): (usize, usize, usize, usize);
    // SAFETY: as `syscall`; the replies land in a1..a4 and are declared
    // written, so the compiler assumes nothing about them across the trap.
    unsafe {
        asm!(
            "ecall",
            in("a7") SYS_INVOKE as usize,
            inlateout("a0") handle as usize => ret,
            inlateout("a1") opw => r1,
            inlateout("a2") w[0] => r2,
            inlateout("a3") w[1] => r3,
            inlateout("a4") w[2] => r4,
            inlateout("a5") w[3] => _,
            lateout("a6") _,
            options(nostack),
        );
    }
    (ret, [r1, r2, r3, r4])
}

/// The timebase counter as the two words the uptime op of the task's own
/// domain answers: the low word (a0) and what is above it (a1). One word
/// alone wraps in minutes at the timebase, so the counter is not truncated;
/// the caller joins the pair at its word size (`join_words` in
/// `micro/src/kernel.rs`, the inverse of the kernel's split), or subtracts the
/// low words for a short interval, which is right across the wrap. Always the
/// trap: the 64-bit `uptime` reads the vDSO page, which this kernel has not.
pub fn uptime_words() -> (usize, usize) {
    let (lo, w) = invoke(DOMAIN_SELF.as_raw(), DOMAIN_UPTIME, [0; 4]);
    (lo as usize, w[0])
}

/// Write `s` to the console: this task's console handle is looked up, then
/// its `WRITE` op invoked. Nothing is written if the task holds no console.
pub fn print(s: &[u8]) {
    let h = cap_lookup(ty::CONSOLE.raw(), 0);
    if h > 0 {
        invoke(h as u32, LOG_CONSOLE_WRITE, [s.as_ptr() as usize, s.len(), 0, 0]);
    }
}

/// The words of a fast IPC message: the 64-bit API carries `u64`s, this one a
/// machine word each.
pub const FAST_IPC_MAX_WORDS: usize = 4;

/// One accepted fast-IPC request, as the server sees it: the 64-bit
/// `FastRequest` without the fields no task of this kernel reads (the
/// caller's TID, a1, and the handle of a moved capability, a6).
#[derive(Clone, Copy)]
pub struct FastRequest {
    /// The exchange handle: pass it back to [`fast_ipc_reply_accept`]
    /// untouched.
    pub handle: usize,
    /// The four request words, as the client passed them.
    pub words: [usize; FAST_IPC_MAX_WORDS],
}

/// Server: block until a client calls an endpoint this task serves, and
/// receive the request. `None` when the kernel answered with an error code
/// (the caller asks again).
pub fn fast_ipc_accept_req() -> Option<FastRequest> {
    let (r0, r2, r3, r4, r5): (isize, usize, usize, usize, usize);
    // SAFETY: as `syscall`; the kernel writes a0..a6 on this call.
    unsafe {
        asm!(
            "ecall",
            in("a7") SYS_IPC_FAST_ACCEPT as usize,
            inlateout("a0") 0usize => r0,
            inlateout("a1") 0usize => _,
            inlateout("a2") 0usize => r2,
            inlateout("a3") 0usize => r3,
            inlateout("a4") 0usize => r4,
            inlateout("a5") 0usize => r5,
            lateout("a6") _,
            options(nostack),
        );
    }
    request(r0, [r2, r3, r4, r5])
}

/// Server: reply to the exchange `handle` names with `words` and accept the
/// next request, in one trap. `Ok(Some(request))` is the next request;
/// `Ok(None)` is a reply that went out with nothing to accept (the caller
/// accepts the plain way); `Err` is the kernel's code for a reply that did not
/// go out.
pub fn fast_ipc_reply_accept(
    handle: usize,
    words: [usize; FAST_IPC_MAX_WORDS],
) -> Result<Option<FastRequest>, isize> {
    let (r0, r2, r3, r4, r5): (isize, usize, usize, usize, usize);
    // SAFETY: as `fast_ipc_accept_req`.
    unsafe {
        asm!(
            "ecall",
            in("a7") SYS_IPC_FAST_REPLY_ACCEPT as usize,
            inlateout("a0") handle => r0,
            inlateout("a1") 0usize => _,
            inlateout("a2") words[0] => r2,
            inlateout("a3") words[1] => r3,
            inlateout("a4") words[2] => r4,
            inlateout("a5") words[3] => r5,
            lateout("a6") _,
            options(nostack),
        );
    }
    match r0 {
        r if r >= 0 => Ok(request(r0, [r2, r3, r4, r5])),
        -1 => Ok(None),
        e => Err(e),
    }
}

/// An accept-shaped answer as a request: a0 is the handle, or a negative code.
fn request(r0: isize, words: [usize; FAST_IPC_MAX_WORDS]) -> Option<FastRequest> {
    (r0 >= 0).then_some(FastRequest { handle: r0 as usize, words })
}

/// Call the endpoint `endpoint` with four words; the four reply words, or the
/// kernel's code (`-1` for a refused or abandoned call, `-EPEERDIED`,
/// `-EREVOKED`). Moves no capability.
pub fn fast_ipc_call_ep_status(
    endpoint: u32,
    words: [usize; FAST_IPC_MAX_WORDS],
) -> Result<[usize; FAST_IPC_MAX_WORDS], isize> {
    let (r0, r1, r2, r3): (isize, usize, usize, usize);
    // SAFETY: as `syscall`; the reply comes back in a0..a3.
    unsafe {
        asm!(
            "ecall",
            in("a7") SYS_IPC_FAST_CALL_EP as usize,
            inlateout("a0") endpoint as usize => r0,
            inlateout("a1") words[0] => r1,
            inlateout("a2") words[1] => r2,
            inlateout("a3") words[2] => r3,
            inlateout("a4") words[3] => _,
            inlateout("a5") 0usize => _,
            lateout("a6") _,
            options(nostack),
        );
    }
    if r0 < 0 {
        return Err(r0);
    }
    Ok([r0 as usize, r1, r2, r3])
}
