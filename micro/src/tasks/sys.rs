// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The U-mode side of the syscalls: `ecall` with the register convention of
//! `azos_abi::syscall_nr` (number in a7, arguments a0..a5, result a0), one
//! machine word wide. The tasks hold no static data (U-mode reaches only
//! its own region), so everything here is on the stack.

use core::arch::asm;

use azos_abi::cap::ty;
use azos_abi::invoke::{DOMAIN_SELF, DOMAIN_UPTIME, INVOKE_REGS, LOG_CONSOLE_WRITE};
use azos_abi::syscall_nr::*;

/// Issue syscall `nr`.
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

/// An accepted request: what `SYS_IPC_FAST_ACCEPT` returns of it (a1, the
/// caller's TID, and a6, the handle of a moved capability, are not used by
/// these tasks).
#[derive(Clone, Copy)]
pub struct Request {
    /// The exchange handle: pass it back untouched.
    pub handle: usize,
    /// The four words.
    pub words: [usize; 4],
}

/// Run an accept-shaped syscall (accept, or reply and accept) and read the
/// request; `None` when it answered with an error code.
fn accept_call(nr: u64, a: [usize; 6]) -> Option<Request> {
    let (r0, r2, r3, r4, r5): (isize, usize, usize, usize, usize);
    // SAFETY: as `syscall`; the kernel writes a0..a6 on these two calls.
    unsafe {
        asm!(
            "ecall",
            in("a7") nr as usize,
            inlateout("a0") a[0] => r0,
            inlateout("a1") a[1] => _,
            inlateout("a2") a[2] => r2,
            inlateout("a3") a[3] => r3,
            inlateout("a4") a[4] => r4,
            inlateout("a5") a[5] => r5,
            lateout("a6") _,
            options(nostack),
        );
    }
    if r0 < 0 {
        return None;
    }
    Some(Request { handle: r0 as usize, words: [r2, r3, r4, r5] })
}

/// Block for the next request on any endpoint this task serves.
pub fn accept() -> Request {
    loop {
        if let Some(r) = accept_call(SYS_IPC_FAST_ACCEPT, [0; 6]) {
            return r;
        }
    }
}

/// Answer `handle` with `words` and block for the next request.
pub fn reply_accept(handle: usize, words: [usize; 4]) -> Request {
    match accept_call(SYS_IPC_FAST_REPLY_ACCEPT, [handle, 0, words[0], words[1], words[2], words[3]]) {
        Some(r) => r,
        // The reply went nowhere: take the next request the plain way.
        None => accept(),
    }
}

/// Call the endpoint `ep` with four words; the four reply words.
pub fn call(ep: usize, words: [usize; 4]) -> Result<[usize; 4], isize> {
    let (r0, r1, r2, r3): (isize, usize, usize, usize);
    // SAFETY: as `syscall`; the reply comes back in a0..a3.
    unsafe {
        asm!(
            "ecall",
            in("a7") SYS_IPC_FAST_CALL_EP as usize,
            inlateout("a0") ep => r0,
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

/// The 64-bit timebase counter: the uptime op of the task's own domain answers
/// its low word in a0 and the rest in a1 (a word alone wraps in minutes at the
/// timebase).
pub fn uptime() -> u64 {
    let (lo, hi): (usize, usize);
    let opw = (INVOKE_REGS | DOMAIN_UPTIME as u64) as usize;
    // SAFETY: as `syscall`; the kernel writes a0 and a1 on this call.
    unsafe {
        asm!(
            "ecall",
            in("a7") SYS_INVOKE as usize,
            inlateout("a0") DOMAIN_SELF.as_raw() as usize => lo,
            inlateout("a1") opw => hi,
            lateout("a2") _,
            lateout("a3") _,
            lateout("a4") _,
            lateout("a5") _,
            lateout("a6") _,
            options(nostack),
        );
    }
    azos_micro::kernel::join_words(lo as u64, hi as u64, usize::BITS)
}

/// Write to the console: look up this task's console handle, then its `WRITE`
/// op.
pub fn print(b: &[u8]) {
    let h = syscall(SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::CONSOLE.raw() as usize, 0, 0, 0]);
    if h > 0 {
        syscall(
            SYS_INVOKE,
            [h as usize, (INVOKE_REGS | LOG_CONSOLE_WRITE as u64) as usize, b.as_ptr() as usize, b.len(), 0, 0],
        );
    }
}

/// End the task.
pub fn exit(code: isize) -> ! {
    syscall(SYS_EXIT, [code as usize, 0, 0, 0, 0, 0]);
    loop {}
}

/// Sleep `ms` milliseconds.
pub fn sleep(ms: usize) {
    syscall(SYS_SLEEP_UNTIL, [ms.saturating_mul(1_000_000), SLEEP_RELATIVE as usize, 0, 0, 0, 0]);
}

/// The handle of the endpoint capability naming endpoint `index`.
pub fn endpoint(index: usize) -> Option<usize> {
    let h = syscall(SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, azos_abi::cap::CapKind::Endpoint as usize, index, 0, 0]);
    (h > 0).then_some(h as usize)
}

/// One console line built in a buffer and written with one call.
pub struct Line {
    buf: [u8; 128],
    n: usize,
}

impl Line {
    /// An empty line.
    pub fn new() -> Self {
        Line { buf: [0; 128], n: 0 }
    }

    /// Append bytes (truncated at the buffer's end).
    pub fn s(&mut self, b: &[u8]) -> &mut Self {
        let take = b.len().min(self.buf.len() - self.n);
        self.buf[self.n..self.n + take].copy_from_slice(&b[..take]);
        self.n += take;
        self
    }

    /// Append a signed decimal.
    pub fn i(&mut self, v: isize) -> &mut Self {
        if v < 0 {
            self.s(b"-");
        }
        let mut n = v.unsigned_abs();
        let mut tmp = [0u8; 12];
        let mut i = tmp.len();
        if n == 0 {
            i -= 1;
            tmp[i] = b'0';
        }
        while n > 0 {
            i -= 1;
            tmp[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        self.s(&tmp[i..])
    }

    /// End the line and write it.
    pub fn flush(&mut self) {
        self.s(b"\n");
        print(&self.buf[..self.n]);
        self.n = 0;
    }
}
