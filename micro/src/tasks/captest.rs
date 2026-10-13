// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `CAPTEST.ELF`: the micro kernel's capability test. The ABI-level cases are
//! the main kernel's own source (`userspace/tests/captest/src/abi_cases.rs`),
//! compiled here against this kernel's `ecall`; the rest is what only this
//! kernel declares: a call through the granted endpoint, the device window
//! and the contiguous block its capabilities map, a spawn under a launch
//! capability, and a task refused by the PMP.

use azos_abi::syscall_nr::{CAP_INFO_LOOKUP, SYS_CAP_CLOSE, SYS_CAP_INFO, SYS_IPC_FAST_CALL_EP, SYS_IPC_FAST_REPLY, SYS_INVOKE, SYS_SPAWN_EX};
use azos_micro::kernel::{StartInfo, REGION_CONTIG, REGION_PHYS};

use super::sys::{self, Line};

#[path = "../../../userspace/tests/captest/src/abi_cases.rs"]
mod abi_cases;

struct Run {
    failures: usize,
}

impl abi_cases::Env for Run {
    fn close_typed(&mut self, handle: usize) -> isize {
        sys::syscall(SYS_CAP_CLOSE, [handle, 0, 0, 0, 0, 0])
    }

    fn cap_lookup(&mut self, kind: usize, resource: usize) -> isize {
        sys::syscall(SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, kind, resource, 0, 0])
    }

    fn fast_call(&mut self, endpoint: usize, w: [usize; 4]) -> isize {
        sys::syscall(SYS_IPC_FAST_CALL_EP, [endpoint, w[0], w[1], w[2], w[3], 0])
    }

    fn fast_reply(&mut self, handle: usize, w: [usize; 4]) -> isize {
        sys::syscall(SYS_IPC_FAST_REPLY, [handle, w[0], w[1], w[2], w[3], 0])
    }

    fn uptime(&mut self) -> usize {
        let opw = (azos_abi::invoke::INVOKE_REGS | azos_abi::invoke::DOMAIN_UPTIME as u64) as usize;
        sys::syscall(SYS_INVOKE, [azos_abi::invoke::DOMAIN_SELF.as_raw() as usize, opw, 0, 0, 0, 0]) as usize
    }

    fn report(&mut self, name: &[u8], ok: bool, rc: isize) {
        Line::new()
            .s(if ok { b"[CAPTEST]   ok   " } else { b"[CAPTEST]  FAIL  " })
            .s(name)
            .s(b" rc=")
            .i(rc)
            .flush();
        if !ok {
            self.failures += 1;
        }
    }
}

pub extern "C" fn main(_region: usize, info: usize) -> ! {
    // SAFETY: the kernel wrote a `StartInfo` at `info`, in this task's region.
    let info = unsafe { &*(info as *const StartInfo) };
    sys::print(b"[CAPTEST] Starting...\n");
    let mut run = Run { failures: 0 };
    abi_cases::run(&mut run);
    let run = &mut run;
    let mut check = |name: &[u8], ok: bool, rc: isize| abi_cases::Env::report(run, name, ok, rc);

    // The timebase counter is 64 bits wide on every word size: a0 and a1.
    let (t0, t1) = (sys::uptime(), sys::uptime());
    check(b"micro: uptime (a0, a1) is a 64-bit counter that does not run backwards", t1 >= t0 && t0 > 0, t1.wrapping_sub(t0) as isize);

    // A number the ABI has not assigned answers -1, as in the main kernel;
    // zero, the table's length and a number far past it are unassigned.
    for nr in [0x7fff, 0, 34] {
        let rc = sys::syscall(nr, [0; 6]);
        check(b"micro: unassigned or absent syscall -> -1", rc == -1, rc);
    }

    // The granted endpoint: a call is answered by the server, which adds
    // one to the first word and leaves the rest.
    match sys::endpoint(0) {
        Some(ep) => match sys::call(ep, [1, 2, 3, 4]) {
            Ok(r) => check(b"micro: echo call answers [2,2,3,4]", r == [2, 2, 3, 4], r[0] as isize),
            Err(e) => check(b"micro: echo call answers [2,2,3,4]", false, e),
        },
        None => check(b"micro: cap_lookup(Endpoint, 0) [granted]", false, -1),
    }

    // The device window and the contiguous block the capabilities map are in
    // the start block, and are usable: a byte to the UART, a pattern to the
    // block and back.
    let mut phys = None;
    let mut contig = None;
    for r in &info.regions[..info.n as usize] {
        match r.kind {
            REGION_PHYS => phys = Some(*r),
            REGION_CONTIG => contig = Some(*r),
            _ => {}
        }
    }
    match phys {
        Some(r) => {
            // SAFETY: the window the `mmio.0` capability maps (the UART's
            // transmit register, write-only here by the PMP rights).
            unsafe { core::ptr::write_volatile(r.base as *mut u8, b'.') };
            sys::print(b"\n");
            check(b"micro: device window mapped (UART byte written)", true, 0);
        }
        None => check(b"micro: device window mapped (UART byte written)", false, -1),
    }
    match contig {
        Some(r) => {
            let p = r.base as *mut u32;
            let words = (r.size as usize / 4).min(64);
            let mut ok = true;
            for i in 0..words {
                // SAFETY: inside the block the `shm` capability maps, RW.
                unsafe { core::ptr::write_volatile(p.add(i), 0xC0DE_0000 + i as u32) };
            }
            for i in 0..words {
                // SAFETY: as above.
                ok &= unsafe { core::ptr::read_volatile(p.add(i)) } == 0xC0DE_0000 + i as u32;
            }
            check(b"micro: contiguous block holds a pattern", ok, words as isize);
        }
        None => check(b"micro: contiguous block holds a pattern", false, -1),
    }

    // Spawn under the launch capabilities of the row: one task that works,
    // one that is refused by the PMP. A name no capability covers is refused.
    let rc = sys::syscall(SYS_SPAWN_EX, [b"SPAWNEE.ELF\0".as_ptr() as usize, 0, 0, 0, 0, 0]);
    check(b"micro: spawn_ex(SPAWNEE.ELF) [launch granted]", rc > 0, rc);
    let rc = sys::syscall(SYS_SPAWN_EX, [b"FAULTER.ELF\0".as_ptr() as usize, 0, 0, 0, 0, 0]);
    check(b"micro: spawn_ex(FAULTER.ELF) [launch granted]", rc > 0, rc);
    let rc = sys::syscall(SYS_SPAWN_EX, [b"ECHO.ELF\0".as_ptr() as usize, 0, 0, 0, 0, 0]);
    check(b"micro: spawn_ex(ECHO.ELF) [no launch grant] -> -EACCES", rc == -(azos_abi::error::Errno::EACCES as isize), rc);
    sys::sleep(50);

    let failed = run.failures;
    if failed == 0 {
        sys::print(b"[CAPTEST] ALL PASSED\n");
        sys::exit(0)
    } else {
        Line::new().s(b"[CAPTEST] FAILED: ").i(failed as isize).s(b" check(s)").flush();
        sys::exit(1)
    }
}
