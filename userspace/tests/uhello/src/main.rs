// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Minimal Rust user-space program (E11.AQ3 phase-1 de-risk).
//!
//! Proves that a `no_std` / `no_main` Rust binary built against `libsys` and
//! linked at VA 0x10000 loads and runs via the kernel's ELF exec path — the
//! prerequisite for a real userspace driver process. Prints a line, makes one
//! call its seccomp profile does not allow, and exits.
//!
//! THE REFUSAL CHECK. The kernel installs `UHELLO.ELF`'s profile at exec
//! (`crates/core/sched/src/seccomp.rs`, `IMAGE_PROFILES`): putchar, exit and write.
//! `getpid` is outside it. Unfiltered, `getpid` answers the task id, which is
//! positive; the filter answers `-1` (`E_PERM_DISPATCH`), and nothing else on
//! that path can. So `-1` proves the profile is in force and refused a call
//! outside it, and a positive value proves it is not. The
//! `userspace: minimal Rust ELF` scenario in `tools/ci_check.sh` asserts the
//! refusal line.

#![no_std]
#![no_main]

use azos_libsys as sys;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    sys::println(b"[uhello] Rust user-space ELF running");
    if sys::getpid() == sys::E_PERM_DISPATCH {
        sys::println(b"[uhello] seccomp refused getpid outside the UHELLO.ELF profile");
        sys::exit(0);
    }
    sys::println(b"[uhello] FAILED: getpid outside the UHELLO.ELF profile was answered");
    sys::exit(1);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(1);
}
