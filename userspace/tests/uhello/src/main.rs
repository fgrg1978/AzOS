// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Minimal Rust user-space program (E11.AQ3 phase-1 de-risk).
//!
//! Proves that a `no_std` / `no_main` Rust binary built against `libsys` and
//! linked by its target spec alone (sdk/targets: no linker script) loads and
//! runs via the kernel's ELF exec path — the
//! prerequisite for a real userspace driver process. Prints a line, makes one
//! call its seccomp profile does not allow, and is killed by it.
//!
//! THE REFUSAL CHECK. The kernel installs `UHELLO.ELF`'s profile at exec
//! (`crates/core/sched/src/seccomp.rs`, `IMAGE_PROFILES`): putchar, exit and
//! write. The call outside it is `SYS_IPC_FAST_CALL_EP`, with a null
//! capability. Filtered, the call never returns: the kernel records the
//! denial and kills the task (exit 159, `seccomp_deny_kill`). Unfiltered, the
//! null capability is refused with a negative value and this program prints
//! `FAILED:` and exits 1. The native syscall entries send the two IPC fast
//! calls through a branch of their own (Chain E cut 7), so this is also the
//! runtime proof that the filter stands in front of that branch. The
//! `userspace: minimal Rust ELF` scenario in `tools/ci_check.sh` asserts the
//! kill line, and abitest's `check_spawn` (every ISA) the exit status.

#![no_std]
#![no_main]

use azos_libsys as sys;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    sys::println(b"[uhello] Rust user-space ELF running");
    let _ = sys::fast_ipc_call_ep_status(0, [0; sys::FAST_IPC_MAX_WORDS], sys::NO_CAP_TO_MOVE);
    sys::println(b"[uhello] FAILED: a fast IPC call outside the UHELLO.ELF profile was answered");
    sys::exit(1);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(1);
}
