// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ktest `copyout_refused_in_kernel_context`: a task with no user page table
//! (this one, a kernel task) that names a user-range address to a copy helper
//! is refused, and nothing is stored through it.
//!
//! The crash it pins: `[PAGE FAULT] CPU 3 - Store/AMO page fault at 0x14fb8`
//! in task `thread`, `sepc` in `compiler_builtins`' word copy, `ra` in
//! `copy_to_user`, then `[FATAL] Kernel page fault` (riscv64 `-smp 4`, the
//! GPIODRV autorun volume, host load 17-25, right after `[AQ3] GPIO ring-3
//! round-trip OK`). A task whose `current_user_pt()` read 0 took the helper's
//! kernel-context branch, which memcpy'd straight to the user VA the syscall
//! carried (`sys_ipc_accept_v2`'s `write_desc` into the endpoint thread's
//! stack, in gpio_drv's image). Two changes close it:
//!
//! - `current_user_pt()` reads the hart id and that hart's slot with
//!   interrupts masked (`scheduler/budget.rs`). The pair was open to a tick
//!   that moved the task between the two steps, so a ring-3 task could read a
//!   kernel task's `0`. The race itself needs a migration at one instruction
//!   and cannot be forced from a ktest; the test pins the part it can see,
//!   that the call leaves the interrupt state as it found it (enabled stays
//!   enabled, masked stays masked: it nests), and the `cpuid-probe` gate rows
//!   (`cpuid matches hardware`, `aarch64 cpuid matches hw`) count any call
//!   that ended on another hart (`foreign=0` on every line).
//! - A kernel-context copy to a user-range VA is a refusal
//!   (`azos_sched::process::KERNEL_CTX_FLOOR`), so a kernel task holding a
//!   user pointer reads as an EFAULT and a `[COPYOUT]` line naming the task
//!   instead of a dead machine.
//!
//! It checks, from a kernel task: kernel buffers still copy (the `kcall`
//! transport depends on it); a user-range VA, and a range that starts below
//! the user ceiling and crosses it, are refused by all five helpers with
//! nothing written, and the refusals are counted. The predicates
//! (`user_range_writable`, `user_range_prepare_write`) are asked first, so a
//! broken build fails the test by an answer and not by a fault.
//!
//! Canary (runtime): `canary=copyout-raw-kernel-ctx` stops enforcing the floor
//! (the old behaviour): the first predicate says yes for the user-range VA and
//! the test is `not ok` before any copy runs.

use azos_sched::process::{ktest_raw_kernel_ctx, kernel_ctx_refusals, USER_STACK_TOP};
use azos_sched::{copy_cstr_from_user, copy_from_user, copy_to_user, user_range_prepare_write, user_range_writable};

/// The address the crash stored to: the endpoint thread's stack in a ring-3
/// image linked at 0x1_0000.
const USER_VA: usize = 0x14fb8;

/// Puts the floor back whichever way the test ends.
struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        ktest_raw_kernel_ctx(false);
    }
}

azos_ktest::ktest_late! {
    fn copyout_refused_in_kernel_context() {
        if azos_sched::current_user_pt() != 0 {
            return Err("the ktest task has a user page table: this is not a kernel context");
        }
        let _restore = Restore;

        // `current_user_pt()` masks interrupts across its two-step lookup and
        // must hand the state back as it found it, in either state.
        {
            use azos_arch::Interrupts;
            let was_on = azos_arch::ARCH.interrupts_enabled();
            let _ = azos_sched::current_user_pt();
            if azos_arch::ARCH.interrupts_enabled() != was_on {
                return Err("current_user_pt changed the interrupt state");
            }
            let saved = azos_arch::ARCH.disable_all();
            let _ = azos_sched::current_user_pt();
            let still_masked = !azos_arch::ARCH.interrupts_enabled();
            azos_arch::ARCH.restore(saved);
            if !still_masked {
                return Err("current_user_pt re-enabled interrupts it found masked");
            }
        }
        if canary!("copyout-raw-kernel-ctx") {
            ktest_raw_kernel_ctx(true);
        }

        // The kernel's own pointers keep working: the transport a kernel task
        // uses to call a task server passes a descriptor on its stack.
        let src = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut kdst = [0u8; 8];
        if !user_range_writable(kdst.as_mut_ptr() as usize, kdst.len())
            || !user_range_prepare_write(kdst.as_mut_ptr() as usize, kdst.len())
        {
            return Err("a kernel buffer was refused as a destination");
        }
        if !copy_to_user(kdst.as_mut_ptr() as usize, src.as_ptr(), src.len()) || kdst != src {
            return Err("a copy to a kernel buffer did not land");
        }
        let mut back = [0u8; 8];
        if !copy_from_user(back.as_mut_ptr(), kdst.as_ptr() as usize, back.len()) || back != src {
            return Err("a copy from a kernel buffer did not land");
        }
        let cstr = *b"ktest\0";
        let mut name = [0xffu8; 8];
        if copy_cstr_from_user(&mut name, cstr.as_ptr() as usize) != Some(5) || &name[..6] != &cstr[..] {
            return Err("a C string in kernel memory was not read");
        }

        // A user-range address is refused. The questions first: they touch no
        // memory, so a build that lost the floor fails here, cleanly.
        let before = kernel_ctx_refusals();
        if user_range_writable(USER_VA, 8) {
            return Err("user_range_writable says yes to a user-range VA in kernel context");
        }
        if user_range_prepare_write(USER_VA, 8) {
            return Err("user_range_prepare_write says yes to a user-range VA in kernel context");
        }
        // A range that starts under the ceiling and runs over it is not a kernel range.
        if user_range_writable(USER_STACK_TOP - 4, 8) {
            return Err("a range crossing the user ceiling was accepted as a kernel range");
        }
        // The copies: refused, and nothing written. A store through the VA is
        // the kernel page fault this test exists to prevent.
        if copy_to_user(USER_VA, src.as_ptr(), src.len()) {
            return Err("copy_to_user stored to a user-range VA from a task with no user page table");
        }
        let mut sentinel = [0xa5u8; 8];
        if copy_from_user(sentinel.as_mut_ptr(), USER_VA, sentinel.len()) || sentinel != [0xa5u8; 8] {
            return Err("copy_from_user read a user-range VA from a task with no user page table");
        }
        let mut name = [0xffu8; 8];
        if copy_cstr_from_user(&mut name, USER_VA).is_some() || name != [0xffu8; 8] {
            return Err("copy_cstr_from_user read a user-range VA from a task with no user page table");
        }
        // Six refusals: three questions, three copies.
        if kernel_ctx_refusals().wrapping_sub(before) != 6 {
            return Err("the refusals were not counted");
        }
        Ok(())
    }
}
