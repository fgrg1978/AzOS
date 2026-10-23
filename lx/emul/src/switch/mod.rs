// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! Stack switching for the cooperative tasks of [`crate::sched`].
//!
//! One file per ISA, the same two items in each:
//!
//! * `switch(save, load, ctx)` pushes the callee-saved registers of the
//!   running code onto its own stack, stores the stack pointer in `*save`,
//!   loads `load` as the stack pointer and pops the registers saved there.
//!   It returns into whatever called `switch` on that stack last. `ctx` is
//!   not read: it hands the [`crate::Env`] pointer to the call, so the
//!   compiler treats every byte of the environment as read and written
//!   across a switch and caches nothing of it in registers.
//! * `prepare(top, entry, ctx, arg)` writes the frame a first `switch` to a
//!   new stack pops: the saved return address is a small trampoline that
//!   calls `entry(ctx, arg)` on that stack. `entry` never returns.
//!
//! Only the registers the C ABI makes callee-saved are saved: `switch` is
//! an ordinary call to the code around it, so the caller-saved ones are
//! already dead. The floating-point callee-saved registers are saved when
//! the build has them (`target_feature`); a soft-float build has none.
//!
//! The functions are naked (no prologue, no hand-written symbol name), so
//! the same source assembles as ELF for lxsrv and as Mach-O for the host
//! tests. This is the first user-space context switch in the tree: the
//! kernel's (`kernel/src/entry/<isa>/asm/context_switch.S`) saves
//! supervisor state and runs in ring 0, and relibc's `setjmp` is a libc
//! symbol a `no_std` crate cannot link.

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
use aarch64 as isa;
#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(target_arch = "riscv64")]
use riscv64 as isa;
#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
use x86_64 as isa;
#[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64", target_arch = "x86_64")))]
compile_error!("lx_emul: no task switch for this ISA (switch/<isa>.rs)");

pub(crate) use isa::switch;

/// The first function a new stack runs, with the two words given to
/// [`prepare`]. It must never return: there is no frame to return to.
pub(crate) type Entry = extern "C" fn(*mut u8, usize) -> !;

/// Word written at the lowest address of every task stack and compared at
/// each switch back to the loop: a changed word means the task ran past
/// the end of its stack.
pub(crate) const CANARY: u64 = 0x6c78_5354_4143_4b21;

/// Stack alignment every ISA's ABI asks for at a call.
pub(crate) const ALIGN: usize = 16;

/// Prepare the stack `[base, base + len)` so that the first [`switch`] to
/// the returned stack pointer runs `entry(ctx, arg)` on it, and write the
/// [`CANARY`] at `base`.
///
/// # Safety
///
/// The range must be writable memory that nothing else uses until the task
/// on it has exited, `base` must be 8-byte aligned, and `len` must be large
/// enough for the frame (the caller checks [`crate::sched::MIN_STACK`]).
pub(crate) unsafe fn prepare(base: usize, len: usize, entry: Entry, ctx: *mut u8, arg: usize) -> usize {
    // SAFETY: the caller hands over [base, base + len), 8-byte aligned.
    unsafe {
        (base as *mut u64).write(CANARY);
        isa::prepare((base + len) & !(ALIGN - 1), entry, ctx, arg)
    }
}

/// Whether the canary at `base` is intact.
///
/// # Safety
///
/// `base` must be the base of a stack given to [`prepare`].
pub(crate) unsafe fn canary_intact(base: usize) -> bool {
    // SAFETY: the caller passes a prepared stack's base.
    unsafe { (base as *const u64).read_volatile() == CANARY }
}
