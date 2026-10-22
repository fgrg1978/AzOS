// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The foreign-ABI family (plan D6, "Linux ABI without a kernel map"): two
//! native calls that let a ring-3 runtime host the system-call ABI of another
//! operating system inside one address space. The kernel keeps no foreign
//! system-call number and no foreign state; it only bounces a trap to the
//! runtime and takes the thread back when the runtime says so.
//!
//! * [`SYS_FOREIGN_ENTRY`] registers the
//!   runtime's trap entry.
//! * [`SYS_FOREIGN_RESUME`] hands the
//!   thread back to the foreign program with a register frame.
//!
//! # Modes
//!
//! A thread that registered an entry is in one of two modes, a per-thread bit
//! the kernel flips at exactly two points:
//!
//! | mode | what a trap (`ecall`, `svc`, `syscall`) means | enters it |
//! |---|---|---|
//! | *runtime* | a native system call, filtered by the image profile | thread start; a reflected trap |
//! | *foreign* | a foreign system call: reflected to the entry | `SYS_FOREIGN_RESUME` |
//!
//! There is no address-range test and no selector byte: the foreign program
//! and the runtime share the instruction set, so the mode is what tells their
//! traps apart. The mode is published through the same per-CPU filter word the
//! native path already loads, so a native thread's system call pays nothing
//! for the existence of this family.
//!
//! # Reflect
//!
//! A trap taken in foreign mode is not executed. The kernel pushes a
//! [`ForeignFrame`] (every register of the trapping thread; the program
//! counter is the instruction after the trap) on the thread's own user stack,
//! below the stack pointer and the ABI's red zone, 16-byte aligned. It then
//! switches to runtime mode and returns to user mode at the registered entry
//! with the frame address in the first argument register **and** in the stack
//! pointer. The runtime therefore runs on the foreign program's stack, one
//! frame deep per thread, and needs no stack bookkeeping of its own.
//!
//! The foreign system call's number and arguments are in the frame, in the
//! foreign ABI's registers. The runtime answers by writing the result into the
//! frame and calling `SYS_FOREIGN_RESUME(frame)`.
//!
//! The frame holds every register the trap saved. A task created for a
//! foreign ABI (`Task::abi` not native: the tasks a runtime hosts) always has
//! full trap frames, so its frame is the whole register file. A native task
//! that registers an entry (a test, or a runtime of its own) keeps the native
//! calling convention's frames, which do not save the caller-saved registers
//! across a system call; its foreign program may rely on the registers a
//! native call preserves (the callee-saved ones, the stack pointer and
//! the thread pointer) and the argument and result registers, and nothing
//! else.
//!
//! # Resume
//!
//! `SYS_FOREIGN_RESUME(frame)` reads a frame back from user memory, restores
//! every register in it, sets foreign mode and returns to user mode at the
//! frame's program counter. Only the bits of the flags word named by
//! [`FLAGS_USER_MASK`] come from the frame: a frame can change neither the
//! privilege level nor the interrupt mask. The call does not return to its
//! caller; it fails (with the thread still in runtime mode) only for a frame
//! that cannot be read (`-EFAULT`) or a thread with no registered entry
//! (`-EINVAL`).
//!
//! The floating-point and vector state, and the thread pointer, are not part
//! of the frame: they stay in the hardware and in the scheduler's per-thread
//! save area and belong to the foreign program. The runtime must not touch
//! them (it is built soft-float), except in the dedicated routines that
//! build a foreign program's signal frame.
//!
//! # Inheritance
//!
//! A thread created by `SYS_FOREIGN_FORK` or `SYS_THREAD_CREATE` from a
//! registered thread starts in runtime mode with the same entry (it returns
//! from the creating call into the runtime, which resumes it). The Linux
//! `execve` clears the registration. `SYS_FOREIGN_ENTRY(0)` withdraws it.
//!
//! # Authority
//!
//! None is added. The calls change what the thread's own traps mean; every
//! native call the runtime then makes meets the image profile and the
//! capability tables exactly as before. A foreign program that jumps into the
//! runtime gets the runtime's native authority, which is the image's, no more:
//! only the native filter is enforced (a foreign-ABI filter inside the runtime
//! is advisory).

use crate::syscall_nr::{SYS_FOREIGN_ENTRY, SYS_FOREIGN_RESUME};

// The two numbers are the family; keeping them referenced here makes a
// renumbering fail this module's docs instead of drifting.
const _: () = assert!(SYS_FOREIGN_ENTRY + 1 == SYS_FOREIGN_RESUME);

/// A thread's registers at a reflected trap, in the layout every ISA shares.
///
/// `gpr` is indexed by the ISA's own register numbering:
///
/// * riscv64: `gpr[n]` is `xn` (`gpr[0]` is written 0 and ignored by resume;
///   `gpr[2]` is `sp`; the syscall number is `a7` = `gpr[17]`, arguments
///   `a0..a5` = `gpr[10..16]`, the result goes in `gpr[10]`);
/// * aarch64: `gpr[n]` is `xn` for `n` in 0..=30 and `gpr[31]` is `sp`
///   (number `x8` = `gpr[8]`, arguments `x0..x5`, result `gpr[0]`);
/// * x86_64: the hardware encoding order, `gpr[0..16]` = `rax rcx rdx rbx rsp
///   rbp rsi rdi r8..r15`, `gpr[16..32]` unused (number `rax`, arguments
///   `rdi rsi rdx r10 r8 r9`, result `rax`).
///
/// `pc` is the address to continue at (the instruction after the trap).
/// `flags` is aarch64 `PSTATE` (only [`FLAGS_USER_MASK`] is honoured) or
/// x86_64 `RFLAGS`; riscv64 has no user-visible flags and writes 0.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForeignFrame {
    /// The general-purpose registers, by the ISA's numbering (see above).
    pub gpr: [u64; 32],
    /// The address to continue at.
    pub pc: u64,
    /// The condition flags (see above).
    pub flags: u64,
}

impl ForeignFrame {
    /// A frame of zeros.
    pub const ZERO: ForeignFrame = ForeignFrame { gpr: [0; 32], pc: 0, flags: 0 };
}

/// Size of a [`ForeignFrame`] in bytes: the same on every ISA.
pub const FOREIGN_FRAME_SIZE: usize = core::mem::size_of::<ForeignFrame>();
const _: () = assert!(FOREIGN_FRAME_SIZE == 34 * 8);

/// Where a hosted process's runtime is linked and mapped: the page after the
/// vDSO's two, in the vDSO's 2 MiB slot (which every ISA keeps for ring-3
/// fixtures). `userspace/services/lxrt/build.rs` links the runtime here
/// (`tests/host/linux-rt-tests`). The window is clear of the shm/MMIO window
/// on every board (`azos_sched::process`'s `USER_MMIO_BASE` starts at or above
/// [`RUNTIME_LIMIT`]), so a fork copies it.
pub const RUNTIME_BASE: usize = crate::vdso::VDSO_USER_BASE + 0x1_0000;
/// The end of the runtime's window (1 MiB from the vDSO).
pub const RUNTIME_LIMIT: usize = crate::vdso::VDSO_USER_BASE + 0x10_0000;

/// Alignment of the frame's address on the user stack.
pub const FOREIGN_FRAME_ALIGN: u64 = 16;

/// Bytes below the stack pointer that the foreign ABI lets the program use
/// without moving it (the red zone). Only x86_64 has one.
pub const FOREIGN_RED_ZONE: u64 = if cfg!(target_arch = "x86_64") { 128 } else { 0 };

/// Where the kernel puts the frame for a trap taken with stack pointer `sp`:
/// below the red zone, 16-byte aligned. `None` if the stack has no room.
pub const fn frame_base(sp: u64) -> Option<u64> {
    let Some(below) = sp.checked_sub(FOREIGN_RED_ZONE + FOREIGN_FRAME_SIZE as u64) else { return None };
    Some(below & !(FOREIGN_FRAME_ALIGN - 1))
}

/// Bits of [`ForeignFrame::flags`] a resume takes from the frame.
///
/// aarch64: N, Z, C, V (bits 31..28). x86_64: CF, PF, AF, ZF, SF, DF, OF
/// (`0x0cd5`). riscv64: none.
pub const FLAGS_USER_MASK: u64 = if cfg!(target_arch = "aarch64") {
    0xf000_0000
} else if cfg!(target_arch = "x86_64") {
    0x0cd5
} else {
    0
};

/// Index in [`ForeignFrame::gpr`] of the register that carries the foreign
/// system-call number.
pub const REG_NUMBER: usize = if cfg!(target_arch = "aarch64") {
    8
} else if cfg!(target_arch = "x86_64") {
    0
} else {
    17
};

/// Index of the register that carries a foreign call's result (and, except on
/// x86_64, its first argument).
pub const REG_RESULT: usize = if cfg!(target_arch = "aarch64") {
    0
} else if cfg!(target_arch = "x86_64") {
    0
} else {
    10
};

/// Index of the first argument register of the native calling convention:
/// where the kernel puts the frame address when it enters the runtime.
pub const REG_FIRST_ARG: usize = if cfg!(target_arch = "aarch64") {
    0
} else if cfg!(target_arch = "x86_64") {
    7
} else {
    10
};

/// Index of the stack pointer in [`ForeignFrame::gpr`].
pub const REG_SP: usize = if cfg!(target_arch = "aarch64") {
    31
} else if cfg!(target_arch = "x86_64") {
    4
} else {
    2
};
