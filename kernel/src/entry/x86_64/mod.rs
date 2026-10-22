// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 entry: the `TrapFrame` `x86_64/asm/trap_entry.S` builds; `trap.rs` is
//! the Rust dispatcher that asm calls (the same routing as
//! `riscv64_trap_handler` / `aarch64_trap_entry`) with the frame decode, and the
//! first entry into ring 3; `irq.rs` the interrupt side.
//!
//! **Frame.** Every entry builds one shape, whatever the way in: the CPU's
//! `iretq` frame (or `syscall_entry`'s copy of one), the error code (a 0 the
//! stub pushes when the CPU does not), the vector ([`idt::SYSCALL_VECTOR`]
//! for `syscall`), the 15 general registers, and two software words. Every
//! offset the asm uses is injected from `offset_of!` on this struct
//! (`kernel/src/main.rs`), never copied.
//!
//! **Returns.** The dispatcher returns the CR3 word to install before the
//! return (0 = keep), as riscv64 returns a `satp` and aarch64 a `TTBR0`: the
//! only nonzero case is an `exec` consumed on this syscall.
//!
//! Not here yet: Linux-ABI signal delivery on the way to ring 3 (aarch64's
//! `signal_return`; `azos_linux_abi::signal::Context` is aarch64-shaped).

#![cfg(target_arch = "x86_64")]

/// x86_64-only boot extras with no counterpart on the other ISAs.
pub(crate) mod ext;
pub(crate) mod fp;

use core::sync::atomic::{AtomicU64, Ordering};

use azos_arch::fork_regs::gpr;
use azos_arch::cpu;
use azos_arch::trap::{gdt, idt};

/// Interrupt dispatch (vectors >= 32) and the tick.
pub mod irq;
/// Secondary-CPU entry and bring-up check.
pub(crate) mod resume;
pub(crate) mod smp;
/// The dispatcher `trap_entry.S` calls, the preemption point, the user-fault
/// policy and the first entry into ring 3.
pub(crate) mod trap;

/// The register file `trap_entry.S` saves (layout fixed by that asm, which
/// takes every offset from this struct).
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct TrapFrame {
    /// CR2 at a #PF, written by the dispatcher before anything can enable
    /// interrupts (software slot; 0 for every other vector).
    pub cr2: u64,
    /// The IST entry's saved GS base (`ist_common`); unused elsewhere.
    pub gs_saved: u64,
    /// rax..r15 in `azos_arch::fork_regs::gpr` order.
    pub regs: [u64; gpr::COUNT],
    /// The IDT vector the stub pushed, or `idt::SYSCALL_VECTOR`.
    pub vector: u64,
    /// The CPU-pushed error code (0 for vectors without one).
    pub error_code: u64,
    /// The `iretq` frame.
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

// The hardware frame is the tail: the CPU pushed it, so nothing may follow.
const _: () = assert!(core::mem::size_of::<TrapFrame>() == 192);
const _: () = assert!(core::mem::size_of::<TrapFrame>() % 16 == 0,
    "the frame starts 16-byte aligned (the CPU aligns RSP before pushing) so the asm can call Rust");
const _: () = assert!(core::mem::offset_of!(TrapFrame, ss) == core::mem::size_of::<TrapFrame>() - 8);
const _: () = assert!(core::mem::offset_of!(TrapFrame, rip) == core::mem::size_of::<TrapFrame>() - 40);
const _: () = assert!(core::mem::offset_of!(TrapFrame, error_code) + 8 == core::mem::offset_of!(TrapFrame, rip));
const _: () = assert!(core::mem::offset_of!(TrapFrame, vector) + 8 == core::mem::offset_of!(TrapFrame, error_code));
const _: () = assert!(
    core::mem::offset_of!(TrapFrame, regs) + 8 * gpr::COUNT == core::mem::offset_of!(TrapFrame, vector));

/// Offset of register `r` (`gpr` index) in the frame, for the asm.
pub const fn tf_reg(r: usize) -> usize {
    core::mem::offset_of!(TrapFrame, regs) + 8 * r
}

/// x86_64 Linux syscall convention: number in rax, arguments in rdi, rsi,
/// rdx, r10, r8, r9 (rcx and r11 are taken by `syscall` itself).
const SYSCALL_ARGS: [usize; 6] = [gpr::RDI, gpr::RSI, gpr::RDX, gpr::R10, gpr::R8, gpr::R9];
/// The registers `SyscallOut` writes back (riscv64 a1..a6, aarch64
/// x1..x6): every register `syscall` preserves other than rax, in the
/// order rdx (the SysV second return register), rsi, rdi, r8, r9, r10.
const SYSCALL_OUT: [usize; 6] = [gpr::RDX, gpr::RSI, gpr::RDI, gpr::R8, gpr::R9, gpr::R10];

/// [`TrapFrame::vector`] of a frame the kernel built or rewrote rather than
/// saved: a fresh image's ([`TrapFrame::user`]) and a foreign-ABI resume's
/// (`trap::foreign_return`). Not `idt::SYSCALL_VECTOR`, so the lean
/// `syscall_return` sends the frame through `trap_return`'s `iretq`, which
/// restores every register from it, rcx and r11 included (K1 M1). Nothing
/// decodes it: the next entry stores its own vector.
pub(crate) const REBUILT_VECTOR: u64 = 0;
const _: () = assert!(REBUILT_VECTOR != idt::SYSCALL_VECTOR);

impl TrapFrame {
    /// The frame of a fresh ring-3 entry: `rip`/`rsp`, user selectors,
    /// IF set, every general register zero (K-C18: no kernel value reaches
    /// ring 3).
    pub const fn user(rip: u64, rsp: u64) -> Self {
        TrapFrame {
            cr2: 0,
            gs_saved: 0,
            regs: [0; gpr::COUNT],
            vector: REBUILT_VECTOR,
            error_code: 0,
            rip,
            cs: gdt::USER_CS as u64,
            rflags: cpu::USER_RFLAGS_INIT,
            rsp,
            ss: gdt::USER_DS as u64,
        }
    }
}
