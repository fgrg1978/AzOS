// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What a forked x86_64 child inherits from its parent's ring-3 context:
//! the 15 general registers (the trap frame's order, [`gpr`]), RSP, RFLAGS,
//! the FS and GS bases, and the FP/SIMD state as an XSAVE image. The
//! scheduler keeps one per task (`azos_sched::UserRegs`, `Task::fork_regs`),
//! so the FP image travels with the child instead of being read from the
//! parent's live area later, when the parent may already have moved on.
//!
//! `FP` is the XSAVE area size (Kconfig `X86_XSAVE_AREA_BYTES`), a const
//! parameter so this crate needs no Kconfig of its own.

/// Indices into the 15-register file, shared by the kernel's `TrapFrame`
/// (`kernel/src/entry/x86_64.rs`, which the entry asm fills in this order)
/// and [`ForkRegs::gpr`].
pub mod gpr {
    pub const RAX: usize = 0;
    pub const RBX: usize = 1;
    pub const RCX: usize = 2;
    pub const RDX: usize = 3;
    pub const RSI: usize = 4;
    pub const RDI: usize = 5;
    pub const RBP: usize = 6;
    pub const R8: usize = 7;
    pub const R9: usize = 8;
    pub const R10: usize = 9;
    pub const R11: usize = 10;
    pub const R12: usize = 11;
    pub const R13: usize = 12;
    pub const R14: usize = 13;
    pub const R15: usize = 14;
    /// Registers in the file.
    pub const COUNT: usize = 15;
}

/// [`ForkRegs`] at the kernel's configured XSAVE area (Kconfig
/// `X86_XSAVE_AREA_BYTES`): the type a task slot holds. Kernel builds only
/// (the symbol exists under ARCH_X86_64).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub type TaskForkRegs = ForkRegs<{ azos_limits::X86_XSAVE_AREA_BYTES }>;

/// A forked child's starting ring-3 context.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug)]
pub struct ForkRegs<const FP: usize> {
    /// XSAVE (or FXSAVE) image, 64-byte aligned at offset 0.
    pub fp: [u8; FP],
    /// rax..r15 in [`gpr`] order.
    pub gpr: [u64; gpr::COUNT],
    pub rsp: u64,
    pub rflags: u64,
    pub fs_base: u64,
    pub gs_base: u64,
}

impl<const FP: usize> Default for ForkRegs<FP> {
    /// Zero registers, the initial FP image.
    fn default() -> Self {
        let mut r = ForkRegs { fp: [0; FP], gpr: [0; gpr::COUNT], rsp: 0, rflags: 0, fs_base: 0, gs_base: 0 };
        if FP >= crate::fpu::LEGACY_BYTES {
            crate::fpu::init_area(&mut r.fp);
        }
        r
    }
}
