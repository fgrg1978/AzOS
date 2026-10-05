// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 `fork()` hand-off register file — the userspace context a child
//! must resume with, captured at the parent's `svc` and replayed through
//! `sret_to_user_forked` (`crates/core/sched/src/process.rs`).
//!
//! **Why this exists and not a second `[u64; 32]` padded like RISC-V's.**
//! RISC-V's fork snapshot (`crates/core/sched::task::UserRegs = [u64; 32]`) is
//! `x0..x31` verbatim — RISC-V's whole user-visible register file, `sp`
//! included (`x2`), fits in that one array, so it doubles as both the
//! syscall dispatcher's generic `regs` parameter AND the RISC-V trap
//! frame's own GPR block (`arch-riscv64::trap::TrapFrame::regs`).
//!
//! AArch64 has no such single array: `sp` at EL0 is the BANKED register
//! `SP_EL0`, not one of `x0..x30`, and the parent's `svc`-time PSTATE
//! (`SPSR_EL1`), TLS pointer (`TPIDR_EL0`) and the full NEON/FP file
//! (`V0..V31` + `FPSR`/`FPCR`) are none of them GPRs either. Before this
//! type existed, `kernel/src/entry/aarch64.rs`'s `aarch64_trap_entry`
//! zero-padded the 31 GPRs into a `[u64; 32]` just to satisfy the shared
//! dispatcher's signature (`let mut regs32 = [0u64; 32]; regs32[..31]
//! .copy_from_slice(&frame.regs);`) — silently dropping `SPSR_EL1`,
//! `TPIDR_EL0` and the whole FP file on the floor. A child forked through
//! that padding would resume with a zeroed FP/SIMD register file (silent
//! corruption for any parent using NEON — that includes this crate's own
//! `Vector::dot_f32`) and no TLS pointer.
//!
//! `ForkRegs` carries every piece of EL0 context `sret_to_user_forked`'s
//! aarch64 arm needs to replay, in the same spirit as RISC-V's array: one
//! value, captured once at the parent's `svc`, copied onto the child's own
//! `Task` slot, and read back by the child on its own kernel stack. Its
//! `fpstate` field is literally [`crate::fp_state::FpState`] — the SAME
//! 528-byte layout the kernel's lazy-FP save areas use
//! (`kernel/src/entry/aarch64/fp_lazy.rs`, `context_switch.S`) — not a
//! second copy of that contract. The trap path itself no longer saves FP.

use crate::fp_state::FpState;

/// Register count for the AArch64 general-purpose file this snapshot
/// carries — x0..x30 (x31 is SP/ZR depending on context; at EL0 it is
/// `SP_EL0`, stored separately below, exactly as
/// `kernel::entry::aarch64::TrapFrame` splits it).
pub const NUM_GPR: usize = 31;

/// A forked child's complete AArch64 EL0 context, captured from the
/// parent's `TrapFrame` at the moment of its `svc` (`SYS_FORK`/
/// `SYS_FORK_COW`).
///
/// **Deliberately does NOT carry `ELR_EL1`.** The child's resume PC is
/// passed to `sret_to_user_forked` as its own `entry: usize` parameter —
/// mirroring RISC-V, where `sepc` is likewise a separate parameter and not
/// smuggled into the `[u64; 32]` snapshot. See that function's aarch64 arm
/// for why the value must be the parent's raw `ELR_EL1` UNCHANGED (the ARM
/// ARM already leaves it pointing past the `svc`; RISC-V's sibling adds 4
/// to its own raw `sepc` for the same purpose, because `sepc` is left
/// pointing AT the `ecall` — the two ISAs' "the instruction after the
/// syscall" is computed differently, and computing it is the caller's job,
/// not this struct's).
///
/// Field order and total size are exercised by the `const` asserts below;
/// `sret_to_user_forked`'s aarch64 arm indexes every field beyond `gpr`
/// through `core::mem::offset_of!` on THIS struct rather than a
/// hand-counted byte offset — the array elements themselves (`gpr[i]`) are
/// indexed `i * 8` from the struct base the same way RISC-V's own
/// `sret_to_user_forked` indexes its `[u64; 32]`, which is not the
/// "hand offset" the struct-level fields must avoid: array elements are a
/// single homogeneous type with a language-guaranteed stride, nothing a
/// struct reorder could silently desync.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct ForkRegs {
    /// `x0..x30` at the parent's `svc`. `x0` becomes `0` in the child (the
    /// `fork()` return value) — done in `sret_to_user_forked`, not here, so
    /// this struct stays a faithful, unedited snapshot of what the parent
    /// actually had.
    pub gpr: [u64; NUM_GPR],
    /// `SP_EL0` — the user stack pointer. Not part of `gpr` (see the module
    /// doc): AArch64 banks EL0's SP separately from `x0..x30`.
    pub sp_el0: u64,
    /// `SPSR_EL1` at the parent's `svc` — the PSTATE `eret` must restore so
    /// the child resumes in the exact same mode (EL0t) and condition-flag
    /// state the parent's `svc` trapped from.
    pub spsr_el1: u64,
    /// `TPIDR_EL0` — the userspace TLS/thread-pointer register. EL1 never
    /// writes it (this kernel's own hart id lives in `TPIDR_EL1` — see
    /// `crates/core/sched/src/smp.rs`), so a syscall round-trip on the SAME task
    /// preserves it for free by simply never touching it; a forked CHILD is
    /// a brand-new task dispatched onto a kernel stack that never ran the
    /// parent's code, so nothing carries the parent's `TPIDR_EL0` across
    /// unless this snapshot does.
    pub tpidr_el0: u64,
    /// The parent's full NEON/FP file at the `svc` (`fp_lazy::
    /// snapshot_current`: from the registers if live, else its save area). A
    /// child that resumes with a zeroed FP file has silently lost whatever
    /// vector state the parent's compiled code (or this crate's own
    /// `Vector::dot_f32`) was carrying — see the module doc.
    pub fpstate: FpState,
}

// `gpr` must be the struct's first field at offset 0: `sret_to_user_forked`
// indexes x1..x30 as `i * 8` bytes from the struct's own base pointer,
// exactly as RISC-V's sibling indexes its `[u64; 32]` from `regs.as_ptr()`.
// A reorder that moved `gpr` off offset 0 would silently break that
// indexing without changing anything this assert doesn't already check.
const _: () = assert!(
    core::mem::offset_of!(ForkRegs, gpr) == 0,
    "ForkRegs::gpr must stay the first field — sret_to_user_forked's asm \
     indexes x1..x30 as i*8 from the struct base",
);
const _: () = assert!(
    core::mem::size_of::<ForkRegs>() == 800,
    "ForkRegs changed size: update this assert (and re-check \
     sret_to_user_forked's aarch64 arm still reads every field it expects)",
);
const _: () = assert!(
    core::mem::align_of::<ForkRegs>() == 16,
    "ForkRegs must be 16-byte aligned: it embeds FpState, which stp/ldp q \
     instructions require to be 16-byte aligned",
);
