// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RISC-V entry — the top-level trap handlers `trap_entry.S` calls, over the
//! existing `arch_riscv64::trap::TrapFrame` (its `Frame` decode is in `trap.rs`).
//!
//! The trap-entry asm (x0..x31 + CSRs saved onto the kernel stack) is
//! `asm/trap_entry.S`; this module is the Rust it calls.

#![cfg(target_arch = "riscv64")]

mod asm;
pub(crate) mod board_map;
pub(crate) mod ext;
pub(crate) mod irq;
pub(crate) mod resume;
pub(crate) mod smp;
pub(crate) mod trap;

use crate::trap::{Frame, TrapClass};
// Kernel only depends on the `azos_arch` facade, which
// re-exports the active ISA crate. On riscv64 the facade resolves
// to arch-riscv64's `trap` + `cpu` modules.
use azos_arch::trap::{TrapFrame, INTERRUPT_BIT, TRAP_ECALL_FROM_U};

// ── Top-level dispatch ──────────────────────────────────────────────────────
//
// `trap_entry.S` calls these; the cause decode is `Frame::class`, the policy
// behind each arm is `crate::trap`.
/// The interrupt arm of [`riscv64_trap_handler`]. Out of line so the syscall
/// path's frame stays the size it was (inlined, the QSBR guard's registers
/// grew the handler's prologue on every syscall).
#[inline(never)]
fn interrupt_arm(frame: &mut TrapFrame) {
    crate::handle_interrupt(frame, (frame.scause as usize) & !INTERRUPT_BIT);
}

#[unsafe(no_mangle)]
pub extern "C" fn riscv64_trap_handler(frame: &mut TrapFrame) -> usize {
    // Masked-window tracer (`lat-trace`): a trap from a context with `SIE`
    // set opens a window. The interrupt path closes it in `trap_resched`;
    // the exception path here, on return, when the frame goes back to a
    // context with interrupts on (a syscall usually closed it earlier, at
    // its own `enable_all`).
    #[cfg(feature = "lat-trace")]
    let lat_sstatus = frame.sstatus as usize;
    // Lockdep (N1): no lock held when this returns to U-mode.
    let _ld = azos_sync::lockdep::UserReturn::arm(|| frame.came_from_user());
    match frame.class() {
        TrapClass::Interrupt => {
            #[cfg(feature = "lat-trace")]
            azos_arch::lat_hook::trap_enter(lat_sstatus, core::panic::Location::caller());
            interrupt_arm(frame);
            0
        }
        _ => {
            // QSBR (Kconfig RCU_QSBR, N4): only an RT CPU's user mode is an
            // extended quiescent state; nothing here with RCU_NOCBS_CPUS 0.
            let _rcu = azos_sync::qsbr::TrapBoundary::exception(|| frame.came_from_user());
            #[cfg(feature = "lat-trace")]
            azos_arch::lat_hook::trap_enter(lat_sstatus, core::panic::Location::caller());
            // SYSFLOOR: a U-mode `ecall` goes straight to its own path; every
            // other exception (and an S-mode `ecall`) through the full decode.
            let satp = if frame.scause as usize == TRAP_ECALL_FROM_U {
                crate::handle_ecall(frame)
            } else {
                crate::handle_exception(frame)
            };
            #[cfg(feature = "lat-trace")]
            azos_arch::lat_hook::trap_exit(frame.sstatus as usize, core::panic::Location::caller());
            satp
        }
    }
}

/// The lean native entry's ordinary target (trap_entry.S, `trap_from_user`,
/// Chain E cut 7): a native task's U-mode `ecall` other than the two IPC fast
/// calls. [`riscv64_trap_handler`]'s syscall arm without its decode: the lean
/// path is taken only for the `ecall`-from-U cause of a frame tagged native,
/// so the class and the cause are known. The same guards (lockdep's
/// `UserReturn`, the QSBR exception boundary, `lat-trace`'s window), then
/// `handle_ecall`'s body.
#[unsafe(no_mangle)]
pub extern "C" fn riscv64_native_syscall(frame: &mut TrapFrame) -> usize {
    native_syscall::<false>(frame)
}

/// The lean native entry's IPC branch (trap_entry.S, Chain E cut 7): `a7` is
/// `SYS_IPC_FAST_CALL_EP` or `SYS_IPC_FAST_REPLY_ACCEPT`. As
/// [`riscv64_native_syscall`], but the filter verdict alone and the fast path
/// in this frame (`handle_ecall_as::<true>`): no `riscv64_trap_handler`,
/// `handle_ecall` or `kernel::dispatch` frame on the way to
/// `fastpath::entry`. A miss takes the ordinary dispatch from here.
#[unsafe(no_mangle)]
pub extern "C" fn riscv64_fast_ipc_syscall(frame: &mut TrapFrame) -> usize {
    native_syscall::<true>(frame)
}

#[inline(always)]
fn native_syscall<const FAST: bool>(frame: &mut TrapFrame) -> usize {
    #[cfg(feature = "lat-trace")]
    let lat_sstatus = frame.sstatus as usize;
    // As `riscv64_trap_handler`, in its order.
    let _ld = azos_sync::lockdep::UserReturn::arm(|| frame.came_from_user());
    let _rcu = azos_sync::qsbr::TrapBoundary::exception(|| frame.came_from_user());
    #[cfg(feature = "lat-trace")]
    azos_arch::lat_hook::trap_enter(lat_sstatus, core::panic::Location::caller());
    let satp = crate::handle_ecall_as::<FAST>(frame);
    #[cfg(feature = "lat-trace")]
    azos_arch::lat_hook::trap_exit(frame.sstatus as usize, core::panic::Location::caller());
    satp
}

unsafe extern "C" {
    /// The IPC fast path's resume stub (trap_entry.S, Chain E commit 9).
    fn riscv64_ipc_resume_stub();
}

/// The IPC fast path's resume stub, for `azos_syscall::fastpath::set_resume_stub`.
pub(crate) fn ipc_resume_stub() -> usize {
    riscv64_ipc_resume_stub as *const () as usize
}
