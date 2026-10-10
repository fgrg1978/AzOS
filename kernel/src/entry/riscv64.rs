// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RISC-V entry — wraps the existing `arch_riscv64::trap::TrapFrame`
//! in the cross-arch [`TrapContext`] trait.
//!
//! The actual trap-entry asm (saving x0..x31 + CSRs onto the
//! kernel stack) lives in `arch_riscv64` boot/trap modules and
//! has been working since before this module existed — it is purely the
//! portable lens over that data. No behaviour change today.

#![cfg(target_arch = "riscv64")]

pub(crate) mod board_map;
pub(crate) mod smp;
pub(crate) mod zicboz;

use core::sync::atomic::AtomicBool;
use super::{TrapClass, TrapContext};
// Kernel only depends on the `azos_arch` facade, which
// re-exports the active ISA crate. On riscv64 the facade resolves
// to arch-riscv64's `trap` + `csr` modules.
use azos_arch::{csr, trap};
use trap::{
    TrapFrame, INTERRUPT_BIT,
    TRAP_ECALL_FROM_U, TRAP_ECALL_FROM_S,
    TRAP_INSTR_PAGE_FAULT, TRAP_LOAD_PAGE_FAULT, TRAP_STORE_PAGE_FAULT,
};

/// Position of the syscall argument registers within `regs[]`.
/// RISC-V calling convention: a0..a7 = x10..x17. Syscall number
/// in a7 (x17); first 6 args in a0..a5 (x10..x15).
const REG_A0: usize = 10;
const REG_SP: usize =  2;
const REG_A7: usize = 17;
const MAX_SYSCALL_ARGS: usize = 6;

impl TrapContext for TrapFrame {
    #[inline]
    fn cause(&self) -> usize {
        self.scause as usize
    }

    #[inline]
    fn class(&self) -> TrapClass {
        let cause = self.scause as usize;
        if cause & INTERRUPT_BIT != 0 {
            TrapClass::Interrupt
        } else {
            match cause {
                TRAP_ECALL_FROM_U | TRAP_ECALL_FROM_S => TrapClass::Syscall,
                TRAP_INSTR_PAGE_FAULT
                | TRAP_LOAD_PAGE_FAULT
                | TRAP_STORE_PAGE_FAULT => TrapClass::PageFault,
                _ => TrapClass::OtherException,
            }
        }
    }

    #[inline]
    fn irq_number(&self) -> usize {
        (self.scause as usize) & !INTERRUPT_BIT
    }

    #[inline]
    fn fault_addr(&self) -> usize {
        self.stval as usize
    }

    #[inline]
    fn pc(&self) -> usize {
        self.sepc as usize
    }

    #[inline]
    fn set_pc(&mut self, pc: usize) {
        self.sepc = pc as _;
    }

    #[inline]
    fn user_sp(&self) -> usize {
        self.regs[REG_SP] as usize
    }

    #[inline]
    fn came_from_user(&self) -> bool {
        // SPP bit: 0 = came from U-mode, 1 = came from S-mode.
        (self.sstatus as usize) & csr::SSTATUS_SPP == 0
    }

    #[inline]
    fn syscall_number(&self) -> usize {
        self.regs[REG_A7] as usize
    }

    #[inline]
    fn syscall_arg(&self, n: usize) -> usize {
        debug_assert!(n < MAX_SYSCALL_ARGS,
            "syscall_arg index out of range (RISC-V passes 6 args in a0..a5)");
        self.regs[REG_A0 + n] as usize
    }

    #[inline]
    fn set_syscall_return(&mut self, v: usize) {
        self.regs[REG_A0] = v as _;
    }
}

/// U01-4 (audit): mirrors `entry::aarch64::SCHED_LIVE` exactly. Phase 3 of
/// `arch_hardware_init` (`entry/riscv64/boot_hooks.rs`) enables `SIE_SEIE |
/// SIE_SSIE` — external AND software (IPI) interrupts — long before
/// `sched::start()` runs; only the timer (`SIE_STIE`) was deferred. A cross-
/// hart IPI landing on the boot hart inside that window runs `handle_
/// interrupt` → `request_resched(hart)` → (trap_entry.S's post-handler call)
/// `trap_resched()`, which used to call `schedule()` unconditionally once
/// `NEED_RESCHED[hart]` was set — with `current_idx == MAX` (no task ever
/// dispatched on this hart yet), the exact shape of the open
/// `current_cpu_id()` anomaly (1 fork success in 7 under load, pre-
/// `sched::start()`). `false` until `arch_enter_scheduler` sets it
/// `Release`, immediately before `azos_sched::start()`; `trap_resched`
/// reads it `Acquire` first and returns without touching `NEED_RESCHED` (or
/// calling `schedule()`) while it is false — same semantics as aarch64's
/// gate. **Not dropped: left set.** The gate check runs BEFORE the
/// `NEED_RESCHED[hart].swap(false, ..)`, so a flag raised while the gate is
/// closed stays set and is consumed by the first `trap_resched` that runs
/// AFTER `SCHED_LIVE` goes true — typically the next timer tick once
/// `start()` has dispatched a real task on this hart. `start()` itself
/// still does not consult `NEED_RESCHED` (it unconditionally dequeues), so
/// nothing here changes which task `start()` picks; it only changes when
/// the FLAG gets acted on.
pub static SCHED_LIVE: AtomicBool = AtomicBool::new(false);

// ── B2-04: top-level dispatch, routed through TrapContext ──────────────────
//
// `trap_entry.S` used to call a `trap_handler` in `main.rs` that did the
// scause-bit dispatch by hand: `let cause = frame.scause as usize; if cause &
// INTERRUPT_BIT != 0 { handle_interrupt(..) } else { handle_exception(..) }` —
// reading the CSR field directly instead of through this module's own
// `TrapContext` impl, which is what B2-04 flagged as 509 lines of dead
// trait-shaped code. This function replaced it (the old `trap_handler` is
// gone): `cause()`/`irq_number()` are `#[inline]` and return the same values
// the hand-written dispatch computed, and it forwards to the SAME
// `crate::handle_interrupt` / `crate::handle_exception` (now in
// `kernel/src/trap/interrupt.rs` and `kernel/src/trap/exception.rs`), so
// behaviour is byte-identical.
//
// This only reaches THREE of `TrapContext`'s eleven methods
// (`cause`/`class`/`irq_number`) — `handle_exception`'s ecall arm still
// reads `frame.regs[..]`/`frame.sstatus` directly for the SYS_FORK
// whole-register-file borrow, the fast-IPC out-register writeback, and the
// `exec_user` hand-off, none of which `TrapContext` has an accessor for
// today. Migrating that arm needs new trait methods that aarch64.rs would
// have to implement too.
/// The interrupt arm of [`riscv64_trap_handler`], with its QSBR boundary
/// (Kconfig RCU_QSBR, N4): it leaves idle's extended quiescent state, and
/// its return to U-mode reports a quiescent state. Out of line so the
/// syscall path's frame stays the size it was (inlined, the guard's
/// registers grew the handler's prologue on every syscall).
#[inline(never)]
fn interrupt_arm(frame: &mut TrapFrame) {
    let _rcu = azos_sync::qsbr::TrapBoundary::irq(|| frame.came_from_user());
    crate::handle_interrupt(frame, frame.irq_number());
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
            let cause = frame.cause();
            let satp = if cause == TRAP_ECALL_FROM_U {
                crate::handle_ecall(frame)
            } else {
                crate::handle_exception(frame, cause)
            };
            #[cfg(feature = "lat-trace")]
            azos_arch::lat_hook::trap_exit(frame.sstatus as usize, core::panic::Location::caller());
            satp
        }
    }
}
