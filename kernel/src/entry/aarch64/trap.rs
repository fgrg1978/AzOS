// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 synchronous exceptions: the register-frame decode (`impl Frame`,
//! `impl ArchFrame` for the trap frame), the ESR decode and the entry points
//! `trap_entry.S` calls (the vector dispatcher, the lean native SVC and fast
//! IPC targets, the first entry into EL0). The policy (syscall flow and
//! prologue, page faults, the fatal tail) is `crate::trap`. The `TrapFrame` and
//! the per-core boot state are in `mod.rs`; the interrupt side is in `irq.rs`.

use super::*;
use super::irq::irq_arm;
use crate::trap::frame::{Disposition, KernelFault};
use crate::trap::{ArchFrame, Frame, Kernel, TrapClass};

// R (wave 4) — O3.1 nested-trap probe, aarch64 side. Mirrors riscv64's
// `PROBE_IRQ_IN_SYSCALL_NR`/`probe_irq_in_syscall` (`kernel/src/entry/riscv64/trap.rs`,
// F4/wave 3): a reserved syscall number the syscall arm intercepts BEFORE
// `ARCH.enable_all()` runs for real dispatch, so the probe's OWN inline
// enable is what starts the clock, same as the riscv64 version. Spins
// ~50 ms reading `now_ticks()` with IRQs enabled, across many timer ticks —
// if the aarch64 analogue of the riscv64 O3.1 bug (ELR_EL1/SPSR_EL1
// clobbered by a nested IRQ inside `trap_return`) is
// present, this either wedges (an `eret` into unmapped kernel text takes a
// fault the fatal tail parks on) or corrupts another task's
// kernel stack silently; a clean return with `advanced=true` after MANY
// ticks (not just one) is evidence the window is closed, not proof by a
// single non-crash. `irq-in-syscall-probe` is the SAME feature flag
// riscv64 uses (`kernel/Cargo.toml`, arch-generic — no Cargo.toml edit
// needed here).
#[cfg(all(target_arch = "aarch64", feature = "irq-in-syscall-probe"))]
const PROBE_IRQ_IN_SYSCALL_NR: u64 = 4_000_000;

#[cfg(all(target_arch = "aarch64", feature = "irq-in-syscall-probe"))]
fn probe_irq_in_syscall() -> u64 {
    use azos_arch::{Cpu, Interrupts, ARCH};
    use azos_drv_sys::kprintln;
    ARCH.enable_all();
    let tick_before = azos_actuation::watchdog::ticks();
    let hz = azos_arch::timer::freq_hz();
    let deadline = ARCH.now_ticks() + hz / 20; // ~50 ms
    while ARCH.now_ticks() < deadline {}
    let tick_after = azos_actuation::watchdog::ticks();
    kprintln!("[IRQ-PROBE] tick_before={} tick_after={} advanced={}",
        tick_before, tick_after, tick_after > tick_before);
    0
}

/// Closes a non-IRQ exception's masked window on every return path of
/// [`aarch64_trap_entry`], when the interrupted context (`SPSR_EL1` at entry)
/// runs with IRQs unmasked. Masked-window tracer only.
#[cfg(feature = "lat-trace")]
struct LatTrapExit(u64, &'static core::panic::Location<'static>);

#[cfg(feature = "lat-trace")]
impl Drop for LatTrapExit {
    fn drop(&mut self) {
        azos_arch::lat_hook::trap_exit(self.0, self.1);
    }
}

// I-13's restart point (`TrapFrame::arch_page_fault`): the trap returns here
// with the control task's clean stack top in x0 and its entry in x1, at the
// PSTATE of the fault (EL1h, its interrupt mask). `blr`, not `br`: the entry's
// BTI landing pad is a `bti c`. The entry never returns.
#[cfg(feature = "use-robot")]
core::arch::global_asm!(
    r#"
.pushsection .text.aarch64_txn_restart, "ax"
.p2align 2
.globl aarch64_txn_restart
aarch64_txn_restart:
    mov     sp, x0
    mov     x0, xzr
    blr     x1
    udf     #0
.size aarch64_txn_restart, . - aarch64_txn_restart
.popsection
"#
);

#[cfg(feature = "use-robot")]
unsafe extern "C" {
    /// I-13's restart point (the `global_asm!` above).
    fn aarch64_txn_restart();
}

/// The IPC fast path's view of an `svc` frame: `x0..x5` in, `x1..x6` out
/// (the registers `ArchFrame::write_out` writes).
pub(crate) struct SvcRegs<'a>(&'a mut TrapFrame);

unsafe extern "C" {
    /// The IPC fast path's resume stub (trap_entry.S).
    fn aarch64_ipc_resume_stub();
}

/// The IPC fast path's resume stub, for `azos_syscall::fastpath::set_resume_stub`.
pub(crate) fn ipc_resume_stub() -> usize {
    aarch64_ipc_resume_stub as *const () as usize
}

impl azos_syscall::fastpath::IpcRegs for SvcRegs<'_> {
    #[inline(always)]
    fn arg(&self, n: usize) -> u64 {
        self.0.regs[REG_X0 + n]
    }
    #[inline(always)]
    fn set_out(&mut self, n: usize, v: u64) {
        self.0.regs[REG_X0 + 1 + n] = v;
    }
    /// Kconfig IPC_FASTPATH_RESUME: this frame (an EL0 `svc`'s, the only one
    /// the fast path sees) and the stub that returns through it, without
    /// `lat-trace` (its trap-exit hook).
    #[inline(always)]
    fn resume_point(&self) -> azos_syscall::fastpath::FastResume {
        let pc = Self::resume_pc();
        if cfg!(feature = "lat-trace") || pc == 0 {
            return azos_syscall::fastpath::FastResume::NONE;
        }
        azos_syscall::fastpath::FastResume { sp: &*self.0 as *const TrapFrame as usize, pc }
    }
    /// `aarch64_ipc_resume_stub`, once the boot gave it ([`ipc_resume_stub`]).
    #[inline(always)]
    fn resume_pc() -> usize {
        azos_syscall::fastpath::resume_stub()
    }
    /// What `ArchFrame::write_out` and the syscall flow's tail write: the
    /// extra return registers and `x0` (ELR_EL1 is already past the `svc`).
    #[inline(always)]
    unsafe fn finish_at(at: usize, a0: i64, out: Option<&[u64; 6]>) {
        // SAFETY: the caller's contract: `at` is the trap frame of a claimed
        // task, parked in its syscall, that no CPU runs.
        let frame = unsafe { &mut *(at as *mut TrapFrame) };
        if let Some(out) = out {
            frame.regs[REG_X0 + 1..REG_X0 + 7].copy_from_slice(out);
        }
        frame.regs[REG_X0] = a0 as u64;
    }
}


/// ESR_EL1 ISS bit 6 (WnR) for a Data Abort (EC 0x24/0x25): 1 = the faulting
/// access was a write. Occupies the same absolute bit position in the full
/// register as in the ISS field (ISS is bits [24:0]).
const ESR_ISS_WNR: u64 = 1 << 6;
/// ESR_EL1 ISS bit 8 (CM) for a Data Abort: the abort came from a cache
/// maintenance or address translation instruction (`dc civac`, `at`), which
/// reports WnR = 1 although it writes nothing. Linux treats it as a read.
const ESR_ISS_CM: u64 = 1 << 8;

/// Did this trap's slot write `ESR_EL1`? Only a synchronous exception's
/// syndrome is decoded, and the kernel takes those through the two sync
/// vectors. An IRQ or FIQ does not write the register (ARM ARM D1.10): its
/// `esr_el1` is the previous exception's syndrome, usually an `svc`'s, so
/// decoding it ran the user's x8 as a syscall at an arbitrary instruction, or
/// a page fault at a stale FAR (K1 M3). SError, the SP0 group and AArch32
/// are not decoded either: they take the fatal path (`user_kill_status`).
#[inline(always)]
fn syndrome_is_live(frame: &TrapFrame) -> bool {
    frame.vector == VEC_SYNC_CURRENT_EL_SP0 || frame.vector == VEC_SYNC_LOWER_EL
}

/// `ESR_EL1.EC` -> the exit status of a user task whose exception is not a
/// page fault: `waitpid` reports 128 + signal, not 0.
fn kill_status_of(esr: u64) -> i32 {
    use azos_abi::exit_status as es;
    match (esr >> ESR_EC_SHIFT) & ESR_EC_MASK {
        0x22 | 0x26 => es::KILLED_BUS,   // PC / SP alignment
        0x3C => es::KILLED_TRAP,         // BRK
        _ => es::KILLED_ILL,             // 0x00 unknown (`udf`), trapped sysreg, rest
    }
}

impl Frame for TrapFrame {
    const ISA: &'static str = "aarch64";

    fn class(&self) -> TrapClass {
        if self.vector == VEC_IRQ_CURRENT_EL_SP0 || self.vector == VEC_IRQ_LOWER_EL {
            return TrapClass::Interrupt;
        }
        if !syndrome_is_live(self) {
            return TrapClass::OtherException;
        }
        let ec = (self.esr_el1 >> ESR_EC_SHIFT) & ESR_EC_MASK;
        match ec {
            EC_SVC64 => TrapClass::Syscall,
            EC_INSTR_ABORT_EL0 | EC_INSTR_ABORT_EL1 | EC_DATA_ABORT_EL0 | EC_DATA_ABORT_EL1 => TrapClass::PageFault,
            _ => TrapClass::OtherException,
        }
    }

    #[inline]
    fn came_from_user(&self) -> bool {
        // SPSR_EL1.M[3:0] = 0 => EL0t (user). Anything else (4, 5, 8, 9, 12,
        // 13) means EL1+ kernel context.
        (self.spsr_el1 & SPSR_M_MASK) == 0
    }

    /// The exception class of the ESR (bits [31:26] only: ISS2 above them is
    /// not part of the class).
    #[inline]
    fn fault_cause(&self) -> u32 {
        ((self.esr_el1 >> ESR_EC_SHIFT) & ESR_EC_MASK) as u32
    }

    #[inline]
    fn fault_addr(&self) -> u64 {
        self.far_el1
    }

    /// ISS bit 6 (WnR) of a Data Abort: 1 = the faulting access was a write,
    /// unless it was a cache maintenance one (ISS.CM), which only reads: a
    /// user `dc civac` on a read-only or COW page must not break COW or kill.
    #[inline]
    fn fault_is_write(&self) -> bool {
        self.esr_el1 & (ESR_ISS_WNR | ESR_ISS_CM) == ESR_ISS_WNR
    }

    #[inline]
    fn pc(&self) -> u64 {
        self.elr_el1
    }

    /// `x8`.
    #[inline]
    fn syscall_number(&self) -> u64 {
        self.regs[REG_X8]
    }

    /// `x0..x5`.
    #[inline]
    fn syscall_arg(&self, n: usize) -> u64 {
        self.regs[REG_X0 + n]
    }

    /// `x0`.
    #[inline]
    fn set_syscall_return(&mut self, v: i64) {
        self.regs[REG_X0] = v as u64;
    }

    /// No adjustment: the ARM ARM (D1.10, "Exceptions from an SVC, HVC, or SMC
    /// instruction") leaves ELR_ELx at the instruction AFTER the `svc` before
    /// the handler runs. Adding 4, as RISC-V's `ecall` needs, skipped the
    /// instruction that followed the `svc`.
    #[inline]
    fn skip_syscall(&mut self) {}

    /// A synchronous exception from EL0 is the task's fault (an undefined
    /// instruction, a misaligned SP/PC, a BRK, a trapped system register). SError
    /// and FIQ are not, and take the fatal path.
    fn user_kill_status(&self) -> Option<i32> {
        (self.vector == VEC_SYNC_LOWER_EL).then(|| kill_status_of(self.esr_el1))
    }

    fn print(&self, what: &str) {
        print_trap(self, what);
    }

    /// `lr` is printed on purpose: the faulting PC is almost always inside
    /// `memcpy`/`memset`, and the caller is what identifies the bug. Five of
    /// the six physical-address-as-pointer faults found during the upper-half
    /// migration were located this way in one boot each.
    fn print_kernel_fault(&self, f: &KernelFault) {
        azos_drv_sys::kerr!();
        azos_drv_sys::kerr!("[FATAL] aarch64 kernel page fault: {} at {:#x} (elr={:#x} lr={:#x})",
            if f.write { "write" } else { "read/exec" }, f.va, self.elr_el1, self.regs[30]);
    }
}

impl ArchFrame for TrapFrame {
    type Ipc<'a> = SvcRegs<'a>;

    #[inline(always)]
    fn ipc(&mut self) -> SvcRegs<'_> {
        SvcRegs(self)
    }

    const SNAPSHOT_REGS: bool = true;

    #[inline(always)]
    fn syscall_args(&self) -> [u64; 6] {
        [
            self.regs[REG_X0], self.regs[REG_X0 + 1], self.regs[REG_X0 + 2],
            self.regs[REG_X0 + 3], self.regs[REG_X0 + 4], self.regs[REG_X0 + 5],
        ]
    }

    #[inline(always)]
    fn user_sp(&self) -> u64 {
        self.sp_el0
    }

    /// `ForkRegs` is not `[u64; 32]`: SP_EL0, SPSR_EL1, TPIDR_EL0 and the full
    /// NEON/FP file are none of them GPRs, and a version that zero-padded the 31
    /// GPRs into a bare array silently dropped all four on every fork (a child
    /// resumed with a zeroed FP/SIMD file and no TLS pointer). `TrapFrame`
    /// carries everything but `TPIDR_EL0` (EL1 writes it only at a switch,
    /// which keeps every task's, so it survives a same-task syscall round
    /// trip, but a forked CHILD is a fresh task that
    /// never ran the parent's code and needs it captured here). The untaken
    /// branch hands out a zero-initialised `static`: `Default::default()` on it
    /// measured WORSE than the copy (it zeroes the same 528 bytes).
    fn with_user_regs<R>(&self, wanted: bool, f: impl FnOnce(&azos_sched::UserRegs) -> R) -> R {
        static NO_REGS: azos_sched::UserRegs = unsafe { core::mem::zeroed() };
        if !wanted {
            return f(&NO_REGS);
        }
        let tpidr_el0: u64;
        unsafe {
            core::arch::asm!(
                "mrs {0}, TPIDR_EL0",
                out(reg) tpidr_el0,
                options(nomem, nostack, preserves_flags),
            );
        }
        let built = azos_sched::UserRegs {
            gpr:       self.regs,
            sp_el0:    self.sp_el0,
            spsr_el1:  self.spsr_el1,
            tpidr_el0,
            // Lazy FP: the parent's FP state is in the registers (if live on
            // this hart) or in its save area, not in the frame.
            fpstate:   fp::snapshot_current(),
        };
        f(&built)
    }

    #[inline(always)]
    fn write_out(&mut self, regs: &[u64; 6]) {
        self.regs[1..7].copy_from_slice(regs);
    }

    /// The frame the new image of an exec enters through: its entry point,
    /// EL0t with DAIF clear, its `SP_EL0`, zeroed FP state, and EVERY
    /// general-purpose register zero (the old image's x19-x29, x30 and x1-x9 used
    /// to ride through; an image is bound to its own syscall filter and row, so a
    /// new image may hold a different authority than the one that wrote them;
    /// Linux's arm64 `start_thread_common` zeroes every register at execve).
    /// `syscall_tag` is not a register: kept. Gate canary `exec-regs-canary`: the
    /// old file is kept and abitest's `exec: the new image starts with every
    /// register zero` goes red.
    fn exec_enter(&mut self, ctx: &azos_sched::ExecHandoff) -> u64 {
        // The new image starts with zeroed FP registers, not the old image's.
        fp::discard_current();
        if !cfg!(feature = "exec-regs-canary") {
            self.regs = [0; NUM_GPR];
        }
        self.elr_el1 = ctx.entry;
        self.spsr_el1 = 0; // EL0t, DAIF clear
        self.sp_el0 = ctx.user_sp;
        ctx.satp
    }

    #[cfg(feature = "linux-abi")]
    #[inline(never)]
    fn deliver_work(&mut self, from_syscall: bool) {
        signal_return(self, from_syscall);
    }

    #[cfg(feature = "irq-in-syscall-probe")]
    fn probe(num: u64) -> Option<u64> {
        (num == PROBE_IRQ_IN_SYSCALL_NR).then(probe_irq_in_syscall)
    }

    /// I-13 (`azos_safety_core::txn`): an EL1 Alignment fault of the armed
    /// control task restarts it at its entry, as a misaligned load or store
    /// does on riscv64 (its `arch_exception`). The fault is a data abort, so
    /// it is decoded here, ahead of the page-fault policy; every other abort,
    /// and this one when the rollback declines it, keeps that policy.
    /// Canary `txn-align-route-canary`: the old routing (no decode), so the
    /// fault is the fatal kernel page fault it used to be.
    #[cfg(feature = "use-robot")]
    fn arch_page_fault(&mut self) -> bool {
        if cfg!(feature = "txn-align-route-canary")
            || !syndrome_is_live(self)
            || self.came_from_user()
            || !azos_arch::sysregs::el1_alignment_fault(self.esr_el1)
        {
            return false;
        }
        let Some((sp, pc)) = azos_safety_core::txn::txn_try_rollback(true) else {
            return false;
        };
        // The frame holds no EL1 stack pointer to rewrite (it sits on SP_EL1
        // itself, which `trap_return` pops): the `eret` goes to
        // `aarch64_txn_restart`, which takes SP from x0 and calls the entry
        // in x1.
        self.regs[REG_X0] = sp as u64;
        self.regs[1] = pc as u64;
        self.elr_el1 = aarch64_txn_restart as *const () as u64;
        true
    }

    /// First FP/SIMD instruction from EL0 since this task was switched in: load
    /// its FP state and let the instruction re-execute (IRQs stay masked for the
    /// whole arm). An EC 0x07 from EL1 is a kernel FP use outside the allowed
    /// save/restore code and stays fatal.
    fn arch_exception(&mut self) -> Disposition {
        // A stale EC 0x07 (an FIQ after an FP trap) must not load FP state.
        if !syndrome_is_live(self) || (self.esr_el1 >> ESR_EC_SHIFT) & ESR_EC_MASK != EC_FP_ACCESS || !self.came_from_user() {
            return Disposition::Default;
        }
        if fp::first_use() { Disposition::Resume } else { Disposition::Fatal }
    }
}

/// Entry point `entry/aarch64/asm/trap_entry.S`'s vector table jumps to once it
/// has saved the register file + system registers into a `TrapFrame` on the
/// kernel stack.
///
/// **Return value**: the `TTBR0_EL1` physical address `trap_entry.S` must
/// switch to before the `eret`, or `0` to keep whatever is installed. The only
/// nonzero case is an exec hand-off consumed on this same syscall
/// (`take_current_task_exec_ctx`).
#[unsafe(no_mangle)]
pub extern "C" fn aarch64_trap_entry(frame: &mut TrapFrame) -> u64 {
    // Masked-window tracer (`lat-trace`): an exception from a context with
    // `PSTATE.I` clear opens a window. The IRQ path closes it in
    // `aarch64_trap_resched`; every other class on return, through
    // `LatTrapExit` (a syscall usually closed it earlier, at `enable_all`).
    #[cfg(feature = "lat-trace")]
    let _lat_exit = {
        let spsr = frame.spsr_el1;
        if matches!(frame.class(), TrapClass::Interrupt) {
            azos_arch::lat_hook::trap_enter(spsr, core::panic::Location::caller());
            None
        } else {
            azos_arch::lat_hook::trap_enter(spsr, core::panic::Location::caller());
            Some(LatTrapExit(spsr, core::panic::Location::caller()))
        }
    };
    // Lockdep (N1): no lock held when this returns to EL0.
    // QSBR (Kconfig RCU_QSBR, N4): a syscall or exception does nothing unless
    // this is an RT CPU (RCU_NOCBS_CPUS); the interrupt arm has its own
    // boundary, out of line (`crate::trap::irq::arm`).
    let _rcu = azos_sync::qsbr::TrapBoundary::exception(|| frame.came_from_user());
    let _ld = azos_sync::lockdep::UserReturn::arm(|| frame.came_from_user());
    match frame.class() {
        TrapClass::Syscall => {
            if !frame.came_from_user() {
                // EL1 self-test (Phase 2): a kernel-mode `svc #0` is never a
                // real syscall; nothing at EL1 issues one except
                // `kernel_main`'s own round-trip probe.
                frame.regs[REG_X0] = SELFTEST_SVC_REPLY;
                return 0;
            }
            crate::trap::syscall::enter::<Kernel, TrapFrame, false>(frame)
        }
        // The forced stop and the Linux signal taken at an interrupt from EL0
        // are handled in `aarch64_trap_resched`, on the task's own stack.
        TrapClass::Interrupt => {
            irq_arm(frame);
            0
        }
        TrapClass::PageFault => {
            crate::trap::fault::page_fault::<Kernel, TrapFrame>(frame);
            0
        }
        TrapClass::OtherException => {
            crate::trap::fault::exception::<Kernel, TrapFrame>(frame);
            0
        }
    }
}

/// The lean native entry's ordinary target (trap_entry.S, `_svc_native`, Chain E
/// cut 7): a native task's EL0 `svc` other than the two IPC fast calls.
/// [`aarch64_trap_entry`]'s syscall arm without its decode: the lean path is
/// taken only from the lower-EL sync slot for an `svc` whose frame is tagged
/// native, so the class and the EL are known.
#[unsafe(no_mangle)]
pub extern "C" fn aarch64_native_svc(frame: &mut TrapFrame) -> u64 {
    native_svc::<false>(frame)
}

/// The lean native entry's IPC branch (trap_entry.S, Chain E cut 7): `x8` is
/// `SYS_IPC_FAST_CALL_EP` or `SYS_IPC_FAST_REPLY_ACCEPT`. As
/// [`aarch64_native_svc`], but the filter verdict alone and the fast path in
/// this frame. A miss takes the ordinary dispatch from here.
#[unsafe(no_mangle)]
pub extern "C" fn aarch64_fast_ipc_svc(frame: &mut TrapFrame) -> u64 {
    native_svc::<true>(frame)
}

/// An EL0 `svc`: the guards, then the generic syscall flow
/// (`crate::trap::syscall::enter`).
#[inline(always)]
fn native_svc<const FAST: bool>(frame: &mut TrapFrame) -> u64 {
    // As `aarch64_trap_entry`, in its order.
    #[cfg(feature = "lat-trace")]
    let _lat_exit = {
        let spsr = frame.spsr_el1;
        azos_arch::lat_hook::trap_enter(spsr, core::panic::Location::caller());
        LatTrapExit(spsr, core::panic::Location::caller())
    };
    let _rcu = azos_sync::qsbr::TrapBoundary::exception(|| frame.came_from_user());
    let _ld = azos_sync::lockdep::UserReturn::arm(|| frame.came_from_user());
    crate::trap::syscall::enter::<Kernel, TrapFrame, FAST>(frame)
}

// ── First entry into EL0: the same tail as every trap return ────────────
//
// `crates/core/sched/src/process.rs`'s `sret_to_user`/`sret_to_user_forked`
// call these. Each builds an ordinary `TrapFrame` and hands it to
// `trap_entry.S`'s `trap_return` (through `aarch64_ret_to_user*`), so there
// is one EL0-return sequence in the kernel — see the comment above
// `aarch64_ret_to_user` for what it does and why the reschedule check is
// not part of it.
unsafe extern "C" {
    fn aarch64_ret_to_user(frame: *const TrapFrame, ttbr0: u64) -> !;
    fn aarch64_ret_to_user_tls(frame: *const TrapFrame, ttbr0: u64, tpidr_el0: u64) -> !;
}

/// A task's first entry into a fresh image: `entry` with `user_sp`, every
/// GPR zero, EL0t with DAIF clear, zeroed FP state. `ttbr0` = the new
/// table's PA, or 0 to keep the one installed.
///
/// # Safety
/// Same contract as `process::sret_to_user`: `entry`/`user_sp` valid for
/// the address space `ttbr0` (or the current one) describes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aarch64_enter_user(entry: u64, user_sp: u64, ttbr0: u64) -> ! {
    // The image starts with zeroed FP registers: drop any state the task
    // had (a kernel task that execs has none; a re-exec would have some).
    fp::discard_current();
    let frame = TrapFrame {
        elr_el1: entry, spsr_el1: 0, sp_el0: user_sp, syscall_tag: user_frame_tag(),
        ..TrapFrame::default()
    };
    unsafe { aarch64_ret_to_user(&frame, ttbr0) }
}

/// A forked child's first entry: the parent's EL0 registers from `regs`
/// (`ForkRegs`, captured at the parent's `svc`) with x0 = 0, resuming at
/// `entry`; the parent's FP state becomes the child's saved state.
///
/// # Safety
/// Same contract as `process::sret_to_user_forked`: `entry`, `ttbr0` and
/// `regs` describe the same, fully published child context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aarch64_enter_user_forked(
    entry: u64,
    ttbr0: u64,
    regs: *const azos_sched::UserRegs,
) -> ! {
    let regs = unsafe { &*regs };
    fp::adopt(&regs.fpstate);
    let mut frame = TrapFrame {
        regs: regs.gpr,
        elr_el1: entry,
        // Verbatim, not a fixed EL0t constant: NZCV/DAIF at the instant of
        // the parent's `svc` are part of what the child clones.
        spsr_el1: regs.spsr_el1,
        sp_el0: regs.sp_el0,
        syscall_tag: user_frame_tag(),
        ..TrapFrame::default()
    };
    frame.regs[REG_X0] = 0; // fork() returns 0 in the child
    unsafe { aarch64_ret_to_user_tls(&frame, ttbr0, regs.tpidr_el0) }
}


fn print_trap(frame: &TrapFrame, what: &str) {
    azos_drv_sys::kwarn!();
    azos_drv_sys::kwarn!("[AARCH64-TRAP] {} — vector={:#x} class={:?}",
        what, frame.vector, frame.class());
    azos_drv_sys::kwarn!("[AARCH64-TRAP]   esr_el1:  {:#x} (ec={:#x})",
        frame.esr_el1, (frame.esr_el1 >> ESR_EC_SHIFT) & ESR_EC_MASK);
    azos_drv_sys::kwarn!("[AARCH64-TRAP]   elr_el1:  {:#x}", frame.elr_el1);
    azos_drv_sys::kwarn!("[AARCH64-TRAP]   far_el1:  {:#x}", frame.far_el1);
    azos_drv_sys::kwarn!("[AARCH64-TRAP]   spsr_el1: {:#x} (from_user={})",
        frame.spsr_el1, frame.came_from_user());
    azos_drv_sys::kwarn!("[AARCH64-TRAP]   sp_el0:   {:#x}", frame.sp_el0);
}


/// Wave 13: deliver signals (or apply a `rt_sigreturn`) to the current task
/// at its return to EL0, from a syscall (`from_syscall`) or an interrupt.
/// Out of line and not `#[cold]` (a cold callee reshapes the hot caller).
///
/// `SPSR_EL1` keeps its EL0t mode and interrupt mask; only N, Z, C and V may
/// come from a user frame, so a sigreturn cannot enter EL1 or mask its own
/// interrupts. The FP file moves through the lazy save area.
#[cfg(feature = "linux-abi")]
#[inline(never)]
fn signal_return(frame: &mut TrapFrame, from_syscall: bool) {
    use azos_linux_abi::signal as sig;
    if foreign_return(frame) {
        return;
    }
    let mut gpr = [0u64; 32];
    gpr[..31].copy_from_slice(&frame.regs[..31]);
    gpr[31] = frame.sp_el0;
    let mut ctx = sig::Context { gpr, pc: frame.elr_el1, pstate: frame.spsr_el1 };
    // The frame's FP words: `fpsr | fpcr << 32`, then v0..v31 (two words
    // each). `FpState` is v0..v31, then fpsr and fpcr: the same words, the
    // status word moved. Integer copies only (the kernel is FP-free).
    let changed = azos_syscall::linux::on_return_to_user(
        &mut ctx,
        from_syscall,
        &mut |w| {
            let Some(s) = fp::snapshot_current_if_used() else { return false };
            for (i, d) in w[..65].iter_mut().enumerate() {
                let at = if i == 0 { 512 } else { (i - 1) * 8 };
                let mut b = [0u8; 8];
                b.copy_from_slice(&s.0[at..at + 8]);
                *d = u64::from_le_bytes(b);
            }
            true
        },
        &mut |w| {
            let mut s = azos_arch::fp::FpState::zero();
            for (i, v) in w[..65].iter().enumerate() {
                let at = if i == 0 { 512 } else { (i - 1) * 8 };
                s.0[at..at + 8].copy_from_slice(&v.to_le_bytes());
            }
            fp::discard_current();
            fp::adopt(&s);
        },
    );
    if changed {
        frame.regs[..31].copy_from_slice(&ctx.gpr[..31]);
        frame.sp_el0 = ctx.gpr[31];
        frame.elr_el1 = ctx.pc;
        frame.spsr_el1 = (frame.spsr_el1 & !sig::A64_PSTATE_USER_MASK) | (ctx.pstate & sig::A64_PSTATE_USER_MASK);
    }
}

/// D6, the foreign-ABI family (`azos_abi::foreign`): finish a trap the current
/// thread's dispatch left pending. A trap in foreign mode is reflected: its
/// registers go on the user stack and the thread returns to the runtime's
/// entry with the frame's address in `x0` and `sp`. A `SYS_FOREIGN_RESUME`
/// restores the registers of the frame it names. `SPSR_EL1` keeps its EL0t
/// mode and interrupt mask; only N, Z, C and V come from a user frame.
#[cfg(feature = "linux-abi")]
#[inline(never)]
fn foreign_return(frame: &mut TrapFrame) -> bool {
    use azos_abi::foreign::{ForeignFrame, FLAGS_USER_MASK};
    use azos_sched::foreign::{self, Pending};
    match foreign::take_pending() {
        None => false,
        Some(Pending::Reflect { num, arg0 }) => {
            let mut f = ForeignFrame::ZERO;
            f.gpr[..31].copy_from_slice(&frame.regs[..31]);
            f.gpr[31] = frame.sp_el0;
            // `x0` holds the call's result by now, `x8` is as the program left it.
            f.gpr[0] = arg0;
            f.gpr[8] = num;
            // `ELR_EL1` is already past the `svc`.
            f.pc = frame.elr_el1;
            f.flags = frame.spsr_el1 & FLAGS_USER_MASK;
            match foreign::reflect(&f) {
                Some((entry, base)) => {
                    frame.elr_el1 = entry;
                    frame.sp_el0 = base;
                    frame.regs[0] = base;
                }
                // The stack cannot take the frame: a fault's end.
                None => crate::trap::kernel::kill(azos_abi::exit_status::KILLED_SEGV),
            }
            true
        }
        Some(Pending::Resume { frame: at }) => {
            match foreign::read_frame(at).and_then(foreign::resume) {
                Some(f) => {
                    frame.regs[..31].copy_from_slice(&f.gpr[..31]);
                    frame.sp_el0 = f.gpr[31];
                    frame.elr_el1 = f.pc;
                    frame.spsr_el1 = (frame.spsr_el1 & !FLAGS_USER_MASK) | f.flags;
                }
                None => crate::trap::kernel::kill(azos_abi::exit_status::KILLED_SEGV),
            }
            true
        }
    }
}
