// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! riscv64 synchronous exceptions: the register-frame decode (`impl Frame`,
//! `impl ArchFrame` for the trap frame), the `scause` decode and the entry
//! points `entry/riscv64/mod.rs` and `trap_entry.S` call. The policy (syscall
//! flow and prologue, page faults, the fatal tail) is `crate::trap`.

use azos_arch::Cpu as _;
use crate::trap::{ArchFrame, Frame, Kernel, TrapClass};
use crate::trap::frame::{Disposition, KernelFault};
use crate::*;
// The ISA crate's trap-frame definitions, not this module.
use azos_arch::trap;

// F4 (wave 3) — O3.1 nested-trap probe. Reserved syscall number the ecall
// arm intercepts BEFORE normal dispatch (`ArchFrame::probe`, below): well
// past the real syscall table (`crates/core/abi/src/syscall_nr.rs`), so it can
// never collide with a real syscall a build ships.
//
// Spins ~50 ms reading `time` (`now_ticks`) with interrupts already enabled
// by THIS call's own `ARCH.enable_all()` (skipped for this arm — the probe
// enables inline below so the deadline is measured from the same point a
// real syscall's enable would run). Meant for `-smp 1`: the timer fires
// locally, no cross-hart placement to account for. Prints `TICK_COUNT`
// (`azos_actuation::watchdog::ticks()`) before and after — the tick
// must have advanced, proving the timer actually fired and returned control
// here rather than crashing into another task's stack. Returns 0 (no SATP
// switch) unconditionally; a return that reaches this line is a pass by
// definition, since a wrong-stack corruption from the bug this proves kills
// the boot before any return value is observed.
#[cfg(all(target_arch = "riscv64", feature = "irq-in-syscall-probe"))]
pub(crate) const PROBE_IRQ_IN_SYSCALL_NR: usize = 4_000_000;

#[cfg(all(target_arch = "riscv64", feature = "irq-in-syscall-probe"))]
pub(crate) fn probe_irq_in_syscall() -> usize {
    use azos_arch::Interrupts;
    azos_arch::ARCH.enable_all();
    let tick_before = azos_actuation::watchdog::ticks();
    let hz = azos_drv_sys::timebase::TIMER_FREQ;
    let deadline = azos_arch::ARCH.now_ticks() + hz / 20; // ~50 ms
    while azos_arch::ARCH.now_ticks() < deadline {}
    let tick_after = azos_actuation::watchdog::ticks();
    kprintln!("[IRQ-PROBE] tick_before={} tick_after={} advanced={}",
        tick_before, tick_after, tick_after > tick_before);
    0
}


/// The IPC fast path's view of an `ecall` frame: `a0..a5` in, `a1..a6`
/// out (the registers `ArchFrame::write_out` writes).
#[cfg(target_arch = "riscv64")]
pub(crate) struct EcallRegs<'a>(&'a mut TrapFrame);

#[cfg(target_arch = "riscv64")]
impl azos_syscall::fastpath::IpcRegs for EcallRegs<'_> {
    #[inline(always)]
    fn arg(&self, n: usize) -> u64 {
        self.0.regs[10 + n] as u64
    }
    #[inline(always)]
    fn set_out(&mut self, n: usize, v: u64) {
        self.0.regs[11 + n] = v as _;
    }
    /// Kconfig IPC_FASTPATH_RESUME: this frame and the stub that returns
    /// through it, for a U-mode `ecall` (an S-mode one returns into its
    /// caller) and without `lat-trace` (its trap-exit hook).
    #[inline(always)]
    fn resume_point(&self) -> azos_syscall::fastpath::FastResume {
        let pc = Self::resume_pc();
        if cfg!(feature = "lat-trace") || pc == 0 || !self.0.came_from_user() {
            return azos_syscall::fastpath::FastResume::NONE;
        }
        azos_syscall::fastpath::FastResume { sp: &*self.0 as *const TrapFrame as usize, pc }
    }
    /// `riscv64_ipc_resume_stub`, once the boot gave it
    /// (`entry::riscv64::ipc_resume_stub`).
    #[inline(always)]
    fn resume_pc() -> usize {
        azos_syscall::fastpath::resume_stub()
    }
    /// What this arm's copy-back and `handle_ecall`'s tail write: the
    /// extra return registers, `a0`, and `sepc` past the `ecall`.
    #[inline(always)]
    unsafe fn finish_at(at: usize, a0: i64, out: Option<&[u64; 6]>) {
        // SAFETY: the caller's contract: `at` is the trap frame of a
        // claimed task, parked in its syscall, that no CPU runs.
        let frame = unsafe { &mut *(at as *mut TrapFrame) };
        if let Some(out) = out {
            for (k, &v) in out.iter().enumerate() {
                frame.regs[11 + k] = v as _;
            }
        }
        frame.set_syscall_return(a0);
        frame.skip_syscall();
    }
}


/// `scause` -> the exit status of a user task whose exception is not a page
/// fault: `waitpid` reports 128 + signal, not 0.
fn kill_status_of(cause: usize) -> i32 {
    use azos_abi::exit_status as es;
    match cause {
        0 | 4 | 6 => es::KILLED_BUS,    // misaligned fetch/load/store
        1 | 5 | 7 => es::KILLED_SEGV,   // access faults (PMP)
        3 => es::KILLED_TRAP,           // ebreak
        _ => es::KILLED_ILL,            // 2 = illegal instruction, rest
    }
}

impl Frame for TrapFrame {
    const ISA: &'static str = "riscv64";

    #[inline]
    fn class(&self) -> TrapClass {
        let cause = self.scause as usize;
        if cause & trap::INTERRUPT_BIT != 0 {
            TrapClass::Interrupt
        } else {
            match cause {
                trap::TRAP_ECALL_FROM_U | trap::TRAP_ECALL_FROM_S => TrapClass::Syscall,
                trap::TRAP_INSTR_PAGE_FAULT | trap::TRAP_LOAD_PAGE_FAULT | trap::TRAP_STORE_PAGE_FAULT => {
                    TrapClass::PageFault
                }
                _ => TrapClass::OtherException,
            }
        }
    }

    #[inline]
    fn came_from_user(&self) -> bool {
        // SPP bit: 0 = came from U-mode, 1 = came from S-mode.
        (self.sstatus as usize) & cpu::SSTATUS_SPP == 0
    }

    #[inline]
    fn fault_cause(&self) -> u32 {
        self.scause as u32
    }

    #[inline]
    fn fault_addr(&self) -> u64 {
        self.stval as u64
    }

    #[inline]
    fn fault_is_write(&self) -> bool {
        self.scause as usize == trap::TRAP_STORE_PAGE_FAULT
    }

    #[inline]
    fn pc(&self) -> u64 {
        self.sepc as u64
    }

    /// `a7`.
    #[inline]
    fn syscall_number(&self) -> u64 {
        self.regs[17] as u64
    }

    /// `a0..a5`.
    #[inline]
    fn syscall_arg(&self, n: usize) -> u64 {
        self.regs[10 + n] as u64
    }

    /// `a0`.
    #[inline]
    fn set_syscall_return(&mut self, v: i64) {
        self.regs[10] = v as _;
    }

    /// `sepc` is left AT the `ecall`: step over it. Wrapping: an `ecall` at the
    /// top 4 bytes of the address space cannot exist (no U-mode or kernel
    /// mapping is there), so the overflow panic was two dead instructions on
    /// every syscall.
    #[inline]
    fn skip_syscall(&mut self) {
        self.sepc = self.sepc.wrapping_add(4);
    }

    fn user_kill_status(&self) -> Option<i32> {
        Some(kill_status_of(self.scause as usize))
    }

    fn print(&self, what: &str) {
        azos_drv_sys::kwarn!();
        azos_drv_sys::kwarn!("[EXCEPTION] CPU {} - {}: {}", azos_arch::ARCH.hart_id(), what,
            trap::cause_str(self.scause as usize));
        azos_drv_sys::kwarn!("  sepc:   {:#x}", self.sepc);
        azos_drv_sys::kwarn!("  stval:  {:#x}", self.stval);
        azos_drv_sys::kwarn!("  scause: {:#x}", self.scause);
        azos_drv_sys::kwarn!("  regs[1] (ra):  {:#x}", self.regs[1]);
        azos_drv_sys::kwarn!("  regs[2] (sp):  {:#x}", self.regs[2]);
    }

    fn print_kernel_fault(&self, f: &KernelFault) {
        azos_drv_sys::kerr!();
        azos_drv_sys::kerr!("[PAGE FAULT] CPU {} \u{2014} {} at {:#x}", f.cpu, trap::cause_str(self.scause as usize), self.stval);
        azos_drv_sys::kerr!("  sepc: {:#x}  task: {}", self.sepc, azos_sched::current_task_name());
        // The kernel REFUSED to fix a fault in the null guard: without this
        // line it looks like an ordinary unmapped page. `azos_mm::vmm::USER_GUARD_LIMIT`.
        if f.null_guard {
            azos_drv_sys::kerr!("  null guard: VA < {:#x} is never mapped (null pointer dereference)",
                azos_mm::vmm::USER_GUARD_LIMIT);
        }
        azos_drv_sys::kerr!("  resolved so far: {} COW, {} demand", f.resolved.0, f.resolved.1);
        azos_drv_sys::kerr!("[FATAL] Kernel page fault on CPU {} \u{2014} initiating shutdown", f.cpu);
        azos_drv_sys::kerr!("  regs[1] (ra):  {:#x}", self.regs[1]);
        azos_drv_sys::kerr!("  regs[2] (sp):  {:#x}", self.regs[2]);
        azos_drv_sys::kerr!("  regs[8] (s0):  {:#x}", self.regs[8]);
    }
}

impl ArchFrame for TrapFrame {
    type Ipc<'a> = EcallRegs<'a>;

    #[inline(always)]
    fn ipc(&mut self) -> EcallRegs<'_> {
        EcallRegs(self)
    }

    /// The arms get `&regs` as it is: a shared borrow, so no arm can write
    /// through it, which keeps a forked child inheriting the register file as
    /// it stood at the `ecall` (`set_task_fork_ctx` copies it at once; the
    /// result registers are written after the dispatch returned).
    const SNAPSHOT_REGS: bool = false;

    #[inline(always)]
    fn syscall_args(&self) -> [u64; 6] {
        [
            self.regs[10] as u64, self.regs[11] as u64, self.regs[12] as u64,
            self.regs[13] as u64, self.regs[14] as u64, self.regs[15] as u64,
        ]
    }

    #[inline(always)]
    fn user_sp(&self) -> u64 {
        self.regs[2] as u64
    }

    #[inline(always)]
    fn with_user_regs<R>(&self, _wanted: bool, f: impl FnOnce(&azos_sched::UserRegs) -> R) -> R {
        f(&self.regs)
    }

    /// `a1..a6`: `a1` the caller TID, `a2..a5` the request words, `a6` the
    /// handle a moved capability took in the receiver's table (or
    /// `NO_CAP_MOVED`). `a7` is the syscall number and never written back.
    #[inline(always)]
    fn write_out(&mut self, regs: &[u64; 6]) {
        for (k, &v) in regs.iter().enumerate() {
            self.regs[11 + k] = v as _;
        }
    }

    /// The frame the new image of an exec enters through: its entry point, its
    /// `sstatus` (SPP=0, SPIE=1), its stack pointer, and EVERY other
    /// general-purpose register zero. The old image's registers used to ride
    /// through: an image is bound to its own syscall filter and row, so a new
    /// image may hold a different authority than the one that wrote them.
    /// Zero for both personalities: Linux arm64 and x86_64 zero every register
    /// at execve, riscv64 Linux writes only `sp`/`epc`/`status`; no `_start`
    /// reads anything but `sp`. `regs[0]` is the frame tag (`TF_TAG`, written
    /// once at the task's first entry to U-mode), not `x0`: kept, or every
    /// exec'd native image would fall off the lean syscall path for good. `tp`
    /// is zeroed too: the kernel re-derives its own from `stvec` on every trap
    /// from U-mode (K-C16). Gate canary `exec-regs-canary`: the old file is
    /// kept and abitest's `exec: the new image starts with every register zero`
    /// goes red.
    fn exec_enter(&mut self, ctx: &azos_sched::ExecHandoff) -> u64 {
        if !cfg!(feature = "exec-regs-canary") {
            self.regs[1..].fill(0);
        }
        self.sepc = ctx.entry as _;
        self.sstatus = ctx.sstatus as _; // SPP=0, SPIE=1
        self.regs[2] = ctx.user_sp as _; // user SP
        ctx.satp
    }

    #[inline(never)]
    fn deliver_work(&mut self, from_syscall: bool) {
        signal_return(self, from_syscall);
    }

    #[inline]
    fn irq_stack_intact(cpu: usize) -> bool {
        super::irq::irq_stack_intact(cpu)
    }

    #[cfg(feature = "irq-in-syscall-probe")]
    fn probe(num: u64) -> Option<u64> {
        (num == PROBE_IRQ_IN_SYSCALL_NR as u64).then(|| probe_irq_in_syscall() as u64)
    }

    /// An illegal instruction is the first use of the F/D file by a Linux task
    /// (FS is Off in its frame): give it the file and retry. A recoverable fault inside an armed control tick restarts
    /// the control task at a safe stop instead of the generic policy (I-13;
    /// its whitelist excludes ecall and page faults).
    fn arch_exception(&mut self) -> Disposition {
        let cause = self.scause as usize;
        // I-13's whitelist on riscv64: a misaligned load or store (AMO
        // included) taken in S-mode.
        #[cfg(feature = "use-robot")]
        if let Some((sp, pc)) = azos_safety_core::txn::txn_try_rollback(
            !self.came_from_user() && matches!(cause, trap::TRAP_LOAD_MISALIGNED | trap::TRAP_STORE_MISALIGNED),
        ) {
            self.regs[2] = sp as _;
            self.sepc = pc as _;
            return Disposition::Resume;
        }
        if cause == 2 && self.came_from_user() && azos_sched::fp::first_use(&mut self.sstatus) {
            return Disposition::Resume;
        }
        Disposition::Default
    }
}

/// The U-mode `ecall` path (SYSFLOOR): entered straight from
/// `riscv64_trap_handler`, so a syscall pays neither `handle_exception`'s cause
/// decode nor the frame its page-fault arms need. Returns the `satp` to switch
/// to on `sret` (0 = keep the current page table).
#[inline(never)]
pub(crate) fn handle_ecall(frame: &mut TrapFrame) -> usize {
    handle_ecall_as::<false>(frame)
}

/// [`handle_ecall`]'s body. `FAST`: the lean native entry's IPC branch (Chain E
/// cut 7, `riscv64_fast_ipc_syscall`), entered only for `a7` =
/// `SYS_IPC_FAST_CALL_EP` or `SYS_IPC_FAST_REPLY_ACCEPT`.
#[inline(always)]
pub(crate) fn handle_ecall_as<const FAST: bool>(frame: &mut TrapFrame) -> usize {
    crate::trap::syscall::enter::<Kernel, TrapFrame, FAST>(frame) as usize
}

/// Handle synchronous exceptions. Returns the SATP to switch to on SRET (0 =
/// keep the current page table).
///
/// Never inlined: its one caller, `riscv64_trap_handler`, is also the U-mode
/// `ecall` path. Inlined, this body's register pressure moved into that frame
/// and cost every syscall 22 instructions (vsbench `syscall-floor` 195 -> 217
/// ns/op under -icount), and whether LLVM inlined it flipped on an unrelated
/// edit elsewhere in the kernel crate (wave 14, LOGLEVEL).
#[inline(never)]
pub(crate) fn handle_exception(frame: &mut TrapFrame) -> usize {
    match frame.class() {
        // An `ecall` from S-mode (the U-mode one took `handle_ecall` already).
        TrapClass::Syscall => return handle_ecall(frame),
        TrapClass::PageFault => crate::trap::fault::page_fault::<Kernel, TrapFrame>(frame),
        _ => crate::trap::fault::exception::<Kernel, TrapFrame>(frame),
    }
    0
}

/// Wave 13: deliver signals (or apply a `rt_sigreturn`) to the current task
/// at its return to user mode, from a syscall (`from_syscall`) or an
/// interrupt taken from U-mode. Out of line and not `#[cold]`: a cold callee
/// reshapes the hot caller (`seccomp_deny_kill`'s note in `dispatch.rs`).
///
/// Only `x1..x31` and `sepc` are written back: `sstatus` never comes from a
/// user frame, so a sigreturn cannot raise its own privilege.
#[cfg(target_arch = "riscv64")]
#[inline(never)]
pub(crate) fn signal_return(frame: &mut trap::TrapFrame, from_syscall: bool) {
    use azos_linux_abi::signal as sig;
    if foreign_return(frame) {
        return;
    }
    let mut ctx = sig::Context {
        gpr: core::array::from_fn(|i| frame.regs[i] as u64),
        pc: frame.sepc as u64,
        pstate: 0,
    };
    let changed = azos_syscall::linux::on_return_to_user(
        &mut ctx,
        from_syscall,
        // f0..f31 and fcsr, the save area's own layout (zero when the task
        // has not used the file).
        &mut |w| match azos_sched::fp::frame_save() {
            Some(a) => {
                w[..33].copy_from_slice(&a);
                true
            }
            None => false,
        },
        &mut |w| {
            let mut a = [0u64; 33];
            a.copy_from_slice(&w[..33]);
            a[32] &= 0xffff_ffff;
            azos_sched::fp::frame_load(&a);
        },
    );
    if changed {
        for i in 1..32 {
            frame.regs[i] = ctx.gpr[i] as _;
        }
        frame.sepc = ctx.pc as _;
    }
}

/// D6, the foreign-ABI family (`azos_abi::foreign`): finish a trap the current
/// thread's dispatch left pending. A trap in foreign mode is reflected: its
/// registers go on the user stack and the thread returns to the runtime's
/// entry with the frame's address in `a0` and `sp`. A `SYS_FOREIGN_RESUME`
/// restores the registers of the frame it names. Only `x1..x31` and `sepc`
/// are written: `sstatus` never comes from a user frame.
// arch-only: riscv64's trap frame; aarch64 and x86_64 build theirs in kernel/src/entry/.
#[cfg(target_arch = "riscv64")]
#[inline(never)]
fn foreign_return(frame: &mut trap::TrapFrame) -> bool {
    use azos_abi::foreign::ForeignFrame;
    use azos_sched::foreign::{self, Pending};
    match foreign::take_pending() {
        None => false,
        Some(Pending::Reflect { num, arg0 }) => {
            let mut f = ForeignFrame::ZERO;
            for i in 1..32 {
                f.gpr[i] = frame.regs[i] as u64;
            }
            // `a0` holds the call's result by now, `a7` is as the program left it.
            f.gpr[10] = arg0;
            f.gpr[17] = num;
            // The trap path has already stepped over the `ecall`.
            f.pc = frame.sepc as u64;
            match foreign::reflect(&f) {
                Some((entry, base)) => {
                    frame.sepc = entry as _;
                    frame.regs[2] = base as _;
                    frame.regs[10] = base as _;
                }
                // The stack cannot take the frame: a fault's end.
                None => crate::trap::kernel::kill(azos_abi::exit_status::KILLED_SEGV),
            }
            true
        }
        Some(Pending::Resume { frame: at }) => {
            match foreign::read_frame(at).and_then(foreign::resume) {
                Some(f) => {
                    for i in 1..32 {
                        frame.regs[i] = f.gpr[i] as _;
                    }
                    frame.sepc = f.pc as _;
                }
                None => crate::trap::kernel::kill(azos_abi::exit_status::KILLED_SEGV),
            }
            true
        }
    }
}
