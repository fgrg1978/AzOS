// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 trap handling: the register-frame decode (`impl Frame`, `impl
//! ArchFrame` for the trap frame), the vector decode, the dispatcher
//! `x86_64/asm/trap_entry.S` calls (the same routing as `riscv64_trap_handler` /
//! `aarch64_trap_entry`), the syscall entries, the ISA's own exception cases
//! (NMI, `int3`, split locks) and the first entry into ring 3. The policy
//! (syscall flow and prologue, page faults, the fatal tail) is `crate::trap`;
//! the interrupt side is in `irq.rs`. The `TrapFrame` they take is in `mod.rs`.

use super::*;
use super::irq::irq_arm;
use crate::trap::frame::{Disposition, KernelFault};
use crate::trap::{ArchFrame, Frame, Kernel, TrapClass};

/// NMIs taken (each one returns; nothing else is done with them yet).
pub static NMIS: AtomicU64 = AtomicU64::new(0);
/// `int3` taken in ring 0 (the boot self-test's); each one returns.
pub static KERNEL_BREAKPOINTS: AtomicU64 = AtomicU64::new(0);

/// #PF error code bit 1: the access was a write.
const PF_WRITE: u64 = 1 << 1;

impl Frame for TrapFrame {
    const ISA: &'static str = "x86_64";

    /// `syscall_entry` -> Syscall, #PF -> PageFault, 0..31 -> exception,
    /// 32..255 -> Interrupt.
    #[inline]
    fn class(&self) -> TrapClass {
        let v = self.vector;
        if v == idt::SYSCALL_VECTOR {
            TrapClass::Syscall
        } else if v == idt::PF as u64 {
            TrapClass::PageFault
        } else if v >= idt::FIRST_INTERRUPT as u64 {
            TrapClass::Interrupt
        } else {
            TrapClass::OtherException
        }
    }

    /// CS.RPL == 3.
    #[inline]
    fn came_from_user(&self) -> bool {
        self.cs & 3 == 3
    }

    #[inline]
    fn fault_cause(&self) -> u32 {
        self.error_code as u32
    }

    /// CR2, which the dispatcher copies into the frame before anything can
    /// enable interrupts.
    #[inline]
    fn fault_addr(&self) -> u64 {
        self.cr2
    }

    #[inline]
    fn fault_is_write(&self) -> bool {
        self.error_code & PF_WRITE != 0
    }

    #[inline]
    fn pc(&self) -> u64 {
        self.rip
    }

    /// `rax`.
    #[inline]
    fn syscall_number(&self) -> u64 {
        self.regs[gpr::RAX]
    }

    /// `rdi rsi rdx r10 r8 r9`.
    #[inline]
    fn syscall_arg(&self, n: usize) -> u64 {
        self.regs[SYSCALL_ARGS[n]]
    }

    /// `rax`.
    #[inline]
    fn set_syscall_return(&mut self, v: i64) {
        self.regs[gpr::RAX] = v as u64;
    }

    /// `syscall` already left RIP past itself (RCX): no adjustment.
    #[inline]
    fn skip_syscall(&mut self) {}

    /// A ring-3 fault is the task's, whichever vector, except #DF and #MC:
    /// those are the machine's.
    fn user_kill_status(&self) -> Option<i32> {
        use azos_abi::exit_status as es;
        let v = self.vector as usize;
        if v == idt::DF || v == idt::MC {
            return None;
        }
        Some(match v {
            idt::BP | idt::DB => es::KILLED_TRAP,
            idt::AC => es::KILLED_BUS,
            idt::GP | idt::SS | idt::NP => es::KILLED_SEGV,
            _ => es::KILLED_ILL,
        })
    }

    fn print(&self, what: &str) {
        print_trap(self, what);
    }

    fn print_kernel_fault(&self, f: &KernelFault) {
        azos_drv_sys::kerr!("[FATAL] x86_64 kernel page fault: {} at {:#x} (rip={:#x}, error={:#x})",
            if f.write { "write" } else { "read/exec" }, f.va, self.rip, self.error_code);
    }
}

impl ArchFrame for TrapFrame {
    type Ipc<'a> = SyscallRegs<'a>;

    #[inline(always)]
    fn ipc(&mut self) -> SyscallRegs<'_> {
        SyscallRegs(self)
    }

    const SNAPSHOT_REGS: bool = true;

    #[inline(always)]
    fn syscall_args(&self) -> [u64; 6] {
        SYSCALL_ARGS.map(|r| self.regs[r])
    }

    #[inline(always)]
    fn user_sp(&self) -> u64 {
        self.rsp
    }

    /// SYSFLOOR (aarch64's shape): the snapshot, an XSAVE image included, is
    /// built only for the calls that read it; every other call passes a static
    /// zero set and pays neither the copy nor the FP save.
    fn with_user_regs<R>(&self, wanted: bool, f: impl FnOnce(&azos_sched::UserRegs) -> R) -> R {
        // SAFETY: all-zero is a valid `ForkRegs` (plain integers and bytes).
        static NO_REGS: azos_sched::UserRegs = unsafe { core::mem::zeroed() };
        if !wanted {
            return f(&NO_REGS);
        }
        let mut r = azos_sched::UserRegs::default();
        r.gpr = self.regs;
        r.rsp = self.rsp;
        r.rflags = self.rflags;
        r.fs_base = azos_arch::cpu::rdmsr(cpu::IA32_FS_BASE);
        // In the kernel the user's GS base sits in KERNEL_GS_BASE (swapgs).
        r.gs_base = azos_arch::cpu::rdmsr(cpu::IA32_KERNEL_GS_BASE);
        fp::snapshot_current(&mut r.fp);
        f(&r)
    }

    #[inline(always)]
    fn write_out(&mut self, regs: &[u64; 6]) {
        for (k, &r) in SYSCALL_OUT.iter().enumerate() {
            self.regs[r] = regs[k];
        }
    }

    /// A fresh image: zero registers, initial FP state, the new entry. Every GPR
    /// but rsp, as Linux's `elf_common_init`: none of the old image's reaches the
    /// new one, rcx and r11 included (the frame is `REBUILT_VECTOR`'s, so it
    /// returns by `iretq`, not `sysretq`). Gate canary `exec-regs-canary`: the
    /// old image's registers are put back.
    fn exec_enter(&mut self, ctx: &azos_sched::ExecHandoff) -> u64 {
        fp::discard_current();
        #[cfg(feature = "exec-regs-canary")]
        let old = self.regs;
        *self = TrapFrame::user(ctx.entry, ctx.user_sp);
        #[cfg(feature = "exec-regs-canary")]
        {
            self.regs = old;
        }
        ctx.satp
    }

    /// Only the foreign-ABI work: Linux signal delivery is not here yet (the
    /// `signal::Context` is aarch64-shaped), and a foreign trap is only ever
    /// left pending by a syscall's dispatch.
    #[inline(never)]
    fn deliver_work(&mut self, from_syscall: bool) {
        if from_syscall {
            foreign_return(self);
        }
    }

    /// The TLB probe's one load (`smokes/tlb_probe.rs`) faulted in the kernel.
    #[cfg(all(feature = "qemu", any(feature = "tlb-smoke", feature = "ktest")))]
    fn arch_page_fault(&mut self) -> bool {
        !self.came_from_user() && tlb_probe_fixup(self)
    }

    /// Vectors 0..31 other than #PF and NMI (counted in `x86_64_trap_entry`
    /// before any decode): the livepatch's `int3` sequence resumes; a split
    /// lock is the task's kill; everything else is the generic policy's.
    /// I-13's rollback (`azos_safety_core::txn`) has no fault to take here:
    /// its whitelist is the misaligned load/store, which ring 0 never faults
    /// on (#AC is checked at CPL 3 only), and a kernel split lock already
    /// resumes with detection off on this CPU.
    fn arch_exception(&mut self) -> Disposition {
        let v = self.vector as usize;
        if v == idt::BP && !self.came_from_user() {
            // The livepatch's `int3` sequence (text_poke::write_bp5): continue as
            // if the instruction it is writing were already in place.
            if let Some(rip) = azos_mm::text_poke::bp_resume(self.rip as usize) {
                self.rip = rip as u64;
                return Disposition::Resume;
            }
            // A trap: RIP is already past the `int3`.
            KERNEL_BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
            return Disposition::Resume;
        }
        // Split-lock detection (Kconfig X86_SPLIT_LOCK): an #AC that is a split
        // lock, not the ordinary alignment check.
        if v == idt::AC && azos_arch::ext::splitlock::wanted() {
            let on = azos_arch::ext::splitlock::active_this_cpu();
            let cr0 = azos_arch::mmu::cpu::read_cr0();
            if azos_arch::cpu::features::classify_ac(on, cr0, self.rflags) == azos_arch::cpu::features::AcKind::SplitLock {
                return split_lock_fault(self);
            }
        }
        Disposition::Default
    }
}

// ── The dispatcher ──────────────────────────────────────────────────────────

/// What `trap_entry.S` calls with the saved frame (interrupts masked: every
/// gate is an interrupt gate, and `syscall` clears IF through FMASK).
/// Returns the CR3 word to install before the return, or 0.
#[unsafe(no_mangle)]
pub extern "C" fn x86_64_trap_entry(frame: &mut TrapFrame) -> u64 {
    // An NMI is counted and returns before any guard, decode or policy (K1
    // L17): `ist_common` has no nested-NMI copy, so the handler must take no
    // exception (one would `iretq`, unmask NMIs, and a second NMI would
    // overwrite this frame on the same IST slice). One atomic add takes none.
    if frame.vector as usize == idt::NMI {
        NMIS.fetch_add(1, Ordering::Relaxed);
        return 0;
    }
    // Lockdep (N1): no lock held when this returns to ring 3.
    // QSBR (Kconfig RCU_QSBR, N4): a syscall or exception does nothing
    // unless this is an RT CPU (RCU_NOCBS_CPUS); the interrupt arm has its
    // own boundary, out of line (`crate::trap::irq::arm`).
    let _rcu = azos_sync::qsbr::TrapBoundary::exception(|| frame.came_from_user());
    let _ld = azos_sync::lockdep::UserReturn::arm(|| frame.came_from_user());
    match frame.class() {
        TrapClass::Syscall => crate::trap::syscall::enter::<Kernel, TrapFrame, false>(frame),
        TrapClass::Interrupt => {
            irq_arm(frame);
            0
        }
        TrapClass::PageFault => {
            frame.cr2 = cpu::read_cr2();
            crate::trap::fault::page_fault::<Kernel, TrapFrame>(frame);
            0
        }
        TrapClass::OtherException => {
            crate::trap::fault::exception::<Kernel, TrapFrame>(frame);
            0
        }
    }
}

/// The lean `syscall` entry's ordinary target (trap_entry.S, `syscall_entry`,
/// Chain E cut 7): every syscall but the two IPC fast calls.
/// [`x86_64_trap_entry`]'s syscall arm without its decode: only a `syscall`
/// reaches `syscall_entry`, so the class is known. The same guards (the QSBR
/// exception boundary, lockdep's `UserReturn`), then the generic flow.
#[unsafe(no_mangle)]
pub extern "C" fn x86_64_native_syscall(frame: &mut TrapFrame) -> u64 {
    native_syscall::<false>(frame)
}

/// The lean `syscall` entry's IPC branch (trap_entry.S, Chain E cut 7): `rax`
/// is `SYS_IPC_FAST_CALL_EP` or `SYS_IPC_FAST_REPLY_ACCEPT`. As
/// [`x86_64_native_syscall`], but the filter verdict alone and the fast path in
/// this frame. A miss (a Linux task's number among them: the verdict says so)
/// takes the ordinary dispatch from here.
#[unsafe(no_mangle)]
pub extern "C" fn x86_64_fast_ipc_syscall(frame: &mut TrapFrame) -> u64 {
    native_syscall::<true>(frame)
}

#[inline(always)]
fn native_syscall<const FAST: bool>(frame: &mut TrapFrame) -> u64 {
    // As `x86_64_trap_entry`, in its order.
    let _rcu = azos_sync::qsbr::TrapBoundary::exception(|| frame.came_from_user());
    let _ld = azos_sync::lockdep::UserReturn::arm(|| frame.came_from_user());
    crate::trap::syscall::enter::<Kernel, TrapFrame, FAST>(frame)
}

/// `azos_abi::foreign::ForeignFrame::gpr` index of each of the trap frame's
/// registers (`gpr` order, rax..r15 without rsp), in the hardware's
/// encoding order the ABI documents.
const FOREIGN_GPR: [(usize, usize); gpr::COUNT] = [
    (gpr::RAX, 0), (gpr::RCX, 1), (gpr::RDX, 2), (gpr::RBX, 3), (gpr::RBP, 5), (gpr::RSI, 6),
    (gpr::RDI, 7), (gpr::R8, 8), (gpr::R9, 9), (gpr::R10, 10), (gpr::R11, 11), (gpr::R12, 12),
    (gpr::R13, 13), (gpr::R14, 14), (gpr::R15, 15),
];
/// The foreign frame's index of rsp.
const FOREIGN_RSP: usize = 4;

/// D6, the foreign-ABI family (`azos_abi::foreign`): finish a trap the current
/// thread's dispatch left pending. A trap in foreign mode is reflected: its
/// registers go on the user stack (below the red zone) and the thread
/// returns to the runtime's entry with the frame's address in `rdi` and
/// `rsp`. A `SYS_FOREIGN_RESUME` restores the registers of the frame it
/// names. Only the arithmetic flags and the direction flag come from a user
/// frame (`FLAGS_USER_MASK`): IF, TF, IOPL and the rest stay the kernel's.
#[inline(never)]
fn foreign_return(frame: &mut TrapFrame) {
    use azos_abi::foreign::{ForeignFrame, FLAGS_USER_MASK};
    use azos_sched::foreign::{self, Pending};
    match foreign::take_pending() {
        None => {}
        Some(Pending::Reflect { num, arg0 }) => {
            let mut f = ForeignFrame::ZERO;
            for (k, i) in FOREIGN_GPR {
                f.gpr[i] = frame.regs[k];
            }
            f.gpr[FOREIGN_RSP] = frame.rsp;
            // `rax` holds the call's result by now; `rdi` is as the program left it.
            f.gpr[0] = num;
            f.gpr[7] = arg0;
            // `syscall` overwrote rcx and r11 with the return RIP and RFLAGS,
            // and the lean entry does not save them (its frame slots are an
            // earlier trap's): report what the hardware left, as a full save.
            f.gpr[1] = frame.rip;
            f.gpr[11] = frame.rflags;
            // `syscall` left RIP past itself.
            f.pc = frame.rip;
            f.flags = frame.rflags & FLAGS_USER_MASK;
            match foreign::reflect(&f) {
                Some((entry, base)) => {
                    frame.rip = entry;
                    frame.rsp = base;
                    frame.regs[gpr::RDI] = base;
                }
                // The stack cannot take the frame: a fault's end.
                None => crate::trap::kernel::kill(azos_abi::exit_status::KILLED_SEGV),
            }
        }
        Some(Pending::Resume { frame: at }) => {
            match foreign::read_frame(at).and_then(foreign::resume) {
                Some(f) => {
                    for (k, i) in FOREIGN_GPR {
                        frame.regs[k] = f.gpr[i];
                    }
                    frame.rsp = f.gpr[FOREIGN_RSP];
                    frame.rip = f.pc;
                    frame.rflags = (frame.rflags & !FLAGS_USER_MASK) | f.flags;
                    // rcx and r11 are the runtime's: the full return.
                    frame.vector = super::REBUILT_VECTOR;
                }
                None => crate::trap::kernel::kill(azos_abi::exit_status::KILLED_SEGV),
            }
        }
    }
}

/// The IPC fast path's view of a `syscall` frame: [`SYSCALL_ARGS`] in,
/// [`SYSCALL_OUT`] out (the registers `ArchFrame::write_out` writes).
pub(crate) struct SyscallRegs<'a>(&'a mut TrapFrame);

unsafe extern "C" {
    /// The IPC fast path's resume stub (trap_entry.S).
    fn x86_64_ipc_resume_stub();
}

/// The IPC fast path's resume stub, for `azos_syscall::fastpath::set_resume_stub`.
pub(crate) fn ipc_resume_stub() -> usize {
    x86_64_ipc_resume_stub as *const () as usize
}

impl azos_syscall::fastpath::IpcRegs for SyscallRegs<'_> {
    #[inline(always)]
    fn arg(&self, n: usize) -> u64 {
        self.0.regs[SYSCALL_ARGS[n]]
    }
    #[inline(always)]
    fn set_out(&mut self, n: usize, v: u64) {
        self.0.regs[SYSCALL_OUT[n]] = v;
    }
    /// Kconfig IPC_FASTPATH_RESUME: this frame (a `syscall`'s, the only one
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
    /// `x86_64_ipc_resume_stub`, once the boot gave it ([`ipc_resume_stub`]).
    #[inline(always)]
    fn resume_pc() -> usize {
        azos_syscall::fastpath::resume_stub()
    }
    /// What `syscall_dispatch`'s copy-back and `syscall`'s tail write: the
    /// extra return registers and `rax` (`syscall` left RIP past itself).
    #[inline(always)]
    unsafe fn finish_at(at: usize, a0: i64, out: Option<&[u64; 6]>) {
        // SAFETY: the caller's contract: `at` is the trap frame of a claimed
        // task, parked in its syscall, that no CPU runs.
        let frame = unsafe { &mut *(at as *mut TrapFrame) };
        if let Some(out) = out {
            for (k, &v) in out.iter().enumerate() {
                frame.regs[SYSCALL_OUT[k]] = v;
            }
        }
        frame.regs[gpr::RAX] = a0 as u64;
    }
}

/// The TLB probe's one load (`smokes/tlb_probe.rs`) faulted: resume after
/// it with RAX = 0 and RDX = `14 << 32 | error code`, as its riscv64 and
/// aarch64 versions resume from their private trap vectors.
#[cfg(all(feature = "qemu", any(feature = "tlb-smoke", feature = "ktest")))]
fn tlb_probe_fixup(frame: &mut TrapFrame) -> bool {
    unsafe extern "C" {
        static azos_tlb_probe_load_insn: u8;
        static azos_tlb_probe_resume: u8;
    }
    if frame.rip != (&raw const azos_tlb_probe_load_insn) as u64 {
        return false;
    }
    frame.regs[gpr::RAX] = 0;
    frame.regs[gpr::RDX] = (idt::PF as u64) << 32 | frame.error_code;
    frame.rip = (&raw const azos_tlb_probe_resume) as u64;
    true
}

/// A split-locked atomic raised #AC. Ring 3: the task is killed (a bus lock
/// held across a cache-line split is unbounded jitter for every real-time
/// task on another core) and the kill is a `split-lock` decision record, a
/// durable one (Verdict::Refuse reaches the flight recorder). Ring 0: a
/// kernel bug; it panics when Kconfig `X86_SPLIT_LOCK_KERNEL_PANIC` says so
/// (development kernels), else warns and clears the detection bit on this CPU
/// so the faulting access retries.
fn split_lock_fault(frame: &mut TrapFrame) -> Disposition {
    use azos_abi::exit_status as es;
    let cpu = azos_sched::smp::current_cpu_id() as u64;
    if frame.came_from_user() {
        let tid = azos_sched::current_task_tid();
        azos_decision::record(azos_decision::Rule::SplitLock, azos_decision::Verdict::Refuse, tid,
                              [frame.rip, cpu, 0]);
        if crate::trap::kernel::user_fault_report() {
            azos_drv_sys::kwarn!("[SPLIT-LOCK] task '{}' (tid {}) split-locked an atomic at rip {:#x} on cpu {}: killed",
                azos_sched::current_task_name(), tid, frame.rip, cpu);
        }
        return Disposition::Kill(es::KILLED_BUS);
    }
    if azos_limits::X86_SPLIT_LOCK_KERNEL_PANIC {
        panic!("[SPLIT-LOCK] the kernel split-locked an atomic at rip {:#x} on cpu {}", frame.rip, cpu);
    }
    if crate::trap::kernel::user_fault_report() {
        azos_drv_sys::kwarn!("[SPLIT-LOCK] the kernel split-locked an atomic at rip {:#x} on cpu {}: \
                              detection off on this CPU", frame.rip, cpu);
    }
    azos_arch::ext::splitlock::disable_this_cpu();
    Disposition::Resume
}

fn print_trap(frame: &TrapFrame, what: &str) {
    azos_drv_sys::kwarn!("[X86-TRAP] {}: vector {} ({}), error code {:#x}", what, frame.vector,
        idt::vector_name(frame.vector as usize), frame.error_code);
    azos_drv_sys::kwarn!("[X86-TRAP]   rip {:#x} cs {:#x} rflags {:#x} rsp {:#x} ss {:#x}",
        frame.rip, frame.cs, frame.rflags, frame.rsp, frame.ss);
}


// ── First entry into ring 3: the same tail as every trap return ─────────────
//
// `crates/core/sched/src/process.rs`'s `sret_to_user`/`sret_to_user_forked`
// call these. Each builds an ordinary `TrapFrame` and hands it to
// `trap_entry.S`'s `trap_return` through `x86_64_ret_to_user`, so there is
// one ring-3 return sequence in the kernel (aarch64's shape).

unsafe extern "C" {
    fn x86_64_ret_to_user(frame: *const TrapFrame, cr3: u64) -> !;
}

/// A task's first entry into a fresh image: `entry` with `user_sp`, every
/// register zero, IF set, the initial FP state. `cr3` = the new root word,
/// or 0 to keep the one installed.
///
/// # Safety
/// Same contract as `process::sret_to_user`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x86_64_enter_user(entry: u64, user_sp: u64, cr3: u64) -> ! {
    fp::discard_current();
    let frame = TrapFrame::user(entry, user_sp);
    {
        use azos_arch::Interrupts;
        azos_arch::ARCH.disable_all();
    }
    // A fresh image starts with zero FS and GS bases, not the last ring-3
    // task's on this CPU (the user GS base waits in KERNEL_GS_BASE).
    azos_sched::fp::set_fs_base(0);
    azos_arch::cpu::wrmsr(cpu::IA32_KERNEL_GS_BASE, 0);
    // SAFETY: per the caller; the frame lives on this (abandoned) stack
    // until `trap_return` has loaded it.
    unsafe { x86_64_ret_to_user(&frame, cr3) }
}

/// A forked child's first entry: the parent's ring-3 registers from `regs`
/// with rax = 0, resuming at `entry`; the parent's FP image becomes the
/// child's; FS and GS bases restored.
///
/// # Safety
/// Same contract as `process::sret_to_user_forked`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x86_64_enter_user_forked(entry: u64, cr3: u64, regs: *const azos_sched::UserRegs) -> ! {
    // SAFETY: per the caller, a published child context.
    let regs = unsafe { &*regs };
    fp::adopt(&regs.fp);
    let mut frame = TrapFrame::user(entry, regs.rsp);
    frame.regs = regs.gpr;
    frame.regs[gpr::RAX] = 0; // fork() returns 0 in the child
    // The parent's arithmetic flags, never its IOPL/NT/RF/TF; always IF.
    frame.rflags = (regs.rflags & !(cpu::RFLAGS_IOPL | cpu::RFLAGS_NT | cpu::RFLAGS_RF | cpu::RFLAGS_TF))
        | cpu::USER_RFLAGS_INIT;
    {
        use azos_arch::Interrupts;
        azos_arch::ARCH.disable_all();
    }
    azos_sched::fp::set_fs_base(regs.fs_base);
    // The user GS base waits in KERNEL_GS_BASE for trap_return's swapgs.
    azos_arch::cpu::wrmsr(cpu::IA32_KERNEL_GS_BASE, regs.gs_base);
    // SAFETY: per the caller.
    unsafe { x86_64_ret_to_user(&frame, cr3) }
}

/// Every CPU exception before `trap_init` loads the real IDT (boot.S's
/// early table): report and stop, instead of a triple fault.
#[unsafe(no_mangle)]
pub extern "C" fn x86_64_early_exception(vector: u64, error_code: u64, rip: u64) -> ! {
    azos_drv_sys::kprintln!("[X86] CPU exception {} (error code {:#x}) at rip {:#x}: no trap path yet, stopping",
        vector, error_code, rip);
    azos_arch::Boot::shutdown(&azos_arch::ARCH)
}
