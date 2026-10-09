// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 trap entry: the `TrapFrame` `x86_64/asm/trap_entry.S` builds, its
//! [`TrapContext`] impl, the Rust dispatcher that asm calls (the same
//! routing as `riscv64_trap_handler` / `aarch64_trap_entry`), the
//! preemption point on the way out, and the first entry into ring 3.
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

pub(crate) mod cpu_init;
pub(crate) mod fp;

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use super::{TrapClass, TrapContext};
use azos_arch::fork_regs::gpr;
use azos_arch::{cpu, gdt, idt};

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

impl TrapFrame {
    /// The frame of a fresh ring-3 entry: `rip`/`rsp`, user selectors,
    /// IF set, every general register zero (K-C18: no kernel value reaches
    /// ring 3).
    pub const fn user(rip: u64, rsp: u64) -> Self {
        TrapFrame {
            cr2: 0,
            gs_saved: 0,
            regs: [0; gpr::COUNT],
            vector: 0,
            error_code: 0,
            rip,
            cs: gdt::USER_CS as u64,
            rflags: cpu::USER_RFLAGS_INIT,
            rsp,
            ss: gdt::USER_DS as u64,
        }
    }
}

impl TrapContext for TrapFrame {
    /// The vector in bits 15:0, the error code above.
    #[inline]
    fn cause(&self) -> usize {
        ((self.error_code as usize) << 16) | (self.vector as usize & 0xFFFF)
    }

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

    /// The IDT vector (the irqchip maps it to a line).
    #[inline]
    fn irq_number(&self) -> usize { self.vector as usize }

    #[inline]
    fn fault_addr(&self) -> usize { self.cr2 as usize }

    #[inline]
    fn pc(&self) -> usize { self.rip as usize }

    #[inline]
    fn set_pc(&mut self, pc: usize) { self.rip = pc as u64 }

    #[inline]
    fn user_sp(&self) -> usize { self.rsp as usize }

    /// CS.RPL == 3.
    #[inline]
    fn came_from_user(&self) -> bool { self.cs & 3 == 3 }

    #[inline]
    fn syscall_number(&self) -> usize { self.regs[gpr::RAX] as usize }

    #[inline]
    fn syscall_arg(&self, n: usize) -> usize {
        debug_assert!(n < SYSCALL_ARGS.len());
        self.regs[SYSCALL_ARGS[n]] as usize
    }

    #[inline]
    fn set_syscall_return(&mut self, v: usize) { self.regs[gpr::RAX] = v as u64 }
}

// ── Vectors (Kconfig) ───────────────────────────────────────────────────────

/// First device-interrupt vector (Kconfig `X86_IRQ_VECTOR_BASE`).
pub const IRQ_VECTOR_BASE: usize = azos_limits::X86_IRQ_VECTOR_BASE;
/// The IPI vector (Kconfig `X86_IPI_VECTOR`).
pub const IPI_VECTOR: usize = azos_limits::X86_IPI_VECTOR;
/// The LAPIC spurious vector (Kconfig `X86_SPURIOUS_VECTOR`).
pub const SPURIOUS_VECTOR: usize = azos_limits::X86_SPURIOUS_VECTOR;

const _: () = assert!(IRQ_VECTOR_BASE >= idt::FIRST_INTERRUPT && IPI_VECTOR > IRQ_VECTOR_BASE);
const _: () = assert!(IPI_VECTOR != SPURIOUS_VECTOR && SPURIOUS_VECTOR > IRQ_VECTOR_BASE);
const _: () = assert!(IPI_VECTOR < idt::VECTORS && SPURIOUS_VECTOR < idt::VECTORS);

/// The irqchip's half of a device interrupt: `dispatch(vector)` runs the
/// handler, `eoi()` acknowledges at the LAPIC. Installed by the LAPIC /
/// IOAPIC driver ([`set_irq_hooks`]); until then a device vector is
/// counted in [`UNROUTED_IRQS`] and nothing else happens.
pub struct IrqHooks {
    pub dispatch: fn(usize),
    pub eoi: fn(),
}

static IRQ_HOOKS: AtomicUsize = AtomicUsize::new(0);
/// Device vectors taken before any irqchip installed its hooks.
pub static UNROUTED_IRQS: AtomicU64 = AtomicU64::new(0);
/// LAPIC spurious interrupts (no EOI is sent for them).
pub static SPURIOUS_IRQS: AtomicU64 = AtomicU64::new(0);
/// IPIs received.
pub static IPIS: AtomicU64 = AtomicU64::new(0);
/// NMIs taken (each one returns; nothing else is done with them yet).
pub static NMIS: AtomicU64 = AtomicU64::new(0);

/// Install the irqchip hooks (once, before interrupts are enabled).
#[allow(dead_code)] // the LAPIC/IOAPIC driver's call, not ported yet
pub fn set_irq_hooks(hooks: &'static IrqHooks) {
    IRQ_HOOKS.store(hooks as *const IrqHooks as usize, Ordering::Release);
}

fn irq_hooks() -> Option<&'static IrqHooks> {
    let p = IRQ_HOOKS.load(Ordering::Acquire);
    // SAFETY: only `set_irq_hooks` stores here, from a `&'static`.
    (p != 0).then(|| unsafe { &*(p as *const IrqHooks) })
}

// ── Reschedule on the way out (riscv64 / aarch64 shape) ─────────────────────

/// `false` until the boot CPU enters the scheduler (`arch_enter_scheduler`
/// sets it `Release` just before `azos_sched::start()`); until then
/// [`x86_64_trap_resched`] leaves a pending flag set and returns, as on the
/// other ISAs.
pub static SCHED_LIVE: AtomicBool = AtomicBool::new(false);

static NEED_RESCHED: [AtomicBool; crate::MAX_HARTS] = [const { AtomicBool::new(false) }; crate::MAX_HARTS];

/// Times [`x86_64_trap_resched`] entered `schedule()`.
pub static PREEMPT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Ask for a reschedule on THIS CPU on the way out of the current
/// interrupt (the timer tick and the IPI call it).
pub fn request_resched() {
    let cpu = azos_sched::smp::current_cpu_id();
    if let Some(slot) = NEED_RESCHED.get(cpu) {
        slot.store(true, Ordering::Release);
    }
}

/// The preemption point `trap_entry.S` calls after an interrupt, back on
/// the interrupted task's stack.
#[unsafe(no_mangle)]
pub extern "C" fn x86_64_trap_resched(frame: &mut TrapFrame) {
    if !SCHED_LIVE.load(Ordering::Acquire) {
        return;
    }
    if frame.came_from_user() && azos_sched::scheduler::forced_stop_pending() {
        azos_sched::scheduler::exit_if_forced();
    }
    let cpu = azos_sched::smp::current_cpu_id();
    let Some(slot) = NEED_RESCHED.get(cpu) else { return };
    if slot.swap(false, Ordering::AcqRel) {
        PREEMPT_COUNT.fetch_add(1, Ordering::Relaxed);
        azos_sched::schedule();
    }
}

// ── The dispatcher ──────────────────────────────────────────────────────────

/// What `trap_entry.S` calls with the saved frame (interrupts masked: every
/// gate is an interrupt gate, and `syscall` clears IF through FMASK).
/// Returns the CR3 word to install before the return, or 0.
#[unsafe(no_mangle)]
pub extern "C" fn x86_64_trap_entry(frame: &mut TrapFrame) -> u64 {
    match frame.class() {
        TrapClass::Syscall => syscall(frame),
        TrapClass::Interrupt => {
            let cpu = azos_sched::smp::current_cpu_id();
            azos_sync::isr_depth::enter(cpu);
            handle_irq(frame.vector as usize);
            azos_sync::isr_depth::exit(cpu);
            0
        }
        TrapClass::PageFault => {
            frame.cr2 = cpu::read_cr2();
            handle_page_fault(frame);
            0
        }
        TrapClass::OtherException => {
            handle_exception(frame);
            0
        }
    }
}

/// A `syscall` from ring 3, in aarch64's order: interrupts on (O3.1), the
/// filter and the register-only calls first, the rest out of line.
fn syscall(frame: &mut TrapFrame) -> u64 {
    {
        use azos_arch::Interrupts;
        azos_arch::ARCH.enable_all();
    }
    azos_sched::swcensus::ecall_enter();
    let num = frame.regs[gpr::RAX];
    if azos_trace::syscall_on() {
        trace_sys_enter(frame);
    }
    let result = match azos_syscall::syscall_entry_fast(num) {
        azos_syscall::SyscallEntry::Done(r) => r,
        entry => syscall_dispatch(frame, num, entry),
    };
    frame.regs[gpr::RAX] = result as u64;
    if azos_trace::syscall_on() {
        trace_sys_exit(frame);
    }
    // `syscall` already left RIP past itself (RCX): no adjustment.
    if let Some(ctx) = azos_sched::take_current_task_exec_ctx() {
        // A fresh image: zero registers, initial FP state, the new entry.
        fp::discard_current();
        *frame = TrapFrame::user(ctx.entry, ctx.user_sp);
        azos_sched::swcensus::ecall_exit();
        return ctx.satp;
    }
    azos_sched::swcensus::ecall_exit();
    0
}

/// The full dispatch: the fork snapshot when the call needs one, the
/// argument registers, and the out-register writeback.
#[inline(never)]
fn syscall_dispatch(frame: &mut TrapFrame, num: u64, entry: azos_syscall::SyscallEntry) -> i64 {
    let wants_regs = num == azos_abi::syscall_nr::SYS_FORK
        || num == azos_abi::syscall_nr::SYS_FORK_COW
        || (azos_limits::LINUX_ABI
            && num == azos_linux_abi::nr::CLONE
            && azos_sched::scheduler::current_is_linux());
    // SYSFLOOR (aarch64's shape): the snapshot, an XSAVE image included, is
    // built only for the calls that read it; every other call passes a
    // static zero set and pays neither the copy nor the FP save.
    // SAFETY: all-zero is a valid `ForkRegs` (plain integers and bytes).
    static NO_REGS: azos_sched::UserRegs = unsafe { core::mem::zeroed() };
    let built;
    let user_regs: &azos_sched::UserRegs = if wants_regs {
        let mut r = azos_sched::UserRegs::default();
        r.gpr = frame.regs;
        r.rsp = frame.rsp;
        r.rflags = frame.rflags;
        r.fs_base = azos_arch::hw::rdmsr(cpu::IA32_FS_BASE);
        // In the kernel the user's GS base sits in KERNEL_GS_BASE (swapgs).
        r.gs_base = azos_arch::hw::rdmsr(cpu::IA32_KERNEL_GS_BASE);
        fp::snapshot_current(&mut r.fp);
        built = r;
        &built
    } else {
        &NO_REGS
    };
    let a = |n: usize| frame.regs[SYSCALL_ARGS[n]];
    let mut out = azos_syscall::SyscallOut::new();
    let result = azos_syscall::syscall_dispatch_checked(
        entry, num, a(0), a(1), a(2), a(3), a(4), a(5),
        frame.rip, frame.rsp,
        user_regs,
        &mut out,
    );
    if out.written {
        for (k, &r) in SYSCALL_OUT.iter().enumerate() {
            frame.regs[r] = out.regs[k];
        }
    }
    result
}

#[inline(never)]
fn trace_sys_enter(frame: &TrapFrame) {
    azos_trace::raw::sys_enter(frame.regs[gpr::RAX] as u32, azos_sched::current_task_tid(),
        frame.regs[gpr::RDI], frame.regs[gpr::RSI]);
}

#[inline(never)]
fn trace_sys_exit(frame: &TrapFrame) {
    azos_trace::raw::sys_exit(frame.regs[gpr::RAX] as u32, azos_sched::current_task_tid(),
        frame.regs[gpr::RAX] as i64);
}

/// A vector >= 32: the IPI, the spurious vector, or a device line for the
/// irqchip.
fn handle_irq(vector: usize) {
    if vector == SPURIOUS_VECTOR {
        SPURIOUS_IRQS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let _scope = azos_trace::IrqScope::enter(vector as u32);
    let hooks = irq_hooks();
    if vector == IPI_VECTOR {
        IPIS.fetch_add(1, Ordering::Relaxed);
        request_resched();
    } else if let Some(h) = hooks {
        (h.dispatch)(vector);
    } else {
        UNROUTED_IRQS.fetch_add(1, Ordering::Relaxed);
    }
    if let Some(h) = hooks {
        (h.eoi)();
    }
}

/// #PF: copy-on-write and demand faults from ring 3 resolve and resume;
/// any other ring-3 fault kills the task (SIGSEGV); a kernel fault halts.
fn handle_page_fault(frame: &mut TrapFrame) {
    const PF_WRITE: u64 = 1 << 1;
    let write = frame.error_code & PF_WRITE != 0;
    let fault_va = frame.cr2 as usize;
    if azos_trace::fault_on() {
        azos_trace::raw::page_fault(fault_va as u64, frame.error_code as u32, azos_sched::current_task_tid());
    }
    if frame.came_from_user() {
        let user_pt = azos_sched::current_user_pt();
        if user_pt != 0 {
            if write && azos_mm::vmm::handle_cow_fault(user_pt, fault_va).is_ok() {
                azos_mm::vmm::note_cow_resolved();
                return;
            }
            if azos_mm::vmm::handle_demand_fault(user_pt, fault_va).is_ok() {
                azos_mm::vmm::note_demand_resolved();
                return;
            }
        }
        let show = user_fault_report();
        if show {
            azos_drv_sys::kwarn!("[PAGE FAULT] {} at {:#x} (rip={:#x}, error={:#x}, tid={}): killing the task",
                if write { "write" } else { "read/exec" }, fault_va, frame.rip, frame.error_code,
                azos_sched::current_task_tid());
        }
        page_fault_note_lease(fault_va, show);
        azos_sched::scheduler::task_exit_by_signal(azos_abi::exit_status::KILLED_SEGV);
    }
    azos_drv_sys::uart::console_bypass_for_halt();
    azos_drv_sys::kerr!("[FATAL] x86_64 kernel page fault: {} at {:#x} (rip={:#x}, error={:#x})",
        if write { "write" } else { "read/exec" }, fault_va, frame.rip, frame.error_code);
    fatal_halt();
}

/// Name and count a user fault on a lease mapping the kernel revoked, or on
/// a lessor's buffer under a seal (aarch64's and riscv64's twin; the caller
/// kills the task). Out of line: the fault path is not the hot path.
#[inline(never)]
fn page_fault_note_lease(fault_va: usize, show: bool) {
    let tid = azos_sched::current_task_tid();
    if let Some(lease) = azos_ipc::lease::lease_revoked_fault(tid, fault_va).filter(|_| show) {
        azos_drv_sys::kwarn!(
            "[LEASE] task {} touched lease {} mapping at {:#x} after it was revoked: recorded ({} since boot)",
            tid, lease, fault_va, azos_ipc::lease::lease_revoked_faults(),
        );
    }
    if let Some(lease) = azos_ipc::lease::lease_sealed_fault(tid, fault_va).filter(|_| show) {
        azos_drv_sys::kwarn!(
            "[LEASE] task {} wrote its buffer at {:#x} while lease {} sealed it: recorded ({} since boot)",
            tid, fault_va, lease, azos_ipc::lease::lease_seal_faults(),
        );
    }
}

/// Vectors 0..31 other than #PF: NMI is counted and returns; a ring-3
/// fault kills the task with its signal; #DF, #MC and any kernel fault halt.
fn handle_exception(frame: &mut TrapFrame) {
    use azos_abi::exit_status as es;
    let v = frame.vector as usize;
    if v == idt::NMI {
        NMIS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if frame.came_from_user() && v != idt::DF && v != idt::MC {
        if user_fault_report() {
            print_trap(frame, "user fault");
            azos_drv_sys::kwarn!("[X86-TRAP] Killing user task '{}' (tid {})",
                azos_sched::current_task_name(), azos_sched::current_task_tid());
        }
        let code = match v {
            idt::BP | idt::DB => es::KILLED_TRAP,
            idt::AC => es::KILLED_BUS,
            idt::GP | idt::SS | idt::NP => es::KILLED_SEGV,
            _ => es::KILLED_ILL,
        };
        azos_sched::scheduler::task_exit_by_signal(code);
    }
    azos_drv_sys::uart::console_bypass_for_halt();
    print_trap(frame, "unhandled exception");
    fatal_halt();
}

fn print_trap(frame: &TrapFrame, what: &str) {
    azos_drv_sys::kwarn!("[X86-TRAP] {}: vector {} ({}), error code {:#x}", what, frame.vector,
        idt::vector_name(frame.vector as usize), frame.error_code);
    azos_drv_sys::kwarn!("[X86-TRAP]   rip {:#x} cs {:#x} rflags {:#x} rsp {:#x} ss {:#x}",
        frame.rip, frame.cs, frame.rflags, frame.rsp, frame.ss);
}

static USER_FAULT_REPORTS: azos_drv_sys::ratelimit::RateLimit = azos_drv_sys::ratelimit::RateLimit::new(10, 5);

#[inline(never)]
fn user_fault_report() -> bool {
    match USER_FAULT_REPORTS.check() {
        Some(0) => true,
        Some(k) => {
            azos_drv_sys::kwarn!("[FAULT] {} user-task fault report(s) suppressed", k);
            true
        }
        None => false,
    }
}

fn fatal_halt() -> ! {
    use azos_arch::Boot;
    azos_common::set_panicked();
    #[cfg(feature = "domain-robot")]
    azos_robot::motor_cmd_publish(0, 0);
    azos_arch::ARCH.shutdown()
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
    azos_arch::hw::wrmsr(cpu::IA32_FS_BASE, 0);
    azos_arch::hw::wrmsr(cpu::IA32_KERNEL_GS_BASE, 0);
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
    azos_arch::hw::wrmsr(cpu::IA32_FS_BASE, regs.fs_base);
    // The user GS base waits in KERNEL_GS_BASE for trap_return's swapgs.
    azos_arch::hw::wrmsr(cpu::IA32_KERNEL_GS_BASE, regs.gs_base);
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
