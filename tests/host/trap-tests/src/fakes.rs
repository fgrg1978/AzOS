// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The fake kernel and the three fake frames.
//!
//! The services are associated functions (the policy is generic over a type,
//! not an object), so the fake's state is thread-local: every test runs on its
//! own thread and starts from [`reset`].

use std::cell::RefCell;

use crate::trap::frame::{
    Cow, Disposition, EntryKind, FaultServices, Frame, IrqServices, KernelFault, SyscallServices, TrapClass,
};
use azos_abi::exit_status as es;

// ── The fake kernel ─────────────────────────────────────────────────────────

pub struct St {
    pub log: Vec<String>,
    // syscalls
    pub domain: u32,
    /// The running task: the subject of a pledge receipt.
    pub tid: u32,
    pub kind: EntryKind,
    pub shortcut: Option<i64>,
    pub dispatch_ret: i64,
    pub dispatches: Vec<(u64, bool)>,
    pub exec: Option<u64>,
    pub work: bool,
    pub trace: bool,
    pub probe: Option<u64>,
    // faults
    pub user_pt: usize,
    pub cow: Vec<Cow>,
    pub demand_ok: bool,
    pub accessed_ok: bool,
    pub report: bool,
    pub arch_pf: bool,
    pub arch_exc: Disposition,
    // interrupts
    pub stack_ok: bool,
    pub schedules: u32,
}

impl St {
    fn new() -> Self {
        St {
            log: Vec::new(),
            domain: 0,
            tid: 0,
            kind: EntryKind::Native,
            shortcut: None,
            dispatch_ret: 1000,
            dispatches: Vec::new(),
            exec: None,
            work: false,
            trace: false,
            probe: None,
            user_pt: 0x8000,
            cow: Vec::new(),
            demand_ok: false,
            accessed_ok: false,
            report: true,
            arch_pf: false,
            arch_exc: Disposition::Default,
            stack_ok: true,
            schedules: 0,
        }
    }
}

thread_local! {
    static ST: RefCell<St> = RefCell::new(St::new());
}

/// Run `f` on this thread's fake kernel.
pub fn with<R>(f: impl FnOnce(&mut St) -> R) -> R {
    ST.with(|s| f(&mut s.borrow_mut()))
}

/// Start a test from a fresh kernel.
pub fn reset() {
    ST.with(|s| *s.borrow_mut() = St::new());
}

pub fn log(s: impl Into<String>) {
    let s = s.into();
    with(|st| st.log.push(s));
}

pub fn logged() -> Vec<String> {
    with(|st| st.log.clone())
}

/// Did the policy log a line that contains `needle`?
pub fn saw(needle: &str) -> bool {
    with(|st| st.log.iter().any(|l| l.contains(needle)))
}

/// Index of the first logged line containing `needle`.
pub fn at(needle: &str) -> Option<usize> {
    with(|st| st.log.iter().position(|l| l.contains(needle)))
}

/// What `kill` and `fatal_halt` (`-> !`) unwind with, so a test can catch them.
#[derive(Debug, PartialEq, Eq)]
pub struct Killed(pub i32);
#[derive(Debug, PartialEq, Eq)]
pub struct Halted;

/// Run `f`; the outcome of a path that never returns.
pub enum Ended {
    Returned,
    Killed(i32),
    Halted,
}

pub fn ends(f: impl FnOnce()) -> Ended {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(()) => Ended::Returned,
        Err(p) => {
            if let Some(k) = p.downcast_ref::<Killed>() {
                Ended::Killed(k.0)
            } else if p.downcast_ref::<Halted>().is_some() {
                Ended::Halted
            } else {
                std::panic::resume_unwind(p)
            }
        }
    }
}

pub struct Fake;

impl<F: Frame> SyscallServices<F> for Fake {
    type Entry = EntryKind;
    type Exec = u64;

    fn probe(_num: u64) -> Option<u64> {
        with(|s| s.probe)
    }
    fn interrupts_on() {
        log("interrupts_on");
    }
    fn census_enter() {
        log("census_enter");
    }
    fn census_exit() {
        log("census_exit");
    }
    fn trace_on() -> bool {
        with(|s| s.trace)
    }
    fn trace_enter(num: u64, a0: u64, a1: u64) {
        log(format!("trace_enter {num} {a0} {a1}"));
    }
    fn trace_exit(num: u64, ret: i64) {
        log(format!("trace_exit {num} {ret}"));
    }
    fn verdict(_num: u64) -> EntryKind {
        log("verdict");
        with(|s| s.kind)
    }
    fn shortcut(num: u64) -> Option<i64> {
        log(format!("shortcut {num}"));
        with(|s| s.shortcut)
    }
    fn kind(entry: &EntryKind) -> EntryKind {
        *entry
    }
    fn domain_entry(num: u64, case: u8, bit: u8) -> bool {
        crate::domain::enter(with(|s| s.domain), with(|s| s.tid), num, case, bit)
    }
    fn fast_or_dispatch(_frame: &mut F, num: u64, _entry: EntryKind) -> i64 {
        log(format!("fast_or_dispatch {num}"));
        with(|s| {
            s.dispatches.push((num, true));
            s.dispatch_ret
        })
    }
    fn dispatch(_frame: &mut F, num: u64, _entry: EntryKind) -> i64 {
        log(format!("dispatch {num}"));
        with(|s| {
            s.dispatches.push((num, false));
            s.dispatch_ret
        })
    }
    fn take_exec() -> Option<u64> {
        with(|s| s.exec.take())
    }
    fn exec_enter(_frame: &mut F, ctx: u64) -> u64 {
        log(format!("exec_enter {ctx:#x}"));
        ctx
    }
    fn return_work_pending() -> bool {
        with(|s| s.work)
    }
    fn return_work(_frame: &mut F) {
        log("return_work");
    }
}

impl<F: Frame> FaultServices<F> for Fake {
    fn trace_fault(addr: u64, cause: u32) {
        log(format!("trace_fault {addr:#x} {cause}"));
    }
    fn user_pt() -> usize {
        with(|s| s.user_pt)
    }
    fn cow(pt: usize, va: u64) -> Cow {
        log(format!("cow {pt:#x} {va:#x}"));
        with(|s| if s.cow.is_empty() { Cow::No } else { s.cow.remove(0) })
    }
    fn demand(pt: usize, va: u64) -> bool {
        log(format!("demand {pt:#x} {va:#x}"));
        with(|s| s.demand_ok)
    }
    fn accessed(pt: usize, va: u64) -> bool {
        log(format!("accessed {pt:#x} {va:#x}"));
        with(|s| s.accessed_ok)
    }
    fn cow_oom(va: u64) {
        log(format!("cow_oom {va:#x}"));
    }
    fn in_null_guard(va: u64) -> bool {
        va < 0x1000
    }
    fn in_stack_area(va: u64) -> bool {
        (0x7ffc_0000..0x8000_0000).contains(&va)
    }
    fn user_fault_report() -> bool {
        with(|s| s.report)
    }
    fn warn(args: core::fmt::Arguments<'_>) {
        log(format!("warn: {args}"));
    }
    fn error(args: core::fmt::Arguments<'_>) {
        log(format!("error: {args}"));
    }
    fn cpu() -> usize {
        3
    }
    fn tid() -> u32 {
        42
    }
    fn task_name() -> &'static str {
        "tester"
    }
    fn crashdump(_frame: &F, status: i32) {
        log(format!("crashdump {status}"));
    }
    fn kill(status: i32) -> ! {
        log(format!("kill {status}"));
        std::panic::resume_unwind(Box::new(Killed(status)))
    }
    fn resolved() -> (u64, u64) {
        (7, 9)
    }
    fn entries() -> [u64; 3] {
        [5, 1, 2]
    }
    fn stop_actuators() {
        log("stop_actuators");
    }
    fn halt_begin() {
        log("halt_begin");
    }
    fn halt_report() {
        log("halt_report");
    }
    fn trace_dump() {
        log("trace_dump");
    }
    fn fatal_halt() -> ! {
        log("fatal_halt");
        std::panic::resume_unwind(Box::new(Halted))
    }
    fn arch_page_fault(_frame: &mut F) -> bool {
        log("arch_page_fault");
        with(|s| s.arch_pf)
    }
    fn arch_exception(_frame: &mut F) -> Disposition {
        log("arch_exception");
        with(|s| s.arch_exc)
    }
}

pub struct Guard(&'static str);
impl Drop for Guard {
    fn drop(&mut self) {
        log(format!("drop {}", self.0));
    }
}

impl<F: Frame> IrqServices<F> for Fake {
    type ArmGuard = Guard;
    fn arm_guard(user: bool) -> Guard {
        log(format!("arm_guard user={user}"));
        Guard("arm_guard")
    }
    type ExitGuard = Guard;
    fn exit_guard(user: bool) -> Guard {
        log(format!("exit_guard user={user}"));
        Guard("exit_guard")
    }
    fn cpu() -> usize {
        3
    }
    fn irq_stack_intact(_cpu: usize) -> bool {
        with(|s| s.stack_ok)
    }
    fn isr_enter(cpu: usize) {
        log(format!("isr_enter {cpu}"));
    }
    fn isr_exit(cpu: usize) {
        log(format!("isr_exit {cpu}"));
    }
    fn watchdog_tick() -> u64 {
        log("watchdog_tick");
        100
    }
    fn vdso_tick(ticks: u64, uptime_ms: Option<u64>, now: u64) {
        log(format!("vdso_tick {ticks} {uptime_ms:?} {now}"));
    }
    fn wake_expired(now: u64) {
        log(format!("wake_expired {now}"));
    }
    fn reap_stamped() {
        log("reap_stamped");
    }
    fn user_return_work(_frame: &mut F) {
        log("user_return_work");
    }
    fn schedule() {
        log("schedule");
        with(|s| s.schedules += 1);
    }
}

// ── Three frames, three conventions ─────────────────────────────────────────

/// riscv64: number in a7 (x17), arguments a0..a5 (x10..), result a0, `ecall`
/// leaves `sepc` AT the instruction, privilege in `sstatus.SPP`, a store page
/// fault is cause 15.
#[derive(Clone, Debug, Default)]
pub struct RvFrame {
    pub regs: [u64; 32],
    pub sepc: u64,
    pub scause: u64,
    pub stval: u64,
    pub s_mode: bool,
}

impl Frame for RvFrame {
    const ISA: &'static str = "riscv64";
    fn class(&self) -> TrapClass {
        match self.scause {
            8 | 9 => TrapClass::Syscall,
            12 | 13 | 15 => TrapClass::PageFault,
            c if c >> 63 != 0 => TrapClass::Interrupt,
            _ => TrapClass::OtherException,
        }
    }
    fn came_from_user(&self) -> bool {
        !self.s_mode
    }
    fn fault_cause(&self) -> u32 {
        self.scause as u32
    }
    fn fault_addr(&self) -> u64 {
        self.stval
    }
    fn fault_is_write(&self) -> bool {
        self.scause == 15
    }
    fn pc(&self) -> u64 {
        self.sepc
    }
    fn syscall_number(&self) -> u64 {
        self.regs[17]
    }
    fn syscall_arg(&self, n: usize) -> u64 {
        self.regs[10 + n]
    }
    fn set_syscall_return(&mut self, v: i64) {
        self.regs[10] = v as u64;
    }
    fn skip_syscall(&mut self) {
        self.sepc = self.sepc.wrapping_add(4);
    }
    fn user_kill_status(&self) -> Option<i32> {
        Some(match self.scause {
            0 | 4 | 6 => es::KILLED_BUS,
            1 | 5 | 7 => es::KILLED_SEGV,
            3 => es::KILLED_TRAP,
            _ => es::KILLED_ILL,
        })
    }
    fn print(&self, what: &str) {
        log(format!("print riscv64 {what}"));
    }
    fn print_kernel_fault(&self, f: &KernelFault) {
        log(format!("print_kernel_fault riscv64 {} at {:#x} cpu={} null={} resolved={:?}",
            if f.write { "write" } else { "read/exec" }, f.va, f.cpu, f.null_guard, f.resolved));
    }
}

/// aarch64: number in x8, arguments x0..x5, result x0, `svc` leaves `ELR`
/// past the instruction, privilege in `SPSR.M`, a data abort's write is ESR
/// ISS bit 6; an exception from EL0 is a task's fault only on the lower-EL
/// synchronous vector.
#[derive(Clone, Debug, Default)]
pub struct ArmFrame {
    pub regs: [u64; 31],
    pub elr: u64,
    pub esr: u64,
    pub far: u64,
    pub el1: bool,
    pub lower_el_sync: bool,
    pub irq: bool,
}

impl Frame for ArmFrame {
    const ISA: &'static str = "aarch64";
    fn class(&self) -> TrapClass {
        if self.irq {
            return TrapClass::Interrupt;
        }
        match self.esr >> 26 {
            0x15 => TrapClass::Syscall,
            0x20 | 0x21 | 0x24 | 0x25 => TrapClass::PageFault,
            _ => TrapClass::OtherException,
        }
    }
    fn came_from_user(&self) -> bool {
        !self.el1
    }
    fn fault_cause(&self) -> u32 {
        (self.esr >> 26) as u32
    }
    fn fault_addr(&self) -> u64 {
        self.far
    }
    fn fault_is_write(&self) -> bool {
        self.esr & (1 << 6) != 0
    }
    fn pc(&self) -> u64 {
        self.elr
    }
    fn syscall_number(&self) -> u64 {
        self.regs[8]
    }
    fn syscall_arg(&self, n: usize) -> u64 {
        self.regs[n]
    }
    fn set_syscall_return(&mut self, v: i64) {
        self.regs[0] = v as u64;
    }
    fn skip_syscall(&mut self) {}
    fn user_kill_status(&self) -> Option<i32> {
        self.lower_el_sync.then(|| match (self.esr >> 26) & 0x3F {
            0x22 | 0x26 => es::KILLED_BUS,
            0x3C => es::KILLED_TRAP,
            _ => es::KILLED_ILL,
        })
    }
    fn print(&self, what: &str) {
        log(format!("print aarch64 {what}"));
    }
    fn print_kernel_fault(&self, f: &KernelFault) {
        log(format!("print_kernel_fault aarch64 {} at {:#x} cpu={} null={} resolved={:?}",
            if f.write { "write" } else { "read/exec" }, f.va, f.cpu, f.null_guard, f.resolved));
    }
}

/// x86_64: number in rax, arguments rdi rsi rdx r10 r8 r9, result rax,
/// `syscall` leaves RIP past itself, privilege in CS.RPL, a write fault is
/// error-code bit 1; #DF and #MC are the machine's, never the task's.
#[derive(Clone, Debug, Default)]
pub struct X86Frame {
    /// rax rcx rdx rbx rbp rsi rdi r8..r15, in the kernel's `gpr` order.
    pub rax: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
    pub rip: u64,
    pub cs: u64,
    pub vector: u64,
    pub error_code: u64,
    pub cr2: u64,
}

impl X86Frame {
    pub const SYSCALL: u64 = 0x80;
    pub const PF: u64 = 14;
    pub const GP: u64 = 13;
    pub const DF: u64 = 8;
    pub const UD: u64 = 6;
}

impl Frame for X86Frame {
    const ISA: &'static str = "x86_64";
    fn class(&self) -> TrapClass {
        match self.vector {
            Self::SYSCALL => TrapClass::Syscall,
            Self::PF => TrapClass::PageFault,
            v if v >= 32 => TrapClass::Interrupt,
            _ => TrapClass::OtherException,
        }
    }
    fn came_from_user(&self) -> bool {
        self.cs & 3 == 3
    }
    fn fault_cause(&self) -> u32 {
        self.error_code as u32
    }
    fn fault_addr(&self) -> u64 {
        self.cr2
    }
    fn fault_is_write(&self) -> bool {
        self.error_code & 2 != 0
    }
    fn pc(&self) -> u64 {
        self.rip
    }
    fn syscall_number(&self) -> u64 {
        self.rax
    }
    fn syscall_arg(&self, n: usize) -> u64 {
        [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9][n]
    }
    fn set_syscall_return(&mut self, v: i64) {
        self.rax = v as u64;
    }
    fn skip_syscall(&mut self) {}
    fn user_kill_status(&self) -> Option<i32> {
        match self.vector {
            Self::DF | 18 => None,
            3 | 1 => Some(es::KILLED_TRAP),
            17 => Some(es::KILLED_BUS),
            Self::GP | 12 | 11 => Some(es::KILLED_SEGV),
            _ => Some(es::KILLED_ILL),
        }
    }
    fn print(&self, what: &str) {
        log(format!("print x86_64 {what}"));
    }
    fn print_kernel_fault(&self, f: &KernelFault) {
        log(format!("print_kernel_fault x86_64 {} at {:#x} cpu={} null={} resolved={:?}",
            if f.write { "write" } else { "read/exec" }, f.va, f.cpu, f.null_guard, f.resolved));
    }
}

/// A user-mode `ecall` / `svc` / `syscall` of number `num` with arguments
/// `args`, on each ISA's frame.
pub fn rv_call(num: u64, args: [u64; 2]) -> RvFrame {
    let mut f = RvFrame { scause: 8, sepc: 0x1000, ..Default::default() };
    f.regs[17] = num;
    f.regs[10] = args[0];
    f.regs[11] = args[1];
    f
}

pub fn arm_call(num: u64, args: [u64; 2]) -> ArmFrame {
    let mut f = ArmFrame { esr: 0x15 << 26, elr: 0x2000, lower_el_sync: true, ..Default::default() };
    f.regs[8] = num;
    f.regs[0] = args[0];
    f.regs[1] = args[1];
    f
}

pub fn x86_call(num: u64, args: [u64; 2]) -> X86Frame {
    X86Frame { vector: X86Frame::SYSCALL, rax: num, rdi: args[0], rsi: args[1], rip: 0x3000, cs: 3, ..Default::default() }
}
