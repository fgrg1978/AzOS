// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sampling profiler, kernel side (Kconfig `PROFILER`, trace class
//! `prof`; the walker, the record format and the reader are
//! `azos_trace::prof`).
//!
//! # The tick
//!
//! The scheduler tick of each ISA calls [`on_tick`] with what it knows of
//! the code it interrupted (its PC, frame pointer, stack pointer, and
//! whether it ran in user mode). While the `prof` class is switched on, every
//! `PROFILER_TICK_DIV`-th tick on a CPU walks the interrupted frame-pointer
//! chain and writes one sample (a header record and the frames, two to a
//! record) into the CPU's trace ring. With the class off, or `PROFILER` off,
//! the hook is the trace mask's test or nothing at all: [`azos_trace::prof_on`]
//! folds to `false` and the closure is never built.
//!
//! The tick runs with interrupts masked, so a sample's records follow one
//! another on the ring; no lock is taken and nothing is allocated, which is
//! why the user stack is read through its page table without committing a
//! missing page ([`azos_mm::vmm::translate_user_readable_nofault`]) rather
//! than through `copy_from_user`.
//!
//! # The PMU's sampling counter
//!
//! With Kconfig `PROFILER_PMU` a CPU whose PMU can interrupt on an overflow
//! ([`azos_arch_api::Pmu::sample_arm`]) samples every `PROFILER_PMU_PERIOD`
//! core cycles instead: its tick arms the counter the first time it sees the
//! class on and takes no sample of its own from then on, and the PMU
//! interrupt ([`on_overflow`]) samples exactly as the tick does, without
//! `PROFILER_TICK_DIV`, and re-arms. Once the class is off, the next overflow
//! disarms the counter, so a profiler that is off arms nothing. The PMU
//! interrupt is maskable on every ISA (x86_64 included, see
//! `azos_arch::pmu`), so the trace ring sees the tick's discipline.
//!
//! # Real-time CPUs
//!
//! A real-time CPU ([`azos_sched::cpu_is_real_time`]: `isolcpus`, a band
//! task or an admitted reservation) is never armed, and a counter whose CPU
//! became one disarms at its next overflow: the interrupt and its walk are
//! jitter the CPU's reservations did not budget for. Its tick, which runs
//! anyway, records the interrupted PC only ([`Origin::RtTick`], no walk), so
//! `tracectl profile` shows where the CPU was and that its samples were
//! refused.
//!
//! # Which stack
//!
//! A kernel-mode sample is bounded by the stack it was taken on: the
//! interrupted stack pointer up to the top of the running task's kernel stack,
//! or of this CPU's interrupt stack. A stack pointer on neither (the boot
//! stack, early boot) walks nothing and records only the PC (`no-stack`).
//! A user-mode sample is bounded by the interrupted user stack pointer and
//! the user stack's size, below the top of the user address space.
//!
//! # A fatal trap or panic
//!
//! [`backtrace`] prints the panicking CPU's own call chain with the same
//! walker, from the panic handler and from [`crate::panic::halt_report`] (the
//! tail every fatal trap shares). The trap entry does not touch the frame
//! pointer, so the chain runs through the handler into the code that
//! faulted: its callers appear, the faulting function itself is the `sepc` /
//! `elr` / `rip` the handler already prints. The addresses are for
//! `addr2line -f -e <kernel ELF>`.

use azos_arch::Pmu as _;
use azos_trace::prof::{self, Layout, Origin, Stop, Walk, MAX_DEPTH};
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

/// Frames a sample holds, the PC included (Kconfig `PROFILER_DEPTH`).
const DEPTH: usize = azos_limits::PROFILER_DEPTH as usize;
/// Sample every this many ticks on a CPU (Kconfig `PROFILER_TICK_DIV`).
const DIV: u32 = azos_limits::PROFILER_TICK_DIV as u32;
/// Sample on the PMU's sampling counter where a CPU has one (Kconfig
/// `PROFILER_PMU`), every this many core cycles (`PROFILER_PMU_PERIOD`).
const PMU: bool = azos_limits::PROFILER_PMU;
const PERIOD: u64 = azos_limits::PROFILER_PMU_PERIOD as u64;
const _: () = assert!(DEPTH >= 2 && DEPTH <= MAX_DEPTH, "PROFILER_DEPTH is 2..=32");
const _: () = assert!(DIV >= 1);

#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("prof: no frame layout for this ISA: a new ISA names its `LAYOUT` and `regs!` here");

#[cfg(target_arch = "riscv64")]
const LAYOUT: Layout = prof::RISCV64;
#[cfg(target_arch = "aarch64")]
const LAYOUT: Layout = prof::AARCH64;
#[cfg(target_arch = "x86_64")]
const LAYOUT: Layout = prof::X86_64;

/// What a scheduler tick knows of the code it interrupted.
pub(crate) struct Interrupted {
    pub pc: usize,
    /// The frame-pointer register (`s0`, `x29`, `rbp`).
    pub fp: usize,
    /// The stack pointer the code had. For a kernel-mode interrupt on a
    /// trap frame that does not hold it (aarch64): just above the frame.
    pub sp: usize,
    pub user: bool,
}

/// Ticks seen per CPU, for `PROFILER_TICK_DIV`. Each slot is written by its
/// own CPU's tick only.
static TICKS: [AtomicU32; azos_sched::MAX_CPUS] = [const { AtomicU32::new(0) }; azos_sched::MAX_CPUS];

/// Per CPU, its PMU sampling counter: [`IDLE`], [`ARMED`], or [`REFUSED`]
/// (the arm failed: no counter, no interrupt, a period it does not take;
/// the tick samples for the rest of the boot and never asks again, which on
/// riscv64 would be an SBI call per tick). Written by the CPU's own tick and
/// PMU interrupt only.
static COUNTER: [AtomicU8; azos_sched::MAX_CPUS] = [const { AtomicU8::new(IDLE) }; azos_sched::MAX_CPUS];
const IDLE: u8 = 0;
const ARMED: u8 = 1;
const REFUSED: u8 = 2;

/// The scheduler tick's hook: sample the interrupted code if the class is on.
/// `what` is only called then, so the caller's frame is not read otherwise.
#[inline(always)]
pub(crate) fn on_tick(what: impl FnOnce() -> Interrupted) {
    if azos_trace::prof_on() {
        tick(what);
    }
}

#[inline(never)]
fn tick(what: impl FnOnce() -> Interrupted) {
    let cpu = azos_sched::smp::current_cpu_id();
    let Some(counter) = COUNTER.get(cpu) else { return };
    let rt = azos_sched::cpu_is_real_time(cpu);
    if PMU && !rt {
        // The counter samples this CPU; the first tick with the class on arms it.
        match counter.load(Ordering::Relaxed) {
            ARMED => return,
            IDLE if azos_arch::ARCH.sample_arm(PERIOD) => {
                counter.store(ARMED, Ordering::Relaxed);
                return;
            }
            IDLE => counter.store(REFUSED, Ordering::Relaxed),
            _ => {}
        }
    }
    if DIV > 1 {
        let Some(t) = TICKS.get(cpu) else { return };
        let n = t.load(Ordering::Relaxed);
        t.store(n.wrapping_add(1), Ordering::Relaxed);
        if n % DIV != 0 {
            return;
        }
    }
    sample(what(), cpu, if rt { Origin::RtTick } else { Origin::Tick });
}

/// The PMU interrupt's hook (Kconfig `PROFILER_PMU`): acknowledge the
/// sampling counter and, while the class is on and the CPU is not real-time,
/// re-arm it and sample the interrupted code; otherwise disarm it. `what` is
/// only called for a sample.
#[inline(never)]
pub(crate) fn on_overflow(what: impl FnOnce() -> Interrupted) {
    let cpu = azos_sched::smp::current_cpu_id();
    let keep = PMU && azos_trace::prof_on() && !azos_sched::cpu_is_real_time(cpu);
    let overflowed = azos_arch::ARCH.sample_ack(keep.then_some(PERIOD));
    if !keep {
        if let Some(c) = COUNTER.get(cpu) {
            c.store(IDLE, Ordering::Relaxed);
        }
    } else if overflowed {
        sample(what(), cpu, Origin::Pmu);
    }
}

/// One sample of the interrupted code into this CPU's ring: the walked
/// frame-pointer chain, or the PC alone on a real-time CPU.
fn sample(i: Interrupted, cpu: usize, origin: Origin) {
    let mut frames = [0u64; DEPTH];
    let w = if origin == Origin::RtTick {
        frames[0] = i.pc as u64;
        Walk { depth: 1, stop: Stop::Depth }
    } else if i.user {
        walk_user(&i, &mut frames)
    } else {
        walk_kernel(&i, cpu, &mut frames)
    };
    prof::encode(azos_sched::current_task_tid(), i.user, origin, w, &frames, |ev, a| {
        azos_trace::record(ev, a[0], a[1], a[2], a[3]);
    });
}

// ── Kernel stacks ───────────────────────────────────────────────────────────

/// The stack `sp` is on, as `(sp, top)`: the running task's kernel stack, or
/// this CPU's interrupt stack. `None` when it is neither.
fn kernel_stack(sp: usize, cpu: usize) -> Option<(u64, u64)> {
    let top = azos_sched::current_task_stack_top();
    if top != 0 && sp <= top && top - sp <= azos_limits::KERNEL_STACK_SIZE_BYTES {
        return Some((sp as u64, top as u64));
    }
    let base = crate::boot::irq_stack_base(cpu);
    let end = base + azos_limits::INTERRUPT_STACK_SIZE_BYTES;
    if base != 0 && sp >= base && sp < end {
        return Some((sp as u64, end as u64));
    }
    None
}

/// A return address into the kernel's code.
fn kernel_text(a: u64) -> bool {
    // Linker symbols; only their addresses are taken.
    let (lo, hi) = (&raw const crate::_text_start as u64, &raw const crate::_text_end as u64);
    a >= lo && a < hi && a & 1 == 0
}

/// A stack word with the pointer-authentication code of a signed return
/// address removed (aarch64 `pac-ret`, `azos_arch::cpu::cfi`: the kernel and
/// the user images sign every saved link register). `xpaclri` (HINT #7)
/// leaves a canonical pointer, the frame pointers among them, unchanged and
/// is a no-op on a core without FEAT_PAuth. Other ISAs store plain addresses.
#[cfg(target_arch = "aarch64")]
fn unsigned(v: u64) -> u64 {
    let r: u64;
    // SAFETY: a register move around a HINT; x30 is declared clobbered.
    unsafe {
        core::arch::asm!("mov x30, {v}", "hint #7", "mov {r}, x30",
            v = in(reg) v, r = out(reg) r, out("x30") _, options(nomem, nostack));
    }
    r
}
#[cfg(not(target_arch = "aarch64"))]
fn unsigned(v: u64) -> u64 {
    v
}

/// One word of a kernel stack. The walker only asks for addresses inside the
/// stack [`kernel_stack`] found, which is live memory.
fn read_stack(a: u64) -> Option<u64> {
    // SAFETY: inside the live stack (see above), 8-byte aligned by the
    // walker's frame-pointer alignment and the layout's offsets.
    (a & 7 == 0).then(|| unsigned(unsafe { core::ptr::read_volatile(a as *const u64) }))
}

fn walk_kernel(i: &Interrupted, cpu: usize, out: &mut [u64]) -> Walk {
    match kernel_stack(i.sp, cpu) {
        Some((lo, hi)) => prof::walk(&LAYOUT, i.pc as u64, i.fp as u64, lo, hi, kernel_text, read_stack, out),
        None => {
            out[0] = i.pc as u64;
            Walk { depth: 1, stop: Stop::NoStack }
        }
    }
}

// ── The user stack ──────────────────────────────────────────────────────────

/// A return address into user code: above the null page, below the top of the
/// user address space.
fn user_text(a: u64) -> bool {
    a >= 0x1000 && a < azos_sched::process::USER_STACK_TOP as u64 && a & 1 == 0
}

/// One word of the interrupted task's user stack, from its page table, in
/// interrupt context: a page that is not mapped (or not readable) answers
/// `None`; nothing is committed, copied-on-write or allocated.
fn read_user(a: u64) -> Option<u64> {
    let pt = azos_sched::current_user_pt();
    if pt == 0 || a & 7 != 0 {
        return None;
    }
    // One resident read in one access section (uaccess-pin): a frame the
    // walk finds is not freed under the read.
    let mut w = [0u8; 8];
    (azos_mm::uaccess::copy_in_resident(pt, w.as_mut_ptr(), a as usize, 8) == 8)
        .then(|| unsigned(u64::from_ne_bytes(w)))
}

fn walk_user(i: &Interrupted, out: &mut [u64]) -> Walk {
    let lo = i.sp as u64;
    let hi = lo.saturating_add(azos_limits::USER_STACK_MAX_BYTES as u64).min(azos_sched::process::USER_STACK_TOP as u64);
    prof::walk(&LAYOUT, i.pc as u64, i.fp as u64, lo, hi, user_text, read_user, out)
}

// ── A fatal trap or panic ───────────────────────────────────────────────────

#[cfg(target_arch = "riscv64")]
macro_rules! regs {
    () => {{
        let (fp, sp): (u64, u64);
        // SAFETY: reads two registers.
        unsafe { core::arch::asm!("mv {0}, s0", "mv {1}, sp", out(reg) fp, out(reg) sp, options(nomem, nostack, preserves_flags)) };
        (fp, sp)
    }};
}
#[cfg(target_arch = "aarch64")]
macro_rules! regs {
    () => {{
        let (fp, sp): (u64, u64);
        // SAFETY: reads two registers.
        unsafe { core::arch::asm!("mov {0}, x29", "mov {1}, sp", out(reg) fp, out(reg) sp, options(nomem, nostack, preserves_flags)) };
        (fp, sp)
    }};
}
#[cfg(target_arch = "x86_64")]
macro_rules! regs {
    () => {{
        let (fp, sp): (u64, u64);
        // SAFETY: reads two registers.
        unsafe { core::arch::asm!("mov {0}, rbp", "mov {1}, rsp", out(reg) fp, out(reg) sp, options(nomem, nostack, preserves_flags)) };
        (fp, sp)
    }};
}

fn puts_hex(v: u64) {
    let mut d = [b'0'; 16];
    for (k, c) in d.iter_mut().rev().enumerate() {
        *c = b"0123456789abcdef"[(v >> (4 * k) & 15) as usize];
    }
    let first = d.iter().position(|&c| c != b'0').unwrap_or(15);
    azos_drv_sys::uart::puts("0x");
    azos_drv_sys::uart::puts(core::str::from_utf8(&d[first..]).unwrap_or("?"));
}

/// Print this CPU's call chain on the console, from the caller's frame up:
/// `[PANIC] backtrace: 0x... 0x...` and why the walk stopped. Raw console
/// writes only (no lock, no allocation), for the panic path.
#[inline(never)]
pub(crate) fn backtrace() {
    if !azos_limits::PROFILER {
        return;
    }
    let (fp, sp) = regs!();
    let cpu = azos_sched::smp::current_cpu_id();
    let mut frames = [0u64; MAX_DEPTH];
    let pc = backtrace as *const () as usize as u64;
    let w = match kernel_stack(sp as usize, cpu) {
        Some((lo, hi)) => prof::walk(&LAYOUT, pc, fp, lo, hi, kernel_text, read_stack, &mut frames),
        None => {
            frames[0] = pc;
            Walk { depth: 1, stop: Stop::NoStack }
        }
    };
    azos_drv_sys::uart::puts("[PANIC] backtrace:");
    // Frame 0 is this function; the report starts at its caller.
    for &f in &frames[1..w.depth] {
        azos_drv_sys::uart::puts(" ");
        puts_hex(f);
    }
    azos_drv_sys::uart::puts(" (stopped: ");
    azos_drv_sys::uart::puts(w.stop.name());
    azos_drv_sys::uart::puts(")\n");
}
