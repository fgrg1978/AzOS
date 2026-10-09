// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! The kernel event tracer (wave 15, TRACE; Kconfig `KTRACE`).
//!
//! One lock-free single-producer/single-consumer ring per CPU, all in one
//! kernel-owned shared-memory region (`azos_ipc::trace` creates it at boot
//! and maps it for a reader holding `Cap<Trace>`). Each CPU is the only
//! producer of its ring; the ring-3 reader (`tracectl`) the only consumer.
//! The layout, the producer and the consumer are `azos_spsc::trace`; this
//! crate is the kernel's side: the per-CPU producers, the runtime class mask
//! and the tracepoints.
//!
//! # What a tracepoint costs
//!
//! * `KTRACE` off, or its class off (`KTRACE_CLASS_*`): nothing. Every
//!   tracepoint is an `#[inline(always)]` test of `azos_limits` constants
//!   that folds to no instruction at all.
//! * Compiled in, class masked off at run time: one load of the mask, an
//!   `and` and a branch (the mask sits alone on its cache line, read-mostly).
//! * Recording: [`record`], out of line: interrupts masked (the ring is
//!   per CPU, so masking them is the whole of its mutual exclusion: an
//!   interrupt's own tracepoint cannot land in the middle of a record), the
//!   CPU from `tp` / `TPIDR_EL1`, the timestamp, five stores into the
//!   record's own cache line, and interrupts restored. No lock, no atomic
//!   read-modify-write, no division, and the shared tail is read only when
//!   the producer's cached copy says the ring is full.
//!
//! Masking uses the CSR / DAIF directly, not `azos_arch`'s `Interrupts`
//! trait, whose `LAT_TRACE` hooks would otherwise measure (and, through
//! the `lat` class, trace) the tracer itself.

use azos_abi::trace::*;
use azos_spsc::trace::{region_init, TraceProducer, TraceRecord, POLICY_DROP, POLICY_OVERWRITE, TS_CYCLES, TS_TIMEBASE};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

/// Per-CPU producer slots: the CPU ceiling (Kconfig `NR_CPUS`). The kernel
/// asserts it equals the scheduler's hart bound (`azos_sync::isr_depth::
/// MAX_HARTS`) where it creates the region; a hart at or above it never
/// records. The region layout's own bound, `TRACE_MAX_CPUS`, is the ABI
/// ceiling `tracectl` validates against and may not be exceeded.
pub const MAX_CPUS: usize = azos_limits::NR_CPUS;
const _: () = assert!(MAX_CPUS <= azos_spsc::trace::TRACE_MAX_CPUS as usize, "NR_CPUS exceeds the trace region's ring bound");

/// Is the tracer compiled in?
pub const ENABLED: bool = azos_limits::KTRACE;

/// Are tracepoints patched branches (Kconfig `KTRACE_STATIC_KEYS`)?
pub const STATIC_KEYS: bool = ENABLED && azos_limits::KTRACE_STATIC_KEYS;

pub mod jump;

/// The classes compiled in, as a mask.
pub const CLASSES: u32 = if !ENABLED {
    0
} else {
    (azos_limits::KTRACE_CLASS_SCHED as u32) << TRACE_CLASS_SCHED
        | (azos_limits::KTRACE_CLASS_IRQ as u32) << TRACE_CLASS_IRQ
        | (azos_limits::KTRACE_CLASS_SYSCALL as u32) << TRACE_CLASS_SYSCALL
        | (azos_limits::KTRACE_CLASS_IPC as u32) << TRACE_CLASS_IPC
        | (azos_limits::KTRACE_CLASS_FAULT as u32) << TRACE_CLASS_FAULT
        | (azos_limits::KTRACE_CLASS_PROC as u32) << TRACE_CLASS_PROC
        | (azos_limits::KTRACE_CLASS_LAT as u32) << TRACE_CLASS_LAT
};

/// The ring policy (Kconfig choice): overwrite, else drop.
pub const OVERWRITE: bool = azos_limits::KTRACE_POLICY_OVERWRITE;
/// The timestamp source (Kconfig choice): the cycle counter, else the timebase.
pub const TS_IS_CYCLES: bool = azos_limits::KTRACE_TS_CYCLES;
/// Records per CPU ring, as configured (the boot may halve it to fit).
pub const RING_ENTRIES: u32 = azos_limits::KTRACE_RING_ENTRIES as u32;
/// The runtime mask at boot, restricted to the compiled classes.
pub const BOOT_MASK: u32 = azos_limits::KTRACE_BOOT_MASK as u32 & CLASSES;

const _: () = assert!(!ENABLED || RING_ENTRIES.is_power_of_two(), "KTRACE_RING_ENTRIES must be a power of two");
const _: () = assert!(TRACE_CLASSES <= 32);

#[repr(C, align(64))]
struct Producer(UnsafeCell<TraceProducer>);
// SAFETY: slot `i` is only touched by CPU `i` with its interrupts masked
// (`record`), or by `install` before any other CPU can record.
unsafe impl Sync for Producer {}

/// Each CPU's producer (the ring control: head, drops, its ring's address),
/// in its per-CPU area (wave 15, NRCPUS), one cache line a CPU. All-zero is
/// `TraceProducer::empty()`, a producer that is not live and records nothing.
///
/// Scope: a bare `PerCpuRemote` for now: written by its own CPU only
/// (`PerCpu`), read racily by statistics and the panic dump from any CPU.
static CPUS: azos_percpu::PerCpuRemote<Producer> =
    // SAFETY: all-zero bytes are `Producer(UnsafeCell::new(TraceProducer::empty()))`.
    unsafe { azos_percpu::PerCpuRemote::zeroed() };

/// The per-CPU variables this crate keeps in the areas, for the kernel's
/// `setup_per_cpu_areas`.
pub fn for_each_percpu_var(f: &mut dyn FnMut(&'static dyn azos_percpu::PerCpuVar)) {
    if ENABLED {
        f(&CPUS);
    }
}

/// CPU `cpu`'s producer, or `None` if it has no area (past `nr_cpu_ids`, or
/// before the areas are attached at boot).
#[inline(always)]
fn producer(cpu: usize) -> Option<&'static Producer> {
    // SAFETY: an attached slot lives as long as the kernel.
    CPUS.attached(cpu).then(|| unsafe { &*CPUS.ptr(cpu) })
}

/// The runtime mask, alone on its line: every tracepoint reads it, only
/// `set_mask` writes it.
#[repr(C, align(64))]
struct Mask(AtomicU32);
static MASK: Mask = Mask(AtomicU32::new(0));

/// The region (kernel address), its rings and their entries, once installed.
static REGION: AtomicUsize = AtomicUsize::new(0);
static NCPU: AtomicU32 = AtomicU32::new(0);
static ENTRIES: AtomicU32 = AtomicU32::new(0);

// ── ISA primitives (inline, no hooks) ───────────────────────────────────────

#[cfg(target_arch = "riscv64")]
mod isa {
    #[inline(always)]
    pub fn irq_save() -> usize {
        let s: usize;
        // SIE is bit 1 of sstatus.
        unsafe { core::arch::asm!("csrrci {0}, sstatus, 2", out(reg) s, options(nostack)) };
        s
    }
    #[inline(always)]
    pub fn irq_restore(s: usize) {
        if s & 2 != 0 {
            unsafe { core::arch::asm!("csrsi sstatus, 2", options(nostack)) };
        }
    }
    #[inline(always)]
    pub fn cpu() -> usize {
        let id: usize;
        unsafe { core::arch::asm!("mv {0}, tp", out(reg) id, options(nomem, nostack, preserves_flags)) };
        id
    }
    #[inline(always)]
    pub fn ts() -> u64 {
        let t: u64;
        if super::TS_IS_CYCLES {
            unsafe { core::arch::asm!("rdcycle {0}", out(reg) t, options(nomem, nostack)) };
        } else {
            unsafe { core::arch::asm!("rdtime {0}", out(reg) t, options(nomem, nostack)) };
        }
        t
    }
    pub fn cycles_enable() {}
    /// The runtime mask, loaded where it is tested: an `asm!` the compiler
    /// cannot hoist, so a function with two tracepoints does not keep the
    /// mask's address in a callee-saved register (which cost a save and a
    /// restore on every syscall, tracing on or off). Same as a relaxed load.
    #[inline(always)]
    pub fn mask_now() -> u32 {
        let m: u32;
        unsafe {
            core::arch::asm!(
                "1: auipc {m}, %pcrel_hi({mask})",
                "lw {m}, %pcrel_lo(1b)({m})",
                m = out(reg) m, mask = sym super::MASK,
                options(nostack, readonly, preserves_flags),
            )
        };
        m
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
mod isa {
    #[inline(always)]
    pub fn irq_save() -> usize {
        let s: usize;
        unsafe { core::arch::asm!("mrs {0}, daif", "msr daifset, #2", out(reg) s, options(nostack)) };
        s
    }
    #[inline(always)]
    pub fn irq_restore(s: usize) {
        unsafe { core::arch::asm!("msr daif, {0}", in(reg) s, options(nostack)) };
    }
    #[inline(always)]
    pub fn cpu() -> usize {
        let id: usize;
        unsafe { core::arch::asm!("mrs {0}, TPIDR_EL1", out(reg) id, options(nomem, nostack, preserves_flags)) };
        id
    }
    #[inline(always)]
    pub fn ts() -> u64 {
        let t: u64;
        if super::TS_IS_CYCLES {
            unsafe { core::arch::asm!("mrs {0}, PMCCNTR_EL0", out(reg) t, options(nomem, nostack)) };
        } else {
            unsafe { core::arch::asm!("mrs {0}, CNTVCT_EL0", out(reg) t, options(nomem, nostack)) };
        }
        t
    }
    /// Start this CPU's cycle counter: PMCR_EL0.E, PMCNTENSET_EL0.C.
    pub fn cycles_enable() {
        unsafe {
            core::arch::asm!(
                "mrs {t}, PMCR_EL0", "orr {t}, {t}, #1", "msr PMCR_EL0, {t}",
                "mov {t}, #0x80000000", "msr PMCNTENSET_EL0, {t}", "isb",
                t = out(reg) _, options(nostack),
            )
        };
    }
    /// See the riscv64 twin.
    #[inline(always)]
    pub fn mask_now() -> u32 {
        let m: u32;
        unsafe {
            core::arch::asm!(
                "adrp {a}, {mask}",
                "ldr {m:w}, [{a}, :lo12:{mask}]",
                a = out(reg) _, m = out(reg) m, mask = sym super::MASK,
                options(nostack, readonly, preserves_flags),
            )
        };
        m
    }
}

/// The host (unit tests of code that calls a tracepoint): no CPU state to
/// touch; a recording host build writes ring 0 at time 0.
#[cfg(not(any(target_arch = "riscv64", all(target_arch = "aarch64", target_os = "none"))))]
mod isa {
    pub fn irq_save() -> usize { 0 }
    pub fn irq_restore(_s: usize) {}
    pub fn cpu() -> usize { 0 }
    pub fn ts() -> u64 { 0 }
    pub fn cycles_enable() {}
    pub fn mask_now() -> u32 {
        super::MASK.0.load(core::sync::atomic::Ordering::Relaxed)
    }
}

// ── Set-up and control ──────────────────────────────────────────────────────

/// Lay the rings out in the region at kernel address `base`
/// (`azos_spsc::trace::region_bytes(ncpu, entries)` long, zeroed or not),
/// attach every CPU's producer and start recording the boot mask. Called
/// once, at boot, while only the boot CPU runs.
pub fn install(base: usize, ncpu: u32, entries: u32, ts_hz: u64) {
    if !ENABLED || ncpu == 0 || ncpu as usize > MAX_CPUS || !entries.is_power_of_two() {
        return;
    }
    let (policy, src, hz) = (
        if OVERWRITE { POLICY_OVERWRITE } else { POLICY_DROP },
        if TS_IS_CYCLES { TS_CYCLES } else { TS_TIMEBASE },
        if TS_IS_CYCLES { 0 } else { ts_hz },
    );
    region_init(base, ncpu, entries, policy, hz, src, CLASSES);
    for cpu in 0..ncpu {
        // SAFETY: no CPU records before the mask below is set, and only
        // the boot CPU runs.
        if let Some(slot) = producer(cpu as usize) {
            unsafe { *slot.0.get() = TraceProducer::attach(base, cpu, entries) };
        }
    }
    NCPU.store(ncpu, Ordering::Relaxed);
    ENTRIES.store(entries, Ordering::Relaxed);
    REGION.store(base, Ordering::Release);
    set_mask(BOOT_MASK);
}

/// Per-CPU set-up a CPU runs on itself before it can record: starts its
/// cycle counter when that is the timestamp source (aarch64).
pub fn cpu_online() {
    if ENABLED && TS_IS_CYCLES {
        isa::cycles_enable();
    }
}

/// The region's kernel address, rings and entries per ring, once installed.
pub fn region() -> Option<(usize, u32, u32)> {
    let b = REGION.load(Ordering::Acquire);
    (b != 0).then(|| (b, NCPU.load(Ordering::Relaxed), ENTRIES.load(Ordering::Relaxed)))
}

/// The runtime class mask.
pub fn mask() -> u32 {
    MASK.0.load(Ordering::Relaxed)
}

/// Set the runtime class mask (bits of classes not compiled in are
/// dropped) and return the previous one. Nothing records before
/// [`install`], whatever the mask.
pub fn set_mask(m: u32) -> u32 {
    let base = REGION.load(Ordering::Acquire);
    let m = if base == 0 { 0 } else { m & CLASSES };
    let prev = MASK.0.swap(m, Ordering::AcqRel);
    if base != 0 {
        azos_spsc::trace::TraceGeometry::set_mask(base, m, isa::ts());
    }
    prev
}

// ── The record path ─────────────────────────────────────────────────────────

/// Is `class` compiled in (`compiled`, its `KTRACE_CLASS_*`) and switched
/// on at run time? Folds to `false` with no instruction when not compiled.
#[inline(always)]
pub fn on(class: u32, compiled: bool) -> bool {
    ENABLED && compiled && isa::mask_now() & (1 << class) != 0
}

/// Write one record into this CPU's ring. Out of line, and deliberately not
/// `#[cold]`: a cold callee reshapes its hot caller. Callers test [`on`]
/// first (every tracepoint below does).
#[inline(never)]
pub fn record(event: u16, a0: u32, a1: u32, a2: u32, a3: u32) {
    let s = isa::irq_save();
    if let Some(slot) = producer(isa::cpu()) {
        // SAFETY: this CPU's own producer, with its interrupts masked.
        let p = unsafe { &mut *slot.0.get() };
        if p.is_live() {
            let ts = isa::ts();
            p.push::<OVERWRITE>(ts, event, [a0, a1, a2, a3]);
        }
    }
    isa::irq_restore(s);
}

/// The last `n` records CPU `cpu` wrote, oldest first, from the producer's
/// own view (never the reader's tail): the panic path's dump. Racy against
/// that CPU if it is still running; a record being rewritten is skipped.
pub fn for_each_recent(cpu: usize, n: u32, mut f: impl FnMut(&TraceRecord)) {
    let Some(slot) = producer(cpu) else { return };
    // SAFETY: read-only; see the doc.
    let p = unsafe { &*slot.0.get() };
    if !p.is_live() {
        return;
    }
    let head = p.head();
    let n = n.min(ENTRIES.load(Ordering::Relaxed)).min(head);
    for i in head.wrapping_sub(n)..head {
        if let Some(r) = p.peek(i) {
            f(&r);
        }
    }
}

/// `(records written, drops)` of CPU `cpu`'s ring, for statistics. Racy by
/// nature against that CPU.
pub fn cpu_stats(cpu: usize) -> (u32, u32) {
    match producer(cpu) {
        // SAFETY: read-only snapshot of two words.
        Some(slot) => unsafe {
            let p = &*slot.0.get();
            (p.head(), p.drops())
        },
        None => (0, 0),
    }
}

// ── Static keys (Kconfig `KTRACE_STATIC_KEYS`) ─────────────────────────────

/// The site emitter. `branch!(CLASS)` is one 32-bit instruction, linked as a
/// branch to the class's mask test and recorded in `.azos_keys` (see
/// [`jump`]); the fall-through (a patched nop) answers `false`.
// arch-only: patched-branch static keys exist per ISA; an ISA without them
// keeps KTRACE_STATIC_KEYS off (its default on x86_64) and tests the mask.
#[cfg(any(target_arch = "riscv64", all(target_arch = "aarch64", target_os = "none")))]
mod keys {
    #[cfg(target_arch = "riscv64")]
    macro_rules! branch {
        ($class:expr) => {{
            // SAFETY: one instruction and a table entry; the label block is
            // the mask test, correct whichever word the site holds.
            unsafe {
                core::arch::asm!(
                    // 4-byte, 4-aligned, and never relaxed to `c.j` by the
                    // linker: the patcher swaps one aligned 32-bit word. The
                    // alignment can cost a 2-byte `c.nop` of padding before
                    // the site (Linux's riscv sites pay the same).
                    ".option push",
                    ".option norelax",
                    ".option norvc",
                    ".balign 4",
                    "2: jal zero, {on}",
                    ".option pop",
                    ".pushsection .azos_keys, \"a\"",
                    ".balign 8",
                    ".8byte 2b",
                    ".8byte {on}",
                    ".4byte {class}",
                    ".4byte {kind}",
                    ".popsection",
                    on = label { return $crate::isa::mask_now() & (1 << $class) != 0; },
                    class = const $class,
                    kind = const $crate::jump::KIND_RV_JAL,
                    options(nostack),
                );
            }
            false
        }};
    }
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    macro_rules! branch {
        ($class:expr) => {{
            // SAFETY: as riscv64's.
            unsafe {
                core::arch::asm!(
                    "2: b {on}",
                    ".pushsection .azos_keys, \"a\"",
                    ".balign 8",
                    ".8byte 2b",
                    ".8byte {on}",
                    ".4byte {class}",
                    ".4byte {kind}",
                    ".popsection",
                    on = label { return $crate::isa::mask_now() & (1 << $class) != 0; },
                    class = const $class,
                    kind = const $crate::jump::KIND_A64_B,
                    options(nostack, preserves_flags),
                );
            }
            false
        }};
    }
    pub(crate) use branch;
}

/// Every static-key site the kernel links (empty on the host).
pub fn key_sites() -> &'static [jump::KeySite] {
    #[cfg(target_os = "none")]
    {
        unsafe extern "C" {
            static __azos_keys_start: jump::KeySite;
            static __azos_keys_end: jump::KeySite;
        }
        // SAFETY: the linker scripts bracket `.azos_keys` with these two
        // symbols; the section holds whole 24-byte entries.
        unsafe {
            let s = &raw const __azos_keys_start;
            let e = &raw const __azos_keys_end;
            let n = (e as usize - s as usize) / core::mem::size_of::<jump::KeySite>();
            core::slice::from_raw_parts(s, n)
        }
    }
    #[cfg(not(target_os = "none"))]
    {
        &[]
    }
}

// ── Tracepoints ─────────────────────────────────────────────────────────────

macro_rules! class_on {
    ($fn:ident, $class:expr, $kconfig:ident) => {
        /// Is this class recording now? Use before computing arguments that
        /// cost something; folds to `false` when compiled out. With
        /// `KTRACE_STATIC_KEYS` it is one patched instruction (a nop while
        /// the class is masked off, a branch to the mask test otherwise).
        #[inline(always)]
        pub fn $fn() -> bool {
            if !(ENABLED && azos_limits::$kconfig) {
                return false;
            }
            // arch-only: static keys (see `mod keys`).
            #[cfg(any(target_arch = "riscv64", all(target_arch = "aarch64", target_os = "none")))]
            if STATIC_KEYS {
                return keys::branch!($class);
            }
            on($class, true)
        }
    };
}
class_on!(sched_on, TRACE_CLASS_SCHED, KTRACE_CLASS_SCHED);
class_on!(irq_on, TRACE_CLASS_IRQ, KTRACE_CLASS_IRQ);
class_on!(syscall_on, TRACE_CLASS_SYSCALL, KTRACE_CLASS_SYSCALL);
class_on!(ipc_on, TRACE_CLASS_IPC, KTRACE_CLASS_IPC);
class_on!(fault_on, TRACE_CLASS_FAULT, KTRACE_CLASS_FAULT);
class_on!(proc_on, TRACE_CLASS_PROC, KTRACE_CLASS_PROC);
class_on!(lat_on, TRACE_CLASS_LAT, KTRACE_CLASS_LAT);

/// A context switch on this CPU.
#[inline(always)]
pub fn sched_switch(prev: u32, next: u32, prev_state: u32, reason: u32) {
    if sched_on() {
        raw::sched_switch(prev, next, prev_state, reason);
    }
}

/// A sleeping task made runnable.
#[inline(always)]
pub fn sched_wakeup(tid: u32, target_cpu: u32, waker: u32) {
    if sched_on() {
        raw::sched_wakeup(tid, target_cpu, waker);
    }
}

/// An interrupt's dispatch begins.
#[inline(always)]
pub fn irq_entry(irq: u32) {
    if irq_on() {
        raw::irq_entry(irq);
    }
}

/// An interrupt's dispatch ends.
#[inline(always)]
pub fn irq_exit(irq: u32) {
    if irq_on() {
        raw::irq_exit(irq);
    }
}

/// A syscall enters the kernel.
#[inline(always)]
pub fn sys_enter(nr: u32, tid: u32, a0: u64, a1: u64) {
    if syscall_on() {
        raw::sys_enter(nr, tid, a0, a1);
    }
}

/// A syscall returns.
#[inline(always)]
pub fn sys_exit(nr: u32, tid: u32, ret: i64) {
    if syscall_on() {
        raw::sys_exit(nr, tid, ret);
    }
}

/// A seccomp denial.
#[inline(always)]
pub fn sys_deny(nr: u32, tid: u32) {
    if syscall_on() {
        raw::sys_deny(nr, tid);
    }
}

/// A fast-IPC call.
#[inline(always)]
pub fn ipc_call(caller: u32, server: u32, label: u32) {
    if ipc_on() {
        raw::ipc_call(caller, server, label);
    }
}

/// A fast-IPC reply.
#[inline(always)]
pub fn ipc_reply(server: u32, caller: u32, status: u32) {
    if ipc_on() {
        raw::ipc_reply(server, caller, status);
    }
}

/// A page fault.
#[inline(always)]
pub fn page_fault(addr: u64, cause: u32, tid: u32) {
    if fault_on() {
        raw::page_fault(addr, cause, tid);
    }
}

/// A task created.
#[inline(always)]
pub fn proc_spawn(child: u32, parent: u32) {
    if proc_on() {
        raw::proc_spawn(child, parent);
    }
}

/// A task exits.
#[inline(always)]
pub fn proc_exit(tid: u32, code: i32) {
    if proc_on() {
        raw::proc_exit(tid, code);
    }
}

/// A signal delivered to a Linux task (action 0 discarded, 1 handler,
/// 2 terminated).
#[inline(always)]
pub fn proc_signal(tid: u32, signo: u32, sender: u32, action: u32) {
    if proc_on() {
        raw::proc_signal(tid, signo, sender, action);
    }
}

/// A new longest masked window on this CPU (`LAT_TRACE`): `preempt` false
/// for interrupts masked, true for preemption disabled.
#[inline(always)]
pub fn lat_window(preempt: bool, ticks: u64, open_site: usize, close_site: usize) {
    if lat_on() {
        raw::lat_window(preempt, ticks, open_site, close_site);
    }
}

/// An interrupt's dispatch as a scope: the entry record now, the exit
/// record when dropped (a handler with several returns).
pub struct IrqScope(u32);

impl IrqScope {
    /// Record the entry of interrupt `irq`.
    #[inline(always)]
    pub fn enter(irq: u32) -> IrqScope {
        irq_entry(irq);
        IrqScope(irq)
    }
}

impl Drop for IrqScope {
    #[inline(always)]
    fn drop(&mut self) {
        irq_exit(self.0);
    }
}


/// The tracepoints without their class test, for a call site that has
/// already asked `*_on()` (because computing an argument costs something)
/// and must not pay the mask load twice.
pub mod raw {
    use super::*;

    /// A context switch on this CPU.
    #[inline(always)]
    pub fn sched_switch(prev: u32, next: u32, prev_state: u32, reason: u32) {
        record(TRACE_EV_SCHED_SWITCH, prev, next, prev_state, reason);
    }

    /// A sleeping task made runnable.
    #[inline(always)]
    pub fn sched_wakeup(tid: u32, target_cpu: u32, waker: u32) {
        record(TRACE_EV_SCHED_WAKEUP, tid, target_cpu, waker, 0);
    }

    /// An interrupt's dispatch begins.
    #[inline(always)]
    pub fn irq_entry(irq: u32) {
        record(TRACE_EV_IRQ_ENTRY, irq, 0, 0, 0);
    }

    /// An interrupt's dispatch ends.
    #[inline(always)]
    pub fn irq_exit(irq: u32) {
        record(TRACE_EV_IRQ_EXIT, irq, 0, 0, 0);
    }

    /// A syscall enters the kernel.
    #[inline(always)]
    pub fn sys_enter(nr: u32, tid: u32, a0: u64, a1: u64) {
        record(TRACE_EV_SYS_ENTER, nr, tid, a0 as u32, a1 as u32);
    }

    /// A syscall returns.
    #[inline(always)]
    pub fn sys_exit(nr: u32, tid: u32, ret: i64) {
        record(TRACE_EV_SYS_EXIT, nr, tid, ret as u32, (ret >> 32) as u32);
    }

    /// A seccomp denial.
    #[inline(always)]
    pub fn sys_deny(nr: u32, tid: u32) {
        record(TRACE_EV_SYS_DENY, nr, tid, 0, 0);
    }

    /// A fast-IPC call.
    #[inline(always)]
    pub fn ipc_call(caller: u32, server: u32, label: u32) {
        record(TRACE_EV_IPC_CALL, caller, server, label, 0);
    }

    /// A fast-IPC reply.
    #[inline(always)]
    pub fn ipc_reply(server: u32, caller: u32, status: u32) {
        record(TRACE_EV_IPC_REPLY, server, caller, status, 0);
    }

    /// A page fault.
    #[inline(always)]
    pub fn page_fault(addr: u64, cause: u32, tid: u32) {
        record(TRACE_EV_PAGE_FAULT, addr as u32, (addr >> 32) as u32, cause, tid);
    }

    /// A task created.
    #[inline(always)]
    pub fn proc_spawn(child: u32, parent: u32) {
        record(TRACE_EV_PROC_SPAWN, child, parent, 0, 0);
    }

    /// A task exits.
    #[inline(always)]
    pub fn proc_exit(tid: u32, code: i32) {
        record(TRACE_EV_PROC_EXIT, tid, code as u32, 0, 0);
    }

    /// A signal delivered to a Linux task (action 0 discarded, 1 handler,
    /// 2 terminated).
    #[inline(always)]
    pub fn proc_signal(tid: u32, signo: u32, sender: u32, action: u32) {
        record(TRACE_EV_PROC_SIGNAL, tid, signo, sender, action);
    }

    /// A new longest masked window on this CPU (`LAT_TRACE`): `preempt` false
    /// for interrupts masked, true for preemption disabled.
    #[inline(always)]
    pub fn lat_window(preempt: bool, ticks: u64, open_site: usize, close_site: usize) {
        let ev = if preempt { TRACE_EV_LAT_PREEMPTOFF } else { TRACE_EV_LAT_IRQSOFF };
        record(ev, ticks as u32, (ticks >> 32) as u32, open_site as u32, close_site as u32);
    }
}
