// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The riscv64 floating-point state of Linux tasks.
//!
//! The kernel and every native image are `rv64imac`: none touches `f0..f31`,
//! and a native task runs with `sstatus.FS = Off`. A Linux image is usually
//! `rv64gc`/`lp64d` (musl's `setjmp` alone saves `fs0..fs11`), so a Linux
//! task gets the F/D file on first use:
//!
//! - Its first FP instruction traps (illegal instruction, `FS = Off` in the
//!   frame). [`first_use`] marks the slot, zeroes the register file, sets
//!   `FS = Clean` in the frame and the instruction is retried.
//! - From then on [`switch`] (called by `set_current_task`, the one place a
//!   hart changes task) saves the outgoing task's file and loads the
//!   incoming one's, only for slots so marked. A native task pays two loads
//!   of a flag per switch, and only with Kconfig `LINUX_ABI`.
//! - A fork child inherits the parent's live file ([`fork_copy`]); an exec
//!   starts clean ([`exec_reset`]).
//!
//! aarch64 needs none of this: its kernel saves the FP/SIMD file of every
//! task already.
//!
//! Every task's thread pointer is its own on every ISA
//! ([`switch_thread_pointer`], also called by `set_current_task`): riscv64
//! `tp` (a general register every trap frame saves), aarch64 `TPIDR_EL0` and
//! x86_64 FS base (kept per slot here).

use core::sync::atomic::{AtomicBool, Ordering};
use crate::task::MAX_TASKS;

/// `f0..f31` then `fcsr`.
#[repr(C, align(8))]
struct FpArea([u64; 33]);

static mut AREA: [FpArea; MAX_TASKS] = [const { FpArea([0; 33]) }; MAX_TASKS];
static USED: [AtomicBool; MAX_TASKS] = [const { AtomicBool::new(false) }; MAX_TASKS];

/// `sstatus.FS = Clean`.
pub const SSTATUS_FS_CLEAN: usize = 2 << 13;
/// The `sstatus.FS` field.
pub const SSTATUS_FS_MASK: usize = 3 << 13;

/// Does this build have tasks whose per-thread CPU state the out-of-line
/// path moves ([`switch_slow`])? Only a Linux task's riscv64 F/D file (Kconfig
/// `LINUX_ABI`); on the other ISAs `set_current_task` compiles none of it.
pub const SWITCH_STATE: bool = azos_limits::LINUX_ABI && cfg!(all(target_arch = "riscv64", target_os = "none"));

/// A new task in slot `idx` has not used the FP file, and has no thread
/// pointer: its first switch in loads 0 ([`switch_thread_pointer`]), never
/// the value the hart's previous task left.
pub fn reset(idx: usize) {
    if idx < MAX_TASKS {
        USED[idx].store(false, Ordering::Relaxed);
        #[cfg(all(target_os = "none", not(target_arch = "riscv64")))]
        TLS[idx].store(0, Ordering::Relaxed);
    }
}

/// aarch64: each task's `TPIDR_EL0` (relibc's and musl's thread pointer, a
/// Linux class server's Linux `current`), saved when it leaves a hart. EL0
/// writes the register itself, so the value is read back at every switch
/// away ([`switch_thread_pointer`]).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
static TLS: [core::sync::atomic::AtomicU64; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; MAX_TASKS];
/// x86_64: each task's FS base (its thread pointer: musl's TLS for a Linux
/// task, `SYS_THREAD_CREATE`'s `tls` for a native thread), kept per slot.
/// Only the kernel writes the MSR (see [`set_fs_base`]), so this is the value
/// a task has whenever it is switched away.
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
static TLS: [core::sync::atomic::AtomicU64; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; MAX_TASKS];

/// riscv64: save `prev`'s F/D file and load `next`'s, for the slots that use
/// it. Called by `set_current_task` on the switching hart before the switch,
/// and only when `prev` or `next` is a Linux task (its slot's switch flag is
/// set, [`SWITCH_STATE`]); the kernel itself never touches the FP file in
/// between. The other ISAs have nothing here: aarch64's FP/SIMD file is the
/// kernel's own lazy switch, x86_64's is the XSAVE switch. Out of line on
/// purpose: its two 32-register blocks inlined into `do_schedule` cost every
/// native switch (+90 on `switch-loaded`).
#[inline(never)]
pub fn switch_slow(prev: usize, next: usize) {
    // Gate canary only (`linux-abi-fp-canary`): nothing follows the task.
    if cfg!(feature = "linux-abi-fp-canary") || !SWITCH_STATE {
        return;
    }
    if prev < MAX_TASKS && prev != next && USED[prev].load(Ordering::Relaxed) {
        // SAFETY: the area of the slot this hart is leaving, written only
        // here and by `fork_copy` (for a child not yet runnable).
        unsafe { save(core::ptr::addr_of_mut!(AREA[prev]) as *mut u64) }
    }
    if next < MAX_TASKS && prev != next && USED[next].load(Ordering::Relaxed) {
        // SAFETY: the incoming slot's area, saved when it last left a hart.
        unsafe { load(core::ptr::addr_of!(AREA[next]) as *const u64) }
    }
}

/// An illegal-instruction trap from user mode with `FS = Off` in `sstatus`
/// (the frame's): if the current task is a Linux task, give it the FP file
/// and answer `true` (retry the instruction). `false`: a real illegal
/// instruction, or a native task.
pub fn first_use(sstatus: &mut u64) -> bool {
    if !azos_limits::LINUX_ABI || !cfg!(all(target_arch = "riscv64", target_os = "none")) {
        return false;
    }
    if *sstatus as usize & SSTATUS_FS_MASK != 0 || !crate::scheduler::current_is_foreign() {
        return false;
    }
    let Some(idx) = crate::scheduler::current_slot() else { return false };
    if !USED[idx].swap(true, Ordering::Relaxed) {
        // SAFETY: the live file, owned by the current task from now on.
        unsafe { zero() }
    }
    *sstatus |= SSTATUS_FS_CLEAN as u64;
    true
}

/// The current task forks child slot `child`: the child starts with the
/// parent's live file (Linux semantics), not yet runnable.
pub fn fork_copy(child: usize) {
    if !azos_limits::LINUX_ABI || !cfg!(all(target_arch = "riscv64", target_os = "none")) {
        return;
    }
    let Some(me) = crate::scheduler::current_slot() else { return };
    if child < MAX_TASKS && USED[me].load(Ordering::Relaxed) {
        // SAFETY: the child is parked before its hand-off; its area is not
        // read until it is first switched to.
        unsafe { save(core::ptr::addr_of_mut!(AREA[child]) as *mut u64) }
        USED[child].store(true, Ordering::Relaxed);
    }
}

/// Wave 13: the current Linux task's live F/D file, for its signal frame;
/// `None` when it has not used the file (riscv64 only).
pub fn frame_save() -> Option<[u64; 33]> {
    if !azos_limits::LINUX_ABI || !cfg!(all(target_arch = "riscv64", target_os = "none")) {
        return None;
    }
    let idx = crate::scheduler::current_slot()?;
    if !USED[idx].load(Ordering::Relaxed) {
        return None;
    }
    let mut a = [0u64; 33];
    // SAFETY: the current task's live file (it is loaded on every switch to
    // a slot that uses it), copied out.
    unsafe { save(a.as_mut_ptr()) }
    Some(a)
}

/// Wave 13: `rt_sigreturn` puts back the F/D file a signal frame saved, for a
/// task that uses the file (riscv64 only; anything else is ignored).
pub fn frame_load(a: &[u64; 33]) {
    if !azos_limits::LINUX_ABI || !cfg!(all(target_arch = "riscv64", target_os = "none")) {
        return;
    }
    let Some(idx) = crate::scheduler::current_slot() else { return };
    if USED[idx].load(Ordering::Relaxed) {
        // SAFETY: the current task's live file, replaced in place; the next
        // switch away saves it as usual.
        unsafe { load(a.as_ptr()) }
    }
}

#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
static CUR_FS: [core::sync::atomic::AtomicU64; crate::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; crate::MAX_CPUS];

/// CPU `cpu` stops running slot `prev` and starts `next`: the thread pointer
/// becomes `next`'s. Called by `set_current_task` for EVERY switch, native or
/// Linux, kernel task or not, because every task can have one (relibc's and
/// musl's TLS, `SYS_THREAD_CREATE`'s `tls`, a Linux class server's
/// `current`). A new slot's is 0 ([`reset`]), so no task starts with the
/// one its hart's previous task left. The caller has interrupts off.
///
/// x86_64: the FS base. Ring 3 cannot change it (CR4.FSGSBASE is off and no
/// call sets it), so nothing is read back from the MSR: the per-slot value
/// is the task's, and `CUR_FS` is what this CPU's MSR holds. The MSR is
/// written only when the two differ (`azos_arch::cpu::fs_base_to_load`).
/// The user GS base is 0 for every task (`x86_64_enter_user`, and a fork
/// child takes its parent's), so nothing is kept for it.
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
#[inline]
pub fn switch_thread_pointer(cpu: usize, _prev: usize, next: usize) {
    if next >= MAX_TASKS || cpu >= crate::MAX_CPUS {
        return;
    }
    let want = TLS[next].load(Ordering::Relaxed);
    if let Some(b) = azos_arch::cpu::fs_base_to_load(CUR_FS[cpu].load(Ordering::Relaxed), want) {
        azos_arch::cpu::wrmsr(azos_arch::cpu::IA32_FS_BASE, b);
        CUR_FS[cpu].store(b, Ordering::Relaxed);
    }
}
/// aarch64: `TPIDR_EL0`. EL0 writes it without a call (relibc's
/// `activate_tls`, a thread's start shim, musl), so unlike x86_64's FS base
/// it is read back from the register as `prev` leaves (`mrs`, a store) and
/// `next`'s is written (a load, `msr`): four instructions on every switch.
/// The kernel itself never uses `TPIDR_EL0` (its hart id is `TPIDR_EL1`).
/// Gate canaries: `tpidr-foreign-only-canary` keeps it only for a Linux
/// task, the old rule (ktests `native_tasks_keep_tpidr_el0` and
/// `new_task_starts_with_tpidr_el0_zero` are `not ok`);
/// `linux-abi-fp-canary` keeps it for every task but a Linux one.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[inline]
pub fn switch_thread_pointer(_cpu: usize, prev: usize, next: usize) {
    let keeps = |idx: usize| {
        if cfg!(feature = "linux-abi-fp-canary") {
            !crate::scheduler::slot_is_foreign(idx)
        } else if cfg!(feature = "tpidr-foreign-only-canary") {
            crate::scheduler::slot_is_foreign(idx)
        } else {
            true
        }
    };
    if prev < MAX_TASKS && keeps(prev) {
        let v: u64;
        // SAFETY: reading this hart's EL0 thread pointer, the outgoing
        // task's.
        unsafe { core::arch::asm!("mrs {0}, TPIDR_EL0", out(reg) v, options(nomem, nostack, preserves_flags)) };
        TLS[prev].store(v, Ordering::Relaxed);
    }
    if next < MAX_TASKS && keeps(next) {
        let v = TLS[next].load(Ordering::Relaxed);
        // SAFETY: EL1 writes the incoming task's EL0 thread pointer; the
        // kernel itself does not use TPIDR_EL0.
        unsafe { core::arch::asm!("msr TPIDR_EL0, {0}", in(reg) v, options(nomem, nostack, preserves_flags)) };
    }
}
/// riscv64: nothing. The thread pointer is `tp`, a general register that
/// every trap frame saves and restores and every syscall preserves
/// (`azos_abi::syscall_nr`), so it is the task's own already; a new task's
/// first entry zeroes it with the rest. A host build has no thread pointer
/// to switch.
#[cfg(any(target_arch = "riscv64", not(target_os = "none")))]
#[inline(always)]
pub fn switch_thread_pointer(_cpu: usize, _prev: usize, _next: usize) {}

/// x86_64: the current task's FS base becomes `base` now (the one writer of
/// the MSR besides [`switch_thread_pointer`]): a task's first entry to ring 3 and an
/// exec. The slot's value, this CPU's cache and the MSR change together with
/// interrupts off, so no switch sees them apart.
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
pub fn set_fs_base(base: u64) {
    use azos_arch::Interrupts;
    let irq = azos_arch::ARCH.disable_all();
    if let Some(me) = crate::scheduler::current_slot() {
        TLS[me].store(base, Ordering::Relaxed);
    }
    azos_arch::cpu::wrmsr(azos_arch::cpu::IA32_FS_BASE, base);
    CUR_FS[crate::smp::current_cpu_id()].store(base, Ordering::Relaxed);
    azos_arch::ARCH.restore(irq);
}

/// The current task execs a new image: it starts without FP state, and
/// (aarch64 `TPIDR_EL0`, x86_64 FS base) without a thread pointer, as Linux
/// starts it (arm64 `tls_thread_flush`, x86_64 `start_thread_common`). The
/// old image's pointer used to ride into the new one. riscv64's is `tp`, a
/// general-purpose register the exec hand-off zeroes with the rest. Gate
/// canary `exec-regs-canary`: the pointer is kept.
pub fn exec_reset() {
    if let Some(me) = crate::scheduler::current_slot() {
        USED[me].store(false, Ordering::Relaxed);
        if cfg!(feature = "exec-regs-canary") {
            return;
        }
        // The register only: the slot's copy is written as the task
        // leaves the hart ([`switch_thread_pointer`]).
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        // SAFETY: EL1 clears this task's EL0 thread pointer; the kernel
        // itself does not use TPIDR_EL0.
        unsafe { core::arch::asm!("msr TPIDR_EL0, xzr") };
        #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
        set_fs_base(0);
    }
}

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
unsafe fn save(a: *mut u64) {
    unsafe {
        core::arch::asm!(
        ".option push",
        ".option arch, +d",
        "csrr {t}, sstatus",
        "li {m}, 0x6000",
        "or {u}, {t}, {m}",
        "csrw sstatus, {u}",
        "fsd f0, 0({a})",
        "fsd f1, 8({a})",
        "fsd f2, 16({a})",
        "fsd f3, 24({a})",
        "fsd f4, 32({a})",
        "fsd f5, 40({a})",
        "fsd f6, 48({a})",
        "fsd f7, 56({a})",
        "fsd f8, 64({a})",
        "fsd f9, 72({a})",
        "fsd f10, 80({a})",
        "fsd f11, 88({a})",
        "fsd f12, 96({a})",
        "fsd f13, 104({a})",
        "fsd f14, 112({a})",
        "fsd f15, 120({a})",
        "fsd f16, 128({a})",
        "fsd f17, 136({a})",
        "fsd f18, 144({a})",
        "fsd f19, 152({a})",
        "fsd f20, 160({a})",
        "fsd f21, 168({a})",
        "fsd f22, 176({a})",
        "fsd f23, 184({a})",
        "fsd f24, 192({a})",
        "fsd f25, 200({a})",
        "fsd f26, 208({a})",
        "fsd f27, 216({a})",
        "fsd f28, 224({a})",
        "fsd f29, 232({a})",
        "fsd f30, 240({a})",
        "fsd f31, 248({a})",
        "frcsr {u}",
        "sd {u}, 256({a})",
        "csrw sstatus, {t}",
        ".option pop",
        a = in(reg) a, t = out(reg) _, m = out(reg) _, u = out(reg) _,
        );
    }
}

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
unsafe fn load(a: *const u64) {
    unsafe {
        core::arch::asm!(
        ".option push",
        ".option arch, +d",
        "csrr {t}, sstatus",
        "li {m}, 0x6000",
        "or {u}, {t}, {m}",
        "csrw sstatus, {u}",
        "fld f0, 0({a})",
        "fld f1, 8({a})",
        "fld f2, 16({a})",
        "fld f3, 24({a})",
        "fld f4, 32({a})",
        "fld f5, 40({a})",
        "fld f6, 48({a})",
        "fld f7, 56({a})",
        "fld f8, 64({a})",
        "fld f9, 72({a})",
        "fld f10, 80({a})",
        "fld f11, 88({a})",
        "fld f12, 96({a})",
        "fld f13, 104({a})",
        "fld f14, 112({a})",
        "fld f15, 120({a})",
        "fld f16, 128({a})",
        "fld f17, 136({a})",
        "fld f18, 144({a})",
        "fld f19, 152({a})",
        "fld f20, 160({a})",
        "fld f21, 168({a})",
        "fld f22, 176({a})",
        "fld f23, 184({a})",
        "fld f24, 192({a})",
        "fld f25, 200({a})",
        "fld f26, 208({a})",
        "fld f27, 216({a})",
        "fld f28, 224({a})",
        "fld f29, 232({a})",
        "fld f30, 240({a})",
        "fld f31, 248({a})",
        "ld {u}, 256({a})",
        "fscsr {u}",
        "csrw sstatus, {t}",
        ".option pop",
        a = in(reg) a, t = out(reg) _, m = out(reg) _, u = out(reg) _,
        );
    }
}

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
unsafe fn zero() {
    unsafe {
        core::arch::asm!(
        ".option push",
        ".option arch, +d",
        "csrr {t}, sstatus",
        "li {m}, 0x6000",
        "or {u}, {t}, {m}",
        "csrw sstatus, {u}",
        "fmv.d.x f0, zero",
        "fmv.d.x f1, zero",
        "fmv.d.x f2, zero",
        "fmv.d.x f3, zero",
        "fmv.d.x f4, zero",
        "fmv.d.x f5, zero",
        "fmv.d.x f6, zero",
        "fmv.d.x f7, zero",
        "fmv.d.x f8, zero",
        "fmv.d.x f9, zero",
        "fmv.d.x f10, zero",
        "fmv.d.x f11, zero",
        "fmv.d.x f12, zero",
        "fmv.d.x f13, zero",
        "fmv.d.x f14, zero",
        "fmv.d.x f15, zero",
        "fmv.d.x f16, zero",
        "fmv.d.x f17, zero",
        "fmv.d.x f18, zero",
        "fmv.d.x f19, zero",
        "fmv.d.x f20, zero",
        "fmv.d.x f21, zero",
        "fmv.d.x f22, zero",
        "fmv.d.x f23, zero",
        "fmv.d.x f24, zero",
        "fmv.d.x f25, zero",
        "fmv.d.x f26, zero",
        "fmv.d.x f27, zero",
        "fmv.d.x f28, zero",
        "fmv.d.x f29, zero",
        "fmv.d.x f30, zero",
        "fmv.d.x f31, zero",
        "fscsr zero",
        "csrw sstatus, {t}",
        ".option pop",
        t = out(reg) _, m = out(reg) _, u = out(reg) _,
        );
    }
}

#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
unsafe fn save(_a: *mut u64) {}
#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
unsafe fn load(_a: *const u64) {}
#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
unsafe fn zero() {}
