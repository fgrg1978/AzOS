// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RFC-0047 stage 3: the riscv64 floating-point state of Linux tasks.
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

/// A new task in slot `idx` has not used the FP file.
pub fn reset(idx: usize) {
    if idx < MAX_TASKS {
        USED[idx].store(false, Ordering::Relaxed);
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        TLS[idx].store(0, Ordering::Relaxed);
        // x86_64: a Linux task's thread pointer is its FS base.
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        TLS[idx].store(0, Ordering::Relaxed);
    }
}

/// aarch64: each Linux task's `TPIDR_EL0` (musl's thread pointer). EL1 never
/// writes it and a native image never uses it, but a spawned task's entry
/// writes it (0), so a Linux task's value is kept per slot across switches.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
static TLS: [core::sync::atomic::AtomicU64; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; MAX_TASKS];
/// x86_64: each Linux task's FS base (musl's thread pointer),
/// kept per slot like aarch64's `TPIDR_EL0` above.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static TLS: [core::sync::atomic::AtomicU64; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; MAX_TASKS];

/// Save `prev`'s file and load `next`'s, for the slots that use it. Called by
/// `set_current_task` on the switching hart before the switch, and only when
/// `prev` or `next` is a Linux task (its filter word is 0); the kernel itself
/// never touches the FP file in between. On aarch64 it carries a Linux
/// task's `TPIDR_EL0` instead (the FP/SIMD file is the kernel's own lazy
/// switch there). Out of line on purpose: its two 32-register blocks inlined
/// into `do_schedule` cost every native switch (+90 on `switch-loaded`).
#[inline(never)]
pub fn switch_slow(prev: usize, next: usize) {
    // Gate canary only (`linux-abi-fp-canary`): nothing follows the task.
    if cfg!(feature = "linux-abi-fp-canary") {
        return;
    }
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    if azos_limits::LINUX_ABI && prev != next {
        if prev < MAX_TASKS && crate::scheduler::slot_is_linux(prev) {
            let v: u64;
            // SAFETY: reading this hart's EL0 thread pointer.
            unsafe { core::arch::asm!("mrs {0}, TPIDR_EL0", out(reg) v) };
            TLS[prev].store(v, Ordering::Relaxed);
        }
        if next < MAX_TASKS && crate::scheduler::slot_is_linux(next) {
            let v = TLS[next].load(Ordering::Relaxed);
            // SAFETY: EL1 writes the incoming task's EL0 thread pointer; the
            // kernel itself does not use TPIDR_EL0.
            unsafe { core::arch::asm!("msr TPIDR_EL0, {0}", in(reg) v) };
        }
    }
    // x86_64: a Linux task's thread pointer is its FS base (musl's TLS),
    // per CPU in IA32_FS_BASE: saved and loaded like TPIDR_EL0 above
    // (`rdfsbase`/`wrfsbase` once X86_FSGSBASE is wired). Its FP/SIMD file
    // is the ISA's FPU path's (kernel/src/entry/x86_64/fp.rs), not here.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    if azos_limits::LINUX_ABI && prev != next {
        use azos_arch::{cpu::IA32_FS_BASE, hw};
        if prev < MAX_TASKS && crate::scheduler::slot_is_linux(prev) {
            TLS[prev].store(hw::rdmsr(IA32_FS_BASE), Ordering::Relaxed);
        }
        if next < MAX_TASKS && crate::scheduler::slot_is_linux(next) {
            hw::wrmsr(IA32_FS_BASE, TLS[next].load(Ordering::Relaxed));
        }
    }
    if !azos_limits::LINUX_ABI || !cfg!(all(target_arch = "riscv64", target_os = "none")) {
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
    if *sstatus as usize & SSTATUS_FS_MASK != 0 || !crate::scheduler::current_is_linux() {
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

/// The current task execs a new image: it starts without FP state.
pub fn exec_reset() {
    if let Some(me) = crate::scheduler::current_slot() {
        USED[me].store(false, Ordering::Relaxed);
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
