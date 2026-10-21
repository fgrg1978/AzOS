// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Child module of `scheduler.rs` (pulled in with `#[path]`), moved out of it unchanged.

use super::*;
pub const DISPATCH: u8 = 1;
pub const RESUME: u8 = 2;
pub const REAP: u8 = 3;
pub const DIRECT: u8 = 4;
pub const ENTRY: u8 = 5;
pub const TAIL: u8 = 6;

#[inline(always)]
pub fn sp_now() -> usize {
    let sp: usize;
    #[cfg(target_arch = "riscv64")]
    unsafe { core::arch::asm!("mv {}, sp", out(reg) sp) };
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("mov {}, sp", out(reg) sp) };
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
    { sp = 0; }
    sp
}

/// The CPU the trap entry would name (riscv64: the word under this hart's
/// `stvec` slot). `usize::MAX` where the ISA gives no independent answer.
pub fn true_hart() -> usize {
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        let v: usize;
        unsafe { core::arch::asm!("csrr {}, stvec", out(reg) v) };
        let w = unsafe { core::ptr::read_volatile((v - 4) as *const i32) };
        w as usize
    }
    #[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
    { usize::MAX }
}

/// The task slot whose kernel stack holds `sp`, or `usize::MAX`.
pub fn stack_slot_of(sp: usize) -> usize {
    let base = core::ptr::addr_of!(TASK_STACKS) as usize;
    if sp <= base || sp > base + STACK_SIZE * MAX_TASKS { return usize::MAX; }
    (sp - 1 - base) / STACK_SIZE
}

#[cold]
#[inline(never)]
pub fn fail(site: u8, cpu: usize, idx: usize, other: usize, what: &str, val: usize) -> ! {
    static FIRST: AtomicBool = AtomicBool::new(false);
    if FIRST.swap(true, Ordering::AcqRel) {
        loop { core::hint::spin_loop(); }
    }
    let name = |i: usize| -> &'static str {
        if i >= MAX_TASKS { return "-"; }
        let t = unsafe { task_ref(i) };
        let n = t.name.iter().position(|&b| b == 0).unwrap_or(TASK_NAME_MAX_LEN);
        core::str::from_utf8(&t.name[..n]).unwrap_or("?")
    };
    let (tid, st, rs, ra, ssp) = if idx < MAX_TASKS {
        let t = unsafe { task_ref(idx) };
        (t.tid, t.state() as u32, t.ready_site.load(Ordering::Relaxed),
         t.context.ra as usize, t.context.sp as usize)
    } else { (0, 0, 0, 0, 0) };
    let otid = if other < MAX_TASKS { unsafe { task_ref(other).tid } } else { 0 };
    azos_drv_sys::uart::console_bypass_for_halt();
    azos_drv_sys::kerr!(
        "[CTXPROBE] site={} cpu={} slot={} tid={} ({}) state={} ready_site={:#x} saved ra={:#x} sp={:#x}; other slot={} tid={} ({}); {}={:#x}",
        site, cpu, idx, tid, name(idx), st, rs, ra, ssp, other, otid, name(other), what, val);
    panic!("ctx-probe");
}

/// `idx` is current on `cpu`: on no other hart.
pub fn check_unique(site: u8, cpu: usize, idx: usize) {
    for c in 0..ncpu() {
        if c != cpu && unsafe { PER_CPU[c].current_idx.load(Ordering::Acquire) } == idx {
            fail(site, cpu, idx, usize::MAX, "also_current_on_cpu", c);
        }
    }
}

/// Before a switch to `next_idx` on `cpu`.
pub fn check_dispatch(site: u8, cpu: usize, next_idx: usize) {
    if next_idx >= MAX_TASKS { return; }
    let t = unsafe { task_ref(next_idx) };
    if !unsafe { TASK_VALID[next_idx].load(Ordering::Acquire) } {
        fail(site, cpu, next_idx, usize::MAX, "invalid_slot", 0);
    }
    let sp = t.context.sp as usize;
    let owner = stack_slot_of(sp);
    if owner != next_idx && owner != usize::MAX {
        fail(site, cpu, next_idx, owner, "saved_sp_on_other_stack", sp);
    }
    if t.context.ra == 0 {
        fail(site, cpu, next_idx, usize::MAX, "saved_ra_zero", 0);
    }
    check_unique(site, cpu, next_idx);
}

/// Code running on this hart: `tp` names it, `sp` is the current task's.
pub fn check_running(site: u8) {
    // percpu-hint: gate probe, called from do_schedule and the resume path with interrupts off
    let cpu = current_cpu_id();
    if cpu >= MAX_CPUS { return; }
    let idx = unsafe { PER_CPU[cpu].current_idx.load(Ordering::Relaxed) };
    let th = true_hart();
    if th != usize::MAX && th != cpu {
        fail(site, cpu, idx, usize::MAX, "tp_is_not_this_hart_which_is", th);
    }
    let owner = stack_slot_of(sp_now());
    if idx < MAX_TASKS && owner != usize::MAX && owner != idx {
        fail(site, cpu, idx, owner, "running_on_other_stack", sp_now());
    }
    if idx < MAX_TASKS {
        check_unique(site, cpu, idx);
    }
}

/// `idx` is about to be freed by `cpu`: nobody runs on it.
pub fn check_reap(cpu: usize, idx: usize) {
    if stack_slot_of(sp_now()) == idx {
        fail(REAP, cpu, idx, idx, "reaping_own_stack", sp_now());
    }
    for c in 0..ncpu() {
        if unsafe { PER_CPU[c].current_idx.load(Ordering::Acquire) } == idx {
            fail(REAP, cpu, idx, usize::MAX, "reaping_current_of_cpu", c);
        }
    }
}
