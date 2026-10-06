// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SWITCH_CENSUS` (Kconfig; cargo `switch-census`, wave 15): where the
//! instructions of a yield that switches go, phase by phase. Off by default;
//! every hook compiles to nothing without the feature, so the census-off cost
//! is zero.
//!
//! The clock is the core's own counter: `rdcycle` on riscv64, `cntvct_el0`
//! (scaled to ns at the dump) on aarch64. Under QEMU `-icount shift=0` both count guest
//! instructions exactly, so every figure is an instruction count. Each
//! boundary costs the census itself a few instructions (a counter read and
//! plain loads/stores), charged to the phase that ends there.
//!
//! Phases, in the order a yield that switches runs them:
//!
//! - `trap`: the previous syscall's return to user mode, user mode, and this
//!   syscall's trap entry (`ecall_exit` to `ecall_enter`);
//! - `entry`: the syscall handler's entry to `yield_as` (dispatch, filter);
//! - `pick`: `yield_as` entry to a picked task (dequeue);
//! - `req`: re-queueing the outgoing task;
//! - `gate`: the next task's context-saving gate;
//! - `acct`: state, accounting and hooks up to the `context_switch` call;
//! - `asm`: `context_switch` itself (registers, address space), to its return
//!   in the next task;
//! - `post`: back in the next task, to the end of the syscall handler.
//!
//! A dump is printed by `SYS_TASKINFO` when at least
//! `SWITCH_CENSUS_DUMP_MIN` (Kconfig) switches happened since the previous
//! `SYS_TASKINFO` from any task: in vsbench's `switch-loaded`, that is
//! exactly the measured window. Meaningful at `-smp 1` (one set of globals
//! for all harts).

#[cfg(feature = "switch-census")]
mod imp {
    use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

    const TRAP: usize = 0;
    const ENTRY: usize = 1;
    const PICK: usize = 2;
    const REQ: usize = 3;
    const GATE: usize = 4;
    const ACCT: usize = 5;
    const ASM: usize = 6;
    const POST: usize = 7;
    const N: usize = 8;
    const NAMES: [&str; N] = ["trap", "entry", "pick", "req", "gate", "acct", "asm", "post"];

    // States of the one path being followed.
    const NONE: u64 = 0;
    const ECALL: u64 = 1;
    const YIELD: u64 = 2;
    const SWITCHING: u64 = 3;
    const SWITCHED: u64 = 4;
    const RETURNED: u64 = 5;

    static ACC: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
    static HITS: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
    static SWITCHES: AtomicU64 = AtomicU64::new(0);
    static SW_EPOCH: AtomicU64 = AtomicU64::new(0);
    static YIELDS: AtomicU64 = AtomicU64::new(0);
    /// Switches into each task slot (first 64 slots) since the last dump.
    static INTO: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
    static LAST: AtomicU64 = AtomicU64::new(0);
    static STATE: AtomicU64 = AtomicU64::new(NONE);

    /// Least switches since the last dump that make one worth printing.
    const DUMP_MIN: u64 = azos_limits::SWITCH_CENSUS_DUMP_MIN as u64;

    #[inline(always)]
    fn now() -> u64 {
        #[cfg(target_arch = "riscv64")]
        {
            let c: u64;
            unsafe { core::arch::asm!("rdcycle {}", out(reg) c, options(nomem, nostack)) };
            c
        }
        #[cfg(target_arch = "aarch64")]
        {
            // Raw ticks; `dump_window` scales them by CNTFRQ_EL0 once.
            let c: u64;
            unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) c, options(nomem, nostack)) };
            c
        }
        #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
        { 0 }
    }

    #[inline(always)]
    fn add(a: &AtomicU64, v: u64) { a.store(a.load(Relaxed).wrapping_add(v), Relaxed); }

    /// Charge the time since the previous boundary to `phase` when the path
    /// was in state `from`, then move to state `to`.
    #[inline(always)]
    fn step(from: u64, phase: usize, to: u64) {
        let t = now();
        if STATE.load(Relaxed) == from {
            add(&ACC[phase], t.wrapping_sub(LAST.load(Relaxed)));
            add(&HITS[phase], 1);
            STATE.store(to, Relaxed);
        } else {
            STATE.store(if to == YIELD || to == ECALL { to } else { NONE }, Relaxed);
        }
        LAST.store(now(), Relaxed);
    }

    pub fn ecall_enter() { step(RETURNED, TRAP, ECALL); }
    pub fn yield_enter() {
        add(&YIELDS, 1);
        step(ECALL, ENTRY, YIELD);
    }
    pub fn picked() { step(YIELD, PICK, YIELD); }
    pub fn requeued() { step(YIELD, REQ, YIELD); }
    pub fn gated() { step(YIELD, GATE, YIELD); }
    pub fn before_switch(next_idx: usize) {
        add(&SWITCHES, 1);
        if next_idx < INTO.len() { add(&INTO[next_idx], 1); }
        step(YIELD, ACCT, SWITCHING);
    }
    pub fn after_switch() { step(SWITCHING, ASM, SWITCHED); }
    pub fn ecall_exit() { step(SWITCHED, POST, RETURNED); }

    pub fn dump_window() {
        let sw = SWITCHES.load(Relaxed);
        let since = sw.wrapping_sub(SW_EPOCH.swap(sw, Relaxed));
        let y = YIELDS.swap(0, Relaxed);
        let mut acc = [0u64; N];
        let mut hits = [0u64; N];
        for i in 0..N {
            acc[i] = ACC[i].swap(0, Relaxed);
            hits[i] = HITS[i].swap(0, Relaxed);
        }
        let mut into = [0u64; 64];
        for (a, v) in INTO.iter().zip(into.iter_mut()) { *v = a.swap(0, Relaxed); }
        STATE.store(NONE, Relaxed);
        if since < DUMP_MIN { return; }
        // aarch64 counts CNTVCT ticks: scale to ns (= instructions under
        // -icount shift=0). riscv64's rdcycle is already instructions.
        #[cfg(target_arch = "aarch64")]
        let (num, den) = {
            let f: u64;
            unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack)) };
            (1_000_000_000u128, f.max(1) as u128)
        };
        #[cfg(not(target_arch = "aarch64"))]
        let (num, den) = (1u128, 1u128);
        let mut line = [0u64; N];
        let mut total = 0u64;
        for i in 0..N {
            line[i] = (acc[i] as u128 * num / den / hits[i].max(1) as u128) as u64;
            total += line[i];
        }
        azos_drv_sys::kprintln!(
            "[SW-CENSUS] switches={} yields={} instr/switch {}={} {}={} {}={} {}={} {}={} {}={} {}={} {}={} sum={} (hits pick={} trap={})",
            since, y, NAMES[0], line[0], NAMES[1], line[1], NAMES[2], line[2], NAMES[3], line[3],
            NAMES[4], line[4], NAMES[5], line[5], NAMES[6], line[6], NAMES[7], line[7], total,
            hits[PICK], hits[TRAP],
        );
        for (i, &n) in into.iter().enumerate() {
            if n > 0 { azos_drv_sys::kprintln!("[SW-CENSUS] into slot {} = {}", i, n); }
        }
    }
}

#[cfg(feature = "switch-census")]
pub use imp::{
    after_switch, before_switch, dump_window, ecall_enter, ecall_exit, gated, picked, requeued,
    yield_enter,
};

#[cfg(not(feature = "switch-census"))]
mod off {
    #[inline(always)] pub fn ecall_enter() {}
    #[inline(always)] pub fn yield_enter() {}
    #[inline(always)] pub fn picked() {}
    #[inline(always)] pub fn requeued() {}
    #[inline(always)] pub fn gated() {}
    #[inline(always)] pub fn before_switch(_: usize) {}
    #[inline(always)] pub fn after_switch() {}
    #[inline(always)] pub fn ecall_exit() {}
    #[inline(always)] pub fn dump_window() {}
}
#[cfg(not(feature = "switch-census"))]
pub use off::*;
