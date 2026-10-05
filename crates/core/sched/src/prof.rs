// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Process life-cycle phase profile (feature `fork-profile`, wave 13).
//!
//! Under QEMU `-icount shift=0` virtual time advances one nanosecond per
//! instruction, so on aarch64 (`CNTVCT_EL0` at 1 GHz) a counter difference is
//! an instruction count. riscv64's `time` runs at 10 MHz there: its figures
//! are in units of 100 instructions. Off (the default), every call is empty
//! and inlined away.
//!
//! Each phase sums its spans and counts them; [`report`] prints the means
//! every `N` samples of the phase passed to it and starts over.

#[cfg(feature = "fork-profile")]
use core::sync::atomic::{AtomicU64, Ordering};

/// Phases measured.
pub const PHASES: usize = 24;

/// Names, in phase order.
pub const NAMES: [&str; PHASES] = [
    "fork.total", "fork.cow", "fork.kernel-slots", "fork.task-create", "fork.user-info",
    "fork.before-release", "fork.endpoint-hook", "fork.fp+ctx", "natfork.pass1", "natfork.seed",
    "natfork.pass3", "exit.total", "exit.hook", "exit.address-space", "exit.notice",
    "exit.late-hook", "child.entry", "wait.call", "exit.hook.svc+ipc", "exit.hook.fs",
    "exit.hook.net", "exit.hook.drv", "exit.hook.head", "fork.syscall",
];

#[cfg(feature = "fork-profile")]
static SUM: [AtomicU64; PHASES] = [const { AtomicU64::new(0) }; PHASES];
#[cfg(feature = "fork-profile")]
static CNT: [AtomicU64; PHASES] = [const { AtomicU64::new(0) }; PHASES];

/// The counter now (0 without the feature).
#[inline(always)]
pub fn t() -> u64 {
    #[cfg(feature = "fork-profile")]
    {
        azos_arch::cpu::now_ticks()
    }
    #[cfg(not(feature = "fork-profile"))]
    {
        0
    }
}

/// Add the span since `t0` to phase `p`.
#[inline(always)]
pub fn add(p: usize, t0: u64) {
    #[cfg(feature = "fork-profile")]
    if p < PHASES {
        let d = azos_arch::cpu::now_ticks().wrapping_sub(t0);
        SUM[p].fetch_add(d, Ordering::Relaxed);
        CNT[p].fetch_add(1, Ordering::Relaxed);
    }
    #[cfg(not(feature = "fork-profile"))]
    let _ = (p, t0);
}

/// Every `n` samples of phase `p`: print each phase's mean and count, then
/// start over.
pub fn report(p: usize, n: u64) {
    #[cfg(feature = "fork-profile")]
    if p < PHASES && n != 0 && CNT[p].load(Ordering::Relaxed) >= n {
        for i in 0..PHASES {
            let c = CNT[i].swap(0, Ordering::Relaxed);
            let s = SUM[i].swap(0, Ordering::Relaxed);
            if c != 0 {
                azos_drv_sys::kprintln!("[PROF] {:<20} mean={} n={}", NAMES[i], s / c, c);
            }
        }
    }
    #[cfg(not(feature = "fork-profile"))]
    let _ = (p, n);
}
