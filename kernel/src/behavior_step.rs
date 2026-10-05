// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-step timing of `behavior_task`'s control loop.
//!
//! Two spans per step, both in raw `timebase::now()` ticks:
//!
//! * **ml** — the loop's ML section: from before the camera capture to after
//!   the verdict is in hand (whatever produces it).
//! * **work** — the whole step, from the top of the loop body to the sleep.
//!
//! A step whose work exceeds the loop's period (`TIMER_FREQ / 10`) is an
//! overrun: the loop missed its deadline. Printed with the loop's periodic
//! WCET report (`qemu` builds), as one `[BSTEP]` line.
//!
//! Under QEMU `-icount shift=0` one instruction is one nanosecond of virtual
//! time, so a span converted to ns (`ticks * 1e9 / freq`) is an instruction
//! count. With more than one vCPU the virtual clock also advances while
//! another vCPU runs, so `min` is the cleanest figure and `avg` an upper
//! bound.

// The report is called from the loop's `qemu`-only periodic block.
#![cfg_attr(not(feature = "qemu"), allow(dead_code))]

/// Running statistics of one span. Cumulative since boot.
#[derive(Clone, Copy)]
pub struct Span {
    pub n: u64,
    pub min: u64,
    pub max: u64,
    pub sum: u64,
}

impl Span {
    pub const fn new() -> Self {
        Span { n: 0, min: u64::MAX, max: 0, sum: 0 }
    }

    #[inline]
    pub fn add(&mut self, ticks: u64) {
        self.n += 1;
        self.sum = self.sum.wrapping_add(ticks);
        if ticks < self.min { self.min = ticks; }
        if ticks > self.max { self.max = ticks; }
    }

    pub fn avg(&self) -> u64 {
        if self.n == 0 { 0 } else { self.sum / self.n }
    }

    pub fn min_or_zero(&self) -> u64 {
        if self.n == 0 { 0 } else { self.min }
    }
}

/// The loop's two spans and its overrun count.
pub struct StepStats {
    pub ml: Span,
    pub work: Span,
    pub overruns: u64,
}

impl StepStats {
    pub const fn new() -> Self {
        StepStats { ml: Span::new(), work: Span::new(), overruns: 0 }
    }

    /// One finished step: its work span against the loop's period.
    #[inline]
    pub fn step(&mut self, work_ticks: u64, period_ticks: u64) {
        self.work.add(work_ticks);
        if work_ticks > period_ticks {
            self.overruns += 1;
        }
    }

    pub fn report(&self) {
        azos_drv_sys::kprintln!(
            "[BSTEP] steps={} ml_ticks min/avg/max={}/{}/{} work_ticks min/avg/max={}/{}/{} \
             overruns={} freq={}",
            self.work.n,
            self.ml.min_or_zero(), self.ml.avg(), self.ml.max,
            self.work.min_or_zero(), self.work.avg(), self.work.max,
            self.overruns, freq(),
        );
    }
}

/// Ticks per second of the counter the spans are read from.
///
/// aarch64 reads `CNTFRQ_EL0` itself: `TIMER_FREQ` there is a board constant
/// and the generic timer QEMU models under `-cpu max` runs at whatever the
/// register says.
pub fn freq() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let f: u64;
        unsafe { core::arch::asm!("mrs {0}, cntfrq_el0", out(reg) f, options(nomem, nostack)); }
        f
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        azos_drv_sys::timebase::TIMER_FREQ
    }
}
