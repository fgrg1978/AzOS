// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ktest only: a task that reads its hart id and then a per-hart table does so
//! with interrupts masked.
//!
//! `current_cpu_id()` followed by `PER_CPU[cpu].field` is two steps; with
//! interrupts on, a tick between them can move the task and the second read
//! answers for the hart the task left. The sites that were fixed (the audit
//! table of the front `percpu-hazard-b`) mask across the pair. This module
//! counts, in a ktest build, how often a representative site is open to
//! interrupts at the point between the two reads, so the ktest can require
//! zero without having to win a real race.
//!
//! Canary `percpu-hazard-canary` (cargo feature, gate only): the site takes no
//! mask, as before the fix; the open count rises and the ktest is `not ok`.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::scheduler::MAX_CPUS;

/// Windows a task opened, per hart.
static WINDOWS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
/// Windows that were open to interrupts between the id read and the table read.
static OPEN: AtomicU32 = AtomicU32::new(0);

/// Called by the audited site between the two reads. A window an interrupt
/// handler opens is masked by hardware and says nothing about the site.
pub(crate) fn note(cpu: usize) {
    use azos_arch::Interrupts;
    if cpu >= MAX_CPUS || azos_sync::isr_depth::in_isr(cpu) {
        return;
    }
    WINDOWS[cpu].fetch_add(1, Ordering::Relaxed);
    if azos_arch::ARCH.interrupts_enabled() {
        OPEN.fetch_add(1, Ordering::Relaxed);
    }
}

/// The late runner (a kernel task) calls the audited site and checks that it
/// opened one window, that the window was masked, and that the answer is the
/// runner's own slot.
pub fn ktest_current_reads_masked() -> Result<(), &'static str> {
    // The runner stays on this hart, so the per-hart window count is its own.
    let _stay = azos_sync::preempt::critical_section();
    let cpu = crate::smp::current_cpu_id();
    let Some(want) = crate::idx_for_tid(crate::current_task_tid()) else {
        return Err("the late runner is not a task");
    };
    OPEN.store(0, Ordering::Relaxed);
    let before = WINDOWS[cpu].load(Ordering::Relaxed);
    let got = crate::classes::current();
    if WINDOWS[cpu].load(Ordering::Relaxed) == before {
        return Err("classes::current no longer reaches the audited window");
    }
    if OPEN.load(Ordering::Relaxed) != 0 {
        return Err("classes::current reads the hart id and its slot with interrupts on");
    }
    if got != Some(want) {
        return Err("classes::current is not the caller's slot");
    }
    Ok(())
}
