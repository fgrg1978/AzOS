// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Child module of `scheduler.rs` (pulled in with `#[path]`), moved out of it unchanged.

use super::*;
static ENTRY_CPU: [AtomicUsize; MAX_TASKS] = [const { AtomicUsize::new(usize::MAX) }; MAX_TASKS];

pub unsafe fn arm(cpu: usize, idx: usize) {
    if idx >= MAX_TASKS || ncpu() < 2 { return; }
    let saved = task_ref(idx).cpu_affinity;
    task_mut(idx).cpu_affinity = ((cpu + 1) % ncpu()) as i8;
    let until = azos_drv_sys::timebase::now() + azos_drv_sys::timebase::TIMER_FREQ / 1000;
    crate::task_block(WaitReason::Timer(until));
    task_mut(idx).cpu_affinity = saved;
    ENTRY_CPU[idx].store(cpu, Ordering::Release);
}

pub unsafe fn take(cpu: usize) -> usize {
    let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
    if idx < MAX_TASKS {
        let c = ENTRY_CPU[idx].swap(usize::MAX, Ordering::AcqRel);
        if c != usize::MAX { return c; }
    }
    cpu
}
