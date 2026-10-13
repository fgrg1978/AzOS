// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Child module of `scheduler.rs` (pulled in with `#[path]`), moved out of it unchanged.

use core::sync::atomic::{AtomicU32, Ordering};
pub static SAME_HART: AtomicU32 = AtomicU32::new(0);
pub static OTHER_HART: AtomicU32 = AtomicU32::new(0);

#[inline]
pub(super) fn record(target_cpu: usize) {
    let same = target_cpu == crate::smp::current_cpu_id();
    let (s, o) = if same {
        (SAME_HART.fetch_add(1, Ordering::Relaxed) + 1, OTHER_HART.load(Ordering::Relaxed))
    } else {
        (SAME_HART.load(Ordering::Relaxed), OTHER_HART.fetch_add(1, Ordering::Relaxed) + 1)
    };
    let n = s.wrapping_add(o);
    if n >= 64 && n.is_power_of_two() {
        azos_drv_sys::kprintln!(
            "[SCHED] ipc-placement wakes={} same_hart={} other_hart={} affinity={}",
            n, s, o, cfg!(feature = "sched-ipc-affinity"),
        );
    }
}
