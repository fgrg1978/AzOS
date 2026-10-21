// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the handler waits that used to be counted in `task_yield()`
// calls (wave 11), now bounded by the clock and sleeping between looks
// through `crate::sleep::wait_until_ms`.
//
// HOW THE SHIMS MODEL TIME
//
// `task_yield` (armed) only counts: it does not move the clock. That is the
// host-load case the old bounds failed in: a yield costs whatever CPU the
// host gives the guest, so a count of them can end long before a wall-clock
// event (a peer) arrives. `task_block_outcome` (armed `Returned`)
// records the reason and runs the block hook; the hook below plays the timer
// and moves the clock to the sleep's deadline, as a wake at that deadline
// would. A handler that waited by yields therefore sees no time pass at all.
//
// CANARY: make `wait_until_ms` yield instead of sleeping: the test below
// reads a clock that never moved.

use azos_drv_irqchip::clint::{get_time, set_time};
use azos_drv_sys::timebase::TIMER_FREQ;
use azos_sched::{BlockOutcome, WaitReason};

const TICKS_PER_MS: u64 = TIMER_FREQ / 1000;

/// Arm the shims for a sleeping wait: yields count (and must stay 0), every
/// block returns at its timer deadline, and `on_wake` runs at each wake with
/// the new clock.
fn arm_sleep(mut on_wake: impl FnMut(u64) + Send + 'static) {
    azos_sched::shim_arm_yield();
    azos_sched::shim_arm_block_outcome(BlockOutcome::Returned);
    azos_sched::shim_set_block_hook(Some(Box::new(move |r| {
        if let WaitReason::Timer(deadline) = r {
            if deadline > get_time() {
                set_time(deadline);
            }
            on_wake(get_time());
        }
    })));
}

fn timer_blocks() -> usize {
    azos_sched::shim_take_blocks()
        .into_iter()
        .filter(|r| matches!(r, WaitReason::Timer(_)))
        .count()
}

/// `wait_until_ms` asks once more after the deadline: a condition that turns
/// true during the last step is reported, not timed out.
#[test]
fn wait_until_ms_reports_a_condition_met_in_the_last_step() {
    let _g = super::harness::serial();
    arm_sleep(|_| {});
    let mut looks = 0u32;
    let ok = crate::sleep::wait_until_ms(10, 5, || {
        looks += 1;
        get_time() >= 10 * TICKS_PER_MS
    });
    assert!(ok, "true at the deadline must count");
    assert_eq!(looks, 3, "at 0, 5 and 10 ms");
}
