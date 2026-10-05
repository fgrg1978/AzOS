// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the handler waits that used to be counted in `task_yield()`
// calls (wave 11): `sys_accept` (50,000 yields) and `sys_pause` (1,000), now
// bounded by the counter (`ACCEPT_WAIT_MS`, `PAUSE_WAIT_MS`) and sleeping
// between looks through `crate::sleep::wait_until_ms`.
//
// HOW THE SHIMS MODEL TIME
//
// `task_yield` (armed) only counts: it does not move the clock. That is the
// host-load case the old bounds failed in: a yield costs whatever CPU the
// host gives the guest, so a count of them can end long before a wall-clock
// event (a peer, a signal) arrives. `task_block_outcome` (armed `Returned`)
// records the reason and runs the block hook; the hook below plays the timer
// and moves the clock to the sleep's deadline, as a wake at that deadline
// would. A handler that waited by yields therefore sees no time pass at all.
//
// CANARY: put the yield loops back (`for _ in 0..1000 { ...; task_yield() }`
// in `sys_pause`, `0..50_000` in `sys_accept`). The pause test then reads -1
// at clock 0 (the signal comes at 2 s) and the accept test reads a clock that
// never moved. With `yield` disarmed instead of armed, the old code panics on
// the stand-in's `todo!()`.

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

/// A signal that arrives after 2 s of counter time ends the pause with 0.
/// The old 1000 yields ended it with -1 at clock 0.
#[test]
fn pause_returns_for_a_signal_that_arrives_after_two_seconds() {
    let _g = super::harness::serial();
    azos_ipc::shim_set_signal_pending(Some(0));
    arm_sleep(|now| {
        if now >= 2_000 * TICKS_PER_MS {
            azos_ipc::shim_set_signal_pending(Some(1 << 14));
        }
    });
    assert_eq!(sys_pause(), 0, "the signal came at 2 s, inside PAUSE_WAIT_MS");
    let t = get_time();
    assert!(
        (2_000 * TICKS_PER_MS..=2_001 * TICKS_PER_MS).contains(&t),
        "pause must end at the first look after the signal, clock {t}",
    );
    assert_eq!(azos_sched::shim_yields(), Some(0), "a sleeping wait yields nothing");
}

/// No signal: the pause gives up when PAUSE_WAIT_MS of counter time has
/// passed, after one look per millisecond.
#[test]
fn pause_without_a_signal_gives_up_on_the_clock() {
    let _g = super::harness::serial();
    azos_ipc::shim_set_signal_pending(Some(0));
    arm_sleep(|_| {});
    assert_eq!(sys_pause(), -1);
    assert_eq!(get_time(), PAUSE_WAIT_MS * TICKS_PER_MS, "the deadline, to the tick");
    let blocks = timer_blocks() as u64;
    assert!(
        (PAUSE_WAIT_MS - 1..=PAUSE_WAIT_MS).contains(&blocks),
        "{blocks} sleeps of 1 ms for a {PAUSE_WAIT_MS} ms wait",
    );
    assert_eq!(azos_sched::shim_yields(), Some(0));
}

/// A pending signal at entry answers 0 without sleeping at all.
#[test]
fn pause_with_a_signal_already_pending_does_not_sleep() {
    let _g = super::harness::serial();
    azos_ipc::shim_set_signal_pending(Some(1 << 14));
    arm_sleep(|_| {});
    assert_eq!(sys_pause(), 0);
    assert_eq!(timer_blocks(), 0);
    assert_eq!(get_time(), 0);
}

/// No connection ever arrives: accept answers -1 when ACCEPT_WAIT_MS of
/// counter time has passed, polling the stack once per look and never
/// yielding. The old 50,000 yields ended it with the clock unmoved.
#[test]
fn accept_with_no_connection_gives_up_on_the_clock() {
    let _g = super::harness::serial();
    let fd = azos_net::socket_create_owned(2, 1, 0, azos_net::SOCK_OWNER_KERNEL);
    assert!(fd >= 0, "no free socket");
    azos_net::shim_arm_net_poll(true);
    arm_sleep(|_| {});
    assert_eq!(sys_accept(fd as u64, 0, 0), -1);
    assert_eq!(get_time(), ACCEPT_WAIT_MS * TICKS_PER_MS, "the deadline, to the tick");
    let polls = azos_net::shim_net_polls().unwrap_or(0);
    assert!(
        (ACCEPT_WAIT_MS..=ACCEPT_WAIT_MS + 1).contains(&polls),
        "{polls} polls: one per 1 ms look over {ACCEPT_WAIT_MS} ms",
    );
    assert_eq!(azos_sched::shim_yields(), Some(0), "a sleeping wait yields nothing");
    azos_net::socket_close(fd);
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
