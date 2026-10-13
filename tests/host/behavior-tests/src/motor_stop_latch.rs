// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for the motor stop latch (`domains/robot/robot/src/motor_cmd.rs`,
//! pulled in with `#[path]`, so this is the source the kernel links).
//!
//! Trap, fault and shutdown paths used to publish `(0, 0)` into the motor
//! command channel from any hart, next to behaviour's 10 Hz publisher. Two
//! writers can make a reader accept a torn command. They now set a stop
//! timestamp, and the reader resolves the command against it. These tests pin
//! that resolution: what wins, and what the motor watchdog sees as the age.

#[path = "../../../../domains/robot/robot/src/motor_cmd.rs"]
mod motor_cmd;

use motor_cmd::{age, resolve};

const STOP: (i32, i32) = (0, 0);
const GO: (i32, i32) = (60, -60);

#[test]
fn no_stop_requested_keeps_the_command() {
    assert_eq!(resolve(GO, 100, 0, STOP), GO);
}

#[test]
fn a_stop_after_the_command_wins() {
    assert_eq!(resolve(GO, 100, 101, STOP), STOP);
}

#[test]
fn a_stop_in_the_same_tick_wins() {
    // Fail safe: equal timestamps cannot be ordered, so the stop is applied.
    assert_eq!(resolve(GO, 100, 100, STOP), STOP);
}

#[test]
fn a_command_after_the_stop_overrides_it() {
    // The same as the old `(0, 0)` publish being overwritten by behaviour's
    // next tick.
    assert_eq!(resolve(GO, 102, 101, STOP), GO);
}

#[test]
fn a_stop_with_nothing_published_is_a_stop() {
    // Channel never published: value is its initial (0, 0), timestamp 0.
    assert_eq!(resolve(STOP, 0, 5, STOP), STOP);
}

#[test]
fn age_without_a_stop_is_the_channel_age() {
    assert_eq!(age(u64::MAX, 1_000, 0), u64::MAX);
    assert_eq!(age(40, 1_000, 0), 40);
}

#[test]
fn a_stop_refreshes_the_age_like_the_publish_it_replaces() {
    // Never published, stop at 900: age 100, not "never".
    assert_eq!(age(u64::MAX, 1_000, 900), 100);
    // Published 40 ticks ago, stop 100 ago: the newer one counts.
    assert_eq!(age(40, 1_000, 900), 40);
    // Published 300 ago, stop 100 ago.
    assert_eq!(age(300, 1_000, 900), 100);
}

#[test]
fn a_stop_stamped_after_now_reads_as_age_zero() {
    // Another hart's timebase may run a tick ahead.
    assert_eq!(age(u64::MAX, 1_000, 1_001), 0);
}
