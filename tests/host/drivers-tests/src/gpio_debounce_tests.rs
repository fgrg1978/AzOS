// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `debounce.rs` (the kill switch's debounce) on the host.
//!
//! The canary is the old reader: `sys-wdt`'s 500 ms poll kept one flag
//! (`estop_pin_was_pressed`) and called every inactive sample a release, so a
//! contact that bounced on release was a second press and a second durable
//! record. [`OldPoll`] is that flag, verbatim; each test that the new machine
//! passes on chatter is run against it too and must fail there.

use super::debounce::{Debounce, Step};

/// `system_wdt_task` §3 before the edge interrupt: one flag, no window.
struct OldPoll {
    was_pressed: bool,
}

impl OldPoll {
    fn observe(&mut self, _now: u64, active: bool) -> Step {
        if !active {
            self.was_pressed = false;
        }
        if active && !self.was_pressed {
            self.was_pressed = true;
            return Step::Press;
        }
        Step::Quiet
    }
}

trait Line {
    fn observe(&mut self, now: u64, active: bool) -> Step;
}
impl Line for Debounce {
    fn observe(&mut self, now: u64, active: bool) -> Step {
        Debounce::observe(self, now, active)
    }
}
impl Line for OldPoll {
    fn observe(&mut self, now: u64, active: bool) -> Step {
        OldPoll::observe(self, now, active)
    }
}

fn presses(l: &mut dyn Line, samples: &[(u64, bool)]) -> usize {
    samples.iter().filter(|&&(t, a)| l.observe(t, a) == Step::Press).count()
}

const WINDOW: u64 = 5_000;

/// A press, a release that bounces three times inside the window, then
/// stable: one press.
const BOUNCING_RELEASE: &[(u64, bool)] = &[
    (100, true),
    (10_000, false),
    (10_300, true),
    (10_600, false),
    (11_000, true),
    (11_200, false),
    (20_000, false),
];

#[test]
fn the_first_active_sample_is_the_press_with_no_wait() {
    let mut d = Debounce::new(WINDOW);
    assert_eq!(d.observe(100, true), Step::Press, "a press must not wait out the window");
    assert!(d.pressed());
}

#[test]
fn a_bouncing_release_is_one_press() {
    assert_eq!(presses(&mut Debounce::new(WINDOW), BOUNCING_RELEASE), 1);
}

#[test]
fn canary_the_old_poll_counts_each_bounce_as_a_press() {
    // Discriminates: the same samples were three records under the old flag.
    assert_eq!(presses(&mut OldPoll { was_pressed: false }, BOUNCING_RELEASE), 3);
}

#[test]
fn a_release_held_for_the_window_then_a_press_is_two_events() {
    let s = [(0, true), (1_000, false), (1_000 + WINDOW, false), (1_000 + WINDOW + 1, true)];
    assert_eq!(presses(&mut Debounce::new(WINDOW), &s), 2);
}

#[test]
fn a_release_one_tick_short_of_the_window_is_still_the_same_press() {
    let s = [(0, true), (1_000, false), (1_000 + WINDOW - 1, false), (1_000 + WINDOW, true)];
    assert_eq!(presses(&mut Debounce::new(WINDOW), &s), 1);
}

#[test]
fn a_line_already_active_when_armed_is_a_press_without_an_edge() {
    // The arm-time sample: a switch held while the kernel arms the line gives
    // the controller no edge to report.
    let mut d = Debounce::new(WINDOW);
    assert_eq!(d.observe(0, true), Step::Press);
}

#[test]
fn a_released_line_is_quiet_forever() {
    let s: Vec<(u64, bool)> = (0..100).map(|i| (i * 1_000, false)).collect();
    assert_eq!(presses(&mut Debounce::new(WINDOW), &s), 0);
}

#[test]
fn the_deadline_is_the_end_of_the_release_window_and_only_then() {
    let mut d = Debounce::new(WINDOW);
    assert_eq!(d.deadline(), None);
    d.observe(0, true);
    assert_eq!(d.deadline(), None, "held: nothing to sample without an edge");
    d.observe(1_000, false);
    assert_eq!(d.deadline(), Some(1_000 + WINDOW));
    d.observe(1_000 + WINDOW, false);
    assert_eq!(d.deadline(), None);
    assert!(!d.pressed());
}

#[test]
fn window_zero_releases_on_the_first_inactive_sample() {
    let s = [(0, true), (1, false), (2, true)];
    assert_eq!(presses(&mut Debounce::new(0), &s), 2);
}

#[test]
fn a_wrapping_clock_still_ends_the_window() {
    let start = u64::MAX - 10;
    let s = [(start, true), (start + 1, false), (start.wrapping_add(1 + WINDOW), false), (start.wrapping_add(2 + WINDOW), true)];
    assert_eq!(presses(&mut Debounce::new(WINDOW), &s), 2);
}
