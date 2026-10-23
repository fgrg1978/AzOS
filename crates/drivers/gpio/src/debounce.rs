// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Debounce of a switch read on its edges: which samples of the line are a
//! new press.
//!
//! **Leading-edge debounce.** A press is accepted on the first sample that
//! reads the line active, with no wait: the e-stop latch it feeds is
//! fail-safe and never cleared by the switch, so holding the stop back for a
//! debounce window would only add the window to the stop's latency (Linux's
//! `gpio-keys` waits its whole `debounce-interval`, 5 ms by default, before
//! it reports a key). The window is spent on the other side: once pressed,
//! the line has to read inactive for the whole window, uninterrupted, before
//! a later active sample counts as a NEW press. So a contact that bounces on
//! release, or chatters while held, is one press and one record, not one per
//! bounce.
//!
//! What filters a glitch is the sample itself: the caller samples the level
//! when it handles the edge, so a spike that is over by then reads inactive
//! and is no press. An e-stop button latches mechanically, so a real press is
//! still active seconds later.
//!
//! Time is whatever monotonic unit the caller uses (the kernel passes
//! timebase ticks); the window is in the same unit.

/// Where the switch is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    /// Released and stable: the next active sample is a press.
    Released,
    /// Pressed: active on the last sample.
    Pressed,
    /// Read inactive since `since`, not yet for the whole window.
    Releasing { since: u64 },
}

/// What one sample meant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    /// Nothing new: the line is where it was, or a bounce.
    Quiet,
    /// A new press: the caller stops and records.
    Press,
}

/// The debounce state of one line.
#[derive(Clone, Copy, Debug)]
pub struct Debounce {
    window: u64,
    state: State,
}

impl Debounce {
    /// A released line, with `window` (the caller's time unit) of stable
    /// inactivity between two presses. A line that is already active at the
    /// first sample is a press: arming a switch that is held is a stop, there
    /// is no edge to wait for.
    pub const fn new(window: u64) -> Self {
        Self { window, state: State::Released }
    }

    /// The line read `active` at `now`.
    pub fn observe(&mut self, now: u64, active: bool) -> Step {
        match (self.state, active) {
            (State::Released, true) => {
                self.state = State::Pressed;
                Step::Press
            }
            (State::Released, false) => Step::Quiet,
            // Held, or a bounce back inside the window: the same press.
            (State::Pressed, true) | (State::Releasing { .. }, true) => {
                self.state = State::Pressed;
                Step::Quiet
            }
            (State::Pressed, false) => {
                self.state = if self.window == 0 { State::Released } else { State::Releasing { since: now } };
                Step::Quiet
            }
            (State::Releasing { since }, false) => {
                if now.wrapping_sub(since) >= self.window {
                    self.state = State::Released;
                }
                Step::Quiet
            }
        }
    }

    /// When the line has to be sampled again although no edge came: the end
    /// of a release window (the release only completes on a sample at or
    /// after it). `None` when nothing is pending.
    pub fn deadline(&self) -> Option<u64> {
        match self.state {
            State::Releasing { since } => Some(since.wrapping_add(self.window)),
            _ => None,
        }
    }

    /// Whether the switch counts as pressed (active, or inside its release
    /// window).
    pub fn pressed(&self) -> bool {
        !matches!(self.state, State::Released)
    }
}

/// A switch on a GPIO line: its polarity, from the tree, and its debounce.
/// What the kill switch's task feeds each sample through.
#[derive(Clone, Copy, Debug)]
pub struct Switch {
    active_low: bool,
    debounce: Debounce,
}

impl Switch {
    /// A released switch, pressed when the line reads low (`active_low`) or
    /// high, with `window` of stable release between two presses.
    pub const fn new(active_low: bool, window: u64) -> Self {
        Self { active_low, debounce: Debounce::new(window) }
    }

    /// The line read `level` at `now`: 0 or 1, or a negative value for a read
    /// the controller refused, which is no sample.
    pub fn sample(&mut self, now: u64, level: i32) -> Step {
        if level < 0 {
            return Step::Quiet;
        }
        self.debounce.observe(now, (level == 0) == self.active_low)
    }

    /// See [`Debounce::deadline`].
    pub fn deadline(&self) -> Option<u64> {
        self.debounce.deadline()
    }
}
