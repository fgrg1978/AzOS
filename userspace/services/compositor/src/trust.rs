// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The trusted path's timing: when the banner goes up and when the focus is
//! handed on.
//!
//! The input server closes its gate at the Secure Attention Key (`inputd`'s
//! `focus.rs`): until the compositor takes the focus, every other caller is
//! refused it. The compositor learns of the chord by the count on the
//! trusted-path page moving ([`Trust::observe`]), draws the banner at once, and
//! takes the focus (and gives it back, which is what opens the gate)
//! [`Trust::due`] after `banner_ms` of the last chord. In between no
//! application can ask for the keyboard, so none can put a look-alike prompt on
//! the screen and receive what is typed into it before the user has seen the
//! real banner. A second chord inside the interval extends it.
//!
//! Pure: the caller reads the page and the clock; this decides.

/// The trusted path's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trust {
    /// The chord count last seen on the page.
    seen: u32,
    /// When the gate is opened; `None` while no chord is being handled.
    deadline_ns: Option<u64>,
    banner_ns: u64,
}

impl Trust {
    /// A path that has seen `seen` chords already (the page's count when the
    /// compositor started) and holds the gate for `banner_ms` after each.
    pub const fn new(seen: u32, banner_ms: u32) -> Trust {
        Trust { seen, deadline_ns: None, banner_ns: banner_ms as u64 * 1_000_000 }
    }

    /// The page's count was read at `now_ns`. `true` when a chord happened since
    /// the last look: show (or redraw) the banner.
    pub fn observe(&mut self, count: u32, now_ns: u64) -> bool {
        if count == self.seen {
            return false;
        }
        self.seen = count;
        self.deadline_ns = Some(now_ns.saturating_add(self.banner_ns));
        true
    }

    /// The count of chords seen.
    pub fn chords(&self) -> u32 {
        self.seen
    }

    /// Is a chord being handled: the banner is up and the gate closed?
    pub fn active(&self) -> bool {
        self.deadline_ns.is_some()
    }

    /// Is it time to take the focus and give it on?
    pub fn due(&self, now_ns: u64) -> bool {
        self.deadline_ns.is_some_and(|d| now_ns >= d)
    }

    /// The focus was handed on: the banner comes down.
    pub fn handed_on(&mut self) {
        self.deadline_ns = None;
    }
}
