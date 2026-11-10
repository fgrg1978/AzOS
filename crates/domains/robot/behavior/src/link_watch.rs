// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's view of the companion link as the ring-3 engine reports it
//! (`PKT_LINK_STATE`), and the flight handoff a lost link requests of a drone.
//! Atomics only, no external crate: the host suite compiles this file.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::containment::{LINK_LOST, LINK_UP, LINK_VERDICT_LOST};

/// Why containment is being armed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Loss {
    /// The engine reported the session ended.
    Session,
    /// The engine reported the verdict missing.
    Verdict,
    /// A session reported up went silent: the engine stopped.
    Silent,
    /// A report the kernel cannot read: fail closed.
    Malformed,
}

/// When the last "up" arrived (clock ticks), 0 while no session is reported.
pub struct LinkWatch {
    beat: AtomicU64,
}

impl LinkWatch {
    pub const fn new() -> Self {
        Self { beat: AtomicU64::new(0) }
    }

    /// A `PKT_LINK_STATE` payload at `now`. `Some` when it arms containment:
    /// a loss report does, once per reported session; a report the kernel
    /// cannot read (none, or an unknown state) does too.
    pub fn report(&self, payload: &[u8], now: u64) -> Option<Loss> {
        match payload.first() {
            Some(&LINK_UP) => {
                self.beat.store(now.max(1), Ordering::Release);
                None
            }
            Some(&LINK_VERDICT_LOST) => self.take().then_some(Loss::Verdict),
            Some(&LINK_LOST) => self.take().then_some(Loss::Session),
            _ => {
                self.beat.store(0, Ordering::Release);
                Some(Loss::Malformed)
            }
        }
    }

    /// A session reported up that has gone `silence` ticks without a report.
    pub fn tick(&self, now: u64, silence: u64) -> Option<Loss> {
        if cfg!(feature = "link-silence-canary") {
            return None;
        }
        let beat = self.beat.load(Ordering::Acquire);
        (beat != 0 && now.saturating_sub(beat) > silence && self.take()).then_some(Loss::Silent)
    }

    fn take(&self) -> bool {
        self.beat.swap(0, Ordering::AcqRel) != 0
    }
}

pub static LINK: LinkWatch = LinkWatch::new();

/// When a drone's flight failsafe was asked to take over (clock ticks), 0 for
/// no request.
static FLIGHT_HANDOFF: AtomicU64 = AtomicU64::new(0);

/// Ask the flight failsafe to take over; the first request keeps its time.
pub fn flight_handoff_request(now: u64) {
    let _ = FLIGHT_HANDOFF.compare_exchange(0, now.max(1), Ordering::AcqRel, Ordering::Acquire);
}

/// When the handoff was requested, if it stands.
pub fn flight_handoff_since() -> Option<u64> {
    match FLIGHT_HANDOFF.load(Ordering::Acquire) {
        0 => None,
        t => Some(t),
    }
}

/// The link is back: the request lapses (a landing already begun continues).
pub fn flight_handoff_clear() {
    FLIGHT_HANDOFF.store(0, Ordering::Release);
}
