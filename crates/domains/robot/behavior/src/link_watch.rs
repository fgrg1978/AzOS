// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's view of the companion link as the ring-3 engine reports it
//! (`PKT_LINK_STATE`), and the flight handoff a lost link requests of a drone.
//! Atomics only, no external crate: the host suite compiles this file.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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

/// What a report did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    /// Containment is to be armed.
    pub loss: Option<Loss>,
    /// A session is back after one that ended or went silent (not after a
    /// missing verdict, whose session never ended).
    pub reconnected: bool,
}

/// When the last sign of a session arrived (clock ticks), 0 while none stands,
/// and whether a session's end is still unanswered by a new one.
pub struct LinkWatch {
    beat: AtomicU64,
    down: AtomicBool,
}

impl LinkWatch {
    pub const fn new() -> Self {
        Self { beat: AtomicU64::new(0), down: AtomicBool::new(false) }
    }

    /// A `PKT_LINK_STATE` payload at `now`. A loss report arms once per
    /// reported session; a report the kernel cannot read (none, or an unknown
    /// state) arms too.
    pub fn report(&self, payload: &[u8], now: u64) -> Report {
        let mut reconnected = false;
        let loss = match payload.first() {
            Some(&LINK_UP) => {
                self.beat.store(now.max(1), Ordering::Release);
                reconnected = self.down.swap(false, Ordering::AcqRel) || cfg!(feature = "reconnect-any-beat-canary");
                None
            }
            Some(&LINK_VERDICT_LOST) => self.take().then_some(Loss::Verdict),
            Some(&LINK_LOST) => self.end(Loss::Session),
            _ => {
                self.beat.store(0, Ordering::Release);
                self.down.store(true, Ordering::Release);
                Some(Loss::Malformed)
            }
        };
        Report { loss, reconnected }
    }

    /// A companion command reached the kernel: a session stands. An engine
    /// that drives from commands but never reports is watched all the same.
    pub fn heard(&self, now: u64) {
        self.beat.store(now.max(1), Ordering::Release);
    }

    /// A session that has gone `silence` ticks without a sign.
    pub fn tick(&self, now: u64, silence: u64) -> Option<Loss> {
        if cfg!(feature = "link-silence-canary") {
            return None;
        }
        let beat = self.beat.load(Ordering::Acquire);
        if beat != 0 && now.saturating_sub(beat) > silence {
            return self.end(Loss::Silent);
        }
        None
    }

    fn end(&self, loss: Loss) -> Option<Loss> {
        let was_up = self.take();
        if was_up {
            self.down.store(true, Ordering::Release);
        }
        was_up.then_some(loss)
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
